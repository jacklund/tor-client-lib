use crate::control_connection::TorControlConnection;
use crate::error::TorError;
use hex;
use hmac::{Hmac, Mac};
use lazy_static::lazy_static;
use rand;
use regex::Regex;
use sha2::Sha256;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

fn parse_authchallenge_response(response: &str) -> Result<(Vec<u8>, Vec<u8>), TorError> {
    // Parse the controller response
    lazy_static! {
        static ref RE: Regex =
            Regex::new(r"^AUTHCHALLENGE SERVERHASH=(?P<server_hash>[0-9A-F]*) SERVERNONCE=(?P<server_nonce>[0-9A-F]*)")
                .unwrap();
    }
    match RE.captures(response) {
        Some(captures) => {
            let server_hash_hex = &captures["server_hash"];
            let server_nonce_hex = &captures["server_nonce"];
            let server_hash = match hex::decode(server_hash_hex) {
                Ok(hash) => hash,
                Err(error) => {
                    return Err(TorError::protocol_error(&format!(
                        "Error decoding base64 server hash from server: {}",
                        error
                    )))
                }
            };
            let server_nonce = match hex::decode(server_nonce_hex) {
                Ok(nonce) => nonce,
                Err(error) => {
                    return Err(TorError::protocol_error(&format!(
                        "Error decoding base64 server nonce from server: {}",
                        error
                    )))
                }
            };
            Ok((server_hash, server_nonce))
        }
        None => Err(TorError::protocol_error(&format!(
            "Unexpected response from AUTHCHALLENGE: {}",
            response
        ))),
    }
}

fn generate_hmac(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut hmac = HmacSha256::new_from_slice(key).unwrap();
    hmac.update(message);
    hmac.finalize().into_bytes().to_vec()
}

fn validate_server_hash(
    safe_cookie_value: &[u8],
    client_nonce: &mut Vec<u8>,
    server_nonce: &mut Vec<u8>,
    server_hash: &[u8],
) -> Result<Vec<u8>, TorError> {
    // Generate HMAC
    let mut message = safe_cookie_value.to_vec();
    message.append(client_nonce);
    message.append(server_nonce);
    let hash = generate_hmac(
        b"Tor safe cookie authentication server-to-controller hash",
        &message,
    );

    if hash.as_slice() == server_hash {
        Ok(message)
    } else {
        Err(TorError::authentication_error(
            "Server hash didn't validate",
        ))
    }
}

async fn safe_cookie_authentication(
    cookie: &[u8],
    connection: &mut TorControlConnection,
) -> Result<(), TorError> {
    let mut client_nonce = vec![rand::random::<u8>(), rand::random::<u8>()];
    let client_nonce_hex = hex::encode(&client_nonce);
    let response = connection
        .send_command(
            "AUTHCHALLENGE",
            Some(&format!("SAFECOOKIE {}", client_nonce_hex)),
        )
        .await?;

    // Handle the response
    if response.status_code != 250 {
        return Err(TorError::protocol_error(&format!(
            "Expected status code 250, got {}",
            response.status_code
        )));
    }
    let (server_hash, mut server_nonce) = parse_authchallenge_response(&response.reply)?;

    // Validate server hash
    // Note: we reuse the message from the HMAC
    let message = validate_server_hash(cookie, &mut client_nonce, &mut server_nonce, &server_hash)?;

    // Generate authentication string
    let auth_string = hex::encode(generate_hmac(
        b"Tor safe cookie authentication controller-to-server hash",
        &message,
    ));

    // Send authentication request
    let response = connection
        .send_command("AUTHENTICATE", Some(&auth_string))
        .await?;
    if response.status_code != 250 {
        return Err(TorError::protocol_error(&format!(
            "Expected status code 250, got {}",
            response.status_code
        )));
    }
    Ok(())
}

/// Methods for Tor authentication:
/// - Null - No authentication
/// - SafeCookie - `SAFECOOKIE` authentication
/// - HashedPassword - pass the hashed password to authenticate
///
/// With `SafeCookie` auth, you can either pass in the cookie value as a binary vector, or, if you
/// pass in "None", it will call the PROTOCOLINFO command to get the location of the cookie file,
/// and attempt to read that and pass the value to authenticate.
///
/// Note that we don't support plain `COOKIE` authentication, since that's been determmined to be
/// unsafe.
pub enum TorAuthentication {
    Null,
    SafeCookie(Option<Vec<u8>>), // Cookie String
    HashedPassword(String),      // Password
}

lazy_static! {
    static ref NULL_AUTH_NAME: String = "NULL".to_string();
    static ref HASHED_PASSWORD_NAME: String = "HASHEDPASSWORD".to_string();
    static ref SAFE_COOKIE_NAME: String = "SAFECOOKIE".to_string();
}

impl TorAuthentication {
    /// Authenticate using this method to the server
    pub async fn authenticate(
        &self,
        connection: &mut TorControlConnection,
    ) -> Result<(), TorError> {
        let protocol_info = connection.get_protocol_info().await?;
        match self {
            TorAuthentication::Null => {
                if !protocol_info.auth_methods.contains(&*NULL_AUTH_NAME) {
                    return Err(TorError::authentication_error(
                        "Null auth not allowed by this server",
                    ));
                }
                match connection.send_command("AUTHENTICATE", None).await {
                    Ok(_) => Ok(()),
                    Err(TorError::ProtocolError(error)) => {
                        Err(TorError::AuthenticationError(error))
                    }
                    Err(error) => Err(error),
                }
            }
            TorAuthentication::HashedPassword(password) => {
                if !protocol_info.auth_methods.contains(&*HASHED_PASSWORD_NAME) {
                    return Err(TorError::authentication_error(
                        "HashedPassword auth not allowed by this server",
                    ));
                }
                match connection
                    .send_command("AUTHENTICATE", Some(&format!("\"{}\"", password)))
                    .await
                {
                    Ok(_) => Ok(()),
                    Err(TorError::ProtocolError(error)) => {
                        Err(TorError::AuthenticationError(error))
                    }
                    Err(error) => Err(error),
                }
            }
            TorAuthentication::SafeCookie(cookie) => {
                if !protocol_info.auth_methods.contains(&*SAFE_COOKIE_NAME) {
                    return Err(TorError::authentication_error(
                        "SafeCookie auth not allowed by this server",
                    ));
                }
                match cookie {
                    // Authenticate using the passed-in cookie
                    Some(cookie) => safe_cookie_authentication(cookie, connection).await,

                    // None means to read the cookie from the cookie file as defined in the
                    // server's protocol_info
                    None => match protocol_info.cookie_file {
                        Some(cookie_file) => match std::fs::read(cookie_file.clone()) {
                            Ok(cookie) => safe_cookie_authentication(&cookie, connection).await,
                            Err(error) => Err(TorError::authentication_error(&format!(
                                "Error reading cookie file {}: {}",
                                cookie_file, error
                            ))),
                        },
                        None => Err(TorError::authentication_error(
                            "No cookie file provided in tor protocol info",
                        )),
                    },
                }
            }
        }
    }
}
