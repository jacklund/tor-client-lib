use crate::base64;
use crate::control_connection::TorControlConnection;
use crate::error::TorError;
use hmac::{Hmac, Mac};
use lazy_static::lazy_static;
use rand;
use regex::Regex;
use sha2::Sha256;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

pub enum TorAuthentication {
    Null,
    SafeCookie(Option<String>), // Cookie String
    HashedPassword(String),     // Password
}

impl TorAuthentication {
    pub async fn authenticate(
        &self,
        connection: &mut TorControlConnection,
    ) -> Result<(), TorError> {
        match self {
            TorAuthentication::Null => match connection.send_command("AUTHENTICATE", None).await {
                Ok(_) => Ok(()),
                Err(TorError::ProtocolError(error)) => Err(TorError::AuthenticationError(error)),
                Err(error) => Err(error),
            },
            TorAuthentication::HashedPassword(value) => {
                match connection
                    .send_command("AUTHENTICATE", Some(&base64::encode(value.as_bytes())))
                    .await
                {
                    Ok(_) => Ok(()),
                    Err(TorError::ProtocolError(error)) => {
                        Err(TorError::AuthenticationError(error))
                    }
                    Err(error) => Err(error),
                }
            }
            TorAuthentication::SafeCookie(value) => {
                match value {
                    Some(value) => {
                        let mut client_nonce = vec![rand::random::<u8>(), rand::random::<u8>()];
                        let client_nonce_hex = base64::encode(&client_nonce);
                        let response = connection
                            .send_command("AUTHCHALLENGE", Some(&client_nonce_hex))
                            .await?;
                        if response.status_code != 250 {
                            return Err(TorError::protocol_error(&format!(
                                "Expected status code 250, got {}",
                                response.status_code
                            )));
                        }
                        // Parse the controller response
                        lazy_static! {
                            static ref RE: Regex =
                                Regex::new(r"^AUTHCHALLENGE SERVERHASH=(?P<server_hash>[^ ]*) SERVERNONCE=(?P<server_nonce>[^ ]*)\n")
                                    .unwrap();
                        }
                        match RE.captures(&response.reply) {
                            Some(captures) => {
                                let server_hash_hex = &captures["server_hash"];
                                let server_hash = base64::decode(&server_hash_hex).unwrap();
                                let server_nonce_hex = &captures["server_nonce"];
                                let mut server_nonce = base64::decode(&server_nonce_hex).unwrap();

                                // Validate server hash
                                let mut hmac = HmacSha256::new_from_slice(
                                    b"Tor safe cookie authentication server-to-controller hash",
                                )
                                .unwrap();
                                let mut message = value.as_bytes().to_vec();
                                message.append(&mut client_nonce);
                                message.append(&mut server_nonce);
                                hmac.update(&message);
                                let hash = hmac.finalize().into_bytes();
                                if hash.as_slice() != server_hash {
                                    return Err(TorError::authentication_error(&format!(
                                        "Server hash didn't validate"
                                    )));
                                }

                                // Generate authentication string
                                let mut hmac = HmacSha256::new_from_slice(
                                    b"Tor safe cookie authentication controller-to-server hash",
                                )
                                .unwrap();
                                hmac.update(&message);
                                let auth_string = hmac.finalize().into_bytes();
                                let auth_string_hex = base64::encode(&auth_string);
                                let response = connection
                                    .send_command("AUTHENTICATE", Some(&auth_string_hex))
                                    .await?;
                                if response.status_code != 250 {
                                    return Err(TorError::protocol_error(&format!(
                                        "Expected status code 250, got {}",
                                        response.status_code
                                    )));
                                }
                            }
                            None => {
                                unimplemented!()
                            }
                        }
                    }
                    None => {
                        unimplemented!()
                    }
                }
                // TODO: Implement. See https://gitlab.torproject.org/tpo/core/torspec/-/blob/main/control-spec.txt#L1638
                unimplemented!()
            }
        }
    }
}
