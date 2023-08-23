use crate::control_connection::TorControlConnection;
use crate::error::TorError;
use base64::{self, Engine};

pub enum TorAuthentication {
    Null,
    SafeCookie(String),     // Cookie String
    HashedPassword(String), // Password
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
                    .send_command(
                        "AUTHENTICATE",
                        Some(&base64::engine::general_purpose::STANDARD.encode(value)),
                    )
                    .await
                {
                    Ok(_) => Ok(()),
                    Err(TorError::ProtocolError(error)) => {
                        Err(TorError::AuthenticationError(error))
                    }
                    Err(error) => Err(error),
                }
            }
            TorAuthentication::SafeCookie(_value) => {
                // TODO: Implement. See https://gitlab.torproject.org/tpo/core/torspec/-/blob/main/control-spec.txt#L1638
                unimplemented!()
            }
        }
    }
}
