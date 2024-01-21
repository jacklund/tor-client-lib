use tokio_util::codec::LinesCodecError;

/// Error type returned by this library
#[derive(Debug)]
pub enum TorError {
    /// Authentication error
    AuthenticationError(String),

    /// General protocol error
    ProtocolError(String),

    /// I/O Error
    IOError(std::io::Error),
}

impl std::fmt::Display for TorError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::AuthenticationError(error) => write!(f, "Authentication Error: {}", error),
            Self::ProtocolError(error) => write!(f, "Protocol Error: {}", error),
            Self::IOError(error) => write!(f, "IO Error: {}", error),
        }
    }
}

impl std::error::Error for TorError {}

impl TorError {
    pub fn authentication_error(msg: &str) -> TorError {
        TorError::AuthenticationError(msg.to_string())
    }

    pub fn protocol_error(msg: &str) -> TorError {
        TorError::ProtocolError(msg.to_string())
    }
}

impl From<std::io::Error> for TorError {
    fn from(error: std::io::Error) -> TorError {
        TorError::IOError(error)
    }
}

impl From<LinesCodecError> for TorError {
    fn from(error: LinesCodecError) -> TorError {
        match error {
            LinesCodecError::MaxLineLengthExceeded => TorError::ProtocolError(error.to_string()),
            LinesCodecError::Io(error) => error.into(),
        }
    }
}
