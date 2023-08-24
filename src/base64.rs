use base64::{self, DecodeError, Engine};

pub fn encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub fn decode(string: &str) -> Result<Vec<u8>, DecodeError> {
    base64::engine::general_purpose::STANDARD.decode(string)
}
