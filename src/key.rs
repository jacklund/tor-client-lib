use crate::base64;
use crate::error::TorError;
use ed25519_dalek::SigningKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::RsaPrivateKey;

#[derive(Clone, Debug)]
pub enum PrivateKey {
    RSA1024(RsaPrivateKey),
    ED25519V3(SigningKey),
}

impl PrivateKey {
    pub fn to_blob(&self) -> String {
        match self {
            Self::RSA1024(key) => base64::encode(key.to_pkcs1_der().unwrap().as_bytes()),
            Self::ED25519V3(key) => {
                let secret_key: [u8; 32] = key.to_bytes();
                let secret_scalar: [u8; 32] = key.to_scalar().to_bytes();
                base64::encode(&[secret_scalar, secret_key].concat())
            }
        }
    }

    pub fn from_blob(key_type: &str, blob: &str) -> Result<Self, TorError> {
        match key_type {
            "RSA1024" => Ok(Self::RSA1024(
                RsaPrivateKey::from_pkcs1_der(&base64::decode(blob).unwrap()).unwrap(),
            )),
            "ED25519-V3" => Ok(Self::ED25519V3(SigningKey::from_bytes(
                base64::decode(blob).unwrap()[..32].try_into().unwrap(),
            ))),
            _ => Err(TorError::protocol_error(&format!(
                "Unknown KeyType parameter from server: '{}'",
                key_type
            ))),
        }
    }
}

pub enum KeyRequest {
    RSA1024,
    ED25519V3,
    Best,
    PrivateKey(Box<PrivateKey>),
}
