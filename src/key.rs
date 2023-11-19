use crate::{base64, error::TorError};
use base32::{self, Alphabet};
use curve25519_dalek::Scalar;
use ed25519_dalek::{
    hazmat::{raw_sign, ExpandedSecretKey},
    Signature, SignatureError, Signer, SigningKey as DalekSigningKey, Verifier, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as, Bytes};
use sha2::Sha512;
use sha3::{Digest, Sha3_256};

const TOR_VERSION: u8 = 3;

#[serde_as]
#[derive(Clone, Deserialize, Serialize, Debug, Hash, PartialEq, Eq)]
pub struct TorServiceId {
    #[serde_as(as = "Base64")]
    verifying_key: [u8; 32],
    service_id: String,
}

impl From<TorServiceId> for String {
    fn from(id: TorServiceId) -> String {
        id.service_id
    }
}

impl std::fmt::Display for TorServiceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.service_id)
    }
}

/// Generate the Tor service ID from a verifying key
/// From section 6 of rend-spec-v3.txt
impl std::convert::From<VerifyingKey> for TorServiceId {
    fn from(verifying_key: VerifyingKey) -> Self {
        // Version number
        let version = &[TOR_VERSION];

        // Hash the verifying key concatenated with the checksum and the version
        let verifying_key_bytes = verifying_key.as_bytes();
        let checksum = TorServiceId::calculate_checksum(verifying_key_bytes.as_ref());

        // Base32 the verifying key concatenated with the checksum and the version
        let mut onion_bytes = verifying_key_bytes.to_vec();
        onion_bytes.extend_from_slice(&checksum);
        onion_bytes.extend_from_slice(version);

        Self {
            verifying_key: *verifying_key_bytes,
            service_id: base32::encode(Alphabet::RFC4648 { padding: false }, &onion_bytes)
                .to_lowercase(),
        }
    }
}

impl std::str::FromStr for TorServiceId {
    type Err = TorError;

    fn from_str(service_id: &str) -> Result<Self, Self::Err> {
        let onion_bytes = match base32::decode(Alphabet::RFC4648 { padding: false }, service_id) {
            Some(bytes) => bytes,
            None => return Err(TorError::protocol_error("Error base32 decoding service ID")),
        };
        let mut verifying_key_bytes = [0u8; 32];
        verifying_key_bytes.copy_from_slice(&onion_bytes[..32]);
        let verifying_key = match VerifyingKey::from_bytes(&verifying_key_bytes) {
            Ok(key) => key,
            Err(_) => {
                return Err(TorError::protocol_error(
                    "Error parsing verifying key from bytes",
                ))
            }
        };
        let mut checksum = [0u8; 2];
        checksum.copy_from_slice(&onion_bytes[32..34]);
        let verifying_checksum = Self::calculate_checksum(&verifying_key_bytes);
        if checksum != verifying_checksum {
            return Err(TorError::protocol_error("Invalid checksum"));
        }

        Ok(Self {
            verifying_key: *verifying_key.as_bytes(),
            service_id: service_id.to_string(),
        })
    }
}

impl TorServiceId {
    fn calculate_checksum(verifying_key_bytes: &[u8]) -> [u8; 2] {
        let mut checksum_bytes = ".onion checksum".as_bytes().to_vec();
        checksum_bytes.extend_from_slice(verifying_key_bytes);
        checksum_bytes.extend_from_slice(&[TOR_VERSION]);
        let mut checksum = [0u8; 2];
        checksum
            .copy_from_slice(&Sha3_256::default().chain_update(&checksum_bytes).finalize()[..2]);

        checksum
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from_bytes(&self.verifying_key).unwrap()
    }

    pub fn as_str(&self) -> &str {
        &self.service_id
    }
}

/// Ed25519 Signing key
#[serde_as]
#[derive(Clone, Deserialize, Serialize)]
pub struct TorEd25519SigningKey {
    #[serde_as(as = "Bytes")]
    blob: [u8; 64],
}

impl TorEd25519SigningKey {
    fn expanded_secret_key(&self) -> ExpandedSecretKey {
        ExpandedSecretKey::from_bytes(&self.blob)
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from(&self.expanded_secret_key())
    }

    /// Return the ED25519 scalar
    pub fn scalar(&self) -> Scalar {
        Scalar::from_bytes_mod_order(self.blob[..32].try_into().unwrap())
    }

    /// Create the signing key from the key blob returned by the `ADD_ONION` call
    /// (see https://github.com/torproject/torspec/blob/main/control-spec.txt#L1862-L1864)
    pub fn from_blob(blob: &str) -> Self {
        // Decode the blob and turn it into the Dalek ExpandedSecretKey
        let blob = base64::decode(blob).unwrap();

        Self {
            blob: blob.try_into().unwrap(),
        }
    }

    /// Verify a message against a signature
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        self.verifying_key().verify(message, signature)
    }

    pub fn to_blob(&self) -> String {
        base64::encode(&self.blob)
    }
}

impl From<&DalekSigningKey> for TorEd25519SigningKey {
    fn from(signing_key: &DalekSigningKey) -> Self {
        // Hash the secret key
        let blob = Sha512::default()
            .chain_update(signing_key.to_bytes())
            .finalize();

        Self {
            blob: blob.try_into().unwrap(),
        }
    }
}

/// Implement signing for the Tor key
impl Signer<Signature> for TorEd25519SigningKey {
    fn try_sign(&self, message: &[u8]) -> Result<Signature, SignatureError> {
        Ok(raw_sign::<Sha512>(
            &self.expanded_secret_key(),
            message,
            &self.verifying_key(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;
    use std::str::FromStr;

    // Signing key is (base64) 0H/jnBeWzMoU1MGNRQPnmd8JqlpTNS3UeTiDOMyPTGGXXpLd0KinCtQbcgz2fCYjbzfK3ElJ7x3zGCkB1fAtAA==
    // Service id is vvqbbaknxi6w44t6rplzh7nmesfzw3rjujdijpqsu5xl3nhlkdscgqad
    #[test]
    fn test_ed25519v3_service_id() -> Result<(), anyhow::Error> {
        let base64_blob = "0H/jnBeWzMoU1MGNRQPnmd8JqlpTNS3UeTiDOMyPTGGXXpLd0KinCtQbcgz2fCYjbzfK3ElJ7x3zGCkB1fAtAA==";
        let signing_key = TorEd25519SigningKey::from_blob(base64_blob);
        let public_key = signing_key.verifying_key();
        assert_eq!(
            "vvqbbaknxi6w44t6rplzh7nmesfzw3rjujdijpqsu5xl3nhlkdscgqad",
            TorServiceId::from(public_key).as_str(),
        );
        Ok(())
    }

    #[test]
    fn test_tor_ed25519v3_sign_verify() -> Result<(), anyhow::Error> {
        let message = b"This is my very secret message";
        let base64_blob = "0H/jnBeWzMoU1MGNRQPnmd8JqlpTNS3UeTiDOMyPTGGXXpLd0KinCtQbcgz2fCYjbzfK3ElJ7x3zGCkB1fAtAA==";
        let signing_key = TorEd25519SigningKey::from_blob(base64_blob);
        let signature = signing_key.sign(message);
        assert!(signing_key.verify(message, &signature).is_ok());
        Ok(())
    }

    #[test]
    fn test_to_from_blob() -> Result<(), anyhow::Error> {
        let blob_in = "0H/jnBeWzMoU1MGNRQPnmd8JqlpTNS3UeTiDOMyPTGGXXpLd0KinCtQbcgz2fCYjbzfK3ElJ7x3zGCkB1fAtAA==";
        let signing_key = TorEd25519SigningKey::from_blob(blob_in);
        let blob_out = signing_key.to_blob();
        assert_eq!(blob_in, blob_out);

        Ok(())
    }

    #[test]
    fn test_serialize_service_id() -> Result<(), anyhow::Error> {
        let service_id =
            TorServiceId::from_str("vvqbbaknxi6w44t6rplzh7nmesfzw3rjujdijpqsu5xl3nhlkdscgqad")?;
        let expected = "{\"verifying_key\":\"rWAQgU26PW5yfovXk/2sJIubbimiRoS+EqduvbTrUOQ=\",\"service_id\":\"vvqbbaknxi6w44t6rplzh7nmesfzw3rjujdijpqsu5xl3nhlkdscgqad\"}";
        let json_out = serde_json::to_string(&service_id)?;
        assert_eq!(expected, json_out);
        let deserialized_service_id: TorServiceId = serde_json::from_str(&json_out)?;
        assert_eq!(service_id, deserialized_service_id);
        Ok(())
    }
}
