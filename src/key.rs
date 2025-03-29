use crate::{base64, error::TorError};
use base32::{self, Alphabet};
use curve25519_dalek::Scalar;
use ed25519_dalek::{
    hazmat::{raw_sign, ExpandedSecretKey},
    Signature, SignatureError, Signer, SigningKey, Verifier, VerifyingKey,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sha2::Sha512;
use sha3::{Digest, Sha3_256};
use std::str::FromStr;
use zeroize::{Zeroize, ZeroizeOnDrop};

const TOR_VERSION: u8 = 3;

/// The service ID for the onion service.
///
/// Basically the service ID is the part of the onion address
/// before the ".onion" part. This is an encoding of the onion service's public key into a string.
/// As such, you can convert from the service ID to the public key, and vice-versa.
#[derive(
    Clone,
    Deserialize,
    Serialize,
    Debug,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Zeroize,
    ZeroizeOnDrop,
)]
pub struct TorServiceId(String);

/// Convert the service ID to a String
impl From<TorServiceId> for String {
    fn from(id: TorServiceId) -> String {
        id.0.clone()
    }
}

impl std::fmt::Display for TorServiceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Generate the Tor service ID from an ed25519_dalek verifying (public) key
/// From section 6 of <https://github.com/torproject/torspec/blob/main/rend-spec-v3.txt>
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

        Self(base32::encode(Alphabet::RFC4648 { padding: false }, &onion_bytes).to_lowercase())
    }
}

/// Parse a String into a service ID. Note that this does a good bit of verification that the
/// service ID is indeed a service ID
impl FromStr for TorServiceId {
    type Err = TorError;

    fn from_str(service_id: &str) -> Result<Self, Self::Err> {
        let onion_bytes = match base32::decode(Alphabet::RFC4648 { padding: false }, service_id) {
            Some(bytes) => bytes,
            None => return Err(TorError::protocol_error("Error base32 decoding service ID")),
        };
        if onion_bytes.len() != 35 {
            return Err(TorError::protocol_error("Service ID is of wrong length"));
        }
        let mut verifying_key_bytes = [0u8; 32];
        verifying_key_bytes.copy_from_slice(&onion_bytes[..32]);
        let mut checksum = [0u8; 2];
        checksum.copy_from_slice(&onion_bytes[32..34]);
        let verifying_checksum = Self::calculate_checksum(&verifying_key_bytes);
        if checksum != verifying_checksum {
            return Err(TorError::protocol_error("Invalid checksum"));
        }

        Ok(Self(service_id.to_string()))
    }
}

impl TorServiceId {
    /// Generate a new ED25519 public key, and the corresponding TorServiceId
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        signing_key.verifying_key().into()
    }

    fn calculate_checksum(verifying_key_bytes: &[u8]) -> [u8; 2] {
        let mut checksum_bytes = ".onion checksum".as_bytes().to_vec();
        checksum_bytes.extend_from_slice(verifying_key_bytes);
        checksum_bytes.extend_from_slice(&[TOR_VERSION]);
        let mut checksum = [0u8; 2];
        checksum
            .copy_from_slice(&Sha3_256::default().chain_update(&checksum_bytes).finalize()[..2]);

        checksum
    }

    /// Retrieve the public ED25519 verifying key from the TorServiceId
    pub fn verifying_key(&self) -> Result<VerifyingKey, TorError> {
        let onion_bytes = match base32::decode(Alphabet::RFC4648 { padding: false }, &self.0) {
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
        Ok(verifying_key)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn short_id(&self) -> &str {
        &self.0[..10]
    }

    /// Generate the corresponding onion hostname (by tacking on the ".onion" part)
    pub fn onion_hostname(&self) -> String {
        format!("{}.onion", self.0)
    }
}

/// Type definition for the blob data returned by Tor
/// The blob is the byte representation of the Ed25519 key as used by Tor.
/// It's the output of doing a SHA-512 hash of the original secret key,
/// followed by clamping, so it's basically the "ExpandedSecretKey", but
/// with an unreduced scalar.
pub type TorBlob = [u8; 64];

/// Tor Ed25519 Signing (private) key
///
/// Note that, because of the Tor key blinding, they never transmit the
/// secret key - what we get is, basically, the ExpandedSecretKey (see above),
/// but with the scalar unreduced. This violates one of the invariants for
/// ed25519_dalek, so we can't just store the ExpandedSecretKey, we also need to
/// store the original scalar bytes from the blob so that we can recreate the blob
/// in its original form when needed.
#[serde_as]
#[derive(ZeroizeOnDrop)]
pub struct TorEd25519SigningKey {
    // Used to recreate the original blob
    scalar_bytes: [u8; 32],

    // Actual key data
    expanded_secret_key: ExpandedSecretKey,
}

impl TorEd25519SigningKey {
    /// Expanded secret key, used for signing
    fn expanded_secret_key(&self) -> &ExpandedSecretKey {
        &self.expanded_secret_key
    }

    /// Retrieve the public verifying key from the secret key
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from(self.expanded_secret_key())
    }

    /// Return the ED25519 scalar
    pub fn scalar(&self) -> Scalar {
        self.expanded_secret_key.scalar
    }

    /// Create the signing key from the key blob returned by the `ADD_ONION` call
    /// (see <https://github.com/torproject/torspec/blob/main/control-spec.txt#L1862-L1864>)
    pub fn from_blob(blob: &str) -> Result<Self, TorError> {
        // Decode the blob and turn it into the Dalek ExpandedSecretKey
        let blob_bytes: [u8; 64] = match base64::decode(blob) {
            Ok(bytes) => match bytes.try_into() {
                Ok(bytes) => bytes,
                Err(_) => Err(TorError::protocol_error(&format!(
                    "Wrong number of bytes in blob"
                )))?,
            },
            Err(error) => Err(TorError::protocol_error(&format!(
                "Error decoding blob: {error}"
            )))?,
        };
        Ok(Self::from_bytes(blob_bytes))
    }

    /// Convert from raw bytes to the SigningKey
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&bytes[..32]);
        Self {
            scalar_bytes,
            expanded_secret_key: ExpandedSecretKey::from_bytes(&bytes),
        }
    }

    /// Verify a message against a signature
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        self.verifying_key().verify(message, signature)
    }

    /// Convert the key to a Tor blob value
    pub fn to_blob(&self) -> String {
        let mut blob_bytes = [0u8; 64];
        blob_bytes[..32].copy_from_slice(&self.scalar_bytes);
        blob_bytes[32..].copy_from_slice(&self.expanded_secret_key.hash_prefix);
        base64::encode(&blob_bytes)
    }
}

/// Convert from a Base64-encoded Tor blob to our signing key
impl std::str::FromStr for TorEd25519SigningKey {
    type Err = TorError;

    fn from_str(key: &str) -> Result<Self, Self::Err> {
        Self::from_blob(key)
    }
}

impl std::fmt::Display for TorEd25519SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_blob())
    }
}

impl From<TorBlob> for TorEd25519SigningKey {
    fn from(blob: TorBlob) -> Self {
        Self::from_bytes(blob)
    }
}

/// Convert from an ED25519 signing key to our signing key.
/// This takes the 32-byte secret key, hashes it, and stores that as the blob
impl From<SigningKey> for TorEd25519SigningKey {
    fn from(signing_key: SigningKey) -> Self {
        let expanded_secret_key = ExpandedSecretKey::from(signing_key.as_bytes());

        Self {
            scalar_bytes: expanded_secret_key.scalar.as_bytes().clone(),
            expanded_secret_key,
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
        let signing_key = TorEd25519SigningKey::from_blob(base64_blob)?;
        let public_key = signing_key.verifying_key();
        assert_eq!(
            "vvqbbaknxi6w44t6rplzh7nmesfzw3rjujdijpqsu5xl3nhlkdscgqad",
            TorServiceId::from(public_key).as_str(),
        );
        Ok(())
    }

    #[test]
    fn test_tor_generated_tor_ed25519v3_sign_verify() -> Result<(), anyhow::Error> {
        let message = b"This is my very secret message";
        let base64_blob = "0H/jnBeWzMoU1MGNRQPnmd8JqlpTNS3UeTiDOMyPTGGXXpLd0KinCtQbcgz2fCYjbzfK3ElJ7x3zGCkB1fAtAA==";
        let signing_key = TorEd25519SigningKey::from_blob(base64_blob)?;
        let signature = signing_key.sign(message);
        assert!(signing_key.verify(message, &signature).is_ok());
        Ok(())
    }

    #[test]
    fn test_ed25519_tor_ed25519v3_expanded_keys() -> Result<(), anyhow::Error> {
        let dalek_signing_key = SigningKey::generate(&mut OsRng);
        let dalek_expanded_key = ExpandedSecretKey::from(dalek_signing_key.as_bytes());
        let signing_key = TorEd25519SigningKey::from(dalek_signing_key);
        let expanded_key = signing_key.expanded_secret_key();
        assert_eq!(dalek_expanded_key.scalar, expanded_key.scalar);
        assert_eq!(dalek_expanded_key.hash_prefix, expanded_key.hash_prefix);
        Ok(())
    }

    #[test]
    fn test_self_generated_tor_ed25519v3_sign_verify() -> Result<(), anyhow::Error> {
        let message = b"This is my very secret message";
        let dalek_signing_key = SigningKey::generate(&mut OsRng);
        let signing_key = TorEd25519SigningKey::from(dalek_signing_key);
        let signature = signing_key.sign(message);
        assert!(signing_key.verify(message, &signature).is_ok());
        Ok(())
    }

    #[test]
    fn test_to_from_blob() -> Result<(), anyhow::Error> {
        let blob_in = "0H/jnBeWzMoU1MGNRQPnmd8JqlpTNS3UeTiDOMyPTGGXXpLd0KinCtQbcgz2fCYjbzfK3ElJ7x3zGCkB1fAtAA==";
        let signing_key = TorEd25519SigningKey::from_blob(blob_in)?;
        let blob_out = signing_key.to_blob();
        assert_eq!(blob_in, blob_out);

        Ok(())
    }

    #[test]
    fn test_blob_reduced() -> Result<(), anyhow::Error> {
        let blob_in = "0H/jnBeWzMoU1MGNRQPnmd8JqlpTNS3UeTiDOMyPTGGXXpLd0KinCtQbcgz2fCYjbzfK3ElJ7x3zGCkB1fAtAA==";
        let bytes = base64::decode(blob_in)?;
        let scalar_bytes: [u8; 32] = bytes[..32].try_into().unwrap();
        let scalar = Scalar::from_bytes_mod_order(scalar_bytes);
        let output = scalar.to_bytes();
        let scalar2 = Scalar::from_bytes_mod_order(output);
        let output2 = scalar2.to_bytes();

        assert_eq!(output, output2);

        Ok(())
    }

    #[test]
    fn test_serialize_service_id() -> Result<(), anyhow::Error> {
        let service_id =
            TorServiceId::from_str("vvqbbaknxi6w44t6rplzh7nmesfzw3rjujdijpqsu5xl3nhlkdscgqad")?;
        let expected = "\"vvqbbaknxi6w44t6rplzh7nmesfzw3rjujdijpqsu5xl3nhlkdscgqad\"";
        let json_out = serde_json::to_string(&service_id)?;
        assert_eq!(expected, json_out);
        let deserialized_service_id: TorServiceId = serde_json::from_str(&json_out)?;
        assert_eq!(service_id, deserialized_service_id);
        Ok(())
    }

    #[test]
    fn test_ed25519_signing_key_to_tor_signing_key() -> Result<(), Box<dyn std::error::Error>> {
        let mut csprng = OsRng;
        let signing_key: SigningKey = SigningKey::generate(&mut csprng);
        let tor_signing_key: TorEd25519SigningKey = signing_key.clone().into();

        assert_eq!(signing_key.verifying_key(), tor_signing_key.verifying_key());

        Ok(())
    }
}
