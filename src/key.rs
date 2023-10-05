use crate::base64;
use base32::{self, Alphabet};
use curve25519_dalek::{scalar::clamp_integer, Scalar};
use ed25519_dalek::{
    hazmat::{raw_sign, ExpandedSecretKey},
    Signature, SignatureError, Signer, SigningKey as DalekSigningKey, Verifier, VerifyingKey,
};
use sha2::Sha512;
use sha3::{Digest, Sha3_256};

/// Trait to convert a key into a Tor blob
pub trait Blobify {
    fn to_blob(&self) -> String;
}

const TOR_VERSION: u8 = 3;

pub struct TorServiceId {
    verifying_key: VerifyingKey,
    service_id: String,
}

/// Generate the Tor service ID from a verifying key
/// From section 6 of rend-spec-v3.txt
impl std::convert::From<VerifyingKey> for TorServiceId {
    fn from(verifying_key: VerifyingKey) -> Self {
        // Version number
        let version = &[TOR_VERSION];

        // Hash the verifying key concatenated with the checksum and the version
        let verifying_key_bytes = verifying_key.as_bytes().to_vec();
        let checksum = TorServiceId::calculate_checksum(&verifying_key_bytes);

        // Base32 the verifying key concatenated with the checksum and the version
        let mut onion_bytes = verifying_key_bytes;
        onion_bytes.extend_from_slice(&checksum);
        onion_bytes.extend_from_slice(version);

        Self {
            verifying_key,
            service_id: base32::encode(Alphabet::RFC4648 { padding: false }, &onion_bytes)
                .to_lowercase(),
        }
    }
}

pub struct ParseServiceIDError(String);

impl std::str::FromStr for TorServiceId {
    type Err = ParseServiceIDError;

    fn from_str(service_id: &str) -> Result<Self, Self::Err> {
        let onion_bytes = match base32::decode(Alphabet::RFC4648 { padding: false }, service_id) {
            Some(bytes) => bytes,
            None => {
                return Err(ParseServiceIDError(
                    "Error base32 decoding service ID".to_string(),
                ))
            }
        };
        let mut verifying_key_bytes = [0u8; 32];
        verifying_key_bytes.copy_from_slice(&onion_bytes[..32]);
        let verifying_key = match VerifyingKey::from_bytes(&verifying_key_bytes) {
            Ok(key) => key,
            Err(_) => {
                return Err(ParseServiceIDError(
                    "Error parsing verifying key from bytes".to_string(),
                ))
            }
        };
        let mut checksum = [0u8; 2];
        checksum.copy_from_slice(&onion_bytes[32..34]);
        let verifying_checksum = Self::calculate_checksum(&verifying_key_bytes);
        if checksum != verifying_checksum {
            return Err(ParseServiceIDError("Invalid checksum".to_string()));
        }

        Ok(Self {
            verifying_key,
            service_id: service_id.to_string(),
        })
    }
}

impl TorServiceId {
    fn calculate_checksum(verifying_key_bytes: &[u8]) -> [u8; 2] {
        let mut checksum_bytes = ".onion checksum".as_bytes().to_vec();
        checksum_bytes.extend_from_slice(&verifying_key_bytes);
        checksum_bytes.extend_from_slice(&[TOR_VERSION]);
        let mut checksum = [0u8; 2];
        checksum
            .copy_from_slice(&Sha3_256::default().chain_update(&checksum_bytes).finalize()[..2]);

        checksum
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.verifying_key
    }

    pub fn as_str(&self) -> &str {
        &self.service_id
    }
}

// It sucks to have to have a separate type for the ED25519 key returned by Tor, but
// because of the fact that they don't return the original secret key, but instead return
// the scalar and hash prefix, we can't retrieve the secret key from them, so we can't turn
// this into a Dalek SigningKey. We can, however, retrieve the ExpandedSecretKey and from that the
// VerifyingKey, which is enough to allow us to sign and verify.

/// Ed25519 Signing key returned by Tor
pub struct TorEd25519SigningKey {
    pub tor_scalar: [u8; 32],
    pub hash_prefix: [u8; 32],
    pub expanded_secret_key: ExpandedSecretKey,
    pub verifying_key: VerifyingKey,
}

impl TorEd25519SigningKey {
    /// Return the ED25519 scalar
    pub fn scalar(&self) -> Scalar {
        Scalar::from_bytes_mod_order(self.tor_scalar)
    }

    /// Create the signing key from the key blob returned by the `ADD_ONION` call
    /// (see https://github.com/torproject/torspec/blob/main/control-spec.txt#L1862-L1864)
    pub fn from_blob(blob: &str) -> Self {
        // Decode the blob and turn it into the Dalek ExpandedSecretKey
        let blob = base64::decode(blob).unwrap();
        let expanded_secret_key = ExpandedSecretKey::from_bytes(&blob.clone().try_into().unwrap());

        // Extract the VerifyingKey from the ExpandedSecretKey
        let verifying_key = VerifyingKey::from(&expanded_secret_key);

        // Extract the tor scalar and hash prefix from the blob data
        let mut tor_scalar: [u8; 32] = [0u8; 32];
        tor_scalar.copy_from_slice(&blob[..32]);
        let mut hash_prefix: [u8; 32] = [0u8; 32];
        hash_prefix.copy_from_slice(&blob[32..]);

        Self {
            tor_scalar,
            hash_prefix,
            expanded_secret_key,
            verifying_key,
        }
    }

    /// Verify a message against a signature
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        self.verifying_key.verify(message, signature)
    }
}

/// Convert the Tor key to a blob
impl Blobify for TorEd25519SigningKey {
    fn to_blob(&self) -> String {
        base64::encode(&[self.tor_scalar, self.hash_prefix].concat())
    }
}

/// Implement signing for the Tor key
impl Signer<Signature> for TorEd25519SigningKey {
    fn try_sign(&self, message: &[u8]) -> Result<Signature, SignatureError> {
        Ok(raw_sign::<Sha512>(
            &self.expanded_secret_key,
            message,
            &self.verifying_key,
        ))
    }
}

impl Blobify for DalekSigningKey {
    /// Convert a Dalek key to a blob to be used as the key for an Onion Service
    fn to_blob(&self) -> String {
        // Hash the secret key
        let hash = Sha512::default().chain_update(self.to_bytes()).finalize();

        // Generate the scalar and the hash prefix from the hash
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&hash);
        let mut hash_prefix = [0u8; 32];
        hash_prefix.copy_from_slice(&hash[32..]);

        // Note: We don't do the mod multiplication for tor, just the clamping
        scalar = clamp_integer(scalar);
        base64::encode(&[scalar, hash_prefix].concat())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Signing key is (base64) 0H/jnBeWzMoU1MGNRQPnmd8JqlpTNS3UeTiDOMyPTGGXXpLd0KinCtQbcgz2fCYjbzfK3ElJ7x3zGCkB1fAtAA==
    // Service id is vvqbbaknxi6w44t6rplzh7nmesfzw3rjujdijpqsu5xl3nhlkdscgqad
    #[test]
    fn test_ed25519v3_service_id() -> Result<(), anyhow::Error> {
        let base64_blob = "0H/jnBeWzMoU1MGNRQPnmd8JqlpTNS3UeTiDOMyPTGGXXpLd0KinCtQbcgz2fCYjbzfK3ElJ7x3zGCkB1fAtAA==";
        let signing_key = TorEd25519SigningKey::from_blob(base64_blob);
        let public_key = signing_key.verifying_key;
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
        println!(
            "blob_in = {}",
            hex::encode(base64::decode(blob_in).unwrap())
        );
        let signing_key = TorEd25519SigningKey::from_blob(blob_in);
        let blob_out = signing_key.to_blob();
        println!(
            "blob_out = {}",
            hex::encode(base64::decode(&blob_out).unwrap())
        );
        assert_eq!(blob_in, blob_out);

        Ok(())
    }
}
