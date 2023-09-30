use crate::base64;
use base32::{self, Alphabet};
use curve25519_dalek::{scalar::clamp_integer, Scalar};
use ed25519_dalek::{hazmat::ExpandedSecretKey, SigningKey as DalekSigningKey, VerifyingKey};
use sha2::Sha512;
use sha3::{Digest, Sha3_256};

pub struct TorEd25519SigningKey {
    pub scalar: Scalar,
    pub hash_prefix: [u8; 32],
    pub verifying_key: VerifyingKey,
}

impl TorEd25519SigningKey {
    pub fn from_blob(blob: &str) -> Self {
        let blob = base64::decode(blob).unwrap();
        let expanded_secret_key = ExpandedSecretKey::from_bytes(&blob.clone().try_into().unwrap());
        let verifying_key = VerifyingKey::from(&expanded_secret_key);
        let mut tor_scalar: [u8; 32] = [0u8; 32];
        tor_scalar.copy_from_slice(&blob[..32]);
        let scalar = Scalar::from_bytes_mod_order(tor_scalar);
        let mut hash_prefix: [u8; 32] = [0u8; 32];
        hash_prefix.copy_from_slice(&blob[32..]);

        Self {
            scalar,
            hash_prefix,
            verifying_key,
        }
    }
}

pub fn blobify(signing_key: &DalekSigningKey) -> String {
    let hash = Sha512::default()
        .chain_update(signing_key.to_bytes())
        .finalize();
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&hash);
    let mut hash_prefix = [0u8; 32];
    hash_prefix.copy_from_slice(&hash[32..]);
    scalar = clamp_integer(scalar);
    base64::encode(&[scalar, hash_prefix].concat())
}

pub fn tor_service_id(verifying_key: &VerifyingKey) -> String {
    let version = &[3u8];
    let verifying_key_bytes = verifying_key.as_bytes().to_vec();
    let mut checksum_bytes = ".onion checksum".as_bytes().to_vec();
    checksum_bytes.extend_from_slice(&verifying_key_bytes);
    checksum_bytes.extend_from_slice(version);
    let mut hasher = Sha3_256::new();
    hasher.update(&checksum_bytes);
    let checksum: Vec<u8> = hasher.finalize()[..2].to_vec();
    let mut onion_bytes = verifying_key_bytes;
    onion_bytes.extend_from_slice(&checksum);
    onion_bytes.extend_from_slice(&[3u8]);
    base32::encode(Alphabet::RFC4648 { padding: false }, &onion_bytes).to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Private key is (base64) 0H/jnBeWzMoU1MGNRQPnmd8JqlpTNS3UeTiDOMyPTGGXXpLd0KinCtQbcgz2fCYjbzfK3ElJ7x3zGCkB1fAtAA==
    // Service id is vvqbbaknxi6w44t6rplzh7nmesfzw3rjujdijpqsu5xl3nhlkdscgqad
    #[test]
    fn test_ed25519v3_service_id() -> Result<(), anyhow::Error> {
        let base64_blob = "0H/jnBeWzMoU1MGNRQPnmd8JqlpTNS3UeTiDOMyPTGGXXpLd0KinCtQbcgz2fCYjbzfK3ElJ7x3zGCkB1fAtAA==";
        let private_key = TorEd25519SigningKey::from_blob(base64_blob);
        let public_key = private_key.verifying_key;
        assert_eq!(
            "vvqbbaknxi6w44t6rplzh7nmesfzw3rjujdijpqsu5xl3nhlkdscgqad",
            tor_service_id(&public_key),
        );
        Ok(())
    }
}
