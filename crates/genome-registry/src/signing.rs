//! ed25519 sign + verify primitives wrapped in a thin error-typed
//! API. The wrapper exists so consumers don't need to depend on
//! `ed25519-dalek` directly.

use ed25519_dalek::{
    Signature, SigningKey as Ed25519SigningKey, Verifier, VerifyingKey,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Hex-encoded verifying (public) key. 64 hex chars.
pub type VerifyingKeyHex = String;

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("serde_json serialise failed: {0}")]
    SerializationFailed(serde_json::Error),
    #[error("serde_json deserialise failed: {0}")]
    DeserializationFailed(serde_json::Error),
    #[error("ed25519 signature verification failed")]
    SignatureInvalid,
    #[error("publisher key not in trust list: {public_key_hex}")]
    UntrustedPublisher { public_key_hex: VerifyingKeyHex },
    #[error("invalid hex (expected {expected} chars, got {got}): {context}")]
    InvalidHex {
        expected: usize,
        got: usize,
        context: String,
    },
    #[error("malformed hex digit in {context}: {source}")]
    HexDecode {
        context: String,
        #[source]
        source: hex::FromHexError,
    },
    #[error("trust-list TOML parse failed: {0}")]
    TrustListParse(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// ed25519 secret key wrapper.
///
/// Wraps the keypair so `sign()` can produce a signature and the
/// matching public key is recoverable via [`Self::verifying_key_hex`].
#[derive(Debug, Serialize, Deserialize)]
pub struct SigningKey {
    /// Hex-encoded 32-byte secret. NEVER log this.
    secret_hex: String,
}

impl SigningKey {
    /// Generate a fresh keypair from the OS RNG.
    #[must_use]
    pub fn generate() -> Self {
        let kp = Ed25519SigningKey::generate(&mut OsRng);
        Self {
            secret_hex: hex::encode(kp.to_bytes()),
        }
    }

    /// Reconstruct from a hex-encoded 32-byte secret.
    pub fn from_secret_hex(secret_hex: &str) -> Result<Self, RegistryError> {
        if secret_hex.len() != 64 {
            return Err(RegistryError::InvalidHex {
                expected: 64,
                got: secret_hex.len(),
                context: "secret_hex".into(),
            });
        }
        let bytes = hex::decode(secret_hex).map_err(|e| RegistryError::HexDecode {
            context: "secret_hex".into(),
            source: e,
        })?;
        let arr: [u8; 32] = bytes
            .try_into()
            .expect("length checked above");
        let _ = Ed25519SigningKey::from_bytes(&arr);
        Ok(Self {
            secret_hex: secret_hex.to_string(),
        })
    }

    /// Hex-encoded 32-byte verifying (public) key.
    #[must_use]
    pub fn verifying_key_hex(&self) -> VerifyingKeyHex {
        let bytes = hex::decode(&self.secret_hex).expect("constructor checked");
        let arr: [u8; 32] = bytes.try_into().expect("constructor checked");
        let kp = Ed25519SigningKey::from_bytes(&arr);
        hex::encode(kp.verifying_key().to_bytes())
    }

    /// Hex-encoded 32-byte secret. Exposed for export to a key file
    /// or environment variable; treat as sensitive.
    #[must_use]
    pub fn secret_hex(&self) -> &str {
        &self.secret_hex
    }
}

/// Sign `bytes` with `key`, returning the hex-encoded 64-byte
/// signature.
pub fn sign_bytes(key: &SigningKey, bytes: &[u8]) -> String {
    let secret = hex::decode(key.secret_hex()).expect("constructor checked");
    let arr: [u8; 32] = secret.try_into().expect("constructor checked");
    let kp = Ed25519SigningKey::from_bytes(&arr);
    let sig = ed25519_dalek::Signer::sign(&kp, bytes);
    hex::encode(sig.to_bytes())
}

/// Verify `signature_hex` over `bytes` against `public_key_hex`.
pub fn verify_bytes(
    public_key_hex: &str,
    signature_hex: &str,
    bytes: &[u8],
) -> Result<(), RegistryError> {
    if public_key_hex.len() != 64 {
        return Err(RegistryError::InvalidHex {
            expected: 64,
            got: public_key_hex.len(),
            context: "public_key_hex".into(),
        });
    }
    if signature_hex.len() != 128 {
        return Err(RegistryError::InvalidHex {
            expected: 128,
            got: signature_hex.len(),
            context: "signature_hex".into(),
        });
    }
    let pk_bytes = hex::decode(public_key_hex).map_err(|e| RegistryError::HexDecode {
        context: "public_key_hex".into(),
        source: e,
    })?;
    let sig_bytes = hex::decode(signature_hex).map_err(|e| RegistryError::HexDecode {
        context: "signature_hex".into(),
        source: e,
    })?;
    let pk_arr: [u8; 32] = pk_bytes.try_into().expect("length checked above");
    let sig_arr: [u8; 64] = sig_bytes.try_into().expect("length checked above");
    let pk = VerifyingKey::from_bytes(&pk_arr).map_err(|_| RegistryError::SignatureInvalid)?;
    let sig = Signature::from_bytes(&sig_arr);
    pk.verify(bytes, &sig)
        .map_err(|_| RegistryError::SignatureInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_round_trip() {
        let key = SigningKey::generate();
        let pk = key.verifying_key_hex();
        let sig = sign_bytes(&key, b"hello world");
        verify_bytes(&pk, &sig, b"hello world").expect("verify");
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let key = SigningKey::generate();
        let sig = sign_bytes(&key, b"hello");
        let err = verify_bytes(&key.verifying_key_hex(), &sig, b"goodbye").unwrap_err();
        assert!(matches!(err, RegistryError::SignatureInvalid));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let k1 = SigningKey::generate();
        let k2 = SigningKey::generate();
        let sig = sign_bytes(&k1, b"hello");
        let err = verify_bytes(&k2.verifying_key_hex(), &sig, b"hello").unwrap_err();
        assert!(matches!(err, RegistryError::SignatureInvalid));
    }

    #[test]
    fn from_secret_hex_round_trip() {
        let k1 = SigningKey::generate();
        let secret = k1.secret_hex().to_string();
        let pk1 = k1.verifying_key_hex();
        let k2 = SigningKey::from_secret_hex(&secret).expect("reconstruct");
        assert_eq!(k2.verifying_key_hex(), pk1);
    }

    #[test]
    fn from_secret_hex_rejects_wrong_length() {
        let err = SigningKey::from_secret_hex("abc").unwrap_err();
        assert!(matches!(err, RegistryError::InvalidHex { expected: 64, .. }));
    }

    #[test]
    fn verify_rejects_bad_hex_length() {
        let key = SigningKey::generate();
        let pk = key.verifying_key_hex();
        let err = verify_bytes(&pk, "ABCDEF", b"x").unwrap_err();
        assert!(matches!(err, RegistryError::InvalidHex { .. }));
    }

    #[test]
    fn verify_rejects_non_hex_chars() {
        let key = SigningKey::generate();
        let pk = key.verifying_key_hex();
        let bogus = "Z".repeat(128);
        let err = verify_bytes(&pk, &bogus, b"x").unwrap_err();
        assert!(matches!(err, RegistryError::HexDecode { .. }));
    }
}
