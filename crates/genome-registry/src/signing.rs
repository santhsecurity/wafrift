//! ed25519 sign + verify primitives wrapped in a thin error-typed
//! API. The wrapper exists so consumers don't need to depend on
//! `ed25519-dalek` directly.

use ed25519_dalek::{Signature, SigningKey as Ed25519SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

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
    #[error("bundle JSON exceeds size cap ({bytes} > {limit} bytes)")]
    BundleTooLarge { bytes: usize, limit: usize },
    #[error("bundle has too many genomes ({count} > {limit})")]
    TooManyGenomes { count: usize, limit: usize },
    #[error("genome has too many target tags ({count} > {limit})")]
    TooManyTargets { count: usize, limit: usize },
    #[error("field `{field}` is too long ({len} > {limit} chars)")]
    FieldTooLong {
        field: &'static str,
        len: usize,
        limit: usize,
    },
    #[error(
        "bundle created_unix={created_unix} is older than max age \
         ({age_secs}s > {max_age_secs}s) — refusing replay of stale bundle"
    )]
    BundleTooOld {
        created_unix: u64,
        age_secs: u64,
        max_age_secs: u64,
    },
    #[error(
        "bundle created_unix={created_unix} is dated more than \
         {skew_secs}s in the future (system clock skew? rejecting)"
    )]
    BundleFutureDated { created_unix: u64, skew_secs: u64 },
}

/// ed25519 secret key wrapper.
///
/// Wraps the keypair so `sign()` can produce a signature and the
/// matching public key is recoverable via [`Self::verifying_key_hex`].
///
/// **Memory hygiene.** The hex-encoded secret is wiped on drop via
/// [`ZeroizeOnDrop`]. `Debug` is implemented manually to redact the
/// secret — the prior derive would have spilled the 32-byte key into
/// any tracing line, panic message, or `format!("{key:?}")` call.
///
/// `Deserialize` is implemented manually and routes through
/// [`Self::from_secret_hex`] so loading a key from JSON cannot produce
/// a `SigningKey` with malformed hex (which would panic later inside
/// `verifying_key_hex` / `sign_bytes` on the constructor-checked
/// unwraps). The derive would otherwise accept any string and arm a
/// panic-on-first-use bomb.
#[derive(Serialize, ZeroizeOnDrop)]
pub struct SigningKey {
    /// Hex-encoded 32-byte secret. NEVER log this.
    secret_hex: String,
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Pre-fix this used the derive, which printed the full secret_hex
        // into any log line that included a SigningKey. The fingerprint
        // (first 8 hex chars of the verifying key, NOT the secret) is
        // enough to disambiguate keys for an operator without ever
        // exposing the private material.
        let fingerprint = self.verifying_key_hex();
        let short = fingerprint.get(..8).unwrap_or("????????");
        f.debug_struct("SigningKey")
            .field("vk_fingerprint", &short)
            .field("secret_hex", &"<redacted>")
            .finish()
    }
}

impl<'de> Deserialize<'de> for SigningKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            secret_hex: String,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::from_secret_hex(&wire.secret_hex).map_err(serde::de::Error::custom)
    }
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
        let mut bytes = hex::decode(secret_hex).map_err(|e| RegistryError::HexDecode {
            context: "secret_hex".into(),
            source: e,
        })?;
        let mut arr: [u8; 32] = bytes.as_slice().try_into().expect("length checked above");
        // Validates the bytes are a usable scalar; the resulting key is
        // zeroized on Drop by dalek's own impl.
        let _ = Ed25519SigningKey::from_bytes(&arr);
        bytes.zeroize();
        arr.zeroize();
        Ok(Self {
            secret_hex: secret_hex.to_string(),
        })
    }

    /// Hex-encoded 32-byte verifying (public) key.
    #[must_use]
    pub fn verifying_key_hex(&self) -> VerifyingKeyHex {
        let mut bytes = hex::decode(&self.secret_hex).expect("constructor checked");
        let mut arr: [u8; 32] = bytes.as_slice().try_into().expect("constructor checked");
        let kp = Ed25519SigningKey::from_bytes(&arr);
        let out = hex::encode(kp.verifying_key().to_bytes());
        // Zero intermediate copies of the secret material so they don't
        // sit in the heap / stack until the OS reclaims them.
        // Ed25519SigningKey itself is ZeroizeOnDrop in dalek 2.x.
        bytes.zeroize();
        arr.zeroize();
        out
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
    let mut secret = hex::decode(key.secret_hex()).expect("constructor checked");
    let mut arr: [u8; 32] = secret.as_slice().try_into().expect("constructor checked");
    let kp = Ed25519SigningKey::from_bytes(&arr);
    let sig = ed25519_dalek::Signer::sign(&kp, bytes);
    let out = hex::encode(sig.to_bytes());
    // Wipe the intermediate secret-bearing buffers. dalek's SigningKey
    // is ZeroizeOnDrop so kp is handled when it falls out of scope.
    secret.zeroize();
    arr.zeroize();
    out
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
        assert!(matches!(
            err,
            RegistryError::InvalidHex { expected: 64, .. }
        ));
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
