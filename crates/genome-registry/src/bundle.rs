//! Wire format for community-contributed evasion-genome bundles.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::signing::{RegistryError, SigningKey, sign_bytes, verify_bytes};
use crate::trust::TrustList;

/// One named evasion recipe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Genome {
    /// Stable, human-readable identifier — e.g. `akamai-bm-bypass-jul24`.
    pub name: String,
    /// Free-form recipe payload. The wafrift gene-bank already has
    /// its own structured shape; we treat it as opaque bytes here so
    /// the registry can transport future recipe formats without
    /// schema lock-step.
    pub payload: String,
    /// Optional short description shown on import.
    #[serde(default)]
    pub description: String,
    /// Optional list of WAFs the genome is known to bypass.
    #[serde(default)]
    pub targets: Vec<String>,
}

impl Genome {
    pub fn new(name: impl Into<String>, payload: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            payload: payload.into(),
            description: String::new(),
            targets: Vec::new(),
        }
    }
}

/// A named, ordered bundle of genomes ready to be signed and shared.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenomeBundle {
    pub bundle_name: String,
    pub genomes: Vec<Genome>,
    /// Unix-epoch seconds (set by [`Self::new`] to current time).
    pub created_unix: u64,
}

impl GenomeBundle {
    pub fn new(bundle_name: impl Into<String>, genomes: Vec<Genome>) -> Self {
        Self {
            bundle_name: bundle_name.into(),
            genomes,
            created_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Deterministic JSON for the inner bundle — sort genomes by name
    /// so two byte-equal bundles produce byte-equal signatures.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RegistryError> {
        let mut sorted = self.clone();
        sorted.genomes.sort_by(|a, b| a.name.cmp(&b.name));
        serde_json::to_vec(&sorted).map_err(RegistryError::SerializationFailed)
    }

    /// Sign this bundle, producing a [`SignedBundle`] ready to ship.
    pub fn sign(self, key: &SigningKey) -> Result<SignedBundle, RegistryError> {
        let bytes = self.canonical_bytes()?;
        let signature_hex = sign_bytes(key, &bytes);
        Ok(SignedBundle {
            bundle: self,
            signature_hex,
            public_key_hex: key.verifying_key_hex(),
        })
    }
}

/// Signed bundle — the wire payload distributed to consumers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBundle {
    pub bundle: GenomeBundle,
    pub signature_hex: String,
    pub public_key_hex: String,
}

impl SignedBundle {
    /// JSON-encode for transport.
    pub fn to_json(&self) -> Result<String, RegistryError> {
        serde_json::to_string_pretty(self).map_err(RegistryError::SerializationFailed)
    }

    /// Parse a signed bundle from JSON without verifying.
    pub fn from_json(s: &str) -> Result<Self, RegistryError> {
        serde_json::from_str(s).map_err(RegistryError::DeserializationFailed)
    }

    /// Verify the signature AND that the publishing key is in the
    /// trust list. Returns the inner bundle on success.
    pub fn verify(self, trust: &TrustList) -> Result<GenomeBundle, RegistryError> {
        let canonical = self.bundle.canonical_bytes()?;
        verify_bytes(&self.public_key_hex, &self.signature_hex, &canonical)?;
        if !trust.contains(&self.public_key_hex) {
            return Err(RegistryError::UntrustedPublisher {
                public_key_hex: self.public_key_hex,
            });
        }
        Ok(self.bundle)
    }

    /// Verify ONLY the signature (does NOT consult the trust list).
    /// Useful for diagnostic tooling that wants to know whether a
    /// bundle is internally consistent without forming a trust
    /// decision. Production load paths should use [`Self::verify`].
    pub fn verify_signature_only(&self) -> Result<(), RegistryError> {
        let canonical = self.bundle.canonical_bytes()?;
        verify_bytes(&self.public_key_hex, &self.signature_hex, &canonical)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn three_genomes() -> Vec<Genome> {
        vec![
            Genome::new("akamai-bypass-1", "raw bytes"),
            Genome::new("cf-bypass-2", "more raw bytes"),
            Genome::new("imperva-bypass-3", "yet more bytes"),
        ]
    }

    #[test]
    fn canonical_bytes_are_order_invariant() {
        let a = GenomeBundle::new("pack", three_genomes());
        let mut b = a.clone();
        b.genomes.reverse();
        let ba = a.canonical_bytes().unwrap();
        let bb = b.canonical_bytes().unwrap();
        assert_eq!(ba, bb, "reorder must not change canonical encoding");
    }

    #[test]
    fn sign_then_verify_signature_roundtrip() {
        let key = SigningKey::generate();
        let bundle = GenomeBundle::new("p", three_genomes());
        let signed = bundle.sign(&key).unwrap();
        signed.verify_signature_only().expect("signature valid");
    }

    #[test]
    fn json_roundtrip_preserves_bundle_and_signature() {
        let key = SigningKey::generate();
        let bundle = GenomeBundle::new("p", three_genomes());
        let signed = bundle.sign(&key).unwrap();
        let wire = signed.to_json().unwrap();
        let parsed = SignedBundle::from_json(&wire).unwrap();
        assert_eq!(parsed, signed);
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let key = SigningKey::generate();
        let bundle = GenomeBundle::new("p", three_genomes());
        let mut signed = bundle.sign(&key).unwrap();
        // Tamper a genome payload AFTER signing
        signed.bundle.genomes[0].payload = "TAMPERED".into();
        let err = signed.verify_signature_only().unwrap_err();
        assert!(matches!(err, RegistryError::SignatureInvalid));
    }

    #[test]
    fn verify_rejects_tampered_bundle_name() {
        let key = SigningKey::generate();
        let bundle = GenomeBundle::new("p", three_genomes());
        let mut signed = bundle.sign(&key).unwrap();
        signed.bundle.bundle_name = "evil".into();
        assert!(matches!(
            signed.verify_signature_only().unwrap_err(),
            RegistryError::SignatureInvalid
        ));
    }

    #[test]
    fn verify_with_trust_list_accepts_allowlisted_publisher() {
        let key = SigningKey::generate();
        let bundle = GenomeBundle::new("p", three_genomes());
        let signed = bundle.sign(&key).unwrap();

        let mut trust = TrustList::default();
        trust.allow_hex(&key.verifying_key_hex(), "alice");
        let inner = signed.verify(&trust).unwrap();
        assert_eq!(inner.bundle_name, "p");
    }

    #[test]
    fn verify_with_trust_list_rejects_unknown_publisher() {
        let key = SigningKey::generate();
        let bundle = GenomeBundle::new("p", three_genomes());
        let signed = bundle.sign(&key).unwrap();

        let trust = TrustList::default(); // empty
        let err = signed.verify(&trust).unwrap_err();
        assert!(matches!(err, RegistryError::UntrustedPublisher { .. }));
    }

    #[test]
    fn signature_invariant_under_genome_reorder() {
        // Two senders building the same bundle in different orders
        // must produce the SAME signature when canonicalised.
        let key = SigningKey::generate();
        let mut g = three_genomes();
        let bundle1 = GenomeBundle::new("p", g.clone());
        g.reverse();
        let mut bundle2 = GenomeBundle::new("p", g);
        bundle2.created_unix = bundle1.created_unix; // align timestamps for fairness

        let signed1 = bundle1.sign(&key).unwrap();
        let signed2 = bundle2.sign(&key).unwrap();
        assert_eq!(signed1.signature_hex, signed2.signature_hex);
    }
}
