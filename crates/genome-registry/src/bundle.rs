//! Wire format for community-contributed evasion-genome bundles.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::signing::{RegistryError, SigningKey, sign_bytes, verify_bytes};
use crate::trust::TrustList;

// Hard limits enforced at the trust boundary (`SignedBundle::from_json`)
// so a malicious feed can't OOM the registry.

/// Soft cap on accepted JSON envelope size. Larger inputs are rejected
/// before serde even sees them; the largest legitimate bundle we've
/// seen in the wild is ~120KB, so 50MB is generous.
pub const MAX_BUNDLE_JSON_BYTES: usize = 50 * 1024 * 1024;
/// Maximum genomes in a single bundle.
pub const MAX_GENOMES_PER_BUNDLE: usize = 10_000;
/// Maximum length of any genome / bundle name.
pub const MAX_NAME_LEN: usize = 256;
/// Maximum payload length per genome (recipes are usually <16KB).
pub const MAX_PAYLOAD_LEN: usize = 1024 * 1024;
/// Maximum description length.
pub const MAX_DESCRIPTION_LEN: usize = 4096;
/// Maximum number of WAF target tags per genome.
pub const MAX_TARGETS_PER_GENOME: usize = 100;
/// Maximum length per WAF target tag.
pub const MAX_TARGET_LEN: usize = 64;
/// Maximum hex string length for signature / public key (ed25519 = 64
/// bytes = 128 hex chars; allow a little slack for variant encodings).
pub const MAX_HEX_LEN: usize = 256;

/// One named evasion recipe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

    /// Deterministic JSON for the inner bundle.
    ///
    /// Sort key is `(name, payload, description, targets)` rather than
    /// `name` alone — two genomes with the same name but different
    /// payloads would otherwise preserve their input order and produce
    /// different canonical bytes (and therefore different signatures)
    /// for the same logical bundle.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RegistryError> {
        let mut sorted = self.clone();
        sorted.genomes.sort_by(|a, b| {
            (&a.name, &a.payload, &a.description, &a.targets).cmp(&(
                &b.name,
                &b.payload,
                &b.description,
                &b.targets,
            ))
        });
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
#[serde(deny_unknown_fields)]
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
    ///
    /// Bounded at the trust boundary against:
    /// - oversize input (`MAX_BUNDLE_JSON_BYTES`)
    /// - oversize fields (`MAX_NAME_LEN`, `MAX_PAYLOAD_LEN`,
    ///   `MAX_DESCRIPTION_LEN`, `MAX_TARGET_LEN`)
    /// - excessive cardinality (`MAX_GENOMES_PER_BUNDLE`,
    ///   `MAX_TARGETS_PER_GENOME`)
    /// - excessive hex (`MAX_HEX_LEN`) on signature / `public_key`
    /// - unknown fields (`#[serde(deny_unknown_fields)]`)
    ///
    /// All limits are conservative — legitimate bundles fit comfortably.
    /// A malicious feed that tries to OOM the registry hits the input
    /// cap *before* serde allocates any backing buffers.
    pub fn from_json(s: &str) -> Result<Self, RegistryError> {
        if s.len() > MAX_BUNDLE_JSON_BYTES {
            return Err(RegistryError::BundleTooLarge {
                bytes: s.len(),
                limit: MAX_BUNDLE_JSON_BYTES,
            });
        }
        let parsed: SignedBundle =
            serde_json::from_str(s).map_err(RegistryError::DeserializationFailed)?;
        parsed.validate_limits()?;
        Ok(parsed)
    }

    /// Enforce all post-deserialisation length / cardinality limits.
    /// Called automatically by [`Self::from_json`]; exposed so tests
    /// and library consumers that build a bundle by other means can
    /// run the same checks.
    pub fn validate_limits(&self) -> Result<(), RegistryError> {
        if self.signature_hex.len() > MAX_HEX_LEN {
            return Err(RegistryError::FieldTooLong {
                field: "signature_hex",
                len: self.signature_hex.len(),
                limit: MAX_HEX_LEN,
            });
        }
        if self.public_key_hex.len() > MAX_HEX_LEN {
            return Err(RegistryError::FieldTooLong {
                field: "public_key_hex",
                len: self.public_key_hex.len(),
                limit: MAX_HEX_LEN,
            });
        }
        if self.bundle.bundle_name.len() > MAX_NAME_LEN {
            return Err(RegistryError::FieldTooLong {
                field: "bundle_name",
                len: self.bundle.bundle_name.len(),
                limit: MAX_NAME_LEN,
            });
        }
        if self.bundle.genomes.len() > MAX_GENOMES_PER_BUNDLE {
            return Err(RegistryError::TooManyGenomes {
                count: self.bundle.genomes.len(),
                limit: MAX_GENOMES_PER_BUNDLE,
            });
        }
        for g in &self.bundle.genomes {
            if g.name.len() > MAX_NAME_LEN {
                return Err(RegistryError::FieldTooLong {
                    field: "genome.name",
                    len: g.name.len(),
                    limit: MAX_NAME_LEN,
                });
            }
            if g.payload.len() > MAX_PAYLOAD_LEN {
                return Err(RegistryError::FieldTooLong {
                    field: "genome.payload",
                    len: g.payload.len(),
                    limit: MAX_PAYLOAD_LEN,
                });
            }
            if g.description.len() > MAX_DESCRIPTION_LEN {
                return Err(RegistryError::FieldTooLong {
                    field: "genome.description",
                    len: g.description.len(),
                    limit: MAX_DESCRIPTION_LEN,
                });
            }
            if g.targets.len() > MAX_TARGETS_PER_GENOME {
                return Err(RegistryError::TooManyTargets {
                    count: g.targets.len(),
                    limit: MAX_TARGETS_PER_GENOME,
                });
            }
            for t in &g.targets {
                if t.len() > MAX_TARGET_LEN {
                    return Err(RegistryError::FieldTooLong {
                        field: "genome.targets[]",
                        len: t.len(),
                        limit: MAX_TARGET_LEN,
                    });
                }
            }
        }
        Ok(())
    }

    /// Verify the signature AND that the publishing key is in the
    /// trust list. Returns the inner bundle on success.
    ///
    /// **Does NOT check `created_unix` freshness.** A captured
    /// bundle signed by a still-trusted key replays forever.
    /// Production import paths SHOULD prefer [`Self::verify_fresh`]
    /// which adds an upper bound on bundle age + clock-skew guard.
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

    /// Verify signature + trust + freshness window.
    ///
    /// Rejects bundles older than `max_age_secs` (replay defence —
    /// a captured bundle from a key that has since been revoked
    /// cannot be re-imported indefinitely) AND bundles dated more
    /// than `future_skew_secs` ahead of the local clock (defends
    /// against a publisher with a wildly-wrong clock or a forged
    /// future-dated timestamp).
    ///
    /// Suggested defaults: `max_age_secs = 30 * 86_400` (30 days),
    /// `future_skew_secs = 300` (5 minutes).
    pub fn verify_fresh(
        self,
        trust: &TrustList,
        max_age_secs: u64,
        future_skew_secs: u64,
    ) -> Result<GenomeBundle, RegistryError> {
        // Signature + trust first — never reveal anything about
        // freshness for unsigned / untrusted input.
        let bundle = self.verify(trust)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if bundle.created_unix > now.saturating_add(future_skew_secs) {
            return Err(RegistryError::BundleFutureDated {
                created_unix: bundle.created_unix,
                skew_secs: future_skew_secs,
            });
        }
        let age = now.saturating_sub(bundle.created_unix);
        if age > max_age_secs {
            return Err(RegistryError::BundleTooOld {
                created_unix: bundle.created_unix,
                age_secs: age,
                max_age_secs,
            });
        }
        Ok(bundle)
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

    // ── verify_fresh: replay-defence + clock-skew ────────────

    fn now_unix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn trust_with(key: &SigningKey) -> TrustList {
        let mut t = TrustList::default();
        t.allow_hex(&key.verifying_key_hex(), "test");
        t
    }

    #[test]
    fn verify_fresh_accepts_recent_bundle() {
        let key = SigningKey::generate();
        let bundle = GenomeBundle::new("pack", three_genomes());
        let signed = bundle.sign(&key).unwrap();
        let trust = trust_with(&key);
        // 30-day window, recent bundle — Ok.
        assert!(
            signed.verify_fresh(&trust, 30 * 86_400, 300).is_ok(),
            "fresh bundle within window must verify"
        );
    }

    #[test]
    fn verify_fresh_rejects_too_old_bundle() {
        let key = SigningKey::generate();
        let mut bundle = GenomeBundle::new("pack", three_genomes());
        // Date the bundle 60 days ago.
        bundle.created_unix = now_unix().saturating_sub(60 * 86_400);
        let signed = bundle.sign(&key).unwrap();
        let trust = trust_with(&key);
        // 30-day window — must reject.
        let err = signed
            .verify_fresh(&trust, 30 * 86_400, 300)
            .expect_err("60-day-old bundle must not verify with 30-day window");
        assert!(matches!(err, RegistryError::BundleTooOld { .. }));
    }

    #[test]
    fn verify_fresh_rejects_far_future_bundle() {
        let key = SigningKey::generate();
        let mut bundle = GenomeBundle::new("pack", three_genomes());
        // Date the bundle 1 hour in the future — well past the 5-min
        // skew tolerance.
        bundle.created_unix = now_unix().saturating_add(3600);
        let signed = bundle.sign(&key).unwrap();
        let trust = trust_with(&key);
        let err = signed
            .verify_fresh(&trust, 30 * 86_400, 300)
            .expect_err("future-dated bundle must not verify");
        assert!(matches!(err, RegistryError::BundleFutureDated { .. }));
    }

    #[test]
    fn verify_fresh_tolerates_small_clock_skew() {
        let key = SigningKey::generate();
        let mut bundle = GenomeBundle::new("pack", three_genomes());
        // 30 seconds in the future — within the 300s skew window.
        bundle.created_unix = now_unix().saturating_add(30);
        let signed = bundle.sign(&key).unwrap();
        let trust = trust_with(&key);
        assert!(signed.verify_fresh(&trust, 30 * 86_400, 300).is_ok());
    }

    #[test]
    fn verify_fresh_still_rejects_untrusted_publisher() {
        // Freshness check must NOT bypass the trust-list check.
        let key = SigningKey::generate();
        let bundle = GenomeBundle::new("pack", three_genomes());
        let signed = bundle.sign(&key).unwrap();
        let empty_trust = TrustList::new(); // key not added
        let err = signed
            .verify_fresh(&empty_trust, 30 * 86_400, 300)
            .expect_err("untrusted publisher must reject");
        assert!(matches!(err, RegistryError::UntrustedPublisher { .. }));
    }
}
