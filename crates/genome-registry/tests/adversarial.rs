//! Adversarial coverage for the genome-registry trust boundary.
//!
//! Each finding from the 2026-05-10 audit gets a proving test that
//! would have FAILED on the pre-fix codebase. Tests are organised by
//! attack surface so future regressions are obvious from the test
//! name.

use wafrift_genome_registry::{
    Genome, GenomeBundle, RegistryError, SignedBundle, SigningKey, TrustList,
};

fn fixture_signed() -> (SigningKey, SignedBundle) {
    let key = SigningKey::generate();
    let bundle = GenomeBundle::new(
        "p",
        vec![
            Genome::new("akamai-1", "raw"),
            Genome::new("cf-2", "more"),
        ],
    );
    let signed = bundle.sign(&key).expect("sign");
    (key, signed)
}

// ── DoS: oversize JSON envelope (CRITICAL #2 in audit) ──────────────

#[test]
fn from_json_rejects_input_above_size_cap() {
    let huge = format!(
        "{{\"bundle\":{{\"bundle_name\":\"x\",\"genomes\":[],\"created_unix\":1}},\"signature_hex\":\"{}\",\"public_key_hex\":\"{}\"}}",
        "0".repeat(128),
        "0".repeat(64),
    );
    let mut padded = huge.clone();
    while padded.len() < 60 * 1024 * 1024 {
        padded.push_str(&"x".repeat(1024));
    }
    let err = SignedBundle::from_json(&padded).unwrap_err();
    assert!(
        matches!(err, RegistryError::BundleTooLarge { .. }),
        "expected BundleTooLarge, got {err:?}"
    );
}

// ── DoS: oversize string field ──────────────────────────────────────

#[test]
fn validate_limits_rejects_oversize_payload() {
    let mut bundle = GenomeBundle::new(
        "p",
        vec![Genome::new(
            "g",
            "x".repeat(2 * 1024 * 1024), // 2 MB
        )],
    );
    bundle.created_unix = 0;
    let key = SigningKey::generate();
    let signed = bundle.sign(&key).unwrap();
    let err = signed.validate_limits().unwrap_err();
    assert!(
        matches!(
            err,
            RegistryError::FieldTooLong {
                field: "genome.payload",
                ..
            }
        ),
        "expected FieldTooLong on genome.payload, got {err:?}"
    );
}

#[test]
fn validate_limits_rejects_oversize_genome_name() {
    let mut bundle = GenomeBundle::new(
        "p",
        vec![Genome::new("n".repeat(257), "tiny payload")],
    );
    bundle.created_unix = 0;
    let key = SigningKey::generate();
    let signed = bundle.sign(&key).unwrap();
    let err = signed.validate_limits().unwrap_err();
    assert!(
        matches!(err, RegistryError::FieldTooLong { field: "genome.name", .. }),
        "expected FieldTooLong on genome.name, got {err:?}"
    );
}

#[test]
fn validate_limits_rejects_oversize_bundle_name() {
    let mut bundle = GenomeBundle::new("a".repeat(257), vec![Genome::new("g", "p")]);
    bundle.created_unix = 0;
    let key = SigningKey::generate();
    let signed = bundle.sign(&key).unwrap();
    let err = signed.validate_limits().unwrap_err();
    assert!(
        matches!(err, RegistryError::FieldTooLong { field: "bundle_name", .. }),
        "expected FieldTooLong on bundle_name, got {err:?}"
    );
}

#[test]
fn validate_limits_rejects_oversize_description() {
    let mut g = Genome::new("g", "p");
    g.description = "d".repeat(4097);
    let mut bundle = GenomeBundle::new("p", vec![g]);
    bundle.created_unix = 0;
    let key = SigningKey::generate();
    let signed = bundle.sign(&key).unwrap();
    let err = signed.validate_limits().unwrap_err();
    assert!(
        matches!(err, RegistryError::FieldTooLong { field: "genome.description", .. }),
        "expected FieldTooLong on genome.description, got {err:?}"
    );
}

#[test]
fn validate_limits_rejects_too_many_genomes() {
    let many: Vec<Genome> = (0..10_001)
        .map(|i| Genome::new(format!("g{i}"), "p"))
        .collect();
    let mut bundle = GenomeBundle::new("p", many);
    bundle.created_unix = 0;
    let key = SigningKey::generate();
    let signed = bundle.sign(&key).unwrap();
    let err = signed.validate_limits().unwrap_err();
    assert!(
        matches!(err, RegistryError::TooManyGenomes { .. }),
        "expected TooManyGenomes, got {err:?}"
    );
}

#[test]
fn validate_limits_rejects_too_many_targets() {
    let mut g = Genome::new("g", "p");
    g.targets = (0..101).map(|i| format!("waf{i}")).collect();
    let mut bundle = GenomeBundle::new("p", vec![g]);
    bundle.created_unix = 0;
    let key = SigningKey::generate();
    let signed = bundle.sign(&key).unwrap();
    let err = signed.validate_limits().unwrap_err();
    assert!(
        matches!(err, RegistryError::TooManyTargets { .. }),
        "expected TooManyTargets, got {err:?}"
    );
}

#[test]
fn validate_limits_rejects_oversize_target_tag() {
    let mut g = Genome::new("g", "p");
    g.targets = vec!["t".repeat(65)];
    let mut bundle = GenomeBundle::new("p", vec![g]);
    bundle.created_unix = 0;
    let key = SigningKey::generate();
    let signed = bundle.sign(&key).unwrap();
    let err = signed.validate_limits().unwrap_err();
    assert!(
        matches!(err, RegistryError::FieldTooLong { field: "genome.targets[]", .. }),
        "expected FieldTooLong on targets[], got {err:?}"
    );
}

// ── Determinism: duplicate names must canonicalise stably (HIGH #3) ──

#[test]
fn canonical_bytes_stable_under_duplicate_genome_names() {
    let key = SigningKey::generate();

    let bundle_a = GenomeBundle::new(
        "p",
        vec![
            Genome::new("dup", "payload_x"),
            Genome::new("dup", "payload_y"),
        ],
    );
    let mut bundle_b = GenomeBundle::new(
        "p",
        vec![
            Genome::new("dup", "payload_y"),
            Genome::new("dup", "payload_x"),
        ],
    );
    bundle_b.created_unix = bundle_a.created_unix;

    let sig_a = bundle_a.sign(&key).unwrap();
    let sig_b = bundle_b.sign(&key).unwrap();
    assert_eq!(
        sig_a.signature_hex, sig_b.signature_hex,
        "duplicate-name canonical bytes must be deterministic"
    );
}

// ── Strict schema: unknown fields rejected (HIGH #4) ────────────────

#[test]
fn from_json_rejects_unknown_field_in_bundle() {
    let (_, signed) = fixture_signed();
    let mut wire: serde_json::Value = serde_json::from_str(&signed.to_json().unwrap()).unwrap();
    wire["bundle"]["evil_extra"] = serde_json::json!("payload");
    let mutated = wire.to_string();
    let err = SignedBundle::from_json(&mutated).unwrap_err();
    assert!(
        matches!(err, RegistryError::DeserializationFailed(_)),
        "expected DeserializationFailed for unknown field, got {err:?}"
    );
}

#[test]
fn from_json_rejects_unknown_field_in_genome() {
    let (_, signed) = fixture_signed();
    let mut wire: serde_json::Value = serde_json::from_str(&signed.to_json().unwrap()).unwrap();
    wire["bundle"]["genomes"][0]["evil_extra"] = serde_json::json!("payload");
    let mutated = wire.to_string();
    let err = SignedBundle::from_json(&mutated).unwrap_err();
    assert!(
        matches!(err, RegistryError::DeserializationFailed(_)),
        "expected DeserializationFailed for unknown field on Genome, got {err:?}"
    );
}

#[test]
fn from_json_rejects_unknown_field_at_top_level() {
    let (_, signed) = fixture_signed();
    let mut wire: serde_json::Value = serde_json::from_str(&signed.to_json().unwrap()).unwrap();
    wire["evil_top_level"] = serde_json::json!("payload");
    let mutated = wire.to_string();
    let err = SignedBundle::from_json(&mutated).unwrap_err();
    assert!(
        matches!(err, RegistryError::DeserializationFailed(_)),
        "expected DeserializationFailed for unknown top-level field, got {err:?}"
    );
}

// ── Tamper detection: byte-level integrity ──────────────────────────

#[test]
fn from_json_then_verify_rejects_one_bit_payload_flip() {
    let (key, signed) = fixture_signed();
    let mut trust = TrustList::default();
    trust.allow_hex(&key.verifying_key_hex(), "alice");

    let json = signed.to_json().unwrap();
    let parsed = SignedBundle::from_json(&json).unwrap();
    parsed.verify(&trust).expect("baseline verify");

    // Now flip one byte in the canonical payload via parse-mutate-reserialize.
    let mut mutated = signed.clone();
    mutated.bundle.genomes[0].payload =
        format!("{}!", mutated.bundle.genomes[0].payload);
    let mut trust2 = TrustList::default();
    trust2.allow_hex(&key.verifying_key_hex(), "alice");
    assert!(
        matches!(
            mutated.verify(&trust2).unwrap_err(),
            RegistryError::SignatureInvalid
        ),
        "tampered payload must not verify"
    );
}

// ── Trust list: revocation is honoured ──────────────────────────────

#[test]
fn revoked_publisher_no_longer_verifies() {
    let (key, signed) = fixture_signed();
    let mut trust = TrustList::default();
    trust.allow_hex(&key.verifying_key_hex(), "alice");
    let _verified = signed.clone().verify(&trust).expect("baseline");

    trust.revoke_hex(&key.verifying_key_hex());
    let err = signed.verify(&trust).unwrap_err();
    assert!(
        matches!(err, RegistryError::UntrustedPublisher { .. }),
        "revoked publisher must produce UntrustedPublisher, got {err:?}"
    );
}

// ── Happy paths still work — make sure the bounds didn't break them ──

#[test]
fn from_json_accepts_a_normal_bundle() {
    let (key, signed) = fixture_signed();
    let json = signed.to_json().unwrap();
    let parsed = SignedBundle::from_json(&json).expect("parse normal bundle");
    let mut trust = TrustList::default();
    trust.allow_hex(&key.verifying_key_hex(), "alice");
    parsed.verify(&trust).expect("verify normal bundle");
}

#[test]
fn validate_limits_accepts_bundle_at_each_boundary() {
    // genome name exactly at limit (256 chars), payload at limit (1MB),
    // 100 targets each 64 chars.
    let mut g = Genome::new("n".repeat(256), "x".repeat(1024 * 1024));
    g.description = "d".repeat(4096);
    g.targets = (0..100).map(|_| "t".repeat(64)).collect();
    let mut bundle = GenomeBundle::new("a".repeat(256), vec![g]);
    bundle.created_unix = 0;
    let key = SigningKey::generate();
    let signed = bundle.sign(&key).unwrap();
    signed.validate_limits().expect("at-limit must pass");
}
