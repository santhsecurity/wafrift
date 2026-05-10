//! Regression coverage for the 2026-05-10 genome-registry signing
//! audit finding:
//!   MEDIUM: SigningKey derived Deserialize, which accepted any string
//!     for `secret_hex` without validation. The constructor `from_secret_hex`
//!     validated length + hex shape, but a JSON-loaded SigningKey
//!     bypassed that check and armed a panic-on-first-use bomb inside
//!     `verifying_key_hex` and `sign_bytes` (both call
//!     `hex::decode().expect("constructor checked")`).
//!
//! Pre-fix this would have panicked the moment the loaded key was used.
//! Post-fix the manual Deserialize routes through from_secret_hex and
//! returns a clean serde error.

use wafrift_genome_registry::SigningKey;

#[test]
fn deserialize_rejects_short_secret_hex() {
    let bad = r#"{"secret_hex":"abc"}"#;
    let err = serde_json::from_str::<SigningKey>(bad)
        .expect_err("must reject 3-char secret_hex (not 64)");
    let msg = err.to_string();
    assert!(
        msg.contains("64") || msg.to_lowercase().contains("invalid"),
        "error must surface invalid-hex failure, got {msg}"
    );
}

#[test]
fn deserialize_rejects_non_hex_chars_in_secret() {
    let bad = format!(r#"{{"secret_hex":"{}"}}"#, "Z".repeat(64));
    let err = serde_json::from_str::<SigningKey>(&bad)
        .expect_err("must reject Z-only string (not hex)");
    let msg = err.to_string();
    assert!(
        msg.to_lowercase().contains("hex") || msg.to_lowercase().contains("invalid"),
        "error must surface hex-decode failure, got {msg}"
    );
}

#[test]
fn deserialize_accepts_valid_secret_hex_round_trip() {
    let original = SigningKey::generate();
    let json = serde_json::to_string(&original).expect("serialize");
    let restored: SigningKey =
        serde_json::from_str(&json).expect("valid generated key must deserialize");
    assert_eq!(
        restored.verifying_key_hex(),
        original.verifying_key_hex(),
        "round-trip must preserve identity"
    );
}

#[test]
fn deserialize_does_not_panic_on_first_use_after_bad_load() {
    // The whole point of the fix: pre-fix this would compile-and-panic
    // at the call to verifying_key_hex(). Post-fix the deserialize
    // returns Err and we never construct a usable SigningKey.
    let bad_inputs = [
        r#"{"secret_hex":""}"#,
        r#"{"secret_hex":"00"}"#,
        r#"{"secret_hex":"GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG"}"#,
        r#"{"secret_hex":"0000000000000000000000000000000000000000000000000000000000000000000"}"#,
    ];
    for input in &bad_inputs {
        let result = serde_json::from_str::<SigningKey>(input);
        assert!(
            result.is_err(),
            "bad input {input:?} must surface as Err, never produce a panic-armed SigningKey"
        );
    }
}
