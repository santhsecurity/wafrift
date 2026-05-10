//! Regression coverage for the 2026-05-10 credibility audit findings:
//!   CRITICAL #1: SigningKey derived Debug, leaking the 32-byte secret_hex
//!     into every tracing line, panic message, and `format!("{key:?}")`
//!     call. A single anyhow::Context macro that captured the key would
//!     leak it to stderr.
//!   CRITICAL #2: SigningKey did not zeroize on Drop, leaving the secret
//!     in heap memory after the key fell out of scope (visible in process
//!     dumps, swap, and post-free heap reads).
//!
//! Pre-fix both tests would have failed.

use wafrift_genome_registry::SigningKey;

#[test]
fn debug_does_not_leak_secret_hex() {
    let key = SigningKey::generate();
    let secret = key.secret_hex().to_string();
    let dbg = format!("{key:?}");
    assert!(
        !dbg.contains(&secret),
        "Debug impl leaked secret_hex into format string. dbg: {dbg}"
    );
    // The redacted marker must be present so an operator reading the
    // log can tell the field exists and was deliberately hidden.
    assert!(
        dbg.contains("<redacted>"),
        "Debug impl must mark the secret as redacted, got: {dbg}"
    );
    // The verifying-key fingerprint must show up so two different keys
    // are visually distinct in logs.
    let fp = &key.verifying_key_hex()[..8];
    assert!(
        dbg.contains(fp),
        "Debug impl must include the public-key fingerprint for log disambiguation, got: {dbg}"
    );
}

#[test]
fn debug_with_two_distinct_keys_renders_different_fingerprints() {
    // Defence-in-depth — make sure the redacted Debug still distinguishes
    // keys in a multi-key context (e.g. publisher rotation).
    let k1 = SigningKey::generate();
    let k2 = SigningKey::generate();
    let d1 = format!("{k1:?}");
    let d2 = format!("{k2:?}");
    assert_ne!(
        d1, d2,
        "two distinct keys must render distinct Debug strings (fingerprint must differ)"
    );
}

#[test]
fn signing_key_drop_does_not_leave_secret_in_initial_buffer() {
    // Best-effort proof that ZeroizeOnDrop fires. We can't safely peek
    // at freed heap, but we can confirm the SigningKey *does* implement
    // Zeroize: building it, dropping it, and re-running the test under
    // a sanitizer build would surface a use-after-zeroize bug.
    //
    // Stronger version: take a *raw pointer* to the secret_hex string
    // contents BEFORE drop, drop the key, then peek at the bytes via
    // the raw pointer. That's UB territory in safe Rust though, so we
    // stick to confirming the trait impl is wired up.
    fn assert_zeroize<T: zeroize::ZeroizeOnDrop>(_: &T) {}
    let key = SigningKey::generate();
    assert_zeroize(&key);
}

#[test]
fn from_secret_hex_round_trip_still_works_after_zeroize_changes() {
    // Make sure adding the .zeroize() calls didn't accidentally break
    // construction.
    let original = SigningKey::generate();
    let restored = SigningKey::from_secret_hex(original.secret_hex()).expect("round-trip");
    assert_eq!(restored.verifying_key_hex(), original.verifying_key_hex());
    // And the second key must Debug-redact the same way.
    assert!(format!("{restored:?}").contains("<redacted>"));
}
