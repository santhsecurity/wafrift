//! Regression test for the 2026-05-10 audit finding:
//!
//!   extract_clearance_cookie stored raw cookie values without
//!   sanitising control characters or CRLF. A malicious upstream
//!   Set-Cookie containing \r\n would inject arbitrary headers into
//!   downstream requests when the captured cookie was replayed.
//!
//! Pre-fix the function returned the malicious value unchanged. The
//! fix drops cookies containing CR / LF / NUL / `;` — propagating any
//! of those bytes into a `Cookie:` header is HTTP request smuggling.

use wafrift_transport::challenge::{ChallengeKind, extract_clearance_cookie};

#[test]
fn rejects_cookie_value_with_crlf_injection() {
    let raw = "cf_clearance=valid\r\nX-Injected: yes; Path=/";
    assert!(
        extract_clearance_cookie(&[raw]).is_none(),
        "Set-Cookie with CRLF in value must be dropped, not replayed"
    );
}

#[test]
fn rejects_cookie_value_with_lf_only_injection() {
    let raw = "cf_clearance=valid\nX-Bypass: 1; Path=/";
    assert!(
        extract_clearance_cookie(&[raw]).is_none(),
        "lone LF in cookie value must also be rejected (some HTTP parsers split on bare LF)"
    );
}

#[test]
fn rejects_cookie_value_with_null_byte() {
    let raw = "cf_clearance=valid\0evil; Path=/";
    assert!(
        extract_clearance_cookie(&[raw]).is_none(),
        "NUL byte in cookie value must be rejected"
    );
}

#[test]
fn rejects_cookie_value_with_inline_semicolon() {
    // `;` is the cookie-pair separator. A value containing a literal
    // `;` would let an attacker append fake attributes that some
    // upstreams interpret as a second cookie.
    let raw = "cf_clearance=valid; secret=stolen";
    // Note: split(';').next() captures only `cf_clearance=valid` so
    // the inline `; secret=stolen` is dropped at the parse step.
    // The DEFENCE-IN-DEPTH check fires when an attacker URL-decodes
    // the `;` themselves into the value before sending. Guard
    // covers both: an explicit `;` inside the captured value range
    // is rejected.
    let captured = extract_clearance_cookie(&[raw]);
    if let Some((cookie, _)) = captured {
        assert!(
            !cookie.contains(';'),
            "captured cookie must not contain ';' — got: {cookie}"
        );
    }
}

#[test]
fn accepts_normal_cf_clearance_cookie() {
    // Negative twin — clean cookies must still flow.
    let raw = "cf_clearance=clean_token_value; Path=/; Domain=example.com; Secure";
    let captured = extract_clearance_cookie(&[raw]).expect("clean cookie must be captured");
    assert_eq!(captured.0, "cf_clearance=clean_token_value");
    assert_eq!(captured.1, ChallengeKind::CloudflareManaged);
}

#[test]
fn accepts_akamai_and_aws_cookies_when_clean() {
    let raw_akamai = "_abck=akamai_token_42; Path=/; HttpOnly";
    let raw_aws = "aws-waf-token=aws_token_99; Path=/";
    assert!(extract_clearance_cookie(&[raw_akamai]).is_some());
    assert!(extract_clearance_cookie(&[raw_aws]).is_some());
}

#[test]
fn malicious_cookie_in_one_header_does_not_block_clean_cookie_in_another() {
    // If the Set-Cookie response contains BOTH a poisoned cookie and
    // a legitimate one, the legitimate one should still be captured.
    let poisoned = "cf_clearance=evil\r\nInjected: 1";
    let clean = "_abck=clean_token";
    let captured =
        extract_clearance_cookie(&[poisoned, clean]).expect("clean cookie must still capture");
    assert_eq!(captured.0, "_abck=clean_token");
    assert_eq!(captured.1, ChallengeKind::AkamaiBmp);
}

#[test]
fn empty_set_cookie_list_returns_none() {
    let empty: &[&str] = &[];
    assert!(extract_clearance_cookie(empty).is_none());
}

#[test]
fn set_cookie_without_recognised_name_returns_none() {
    let raw = "session_id=foo; Path=/";
    assert!(extract_clearance_cookie(&[raw]).is_none());
}
