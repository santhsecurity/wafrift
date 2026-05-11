//! Integration: `extract_clearance_cookie` keeps `name=value` for replay and strips
//! `Set-Cookie` attributes (Path, Domain, Secure, `HttpOnly`, Expires, Max-Age).

use wafrift_transport::challenge::{ChallengeKind, extract_clearance_cookie};

fn assert_cf_pair_only(raw: &str, expected_pair: &str) {
    let got = extract_clearance_cookie(&[raw]).unwrap_or_else(|| {
        panic!(
            "Fix: must capture clearance from Set-Cookie — input: {raw:?}"
        )
    });
    assert_eq!(got.0, expected_pair, "Fix: replay string must be pair only");
    assert_eq!(got.1, ChallengeKind::CloudflareManaged);
    assert!(
        !got.0.contains("path"),
        "Fix: Path attribute must not appear in Cookie header — got {:?}",
        got.0
    );
    assert!(
        !got.0.contains("domain"),
        "Fix: Domain attribute must not appear — got {:?}",
        got.0
    );
    assert!(
        !got.0.contains("secure"),
        "Fix: Secure flag must not appear — got {:?}",
        got.0
    );
    assert!(
        !got.0.contains("httponly"),
        "Fix: HttpOnly flag must not appear — got {:?}",
        got.0
    );
    assert!(
        !got.0.contains("expires"),
        "Fix: Expires must not appear — got {:?}",
        got.0
    );
    assert!(
        !got.0.contains("max-age"),
        "Fix: Max-Age must not appear — got {:?}",
        got.0
    );
}

#[test]
fn cf_clearance_path_only_attribute() {
    assert_cf_pair_only(
        "cf_clearance=tokenPath; Path=/",
        "cf_clearance=tokenPath",
    );
}

#[test]
fn cf_clearance_domain_attribute() {
    assert_cf_pair_only(
        "cf_clearance=tokDom; Path=/; Domain=.example.com",
        "cf_clearance=tokDom",
    );
}

#[test]
fn cf_clearance_secure_httponly_flags() {
    assert_cf_pair_only(
        "cf_clearance=tokSH; Path=/; Domain=.cdn.example; Secure; HttpOnly",
        "cf_clearance=tokSH",
    );
}

#[test]
fn cf_clearance_expires_max_age_attributes() {
    assert_cf_pair_only(
        "cf_clearance=tokEM; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Max-Age=3600",
        "cf_clearance=tokEM",
    );
}

#[test]
fn cf_clearance_all_attributes_combined() {
    let raw = concat!(
        "cf_clearance=FULL123; ",
        "Path=/api; ",
        "Domain=.example.com; ",
        "Secure; ",
        "HttpOnly; ",
        "Expires=Thu, 01 Jan 2026 00:00:00 GMT; ",
        "Max-Age=7200",
    );
    assert_cf_pair_only(raw, "cf_clearance=FULL123");
}

#[test]
fn akamai_abck_strips_attributes_identically() {
    let raw = "_abck=AK~-1~Y; Path=/; Domain=.akamai.edge; HttpOnly; Secure; Max-Age=86400";
    let got = extract_clearance_cookie(&[raw]).expect("Fix: _abck must extract");
    assert_eq!(got.0, "_abck=AK~-1~Y");
    assert_eq!(got.1, ChallengeKind::AkamaiBmp);
    assert!(!got.0.contains(';'), "Fix: captured pair must be single name=value");
}

#[test]
fn aws_waf_token_strips_attributes() {
    let raw = "aws-waf-token=WAF99; Path=/; Secure; HttpOnly; Expires=Tue, 10 May 2026 12:00:00 GMT";
    let got = extract_clearance_cookie(&[raw]).expect("Fix: aws-waf-token must extract");
    assert_eq!(got.0, "aws-waf-token=WAF99");
    assert_eq!(got.1, ChallengeKind::AwsWaf);
}

#[test]
fn negative_twin_attribute_like_text_in_value_position_not_confused_with_flags() {
    // Value is intentionally weird but safe — still must not pull "; foo=bar" from attributes.
    let raw = "cf_clearance=safe_value_42; Path=/; Domain=test.local";
    let got = extract_clearance_cookie(&[raw]).unwrap();
    assert_eq!(got.0, "cf_clearance=safe_value_42");
}
