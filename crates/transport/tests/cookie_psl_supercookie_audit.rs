//! Regression coverage for the 2026-05-10 swarm-audit CRITICAL:
//!   Cookie Domain attribute had no PSL guard. `Domain=co.uk`,
//!   `Domain=com`, `Domain=github.io`, etc. were silently accepted —
//!   a captured cookie would then replay on EVERY site under that
//!   suffix (the classic supercookie vulnerability). RFC 6265 §5.2.3
//!   plus Mozilla's PSL project document this exact failure mode.

use wafrift_transport::challenge::extract_clearance_cookie_scoped;

fn parse_domain(set_cookie: &str) -> Option<String> {
    extract_clearance_cookie_scoped(&[set_cookie]).and_then(|(_, _, scope)| scope.domain)
}

// ── eTLDs (bare) must be rejected ─────────────────────────────────

#[test]
fn rejects_top_level_dot_com() {
    let cookie = "cf_clearance=tok; Domain=com";
    assert!(
        parse_domain(cookie).is_none(),
        "Domain=com is a public suffix — accepting it lets the cookie supercookie every .com site"
    );
}

#[test]
fn rejects_country_code_etld() {
    assert!(parse_domain("cf_clearance=tok; Domain=co.uk").is_none());
    assert!(parse_domain("cf_clearance=tok; Domain=com.au").is_none());
    assert!(parse_domain("cf_clearance=tok; Domain=org.uk").is_none());
    assert!(parse_domain("cf_clearance=tok; Domain=ac.jp").is_none());
}

#[test]
fn rejects_gh_pages_class_psl() {
    // github.io is a private-namespace eTLD — supercookie risk
    // across every github.io project.
    assert!(parse_domain("cf_clearance=tok; Domain=github.io").is_none());
    assert!(parse_domain("cf_clearance=tok; Domain=netlify.app").is_none());
    assert!(parse_domain("cf_clearance=tok; Domain=vercel.app").is_none());
    assert!(parse_domain("cf_clearance=tok; Domain=cloudfront.net").is_none());
}

// ── Real second-level domains must still pass ───────────────────────

#[test]
fn accepts_normal_second_level_domain() {
    assert_eq!(
        parse_domain("cf_clearance=tok; Domain=example.com").as_deref(),
        Some("example.com")
    );
    assert_eq!(
        parse_domain("cf_clearance=tok; Domain=bbc.co.uk").as_deref(),
        Some("bbc.co.uk")
    );
}

#[test]
fn accepts_subdomain_under_psl_namespace() {
    // `myapp.github.io` is a real site, not a public suffix.
    assert_eq!(
        parse_domain("cf_clearance=tok; Domain=myapp.github.io").as_deref(),
        Some("myapp.github.io")
    );
    assert_eq!(
        parse_domain("cf_clearance=tok; Domain=site.netlify.app").as_deref(),
        Some("site.netlify.app")
    );
}

#[test]
fn accepts_leading_dot_domain() {
    // RFC 6265 says leading dot is stripped — must still pass PSL guard.
    assert_eq!(
        parse_domain("cf_clearance=tok; Domain=.example.com").as_deref(),
        Some("example.com")
    );
}

#[test]
fn rejects_unparseable_domain_value() {
    // Garbage text doesn't parse as a hostname → reject conservatively.
    assert!(parse_domain("cf_clearance=tok; Domain=not a domain").is_none());
}
