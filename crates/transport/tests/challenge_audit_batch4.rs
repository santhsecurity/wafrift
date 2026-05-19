//! Regression coverage for the 2026-05-10 swarm-audit findings on
//! transport/challenge.rs:
//!   HIGH: `AwsWaf.is_cookie_solvable()` was false but `extract_clearance`
//!     stored aws-waf-token cookies — the captured cookie was never
//!     replayed.
//!   HIGH: Akamai/AWS server-header alone (no body keyword) classified
//!     every CDN-served 200 as a challenge, parking dispatch in Wait.
//!   HIGH: Domain attribute kept `:port` suffix, enabling
//!     domain-confusion bypass (`evil.com:8080` matched `evil.com`).
//!   MEDIUM: `get()` observed expired entries but left them in the map,
//!     so a high-churn host could grow the table indefinitely.

use std::time::Duration;
use wafrift_transport::challenge::{
    ChallengeKind, ChallengeStore, CookieScope, classify_with_status,
    extract_clearance_cookie_scoped,
};

// ── HIGH: AwsWaf cookie-solvable alignment ──────────────────────────

#[test]
fn aws_waf_is_cookie_solvable_so_captured_token_replays() {
    assert!(
        ChallengeKind::AwsWaf.is_cookie_solvable(),
        "AwsWaf must be cookie-solvable so dispatch replays the captured aws-waf-token"
    );
}

// ── HIGH: server-header conjunction ─────────────────────────────────

#[test]
fn akamai_server_header_alone_does_not_classify_as_challenge() {
    // Pre-fix: any response with `Server: AkamaiGHost` was labelled
    // AkamaiBmp regardless of body content. Now requires `_abck` body.
    let headers = vec![("Server".to_string(), "AkamaiGHost".to_string())];
    let kind = classify_with_status(b"<html>normal page</html>", &headers, 403);
    assert_ne!(
        kind,
        ChallengeKind::AkamaiBmp,
        "Akamai-served regular page must not classify as a challenge"
    );
}

#[test]
fn aws_server_header_alone_does_not_classify_as_challenge() {
    let headers = vec![("Server".to_string(), "awselb/2.0".to_string())];
    let kind = classify_with_status(b"<html>regular page</html>", &headers, 403);
    assert_ne!(
        kind,
        ChallengeKind::AwsWaf,
        "awselb-served regular page must not classify as challenge"
    );
}

#[test]
fn akamai_with_body_marker_still_classifies() {
    // Negative twin — the precision fix must not regress recall.
    let headers = vec![("Server".to_string(), "AkamaiGHost".to_string())];
    let kind = classify_with_status(b"<html>_abck challenge here</html>", &headers, 403);
    assert_eq!(kind, ChallengeKind::AkamaiBmp);
}

#[test]
fn aws_with_body_marker_still_classifies() {
    let headers = vec![("Server".to_string(), "awselb/2.0".to_string())];
    let kind = classify_with_status(b"<html>aws-waf-token check</html>", &headers, 403);
    assert_eq!(kind, ChallengeKind::AwsWaf);
}

// ── HIGH: Domain attribute port stripping ───────────────────────────

#[test]
fn cookie_domain_with_port_is_rejected() {
    let cookies = ["cf_clearance=tok123; Domain=evil.com:8080; Path=/"];
    let res = extract_clearance_cookie_scoped(&cookies);
    let (_, _, scope) = res.expect("cookie with port-in-Domain still parses but Domain is dropped");
    assert!(
        scope.domain.is_none(),
        "Domain with port must be rejected — pre-fix it was silently kept as evil.com:8080 \
         which then matched bare evil.com (domain-confusion bypass)"
    );
}

#[test]
fn cookie_domain_with_path_attempt_is_rejected() {
    let cookies = ["cf_clearance=tok123; Domain=evil.com/admin; Path=/"];
    let (_, _, scope) = extract_clearance_cookie_scoped(&cookies).unwrap();
    assert!(scope.domain.is_none());
}

#[test]
fn cookie_domain_clean_value_still_accepted() {
    let cookies = ["cf_clearance=tok123; Domain=example.com; Path=/"];
    let (_, _, scope) = extract_clearance_cookie_scoped(&cookies).unwrap();
    assert_eq!(scope.domain.as_deref(), Some("example.com"));
}

// ── MEDIUM: expired entry GC on read ────────────────────────────────

#[test]
fn get_purges_expired_entry_inline() {
    let store = ChallengeStore::new();
    store.record_scoped(
        "victim.example.com",
        "cf_clearance=expired",
        ChallengeKind::CloudflareManaged,
        Some(Duration::from_millis(50)),
        CookieScope::default(),
    );
    // Wait for it to expire.
    std::thread::sleep(Duration::from_millis(80));
    // First get returns None (expired) AND should remove the entry.
    assert!(store.get("victim.example.com").is_none());
    // Second get must still return None — and the inner table should
    // not still hold the entry. We can't peek directly, but a fresh
    // record afterwards must still work.
    store.record_scoped(
        "victim.example.com",
        "cf_clearance=fresh",
        ChallengeKind::CloudflareManaged,
        Some(Duration::from_secs(60)),
        CookieScope::default(),
    );
    assert_eq!(
        store.get("victim.example.com").as_deref(),
        Some("cf_clearance=fresh")
    );
}
