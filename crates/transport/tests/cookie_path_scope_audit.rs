//! Regression coverage for the 2026-05-10 swarm-audit finding:
//!   HIGH | challenge.rs | Cookie path scope used raw `starts_with`.
//!     A cookie scoped to `/admin` would replay on `/adminxss` because
//!     `"/adminxss".starts_with("/admin")` is true. RFC 6265 §5.1.4
//!     requires the request-path to equal the cookie-path OR continue
//!     with `/` after the prefix.
//!
//! Pre-fix `replays_admin_cookie_on_unrelated_subtree` would have
//! returned the cookie for `/adminxss/login`.

use std::time::Duration;
use wafrift_transport::challenge::{ChallengeKind, ChallengeStore, CookieScope};

fn store_with_admin_cookie() -> ChallengeStore {
    let store = ChallengeStore::new();
    store.record_scoped(
        "example.com",
        "cf_clearance=admin_only",
        ChallengeKind::CloudflareManaged,
        Some(Duration::from_secs(60)),
        CookieScope {
            domain: None,
            path: Some("/admin".to_string()),
            secure: false,
        },
    );
    store
}

#[test]
fn cookie_replays_on_exact_path() {
    let store = store_with_admin_cookie();
    let got = store.get_for_request("example.com", "/admin", true);
    assert!(
        got.is_some(),
        "cookie scoped to /admin must replay on exactly /admin"
    );
}

#[test]
fn cookie_replays_on_proper_subpath() {
    let store = store_with_admin_cookie();
    let got = store.get_for_request("example.com", "/admin/users", true);
    assert!(
        got.is_some(),
        "cookie scoped to /admin must replay on /admin/users (proper RFC 6265 prefix)"
    );
    let got2 = store.get_for_request("example.com", "/admin/", true);
    assert!(
        got2.is_some(),
        "cookie scoped to /admin must replay on /admin/ (immediate trailing slash)"
    );
}

#[test]
fn cookie_does_not_replay_on_extension_attack_path() {
    let store = store_with_admin_cookie();
    // PRE-FIX: this returned Some(...) — RFC 6265 violation, real
    // credibility hit because the proxy was effectively widening the
    // cookie's reach.
    let got = store.get_for_request("example.com", "/adminxss/login", true);
    assert!(
        got.is_none(),
        "cookie scoped to /admin MUST NOT replay on /adminxss/login (extension attack)"
    );
}

#[test]
fn cookie_does_not_replay_on_unrelated_path() {
    let store = store_with_admin_cookie();
    let got = store.get_for_request("example.com", "/api/users", true);
    assert!(
        got.is_none(),
        "cookie scoped to /admin must not replay on /api/users"
    );
}

#[test]
fn cookie_with_trailing_slash_scope_replays_correctly() {
    // When the scope ends with `/`, any starts_with match is by
    // definition a proper subpath — confirm we don't break that case.
    let store = ChallengeStore::new();
    store.record_scoped(
        "example.com",
        "cf=ok",
        ChallengeKind::CloudflareManaged,
        Some(Duration::from_secs(60)),
        CookieScope {
            domain: None,
            path: Some("/api/".to_string()),
            secure: false,
        },
    );
    assert!(store.get_for_request("example.com", "/api/", true).is_some());
    assert!(
        store
            .get_for_request("example.com", "/api/users", true)
            .is_some()
    );
    // /apixss does NOT start with /api/, so it correctly drops out.
    assert!(
        store
            .get_for_request("example.com", "/apixss", true)
            .is_none()
    );
}
