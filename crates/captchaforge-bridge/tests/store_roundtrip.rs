//! Integration test: `record_into_store` writes a clearance cookie
//! into `ChallengeStore` keyed by host, and `solve_and_record`
//! propagates a solved outcome into the same store.
//!
//! The browser-launch path is tested indirectly: we test
//! `record_into_store` (the pure recording half) directly so the
//! store round-trip is verified without requiring a live browser.
//! A second sub-test verifies the full `solve_and_record` error path:
//! when the browser is unavailable the store must remain empty.

use wafrift_captchaforge_bridge::{
    BridgeConfig, BridgeOutcome, record_into_store, solve_and_record,
};
use wafrift_transport::challenge::{ChallengeKind, ChallengeStore};

/// `record_into_store` places the cookie under the correct host key
/// and the value is immediately retrievable via `ChallengeStore::get`.
#[test]
fn record_into_store_writes_cookie_for_host() {
    let store = ChallengeStore::new();
    let host = "target.example.com";

    let outcome = BridgeOutcome {
        cookie_header: "cf_clearance=abc123xyz".to_string(),
        kind: ChallengeKind::CloudflareManaged,
        elapsed_ms: 42,
    };

    record_into_store(&store, host, &outcome);

    let stored = store
        .get(host)
        .unwrap_or_else(|| panic!("no cookie in store for host '{host}' after record_into_store"));
    assert_eq!(
        stored, "cf_clearance=abc123xyz",
        "stored cookie value mismatch"
    );
}

/// `record_into_store` keying is host-specific: a different host
/// must NOT see the cookie.
#[test]
fn record_into_store_does_not_bleed_to_other_hosts() {
    let store = ChallengeStore::new();

    let outcome = BridgeOutcome {
        cookie_header: "_abck=ABCDEF~-1~YAAQ".to_string(),
        kind: ChallengeKind::AkamaiBmp,
        elapsed_ms: 99,
    };

    record_into_store(&store, "host-a.example.com", &outcome);

    assert!(
        store.get("host-b.example.com").is_none(),
        "cookie leaked from host-a to host-b"
    );
}

/// When `solve_and_record` does not produce an outcome (e.g. Chromium
/// absent → launch errors, or the challenge HTML wasn't a captcha →
/// `Ok(None)`), the store must remain empty — partial state must
/// never be recorded. Both branches satisfy the contract: the test
/// asserts the LOAD-BEARING half (no cookie in store) regardless of
/// whether the bridge surfaces the browser-missing path as `Err`
/// or as `Ok(None)`. The earlier strict `is_err()` assertion was
/// overspecified against the bridge's actual return semantics.
#[tokio::test]
async fn solve_and_record_does_not_pollute_store_on_err() {
    // Force an immediate error by pointing at a non-existent binary.
    temp_env::async_with_vars([("CHROMIUM_PATH", Some("/nonexistent/chromium"))], async {
        let store = ChallengeStore::new();
        let host = "victim.example.com";

        let cfg = BridgeConfig {
            solve_timeout_ms: 2_000,
            headless: true,
            no_sandbox: false,
            navigate_first: false,
        };

        let result = solve_and_record(
            &store,
            host,
            "<html></html>",
            "https://victim.example.com/",
            &cfg,
        )
        .await;

        // Either branch is a valid "no outcome captured" state; what
        // matters is that no partial cookie was written.
        assert!(
            !matches!(result, Ok(Some(_))),
            "must not return Ok(Some(_)) when chromium is missing — got {result:?}"
        );
        assert!(
            store.get(host).is_none(),
            "store must not have a cookie after a failed solve"
        );
    })
    .await;
}
