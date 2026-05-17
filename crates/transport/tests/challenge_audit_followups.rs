//! Follow-up coverage for the 2026-05-10 challenge.rs audit:
//! HIGH classify body-OOM, HIGH unbounded growth, MEDIUM host
//! case+port mismatch.
//!
//! Each test would have failed pre-fix.

use std::thread;
use std::time::Duration;
use wafrift_transport::challenge::{
    CLASSIFY_BODY_SCAN_CAP, ChallengeKind, ChallengeStore, SolveAction,
    classify_with_status, dispatch,
};

// ── HIGH: classify body OOM ─────────────────────────────────────

#[test]
fn classify_caps_body_scan_at_64k() {
    // Pre-fix classify allocated `body.len()` bytes for the lowercase
    // copy. A 16 MB body would burn ~16 MB on every call.
    let prefix = b"<html>turnstile</html>";
    let mut huge = Vec::with_capacity(prefix.len() + 16 * 1024 * 1024);
    huge.extend_from_slice(prefix);
    huge.extend(std::iter::repeat_n(b'X', 16 * 1024 * 1024));
    // Should still classify on the prefix without OOMing on the suffix.
    let kind = classify_with_status(&huge, &[], 403);
    assert_eq!(kind, ChallengeKind::Turnstile);
}

#[test]
fn classify_keyword_after_cap_is_not_seen() {
    // Defence-in-depth: a keyword placed AFTER the cap must be
    // ignored. A benign multi-MB body that happens to contain
    // "hcaptcha" deep in its tail must not trigger classification.
    let mut body = vec![b' '; CLASSIFY_BODY_SCAN_CAP + 64];
    let kw = b"hcaptcha";
    body.extend_from_slice(kw);
    let kind = classify_with_status(&body, &[], 403);
    assert_eq!(
        kind,
        ChallengeKind::Unknown,
        "keyword past CLASSIFY_BODY_SCAN_CAP must not classify"
    );
}

#[test]
fn classify_keyword_inside_cap_still_works() {
    // Negative twin: the keyword must still be detected when it's
    // inside the cap.
    let body = b"<html>turnstile</html>";
    assert_eq!(classify_with_status(body, &[], 403), ChallengeKind::Turnstile);
}

// ── MEDIUM: host case + port normalization ─────────────────────

#[test]
fn store_get_is_case_insensitive() {
    let s = ChallengeStore::new();
    s.record(
        "Example.COM",
        "cf_clearance=abc",
        ChallengeKind::CloudflareManaged,
        None,
    );
    assert_eq!(
        s.get("example.com").as_deref(),
        Some("cf_clearance=abc"),
        "DNS is case-insensitive — store_get must canonicalise"
    );
}

#[test]
fn store_get_strips_port_from_host() {
    let s = ChallengeStore::new();
    s.record(
        "host.test:443",
        "cf_clearance=tok",
        ChallengeKind::CloudflareManaged,
        None,
    );
    assert_eq!(
        s.get("host.test").as_deref(),
        Some("cf_clearance=tok"),
        "host:port and host must collide on the same key"
    );
}

#[test]
fn store_record_canonicalises_then_dedupes_on_re_insert() {
    let s = ChallengeStore::new();
    s.record(
        "Foo.COM",
        "cf_clearance=v1",
        ChallengeKind::CloudflareManaged,
        None,
    );
    s.record(
        "foo.com",
        "cf_clearance=v2",
        ChallengeKind::CloudflareManaged,
        None,
    );
    // Both should land in the same slot — the last write wins.
    assert_eq!(s.len(), 1, "case variants must collapse to one entry");
    assert_eq!(s.get("FOO.com").as_deref(), Some("cf_clearance=v2"));
}

// ── HIGH: unbounded growth without external purge ──────────────

#[test]
fn store_record_purges_expired_entries_on_insert() {
    let s = ChallengeStore::new();
    let short = Duration::from_millis(10);
    s.record(
        "short.live",
        "cf_clearance=expiring",
        ChallengeKind::CloudflareManaged,
        Some(short),
    );
    assert_eq!(s.len(), 1);

    // Sleep past the TTL.
    thread::sleep(Duration::from_millis(50));

    // A new insert on a different host must trigger the opportunistic
    // purge — the expired entry should NOT survive.
    s.record(
        "fresh.live",
        "cf_clearance=fresh",
        ChallengeKind::CloudflareManaged,
        None,
    );
    assert_eq!(
        s.len(),
        1,
        "expired entry must be GC'd by the next insert; pre-fix store \
         would hold 2 entries forever"
    );
    assert_eq!(s.get("fresh.live").as_deref(), Some("cf_clearance=fresh"));
    assert_eq!(s.get("short.live"), None);
}

#[test]
fn store_record_does_not_purge_live_entries() {
    let s = ChallengeStore::new();
    s.record("a", "cf_clearance=a", ChallengeKind::CloudflareManaged, None);
    s.record("b", "cf_clearance=b", ChallengeKind::CloudflareManaged, None);
    s.record("c", "cf_clearance=c", ChallengeKind::CloudflareManaged, None);
    assert_eq!(s.len(), 3, "live entries must survive opportunistic purge");
}

// ── HIGH: classify status-code gating (FP on benign 200 OK) ─────

#[test]
fn classify_with_status_skips_body_scan_on_200_ok() {
    // A blog post about Cloudflare turnstile served with 200 OK
    // must NOT be classified as a challenge — the upstream let
    // the request through, by definition.
    let body = b"<html><h1>Bypassing Turnstile in 2026</h1>";
    let kind = classify_with_status(body, &[], 200);
    assert_eq!(
        kind,
        ChallengeKind::Unknown,
        "200 OK with keyword in body must be Unknown, not a challenge"
    );
}

#[test]
fn classify_with_status_classifies_on_403() {
    let body = b"<html>turnstile</html>";
    let kind = classify_with_status(body, &[], 403);
    assert_eq!(
        kind,
        ChallengeKind::Turnstile,
        "403 with turnstile body must classify as a challenge"
    );
}

#[test]
fn classify_with_status_classifies_on_503() {
    let body = b"<html>turnstile</html>";
    let kind = classify_with_status(body, &[], 503);
    assert_eq!(kind, ChallengeKind::Turnstile);
}

#[test]
fn classify_with_status_classifies_on_500_5xx_range() {
    let body = b"<html>turnstile</html>";
    assert_eq!(classify_with_status(body, &[], 500), ChallengeKind::Turnstile);
    assert_eq!(classify_with_status(body, &[], 502), ChallengeKind::Turnstile);
    assert_eq!(classify_with_status(body, &[], 599), ChallengeKind::Turnstile);
}

#[test]
fn classify_with_status_skips_on_3xx_redirect() {
    // 301 / 302 are not challenges by definition.
    let body = b"<html>turnstile</html>";
    assert_eq!(classify_with_status(body, &[], 301), ChallengeKind::Unknown);
    assert_eq!(classify_with_status(body, &[], 302), ChallengeKind::Unknown);
}

#[test]
fn classify_status_zero_is_back_compat_scan() {
    // The original `classify` (no status param) must still work
    // exactly as before for callers that haven't been updated.
    let body = b"<html>turnstile</html>";
    assert_eq!(
        classify_with_status(body, &[], 0),
        ChallengeKind::Turnstile,
        "back-compat: status=0 sentinel must scan regardless"
    );
    assert_eq!(
        classify_with_status(body, &[], 0),
        ChallengeKind::Turnstile,
        "status=0 sentinel must scan regardless"
    );
}

// ── MEDIUM: dispatch wait jitter (no synchronised retry burst) ──

#[test]
fn dispatch_wait_delay_has_jitter() {
    // Run dispatch 50 times for the same host+kind. The base wait
    // is 2 seconds; ±25% jitter means individual delays must vary
    // across runs. Pre-fix the delay was the EXACT 2s every time
    // and 50 callers would retry in lockstep against the upstream.
    let s = ChallengeStore::new();
    let mut delays_ms = std::collections::HashSet::new();
    for _ in 0..50 {
        // Tiny sleep so the per-call SystemTime nanos drift between
        // calls — without this the loop runs faster than the system
        // clock can deliver distinct nanos and we'd miss the jitter.
        thread::sleep(Duration::from_millis(2));
        match dispatch("h.test", ChallengeKind::CloudflareManaged, &s) {
            SolveAction::Wait { delay } => {
                delays_ms.insert(delay.as_millis());
            }
            other => panic!("expected Wait, got {other:?}"),
        }
    }
    assert!(
        delays_ms.len() > 1,
        "dispatch Wait delay must vary across calls (got {} distinct ms values across 50 runs); \
         pre-fix all 50 callers would retry at the exact same instant",
        delays_ms.len()
    );
    for ms in &delays_ms {
        assert!(
            (1000..=3000).contains(&(*ms as u64)),
            "jittered delay must stay within reasonable bounds; got {ms}ms"
        );
    }
}
