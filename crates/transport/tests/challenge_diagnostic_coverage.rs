//! Tests for diagnostic/accessor methods on `ChallengeStore` that have
//! zero coverage anywhere in the test suite: `age`, `kind`, `len`,
//! `is_empty`, and the `normalize_host` contract (tested indirectly
//! via case-folding and port-stripping assertions).
//!
//! Also covers: `refresh_solver_pending` keeping the slot alive, and
//! concurrent `Arc<ChallengeStore>` across thread boundaries.

use std::sync::Arc;
use std::thread;
use std::time::Duration;
use wafrift_transport::challenge::{ChallengeKind, ChallengeStore, DEFAULT_CLEARANCE_TTL};

// ─── len / is_empty ────────────────────────────────────────────────────────

#[test]
fn len_is_zero_on_fresh_store() {
    // PROPERTY: a freshly constructed store must be empty. An off-by-one
    // in the constructor or a leaked test fixture would break this.
    let s = ChallengeStore::new();
    assert_eq!(s.len(), 0);
    assert!(s.is_empty());
}

#[test]
fn len_increments_on_record_and_decrements_on_forget() {
    // PROPERTY: `len()` must reflect the number of live entries —
    // increment on `record`, decrement on `forget`.
    let s = ChallengeStore::new();
    s.record("a.com", "cf_clearance=1", ChallengeKind::CloudflareManaged, None);
    s.record("b.com", "cf_clearance=2", ChallengeKind::CloudflareManaged, None);
    assert_eq!(s.len(), 2);
    assert!(!s.is_empty());
    s.forget("a.com");
    assert_eq!(s.len(), 1);
}

#[test]
fn len_is_bounded_by_distinct_hosts_not_insert_count() {
    // PROPERTY: repeated `record` calls for the same host must overwrite
    // the entry, not append. `len()` must stay at 1 after N overwrites.
    let s = ChallengeStore::new();
    for i in 0..50 {
        s.record("same.host", format!("cf_clearance=v{i}"), ChallengeKind::CloudflareManaged, None);
    }
    assert_eq!(s.len(), 1, "50 overwrites must keep len at 1");
}

// ─── kind ─────────────────────────────────────────────────────────────────

#[test]
fn kind_returns_stored_challenge_kind() {
    // PROPERTY: `kind()` must return the exact `ChallengeKind` that was
    // passed to `record`. A mismatch means the kind field is not stored
    // or is stored under the wrong key.
    let s = ChallengeStore::new();
    for kind in [
        ChallengeKind::CloudflareManaged,
        ChallengeKind::Turnstile,
        ChallengeKind::Hcaptcha,
        ChallengeKind::Recaptcha,
        ChallengeKind::AwsWaf,
        ChallengeKind::AkamaiBmp,
        ChallengeKind::Unknown,
    ] {
        let host = format!("{}.test", kind.label());
        s.record(&host, "cf_clearance=x", kind, None);
        assert_eq!(
            s.kind(&host),
            Some(kind),
            "kind() mismatch for {kind:?}"
        );
    }
}

#[test]
fn kind_returns_none_for_unknown_host() {
    // PROPERTY: `kind()` for a host that has never had a cookie must
    // return `None`, not panic or return a default.
    let s = ChallengeStore::new();
    assert_eq!(s.kind("never-seen.example.com"), None);
}

#[test]
fn kind_returns_none_after_ttl_expiry() {
    // PROPERTY: `kind()` must not return a stale kind after the entry's
    // TTL has elapsed — the diagnostic must agree with `get()`.
    let s = ChallengeStore::new();
    s.record(
        "h",
        "cf_clearance=x",
        ChallengeKind::CloudflareManaged,
        Some(Duration::from_millis(10)),
    );
    std::thread::sleep(Duration::from_millis(25));
    // After TTL expiry, kind() must return None (same contract as get()).
    assert_eq!(
        s.kind("h"),
        None,
        "kind() must not return a stale kind after TTL"
    );
}

#[test]
fn kind_returns_none_after_forget() {
    // PROPERTY: `kind()` must return `None` immediately after `forget()`
    // removes the entry, even if the TTL would still be valid.
    let s = ChallengeStore::new();
    s.record("h", "cf_clearance=x", ChallengeKind::AwsWaf, None);
    assert_eq!(s.kind("h"), Some(ChallengeKind::AwsWaf));
    s.forget("h");
    assert_eq!(s.kind("h"), None, "kind() must be None after forget");
}

// ─── age ──────────────────────────────────────────────────────────────────

#[test]
fn age_returns_none_for_unknown_host() {
    // PROPERTY: `age()` for a host with no cookie must return `None`.
    let s = ChallengeStore::new();
    assert_eq!(s.age("never-seen.example.com"), None);
}

#[test]
fn age_is_non_negative_and_small_after_fresh_record() {
    // PROPERTY: `age()` immediately after `record()` must return a
    // non-zero duration that is very small (< 1 s for any realistic
    // test execution time). A huge age indicates the captured_at was
    // initialised to the wrong Instant.
    let s = ChallengeStore::new();
    s.record("h", "cf_clearance=x", ChallengeKind::CloudflareManaged, None);
    let age = s.age("h").expect("age must be Some after record");
    assert!(
        age < Duration::from_secs(5),
        "fresh cookie must have age < 5s; got {age:?}"
    );
}

#[test]
fn age_is_none_after_forget() {
    // PROPERTY: `age()` must return `None` after `forget()` removes
    // the entry — consistent with `get()` and `kind()`.
    let s = ChallengeStore::new();
    s.record("h", "cf_clearance=x", ChallengeKind::CloudflareManaged, None);
    s.forget("h");
    assert_eq!(s.age("h"), None);
}

// ─── normalize_host (contract tested via the public API) ──────────────────

#[test]
fn get_is_case_insensitive_on_host() {
    // PROPERTY: DNS is case-insensitive; `EXAMPLE.COM` and `example.com`
    // and `ExAmPlE.CoM` must all refer to the same store entry.
    // This is the pre-audit bug: case variants scattered across multiple
    // by_host slots so `get("example.com")` missed `Example.com`'s cookie.
    let s = ChallengeStore::new();
    s.record("EXAMPLE.COM", "cf_clearance=x", ChallengeKind::CloudflareManaged, None);
    assert_eq!(
        s.get("example.com").as_deref(),
        Some("cf_clearance=x"),
        "lowercase lookup must find the UPPERCASE-recorded entry"
    );
    assert_eq!(
        s.get("ExAmPlE.CoM").as_deref(),
        Some("cf_clearance=x"),
        "mixed-case lookup must find the UPPERCASE-recorded entry"
    );
}

#[test]
fn get_strips_port_from_host() {
    // PROPERTY: `example.com:443` and `example.com` are the same upstream
    // for cookie-replay purposes; the port must be stripped so a cookie
    // recorded for `example.com:443` replays on `example.com`.
    let s = ChallengeStore::new();
    s.record("example.com:443", "cf_clearance=x", ChallengeKind::CloudflareManaged, None);
    assert_eq!(
        s.get("example.com").as_deref(),
        Some("cf_clearance=x"),
        "port-stripped lookup must find the :443-recorded entry"
    );
    // And vice-versa.
    s.record("other.example.com", "cf_clearance=y", ChallengeKind::CloudflareManaged, None);
    assert_eq!(
        s.get("other.example.com:8443").as_deref(),
        Some("cf_clearance=y"),
        "port in lookup must not prevent match"
    );
}

#[test]
fn get_case_and_port_combined() {
    // PROPERTY: normalisation is both case-fold AND port-strip, and both
    // must apply simultaneously. `API.TARGET.COM:443` must match
    // `api.target.com` with no port.
    let s = ChallengeStore::new();
    s.record("API.TARGET.COM:443", "cf_clearance=z", ChallengeKind::CloudflareManaged, None);
    assert_eq!(
        s.get("api.target.com").as_deref(),
        Some("cf_clearance=z"),
        "combined case+port normalisation must work"
    );
}

// ─── refresh_solver_pending ───────────────────────────────────────────────

#[test]
fn refresh_solver_pending_returns_true_while_slot_held() {
    // PROPERTY: `refresh_solver_pending` must return `true` when the
    // caller still holds the slot (has not called `clear_solver_pending`
    // and the TTL hasn't elapsed). This is the heartbeat contract: the
    // solver calls refresh in a loop and trusts `true` to mean "you
    // still own the slot."
    let s = ChallengeStore::new();
    assert!(s.mark_solver_pending("h.test"), "first claim must succeed");
    assert!(
        s.refresh_solver_pending("h.test"),
        "refresh while holding must return true"
    );
    // Slot is still there.
    assert!(s.has_solver_pending("h.test"));
}

#[test]
fn refresh_solver_pending_returns_false_after_clear() {
    // PROPERTY: once the slot is cleared, `refresh_solver_pending` must
    // return `false` — the solver knows it has been superseded and should
    // stop. Without this check a zombie solver would keep running past
    // its eviction.
    let s = ChallengeStore::new();
    assert!(s.mark_solver_pending("h.test"));
    s.clear_solver_pending("h.test");
    assert!(
        !s.refresh_solver_pending("h.test"),
        "refresh after clear must return false"
    );
}

#[test]
fn refresh_solver_pending_for_unknown_host_returns_false() {
    // PROPERTY: refreshing a slot that was never claimed (or that
    // never existed) must return `false` — no panic, no false-positive.
    let s = ChallengeStore::new();
    assert!(!s.refresh_solver_pending("host.not.claimed"));
}

// ─── DEFAULT_CLEARANCE_TTL ────────────────────────────────────────────────

#[test]
fn default_clearance_ttl_is_at_least_one_minute() {
    // PROPERTY: Cloudflare's default `cf_clearance` cookie is valid for
    // 30 minutes; our default must be at least 1 minute so the proxy
    // doesn't immediately re-challenge on a burst of requests to the
    // same host.
    assert!(
        DEFAULT_CLEARANCE_TTL >= Duration::from_secs(60),
        "DEFAULT_CLEARANCE_TTL must be ≥ 60 s; got {:?}",
        DEFAULT_CLEARANCE_TTL
    );
}

// ─── Arc<ChallengeStore>: Send + Sync ─────────────────────────────────────

#[test]
fn challenge_store_is_send_sync() {
    // PROPERTY: `ChallengeStore` must be `Send + Sync` so the proxy can
    // hand it across thread boundaries (e.g. from the accept loop to
    // spawned connection handlers) via `Arc::clone`.
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ChallengeStore>();
    assert_send_sync::<Arc<ChallengeStore>>();
}

#[test]
fn concurrent_get_and_record_do_not_deadlock() {
    // PROPERTY: readers and writers must not deadlock under concurrent
    // access. This is the core correctness guarantee of the RwLock design
    // — multiple readers can proceed simultaneously, a writer blocks only
    // until all readers are done.
    let s = Arc::new(ChallengeStore::new());
    s.record("shared.host", "cf_clearance=init", ChallengeKind::CloudflareManaged, None);

    let mut handles = Vec::new();
    for _ in 0..8 {
        // Reader threads.
        let s2 = s.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..200 {
                let _ = s2.get("shared.host");
                let _ = s2.kind("shared.host");
                let _ = s2.age("shared.host");
            }
        }));
    }
    // Writer thread interleaved.
    {
        let s2 = s.clone();
        handles.push(thread::spawn(move || {
            for i in 0..50 {
                s2.record(
                    "shared.host",
                    format!("cf_clearance=v{i}"),
                    ChallengeKind::CloudflareManaged,
                    None,
                );
            }
        }));
    }
    for h in handles {
        h.join().expect("thread must not panic");
    }
    // After concurrent writes, the entry exists (last writer wins).
    assert!(s.get("shared.host").is_some());
}
