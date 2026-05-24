//! [`ChallengeStore`] TTL expiry: expired cookies are not served and are GC'd.

use std::thread;
use std::time::Duration;

use wafrift_transport::challenge::{ChallengeKind, ChallengeStore};

#[cfg(test)]
mod helpers {
    use super::*;

    pub fn store() -> ChallengeStore {
        ChallengeStore::new()
    }

    pub fn record_short(store: &ChallengeStore, host: &str, cookie: &str, ttl: Duration) {
        store.record(host, cookie, ChallengeKind::CloudflareManaged, Some(ttl));
    }
}

use helpers::{record_short, store};

#[test]
fn get_returns_none_after_ttl_expires() {
    let s = store();
    record_short(
        &s,
        "ttl.example",
        "cf_clearance=dead",
        Duration::from_millis(15),
    );
    assert_eq!(s.get("ttl.example").as_deref(), Some("cf_clearance=dead"));
    thread::sleep(Duration::from_millis(40));
    assert_eq!(
        s.get("ttl.example"),
        None,
        "expired clearance must not be returned"
    );
}

#[test]
fn purge_expired_removes_stale_entries() {
    let s = store();
    record_short(&s, "a.example", "cf_clearance=a", Duration::from_millis(10));
    thread::sleep(Duration::from_millis(30));
    s.purge_expired();
    assert_eq!(s.len(), 0, "purge_expired must drop expired host entries");
}

#[test]
fn record_on_other_host_gc_expired_entry() {
    let s = store();
    record_short(
        &s,
        "old.example",
        "cf_clearance=old",
        Duration::from_millis(10),
    );
    assert_eq!(s.len(), 1);
    thread::sleep(Duration::from_millis(40));
    s.record(
        "new.example",
        "cf_clearance=new",
        ChallengeKind::CloudflareManaged,
        None,
    );
    assert_eq!(s.len(), 1);
    assert_eq!(s.get("old.example"), None);
    assert_eq!(s.get("new.example").as_deref(), Some("cf_clearance=new"));
}

#[test]
fn forget_drops_entry_before_natural_expiry() {
    let s = store();
    s.record(
        "live.example",
        "cf_clearance=live",
        ChallengeKind::CloudflareManaged,
        Some(Duration::from_secs(60)),
    );
    assert!(s.get("live.example").is_some());
    s.forget("live.example");
    assert_eq!(s.get("live.example"), None);
}
