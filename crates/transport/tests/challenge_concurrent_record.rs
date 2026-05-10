//! Integration: concurrent `ChallengeStore::record` — no lost updates across threads,
//! distinct hosts collapse to `len() == 2000`.

use std::sync::Arc;
use std::thread;

use wafrift_transport::challenge::{ChallengeKind, ChallengeStore};

#[test]
fn eight_threads_two_thousand_distinct_hosts_all_retained() {
    let store = Arc::new(ChallengeStore::new());
    let mut handles = Vec::with_capacity(8);

    for t in 0..8 {
        let s = Arc::clone(&store);
        handles.push(thread::spawn(move || {
            for i in 0..250 {
                let host = format!("concurrent-host-{t}-{i:03}.stress.test");
                let cookie = format!("cf_clearance={t}_{i:03}");
                s.record(
                    host,
                    cookie,
                    ChallengeKind::CloudflareManaged,
                    None,
                );
            }
        }));
    }

    for h in handles {
        h.join().expect("Fix: worker thread must not panic");
    }

    assert_eq!(
        store.len(),
        2000,
        "Fix: 8×250 distinct hosts must yield len() == 2000 — possible lost update or hash bug"
    );

    for t in 0..8 {
        for i in 0..250 {
            let host = format!("concurrent-host-{t}-{i:03}.stress.test");
            let expected = format!("cf_clearance={t}_{i:03}");
            let got = store.get(&host).unwrap_or_else(|| {
                panic!("Fix: missing entry for {host} — concurrent record lost an update")
            });
            assert_eq!(
                got, expected,
                "Fix: last write for host must match this thread's final cookie"
            );
        }
    }
}

#[test]
fn concurrent_re_record_same_host_last_write_wins_without_length_inflation() {
    let store = Arc::new(ChallengeStore::new());
    let host = "racing-single-host.test";
    let mut handles = Vec::new();
    for wave in 0..8 {
        let s = Arc::clone(&store);
        let h = host.to_string();
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                s.record(
                    &h,
                    format!("cf_clearance=wave{wave}"),
                    ChallengeKind::CloudflareManaged,
                    None,
                );
            }
        }));
    }
    for h in handles {
        h.join().expect("Fix: worker must not panic");
    }
    assert_eq!(
        store.len(),
        1,
        "Fix: single logical host must occupy one map slot"
    );
    let final_cookie = store.get(host).expect("Fix: host must have a cookie");
    assert!(
        final_cookie.starts_with("cf_clearance=wave"),
        "Fix: final cookie must be one of the racing writes — got {final_cookie:?}"
    );
}

#[test]
fn forget_cancel_drops_entry_under_concurrent_read_pressure() {
    let store = Arc::new(ChallengeStore::new());
    store.record(
        "cancel-target.test",
        "cf_clearance=pre",
        ChallengeKind::CloudflareManaged,
        None,
    );
    let reader = Arc::clone(&store);
    let canceller = Arc::clone(&store);
    let t_read = thread::spawn(move || {
        for _ in 0..500 {
            let _ = reader.get("cancel-target.test");
            let _ = reader.len();
        }
    });
    let t_forget = thread::spawn(move || {
        canceller.forget("cancel-target.test");
    });
    t_read.join().unwrap();
    t_forget.join().unwrap();
    assert_eq!(
        store.get("cancel-target.test"),
        None,
        "Fix: forget (cancel clearance) must drop cookie — got stale replay"
    );
}
