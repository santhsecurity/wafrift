//! Regression coverage for the 2026-05-10 proxy intercept audit:
//!   MEDIUM: InterceptStore.{senders, pending} leaked entries when the
//!     request handler future was cancelled mid-rendezvous (client
//!     disconnect, hyper drop, panic-induced unwind). Neither `resolve()`
//!     nor the timeout's `cancel()` ran in that path, so the `BTreeMap`
//!     entries persisted forever and the operator's intercept queue
//!     filled with ghost entries the TUI couldn't dismiss.
//!
//! Pre-fix: `register()` did not GC dead senders. After 1000 dropped
//! receivers the maps would still hold 1000 stale entries.

use std::time::Duration;
use wafrift_proxy::intercept::InterceptStore;

#[tokio::test(flavor = "current_thread")]
async fn dropped_receivers_are_gced_on_next_register() {
    let store = InterceptStore::new();
    // Simulate 100 client-disconnect rendezvous: register, drop rx
    // immediately. Before the GC fix these would all stay in the maps.
    for _ in 0..100 {
        let (_id, rx) = store.register("h", "GET", "/");
        drop(rx);
    }
    // Yield so the closed-channel state is observable.
    tokio::time::sleep(Duration::from_millis(1)).await;
    // Trigger the GC by registering one more — register() opportunistically
    // sweeps closed senders. The freshly-registered one stays.
    let (_id, _rx) = store.register("h", "GET", "/last");
    // Pre-fix: pending_count would be 101. Post-fix: 1.
    let count = store.pending_count();
    assert!(
        count <= 5,
        "pending_count {count} did not GC dropped receivers — \
         intercept queue leaks ghost entries"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn explicit_gc_returns_count_of_pruned_entries() {
    let store = InterceptStore::new();
    // Register all 50 first so register's opportunistic GC doesn't
    // prune them mid-loop (it would otherwise reduce the count we
    // can later assert against).
    let mut all_rx = Vec::with_capacity(50);
    for _ in 0..50 {
        let (_id, rx) = store.register("h", "GET", "/");
        all_rx.push(rx);
    }
    // Now drop the odd-indexed receivers in one go.
    let mut keepers = Vec::new();
    for (i, rx) in all_rx.into_iter().enumerate() {
        if i % 2 == 0 {
            keepers.push(rx);
        } else {
            drop(rx);
        }
    }
    tokio::time::sleep(Duration::from_millis(1)).await;
    let pruned = store.gc_dead_senders();
    assert_eq!(pruned, 25, "expected to GC the 25 dropped receivers");
    assert_eq!(
        store.pending_count(),
        25,
        "the 25 live receivers must still be in the queue"
    );
    drop(keepers);
}

#[tokio::test(flavor = "current_thread")]
async fn gc_does_not_drop_live_pending_entries() {
    let store = InterceptStore::new();
    let (_id, rx) = store.register("h", "GET", "/important");
    let pruned = store.gc_dead_senders();
    assert_eq!(pruned, 0, "live receiver must not be pruned");
    assert_eq!(store.pending_count(), 1, "live entry must survive");
    drop(rx);
}
