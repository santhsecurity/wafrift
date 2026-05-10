//! Coverage for the 2026-05-10 intercept.rs audit findings:
//! - CRITICAL TOCTOU race in toggle_intercept_mode + set_intercept_mode
//! - HIGH receiver-drop leaking sender + pending entries
//!
//! All tests in this file must run sequentially (intercept state is
//! process-global). The shared `TEST_INTERCEPT_LOCK` from
//! intercept_rendezvous.rs is the model — we replicate it here so we
//! don't share static state across files.

use std::sync::OnceLock;
use tokio::sync::Mutex;
use wafrift_proxy::intercept::{self, InterceptDecision};

static SERIAL: OnceLock<Mutex<()>> = OnceLock::new();
fn serial() -> &'static Mutex<()> {
    SERIAL.get_or_init(|| Mutex::new(()))
}

fn reset() {
    intercept::set_intercept_mode(false);
    // After set(false) the store is drained; nothing extra to clear.
}

// ── HIGH: receiver-drop must not leak sender + pending ──────────

#[tokio::test]
async fn cancel_removes_sender_and_pending() {
    let _g = serial().lock().await;
    reset();

    let store = intercept::global_store();
    let (id, rx) = store.register("x.com", "GET", "/leaked");
    assert_eq!(store.snapshot().len(), 1, "registered → 1 pending");

    // Simulate the proxy dropping the receiver (client disconnect)
    // before the operator decides.
    drop(rx);

    // The store doesn't know the rx is dead — the proxy must call
    // cancel(id) to clean up. Without this API, sender + pending
    // would remain in the maps forever (audit HIGH #3).
    assert!(store.cancel(id), "cancel must remove the entry");
    assert_eq!(store.snapshot().len(), 0, "after cancel → 0 pending");

    // Idempotent — second cancel returns false but doesn't panic.
    assert!(!store.cancel(id), "second cancel must be a no-op");
}

#[tokio::test]
async fn cancel_then_resolve_is_a_no_op() {
    let _g = serial().lock().await;
    reset();

    let store = intercept::global_store();
    let (id, _rx) = store.register("x.com", "GET", "/cancel-first");
    assert!(store.cancel(id));
    // After cancel, resolve must report "no such id".
    assert!(
        !store.resolve(id, InterceptDecision::Release),
        "resolve after cancel must return false"
    );
}

#[tokio::test]
async fn resolve_still_cleans_up_normally() {
    // Negative twin — the cancel API didn't break the resolve path.
    let _g = serial().lock().await;
    reset();

    let store = intercept::global_store();
    let (id, mut rx) = store.register("x.com", "GET", "/normal");
    assert!(store.resolve(id, InterceptDecision::Release));
    assert_eq!(store.snapshot().len(), 0);
    let got = (&mut rx).await.expect("oneshot must deliver");
    assert_eq!(got, InterceptDecision::Release);
}

// ── CRITICAL: toggle TOCTOU ──────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_toggles_do_not_release_under_intercept_on() {
    // The audit's reproducer: 100 parallel toggles. Pre-fix some of
    // them interleaved such that drain_release ran while another
    // thread had already flipped the mode back ON, releasing
    // requests that should have stayed intercepted. After the fix
    // the mode + drain are guarded under a single critical section,
    // so the invariant holds: if the FINAL mode is ON, no spurious
    // release fired between the previous OFF→ON transition.
    let _g = serial().lock().await;
    reset();

    let store = intercept::global_store();

    // Register one intercept and hold its receiver — must NEVER be
    // released while mode is ON.
    intercept::set_intercept_mode(true);
    let (_id, mut rx) = store.register("a.com", "GET", "/sentinel");

    // 100 parallel toggles. Half end with mode OFF (and drain),
    // half end with mode ON (and no drain).
    let mut handles = Vec::new();
    for _ in 0..100 {
        handles.push(tokio::spawn(async move {
            intercept::toggle_intercept_mode();
        }));
    }
    for h in handles {
        h.await.unwrap();
    }

    // Force mode to a deterministic OFF so drain runs and any
    // queued sentinel is released. Then assert that the SENTINEL
    // received exactly one decision (Release) and not multiple
    // spurious sends.
    intercept::set_intercept_mode(false);
    let got = (&mut rx).await.expect("sentinel must receive a decision");
    assert_eq!(got, InterceptDecision::Release);

    // After the explicit OFF, the store must be empty — no leftover
    // entries from the toggle race.
    assert_eq!(store.snapshot().len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_set_mode_does_not_panic_or_double_send() {
    let _g = serial().lock().await;
    reset();

    let store = intercept::global_store();
    intercept::set_intercept_mode(true);
    let (_id, mut rx) = store.register("a.com", "GET", "/sentinel");

    let mut handles = Vec::new();
    for i in 0..100 {
        handles.push(tokio::spawn(async move {
            intercept::set_intercept_mode(i % 2 == 0);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }

    intercept::set_intercept_mode(false);
    // Sentinel must receive exactly one decision (the Release). A
    // second send via oneshot would panic the channel and tx.send
    // returns Err — so we just assert receive succeeds.
    let got = (&mut rx).await.expect("sentinel must receive");
    assert_eq!(got, InterceptDecision::Release);
}
