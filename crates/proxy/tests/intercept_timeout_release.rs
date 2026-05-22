//! Intercept store timeout / cancel behaviour — mirrors the proxy's
//! `tokio::select!` arm in `main.rs` (default-allow after
//! `INTERCEPT_TIMEOUT` + `store.cancel(id)` so pending maps don't leak).
//!
//! Uses a short sleep instead of the 30s production constant so the
//! suite stays fast. Process-global store: tests run serially.

use std::sync::OnceLock;
use std::time::Duration;

use tokio::sync::Mutex;
use wafrift_proxy::intercept::{self, InterceptDecision};

static SERIAL: OnceLock<Mutex<()>> = OnceLock::new();

fn serial() -> &'static Mutex<()> {
    SERIAL.get_or_init(|| Mutex::new(()))
}

fn reset() {
    intercept::set_intercept_mode(false);
}

/// Reproduce the proxy timeout path: park on `rx`, on timer fire call
/// `cancel(id)` and default to `Release` without leaving pending entries.
#[tokio::test]
async fn simulated_timeout_cancels_and_clears_pending() {
    let _g = serial().lock().await;
    reset();

    let store = intercept::global_store();
    let baseline = store.pending_count();

    intercept::set_intercept_mode(true);
    let (id, rx) = store.register("timeout.example", "GET", "/wait");

    assert_eq!(store.pending_count(), baseline + 1);

    let decision = tokio::select! {
        d = rx => d.unwrap_or(InterceptDecision::Release),
        _ = tokio::time::sleep(Duration::from_millis(25)) => {
            assert!(store.cancel(id), "timeout path must cancel the registration");
            InterceptDecision::Release
        }
    };

    assert_eq!(decision, InterceptDecision::Release);
    assert_eq!(
        store.pending_count(),
        baseline,
        "cancel after timeout must not leak pending entries"
    );
    assert!(
        !store.resolve(id, InterceptDecision::Kill),
        "resolve after timeout cancel must be a no-op"
    );
}

#[tokio::test]
async fn cancel_before_timeout_keeps_store_empty() {
    let _g = serial().lock().await;
    reset();

    let store = intercept::global_store();
    let baseline = store.pending_count();

    let (id, rx) = store.register("x.com", "GET", "/early-cancel");
    assert_eq!(store.pending_count(), baseline + 1);

    assert!(store.cancel(id));
    assert_eq!(store.pending_count(), baseline);

    // Dropping the sender without `send` closes the oneshot — await
    // returns `Err`, not a decision.
    assert!(
        rx.await.is_err(),
        "receiver must be closed after cancel (no decision sent)"
    );
}

#[tokio::test]
async fn resolve_before_timeout_drains_pending() {
    let _g = serial().lock().await;
    reset();

    let store = intercept::global_store();
    let baseline = store.pending_count();

    let (id, rx) = store.register("x.com", "POST", "/resolve-first");
    assert_eq!(store.pending_count(), baseline + 1);

    assert!(store.resolve(id, InterceptDecision::Kill));
    assert_eq!(store.pending_count(), baseline);
    assert_eq!(rx.await.unwrap(), InterceptDecision::Kill);
}
