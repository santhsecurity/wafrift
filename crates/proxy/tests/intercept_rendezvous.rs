use std::sync::OnceLock;
use std::time::Duration;

use wafrift_proxy::intercept::{self, InterceptDecision};

static TEST_INTERCEPT_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

fn test_intercept_lock() -> &'static tokio::sync::Mutex<()> {
    TEST_INTERCEPT_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

#[tokio::test]
async fn intercept_rendezvous_must_drain_pending_requests_when_mode_turns_off() {
    let _guard = test_intercept_lock().lock().await;
    intercept::set_intercept_mode(false);
    let store = intercept::global_store();
    let baseline = store.pending_count();

    intercept::set_intercept_mode(true);
    let (_id_a, pending_a) = store.register("example.com", "GET", "/alpha");
    let (_id_b, pending_b) = store.register("example.com", "POST", "/beta");

    assert_eq!(store.pending_count(), baseline + 2);

    let wait_a = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(2), pending_a)
            .await
            .expect("pending request A should be released")
            .expect("pending request A not cancelled")
    });
    let wait_b = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(2), pending_b)
            .await
            .expect("pending request B should be released")
            .expect("pending request B not cancelled")
    });

    tokio::time::sleep(Duration::from_millis(25)).await;
    intercept::set_intercept_mode(false);

    let decision_a = wait_a.await.expect("join A");
    let decision_b = wait_b.await.expect("join B");
    assert_eq!(decision_a, InterceptDecision::Release);
    assert_eq!(decision_b, InterceptDecision::Release);
    assert_eq!(store.pending_count(), baseline);
}

#[tokio::test]
async fn intercept_rendezvous_must_not_drain_without_mode_toggle() {
    let _guard = test_intercept_lock().lock().await;
    intercept::set_intercept_mode(false);
    let store = intercept::global_store();
    let baseline = store.pending_count();

    intercept::set_intercept_mode(true);
    let (_id, pending) = store.register("example.com", "GET", "/hold");
    assert_eq!(store.pending_count(), baseline + 1);

    let timed_out = tokio::time::timeout(Duration::from_millis(100), pending).await;
    assert!(
        timed_out.is_err(),
        "request should stay held while intercept mode remains on"
    );
    assert_eq!(store.pending_count(), baseline + 1);

    intercept::set_intercept_mode(false);
    assert_eq!(store.pending_count(), baseline);
}
