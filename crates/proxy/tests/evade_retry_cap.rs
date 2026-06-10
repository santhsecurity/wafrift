//! Proving + adversarial tests for --max-evade-retries upper bound.
//!
//! Defect: validate_args did not cap --max-evade-retries, allowing
//! arbitrary u32 values. A pentester passing --max-evade-retries 99999
//! would pin the proxy in per-request retry storms.

mod common;
use common::{pick_free_port, start_proxy_on_free_port, start_proxy_with_output, stop_proxy};

#[tokio::test]
async fn max_evade_retries_11_rejected_with_actionable_message() {
    let port = pick_free_port().expect("pick port");
    let output = start_proxy_with_output(port, &["--max-evade-retries", "11"])
        .await
        .expect("invoke proxy");
    assert!(
        !output.status.success(),
        "expected non-zero exit for --max-evade-retries 11"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("must be <= 10"),
        "stderr must contain actionable cap message, got: {stderr}"
    );
}

#[tokio::test]
async fn max_evade_retries_u32_max_rejected_at_startup() {
    // Adversarial twin: the largest possible u32 must also be rejected.
    let port = pick_free_port().expect("pick port");
    let output = start_proxy_with_output(port, &["--max-evade-retries", "4294967295"])
        .await
        .expect("invoke proxy");
    assert!(
        !output.status.success(),
        "expected non-zero exit for --max-evade-retries u32::MAX"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("must be <= 10"),
        "stderr must cap u32::MAX, got: {stderr}"
    );
}

#[tokio::test]
async fn max_evade_retries_10_starts_cleanly() {
    // Negative twin: the cap boundary itself must still be accepted.
    let (mut proxy, _port) = start_proxy_on_free_port(&["--max-evade-retries", "10"])
        .await
        .expect("proxy must start with --max-evade-retries 10");
    stop_proxy(&mut proxy).await;
}
