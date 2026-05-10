//! Very large payload — 10 MB body must evade without OOM and complete
//! within 5 seconds.

use std::time::{Duration, Instant};
use wafrift_strategy::{HostState, strategy::evade};
use wafrift_types::{EvasionConfig, Request};

// ── Positive: 10 MB payload finishes in < 5s ──────────────────────────────

#[test]
fn ten_mb_payload_completes_within_5_seconds() {
    let body = vec![b'a'; 10 * 1024 * 1024];
    let req = Request::post("https://example.com/api", body.clone())
        .header("Content-Type", "application/x-www-form-urlencoded");
    let state = HostState::default();
    let config = EvasionConfig::default();

    let start = Instant::now();
    let result = evade(&req, &state, &config);
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(5),
        "evade on 10 MB payload took {:?}, expected < 5s",
        elapsed
    );
    assert!(
        result.request.body.is_some(),
        "body must survive the evasion pipeline"
    );
    assert_eq!(
        result.request.body.as_ref().unwrap().len(),
        body.len(),
        "body length must be preserved"
    );
}

// ── Negative: 0-byte payload finishes instantly ───────────────────────────

#[test]
fn zero_byte_payload_completes_instantly() {
    let req = Request::post("https://example.com/api", vec![])
        .header("Content-Type", "application/x-www-form-urlencoded");
    let state = HostState::default();
    let config = EvasionConfig::default();

    let start = Instant::now();
    let result = evade(&req, &state, &config);
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(100),
        "empty payload evade took {:?}, expected < 100ms",
        elapsed
    );
    assert_eq!(result.request.body, Some(vec![]));
}

// ── Negative: heavy escalation on 10 MB must not OOM ──────────────────────

#[test]
fn ten_mb_payload_with_heavy_escalation_no_oom() {
    let body = vec![b'x'; 10 * 1024 * 1024];
    let req = Request::post("https://example.com/api", body)
        .header("Content-Type", "application/x-www-form-urlencoded");

    let mut state = HostState::default();
    for _ in 0..10 {
        state.record_block();
    }

    let config = EvasionConfig::default();

    let start = Instant::now();
    let result = evade(&req, &state, &config);
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(5),
        "heavy escalation on 10 MB payload took {:?}, expected < 5s",
        elapsed
    );
    assert!(result.request.body.is_some());
}
