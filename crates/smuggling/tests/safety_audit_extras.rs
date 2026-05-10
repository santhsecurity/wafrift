//! Regression coverage for the 2026-05-10 swarm-audit findings on
//! smuggling/safety.rs:
//!   CRITICAL: sanitize_input + guard_no_crlf only checked CR/LF.
//!     NULL bytes were allowed, but HTTP/1 stacks truncate header
//!     values at the first NUL — turning benign-looking detection
//!     probes into active header-injection / smuggling vectors.
//!   HIGH: ScanPolicy::backoff_delay computed `ms + jitter_ms` with
//!     plain addition; near u64::MAX max_delay this panics in debug
//!     and wraps in release.
//!   HIGH: CircuitBreaker::record_failure used plain `+= 1` on a u32,
//!     which panics in debug after 2^32 failures (and silently wraps
//!     in release, secretly resetting the breaker).

use std::time::Duration;
use wafrift_smuggling::safety::{
    CircuitBreaker, CircuitState, SafetyError, ScanPolicy, guard_no_crlf, sanitize_input,
};

// ── CRITICAL: NULL byte rejection ───────────────────────────────────

#[test]
fn sanitize_input_rejects_null_byte() {
    assert!(matches!(
        sanitize_input("safe\0evil.com"),
        Err(SafetyError::HeaderInjection)
    ));
}

#[test]
fn guard_no_crlf_also_rejects_null_byte() {
    assert!(matches!(
        guard_no_crlf("host\0attacker"),
        Err(SafetyError::HeaderInjection)
    ));
}

#[test]
fn sanitize_input_still_rejects_crlf() {
    // Negative twin — adding NUL must not regress CRLF coverage.
    assert!(sanitize_input("a\r\nb").is_err());
    assert!(sanitize_input("a\nb").is_err());
    assert!(sanitize_input("a\rb").is_err());
}

#[test]
fn sanitize_input_accepts_clean_text() {
    assert!(sanitize_input("safe-host.example.com").is_ok());
    assert!(sanitize_input("/admin/users?id=42").is_ok());
}

// ── HIGH: backoff_delay overflow ────────────────────────────────────

#[test]
fn backoff_delay_does_not_panic_at_extreme_max_delay() {
    // Pre-fix `Duration::from_millis(ms + jitter_ms)` would overflow
    // in debug when ms is near u64::MAX. Saturating add keeps it sane.
    let policy = ScanPolicy {
        base_delay_ms: 1,
        max_delay_ms: u64::MAX,
        max_retries: 3,
        jitter: true,
        fresh_connection: true,
    };
    // Attempt 100 saturates the shift; the resulting `ms` is u64::MAX
    // and adding any jitter would overflow without saturating_add.
    let _ = policy.backoff_delay(100);
    let _ = policy.backoff_delay(63);
    let _ = policy.backoff_delay(255);
}

// ── HIGH: record_failure overflow ───────────────────────────────────

#[test]
fn circuit_breaker_record_failure_saturates() {
    // Pre-fix `+= 1` panics in debug after 2^32 failures and wraps in
    // release. We can't actually call record_failure 2^32 times in a
    // test, but we can confirm saturating_add by setting the field
    // close to MAX and exercising the path.
    let mut cb = CircuitBreaker::new(5, 100);
    // Set the counter near MAX directly (fields are pub).
    cb.consecutive_failures = u32::MAX - 1;
    cb.record_failure(); // saturates to MAX, doesn't panic
    assert_eq!(cb.consecutive_failures, u32::MAX);
    cb.record_failure(); // stays at MAX, doesn't wrap to 0
    assert_eq!(cb.consecutive_failures, u32::MAX);
    // Breaker must be Open since u32::MAX >= threshold of 5.
    assert_eq!(cb.state, CircuitState::Open);
}

#[test]
fn circuit_breaker_normal_path_unchanged() {
    // Negative twin — saturating_add must not change normal behavior
    // for small failure counts.
    let mut cb = CircuitBreaker::new(2, 100);
    assert_eq!(cb.consecutive_failures, 0);
    cb.record_failure();
    assert_eq!(cb.consecutive_failures, 1);
    assert_eq!(cb.state, CircuitState::Closed);
    cb.record_failure();
    assert_eq!(cb.consecutive_failures, 2);
    assert_eq!(cb.state, CircuitState::Open);
}

// ── Scan-policy backoff sanity ──────────────────────────────────────

#[test]
fn backoff_delay_monotonic_for_small_attempts() {
    let policy = ScanPolicy {
        base_delay_ms: 100,
        max_delay_ms: 10_000,
        max_retries: 3,
        jitter: false,
        fresh_connection: true,
    };
    let d0 = policy.backoff_delay(0);
    let d1 = policy.backoff_delay(1);
    let d2 = policy.backoff_delay(2);
    assert!(d1 >= d0);
    assert!(d2 >= d1);
    assert!(d2 <= Duration::from_millis(10_000));
}
