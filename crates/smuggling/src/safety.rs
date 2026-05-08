//! Safety controls to prevent collateral damage during smuggling scans.

use rand::Rng;
use std::time::{Duration, Instant};

/// Per-request poison canary used to distinguish true smuggling responses
/// from coincidental server variance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Canary {
    pub token: String,
}

impl Canary {
    /// Generate a random 16-byte alphanumeric canary.
    #[must_use]
    pub fn generate() -> Self {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut rng = rand::thread_rng();
        let token: String = (0..16)
            .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
            .collect();
        Self { token }
    }
}

/// Policy that governs safe scanning behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanPolicy {
    /// Initial delay between probes (milliseconds).
    pub base_delay_ms: u64,
    /// Maximum delay between probes (milliseconds).
    pub max_delay_ms: u64,
    /// Maximum number of retries for a single probe.
    pub max_retries: u32,
    /// Whether to add random jitter to delays.
    pub jitter: bool,
    /// Whether this probe requires a fresh TCP connection.
    pub fresh_connection: bool,
}

impl Default for ScanPolicy {
    fn default() -> Self {
        Self {
            base_delay_ms: 100,
            max_delay_ms: 10_000,
            max_retries: 3,
            jitter: true,
            fresh_connection: true,
        }
    }
}

impl ScanPolicy {
    /// Compute the backoff delay for a given retry attempt.
    #[must_use]
    pub fn backoff_delay(&self, attempt: u32) -> Duration {
        let exp = 1u64 << attempt.min(63);
        let ms = self
            .base_delay_ms
            .saturating_mul(exp)
            .min(self.max_delay_ms);
        let jitter_ms = if self.jitter {
            rand::thread_rng().gen_range(0..=(ms / 4))
        } else {
            0
        };
        Duration::from_millis(ms + jitter_ms)
    }
}

/// Connection isolation policy for a probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionPolicy {
    /// Send on a brand-new connection.
    Fresh,
    /// Reuse an existing connection.
    Reuse,
    /// Multiplex on an HTTP/2 stream.
    Multiplex,
}

/// Circuit-breaker state machine to halt scanning before DoSing the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

/// Simple in-memory circuit breaker.
#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    pub failure_threshold: u32,
    pub recovery_timeout: Duration,
    pub state: CircuitState,
    pub consecutive_failures: u32,
    pub last_failure: Option<Instant>,
}

impl CircuitBreaker {
    #[must_use]
    pub fn new(failure_threshold: u32, recovery_timeout_ms: u64) -> Self {
        Self {
            failure_threshold,
            recovery_timeout: Duration::from_millis(recovery_timeout_ms),
            state: CircuitState::Closed,
            consecutive_failures: 0,
            last_failure: None,
        }
    }

    /// Record a probe failure (timeout, 5xx, or connection reset).
    pub fn record_failure(&mut self) {
        self.consecutive_failures += 1;
        self.last_failure = Some(Instant::now());
        if self.consecutive_failures >= self.failure_threshold {
            self.state = CircuitState::Open;
        }
    }

    /// Record a successful probe.
    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.state = CircuitState::Closed;
    }

    /// Returns `true` if the circuit allows another probe.
    #[must_use]
    pub fn can_proceed(&mut self) -> bool {
        match self.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                if let Some(last) = self.last_failure
                    && last.elapsed() >= self.recovery_timeout
                {
                    self.state = CircuitState::HalfOpen;
                    return true;
                }
                false
            }
            CircuitState::HalfOpen => true,
        }
    }
}

/// Generate a cache-busting query parameter token.
#[must_use]
pub fn cache_buster() -> String {
    let mut rng = rand::thread_rng();
    format!("{}", rng.gen_range(0..=u32::MAX))
}

/// Sanitize a user-supplied host/path/prefix to prevent accidental header injection.
///
/// # Errors
/// Returns an error if the input contains `\r` or `\n`.
pub fn sanitize_input(input: &str) -> Result<String, SafetyError> {
    if input.contains('\r') || input.contains('\n') {
        return Err(SafetyError::HeaderInjection);
    }
    Ok(input.into())
}

/// Guard against absurdly long prefixes that could exceed proxy buffers.
pub fn guard_prefix_len(prefix: &str, max: usize) -> Result<(), SafetyError> {
    if prefix.len() > max {
        return Err(SafetyError::PrefixTooLong {
            len: prefix.len(),
            max,
        });
    }
    Ok(())
}

/// Safety-related errors.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum SafetyError {
    #[error("input contains CRLF — possible accidental header injection")]
    HeaderInjection,
    #[error("prefix length {len} exceeds maximum {max}")]
    PrefixTooLong { len: usize, max: usize },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn canary_unique() {
        let mut set = HashSet::new();
        for _ in 0..100 {
            let c = Canary::generate();
            assert_eq!(c.token.len(), 16);
            assert!(set.insert(c.token));
        }
    }

    #[test]
    fn scan_policy_backoff_monotonic() {
        let policy = ScanPolicy::default();
        let d0 = policy.backoff_delay(0);
        let d1 = policy.backoff_delay(1);
        let d2 = policy.backoff_delay(2);
        assert!(d1 >= d0);
        assert!(d2 >= d1);
        let d_max = policy.backoff_delay(100);
        assert!(d_max <= Duration::from_millis(policy.max_delay_ms + policy.max_delay_ms / 4));
    }

    #[test]
    fn circuit_breaker_cycles() {
        let mut cb = CircuitBreaker::new(2, 10);
        assert!(cb.can_proceed());
        cb.record_failure();
        assert!(cb.can_proceed());
        cb.record_failure();
        assert!(!cb.can_proceed());
        assert_eq!(cb.state, CircuitState::Open);
        std::thread::sleep(Duration::from_millis(15));
        assert!(cb.can_proceed());
        assert_eq!(cb.state, CircuitState::HalfOpen);
        cb.record_success();
        assert_eq!(cb.state, CircuitState::Closed);
    }

    #[test]
    fn sanitize_rejects_crlf() {
        assert!(sanitize_input("a\r\nb").is_err());
        assert!(sanitize_input("a\nb").is_err());
        assert!(sanitize_input("a\rb").is_err());
        assert!(sanitize_input("safe").is_ok());
    }

    #[test]
    fn guard_prefix_len_rejects_overflow() {
        assert!(guard_prefix_len(&"A".repeat(100_000), 1000).is_err());
        assert!(guard_prefix_len("short", 1000).is_ok());
    }

    #[test]
    fn cache_buster_changes() {
        let a = cache_buster();
        let b = cache_buster();
        assert!(!a.is_empty());
        assert!(!b.is_empty());
        // Very unlikely to collide
        assert_ne!(a, b);
    }
}
