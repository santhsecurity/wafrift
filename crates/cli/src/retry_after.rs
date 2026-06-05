//! Retry-After header parsing for adaptive rate-limit backoff.
//!
//! The implementation lives in `stealth-pacing` so scanner CLIs, transport
//! layers, and browser-facing stealth flows share the same capped wait and
//! deterministic jitter contract.

use std::time::{Duration, SystemTime};

pub(crate) const MAX_OBEYED: Duration = guise_pacing::MAX_RETRY_AFTER_OBEYED;

#[must_use]
pub(crate) fn parse(value: &str, now: SystemTime) -> Option<Duration> {
    guise_pacing::parse_retry_after(value, now)
}

#[must_use]
pub(crate) fn jittered(base: Duration, nonce: u32) -> Duration {
    guise_pacing::jittered_backoff(base, nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uses_shared_retry_after_cap() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);

        assert_eq!(parse("12", now), Some(Duration::from_secs(12)));
        assert_eq!(parse("3600", now), Some(MAX_OBEYED));
        assert_eq!(parse("-1", now), None);
    }

    #[test]
    fn jittered_uses_shared_deterministic_bounds() {
        let base = Duration::from_millis(1000);
        let delay = jittered(base, 42);

        assert!(delay >= Duration::from_millis(800));
        assert!(delay <= Duration::from_millis(1200));
        assert_eq!(jittered(base, 42), delay);
    }
}
