//! Retry-After header parsing for adaptive rate-limit backoff.
//!
//! The audit's earlier work surfaced a single-bit "this batch was
//! rate-limited" signal. That is enough to detect — but not enough to
//! *respect* the target's own stated wait. RFC 9110 §10.2.3 (and the
//! older RFC 6585 §4 / RFC 7231 §7.1.3) defines `Retry-After` as
//! either a delta-seconds integer or an HTTP-date; when a polite WAF
//! ships one, the right answer is to sleep exactly that long
//! (capped — see `MAX_OBEYED`) rather than doubling blindly.
//!
//! This module:
//! - parses both forms total-and-pure (no panic on any input);
//! - hard-caps at [`MAX_OBEYED`] so a hostile or buggy server cannot
//!   pin the scan asleep for an hour;
//! - returns `None` for absent / unparseable headers so the caller
//!   falls back to its own backoff curve.

use std::time::Duration;
use std::time::SystemTime;

/// Upper bound on how long we will obey `Retry-After`. A WAF-evasion
/// scan should fail loud before sleeping minutes — past this cap the
/// adaptive backoff hands off to the early-abort path (≥80% RL ⇒
/// `aborted_rate_limited`). 60 s = the longest reasonable cooldown for
/// an authorized bug-bounty scan; longer means "test a different
/// endpoint or use a different egress IP".
pub const MAX_OBEYED: Duration = Duration::from_secs(60);

/// Parse a `Retry-After` header value at the given `now` reference,
/// returning the wait duration the server is asking for. Caps at
/// [`MAX_OBEYED`].
///
/// Accepted forms:
/// - integer delta-seconds, e.g. `120`
/// - HTTP-date (IMF-fixdate), e.g. `Wed, 21 Oct 2015 07:28:00 GMT`
///
/// Returns `None` on:
/// - empty / whitespace-only input,
/// - negative or non-numeric integers (per RFC, MUST be non-negative
///   integer; negative is malformed, not "sleep forever"),
/// - HTTP-dates we cannot parse,
/// - HTTP-dates already in the past (treated as "no wait required").
#[must_use]
pub fn parse(value: &str, now: SystemTime) -> Option<Duration> {
    let v = value.trim();
    if v.is_empty() {
        return None;
    }
    if let Ok(secs) = v.parse::<i64>() {
        if secs < 0 {
            return None;
        }
        let d = Duration::from_secs(secs.try_into().ok()?);
        return Some(d.min(MAX_OBEYED));
    }
    let target = httpdate::parse_http_date(v).ok()?;
    let delta = target.duration_since(now).ok()?;
    Some(delta.min(MAX_OBEYED))
}

/// Apply deterministic ±20% jitter to a backoff `base`. The jitter is
/// keyed on `nonce` (the scan's `total_fired` counter, monotonic per
/// scan) so the sequence is reproducible across runs but does not
/// align with other clients hammering the same target — that
/// alignment is what some WAFs penalise after a 429 cooldown opens.
///
/// Properties pinned by test:
/// - bounded in `[0.80 * base, 1.20 * base]` for every nonce,
/// - bounded with zero base = zero (no overflow / spurious sleep),
/// - distinct `nonce`s produce distinct multipliers across a window
///   (no constant-factor degenerate case).
#[must_use]
pub fn jittered(base: Duration, nonce: u32) -> Duration {
    if base.is_zero() {
        return Duration::ZERO;
    }
    // 0..=200 maps to [-100, +100] of "tenths of a percent of base /10",
    // i.e. ±10% × 2 = ±20%. A xorshift fold of the nonce keeps adjacent
    // nonces from producing adjacent multipliers (anti-correlation).
    let mut x = nonce ^ 0x9E37_79B9;
    x ^= x.wrapping_shl(13);
    x ^= x.wrapping_shr(17);
    x ^= x.wrapping_shl(5);
    let span = 401_u32; // 0..=400
    let r = x % span; // 0..=400
    // Scale to factor in [0.80, 1.20] using milli-multiplier math
    // (avoids floats — every result is deterministic per nonce).
    let milli_mult: u64 = 800 + u64::from(r); // 800..=1200
    let base_nanos = u64::try_from(base.as_nanos()).unwrap_or(u64::MAX);
    let jittered_nanos = base_nanos.saturating_mul(milli_mult) / 1000;
    Duration::from_nanos(jittered_nanos)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn t0() -> SystemTime {
        // Fixed epoch reference makes HTTP-date arithmetic deterministic.
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    #[test]
    fn integer_seconds_is_parsed_and_returned_verbatim() {
        assert_eq!(parse("12", t0()), Some(Duration::from_secs(12)));
        assert_eq!(parse("0", t0()), Some(Duration::ZERO));
        assert_eq!(parse("  45  ", t0()), Some(Duration::from_secs(45)));
    }

    #[test]
    fn integer_is_capped_at_max_obeyed() {
        // RFC permits an arbitrarily large delta — we MUST NOT sleep for
        // 3600 s on the say-so of an adversarial origin.
        assert_eq!(parse("3600", t0()), Some(MAX_OBEYED));
        assert_eq!(parse("9999999", t0()), Some(MAX_OBEYED));
    }

    #[test]
    fn negative_or_garbage_integer_is_none_not_zero_or_forever() {
        // Anti-rig: a malformed header must not become "wait forever"
        // or "wait zero by silent coercion". The caller falls back to
        // its own backoff curve.
        assert_eq!(parse("-1", t0()), None);
        assert_eq!(parse("abc", t0()), None);
        assert_eq!(parse("", t0()), None);
        assert_eq!(parse("   ", t0()), None);
        assert_eq!(parse("12.5", t0()), None, "fractional seconds not RFC");
    }

    #[test]
    fn http_date_in_future_yields_the_delta_until_then() {
        // 30 s in the future ⇒ ~30 s wait.
        let future = t0() + Duration::from_secs(30);
        let s = httpdate::fmt_http_date(future);
        let d = parse(&s, t0()).expect("future date should parse");
        // 1 s slack for the second-precision of HTTP-date.
        assert!(d >= Duration::from_secs(29) && d <= Duration::from_secs(30));
    }

    #[test]
    fn http_date_in_past_yields_none_not_a_negative_or_zero() {
        // A polite server saying "you may retry after a moment that has
        // already passed" means "retry now". Returning None lets the
        // caller skip the sleep entirely (don't fabricate a 0 ms wait
        // that bypasses the audit's existing inter-batch delay).
        let past = t0() - Duration::from_secs(60);
        let s = httpdate::fmt_http_date(past);
        assert_eq!(parse(&s, t0()), None);
    }

    #[test]
    fn http_date_far_future_is_capped() {
        // An adversarial WAF could ship a date a decade out.
        let far = t0() + Duration::from_secs(60 * 60 * 24 * 365);
        let s = httpdate::fmt_http_date(far);
        assert_eq!(parse(&s, t0()), Some(MAX_OBEYED));
    }

    #[test]
    fn integer_at_exactly_max_obeyed_passes_through() {
        let exactly = MAX_OBEYED.as_secs().to_string();
        assert_eq!(parse(&exactly, t0()), Some(MAX_OBEYED));
    }

    // ── jittered backoff ────────────────────────────────────────────

    #[test]
    fn jitter_is_bounded_in_eighty_to_one_twenty_percent() {
        // For every nonce in a wide window, the result must be within
        // ±20% of the base — never below 80% (would hammer the target
        // faster than the user's intent) and never above 120% (would
        // over-sleep on a tight time budget).
        let base = Duration::from_millis(1000);
        let lo = Duration::from_millis(800);
        let hi = Duration::from_millis(1200);
        for n in 0..10_000_u32 {
            let j = jittered(base, n);
            assert!(
                j >= lo && j <= hi,
                "nonce {n}: {:?} outside [{:?}, {:?}]",
                j,
                lo,
                hi
            );
        }
    }

    #[test]
    fn jitter_of_zero_base_is_zero_no_overflow() {
        // Anti-rig: a zero base must never become a nonzero sleep — the
        // caller is signalling "do not pause" and we must honour it.
        for n in 0..1000_u32 {
            assert_eq!(jittered(Duration::ZERO, n), Duration::ZERO);
        }
    }

    #[test]
    fn jitter_is_deterministic_per_nonce() {
        // Same (base, nonce) ⇒ same Duration — required for
        // reproducible scan traces.
        let base = Duration::from_millis(500);
        for n in [0, 1, 42, 9_999, u32::MAX] {
            assert_eq!(jittered(base, n), jittered(base, n));
        }
    }

    #[test]
    fn jitter_varies_across_adjacent_nonces() {
        // Anti-rig: a degenerate "always return base × 1.0" would still
        // satisfy the bounded-range test. Adjacent nonces must produce
        // a non-trivially diverse multiplier set so we are not
        // accidentally aligning with other clients on the same window.
        let base = Duration::from_millis(1000);
        let set: std::collections::HashSet<Duration> =
            (0..64_u32).map(|n| jittered(base, n)).collect();
        assert!(
            set.len() >= 20,
            "only {} distinct durations across 64 nonces — jitter is degenerate",
            set.len()
        );
    }

    #[test]
    fn jitter_does_not_overflow_on_huge_base() {
        // u64::MAX nanos would overflow the milli-multiplier math
        // unless saturating_mul is in place; a one-hour base is the
        // realistic upper bound and must compute cleanly.
        let big = Duration::from_secs(3600);
        let j = jittered(big, 7);
        assert!(j >= Duration::from_secs(2880) && j <= Duration::from_secs(4320));
    }
}
