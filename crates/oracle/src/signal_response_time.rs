//! Response-time anomaly signal extractor.
//!
//! Detects when a response time deviates significantly from a learned
//! baseline for the target.

use wafrift_types::Signal;

/// Threshold multiplier: a response is considered anomalous if it takes
/// more than `BASELINE_MULTIPLIER` times the baseline, or less than
/// `1/BASELINE_MULTIPLIER`.
const BASELINE_MULTIPLIER: f64 = 3.0;

/// Minimum baseline in milliseconds to avoid division issues. R55
/// pass-18 I5 (CLAUDE.md §7 DEDUP): named distinctly from
/// `timing::MIN_TIMING_ORACLE_BASELINE_MS` (50.0 f64) because the two
/// floors apply to different oracle semantics — this one is a
/// signal-extraction divide-by-zero guard, the other is the
/// online-mean lower bound used by the bias-aware timing oracle.
/// Different name = no collision = no silent drift when one is tuned.
const MIN_SIGNAL_BASELINE_MS: u64 = 10;

/// Compare an observed response time against a baseline.
///
/// Returns `Some(Signal::ResponseTimeAnomaly)` if the deviation is
/// significant, otherwise `None`.
#[must_use]
pub fn classify_response_time(baseline_ms: u64, actual_ms: u64) -> Option<Signal> {
    let baseline = baseline_ms.max(MIN_SIGNAL_BASELINE_MS);
    let actual = actual_ms.max(1);

    let ratio = actual as f64 / baseline as f64;
    if (1.0 / BASELINE_MULTIPLIER..=BASELINE_MULTIPLIER).contains(&ratio) {
        None
    } else {
        Some(Signal::ResponseTimeAnomaly {
            baseline_ms,
            actual_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_time_no_signal() {
        assert!(classify_response_time(100, 120).is_none());
        assert!(classify_response_time(100, 80).is_none());
    }

    #[test]
    fn slow_time_signal() {
        let s = classify_response_time(100, 400).unwrap();
        assert!(matches!(
            s,
            Signal::ResponseTimeAnomaly {
                baseline_ms: 100,
                actual_ms: 400
            }
        ));
    }

    #[test]
    fn fast_time_signal() {
        let s = classify_response_time(1000, 10).unwrap();
        assert!(matches!(
            s,
            Signal::ResponseTimeAnomaly {
                baseline_ms: 1000,
                actual_ms: 10
            }
        ));
    }
    // -- Section 12 TESTING: boundary tests at the 3x threshold ------------

    /// Exact 3x upper bound: not anomalous (inclusive range).
    #[test]
    fn boundary_at_3x_upper_not_anomalous() {
        // 300ms vs 100ms baseline: ratio = 3.0, which is IN [1/3, 3] => no signal.
        assert!(classify_response_time(100, 300).is_none(), "exact 3x must NOT trigger");
    }

    /// One past 3x upper bound: anomalous.
    #[test]
    fn boundary_just_above_3x_is_anomalous() {
        // 301ms vs 100ms baseline: ratio = 3.01 > 3.0 => signal.
        assert!(classify_response_time(100, 301).is_some(), "3.01x must trigger");
    }

    /// Exact 1/3 lower bound: not anomalous.
    #[test]
    fn boundary_at_lower_third_not_anomalous() {
        // 33ms vs 100ms baseline: ratio ~ 0.33, floor of 1/3 => not anomalous.
        // We use 34 which is still >= 1/3 (0.34 > 0.333...).
        assert!(classify_response_time(100, 34).is_none(), "34ms vs 100ms must not trigger");
    }

    /// Just below 1/3 lower bound: anomalous.
    #[test]
    fn boundary_just_below_lower_third_is_anomalous() {
        // 33ms vs 100ms: ratio = 0.33 < 1/3 (0.333...) => signal.
        assert!(classify_response_time(100, 33).is_some(), "33ms vs 100ms must trigger");
    }

    /// Zero baseline is floored to MIN_SIGNAL_BASELINE_MS (10ms).
    #[test]
    fn zero_baseline_uses_floor() {
        // Passing 0 must not panic; it uses the 10ms floor.
        let result = classify_response_time(0, 100);
        // 100ms vs 10ms floor = 10x > 3 => anomalous.
        assert!(result.is_some(), "100ms vs 0-baseline (floored to 10ms) must trigger");
        if let Some(s) = result {
            // The *reported* baseline_ms is the original 0, not the floor.
            assert!(matches!(s, wafrift_types::Signal::ResponseTimeAnomaly { baseline_ms: 0, .. }));
        }
    }

    /// Zero actual is floored to 1ms.
    #[test]
    fn zero_actual_uses_floor() {
        // 0ms actual vs 100ms baseline: 1/100 = 0.01 << 1/3 => anomalous.
        let result = classify_response_time(100, 0);
        assert!(result.is_some(), "0ms actual vs 100ms baseline must trigger");
    }

    /// MIN_SIGNAL_BASELINE_MS floor: baseline of 5 acts as 10.
    #[test]
    fn sub_min_baseline_floored_to_min() {
        // 5ms baseline, 25ms actual: without floor ratio=5 (>3), with floor (10ms) ratio=2.5 (<3).
        // The floor suppresses the signal.
        assert!(classify_response_time(5, 25).is_none(), "floor to 10ms makes 25/10=2.5 not anomalous");
        // 35ms actual: 35/10 = 3.5 > 3 => anomalous even with the floor.
        assert!(classify_response_time(5, 35).is_some(), "35/10=3.5 must trigger");
    }

}
