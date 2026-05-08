//! Response-time anomaly signal extractor.
//!
//! Detects when a response time deviates significantly from a learned
//! baseline for the target.

use wafrift_types::Signal;

/// Threshold multiplier: a response is considered anomalous if it takes
/// more than `BASELINE_MULTIPLIER` times the baseline, or less than
/// `1/BASELINE_MULTIPLIER`.
const BASELINE_MULTIPLIER: f64 = 3.0;

/// Minimum baseline in milliseconds to avoid division issues.
const MIN_BASELINE_MS: u64 = 10;

/// Compare an observed response time against a baseline.
///
/// Returns `Some(Signal::ResponseTimeAnomaly)` if the deviation is
/// significant, otherwise `None`.
#[must_use]
pub fn classify_response_time(baseline_ms: u64, actual_ms: u64) -> Option<Signal> {
    let baseline = baseline_ms.max(MIN_BASELINE_MS);
    let actual = actual_ms.max(1);

    let ratio = actual as f64 / baseline as f64;
    if !(1.0 / BASELINE_MULTIPLIER..=BASELINE_MULTIPLIER).contains(&ratio) {
        Some(Signal::ResponseTimeAnomaly {
            baseline_ms,
            actual_ms,
        })
    } else {
        None
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
}
