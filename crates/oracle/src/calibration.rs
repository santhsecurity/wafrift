//! Per-target calibration session.
//!
//! Records benign and blocked baseline fingerprints for a target,
//! then uses them to classify subsequent responses.

use serde::{Deserialize, Serialize};
use crate::timing::TimingOracle;

/// Minimum number of latency samples before we prefer the statistical
/// TimingOracle over the heuristic 3x ratio oracle.
const MIN_STATISTICAL_SAMPLES: usize = 3;

/// A fingerprint of an HTTP response for baseline comparison.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseFingerprint {
    /// HTTP status code.
    pub status: u16,
    /// Content-Length header value (if present).
    pub content_length: Option<usize>,
    /// Normalized body hash (simple length-based proxy).
    pub body_length: usize,
    /// Set of header names present.
    pub header_names: Vec<String>,
}

impl ResponseFingerprint {
    /// Build a fingerprint from raw response data.
    #[must_use]
    pub fn from_response(status: u16, headers: &[(String, String)], body: &[u8]) -> Self {
        let content_length = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, v)| v.parse().ok());
        let header_names: Vec<String> = headers
            .iter()
            .map(|(k, _)| k.to_ascii_lowercase())
            .collect();
        Self {
            status,
            content_length,
            body_length: body.len(),
            header_names,
        }
    }
}

/// Calibration state for a single target.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationSession {
    /// Baseline fingerprint for a known-safe request.
    pub benign: Option<ResponseFingerprint>,
    /// Baseline fingerprint for a known-blocked request.
    pub blocked: Option<ResponseFingerprint>,
    /// Observed benign request round-trip latency (ms), for response-time classification.
    #[serde(default)]
    pub benign_latency_ms: Option<u64>,
    /// Observed blocked baseline latency (ms).
    #[serde(default)]
    pub blocked_latency_ms: Option<u64>,
    /// Multi-sample benign latency buffer (ms) for statistical timing oracle.
    ///
    /// When len >= MIN_STATISTICAL_SAMPLES, build_timing_oracle() returns a
    /// statistically-grounded TimingOracle (mean + 3*sigma threshold).
    #[serde(default)]
    pub benign_latency_samples_ms: Vec<u64>,
}

impl CalibrationSession {
    /// Record the benign baseline.
    pub fn record_benign(&mut self, status: u16, headers: &[(String, String)], body: &[u8]) {
        self.benign = Some(ResponseFingerprint::from_response(status, headers, body));
    }

    /// Record the benign baseline and measured latency for timing signals.
    pub fn record_benign_with_latency(
        &mut self,
        status: u16,
        headers: &[(String, String)],
        body: &[u8],
        latency_ms: u64,
    ) {
        self.record_benign(status, headers, body);
        self.benign_latency_ms = Some(latency_ms);
        self.benign_latency_samples_ms.push(latency_ms);
    }

    /// Record the blocked baseline.
    pub fn record_blocked(&mut self, status: u16, headers: &[(String, String)], body: &[u8]) {
        self.blocked = Some(ResponseFingerprint::from_response(status, headers, body));
    }

    /// Record the blocked baseline and measured latency.
    pub fn record_blocked_with_latency(
        &mut self,
        status: u16,
        headers: &[(String, String)],
        body: &[u8],
        latency_ms: u64,
    ) {
        self.record_blocked(status, headers, body);
        self.blocked_latency_ms = Some(latency_ms);
    }

    /// Returns true if both baselines have been recorded.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.benign.is_some() && self.blocked.is_some()
    }

    /// Build a statistical TimingOracle from accumulated benign latency samples.
    ///
    /// Returns Some(oracle) when at least MIN_STATISTICAL_SAMPLES (3) latency
    /// samples have been collected via record_benign_with_latency. The oracle
    /// uses mean + 3*sigma (Chebyshev false-positive rate <= 11%), far tighter
    /// than the 3x ratio heuristic on low-variance targets.
    ///
    /// Returns None when fewer samples exist; ResponseOracle falls back to
    /// classify_response_time (the 3x ratio signal) in that case.
    #[must_use]
    pub fn build_timing_oracle(&self) -> Option<TimingOracle> {
        if self.benign_latency_samples_ms.len() < MIN_STATISTICAL_SAMPLES {
            return None;
        }
        let samples_f64: Vec<f64> = self
            .benign_latency_samples_ms
            .iter()
            .map(|&ms| ms as f64)
            .collect();
        Some(TimingOracle::from_calibration(&samples_f64))
    }

    /// Compute drift between a response and the benign baseline.
    #[must_use]
    pub fn drift_from_benign(&self, status: u16, body_len: usize) -> Option<DriftScore> {
        self.benign.as_ref().map(|base| DriftScore {
            status_delta: status.abs_diff(base.status),
            body_length_delta: body_len.abs_diff(base.body_length),
        })
    }

    /// Compute drift between a response and the blocked baseline.
    #[must_use]
    pub fn drift_from_blocked(&self, status: u16, body_len: usize) -> Option<DriftScore> {
        self.blocked.as_ref().map(|base| DriftScore {
            status_delta: status.abs_diff(base.status),
            body_length_delta: body_len.abs_diff(base.body_length),
        })
    }
}

/// A simple drift score between a response and a baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriftScore {
    /// Absolute difference in status code.
    pub status_delta: u16,
    /// Absolute difference in body length.
    pub body_length_delta: usize,
}

impl DriftScore {
    /// Returns true if this response looks more like the benign baseline
    /// than the other score.
    #[must_use]
    pub fn is_closer_than(&self, other: &Self) -> bool {
        self.status_delta < other.status_delta
            || (self.status_delta == other.status_delta
                && self.body_length_delta < other.body_length_delta)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_from_response() {
        let fp = ResponseFingerprint::from_response(
            200,
            &[("Content-Length".into(), "12".into())],
            b"hello world!",
        );
        assert_eq!(fp.status, 200);
        assert_eq!(fp.content_length, Some(12));
        assert_eq!(fp.body_length, 12);
        assert!(fp.header_names.contains(&"content-length".to_string()));
    }

    #[test]
    fn calibration_complete() {
        let mut cal = CalibrationSession::default();
        assert!(!cal.is_complete());
        cal.record_benign(200, &[], b"ok");
        assert!(!cal.is_complete());
        cal.record_blocked(403, &[], b"blocked");
        assert!(cal.is_complete());
    }

    #[test]
    fn record_benign_with_latency_stores_ms() {
        let mut cal = CalibrationSession::default();
        cal.record_benign_with_latency(200, &[], b"x", 77);
        assert_eq!(cal.benign_latency_ms, Some(77));
        assert_eq!(cal.benign_latency_samples_ms, vec![77]);
    }

    #[test]
    fn drift_scores() {
        let mut cal = CalibrationSession::default();
        cal.record_benign(200, &[], b"x".repeat(100).as_slice());
        cal.record_blocked(403, &[], b"y".repeat(200).as_slice());

        let benign_drift = cal.drift_from_benign(200, 100).unwrap();
        let blocked_drift = cal.drift_from_blocked(200, 100).unwrap();

        assert!(benign_drift.is_closer_than(&blocked_drift));
    }

    // -- Section 11 UTILIZATION: build_timing_oracle wire-in ---------------

    #[test]
    fn build_timing_oracle_zero_samples_returns_none() {
        let cal = CalibrationSession::default();
        assert!(cal.build_timing_oracle().is_none());
    }

    #[test]
    fn build_timing_oracle_one_sample_below_min_returns_none() {
        let mut cal = CalibrationSession::default();
        cal.record_benign_with_latency(200, &[], b"ok", 100);
        assert!(cal.build_timing_oracle().is_none(), "1 sample < MIN=3");
    }

    #[test]
    fn build_timing_oracle_two_samples_below_min_returns_none() {
        let mut cal = CalibrationSession::default();
        cal.record_benign_with_latency(200, &[], b"ok", 100);
        cal.record_benign_with_latency(200, &[], b"ok", 110);
        assert!(cal.build_timing_oracle().is_none(), "2 samples < MIN=3");
    }

    #[test]
    fn build_timing_oracle_at_min_samples_returns_oracle() {
        let mut cal = CalibrationSession::default();
        for ms in [100u64, 110, 105] {
            cal.record_benign_with_latency(200, &[], b"ok", ms);
        }
        let oracle = cal.build_timing_oracle().expect("3 samples must yield oracle");
        // Normal jitter -- not anomalous.
        assert!(!oracle.is_anomalous(120.0));
        // 9 second delay -- clearly anomalous.
        assert!(oracle.is_anomalous(9_000.0));
    }

    /// Statistical threshold is strictly tighter than the crude 3x ratio on
    /// low-variance targets. Pre-fix: all classification used the 3x heuristic,
    /// giving a 300 ms threshold for a 100 ms target (too permissive).
    /// Post-fix: 5 samples around 100 ms -> threshold ~105 ms (mean + 3*sigma).
    #[test]
    fn build_timing_oracle_threshold_tighter_than_3x_ratio() {
        let mut cal = CalibrationSession::default();
        for ms in [98u64, 100, 101, 99, 102] {
            cal.record_benign_with_latency(200, &[], b"ok", ms);
        }
        let oracle = cal.build_timing_oracle().expect("5 samples must yield oracle");
        let threshold = oracle.threshold_ms();
        // 3x ratio would give 300 ms; statistical oracle gives ~105 ms.
        assert!(
            threshold < 200.0,
            "stat threshold {threshold} must be < 200 (3x heuristic gives 300)"
        );
        assert!(oracle.is_anomalous(200.0), "200ms must be anomalous with ~105ms threshold");
    }

    /// All accumulated samples contribute -- not just the last one.
    #[test]
    fn build_timing_oracle_uses_all_accumulated_samples() {
        let mut cal = CalibrationSession::default();
        for ms in [1_000u64, 1_100, 1_050] {
            cal.record_benign_with_latency(200, &[], b"ok", ms);
        }
        assert_eq!(cal.benign_latency_samples_ms.len(), 3);
        let oracle = cal.build_timing_oracle().unwrap();
        // 10 second delay is clearly anomalous vs ~1050 ms baseline.
        assert!(oracle.is_anomalous(10_000.0));
        // 1100 ms is within normal jitter for this baseline.
        assert!(!oracle.is_anomalous(1_100.0));
    }


}