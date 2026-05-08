//! Per-target calibration session.
//!
//! Records benign and blocked baseline fingerprints for a target,
//! then uses them to classify subsequent responses.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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

/// In-memory store of calibration sessions keyed by host.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CalibrationStore {
    sessions: HashMap<String, CalibrationSession>,
}

impl CalibrationStore {
    /// Get or create a session for a host.
    pub fn session(&mut self, host: &str) -> &mut CalibrationSession {
        self.sessions.entry(host.to_lowercase()).or_default()
    }

    /// Get an existing session (read-only).
    #[must_use]
    pub fn get(&self, host: &str) -> Option<&CalibrationSession> {
        self.sessions.get(&host.to_lowercase())
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

    #[test]
    fn store_roundtrip() {
        let mut store = CalibrationStore::default();
        store.session("example.com").record_benign(200, &[], b"ok");
        assert!(store.get("example.com").is_some());
        assert!(store.get("Example.COM").is_some());
    }
}
