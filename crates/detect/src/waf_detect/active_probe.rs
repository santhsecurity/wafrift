//! Active probing for WAF detection via response-difference fingerprinting.
//!
//! This module is I/O-free: it defines probe payloads and provides a
//! classifier that consumes a benign baseline response plus one or more
//! probed responses, computes [`FingerprintDrift`], and returns a ranked
//! list of likely WAF families based on drift patterns.

use crate::response_fingerprint::{FingerprintDrift, ResponseFingerprint, compare, fingerprint};
use crate::waf_detect::DetectedWaf;

/// A single probe payload definition.
#[derive(Debug, Clone)]
pub struct ProbePayload {
    pub label: &'static str,
    pub payload: &'static str,
    pub category: ProbeCategory,
}

/// Category of attack simulated by the probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeCategory {
    Xss,
    Sqli,
    PathTraversal,
}

/// Result of running one active probe against a target.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub payload: &'static ProbePayload,
    pub baseline: ResponseFingerprint,
    pub probed: ResponseFingerprint,
    pub drift: FingerprintDrift,
}

/// Returns the standard probe set: one XSS, one SQLi, one path-traversal.
///
/// All payloads are benign in structure (no actual exploitation) but
/// contain substrings that are widely blocked by WAF signatures.
#[must_use]
pub fn probe_set() -> &'static [ProbePayload] {
    &[
        ProbePayload {
            label: "xss_probe",
            payload: "<script>alert('waf_probe')</script>",
            category: ProbeCategory::Xss,
        },
        ProbePayload {
            label: "sqli_probe",
            payload: "' OR '1'='1' -- waf_probe",
            category: ProbeCategory::Sqli,
        },
        ProbePayload {
            label: "path_traversal_probe",
            payload: "../../../etc/passwd?waf_probe=1",
            category: ProbeCategory::PathTraversal,
        },
    ]
}

/// Build a [`ProbeResult`] from pre-recorded baseline and probed responses.
///
/// This function is I/O-free; the caller (transport layer, CLI, or test
/// harness) is responsible for sending the actual HTTP requests.
#[must_use]
pub fn active_probe(
    payload: &'static ProbePayload,
    baseline_status: u16,
    baseline_headers: &[(String, String)],
    baseline_body: &[u8],
    probed_status: u16,
    probed_headers: &[(String, String)],
    probed_body: &[u8],
) -> ProbeResult {
    let baseline = fingerprint(baseline_status, baseline_headers, baseline_body);
    let probed = fingerprint(probed_status, probed_headers, probed_body);
    let drift = compare(&baseline, &probed);
    ProbeResult {
        payload,
        baseline,
        probed,
        drift,
    }
}

/// Weight when 100 % of probes are blocked.
const ALL_BLOCKED_WEIGHT: f64 = 0.50;
/// Weight when ≥50 % of probes are blocked.
const MAJORITY_BLOCKED_WEIGHT: f64 = 0.30;
/// Threshold for "majority" of probes blocked.
const MAJORITY_BLOCKED_THRESHOLD: f64 = 0.50;
/// Weight for high average drift (≥0.6).
const HIGH_DRIFT_WEIGHT: f64 = 0.30;
/// Weight for moderate average drift (≥0.4).
const MODERATE_DRIFT_WEIGHT: f64 = 0.20;
/// Threshold for high average drift.
const HIGH_DRIFT_THRESHOLD: f64 = 0.60;
/// Threshold for moderate average drift.
const MODERATE_DRIFT_THRESHOLD: f64 = 0.40;
/// Weight for uniform 4xx status across all probes.
const UNIFORM_BLOCK_STATUS_WEIGHT: f64 = 0.10;
/// Weight when the title tag changes on every probe.
const UNIVERSAL_TITLE_CHANGE_WEIGHT: f64 = 0.20;

/// Classify a collection of probe results into likely WAF detections.
///
/// The classifier looks at drift patterns across the probe set and
/// assigns confidence scores based on how strongly the responses
/// diverged from baseline.  Heavy drift with block markers is treated
/// as a strong WAF signal, but the specific WAF family is inferred
/// from drift characteristics rather than banner strings.
#[must_use]
pub fn classify_drift(results: &[ProbeResult]) -> Vec<DetectedWaf> {
    let mut score: f64 = 0.0;
    let mut indicators = Vec::new();

    let blocked_count = results.iter().filter(|r| r.drift.likely_blocked).count();
    let total = results.len().max(1);
    let block_rate = blocked_count as f64 / total as f64;

    if block_rate >= 1.0 {
        score += ALL_BLOCKED_WEIGHT;
        indicators.push("all probes blocked".into());
    } else if block_rate >= MAJORITY_BLOCKED_THRESHOLD {
        score += MAJORITY_BLOCKED_WEIGHT;
        indicators.push("majority of probes blocked".into());
    }

    // High average drift score
    let avg_drift: f64 = results.iter().map(|r| r.drift.score).sum::<f64>() / total as f64;
    if avg_drift >= HIGH_DRIFT_THRESHOLD {
        score += HIGH_DRIFT_WEIGHT;
        indicators.push(format!("high avg drift {:.0}%", avg_drift * 100.0));
    } else if avg_drift >= MODERATE_DRIFT_THRESHOLD {
        score += MODERATE_DRIFT_WEIGHT;
        indicators.push(format!("moderate avg drift {:.0}%", avg_drift * 100.0));
    }

    // Status-code consistency (all same status) suggests automated block
    let statuses: std::collections::HashSet<u16> =
        results.iter().map(|r| r.probed.status).collect();
    if let Some(status) = (statuses.len() == 1)
        .then(|| statuses.iter().next().copied())
        .flatten()
        && status >= 400
    {
        score += UNIFORM_BLOCK_STATUS_WEIGHT;
        indicators.push(format!("uniform block status {status}"));
    }

    // Title-tag changes across all probes are a strong silent-block signal
    let title_changes = results
        .iter()
        .filter(|r| r.drift.changed.contains(&"title_tag"))
        .count();
    if title_changes == total {
        score += UNIVERSAL_TITLE_CHANGE_WEIGHT;
        indicators.push("title changed on every probe".into());
    }

    if score > 0.0 {
        vec![DetectedWaf {
            name: "Active-Probe-Generic".into(),
            confidence: score.min(1.0),
            indicators,
        }]
    } else {
        Vec::new()
    }
}
