//! I/O-free adversarial tests for [`active_probe`] and [`classify_drift`]
//! using synthetic baseline/probed fingerprints (no HTTP).

use wafrift_detect::waf_detect::{ProbePayload, active_probe, classify_drift, probe_set};

#[cfg(test)]
mod helpers {
    use super::*;

    pub fn baseline_tuple() -> (u16, Vec<(String, String)>, Vec<u8>) {
        let headers = vec![
            ("content-type".into(), "text/html".into()),
            ("server".into(), "nginx".into()),
        ];
        let body = b"<html><head><title>Welcome</title></head><body>ok</body></html>".to_vec();
        (200, headers, body)
    }

    pub fn blocked_probe_tuple() -> (u16, Vec<(String, String)>, Vec<u8>) {
        let headers = vec![("content-type".into(), "text/html".into())];
        let body =
            b"<html><head><title>Access Denied</title></head><body>Request blocked</body></html>"
                .to_vec();
        (403, headers, body)
    }

    pub fn synthetic_probe_result(
        payload: &'static ProbePayload,
        probed_status: u16,
        probed_body: &[u8],
    ) -> wafrift_detect::ProbeResult {
        let (b_status, b_headers, b_body) = baseline_tuple();
        active_probe(
            payload,
            b_status,
            &b_headers,
            &b_body,
            probed_status,
            &b_headers,
            probed_body,
        )
    }
}

use helpers::{baseline_tuple, blocked_probe_tuple, synthetic_probe_result};

#[test]
fn probe_set_has_three_categories() {
    let set = probe_set();
    assert_eq!(set.len(), 3);
    let labels: Vec<_> = set.iter().map(|p| p.label).collect();
    assert!(labels.iter().any(|l| l.contains("xss")));
    assert!(labels.iter().any(|l| l.contains("sqli")));
    assert!(labels.iter().any(|l| l.contains("path")));
}

#[test]
fn active_probe_identical_responses_yield_zero_drift_score() {
    let payload = &probe_set()[0];
    let (status, headers, body) = baseline_tuple();
    let result = active_probe(payload, status, &headers, &body, status, &headers, &body);
    assert!(
        result.drift.score < 0.05,
        "identical fingerprints should not drift, got {}",
        result.drift.score
    );
    assert!(!result.drift.likely_blocked);
}

#[test]
fn classify_drift_empty_results_is_benign() {
    assert!(classify_drift(&[]).is_empty());
}

#[test]
fn classify_drift_all_blocked_probes_scores_high() {
    let results: Vec<_> = probe_set()
        .iter()
        .map(|p| {
            let (status, _, body) = blocked_probe_tuple();
            synthetic_probe_result(p, status, &body)
        })
        .collect();

    let wafs = classify_drift(&results);
    assert_eq!(wafs.len(), 1);
    assert_eq!(wafs[0].name, "Active-Probe-Generic");
    assert!(
        wafs[0].confidence >= 0.5,
        "all-blocked probe set should score highly: {}",
        wafs[0].confidence
    );
    assert!(
        wafs[0]
            .indicators
            .iter()
            .any(|i| i.contains("all probes blocked")),
        "indicators: {:?}",
        wafs[0].indicators
    );
}

#[test]
fn classify_drift_benign_probes_stay_empty() {
    let (status, headers, body) = baseline_tuple();
    let results: Vec<_> = probe_set()
        .iter()
        .map(|p| active_probe(p, status, &headers, &body, status, &headers, &body))
        .collect();
    assert!(classify_drift(&results).is_empty());
}

#[test]
fn classify_drift_title_change_on_every_probe_adds_weight() {
    let mut results = Vec::new();
    for p in probe_set() {
        let (b_status, b_headers, b_body) = baseline_tuple();
        let probed_body = b"<html><head><title>Blocked</title></head></html>";
        results.push(active_probe(
            p,
            b_status,
            &b_headers,
            &b_body,
            200,
            &b_headers,
            probed_body,
        ));
    }
    let wafs = classify_drift(&results);
    assert!(!wafs.is_empty());
    assert!(
        wafs[0]
            .indicators
            .iter()
            .any(|i| i.contains("title changed")),
        "indicators: {:?}",
        wafs[0].indicators
    );
}
