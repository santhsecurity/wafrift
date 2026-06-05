//! Integration tests for #128 — ensemble dilution wiring.
//!
//! Covers: dilution=0 unchanged from baseline, dilution=1 only dilution
//! matters, known-good dilutive payload scores higher than known-bad,
//! fingerprint gating (no effect on non-ensemble WAFs), determinism.

use wafrift_evolution::dilution::{
    DEFAULT_DILUTION_THRESHOLD, compute_dilution_score, default_estimator,
    dilution_adjusted_fitness, is_ensemble_waf,
};
use wafrift_types::EvasionConfig;
use wafrift_wafmodel::ensemble_dilution::{RuleGroup, SubScoreEstimator};

fn config_with_weight(w: f64) -> EvasionConfig {
    EvasionConfig { dilution_weight: w, ..Default::default() }
}

// ── Test 1: dilution_weight=0.0 leaves oracle fitness unchanged ──────────────

#[test]
fn dilution_weight_zero_no_change_from_baseline() {
    let est = default_estimator();
    let oracle_fitness = 0.42;
    let cfg = config_with_weight(0.0);

    let adj = dilution_adjusted_fitness(
        oracle_fitness,
        "' UNION SELECT 1,2--",
        &est,
        DEFAULT_DILUTION_THRESHOLD,
        &cfg,
        "Cloudflare WAF",
    );
    assert_eq!(
        adj, oracle_fitness,
        "weight=0 must leave oracle fitness exactly unchanged"
    );
}

// ── Test 2: dilution_weight=1.0 → only dilution matters ──────────────────────

#[test]
fn dilution_weight_one_pure_dilution_score() {
    let est = default_estimator();
    let cfg = config_with_weight(1.0);

    // Pre-compute the pure dilution score for this payload.
    let dilution_only = compute_dilution_score(
        "' UNION SELECT 1,2--",
        &est,
        DEFAULT_DILUTION_THRESHOLD,
    );

    // With weight=1.0, oracle fitness (0.0 = fully blocked) should not matter.
    let adj = dilution_adjusted_fitness(
        0.0,
        "' UNION SELECT 1,2--",
        &est,
        DEFAULT_DILUTION_THRESHOLD,
        &cfg,
        "Cloudflare WAF",
    );

    assert!(
        (adj - dilution_only).abs() < 1e-9,
        "weight=1.0: expected {dilution_only}, got {adj}"
    );
}

// ── Test 3: known-good dilutive payload scores higher than known-bad ──────────

#[test]
fn dilutive_payload_scores_higher_than_non_dilutive() {
    // "Good" payload: SQLi in a LOW-score group → easy to dilute below threshold.
    let mut est_friendly = SubScoreEstimator::new(5.0, 0.1);
    *est_friendly
        .coeffs
        .get_mut(&RuleGroup::SqlInjection)
        .unwrap() = 2.0; // low contribution → predicted total well below threshold

    // "Bad" payload: SQLi in a HIGH-score group → hard to dilute below threshold.
    let mut est_hostile = SubScoreEstimator::new(5.0, 0.1);
    *est_hostile
        .coeffs
        .get_mut(&RuleGroup::SqlInjection)
        .unwrap() = 35.0; // high contribution → predicted total above threshold

    let threshold = 30.0;
    let payload = "' UNION SELECT--";

    let score_good = compute_dilution_score(payload, &est_friendly, threshold);
    let score_bad = compute_dilution_score(payload, &est_hostile, threshold);

    assert!(
        score_good >= score_bad,
        "dilutive payload (good) should score >= non-dilutive (bad): {score_good} vs {score_bad}"
    );
}

// ── Test 4: fingerprint gating — non-ensemble WAF → no effect ────────────────

#[test]
fn non_ensemble_waf_dilution_has_no_effect() {
    let est = default_estimator();
    let oracle_fitness = 0.65;
    let cfg = config_with_weight(1.0); // maximum weight — still must be ignored

    // Unknown / non-ensemble WAF names.
    for non_ensemble in &[
        "SomeRandomVendor",
        "F5 AWAF",
        "AWS Bot Control",   // ML-backed, not ensemble
        "Cloudflare Bot Management", // ML-backed, not ensemble
    ] {
        let adj = dilution_adjusted_fitness(
            oracle_fitness,
            "' UNION SELECT--",
            &est,
            DEFAULT_DILUTION_THRESHOLD,
            &cfg,
            non_ensemble,
        );
        assert_eq!(
            adj, oracle_fitness,
            "non-ensemble WAF '{non_ensemble}': must not affect fitness, got {adj}"
        );
    }
}

// ── Test 5: determinism — same seed+payload → same score ─────────────────────

#[test]
fn deterministic_same_inputs_same_score() {
    let est = default_estimator();
    let cfg = config_with_weight(0.3);
    let payload = "' UNION SELECT 1,2,3--";
    let waf = "Cloudflare WAF";

    let s1 = dilution_adjusted_fitness(
        0.5,
        payload,
        &est,
        DEFAULT_DILUTION_THRESHOLD,
        &cfg,
        waf,
    );
    let s2 = dilution_adjusted_fitness(
        0.5,
        payload,
        &est,
        DEFAULT_DILUTION_THRESHOLD,
        &cfg,
        waf,
    );

    assert_eq!(s1, s2, "same inputs must produce same score (determinism)");
}

// ── Test 6: ensemble WAF names are recognized ─────────────────────────────────

#[test]
fn ensemble_waf_names_recognized() {
    // Cloudflare and AWS CRS are the canonical ensemble WAFs per the task spec.
    // OWASP CRS / GenericCrs is also ensemble. ModSecurity with pure anomaly
    // scoring maps to GenericCrs via the "crs"/"owasp" substring match.
    let ensemble_names = [
        "Cloudflare WAF",
        "cloudflare",
        "AWS WAF",
        "aws",
        "amazon",
        "OWASP CRS",
        "crs",
    ];
    for name in ensemble_names {
        assert!(
            is_ensemble_waf(name),
            "expected '{name}' to be recognized as ensemble WAF"
        );
    }
}

// ── Test 7: result is always in [0.0, 1.0] ───────────────────────────────────

#[test]
fn adjusted_fitness_always_in_unit_interval() {
    let est = default_estimator();
    let payloads = [
        "' UNION SELECT 1,2,3--",
        "<script>alert(1)</script>",
        "../../../etc/passwd",
        "$(system('id'))",
        "hello world",
    ];
    let weights = [0.0, 0.1, 0.3, 0.5, 0.7, 1.0];
    let oracles = [0.0, 0.25, 0.5, 0.75, 1.0];

    for payload in payloads {
        for &w in &weights {
            for &oracle in &oracles {
                let cfg = EvasionConfig { dilution_weight: w, ..Default::default() };
                let adj = dilution_adjusted_fitness(
                    oracle,
                    payload,
                    &est,
                    DEFAULT_DILUTION_THRESHOLD,
                    &cfg,
                    "Cloudflare WAF",
                );
                assert!(
                    (0.0..=1.0).contains(&adj),
                    "out of [0,1]: payload={payload:?} w={w} oracle={oracle} → {adj}"
                );
            }
        }
    }
}
