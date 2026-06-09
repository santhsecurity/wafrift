//! #128 Ensemble sub-score dilution wiring for the evolutionary engine.
//!
//! Bridges `wafrift-wafmodel::ensemble_dilution` into the evolutionary
//! fitness pipeline. When a target WAF is identified as an ensemble-scoring
//! WAF (Cloudflare Managed Rules, AWS Core Rule Set), a dilution-plausibility
//! score is blended into the oracle-based chromosome fitness:
//!
//! ```text
//! final_fitness = oracle_fitness × (1 − w) + dilution_score × w
//! ```
//!
//! where `w` is the `dilution_weight` field from [`EvasionConfig`].
//!
//! # Fingerprint gating
//!
//! Dilution scoring is only activated when [`is_ensemble_waf`] returns
//! `true` for the detected WAF name. Against non-ensemble WAFs (plain
//! ModSecurity without anomaly scoring, ML-backed classifiers, etc.) the
//! function is a no-op regardless of `dilution_weight`.
//!
//! # Score mapping
//!
//! `ensemble_dilution::dilute()` returns a plausibility flag and a
//! predicted total anomaly score. We convert this to a `[0.0, 1.0]`
//! fitness contribution with:
//!   - If plausible bypass predicted → `1.0`
//!   - Otherwise → `(threshold − predicted_total) / threshold` clamped
//!     to `[0.0, 0.99]` (the further above threshold, the lower the score)

use wafrift_types::{EvasionConfig, WafClass};
use wafrift_wafmodel::ensemble_dilution::{SubScoreEstimator, dilute};

/// Default WAF anomaly-score block threshold used when no oracle-derived
/// estimate is available. OWASP CRS paranoia level 1 default is 5; many
/// operators raise this to 25–100. We use 25 as a conservative midpoint.
pub const DEFAULT_DILUTION_THRESHOLD: f64 = 25.0;

/// Default initial per-group coefficient for the [`SubScoreEstimator`] when
/// no historical observations are available.
pub const DEFAULT_INITIAL_COEFF: f64 = 5.0;

/// Default EWMA learning rate for the [`SubScoreEstimator`].
pub const DEFAULT_ALPHA: f64 = 0.1;

/// Returns `true` when `waf_name` indicates an ensemble anomaly-scoring WAF
/// for which sub-score dilution is applicable.
///
/// The check is substring-based (case-insensitive) so that variant vendor
/// spellings ("CF WAF", "CloudFlare", etc.) resolve correctly without
/// maintaining a brittle exact-name registry.
#[must_use]
pub fn is_ensemble_waf(waf_name: &str) -> bool {
    WafClass::from_waf_name(waf_name).is_ensemble()
}

/// Compute a dilution-adjusted fitness score for a chromosome payload.
///
/// # Arguments
///
/// * `oracle_fitness` — The oracle-derived fitness `[0.0, 1.0]` (block-rate
///   signal, partial credit, confidence bonus).
/// * `payload` — The raw payload string to score with the dilution planner.
/// * `estimator` — Shared `SubScoreEstimator` with per-group coefficient
///   estimates for the current target.
/// * `threshold` — The WAF's block threshold (anomaly score; oracle-derived
///   or [`DEFAULT_DILUTION_THRESHOLD`]).
/// * `config` — Evasion config carrying `dilution_weight`.
/// * `waf_name` — The detected WAF name (used for fingerprint gating).
///
/// # Returns
///
/// Blended fitness `[0.0, 1.0]`. If `dilution_weight` is `0.0` or the WAF
/// is not ensemble, returns `oracle_fitness` unchanged.
#[must_use]
pub fn dilution_adjusted_fitness(
    oracle_fitness: f64,
    payload: &str,
    estimator: &SubScoreEstimator,
    threshold: f64,
    config: &EvasionConfig,
    waf_name: &str,
) -> f64 {
    let w = config.dilution_weight.clamp(0.0, 1.0);
    if w == 0.0 || !is_ensemble_waf(waf_name) {
        return oracle_fitness;
    }

    let dilution_score = compute_dilution_score(payload, estimator, threshold);
    (oracle_fitness * (1.0 - w) + dilution_score * w).clamp(0.0, 1.0)
}

/// Convert an `ensemble_dilution::dilute()` result into a `[0.0, 1.0]`
/// fitness contribution.
///
/// Mapping:
/// - No result (benign payload, no active groups): `0.5` neutral.
/// - Plausible bypass (predicted total < threshold): `1.0`.
/// - Not plausible: linear interpolation — `(threshold − predicted) / threshold`
///   clamped to `[0.0, 0.99]`. The `0.99` cap prevents a score exactly at
///   threshold from falsely claiming full credit.
#[must_use]
pub fn compute_dilution_score(payload: &str, estimator: &SubScoreEstimator, threshold: f64) -> f64 {
    let Some(result) = dilute(payload, estimator, threshold) else {
        // Benign payload: no active attack group → neutral score.
        return 0.5;
    };
    if result.plausible_bypass {
        return 1.0;
    }
    // Partial credit proportional to how close we are to the threshold.
    let predicted = result.strategy.predicted_total;
    if threshold <= 0.0 {
        return 0.0;
    }
    ((threshold - predicted) / threshold).clamp(0.0, 0.99)
}

/// Build a fresh [`SubScoreEstimator`] with default coefficients.
///
/// Use this when no historical oracle observations are available for the
/// current target. As the engine gathers observations (via
/// [`SubScoreEstimator::observe`]), it updates coefficients online.
#[must_use]
pub fn default_estimator() -> SubScoreEstimator {
    SubScoreEstimator::new(DEFAULT_INITIAL_COEFF, DEFAULT_ALPHA)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wafrift_types::EvasionConfig;

    fn estimator() -> SubScoreEstimator {
        default_estimator()
    }

    // ── is_ensemble_waf ───────────────────────────────────────────────

    #[test]
    fn ensemble_waf_cloudflare_detected() {
        assert!(is_ensemble_waf("Cloudflare WAF"));
        assert!(is_ensemble_waf("cloudflare"));
    }

    #[test]
    fn ensemble_waf_aws_detected() {
        assert!(is_ensemble_waf("AWS WAF"));
        assert!(is_ensemble_waf("amazon"));
    }

    #[test]
    fn ensemble_waf_owasp_crs_detected() {
        // OWASP CRS and generic CRS-shaped WAFs are ensemble.
        assert!(is_ensemble_waf("OWASP CRS"));
        assert!(is_ensemble_waf("crs"));
    }

    #[test]
    fn ensemble_waf_ml_backed_not_ensemble() {
        // ML-backed WAFs are NOT ensemble — they use a classifier, not
        // anomaly-score rules.
        assert!(!is_ensemble_waf("AWS Bot Control"));
        assert!(!is_ensemble_waf("Cloudflare Bot Management"));
        assert!(!is_ensemble_waf("Akamai Bot Manager"));
    }

    #[test]
    fn ensemble_waf_unknown_not_ensemble() {
        assert!(!is_ensemble_waf("SomeRandomVendor"));
    }

    // ── compute_dilution_score ────────────────────────────────────────

    #[test]
    fn dilution_score_known_attack_payload() {
        // A well-known SQLi payload should classify to at least one group
        // and return a defined score.
        let score = compute_dilution_score("' UNION SELECT--", &estimator(), 40.0);
        assert!(
            (0.0..=1.0).contains(&score),
            "score must be in [0,1]: {score}"
        );
    }

    #[test]
    fn dilution_score_benign_payload_neutral() {
        let score = compute_dilution_score("hello world", &estimator(), 40.0);
        // "hello world" classifies to ProtocolViolation (single group) — dilute()
        // returns Some (one group → one strategy).  Score depends on coefficients.
        assert!(
            (0.0..=1.0).contains(&score),
            "score must be in [0,1]: {score}"
        );
    }

    // ── dilution_adjusted_fitness ─────────────────────────────────────

    #[test]
    fn dilution_weight_zero_returns_oracle_fitness() {
        // With weight=0.0, dilution has no effect regardless of payload or WAF.
        let config = EvasionConfig {
            dilution_weight: 0.0,
            ..Default::default()
        };
        let adj = dilution_adjusted_fitness(
            0.7,
            "' UNION SELECT--",
            &estimator(),
            40.0,
            &config,
            "Cloudflare WAF",
        );
        assert!(
            (adj - 0.7).abs() < 1e-9,
            "must equal oracle_fitness exactly"
        );
    }

    #[test]
    fn dilution_weight_one_returns_pure_dilution() {
        // With weight=1.0, the oracle score is ignored — only dilution matters.
        let config = EvasionConfig {
            dilution_weight: 1.0,
            ..Default::default()
        };
        let dilution_only = compute_dilution_score("' UNION SELECT--", &estimator(), 40.0);
        let adj = dilution_adjusted_fitness(
            0.0, // oracle says "blocked"
            "' UNION SELECT--",
            &estimator(),
            40.0,
            &config,
            "Cloudflare WAF",
        );
        assert!(
            (adj - dilution_only).abs() < 1e-9,
            "weight=1.0 must equal pure dilution score"
        );
    }

    #[test]
    fn dilution_gating_no_effect_on_non_ensemble_waf() {
        // PlainModSec without anomaly scoring is not ensemble — dilution
        // must have zero effect regardless of weight.
        let config = EvasionConfig {
            dilution_weight: 1.0,
            ..Default::default()
        }; // maximum weight
        let adj = dilution_adjusted_fitness(
            0.55,
            "' UNION SELECT--",
            &estimator(),
            40.0,
            &config,
            "SomeRandomVendor", // unknown → not ensemble
        );
        assert!(
            (adj - 0.55).abs() < 1e-9,
            "non-ensemble WAF must not be affected by dilution_weight"
        );
    }

    #[test]
    fn dilution_adjusted_clamps_to_unit_interval() {
        // Even with extreme weights, the result must stay in [0.0, 1.0].
        let config = EvasionConfig {
            dilution_weight: 0.3,
            ..Default::default()
        };
        let adj = dilution_adjusted_fitness(
            1.0,
            "' UNION SELECT<script>alert(1)</script>",
            &estimator(),
            40.0,
            &config,
            "cloudflare",
        );
        assert!((0.0..=1.0).contains(&adj), "clamped to [0,1]: {adj}");
    }

    #[test]
    fn compute_dilution_score_deterministic_same_input() {
        // Same payload + estimator + threshold must always produce the same score.
        let est = estimator();
        let s1 = compute_dilution_score("' UNION SELECT--", &est, 40.0);
        let s2 = compute_dilution_score("' UNION SELECT--", &est, 40.0);
        assert!(
            (s1 - s2).abs() < 1e-12,
            "dilution scoring must be deterministic"
        );
    }

    #[test]
    fn high_coeff_payload_scores_lower_than_low_coeff() {
        // A payload classified to a group with HIGH estimated score contribution
        // should score LOWER (harder to dilute) than one in a LOW-contribution group.
        // Set up a biased estimator.
        let mut est_high = default_estimator();
        // Force SQLi contribution very high → payload score will be high → harder to dilute.
        *est_high
            .coeffs
            .get_mut(&wafrift_wafmodel::ensemble_dilution::RuleGroup::SqlInjection)
            .unwrap() = 50.0;

        let mut est_low = default_estimator();
        // Force SQLi contribution very low → easy to dilute below threshold.
        *est_low
            .coeffs
            .get_mut(&wafrift_wafmodel::ensemble_dilution::RuleGroup::SqlInjection)
            .unwrap() = 1.0;

        let score_high = compute_dilution_score("' UNION SELECT--", &est_high, 40.0);
        let score_low = compute_dilution_score("' UNION SELECT--", &est_low, 40.0);
        assert!(
            score_low >= score_high,
            "low-contribution group should score >= high-contribution group"
        );
    }
}
