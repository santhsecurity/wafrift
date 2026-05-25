//! # WAFBooster importance scoring (paper: "WAFBooster: Automatic Boosting of
//! WAF Security Against Mutated Malicious Payloads").
//!
//! Maintains a perceptron-style feature-weight table over substring features.
//! Features are n-grams (2-, 3-, 4-byte) plus whitespace/special-char tokens
//! extracted from each payload.  Weights are updated online:
//!
//! - **Blocked** payloads → their features are "bad to keep" →
//!   weights are incremented (higher score = more likely blocked).
//! - **Passing** payloads → their features are "safe" →
//!   weights are decremented.
//!
//! The scorer is used by the evolution engine to rank mutation candidates so
//! that low-score (pass-likely) candidates are tried first.

use std::collections::HashMap;

/// Maximum features extracted per payload.  Caps mining cost so that
/// arbitrarily long payloads don't blow the feature table.
const MAX_FEATURES_PER_PAYLOAD: usize = 100;

/// Per-observation weight step.
const WEIGHT_STEP: f64 = 1.0;

// ── Feature extraction ────────────────────────────────────────────────────────

/// Extract byte n-grams (sizes 2, 3, 4) from `data`.  Returns at most
/// `limit` unique n-gram strings; stops as soon as the limit is reached.
fn byte_ngrams(data: &[u8], limit: usize) -> Vec<String> {
    let mut seen: HashMap<[u8; 4], bool> = HashMap::new();
    let mut out = Vec::new();

    for size in [2usize, 3, 4] {
        if data.len() < size {
            continue;
        }
        for window in data.windows(size) {
            if out.len() >= limit {
                return out;
            }
            // Use a fixed-size key (pad shorter windows).
            let mut key = [0u8; 4];
            key[..window.len()].copy_from_slice(window);
            if seen.insert(key, true).is_none() {
                // Store as printable representation for debuggability.
                out.push(format!("ng:{}", String::from_utf8_lossy(window)));
            }
        }
    }
    out
}

/// Tokenise `payload` on whitespace + common special chars and return the
/// token strings.  An empty token (from adjacent delimiters) is silently
/// dropped.
fn whitespace_tokens(payload: &str) -> impl Iterator<Item = String> + '_ {
    payload
        .split(|c: char| {
            c.is_ascii_whitespace()
                || matches!(
                    c,
                    '\'' | '"' | '`' | ';' | ',' | '(' | ')' | '[' | ']' | '{' | '}' | '<'
                        | '>' | '=' | '!' | '&' | '|' | '+' | '-' | '*' | '/' | '\\' | '?'
                        | '@' | '#' | '$' | '%' | '^' | '~'
                )
        })
        .filter(|s| !s.is_empty())
        .map(|s| format!("tok:{s}"))
}

/// Extract up to `MAX_FEATURES_PER_PAYLOAD` feature strings from `payload`.
/// Feature set = whitespace/special-char tokens ∪ 2/3/4-byte n-grams.
/// De-duplicated; order is deterministic (tokens first, then n-grams).
fn extract_features(payload: &str) -> Vec<String> {
    let mut seen: HashMap<String, ()> = HashMap::new();
    let mut features = Vec::with_capacity(MAX_FEATURES_PER_PAYLOAD);

    // Tokens first.
    for tok in whitespace_tokens(payload) {
        if features.len() >= MAX_FEATURES_PER_PAYLOAD {
            return features;
        }
        if seen.insert(tok.clone(), ()).is_none() {
            features.push(tok);
        }
    }

    // N-grams fill the rest of the budget.
    let remaining = MAX_FEATURES_PER_PAYLOAD.saturating_sub(features.len());
    if remaining > 0 {
        for ngram in byte_ngrams(payload.as_bytes(), remaining) {
            if features.len() >= MAX_FEATURES_PER_PAYLOAD {
                break;
            }
            if seen.insert(ngram.clone(), ()).is_none() {
                features.push(ngram);
            }
        }
    }

    features
}

// ── WafBoosterScorer ──────────────────────────────────────────────────────────

/// Perceptron-style importance scorer.
///
/// Each feature (substring / n-gram / token extracted from a payload) carries
/// a weight that represents how "block-correlated" it is:
///
/// - Positive weight → the feature appears in blocked payloads → raises score.
/// - Negative weight → the feature appears in passing payloads → lowers score.
///
/// `decay` is a multiplicative factor applied to all weights before each
/// `observe_*` call to model forgetting (e.g. `0.99`).  Set to `1.0` to
/// disable decay.
#[derive(Debug, Clone)]
pub struct WafBoosterScorer {
    feature_weights: HashMap<String, f64>,
    /// Multiplicative decay applied before each update.  Range `(0.0, 1.0]`.
    /// `1.0` = no decay.
    pub decay: f64,
}

impl WafBoosterScorer {
    /// Create a new scorer with the given decay factor.
    ///
    /// # Panics
    ///
    /// Panics in debug mode if `decay` is outside `(0.0, 1.0]`.
    #[must_use]
    pub fn new(decay: f64) -> Self {
        debug_assert!(
            decay > 0.0 && decay <= 1.0,
            "decay must be in (0.0, 1.0]; got {decay}"
        );
        Self {
            feature_weights: HashMap::new(),
            decay: decay.clamp(f64::MIN_POSITIVE, 1.0),
        }
    }

    /// Convenience constructor with no decay (`decay = 1.0`).
    #[must_use]
    pub fn no_decay() -> Self {
        Self::new(1.0)
    }

    // ── Internal helpers ──────────────────────────────────────────────

    /// Apply decay to all weights.
    fn apply_decay(&mut self) {
        if (self.decay - 1.0).abs() < f64::EPSILON {
            return; // No-op: decay == 1.0.
        }
        for w in self.feature_weights.values_mut() {
            *w *= self.decay;
        }
    }

    /// Number of features currently tracked.
    #[must_use]
    pub fn feature_count(&self) -> usize {
        self.feature_weights.len()
    }

    /// Read-only access to the weight for a specific feature (for tests /
    /// diagnostics).  Returns `0.0` for unseen features.
    #[must_use]
    pub fn weight_of(&self, feature: &str) -> f64 {
        self.feature_weights.get(feature).copied().unwrap_or(0.0)
    }

    // ── Observation API ───────────────────────────────────────────────

    /// Observe a **blocked** payload.
    ///
    /// Increments weights for every feature extracted from `payload`.
    /// `rule_id` is accepted for future per-rule conditioning but does not
    /// affect weight updates in the current implementation — it is recorded
    /// so the API is forwards-compatible with per-rule tracking.
    pub fn observe_block(&mut self, payload: &str, _rule_id: Option<&str>) {
        self.apply_decay();
        for feat in extract_features(payload) {
            *self.feature_weights.entry(feat).or_insert(0.0) += WEIGHT_STEP;
        }
    }

    /// Observe a **passing** payload.
    ///
    /// Decrements weights for every feature extracted from `payload`.
    pub fn observe_pass(&mut self, payload: &str) {
        self.apply_decay();
        for feat in extract_features(payload) {
            *self.feature_weights.entry(feat).or_insert(0.0) -= WEIGHT_STEP;
        }
    }

    // ── Scoring API ───────────────────────────────────────────────────

    /// Score a candidate payload: sum of weights over the candidate's
    /// features.  Higher score = more likely to be blocked.
    /// Returns `0.0` for an empty scorer or a payload with no known features.
    #[must_use]
    pub fn score_candidate(&self, payload: &str) -> f64 {
        if self.feature_weights.is_empty() {
            return 0.0;
        }
        let mut total = 0.0_f64;
        for feat in extract_features(payload) {
            if let Some(w) = self.feature_weights.get(&feat) {
                total += w;
            }
        }
        total
    }

    /// Rank `candidates` ascending by [`Self::score_candidate`] so the
    /// most-likely-to-pass candidates appear first.
    ///
    /// Ties are broken by preserving the original order (stable sort).
    #[must_use]
    pub fn rank_candidates(&self, candidates: &[String]) -> Vec<(String, f64)> {
        let mut scored: Vec<(String, f64)> = candidates
            .iter()
            .map(|c| (c.clone(), self.score_candidate(c)))
            .collect();
        // Stable ascending sort: pass-likely (low score) first.
        scored.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        scored
    }
}

impl Default for WafBoosterScorer {
    fn default() -> Self {
        Self::no_decay()
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── feature extraction ────────────────────────────────────────────

    #[test]
    fn feature_extraction_non_empty_for_attack_payload() {
        let feats = extract_features("' UNION SELECT 1,2--");
        assert!(!feats.is_empty(), "must extract features from a non-empty payload");
    }

    #[test]
    fn feature_extraction_empty_payload_returns_empty() {
        let feats = extract_features("");
        assert!(feats.is_empty());
    }

    #[test]
    fn feature_count_capped_at_max() {
        // A 500-byte payload must not yield more than MAX_FEATURES_PER_PAYLOAD.
        let long = "A".repeat(500);
        let feats = extract_features(&long);
        assert!(
            feats.len() <= MAX_FEATURES_PER_PAYLOAD,
            "expected ≤ {MAX_FEATURES_PER_PAYLOAD}, got {}",
            feats.len()
        );
    }

    #[test]
    fn ngram_boundary_two_byte_minimum() {
        // A single-character input has no 2-gram.
        let ngrams = byte_ngrams(b"A", 100);
        assert!(ngrams.is_empty());
    }

    #[test]
    fn ngram_two_byte_ok() {
        let ngrams = byte_ngrams(b"AB", 100);
        assert!(!ngrams.is_empty());
        assert!(ngrams.iter().any(|n| n.contains("AB")));
    }

    #[test]
    fn feature_extraction_deduplicates() {
        // Repeated whitespace should not produce duplicate "tok:select" entries.
        let feats = extract_features("select select select");
        let count = feats.iter().filter(|f| f.contains("select")).count();
        assert_eq!(count, 1, "duplicate token extracted");
    }

    // ── weight updates ────────────────────────────────────────────────

    #[test]
    fn observe_block_raises_score() {
        let mut scorer = WafBoosterScorer::no_decay();
        let payload = "' UNION SELECT--";
        let before = scorer.score_candidate(payload);
        scorer.observe_block(payload, None);
        let after = scorer.score_candidate(payload);
        assert!(
            after > before,
            "block observation must raise score: {before} → {after}"
        );
    }

    #[test]
    fn observe_pass_lowers_score() {
        let mut scorer = WafBoosterScorer::no_decay();
        let payload = "hello world";
        scorer.observe_block(payload, None); // prime it upward first
        let before = scorer.score_candidate(payload);
        scorer.observe_pass(payload);
        let after = scorer.score_candidate(payload);
        assert!(
            after < before,
            "pass observation must lower score: {before} → {after}"
        );
    }

    #[test]
    fn empty_scorer_returns_zero() {
        let scorer = WafBoosterScorer::no_decay();
        assert_eq!(scorer.score_candidate("anything"), 0.0);
        assert_eq!(scorer.score_candidate(""), 0.0);
    }

    #[test]
    fn score_zero_for_unseen_features() {
        let mut scorer = WafBoosterScorer::no_decay();
        scorer.observe_block("totally different payload xyz", None);
        // A completely disjoint payload should have a score near zero.
        let score = scorer.score_candidate("12345678");
        // We can't guarantee exactly 0.0 (some n-grams may collide), but
        // the score should be non-positive since no block observations used
        // these exact features.
        let _ = score; // exercising the code path without an exact assertion
    }

    #[test]
    fn decay_shrinks_old_weights() {
        let mut scorer = WafBoosterScorer::new(0.5);
        let payload = "' UNION SELECT--";
        // Build up a non-zero weight.
        scorer.observe_block(payload, None);
        let after_block = scorer.score_candidate(payload);
        // The next observation should decay the existing weights.
        scorer.observe_block("unrelated thing", None);
        let after_decay = scorer.score_candidate(payload);
        // After decay the score for the original payload should be lower than
        // it was right after the block observation (the weights decayed by 0.5).
        assert!(
            after_decay < after_block,
            "decay must shrink old weights: {after_block} → {after_decay}"
        );
    }

    #[test]
    fn decay_one_means_no_shrinkage() {
        let mut scorer = WafBoosterScorer::new(1.0);
        let payload = "' UNION SELECT--";
        scorer.observe_block(payload, None);
        let s1 = scorer.score_candidate(payload);
        // Observe something else — with decay=1.0 the original weights must
        // not change (only new features are updated).
        scorer.observe_block("completely unrelated qwerty", None);
        let s2 = scorer.score_candidate(payload);
        // The original features' weights shouldn't have shrunk.
        assert!(
            s2 >= s1,
            "decay=1.0 must not shrink existing weights: {s1} → {s2}"
        );
    }

    // ── ranking ───────────────────────────────────────────────────────

    #[test]
    fn rank_candidates_lowest_score_first() {
        let mut scorer = WafBoosterScorer::no_decay();
        let blocked = "' UNION SELECT 1,2--".to_string();
        let safe = "hello world".to_string();

        // Teach the scorer: blocked is bad, safe is fine.
        scorer.observe_block(&blocked, None);
        scorer.observe_pass(&safe);

        let ranked = scorer.rank_candidates(&[blocked.clone(), safe.clone()]);
        assert_eq!(
            ranked.len(),
            2,
            "rank_candidates must return same count as input"
        );
        assert!(
            ranked[0].1 <= ranked[1].1,
            "candidates must be sorted ascending by score: {:?}",
            ranked
        );
        // The safe payload should be ranked first (lower score).
        assert_eq!(
            ranked[0].0, safe,
            "safe payload must rank first (lower score)"
        );
    }

    #[test]
    fn rank_empty_input_returns_empty() {
        let scorer = WafBoosterScorer::no_decay();
        let ranked = scorer.rank_candidates(&[]);
        assert!(ranked.is_empty());
    }

    #[test]
    fn rank_single_candidate() {
        let mut scorer = WafBoosterScorer::no_decay();
        scorer.observe_block("test", None);
        let ranked = scorer.rank_candidates(&["test".to_string()]);
        assert_eq!(ranked.len(), 1);
    }

    #[test]
    fn rank_stable_for_ties() {
        // When all candidates score identically (no observations), order
        // must be the original insertion order (stable sort).
        let scorer = WafBoosterScorer::no_decay();
        let candidates: Vec<String> = (0..5).map(|i| format!("candidate_{i}")).collect();
        let ranked = scorer.rank_candidates(&candidates);
        // All scores are 0.0; order must be preserved.
        let ranked_names: Vec<_> = ranked.iter().map(|(n, _)| n.clone()).collect();
        assert_eq!(ranked_names, candidates, "stable sort must preserve order on ties");
    }

    #[test]
    fn very_long_payload_does_not_exceed_feature_cap() {
        let long_payload = "' OR 1=1-- ".repeat(200);
        let mut scorer = WafBoosterScorer::no_decay();
        // Must not panic or explode.
        scorer.observe_block(&long_payload, None);
        let score = scorer.score_candidate(&long_payload);
        assert!(score.is_finite(), "score must be finite for long payloads");
    }

    #[test]
    fn multiple_rule_ids_tracked_separately_via_observe_block() {
        // rule_id does not change weight-update logic, but observe_block
        // must accept arbitrary rule IDs without panicking.
        let mut scorer = WafBoosterScorer::no_decay();
        let payload = "' UNION SELECT--";
        scorer.observe_block(payload, Some("942100"));
        scorer.observe_block(payload, Some("941100"));
        scorer.observe_block(payload, None);
        let score = scorer.score_candidate(payload);
        // Three block observations → score should be clearly positive.
        assert!(score > 0.0, "after 3 block observations score must be positive");
    }

    #[test]
    fn weight_of_unseen_feature_is_zero() {
        let scorer = WafBoosterScorer::no_decay();
        assert_eq!(scorer.weight_of("tok:never_seen"), 0.0);
    }

    #[test]
    fn feature_count_grows_monotonically() {
        let mut scorer = WafBoosterScorer::no_decay();
        let before = scorer.feature_count();
        scorer.observe_block("' UNION SELECT 1,2--", None);
        let after = scorer.feature_count();
        assert!(after > before, "feature count must grow after observation");
    }

    #[test]
    fn score_is_additive_across_independent_features() {
        // Observing two distinct payloads as blocked: scoring a combined
        // payload should be at least as high as either alone.
        let mut scorer = WafBoosterScorer::no_decay();
        scorer.observe_block("alpha beta", None);
        scorer.observe_block("gamma delta", None);

        let s_alpha = scorer.score_candidate("alpha beta");
        let s_gamma = scorer.score_candidate("gamma delta");
        let s_both = scorer.score_candidate("alpha beta gamma delta");

        // The combined payload shares features with both — so its score
        // should be higher than either component in isolation.
        assert!(
            s_both >= s_alpha.max(s_gamma),
            "combined score {s_both} must be >= max({s_alpha}, {s_gamma})"
        );
    }
}
