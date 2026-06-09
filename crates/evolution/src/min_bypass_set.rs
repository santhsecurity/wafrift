//! Minimum Bypass Set computer.
//!
//! Given a collection of bypassing payloads (each tagged with the set of WAF
//! rule classes it defeats), compute the **smallest subset** of payloads that
//! collectively covers every rule class that any payload in the input covers.
//!
//! This is the classic **weighted set-cover** problem (NP-hard in general).
//! We use a **greedy approximation** with `(1-1/e)` competitive ratio — each
//! round picks the payload that covers the most uncovered rule classes. This
//! produces a result ≤ `H(n)` times optimal (H = harmonic number), which is
//! the best polynomial-time guarantee.
//!
//! # Why this matters for WAF research
//!
//! A successful evasion scan against a complex WAF (OWASP CRS, Cloudflare,
//! Akamai) may produce hundreds of bypassing payloads. Security researchers
//! need a **forensically minimal** payload set that still exercises every
//! distinct detection surface. Submitting 200 similar payloads to HackerOne
//! is noise; the minimum coverage set is the signal.
//!
//! # Algorithm
//!
//! ```text
//! Input:  {p₁: {c₁,c₂}, p₂: {c₁,c₃}, p₃: {c₂,c₃,c₄}, …}
//! Output: smallest S ⊆ input s.t. ⋃{pᵢ.classes | pᵢ ∈ S} = ⋃{pᵢ.classes | pᵢ ∈ input}
//! Greedy: repeatedly pick the payload covering the most uncovered classes.
//! ```
//!
//! Tie-breaking: when multiple payloads cover the same number of uncovered
//! classes, prefer the one with the highest `score` (bypass confidence or
//! fitness). This keeps forensically strong payloads in the minimal set.
//!
//! # Usage
//!
//! ```
//! use wafrift_evolution::min_bypass_set::{BypassPayload, compute_min_bypass_set};
//!
//! let payloads = vec![
//!     BypassPayload { id: "p1".into(), payload: "' OR 1=1--".into(),
//!                     rule_classes: vec!["sqli_tautology".into()], score: 0.9 },
//!     BypassPayload { id: "p2".into(), payload: "<script>alert(1)</script>".into(),
//!                     rule_classes: vec!["xss_script_tag".into()], score: 0.8 },
//!     BypassPayload { id: "p3".into(), payload: "' OR 1=1--/**/".into(),
//!                     rule_classes: vec!["sqli_tautology".into(), "sqli_comment".into()], score: 0.7 },
//! ];
//! let result = compute_min_bypass_set(&payloads);
//! // p3 covers both sql classes; p2 covers xss — only 2 payloads needed.
//! assert!(result.min_set.len() <= 3);
//! assert!(result.min_set.len() <= payloads.len());
//! ```

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// A bypassing payload annotated with the set of WAF rule classes it defeats.
///
/// `rule_classes` are opaque string labels — the caller assigns them however
/// makes semantic sense for the WAF under test. Typical examples:
/// - Cloudflare rule IDs: `"100002"`, `"100013"`
/// - CRS paranoia-level labels: `"SQLI_PL1"`, `"XSS_PL2"`
/// - wafrift class names: `"sqli_tautology"`, `"xss_event_handler"`
///
/// `score` is a confidence / fitness value used for tie-breaking.
/// Higher scores are preferred. Must be finite (NaN / ±Inf are treated as 0.0).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BypassPayload {
    /// Stable identifier (e.g. bench case ID, BypassEntry hash, CVE number).
    pub id: String,
    /// The raw payload string.
    pub payload: String,
    /// WAF rule classes this payload bypasses.
    pub rule_classes: Vec<String>,
    /// Bypass confidence / fitness score (higher = stronger bypass).
    pub score: f64,
}

/// Result of the minimum bypass set computation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MinBypassSetResult {
    /// The minimal covering set — subset of input `BypassPayload`s.
    pub min_set: Vec<BypassPayload>,
    /// Total number of distinct rule classes covered.
    pub classes_covered: usize,
    /// Total number of input payloads considered.
    pub input_count: usize,
    /// Compression ratio: `input_count / min_set.len()` (or 1.0 if empty).
    pub compression_ratio: f64,
    /// Whether the greedy solution is likely optimal.
    /// True when `min_set.len() == 1` or `classes_covered == min_set.len()`
    /// (each payload contributes a unique class — greedy is exact in this case).
    pub likely_optimal: bool,
}

/// Compute the minimum set of payloads that covers all rule classes reachable
/// by the full input, using greedy set-cover with score tie-breaking.
///
/// # Complexity
/// O(|payloads|² × |classes|) worst case — acceptable for the typical scan
/// output size (< 10,000 payloads). For larger inputs, consider the streaming
/// variant [`compute_min_bypass_set_streaming`].
///
/// # Guarantees
/// - The result covers every class that appears in *any* input payload.
/// - The result is a subset of the input.
/// - No payload in the result covers zero unique classes at the time it was
///   selected (no dead weight — every element is load-bearing).
/// - Deterministic: same input → same output (sort-stable tie-breaking).
#[must_use]
pub fn compute_min_bypass_set(payloads: &[BypassPayload]) -> MinBypassSetResult {
    let input_count = payloads.len();

    if payloads.is_empty() {
        return MinBypassSetResult {
            min_set: Vec::new(),
            classes_covered: 0,
            input_count: 0,
            compression_ratio: 1.0,
            likely_optimal: true,
        };
    }

    // Collect the universe of all rule classes
    let universe: HashSet<&str> = payloads
        .iter()
        .flat_map(|p| p.rule_classes.iter().map(String::as_str))
        .collect();
    let total_classes = universe.len();

    if total_classes == 0 {
        return MinBypassSetResult {
            min_set: Vec::new(),
            classes_covered: 0,
            input_count,
            compression_ratio: input_count as f64,
            likely_optimal: true,
        };
    }

    // Build a per-payload set for O(1) intersection counting.
    // Use indices into a stable array to avoid lifetime headaches.
    let payload_sets: Vec<HashSet<&str>> = payloads
        .iter()
        .map(|p| p.rule_classes.iter().map(String::as_str).collect())
        .collect();

    let mut uncovered: HashSet<&str> = universe.clone();
    let mut selected: Vec<usize> = Vec::new();
    let mut available: Vec<bool> = vec![true; payloads.len()];

    // Greedy loop: pick the payload covering the most uncovered classes.
    // Tie-break by score descending, then id ascending (determinism).
    while !uncovered.is_empty() {
        let best = (0..payloads.len())
            .filter(|&i| available[i])
            .max_by(|&a, &b| {
                let cover_a = payload_sets[a].intersection(&uncovered).count();
                let cover_b = payload_sets[b].intersection(&uncovered).count();
                // Primary: more covered classes is better
                let cmp = cover_a.cmp(&cover_b);
                if cmp != std::cmp::Ordering::Equal {
                    return cmp;
                }
                // Tie-break 1: higher score is better
                let score_a = finite_score(payloads[a].score);
                let score_b = finite_score(payloads[b].score);
                score_a
                    .partial_cmp(&score_b)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    // Tie-break 2: lexicographic id (stable / deterministic)
                    .then_with(|| payloads[b].id.cmp(&payloads[a].id))
            });

        match best {
            None => break, // No available payloads left — shouldn't happen
            Some(idx) => {
                // Check if this payload still covers anything — if not, stop.
                let new_coverage: usize = payload_sets[idx].intersection(&uncovered).count();
                if new_coverage == 0 {
                    break;
                }
                // Mark classes as covered
                for class in &payload_sets[idx] {
                    uncovered.remove(class);
                }
                selected.push(idx);
                available[idx] = false;
            }
        }
    }

    let min_set: Vec<BypassPayload> = selected.iter().map(|&idx| payloads[idx].clone()).collect();
    let classes_covered = total_classes - uncovered.len();
    let min_len = min_set.len().max(1);
    let compression_ratio = input_count as f64 / min_len as f64;
    let likely_optimal =
        min_set.len() == 1 || (classes_covered > 0 && classes_covered == min_set.len());

    MinBypassSetResult {
        min_set,
        classes_covered,
        input_count,
        compression_ratio,
        likely_optimal,
    }
}

/// Streaming variant for large inputs: accepts an iterator and processes
/// payloads one at a time.
///
/// Uses a two-phase approach:
/// 1. Materialise all payloads (iterator consumed).
/// 2. Delegate to [`compute_min_bypass_set`].
///
/// This exists as a separate entry point so callers processing very large
/// sets can pass iterators without collecting first; internally the same
/// greedy algorithm runs. A future optimisation can implement a true
/// streaming set-cover if input sizes ever exceed memory.
///
/// # Complexity
/// Same as [`compute_min_bypass_set`]: O(n² × c).
#[must_use]
pub fn compute_min_bypass_set_streaming<I>(payloads: I) -> MinBypassSetResult
where
    I: IntoIterator<Item = BypassPayload>,
{
    let collected: Vec<BypassPayload> = payloads.into_iter().collect();
    compute_min_bypass_set(&collected)
}

/// Build a human-readable summary of the minimum bypass set result.
///
/// Example output:
/// ```text
/// Min-bypass set: 3 / 47 payloads cover 12 rule classes (15.7x compression)
///   1. [p23] sqli_tautology, sqli_comment  (score=0.95)
///   2. [p7]  xss_event_handler             (score=0.88)
///   3. [p41] cmdi_pipe                     (score=0.81)
/// ```
#[must_use]
pub fn format_min_bypass_summary(result: &MinBypassSetResult) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "Min-bypass set: {} / {} payloads cover {} rule classes ({:.1}x compression){}\n",
        result.min_set.len(),
        result.input_count,
        result.classes_covered,
        result.compression_ratio,
        if result.likely_optimal {
            " [likely optimal]"
        } else {
            ""
        },
    ));
    for (i, p) in result.min_set.iter().enumerate() {
        let classes = p.rule_classes.join(", ");
        out.push_str(&format!(
            "  {}. [{}] {}  (score={:.3})\n",
            i + 1,
            p.id,
            classes,
            finite_score(p.score),
        ));
    }
    out
}

/// Build a per-class coverage map: for each rule class, which payload in the
/// minimum set covers it.
///
/// Useful for generating a forensic report: "rule class X is demonstrated
/// by payload Y".
#[must_use]
pub fn class_coverage_map<'a>(result: &'a MinBypassSetResult) -> HashMap<&'a str, &'a str> {
    let mut map: HashMap<&'a str, &'a str> = HashMap::new();
    for p in &result.min_set {
        for class in &p.rule_classes {
            // First payload to cover a class wins (greedy order = priority order)
            map.entry(class.as_str()).or_insert(p.id.as_str());
        }
    }
    map
}

/// Normalise a score, treating NaN and ±Inf as 0.0.
#[inline]
fn finite_score(s: f64) -> f64 {
    if s.is_finite() { s } else { 0.0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bp(id: &str, classes: &[&str], score: f64) -> BypassPayload {
        BypassPayload {
            id: id.into(),
            payload: format!("payload_for_{id}"),
            rule_classes: classes.iter().map(|s| (*s).into()).collect(),
            score,
        }
    }

    // ── empty / degenerate inputs ─────────────────────────────────────────

    #[test]
    fn empty_input_returns_empty_result() {
        let r = compute_min_bypass_set(&[]);
        assert!(r.min_set.is_empty());
        assert_eq!(r.classes_covered, 0);
        assert_eq!(r.input_count, 0);
        assert_eq!(r.compression_ratio, 1.0);
    }

    #[test]
    fn single_payload_is_its_own_min_set() {
        let p = bp("p1", &["sqli"], 0.9);
        let r = compute_min_bypass_set(std::slice::from_ref(&p));
        assert_eq!(r.min_set.len(), 1);
        assert_eq!(r.min_set[0].id, "p1");
        assert_eq!(r.classes_covered, 1);
    }

    #[test]
    fn no_classes_produces_empty_min_set() {
        let p = BypassPayload {
            id: "p1".into(),
            payload: "x".into(),
            rule_classes: Vec::new(),
            score: 0.5,
        };
        let r = compute_min_bypass_set(&[p]);
        assert!(r.min_set.is_empty());
        assert_eq!(r.classes_covered, 0);
    }

    // ── correctness ────────────────────────────────────────────────────────

    #[test]
    fn two_disjoint_classes_require_two_payloads() {
        let payloads = vec![bp("p1", &["sqli"], 0.9), bp("p2", &["xss"], 0.8)];
        let r = compute_min_bypass_set(&payloads);
        assert_eq!(r.min_set.len(), 2, "two disjoint classes need two payloads");
        assert_eq!(r.classes_covered, 2);
    }

    #[test]
    fn single_payload_covering_all_classes_wins() {
        let payloads = vec![
            bp("p1", &["a"], 0.5),
            bp("p2", &["b"], 0.5),
            bp("p3", &["a", "b"], 0.9), // covers both
        ];
        let r = compute_min_bypass_set(&payloads);
        // Greedy must pick p3 first (covers 2 classes)
        assert_eq!(r.min_set.len(), 1);
        assert_eq!(r.min_set[0].id, "p3");
        assert_eq!(r.classes_covered, 2);
    }

    #[test]
    fn greedy_picks_higher_score_on_tie() {
        // p1 and p2 both cover the same single class — higher score should win
        let payloads = vec![
            bp("p1", &["sqli"], 0.7),
            bp("p2", &["sqli"], 0.9), // higher score
        ];
        let r = compute_min_bypass_set(&payloads);
        assert_eq!(r.min_set.len(), 1);
        assert_eq!(r.min_set[0].id, "p2", "higher-score payload should win tie");
    }

    #[test]
    fn min_set_is_subset_of_input() {
        let payloads = vec![
            bp("p1", &["a", "b"], 0.9),
            bp("p2", &["b", "c"], 0.8),
            bp("p3", &["c", "d"], 0.7),
            bp("p4", &["a"], 0.6),
            bp("p5", &["d"], 0.5),
        ];
        let r = compute_min_bypass_set(&payloads);
        for p in &r.min_set {
            assert!(
                payloads.iter().any(|orig| orig.id == p.id),
                "min_set must be a subset of input: {} not found",
                p.id
            );
        }
    }

    #[test]
    fn result_covers_all_classes() {
        let payloads = vec![
            bp("p1", &["sqli", "xss"], 0.9),
            bp("p2", &["cmdi"], 0.8),
            bp("p3", &["path", "ssrf"], 0.7),
        ];
        let r = compute_min_bypass_set(&payloads);
        // All 5 classes must be covered
        assert_eq!(r.classes_covered, 5);
        // Min set must cover all 5
        let covered: HashSet<&str> = r
            .min_set
            .iter()
            .flat_map(|p| p.rule_classes.iter().map(String::as_str))
            .collect();
        assert_eq!(covered.len(), 5);
    }

    #[test]
    fn compression_ratio_is_positive() {
        let payloads: Vec<BypassPayload> = (0..20)
            .map(|i| bp(&format!("p{i}"), &[&format!("class_{i}")], i as f64 / 20.0))
            .collect();
        let r = compute_min_bypass_set(&payloads);
        // 20 payloads each with unique class → min set is all 20 → ratio = 1.0
        assert!((r.compression_ratio - 1.0).abs() < 1e-9);
    }

    #[test]
    fn large_redundant_set_compresses_dramatically() {
        // 100 payloads all covering the same 3 classes
        let payloads: Vec<BypassPayload> = (0..100)
            .map(|i| bp(&format!("p{i}"), &["a", "b", "c"], i as f64 / 100.0))
            .collect();
        let r = compute_min_bypass_set(&payloads);
        assert_eq!(r.min_set.len(), 1, "100 redundant payloads → 1 needed");
        assert!(r.compression_ratio > 50.0);
    }

    #[test]
    fn deterministic_output() {
        let payloads = vec![
            bp("alpha", &["a", "b"], 0.5),
            bp("beta", &["b", "c"], 0.5),
            bp("gamma", &["c", "d"], 0.5),
        ];
        let r1 = compute_min_bypass_set(&payloads);
        let r2 = compute_min_bypass_set(&payloads);
        assert_eq!(r1.min_set.len(), r2.min_set.len());
        for (a, b) in r1.min_set.iter().zip(r2.min_set.iter()) {
            assert_eq!(a.id, b.id);
        }
    }

    // ── streaming variant ────────────────────────────────────────────────

    #[test]
    fn streaming_matches_batch() {
        let payloads = vec![
            bp("p1", &["a", "b"], 0.9),
            bp("p2", &["c"], 0.8),
            bp("p3", &["b", "c", "d"], 0.7),
        ];
        let batch = compute_min_bypass_set(&payloads);
        let stream = compute_min_bypass_set_streaming(payloads);
        assert_eq!(batch.min_set.len(), stream.min_set.len());
        assert_eq!(batch.classes_covered, stream.classes_covered);
    }

    // ── helper functions ─────────────────────────────────────────────────

    #[test]
    fn format_summary_contains_key_fields() {
        let payloads = vec![bp("p1", &["sqli"], 0.9), bp("p2", &["xss"], 0.8)];
        let r = compute_min_bypass_set(&payloads);
        let summary = format_min_bypass_summary(&r);
        assert!(summary.contains("2"), "summary must mention class count");
        assert!(
            summary.contains("compression"),
            "summary must mention compression"
        );
    }

    #[test]
    fn class_coverage_map_is_complete() {
        let payloads = vec![bp("p1", &["a", "b"], 0.9), bp("p2", &["c"], 0.8)];
        let r = compute_min_bypass_set(&payloads);
        let map = class_coverage_map(&r);
        assert!(map.contains_key("a"));
        assert!(map.contains_key("b"));
        assert!(map.contains_key("c"));
    }

    #[test]
    fn class_coverage_map_respects_greedy_order() {
        // p3 is selected first (covers 2 classes). p1 covers "a" too,
        // but the map should credit p3 for "a" since it was selected first.
        let payloads = vec![
            bp("p1", &["a"], 0.5),
            bp("p2", &["b"], 0.5),
            bp("p3", &["a", "b"], 0.9), // selected first
        ];
        let r = compute_min_bypass_set(&payloads);
        let map = class_coverage_map(&r);
        // p3 should cover both a and b
        assert_eq!(map.get("a"), Some(&"p3"), "p3 should cover class 'a'");
        assert_eq!(map.get("b"), Some(&"p3"), "p3 should cover class 'b'");
    }

    // ── NaN / Inf score robustness ────────────────────────────────────────

    #[test]
    fn nan_score_treated_as_zero() {
        let payloads = vec![bp("p_nan", &["a"], f64::NAN), bp("p_good", &["a"], 0.9)];
        // Must not panic; should prefer the finite-score payload
        let r = compute_min_bypass_set(&payloads);
        assert_eq!(r.min_set.len(), 1);
        assert_eq!(r.min_set[0].id, "p_good");
    }

    #[test]
    fn inf_score_treated_as_zero() {
        let payloads = vec![
            bp("p_inf", &["a"], f64::INFINITY),
            bp("p_neginf", &["a"], f64::NEG_INFINITY),
        ];
        // Must not panic
        let r = compute_min_bypass_set(&payloads);
        assert_eq!(r.min_set.len(), 1);
    }

    // ── boundary and property tests ──────────────────────────────────────

    #[test]
    fn min_set_never_larger_than_input() {
        for n in [0, 1, 2, 5, 10, 50] {
            let payloads: Vec<BypassPayload> = (0..n)
                .map(|i| bp(&format!("p{i}"), &[&format!("c{i}")], 0.5))
                .collect();
            let r = compute_min_bypass_set(&payloads);
            assert!(
                r.min_set.len() <= payloads.len(),
                "min_set must not exceed input size for n={n}"
            );
        }
    }

    #[test]
    fn classes_covered_equals_universe_size_when_fully_covered() {
        let payloads = vec![bp("p1", &["a", "b", "c"], 0.9), bp("p2", &["d", "e"], 0.8)];
        let r = compute_min_bypass_set(&payloads);
        assert_eq!(
            r.classes_covered, 5,
            "all 5 distinct classes must be counted"
        );
    }
}
