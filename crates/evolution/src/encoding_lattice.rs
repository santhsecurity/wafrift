//! Encoding-stack lattice search — enumerate compositions of N
//! encoders and find the ones that defeat a target WAF rule.
//!
//! wafrift ships ~30 [`wafrift_encoding::Strategy`] encoders.
//! Compositions of 2..=5 produce 30² + 30³ + 30⁴ + 30⁵ ≈ 24M
//! ordered chains. Most don't preserve attack semantics (the
//! origin's normalizer must still recover the original payload)
//! and most that do still get blocked. The few that pass the
//! semantic-preservation oracle AND defeat the live WAF rule are
//! the high-yield bypass candidates.
//!
//! ## Workflow
//!
//! 1. Caller passes a seed `payload`, target `rule_id`, and a
//!    bound `max_depth` (default 3 — beyond which compositions
//!    are usually noise).
//! 2. `LatticeSearch::enumerate_chains` produces a deterministic
//!    sequence of [`EncodingChain`] candidates.
//! 3. For each candidate the caller:
//!    a. Applies the chain via [`apply_chain`].
//!    b. Verifies semantic preservation via the operator-supplied
//!       oracle callback (`wafrift_oracle::oracle_for` is the
//!       canonical implementation).
//!    c. Fires the encoded payload at the live target; records the
//!       outcome via [`super::hunt_corpus_bridge::record_outcome`].
//! 4. Confirmed bypasses get fingerprinted via [`super::h1_dedup`]
//!    and gated for HackerOne submission.
//!
//! ## Determinism
//!
//! The enumeration is **canonical lexicographic order** over the
//! input strategy list. Two runs with the same input produce the
//! same chain sequence — required so `wafrift bench` is
//! reproducible.

use serde::{Deserialize, Serialize};
use wafrift_encoding::Strategy;

/// One enumerated encoding-chain candidate. The chain is applied
/// LEFT-TO-RIGHT: `[Url, Unicode]` means url-encode first, then
/// unicode-encode the result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncodingChain {
    pub strategies: Vec<Strategy>,
}

impl EncodingChain {
    /// Compose into a list of strategy identifiers — the same form
    /// [`super::rule_corpus::RecordedAttempt::encoding_chain`]
    /// stores so callers don't need a re-encoder.
    #[must_use]
    pub fn to_chain_names(&self) -> Vec<String> {
        self.strategies.iter().map(|s| s.as_str().to_string()).collect()
    }

    /// Number of encoder applications in the chain.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.strategies.len()
    }
}

/// Search configuration. The default produces ~6,400 candidates
/// (8 encoders ⨯ 1-3 depth ≈ 8 + 64 + 512), which is enough to
/// systematically probe a single rule without burning the egress
/// budget.
#[derive(Debug, Clone)]
pub struct LatticeSearch {
    /// Encoder palette to compose over. Caller picks a subset to
    /// constrain the search (e.g. only keyword-bypass encoders for
    /// a CRS SQL rule, only path-encoders for a path-traversal rule).
    pub strategies: Vec<Strategy>,
    /// Minimum chain length (1 = single encoder; useful for the
    /// "is one transform enough?" baseline before composing).
    pub min_depth: usize,
    /// Maximum chain length. Default 3; bumping to 4 or 5 is
    /// useful only after the depth-3 sweep has stalled.
    pub max_depth: usize,
    /// Skip chains where any two consecutive strategies are the
    /// same — `[Url, Url]` is rarely useful (double-encode is
    /// already its own `DoubleUrlEncode` strategy). Set false for
    /// research-grade exhaustive sweeps.
    pub skip_consecutive_dupes: bool,
    /// Hard cap on total chains enumerated. Stops the iterator
    /// early on huge palettes so the caller doesn't run out of
    /// egress budget mid-round. 0 = no cap.
    pub max_chains: usize,
}

impl LatticeSearch {
    /// Sensible defaults: depth 1-3, no consecutive dupes, no cap.
    #[must_use]
    pub fn new(strategies: Vec<Strategy>) -> Self {
        Self {
            strategies,
            min_depth: 1,
            max_depth: 3,
            skip_consecutive_dupes: true,
            max_chains: 0,
        }
    }

    /// Builder: set max depth.
    #[must_use]
    pub fn with_max_depth(mut self, d: usize) -> Self {
        self.max_depth = d;
        self
    }

    /// Builder: set min depth.
    #[must_use]
    pub fn with_min_depth(mut self, d: usize) -> Self {
        self.min_depth = d;
        self
    }

    /// Builder: cap total chains enumerated.
    #[must_use]
    pub fn with_max_chains(mut self, n: usize) -> Self {
        self.max_chains = n;
        self
    }

    /// Builder: allow consecutive-same-strategy chains.
    #[must_use]
    pub fn allowing_consecutive_dupes(mut self) -> Self {
        self.skip_consecutive_dupes = false;
        self
    }

    /// Enumerate every chain in canonical lex order. The result
    /// is a `Vec` (not an iterator) so callers can paginate /
    /// shuffle / process in parallel chunks.
    #[must_use]
    pub fn enumerate_chains(&self) -> Vec<EncodingChain> {
        let mut out = vec![];
        if self.strategies.is_empty() || self.min_depth == 0 || self.max_depth < self.min_depth {
            return out;
        }
        for depth in self.min_depth..=self.max_depth {
            self.enumerate_at_depth(depth, &mut Vec::with_capacity(depth), &mut out);
            if self.max_chains > 0 && out.len() >= self.max_chains {
                out.truncate(self.max_chains);
                return out;
            }
        }
        out
    }

    fn enumerate_at_depth(
        &self,
        remaining: usize,
        prefix: &mut Vec<Strategy>,
        out: &mut Vec<EncodingChain>,
    ) {
        if self.max_chains > 0 && out.len() >= self.max_chains {
            return;
        }
        if remaining == 0 {
            out.push(EncodingChain {
                strategies: prefix.clone(),
            });
            return;
        }
        for &s in &self.strategies {
            if self.skip_consecutive_dupes {
                if let Some(last) = prefix.last() {
                    if *last == s {
                        continue;
                    }
                }
            }
            prefix.push(s);
            self.enumerate_at_depth(remaining - 1, prefix, out);
            prefix.pop();
        }
    }

    /// Total chain count this search would emit. Cheap-to-compute
    /// (closed-form) so callers can budget before iterating.
    #[must_use]
    pub fn estimated_chain_count(&self) -> usize {
        if self.strategies.is_empty() || self.min_depth == 0 || self.max_depth < self.min_depth {
            return 0;
        }
        let n = self.strategies.len();
        let mut total = 0usize;
        for depth in self.min_depth..=self.max_depth {
            let count = if self.skip_consecutive_dupes && n >= 2 {
                // n choices for position 0, (n-1) for every
                // subsequent position (any strategy except the
                // previous one).
                n * (n - 1).saturating_pow((depth - 1) as u32)
            } else {
                n.saturating_pow(depth as u32)
            };
            total = total.saturating_add(count);
            if self.max_chains > 0 && total >= self.max_chains {
                return self.max_chains;
            }
        }
        total
    }
}

/// Apply an [`EncodingChain`] to a payload, left-to-right. Returns
/// an error if any encoder fails (typically on malformed UTF-8 input
/// for text-only encoders).
pub fn apply_chain(payload: &[u8], chain: &EncodingChain) -> Result<String, ChainApplyError> {
    let mut current: String = std::str::from_utf8(payload)
        .map_err(|_| ChainApplyError::InvalidUtf8)?
        .to_string();
    for &strategy in &chain.strategies {
        match wafrift_encoding::encode(&current, strategy) {
            Ok(encoded) => current = encoded,
            Err(e) => return Err(ChainApplyError::EncoderRejected(format!("{strategy:?}: {e}"))),
        }
    }
    Ok(current)
}

/// Error from [`apply_chain`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainApplyError {
    /// Input wasn't valid UTF-8 for text-oriented encoders.
    InvalidUtf8,
    /// An encoder rejected the input. The string carries the
    /// strategy + reason for operator triage.
    EncoderRejected(String),
}

impl std::fmt::Display for ChainApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUtf8 => f.write_str("input is not valid UTF-8"),
            Self::EncoderRejected(s) => write!(f, "encoder rejected: {s}"),
        }
    }
}

impl std::error::Error for ChainApplyError {}

/// Convenience: build a search from the workspace's full strategy
/// palette and enumerate up to depth 2 (the most common starting
/// point — single encoders + pairs).
#[must_use]
pub fn shallow_lattice() -> LatticeSearch {
    LatticeSearch::new(wafrift_encoding::all_strategies().to_vec())
        .with_max_depth(2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wafrift_encoding::Strategy;

    fn three_strategies() -> Vec<Strategy> {
        vec![
            Strategy::UrlEncode,
            Strategy::UnicodeEncode,
            Strategy::CaseAlternation,
        ]
    }

    #[test]
    fn empty_palette_yields_no_chains() {
        let s = LatticeSearch::new(vec![]);
        assert_eq!(s.enumerate_chains().len(), 0);
        assert_eq!(s.estimated_chain_count(), 0);
    }

    #[test]
    fn depth_1_one_chain_per_strategy() {
        let s = LatticeSearch::new(three_strategies()).with_max_depth(1);
        let chains = s.enumerate_chains();
        assert_eq!(chains.len(), 3);
        for c in &chains {
            assert_eq!(c.depth(), 1);
        }
    }

    #[test]
    fn depth_2_no_consecutive_dupes_default() {
        let s = LatticeSearch::new(three_strategies()).with_max_depth(2);
        // 3 (depth 1) + 3 × 2 (depth 2, no dupes) = 3 + 6 = 9.
        assert_eq!(s.estimated_chain_count(), 9);
        let chains = s.enumerate_chains();
        assert_eq!(chains.len(), 9);
        // No chain has two equal consecutive strategies.
        for c in &chains {
            for w in c.strategies.windows(2) {
                assert_ne!(w[0], w[1]);
            }
        }
    }

    #[test]
    fn allowing_consecutive_dupes_gives_full_product() {
        let s = LatticeSearch::new(three_strategies())
            .with_max_depth(2)
            .allowing_consecutive_dupes();
        // 3 + 3² = 3 + 9 = 12.
        assert_eq!(s.estimated_chain_count(), 12);
        assert_eq!(s.enumerate_chains().len(), 12);
    }

    #[test]
    fn depth_3_count_correct_with_dedup() {
        let s = LatticeSearch::new(three_strategies())
            .with_min_depth(3)
            .with_max_depth(3);
        // depth 3, no consecutive dupes: 3 * 2 * 2 = 12.
        assert_eq!(s.estimated_chain_count(), 12);
        assert_eq!(s.enumerate_chains().len(), 12);
    }

    #[test]
    fn enumeration_is_deterministic() {
        let s = LatticeSearch::new(three_strategies()).with_max_depth(3);
        let a = s.enumerate_chains();
        let b = s.enumerate_chains();
        assert_eq!(a, b);
    }

    #[test]
    fn max_chains_caps_output() {
        let s = LatticeSearch::new(three_strategies())
            .with_max_depth(3)
            .with_max_chains(5);
        assert_eq!(s.enumerate_chains().len(), 5);
        assert_eq!(s.estimated_chain_count(), 5);
    }

    #[test]
    fn max_chains_zero_means_no_cap() {
        let s = LatticeSearch::new(three_strategies())
            .with_max_depth(2)
            .with_max_chains(0);
        assert_eq!(s.enumerate_chains().len(), 9);
    }

    #[test]
    fn min_greater_than_max_yields_empty() {
        let s = LatticeSearch::new(three_strategies())
            .with_min_depth(5)
            .with_max_depth(3);
        assert!(s.enumerate_chains().is_empty());
        assert_eq!(s.estimated_chain_count(), 0);
    }

    #[test]
    fn to_chain_names_round_trips() {
        let chain = EncodingChain {
            strategies: vec![Strategy::UrlEncode, Strategy::Base64Encode],
        };
        let names = chain.to_chain_names();
        assert_eq!(names, vec!["UrlEncode".to_string(), "Base64Encode".to_string()]);
    }

    #[test]
    fn apply_chain_url_then_case() {
        let chain = EncodingChain {
            strategies: vec![Strategy::UrlEncode, Strategy::CaseAlternation],
        };
        let out = apply_chain(b"SELECT", &chain).expect("apply");
        // url-encode preserves bytes for ASCII-alpha; case alternation
        // flips alternating letters.
        assert!(!out.is_empty());
    }

    #[test]
    fn apply_chain_invalid_utf8_errors() {
        let chain = EncodingChain {
            strategies: vec![Strategy::CaseAlternation],
        };
        let invalid = vec![0xFF, 0xFE, 0xFD];
        let r = apply_chain(&invalid, &chain);
        // Case-alternation requires text — fails on invalid UTF-8.
        assert!(matches!(
            r,
            Err(ChainApplyError::InvalidUtf8 | ChainApplyError::EncoderRejected(_))
        ));
    }

    #[test]
    fn apply_empty_chain_returns_input() {
        let chain = EncodingChain { strategies: vec![] };
        let out = apply_chain(b"hello", &chain).expect("apply");
        assert_eq!(out, "hello");
    }

    #[test]
    fn shallow_lattice_uses_full_palette() {
        let s = shallow_lattice();
        assert_eq!(s.max_depth, 2);
        assert!(!s.strategies.is_empty());
    }

    #[test]
    fn chain_serializes_round_trip() {
        let chain = EncodingChain {
            strategies: vec![Strategy::UrlEncode, Strategy::HtmlEntityEncode],
        };
        let json = serde_json::to_string(&chain).expect("ser");
        let back: EncodingChain = serde_json::from_str(&json).expect("de");
        assert_eq!(chain, back);
    }

    #[test]
    fn chain_depth_reports_correct_length() {
        let chain = EncodingChain {
            strategies: vec![
                Strategy::UrlEncode,
                Strategy::CaseAlternation,
                Strategy::Base64Encode,
            ],
        };
        assert_eq!(chain.depth(), 3);
    }

    #[test]
    fn lex_order_first_chain_is_first_strategy() {
        let s = LatticeSearch::new(three_strategies()).with_max_depth(1);
        let chains = s.enumerate_chains();
        // First chain at depth 1 = the first strategy in the palette.
        assert_eq!(chains[0].strategies, vec![Strategy::UrlEncode]);
    }

    #[test]
    fn estimated_count_matches_actual() {
        // Pin the closed-form math against the iterator for a few
        // configurations.
        for max_depth in 1..=4 {
            let s = LatticeSearch::new(three_strategies()).with_max_depth(max_depth);
            let actual = s.enumerate_chains().len();
            let estimated = s.estimated_chain_count();
            assert_eq!(
                actual, estimated,
                "depth {max_depth}: actual {actual} vs estimated {estimated}"
            );
        }
    }

    #[test]
    fn skip_consecutive_dupes_pins_no_aa() {
        let s = LatticeSearch::new(three_strategies()).with_max_depth(2);
        let chains = s.enumerate_chains();
        // None of the chains should be [Url, Url].
        for c in &chains {
            if c.depth() == 2 {
                assert_ne!(c.strategies[0], c.strategies[1]);
            }
        }
    }

    #[test]
    fn adversarial_huge_max_depth_capped_by_max_chains() {
        // 30 strategies ⨯ 6 deep ≈ 4M chains without a cap. The
        // cap protects against memory blow-up.
        let pal = wafrift_encoding::all_strategies().to_vec();
        let s = LatticeSearch::new(pal)
            .with_max_depth(6)
            .with_max_chains(100);
        let chains = s.enumerate_chains();
        assert!(chains.len() <= 100);
    }

    #[test]
    fn estimated_count_saturates_on_huge_palette() {
        let pal = wafrift_encoding::all_strategies().to_vec();
        let s = LatticeSearch::new(pal)
            .with_max_depth(10)
            .with_max_chains(50);
        // Closed-form should not overflow; the cap holds.
        assert_eq!(s.estimated_chain_count(), 50);
    }

    #[test]
    fn min_depth_zero_yields_empty() {
        let s = LatticeSearch::new(three_strategies())
            .with_min_depth(0)
            .with_max_depth(0);
        assert!(s.enumerate_chains().is_empty());
    }

    #[test]
    fn single_strategy_palette() {
        let s = LatticeSearch::new(vec![Strategy::UrlEncode]).with_max_depth(3);
        // Depth 1 → 1 chain. Depths 2 & 3 → 0 because consecutive
        // dupes are skipped and there's only one option.
        assert_eq!(s.enumerate_chains().len(), 1);
    }

    #[test]
    fn single_strategy_palette_allowing_dupes() {
        let s = LatticeSearch::new(vec![Strategy::UrlEncode])
            .with_max_depth(3)
            .allowing_consecutive_dupes();
        // 1 + 1 + 1 = 3 chains.
        assert_eq!(s.enumerate_chains().len(), 3);
    }
}
