//! The oracle the learner queries: *does this request reach the app?*
//!
//! Three faithful realisations:
//!
//! - [`SimRegexWaf`] — a CRS-anomaly-scoring WAF whose ruleset we
//!   control. It is the **ground truth** the learner is proven against
//!   (we know its exact language because we wrote the rules) and it is
//!   *faithful*, not a toy: it applies real ModSecurity transforms, so
//!   it exhibits the real normalization-mismatch behaviour P2 must
//!   rediscover. Load real CRS rules into it ([`SimRegexWaf::from_toml`])
//!   and it *is* a pure-Rust CRS evaluator — no external Coraza, no
//!   network, zero-config.
//! - [`FnOracle`] — wraps any `FnMut(&Request) -> Result<Outcome>`.
//!   This is how a live HTTP WAF plugs in (scald / the wafrift CLI
//!   already own a client) without dragging an HTTP stack — or a
//!   tokio runtime — into this crate.
//!
//! Every oracle counts its membership queries; that count is the only
//! real cost of decompilation and the thing the query strategy (P1
//! `equiv_query`) minimises.

use crate::canon::{Channel, canonicalize};
use crate::error::{Result, WafModelError};
use crate::normalize::{Transform, apply_chain};
use crate::outcome::Outcome;
use regex::bytes::Regex;
use wafrift_types::Request;
use wafrift_types::hash::{FNV_OFFSET_64, FNV_PRIME_64};

/// The oracle abstraction the active learner is generic over.
pub trait WafOracle {
    /// Classify one request. Errors are transport/again-style failures
    /// (the learner may retry); they are *not* a `Block`.
    fn classify(&mut self, req: &Request) -> Result<Outcome>;

    /// Total membership queries answered so far.
    fn queries(&self) -> u64;
}

/// Set of [`Channel`]s a rule inspects (CRS rules are scoped to
/// variable families; an `ARGS` rule never fires on `REQUEST_HEADERS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct ChannelSet(u16);

impl ChannelSet {
    const fn bit(ch: Channel) -> u16 {
        1 << (ch as u16)
    }

    /// Empty set.
    #[must_use]
    pub const fn none() -> Self {
        ChannelSet(0)
    }

    /// Every channel (an unscoped rule).
    #[must_use]
    pub const fn all() -> Self {
        ChannelSet(0x00FF)
    }

    /// Add a channel.
    #[must_use]
    pub const fn with(self, ch: Channel) -> Self {
        ChannelSet(self.0 | Self::bit(ch))
    }

    /// Membership test.
    #[must_use]
    pub const fn contains(self, ch: Channel) -> bool {
        self.0 & Self::bit(ch) != 0
    }
}

impl FromIterator<Channel> for ChannelSet {
    fn from_iter<I: IntoIterator<Item = Channel>>(iter: I) -> Self {
        iter.into_iter().fold(ChannelSet::none(), ChannelSet::with)
    }
}

/// One CRS-style detection rule.
#[derive(Debug, Clone)]
pub struct Rule {
    /// CRS rule id (e.g. `"941100"`).
    pub id: String,
    /// Channels this rule inspects.
    pub channels: ChannelSet,
    /// `t:` transform chain applied before matching.
    pub transforms: Vec<Transform>,
    /// Compiled detection pattern (matched on the transformed bytes).
    pub pattern: Regex,
    /// Anomaly score contributed on a match.
    pub score: u32,
}

/// A CRS-anomaly-scoring WAF. Blocks when the summed anomaly score of
/// matched rules reaches `threshold` (CRS inbound anomaly threshold;
/// paranoia level is modelled by which rules are present).
#[derive(Debug)]
pub struct SimRegexWaf {
    rules: Vec<Rule>,
    threshold: u32,
    queries: u64,
}

impl SimRegexWaf {
    /// Build from explicit rules.
    #[must_use]
    pub fn new(rules: Vec<Rule>, threshold: u32) -> Self {
        SimRegexWaf {
            rules,
            threshold,
            queries: 0,
        }
    }

    /// Number of loaded rules.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// The inbound anomaly threshold.
    #[must_use]
    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// A stable content fingerprint of the ruleset (FNV-1a over the
    /// sorted `id|pattern|score` lines plus the threshold). Recorded
    /// in a learned-model artifact so a model can be matched back to
    /// the exact WAF configuration it decompiled, and so two WAFs can
    /// be told apart before any learning.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let mut lines: Vec<String> = self
            .rules
            .iter()
            .map(|r| format!("{}|{}|{}", r.id, r.pattern.as_str(), r.score))
            .collect();
        lines.sort();
        let mut h: u64 = FNV_OFFSET_64;
        for byte in format!("t={};{}", self.threshold, lines.join("\n")).bytes() {
            h ^= u64::from(byte);
            h = h.wrapping_mul(FNV_PRIME_64);
        }
        format!("{h:016x}")
    }

    /// Classify *without* counting (used internally by offline mining
    /// against the modelled WAF — those are not live queries).
    #[must_use]
    pub fn classify_uncounted(&self, req: &Request) -> Outcome {
        let view = canonicalize(req);
        let mut total = 0u32;
        for rule in &self.rules {
            let hit = view
                .segments
                .iter()
                .filter(|s| rule.channels.contains(s.channel))
                .any(|s| {
                    let t = apply_chain(&rule.transforms, &s.bytes);
                    rule.pattern.is_match(&t)
                });
            if hit {
                total = total.saturating_add(rule.score);
                if total >= self.threshold {
                    return Outcome::Block;
                }
            }
        }
        Outcome::Pass
    }

    /// The loaded rules (so a hardener can clone + extend them).
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// A copy of this WAF with extra rules appended (same threshold) —
    /// the hardened configuration a defender would deploy.
    #[must_use]
    pub fn with_rules_added(&self, extra: Vec<Rule>) -> SimRegexWaf {
        let mut rules = self.rules.clone();
        rules.extend(extra);
        SimRegexWaf::new(rules, self.threshold)
    }

    /// Parse a Tier-B ruleset.
    ///
    /// ```toml
    /// threshold = 5
    ///
    /// [[rule]]
    /// id = "941100"
    /// channels = ["ArgValue", "ArgName", "CookieValue", "HeaderValue"]
    /// transforms = ["UrlDecodeUni", "HtmlEntityDecode", "Lowercase"]
    /// pattern = "<script[\\s/>]"
    /// score = 5
    /// ```
    pub fn from_toml(src: &str) -> Result<Self> {
        #[derive(serde::Deserialize)]
        struct RawRule {
            id: String,
            channels: Vec<Channel>,
            transforms: Vec<Transform>,
            pattern: String,
            score: u32,
        }
        #[derive(serde::Deserialize)]
        struct Doc {
            threshold: u32,
            rule: Vec<RawRule>,
        }
        let doc: Doc = toml::from_str(src)
            .map_err(|e| WafModelError::Artifact(format!("ruleset TOML: {e}")))?;
        let mut rules = Vec::with_capacity(doc.rule.len());
        // R48 pass-10 I7 (CLAUDE.md §15 AUDIT/ReDoS): cap pattern
        // length and use RegexBuilder.size_limit() so a crafted
        // ruleset cannot drive Regex::new into exponential compile
        // time or stack overflow via deeply nested alternation
        // (e.g. `(a?){200}`). The runtime regex crate is linear-
        // time on match, but compilation is not bounded by default.
        //
        // MAX_PATTERN_LEN is intentionally larger (16 KiB) than the
        // detect crate's 4096-byte cap: wafmodel loads operator-
        // supplied CRS rulesets where individual patterns (e.g. long
        // keyword-alternation chains) legitimately exceed 4 KiB.
        // REGEX_NFA_SIZE_LIMIT is the workspace-canonical 4 MiB NFA
        // cap (wafrift_types::REGEX_NFA_SIZE_LIMIT), shared with
        // wafrift-detect so the ReDoS protection level is uniform.
        const MAX_PATTERN_LEN: usize = 16 * 1024;
        for r in doc.rule {
            if r.pattern.len() > MAX_PATTERN_LEN {
                return Err(WafModelError::Artifact(format!(
                    "rule {} pattern is {} bytes; max {} (defends against \
                     hostile ruleset compile-time blowup)",
                    r.id,
                    r.pattern.len(),
                    MAX_PATTERN_LEN
                )));
            }
            let pattern = regex::bytes::RegexBuilder::new(&r.pattern)
                .size_limit(wafrift_types::REGEX_NFA_SIZE_LIMIT)
                .build()
                .map_err(|source| WafModelError::BadRule {
                    rule: r.id.clone(),
                    source,
                })?;
            rules.push(Rule {
                id: r.id,
                channels: r.channels.into_iter().collect(),
                transforms: r.transforms,
                pattern,
                score: r.score,
            });
        }
        Ok(SimRegexWaf::new(rules, doc.threshold))
    }
}

impl WafOracle for SimRegexWaf {
    fn classify(&mut self, req: &Request) -> Result<Outcome> {
        self.queries += 1;
        Ok(self.classify_uncounted(req))
    }

    fn queries(&self) -> u64 {
        self.queries
    }
}

/// Wraps an arbitrary classifier closure (live HTTP, a recorded trace,
/// a remote service) so the learner stays HTTP/runtime-free.
pub struct FnOracle<F> {
    f: F,
    queries: u64,
}

impl<F> FnOracle<F>
where
    F: FnMut(&Request) -> Result<Outcome>,
{
    /// Wrap a classifier.
    pub fn new(f: F) -> Self {
        FnOracle { f, queries: 0 }
    }
}

impl<F> WafOracle for FnOracle<F>
where
    F: FnMut(&Request) -> Result<Outcome>,
{
    fn classify(&mut self, req: &Request) -> Result<Outcome> {
        self.queries += 1;
        (self.f)(req)
    }

    fn queries(&self) -> u64 {
        self.queries
    }
}
