//! Error type for the WAF-decompilation engine.

/// Anything that can go wrong while decompiling, mining, or hardening.
#[derive(Debug, thiserror::Error)]
pub enum WafModelError {
    /// The oracle could not be queried (transport, timeout, etc.).
    #[error("oracle query failed: {0}")]
    Oracle(String),

    /// The learner exhausted its membership-query budget before the
    /// hypothesis stabilized. Carries the budget that was spent so the
    /// caller can decide to raise it rather than trust a partial model.
    #[error("learning budget exhausted after {queries} membership queries (hypothesis unstable)")]
    BudgetExhausted {
        /// Membership queries spent before giving up.
        queries: u64,
    },

    /// A learned-model artifact failed to (de)serialize or its schema
    /// version is not understood by this build.
    #[error("model artifact error: {0}")]
    Artifact(String),

    /// A regex shipped in a Tier-B ruleset failed to compile.
    #[error("Tier-B rule {rule} has an invalid pattern: {source}")]
    BadRule {
        /// The offending rule id.
        rule: String,
        /// The underlying regex compile error.
        #[source]
        source: regex::Error,
    },

    /// The equivalence oracle's UCB bandit was asked to draw a
    /// counterexample word but the search space was empty — the
    /// hypothesis has zero states, or the alphabet has zero symbols.
    /// Neither is a valid input; the caller must supply a non-trivial
    /// automaton and a non-empty alphabet.
    #[error(
        "UCB bandit equivalence oracle: search space is empty \
         (state cover is empty or alphabet has zero symbols). \
         Supply a non-trivial hypothesis and a non-empty alphabet."
    )]
    EmptySearchSpace,

    /// The L\* observation table was found to be non-closed while
    /// building a hypothesis. Pre-R51 this surfaced as a panic (the
    /// `.expect("table closed ⇒ …")` call sites in build_hypothesis).
    /// A WAF that returns non-deterministic oracle answers (load-
    /// balanced cluster with inconsistent rule sets, mid-scan rule
    /// reload, etc.) can push two identical prefixes to different
    /// rows and trip this invariant. R51 pass-13 I3 (CLAUDE.md §15).
    #[error(
        "L* observation table is not closed at hypothesis-build time \
         — likely caused by a non-deterministic oracle (WAF cluster, \
         mid-scan rule reload). Retry with a stable target or raise \
         the query budget."
    )]
    TableNotClosed,
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, WafModelError>;
