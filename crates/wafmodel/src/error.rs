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
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, WafModelError>;
