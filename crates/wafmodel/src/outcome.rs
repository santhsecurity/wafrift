//! The two-valued projection of a WAF verdict that the learner reasons
//! over.
//!
//! A real WAF verdict ([`wafrift_types::Verdict`]) is rich
//! (blocked / allowed / rate-limited / challenge / server-error /
//! partial). Automaton learning is a *binary* classification problem:
//! the request either reaches the application or it does not. This is
//! the deliberate, lossy projection — kept distinct from `Verdict` on
//! purpose (it is not a duplicate of it; it is the learning-relevant
//! quotient).

use wafrift_types::Verdict;

/// Did the request reach the protected application, or was it stopped
/// by the WAF?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Outcome {
    /// The WAF let the request through (the app would see it).
    Pass,
    /// The WAF stopped the request (block / challenge / rate-limit).
    Block,
}

impl Outcome {
    /// Project a full [`Verdict`] onto the learning-relevant binary.
    ///
    /// Block, challenge, and rate-limit all mean "the attack payload
    /// did not reach the sink" — they are `Block`. Only an outright
    /// allow is `Pass`. `ServerError`/`Partial` are treated as `Block`:
    /// a request that does not produce a normal application response
    /// did not deliver the attack, and counting it as `Pass` would
    /// teach the learner a bypass that does not exist (anti-rig).
    #[must_use]
    pub fn from_verdict(v: &Verdict) -> Self {
        if v.is_allowed() {
            Outcome::Pass
        } else {
            Outcome::Block
        }
    }

    /// `true` iff the request reached the application.
    #[must_use]
    pub fn is_pass(self) -> bool {
        matches!(self, Outcome::Pass)
    }
}
