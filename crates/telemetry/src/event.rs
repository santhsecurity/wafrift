//! [`Event`] — the unified telemetry event type.
//!
//! Marked `#[non_exhaustive]` so future variants (added in minor releases)
//! never break downstream `match` arms (LAW 2).

use serde::{Deserialize, Serialize};

/// A discrete observability event emitted by wafrift subsystems.
///
/// # Backwards compatibility
///
/// This enum is `#[non_exhaustive]`. Consumers **must** include a catch-all
/// arm:
///
/// ```rust
/// # use wafrift_telemetry::Event;
/// fn handle(e: &Event) {
///     match e {
///         Event::ProbeSent => {}
///         _ => {}
///     }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    /// A single HTTP probe was dispatched toward the target.
    ProbeSent,

    /// The WAF blocked the probe (4xx / challenge response received).
    ProbeBlocked,

    /// A bypass was discovered and optionally validated by the oracle.
    BypassFound {
        /// The matched WAF rule identifier (e.g. `"SQLI-942100"`).
        rule_id: String,
        /// `true` when the oracle confirmed the payload reached the backend.
        oracle_valid: bool,
    },

    /// The WAF fingerprint profile changed mid-campaign (rotation detected).
    WafProfileChanged,

    /// An egress IP hit a rate limit imposed by the target or upstream.
    RateLimitHit {
        /// The egress IP address or label that was rate-limited.
        egress: String,
    },

    /// A payload was mutated by an evasion strategy.
    PayloadMutated {
        /// The name of the mutation strategy (e.g. `"unicode-escape"`).
        strategy: String,
    },

    /// Periodic heartbeat emitted by the campaign loop (approximately 1 Hz).
    CampaignTick,
}
