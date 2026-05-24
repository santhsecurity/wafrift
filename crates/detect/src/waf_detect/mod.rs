//! WAF detection from response headers and body.
//!
//! Identifies which WAF is protecting a target so the strategy engine
//! can choose the most effective evasion techniques.

mod active_probe;
mod blocking;
mod classifier;
mod rules;

#[cfg(test)]
mod tests;

pub use active_probe::{ProbePayload, ProbeResult, active_probe, classify_drift, probe_set};
pub use blocking::is_blocked_response;
pub use classifier::{ACTIONABLE_CONFIDENCE_THRESHOLD, DetectedWaf, detect, supported_wafs};
// `suggest_evasion` is re-exported directly from `rules` — the prior
// `evasion` sub-module was a 17-line one-function passthrough that
// added an indirection without a purpose. Per consolidation F03.
pub use rules::{
    DetectConfig, DetectRulesError, RuleEngine, reload as reload_rules, suggest_evasion,
};
