//! WAF detection from response headers and body.
//!
//! Identifies which WAF is protecting a target so the strategy engine
//! can choose the most effective evasion techniques.

mod active_probe;
mod blocking;
mod classifier;
mod evasion;
mod rules;

#[cfg(test)]
mod tests;

pub use active_probe::{ProbePayload, ProbeResult, active_probe, classify_drift, probe_set};
pub use blocking::is_blocked_response;
pub use classifier::{ACTIONABLE_CONFIDENCE_THRESHOLD, DetectedWaf, detect, supported_wafs};
pub use evasion::suggest_evasion;
pub use rules::{DetectConfig, reload as reload_rules};
