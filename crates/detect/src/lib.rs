//! wafrift-detect — WAF detection and response fingerprint analysis.
//!
//! Identifies WAFs from response headers and body content.
//! Detects silent blocking via response fingerprint drift analysis.

pub mod response_fingerprint;
pub mod waf_detect;

pub use response_fingerprint::FingerprintDrift;
pub use waf_detect::{
    DetectConfig, DetectRulesError, DetectedWaf, ProbePayload, ProbeResult, RuleEngine,
    active_probe, classify_drift, detect, is_blocked_response, reload_rules, suggest_evasion,
    supported_wafs,
};

pub mod explain;
