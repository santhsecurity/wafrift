//! Public WAF classifier entry points.

use std::fmt;

use crate::waf_detect::rules;
pub use crate::waf_detect::rules::{DetectConfig, DetectedWaf};

/// Confidence threshold for callers that need a high-confidence WAF identity.
///
/// Use this when persisting or acting on a single guessed vendor.
pub const ACTIONABLE_CONFIDENCE_THRESHOLD: f64 = 0.5;

impl fmt::Display for DetectedWaf {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} (confidence: {:.0}%, indicators: {})",
            self.name,
            self.confidence * 100.0,
            self.indicators.join(", ")
        )
    }
}

/// Detects WAFs from a response status, headers, and body.
///
/// The body is truncated to the first 4 KiB before matching to keep the
/// classifier predictable and inexpensive.
///
/// Returns a `Vec<DetectedWaf>` sorted by confidence descending, then by
/// WAF name ascending when scores tie (deterministic ordering).
/// If two or more WAFs have confidence within [`DetectConfig::ambiguity_delta`]
/// of each other, all are returned so callers can union evasion techniques
/// or escalate to the user.
#[must_use]
pub fn detect(status: u16, headers: &[(String, String)], body: &[u8]) -> Vec<DetectedWaf> {
    let lower_headers: Vec<(String, String)> = headers
        .iter()
        .map(|(key, value)| (key.to_ascii_lowercase(), value.to_ascii_lowercase()))
        .collect();
    let body_str = String::from_utf8_lossy(&body[..body.len().min(4096)]).to_ascii_lowercase();

    rules::detect_with_config(status, &lower_headers, &body_str, DetectConfig::default())
}

/// Returns the names of all supported WAF detectors.
#[must_use]
pub fn supported_wafs() -> Vec<String> {
    rules::supported_wafs()
}
