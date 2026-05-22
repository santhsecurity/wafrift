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

/// Maximum body bytes considered by the classifier when matching
/// body-regex signatures.
///
/// WAF block pages, EULA-style "powered by" footers, and CDN
/// branding strings often live well past the first kilobyte —
/// Imperva's `imperva_incident_id` line was the most-cited
/// historical miss when this cap was 4 KiB.  The bench corpus's
/// largest interesting body is ~24 KiB; 64 KiB matches the cap
/// applied by `fetch_for_detect` upstream, so no truncation
/// happens in the common path.
///
/// `RegexSet` body scanning is `O(n)` in body length regardless of
/// pattern count, so paying the extra bytes is cheap (low single-
/// digit microseconds on a workstation for the full 60-pattern
/// catalog at 64 KiB).
const BODY_SCAN_MAX_BYTES: usize = 65_536;

/// Detects WAFs from a response status, headers, and body.
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
    let body_str =
        String::from_utf8_lossy(&body[..body.len().min(BODY_SCAN_MAX_BYTES)]).to_ascii_lowercase();

    rules::detect_with_config(status, &lower_headers, &body_str, DetectConfig::default())
}

/// Returns the names of all supported WAF detectors.
#[must_use]
pub fn supported_wafs() -> Vec<String> {
    rules::supported_wafs()
}
