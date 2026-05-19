//! HTTP/2 GOAWAY frame signal extractor.
//!
//! Detects WAF termination via H2 GOAWAY frames.

use wafrift_types::Signal;

/// Known GOAWAY reason strings that indicate WAF intervention.
/// Loaded from `rules/h2/goaway.toml` so the community can add new
/// vendor identifiers without recompiling.
#[derive(serde::Deserialize)]
struct GoawayRules {
    reason: Vec<GoawayReason>,
}
#[derive(serde::Deserialize)]
struct GoawayReason {
    phrase: String,
}

fn waf_goaway_reasons() -> &'static [String] {
    static CACHE: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| {
        let raw = include_str!("../rules/h2/goaway.toml");
        let parsed: GoawayRules = toml::from_str(raw).expect("rules/h2/goaway.toml must parse");
        parsed.reason.into_iter().map(|r| r.phrase).collect()
    })
}

/// Classify an HTTP/2 GOAWAY frame reason string.
///
/// Returns `Some(Signal::H2Goaway)` if the reason suggests WAF action,
/// otherwise `None`.
#[must_use]
pub fn classify_h2_goaway(reason: &str) -> Option<Signal> {
    let lower = reason.to_ascii_lowercase();
    if waf_goaway_reasons()
        .iter()
        .any(|r| lower.contains(&r.to_ascii_lowercase()))
    {
        Some(Signal::H2Goaway(reason.to_string()))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waf_goaway_detected() {
        let s = classify_h2_goaway("ENHANCE_YOUR_CALM");
        assert!(s.is_some());
        assert!(matches!(s.unwrap(), Signal::H2Goaway(r) if r == "ENHANCE_YOUR_CALM"));
    }

    #[test]
    fn benign_goaway_ignored() {
        assert!(classify_h2_goaway("NO_ERROR").is_none());
    }
}
