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

    // -- §12 boundary and edge-case tests -----------------------------------

    #[test]
    fn empty_reason_returns_none() {
        // Empty string cannot contain any known WAF phrase.
        assert!(classify_h2_goaway("").is_none());
    }

    #[test]
    fn case_insensitive_detection_lower() {
        // "enhance_your_calm" should match even in all lowercase.
        let s = classify_h2_goaway("enhance_your_calm");
        assert!(
            s.is_some(),
            "lowercase ENHANCE_YOUR_CALM must be detected as WAF GOAWAY"
        );
    }

    #[test]
    fn case_insensitive_detection_mixed() {
        let s = classify_h2_goaway("Enhance_Your_Calm");
        assert!(
            s.is_some(),
            "mixed-case ENHANCE_YOUR_CALM must be detected as WAF GOAWAY"
        );
    }

    #[test]
    fn original_reason_string_preserved_in_signal() {
        // The signal must carry the *original* reason (not lowercased),
        // so the operator sees what the server actually sent.
        let original = "ENHANCE_YOUR_CALM";
        let s = classify_h2_goaway(original).expect("must be detected");
        match s {
            Signal::H2Goaway(r) => assert_eq!(r, original, "original casing must be preserved"),
            other => panic!("unexpected signal variant: {other:?}"),
        }
    }

    #[test]
    fn whitespace_in_reason_benign_passes_through() {
        // A reason that is pure whitespace is not a WAF signal.
        assert!(classify_h2_goaway("   ").is_none());
    }

    #[test]
    fn goaway_rules_file_is_nonempty() {
        // Smoke test: the bundled TOML must parse and have at least one
        // entry so the detector is not silently disabled.
        let reasons = super::waf_goaway_reasons();
        assert!(
            !reasons.is_empty(),
            "rules/h2/goaway.toml has no entries -- GOAWAY detection is disabled"
        );
    }

    #[test]
    fn very_long_reason_string_does_not_panic() {
        // §15 OOM guard: the classifier must not stack-overflow or panic
        // on a megabyte-scale reason string from a hostile server.
        let huge = "X".repeat(1_000_000);
        // Must complete without panic (no signal expected for junk input).
        let result = classify_h2_goaway(&huge);
        let _ = result;
    }

    #[test]
    fn reason_with_embedded_waf_phrase_is_detected() {
        // WAF phrases may appear embedded in a longer reason string.
        let reason = "Server-side ENHANCE_YOUR_CALM enforcement active";
        let s = classify_h2_goaway(reason);
        assert!(
            s.is_some(),
            "ENHANCE_YOUR_CALM embedded in a longer reason must still be detected"
        );
        // Original full reason must be preserved, not just the matched phrase.
        if let Some(Signal::H2Goaway(r)) = s {
            assert_eq!(r, reason, "full reason must be preserved in signal");
        }
    }
}
