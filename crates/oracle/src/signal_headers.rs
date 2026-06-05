//! WAF header signal classification.
//!
//! Many WAFs leak their presence through response headers. Detecting
//! these headers provides two benefits:
//! 1. **WAF identification** — knowing which WAF we face lets us
//!    select targeted bypass strategies.
//! 2. **Block signal** — some headers only appear on blocked requests,
//!    providing a strong classification signal even with 200 status.
//!
//! `WAF_HEADERS` and `BLOCK_HEADER_NAMES` come from
//! `crates/oracle/rules/markers/{waf_headers,block_headers}.toml` via
//! `build.rs` — adding a header is a one-line PR with no Rust knowledge.

use wafrift_types::Signal;

// `WAF_HEADERS` and `BLOCK_HEADER_NAMES` are emitted by build.rs into
// markers_data.rs, which is included by signal_body_marker.rs. Re-import
// here via the parent crate path.
use crate::signal_body_marker::{BLOCK_HEADER_NAMES, WAF_HEADERS};

/// Classify response headers for WAF signals.
///
/// Returns a list of signals indicating WAF presence and block indicators.
pub fn classify_headers(headers: &[(String, String)]) -> Vec<Signal> {
    let mut signals = Vec::new();

    for (header_name, header_value) in headers {
        let name_lower = header_name.to_ascii_lowercase();
        let value_lower = header_value.to_ascii_lowercase();

        for &(waf_header, value_pattern, description) in WAF_HEADERS {
            if name_lower == waf_header {
                // If a value pattern is specified, check it matches
                if value_pattern.is_empty() || value_lower.contains(value_pattern) {
                    signals.push(Signal::BodyMarker(format!("header:{description}")));
                }
            }
        }

        // Check for explicit block headers
        if BLOCK_HEADER_NAMES.contains(&name_lower.as_str()) {
            signals.push(Signal::BodyMarker(format!(
                "waf_block_header:{}={}",
                name_lower,
                header_value.chars().take(64).collect::<String>()
            )));
        }
    }

    signals
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_cloudflare() {
        let headers = vec![("cf-ray".to_string(), "abc123".to_string())];
        let signals = classify_headers(&headers);
        assert!(!signals.is_empty());
        assert!(signals.iter().any(|s| {
            if let Signal::BodyMarker(m) = s {
                m.contains("cloudflare")
            } else {
                false
            }
        }));
    }

    #[test]
    fn detects_aws_waf_block() {
        let headers = vec![("x-amzn-waf-action".to_string(), "block".to_string())];
        let signals = classify_headers(&headers);
        assert!(
            signals.len() >= 2,
            "should detect both WAF header and block header"
        );
    }

    #[test]
    fn detects_imperva() {
        let headers = vec![("x-iinfo".to_string(), "test123".to_string())];
        let signals = classify_headers(&headers);
        assert!(!signals.is_empty());
    }

    #[test]
    fn ignores_unrelated_headers() {
        let headers = vec![
            ("content-type".to_string(), "text/html".to_string()),
            ("content-length".to_string(), "1024".to_string()),
        ];
        let signals = classify_headers(&headers);
        assert!(signals.is_empty());
    }

    #[test]
    fn case_insensitive_header_names() {
        let headers = vec![("CF-Ray".to_string(), "abc".to_string())];
        let signals = classify_headers(&headers);
        assert!(!signals.is_empty(), "should match case-insensitively");
    }

    #[test]
    fn value_pattern_matching() {
        // x-amzn-waf-action: allow should match the allow pattern, not block
        let headers = vec![("x-amzn-waf-action".to_string(), "allow".to_string())];
        let signals = classify_headers(&headers);
        let has_allow = signals.iter().any(|s| {
            if let Signal::BodyMarker(m) = s {
                m.contains("aws_waf_allow")
            } else {
                false
            }
        });
        assert!(has_allow, "should detect AWS WAF allow action");
    }

    // -- §12 boundary tests -------------------------------------------------

    #[test]
    fn empty_header_list_produces_no_signals() {
        let signals = classify_headers(&[]);
        assert!(signals.is_empty(), "empty header list must produce no signals");
    }

    #[test]
    fn multiple_waf_headers_all_detected() {
        // A response carrying both cf-ray and x-iinfo must produce a signal
        // for each -- no early-exit on first match.
        let headers = vec![
            ("cf-ray".to_string(), "abc".to_string()),
            ("x-iinfo".to_string(), "xyz".to_string()),
        ];
        let signals = classify_headers(&headers);
        assert!(
            signals.len() >= 2,
            "both WAF headers must produce signals, got: {signals:?}"
        );
    }

    #[test]
    fn header_value_uppercase_matched_case_insensitively() {
        // Header value matching must be case-insensitive.
        let headers = vec![("x-amzn-waf-action".to_string(), "BLOCK".to_string())];
        let signals = classify_headers(&headers);
        assert!(
            !signals.is_empty(),
            "uppercase BLOCK must be matched case-insensitively"
        );
    }

    #[test]
    fn block_header_value_long_does_not_panic() {
        // A hostile server sending a 100-char header value must not panic
        // or produce a signal with unbounded length.
        let long_value = "x".repeat(200);
        let headers = vec![("x-amzn-waf-action".to_string(), long_value)];
        // Must not panic.
        let signals = classify_headers(&headers);
        // Check that any BodyMarker signals have reasonably bounded length.
        for s in &signals {
            if let Signal::BodyMarker(m) = s {
                assert!(
                    m.len() <= 512,
                    "signal string should not be unbounded: len={} sig={m}",
                    m.len()
                );
            }
        }
    }
}
