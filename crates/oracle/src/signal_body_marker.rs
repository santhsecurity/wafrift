//! Body-marker signal extractor.
//!
//! Scans response bodies for known WAF block-page markers and success
//! indicators. Operates on raw bytes and can decompress gzip if needed.

use std::io::Read;
use wafrift_types::{BlockReason, Signal};

/// Known block-page substrings (case-insensitive).
const BLOCK_MARKERS: &[&str] = &[
    "access denied",
    "forbidden",
    "blocked",
    "waf",
    "cloudflare",
    "akamai",
    "incapsula",
    "sucuri",
    "mod_security",
    "modsecurity",
    "owasp",
    "imperva",
    "big-ip",
    "f5",
    "rule violation",
    "request rejected",
    "unauthorized request",
    "bad request",
    "security check",
    "challenge",
];

/// Known challenge-page substrings.
const CHALLENGE_MARKERS: &[&str] = &[
    "challenge-platform",
    "cf-im-under-attack",
    "jschl_vc",
    "js_challenge",
    "recaptcha",
    "g-recaptcha",
    "hcaptcha",
    "turnstile",
    "checking your browser",
    "ddos-guard",
    "please wait",
];

/// Known rate-limit substrings.
const RATE_LIMIT_MARKERS: &[&str] = &[
    "rate limit",
    "too many requests",
    "slow down",
    "throttled",
    "quota exceeded",
];

/// Known success markers.
const SUCCESS_MARKERS: &[&str] = &[
    "welcome",
    "login successful",
    "success",
    "authenticated",
    "dashboard",
    "home",
];

/// Extract body-marker signals from a response body.
///
/// # Arguments
///
/// * `body` — Raw response body bytes.
/// * `is_gzipped` — Whether the body is gzip-compressed.
///
/// # Returns
///
/// A vector of signals for every matched marker.
#[must_use]
pub fn extract_body_signals(body: &[u8], is_gzipped: bool) -> Vec<Signal> {
    let text = if is_gzipped {
        decompress_gzip(body).unwrap_or_default()
    } else {
        String::from_utf8_lossy(body).to_string()
    };
    let lower = text.to_ascii_lowercase();
    let mut signals = Vec::new();

    for marker in BLOCK_MARKERS {
        if lower.contains(marker) {
            signals.push(Signal::BodyMarker(marker.to_string()));
        }
    }
    for marker in CHALLENGE_MARKERS {
        if lower.contains(marker) {
            signals.push(Signal::ChallengePlatform(marker.to_string()));
        }
    }
    for marker in RATE_LIMIT_MARKERS {
        if lower.contains(marker) {
            signals.push(Signal::BodyMarker(format!("rate-limit: {marker}")));
        }
    }
    for marker in SUCCESS_MARKERS {
        if lower.contains(marker) {
            signals.push(Signal::SuccessMarker(marker.to_string()));
        }
    }

    signals
}

/// Attempt to extract a block reason from the response body.
#[must_use]
pub fn extract_block_reason(body: &[u8], is_gzipped: bool) -> Option<BlockReason> {
    let text = if is_gzipped {
        decompress_gzip(body).unwrap_or_default()
    } else {
        String::from_utf8_lossy(body).to_string()
    };
    let lower = text.to_ascii_lowercase();

    // Rule ID patterns: "Rule ID: 12345", "rule_id=12345", etc.
    for prefix in ["rule id:", "rule_id", "ruleid", " incident id:"] {
        if let Some(pos) = lower.find(prefix) {
            let start = pos + prefix.len();
            let after = &text[start..];
            let id: String = after
                .trim_start_matches(|c: char| !c.is_ascii_digit())
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '-' || *c == '_')
                .collect();
            if !id.is_empty() {
                return Some(BlockReason::RuleId(id));
            }
        }
    }

    // Category patterns
    for cat in ["sql injection", "xss", "rfi", "lfi", "rce", "cmd injection"] {
        if lower.contains(cat) {
            return Some(BlockReason::RuleCategory(cat.to_string()));
        }
    }

    // Vendor-specific prefixes
    for vendor in [
        "cloudflare",
        "akamai",
        "imperva",
        "f5",
        "aws waf",
        "modsecurity",
    ] {
        if lower.contains(vendor) {
            return Some(BlockReason::VendorReason(vendor.to_string()));
        }
    }

    // Custom block page
    for marker in BLOCK_MARKERS {
        if lower.contains(marker) {
            return Some(BlockReason::CustomBlockPage(marker.to_string()));
        }
    }

    None
}

fn decompress_gzip(data: &[u8]) -> Option<String> {
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut out = String::new();
    decoder.read_to_string(&mut out).ok()?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_marker_detected() {
        let body = b"Access Denied - Your request was blocked.";
        let signals = extract_body_signals(body, false);
        assert!(
            signals
                .iter()
                .any(|s| matches!(s, Signal::BodyMarker(m) if m == "access denied"))
        );
    }

    #[test]
    fn challenge_marker_detected() {
        let body = b"<script>challenge-platform</script>";
        let signals = extract_body_signals(body, false);
        assert!(
            signals
                .iter()
                .any(|s| matches!(s, Signal::ChallengePlatform(m) if m == "challenge-platform"))
        );
    }

    #[test]
    fn block_reason_rule_id() {
        let body = b"Error: Rule ID: 12345 triggered";
        let reason = extract_block_reason(body, false);
        assert_eq!(reason, Some(BlockReason::RuleId("12345".into())));
    }

    #[test]
    fn block_reason_vendor() {
        let body = b"Protected by Cloudflare";
        let reason = extract_block_reason(body, false);
        assert_eq!(reason, Some(BlockReason::VendorReason("cloudflare".into())));
    }

    #[test]
    fn gzipped_body_decompress() {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"access denied").unwrap();
        let gzipped = encoder.finish().unwrap();

        let signals = extract_body_signals(&gzipped, true);
        assert!(
            signals
                .iter()
                .any(|s| matches!(s, Signal::BodyMarker(m) if m == "access denied"))
        );
    }
}
