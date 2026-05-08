//! WAF header signal classification.
//!
//! Many WAFs leak their presence through response headers. Detecting
//! these headers provides two benefits:
//! 1. **WAF identification** — knowing which WAF we face lets us
//!    select targeted bypass strategies.
//! 2. **Block signal** — some headers only appear on blocked requests,
//!    providing a strong classification signal even with 200 status.

use wafrift_types::Signal;

/// Known WAF response headers and their significance.
///
/// Format: (header_name_lowercase, value_pattern, signal_description)
const WAF_HEADERS: &[(&str, &str, &str)] = &[
    // Cloudflare
    ("cf-ray", "", "cloudflare_ray_id"),
    ("cf-mitigated", "", "cloudflare_mitigated"),
    ("cf-cache-status", "", "cloudflare_cache"),
    // Akamai
    ("x-akamai-transformed", "", "akamai_transformed"),
    ("akamai-grn", "", "akamai_grn"),
    // AWS WAF / CloudFront
    ("x-amzn-requestid", "", "aws_request_id"),
    ("x-amzn-waf-action", "block", "aws_waf_block"),
    ("x-amzn-waf-action", "allow", "aws_waf_allow"),
    // Imperva / Incapsula
    ("x-iinfo", "", "imperva_incapsula"),
    ("x-cdn", "Incapsula", "imperva_incapsula_cdn"),
    // ModSecurity
    ("x-mod-security", "", "modsecurity"),
    ("server", "ModSecurity", "modsecurity_server"),
    // Sucuri
    ("x-sucuri-id", "", "sucuri_waf"),
    ("x-sucuri-cache", "", "sucuri_cache"),
    // F5 BIG-IP ASM
    ("x-waf-status", "", "f5_bigip_waf"),
    ("ts", "", "f5_bigip_cookie"),
    // Barracuda
    ("barra_counter_session", "", "barracuda_waf"),
    // Fortinet / FortiWeb
    ("fortiwafd", "", "fortiweb"),
    // DDoS-GUARD
    ("server", "ddos-guard", "ddos_guard"),
    // Generic block indicators
    ("x-blocked-by", "", "generic_blocked_by"),
    ("x-waf-event-info", "", "generic_waf_event"),
    ("x-firewall-protection", "", "generic_firewall"),
];

/// Block-specific headers — these ONLY appear when the WAF blocks a request.
const BLOCK_HEADERS: &[&str] = &[
    "x-amzn-waf-action",
    "cf-mitigated",
    "x-blocked-by",
    "x-waf-event-info",
    "x-mod-security",
    "x-waf-status",
];

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
        if BLOCK_HEADERS.contains(&name_lower.as_str()) {
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
        assert!(signals.len() >= 2, "should detect both WAF header and block header");
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
            if let Signal::BodyMarker(m) = s { m.contains("aws_waf_allow") } else { false }
        });
        assert!(has_allow, "should detect AWS WAF allow action");
    }
}
