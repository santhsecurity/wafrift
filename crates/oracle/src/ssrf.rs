//! SSRF (Server-Side Request Forgery) payload oracle.
//!
//! SSRF payloads manipulate URLs to make the server issue requests to
//! unintended destinations. A valid SSRF payload must preserve:
//! 1. **URL scheme** — `http://`, `https://`, `ftp://`, `file://`, etc.
//! 2. **Host identifier** — IP address, hostname, or special address like `[::1]`
//! 3. **Path/query structure** — `/admin`, `?action=read`, etc.
//!
//! If encoding destroys the URL structure, the request cannot be parsed
//! and the SSRF attack fails.

use crate::traits::PayloadOracle;
use serde::Deserialize;
use std::sync::OnceLock;

/// SSRF oracle that validates URL structure preservation.
pub struct SsrfOracle;

// ──────────────────────────────────────────────
//  Hardcoded constants (not in TOML - URL schemes are protocol constants)
// ──────────────────────────────────────────────

/// URL schemes that indicate a network request.
const URL_SCHEMES: &[&str] = &[
    "http://",
    "https://",
    "ftp://",
    "file://",
    "dict://",
    "gopher://",
    "ldap://",
    "ldaps://",
    "tftp://",
    "sftp://",
];

// ──────────────────────────────────────────────
//  TOML-loaded SSRF indicator rules
// ──────────────────────────────────────────────

/// Compile-time embedded TOML rules for SSRF indicators.
const SSRF_INDICATORS_TOML: &str = include_str!("../../../rules/ssrf/indicators.toml");

/// Indicator host definition from TOML.
#[derive(Debug, Clone, Deserialize)]
struct IndicatorHost {
    host: String,
    #[allow(dead_code)]
    description: String,
}

/// Private IP prefix definition from TOML.
#[derive(Debug, Clone, Deserialize)]
struct PrivateIpPrefix {
    prefix: String,
    #[allow(dead_code)]
    description: String,
}

/// Internal path definition from TOML.
#[derive(Debug, Clone, Deserialize)]
struct InternalPath {
    path: String,
    #[allow(dead_code)]
    description: String,
}

/// Root structure for indicators.toml.
#[derive(Debug, Clone, Deserialize)]
struct SsrfIndicatorRules {
    #[serde(default)]
    indicator_host: Vec<IndicatorHost>,
    #[serde(default)]
    private_ip_prefix: Vec<PrivateIpPrefix>,
    #[serde(default)]
    internal_path: Vec<InternalPath>,
}

/// Parse the embedded TOML rules once at first access.
fn get_rules() -> &'static SsrfIndicatorRules {
    static RULES: OnceLock<SsrfIndicatorRules> = OnceLock::new();
    RULES.get_or_init(|| {
        toml::from_str(SSRF_INDICATORS_TOML)
            .expect("Failed to parse rules/ssrf/indicators.toml - invalid TOML format")
    })
}

/// Get loopback/sensitive IP patterns that indicate SSRF intent.
fn ssrf_indicator_hosts() -> &'static [String] {
    static CACHE: OnceLock<Vec<String>> = OnceLock::new();
    CACHE.get_or_init(|| {
        get_rules()
            .indicator_host
            .iter()
            .map(|h| h.host.clone())
            .collect()
    })
}

/// Get private network ranges that indicate SSRF targets.
fn private_ip_prefixes() -> &'static [String] {
    static CACHE: OnceLock<Vec<String>> = OnceLock::new();
    CACHE.get_or_init(|| {
        get_rules()
            .private_ip_prefix
            .iter()
            .map(|p| p.prefix.clone())
            .collect()
    })
}

/// Get URL path indicators that suggest API/internal endpoints.
fn internal_path_indicators() -> &'static [String] {
    static CACHE: OnceLock<Vec<String>> = OnceLock::new();
    CACHE.get_or_init(|| {
        get_rules()
            .internal_path
            .iter()
            .map(|p| p.path.clone())
            .collect()
    })
}

/// Checks whether a payload contains SSRF URL structure.
fn has_ssrf_structure(payload: &str) -> bool {
    let lower = payload.to_ascii_lowercase();

    // Must have a URL scheme or be a bare IP/hostname
    let has_scheme = URL_SCHEMES.iter().any(|scheme| lower.starts_with(scheme));

    // Check for SSRF indicator hosts
    let has_indicator_host = ssrf_indicator_hosts()
        .iter()
        .any(|host| lower.contains(host));

    // Check for private IP prefixes
    let has_private_ip = private_ip_prefixes()
        .iter()
        .any(|prefix| lower.contains(prefix) || lower.contains(&prefix.replace('.', "_")));

    // Check for internal path indicators
    let has_internal_path = internal_path_indicators()
        .iter()
        .any(|path| lower.contains(path));

    // Valid SSRF structure: scheme + (indicator host OR private IP OR internal path)
    // OR protocol-relative URL (//localhost)
    let is_protocol_relative = payload.starts_with("//");

    has_scheme && (has_indicator_host || has_private_ip || has_internal_path)
        || is_protocol_relative
}

/// Validates that the payload looks like a parseable URL.
fn has_valid_url_syntax(payload: &str) -> bool {
    // Trailing nulls / UTF-8 replacement bytes from lossy decoding do not change URL semantics.
    let payload = payload.trim_end_matches(['\0', '\u{FFFD}']);

    // Protocol-relative URLs are valid SSRF structures
    if payload.starts_with("//") {
        return true;
    }

    // Use the `url` crate for rigorous validation
    match url::Url::parse(payload) {
        Ok(url) => {
            // Must have a scheme we recognize
            let scheme_ok = URL_SCHEMES
                .iter()
                .any(|s| s.trim_end_matches("://") == url.scheme());
            if !scheme_ok {
                return false;
            }
            // For non-file schemes, require some host component or a path
            if url.scheme() == "file" {
                return true;
            }
            // IPv6 literals must have matching brackets (Url enforces this)
            true
        }
        Err(_) => {
            // Fallback: allow raw scheme://[ IPv6 fragments that Url rejects
            // because they lack a closing bracket — we reject these.
            false
        }
    }
}

impl PayloadOracle for SsrfOracle {
    fn is_semantically_valid(&self, _original: &str, transformed: &str) -> bool {
        // Empty or whitespace-only is invalid
        if transformed.trim().is_empty() {
            return false;
        }

        // Must have SSRF structure (URL scheme + target)
        if !has_ssrf_structure(transformed) {
            return false;
        }

        // Must have valid URL syntax
        has_valid_url_syntax(transformed)
    }

    fn name(&self) -> &'static str {
        "SSRF"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn localhost_http_valid() {
        let oracle = SsrfOracle;
        assert!(oracle.is_semantically_valid("http://localhost/admin", "http://localhost/admin",));
    }

    #[test]
    fn loopback_ip_valid() {
        let oracle = SsrfOracle;
        assert!(oracle.is_semantically_valid("http://127.0.0.1/", "http://127.0.0.1/",));
    }

    #[test]
    fn https_localhost_valid() {
        let oracle = SsrfOracle;
        assert!(
            oracle.is_semantically_valid("https://localhost:8443/", "https://localhost:8443/",)
        );
    }

    #[test]
    fn aws_metadata_valid() {
        let oracle = SsrfOracle;
        assert!(oracle.is_semantically_valid(
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/",
        ));
    }

    #[test]
    fn gcp_metadata_valid() {
        let oracle = SsrfOracle;
        assert!(oracle.is_semantically_valid(
            "http://metadata.google.internal/",
            "http://metadata.google.internal/",
        ));
    }

    #[test]
    fn ipv6_loopback_valid() {
        let oracle = SsrfOracle;
        assert!(oracle.is_semantically_valid("http://[::1]/admin", "http://[::1]/admin",));
    }

    #[test]
    fn ipv4_mapped_ipv6_valid() {
        let oracle = SsrfOracle;
        assert!(
            oracle
                .is_semantically_valid("http://[::ffff:127.0.0.1]/", "http://[::ffff:127.0.0.1]/",)
        );
    }

    #[test]
    fn private_ip_10_x_valid() {
        let oracle = SsrfOracle;
        assert!(
            oracle.is_semantically_valid("http://10.0.0.1/internal", "http://10.0.0.1/internal",)
        );
    }

    #[test]
    fn private_ip_192_168_valid() {
        let oracle = SsrfOracle;
        assert!(oracle.is_semantically_valid("http://192.168.1.1/", "http://192.168.1.1/",));
    }

    #[test]
    fn ip_integer_encoding_valid() {
        let oracle = SsrfOracle;
        // 127.0.0.1 as 32-bit integer
        assert!(oracle.is_semantically_valid("http://2130706433/", "http://2130706433/",));
    }

    #[test]
    fn ip_octal_encoding_valid() {
        let oracle = SsrfOracle;
        assert!(oracle.is_semantically_valid("http://0177.0.0.1/", "http://0177.0.0.1/",));
    }

    #[test]
    fn protocol_relative_url_valid() {
        let oracle = SsrfOracle;
        assert!(oracle.is_semantically_valid("//localhost/admin", "//localhost/admin",));
    }

    #[test]
    fn file_scheme_valid() {
        let oracle = SsrfOracle;
        assert!(oracle.is_semantically_valid("file:///etc/passwd", "file:///etc/passwd",));
    }

    #[test]
    fn dict_scheme_valid() {
        let oracle = SsrfOracle;
        assert!(
            oracle.is_semantically_valid("dict://localhost:11211/", "dict://localhost:11211/",)
        );
    }

    #[test]
    fn gopher_scheme_valid() {
        let oracle = SsrfOracle;
        assert!(
            oracle.is_semantically_valid("gopher://localhost:9001/", "gopher://localhost:9001/",)
        );
    }

    #[test]
    fn internal_api_path_valid() {
        let oracle = SsrfOracle;
        assert!(oracle.is_semantically_valid(
            "http://127.0.0.1/api/v1/users",
            "http://127.0.0.1/api/v1/users",
        ));
    }

    #[test]
    fn internal_admin_path_valid() {
        let oracle = SsrfOracle;
        assert!(oracle.is_semantically_valid("http://localhost/admin", "http://localhost/admin",));
    }

    #[test]
    fn empty_string_invalid() {
        let oracle = SsrfOracle;
        assert!(!oracle.is_semantically_valid("http://127.0.0.1/", ""));
    }

    #[test]
    fn plain_text_invalid() {
        let oracle = SsrfOracle;
        assert!(!oracle.is_semantically_valid("http://127.0.0.1/", "hello world"));
    }

    #[test]
    fn url_without_scheme_invalid() {
        let oracle = SsrfOracle;
        // No scheme and doesn't start with //
        assert!(!oracle.is_semantically_valid("http://127.0.0.1/", "127.0.0.1/admin",));
    }

    #[test]
    fn public_url_invalid() {
        let oracle = SsrfOracle;
        // Public URL without internal indicators
        assert!(!oracle.is_semantically_valid("http://127.0.0.1/", "http://example.com/",));
    }

    #[test]
    fn destroyed_scheme_invalid() {
        let oracle = SsrfOracle;
        // URL encoding destroyed the scheme
        assert!(!oracle.is_semantically_valid("http://127.0.0.1/", "%68%74%74%70://127.0.0.1/",));
    }

    #[test]
    fn alibaba_metadata_valid() {
        let oracle = SsrfOracle;
        assert!(oracle.is_semantically_valid(
            "http://100.100.100.200/latest/meta-data/",
            "http://100.100.100.200/latest/meta-data/",
        ));
    }

    #[test]
    fn oracle_metadata_valid() {
        let oracle = SsrfOracle;
        assert!(oracle.is_semantically_valid("http://192.0.0.1/", "http://192.0.0.1/",));
    }

    #[test]
    fn zero_ip_valid() {
        let oracle = SsrfOracle;
        // 0 can represent 0.0.0.0
        assert!(oracle.is_semantically_valid("http://0/", "http://0/",));
    }

    #[test]
    fn short_loopback_valid() {
        let oracle = SsrfOracle;
        // 127.1 is shorthand for 127.0.0.1
        assert!(oracle.is_semantically_valid("http://127.1/", "http://127.1/",));
    }

    #[test]
    fn ldap_scheme_valid() {
        let oracle = SsrfOracle;
        assert!(oracle.is_semantically_valid("ldap://localhost:389/", "ldap://localhost:389/",));
    }

    #[test]
    fn url_with_query_valid() {
        let oracle = SsrfOracle;
        assert!(oracle.is_semantically_valid(
            "http://127.0.0.1/api?action=read",
            "http://127.0.0.1/api?action=read",
        ));
    }

    #[test]
    fn url_with_fragment_valid() {
        let oracle = SsrfOracle;
        assert!(
            oracle.is_semantically_valid("http://127.0.0.1/#section", "http://127.0.0.1/#section",)
        );
    }

    #[test]
    fn userinfo_in_url_valid() {
        let oracle = SsrfOracle;
        assert!(
            oracle.is_semantically_valid(
                "http://user:pass@127.0.0.1/",
                "http://user:pass@127.0.0.1/",
            )
        );
    }

    #[test]
    fn nip_io_domain_valid() {
        let oracle = SsrfOracle;
        // nip.io is a wildcard DNS that resolves to the IP in the subdomain
        assert!(
            oracle.is_semantically_valid("http://127.0.0.1.nip.io/", "http://127.0.0.1.nip.io/",)
        );
    }

    #[test]
    fn adversarial_unicode_host() {
        let oracle = SsrfOracle;
        // Unicode lookalike for localhost - should be invalid as it won't resolve
        // to the intended target
        assert!(!oracle.is_semantically_valid(
            "http://127.0.0.1/",
            "http://ｌｏｃａｌｈｏｓｔ/", // Fullwidth characters
        ));
    }

    #[test]
    fn adversarial_null_byte() {
        let oracle = SsrfOracle;
        // Null byte injection - structure is still valid
        assert!(oracle.is_semantically_valid("http://127.0.0.1/", "http://127.0.0.1/\x00",));
    }

    #[test]
    fn oracle_name_is_ssrf() {
        let oracle = SsrfOracle;
        assert_eq!(oracle.name(), "SSRF");
    }

    #[test]
    fn scheme_only_invalid() {
        let oracle = SsrfOracle;
        // Just a scheme with no host
        assert!(!oracle.is_semantically_valid("http://127.0.0.1/", "http://",));
    }

    #[test]
    fn ftp_scheme_private_ip_valid() {
        let oracle = SsrfOracle;
        assert!(oracle.is_semantically_valid("ftp://192.168.1.1/", "ftp://192.168.1.1/",));
    }
}
