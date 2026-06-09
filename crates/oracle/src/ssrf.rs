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

use crate::ascii_scan::{contains_ascii_insensitive, starts_with_ascii_insensitive};
use crate::traits::PayloadOracle;
use serde::Deserialize;
use std::sync::OnceLock;

/// SSRF oracle that validates URL structure preservation.
pub struct SsrfOracle;

// ──────────────────────────────────────────────
//  Hardcoded constants (not in TOML - URL schemes are protocol constants)
// ──────────────────────────────────────────────

/// URL schemes that indicate a network request — loaded from
/// `rules/ssrf/schemes.toml` so the community can extend the set
/// without touching Rust.
#[derive(serde::Deserialize)]
struct SchemeRules {
    scheme: Vec<SchemePrefix>,
}
#[derive(serde::Deserialize)]
struct SchemePrefix {
    prefix: String,
}

fn url_schemes() -> &'static [String] {
    static CACHE: OnceLock<Vec<String>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let raw = include_str!("../rules/ssrf/schemes.toml");
        let parsed: SchemeRules = toml::from_str(raw).expect("rules/ssrf/schemes.toml must parse");
        parsed.scheme.into_iter().map(|s| s.prefix).collect()
    })
}

// ──────────────────────────────────────────────
//  TOML-loaded SSRF indicator rules
// ──────────────────────────────────────────────

/// Compile-time embedded TOML rules for SSRF indicators.
const SSRF_INDICATORS_TOML: &str = include_str!("../rules/ssrf/indicators.toml");

// Per consolidation F13: `description` is a TOML doc field, not
// consumed at runtime. Serde ignores unknown fields by default.

/// Indicator host definition from TOML.
#[derive(Debug, Clone, Deserialize)]
struct IndicatorHost {
    host: String,
}

/// Private IP prefix definition from TOML.
#[derive(Debug, Clone, Deserialize)]
struct PrivateIpPrefix {
    prefix: String,
}

/// Internal path definition from TOML.
#[derive(Debug, Clone, Deserialize)]
struct InternalPath {
    path: String,
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
        toml::from_str(SSRF_INDICATORS_TOML).unwrap_or_else(|_| SsrfIndicatorRules {
            indicator_host: Vec::new(),
            private_ip_prefix: Vec::new(),
            internal_path: Vec::new(),
        })
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

/// Whole-token matcher for short indicator hosts (the "0" shorthand
/// being the canonical case). A token is bounded by `://`, `/`, `?`,
/// `#`, `:`, or end-of-string — i.e. the URL grammar boundaries
/// around an authority. Returns true iff one occurrence of `host`
/// in `payload` is a complete authority component, ignoring case.
fn host_is_complete_token(payload: &str, host: &str) -> bool {
    let host_bytes = host.as_bytes();
    if host_bytes.is_empty() {
        return false;
    }
    let bytes = payload.as_bytes();
    let is_boundary = |b: u8| -> bool {
        // URL authority terminators + scheme separator bytes,
        // plus IPv6 authority brackets `[` `]`.
        matches!(
            b,
            b'/' | b'?' | b'#' | b':' | b'@' | b'[' | b']' | b' ' | b'\t' | b'\n' | b'\r'
        )
    };
    let mut i = 0;
    while i + host_bytes.len() <= bytes.len() {
        let prefix_match = bytes[i..i + host_bytes.len()]
            .iter()
            .zip(host_bytes.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b));
        if prefix_match {
            // Left boundary: start-of-string OR after `//` OR after a boundary char.
            let left_ok =
                i == 0 || is_boundary(bytes[i - 1]) || (i >= 2 && &bytes[i - 2..i] == b"//");
            // Right boundary: end-of-string OR boundary char.
            let right_ok =
                i + host_bytes.len() == bytes.len() || is_boundary(bytes[i + host_bytes.len()]);
            if left_ok && right_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Extract the authority (host[:port][@userinfo]) from a
/// `scheme://...` URL. Returns the authority slice without the
/// surrounding URL plumbing. None when the payload doesn't have a
/// `://` separator — caller decides the fallback.
fn extract_authority(payload: &str) -> Option<&str> {
    let scheme_end = payload.find("://")?;
    let auth_start = scheme_end + 3;
    let rest = payload.get(auth_start..)?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    Some(&rest[..end])
}

/// Checks whether a payload contains SSRF URL structure.
fn has_ssrf_structure(payload: &str) -> bool {
    // Protocol-relative URLs are valid SSRF shapes; no need to scan megabyte bodies for indicators.
    if payload.starts_with("//") {
        return true;
    }

    // Must have a URL scheme or be a bare IP/hostname
    let has_scheme = url_schemes()
        .iter()
        .any(|scheme| starts_with_ascii_insensitive(payload, scheme));

    if !has_scheme {
        return false;
    }

    // F130: indicator host + private-IP checks were previously run
    // against the WHOLE payload via substring match. That turns
    // `http://example.com/api/v10.txt` into a false-positive SSRF
    // (because `10.` matches the private prefix list anywhere in the
    // URL), and worse, anti-rigs the bypass count by accepting
    // mutations whose host became public but whose path happened to
    // include an indicator-shaped substring. Extract the URL
    // authority first and run host/IP-prefix checks against THAT.
    // Fall back to the whole payload if extraction fails (preserves
    // behavior for non-standard URL shapes).
    let authority = extract_authority(payload).unwrap_or(payload);

    // Check for SSRF indicator hosts. Single-character indicator
    // tokens (the legitimate "0" → "0.0.0.0" shorthand) MUST be
    // matched as a complete host token, not a substring — otherwise
    // any URL containing the digit '0' (e.g. /page?id=100) trips
    // the indicator. Multi-character indicators are substring
    // matched against the AUTHORITY only.
    let has_indicator_host = ssrf_indicator_hosts().iter().any(|host| {
        if host.len() <= 2 {
            host_is_complete_token(authority, host)
        } else {
            contains_ascii_insensitive(authority, host)
        }
    });

    // Private IP prefixes likewise scan the authority only — a `10.`
    // sitting in the path is not a private-IP indicator.
    let has_private_ip = private_ip_prefixes().iter().any(|prefix| {
        contains_ascii_insensitive(authority, prefix)
            || contains_ascii_insensitive(authority, &prefix.replace('.', "_"))
    });

    // Internal-path indicators DO scan the full payload — they are
    // path patterns by definition (`/api/`, `/admin/`, etc.).
    let has_internal_path = internal_path_indicators()
        .iter()
        .any(|path| contains_ascii_insensitive(payload, path));

    // Valid SSRF structure: scheme + (indicator host OR private IP OR internal path)
    has_indicator_host || has_private_ip || has_internal_path
}

/// Upper bound for passing the full string into the URL parser (hostile multi-megabyte bodies).
const MAX_URL_PARSE_BYTES: usize = 16 * 1024 * 1024;

/// Validates that the payload looks like a parseable URL.
fn has_valid_url_syntax(payload: &str) -> bool {
    // Trailing nulls / UTF-8 replacement bytes from lossy decoding do not change URL semantics.
    let payload = payload.trim_end_matches(['\0', '\u{FFFD}']);

    // Protocol-relative URLs are valid SSRF structures
    if payload.starts_with("//") {
        return true;
    }

    if payload.len() > MAX_URL_PARSE_BYTES {
        return false;
    }

    // Use the `url` crate for rigorous validation
    match url::Url::parse(payload) {
        Ok(url) => {
            // Must have a scheme we recognize
            let scheme_ok = url_schemes()
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
            // Salvage known split-parsing bypass families where url::Url
            // rejects the raw form but real backends still ingest it.
            // Currently covers NUL-in-authority (CVE-2017-15046 family):
            // `http://127.0.0.1%00.evil.com/` and
            // `http://127.0.0.1\0.evil.com/` are parsed by some
            // backend HTTP clients as host=127.0.0.1 while permissive
            // SSRF allowlists see the suffix and assume it's safe.
            //
            // Strategy: locate the first encoded or literal NUL after
            // the `://` authority boundary, strip it and everything
            // after, then re-parse the prefix. If the prefix is a
            // valid SSRF-shaped URL, accept the original.
            //
            // Bare `scheme://[ipv6-fragment` (no closing bracket) is
            // still rejected — the salvage only fires on NUL.
            nul_in_authority_salvage(payload)
        }
    }
}

/// Salvage URL parsing for the NUL-in-authority bypass family.
/// See `has_valid_url_syntax` for the rationale. Returns true iff
/// the prefix preceding the first encoded-or-literal NUL (after
/// `://`) parses as a valid URL whose HOST is itself an SSRF
/// target — the salvage must not promote arbitrary public hosts.
fn nul_in_authority_salvage(payload: &str) -> bool {
    // Find the `://` authority boundary; if missing, no salvage.
    let Some(authority_start) = payload.find("://") else {
        return false;
    };
    let after_scheme = authority_start + "://".len();
    let tail = &payload[after_scheme..];

    // Look for percent-encoded NUL (case-insensitive) or literal NUL.
    let mut nul_offset: Option<usize> = None;
    let bytes = tail.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0 {
            nul_offset = Some(i);
            break;
        }
        if i + 3 <= bytes.len()
            && bytes[i] == b'%'
            && bytes[i + 1] == b'0'
            && (bytes[i + 2] == b'0')
        {
            nul_offset = Some(i);
            break;
        }
        i += 1;
    }
    let Some(off) = nul_offset else {
        return false;
    };

    // Reconstruct prefix + trailing slash so the parser sees a valid
    // URL with empty path (rather than authority-only ambiguity).
    let prefix = &payload[..after_scheme + off];
    let candidate = format!("{prefix}/");

    let Ok(url) = url::Url::parse(&candidate) else {
        return false;
    };
    if !url_schemes()
        .iter()
        .any(|s| s.trim_end_matches("://") == url.scheme())
    {
        return false;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    // Salvage gate: the bypass is only "really" SSRF if the
    // pre-NUL host is one of: an indicator host (127.0.0.1,
    // localhost, metadata names, ...) OR begins with a private-IP
    // prefix (10., 127., 192.168., ...). This is the per-host
    // version of the looser `has_ssrf_structure` check, applied to
    // the parsed authority instead of the raw payload — so
    // "%00." substring tricks against public hosts no longer
    // promote them.
    let host_lc = host.to_ascii_lowercase();
    let indicator_hit = ssrf_indicator_hosts()
        .iter()
        .any(|h| host_lc == h.to_ascii_lowercase());
    let private_hit = private_ip_prefixes()
        .iter()
        .any(|p| host_lc.starts_with(&p.to_ascii_lowercase()));
    indicator_hit || private_hit
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
    fn short_indicator_requires_token_boundary() {
        // "0" should match when it's a standalone host token
        assert!(host_is_complete_token("http://0/", "0"));
        assert!(host_is_complete_token("0", "0"));
        // "0" should NOT match as a substring inside "100"
        assert!(!host_is_complete_token("/page?id=100", "0"));
        // "0" should NOT match as a substring inside "a0b"
        assert!(!host_is_complete_token("a0b", "0"));
        // The IPv6 `::` substring inside `abc::def` is not at a
        // host boundary — the surrounding `c` and `d` are not
        // authority delimiters.
        assert!(!host_is_complete_token("abc::def", "::"));
    }

    #[test]
    fn ftp_scheme_private_ip_valid() {
        let oracle = SsrfOracle;
        assert!(oracle.is_semantically_valid("ftp://192.168.1.1/", "ftp://192.168.1.1/",));
    }

    // F130 regression suite: indicator-host + private-IP scans must
    // run against the URL authority, NOT the whole payload. Pre-fix
    // a public URL with a `10.` or `127.` substring anywhere in the
    // path/query falsely matched a private indicator — anti-rigging
    // the bypass count for SSRF mutations that became public.

    #[test]
    fn extract_authority_basic_host() {
        assert_eq!(
            extract_authority("http://example.com/"),
            Some("example.com")
        );
        assert_eq!(
            extract_authority("http://example.com/path?q=1"),
            Some("example.com")
        );
        assert_eq!(extract_authority("http://example.com"), Some("example.com"));
    }

    #[test]
    fn extract_authority_with_port_and_userinfo() {
        assert_eq!(
            extract_authority("http://user:pass@127.0.0.1:8080/admin"),
            Some("user:pass@127.0.0.1:8080")
        );
    }

    #[test]
    fn extract_authority_no_scheme_returns_none() {
        assert_eq!(extract_authority("not-a-url"), None);
        assert_eq!(extract_authority("/path/only"), None);
    }

    #[test]
    fn extract_authority_fragment_terminates_authority() {
        assert_eq!(
            extract_authority("http://example.com#frag"),
            Some("example.com")
        );
    }

    #[test]
    fn public_url_with_private_prefix_in_path_rejected() {
        // Pre-fix: substring `10.` matched private prefix list
        // anywhere in payload → false-positive SSRF. Avoid `/api/`
        // in this test URL because internal_path indicators ALSO
        // scan full payload (separate concern from F130).
        let oracle = SsrfOracle;
        assert!(
            !oracle
                .is_semantically_valid("http://127.0.0.1/wiki", "http://example.com/wiki/v10.txt",),
            "F130: public host with '10.' in path is NOT SSRF"
        );
    }

    #[test]
    fn public_url_with_loopback_in_query_rejected() {
        // `127.0.0.1` substring in a query string does not make the
        // request go to localhost.
        let oracle = SsrfOracle;
        assert!(
            !oracle
                .is_semantically_valid("http://127.0.0.1/", "http://example.com/?ref=127.0.0.1",),
            "F130: public host with '127.0.0.1' in query is NOT SSRF"
        );
    }

    #[test]
    fn public_url_with_metadata_hostname_in_path_rejected() {
        let oracle = SsrfOracle;
        assert!(
            !oracle.is_semantically_valid(
                "http://169.254.169.254/",
                "http://example.com/wiki/169.254.169.254",
            ),
            "F130: public host with metadata IP in path is NOT SSRF"
        );
    }

    #[test]
    fn public_url_with_localhost_in_query_rejected() {
        let oracle = SsrfOracle;
        assert!(
            !oracle
                .is_semantically_valid("http://localhost/", "http://example.com/?host=localhost",),
            "F130: public host with 'localhost' in query is NOT SSRF"
        );
    }

    #[test]
    fn anti_rig_public_url_with_router_ip_substring_rejected() {
        // `172.16.` is a private prefix — must match only in authority.
        let oracle = SsrfOracle;
        assert!(
            !oracle.is_semantically_valid(
                "http://172.16.0.1/",
                "http://news.example.com/172.16.0.1-router-review",
            ),
            "F130: blog about routers should not be flagged as SSRF"
        );
    }

    #[test]
    fn private_ip_in_authority_still_accepted() {
        // Regression-guard: the F130 fix must NOT loosen the real
        // positive case where the private IP IS the authority.
        let oracle = SsrfOracle;
        assert!(oracle.is_semantically_valid("http://10.0.0.5/", "http://10.0.0.5/"));
        assert!(oracle.is_semantically_valid("http://172.16.0.1/api", "http://172.16.0.1/api"));
        assert!(oracle.is_semantically_valid(
            "http://169.254.169.254/latest/",
            "http://169.254.169.254/latest/"
        ));
    }
}
