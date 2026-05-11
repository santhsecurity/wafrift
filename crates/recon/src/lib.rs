//! Origin discovery via OSINT (CT logs, DNS history) for WAF evasion.
//!
//! ## Active probing
//!
//! The [`active`] module performs in-band HTTP header classification (WAF / CDN /
//! framework heuristics driven by TOML rules) and TCP first-line banner grabs.
//!
//! This module fulfills the P3 "Full discovery (CT, historical DNS, leaks)" roadmap item.
//! It queries public APIs like crt.sh to discover subdomains that might point directly
//! to origin infrastructure, bypassing the edge WAF.
//!
//! # Examples
//!
//! Filter a candidate IP list to drop known CDN/WAF edge addresses —
//! the IPs left over are origin candidates worth probing directly:
//!
//! ```
//! use wafrift_recon::{filter_origin_ips, is_edge_ip};
//!
//! // Cloudflare, Fastly, CloudFront edge prefixes are recognised.
//! assert!(is_edge_ip("104.16.0.1"));     // Cloudflare
//! assert!(is_edge_ip("151.101.1.1"));    // Fastly
//! assert!(is_edge_ip("13.32.0.1"));      // CloudFront
//!
//! // Public origin IPs and RFC1918 ranges are not edge.
//! assert!(!is_edge_ip("8.8.8.8"));
//! assert!(!is_edge_ip("10.0.0.1"));
//!
//! let candidates = vec![
//!     "104.16.0.1".to_string(),    // Cloudflare — drop
//!     "10.0.0.1".to_string(),      // origin — keep
//!     "151.101.0.1".to_string(),   // Fastly — drop
//!     "192.168.1.1".to_string(),   // origin — keep
//! ];
//! let origins = filter_origin_ips(&candidates);
//! assert_eq!(origins, vec!["10.0.0.1", "192.168.1.1"]);
//! ```

use serde::Deserialize;
use std::time::Duration;
use thiserror::Error;

/// Timeout for outbound CT log queries. crt.sh routinely takes 10-20s
/// and occasionally hangs entirely; without a timeout `wafrift discover`
/// would be a DoS-on-self for every blocked-up upstream.
const CT_QUERY_TIMEOUT: Duration = Duration::from_secs(30);

/// Public error type for the recon crate. Library callers should pattern-
/// match on this rather than `anyhow::Error` so they can react to
/// transport vs parse vs status failures distinctly.
#[derive(Debug, Error)]
pub enum ReconError {
    #[error("crt.sh request failed: {0}")]
    Transport(#[from] reqwest::Error),

    #[error("crt.sh returned status {0}")]
    BadStatus(reqwest::StatusCode),

    #[error("failed to parse crt.sh response: {0}")]
    Parse(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, ReconError>;

#[derive(Debug, Deserialize)]
struct CrtShEntry {
    name_value: String,
}

/// Discovers potential origin subdomains via Certificate Transparency logs (crt.sh).
///
/// Returns a list of unique subdomains found for the target host.
pub async fn discover_subdomains_ct(domain: &str) -> Result<Vec<String>> {
    tracing::info!(domain, "querying crt.sh for CT logs");

    let client = reqwest::Client::builder()
        .timeout(CT_QUERY_TIMEOUT)
        .build()?;
    let url = format!("https://crt.sh/?q=%.{domain}&output=json");

    let res = client.get(&url).send().await?;

    if !res.status().is_success() {
        return Err(ReconError::BadStatus(res.status()));
    }

    let body = res.text().await?;
    let subdomains = parse_crtsh_response(&body, domain)?;

    tracing::info!(
        found = subdomains.len(),
        "discovered subdomains via CT logs"
    );
    Ok(subdomains)
}

/// Parse a crt.sh JSON response into deduplicated subdomain list.
///
/// Extracted for testability — this is the pure logic without HTTP.
fn parse_crtsh_response(body: &str, domain: &str) -> Result<Vec<String>> {
    let entries: Vec<CrtShEntry> = serde_json::from_str(body)?;

    let mut subdomains: Vec<String> = entries
        .into_iter()
        .flat_map(|e| {
            e.name_value
                .split('\n')
                .map(|s| s.trim().to_lowercase())
                .collect::<Vec<_>>()
        })
        .filter(|s| !s.is_empty() && !s.contains('*') && s != domain)
        .collect();

    subdomains.sort();
    subdomains.dedup();
    Ok(subdomains)
}

/// Resolves a list of hostnames to IP addresses using local DNS.
///
/// Filters out IPs that are known WAF/Edge networks (e.g. Cloudflare) to isolate origins.
pub async fn resolve_origins(hosts: &[String]) -> Result<Vec<String>> {
    let mut origin_ips = Vec::new();

    for host in hosts {
        // Simple tokio DNS resolution
        if let Ok(addrs) = tokio::net::lookup_host(format!("{host}:443")).await {
            for addr in addrs {
                let ip = addr.ip().to_string();
                if !is_edge_ip(&ip) {
                    origin_ips.push(ip);
                }
            }
        }
    }

    origin_ips.sort();
    origin_ips.dedup();

    Ok(origin_ips)
}

/// Known WAF/CDN IP ranges (CIDR prefixes) used to filter origins.
///
/// Returns `true` if the IP belongs to a known edge network.
#[must_use]
pub fn is_edge_ip(ip: &str) -> bool {
    // Cloudflare IPv4 ranges (prefixes — not exhaustive, but covers most)
    const CF_PREFIXES: &[&str] = &[
        "173.245.", "103.21.", "103.22.", "103.31.", "141.101.", "108.162.", "190.93.", "188.114.",
        "197.234.", "198.41.", "162.158.", "104.16.", "104.17.", "104.18.", "104.19.", "104.20.",
        "104.21.", "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
    ];
    // Fastly IPv4 prefixes
    const FASTLY_PREFIXES: &[&str] = &["151.101.", "199.232."];
    // AWS CloudFront prefix (partial)
    const CF_AWS_PREFIXES: &[&str] = &[
        "13.32.", "13.33.", "13.35.", "52.84.", "52.85.", "54.182.", "54.192.", "54.230.",
        "54.239.", "99.84.", "99.86.", "143.204.", "204.246.", "205.251.",
    ];

    CF_PREFIXES.iter().any(|p| ip.starts_with(p))
        || FASTLY_PREFIXES.iter().any(|p| ip.starts_with(p))
        || CF_AWS_PREFIXES.iter().any(|p| ip.starts_with(p))
}

/// Filter a list of IPs to remove known CDN/WAF edge addresses.
#[must_use]
pub fn filter_origin_ips(ips: &[String]) -> Vec<String> {
    ips.iter().filter(|ip| !is_edge_ip(ip)).cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_crtsh_response tests ─────────────────────────────────────

    #[test]
    fn parses_valid_crtsh_json() {
        let json = r#"[
            {"name_value": "api.example.com"},
            {"name_value": "www.example.com\nmail.example.com"},
            {"name_value": "*.example.com"},
            {"name_value": "example.com"}
        ]"#;

        let result = parse_crtsh_response(json, "example.com").unwrap();
        assert_eq!(
            result,
            vec!["api.example.com", "mail.example.com", "www.example.com",]
        );
    }

    #[test]
    fn deduplicates_subdomains() {
        let json = r#"[
            {"name_value": "api.example.com"},
            {"name_value": "api.example.com"},
            {"name_value": "API.EXAMPLE.COM"}
        ]"#;

        let result = parse_crtsh_response(json, "example.com").unwrap();
        assert_eq!(result, vec!["api.example.com"]);
    }

    #[test]
    fn filters_wildcards_and_base_domain() {
        let json = r#"[
            {"name_value": "*.example.com"},
            {"name_value": "example.com"},
            {"name_value": "sub.example.com"}
        ]"#;

        let result = parse_crtsh_response(json, "example.com").unwrap();
        assert_eq!(result, vec!["sub.example.com"]);
    }

    #[test]
    fn handles_empty_json_array() {
        let result = parse_crtsh_response("[]", "example.com").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn rejects_invalid_json() {
        let result = parse_crtsh_response("not json", "example.com");
        assert!(result.is_err());
    }

    #[test]
    fn handles_multiline_name_values() {
        let json = r#"[
            {"name_value": "a.example.com\nb.example.com\nc.example.com"}
        ]"#;

        let result = parse_crtsh_response(json, "example.com").unwrap();
        assert_eq!(
            result,
            vec!["a.example.com", "b.example.com", "c.example.com",]
        );
    }

    #[test]
    fn trims_whitespace_in_entries() {
        let json = r#"[
            {"name_value": "  api.example.com  "},
            {"name_value": "\n  www.example.com \n"}
        ]"#;

        let result = parse_crtsh_response(json, "example.com").unwrap();
        assert_eq!(result, vec!["api.example.com", "www.example.com",]);
    }

    // ── is_edge_ip tests ───────────────────────────────────────────────

    #[test]
    fn detects_cloudflare_ips() {
        assert!(is_edge_ip("104.16.0.1"));
        assert!(is_edge_ip("173.245.48.1"));
        assert!(is_edge_ip("141.101.64.1"));
    }

    #[test]
    fn detects_fastly_ips() {
        assert!(is_edge_ip("151.101.1.1"));
        assert!(is_edge_ip("199.232.0.1"));
    }

    #[test]
    fn detects_cloudfront_ips() {
        assert!(is_edge_ip("13.32.0.1"));
        assert!(is_edge_ip("54.230.0.1"));
    }

    #[test]
    fn allows_non_edge_ips() {
        assert!(!is_edge_ip("10.0.0.1"));
        assert!(!is_edge_ip("192.168.1.1"));
        assert!(!is_edge_ip("8.8.8.8"));
        assert!(!is_edge_ip("203.0.113.1"));
    }

    // ── filter_origin_ips tests ────────────────────────────────────────

    #[test]
    fn filters_edge_ips_from_list() {
        let ips = vec![
            "10.0.0.1".to_string(),    // origin — keep
            "104.16.0.1".to_string(),  // Cloudflare — filter
            "192.168.1.1".to_string(), // origin — keep
            "151.101.0.1".to_string(), // Fastly — filter
        ];

        let origins = filter_origin_ips(&ips);
        assert_eq!(origins, vec!["10.0.0.1", "192.168.1.1"]);
    }

    #[test]
    fn empty_list_returns_empty() {
        let origins = filter_origin_ips(&[]);
        assert!(origins.is_empty());
    }
}

pub mod discovery;

/// HTTP header probes and TCP banner classification for edge/stack fingerprinting.
pub mod active;
