//! Origin discovery via OSINT (CT logs, DNS history) and active HTTP/TCP probing for WAF evasion.
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

use thiserror::Error;

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

    #[error(
        "crt.sh response exceeded {limit} byte cap (got {got}+ bytes) — \
         refusing to buffer; aborting"
    )]
    ResponseTooLarge { limit: usize, got: usize },
}

/// Map the canonical [`ctlog`] error onto wafrift's public `ReconError`
/// so the crt.sh transport + parse can be shared fleet-wide without
/// changing this crate's error contract.
impl From<ctlog::CtError> for ReconError {
    fn from(e: ctlog::CtError) -> Self {
        match e {
            ctlog::CtError::Transport(t) => ReconError::Transport(t),
            ctlog::CtError::BadStatus(s) => ReconError::BadStatus(s),
            ctlog::CtError::Parse(p) => ReconError::Parse(p),
            ctlog::CtError::ResponseTooLarge { limit, got } => {
                ReconError::ResponseTooLarge { limit, got }
            }
        }
    }
}

pub type Result<T> = std::result::Result<T, ReconError>;

/// Discovers potential origin subdomains via Certificate Transparency logs (crt.sh).
///
/// Returns a list of unique subdomains found for the target host. The
/// crt.sh query URL, the bounded/timeout-guarded read, and the response
/// normalization all live in the canonical [`ctlog`] crate (wafrift was
/// the donor for that reader); this entry point preserves the historical
/// `ReconError` contract callers match on.
pub async fn discover_subdomains_ct(domain: &str) -> Result<Vec<String>> {
    Ok(ctlog::discover_subdomains_ct(domain).await?)
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

    // crt.sh query-URL construction + response normalization (the parse
    // path these tests used to cover) now live in the canonical `ctlog`
    // crate and are exercised by `ctlog`'s own suite. wafrift consumes
    // `ctlog::discover_subdomains_ct` via `discover_subdomains_ct` above;
    // the edge-IP origin-filtering below is wafrift-specific and stays here.

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

    // ── is_edge_ip hostile-input tests ─────────────────────────────────

    #[test]
    fn is_edge_ip_handles_empty_string() {
        assert!(!is_edge_ip(""));
    }

    #[test]
    fn is_edge_ip_handles_garbage_input() {
        // The string-prefix lookup happily inspects non-IP input;
        // hostile-source candidate lists (e.g. malformed entries
        // from a CT log) must not panic and must classify as
        // non-edge so the caller doesn't silently drop them.
        assert!(!is_edge_ip("not.an.ip"));
        assert!(!is_edge_ip("hello"));
        assert!(!is_edge_ip("..."));
    }

    #[test]
    fn is_edge_ip_handles_ipv6() {
        // No IPv6 ranges are encoded; IPv6 always classifies as
        // non-edge. The dual-stack origin-filtering path must
        // remain stable — `2606:4700::1111` is Cloudflare but the
        // prefix table only covers v4.
        assert!(!is_edge_ip("2606:4700::1111"));
        assert!(!is_edge_ip("::1"));
        assert!(!is_edge_ip("fe80::1"));
    }

    #[test]
    fn is_edge_ip_rejects_substring_match_in_middle() {
        // "10.104.16.0.1" CONTAINS "104.16." but doesn't START
        // with it — must not be classified as Cloudflare. This is
        // the regression test for the string-prefix approach: only
        // a true leading match counts.
        assert!(!is_edge_ip("10.104.16.0.1"));
        assert!(!is_edge_ip("99.151.101.1"));
    }

    #[test]
    fn is_edge_ip_handles_boundary_ips() {
        // Exact first IP of a Cloudflare prefix.
        assert!(is_edge_ip("104.16.0.0"));
        // Exact-prefix boundary — the trailing dot rule means
        // "104.16." matches "104.16.x.y" but NOT "104.160.0.1"
        // (which lives in a different /16). Documented invariant.
        assert!(!is_edge_ip("104.160.0.1"));
        assert!(!is_edge_ip("104.280.0.1")); // 104.28. is NOT covered
    }

    #[test]
    fn is_edge_ip_detects_fastly_secondary_prefix() {
        // 199.232. (the lesser-known Fastly prefix) is included.
        assert!(is_edge_ip("199.232.0.1"));
    }

    #[test]
    fn filter_origin_preserves_order() {
        let ips = vec![
            "203.0.113.5".into(),
            "104.16.0.1".into(), // CF — drop
            "203.0.113.6".into(),
        ];
        // Order of survivors == order in input.
        assert_eq!(
            filter_origin_ips(&ips),
            vec!["203.0.113.5".to_string(), "203.0.113.6".to_string()]
        );
    }

    #[test]
    fn filter_origin_preserves_duplicates() {
        // No dedup — caller decides. A repeated non-edge IP comes
        // back twice. (Important: dedup-by-default could silently
        // mask a CT log that lists the same origin under multiple
        // alias names.)
        let ips = vec!["10.0.0.1".into(), "10.0.0.1".into()];
        assert_eq!(filter_origin_ips(&ips).len(), 2);
    }
}

pub mod discovery;

/// HTTP header probes and TCP banner classification for edge/stack fingerprinting.
pub mod active;
