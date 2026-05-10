//! Upstream destination policy: literal-IP bogons and DNS SSRF-style checks.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

/// Policy for CONNECT and cleartext forward destinations.
#[derive(Debug, Clone, Default)]
pub struct UpstreamPolicy {
    /// Allow RFC1918 / loopback / link-local targets (literal or DNS).
    pub allow_private_upstream: bool,
    /// Skip all destination checks (lab only).
    pub insecure_open_upstream: bool,
}

/// True if this IP should be blocked when `allow_private_upstream` is false.
#[must_use]
pub fn ip_addr_is_bogon(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            if v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_broadcast()
                || v.is_documentation()
                || v.is_unspecified()
            {
                return true;
            }
            // Audit additions (2026-05-10):
            //   100.64.0.0/10  — Carrier-Grade NAT (RFC 6598)
            //   192.0.0.0/24   — IETF protocol assignments (RFC 6890)
            //   198.18.0.0/15  — benchmark testing (RFC 2544)
            // These are not "private" per std::net::Ipv4Addr but
            // routing them upstream from a security tool would still
            // exfiltrate to attacker-side infra in many topologies.
            let octets = v.octets();
            if octets[0] == 100 && (octets[1] & 0xc0) == 0x40 {
                return true; // 100.64.0.0/10
            }
            if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
                return true; // 192.0.0.0/24
            }
            if octets[0] == 198 && (octets[1] & 0xfe) == 18 {
                return true; // 198.18.0.0/15
            }
            false
        }
        IpAddr::V6(v) => {
            // IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1, ::ffff:169.254.169.254)
            // would otherwise sneak past the V6 bogon checks because
            // is_loopback / is_unique_local return false for the mapped form.
            // Re-check the embedded V4 explicitly. Same for IPv4-compatible
            // (deprecated) form.
            if let Some(mapped) = v.to_ipv4_mapped() {
                return ip_addr_is_bogon(IpAddr::V4(mapped));
            }
            if let Some(compat) = v.to_ipv4() {
                return ip_addr_is_bogon(IpAddr::V4(compat));
            }
            // 6to4 (RFC 3056) embeds an IPv4 in `2002:WWXX:YYZZ::/48`.
            // If the embedded V4 is a bogon, the V6 transitively is —
            // an attacker that controls a 6to4 gateway could otherwise
            // route us to RFC1918 space.
            let segs = v.segments();
            if segs[0] == 0x2002 {
                let v4 = std::net::Ipv4Addr::new(
                    (segs[1] >> 8) as u8,
                    (segs[1] & 0xff) as u8,
                    (segs[2] >> 8) as u8,
                    (segs[2] & 0xff) as u8,
                );
                if ip_addr_is_bogon(IpAddr::V4(v4)) {
                    return true;
                }
            }
            // RFC 3849 documentation prefix.
            if segs[0] == 0x2001 && segs[1] == 0x0db8 {
                return true;
            }
            // Audit additions (2026-05-10):
            //   2001:0::/32 — Teredo tunneling (RFC 4380). Embeds an
            //     attacker-controlled IPv4 server *and* exposes the
            //     client's IPv4 — never a legitimate origin endpoint.
            //   2001:20::/28 — ORCHIDv2 (RFC 7343). Pure cryptographic
            //     identifiers; not routable as upstream targets.
            //   2002::/16 with private V4 — handled above.
            //   100::/64 — discard-only address block (RFC 6666).
            if segs[0] == 0x2001 && segs[1] == 0x0000 {
                return true; // Teredo
            }
            if segs[0] == 0x2001 && (segs[1] & 0xfff0) == 0x0020 {
                return true; // ORCHIDv2 2001:20::/28
            }
            if segs[0] == 0x0100
                && segs[1] == 0
                && segs[2] == 0
                && segs[3] == 0
            {
                return true; // 100::/64 discard
            }
            v.is_loopback()
                || v.is_multicast()
                || v.is_unspecified()
                || v.is_unique_local()
                || v.is_unicast_link_local()
        }
    }
}

/// Block forwarding when the URL host is a literal bogon IP.
#[must_use]
pub fn upstream_literal_ip_forbidden(url: &str) -> bool {
    let Ok(u) = reqwest::Url::parse(url) else {
        return false;
    };
    let Some(host) = u.host_str() else {
        return false;
    };
    let Ok(ip) = host.parse::<IpAddr>() else {
        return false;
    };
    ip_addr_is_bogon(ip)
}

async fn resolve_host_all_public(host: &str, port: u16) -> Result<(), String> {
    let mut any = false;
    let sa_iter = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("DNS resolution failed for {host}: {e}"))?;
    for sa in sa_iter {
        any = true;
        if ip_addr_is_bogon(sa.ip()) {
            return Err(format!(
                "refusing upstream: DNS for {host} includes non-public address {}",
                sa.ip()
            ));
        }
    }
    if !any {
        return Err(format!("refusing upstream: no addresses for {host}"));
    }
    Ok(())
}

/// Validate `https?://…` (or absolute URL) before forwarding.
pub async fn assert_forward_url_allowed(url: &str, policy: &UpstreamPolicy) -> Result<(), String> {
    if policy.insecure_open_upstream {
        return Ok(());
    }
    if policy.allow_private_upstream {
        return Ok(());
    }
    if upstream_literal_ip_forbidden(url) {
        return Err(format!(
            "upstream URL uses a disallowed literal IP (private / loopback / link-local / RFC1918): {url}. \
             If you're intentionally targeting localhost or RFC1918 lab infrastructure, \
             restart wafrift-proxy with `--allow-private-upstream`."
        ));
    }
    let u = reqwest::Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;
    let Some(host) = u.host_str() else {
        return Err("upstream URL has no host".to_string());
    };
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    let port = u.port_or_known_default().unwrap_or(80);
    resolve_host_all_public(host, port).await
}

/// Validate `CONNECT` authority `host:port` before tunnel/MITM.
pub async fn assert_connect_target_allowed(
    addr: &str,
    policy: &UpstreamPolicy,
) -> Result<(), String> {
    if policy.insecure_open_upstream {
        return Ok(());
    }
    if policy.allow_private_upstream {
        return Ok(());
    }
    let authority = addr
        .parse::<hyper::http::uri::Authority>()
        .map_err(|_| format!("invalid CONNECT authority: {addr}"))?;
    let host = authority.host();
    let port = authority.port_u16().unwrap_or(443);
    if let Ok(ip) = host.parse::<IpAddr>() {
        if ip_addr_is_bogon(ip) {
            return Err(format!(
                "refusing CONNECT to non-public literal IP {ip}. \
                 If you're targeting a localhost or RFC1918 lab service, \
                 restart wafrift-proxy with `--allow-private-upstream`."
            ));
        }
        return Ok(());
    }
    resolve_host_all_public(host, port).await
}

/// `reqwest::dns::Resolve` impl that wraps the system resolver and
/// drops any address that fails `ip_addr_is_bogon`. This closes the
/// DNS-rebinding TOCTOU between `assert_forward_url_allowed` (first
/// lookup) and reqwest's connection-time lookup (second lookup): both
/// now go through the same bogon filter, so a hostname that resolves
/// to a public IP at policy-check time can't suddenly resolve to
/// 169.254.169.254 / 127.0.0.1 / RFC1918 at fetch time.
///
/// The wrapper is permissive when `allow_private_upstream` is set —
/// caller flips that switch when targeting localhost on purpose
/// (e.g. lab tests).
pub struct BogonFilteringResolver {
    pub policy: Arc<UpstreamPolicy>,
}

impl reqwest::dns::Resolve for BogonFilteringResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let policy = self.policy.clone();
        let host = name.as_str().to_string();
        Box::pin(async move {
            let lookups = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
            let allow_private = policy.allow_private_upstream || policy.insecure_open_upstream;
            let filtered: Vec<SocketAddr> = lookups
                .into_iter()
                .filter(|sa| allow_private || !ip_addr_is_bogon(sa.ip()))
                .collect();
            if filtered.is_empty() {
                return Err(Box::<dyn std::error::Error + Send + Sync>::from(format!(
                    "DNS rebinding refused: every address for {host} is in the bogon set"
                )));
            }
            let iter: reqwest::dns::Addrs = Box::new(filtered.into_iter());
            Ok(iter)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bogon_v4_loopback() {
        assert!(ip_addr_is_bogon("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn public_v4_ok() {
        assert!(!ip_addr_is_bogon("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn ipv4_mapped_v6_loopback_is_bogon() {
        // ::ffff:127.0.0.1 — without the IPv4-mapped re-check, this
        // sneaks past v.is_loopback() (which only catches ::1).
        assert!(ip_addr_is_bogon("::ffff:127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn ipv4_mapped_v6_imds_is_bogon() {
        // The exact bypass that would have leaked AWS IMDS via SSRF.
        assert!(ip_addr_is_bogon("::ffff:169.254.169.254".parse().unwrap()));
    }

    #[test]
    fn ipv4_mapped_v6_rfc1918_is_bogon() {
        assert!(ip_addr_is_bogon("::ffff:10.0.0.1".parse().unwrap()));
        assert!(ip_addr_is_bogon("::ffff:192.168.1.1".parse().unwrap()));
        assert!(ip_addr_is_bogon("::ffff:172.16.0.1".parse().unwrap()));
    }

    #[test]
    fn ipv4_mapped_v6_public_ok() {
        // Sanity — mapped form of a public address must NOT be flagged.
        assert!(!ip_addr_is_bogon("::ffff:8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn rfc3849_documentation_v6_is_bogon() {
        // 2001:db8::/32 is the IPv6 documentation prefix. Real upstream
        // services should never live there; if a target's DNS returned
        // it, that's almost certainly a misconfiguration we want to refuse.
        assert!(ip_addr_is_bogon("2001:db8::1".parse().unwrap()));
        assert!(ip_addr_is_bogon("2001:db8:cafe::1".parse().unwrap()));
    }

    #[test]
    fn six_to_four_with_private_v4_is_bogon() {
        // 6to4 (RFC 3056) embeds an IPv4 in 2002:WWXX:YYZZ::/48.
        // 2002:7f00:0001:: -> 127.0.0.1 over 6to4.
        assert!(ip_addr_is_bogon("2002:7f00:1::".parse().unwrap()));
        // 2002:c0a8:0101:: -> 192.168.1.1 over 6to4.
        assert!(ip_addr_is_bogon("2002:c0a8:101::".parse().unwrap()));
        // 2002:a9fe:a9fe:: -> 169.254.169.254 over 6to4 (AWS IMDS).
        assert!(ip_addr_is_bogon("2002:a9fe:a9fe::".parse().unwrap()));
    }

    #[test]
    fn six_to_four_with_public_v4_ok() {
        // 2002:0808:0808:: -> 8.8.8.8 over 6to4. Not a bogon.
        assert!(!ip_addr_is_bogon("2002:808:808::".parse().unwrap()));
    }

    #[test]
    fn public_v6_google_dns_ok() {
        assert!(!ip_addr_is_bogon("2001:4860:4860::8888".parse().unwrap()));
    }
}
