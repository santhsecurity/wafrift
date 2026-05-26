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

/// Re-export the workspace-canonical bogon classifier.
pub use wafrift_types::ip_addr_is_bogon;

/// True when this IP should never be the target of a proxy-initiated
/// outbound connection.
///
/// Extends [`ip_addr_is_bogon`] with IPv4 multicast (`224.0.0.0/4`).
/// The bogon crate intentionally leaves IPv4 multicast allowed because
/// scanner workloads legitimately probe multicast addresses; the proxy
/// forward/CONNECT path has no such use case and must refuse them to
/// prevent SSRF via multicast-capable LAN services.
#[must_use]
pub fn proxy_ip_is_forbidden(ip: IpAddr) -> bool {
    if ip_addr_is_bogon(ip) {
        return true;
    }
    // IPv4 multicast: 224.0.0.0/4 (first octet 224–239).
    if let IpAddr::V4(v4) = ip {
        if v4.is_multicast() {
            return true;
        }
    }
    false
}

/// Block forwarding when the URL host is a literal forbidden IP.
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
    proxy_ip_is_forbidden(ip)
}

async fn resolve_host_all_public(host: &str, port: u16) -> Result<(), String> {
    let mut any = false;
    let sa_iter = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("DNS resolution failed for {host}: {e}"))?;
    for sa in sa_iter {
        any = true;
        if proxy_ip_is_forbidden(sa.ip()) {
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

/// Validate `https?://...` (or absolute URL) before forwarding.
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
    resolve_host_all_public(host, port).await?;
    Ok(())
}

/// Resolve a forward URL to validated public socket addresses.
///
/// Callers (especially the stealth TLS path) must use these pinned
/// addresses instead of re-resolving DNS after an intercept wait, which
/// would reopen a DNS-rebinding TOCTOU window.
pub async fn resolve_forward_url_pinned(
    url: &str,
    policy: &UpstreamPolicy,
) -> Result<Vec<SocketAddr>, String> {
    if policy.insecure_open_upstream || policy.allow_private_upstream {
        let u = reqwest::Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;
        let host = u
            .host_str()
            .ok_or_else(|| "upstream URL has no host".to_string())?;
        let port = u.port_or_known_default().unwrap_or(80);
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        let lookups = tokio::net::lookup_host((host, port))
            .await
            .map_err(|e| format!("DNS resolution failed for {host}: {e}"))?;
        let v: Vec<SocketAddr> = lookups.collect();
        if v.is_empty() {
            return Err(format!("refusing upstream: no addresses for {host}"));
        }
        return Ok(v);
    }
    if upstream_literal_ip_forbidden(url) {
        return Err(format!(
            "upstream URL uses a disallowed literal IP (private / loopback / link-local / RFC1918): {url}"
        ));
    }
    let u = reqwest::Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;
    let host = u
        .host_str()
        .ok_or_else(|| "upstream URL has no host".to_string())?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(
            ip,
            u.port_or_known_default().unwrap_or(80),
        )]);
    }
    let port = u.port_or_known_default().unwrap_or(80);
    let mut filtered = Vec::new();
    let lookups = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("DNS resolution failed for {host}: {e}"))?;
    for sa in lookups {
        if proxy_ip_is_forbidden(sa.ip()) {
            return Err(format!(
                "refusing upstream: DNS for {host} includes non-public address {}",
                sa.ip()
            ));
        }
        filtered.push(sa);
    }
    if filtered.is_empty() {
        return Err(format!("refusing upstream: no addresses for {host}"));
    }
    Ok(filtered)
}

/// Validate `CONNECT` authority `host:port` before tunnel/MITM.
pub async fn assert_connect_target_allowed(
    addr: &str,
    policy: &UpstreamPolicy,
) -> Result<(), String> {
    let _ = resolve_connect_target_allowed(addr, policy).await?;
    Ok(())
}

/// Validate `CONNECT` authority `host:port` AND return the resolved
/// public socket addresses. Callers should pass these straight to
/// `TcpStream::connect` instead of reusing `host:port` so a DNS rebinding
/// flip between the validation and the connect cannot land.
pub async fn resolve_connect_target_allowed(
    addr: &str,
    policy: &UpstreamPolicy,
) -> Result<Vec<SocketAddr>, String> {
    let authority = addr
        .parse::<hyper::http::uri::Authority>()
        .map_err(|_| format!("invalid CONNECT authority: {addr}"))?;
    let host = authority.host();
    let port = authority.port_u16().unwrap_or(443);

    if policy.insecure_open_upstream || policy.allow_private_upstream {
        // Permissive mode: still resolve so the caller has addresses
        // to connect to without doing its own lookup, but skip bogon
        // filtering.
        let lookups = tokio::net::lookup_host((host, port))
            .await
            .map_err(|e| format!("DNS resolution failed for {host}: {e}"))?;
        let v: Vec<SocketAddr> = lookups.collect();
        if v.is_empty() {
            return Err(format!("no addresses for {host}"));
        }
        return Ok(v);
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        if proxy_ip_is_forbidden(ip) {
            return Err(format!(
                "refusing CONNECT to non-public literal IP {ip}. \
                 If you're targeting a localhost or RFC1918 lab service, \
                 restart wafrift-proxy with `--allow-private-upstream`."
            ));
        }
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    let mut filtered = Vec::new();
    let lookups = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("DNS resolution failed for {host}: {e}"))?;
    for sa in lookups {
        if proxy_ip_is_forbidden(sa.ip()) {
            return Err(format!(
                "refusing upstream: DNS for {host} includes non-public address {}",
                sa.ip()
            ));
        }
        filtered.push(sa);
    }
    if filtered.is_empty() {
        return Err(format!("refusing upstream: no addresses for {host}"));
    }
    Ok(filtered)
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
                .filter(|sa| allow_private || !proxy_ip_is_forbidden(sa.ip()))
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

/// Rewrite `url` so that its hostname is replaced with an IP literal taken
/// from `addrs` (the first entry). This eliminates the DNS-rebinding TOCTOU
/// window on the reqwest forward path: once the hostname is gone from the URL
/// reqwest never does another DNS lookup for it — the connection goes straight
/// to the validated IP.
///
/// Returns `(pinned_url, original_host)`. The caller must set a `Host`
/// request header using `original_host` so that virtual-hosting on the
/// upstream works correctly.
///
/// # Errors
///
/// - `addrs` is empty.
/// - `url` cannot be parsed as an absolute URL.
/// - The URL has no host component.
pub fn pin_url_to_first_addr(
    url: &str,
    addrs: &[SocketAddr],
) -> Result<(String, String), String> {
    let addr = addrs
        .first()
        .ok_or_else(|| "pin_url_to_first_addr: no addresses supplied".to_string())?;
    let mut u = reqwest::Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;
    let original_host = u
        .host_str()
        .ok_or_else(|| "upstream URL has no host".to_string())?
        .to_string();
    // If the URL is already an IP literal there is nothing to rewrite.
    if original_host.parse::<IpAddr>().is_ok() {
        return Ok((url.to_string(), original_host));
    }
    // set_host accepts bare IPv4 / bracketed IPv6.
    let ip_str = match addr.ip() {
        IpAddr::V6(v6) => format!("[{v6}]"),
        IpAddr::V4(v4) => v4.to_string(),
    };
    u.set_host(Some(&ip_str))
        .map_err(|e| format!("failed to rewrite host to IP literal: {e}"))?;
    Ok((u.to_string(), original_host))
}

/// `reqwest::dns::Resolve` impl that pins a hostname to the first IP address
/// returned by the system resolver (after bogon-filtering). Subsequent
/// resolution requests for the **same hostname** return the cached IP
/// directly: a DNS rebinding flip cannot land because the proxy never asks
/// DNS again for a host it has already resolved to a public address.
///
/// When `allow_private_upstream` / `insecure_open_upstream` are set the
/// bogon filter is skipped (lab mode), but the pin-on-first-resolution
/// behaviour still applies so connections stay coherent.
///
/// The `pinned` table is exposed so callers can seed it from the result of
/// `resolve_forward_url_pinned`, ensuring the URL-rewrite path and the
/// resolver path both agree on the pinned IP.
pub struct PinningResolver {
    pub policy: Arc<UpstreamPolicy>,
    /// hostname -> first validated IP seen. Pinned once, never evicted.
    pub pinned: Arc<std::sync::Mutex<std::collections::HashMap<String, IpAddr>>>,
}

impl PinningResolver {
    /// Create a new resolver with an empty pin table.
    pub fn new(policy: Arc<UpstreamPolicy>) -> Self {
        Self {
            policy,
            pinned: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }
}

impl reqwest::dns::Resolve for PinningResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let policy = self.policy.clone();
        let pinned = self.pinned.clone();
        let host = name.as_str().to_string();
        Box::pin(async move {
            // Fast path: already pinned for this resolver instance.
            {
                let map = pinned.lock().map_err(|_| {
                    Box::<dyn std::error::Error + Send + Sync>::from(
                        "PinningResolver: mutex poisoned".to_string(),
                    )
                })?;
                if let Some(&ip) = map.get(&host) {
                    // Return the pinned address. Port 0 — reqwest derives the
                    // actual port from the URL, not the DNS result.
                    let sa = SocketAddr::new(ip, 0);
                    let iter: reqwest::dns::Addrs = Box::new(std::iter::once(sa));
                    return Ok(iter);
                }
            }
            // Slow path: first resolution for this host.
            let allow_private = policy.allow_private_upstream || policy.insecure_open_upstream;
            let lookups = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
            let candidates: Vec<SocketAddr> = lookups
                .into_iter()
                .filter(|sa| allow_private || !ip_addr_is_bogon(sa.ip()))
                .collect();
            if candidates.is_empty() {
                return Err(Box::<dyn std::error::Error + Send + Sync>::from(format!(
                    "DNS rebinding refused: every address for {host} is in the bogon set"
                )));
            }
            // Pin the first valid address so all future connections for this
            // hostname in this client go to the same IP.
            let pinned_ip = candidates[0].ip();
            {
                let mut map = pinned.lock().map_err(|_| {
                    Box::<dyn std::error::Error + Send + Sync>::from(
                        "PinningResolver: mutex poisoned".to_string(),
                    )
                })?;
                map.entry(host).or_insert(pinned_ip);
            }
            let iter: reqwest::dns::Addrs = Box::new(candidates.into_iter());
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

    // ── proxy_ip_is_forbidden: extends bogon with IPv4 multicast ────────────

    #[test]
    fn proxy_forbidden_blocks_multicast_224() {
        // 224.0.0.0/4 is IPv4 multicast. ip_addr_is_bogon allows it
        // (scanner workloads need it); the proxy layer adds the check.
        for a in [224u8, 225, 239] {
            let ip: IpAddr = format!("{a}.0.0.1").parse().unwrap();
            assert!(
                proxy_ip_is_forbidden(ip),
                "{ip} in 224–239 multicast must be forbidden by proxy policy"
            );
        }
    }

    #[test]
    fn proxy_forbidden_passes_public_not_multicast() {
        for addr in ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"] {
            let ip: IpAddr = addr.parse().unwrap();
            assert!(
                !proxy_ip_is_forbidden(ip),
                "{ip} is public and must not be blocked by proxy policy"
            );
        }
    }

    #[test]
    fn proxy_forbidden_inherits_all_bogon_ranges() {
        // Spot-check that proxy_ip_is_forbidden is at least as strict as
        // ip_addr_is_bogon for the ranges that matter most to the proxy.
        for addr in [
            "127.0.0.1",
            "169.254.169.254",
            "10.0.0.1",
            "192.168.1.1",
            "::1",
        ] {
            let ip: IpAddr = addr.parse().unwrap();
            assert!(
                proxy_ip_is_forbidden(ip),
                "{ip} must be blocked by proxy policy (inherited from bogon)"
            );
        }
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

    #[test]
    fn pin_url_rewrites_hostname_to_ip_literal() {
        let addrs = vec!["203.0.113.5:443".parse::<SocketAddr>().unwrap()];
        let (pinned, host) =
            pin_url_to_first_addr("https://example.com/some/path?q=1", &addrs).unwrap();
        assert_eq!(host, "example.com");
        assert!(
            pinned.starts_with("https://203.0.113.5/"),
            "expected IP-literal URL, got: {pinned}"
        );
        assert!(pinned.contains("/some/path"), "path must be preserved: {pinned}");
        assert!(pinned.contains("q=1"), "query must be preserved: {pinned}");
    }

    #[test]
    fn pin_url_noop_when_already_literal_ip() {
        let addrs = vec!["203.0.113.5:443".parse::<SocketAddr>().unwrap()];
        let url = "https://203.0.113.5/path";
        let (pinned, host) = pin_url_to_first_addr(url, &addrs).unwrap();
        assert_eq!(pinned, url);
        assert_eq!(host, "203.0.113.5");
    }

    #[test]
    fn pin_url_empty_addrs_errors() {
        let result = pin_url_to_first_addr("https://example.com/", &[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no addresses supplied"));
    }

    /// DNS rebinding regression test.
    ///
    /// Simulates the exact attack: the mock resolver returns a public IP on
    /// the first lookup, then switches to 127.0.0.1 on subsequent calls.
    /// The `PinningResolver` must return the first (public) IP for every
    /// call after the initial resolution, never the private rebind address.
    #[tokio::test]
    async fn dns_rebinding_pinning_resolver_holds_first_ip() {
        use reqwest::dns::Resolve as _;
        use std::str::FromStr as _;

        // Public IP returned on the first DNS lookup.
        let public_ip: IpAddr = "203.0.113.5".parse().unwrap();
        // Private IP the attacker's DNS would return on subsequent lookups.
        let private_ip: IpAddr = "127.0.0.1".parse().unwrap();

        let policy = Arc::new(UpstreamPolicy {
            allow_private_upstream: false,
            insecure_open_upstream: false,
        });
        let resolver = PinningResolver::new(policy.clone());
        let pinned_map = resolver.pinned.clone();

        // Seed the pin table as if the resolver already performed the first
        // (public) lookup. This replicates how PinningResolver.resolve() works
        // on the initial call — we cannot mock tokio::net::lookup_host so we
        // directly inject the validated result.
        {
            let mut map = pinned_map.lock().unwrap();
            map.insert("rebind-target.example".to_string(), public_ip);
        }

        // Second resolution attempt via the Resolve trait — the attacker has
        // now flipped DNS so the system resolver would return private_ip.
        // Because the host is already pinned, PinningResolver must return
        // public_ip WITHOUT performing a new system lookup.
        let name = reqwest::dns::Name::from_str("rebind-target.example")
            .expect("valid DNS name");
        let mut addrs_iter = resolver
            .resolve(name)
            .await
            .expect("resolution must succeed for a pinned hostname");

        let returned = addrs_iter.next().expect("must return at least one address");
        assert_eq!(
            returned.ip(),
            public_ip,
            "PinningResolver returned {}, expected pinned public IP {}",
            returned.ip(),
            public_ip
        );
        assert_ne!(
            returned.ip(),
            private_ip,
            "PinningResolver must NEVER return the private rebind address"
        );

        // Also verify pin_url_to_first_addr produces an IP-literal URL so
        // reqwest has no hostname left to re-resolve at connect time.
        let addrs = vec![SocketAddr::new(public_ip, 443)];
        let (pinned_url, original_host) =
            pin_url_to_first_addr("https://rebind-target.example/api", &addrs)
                .expect("pin_url_to_first_addr must succeed");
        assert_eq!(original_host, "rebind-target.example");
        assert!(
            pinned_url.contains("203.0.113.5"),
            "URL must contain IP literal, got: {pinned_url}"
        );
        assert!(
            !pinned_url.contains("rebind-target.example"),
            "URL must not contain hostname after pinning, got: {pinned_url}"
        );
    }

    /// Concurrent second resolutions all hit the fast path and return the
    /// pinned IP, never racing to insert a different value.
    #[tokio::test]
    async fn dns_rebinding_pinning_resolver_concurrent_resolutions_hold() {
        use reqwest::dns::Resolve as _;
        use std::str::FromStr as _;

        let public_ip: IpAddr = "198.51.100.7".parse().unwrap();
        let policy = Arc::new(UpstreamPolicy {
            allow_private_upstream: false,
            insecure_open_upstream: false,
        });
        let resolver = Arc::new(PinningResolver::new(policy));
        // Seed the pin table.
        {
            let mut map = resolver.pinned.lock().unwrap();
            map.insert("concurrent-rebind.example".to_string(), public_ip);
        }

        // Fire 8 concurrent resolution attempts — all must return the pinned IP.
        let mut handles = Vec::new();
        for _ in 0..8 {
            let r = resolver.clone();
            handles.push(tokio::spawn(async move {
                let name = reqwest::dns::Name::from_str("concurrent-rebind.example").unwrap();
                let mut iter = r.resolve(name).await.unwrap();
                iter.next().unwrap().ip()
            }));
        }
        for h in handles {
            let ip = h.await.unwrap();
            assert_eq!(
                ip, public_ip,
                "concurrent resolution returned wrong IP: {ip}"
            );
        }
    }

    /// Verify that pin_url_to_first_addr correctly handles IPv6 addresses
    /// by emitting bracketed notation in the URL.
    #[test]
    fn pin_url_rewrites_hostname_to_ipv6_literal() {
        let v6_ip: IpAddr = "2001:db8::1".parse().unwrap();
        let addrs = vec![SocketAddr::new(v6_ip, 443)];
        let (pinned, host) =
            pin_url_to_first_addr("https://example.com/path", &addrs).unwrap();
        assert_eq!(host, "example.com");
        // IPv6 in URLs requires brackets: https://[2001:db8::1]/path
        assert!(
            pinned.contains("[2001:db8::1]"),
            "IPv6 URL must use bracketed notation, got: {pinned}"
        );
        assert!(
            !pinned.contains("example.com"),
            "hostname must not appear after pinning, got: {pinned}"
        );
    }
}
