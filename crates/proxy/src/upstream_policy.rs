//! Upstream destination policy: literal-IP bogons and DNS SSRF-style checks.

use std::net::IpAddr;

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
            v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_broadcast()
                || v.is_documentation()
                || v.is_unspecified()
        }
        IpAddr::V6(v) => {
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
        return Err(
            "upstream URL uses a disallowed literal IP (private/link-local/etc.)".to_string(),
        );
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
            return Err(format!("refusing CONNECT to non-public literal IP {ip}"));
        }
        return Ok(());
    }
    resolve_host_all_public(host, port).await
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
}
