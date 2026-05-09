pub mod hop_by_hop;
pub mod mitm;
pub mod rate_limit;
pub mod scope;
pub mod upstream_policy;

/// Extract the host from a Host header, handling IPv6 bracket notation and bare IPv6 literals.
#[allow(clippy::collapsible_if)]
pub fn extract_host_from_header(s: &str) -> String {
    if s.starts_with('[') {
        if let Some(end_idx) = s.find(']') {
            return s[1..end_idx].to_string();
        }
    }
    // Bare IPv6 (no brackets). Avoid `split(':')` which would truncate at the first segment.
    if s.contains(':') {
        if let Ok(std::net::IpAddr::V6(ip)) = s.parse() {
            return ip.to_string();
        }
    }
    s.split(':').next().unwrap_or(s).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_bare_ipv6() {
        assert_eq!(extract_host_from_header("2001:db8::1"), "2001:db8::1");
    }

    #[test]
    fn extract_bracketed_v6_with_port() {
        assert_eq!(extract_host_from_header("[::1]:443"), "::1");
    }

    #[test]
    fn extract_hostname_with_port() {
        assert_eq!(extract_host_from_header("example.com:443"), "example.com");
    }
}
