//! Library surface for `wafrift-proxy`.
//!
//! The binary entry point lives in `main.rs`; this lib module exposes
//! the building blocks downstream consumers (the bench harness,
//! integration tests, third-party Rust code that wants the
//! evasion proxy as a library) need.

pub mod hop_by_hop;
pub mod intercept;
pub mod mitm;
pub mod rate_limit;
pub mod scope;
pub mod tui;
pub mod upstream;
pub mod upstream_policy;

/// Extract the host from a Host header, handling IPv6 bracket notation and bare IPv6 literals.
///
/// Returns the host component only (strips `:port`). For malformed input
/// (e.g. unclosed brackets) returns an empty string so callers can fall
/// back to a safe default rather than routing to garbage.
#[allow(clippy::collapsible_if)]
pub fn extract_host_from_header(s: &str) -> String {
    let s = s.trim();
    if s.is_empty() {
        return String::new();
    }
    if s.starts_with('[') {
        if let Some(end_idx) = s.find(']') {
            if end_idx > 1 {
                return s[1..end_idx].to_string();
            }
        }
        // Malformed bracket notation — don't attempt to route it.
        return String::new();
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

    #[test]
    fn extract_bare_ipv4() {
        assert_eq!(extract_host_from_header("192.168.1.1"), "192.168.1.1");
    }

    #[test]
    fn extract_ipv4_with_port() {
        assert_eq!(extract_host_from_header("192.168.1.1:8080"), "192.168.1.1");
    }

    #[test]
    fn extract_bracketed_v6_no_port() {
        assert_eq!(extract_host_from_header("[::1]"), "::1");
        assert_eq!(extract_host_from_header("[2001:db8::1]"), "2001:db8::1");
    }

    #[test]
    fn extract_malformed_bracket_returns_empty() {
        // Unclosed bracket — must not crash or return garbage like "[".
        assert_eq!(extract_host_from_header("[::1"), "");
        assert_eq!(extract_host_from_header("["), "");
    }

    #[test]
    fn extract_empty_returns_empty() {
        assert_eq!(extract_host_from_header(""), "");
        assert_eq!(extract_host_from_header("   "), "");
    }
}
