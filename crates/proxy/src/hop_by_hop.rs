//! Hop-by-hop headers (RFC 7230 §6.1) must not be blindly forwarded through proxies.
//!
//! Also strips header field names listed in the `Connection` header value.

use std::collections::HashSet;

/// Returns true if the header name is hop-by-hop and should be dropped on forward paths.
#[must_use]
pub fn is_hop_by_hop(name: &str) -> bool {
    name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("proxy-authenticate")
        || name.eq_ignore_ascii_case("proxy-authorization")
        || name.eq_ignore_ascii_case("proxy-connection")
        || name.eq_ignore_ascii_case("te")
        || name.eq_ignore_ascii_case("trailer")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("upgrade")
        || name.eq_ignore_ascii_case("x-forwarded-for")
}

/// Parse a single `Connection` header field-value into lowercase token names.
#[must_use]
pub fn connection_header_tokens(connection_header_value: &str) -> HashSet<String> {
    connection_header_value
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Merge all `Connection` header values from a `(name, value)` list (e.g. wafrift headers).
#[must_use]
pub fn collect_connection_header_names(headers: &[(String, String)]) -> HashSet<String> {
    let mut out = HashSet::new();
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("connection") {
            out.extend(connection_header_tokens(v));
        }
    }
    out
}

/// Merge all `Connection` header values from a Hyper header map.
#[must_use]
pub fn collect_connection_header_names_hyper(headers: &hyper::HeaderMap) -> HashSet<String> {
    let mut out = HashSet::new();
    for v in headers.get_all(hyper::header::CONNECTION) {
        if let Ok(s) = v.to_str() {
            out.extend(connection_header_tokens(s));
        }
    }
    out
}

/// True if this header must not be forwarded to the next hop.
#[must_use]
pub fn should_strip_proxy_header(name: &str, connection_tokens_lower: &HashSet<String>) -> bool {
    if is_hop_by_hop(name) {
        return true;
    }
    connection_tokens_lower.contains(&name.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_common_hop_by_hop() {
        assert!(is_hop_by_hop("Connection"));
        assert!(is_hop_by_hop("TRANSFER-ENCODING"));
        assert!(is_hop_by_hop("Proxy-Connection"));
    }

    #[test]
    fn allows_end_to_end() {
        assert!(!is_hop_by_hop("Content-Type"));
        assert!(!is_hop_by_hop("Authorization"));
    }

    #[test]
    fn connection_tokens_case_insensitive() {
        let t = connection_header_tokens("Foo, BAR,  keep-alive ");
        assert!(t.contains("foo"));
        assert!(t.contains("bar"));
        assert!(t.contains("keep-alive"));
    }

    #[test]
    fn strip_respects_connection_list() {
        let conn = connection_header_tokens("X-My-Hop");
        assert!(should_strip_proxy_header("X-My-Hop", &conn));
        assert!(!should_strip_proxy_header("X-Other", &conn));
    }

    #[test]
    fn burp_zap_proxy_headers_are_hop_by_hop() {
        assert!(is_hop_by_hop("Proxy-Connection"));
        assert!(is_hop_by_hop("Proxy-Authorization"));
        assert!(is_hop_by_hop("X-Forwarded-For"));
    }

    #[test]
    fn connection_header_can_strip_custom_tokens() {
        let conn = connection_header_tokens("X-Forwarded-For, Custom-Header");
        assert!(should_strip_proxy_header("X-Forwarded-For", &conn));
        assert!(should_strip_proxy_header("Custom-Header", &conn));
        assert!(!should_strip_proxy_header("Content-Type", &conn));
    }
}
