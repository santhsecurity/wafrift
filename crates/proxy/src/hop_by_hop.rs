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

    #[test]
    fn collect_connection_header_names_merges_multiple_headers() {
        // Defect: the stealth path used .find() which only parsed the
        // first Connection header, leaking hop-by-hop tokens listed in
        // subsequent Connection headers to the client.
        let headers = vec![
            ("Connection".to_string(), "keep-alive".to_string()),
            ("CONNECTION".to_string(), "X-Custom-Hop".to_string()),
            ("X-Custom-Hop".to_string(), "value".to_string()),
            ("Content-Type".to_string(), "text/html".to_string()),
        ];
        let conn = collect_connection_header_names(&headers);
        assert!(conn.contains("keep-alive"));
        assert!(conn.contains("x-custom-hop"));
        assert!(should_strip_proxy_header("X-Custom-Hop", &conn));
        assert!(!should_strip_proxy_header("Content-Type", &conn));
    }

    #[test]
    fn collect_connection_header_names_empty_list() {
        let headers: Vec<(String, String)> = vec![];
        let conn = collect_connection_header_names(&headers);
        assert!(conn.is_empty());
    }

    // -- §12 boundary tests ------------------------------------------------

    #[test]
    fn connection_tokens_empty_value_produces_empty_set() {
        // Empty Connection header value → no tokens.
        let t = connection_header_tokens("");
        assert!(t.is_empty(), "empty value must produce no tokens");
    }

    #[test]
    fn connection_tokens_whitespace_only_produces_empty_set() {
        // A value of only commas and spaces has no meaningful tokens.
        let t = connection_header_tokens("  ,  ,  ");
        assert!(
            t.is_empty(),
            "whitespace-only comma-separated value must yield no tokens: {t:?}"
        );
    }

    #[test]
    fn is_hop_by_hop_te_header() {
        // TE is listed in RFC 7230 §6.1 as hop-by-hop; make sure it's covered.
        assert!(is_hop_by_hop("te"), "TE must be hop-by-hop");
        assert!(is_hop_by_hop("TE"), "TE must be hop-by-hop (uppercase)");
    }

    #[test]
    fn is_hop_by_hop_unknown_header_is_not_hop_by_hop() {
        // Non-connection management headers must pass through.
        assert!(!is_hop_by_hop("X-Request-Id"));
        assert!(!is_hop_by_hop("accept-encoding"));
    }

    #[test]
    fn collect_connection_headers_from_hyper_empty_map() {
        use hyper::HeaderMap;
        let map = HeaderMap::new();
        let conn = collect_connection_header_names_hyper(&map);
        assert!(
            conn.is_empty(),
            "no Connection headers in hyper map → empty set"
        );
    }

    #[test]
    fn collect_connection_headers_from_hyper_single_value() {
        use hyper::header::CONNECTION;
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let mut map = HeaderMap::new();
        map.insert(CONNECTION, HeaderValue::from_static("keep-alive, X-Hop"));
        let conn = collect_connection_header_names_hyper(&map);
        assert!(conn.contains("keep-alive"));
        assert!(conn.contains("x-hop"));
    }

    #[test]
    fn strip_all_hop_by_hop_headers_individually() {
        // Every header in the RFC 7230 list must be stripped; none
        // must sneak through the is_hop_by_hop gate.
        let hop_headers = [
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "proxy-connection",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
            "x-forwarded-for",
        ];
        let empty_conn: std::collections::HashSet<String> = std::collections::HashSet::new();
        for h in hop_headers {
            assert!(
                should_strip_proxy_header(h, &empty_conn),
                "{h} must be stripped by hop-by-hop check"
            );
        }
    }
}
