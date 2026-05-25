//! URL parsing primitives shared across the workspace.
//!
//! Pre-extract, four crates each had their own `extract_host` /
//! `host_from_url` / `extract_host_from_url` — diverging on:
//! - scheme-optional handling (some required `http(s)://`, others
//!   tolerated bare `example.com:443`)
//! - userinfo handling (`user@host` form — only cors_diff stripped)
//! - IPv6 brackets (transport stripped; detect_cmd kept; others
//!   ignored the case entirely → silently mis-parsed `[::1]:443`)
//! - port stripping
//! - return shape (`Result<String>` / `Option<String>` / `Option<&str>`)
//!
//! `host_from_url` here is the union of correct behaviours from all
//! four. Callers wrap the `Option<String>` in their own error type.
//!
//! `extract_host_from_header` (in `wafrift_proxy`) handles a
//! DIFFERENT input — bare Host header values, no scheme — and stays
//! separate by design.

/// Extract the host (no scheme, port, userinfo, path, query, or
/// fragment) from a URL string. Lower-cased. Returns `None` when the
/// URL has no parseable host component.
///
/// Behaviour:
/// - Scheme-optional: `example.com/path` parses the same as
///   `https://example.com/path`.
/// - Userinfo (`user[:pass]@host`) is stripped.
/// - IPv6 literals: brackets are stripped (`[::1]:443` → `::1`).
///   Use the bracketed form yourself if rebuilding a URL.
/// - Port suffix on IPv4 / hostname is stripped.
/// - Trailing whitespace and empty inputs return `None`.
///
/// This helper does NOT validate that the host is a syntactically
/// correct DNS name or IP literal — that is the caller's call, since
/// the policy depends on context (DNS lookup vs. cert SAN match vs.
/// allowlist comparison).
#[must_use]
pub fn host_from_url(url: &str) -> Option<String> {
    let url = url.trim();
    if url.is_empty() {
        return None;
    }
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    // Strip userinfo (rightmost `@` so passwords containing `@` work).
    let host_path = after_scheme
        .rsplit_once('@')
        .map_or(after_scheme, |(_, h)| h);
    let host_port = host_path.split(['/', '?', '#']).next()?;
    let host = if let Some(stripped) = host_port.strip_prefix('[') {
        // IPv6 literal: take until ']', drop port suffix if any.
        let end = stripped.find(']')?;
        &stripped[..end]
    } else {
        host_port.rsplit_once(':').map_or(host_port, |(h, _)| h)
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_hostname() {
        assert_eq!(
            host_from_url("https://example.com/path"),
            Some("example.com".into())
        );
    }

    #[test]
    fn scheme_optional() {
        assert_eq!(host_from_url("example.com"), Some("example.com".into()));
        assert_eq!(
            host_from_url("example.com/path?q=1"),
            Some("example.com".into())
        );
    }

    #[test]
    fn lowercases() {
        assert_eq!(
            host_from_url("https://EXAMPLE.COM/"),
            Some("example.com".into())
        );
    }

    #[test]
    fn strips_port() {
        assert_eq!(
            host_from_url("https://example.com:8443/"),
            Some("example.com".into())
        );
        assert_eq!(host_from_url("example.com:80"), Some("example.com".into()));
    }

    #[test]
    fn strips_userinfo() {
        assert_eq!(
            host_from_url("https://user:pass@example.com/"),
            Some("example.com".into())
        );
        assert_eq!(
            host_from_url("user@example.com:443"),
            Some("example.com".into())
        );
    }

    #[test]
    fn ipv6_literal_brackets_stripped() {
        assert_eq!(host_from_url("https://[::1]:8443/"), Some("::1".into()));
        assert_eq!(host_from_url("[2001:db8::1]"), Some("2001:db8::1".into()));
        assert_eq!(
            host_from_url("https://[2001:db8::1]:443/path"),
            Some("2001:db8::1".into())
        );
    }

    #[test]
    fn ipv4_passthrough() {
        assert_eq!(
            host_from_url("https://192.168.1.1:8080/"),
            Some("192.168.1.1".into())
        );
        assert_eq!(host_from_url("10.0.0.1"), Some("10.0.0.1".into()));
    }

    #[test]
    fn empty_inputs_return_none() {
        assert_eq!(host_from_url(""), None);
        assert_eq!(host_from_url("   "), None);
        assert_eq!(host_from_url("https://"), None);
    }

    #[test]
    fn malformed_ipv6_returns_none() {
        // Missing closing bracket — no parseable end position.
        assert_eq!(host_from_url("[::1"), None);
        assert_eq!(host_from_url("https://["), None);
    }

    #[test]
    fn fragment_and_query_stripped() {
        assert_eq!(
            host_from_url("https://example.com?q=1"),
            Some("example.com".into())
        );
        assert_eq!(
            host_from_url("https://example.com#section"),
            Some("example.com".into())
        );
    }

    #[test]
    fn password_with_at_sign_handled_via_rsplit() {
        // RFC 3986 allows `@` in userinfo when percent-encoded; this
        // test pins the rightmost-`@` policy that handles the common
        // mistake of an unencoded `@` in the password.
        assert_eq!(
            host_from_url("https://user:p@ss@example.com/"),
            Some("example.com".into())
        );
    }

    #[test]
    fn trims_whitespace() {
        assert_eq!(
            host_from_url("  https://example.com  "),
            Some("example.com".into())
        );
    }
}
