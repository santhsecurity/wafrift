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
    // Isolate the authority FIRST: it ends at the first `/`, `?`, or `#`
    // (RFC 3986 §3.2). This must happen BEFORE userinfo stripping — an `@`
    // in the PATH (`https://target/@decoy.com`) would otherwise be mistaken
    // for the userinfo separator, and the path's trailing token returned as
    // the host. That confusion is an SSRF allowlist bypass: a host-allowlist
    // check sees `decoy.com` and admits a request reqwest actually sends to
    // `target` (e.g. `https://169.254.169.254/@allowed.com` → metadata IP).
    let authority = after_scheme.split(['/', '?', '#']).next()?;
    // Strip userinfo within the authority only (rightmost `@` so a password
    // containing `@` still resolves to the real host).
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if let Some(stripped) = host_port.strip_prefix('[') {
        // IPv6 literal: take until ']', drop port suffix if any.
        let end = stripped.find(']')?;
        &stripped[..end]
    } else {
        host_port.rsplit_once(':').map_or(host_port, |(h, _)| h)
    };
    if host.is_empty() {
        return None;
    }
    // CRLF + control-byte guard. Without it a URL like
    //   https://evil.com\r\nX-Injected: yes/path
    // produces the host string "evil.com\r\nx-injected: yes" which
    // downstream code drops verbatim into a `Host:` header or a
    // CONNECT line — splitting the request line and injecting an
    // arbitrary new header. Reject any host containing bytes outside
    // the RFC 3986 host charset (we accept letters, digits, `.`, `-`,
    // `:`, plus IPv6 internal chars). Anything with a control byte
    // or space or quote IS the attack.
    for ch in host.chars() {
        let safe = ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | ':');
        if !safe {
            return None;
        }
    }
    Some(host.to_ascii_lowercase())
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

    // ── Round 24: CRLF / control-byte injection defence ──────────────
    //
    // A URL like `https://evil.com\r\nX-Injected: yes/path` produced
    // host = `evil.com\r\nx-injected: yes` pre-fix. Downstream code
    // dropped that verbatim into a `Host:` header or CONNECT line,
    // injecting an attacker-controlled header (classic CRLF
    // injection). The guard rejects any non-host charset byte.

    #[test]
    fn rejects_crlf_in_host() {
        assert_eq!(
            host_from_url("https://evil.com\r\nX-Injected: yes/path"),
            None
        );
        assert_eq!(host_from_url("evil.com\r\nfoo"), None);
        assert_eq!(host_from_url("https://evil.com\rbar"), None);
        assert_eq!(host_from_url("https://evil.com\nbar"), None);
    }

    #[test]
    fn rejects_null_byte_in_host() {
        assert_eq!(host_from_url("https://evil.com\0extra/path"), None);
    }

    #[test]
    fn rejects_space_or_tab_in_host() {
        assert_eq!(host_from_url("https://evil .com/"), None);
        assert_eq!(host_from_url("https://evil\t.com/"), None);
    }

    #[test]
    fn rejects_quote_or_brace_in_host() {
        assert_eq!(host_from_url("https://evil\".com/"), None);
        assert_eq!(host_from_url("https://evil<.com/"), None);
        assert_eq!(host_from_url("https://evil>.com/"), None);
    }

    // ── SSRF allowlist bypass: `@` in the PATH must not be read as userinfo ──
    //
    // Pre-fix, userinfo was stripped via rsplit('@') on the whole post-scheme
    // string — so `https://target/@decoy.com` returned `decoy.com` (the path
    // tail) instead of `target`. A host-allowlist check would admit `decoy.com`
    // while reqwest sent the request to `target`. The authority must be
    // isolated (split on `/?#`) BEFORE userinfo stripping.

    #[test]
    fn at_sign_in_path_is_not_userinfo() {
        // The real host is the authority before the first `/`, never the
        // path's trailing token after an `@`.
        assert_eq!(
            host_from_url("https://169.254.169.254/@public-decoy.com"),
            Some("169.254.169.254".into()),
            "an `@` in the path must not be parsed as the userinfo separator"
        );
        assert_eq!(
            host_from_url("https://real-target.com/redirect?next=@evil.com"),
            Some("real-target.com".into())
        );
        assert_eq!(
            host_from_url("https://real-target.com/path@evil.com"),
            Some("real-target.com".into())
        );
    }

    #[test]
    fn userinfo_with_at_in_path_still_resolves_real_host() {
        // Legit userinfo PLUS a path `@`: authority isolation means only the
        // authority's `@` counts; the path `@` is irrelevant.
        assert_eq!(
            host_from_url("https://user@real-target.com/cb@decoy.com"),
            Some("real-target.com".into())
        );
    }

    #[test]
    fn at_sign_in_fragment_or_query_is_not_userinfo() {
        assert_eq!(
            host_from_url("https://real-target.com#@evil.com"),
            Some("real-target.com".into())
        );
        assert_eq!(
            host_from_url("https://real-target.com?u=a@evil.com"),
            Some("real-target.com".into())
        );
    }

    #[test]
    fn rejects_high_bit_byte_in_host() {
        // Non-ASCII host must arrive as Punycode (xn--…). Raw
        // high-bit bytes are an attempt to slip past header parsers.
        assert_eq!(host_from_url("https://evil\u{0080}.com/"), None);
        assert_eq!(host_from_url("https://evil\u{FFFD}.com/"), None);
    }
}
