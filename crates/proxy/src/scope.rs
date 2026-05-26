//! Per-request scope filtering for the proxy.
//!
//! Without a scope filter, the proxy evades *every* outbound request a
//! client makes — login flows, oauth callbacks, static assets, telemetry
//! beacons. That behaviour is correct for a focused scan but wrong for a
//! security practitioner who has dropped wafrift-proxy in front of Burp
//! and is browsing a target normally. Out-of-scope requests are forwarded
//! verbatim with no evasion, no gene-bank update, no detection logic.
//!
//! The matchers support a tiny ASCII glob grammar: `*` matches any run of
//! characters and `?` matches exactly one. Comparisons are case-
//! insensitive against the host and path components. No regex deps.

use wafrift_types::Method;

/// Compiled scope predicate evaluated on every proxied request.
#[derive(Debug, Clone, Default)]
pub struct ScopeFilter {
    only_hosts: Vec<String>,
    skip_hosts: Vec<String>,
    only_paths: Vec<String>,
    skip_paths: Vec<String>,
    only_methods: Vec<Method>,
}

impl ScopeFilter {
    pub fn new(
        only_hosts: Vec<String>,
        skip_hosts: Vec<String>,
        only_paths: Vec<String>,
        skip_paths: Vec<String>,
        only_methods: Vec<String>,
    ) -> Self {
        Self {
            only_hosts,
            skip_hosts,
            only_paths,
            skip_paths,
            only_methods: only_methods
                .into_iter()
                .map(|m| Method::from(m.as_str()))
                .collect(),
        }
    }

    /// Returns true when no scoping at all is configured — callers can
    /// skip the filter check entirely.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.only_hosts.is_empty()
            && self.skip_hosts.is_empty()
            && self.only_paths.is_empty()
            && self.skip_paths.is_empty()
            && self.only_methods.is_empty()
    }

    /// Decide whether a request is in the evasion scope.
    ///
    /// Semantics:
    ///   * `--only-host`/`--only-path`/`--only-method` are inclusive
    ///     filters: at least one entry must match (an empty list means
    ///     "no filter").
    ///   * `--skip-host`/`--skip-path` are exclusive filters: any match
    ///     drops the request out of scope, evaluated AFTER the inclusive
    ///     filters.
    #[must_use]
    pub fn allows(&self, host: &str, path: &str, method: &Method) -> bool {
        if !self.only_methods.is_empty() && !self.only_methods.contains(method) {
            return false;
        }
        // Strip an optional port suffix before glob-matching. Hyper /
        // many HTTP parsers surface the host as `api.example.com:8443`
        // for non-default ports; pre-fix the glob `*.example.com`
        // would NOT match because `:8443` is an unexpected suffix.
        // Out-of-scope requests to non-standard ports could pass the
        // filter unguarded. IPv6 literals `[::1]:443` are also covered
        // — split on the LAST `:` keeps the bracketed v6 intact.
        let host_no_port = strip_port(host);
        if !self.only_hosts.is_empty()
            && !self.only_hosts.iter().any(|p| glob_match(p, host_no_port))
        {
            return false;
        }
        if self.skip_hosts.iter().any(|p| glob_match(p, host_no_port)) {
            return false;
        }
        if !self.only_paths.is_empty() && !self.only_paths.iter().any(|p| glob_match(p, path)) {
            return false;
        }
        if self.skip_paths.iter().any(|p| glob_match(p, path)) {
            return false;
        }
        true
    }
}

/// Drop a trailing `:PORT` suffix if present. Bracketed IPv6 literals
/// (`[::1]`) keep their brackets; only the suffix AFTER the closing
/// `]` is stripped. For bare hosts (no `:`) the input is returned
/// unchanged.
fn strip_port(host: &str) -> &str {
    if let Some(stripped) = host.strip_prefix('[') {
        // IPv6 literal: find the closing `]`. The port (if any) is
        // after that. Return everything up to and including the `]`.
        if let Some(close) = stripped.find(']') {
            return &host[..close + 2];
        }
        return host;
    }
    // IPv4 / DNS: a single `:` separates host and port.
    match host.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => h,
        _ => host,
    }
}

/// Tiny ASCII glob matcher: `*` matches any run, `?` matches exactly one
/// byte, everything else is a case-insensitive literal. No escape rules
/// — keep the grammar simple so operators don't have to learn regex.
#[must_use]
pub fn glob_match(pattern: &str, s: &str) -> bool {
    glob_recurse(pattern.as_bytes(), s.as_bytes())
}

fn glob_recurse(p: &[u8], s: &[u8]) -> bool {
    match (p.first(), s.first()) {
        (None, None) => true,
        (Some(b'*'), _) => {
            // Greedy: try matching zero, then 1, 2, ... characters.
            glob_recurse(&p[1..], s) || (!s.is_empty() && glob_recurse(p, &s[1..]))
        }
        (Some(b'?'), Some(_)) => glob_recurse(&p[1..], &s[1..]),
        (Some(a), Some(b)) if a.eq_ignore_ascii_case(b) => glob_recurse(&p[1..], &s[1..]),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_literal_match_is_case_insensitive() {
        assert!(glob_match("Example.com", "example.COM"));
        assert!(!glob_match("example.com", "examples.com"));
    }

    #[test]
    fn glob_star_matches_subdomains() {
        assert!(glob_match("*.example.com", "api.example.com"));
        assert!(glob_match("*.example.com", "deep.api.example.com"));
        assert!(!glob_match("*.example.com", "example.com"));
    }

    #[test]
    fn glob_star_anywhere_in_pattern() {
        assert!(glob_match("/api/*", "/api/v1/users"));
        assert!(glob_match("/api/*/users", "/api/v1/users"));
        assert!(!glob_match("/api/*", "/web/v1"));
    }

    #[test]
    fn glob_question_matches_one_char() {
        assert!(glob_match("v?", "v1"));
        assert!(!glob_match("v?", "v10"));
        assert!(!glob_match("v?", "v"));
    }

    #[test]
    fn empty_filter_allows_everything() {
        let f = ScopeFilter::default();
        assert!(f.is_empty());
        assert!(f.allows("any.host", "/anything", &Method::from("POST")));
    }

    #[test]
    fn only_host_blocks_other_hosts() {
        let f = ScopeFilter::new(
            vec!["api.example.com".into()],
            vec![],
            vec![],
            vec![],
            vec![],
        );
        assert!(f.allows("api.example.com", "/x", &Method::from("GET")));
        assert!(!f.allows("oauth.example.com", "/x", &Method::from("GET")));
    }

    #[test]
    fn skip_path_excludes_static_assets() {
        let f = ScopeFilter::new(
            vec![],
            vec![],
            vec![],
            vec!["/static/*".into(), "/oauth/*".into(), "/favicon.ico".into()],
            vec![],
        );
        assert!(f.allows("h", "/api/users", &Method::from("GET")));
        assert!(!f.allows("h", "/static/app.js", &Method::from("GET")));
        assert!(!f.allows("h", "/oauth/callback", &Method::from("GET")));
        assert!(!f.allows("h", "/favicon.ico", &Method::from("GET")));
    }

    #[test]
    fn only_method_filters_by_verb() {
        let f = ScopeFilter::new(
            vec![],
            vec![],
            vec![],
            vec![],
            vec!["POST".into(), "PUT".into()],
        );
        assert!(f.allows("h", "/x", &Method::from("POST")));
        assert!(f.allows("h", "/x", &Method::from("PUT")));
        assert!(!f.allows("h", "/x", &Method::from("GET")));
    }

    #[test]
    fn skip_host_overrides_only_host() {
        // `--only-host *.example.com --skip-host status.example.com`
        let f = ScopeFilter::new(
            vec!["*.example.com".into()],
            vec!["status.example.com".into()],
            vec![],
            vec![],
            vec![],
        );
        assert!(f.allows("api.example.com", "/x", &Method::from("GET")));
        assert!(!f.allows("status.example.com", "/x", &Method::from("GET")));
    }

    #[test]
    fn combined_filters_are_anded() {
        let f = ScopeFilter::new(
            vec!["*.example.com".into()],
            vec![],
            vec!["/api/*".into()],
            vec!["/api/health".into()],
            vec!["GET".into(), "POST".into()],
        );
        assert!(f.allows("api.example.com", "/api/users", &Method::from("GET")));
        assert!(!f.allows("api.example.com", "/api/health", &Method::from("GET")));
        assert!(!f.allows("api.example.com", "/web/users", &Method::from("GET")));
        assert!(!f.allows("oauth.elsewhere.com", "/api/x", &Method::from("GET")));
        assert!(!f.allows("api.example.com", "/api/x", &Method::from("DELETE")));
    }

    #[test]
    fn only_host_does_not_match_substring_smuggling() {
        // Defends against "evil-api.example.com.attacker.tld" sneaking
        // through "*.example.com" — the glob anchors the whole string.
        let f = ScopeFilter::new(vec!["*.example.com".into()], vec![], vec![], vec![], vec![]);
        assert!(!f.allows("api.example.com.attacker.tld", "/", &Method::from("GET")));
    }

    // ── strip_port + allows() with :port suffix ───────────────

    #[test]
    fn strip_port_handles_bare_host() {
        assert_eq!(strip_port("api.example.com"), "api.example.com");
    }

    #[test]
    fn strip_port_removes_port_suffix() {
        assert_eq!(strip_port("api.example.com:8443"), "api.example.com");
        assert_eq!(strip_port("api.example.com:80"), "api.example.com");
    }

    #[test]
    fn strip_port_leaves_non_numeric_suffix_alone() {
        // `:something-not-a-port` is part of the host (defensive
        // against malformed input — keep it visible).
        assert_eq!(
            strip_port("api.example.com:notaport"),
            "api.example.com:notaport"
        );
    }

    #[test]
    fn strip_port_handles_ipv6_literal_with_port() {
        assert_eq!(strip_port("[::1]:8443"), "[::1]");
        assert_eq!(strip_port("[2001:db8::1]:443"), "[2001:db8::1]");
    }

    #[test]
    fn strip_port_handles_ipv6_literal_without_port() {
        assert_eq!(strip_port("[::1]"), "[::1]");
    }

    #[test]
    fn allows_glob_match_after_port_strip() {
        // Regression: pre-fix `*.example.com` would NOT match
        // `api.example.com:8443` and the request would slip past
        // the scope filter unguarded. The port-strip makes the
        // match work as the operator expects.
        let f = ScopeFilter::new(vec!["*.example.com".into()], vec![], vec![], vec![], vec![]);
        assert!(f.allows("api.example.com:8443", "/", &Method::from("GET")));
        assert!(f.allows("api.example.com:80", "/", &Method::from("GET")));
    }

    #[test]
    fn allows_skip_host_match_after_port_strip() {
        // Skip-host also benefits — an attacker can't bypass a
        // skip rule by adding a port.
        let f = ScopeFilter::new(
            vec![],
            vec![],
            vec!["admin.internal".into()],
            vec![],
            vec![],
        );
        assert!(!f.allows("admin.internal:9000", "/", &Method::from("GET")));
    }
}
