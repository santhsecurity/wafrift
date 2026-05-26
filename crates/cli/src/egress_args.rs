//! Bridge between CLI `--egress-*` flags and `wafrift_transport::EgressPool`.
//!
//! Centralizes the construction of the IP-rotation pool so `scan` and
//! `bench-waf` both pick up the operator's `--egress-socks5`,
//! `--egress-http-proxy`, and `--egress-tailscale-nodes` flags through
//! one validated path. Before this helper, both commands defined the
//! flags but never consulted them: the http client was built with
//! `base_client_builder` (no pool) and the egress fields were
//! propagated through struct literals into nothing.
//!
//! The helper:
//!
//! 1. Returns `Ok(None)` when **all** egress inputs are empty — that's
//!    the legacy hot path, no pool overhead.
//! 2. Otherwise builds an `EgressPool` with validated SOCKS5 / HTTP
//!    proxy URLs and any Tailscale exit-node names, applying the
//!    operator's `--egress-challenge-threshold` and
//!    `--egress-cooldown-secs` settings.
//! 3. Surfaces validation errors as `Err(String)` so the caller can
//!    emit a clear message and exit, rather than silently dropping a
//!    malformed proxy from rotation.

use wafrift_transport::EgressPool;
use wafrift_transport::egress_pool::EgressError;

/// Inputs accepted by [`build_egress_pool`].  These mirror the CLI
/// `--egress-*` flag shapes on both `scan` and `bench-waf` so adding
/// new egress flag callers stays a copy-paste away.
pub struct EgressArgs<'a> {
    /// `--egress-socks5` proxy URL list (e.g. `socks5://user:pass@host:port`).
    pub socks5: &'a [String],
    /// `--egress-http-proxy` URL list (e.g. `http://host:port`).
    pub http_proxy: &'a [String],
    /// `--egress-tailscale-nodes` exit-node names accessed via the
    /// local Tailscale SOCKS listener.
    pub tailscale_nodes: &'a [String],
    /// Address of the Tailscale local SOCKS listener. Default `127.0.0.1:1055`.
    pub tailscale_socks_addr: &'a str,
    /// Consecutive challenge responses before cooling an entry.
    pub challenge_threshold: u32,
    /// Seconds a cooled entry stays out of rotation.
    pub cooldown_secs: u64,
}

impl<'a> EgressArgs<'a> {
    /// True when no egress backends were supplied — callers can
    /// skip pool construction entirely in that case.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.socks5.is_empty()
            && self.http_proxy.is_empty()
            && self.tailscale_nodes.is_empty()
    }
}

/// Extract the bare host from an http(s) URL — needed by
/// `EgressPool::next_for` to key per-target cooldown state.
///
/// Handles:
/// - Scheme case-insensitively (`HTTPS://` works).
/// - Bracketed IPv6 literals (`https://[::1]:8443/` → `[::1]`).
/// - Userinfo segments (`https://user:pass@host/` → `host`).
/// - Query strings without paths (`https://host?q=1` → `host`).
/// - Fragments (`https://host#frag` → `host`).
///
/// Returns `None` when the URL has no recognizable host (callers
/// fall back to an empty string, which the transport layer treats
/// as "no host gating").
#[must_use]
pub fn target_host(target_url: &str) -> Option<String> {
    let trimmed = target_url.trim();
    // Case-insensitive scheme strip — RFC 3986 says schemes are
    // case-insensitive; a cheap manual prefix strip otherwise misses
    // `HTTPS://`, `Http://`, etc.
    let after_scheme = strip_scheme_case_insensitive(trimmed);
    // Userinfo is everything before the LAST `@` (an `@` in the path
    // would be after the host so won't appear here since we slice
    // before stripping the path).
    let authority_end = after_scheme
        .find(|c: char| c == '/' || c == '?' || c == '#')
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];
    let host_port = match authority.rfind('@') {
        Some(at) => &authority[at + 1..],
        None => authority,
    };
    // IPv6 literal: `[::1]` or `[::1]:port`. The closing bracket
    // bounds the host; anything after (incl. `:port`) is stripped.
    let host = if let Some(stripped) = host_port.strip_prefix('[') {
        match stripped.find(']') {
            // Re-include the brackets for clarity in the returned
            // identifier — `[::1]` is unambiguous; `::1` could be
            // mistaken for a relative path on Windows.
            Some(close) => format!("[{}]", &stripped[..close]),
            None => return None, // malformed: open bracket, no close
        }
    } else {
        host_port.rsplitn(2, ':').last().unwrap_or(host_port).to_string()
    };
    if host.is_empty() || host == "[]" {
        return None;
    }
    // Defense-in-depth: refuse a host that contains ANY control byte
    // (CR/LF/NUL/etc., per ASCII <0x20 or 0x7f). Pre-fix the parser
    // accepted `https://waf.example.com\r\nX-Smuggle: yes/` and
    // returned `"waf.example.com\r\nX-Smuggle: yes"` (the newline
    // landed in the authority section before the path slash). If any
    // downstream callsite embedded this host in an outgoing HTTP
    // header (e.g. a `Host:` line on a follow-up connection through
    // the egress pool) it would have CRLF-injected the smuggled
    // header into the wire. The test
    // `target_host_with_embedded_newline_does_not_panic` previously
    // documented this as "caller's job to reject" — never the right
    // call for an authority-extraction helper. We reject here so
    // every caller is automatically safe.
    if host
        .bytes()
        .any(|b| b < 0x20 || b == 0x7f)
    {
        return None;
    }
    Some(host)
}

/// Strip `http://` or `https://` from the front of `s`,
/// case-insensitively. Returns the rest of the string unchanged when
/// no scheme matches.
fn strip_scheme_case_insensitive(s: &str) -> &str {
    for scheme in ["https://", "http://"] {
        if s.len() >= scheme.len() && s[..scheme.len()].eq_ignore_ascii_case(scheme) {
            return &s[scheme.len()..];
        }
    }
    s
}

/// Build an [`EgressPool`] from the operator's `--egress-*` flags.
///
/// * `Ok(None)` — no backends supplied; caller should use the bare
///   client builder.
/// * `Ok(Some(pool))` — pool ready to thread into
///   `base_client_builder_with_egress`.
/// * `Err(msg)` — one or more URLs failed validation; caller should
///   emit `msg` and exit with a non-zero status.
pub fn build_egress_pool(args: &EgressArgs<'_>) -> Result<Option<EgressPool>, String> {
    if args.is_empty() {
        return Ok(None);
    }
    let mut builder = EgressPool::builder()
        .challenge_threshold(args.challenge_threshold)
        .cooldown_secs(args.cooldown_secs);
    if !args.socks5.is_empty() {
        builder = builder
            .socks5_str(args.socks5.to_vec())
            .map_err(|e: EgressError| format!("--egress-socks5: {e}"))?;
    }
    if !args.http_proxy.is_empty() {
        builder = builder
            .http_proxy_str(args.http_proxy.to_vec())
            .map_err(|e: EgressError| format!("--egress-http-proxy: {e}"))?;
    }
    if !args.tailscale_nodes.is_empty() {
        builder = builder.tailscale_nodes(
            args.tailscale_nodes.to_vec(),
            Some(args.tailscale_socks_addr.to_string()),
        );
    }
    let pool = builder
        .build()
        .map_err(|e: EgressError| format!("egress pool build failed: {e}"))?;
    Ok(Some(pool))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_args() -> EgressArgs<'static> {
        EgressArgs {
            socks5: &[],
            http_proxy: &[],
            tailscale_nodes: &[],
            tailscale_socks_addr: "127.0.0.1:1055",
            challenge_threshold: 3,
            cooldown_secs: 300,
        }
    }

    #[test]
    fn empty_inputs_return_none() {
        let args = empty_args();
        assert!(args.is_empty());
        let pool = build_egress_pool(&args).expect("no-op succeeds");
        assert!(pool.is_none(), "no backends → no pool, legacy hot path");
    }

    #[test]
    fn valid_socks5_url_builds_pool() {
        let socks = vec!["socks5://127.0.0.1:1080".to_string()];
        let args = EgressArgs {
            socks5: &socks,
            ..empty_args()
        };
        let pool = build_egress_pool(&args).expect("should build");
        assert!(pool.is_some(), "non-empty input must produce a pool");
    }

    #[test]
    fn valid_http_proxy_builds_pool() {
        let hp = vec!["http://proxy.example.com:8080".to_string()];
        let args = EgressArgs {
            http_proxy: &hp,
            ..empty_args()
        };
        let pool = build_egress_pool(&args).expect("should build");
        assert!(pool.is_some());
    }

    #[test]
    fn tailscale_nodes_build_pool() {
        let nodes = vec!["exit-uk".to_string(), "exit-us".to_string()];
        let args = EgressArgs {
            tailscale_nodes: &nodes,
            ..empty_args()
        };
        let pool = build_egress_pool(&args).expect("should build");
        assert!(pool.is_some());
    }

    #[test]
    fn invalid_socks5_url_returns_err_with_flag_name() {
        let bad = vec!["not-a-url".to_string()];
        let args = EgressArgs {
            socks5: &bad,
            ..empty_args()
        };
        let err = build_egress_pool(&args).expect_err("should reject");
        assert!(
            err.contains("--egress-socks5"),
            "error must name the flag for the operator: {err}"
        );
    }

    #[test]
    fn invalid_http_proxy_returns_err_with_flag_name() {
        let bad = vec!["ftp://wrong-scheme:21".to_string()];
        let args = EgressArgs {
            http_proxy: &bad,
            ..empty_args()
        };
        let err = build_egress_pool(&args).expect_err("should reject ftp");
        assert!(
            err.contains("--egress-http-proxy"),
            "error must name the flag: {err}"
        );
    }

    #[test]
    fn mixed_backends_all_combined_into_one_pool() {
        let socks = vec!["socks5://127.0.0.1:1080".to_string()];
        let hp = vec!["http://proxy:8080".to_string()];
        let nodes = vec!["exit-us".to_string()];
        let args = EgressArgs {
            socks5: &socks,
            http_proxy: &hp,
            tailscale_nodes: &nodes,
            ..empty_args()
        };
        let pool = build_egress_pool(&args).expect("mixed pool builds");
        assert!(pool.is_some());
    }

    #[test]
    fn target_host_strips_scheme_and_port() {
        assert_eq!(
            target_host("https://waf.example.com:8443/foo"),
            Some("waf.example.com".to_string())
        );
        assert_eq!(
            target_host("http://waf.example.com/"),
            Some("waf.example.com".to_string())
        );
        assert_eq!(
            target_host("https://waf.example.com"),
            Some("waf.example.com".to_string())
        );
        // No scheme — accept bare host as input.
        assert_eq!(
            target_host("waf.example.com:8443"),
            Some("waf.example.com".to_string())
        );
    }

    #[test]
    fn target_host_empty_returns_none() {
        assert_eq!(target_host(""), None);
        assert_eq!(target_host("https://"), None);
        assert_eq!(target_host("/just/a/path"), None);
    }

    // ─── ADVERSARIAL: target_host edge cases ──────────────────────

    #[test]
    fn target_host_https_with_userinfo_returns_host_not_userinfo() {
        // `https://user:pass@host:port/path` — userinfo is everything
        // before the @. Stripping it correctly avoids mis-keying
        // cooldown state on "user" when many operators share one
        // tailscale-routed target with basic auth.
        assert_eq!(
            target_host("https://user:p%40ss@waf.example.com:443/"),
            Some("waf.example.com".to_string()),
            "must strip userinfo and return the actual host"
        );
    }

    #[test]
    fn target_host_userinfo_no_password() {
        // `https://user@host/` — userinfo with no password is also
        // legal per RFC 3986.
        assert_eq!(
            target_host("https://user@waf.example.com/"),
            Some("waf.example.com".to_string())
        );
    }

    #[test]
    fn target_host_userinfo_with_at_in_password() {
        // userinfo can contain percent-encoded `@`. The last `@` is
        // the authority separator.
        assert_eq!(
            target_host("https://user:p%40@host.example/"),
            Some("host.example".to_string())
        );
    }

    #[test]
    fn target_host_ipv6_bracketed() {
        // `https://[::1]:8443/` — bracketed IPv6 literal. Returns
        // `[::1]` including the brackets so the operator-visible
        // identifier is unambiguous.
        assert_eq!(target_host("https://[::1]:8443/"), Some("[::1]".to_string()));
    }

    #[test]
    fn target_host_ipv6_full_address() {
        assert_eq!(
            target_host("https://[2001:db8::1]:443/"),
            Some("[2001:db8::1]".to_string())
        );
    }

    #[test]
    fn target_host_ipv6_no_port() {
        assert_eq!(target_host("https://[::1]/"), Some("[::1]".to_string()));
    }

    #[test]
    fn target_host_ipv6_malformed_missing_close_bracket() {
        // `[::1` without a closing bracket — must not panic, must
        // return None rather than smuggle a partial parse.
        assert_eq!(target_host("https://[::1/"), None);
    }

    #[test]
    fn target_host_query_only_url() {
        // `https://example.com?q=1` — no path slash, just a query.
        // Query must be stripped from the authority.
        assert_eq!(
            target_host("https://example.com?q=1"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn target_host_fragment_stripped() {
        assert_eq!(
            target_host("https://example.com#fragment"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn target_host_with_trailing_dot_preserved() {
        // FQDN form `example.com.` — TLDs use this. Should preserve.
        assert_eq!(target_host("https://example.com./"), Some("example.com.".into()));
    }

    #[test]
    fn target_host_uppercase_scheme_stripped() {
        // RFC 3986: schemes are case-insensitive.
        assert_eq!(
            target_host("HTTPS://waf.example.com/"),
            Some("waf.example.com".to_string())
        );
        assert_eq!(
            target_host("Http://waf.example.com/"),
            Some("waf.example.com".to_string())
        );
    }

    #[test]
    fn target_host_trimmed_of_whitespace() {
        // Operators sometimes paste with leading/trailing whitespace.
        // RFC says no, but cooldown keying should be robust.
        assert_eq!(
            target_host("  https://waf.example.com/  "),
            Some("waf.example.com".to_string())
        );
    }

    #[test]
    fn target_host_internationalized_domain_passes_through() {
        // Punycode-encoded IDN: `xn--80akhbyknj4f.com` is `испытание.com`.
        // The parser should pass the bytes through unchanged — no
        // punycode munging.
        assert_eq!(
            target_host("https://xn--80akhbyknj4f.com/"),
            Some("xn--80akhbyknj4f.com".to_string())
        );
    }

    #[test]
    fn target_host_with_only_port_no_host() {
        // `https://:8443/` — port present, host empty. Must be None
        // so the caller doesn't key cooldown on "".
        assert_eq!(target_host("https://:8443/"), None);
    }

    #[test]
    fn target_host_handles_unicode_host_bytes() {
        // Raw unicode host (not punycoded). Most production URLs are
        // punycoded but the parser must not panic on raw bytes.
        let h = target_host("https://экспресс.example/");
        assert!(h.is_some(), "must not return None or panic on unicode");
    }

    // ─── ADVERSARIAL: build_egress_pool boundary cases ────────────

    #[test]
    fn pool_rejects_socks5_with_empty_string() {
        let empty = vec![String::new()];
        let args = EgressArgs {
            socks5: &empty,
            ..empty_args()
        };
        let err = build_egress_pool(&args).expect_err("empty URL must reject");
        assert!(err.contains("--egress-socks5"), "error must name flag: {err}");
    }

    #[test]
    fn pool_rejects_socks5_with_whitespace_only() {
        let ws = vec!["   \t\n".to_string()];
        let args = EgressArgs {
            socks5: &ws,
            ..empty_args()
        };
        // The pool's URL validator may or may not strip — pin behavior.
        let result = build_egress_pool(&args);
        assert!(result.is_err(), "whitespace-only must not silently build a pool");
    }

    #[test]
    fn pool_rejects_socks5_with_javascript_scheme_injection() {
        // Defence-in-depth: an operator pasting from a phishing
        // attempt might supply `javascript:alert(1)` as a SOCKS URL.
        // The validator must reject.
        let bad = vec!["javascript:alert(1)".to_string()];
        let args = EgressArgs {
            socks5: &bad,
            ..empty_args()
        };
        assert!(build_egress_pool(&args).is_err());
    }

    #[test]
    fn pool_handles_many_backends_without_overflow() {
        // 1000 SOCKS5 entries — must not OOM, panic, or take seconds.
        let urls: Vec<String> = (0..1000)
            .map(|i| format!("socks5://127.0.0.1:{}", 10000 + i))
            .collect();
        let args = EgressArgs {
            socks5: &urls,
            ..empty_args()
        };
        let pool = build_egress_pool(&args).expect("1000 entries must build");
        assert!(pool.is_some());
    }

    #[test]
    fn pool_with_threshold_zero_does_not_underflow() {
        // challenge_threshold = 0 means "cool on first challenge".
        // Pool must not subtract-with-underflow.
        let socks = vec!["socks5://127.0.0.1:1080".to_string()];
        let args = EgressArgs {
            socks5: &socks,
            challenge_threshold: 0,
            ..empty_args()
        };
        let pool = build_egress_pool(&args).expect("threshold=0 must build");
        assert!(pool.is_some());
    }

    #[test]
    fn pool_with_max_cooldown_does_not_overflow() {
        // u64::MAX seconds — must not panic on Duration::from_secs.
        let socks = vec!["socks5://127.0.0.1:1080".to_string()];
        let args = EgressArgs {
            socks5: &socks,
            cooldown_secs: u64::MAX,
            ..empty_args()
        };
        let pool = build_egress_pool(&args).expect("u64::MAX cooldown must build");
        assert!(pool.is_some());
    }

    #[test]
    fn pool_mixed_valid_invalid_socks_returns_err_at_first_bad() {
        // First valid, second invalid. Builder uses socks5_str (not
        // _raw), so it must surface the validation error at the
        // first failure rather than swallow it.
        let urls = vec![
            "socks5://127.0.0.1:1080".to_string(),
            "not-a-url".to_string(),
            "socks5://10.0.0.1:1080".to_string(),
        ];
        let args = EgressArgs {
            socks5: &urls,
            ..empty_args()
        };
        let err = build_egress_pool(&args).expect_err("invalid in middle must surface");
        assert!(err.contains("--egress-socks5"), "error must name flag: {err}");
    }

    #[test]
    fn pool_duplicate_backends_both_added_no_dedup() {
        // Pool doesn't dedup — pin this behaviour. Operators may
        // intentionally double-weight an exit node.
        let urls = vec![
            "socks5://127.0.0.1:1080".to_string(),
            "socks5://127.0.0.1:1080".to_string(),
        ];
        let args = EgressArgs {
            socks5: &urls,
            ..empty_args()
        };
        let pool = build_egress_pool(&args).expect("duplicates accepted");
        assert!(pool.is_some());
    }

    #[test]
    fn pool_tailscale_with_empty_node_names_treated_as_no_backend() {
        // tailscale_nodes = [""] — empty entry. Should error or
        // accept; pin current behaviour.
        let nodes = vec![String::new()];
        let args = EgressArgs {
            tailscale_nodes: &nodes,
            ..empty_args()
        };
        let result = build_egress_pool(&args);
        // tailscale_nodes is is_empty=false (single empty string),
        // builder calls tailscale_nodes(...) which adds an empty
        // EgressBackend::TailscaleNode { node_name: "", ... }. Pool
        // build will succeed but the node is unroutable.
        assert!(
            result.is_ok(),
            "empty node names currently accepted (operator surface for bug-detect)"
        );
    }

    #[test]
    fn pool_tailscale_with_invalid_socks_addr_format() {
        // tailscale_socks_addr = "not an address". Builder doesn't
        // pre-validate the addr (the SOCKS dial fails at runtime).
        // Pin: build_egress_pool must NOT panic on bad addr.
        let nodes = vec!["exit-us".to_string()];
        let args = EgressArgs {
            tailscale_nodes: &nodes,
            tailscale_socks_addr: "not an address with spaces",
            ..empty_args()
        };
        let result = build_egress_pool(&args);
        assert!(
            result.is_ok(),
            "bad SOCKS addr is a runtime-dial error, not a build error"
        );
    }

    // ─── ADVERSARIAL: fingerprint determinism ─────────────────────

    #[test]
    fn target_host_idempotent_on_repeated_calls() {
        let url = "https://waf.example.com:8443/path";
        let a = target_host(url);
        let b = target_host(url);
        assert_eq!(a, b, "target_host must be a pure function");
    }

    // ─── ADVERSARIAL: control-byte / injection in URL ─────────────

    #[test]
    fn target_host_with_embedded_newline_rejects_to_block_crlf_injection() {
        // Pre-fix the parser returned `"waf.example.com\r\nX-Smuggle:
        // yes"` — a CRLF-injection vector if the host was ever
        // embedded in an outgoing HTTP header. Rejection at the
        // authority extractor is the right defense.
        assert_eq!(
            target_host("https://waf.example.com\r\nX-Smuggle: yes/"),
            None,
            "CRLF in the authority must reject — downstream callers \
             could embed this in a Host: header and smuggle"
        );
        // Lone CR and lone LF must also reject (RFC 3986 §3.2.2:
        // authority is OWS-bounded ASCII).
        assert_eq!(target_host("https://waf.example.com\rfoo/"), None);
        assert_eq!(target_host("https://waf.example.com\nfoo/"), None);
    }

    #[test]
    fn target_host_with_null_byte_rejects() {
        // NUL in a host is malformed; reject per defense-in-depth.
        assert_eq!(target_host("https://waf.example.com\0/"), None);
    }

    #[test]
    fn target_host_rejects_low_control_bytes_in_general() {
        // Anti-rig: pin behaviour across the full control-byte range
        // — not just CR/LF/NUL. RFC 3986 §3.2.2 limits authority to
        // a specific char class; rejecting anything under 0x20 (and
        // 0x7f DEL) is conservative-correct.
        for b in [0x01u8, 0x07, 0x08, 0x0b, 0x0c, 0x1f, 0x7f] {
            let url = format!(
                "https://waf.example.com{}/",
                std::str::from_utf8(&[b]).unwrap_or("")
            );
            if std::str::from_utf8(&[b]).is_ok() {
                assert_eq!(
                    target_host(&url),
                    None,
                    "control byte 0x{b:02x} must reject"
                );
            }
        }
    }

    #[test]
    fn challenge_threshold_and_cooldown_propagate() {
        // The pool's internal config isn't directly observable from
        // outside the builder, but a build with custom values must
        // succeed end-to-end — that's the wire-up the test guards.
        let socks = vec!["socks5://127.0.0.1:1080".to_string()];
        let args = EgressArgs {
            socks5: &socks,
            challenge_threshold: 7,
            cooldown_secs: 600,
            ..empty_args()
        };
        let pool = build_egress_pool(&args).expect("custom threshold/cooldown builds");
        assert!(pool.is_some());
    }
}
