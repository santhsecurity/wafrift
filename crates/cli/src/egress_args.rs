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
/// Strips scheme + port + path. Returns `None` when the URL has no
/// recognizable host (callers should fall back to an empty string in
/// that case, which the transport layer treats as "no host gating").
#[must_use]
pub fn target_host(target_url: &str) -> Option<String> {
    let without_scheme = target_url
        .strip_prefix("https://")
        .or_else(|| target_url.strip_prefix("http://"))
        .unwrap_or(target_url);
    let host_and_rest = without_scheme.split('/').next()?;
    let host = host_and_rest.split(':').next()?;
    if host.is_empty() { None } else { Some(host.to_string()) }
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
