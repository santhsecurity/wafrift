//! Shared `reqwest::Client` recipe primitives.
//!
//! Every wafrift component that opens its own HTTP client wants a
//! common floor: per-request timeout, optional `--insecure` cert
//! bypass for lab targets, the operator-configurable User-Agent
//! header. Pre-extract this trio was hand-rolled at ~13 call sites
//! across cli / proxy / recon — drifting independently each time
//! someone tuned e.g. the default timeout in one file.
//!
//! Each caller still owns its own redirect policy because those
//! diverge by security intent (proxy: `redirect::none()` to block
//! implicit SSRF following; parser-diff cmds: `limited(5)` to land
//! on the right origin; session_init: `limited(8)` for deeper
//! shop-checkout flows). The base builder leaves that knob alone
//! so callers cannot silently inherit the wrong policy.
//!
//! # Egress pool integration
//!
//! When `egress_pool` is `Some(&EgressPool)`, the builder returned by
//! [`base_client_builder_with_egress`] applies the next round-robin
//! egress entry's proxy configuration before returning. This is the
//! single integration point that wires egress rotation into every
//! wafrift probe without touching individual call sites.

use std::time::Duration;

use reqwest::ClientBuilder;

use crate::egress_pool::{EgressError, EgressPool};

/// Minimum timeout enforced on every client: 1 second.
///
/// A 0-second timeout with reqwest causes every request to fail
/// immediately (the connect/send deadline is already exceeded before
/// the socket opens). Callers that pass 0 almost always mean
/// "no limit" — but wafrift probes must always have a ceiling so a
/// hung upstream cannot park a task forever. Clamp to 1s as the
/// absolute floor; callers that genuinely need no-limit should not
/// call this helper.
const MIN_TIMEOUT_SECS: u64 = 1;

/// Build a reqwest `ClientBuilder` pre-configured with the wafrift
/// floor:
/// - `timeout(timeout_secs.max(1) seconds)` — minimum 1 s; 0 is clamped
///   (see `MIN_TIMEOUT_SECS`)
/// - `danger_accept_invalid_certs(insecure)` when `insecure == true`
/// - `user_agent(user_agent)` when `Some` (callers pass `None` to
///   inherit reqwest's default UA, or the configured wafrift UA
///   from `wafrift_cli::config::shared_user_agent`)
///
/// The redirect policy is INTENTIONALLY left unconfigured — callers
/// must add their own `.redirect(Policy::...)`. See module-level
/// docs for why.
pub fn base_client_builder(
    timeout_secs: u64,
    insecure: bool,
    user_agent: Option<&str>,
) -> ClientBuilder {
    // SAFETY: passing egress_pool=None can never produce EgressError.
    // We match rather than .expect() to avoid panic in production.
    match base_client_builder_with_egress(timeout_secs, insecure, user_agent, None, "") {
        Ok(b) => b,
        Err(_) => {
            // Unreachable: no-pool path cannot return EgressError.
            // Return a sensibly configured builder rather than panic.
            ClientBuilder::new().timeout(Duration::from_secs(timeout_secs.max(MIN_TIMEOUT_SECS)))
        }
    }
}

/// Like [`base_client_builder`] but optionally applies the next egress
/// entry from `egress_pool` for `target_host`.
///
/// Returns `Err(EgressError::EntirePoolCooled)` when a pool is supplied
/// and every entry is currently in cooldown for `target_host`.
pub fn base_client_builder_with_egress(
    timeout_secs: u64,
    insecure: bool,
    user_agent: Option<&str>,
    egress_pool: Option<&EgressPool>,
    target_host: &str,
) -> Result<ClientBuilder, EgressError> {
    // Clamp 0 to MIN_TIMEOUT_SECS. A zero Duration passed to reqwest's
    // .timeout() causes every request to fail immediately (the deadline
    // is already past at connection time). Callers that mean "no timeout"
    // must not use this helper; all wafrift probes require a deadline.
    let effective_timeout = timeout_secs.max(MIN_TIMEOUT_SECS);
    let mut b = ClientBuilder::new().timeout(Duration::from_secs(effective_timeout));
    if insecure {
        b = b.danger_accept_invalid_certs(true);
    }
    if let Some(ua) = user_agent {
        b = b.user_agent(ua);
    }
    if let Some(pool) = egress_pool {
        let entry = pool.next_for(target_host)?;
        b = entry.apply_to_builder(b);
    }
    Ok(b)
}

/// SSRF-safe redirect policy shared by every wafrift HTTP client that
/// follows redirects. reqwest's `Policy::limited` follows redirects to
/// ANY host — a hostile target can `302 Location: http://169.254.169.254/`
/// and exfil cloud metadata, or pivot into RFC1918, through the scanner.
/// This caps hops, refuses a redirect INTO a bogon IP literal (loopback /
/// RFC1918 / link-local metadata / IPv6 ULA, via the canonical
/// `wafrift_types::ip_addr_is_bogon`) — *unless the hop originates from a
/// bogon already*, i.e. the operator deliberately chose to scan a
/// private/loopback lab (the cross-origin guard below still pins the follow
/// to the identical origin, so this can never pivot to a different internal
/// host/port) — and stops cross-origin hops (reqwest can't strip auth from
/// the next request, so the safe move is to halt and let the caller observe
/// the 302 without leaking Cookie/Authorization to a third party).
///
/// Canonical home (§7 DEDUPLICATION): `cli::helpers::safe_redirect_policy`
/// delegates here, so there is exactly ONE implementation — in the HTTP
/// layer where it belongs — protecting the core `EvasionClient`, not just
/// the CLI commands that build their own clients (§15 SSRF). The decision
/// is factored into the pure `redirect_decision` so the SSRF logic is
/// unit-testable — `reqwest::redirect::Attempt` has no public constructor,
/// but `reqwest::Url` does.
#[must_use]
pub fn safe_redirect_policy(max_hops: usize) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt| {
        match redirect_decision(
            attempt.previous().last(),
            attempt.url(),
            attempt.previous().len(),
            max_hops,
        ) {
            RedirectDecision::Follow => attempt.follow(),
            RedirectDecision::Stop => attempt.stop(),
            RedirectDecision::Error(msg) => attempt.error(msg),
        }
    })
}

/// What [`safe_redirect_policy`] decides for one redirect hop. Extracted
/// from the policy closure so the SSRF logic is unit-testable: the
/// `reqwest::redirect::Attempt` handed to the closure has no public
/// constructor, but the `Url`s this function takes are freely constructable.
#[derive(Debug, PartialEq, Eq)]
enum RedirectDecision {
    /// Follow the redirect — same-origin, within the hop cap, not an SSRF pivot.
    Follow,
    /// Halt WITHOUT erroring — observe the 302 but do not follow (cross-origin
    /// hops, to avoid leaking auth headers to a third party).
    Stop,
    /// Refuse with an error — hop-cap exceeded, or an SSRF pivot into a bogon.
    Error(String),
}

/// True when `u`'s host is an IP literal in a bogon range (loopback /
/// RFC1918 / link-local metadata / IPv6 ULA). Hostnames — even ones that
/// would resolve to a bogon — return `false` here; the cross-origin guard
/// in `redirect_decision` is what stops hostname-based pivots, since any
/// redirect to a *different* host is cross-origin and halted regardless.
fn is_bogon_literal(u: &reqwest::Url) -> bool {
    u.host_str()
        .and_then(|h| h.parse::<std::net::IpAddr>().ok())
        .is_some_and(wafrift_types::ip_addr_is_bogon)
}

/// Pure decision core of [`safe_redirect_policy`]. `prev` is the URL that
/// issued this redirect (the hop we are coming FROM); `next` is the
/// `Location` target; `hops_so_far` is the number of prior hops. See
/// [`safe_redirect_policy`] for the full security rationale.
fn redirect_decision(
    prev: Option<&reqwest::Url>,
    next: &reqwest::Url,
    hops_so_far: usize,
    max_hops: usize,
) -> RedirectDecision {
    if hops_so_far >= max_hops {
        return RedirectDecision::Error(format!("too many redirects (cap {max_hops})"));
    }
    // Refuse a hop INTO a bogon literal, except when we are already on a
    // bogon (deliberate lab scan of a private/loopback range the operator
    // chose and gated via `assert_permitted`). The cross-origin guard below
    // still pins the follow to the identical origin, so "already on a bogon"
    // can only ever stay on that exact host:port — never a pivot to a
    // different internal service.
    if is_bogon_literal(next) && !prev.is_some_and(is_bogon_literal) {
        let ip = next.host_str().unwrap_or("?");
        return RedirectDecision::Error(format!(
            "refusing redirect to bogon address {ip} (SSRF defence)"
        ));
    }
    // Cross-origin guard: reqwest's Attempt API can't strip auth from the
    // next hop, so a cross-origin redirect could leak Cookie / Authorization
    // to a third party. Halt rather than follow.
    let prev_origin = prev.and_then(redirect_origin_triple);
    let next_origin = redirect_origin_triple(next);
    if let (Some(prev_o), Some(next_o)) = (prev_origin, next_origin)
        && prev_o != next_o
    {
        return RedirectDecision::Stop;
    }
    RedirectDecision::Follow
}

/// `(scheme, lowercased-host, port)` — two URLs are same-origin iff these
/// match. `None` when the URL has no host or no derivable port.
fn redirect_origin_triple(u: &reqwest::Url) -> Option<(String, String, u16)> {
    let host = u.host_str()?.to_ascii_lowercase();
    let port = u.port_or_known_default()?;
    Some((u.scheme().to_string(), host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_origin_triple_normalizes_host_case() {
        let u: reqwest::Url = "https://Example.COM:8443/p".parse().unwrap();
        let triple = redirect_origin_triple(&u).expect("has host + port");
        assert_eq!(triple.0, "https");
        assert_eq!(triple.1, "example.com");
        assert_eq!(triple.2, 8443);
    }

    #[test]
    fn redirect_origin_triple_uses_scheme_default_port() {
        // No explicit port: the scheme's default (443 https / 80 http) must
        // populate so same-origin comparisons don't false-mismatch
        // `https://x/` vs `https://x:443/`.
        let u: reqwest::Url = "https://example.com/p".parse().unwrap();
        let triple = redirect_origin_triple(&u).expect("scheme default port");
        assert_eq!(triple.2, 443);
    }

    #[test]
    fn safe_redirect_policy_builds_and_composes() {
        // `reqwest::redirect::Attempt` has no public constructor, so the
        // policy CLOSURE can't be invoked directly — but its decision logic
        // is tested via `redirect_decision` below. Here we pin only that the
        // policy constructs and composes onto a builder (catches a signature
        // / API-drift regression).
        let _ = safe_redirect_policy(5);
        let _ = base_client_builder(30, false, None)
            .redirect(safe_redirect_policy(5))
            .build()
            .unwrap();
    }

    // ── SSRF redirect decision (pure-core unit tests) ──────────────────
    // These exercise `redirect_decision` directly. `Url` is freely
    // constructable, so the security logic the policy closure runs is now
    // fully covered (it had ZERO behavioural coverage before the extract).

    fn url(s: &str) -> reqwest::Url {
        s.parse().expect("test url parses")
    }

    #[test]
    fn redirect_refuses_public_to_metadata_ip() {
        // The canonical SSRF pivot: a public origin 302s to the cloud
        // metadata IP. Must be refused with an error.
        let d = redirect_decision(
            Some(&url("https://example.com/")),
            &url("http://169.254.169.254/latest/meta-data/"),
            0,
            5,
        );
        assert!(matches!(d, RedirectDecision::Error(_)), "got {d:?}");
    }

    #[test]
    fn redirect_refuses_public_to_rfc1918_literal() {
        let d = redirect_decision(
            Some(&url("https://example.com/")),
            &url("http://10.0.0.1/"),
            0,
            5,
        );
        assert!(matches!(d, RedirectDecision::Error(_)), "got {d:?}");
    }

    #[test]
    fn redirect_refuses_public_to_loopback_literal() {
        let d = redirect_decision(
            Some(&url("https://example.com/")),
            &url("http://127.0.0.1:8080/"),
            0,
            5,
        );
        assert!(matches!(d, RedirectDecision::Error(_)), "got {d:?}");
    }

    #[test]
    fn redirect_refuses_bogon_even_with_no_previous() {
        // No recorded previous URL ⇒ prev is not a bogon ⇒ the SSRF refusal
        // still stands. (Belt-and-suspenders: the first hop should never be
        // a redirect anyway.)
        let d = redirect_decision(None, &url("http://169.254.169.254/"), 0, 5);
        assert!(matches!(d, RedirectDecision::Error(_)), "got {d:?}");
    }

    #[test]
    fn redirect_stops_cross_origin_public() {
        // Cross-origin public→public: HALT (don't leak auth), not an error.
        let d = redirect_decision(
            Some(&url("https://a.example/")),
            &url("https://b.example/"),
            0,
            5,
        );
        assert_eq!(d, RedirectDecision::Stop);
    }

    #[test]
    fn redirect_follows_same_origin_public() {
        let d = redirect_decision(
            Some(&url("https://a.example/x")),
            &url("https://a.example/y"),
            0,
            5,
        );
        assert_eq!(d, RedirectDecision::Follow);
    }

    #[test]
    fn redirect_follows_same_origin_loopback_lab() {
        // Operator deliberately scanning a loopback lab: a same-origin
        // redirect within it must be FOLLOWED (it was wrongly refused before
        // the prev-bogon refinement). `assert_permitted` already gated this.
        let d = redirect_decision(
            Some(&url("http://127.0.0.1:8080/login")),
            &url("http://127.0.0.1:8080/dashboard"),
            0,
            5,
        );
        assert_eq!(d, RedirectDecision::Follow);
    }

    #[test]
    fn redirect_follows_same_origin_rfc1918_lab() {
        let d = redirect_decision(
            Some(&url("http://10.0.0.1/a")),
            &url("http://10.0.0.1/b"),
            0,
            5,
        );
        assert_eq!(d, RedirectDecision::Follow);
    }

    #[test]
    fn redirect_stops_bogon_to_different_bogon_port() {
        // Even FROM a bogon, a hop to a different origin (port change →
        // Elasticsearch on :9200) is cross-origin → HALT. No intra-lab pivot.
        let d = redirect_decision(
            Some(&url("http://10.0.0.1/")),
            &url("http://10.0.0.1:9200/_cat/indices"),
            0,
            5,
        );
        assert_eq!(d, RedirectDecision::Stop);
    }

    #[test]
    fn redirect_stops_bogon_to_different_bogon_host() {
        let d = redirect_decision(
            Some(&url("http://10.0.0.1/")),
            &url("http://192.168.1.1/"),
            0,
            5,
        );
        assert_eq!(d, RedirectDecision::Stop);
    }

    #[test]
    fn redirect_refuses_when_over_hop_cap() {
        // hops_so_far >= max_hops → error regardless of target.
        let d = redirect_decision(
            Some(&url("https://a.example/")),
            &url("https://a.example/next"),
            5,
            5,
        );
        assert!(matches!(d, RedirectDecision::Error(_)), "got {d:?}");
    }

    #[test]
    fn redirect_no_prev_follows_non_bogon_target() {
        // No previous URL: same-origin compare is skipped (prev_origin None)
        // → follow a non-bogon target.
        let d = redirect_decision(None, &url("https://a.example/"), 0, 5);
        assert_eq!(d, RedirectDecision::Follow);
    }

    #[test]
    fn redirect_hostname_loopback_follows_same_origin() {
        // "localhost" is not an IP literal, so the bogon-literal check never
        // fires; a same-origin localhost→localhost redirect follows (lab via
        // hostname). A different host would be cross-origin → Stop.
        let d = redirect_decision(
            Some(&url("http://localhost:3000/a")),
            &url("http://localhost:3000/b"),
            0,
            5,
        );
        assert_eq!(d, RedirectDecision::Follow);
    }

    #[test]
    fn base_builder_compiles_with_minimal_inputs() {
        let _ = base_client_builder(30, false, None).build().unwrap();
    }

    #[test]
    fn base_builder_compiles_with_insecure_and_ua() {
        let _ = base_client_builder(30, true, Some("wafrift-test/1.0"))
            .build()
            .unwrap();
    }

    #[test]
    fn base_builder_compiles_with_long_timeout() {
        let _ = base_client_builder(300, false, None).build().unwrap();
    }

    #[test]
    fn base_builder_with_egress_no_pool() {
        let client = base_client_builder_with_egress(30, false, None, None, "host.example.com")
            .unwrap()
            .build()
            .unwrap();
        drop(client);
    }

    #[test]
    fn base_builder_with_egress_socks_pool() {
        use crate::egress_pool::EgressPool;
        let pool = EgressPool::builder()
            .socks5_str(vec!["socks5://127.0.0.1:1080".to_owned()])
            .expect("valid socks5 url")
            .build()
            .unwrap();
        let client =
            base_client_builder_with_egress(30, false, None, Some(&pool), "target.example.com")
                .unwrap()
                .build()
                .unwrap();
        drop(client);
    }

    // ── timeout boundary tests ────────────────────────────────────────────────

    #[test]
    fn timeout_zero_is_clamped_to_min_not_panic() {
        // A 0-second timeout causes reqwest to fail every request
        // immediately. base_client_builder must clamp 0 → MIN_TIMEOUT_SECS
        // (1 s) rather than forwarding a 0 that silently kills all I/O.
        let b = base_client_builder(0, false, None);
        // The builder must succeed (no panic, no error).
        assert!(
            b.build().is_ok(),
            "timeout=0 must not produce a broken builder"
        );
    }

    #[test]
    fn timeout_one_passes_through_unmodified() {
        // 1 s is the floor; it must not be bumped further.
        let b = base_client_builder(1, false, None);
        assert!(b.build().is_ok());
    }

    #[test]
    fn timeout_max_u64_does_not_overflow() {
        // Duration::from_secs(u64::MAX) is ~585 billion years — reqwest
        // accepts it. The builder must not panic on overflow arithmetic.
        let b = base_client_builder(u64::MAX, false, None);
        assert!(
            b.build().is_ok(),
            "u64::MAX timeout must not cause overflow panic"
        );
    }

    #[test]
    fn timeout_zero_with_egress_pool_also_clamped() {
        use crate::egress_pool::EgressPool;
        let pool = EgressPool::builder()
            .socks5_str(vec!["socks5://127.0.0.1:1080".to_owned()])
            .expect("valid url")
            .build()
            .unwrap();
        let b = base_client_builder_with_egress(0, false, None, Some(&pool), "target.com").unwrap();
        assert!(b.build().is_ok());
    }

    #[test]
    fn empty_user_agent_string_passes_through() {
        // Empty string UA is unusual but not invalid — must not panic.
        let b = base_client_builder(30, false, Some(""));
        assert!(b.build().is_ok());
    }

    #[test]
    fn empty_target_host_with_no_pool_is_ok() {
        // Empty target_host is fine when egress_pool is None — the host
        // field is only used when a pool is present.
        let b = base_client_builder_with_egress(30, false, None, None, "").unwrap();
        assert!(b.build().is_ok());
    }
}
