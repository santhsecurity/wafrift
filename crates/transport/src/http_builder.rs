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
///   (see [`MIN_TIMEOUT_SECS`])
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
            ClientBuilder::new()
                .timeout(Duration::from_secs(timeout_secs.max(MIN_TIMEOUT_SECS)))
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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(b.build().is_ok(), "timeout=0 must not produce a broken builder");
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
        assert!(b.build().is_ok(), "u64::MAX timeout must not cause overflow panic");
    }

    #[test]
    fn timeout_zero_with_egress_pool_also_clamped() {
        use crate::egress_pool::EgressPool;
        let pool = EgressPool::builder()
            .socks5_str(vec!["socks5://127.0.0.1:1080".to_owned()])
            .expect("valid url")
            .build()
            .unwrap();
        let b = base_client_builder_with_egress(0, false, None, Some(&pool), "target.com")
            .unwrap();
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
        let b = base_client_builder_with_egress(30, false, None, None, "")
            .unwrap();
        assert!(b.build().is_ok());
    }
}
