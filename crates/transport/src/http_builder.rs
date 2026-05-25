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

/// Build a reqwest `ClientBuilder` pre-configured with the wafrift
/// floor:
/// - `timeout(timeout_secs seconds)`
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
    base_client_builder_with_egress(timeout_secs, insecure, user_agent, None, "")
        .expect("no egress pool means no EgressError; this never fails")
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
    let mut b = ClientBuilder::new().timeout(Duration::from_secs(timeout_secs));
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
}
