//! Regression coverage for the 2026-05-10 swarm-audit CRITICAL:
//!   tunnel(addr: String) re-resolved DNS at connect time after the
//!   caller had already validated the host via `assert_connect_target`_
//!   allowed. An attacker who flipped the DNS record between the two
//!   lookups (DNS rebinding) could land on 127.0.0.1 or RFC1918 even
//!   though the validation saw a public IP.
//!
//! The fix re-shapes the API:
//!   `resolve_connect_target_allowed()` returns the validated `SocketAddrs`
//!   `tunnel()` now takes Vec<SocketAddr> instead of String
//!   The CONNECT call site resolves once and passes the addresses down
//!
//! This test confirms the new API exists and validates the resolved
//! addresses against the bogon set.

use wafrift_proxy::upstream_policy::{UpstreamPolicy, resolve_connect_target_allowed};

#[tokio::test(flavor = "current_thread")]
async fn literal_loopback_v4_rejected_with_resolved_address() {
    let policy = UpstreamPolicy::default();
    let err = resolve_connect_target_allowed("127.0.0.1:443", &policy)
        .await
        .expect_err("loopback must be rejected");
    assert!(err.contains("127.0.0.1"));
}

#[tokio::test(flavor = "current_thread")]
async fn literal_v6_loopback_rejected() {
    let policy = UpstreamPolicy::default();
    let err = resolve_connect_target_allowed("[::1]:443", &policy)
        .await
        .expect_err("v6 loopback must be rejected");
    let _ = err;
}

#[tokio::test(flavor = "current_thread")]
async fn literal_imds_metadata_rejected() {
    let policy = UpstreamPolicy::default();
    let err = resolve_connect_target_allowed("169.254.169.254:80", &policy)
        .await
        .expect_err("AWS IMDS must be rejected");
    let _ = err;
}

#[tokio::test(flavor = "current_thread")]
async fn cgn_range_rejected() {
    let policy = UpstreamPolicy::default();
    let _ = resolve_connect_target_allowed("100.64.0.1:443", &policy)
        .await
        .expect_err("CGN range must be rejected");
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_authority_returns_error() {
    let policy = UpstreamPolicy::default();
    let err = resolve_connect_target_allowed("not a valid authority", &policy)
        .await
        .expect_err("malformed authority must error");
    assert!(err.contains("invalid"));
}

#[tokio::test(flavor = "current_thread")]
async fn allow_private_upstream_returns_addrs_without_filtering() {
    // When the operator opts into private upstreams (lab mode), the
    // function still resolves the address so the caller can connect
    // without doing a second lookup. It just skips bogon filtering.
    let policy = UpstreamPolicy {
        allow_private_upstream: true,
        insecure_open_upstream: false,
    };
    let addrs = resolve_connect_target_allowed("127.0.0.1:443", &policy)
        .await
        .expect("allow_private_upstream must not reject literal loopback");
    assert!(!addrs.is_empty());
    assert_eq!(addrs[0].port(), 443);
}
