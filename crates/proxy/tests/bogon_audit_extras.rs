//! Regression coverage for the 2026-05-10 swarm-audit findings on
//! `ip_addr_is_bogon` (`proxy/upstream_policy.rs)`:
//!   HIGH: missing IPv4 ranges:
//!     - 100.64.0.0/10  Carrier-Grade NAT (RFC 6598)
//!     - 192.0.0.0/24   IETF protocol assignments (RFC 6890)
//!     - 198.18.0.0/15  benchmark testing (RFC 2544)
//!   HIGH: missing IPv6 ranges:
//!     - `2001:0::/32`    Teredo (RFC 4380)
//!     - `2001:20::/28`   `ORCHIDv2` (RFC 7343)
//!     - `100::/64`       discard-only (RFC 6666)
//!
//! Pre-fix every assertion below would have returned false (treating
//! the bogon address as a public, forward-allowed upstream).

use wafrift_proxy::upstream_policy::ip_addr_is_bogon;

// ── IPv4: CGN ───────────────────────────────────────────────────────

#[test]
fn cgn_100_64_0_1_is_bogon() {
    assert!(ip_addr_is_bogon("100.64.0.1".parse().unwrap()));
}

#[test]
fn cgn_100_127_255_254_is_bogon() {
    // Boundary of 100.64.0.0/10
    assert!(ip_addr_is_bogon("100.127.255.254".parse().unwrap()));
}

#[test]
fn just_outside_cgn_is_not_bogon() {
    // 100.63.x.x is public; 100.128.x.x is public.
    assert!(!ip_addr_is_bogon("100.63.255.255".parse().unwrap()));
    assert!(!ip_addr_is_bogon("100.128.0.1".parse().unwrap()));
}

// ── IPv4: IETF protocol assignments ─────────────────────────────────

#[test]
fn ietf_protocol_192_0_0_x_is_bogon() {
    assert!(ip_addr_is_bogon("192.0.0.1".parse().unwrap()));
    assert!(ip_addr_is_bogon("192.0.0.255".parse().unwrap()));
}

#[test]
fn just_outside_ietf_192_0_1_is_not_bogon() {
    assert!(!ip_addr_is_bogon("192.0.1.1".parse().unwrap()));
}

// ── IPv4: benchmark testing ─────────────────────────────────────────

#[test]
fn benchmark_198_18_0_1_is_bogon() {
    assert!(ip_addr_is_bogon("198.18.0.1".parse().unwrap()));
    assert!(ip_addr_is_bogon("198.19.255.254".parse().unwrap()));
}

#[test]
fn just_outside_benchmark_is_not_bogon() {
    assert!(!ip_addr_is_bogon("198.17.255.255".parse().unwrap()));
    assert!(!ip_addr_is_bogon("198.20.0.1".parse().unwrap()));
}

// ── IPv6: Teredo ────────────────────────────────────────────────────

#[test]
fn teredo_2001_0_is_bogon() {
    assert!(ip_addr_is_bogon("2001::1".parse().unwrap()));
    assert!(ip_addr_is_bogon("2001:0:1234:5678::1".parse().unwrap()));
}

// ── IPv6: ORCHIDv2 ──────────────────────────────────────────────────

#[test]
fn orchidv2_2001_20_is_bogon() {
    assert!(ip_addr_is_bogon("2001:20::1".parse().unwrap()));
    // Boundary check on the /28
    assert!(ip_addr_is_bogon("2001:2f::1".parse().unwrap()));
}

#[test]
fn just_outside_orchidv2_is_not_bogon() {
    // 2001:30:: is past the /28 boundary.
    assert!(!ip_addr_is_bogon("2001:30::1".parse().unwrap()));
}

// ── IPv6: discard-only ──────────────────────────────────────────────

#[test]
fn discard_100_is_bogon() {
    assert!(ip_addr_is_bogon("100::1".parse().unwrap()));
}

// ── Negative regression: public addresses still NOT bogon ───────────

#[test]
fn well_known_public_ips_remain_allowed() {
    assert!(!ip_addr_is_bogon("8.8.8.8".parse().unwrap()));
    assert!(!ip_addr_is_bogon("1.1.1.1".parse().unwrap()));
    assert!(!ip_addr_is_bogon("2001:4860:4860::8888".parse().unwrap()));
    assert!(!ip_addr_is_bogon("2606:4700:4700::1111".parse().unwrap()));
}
