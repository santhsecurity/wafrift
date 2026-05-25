//! Behavioural parity between `wafrift_types::bogon::ip_addr_is_bogon`
//! and `scanclient::bogon::ip_addr_is_bogon`.
//!
//! Two textual copies of the SSRF policy live in the tree (see the
//! module-doc in `wafrift-types/src/bogon.rs` for the layering
//! reason — pulling scanclient's reqwest tree into the foundation
//! types crate is unacceptable). This test exists so any drift —
//! a new range added to one, a fix landing only in one — fails CI
//! instead of leaking through to production.
//!
//! Battery covers every category both implementations classify:
//! IPv4 RFC 1918, loopback, link-local, IMDS, broadcast,
//! documentation, CGN, IETF assignment, benchmark, public DNS;
//! IPv6 loopback (the `::1` regression that pre-2026-05-23
//! escaped the donor copy), unique-local, link-local,
//! documentation, Teredo, ORCHIDv2, discard, multicast,
//! 6to4-wrapping-private and 6to4-wrapping-public, `::ffff:`-mapped
//! private v4, and several public IPv6 addresses.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn v6(s0: u16, s1: u16, s2: u16, s3: u16, s4: u16, s5: u16, s6: u16, s7: u16) -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(s0, s1, s2, s3, s4, s5, s6, s7))
}

fn battery() -> Vec<IpAddr> {
    vec![
        // IPv4 — bogon
        v4(10, 0, 0, 1),
        v4(10, 255, 255, 254),
        v4(172, 16, 0, 1),
        v4(172, 31, 255, 254),
        v4(192, 168, 1, 1),
        v4(127, 0, 0, 1),
        v4(127, 1, 2, 3),
        v4(169, 254, 0, 1),
        v4(169, 254, 169, 254),
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V4(Ipv4Addr::BROADCAST),
        v4(192, 0, 2, 1),
        v4(198, 51, 100, 1),
        v4(203, 0, 113, 1),
        v4(100, 64, 0, 1),
        v4(100, 127, 255, 254),
        v4(192, 0, 0, 1),
        v4(198, 18, 0, 1),
        v4(198, 19, 0, 1),
        // IPv4 — public
        v4(8, 8, 8, 8),
        v4(1, 1, 1, 1),
        v4(208, 67, 222, 222),
        v4(172, 32, 0, 1),
        v4(100, 128, 0, 1),
        v4(198, 20, 0, 1),
        // IPv6 — bogon (loopback regression on left flank)
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        v6(0xfc00, 0, 0, 0, 0, 0, 0, 1),
        v6(0xfd00, 0, 0, 0, 0, 0, 0, 1),
        v6(0xfe80, 0, 0, 0, 0, 0, 0, 1),
        v6(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
        v6(0x2001, 0x0000, 0, 0, 0, 0, 0, 1),
        v6(0x2001, 0x0020, 0, 0, 0, 0, 0, 1),
        v6(0x2001, 0x002f, 0, 0, 0, 0, 0, 1),
        v6(0x0100, 0, 0, 0, 0, 0, 0, 1),
        v6(0xff00, 0, 0, 0, 0, 0, 0, 1),
        // ::ffff:10.0.0.1 — IPv4-mapped private v4
        IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001)),
        // 2002::/16 6to4 wrapping a private v4 (10.0.0.1)
        v6(0x2002, 0x0a00, 0x0001, 0, 0, 0, 0, 1),
        // IPv6 — public
        v6(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
        v6(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
        // 2002::/16 6to4 wrapping a public v4 (8.8.8.8)
        v6(0x2002, 0x0808, 0x0808, 0, 0, 0, 0, 1),
    ]
}

#[test]
fn wafrift_types_and_scanclient_agree_on_battery() {
    let mut mismatches: Vec<(IpAddr, bool, bool)> = Vec::new();
    for ip in battery() {
        let lhs = wafrift_types::ip_addr_is_bogon(ip);
        let rhs = scanclient::bogon::ip_addr_is_bogon(ip);
        if lhs != rhs {
            mismatches.push((ip, lhs, rhs));
        }
    }
    assert!(
        mismatches.is_empty(),
        "wafrift_types and scanclient disagreed on {} IP(s): {mismatches:#?}",
        mismatches.len()
    );
}

#[test]
fn battery_covers_both_verdicts() {
    // Sanity — the parity test would pass trivially if every IP
    // returned the same verdict, so confirm the battery actually
    // exercises both branches.
    let mut bogon = 0usize;
    let mut not_bogon = 0usize;
    for ip in battery() {
        if wafrift_types::ip_addr_is_bogon(ip) {
            bogon += 1;
        } else {
            not_bogon += 1;
        }
    }
    assert!(bogon > 0, "battery has no bogon cases");
    assert!(not_bogon > 0, "battery has no non-bogon cases");
}

#[test]
fn ipv6_loopback_is_bogon_in_both_impls() {
    // Singled out — this is the regression the wafrift donor
    // carried before 2026-05-23. Keep it as its own test so the
    // failure message is unambiguous if it ever re-breaks.
    let lo = IpAddr::V6(Ipv6Addr::LOCALHOST);
    assert!(
        wafrift_types::ip_addr_is_bogon(lo),
        "wafrift_types let ::1 past the SSRF guard"
    );
    assert!(
        scanclient::bogon::ip_addr_is_bogon(lo),
        "scanclient let ::1 past the SSRF guard"
    );
}
