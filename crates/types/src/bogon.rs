//! Canonical bogon / non-public IP classification for the workspace.
//!
//! Single source of truth for SSRF policy in proxy, transport, and stealth
//! paths. Every consumer must use [`ip_addr_is_bogon`] instead of a local copy.

use std::net::IpAddr;

/// True if this IP should be blocked when private/upstream lab access is disallowed.
#[must_use]
pub fn ip_addr_is_bogon(ip: IpAddr) -> bool {
    // Delegates to the canonical `bogon` crate (libs/scanner/bogon) — the
    // single source of truth for SSRF bogon classification shared with
    // gossan and keyhog. wafrift previously carried a copy of this logic
    // that had drifted: it lacked the NAT64 well-known-prefix coverage
    // (64:ff9b::/96 + 64:ff9b:1::/48) that lets a DNS64 resolver returning
    // `64:ff9b::169.254.169.254` reach cloud IMDS past a naive guard.
    // Delegating means that fix — and every future bogon fix — lands here
    // automatically. The tests below stay as the wafrift-side contract
    // pinning the behaviour we rely on (including the inherited NAT64 case).
    ::bogon::ip_addr_is_bogon(ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn rejects_loopback_and_rfc1918() {
        assert!(ip_addr_is_bogon(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(ip_addr_is_bogon(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn rejects_6to4_embedding_private() {
        // 2002:0a00:0001:: encodes 10.0.0.1
        let v6 = Ipv6Addr::new(0x2002, 0x0a00, 0x0001, 0, 0, 0, 0, 1);
        assert!(ip_addr_is_bogon(IpAddr::V6(v6)));
    }

    #[test]
    fn allows_public_ipv4() {
        assert!(!ip_addr_is_bogon(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    // ── Regression: ::1 must be bogon (pre-fix ordering bug) ────────────────
    //
    // Root cause: the old code checked to_ipv4() BEFORE v.is_loopback().
    // ::1 has to_ipv4() == Some(0.0.0.1), which is NOT a bogon in the IPv4
    // branch, so ip_addr_is_bogon(::1) returned false — a silent SSRF
    // bypass for any target whose DNS returned an IPv6 loopback.
    #[test]
    fn ipv6_loopback_is_bogon() {
        assert!(
            ip_addr_is_bogon(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            "::1 must be a bogon — regression for compat-before-loopback bug"
        );
    }

    #[test]
    fn ipv6_unspecified_is_bogon() {
        assert!(ip_addr_is_bogon(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    }

    #[test]
    fn ipv6_unique_local_fc00_is_bogon() {
        // fc00::/7 — unique local (ULA), like RFC1918 for IPv6.
        let ula: Ipv6Addr = "fc00::1".parse().unwrap();
        assert!(ip_addr_is_bogon(IpAddr::V6(ula)));
    }

    #[test]
    fn ipv6_link_local_fe80_is_bogon() {
        let ll: Ipv6Addr = "fe80::1".parse().unwrap();
        assert!(ip_addr_is_bogon(IpAddr::V6(ll)));
    }

    #[test]
    fn ipv6_multicast_is_bogon() {
        // ff02::1 — all-nodes multicast.
        let mc: Ipv6Addr = "ff02::1".parse().unwrap();
        assert!(ip_addr_is_bogon(IpAddr::V6(mc)));
    }

    #[test]
    fn ipv6_public_global_unicast_ok() {
        // 2001:4860:4860::8888 — Google Public DNS.
        let pub_v6: Ipv6Addr = "2001:4860:4860::8888".parse().unwrap();
        assert!(!ip_addr_is_bogon(IpAddr::V6(pub_v6)));
    }

    #[test]
    fn ipv4_compat_with_public_v4_not_bogon() {
        // ::8.8.8.8 (IPv4-compatible, deprecated) must NOT be flagged —
        // the embedded address is public, so neither branch blocks it.
        // Note: this form is deprecated (RFC 4291 §2.5.5.1) but must
        // not accidentally block legitimate traffic.
        let compat: Ipv6Addr = "::8.8.8.8".parse().unwrap();
        assert!(!ip_addr_is_bogon(IpAddr::V6(compat)));
    }

    #[test]
    fn nat64_wellknown_prefix_embedding_imds_is_bogon() {
        // 64:ff9b::169.254.169.254 — a DNS64 resolver embeds the cloud IMDS
        // IPv4 in the NAT64 well-known prefix. `to_ipv4()` does NOT decode
        // this prefix, so wafrift's old fork let it past the guard; the
        // canonical `bogon` crate (which this fn now delegates to) catches
        // it. This pins that we inherited the NAT64 fix via consolidation.
        let nat64: Ipv6Addr = "64:ff9b::a9fe:a9fe".parse().unwrap();
        assert!(ip_addr_is_bogon(IpAddr::V6(nat64)));
        // RFC 8215 local-use /48 is wholly operator-controlled → always bogon.
        let local_use: Ipv6Addr = "64:ff9b:1::1".parse().unwrap();
        assert!(ip_addr_is_bogon(IpAddr::V6(local_use)));
        // A NAT64-embedded PUBLIC v4 (8.8.8.8) must stay allowed.
        let nat64_public: Ipv6Addr = "64:ff9b::808:808".parse().unwrap();
        assert!(!ip_addr_is_bogon(IpAddr::V6(nat64_public)));
    }
}
