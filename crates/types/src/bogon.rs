//! Canonical bogon / non-public IP classification for the workspace.
//!
//! Single source of truth for SSRF policy in proxy, transport, and stealth
//! paths. Every consumer must use [`ip_addr_is_bogon`] instead of a local copy.

use std::net::IpAddr;

/// True if this IP should be blocked when private/upstream lab access is disallowed.
#[must_use]
pub fn ip_addr_is_bogon(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            if v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_broadcast()
                || v.is_documentation()
                || v.is_unspecified()
            {
                return true;
            }
            let octets = v.octets();
            if octets[0] == 100 && (octets[1] & 0xc0) == 0x40 {
                return true; // 100.64.0.0/10 CGN
            }
            if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
                return true; // 192.0.0.0/24
            }
            if octets[0] == 198 && (octets[1] & 0xfe) == 18 {
                return true; // 198.18.0.0/15
            }
            // Link-local + metadata (IMDS) — explicit for stealth parity with proxy audits.
            if octets[0] == 169 && octets[1] == 254 {
                return true;
            }
            false
        }
        IpAddr::V6(v) => {
            // Check native IPv6 properties FIRST so that special addresses
            // like ::1 (loopback) are handled correctly before the
            // IPv4-compat extraction below.
            //
            // Bug: the old ordering put to_ipv4() BEFORE v.is_loopback().
            // ::1 has to_ipv4() == Some(0.0.0.1), which is NOT a bogon in
            // the IPv4 branch, so ip_addr_is_bogon(::1) returned false —
            // a silent SSRF bypass for IPv6 loopback. Fix: gate
            // IPv6-native checks first.
            if v.is_loopback()
                || v.is_multicast()
                || v.is_unspecified()
                || v.is_unique_local()
                || v.is_unicast_link_local()
            {
                return true;
            }
            // IPv4-mapped (::ffff:x.x.x.x): classify by the embedded v4.
            if let Some(mapped) = v.to_ipv4_mapped() {
                return ip_addr_is_bogon(IpAddr::V4(mapped));
            }
            // IPv4-compatible (::x.x.x.x, deprecated RFC 4291 §2.5.5.1):
            // classify by the embedded v4, but only after the native checks
            // so that ::1 (loopback) is already caught above.
            if let Some(compat) = v.to_ipv4() {
                return ip_addr_is_bogon(IpAddr::V4(compat));
            }
            let segs = v.segments();
            if segs[0] == 0x2002 {
                let v4 = std::net::Ipv4Addr::new(
                    (segs[1] >> 8) as u8,
                    (segs[1] & 0xff) as u8,
                    (segs[2] >> 8) as u8,
                    (segs[2] & 0xff) as u8,
                );
                if ip_addr_is_bogon(IpAddr::V4(v4)) {
                    return true;
                }
            }
            if segs[0] == 0x2001 && segs[1] == 0x0db8 {
                return true;
            }
            if segs[0] == 0x2001 && segs[1] == 0x0000 {
                return true; // Teredo
            }
            if segs[0] == 0x2001 && (segs[1] & 0xfff0) == 0x0020 {
                return true; // ORCHIDv2
            }
            if segs[0] == 0x0100 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0 {
                return true; // 100::/64 discard
            }
            false
        }
    }
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
}
