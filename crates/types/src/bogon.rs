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
            if let Some(mapped) = v.to_ipv4_mapped() {
                return ip_addr_is_bogon(IpAddr::V4(mapped));
            }
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
            v.is_loopback()
                || v.is_multicast()
                || v.is_unspecified()
                || v.is_unique_local()
                || v.is_unicast_link_local()
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
}
