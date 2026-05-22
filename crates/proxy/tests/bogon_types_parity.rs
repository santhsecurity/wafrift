//! Parity between `wafrift_types::ip_addr_is_bogon` and proxy upstream
//! policy expectations — focused on IPv6 6to4 (2002::/16) embeds.

use std::net::IpAddr;
use wafrift_types::ip_addr_is_bogon;

#[test]
fn six_to_four_embedded_loopback_is_bogon() {
    assert!(ip_addr_is_bogon("2002:7f00:1::".parse::<IpAddr>().unwrap()));
}

#[test]
fn six_to_four_embedded_rfc1918_is_bogon() {
    assert!(ip_addr_is_bogon("2002:c0a8:101::".parse::<IpAddr>().unwrap()));
}

#[test]
fn six_to_four_embedded_link_local_is_bogon() {
    assert!(ip_addr_is_bogon("2002:a9fe:a9fe::".parse::<IpAddr>().unwrap()));
}

#[test]
fn six_to_four_public_embed_is_not_bogon() {
    assert!(!ip_addr_is_bogon("2002:808:808::".parse::<IpAddr>().unwrap()));
}

#[test]
fn six_to_four_boundary_non_6to4_prefix_is_not_bogon() {
    assert!(!ip_addr_is_bogon("2001:4860:4860::8888".parse::<IpAddr>().unwrap()));
}
