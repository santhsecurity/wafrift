//! Vendored HTTP fingerprints (see `tests/data/*.txt`) exercised against the
//! live `wafrift-detect` rule pack. Every must-detect has a twin fixture
//! that must not register a hit for the same WAF.

mod common;

use std::path::PathBuf;

use common::parse_response_spec;
use wafrift_detect::detect;

fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data")
}

fn load(name: &str) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let path = data_dir().join(name);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Fix: ensure fixture exists at {} ({e})", path.display()));
    parse_response_spec(&raw)
}

#[test]
fn corpus_cloudflare_named() {
    let (st, h, b) = load("cloudflare.txt");
    let hits = detect(st, &h, &b);
    let top = hits
        .first()
        .expect("Fix: Cloudflare corpus must detect Cloudflare");
    assert_eq!(top.name, "Cloudflare");
}

#[test]
fn corpus_akamai_kona_named() {
    let (st, h, b) = load("akamai.txt");
    let hits = detect(st, &h, &b);
    let top = hits.first().expect("Fix: Akamai (Kona) corpus must detect");
    assert_eq!(top.name, "Kona SiteDefender");
}

#[test]
fn corpus_aws_waf_named() {
    let (st, h, b) = load("aws-waf.txt");
    let hits = detect(st, &h, &b);
    let top = hits
        .first()
        .expect("Fix: AWS corpus must detect ELB/WAF rule pack entry");
    assert_eq!(top.name, "AWS Elastic Load Balancer");
}

#[test]
fn corpus_sucuri_named() {
    let (st, h, b) = load("sucuri.txt");
    let hits = detect(st, &h, &b);
    let top = hits.first().expect("Fix: Sucuri corpus must detect");
    assert_eq!(top.name, "Sucuri CloudProxy");
}

#[test]
fn corpus_imperva_incapsula_named() {
    let (st, h, b) = load("imperva.txt");
    let hits = detect(st, &h, &b);
    let top = hits
        .first()
        .expect("Fix: Imperva/Incapsula corpus must detect");
    assert_eq!(top.name, "Incapsula");
}

#[test]
fn corpus_f5_big_ip_asm_named() {
    let (st, h, b) = load("f5-big-ip.txt");
    let hits = detect(st, &h, &b);
    let top = hits.first().expect("Fix: F5 BIG-IP ASM corpus must detect");
    assert_eq!(top.name, "BIG-IP AppSec Manager");
}

#[test]
fn corpus_fortinet_named() {
    let (st, h, b) = load("fortinet.txt");
    let hits = detect(st, &h, &b);
    let top = hits.first().expect("Fix: Fortinet corpus must detect");
    assert_eq!(top.name, "FortiGate");
}

#[test]
fn corpus_barracuda_named() {
    let (st, h, b) = load("barracuda.txt");
    let hits = detect(st, &h, &b);
    let top = hits.first().expect("Fix: Barracuda corpus must detect");
    assert_eq!(top.name, "Barracuda");
}

#[test]
fn corpus_cloudfront_named() {
    let (st, h, b) = load("cloudfront.txt");
    let hits = detect(st, &h, &b);
    let top = hits.first().expect("Fix: CloudFront corpus must detect");
    assert_eq!(top.name, "Cloudfront");
}

/// Each positive fingerprint file `X.txt` has `X.twin.txt` with banners
/// scrubbed so the specific WAF must not appear as the top hit.
#[test]
fn twins_do_not_emit_matching_vendor() {
    let pairs = [
        ("cloudflare.twin.txt", "Cloudflare"),
        ("akamai.twin.txt", "Kona SiteDefender"),
        ("aws-waf.twin.txt", "AWS Elastic Load Balancer"),
        ("sucuri.twin.txt", "Sucuri CloudProxy"),
        ("imperva.twin.txt", "Incapsula"),
        ("f5-big-ip.twin.txt", "BIG-IP AppSec Manager"),
        ("fortinet.twin.txt", "FortiGate"),
        ("barracuda.twin.txt", "Barracuda"),
        ("cloudfront.twin.txt", "Cloudfront"),
    ];

    for (file, forbidden) in pairs {
        let (st, h, b) = load(file);
        let hits = detect(st, &h, &b);
        if let Some(top) = hits.first() {
            assert_ne!(
                top.name, forbidden,
                "Fix: twin {file} must not classify as {forbidden}, got indicators {:?}",
                top.indicators
            );
        }
    }
}
