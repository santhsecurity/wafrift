//! Cloudflare (`CF-Ray`) and Akamai (`AkamaiGHost`) headers sometimes appear
//! together. Detection order must be deterministic when scores tie.

mod common;

use std::path::PathBuf;

use common::parse_response_spec;
use wafrift_detect::detect;

#[test]
fn cf_ray_plus_akamai_server_is_ordered_deterministically() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/cf-akamai-overlap.txt");
    let raw = std::fs::read_to_string(&path).expect("read overlap fixture");
    let (st, h, b) = parse_response_spec(&raw);

    let hits = detect(st, &h, &b);
    assert!(
        hits.len() >= 2,
        "Fix: overlap fixture must hit both CDNs; got {hits:?}"
    );

    assert_eq!(hits[0].name, "Cloudflare");
    assert_eq!(hits[0].confidence, hits[1].confidence);
    assert_eq!(hits[1].name, "Kona SiteDefender");
}
