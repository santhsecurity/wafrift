//! Plain origin stacks must not trip WAF detectors.

mod common;

use std::path::PathBuf;

use common::parse_response_spec;
use wafrift_detect::detect;

fn read_fixture(name: &str) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Fix: read {} ({e})", path.display()));
    parse_response_spec(&raw)
}

#[test]
fn plain_nginx_triggers_no_detection() {
    let (st, h, b) = read_fixture("plain-nginx.txt");
    let hits = detect(st, &h, &b);
    assert!(
        hits.is_empty(),
        "Fix: generic nginx page must not classify as a WAF; got {hits:?}"
    );
}

#[test]
fn plain_apache_triggers_no_detection() {
    let (st, h, b) = read_fixture("plain-apache.txt");
    let hits = detect(st, &h, &b);
    assert!(
        hits.is_empty(),
        "Fix: generic Apache page must not classify as a WAF; got {hits:?}"
    );
}

#[test]
fn plain_s3_error_triggers_no_detection() {
    let (st, h, b) = read_fixture("plain-s3.txt");
    let hits = detect(st, &h, &b);
    assert!(
        hits.is_empty(),
        "Fix: bare S3 XML error must not classify as a WAF; got {hits:?}"
    );
}
