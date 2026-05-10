//! TE.TE — duplicate `Transfer-Encoding` headers with one obfuscated line from the mutation matrix.

mod common;

use common::{BodyFraming, parse_http_requests_no_tail, tcp_capture_one_payload};
use wafrift_smuggling::smuggling::{te_obfuscations, te_te};

const HOST: &str = "127.0.0.1";

fn inner() -> &'static str {
    "POST /hidden HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n"
}

#[test]
fn duplicate_te_obfuscation_index_produces_two_te_lines_in_matrix() {
    let obs = te_obfuscations();
    let idx = obs
        .iter()
        .position(|s| s.contains("\r\nTransfer-Encoding:"))
        .expect("Fix: matrix must contain duplicate Transfer-Encoding lines for TE.TE proofs.");
    assert!(
        obs[idx]
            .lines()
            .filter(|l| l.to_ascii_lowercase().starts_with("transfer-encoding:"))
            .count()
            >= 2,
        "Fix: selected obfuscation must expose duplicate TE headers."
    );
}

#[test]
fn te_te_obfuscated_pair_two_requests_on_wire() {
    let obs = te_obfuscations();
    let idx = obs
        .iter()
        .position(|s| s.contains("\r\nTransfer-Encoding:"))
        .expect("duplicate TE entry");
    let p = te_te(HOST, inner(), idx).expect("te_te");
    let wire = String::from_utf8_lossy(&p.raw_bytes);
    assert!(
        wire.match_indices("Transfer-Encoding").count() >= 2,
        "Fix: encoder must emit multiple Transfer-Encoding fields for TE.TE variant."
    );
    let reqs = parse_http_requests_no_tail(&p.raw_bytes, BodyFraming::Rfc7230).expect("parse");
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[1].method, "POST");
    assert_eq!(reqs[1].path, "/hidden");
}

#[test]
fn te_te_negative_empty_smuggle_tail_one_request() {
    let benign = format!(
        "POST / HTTP/1.1\r\nHost: {HOST}\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n0\r\n\r\n"
    );
    let reqs = parse_http_requests_no_tail(benign.as_bytes(), BodyFraming::Rfc7230).expect("parse");
    assert_eq!(reqs.len(), 1);
}

#[test]
fn tcp_dup_te_payload_round_trips_to_two_parsed_requests() {
    let obs = te_obfuscations();
    let idx = obs
        .iter()
        .position(|s| s.contains("\r\nTransfer-Encoding:"))
        .unwrap();
    let p = te_te(HOST, inner(), idx).expect("te_te");
    let cap = tcp_capture_one_payload(&p.raw_bytes).expect("tcp");
    assert_eq!(cap, p.raw_bytes);
    let n = parse_http_requests_no_tail(&cap, BodyFraming::Rfc7230)
        .expect("parse")
        .len();
    assert_eq!(n, 2);
}
