//! CL=0 smuggling: conflicting declared length versus bytes on the wire.
//!
//! Positive cases show **two** HTTP messages after [`wafrift_smuggling::smuggling::te_te`] (chunked body
//! with `Content-Length: 0`) or [`wafrift_smuggling::smuggling::cl_zero`] (plain body after CL=0).
//! Negative twins are sanitised wire forms where only **one** message exists.

mod common;

use common::{BodyFraming, parse_http_requests_no_tail, tcp_capture_one_payload};
use wafrift_smuggling::smuggling::{cl_te_precedence_test, cl_zero, te_te};

const HOST: &str = "127.0.0.1";

fn second_request_prefix() -> &'static str {
    "GET /smuggled-cl0 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
}

#[test]
fn cl_zero_plain_body_two_requests_on_upstream() {
    let p = cl_zero(HOST, second_request_prefix()).expect("cl_zero");
    let reqs = parse_http_requests_no_tail(&p.raw_bytes, BodyFraming::Rfc7230).expect("parse");
    assert_eq!(
        reqs.len(),
        2,
        "Fix: CL=0 with trailing bytes must deserialize as two HTTP requests when framing honours CL for sizing."
    );
    assert_eq!(reqs[1].method, "GET");
    assert_eq!(reqs[1].path, "/smuggled-cl0");
}

#[test]
fn cl_zero_plain_body_negative_single_request() {
    let benign = format!("POST / HTTP/1.1\r\nHost: {HOST}\r\nContent-Length: 0\r\n\r\n");
    let reqs = parse_http_requests_no_tail(benign.as_bytes(), BodyFraming::Rfc7230).expect("parse");
    assert_eq!(reqs.len(), 1);
}

#[test]
fn te_te_chunked_after_cl_zero_two_requests() {
    let p = te_te(HOST, second_request_prefix(), 0).expect("te_te");
    let reqs = parse_http_requests_no_tail(&p.raw_bytes, BodyFraming::Rfc7230).expect("parse");
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[1].method, "GET");
}

#[test]
fn te_te_chunked_cl_zero_negative_agreed_framing_one_request() {
    let benign = format!(
        "POST / HTTP/1.1\r\nHost: {HOST}\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
    );
    let reqs = parse_http_requests_no_tail(benign.as_bytes(), BodyFraming::Rfc7230).expect("parse");
    assert_eq!(reqs.len(), 1);
}

#[test]
fn tcp_upstream_observes_two_requests_for_te_te_smuggle() {
    let p = te_te(HOST, second_request_prefix(), 0).expect("te_te");
    let captured = tcp_capture_one_payload(&p.raw_bytes).expect("tcp");
    assert_eq!(
        captured, p.raw_bytes,
        "Fix: mock upstream must receive full attacker payload bytes unchanged."
    );
    let reqs = parse_http_requests_no_tail(&captured, BodyFraming::Rfc7230).expect("parse");
    assert_eq!(reqs.len(), 2);
}

#[test]
fn precedence_probe_negative_stays_single_message() {
    let probes = cl_te_precedence_test(HOST).expect("probe");
    let benign = &probes[0].raw_bytes;
    let reqs = parse_http_requests_no_tail(benign, BodyFraming::Rfc7230).expect("parse");
    assert_eq!(reqs.len(), 1);
}
