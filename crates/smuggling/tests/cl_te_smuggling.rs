//! CL.TE conflict: encoder proves **RFC back-end** (`Transfer-Encoding` wins) sees a second request
//! while **CL-only** framing stops after `Content-Length` octets (desynchronised interpretation).

mod common;

use common::{BodyFraming, WireParseError, parse_http_requests, parse_http_requests_no_tail};
use wafrift_smuggling::smuggling::{cl_te, cl_te_precedence_test};

const HOST: &str = "127.0.0.1";

fn smuggled_inner() -> &'static str {
    "GET /smuggled-clte HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
}

#[test]
fn cl_te_rfc7230_upstream_two_requests() {
    let p = cl_te(HOST, smuggled_inner()).expect("cl_te");
    let reqs = parse_http_requests_no_tail(&p.raw_bytes, BodyFraming::Rfc7230).expect("parse");
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[1].method, "GET");
    assert_eq!(reqs[1].path, "/smuggled-clte");
}

#[test]
fn cl_te_content_length_only_front_single_logical_body() {
    let p = cl_te(HOST, smuggled_inner()).expect("cl_te");
    let err = parse_http_requests(&p.raw_bytes, BodyFraming::ContentLengthOnly).expect_err("parse");
    assert!(
        matches!(err, WireParseError::Httparse(_)),
        "Fix: CL-only framing consumes zero octets; leftover chunked bytes must not parse as a second HTTP message — got {err}"
    );
}

#[test]
fn cl_te_negative_matching_lengths_one_message() {
    let probes = cl_te_precedence_test(HOST).expect("precedence");
    let benign = &probes[0].raw_bytes;
    let reqs = parse_http_requests_no_tail(benign, BodyFraming::Rfc7230).expect("parse");
    assert_eq!(reqs.len(), 1);
}

#[test]
fn cl_te_parse_is_deterministic_under_concurrent_reads() {
    let p = cl_te(HOST, smuggled_inner()).expect("cl_te");
    let bytes = std::sync::Arc::new(p.raw_bytes.clone());
    let handles: Vec<_> = (0..32)
        .map(|_| {
            let b = std::sync::Arc::clone(&bytes);
            std::thread::spawn(move || {
                for _ in 0..50 {
                    let n = parse_http_requests_no_tail(&b, BodyFraming::Rfc7230)
                        .expect("parse")
                        .len();
                    assert_eq!(n, 2);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("thread");
    }
}
