//! Property tests: [`wafrift_smuggling::smuggling::te_cl`] encoding round-trips through chunked decoding.

mod common;

use common::{parse_http_requests_no_tail, BodyFraming};
use proptest::prelude::*;
use wafrift_smuggling::smuggling::te_cl;

const HOST: &str = "probe.example";

fn ensure_crlf_local(s: &str) -> String {
    if s.ends_with("\r\n") {
        s.into()
    } else {
        format!("{s}\r\n")
    }
}

/// Decode the HTTP message body using the same RFC 7230 framing as other integration tests.
fn decode_te_cl_roundtrip(raw: &[u8]) -> Result<Vec<u8>, String> {
    let reqs = parse_http_requests_no_tail(raw, BodyFraming::Rfc7230).map_err(|e| e.to_string())?;
    if reqs.len() != 1 {
        return Err(format!(
            "Fix: te_cl wire must be exactly one request — got {} messages",
            reqs.len()
        ));
    }
    Ok(reqs[0].body.clone())
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 10_000,
        failure_persistence: None,
        .. ProptestConfig::default()
    })]

    #[test]
    fn prop_te_cl_no_panic_roundtrip_bounded(host in "[a-z]{5,16}\\.invalid", raw_inner in prop::collection::vec(32u8..127u8, 1..512)) {
        let prefix = String::from_utf8(raw_inner).expect("ascii");
        prop_assume!(!prefix.contains('\r'));
        prop_assume!(!prefix.contains('\n'));

        let payload = te_cl(&host, &prefix).expect("encode");

        let decoded = decode_te_cl_roundtrip(&payload.raw_bytes).expect("decode");
        let inner_len = decoded.len();

        let expected = ensure_crlf_local(&prefix).into_bytes();
        prop_assert_eq!(decoded, expected, "Fix: chunked decode must restore CRLF-normalised prefix.");

        let max_overhead = host.len() + 128;
        prop_assert!(
            payload.raw_bytes.len() <= inner_len + max_overhead,
            "Fix: encoded wire length grows linearly — got {} for inner len {}",
            payload.raw_bytes.len(),
            inner_len
        );
    }
}

#[test]
fn te_cl_single_space_prefix_roundtrips() {
    let p = te_cl("aaaaa.invalid", " ").expect("encode");
    let got = decode_te_cl_roundtrip(&p.raw_bytes).expect("decode");
    assert_eq!(got, b" \r\n");
}

#[test]
fn te_cl_manual_negative_identity_mapping_single_chunk_message() {
    let benign = format!(
        "POST / HTTP/1.1\r\nHost: {HOST}\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"
    );
    let decoded = decode_te_cl_roundtrip(benign.as_bytes()).expect("decode");
    assert_eq!(decoded, b"abc");
}
