//! Property tests: [`wafrift_smuggling::smuggling::te_cl`] encoding round-trips through chunked decoding.

mod common;

use common::chunked_decode_consume;
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

/// Extract HTTP body bytes after first `\r\n\r\n`, then decode chunked framing (RFC TE wins).
fn decode_te_cl_roundtrip(raw: &[u8]) -> Result<Vec<u8>, String> {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "Fix: missing header terminator.".to_string())?;
    let body_start = sep + 4;
    let (decoded, consumed) =
        chunked_decode_consume(&raw[body_start..]).map_err(|e| e.to_string())?;
    if body_start + consumed != raw.len() {
        return Err("Fix: trailing bytes after chunked body.".to_string());
    }
    Ok(decoded)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn prop_te_cl_no_panic_roundtrip_bounded(host in "[a-z]{5,16}\\.invalid", prefix in prop::string::string_regex("[ -~]{0,512}").unwrap()) {
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
fn te_cl_manual_negative_identity_mapping_single_chunk_message() {
    let benign = format!(
        "POST / HTTP/1.1\r\nHost: {HOST}\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"
    );
    let sep = benign
        .as_bytes()
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap()
        + 4;
    let decoded = chunked_decode_consume(&benign.as_bytes()[sep..])
        .expect("decode")
        .0;
    assert_eq!(decoded, b"abc");
}
