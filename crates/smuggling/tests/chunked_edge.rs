//! Chunked encoding edge cases: zero-length chunks, CRLF framing, extensions, and oversized hex.

mod common;

use common::{BodyFraming, chunked_decode_consume, parse_http_requests_no_tail};
use wafrift_smuggling::parser::{ChunkedParser, ParseError};
use wafrift_smuggling::smuggling::{chunk_extension, chunk_size_mutations};

const HOST: &str = "127.0.0.1";

#[test]
fn zero_chunk_then_terminator_decodes_empty_consuming_all_delimiters() {
    let data = b"0\r\n\r\n";
    let (decoded, consumed) = chunked_decode_consume(data).expect("decode");
    assert!(decoded.is_empty());
    assert_eq!(consumed, data.len());
}

#[test]
fn zero_chunk_negative_must_not_emit_follow_on_request() {
    let benign =
        format!("POST / HTTP/1.1\r\nHost: {HOST}\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n");
    let reqs = parse_http_requests_no_tail(benign.as_bytes(), BodyFraming::Rfc7230).expect("parse");
    assert_eq!(reqs.len(), 1);
}

#[test]
fn chunk_extension_encoder_then_decode_preserves_smuggled_tail_as_second_request() {
    let p = chunk_extension(HOST, "GET /ext HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .expect("chunk_extension");
    let reqs = parse_http_requests_no_tail(&p.raw_bytes, BodyFraming::Rfc7230).expect("parse");
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[1].path, "/ext");
}

#[test]
fn chunk_extension_negative_same_encoding_without_suffix_one_request() {
    let benign = format!(
        "POST / HTTP/1.1\r\nHost: {HOST}\r\nTransfer-Encoding: chunked\r\n\r\n1;ext=foo\r\nX\r\n0\r\n\r\n"
    );
    let reqs = parse_http_requests_no_tail(benign.as_bytes(), BodyFraming::Rfc7230).expect("parse");
    assert_eq!(reqs.len(), 1);
}

#[test]
fn trailing_crlf_only_after_chunk_finishes_without_extra_requests() {
    let benign = format!(
        "POST / HTTP/1.1\r\nHost: {HOST}\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
    );
    let reqs = parse_http_requests_no_tail(benign.as_bytes(), BodyFraming::Rfc7230).expect("parse");
    assert_eq!(reqs.len(), 1);
}

#[test]
fn oversize_chunk_hex_errors_without_panic() {
    let hex = "1".repeat(4000);
    let mut buf = Vec::new();
    buf.extend_from_slice(hex.as_bytes());
    buf.extend_from_slice(b"\r\n");
    let parser = ChunkedParser::default();
    let r = parser.parse(&buf);
    assert!(
        matches!(r, Err(ParseError::InvalidChunkSize)),
        "Fix: oversized hex must reject cleanly: {:?}",
        r
    );
}

#[test]
fn chunk_size_mutations_negative_plain_chunk_one_request() {
    let benign = format!(
        "POST / HTTP/1.1\r\nHost: {HOST}\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nX\r\n0\r\n\r\n"
    );
    assert_eq!(
        parse_http_requests_no_tail(benign.as_bytes(), BodyFraming::Rfc7230)
            .expect("parse")
            .len(),
        1
    );
}

#[test]
fn chunk_size_mutations_positive_vectors_remain_two_messages_when_suffix_present() {
    let payloads = chunk_size_mutations(HOST, "GET /sz HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .expect("mutations");
    assert!(!payloads.is_empty());
    for p in &payloads {
        match parse_http_requests_no_tail(&p.raw_bytes, BodyFraming::Rfc7230) {
            Ok(reqs) => {
                assert_eq!(
                    reqs.len(),
                    2,
                    "Fix: well-formed chunk lines must leave a full trailing HTTP message — {}",
                    p.description
                );
            }
            Err(e) => {
                assert!(
                    p.description.contains("'1A'"),
                    "Fix: only the `1A` chunk-size token mismatches payload octets; unexpected for {}: {e}",
                    p.description
                );
            }
        }
    }
}
