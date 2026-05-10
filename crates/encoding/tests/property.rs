//! Property tests for wafrift-encoding.
//!
//! These tests verify round-trip correctness, char-boundary safety,
//! and size-bound enforcement under adversarial conditions.

use wafrift_encoding::{
    EncodeError, Strategy, encode,
    encoding::layered::{MAX_LAYERED_OUTPUT_SIZE, encode_layered},
    encoding::strategy::MAX_PAYLOAD_SIZE,
};

// ---------------------------------------------------------------------------
// Round-trip correctness per encoding (where decoders exist)
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_url_encode() {
    let original = "hello world!@#$%";
    let encoded = encode(original, Strategy::UrlEncode).unwrap();
    // URL decode manually for verification
    let decoded = url_decode(&encoded);
    assert_eq!(decoded, original.as_bytes());
}

#[test]
fn roundtrip_double_url_encode() {
    let original = "hello world!@#$%";
    let encoded = encode(original, Strategy::DoubleUrlEncode).unwrap();
    let once = url_decode(&encoded);
    let twice = url_decode(std::str::from_utf8(&once).unwrap());
    assert_eq!(twice, original.as_bytes());
}

#[test]
fn roundtrip_base64() {
    use base64::{Engine as _, engine::general_purpose};
    let original = b"binary\x00\xff\xfe";
    let encoded = encode(original.as_slice(), Strategy::Base64Encode).unwrap();
    let decoded = general_purpose::STANDARD.decode(&encoded).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn roundtrip_base64_url() {
    use base64::{Engine as _, engine::general_purpose};
    let original = b"binary+++/";
    let encoded = encode(original.as_slice(), Strategy::Base64UrlEncode).unwrap();
    let decoded = general_purpose::URL_SAFE_NO_PAD.decode(&encoded).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn roundtrip_hex() {
    let original = b"binary\x00\xff\xfe";
    let encoded = encode(original.as_slice(), Strategy::HexEncode).unwrap();
    let decoded = hex::decode(&encoded).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn roundtrip_gzip() {
    use base64::{Engine as _, engine::general_purpose};
    let original = b"SELECT * FROM users";
    let encoded = encode(original.as_slice(), Strategy::GzipEncode).unwrap();
    let decoded = general_purpose::STANDARD.decode(&encoded).unwrap();
    let mut decoder = flate2::read::GzDecoder::new(&decoded[..]);
    let mut out = Vec::new();
    std::io::Read::read_to_end(&mut decoder, &mut out).unwrap();
    assert_eq!(out, original);
}

#[test]
fn roundtrip_deflate() {
    use base64::{Engine as _, engine::general_purpose};
    let original = b"SELECT * FROM users";
    let encoded = encode(original.as_slice(), Strategy::DeflateEncode).unwrap();
    let decoded = general_purpose::STANDARD.decode(&encoded).unwrap();
    let mut decoder = flate2::read::DeflateDecoder::new(&decoded[..]);
    let mut out = Vec::new();
    std::io::Read::read_to_end(&mut decoder, &mut out).unwrap();
    assert_eq!(out, original);
}

#[test]
fn roundtrip_json_encode() {
    let original = "hello\nworld\"test";
    let encoded = encode(original, Strategy::JsonEncode).unwrap();
    // JSON string should be parseable
    let parsed: String = serde_json::from_str(&encoded).unwrap();
    assert_eq!(parsed, original);
}

// ---------------------------------------------------------------------------
// Char-boundary safety on multi-byte UTF-8 inputs
// ---------------------------------------------------------------------------

#[test]
fn char_boundary_safety_unicode_encode() {
    let payloads = ["日本語", "🎉🚀", "αβγδ", "مختبر"];
    for payload in payloads {
        let result = encode(payload, Strategy::UnicodeEncode).unwrap();
        assert!(!result.is_empty());
    }
}

#[test]
fn char_boundary_safety_keyword_strategies() {
    let payloads = ["日本語SELECT*FROM", "🎉UNION🚀"];
    for payload in payloads {
        let _ = encode(payload, Strategy::WhitespaceInsertion).unwrap();
        let _ = encode(payload, Strategy::SqlCommentInsertion).unwrap();
        let _ = encode(payload, Strategy::CaseAlternation).unwrap();
        let _ = encode(payload, Strategy::RandomCase).unwrap();
    }
}

// ---------------------------------------------------------------------------
// Size-bound enforcement under OOM-inducing inputs
// ---------------------------------------------------------------------------

#[test]
fn size_bound_single_strategy() {
    let big = vec![b'A'; MAX_PAYLOAD_SIZE + 1];
    let result = encode(&big, Strategy::UrlEncode);
    assert!(matches!(result, Err(EncodeError::PayloadTooLarge { .. })));
}

#[test]
fn size_bound_layered_encoding() {
    // A payload that when URL-encoded once is within bounds, but twice exceeds
    let size = MAX_LAYERED_OUTPUT_SIZE / 2 + 1;
    let payload = vec![b'/'; size];
    let result = encode_layered(&payload, &[Strategy::UrlEncode, Strategy::UrlEncode]);
    assert!(matches!(
        result,
        Err(EncodeError::LayeredOutputTooLarge { .. })
    ));
}

#[test]
fn size_bound_all_strategies_reject_oversized() {
    let big = vec![b'X'; MAX_PAYLOAD_SIZE + 1];
    for &strategy in wafrift_encoding::all_strategies() {
        let result = encode(&big, strategy);
        assert!(
            matches!(result, Err(EncodeError::PayloadTooLarge { .. })),
            "strategy {strategy:?} should reject oversized input"
        );
    }
}

#[test]
fn output_size_bounded_for_small_inputs() {
    let payload = "A".repeat(1000);
    for &strategy in wafrift_encoding::all_strategies() {
        let result = encode(&payload, strategy);
        if let Ok(encoded) = result {
            assert!(
                encoded.len() <= payload.len() * 20,
                "strategy {strategy:?} produced unexpectedly large output: {} bytes",
                encoded.len()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn url_decode(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(hex) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap(), 16)
        {
            out.push(hex);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}
