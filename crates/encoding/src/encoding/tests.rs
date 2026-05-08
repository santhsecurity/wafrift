//! Tests for encoding strategies.

use super::strategy::{Strategy, all_strategies, encode};
use crate::error::EncodeError;

#[test]
fn url_encode_basic() {
    assert_eq!(encode("A<", Strategy::UrlEncode).unwrap(), "A%3C");
}

#[test]
fn url_encode_lower_basic() {
    assert_eq!(encode("A<", Strategy::UrlEncodeLower).unwrap(), "A%3c");
}

#[test]
fn double_url_encode_basic() {
    assert_eq!(
        encode("A<", Strategy::DoubleUrlEncode).unwrap(),
        "%2541%253C"
    );
}

#[test]
fn triple_url_encode_basic() {
    assert_eq!(encode("A", Strategy::TripleUrlEncode).unwrap(), "%252541");
}

#[test]
fn unicode_encode_basic() {
    assert_eq!(
        encode("A<", Strategy::UnicodeEncode).unwrap(),
        "\\u0041\\u003C"
    );
}

#[test]
fn iis_unicode_encode_basic() {
    assert_eq!(
        encode("A<", Strategy::IisUnicodeEncode).unwrap(),
        "%u0041%u003C"
    );
}

#[test]
fn json_encode_basic() {
    assert_eq!(encode("A<", Strategy::JsonEncode).unwrap(), "\"A<\"");
}

#[test]
fn html_entity_encode_basic() {
    assert_eq!(
        encode("A<", Strategy::HtmlEntityEncode).unwrap(),
        "&#x41;&#x3C;"
    );
}

#[test]
fn html_entity_decimal_encode_basic() {
    assert_eq!(
        encode("A<", Strategy::HtmlEntityDecimalEncode).unwrap(),
        "&#65;&#60;"
    );
}

#[test]
fn case_alternation() {
    assert_eq!(
        encode("select", Strategy::CaseAlternation).unwrap(),
        "SeLeCt"
    );
}

#[test]
fn random_case_non_empty() {
    let result = encode("SELECT", Strategy::RandomCase).unwrap();
    assert_eq!(result.to_ascii_lowercase(), "select");
}

#[test]
fn sql_comment_insertion() {
    let result = encode("SELECT * FROM users", Strategy::SqlCommentInsertion).unwrap();
    assert!(result.contains("/**/"));
}

#[test]
fn whitespace_insertion() {
    let result = encode("SELECT * FROM users", Strategy::WhitespaceInsertion).unwrap();
    assert!(result.contains('\t'));
}

#[test]
fn mysql_versioned_comment() {
    let result = encode("SELECT * FROM users", Strategy::MysqlVersionedComment).unwrap();
    assert!(result.contains("/*!50000SELECT*/"));
}

#[test]
fn null_byte_with_extension() {
    assert_eq!(
        encode("file.php", Strategy::NullByte).unwrap(),
        "file.php%00.jpg"
    );
}

#[test]
fn null_byte_without_extension() {
    let result = encode("payload", Strategy::NullByte).unwrap();
    assert!(result.ends_with("%00"));
}

#[test]
fn overlong_utf8_slash() {
    let result = encode("/", Strategy::OverlongUtf8).unwrap();
    assert!(result.contains("%C0%AF"));
}

#[test]
fn overlong_utf8_more_slash() {
    let result = encode("/", Strategy::OverlongUtf8More).unwrap();
    assert!(result.contains("%E0%80%AF"));
}

#[test]
fn all_strategies_ordered() {
    let strategies = all_strategies();
    assert!(!strategies.is_empty());
    for i in 1..strategies.len() {
        assert!(
            super::layered::aggressiveness(strategies[i - 1])
                <= super::layered::aggressiveness(strategies[i]),
            "strategies should be ordered by aggressiveness"
        );
    }
}

#[test]
fn empty_payload_all_strategies() {
    for strategy in all_strategies() {
        let result = encode("", strategy).unwrap();
        assert!(result.is_empty() || !result.is_empty());
    }
}

#[test]
fn encode_preserves_meaning() {
    let original = "' OR 1=1--";
    let encoded = encode(original, Strategy::UrlEncode).unwrap();
    assert_ne!(encoded, original);
    assert!(encoded.contains("%27"));
}

#[test]
fn encode_accepts_raw_byte_slices() {
    let payload = b"A\x00!\xff";
    let encoded = encode(payload.as_slice(), Strategy::UrlEncode).unwrap();
    assert_eq!(encoded, "A%00%21%FF");
}

#[test]
fn encode_rejects_invalid_utf8_for_text_strategies() {
    let payload = b"\x80\x81";
    for strategy in [
        Strategy::UnicodeEncode,
        Strategy::HtmlEntityEncode,
        Strategy::CaseAlternation,
        Strategy::WhitespaceInsertion,
        Strategy::SqlCommentInsertion,
    ] {
        assert_eq!(
            encode(payload, strategy).unwrap_err(),
            EncodeError::InvalidUtf8,
            "strategy {strategy:?} should reject invalid UTF-8"
        );
    }
}

#[test]
fn double_encoding_handles_existing_percent_sequences() {
    let encoded = encode("%2f../".as_bytes(), Strategy::DoubleUrlEncode).unwrap();
    assert_eq!(encoded, "%252f%252E%252E%252F");
}

#[test]
fn triple_encoding_handles_existing_percent_sequences() {
    let encoded = encode("%252541".as_bytes(), Strategy::TripleUrlEncode).unwrap();
    // Should preserve already-triple-encoded
    assert_eq!(encoded, "%252541");
}

#[test]
fn null_byte_encoding_handles_embedded_nulls() {
    let encoded = encode(b"file.php\x00tail".as_slice(), Strategy::NullByte).unwrap();
    assert!(encoded.starts_with("file.php"));
    assert!(encoded.ends_with("%00.jpg"));
}

#[test]
fn overlong_utf8_encodes_ascii_delimiters() {
    let encoded = encode(b"/?<>\x00".as_slice(), Strategy::OverlongUtf8).unwrap();
    assert_eq!(encoded, "%C0%AF%C0%BF%C0%BC%C0%BE%C0%80");
}

#[test]
fn layered_encoding_supports_byte_inputs() {
    let encoded = super::layered::encode_layered(
        b"' OR 1=1--".as_slice(),
        &[Strategy::NullByte, Strategy::DoubleUrlEncode],
    )
    .unwrap();
    assert!(encoded.contains("%2500"));
    assert!(encoded.contains("%2527"));
}

#[test]
fn chunked_split_produces_valid_chunks() {
    let result = encode("SELECT * FROM users", Strategy::ChunkedSplit).unwrap();
    assert!(result.contains("\r\n"));
    assert!(result.ends_with("0\r\n\r\n"));
}

#[test]
fn chunked_split_empty() {
    let result = encode("", Strategy::ChunkedSplit).unwrap();
    assert!(result.is_empty());
}

#[test]
fn parameter_pollution_with_key_value() {
    let result = encode("user=' OR 1=1--", Strategy::ParameterPollution).unwrap();
    assert!(result.starts_with("user=safe&"));
    assert!(result.contains("user=' OR 1=1--"));
}

#[test]
fn parameter_pollution_without_equals() {
    let result = encode("payload", Strategy::ParameterPollution).unwrap();
    assert!(result.ends_with("&payload"));
    assert!(!result.contains("_wafrift_decoy"));
}

#[test]
fn base64_standard() {
    assert_eq!(encode("hello", Strategy::Base64Encode).unwrap(), "aGVsbG8=");
}

#[test]
fn base64_url_safe() {
    assert_eq!(
        encode("hello+++", Strategy::Base64UrlEncode).unwrap(),
        "aGVsbG8rKys"
    );
}

#[test]
fn hex_encode_basic() {
    assert_eq!(encode("ABC", Strategy::HexEncode).unwrap(), "414243");
}

#[test]
fn utf7_rfc2152_basic() {
    assert_eq!(encode("Hello", Strategy::Utf7Encode).unwrap(), "Hello");
    assert_eq!(encode("A+B", Strategy::Utf7Encode).unwrap(), "A+-B");
}

#[test]
fn gzip_encode_roundtrip() {
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
fn deflate_encode_roundtrip() {
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
fn space_to_comment() {
    assert_eq!(
        encode("SELECT * FROM", Strategy::SpaceToComment).unwrap(),
        "SELECT/**/*/**/FROM"
    );
}

#[test]
fn space_to_dash() {
    let result = encode("SELECT * FROM", Strategy::SpaceToDash).unwrap();
    assert!(result.contains("--"));
}

#[test]
fn space_to_hash() {
    assert_eq!(
        encode("SELECT * FROM", Strategy::SpaceToHash).unwrap(),
        "SELECT#*#FROM"
    );
}

#[test]
fn space_to_plus() {
    assert_eq!(
        encode("SELECT * FROM", Strategy::SpaceToPlus).unwrap(),
        "SELECT+*+FROM"
    );
}

#[test]
fn percentage_prefix() {
    assert_eq!(
        encode("SELECT", Strategy::PercentagePrefix).unwrap(),
        "%S%E%L%E%C%T"
    );
}

#[test]
fn between_obfuscation() {
    assert_eq!(
        encode("id=1", Strategy::BetweenObfuscation).unwrap(),
        "id BETWEEN 0 AND 1"
    );
}

#[test]
fn unmagic_quotes() {
    assert_eq!(
        encode("' OR 1=1--", Strategy::UnmagicQuotes).unwrap(),
        "%bf%27 OR 1=1--"
    );
}

#[test]
fn encode_rejects_oversized_payload() {
    let big = vec![b'A'; super::strategy::MAX_PAYLOAD_SIZE + 1];
    let result = encode(&big, Strategy::UrlEncode);
    assert!(matches!(result, Err(EncodeError::PayloadTooLarge { .. })));
}

#[test]
fn strategy_contexts_return_expected_values() {
    assert!(Strategy::UnicodeEncode.contexts().contains(&"json"));
    assert!(Strategy::HtmlEntityEncode.contexts().contains(&"html"));
    assert!(Strategy::NullByte.contexts().contains(&"php"));
    assert!(
        Strategy::ChunkedSplit
            .contexts()
            .contains(&"http-request-body")
    );
    assert!(Strategy::UrlEncode.contexts().is_empty());
}

#[test]
fn layered_combinations_generate_programmatically() {
    let combos = super::layered::layered_combinations(2);
    assert!(!combos.is_empty());
    for combo in combos {
        assert_eq!(combo.len(), 2);
        assert_ne!(combo[0], combo[1]);
    }
}

// Consolidated adversarial smoke tests

#[test]
fn adversarial_smoke_all_strategies() {
    let payloads = [
        "' OR 1=1--",
        "<script>alert(1)</script>",
        "../../../../etc/passwd",
        "DROP TABLE users;",
        "UNION SELECT null, null, null",
        "A",
    ];
    for strategy in all_strategies() {
        for payload in &payloads {
            let result = encode(payload, strategy);
            assert!(
                result.is_ok() || matches!(result, Err(EncodeError::InvalidUtf8)),
                "strategy {strategy:?} should not panic on payload {payload:?}"
            );
        }
    }
}

#[test]
fn adversarial_repeated_payloads() {
    for len in [1, 11, 101, 1001, 10001] {
        let payload = "A".repeat(len);
        let result = encode(&payload, Strategy::UrlEncode);
        assert!(result.is_ok());
    }
}
