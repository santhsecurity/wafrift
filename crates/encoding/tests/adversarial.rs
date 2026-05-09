//! Adversarial tests for every CRITICAL finding in wafrift-encoding.

use wafrift_encoding::{
    EncodeError, Strategy, encode, encoding::strategy::MAX_PAYLOAD_SIZE,
    encoding::structural::chunked_split,
};

// =============================================================================
// F-001: from_utf8_lossy silently corrupts invalid UTF-8
// =============================================================================

#[test]
fn f001_invalid_utf8_rejected_by_text_strategies() {
    let invalid = b"\x80\x81\x82";
    for strategy in [
        Strategy::UnicodeEncode,
        Strategy::HtmlEntityEncode,
        Strategy::CaseAlternation,
        Strategy::WhitespaceInsertion,
        Strategy::SqlCommentInsertion,
        Strategy::JsonEncode,
        Strategy::Utf7Encode,
    ] {
        assert_eq!(
            encode(invalid, strategy).unwrap_err(),
            EncodeError::InvalidUtf8,
            "F-001: {strategy:?} should reject invalid UTF-8"
        );
    }
}

#[test]
fn f001_byte_strategies_preserve_invalid_utf8() {
    let invalid = b"\x80\x81\x82";
    let url = encode(invalid, Strategy::UrlEncode).unwrap();
    assert_eq!(url, "%80%81%82");
    let double = encode(invalid, Strategy::DoubleUrlEncode).unwrap();
    assert_eq!(double, "%2580%2581%2582");
}

// =============================================================================
// F-002: UrlEncode over-encodes unreserved characters
// =============================================================================

#[test]
fn f002_url_encode_preserves_unreserved() {
    let unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~";
    let encoded = encode(unreserved, Strategy::UrlEncode).unwrap();
    assert_eq!(
        encoded, unreserved,
        "F-002: URL encoding should preserve RFC 3986 unreserved chars"
    );
}

// =============================================================================
// F-003: UnicodeEncode and HtmlEntityEncode context drift
// =============================================================================

#[test]
fn f003_context_hints_present() {
    assert_eq!(Strategy::UnicodeEncode.contexts(), &["json", "javascript"]);
    assert_eq!(Strategy::HtmlEntityEncode.contexts(), &["html"]);
}

// =============================================================================
// F-004: OverlongUtf8 produces sequences rejected by modern servers
// =============================================================================

#[test]
fn f004_overlong_utf8_context_hint() {
    assert_eq!(Strategy::OverlongUtf8.contexts(), &["iis-6"]);
}

// =============================================================================
// F-005: NullByte strategy context
// =============================================================================

#[test]
fn f005_null_byte_context_hint() {
    assert_eq!(Strategy::NullByte.contexts(), &["php", "cgi"]);
}

// =============================================================================
// F-006: ChunkedSplit generates body without guaranteeing HTTP framing
// =============================================================================

#[test]
fn f006_chunked_split_returns_structured_body_with_headers() {
    let body = chunked_split(b"abc", 1024).unwrap();
    assert_eq!(
        body.required_headers,
        vec![("Transfer-Encoding".to_string(), "chunked".to_string())]
    );
    assert!(body.body.ends_with(b"0\r\n\r\n"));
}

// =============================================================================
// F-007: Utf7Encode is RFC 2152 compliant
// =============================================================================

#[test]
fn f007_utf7_escapes_plus() {
    assert_eq!(encode("A+B", Strategy::Utf7Encode).unwrap(), "A+-B");
}

#[test]
fn f007_utf7_encodes_non_ascii() {
    let encoded = encode("日本語", Strategy::Utf7Encode).unwrap();
    assert!(encoded.starts_with('+'));
    assert!(encoded.ends_with('-'));
}

// =============================================================================
// F-008: encode_layered allows exponential memory growth
// =============================================================================

#[test]
fn f008_layered_encoding_enforces_size_cap() {
    let big = vec![b'/'; 5 * 1024 * 1024];
    let result = wafrift_encoding::encoding::layered::encode_layered(
        &big,
        &[
            Strategy::UrlEncode,
            Strategy::UrlEncode,
            Strategy::UrlEncode,
        ],
    );
    assert!(
        matches!(result, Err(EncodeError::LayeredOutputTooLarge { .. })),
        "F-008: layered encoding should enforce output size cap"
    );
}

// =============================================================================
// F-009 / F-010 / F-011: line_fold / multi_line_fold / null_byte_inject panics
// =============================================================================

#[test]
fn f009_line_fold_multibyte_utf8_no_panic() {
    let result = wafrift_encoding::header::line_fold("X-Test", "日本語のテスト");
    assert!(result.contains("\r\n\t"));
}

#[test]
fn f010_multi_line_fold_multibyte_utf8_no_panic() {
    let result = wafrift_encoding::header::multi_line_fold("X-Test", "日本語のテストデータ");
    assert!(result.contains("\r\n"));
}

#[test]
fn f011_null_byte_inject_multibyte_utf8_no_panic() {
    let result = wafrift_encoding::header::null_byte_inject("日本語");
    assert!(result.contains('\x00'));
}

// =============================================================================
// F-012: No maximum input size validation leads to OOM
// =============================================================================

#[test]
fn f012_oversized_payload_rejected() {
    let huge = vec![b'X'; MAX_PAYLOAD_SIZE + 1];
    for strategy in wafrift_encoding::all_strategies() {
        let result = encode(&huge, strategy);
        assert!(
            matches!(result, Err(EncodeError::PayloadTooLarge { .. })),
            "F-012: {strategy:?} should reject oversized payload"
        );
    }
}

// =============================================================================
// F-013: WhitespaceInsertion splits SQL keywords in half
// =============================================================================

#[test]
fn f013_whitespace_insertion_preserves_keyword_integrity() {
    let result = encode("SELECT * FROM", Strategy::WhitespaceInsertion).unwrap();
    assert!(
        result.contains("SELECT"),
        "F-013: keyword should not be split: {result}"
    );
    assert!(
        result.contains("FROM"),
        "F-013: keyword should not be split: {result}"
    );
    assert!(
        !result.contains("SEL\tECT"),
        "F-013: keyword should not be split in half"
    );
}

// =============================================================================
// F-015: No panic on invalid UTF-8 for any strategy
// =============================================================================

#[test]
fn f015_no_panic_on_invalid_utf8() {
    let invalid = b"\x80\x81\x82";
    for strategy in wafrift_encoding::all_strategies() {
        let _ = encode(invalid, strategy);
        // Reaching here without panicking is the pass condition.
    }
}

// =============================================================================
// F-014: SqlCommentInsertion splits SQL keywords in half
// =============================================================================

#[test]
fn f014_sql_comment_insertion_preserves_keyword_integrity() {
    let result = encode("SELECT * FROM", Strategy::SqlCommentInsertion).unwrap();
    assert!(
        result.contains("SELECT"),
        "F-014: keyword should not be split: {result}"
    );
    assert!(
        result.contains("FROM"),
        "F-014: keyword should not be split: {result}"
    );
    assert!(
        !result.contains("SEL/**/ECT"),
        "F-014: keyword should not be split in half"
    );
}
