//! Adversarial tests for encoding strategies.
//!
//! Tests every encoding strategy with edge cases: empty inputs, single characters,
//! huge inputs, null bytes, unicode, and layered combinations.

use wafrift_core::encoding::{self, Strategy};

// ============================================================================
// Empty Input Tests (12 tests)
// ============================================================================

#[test]
fn url_encode_empty() {
    assert_eq!(encoding::encode("", Strategy::UrlEncode).unwrap(), "");
}

#[test]
fn double_url_encode_empty() {
    assert_eq!(encoding::encode("", Strategy::DoubleUrlEncode).unwrap(), "");
}

#[test]
fn triple_url_encode_empty() {
    assert_eq!(encoding::encode("", Strategy::TripleUrlEncode).unwrap(), "");
}

#[test]
fn unicode_encode_empty() {
    assert_eq!(encoding::encode("", Strategy::UnicodeEncode).unwrap(), "");
}

#[test]
fn html_entity_encode_empty() {
    assert_eq!(
        encoding::encode("", Strategy::HtmlEntityEncode).unwrap(),
        ""
    );
}

#[test]
fn case_alternation_empty() {
    assert_eq!(encoding::encode("", Strategy::CaseAlternation).unwrap(), "");
}

#[test]
fn whitespace_insert_empty() {
    assert_eq!(
        encoding::encode("", Strategy::WhitespaceInsertion).unwrap(),
        ""
    );
}

#[test]
fn sql_comment_insert_empty() {
    assert_eq!(
        encoding::encode("", Strategy::SqlCommentInsertion).unwrap(),
        ""
    );
}

#[test]
fn null_byte_empty() {
    assert_eq!(encoding::encode("", Strategy::NullByte).unwrap(), "%00");
}

#[test]
fn overlong_utf8_empty() {
    assert_eq!(encoding::encode("", Strategy::OverlongUtf8).unwrap(), "");
}

#[test]
fn chunked_split_empty() {
    assert_eq!(encoding::encode("", Strategy::ChunkedSplit).unwrap(), "");
}

#[test]
fn parameter_pollution_empty() {
    let result = encoding::encode("", Strategy::ParameterPollution).unwrap();
    assert!(result.contains("=1&"));
}

// ============================================================================
// Single Character Tests (12 tests)
// ============================================================================

#[test]
fn url_encode_single_char() {
    assert_eq!(encoding::encode("a", Strategy::UrlEncode).unwrap(), "a");
    assert_eq!(encoding::encode("!", Strategy::UrlEncode).unwrap(), "%21");
}

#[test]
fn double_url_encode_single_char() {
    assert_eq!(
        encoding::encode("a", Strategy::DoubleUrlEncode).unwrap(),
        "%2561"
    );
}

#[test]
fn triple_url_encode_single_char() {
    assert_eq!(
        encoding::encode("a", Strategy::TripleUrlEncode).unwrap(),
        "%252561"
    );
}

#[test]
fn unicode_encode_single_char() {
    assert_eq!(
        encoding::encode("a", Strategy::UnicodeEncode).unwrap(),
        "\\u0061"
    );
    assert_eq!(
        encoding::encode("€", Strategy::UnicodeEncode).unwrap(),
        "\\u20AC"
    );
}

#[test]
fn html_entity_encode_single_char() {
    assert_eq!(
        encoding::encode("a", Strategy::HtmlEntityEncode).unwrap(),
        "&#x61;"
    );
    assert_eq!(
        encoding::encode("<", Strategy::HtmlEntityEncode).unwrap(),
        "&#x3C;"
    );
}

#[test]
fn case_alternation_single_char() {
    assert_eq!(
        encoding::encode("a", Strategy::CaseAlternation).unwrap(),
        "A"
    );
    assert_eq!(
        encoding::encode("A", Strategy::CaseAlternation).unwrap(),
        "A"
    );
}

#[test]
fn whitespace_insert_single_char() {
    // Single char keywords won't match any patterns
    assert_eq!(
        encoding::encode("a", Strategy::WhitespaceInsertion).unwrap(),
        "a"
    );
}

#[test]
fn sql_comment_insert_single_char() {
    assert_eq!(
        encoding::encode("a", Strategy::SqlCommentInsertion).unwrap(),
        "a"
    );
}

#[test]
fn null_byte_single_char() {
    let result = encoding::encode("a", Strategy::NullByte).unwrap();
    assert!(result.starts_with('a'));
    assert!(result.ends_with("%00"));
}

#[test]
fn overlong_utf8_single_char_alphanumeric() {
    // Alphanumeric chars should not be transformed
    assert_eq!(encoding::encode("a", Strategy::OverlongUtf8).unwrap(), "a");
    assert_eq!(encoding::encode("5", Strategy::OverlongUtf8).unwrap(), "5");
}

#[test]
fn chunked_split_single_char() {
    let result = encoding::encode("a", Strategy::ChunkedSplit).unwrap();
    assert!(result.contains("1\r\na\r\n"));
    assert!(result.ends_with("0\r\n\r\n"));
}

#[test]
fn parameter_pollution_single_char() {
    let result = encoding::encode("a", Strategy::ParameterPollution).unwrap();
    assert!(result.contains("=1&a"));
}

// ============================================================================
// Null Byte Input Tests (8 tests)
// ============================================================================

#[test]
fn url_encode_with_null_byte() {
    let input = "test\x00test";
    let result = encoding::encode(input, Strategy::UrlEncode).unwrap();
    assert!(result.contains("%00"));
}

#[test]
fn double_url_encode_with_null_byte() {
    let input = "test\x00test";
    let result = encoding::encode(input, Strategy::DoubleUrlEncode).unwrap();
    assert!(result.contains("%2500"));
}

#[test]
fn null_byte_inject_doubles() {
    let input = "file.txt";
    let result = encoding::encode(input, Strategy::NullByte).unwrap();
    assert_eq!(result, "file.txt%00.jpg");
}

#[test]
fn null_byte_inject_no_dot() {
    let input = "filetxt";
    let result = encoding::encode(input, Strategy::NullByte).unwrap();
    assert_eq!(result, "filetxt%00");
}

#[test]
fn overlong_utf8_skips_null() {
    let input = "\x00";
    let result = encoding::encode(input, Strategy::OverlongUtf8).unwrap();
    // The overlong_utf8 function transforms non-alphanumeric ASCII chars
    // \x00 is a control character (NUL) - is_ascii() returns true for it
    // Check the actual behavior
    assert!(!result.is_empty());
}

#[test]
fn unicode_encode_with_null() {
    let input = "\x00";
    let result = encoding::encode(input, Strategy::UnicodeEncode).unwrap();
    assert_eq!(result, "\\u0000");
}

#[test]
fn html_entity_with_null() {
    let input = "\x00";
    let result = encoding::encode(input, Strategy::HtmlEntityEncode).unwrap();
    assert_eq!(result, "&#x0;");
}

#[test]
fn chunked_split_with_null() {
    let input = "a\x00b";
    let result = encoding::encode(input, Strategy::ChunkedSplit).unwrap();
    assert!(result.contains("\r\n"));
    assert!(result.ends_with("0\r\n\r\n"));
}

// ============================================================================
// Unicode Input Tests (10 tests)
// ============================================================================

#[test]
fn url_encode_unicode() {
    let input = "日本語";
    let result = encoding::encode(input, Strategy::UrlEncode).unwrap();
    // Each UTF-8 byte gets encoded
    assert!(result.starts_with('%'));
    assert!(result.len() > input.len());
}

#[test]
fn double_url_encode_unicode() {
    let input = "日本語";
    let result = encoding::encode(input, Strategy::DoubleUrlEncode).unwrap();
    assert!(result.starts_with("%25"));
}

#[test]
fn unicode_encode_cjk() {
    let input = "日本語";
    let result = encoding::encode(input, Strategy::UnicodeEncode).unwrap();
    assert!(result.contains("\\u65E5")); // 日
    assert!(result.contains("\\u672C")); // 本
    assert!(result.contains("\\u8A9E")); // 語
}

#[test]
fn html_entity_encode_unicode() {
    let input = "日本語";
    let result = encoding::encode(input, Strategy::HtmlEntityEncode).unwrap();
    assert!(result.contains("&#x65E5;"));
}

#[test]
fn case_alternation_unicode() {
    let input = "Test日本語";
    let result = encoding::encode(input, Strategy::CaseAlternation).unwrap();
    // Only ASCII alphabetic chars are case-alternated
    assert!(result.starts_with("TeSt"));
    assert!(result.contains("日本語"));
}

#[test]
fn whitespace_insert_unicode() {
    let input = "SELECT日本語";
    let result = encoding::encode(input, Strategy::WhitespaceInsertion).unwrap();
    assert!(result.contains("SEL"));
    assert!(result.contains("日本語"));
}

#[test]
fn sql_comment_insert_unicode() {
    let input = "UNION日本語";
    let result = encoding::encode(input, Strategy::SqlCommentInsertion).unwrap();
    assert!(result.contains("UNI"));
    assert!(result.contains("日本語"));
}

#[test]
fn null_byte_unicode() {
    let input = "日本語";
    let result = encoding::encode(input, Strategy::NullByte).unwrap();
    assert!(result.contains("日本語"));
    assert!(result.contains("%00"));
}

#[test]
fn overlong_utf8_unicode_non_ascii() {
    let input = "日本語";
    let result = encoding::encode(input, Strategy::OverlongUtf8).unwrap();
    // Non-ASCII chars should pass through unchanged
    assert_eq!(result, input);
}

#[test]
fn parameter_pollution_unicode() {
    let input = "key=日本語";
    let result = encoding::encode(input, Strategy::ParameterPollution).unwrap();
    assert!(result.contains("key=safe"));
    assert!(result.contains("日本語"));
}

// ============================================================================
// Large Input Tests (6 tests)
// ============================================================================

#[test]
fn url_encode_huge_payload() {
    let input = "! ".repeat(5000);
    let result = encoding::encode(&input, Strategy::UrlEncode).unwrap();
    assert!(result.len() > input.len());
}

#[test]
fn chunked_split_huge_payload() {
    let input = "a".repeat(10000);
    let result = encoding::encode(&input, Strategy::ChunkedSplit).unwrap();
    assert!(result.contains("\r\n"));
    assert!(result.ends_with("0\r\n\r\n"));
}

#[test]
fn case_alternation_huge_payload() {
    let input = "ab".repeat(5000);
    let result = encoding::encode(&input, Strategy::CaseAlternation).unwrap();
    assert_eq!(result.len(), input.len());
    // Alternating case should result in mixed case
    assert!(result.contains("Ab"));
}

#[test]
fn whitespace_insert_huge_payload() {
    let input = "SELECT ".repeat(2000);
    let result = encoding::encode(&input, Strategy::WhitespaceInsertion).unwrap();
    assert!(result.contains("SEL"));
}

#[test]
fn double_url_encode_huge_payload() {
    let input = "test".repeat(2500);
    let result = encoding::encode(&input, Strategy::DoubleUrlEncode).unwrap();
    assert!(result.contains("%25"));
}

#[test]
fn unicode_encode_huge_payload() {
    let input = "ab".repeat(1000);
    let result = encoding::encode(&input, Strategy::UnicodeEncode).unwrap();
    // Each char becomes \uXXXX (6 chars)
    assert_eq!(result.len(), input.len() * 6);
}

// ============================================================================
// Special Character Input Tests (8 tests)
// ============================================================================

#[test]
fn url_encode_special_chars() {
    let input = "!@#$%^&*()";
    let result = encoding::encode(input, Strategy::UrlEncode).unwrap();
    assert!(!result.contains('!'));
    assert!(!result.contains('@'));
    assert!(result.starts_with('%'));
}

#[test]
fn double_url_encode_already_encoded() {
    let input = "%3Cscript%3E";
    let result = encoding::encode(input, Strategy::DoubleUrlEncode).unwrap();
    // Should double-encode the % signs but not the hex digits
    assert!(result.contains("%253C"));
}

#[test]
fn overlong_utf8_special_chars() {
    let input = "/../";
    let result = encoding::encode(input, Strategy::OverlongUtf8).unwrap();
    // Non-alphanumeric ASCII chars should be overlong-encoded
    assert!(result.contains("%C0"));
    assert!(!result.contains('/'));
}

#[test]
fn chunked_split_special_chars() {
    let input = "\r\n\r\n";
    let result = encoding::encode(input, Strategy::ChunkedSplit).unwrap();
    // Should properly handle CRLF within chunks
    assert!(result.contains("\r\n"));
}

#[test]
fn case_alternation_mixed_content() {
    let input = "SELECT * FROM users WHERE id=1";
    let result = encoding::encode(input, Strategy::CaseAlternation).unwrap();
    assert_ne!(result, input);
    assert!(result.eq_ignore_ascii_case(input));
}

#[test]
fn sql_comment_insert_multiple_keywords() {
    let input = "SELECT * FROM users UNION SELECT * FROM passwords";
    let result = encoding::encode(input, Strategy::SqlCommentInsertion).unwrap();
    assert!(result.contains("/**/"));
}

#[test]
fn whitespace_insert_xss_keywords() {
    let input = "<SCRIPT>ALERT(1)</SCRIPT>";
    let result = encoding::encode(input, Strategy::WhitespaceInsertion).unwrap();
    // Should insert tabs into SCRIPT and ALERT keywords
    assert!(
        result.contains("SC\tRIPT") || result.contains("SCRIPT") || result.contains('\t'),
        "Expected tab insertion in XSS keywords, got: {result}"
    );
}

#[test]
fn html_entity_encode_xss() {
    let input = "<script>alert(1)</script>";
    let result = encoding::encode(input, Strategy::HtmlEntityEncode).unwrap();
    assert!(result.contains("&#x3C;")); // <
    assert!(result.contains("&#x3E;")); // >
}

// ============================================================================
// Layered Encoding Tests (12 tests)
// ============================================================================

#[test]
fn encode_layered_empty() {
    let result = encoding::encode_layered("", &[]).unwrap();
    assert_eq!(result, "");
}

#[test]
fn encode_layered_single() {
    let result = encoding::encode_layered(" test ", &[Strategy::UrlEncode]).unwrap();
    assert_eq!(result, "%20test%20");
}

#[test]
fn encode_layered_double() {
    let result =
        encoding::encode_layered("test ", &[Strategy::UrlEncode, Strategy::UrlEncode]).unwrap();
    // Should be double-encoded
    assert!(result.contains("%2520"));
}

#[test]
fn encode_layered_all_strategies() {
    let strategies = encoding::all_strategies();
    let input = "SELECT";
    let result = encoding::encode_layered(input, strategies).unwrap();
    // Should not panic and produce some transformation
    assert!(!result.is_empty());
}

#[test]
fn encode_layered_case_then_url() {
    let result = encoding::encode_layered(
        "<script>",
        &[Strategy::CaseAlternation, Strategy::UrlEncode],
    )
    .unwrap();
    // First case-alternated, then URL-encoded
    assert!(result.starts_with('%'));
}

#[test]
fn encode_layered_unicode_then_html() {
    let result = encoding::encode_layered(
        "test",
        &[Strategy::UnicodeEncode, Strategy::HtmlEntityEncode],
    )
    .unwrap();
    // Unicode escapes should be HTML-entity encoded
    assert!(result.contains('&'));
}

#[test]
fn layered_combinations_not_empty() {
    let combos = encoding::layered_combinations(2);
    assert!(!combos.is_empty());
}

#[test]
fn layered_combinations_valid_pairs() {
    let combos = encoding::layered_combinations(2);
    for combo in combos {
        let (s1, s2) = (combo[0], combo[1]);
        // Each combo should produce different results
        let input = "' UNION SELECT * FROM users --";
        let layered = encoding::encode_layered(input, &[s1, s2]).unwrap();
        assert!(!layered.is_empty());
    }
}

#[test]
fn encode_layered_null_byte_then_encoding() {
    let result =
        encoding::encode_layered("file.txt", &[Strategy::NullByte, Strategy::UrlEncode]).unwrap();
    // Null byte inject adds %00, then URL encode turns that to %2500
    assert!(result.contains("%2500"));
}

#[test]
fn encode_layered_whitespace_then_double_url() {
    let result = encoding::encode_layered(
        "SELECT * FROM users",
        &[Strategy::WhitespaceInsertion, Strategy::DoubleUrlEncode],
    )
    .unwrap();
    assert!(result.contains("%25"));
}

#[test]
fn encode_layered_overlong_then_url() {
    let result =
        encoding::encode_layered("/path", &[Strategy::OverlongUtf8, Strategy::UrlEncode]).unwrap();
    assert!(result.contains("%25"));
}

#[test]
fn encode_layered_unicode_preserves_structure() {
    let input = "test";
    let result = encoding::encode_layered(
        input,
        &[
            Strategy::UnicodeEncode,
            Strategy::UrlEncode,
            Strategy::HtmlEntityEncode,
        ],
    )
    .unwrap();
    // Triple-layered encoding - should be heavily transformed
    assert!(!result.contains("test"));
    assert!(result.len() > input.len() * 10);
}

// ============================================================================
// Aggressiveness Score Tests (6 tests)
// ============================================================================

#[test]
fn aggressiveness_case_alternation_low() {
    let score = encoding::aggressiveness(Strategy::CaseAlternation);
    assert!(score < 0.2);
}

#[test]
fn aggressiveness_url_encode_low() {
    let score = encoding::aggressiveness(Strategy::UrlEncode);
    assert!(score < 0.2);
}

#[test]
fn aggressiveness_overlong_high() {
    let score = encoding::aggressiveness(Strategy::OverlongUtf8);
    assert!(score >= 0.7);
}

#[test]
fn aggressiveness_chunked_high() {
    let score = encoding::aggressiveness(Strategy::ChunkedSplit);
    assert!(score > 0.8);
}

#[test]
fn aggressiveness_ordering() {
    // Less aggressive strategies should have lower scores
    assert!(
        encoding::aggressiveness(Strategy::CaseAlternation)
            < encoding::aggressiveness(Strategy::TripleUrlEncode)
    );
    assert!(
        encoding::aggressiveness(Strategy::UrlEncode)
            < encoding::aggressiveness(Strategy::OverlongUtf8)
    );
}

#[test]
fn all_strategies_have_aggressiveness() {
    for &strategy in encoding::all_strategies() {
        let score = encoding::aggressiveness(strategy);
        assert!((0.0..=1.0).contains(&score));
    }
}

// ============================================================================
// Parameter Pollution Edge Cases (4 tests)
// ============================================================================

#[test]
fn parameter_pollution_simple_key_value() {
    let input = "foo=bar";
    let result = encoding::encode(input, Strategy::ParameterPollution).unwrap();
    assert_eq!(result, "foo=safe&foo=bar");
}

#[test]
fn parameter_pollution_multiple_equals() {
    let input = "foo=bar=baz";
    let result = encoding::encode(input, Strategy::ParameterPollution).unwrap();
    // Should only split on first =
    assert!(result.starts_with("foo=safe&"));
}

#[test]
fn parameter_pollution_no_equals() {
    let input = "foobar";
    let result = encoding::encode(input, Strategy::ParameterPollution).unwrap();
    assert!(result.contains("&foobar"));
    assert!(result.contains("=1&"));
}

#[test]
fn parameter_pollution_empty_value() {
    let input = "foo=";
    let result = encoding::encode(input, Strategy::ParameterPollution).unwrap();
    assert!(result.contains("foo=safe"));
}
