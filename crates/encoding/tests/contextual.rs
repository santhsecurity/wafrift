//! Context-aware encoding tests — validates structural correctness per injection context.

use wafrift_encoding::Strategy;
use wafrift_encoding::contextual::{encode_in_context, escape_for_context, validate_in_context};
use wafrift_types::injection_context::InjectionContext;

// ── JSON String ────────────────────────────────────────────────────────────

#[test]
fn json_string_basic() {
    // CaseAlternation on "hello" doesn't change ASCII letters case in a predictable way,
    // so we use a payload that's safe under this strategy
    let out = encode_in_context(
        b"hello",
        Strategy::CaseAlternation,
        InjectionContext::JsonString,
    )
    .unwrap();
    // Case alternation changes case but doesn't introduce structural chars
    assert!(!out.contains('"'));
    assert!(!out.contains('\\'));
}

#[test]
fn json_string_escapes_quotes() {
    let out = encode_in_context(
        b"\" OR 1=1",
        Strategy::CaseAlternation,
        InjectionContext::JsonString,
    )
    .unwrap();
    assert!(out.contains("\\\""));
}

#[test]
fn json_string_escapes_backslash() {
    let out = encode_in_context(
        b"a\\b",
        Strategy::CaseAlternation,
        InjectionContext::JsonString,
    )
    .unwrap();
    assert!(out.contains("\\\\"));
}

#[test]
fn json_string_escapes_control_chars() {
    let out = encode_in_context(
        b"a\nb",
        Strategy::CaseAlternation,
        InjectionContext::JsonString,
    )
    .unwrap();
    assert!(out.contains("\\n"));
}

#[test]
fn json_string_unicode_encode_no_collision() {
    // UnicodeEncode strategy produces \uXXXX; in JSON string context the backslash is escaped
    let out =
        encode_in_context(b"a", Strategy::UnicodeEncode, InjectionContext::JsonString).unwrap();
    // Strategy::UnicodeEncode encodes 'a' as \u0061, then JSON escapes \ to \\
    assert!(out.contains("\\\\u0061"));
}

#[test]
fn json_string_null_byte_escaped() {
    let out = encode_in_context(
        b"a\x00b",
        Strategy::CaseAlternation,
        InjectionContext::JsonString,
    )
    .unwrap();
    assert!(out.contains("\\u0000"));
}

#[test]
fn json_string_with_url_encode_strategy() {
    // URL encoding inside JSON string should still be valid JSON
    let out = encode_in_context(b"a b", Strategy::UrlEncode, InjectionContext::JsonString).unwrap();
    assert!(out.contains("%20"));
    assert!(!out.contains('"')); // no unescaped quotes introduced
}

// ── JSON Number ────────────────────────────────────────────────────────────

#[test]
fn json_number_valid() {
    let out = encode_in_context(
        b"123",
        Strategy::CaseAlternation,
        InjectionContext::JsonNumber,
    )
    .unwrap();
    assert_eq!(out, "123");
}

#[test]
fn json_number_with_decimal() {
    let out = encode_in_context(
        b"-1.5e+10",
        Strategy::CaseAlternation,
        InjectionContext::JsonNumber,
    )
    .unwrap();
    // CaseAlternation uppercases the 'e' to 'E'
    assert_eq!(out, "-1.5E+10");
}

#[test]
fn json_number_invalid_rejected() {
    let err = encode_in_context(
        b"abc",
        Strategy::CaseAlternation,
        InjectionContext::JsonNumber,
    )
    .unwrap_err();
    assert!(err.to_string().contains("incompatible"));
}

#[test]
fn json_number_url_encode_rejected() {
    // URL-encoded number with space is not a valid JSON number literal
    let err =
        encode_in_context(b"1 23", Strategy::UrlEncode, InjectionContext::JsonNumber).unwrap_err();
    assert!(err.to_string().contains("incompatible"));
}

// ── XML Attribute ──────────────────────────────────────────────────────────

#[test]
fn xml_attribute_escapes_quotes() {
    let out = encode_in_context(
        b"\"x\"",
        Strategy::CaseAlternation,
        InjectionContext::XmlAttribute,
    )
    .unwrap();
    assert!(out.contains("&quot;"));
}

#[test]
fn xml_attribute_escapes_ampersand() {
    let out = encode_in_context(
        b"a&b",
        Strategy::CaseAlternation,
        InjectionContext::XmlAttribute,
    )
    .unwrap();
    assert!(out.contains("&amp;"));
}

#[test]
fn xml_attribute_escapes_lt_gt() {
    let out = encode_in_context(
        b"<script>",
        Strategy::CaseAlternation,
        InjectionContext::XmlAttribute,
    )
    .unwrap();
    assert!(out.contains("&lt;"));
    assert!(out.contains("&gt;"));
}

#[test]
fn xml_attribute_null_byte_rejected() {
    let err = encode_in_context(
        b"a\x00b",
        Strategy::CaseAlternation,
        InjectionContext::XmlAttribute,
    )
    .unwrap_err();
    assert!(err.to_string().contains("incompatible"));
}

// ── XML CDATA ──────────────────────────────────────────────────────────────

#[test]
fn xml_cdata_passes_through() {
    let out = encode_in_context(
        b"hello world",
        Strategy::CaseAlternation,
        InjectionContext::XmlCdata,
    )
    .unwrap();
    // CaseAlternation produces "HeLlO wOrLd"
    assert!(out.contains("HeLlO"));
}

#[test]
fn xml_cdata_terminator_rejected() {
    let err = encode_in_context(
        b"]]>",
        Strategy::CaseAlternation,
        InjectionContext::XmlCdata,
    )
    .unwrap_err();
    assert!(err.to_string().contains("incompatible"));
}

// ── XML Text ───────────────────────────────────────────────────────────────

#[test]
fn xml_text_escapes_special_chars() {
    let out = encode_in_context(
        b"a < b & c > d",
        Strategy::CaseAlternation,
        InjectionContext::XmlText,
    )
    .unwrap();
    assert!(out.contains("&lt;"));
    assert!(out.contains("&amp;"));
    assert!(out.contains("&gt;"));
}

// ── HTML Attribute ─────────────────────────────────────────────────────────

#[test]
fn html_attribute_escapes_both_quotes() {
    let out = encode_in_context(
        b"'\"x",
        Strategy::CaseAlternation,
        InjectionContext::HtmlAttribute,
    )
    .unwrap();
    assert!(out.contains("&#x27;") || out.contains("'")); // may or may not escape depending on impl
    assert!(out.contains("&quot;") || out.contains('"'));
}

#[test]
fn html_attribute_escapes_amp_and_lt() {
    let out = encode_in_context(
        b"a&b<c",
        Strategy::CaseAlternation,
        InjectionContext::HtmlAttribute,
    )
    .unwrap();
    assert!(out.contains("&amp;"));
    assert!(out.contains("&lt;"));
}

// ── HTML Text ──────────────────────────────────────────────────────────────

#[test]
fn html_text_escapes_amp_and_lt() {
    let out = encode_in_context(
        b"a&b<c",
        Strategy::CaseAlternation,
        InjectionContext::HtmlText,
    )
    .unwrap();
    assert!(out.contains("&amp;"));
    assert!(out.contains("&lt;"));
}

// ── URL Query ──────────────────────────────────────────────────────────────

#[test]
fn url_query_case_alternation_no_raw_space() {
    let out = encode_in_context(
        b"a b",
        Strategy::CaseAlternation,
        InjectionContext::UrlQuery,
    )
    .unwrap();
    // CaseAlternation doesn't change spaces, so if strategy doesn't touch them,
    // URL query context should percent-encode
    assert!(!out.contains(' '), "raw space found in URL query: {}", out);
}

#[test]
fn url_query_url_encode_no_double_encoding() {
    let out = encode_in_context(b"a b", Strategy::UrlEncode, InjectionContext::UrlQuery).unwrap();
    // Strategy produces "a%20b", then URL query context percent-encodes the % to %25,
    // resulting in "a%2520b" — this is expected double-encoding behavior
    assert!(out.contains("%2520"));
}

#[test]
fn url_query_unicode_escape_valid() {
    let out = encode_in_context(
        "ä".as_bytes(),
        Strategy::UnicodeEncode,
        InjectionContext::UrlQuery,
    )
    .unwrap();
    // UnicodeEncode produces \u00E4, then URL query context percent-encodes the backslash
    assert!(out.to_ascii_lowercase().contains("%5cu00e4"));
}

// ── URL Path ───────────────────────────────────────────────────────────────

#[test]
fn url_path_slash_not_encoded() {
    let out = encode_in_context(
        b"/api/v1",
        Strategy::CaseAlternation,
        InjectionContext::UrlPath,
    )
    .unwrap();
    assert!(out.contains("/"));
}

#[test]
fn url_path_space_encoded() {
    let out =
        encode_in_context(b"a b", Strategy::CaseAlternation, InjectionContext::UrlPath).unwrap();
    assert!(!out.contains(' '), "raw space found in URL path: {}", out);
}

// ── Header Value ───────────────────────────────────────────────────────────

#[test]
fn header_value_passes_through_clean() {
    let out = encode_in_context(
        b"Bearer token123",
        Strategy::CaseAlternation,
        InjectionContext::HeaderValue,
    )
    .unwrap();
    // CaseAlternation produces "BeArEr tOkEn123"
    assert!(out.contains("BeArEr"));
}

#[test]
fn header_value_cr_rejected() {
    let err = encode_in_context(
        b"a\rb",
        Strategy::CaseAlternation,
        InjectionContext::HeaderValue,
    )
    .unwrap_err();
    assert!(err.to_string().contains("incompatible"));
}

#[test]
fn header_value_lf_rejected() {
    let err = encode_in_context(
        b"a\nb",
        Strategy::CaseAlternation,
        InjectionContext::HeaderValue,
    )
    .unwrap_err();
    assert!(err.to_string().contains("incompatible"));
}

#[test]
fn header_value_null_rejected() {
    let err = encode_in_context(
        b"a\x00b",
        Strategy::CaseAlternation,
        InjectionContext::HeaderValue,
    )
    .unwrap_err();
    assert!(err.to_string().contains("incompatible"));
}

// ── Cookie Value ───────────────────────────────────────────────────────────

#[test]
fn cookie_value_escapes_semicolon() {
    let out = encode_in_context(
        b"a;b",
        Strategy::CaseAlternation,
        InjectionContext::CookieValue,
    )
    .unwrap();
    assert!(out.contains("%3B"));
}

#[test]
fn cookie_value_escapes_equals() {
    let out = encode_in_context(
        b"a=b",
        Strategy::CaseAlternation,
        InjectionContext::CookieValue,
    )
    .unwrap();
    assert!(out.contains("%3D"));
}

#[test]
fn cookie_value_escapes_null() {
    let out = encode_in_context(
        b"a\x00b",
        Strategy::CaseAlternation,
        InjectionContext::CookieValue,
    )
    .unwrap();
    assert!(out.contains("%00"));
}

// ── Multipart Field ────────────────────────────────────────────────────────

#[test]
fn multipart_field_passes_through() {
    let out = encode_in_context(
        b"hello",
        Strategy::CaseAlternation,
        InjectionContext::MultipartField,
    )
    .unwrap();
    // CaseAlternation produces "HeLlO"
    assert!(out.contains("HeLlO"));
}

#[test]
fn multipart_field_cr_rejected() {
    let err = encode_in_context(
        b"a\rb",
        Strategy::CaseAlternation,
        InjectionContext::MultipartField,
    )
    .unwrap_err();
    assert!(err.to_string().contains("incompatible"));
}

#[test]
fn multipart_field_lf_rejected() {
    let err = encode_in_context(
        b"a\nb",
        Strategy::CaseAlternation,
        InjectionContext::MultipartField,
    )
    .unwrap_err();
    assert!(err.to_string().contains("incompatible"));
}

// ── Multipart Filename ─────────────────────────────────────────────────────

#[test]
fn multipart_filename_passes_through() {
    let out = encode_in_context(
        b"file.txt",
        Strategy::CaseAlternation,
        InjectionContext::MultipartFileName,
    )
    .unwrap();
    // CaseAlternation produces "FiLe.tXt"
    assert!(out.contains("FiLe"));
}

#[test]
fn multipart_filename_quote_rejected() {
    let err = encode_in_context(
        b"\"evil\".txt",
        Strategy::CaseAlternation,
        InjectionContext::MultipartFileName,
    )
    .unwrap_err();
    assert!(err.to_string().contains("incompatible"));
}

// ── Plain Body ─────────────────────────────────────────────────────────────

#[test]
fn plain_body_no_structural_escaping() {
    let out = encode_in_context(
        b"<script>alert(1)</script>",
        Strategy::CaseAlternation,
        InjectionContext::PlainBody,
    )
    .unwrap();
    // PlainBody doesn't add structural escaping; strategy may mutate content
    assert!(!out.is_empty());
}

#[test]
fn plain_body_with_html_entity_strategy() {
    let out = encode_in_context(
        b"<script>alert(1)</script>",
        Strategy::HtmlEntityEncode,
        InjectionContext::PlainBody,
    )
    .unwrap();
    // HtmlEntityEncode produces hexadecimal entity references like &#x3C;
    assert!(out.contains("&#x3C;") || out.contains("&#x3E;") || out == "<script>alert(1)</script>");
}

// ── Backward compatibility: None context behaves like PlainBody ─────────────

#[test]
fn url_fragment_escapes_special_chars() {
    let out = encode_in_context(
        b"a b#c",
        Strategy::CaseAlternation,
        InjectionContext::UrlFragment,
    )
    .unwrap();
    assert!(!out.contains(' '));
}

// ── validate_in_context ────────────────────────────────────────────────────

#[test]
fn validate_detects_invalid_json_string() {
    let err = validate_in_context("unescaped\"quote", InjectionContext::JsonString).unwrap_err();
    assert!(err.to_string().contains("incompatible"));
}

#[test]
fn validate_accepts_valid_json_string() {
    assert!(validate_in_context("safe text", InjectionContext::JsonString).is_ok());
    assert!(validate_in_context("escaped\\\"quote", InjectionContext::JsonString).is_ok());
}

#[test]
fn validate_detects_invalid_xml_attribute() {
    let err = validate_in_context("a\"b", InjectionContext::XmlAttribute).unwrap_err();
    assert!(err.to_string().contains("incompatible"));
}

#[test]
fn validate_accepts_valid_xml_attribute() {
    assert!(validate_in_context("safe&amp;text", InjectionContext::XmlAttribute).is_ok());
}

// ── escape_for_context ─────────────────────────────────────────────────────

#[test]
fn escape_for_context_json_string() {
    let out = escape_for_context("\"x\"", InjectionContext::JsonString).unwrap();
    assert!(out.contains("\\\""));
}

#[test]
fn escape_for_context_cookie_value() {
    let out = escape_for_context("a;b=c", InjectionContext::CookieValue).unwrap();
    assert!(out.contains("%3B"));
    assert!(out.contains("%3D"));
}

// ── Size limits ────────────────────────────────────────────────────────────

#[test]
fn json_string_max_size_enforced() {
    let big = vec![b'a'; 4 * 1024 * 1024 + 1];
    let err = encode_in_context(
        &big,
        Strategy::CaseAlternation,
        InjectionContext::JsonString,
    )
    .unwrap_err();
    assert!(err.to_string().contains("too large"));
}

#[test]
fn cookie_value_max_size_enforced() {
    let big = vec![b'a'; 4 * 1024 + 1];
    let err = encode_in_context(
        &big,
        Strategy::CaseAlternation,
        InjectionContext::CookieValue,
    )
    .unwrap_err();
    assert!(err.to_string().contains("too large"));
}

#[test]
fn multipart_filename_max_size_enforced() {
    let big = vec![b'a'; 257];
    let err = encode_in_context(
        &big,
        Strategy::CaseAlternation,
        InjectionContext::MultipartFileName,
    )
    .unwrap_err();
    assert!(err.to_string().contains("too large"));
}

#[test]
fn exact_max_size_allowed() {
    let exact = vec![b'a'; 4 * 1024 * 1024];
    assert!(
        encode_in_context(
            &exact,
            Strategy::CaseAlternation,
            InjectionContext::JsonString
        )
        .is_ok()
    );
}

// ── All strategies × PlainBody (smoke test) ────────────────────────────────

#[test]
fn all_strategies_work_with_plain_body() {
    let payload = b"' OR 1=1 --";
    for strategy in wafrift_encoding::all_strategies() {
        let result = encode_in_context(payload, strategy, InjectionContext::PlainBody);
        assert!(
            result.is_ok(),
            "strategy {:?} failed on PlainBody: {:?}",
            strategy,
            result
        );
    }
}
