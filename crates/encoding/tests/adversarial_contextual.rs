//! Adversarial tests for context-aware encoding — edge cases, injections, boundaries.

use wafrift_encoding::Strategy;
use wafrift_encoding::contextual::encode_in_context;
use wafrift_types::injection_context::InjectionContext;

// ── Null byte handling ─────────────────────────────────────────────────────

#[test]
fn null_byte_json_string_escaped_not_rejected() {
    // JSON string can contain null if escaped as \u0000
    let out = encode_in_context(
        b"\x00",
        Strategy::CaseAlternation,
        InjectionContext::JsonString,
    )
    .unwrap();
    assert_eq!(out, "\\u0000");
}

#[test]
fn null_byte_xml_attribute_rejected() {
    let err = encode_in_context(
        b"a\x00b",
        Strategy::CaseAlternation,
        InjectionContext::XmlAttribute,
    )
    .unwrap_err();
    assert!(err.to_string().contains("incompatible"));
}

#[test]
fn null_byte_cookie_value_escaped() {
    let out = encode_in_context(
        b"a\x00b",
        Strategy::CaseAlternation,
        InjectionContext::CookieValue,
    )
    .unwrap();
    assert!(out.contains("%00"));
}

// ── Unicode edge cases ─────────────────────────────────────────────────────

#[test]
fn unicode_rtl_override_html_attribute() {
    let out = encode_in_context(
        "\u{202e}evil".as_bytes(),
        Strategy::CaseAlternation,
        InjectionContext::HtmlAttribute,
    )
    .unwrap();
    // Should preserve the RTL char but escape structural chars
    assert!(out.contains('\u{202e}'));
}

#[test]
fn chinese_characters_json_string() {
    let out = encode_in_context(
        "中文测试".as_bytes(),
        Strategy::CaseAlternation,
        InjectionContext::JsonString,
    )
    .unwrap();
    assert_eq!(out, "中文测试"); // Chinese is valid in JSON strings, no escaping needed
}

#[test]
fn emoji_json_string() {
    // CaseAlternation produces alternating upper/lower case for ASCII letters
    let out = encode_in_context(
        "Hello 👋".as_bytes(),
        Strategy::CaseAlternation,
        InjectionContext::JsonString,
    )
    .unwrap();
    assert_eq!(out, "HeLlO 👋");
}

#[test]
fn surrogate_pairs_json_string() {
    // U+1F600 (😀) is encoded as surrogate pair in UTF-16 but valid UTF-8
    let out = encode_in_context(
        "😀".as_bytes(),
        Strategy::CaseAlternation,
        InjectionContext::JsonString,
    )
    .unwrap();
    assert_eq!(out, "😀");
}

// ── Boundary conditions ────────────────────────────────────────────────────

#[test]
fn empty_payload_all_contexts() {
    for ctx in all_contexts() {
        let result = encode_in_context(b"", Strategy::CaseAlternation, ctx);
        assert!(
            result.is_ok(),
            "empty payload failed for {ctx:?}: {result:?}"
        );
    }
}

#[test]
fn single_byte_payload_all_contexts() {
    for ctx in all_contexts() {
        // JsonNumber only accepts digits, so use a numeric payload there
        let payload: &[u8] = if ctx == InjectionContext::JsonNumber {
            b"1"
        } else {
            b"x"
        };
        let result = encode_in_context(payload, Strategy::CaseAlternation, ctx);
        assert!(result.is_ok(), "single byte failed for {ctx:?}: {result:?}");
    }
}

#[test]
fn max_size_minus_one_all_contexts() {
    let sizes = vec![
        (InjectionContext::JsonString, 4 * 1024 * 1024 - 1),
        (InjectionContext::JsonNumber, 1023),
        (InjectionContext::HeaderValue, 8 * 1024 - 1),
        (InjectionContext::CookieValue, 4 * 1024 - 1),
        (InjectionContext::MultipartFileName, 255),
    ];
    for (ctx, size) in sizes {
        // JsonNumber only accepts digits
        let payload: Vec<u8> = if ctx == InjectionContext::JsonNumber {
            vec![b'1'; size]
        } else {
            vec![b'x'; size]
        };
        assert!(
            encode_in_context(&payload, Strategy::CaseAlternation, ctx).is_ok(),
            "max_size-1 failed for {ctx:?}"
        );
    }
}

#[test]
fn max_size_plus_one_all_contexts() {
    let sizes = vec![
        (InjectionContext::JsonString, 4 * 1024 * 1024 + 1),
        (InjectionContext::JsonNumber, 1025),
        (InjectionContext::HeaderValue, 8 * 1024 + 1),
        (InjectionContext::CookieValue, 4 * 1024 + 1),
        (InjectionContext::MultipartFileName, 257),
    ];
    for (ctx, size) in sizes {
        let payload = vec![b'x'; size];
        let err = encode_in_context(&payload, Strategy::CaseAlternation, ctx).unwrap_err();
        assert!(
            err.to_string().contains("too large"),
            "wrong error for {ctx:?} at size {size}: {err}"
        );
    }
}

// ── Injection attempts in metadata ─────────────────────────────────────────

#[test]
fn header_value_crlf_injection_prevented() {
    // CR/LF in header values can lead to HTTP response splitting / header injection
    let err = encode_in_context(
        b"value\r\nX-Injection: evil",
        Strategy::CaseAlternation,
        InjectionContext::HeaderValue,
    )
    .unwrap_err();
    assert!(err.to_string().contains("incompatible"));
}

#[test]
fn multipart_field_crlf_injection_prevented() {
    // CR/LF in multipart fields breaks the boundary structure
    let err = encode_in_context(
        b"field\r\n--boundary",
        Strategy::CaseAlternation,
        InjectionContext::MultipartField,
    )
    .unwrap_err();
    assert!(err.to_string().contains("incompatible"));
}

#[test]
fn cookie_value_crlf_injection_prevented_indirectly() {
    // CR/LF in cookie values should be escaped, not rejected (cookies don't have same structural risk)
    let out = encode_in_context(
        b"a\r\nb",
        Strategy::CaseAlternation,
        InjectionContext::CookieValue,
    )
    .unwrap();
    // Should be percent-encoded
    assert!(out.contains("%0D") || out.contains("%0A"));
}

// ── Malformed / pathological inputs ────────────────────────────────────────

#[test]
fn invalid_utf8_bytes_handled() {
    // Invalid UTF-8 sequence 0x80 alone
    let payload = vec![0x80];
    let err = encode_in_context(
        &payload,
        Strategy::CaseAlternation,
        InjectionContext::JsonString,
    )
    .unwrap_err();
    assert!(err.to_string().contains("invalid"));
}

#[test]
fn overlong_utf8_sequence() {
    // Overlong encoding of NUL: 0xC0 0x80 (invalid in strict UTF-8)
    let payload = vec![0xC0, 0x80];
    let err = encode_in_context(
        &payload,
        Strategy::CaseAlternation,
        InjectionContext::PlainBody,
    )
    .unwrap_err();
    assert!(err.to_string().contains("invalid"));
}

#[test]
fn truncated_utf8_sequence() {
    // Start of 3-byte sequence without continuation
    let payload = vec![0xE0];
    let err = encode_in_context(
        &payload,
        Strategy::CaseAlternation,
        InjectionContext::PlainBody,
    )
    .unwrap_err();
    assert!(err.to_string().contains("invalid"));
}

// ── Strategy-specific adversarial tests ────────────────────────────────────

#[test]
fn base64_in_json_string_produces_valid_json() {
    let out = encode_in_context(
        b"hello",
        Strategy::Base64Encode,
        InjectionContext::JsonString,
    )
    .unwrap();
    // Base64 output is alphanumeric + / + = — all valid in JSON strings
    assert!(!out.contains('"'));
    assert!(!out.contains('\\'));
}

#[test]
fn html_entity_encode_in_xml_attribute_double_escapes() {
    // HtmlEntityEncode produces &#x3C; which in XML attribute should become &amp;#x3C;
    let out = encode_in_context(
        b"<",
        Strategy::HtmlEntityEncode,
        InjectionContext::XmlAttribute,
    )
    .unwrap();
    // The & from HTML entity must be XML-escaped
    assert!(out.contains("&amp;#x3C;"));
}

#[test]
fn chunked_split_in_header_value_rejected() {
    // Chunked split introduces CR/LF — must be rejected in header context
    let err = encode_in_context(
        b"payload",
        Strategy::ChunkedSplit,
        InjectionContext::HeaderValue,
    )
    .unwrap_err();
    assert!(err.to_string().contains("incompatible"));
}

// ── Structural validation after encoding ───────────────────────────────────

#[test]
fn every_strategy_produces_valid_plain_body() {
    let payload = b"<script>alert(1)</script>";
    for &strategy in wafrift_encoding::all_strategies() {
        let out = encode_in_context(payload, strategy, InjectionContext::PlainBody).unwrap();
        // PlainBody has no structural constraints, so all strategies should succeed
        assert!(
            !out.is_empty(),
            "strategy {strategy:?} produced empty output"
        );
    }
}

#[test]
fn every_strategy_produces_valid_url_query() {
    let payload = b"hello world";
    for &strategy in wafrift_encoding::all_strategies() {
        let result = encode_in_context(payload, strategy, InjectionContext::UrlQuery);
        // Most should succeed; some that introduce spaces or special chars may fail
        if let Ok(out) = result {
            // URL query must not contain raw spaces
            assert!(
                !out.contains(' '),
                "strategy {strategy:?} produced raw space in URL query"
            );
        }
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn all_contexts() -> Vec<InjectionContext> {
    use InjectionContext::*;
    vec![
        JsonString,
        JsonNumber,
        XmlAttribute,
        XmlCdata,
        XmlText,
        HtmlAttribute,
        HtmlText,
        UrlQuery,
        UrlPath,
        UrlFragment,
        HeaderValue,
        CookieValue,
        MultipartField,
        MultipartFileName,
        PlainBody,
    ]
}
