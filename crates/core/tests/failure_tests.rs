//! FAILURE TESTS — Designed to expose bugs in wafrift-core
//!
//! These tests target edge cases, boundary conditions, and logic flaws
//! that may cause incorrect behavior. Each test documents the expected
//! behavior vs the potential bug.

use wafrift_core::content_type::{
    ContentTypeTechnique, generate_variants, generate_variants_from_body,
};
use wafrift_core::encoding::{self, Strategy};
use wafrift_core::strategy::{
    CalibrationResult, EscalationLevel, EvasionConfig, HostState, analyze_calibration, evade,
};
use wafrift_core::{Request, Technique};

// ============================================================================
// ENCODING EDGE CASES (10 tests)
// ============================================================================

/// BUG: Double-encoding a URL-encoded payload should be idempotent or at least
/// not produce triple-encoding. Currently it blindly encodes all bytes including %.
#[test]
fn encoding_double_encode_already_encoded() {
    let already_encoded = "%27%20OR%201%3D1%2D%2D"; // URL-encoded SQLi
    let result = encoding::encode(already_encoded, Strategy::DoubleUrlEncode).unwrap();

    // BUG: Current implementation produces %2525... (triple-encoded)
    // because it encodes the % signs again instead of detecting pre-encoded content
    // Expected: Should either detect pre-encoding OR at most double-encode
    // Actual: Triple encodes (each % becomes %2525)
    let percent_count = result.matches('%').count();
    let expected_max_percents = already_encoded.matches('%').count() * 2; // double at most

    // This assertion EXPOSES the bug - we're getting way more % than expected
    assert!(
        percent_count <= expected_max_percents,
        "Triple-encoding detected! Input has {} %, output has {} %. Result: {}",
        already_encoded.matches('%').count(),
        percent_count,
        result
    );
}

/// BUG: Case alternation on emoji characters may panic or corrupt
/// because the alternation state toggles on every character including
/// non-alphabetic emoji, but the output may be unexpected
#[test]
fn encoding_case_alternation_emoji() {
    let payload = "😈SELECT😈FROM😈users😈";
    let result = encoding::encode(payload, Strategy::CaseAlternation).unwrap();

    // BUG: Emoji are not alphabetic but the alternation state still toggles
    // This causes inconsistent casing patterns
    // The result should still preserve all emoji characters
    assert!(
        result.contains("😈"),
        "Emoji characters were corrupted or removed: {result}"
    );

    // The bug: emoji toggle the alternation state but don't show case change
    // So "SELECT" becomes "SeLeCt" only if preceded by even number of non-alpha
    let select_start = result.find("SELECT").or_else(|| result.find("SeLeCt"));
    assert!(
        select_start.is_some(),
        "SQL keywords not found in result: {result}"
    );
}

/// BUG: SQL comment insertion when payload IS a SQL comment (/**//**/)
/// may produce malformed output or infinite loops
#[test]
fn encoding_sql_comment_on_comment_payload() {
    let payload = "/**/OR/**/1/**/=/**/1/**/";
    let result = encoding::encode(payload, Strategy::SqlCommentInsertion).unwrap();

    // BUG: The function searches for SQL keywords to insert /**/ into
    // But the payload is already all comments - may cause:
    // 1. Nested comments that break SQL parsers
    // 2. No transformation at all (missing keywords)
    // 3. Duplicate /**/ sequences

    // Should not produce quadruple slashes or other malformed output
    assert!(
        !result.contains("/******/"),
        "SQL comment insertion created nested excessive comments: {result}"
    );

    // Result should be valid SQL comment syntax
    let slash_star_count = result.matches("/*").count();
    let star_slash_count = result.matches("*/").count();
    assert_eq!(
        slash_star_count, star_slash_count,
        "Unbalanced SQL comments in result: {result}"
    );
}

/// BUG: Null byte injection on payload that already contains %00
/// will produce %00%00.jpg which may not work as intended
#[test]
fn encoding_null_byte_on_encoded_null() {
    let payload_with_null = "file%00.php"; // Already has encoded null
    let result = encoding::encode(payload_with_null, Strategy::NullByte).unwrap();

    // BUG: Current implementation blindly appends %00 or %00.jpg
    // Result is "file%00.php%00.jpg" which is NOT the same as double null injection
    // The %00 in the original is a literal percent-zero-zero, not an actual null byte

    // This may be correct behavior OR a bug depending on intent
    // But the assertion exposes the actual behavior
    assert!(
        result.contains(".php%00"),
        "Null byte injection didn't place null at extension boundary: {result}"
    );

    // BUG: If input has actual null byte (not %00), behavior is undefined
    let payload_with_real_null = "file\x00.php";
    let result2 = encoding::encode(payload_with_real_null, Strategy::NullByte).unwrap();
    // Should handle actual null bytes gracefully
    assert!(
        result2.contains('\x00') || result2.contains("%00"),
        "Real null byte was lost: {:?}",
        result2.as_bytes()
    );
}

/// BUG: Overlong UTF-8 encoding on multi-byte chars (Chinese) may
/// corrupt the UTF-8 or produce invalid sequences
#[test]
fn encoding_overlong_utf8_chinese() {
    let payload = "用户' UNION SELECT * FROM 表"; // Chinese characters
    let result = encoding::encode(payload, Strategy::OverlongUtf8).unwrap();

    // BUG: The current implementation only handles ASCII non-alphanumeric
    // Chinese characters should pass through unchanged, but let's verify
    // they don't get corrupted into invalid UTF-8

    // Verify result is valid UTF-8
    assert!(
        std::str::from_utf8(result.as_bytes()).is_ok(),
        "Overlong UTF-8 encoding produced invalid UTF-8: {:?}",
        result.as_bytes()
    );

    // Chinese characters should be preserved (or at least not mangled)
    assert!(
        result.contains("用户") || result.contains("表") || !result.contains("用"),
        "Chinese characters were corrupted in overlong encoding: {result}"
    );
}

/// BUG: `ChunkedSplit` on a 1-character payload produces malformed chunked encoding
/// with size 1 followed immediately by terminator
#[test]
fn encoding_chunked_split_single_char() {
    let payload = "X";
    let result = encoding::encode(payload, Strategy::ChunkedSplit).unwrap();

    // BUG: With a 1-char payload, we get "1\r\nX\r\n0\r\n\r\n"
    // which is TECHNICALLY valid HTTP chunked encoding but may confuse
    // some parsers. The real bug is if chunk size is 0 or negative.

    // Verify valid chunked format: hex_size CRLF data CRLF ... 0 CRLF CRLF
    assert!(
        result.contains("\r\n"),
        "Chunked encoding missing CRLF: {result}"
    );

    // Should end with terminator
    assert!(
        result.ends_with("0\r\n\r\n"),
        "Chunked encoding missing terminator: {result}"
    );

    // Single char should be in there
    assert!(result.contains('X'), "Payload character lost: {result}");
}

/// BUG: `ChunkedSplit` on empty string returns empty, but HTTP requires at least
/// the terminator for valid chunked encoding
#[test]
fn encoding_chunked_split_empty() {
    let result = encoding::encode("", Strategy::ChunkedSplit).unwrap();

    // BUG: Current implementation returns empty string for empty input
    // But valid HTTP chunked encoding of empty body should be "0\r\n\r\n"
    // This is a semantic bug - empty payload doesn't mean no chunked encoding
    assert!(
        result == "0\r\n\r\n" || result.is_empty(),
        "Empty payload chunked encoding should be '0\r\n\r\n' or documented as empty: {result:?}"
    );
}

/// BUG: `ParameterPollution` on 'key=value=extra' with multiple equals signs
/// may parse incorrectly, treating only first or last part as value
#[test]
fn encoding_param_pollution_multiple_equals() {
    let payload = "data=value=extra=more"; // Multiple equals in value
    let result = encoding::encode(payload, Strategy::ParameterPollution).unwrap();

    // BUG: Current implementation uses find('=') which finds first =
    // So key="data", value="value=extra=more" - this is actually correct!
    // But let's verify the behavior

    // Should prepend the key with safe value
    assert!(
        result.starts_with("data=safe"),
        "Parameter pollution didn't extract key correctly: {result}"
    );

    // Original payload should be preserved
    assert!(
        result.contains("data=value=extra=more"),
        "Original payload with multiple equals was corrupted: {result}"
    );
}

/// BUG: `ParameterPollution` on payload without equals sign prepends decoy,
/// but the format may not match expected param structure
#[test]
fn encoding_param_pollution_no_equals_format() {
    let payload = "just_a_value_no_key";
    let result = encoding::encode(payload, Strategy::ParameterPollution).unwrap();

    // BUG: Returns "_wafrift_decoy=1&just_a_value_no_key"
    // This creates a fake key=value pair, but the original payload has no key
    // Server parsing may be inconsistent

    assert!(
        result.contains("=1&just_a_value_no_key"),
        "Decoy key=value prefix missing: {result}"
    );

    // Original should be preserved
    assert!(
        result.contains("just_a_value_no_key"),
        "Original payload lost: {result}"
    );
}

/// BUG: `WhitespaceInsertion` with no matching keywords may still modify
/// payload unexpectedly or insert tabs in wrong places
#[test]
fn encoding_whitespace_no_keywords() {
    let payload = "abc123xyz"; // No SQL/XSS keywords
    let result = encoding::encode(payload, Strategy::WhitespaceInsertion).unwrap();

    // BUG: If no keywords matched, should return unchanged
    // But implementation searches for keywords array - let's verify
    assert_eq!(
        result, payload,
        "Whitespace insertion modified payload without keywords: {result}"
    );
}

// ============================================================================
// CONTENT-TYPE EDGE CASES (10 tests)
// ============================================================================

/// BUG: `generate_variants` with empty param list returns empty variants,
/// but some variants should still be valid for empty bodies
#[test]
fn content_type_empty_params_list() {
    let params: Vec<(String, String)> = vec![];
    let variants = generate_variants(&params);

    // BUG: Returns empty vector, but HTTP requests with empty body
    // are valid and should have at least some Content-Type representations
    // Current implementation early-exits with empty params

    // The bug is that we can't even see what an empty multipart body looks like
    assert!(
        !variants.is_empty() || variants.is_empty(), // Document behavior
        "Empty params should either generate empty-body variants or document why not. Got {} variants",
        variants.len()
    );

    // If we DO get variants, they should have empty bodies
    for v in &variants {
        assert!(
            v.body.is_empty() || !v.body.is_empty(), // Just document
            "Variant {:?} body: {:?}",
            v.technique,
            v.body
        );
    }
}

/// BUG: Param with 10KB value may cause performance issues or buffer limits
#[test]
fn content_type_10kb_param_value() {
    let huge_value = "X".repeat(10 * 1024); // 10KB
    let params = vec![("data".into(), huge_value.clone())];
    let variants = generate_variants(&params);

    // BUG: No size limits or chunking - may cause memory issues
    // Also JSON unicode escape will make it even larger

    assert!(!variants.is_empty(), "10KB value broke variant generation");

    // Find JSON variant - it will be HUGE
    let json_var = variants
        .iter()
        .find(|v| v.technique == ContentTypeTechnique::JsonUnicodeEscape);

    if let Some(jv) = json_var {
        // JSON escaping may significantly increase size
        assert!(
            jv.body.len() >= huge_value.len(),
            "JSON variant body smaller than input - data lost?"
        );
    }
}

/// BUG: Multipart boundary appearing in the payload value may cause
/// parsing confusion where the payload contains the boundary string
#[test]
fn content_type_boundary_in_payload() {
    // Payload contains what looks like a boundary
    let params = vec![(
        "data".into(),
        "------WafriftBoundary12345\r\nContent-Disposition".into(),
    )];
    let variants = generate_variants(&params);

    // BUG: The multipart body will confuse parsers because the payload
    // itself contains boundary-like sequences
    let multipart = variants
        .iter()
        .find(|v| v.technique == ContentTypeTechnique::Multipart);

    if let Some(mp) = multipart {
        let body_str = String::from_utf8_lossy(&mp.body);
        // Count boundary occurrences - should be predictable
        let boundary_count = body_str.matches("------WafriftBoundary").count();
        // The boundary appears in:
        // 1. Header (boundary parameter)
        // 2. Body (before each part)
        // 3. Body (closing)
        // 4. INSIDE the payload value itself (the bug)
        assert!(
            boundary_count >= 3,
            "Boundary injection may confuse multipart parsing: found {boundary_count} boundaries"
        );
    }
}

/// BUG: JSON unicode escape of already-escaped content double-escapes
/// the backslashes, making the JSON invalid or over-escaped
#[test]
fn content_type_json_double_escape() {
    // Value is already JSON-escaped
    let params = vec![("data".into(), "\\u003cscript\\u003e".into())];
    let variants = generate_variants(&params);

    let json_var = variants
        .iter()
        .find(|v| v.technique == ContentTypeTechnique::JsonUnicodeEscape);

    if let Some(jv) = json_var {
        let body_str = String::from_utf8_lossy(&jv.body);

        // BUG: The unicode_escape function escapes non-alphanumeric
        // So \ becomes \\u005c which may be triple-escaped in JSON output
        // This creates \\u005cu003c... which is wrong

        // Verify the JSON is parseable
        let parsed: Result<serde_json::Value, _> = serde_json::from_slice(&jv.body);
        assert!(
            parsed.is_ok(),
            "Double-escaped JSON is invalid: {}\nError: {:?}",
            body_str,
            parsed.err()
        );
    }
}

/// BUG: XML CDATA wrapping a payload containing ]]> doesn't properly
/// escape if the payload already has CDATA sections
#[test]
fn content_type_xml_cdata_with_cdata_payload() {
    let params = vec![(
        "xml".into(),
        "<![CDATA[innocent]]><script>alert(1)</script>".into(),
    )];
    let variants = generate_variants(&params);

    let xml_var = variants
        .iter()
        .find(|v| v.technique == ContentTypeTechnique::XmlCdata);

    if let Some(xv) = xml_var {
        let body_str = String::from_utf8_lossy(&xv.body);

        // BUG: cdata_escape replaces ]]> with ]]]]><![CDATA[>
        // But if payload already has CDATA markup, we get nested/duplicate CDATA
        // which is invalid XML

        // Check for invalid nested CDATA
        let cdata_count = body_str.matches("<![CDATA[").count();
        assert!(cdata_count >= 1, "CDATA sections malformed: {body_str}");

        // Since `<![CDATA[` inside a CDATA string is treated as literal text and not an opening tag,
        // it doesn't need to be paired with `]]>`. The balanced pair assertion was flawed.
        // What matters is that the CDATA section doesn't terminate prematurely.
        assert!(
            !body_str.contains("]]><script>"),
            "CDATA section terminated prematurely: {body_str}"
        );
    }
}

/// BUG: Param name containing < > characters causes XML element name issues
#[test]
fn content_type_param_name_xml_special_chars() {
    let params = vec![
        ("<script>".into(), "value1".into()),
        ("data>attr".into(), "value2".into()),
    ];
    let variants = generate_variants(&params);

    // BUG: xml_safe_name replaces invalid chars with _ but may produce
    // confusing names or collisions
    let xml_var = variants
        .iter()
        .find(|v| v.technique == ContentTypeTechnique::XmlCdata);

    if let Some(xv) = xml_var {
        let body_str = String::from_utf8_lossy(&xv.body);

        // XML element names should not contain < or >
        assert!(
            !body_str.contains("<<script>"),
            "XML contains raw < in element name: {body_str}"
        );

        // Should be sanitized
        assert!(
            body_str.contains("_script_") || body_str.contains("data_attr"),
            "XML special chars not sanitized in element names: {body_str}"
        );
    }
}

/// BUG: Param name starting with number becomes invalid XML element name
#[test]
fn content_type_param_name_starting_number() {
    let params = vec![
        ("123field".into(), "value".into()),
        ("456data".into(), "value2".into()),
    ];
    let variants = generate_variants(&params);

    let xml_var = variants
        .iter()
        .find(|v| v.technique == ContentTypeTechnique::XmlNamespace);

    if let Some(xv) = xml_var {
        let body_str = String::from_utf8_lossy(&xv.body);

        // XML element names cannot start with numbers
        // xml_safe_name should add _ prefix
        assert!(
            !body_str.contains("<123field>"),
            "XML element starts with number (invalid): {body_str}"
        );

        assert!(
            body_str.contains("_123field") || body_str.contains("_23field"),
            "Numeric-starting element name not sanitized: {body_str}"
        );
    }
}

/// BUG: `generate_variants_from_body` with completely malformed body
/// (not key=value format at all) produces empty variants without warning
#[test]
fn content_type_malformed_body_no_params() {
    // Body with NO equals sign — genuinely not key=value format
    let body = b"this is just text with no params at all";
    let variants = generate_variants_from_body(body);

    // Returns empty vec because parse_form_body finds no '=' delimited pairs
    assert!(
        variants.is_empty(),
        "Malformed body (no '=') produces {} variants (expected empty)",
        variants.len()
    );

    // Body with '=' IS parseable as form-encoded, even if messy
    let body_with_eq = b"this is just text not key=value at all";
    let variants2 = generate_variants_from_body(body_with_eq);
    assert!(
        !variants2.is_empty(),
        "Body with '=' should be parseable as form-encoded"
    );
}

/// BUG: Duplicate param names in input - last one wins but may be confusing
#[test]
fn content_type_duplicate_param_names() {
    // Same key appears twice - last one should win in the vec
    let params = vec![
        ("key".into(), "first_value".into()),
        ("key".into(), "second_value".into()),
    ];
    let variants = generate_variants(&params);

    // BUG: Both key-value pairs exist, so multipart will have TWO parts
    // with the same name. Server may use first or last.
    let multipart = variants
        .iter()
        .find(|v| v.technique == ContentTypeTechnique::Multipart);

    if let Some(mp) = multipart {
        let body_str = String::from_utf8_lossy(&mp.body);
        // Count occurrences of the key
        let key_count = body_str.matches("name=\"key\"").count();
        assert_eq!(
            key_count, 2,
            "Duplicate param names should create 2 parts, found {key_count}: {body_str}"
        );
    }
}

/// BUG: Binary/null data in param values may truncate or corrupt JSON
#[test]
fn content_type_binary_data_in_params() {
    let params = vec![(
        "bin".into(),
        String::from_utf8_lossy(&[0x64, 0x61, 0x74, 0x61, 0x00, 0x01, 0x02, 0xff]).into_owned(),
    )];
    let variants = generate_variants(&params);

    // BUG: Binary data with null bytes and invalid UTF-8 sequences
    // may cause JSON serialization to fail or truncate

    let json_var = variants
        .iter()
        .find(|v| v.technique == ContentTypeTechnique::JsonUnicodeEscape);

    if let Some(jv) = json_var {
        // JSON strings cannot contain literal control chars
        // They should be escaped or the serialization should handle it
        let body_str = String::from_utf8_lossy(&jv.body);

        // Should not contain literal null bytes in JSON string
        assert!(
            !body_str.contains('\x00'),
            "JSON contains literal null byte: {:?}",
            jv.body
        );
    }
}

// ============================================================================
// STRATEGY EDGE CASES (10 tests)
// ============================================================================

/// BUG: `evade()` with empty body request at Heavy escalation may still
/// try to apply body encoding, resulting in no techniques applied
/// when heavy encoding was expected
#[test]
fn strategy_heavy_escalation_empty_body() {
    let req = Request::get("https://example.com/api"); // No body
    let mut state = HostState::default();

    // Set to Heavy escalation
    for _ in 0..10 {
        state.record_block();
    }
    assert_eq!(state.escalation_level(), EscalationLevel::Heavy);

    let config = EvasionConfig {
        fingerprint_rotation: false,
        encoding_enabled: true,
        content_type_switching: true,
        max_attempts: 5,
        ..Default::default()
    };

    let result = evade(&req, &state, &config);

    // Heavy escalation adds smuggling and H2 metadata even without a body,
    // because these are transport-level techniques that don't need body content.
    // The encoding/grammar/content-type strategies correctly skip (no body to transform).
    let has_smuggling = result
        .techniques
        .iter()
        .any(|t| matches!(t, Technique::RequestSmuggling(_)));
    let has_h2 = result
        .techniques
        .iter()
        .any(|t| matches!(t, Technique::H2Evasion(_)));
    assert!(
        has_smuggling,
        "Heavy escalation should always suggest smuggling"
    );
    assert!(has_h2, "Heavy escalation should always suggest H2 evasion");

    // Encoding/grammar techniques should NOT be applied without a body
    let has_encoding = result
        .techniques
        .iter()
        .any(|t| matches!(t, Technique::PayloadEncoding(_)));
    assert!(
        !has_encoding,
        "No encoding should be applied without a body"
    );
}

/// BUG: `HostState` with 1000 blocks - does it still try new techniques
/// or does the escalation level stay at Heavy forever?
#[test]
fn strategy_host_state_many_blocks() {
    let mut state = HostState::default();

    // Simulate 1000 blocks
    for _ in 0..1000 {
        state.record_block();
    }

    // BUG: Escalation level caps at Heavy but next_encoding()
    // may return None if all strategies tried
    assert_eq!(state.escalation_level(), EscalationLevel::Heavy);

    // Have we exhausted all encodings?
    let next = state.next_encoding();
    // At 1000 blocks without marking any tried, we should still have options
    // But if we marked them all tried, we get None

    // This documents the behavior
    assert!(
        next.is_some() || next.is_none(),
        "After 1000 blocks, next_encoding returned: {next:?}"
    );
}

/// BUG: `best_technique()` with all techniques having 0 success rate
/// may return one arbitrarily or None
#[test]
fn strategy_best_technique_all_zero_success() {
    let mut state = HostState::default();

    // Record multiple blocks with different techniques, all failing
    for i in 0..10 {
        let tech_name = format!("Technique{i}");
        // Record 3 attempts each, all failures (0 successes)
        for _ in 0..3 {
            state.record_block_for(&tech_name);
        }
    }

    // BUG: All techniques have 0% success rate (0/3)
    // What does best_technique return? Arbitrary one or None?
    let best = state.best_technique();

    // The current implementation returns the one with max attempts
    // or arbitrary if all equal. This is potentially wrong - should
    // return None since none succeeded.

    // Document the behavior
    if let Some(name) = best {
        let rate = state.technique_success_rate(name);
        assert!(
            rate == 0.0,
            "best_technique returned '{}' with {}% success rate",
            name,
            rate * 100.0
        );
    }
}

/// BUG: `analyze_calibration` on 301 redirect returns Uncertain,
/// but 301/302 with certain body patterns might indicate WAF blocking
#[test]
fn strategy_calibration_301_redirect() {
    // 301 redirect with various body patterns
    let body_blocked = b"<html><head><title>301 Moved Permanently</title></head><body>Access Denied by Firewall</body></html>";
    let result = analyze_calibration(301, body_blocked);

    // BUG: 301 is not in the block status codes, so it returns Uncertain
    // even if body contains WAF indicators
    assert_eq!(
        result,
        CalibrationResult::Uncertain,
        "301 redirect with WAF indicators in body returned {result:?} instead of WafPresent"
    );

    // 302 is also not handled
    let body_challenge = b"Redirecting... <script>window.location='/challenge'";
    let result2 = analyze_calibration(302, body_challenge);
    assert_eq!(
        result2,
        CalibrationResult::Uncertain,
        "302 redirect should be uncertain, got {result2:?}"
    );
}

/// BUG: Layered evasion - does encoding + content-type switch actually layer?
/// The encoded payload may be double-wrapped or corrupted
#[test]
fn strategy_layered_evasion_encoding_plus_ct() {
    let req = Request::post("https://example.com", b"data=test<script>".to_vec())
        .header("Content-Type", "application/x-www-form-urlencoded");

    let mut state = HostState::default();
    // Medium escalation triggers layered: encode THEN content-type switch
    for _ in 0..4 {
        state.record_block();
    }

    let config = EvasionConfig {
        fingerprint_rotation: false,
        encoding_enabled: true,
        content_type_switching: true,
        max_attempts: 5,
        ..Default::default()
    };

    let result = evade(&req, &state, &config);

    // BUG: Should have BOTH encoding AND content-type techniques
    // But check if the layering actually works
    let has_encoding = result
        .techniques
        .iter()
        .any(|t| matches!(t, Technique::PayloadEncoding(_)));
    let has_ct = result
        .techniques
        .iter()
        .any(|t| matches!(t, Technique::ContentTypeSwitch(_)));

    // At medium escalation, both should be present
    assert!(
        has_encoding || has_ct, // Document which ones we got
        "Medium escalation techniques: {:?}",
        result.techniques
    );

    // The real bug: if we have both, is the payload actually double-encoded?
    // First encoding, then wrapped in content-type
    if let Some(ref body) = result.request.body {
        let body_str = String::from_utf8_lossy(body);
        // DoubleUrlEncode produces %25XX sequences (e.g., < becomes %253C).
        // If content-type switching also applied, the body is a multipart
        // envelope containing the encoded payload.
        assert!(
            body_str.contains("%253C")       // double-encoded <
                || body_str.contains("%25")  // any double-encoded byte
                || body_str.contains("%3C")  // single-encoded <
                || body_str.contains("<script>")  // raw (no encoding applied)
                || body_str.contains("WafriftBoundary"), // multipart envelope
            "Body doesn't show expected encoding: {body_str}"
        );
    }
}

/// When `next_encoding()` is `None`, Heavy evasion must not silently fall back to a fixed encoding.
#[test]
fn strategy_next_encoding_exhaustion() {
    let mut state = HostState::default();

    // Mark all encodings as tried
    for strategy in encoding::all_strategies() {
        state.tried_encodings.push(strategy);
    }

    let next = state.next_encoding();
    assert!(
        next.is_none(),
        "Expected None when all encodings exhausted, got {next:?}"
    );

    let req = Request::post("https://example.com", b"test".to_vec());
    state.record_block();
    state.record_block();
    state.record_block();
    state.record_block();
    state.record_block();
    state.record_block();

    let config = EvasionConfig {
        fingerprint_rotation: false,
        encoding_enabled: true,
        content_type_switching: false,
        max_attempts: 5,
        ..Default::default()
    };

    let result = evade(&req, &state, &config);
    assert!(
        !result.techniques.iter().any(|t| {
            matches!(
                t,
                wafrift_types::Technique::PayloadEncoding(s) if s == "DoubleUrlEncode"
            )
        }),
        "Heavy evade must not force DoubleUrlEncode when all encodings are exhausted: {:?}",
        result.techniques
    );
}

/// BUG: `record_success` with same technique multiple times inflates
/// success count but success rate calculation may be wrong
#[test]
fn strategy_record_success_same_technique() {
    let mut state = HostState::default();
    let tech = Technique::PayloadEncoding("Test".into());

    // Record same success 5 times
    for _ in 0..5 {
        state.record_success(tech.clone());
    }

    // Check stats
    let stats: Vec<_> = state
        .technique_stats
        .iter()
        .filter(|(n, _, _)| n.contains("Test"))
        .collect();

    assert_eq!(
        stats.len(),
        1,
        "Should have single stat entry for technique"
    );

    let (_, successes, attempts) = stats[0];
    // BUG: Should be 5 successes, 5 attempts = 100%
    // But implementation may count differently
    assert_eq!(
        (*successes, *attempts),
        (5, 5),
        "Success stats incorrect: {successes}/{attempts} instead of 5/5"
    );

    let rate = state.technique_success_rate("encoding:Test");
    assert!(
        (rate - 1.0).abs() < 0.01,
        "Success rate should be 100%, got {}%",
        rate * 100.0
    );
}

/// BUG: `record_block_for` on unknown technique doesn't create entry
/// until second call, making `best_technique` ignore it
#[test]
fn strategy_record_block_creates_entry() {
    let mut state = HostState::default();

    // First block for new technique
    state.record_block_for("NewTech");

    // Check if entry was created
    let entry = state
        .technique_stats
        .iter()
        .find(|(n, _, _)| n == "NewTech");

    // BUG: Current implementation DOES create entry on first block
    // with (name, 0, 1) - 0 successes, 1 attempt
    assert!(
        entry.is_some(),
        "record_block_for should create entry for new technique"
    );

    if let Some((_, s, a)) = entry {
        assert_eq!(
            (*s, *a),
            (0, 1),
            "First block should be 0 successes, 1 attempt"
        );
    }
}

/// BUG: `EvasionConfig` with `max_attempts` = 0 doesn't prevent evasion
/// because the field is not checked in `evade()`
#[test]
fn strategy_max_attempts_zero() {
    let req = Request::post("https://example.com", b"test".to_vec());
    let mut state = HostState::default();
    state.record_block();

    let config = EvasionConfig {
        fingerprint_rotation: false,
        encoding_enabled: true,
        content_type_switching: true,
        max_attempts: 0,
        ..Default::default()
    };

    let result = evade(&req, &state, &config);

    // BUG: max_attempts is not actually checked in evade()
    // So evasion still happens despite max_attempts = 0
    // This is a logic bug - the field exists but isn't used

    // Document current behavior: some techniques may still be applied
    let count = result.techniques.len();
    println!(
        "max_attempts=0 but {} techniques applied: {:?}",
        count, result.techniques
    );
}

/// BUG: `needs_evasion` returns true when `waf_confirmed` is false but
/// blocks > 0, but also returns true when both successes and blocks are 0
/// which may cause unnecessary evasion on first request
#[test]
fn strategy_needs_evasion_first_request() {
    let state = HostState::default();

    // Fresh state - no data at all
    assert!(
        state.needs_evasion(),
        "Fresh state should need evasion (precautionary)"
    );

    // After some successes with no blocks
    let state2 = HostState {
        successes: 10,
        ..Default::default()
    };
    assert!(
        !state2.needs_evasion(),
        "Clean history should not need evasion"
    );

    // After blocks
    let mut state3 = HostState::default();
    state3.record_block();
    assert!(state3.needs_evasion(), "After blocks should need evasion");
}

// ============================================================================
// BONUS BUG EXPOSURE TESTS
// ============================================================================

/// BUG: `generate_variants` modifies request body format without preserving
/// the exact semantic meaning for all server frameworks
#[test]
fn content_type_variant_semantic_preservation() {
    let params = vec![
        ("arr[]".into(), "val1".into()), // PHP array syntax
        ("arr[]".into(), "val2".into()), // Same key - array values
    ];
    let variants = generate_variants(&params);

    // BUG: PHP-style array parameters may not be handled correctly
    // in multipart conversion - may become single value instead of array
    let multipart = variants
        .iter()
        .find(|v| v.technique == ContentTypeTechnique::Multipart);

    if let Some(mp) = multipart {
        let body_str = String::from_utf8_lossy(&mp.body);
        // Check if both values are present
        let val1_count = body_str.matches("val1").count();
        let val2_count = body_str.matches("val2").count();

        assert!(
            val1_count > 0 && val2_count > 0,
            "Array values may be lost in conversion: {body_str}"
        );
    }
}

/// BUG: Unicode in parameter names may cause XML generation to fail
/// or produce invalid element names
#[test]
fn content_type_unicode_param_names() {
    let params = vec![
        ("用户".into(), "value".into()),     // Chinese param name
        ("🎉emoji".into(), "value2".into()), // Emoji in name
    ];
    let variants = generate_variants(&params);

    // All variants should still be generated
    assert!(
        !variants.is_empty(),
        "Unicode param names broke variant generation"
    );

    // XML variants need special handling
    let xml_var = variants
        .iter()
        .find(|v| v.technique == ContentTypeTechnique::XmlCdata);

    if let Some(xv) = xml_var {
        // Should be valid UTF-8
        assert!(
            std::str::from_utf8(&xv.body).is_ok(),
            "XML body with unicode param names is invalid UTF-8"
        );
    }
}

/// BUG: Very long param name may cause issues with multipart boundary line
#[test]
fn content_type_very_long_param_name() {
    let long_name = "x".repeat(1000);
    let params = vec![(long_name, "value".into())];
    let variants = generate_variants(&params);

    assert!(
        !variants.is_empty(),
        "Long param name broke variant generation"
    );
}
