//! Adversarial tests for the strategy engine.
//!
//! Tests `evade()` with every escalation level, empty requests, huge bodies,
//! malformed headers, and re-use of successful techniques.

use wafrift_core::{
    EscalationLevel, EvasionConfig, HostState, Request, Technique,
    strategy::{self, CalibrationResult},
};

// ============================================================================
// Escalation Level Tests (12 tests)
// ============================================================================

#[test]
fn evade_none_escalation() {
    let req = Request::post("https://example.com", b"q=test".to_vec());
    let state = HostState::default(); // No blocks
    let config = EvasionConfig::default();
    let result = strategy::evade(&req, &state, &config);

    assert_eq!(state.escalation_level(), EscalationLevel::None);
    // Should only have fingerprint rotation
    assert!(
        result
            .techniques
            .iter()
            .all(|t| matches!(t, Technique::UserAgentRotation))
    );
}

#[test]
fn evade_light_escalation_one_block() {
    let req = Request::post("https://example.com", b"q=test".to_vec());
    let mut state = HostState::default();
    state.record_block();
    let config = EvasionConfig::default();
    let result = strategy::evade(&req, &state, &config);

    assert_eq!(state.escalation_level(), EscalationLevel::Light);
    // Should have encoding and header obfuscation
    assert!(
        result
            .techniques
            .iter()
            .any(|t| matches!(t, Technique::PayloadEncoding(_)))
    );
}

#[test]
fn evade_light_escalation_two_blocks() {
    let req = Request::post("https://example.com", b"q=test".to_vec())
        .header("Content-Type", "application/x-www-form-urlencoded");
    let mut state = HostState::default();
    state.record_block();
    state.record_block();
    let config = EvasionConfig::default();
    let result = strategy::evade(&req, &state, &config);

    assert_eq!(state.escalation_level(), EscalationLevel::Light);
    assert!(
        result
            .techniques
            .iter()
            .any(|t| matches!(t, Technique::HeaderObfuscation(_)))
    );
}

#[test]
fn evade_medium_escalation_three_blocks() {
    let req = Request::post("https://example.com", b"q=test&a=value".to_vec());
    let mut state = HostState::default();
    for _ in 0..3 {
        state.record_block();
    }
    let config = EvasionConfig::default();
    let result = strategy::evade(&req, &state, &config);

    assert_eq!(state.escalation_level(), EscalationLevel::Medium);
    // Should have content type switching
    assert!(
        result
            .techniques
            .iter()
            .any(|t| matches!(t, Technique::ContentTypeSwitch(_)))
    );
}

#[test]
fn evade_medium_escalation_five_blocks() {
    let req = Request::post("https://example.com", b"q=' OR 1=1--".to_vec());
    let mut state = HostState::default();
    for _ in 0..5 {
        state.record_block();
    }
    let config = EvasionConfig::default();
    let result = strategy::evade(&req, &state, &config);

    assert_eq!(state.escalation_level(), EscalationLevel::Medium);
    // Should have grammar mutations
    assert!(
        result
            .techniques
            .iter()
            .any(|t| matches!(t, Technique::GrammarMutation(_)))
    );
}

#[test]
fn evade_heavy_escalation_six_blocks() {
    let req = Request::post("https://example.com", b"q=test".to_vec());
    let mut state = HostState::default();
    for _ in 0..6 {
        state.record_block();
    }
    let config = EvasionConfig::default();
    let result = strategy::evade(&req, &state, &config);

    assert_eq!(state.escalation_level(), EscalationLevel::Heavy);
    // Should have multiple techniques including smuggling/h2 metadata
    assert!(result.techniques.len() >= 3);
}

#[test]
fn evade_heavy_escalation_many_blocks() {
    let req = Request::post("https://example.com", b"q=test".to_vec());
    let mut state = HostState::default();
    for _ in 0..20 {
        state.record_block();
    }
    let config = EvasionConfig::default();
    let result = strategy::evade(&req, &state, &config);

    assert_eq!(state.escalation_level(), EscalationLevel::Heavy);
    // Should include smuggling in heavy mode
    assert!(
        result
            .techniques
            .iter()
            .any(|t| matches!(t, Technique::RequestSmuggling(_)))
    );
}

#[test]
fn escalation_level_transitions() {
    let mut state = HostState::default();
    assert_eq!(state.escalation_level(), EscalationLevel::None);

    state.record_block();
    assert_eq!(state.escalation_level(), EscalationLevel::Light);

    state.record_block();
    assert_eq!(state.escalation_level(), EscalationLevel::Light);

    state.record_block();
    assert_eq!(state.escalation_level(), EscalationLevel::Medium);

    state.record_block();
    state.record_block();
    state.record_block(); // 6 blocks total
    assert_eq!(state.escalation_level(), EscalationLevel::Heavy);
}

#[test]
fn escalation_methods() {
    assert!(!EscalationLevel::None.needs_evasion());
    assert!(EscalationLevel::Light.needs_evasion());
    assert!(EscalationLevel::Medium.needs_evasion());
    assert!(EscalationLevel::Heavy.needs_evasion());

    assert!(!EscalationLevel::None.use_grammar());
    assert!(!EscalationLevel::Light.use_grammar());
    assert!(EscalationLevel::Medium.use_grammar());
    assert!(EscalationLevel::Heavy.use_grammar());

    assert!(!EscalationLevel::None.use_content_type());
    assert!(!EscalationLevel::Light.use_content_type());
    assert!(EscalationLevel::Medium.use_content_type());
    assert!(EscalationLevel::Heavy.use_content_type());

    assert!(!EscalationLevel::None.use_advanced());
    assert!(!EscalationLevel::Light.use_advanced());
    assert!(!EscalationLevel::Medium.use_advanced());
    assert!(EscalationLevel::Heavy.use_advanced());
}

#[test]
fn evade_with_all_config_disabled() {
    let req = Request::post("https://example.com", b"q=test".to_vec());
    let mut state = HostState::default();
    for _ in 0..10 {
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
        mutate_url: false,
        max_attempts: 5,
        insecure_tls: false,
        proxies: vec![],
        origin_bypass: std::collections::HashMap::new(),
        body_padding_bytes: 0,
    };
    let result = strategy::evade(&req, &state, &config);

    // Even with heavy escalation and all disabled, should have no techniques
    // (or just smuggling/h2 which don't depend on those flags)
    assert!(
        !result
            .techniques
            .iter()
            .any(|t| matches!(t, Technique::PayloadEncoding(_)))
    );
    assert!(
        !result
            .techniques
            .iter()
            .any(|t| matches!(t, Technique::GrammarMutation(_)))
    );
}

#[test]
fn evade_with_encoding_only() {
    let req = Request::post("https://example.com", b"q=test".to_vec());
    let mut state = HostState::default();
    state.record_block();
    let config = EvasionConfig::encoding_only();
    let result = strategy::evade(&req, &state, &config);

    assert!(
        result
            .techniques
            .iter()
            .any(|t| matches!(t, Technique::PayloadEncoding(_)))
    );
    assert!(
        !result
            .techniques
            .iter()
            .any(|t| matches!(t, Technique::HeaderObfuscation(_)))
    );
}

#[test]
fn evade_maximum_config() {
    let req = Request::post("https://example.com", b"q=test".to_vec());
    let mut state = HostState::default();
    for _ in 0..10 {
        state.record_block();
    }
    let config = EvasionConfig::maximum();
    let result = strategy::evade(&req, &state, &config);

    // Maximum config should produce many techniques
    assert!(result.techniques.len() >= 3);
}

// ============================================================================
// Empty Request Tests (8 tests)
// ============================================================================

#[test]
fn evade_empty_body() {
    let req = Request::post("https://example.com", b"");
    let mut state = HostState::default();
    state.record_block();
    let config = EvasionConfig::default();
    let result = strategy::evade(&req, &state, &config);

    // Should not panic with empty body
    assert!(
        result
            .request
            .body
            .as_ref()
            .is_none_or(std::vec::Vec::is_empty)
    );
}

#[test]
fn evade_get_request_no_body() {
    let req = Request::get("https://example.com");
    let mut state = HostState::default();
    state.record_block();
    let config = EvasionConfig::default();
    let result = strategy::evade(&req, &state, &config);

    // GET request with no body should still apply headers
    assert!(
        result
            .techniques
            .iter()
            .any(|t| matches!(t, Technique::UserAgentRotation))
    );
}

#[test]
fn evade_delete_request_no_body() {
    let req = Request::delete("https://example.com/api/1");
    let mut state = HostState::default();
    state.record_block();
    let config = EvasionConfig::default();
    let result = strategy::evade(&req, &state, &config);

    // DELETE request should still get fingerprint rotation
    assert!(
        result
            .techniques
            .iter()
            .any(|t| matches!(t, Technique::UserAgentRotation))
    );
}

#[test]
fn evade_no_headers() {
    let req = Request::post("https://example.com", b"test".to_vec());
    let mut state = HostState::default();
    state.record_block();
    let config = EvasionConfig::default();
    let result = strategy::evade(&req, &state, &config);

    // Should still work without headers
    assert!(result.request.get_header("User-Agent").is_some());
}

#[test]
fn evade_empty_url() {
    let req = Request::post("", b"test".to_vec());
    let mut state = HostState::default();
    state.record_block();
    let config = EvasionConfig::default();
    let result = strategy::evade(&req, &state, &config);

    // Should not panic with empty URL
    assert_eq!(result.request.url, "");
}

#[test]
fn evade_no_content_type_header() {
    let req = Request::post("https://example.com", b"q=test");
    let mut state = HostState::default();
    for _ in 0..4 {
        state.record_block();
    }
    let config = EvasionConfig::default();
    let _result = strategy::evade(&req, &state, &config);

    // Medium escalation without Content-Type should still work
    assert_eq!(state.escalation_level(), EscalationLevel::Medium);
}

#[test]
fn evade_put_empty_body() {
    let req = Request::put("https://example.com/api", b"");
    let mut state = HostState::default();
    state.record_block();
    let config = EvasionConfig::default();
    let result = strategy::evade(&req, &state, &config);

    // PUT with empty body should not panic
    assert!(
        result
            .request
            .body
            .as_ref()
            .is_none_or(std::vec::Vec::is_empty)
    );
}

#[test]
fn evade_custom_method_no_body() {
    let req = Request::with_method("CUSTOM", "https://example.com");
    let mut state = HostState::default();
    state.record_block();
    let config = EvasionConfig::default();
    let result = strategy::evade(&req, &state, &config);

    // Custom method should still get techniques
    assert!(
        result
            .techniques
            .iter()
            .any(|t| matches!(t, Technique::UserAgentRotation))
    );
}

// ============================================================================
// Huge Body Tests (6 tests)
// ============================================================================

#[test]
fn evade_huge_body_light() {
    let huge_body = "a".repeat(100000);
    let req = Request::post("https://example.com", huge_body.clone().into_bytes());
    let mut state = HostState::default();
    state.record_block();
    let config = EvasionConfig::default();
    let result = strategy::evade(&req, &state, &config);

    // Should handle huge body without crashing (encoding may change size)
    assert!(!result.request.body.as_ref().unwrap().is_empty());
}

#[test]
fn evade_huge_body_medium() {
    let huge_body = "q=test&".repeat(10000);
    let req = Request::post("https://example.com", huge_body.into_bytes());
    let mut state = HostState::default();
    for _ in 0..4 {
        state.record_block();
    }
    let config = EvasionConfig::default();
    let result = strategy::evade(&req, &state, &config);

    assert_eq!(state.escalation_level(), EscalationLevel::Medium);
    assert!(!result.request.body.as_ref().unwrap().is_empty());
}

#[test]
fn evade_huge_body_heavy() {
    let huge_body = "SELECT ".repeat(10000);
    let req = Request::post("https://example.com", huge_body.into_bytes());
    let mut state = HostState::default();
    for _ in 0..10 {
        state.record_block();
    }
    let config = EvasionConfig::default();
    let result = strategy::evade(&req, &state, &config);

    assert_eq!(state.escalation_level(), EscalationLevel::Heavy);
    assert!(!result.techniques.is_empty());
}

#[test]
fn evade_body_with_null_bytes() {
    let mut body = vec![0u8; 1000];
    body.extend_from_slice(b"test");
    let req = Request::post("https://example.com", body);
    let mut state = HostState::default();
    state.record_block();
    let config = EvasionConfig::default();
    let result = strategy::evade(&req, &state, &config);

    // Should handle null bytes in body
    assert!(result.request.body.as_ref().unwrap().contains(&0));
}

#[test]
fn evade_body_with_unicode() {
    let body = "日本語".repeat(1000);
    let req = Request::post("https://example.com", body.into_bytes());
    let mut state = HostState::default();
    state.record_block();
    let config = EvasionConfig::default();
    let result = strategy::evade(&req, &state, &config);

    // Should handle unicode body
    assert!(!result.request.body.as_ref().unwrap().is_empty());
}

#[test]
fn evade_binary_body() {
    let body: Vec<u8> = (0..=255).cycle().take(10000).collect();
    let req = Request::post("https://example.com", body.clone());
    let mut state = HostState::default();
    state.record_block();
    let config = EvasionConfig::default();
    let result = strategy::evade(&req, &state, &config);

    // Should handle binary body (encoding may change size)
    assert!(!result.request.body.as_ref().unwrap().is_empty());
}

// ============================================================================
// Malformed Header Tests (8 tests)
// ============================================================================

#[test]
fn evade_malformed_header_names() {
    let req = Request::post("https://example.com", b"test".to_vec())
        .header("", "empty-name")
        .header("\n\r", "crlf-name")
        .header("Normal-Header", "value");
    let mut state = HostState::default();
    state.record_block();
    let config = EvasionConfig::default();
    let result = strategy::evade(&req, &state, &config);

    // Should not panic with malformed headers
    assert!(!result.request.headers.is_empty());
}

#[test]
fn evade_malformed_header_values() {
    let req = Request::post("https://example.com", b"test".to_vec())
        .header("Content-Type", "")
        .header("X-Test", "\x00\x01\x02")
        .header("X-Unicode", "日本語");
    let mut state = HostState::default();
    state.record_block();
    let config = EvasionConfig::default();
    let result = strategy::evade(&req, &state, &config);

    // Should handle weird header values
    assert!(result.request.get_header("Content-Type").is_some());
}

#[test]
fn evade_duplicate_headers() {
    let req = Request::post("https://example.com", b"test".to_vec())
        .header("X-Custom", "value1")
        .header("X-Custom", "value2")
        .header("X-Custom", "value3");
    let mut state = HostState::default();
    state.record_block();
    let config = EvasionConfig::default();
    let result = strategy::evade(&req, &state, &config);

    // Should handle duplicate headers
    let custom_headers = result.request.get_headers("X-Custom");
    assert!(!custom_headers.is_empty());
}

#[test]
fn evade_very_long_header_value() {
    let long_value = "a".repeat(10000);
    let req = Request::post("https://example.com", b"test".to_vec()).header("X-Long", &long_value);
    let mut state = HostState::default();
    state.record_block();
    let config = EvasionConfig::default();
    let result = strategy::evade(&req, &state, &config);

    // Should handle very long header values
    assert!(result.request.get_header("X-Long").is_some());
}

#[test]
fn evade_many_headers() {
    let mut headers = vec![];
    for i in 0..100 {
        headers.push((format!("X-Header-{i}"), format!("value{i}")));
    }
    let mut req = Request::post("https://example.com", b"test".to_vec());
    req.headers = headers;
    let mut state = HostState::default();
    state.record_block();
    let config = EvasionConfig::default();
    let result = strategy::evade(&req, &state, &config);

    // Should handle many headers
    assert!(result.request.headers.len() >= 100);
}

#[test]
fn evade_content_type_case_variations() {
    for ct in [
        "content-type",
        "Content-Type",
        "CONTENT-TYPE",
        "CoNtEnT-TyPe",
    ] {
        let req =
            Request::post("https://example.com", b"test".to_vec()).header(ct, "application/json");
        let mut state = HostState::default();
        state.record_block();
        let config = EvasionConfig::default();
        let result = strategy::evade(&req, &state, &config);

        // Should find Content-Type regardless of case
        assert!(result.request.content_type().is_some());
    }
}

#[test]
fn evade_special_chars_in_url() {
    let urls = [
        "https://example.com/path?a=1&b=2",
        "https://example.com/path%20with%20spaces",
        "https://example.com/path#fragment",
        "https://example.com:8080/path",
        "https://user:pass@example.com/path",
    ];

    for url in &urls {
        let req = Request::post(*url, b"test".to_vec());
        let mut state = HostState::default();
        state.record_block();
        let config = EvasionConfig::default();
        let result = strategy::evade(&req, &state, &config);

        assert_eq!(&result.request.url, *url);
    }
}

#[test]
fn evade_weird_url_formats() {
    let urls = [
        "http://example.com",
        "https://example.com",
        "https://example.com/",
        "https://example.com//double//slash",
        "https://example.com/path?",
        "https://example.com/path?&",
    ];

    for url in &urls {
        let req = Request::post(*url, b"test".to_vec());
        let mut state = HostState::default();
        state.record_block();
        let config = EvasionConfig::default();
        let result = strategy::evade(&req, &state, &config);

        // Should not panic with weird URLs
        assert!(!result.request.url.is_empty());
    }
}

// ============================================================================
// Successful Technique Re-use Tests (8 tests)
// ============================================================================

#[test]
fn evade_reuses_last_success_encoding() {
    let req = Request::post("https://example.com", b"q=test".to_vec());
    let mut state = HostState::default();
    state.record_success(Technique::PayloadEncoding("CaseAlternation".to_string()));

    let config = EvasionConfig::default();
    let result = strategy::evade(&req, &state, &config);

    // Should include case alternation technique
    assert!(
        result
            .techniques
            .iter()
            .any(|t| matches!(t, Technique::PayloadEncoding(_)))
    );
}

#[test]
fn evade_reuse_nonexistent_encoding() {
    let req = Request::post("https://example.com", b"q=test".to_vec());
    let mut state = HostState::default();
    // Use a non-existent encoding name
    state.record_success(Technique::PayloadEncoding("NonExistent".to_string()));

    let config = EvasionConfig::default();
    let result = strategy::evade(&req, &state, &config);

    // Should not panic with invalid encoding name
    assert!(!result.request.body.as_ref().unwrap().is_empty());
}

#[test]
fn evade_reuse_with_different_technique_types() {
    let techniques = [
        Technique::PayloadEncoding("UrlEncode".to_string()),
        Technique::ContentTypeSwitch("Multipart".to_string()),
        Technique::HeaderObfuscation("CaseMixing".to_string()),
        Technique::GrammarMutation("sql_tautology".to_string()),
    ];

    for tech in &techniques {
        let req = Request::post("https://example.com", b"q=test".to_vec());
        let mut state = HostState::default();
        state.record_success(tech.clone());

        let config = EvasionConfig::default();
        let result = strategy::evade(&req, &state, &config);

        // Should not panic with any technique type
        assert!(!result.techniques.is_empty());
    }
}

#[test]
fn evade_success_tracking_multiple() {
    let mut state = HostState::default();

    // Record multiple successes
    state.record_success(Technique::PayloadEncoding("CaseAlternation".to_string()));
    state.record_success(Technique::PayloadEncoding("CaseAlternation".to_string()));
    state.record_success(Technique::PayloadEncoding("DoubleUrlEncode".to_string()));

    assert_eq!(state.successes, 3);
    assert_eq!(
        state.last_success,
        Some(Technique::PayloadEncoding("DoubleUrlEncode".to_string()))
    );
}

#[test]
fn evade_no_success_initially() {
    let req = Request::post("https://example.com", b"q=test".to_vec());
    let state = HostState::default();

    assert!(state.last_success.is_none());

    let config = EvasionConfig::default();
    let result = strategy::evade(&req, &state, &config);

    // Should work fine without prior success
    assert!(
        result
            .techniques
            .iter()
            .any(|t| matches!(t, Technique::UserAgentRotation))
    );
}

#[test]
fn evade_success_then_block() {
    let mut state = HostState::default();

    state.record_success(Technique::PayloadEncoding("UrlEncode".to_string()));
    assert_eq!(state.successes, 1);

    state.record_block();
    assert_eq!(state.blocks, 1);

    // Still has last_success recorded
    assert!(state.last_success.is_some());
}

#[test]
fn evade_best_technique_calculation() {
    let mut state = HostState::default();

    // Need at least 2 attempts for best_technique
    // record_success creates a technique stat entry with format "{:?}"
    state.record_success(Technique::PayloadEncoding("TechniqueA".to_string()));
    state.record_success(Technique::PayloadEncoding("TechniqueA".to_string()));

    // For block_for, we need to use the string representation
    let tech_a_repr = Technique::PayloadEncoding("TechniqueA".to_string()).to_string();
    state.record_block_for(&tech_a_repr);

    // Now TechniqueA has 2 successes and 3 attempts = 66% success rate
    let best = state.best_technique();
    assert_eq!(best, Some(tech_a_repr.as_str()));
}

#[test]
fn evade_technique_success_rate() {
    let mut state = HostState::default();

    assert_eq!(state.technique_success_rate("NonExistent"), 0.0);

    let tech = Technique::PayloadEncoding("TestTech".to_string());
    let tech_repr = tech.to_string();

    state.record_success(tech.clone());
    state.record_success(tech.clone());
    state.record_block_for(&tech_repr);

    // 2 successes out of 3 attempts (record_success also increments attempts)
    let expected_rate = 2.0 / 3.0;
    assert_eq!(state.technique_success_rate(&tech_repr), expected_rate);
}

// ============================================================================
// Calibration Tests (6 tests)
// ============================================================================

#[test]
fn calibration_waf_present_403() {
    assert_eq!(
        strategy::analyze_calibration(403, b"Forbidden"),
        CalibrationResult::WafPresent
    );
}

#[test]
fn calibration_waf_present_406() {
    assert_eq!(
        strategy::analyze_calibration(406, b"Not Acceptable"),
        CalibrationResult::WafPresent
    );
}

#[test]
fn calibration_waf_present_429() {
    assert_eq!(
        strategy::analyze_calibration(429, b"Too Many Requests"),
        CalibrationResult::WafPresent
    );
}

#[test]
fn calibration_no_waf_200() {
    assert_eq!(
        strategy::analyze_calibration(200, b"OK"),
        CalibrationResult::NoWaf
    );
}

#[test]
fn calibration_no_waf_404() {
    assert_eq!(
        strategy::analyze_calibration(404, b"Not Found"),
        CalibrationResult::NoWaf
    );
}

#[test]
fn calibration_uncertain_redirects_and_others() {
    // Redirects are uncertain
    for code in [301, 302, 307, 308] {
        assert_eq!(
            strategy::analyze_calibration(code, b"Redirect"),
            CalibrationResult::Uncertain
        );
    }
    // Other codes like 201 Created or 500 Server Error are also uncertain
    assert_eq!(
        strategy::analyze_calibration(201, b"Created"),
        CalibrationResult::Uncertain
    );
    assert_eq!(
        strategy::analyze_calibration(500, b"Server Error"),
        CalibrationResult::Uncertain
    );
}

// ============================================================================
// Evasion Result Tests (4 tests)
// ============================================================================

#[test]
fn evasion_result_confidence_calculation() {
    let req = Request::post("https://example.com", b"q=test".to_vec());
    let mut state = HostState::default();
    for _ in 0..10 {
        state.record_block();
    }
    let config = EvasionConfig::default();
    let result = strategy::evade(&req, &state, &config);

    // Heavy escalation should have high confidence
    assert!(result.confidence > 0.5);
}

#[test]
fn evasion_result_technique_count() {
    let req = Request::post("https://example.com", b"q=test".to_vec());
    let mut state = HostState::default();
    for _ in 0..10 {
        state.record_block();
    }
    let config = EvasionConfig::default();
    let result = strategy::evade(&req, &state, &config);

    assert!(result.technique_count() >= 3);
}

#[test]
fn evasion_result_uses_grammar() {
    let req = Request::post("https://example.com", b"q=' OR 1=1--".to_vec());
    let mut state = HostState::default();
    for _ in 0..5 {
        state.record_block();
    }
    let config = EvasionConfig::default();
    let result = strategy::evade(&req, &state, &config);

    assert!(result.uses_grammar());
}

#[test]
fn evasion_result_uses_smuggling_in_heavy() {
    let req = Request::post("https://example.com", b"q=test".to_vec());
    let mut state = HostState::default();
    for _ in 0..10 {
        state.record_block();
    }
    let config = EvasionConfig::default();
    let result = strategy::evade(&req, &state, &config);

    assert!(result.uses_smuggling());
}

// Total: 52 tests
