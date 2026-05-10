//! Integration tests for the full `WAFrift` evasion pipeline.

use wafrift_core::config::EvasionConfig;
use wafrift_core::encoding;
use wafrift_core::host_state::HostState;
use wafrift_core::strategy::evade;
use wafrift_core::*;

#[test]
fn clean_state_only_fingerprint() {
    let req = Request::post("https://example.com", b"q=test".to_vec())
        .header("Content-Type", "application/x-www-form-urlencoded");
    let state = HostState::default();
    let config = EvasionConfig::default();
    let result = evade(&req, &state, &config);
    assert!(
        result
            .techniques
            .iter()
            .all(|t| matches!(t, Technique::UserAgentRotation))
    );
}

#[test]
fn blocks_increase_escalation() {
    let mut state = HostState::default();
    for _ in 0..10 {
        state.record_block();
    }
    let req = Request::post("https://example.com", b"q=test".to_vec())
        .header("Content-Type", "application/x-www-form-urlencoded");
    let config = EvasionConfig::default();
    let result = evade(&req, &state, &config);
    assert!(
        result.technique_count() >= 2,
        "heavy evasion should use 2+ techniques"
    );
}

#[test]
fn all_features_disabled_no_techniques() {
    let mut state = HostState::default();
    for _ in 0..10 {
        state.record_block();
    }
    let req = Request::post("https://example.com", b"q=test".to_vec());
    let config = EvasionConfig {
        encoding_enabled: false,
        grammar_mutations: false,
        header_obfuscation: false,
        content_type_switching: false,
        fingerprint_rotation: false,
        smuggling_enabled: false,
        h2_evasion_enabled: false,
        max_attempts: 0,
        insecure_tls: false,
        proxies: vec![],
        origin_bypass: std::collections::HashMap::new(),
        body_padding_bytes: 0,
    };
    let result = evade(&req, &state, &config);
    // Smuggling/H2 metadata may still be applied (no config flag yet)
    // But encoding, grammar, headers, content-type should all be off
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
    assert!(
        !result
            .techniques
            .iter()
            .any(|t| matches!(t, Technique::HeaderObfuscation(_)))
    );
    assert!(
        !result
            .techniques
            .iter()
            .any(|t| matches!(t, Technique::ContentTypeSwitch(_)))
    );
}

#[test]
fn encoding_all_strategies_nonempty() {
    let payload = "' OR 1=1--";
    for &strategy in encoding::all_strategies() {
        let encoded = encoding::encode(payload, strategy).unwrap();
        assert!(!encoded.is_empty(), "{strategy:?} produced empty");
    }
}

#[test]
fn layered_encoding_differs() {
    let payload = "test";
    let single = encoding::encode(payload, encoding::Strategy::UrlEncode).unwrap();
    let layered = encoding::encode_layered(
        payload,
        &[
            encoding::Strategy::UrlEncode,
            encoding::Strategy::DoubleUrlEncode,
        ],
    )
    .unwrap();
    assert_ne!(single, layered);
}

#[test]
fn content_type_variants_nonempty() {
    let params = vec![("q".to_string(), "test".to_string())];
    let variants = wafrift_core::content_type::generate_variants(&params);
    assert!(!variants.is_empty());
}

#[test]
fn grammar_classify_sql() {
    assert_eq!(
        wafrift_core::grammar::classify("' OR 1=1--"),
        wafrift_core::grammar::PayloadType::Sql
    );
}

#[test]
fn grammar_classify_xss() {
    assert_eq!(
        wafrift_core::grammar::classify("<script>alert(1)</script>"),
        wafrift_core::grammar::PayloadType::Xss
    );
}

#[test]
fn grammar_mutate_sql_produces_variants() {
    let mutations = wafrift_core::grammar::mutate("' OR 1=1--", 5);
    assert!(!mutations.is_empty());
}

#[test]
fn smuggling_payloads_generated() {
    let p1 = wafrift_core::smuggling::cl_te("example.com", "GET / HTTP/1.1\r\n").unwrap();
    let p2 = wafrift_core::smuggling::te_cl("example.com", "GET / HTTP/1.1\r\n").unwrap();
    let p3 = wafrift_core::smuggling::cl_zero("example.com", "GET / HTTP/1.1\r\n").unwrap();
    assert!(!p1.raw_bytes.is_empty());
    assert!(!p2.raw_bytes.is_empty());
    assert!(!p3.raw_bytes.is_empty());
}

#[test]
fn h2_evasions_generated() {
    let evasions = wafrift_core::h2_evasion::all_evasions("/admin", "example.com").unwrap();
    assert!(!evasions.is_empty());
}

#[test]
fn waf_detect_cloudflare() {
    let headers = vec![
        ("server".to_string(), "cloudflare".to_string()),
        ("cf-ray".to_string(), "abc123".to_string()),
    ];
    let result = wafrift_core::waf_detect::detect(403, &headers, b"blocked");
    assert!(!result.is_empty(), "should detect Cloudflare");
}

#[test]
fn evasion_result_display() {
    let result = EvasionResult::new(
        Request::get("https://example.com"),
        vec![
            Technique::GrammarMutation("sql".into()),
            Technique::PayloadEncoding("url".into()),
        ],
        "test".into(),
    );
    let s = result.to_string();
    assert!(s.contains('%'));
    assert!(result.confidence > 0.3);
}

#[test]
fn encoding_aggressiveness_ordering() {
    let mild = encoding::aggressiveness(encoding::Strategy::CaseAlternation);
    let aggressive = encoding::aggressiveness(encoding::Strategy::ChunkedSplit);
    assert!(
        mild < aggressive,
        "case alternation should be less aggressive than chunked split"
    );
}

#[test]
fn host_state_tracks_blocks() {
    let mut state = HostState::default();
    assert!(!state.escalation_level().needs_evasion());
    state.record_block();
    state.record_block();
    assert!(state.escalation_level().needs_evasion());
}
