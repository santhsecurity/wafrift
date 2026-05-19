//! Empty chain — when the evasion plan has zero encoders and all config
//! layers are disabled, `evade_adaptive` must return the input unchanged
//! and report that no evasion was applied.

use wafrift_evolution::advisor::EvasionPlan;
use wafrift_strategy::{HostState, strategy::evade_adaptive};
use wafrift_types::{EvasionConfig, Request, Technique};

// ── Positive: all-disabled config + empty plan → identity ─────────────────

#[test]
fn empty_chain_returns_input_unchanged() {
    let req = Request::post("https://example.com/api", b"q=test".to_vec())
        .header("Content-Type", "application/x-www-form-urlencoded");
    let state = HostState::default();
    let config = EvasionConfig {
        encoding_enabled: false,
        grammar_mutations: false,
        header_obfuscation: false,
        content_type_switching: false,
        fingerprint_rotation: false,
        smuggling_enabled: false,
        h2_evasion_enabled: false,
        ..EvasionConfig::default()
    };
    let plan = EvasionPlan::default();

    let result = evade_adaptive(&req, &config, &plan, &state);

    assert_eq!(result.request.url, req.url);
    assert_eq!(result.request.method, req.method);
    assert_eq!(result.request.body, req.body);
    assert_eq!(result.request.headers, req.headers);
    assert!(
        result.techniques.is_empty(),
        "empty chain must produce zero techniques, got {:?}",
        result.techniques
    );
    assert_eq!(result.description, "No evasion applied");
}

// ── Negative: encoding enabled with empty plan still leaves body intact ───
// evade_adaptive only encodes what the plan explicitly lists.

#[test]
fn empty_plan_with_encoding_enabled_does_not_mutate() {
    let req = Request::post("https://example.com/api", b"q=test".to_vec())
        .header("Content-Type", "application/x-www-form-urlencoded");
    let state = HostState::default();
    let config = EvasionConfig {
        encoding_enabled: true,
        grammar_mutations: false,
        header_obfuscation: false,
        content_type_switching: false,
        fingerprint_rotation: false,
        smuggling_enabled: false,
        h2_evasion_enabled: false,
        ..EvasionConfig::default()
    };
    let plan = EvasionPlan::default();

    let result = evade_adaptive(&req, &config, &plan, &state);

    assert_eq!(result.request.body, req.body);
    assert!(result.techniques.is_empty());
}

// ── Negative: non-empty plan with disabled config still mutates ───────────
// The plan's encoding strategies are applied regardless of config.encoding_enabled
// in evade_adaptive (the config filter only applies to MCTS result building).

#[test]
fn non_empty_plan_mutates_even_when_config_disabled() {
    let req = Request::post("https://example.com/api", b"q=test".to_vec())
        .header("Content-Type", "application/x-www-form-urlencoded");
    let state = HostState::default();
    let config = EvasionConfig {
        encoding_enabled: false,
        grammar_mutations: false,
        header_obfuscation: false,
        content_type_switching: false,
        fingerprint_rotation: false,
        smuggling_enabled: false,
        h2_evasion_enabled: false,
        ..EvasionConfig::default()
    };
    let plan = EvasionPlan {
        encoding_strategies: vec![wafrift_encoding::encoding::Strategy::UrlEncode],
        ..EvasionPlan::default()
    };

    let result = evade_adaptive(&req, &config, &plan, &state);

    assert_ne!(
        result.request.body, req.body,
        "plan with explicit encoder must mutate body even when config.encoding_enabled is false"
    );
    assert_eq!(result.techniques.len(), 1);
    assert!(matches!(
        &result.techniques[0],
        Technique::PayloadEncoding(s) if s == "UrlEncode"
    ));
}
