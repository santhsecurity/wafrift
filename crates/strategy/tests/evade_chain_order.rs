//! Encoding chain order — assert that `evade_adaptive` applies encoders
//! in the order declared by `EvasionPlan.encoding_strategies` and that
//! reordering the list produces a different payload.

use wafrift_encoding::encoding::Strategy;
use wafrift_evolution::advisor::EvasionPlan;
use wafrift_strategy::{HostState, strategy::evade_adaptive};
use wafrift_types::{EvasionConfig, Request, Technique};

fn isolated_config() -> EvasionConfig {
    EvasionConfig {
        fingerprint_rotation: false,
        grammar_mutations: false,
        header_obfuscation: false,
        content_type_switching: false,
        smuggling_enabled: false,
        h2_evasion_enabled: false,
        ..EvasionConfig::default()
    }
}

// ── Positive: ordered [A, B] vs [B, A] produce different bodies ───────────

#[test]
fn chain_order_ab_produces_different_output_than_ba() {
    let req = Request::post("https://example.com/api", b"q=test".to_vec())
        .header("Content-Type", "application/x-www-form-urlencoded");
    let state = HostState::default();
    let config = isolated_config();

    let plan_ab = EvasionPlan {
        encoding_strategies: vec![Strategy::DoubleUrlEncode, Strategy::UnicodeEncode],
        ..EvasionPlan::default()
    };
    let plan_ba = EvasionPlan {
        encoding_strategies: vec![Strategy::UnicodeEncode, Strategy::DoubleUrlEncode],
        ..EvasionPlan::default()
    };

    let res_ab = evade_adaptive(&req, &config, &plan_ab, &state);
    let res_ba = evade_adaptive(&req, &config, &plan_ba, &state);

    let body_ab = String::from_utf8(res_ab.request.body.clone().unwrap()).unwrap();
    let body_ba = String::from_utf8(res_ba.request.body.clone().unwrap()).unwrap();

    assert_ne!(
        body_ab, body_ba,
        "swapped encoder order must produce different output"
    );

    let tech_ab: Vec<_> = res_ab
        .techniques
        .iter()
        .map(|t| format!("{:?}", t))
        .collect();
    let tech_ba: Vec<_> = res_ba
        .techniques
        .iter()
        .map(|t| format!("{:?}", t))
        .collect();
    assert_eq!(
        tech_ab,
        vec![
            "PayloadEncoding(\"DoubleUrlEncode\")",
            "PayloadEncoding(\"UnicodeEncode\")"
        ]
    );
    assert_eq!(
        tech_ba,
        vec![
            "PayloadEncoding(\"UnicodeEncode\")",
            "PayloadEncoding(\"DoubleUrlEncode\")"
        ]
    );
}

// ── Positive: first encoder in list is applied first ──────────────────────

#[test]
fn chain_order_first_encoder_runs_first() {
    let req = Request::post("https://example.com/api", b"q=test".to_vec())
        .header("Content-Type", "application/x-www-form-urlencoded");
    let state = HostState::default();
    let config = isolated_config();

    let plan = EvasionPlan {
        encoding_strategies: vec![Strategy::UrlEncode, Strategy::HexEncode],
        ..EvasionPlan::default()
    };

    let result = evade_adaptive(&req, &config, &plan, &state);
    let body = String::from_utf8(result.request.body.clone().unwrap()).unwrap();

    // UrlEncode then HexEncode → final output is pure hex digits.
    assert!(
        body.chars().all(|c| c.is_ascii_hexdigit()),
        "hex-encoded body should be all hex chars, got: {}",
        body
    );

    let techs: Vec<_> = result.techniques.iter().collect();
    assert_eq!(techs.len(), 2);
    assert!(matches!(&techs[0], Technique::PayloadEncoding(s) if s == "UrlEncode"));
    assert!(matches!(&techs[1], Technique::PayloadEncoding(s) if s == "HexEncode"));
}

// ── Negative: empty strategy list leaves body untouched ───────────────────

#[test]
fn empty_encoding_chain_leaves_body_unchanged() {
    let req = Request::post("https://example.com/api", b"q=test".to_vec())
        .header("Content-Type", "application/x-www-form-urlencoded");
    let state = HostState::default();
    let config = isolated_config();
    let plan = EvasionPlan::default();

    let result = evade_adaptive(&req, &config, &plan, &state);

    assert_eq!(result.request.body, req.body);
    assert!(
        !result
            .techniques
            .iter()
            .any(|t| matches!(t, Technique::PayloadEncoding(_))),
        "empty plan must produce zero encoding techniques"
    );
}

// ── Negative: single encoder then empty rest still mutates ────────────────

#[test]
fn single_encoder_in_chain_mutates_once() {
    let req = Request::post("https://example.com/api", b"q=test".to_vec())
        .header("Content-Type", "application/x-www-form-urlencoded");
    let state = HostState::default();
    let config = isolated_config();

    let plan = EvasionPlan {
        encoding_strategies: vec![Strategy::UrlEncode],
        ..EvasionPlan::default()
    };

    let result = evade_adaptive(&req, &config, &plan, &state);

    assert_ne!(
        result.request.body,
        req.body,
        "single encoder must still mutate the body"
    );
    assert_eq!(result.techniques.len(), 1);
}
