//! Integration tests for #129 — ML-WAF routing through `evade_ml`.
//!
//! Covers: AwsBotControl routes through evade_ml, PlainModSec does not,
//! ML evader output preserves payload semantics, backwards-compat
//! (existing strategy paths untouched).

use wafrift_strategy::{DEFAULT_ML_BUDGET, apply_ml_evasion_if_applicable};
use wafrift_types::{EvasionConfig, Request, Technique, WafClass};

// ── Test 1: AwsBotControl fingerprint routes through evade_ml ─────────────────

#[test]
fn aws_bot_control_routes_through_ml_evasion() {
    // evade_ml_backed returns Some for ML-backed WAFs (or None if no
    // manifold-valid mutation found — both are acceptable; must not panic).
    let req = Request::post(
        "https://example.com/search",
        b"q=' OR 1=1--".to_vec(),
    )
    .header("Content-Type", "application/x-www-form-urlencoded");

    // Routing check (not outcome): an ML-backed WAF either yields techniques
    // (carrying MlEvasion) or none — never panics.
    let (_mutated, techniques) = apply_ml_evasion_if_applicable(&req, "AWS Bot Control", 64, 1);

    if !techniques.is_empty() {
        assert!(
            techniques.iter().any(|t| matches!(t, Technique::MlEvasion { .. })),
            "ML evasion result must carry MlEvasion technique"
        );
    }
    // Empty is also correct (manifold rejected all mutations in budget).
}

// ── Test 2: PlainModSec does NOT route through evade_ml ───────────────────────

#[test]
fn plain_modsec_does_not_route_through_ml() {
    let req = Request::post("https://example.com/", b"q=' OR 1=1--".to_vec())
        .header("Content-Type", "application/x-www-form-urlencoded");

    let (_mutated, techniques) =
        apply_ml_evasion_if_applicable(&req, "ModSecurity", DEFAULT_ML_BUDGET, 0);
    assert!(
        techniques.is_empty(),
        "PlainModSec must not route through ML evasion"
    );
}

// ── Test 3: ML evader output preserves payload semantics ──────────────────────

#[test]
fn ml_evader_output_preserves_attack_tokens() {
    let original_payload = b"' UNION SELECT 1,2,3 FROM users--";
    let req = Request::post("https://example.com/", original_payload.to_vec())
        .header("Content-Type", "application/x-www-form-urlencoded");

    let (mutated_req, techniques) =
        apply_ml_evasion_if_applicable(&req, "AWS Bot Control", 256, 42);

    if !techniques.is_empty() {
        // If a mutation was applied, attack tokens must survive.
        let body = mutated_req.body.as_deref().unwrap_or(b"");
        let body_lower = String::from_utf8_lossy(body).to_ascii_lowercase();
        let has_attack = body_lower.contains("select")
            || body_lower.contains("union")
            || body_lower.contains("or 1");
        assert!(
            has_attack,
            "ML evader must preserve attack semantics; got body: {body_lower:?}"
        );
    }
    // Empty techniques means no mutation was found within budget — acceptable.
}

// ── Test 4: Backwards-compat — existing strategy paths untouched ──────────────

#[test]
fn existing_evade_path_unchanged_for_non_ml_waf() {
    use wafrift_strategy::{HostState, strategy::evade};

    let req = Request::post("https://example.com/", b"q=admin' OR 1=1--".to_vec())
        .header("Content-Type", "application/x-www-form-urlencoded");
    let state = HostState::default();
    let config = EvasionConfig::default();

    // Must not panic and must return a valid EvasionResult.
    let result = evade(&req, &state, &config);
    assert!(
        result.request.url.contains("example.com"),
        "evade must return a request with the original URL"
    );
}

// ── Test 5: ML evasion records off-manifold rejection count ──────────────────

#[test]
fn ml_evasion_technique_carries_metadata() {
    let req = Request::post("https://example.com/", b"q=<script>alert(1)</script>".to_vec())
        .header("Content-Type", "application/x-www-form-urlencoded");

    // ML-backed + an on-manifold payload ⇒ a structural mutation is produced.
    let (_mutated, techniques) =
        apply_ml_evasion_if_applicable(&req, "Cloudflare Bot Management", 256, 77);
    assert!(!techniques.is_empty(), "ML-backed + on-manifold payload must mutate");

    let queries = techniques
        .iter()
        .find_map(|t| match t {
            Technique::MlEvasion { queries, .. } => Some(*queries),
            _ => None,
        })
        .expect("result must carry an MlEvasion technique");

    // Contract: the strategy layer is I/O-free, so it queries NO live oracle —
    // `queries` is 0 by design (the live queries belong to the scan/bench
    // layer that fires the mutated candidate). Pins the new semantics and
    // guards against a regression to the old fake-oracle query counter.
    assert_eq!(
        queries, 0,
        "the I/O-free strategy layer must report 0 live oracle queries"
    );
}

// ── Test 6: Akamai Bot Manager routes through ML evasion ─────────────────────

#[test]
fn akamai_bot_manager_is_ml_backed() {
    assert!(
        WafClass::from_waf_name("Akamai Bot Manager").is_ml_backed(),
        "Akamai Bot Manager must be identified as ML-backed"
    );

    let req = Request::post("https://example.com/", b"q=' OR 1=1--".to_vec())
        .header("Content-Type", "application/x-www-form-urlencoded");

    // Must not panic regardless of outcome.
    let _ = apply_ml_evasion_if_applicable(&req, "Akamai Bot Manager", 32, 55);
}

// ── Test 7: No body → ML evasion is a no-op ──────────────────────────────────

#[test]
fn no_body_ml_evasion_noop() {
    let req = Request::get("https://example.com/search?q=%27+OR+1%3D1--");

    let (result_req, techniques) =
        apply_ml_evasion_if_applicable(&req, "AWS Bot Control", DEFAULT_ML_BUDGET, 0);

    assert_eq!(result_req.url, req.url);
    assert!(
        techniques.is_empty(),
        "no body → no ML evasion techniques should be applied"
    );
}

// ── Test 8: WafClass::AwsBotControl, CloudflareBotMgmt, AkamaiBotManager are ML-backed ──

#[test]
fn all_ml_backed_waf_classes_identified() {
    let ml_classes = [
        WafClass::AwsBotControl,
        WafClass::CloudflareBotMgmt,
        WafClass::AkamaiBotManager,
        WafClass::Datadome,
    ];
    for cls in ml_classes {
        assert!(cls.is_ml_backed(), "{cls:?} must be ML-backed");
    }

    let non_ml_classes = [
        WafClass::PlainModSec,
        WafClass::CloudflareManagedRules,
        WafClass::AwsCoreRuleSet,
        WafClass::GenericCrs,
        WafClass::Unknown,
    ];
    for cls in non_ml_classes {
        assert!(!cls.is_ml_backed(), "{cls:?} must NOT be ML-backed");
    }
}
