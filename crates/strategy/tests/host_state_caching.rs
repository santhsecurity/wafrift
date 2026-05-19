//! Host-state caching — `evade_smart` must reuse recon results stored in
//! `HostState` (prioritized techniques, proven winners) on the second
//! call to the same host.

use wafrift_strategy::{HostState, evade_smart};
use wafrift_types::{EvasionConfig, Request, Technique};

fn no_fingerprint_config() -> EvasionConfig {
    EvasionConfig {
        fingerprint_rotation: false,
        ..EvasionConfig::default()
    }
}

// ── Positive: second call uses cached prioritized technique ───────────────

#[test]
fn evade_smart_uses_cached_prioritized_technique() {
    let req = Request::post("https://example.com/api", b"q=test".to_vec())
        .header("Content-Type", "application/x-www-form-urlencoded");

    // Call 1: no recon cached → default pipeline (no encoding on clean state)
    let state_no_recon = HostState::default();
    let result1 = evade_smart(&req, &state_no_recon, &no_fingerprint_config());
    assert!(
        !result1
            .techniques
            .iter()
            .any(|t| { matches!(t, Technique::PayloadEncoding(s) if s == "DoubleUrlEncode") }),
        "without recon cache must not pick DoubleUrlEncode"
    );

    // Call 2: same host, recon results now cached in HostState
    let mut state_with_recon = HostState::default();
    state_with_recon
        .prioritized_techniques
        .push("encoding:DoubleUrlEncode".to_string());
    state_with_recon.waf_name = Some("Cloudflare".to_string());
    state_with_recon.waf_confirmed = true;

    let result2 = evade_smart(&req, &state_with_recon, &no_fingerprint_config());
    assert!(
        result2
            .techniques
            .iter()
            .any(|t| { matches!(t, Technique::PayloadEncoding(s) if s == "DoubleUrlEncode") }),
        "second call must use cached recon (prioritized technique), got {:?}",
        result2.techniques
    );
}

// ── Positive: proven winner is reused from cache ──────────────────────────

#[test]
fn evade_smart_uses_cached_proven_winner() {
    let req = Request::post("https://example.com/api", b"q=test".to_vec())
        .header("Content-Type", "application/x-www-form-urlencoded");

    let mut state = HostState::default();
    state
        .proven_winners
        .push("encoding:CaseAlternation".to_string());
    state.discovery_complete = true;

    let result = evade_smart(&req, &state, &no_fingerprint_config());
    assert!(
        result
            .techniques
            .iter()
            .any(|t| { matches!(t, Technique::PayloadEncoding(s) if s == "CaseAlternation") }),
        "must use cached proven winner, got {:?}",
        result.techniques
    );
}

// ── Negative: avoided technique from cache is skipped ─────────────────────

#[test]
fn evade_smart_skips_avoided_technique_from_cache() {
    let req = Request::post("https://example.com/api", b"q=test".to_vec())
        .header("Content-Type", "application/x-www-form-urlencoded");

    let mut state = HostState::default();
    state
        .prioritized_techniques
        .push("encoding:CaseAlternation".to_string());
    state
        .avoided_techniques
        .push("encoding:CaseAlternation".to_string());

    let result = evade_smart(&req, &state, &no_fingerprint_config());
    assert!(
        !result
            .techniques
            .iter()
            .any(|t| { matches!(t, Technique::PayloadEncoding(s) if s == "CaseAlternation") }),
        "avoided technique must be skipped even when prioritized"
    );
}

// ── Negative: empty cache falls through to default pipeline ───────────────

#[test]
fn evade_smart_empty_cache_falls_through() {
    let req = Request::post("https://example.com/api", b"q=test".to_vec())
        .header("Content-Type", "application/x-www-form-urlencoded");

    let state = HostState::default();
    let result = evade_smart(&req, &state, &no_fingerprint_config());

    // Clean state (blocks == 0) → EscalationLevel::None: no encoding.
    // Without fingerprint rotation there are zero techniques.
    assert!(
        result.techniques.is_empty(),
        "empty cache with zero blocks and no fingerprint rotation should produce zero techniques; got {:?}",
        result.techniques
    );
}
