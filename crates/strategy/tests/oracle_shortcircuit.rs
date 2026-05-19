//! Oracle short-circuit — when `HostState` records a previous success
//! (simulating an `Allowed` oracle verdict), `evade` must early-exit
//! the escalation chain and re-apply the winning technique without
//! running the remaining encoders.

use wafrift_strategy::{HostState, strategy::evade};
use wafrift_types::{EvasionConfig, Request, Technique};

fn no_fingerprint_config() -> EvasionConfig {
    EvasionConfig {
        fingerprint_rotation: false,
        ..EvasionConfig::default()
    }
}

// ── Positive: last_success short-circuits heavy escalation ────────────────

#[test]
fn last_success_shortcircuits_escalation_chain() {
    let req = Request::post("https://example.com/api", b"q=test".to_vec())
        .header("Content-Type", "application/x-www-form-urlencoded");

    // Without short-circuit: Heavy escalation runs many techniques.
    let mut state_no_short = HostState::default();
    for _ in 0..10 {
        state_no_short.record_block();
    }
    let result_no_short = evade(&req, &state_no_short, &no_fingerprint_config());
    assert!(
        result_no_short.techniques.len() >= 3,
        "heavy escalation should run multiple techniques, got {:?}",
        result_no_short.techniques
    );

    // With short-circuit: last_success causes early exit.
    let mut state_short = HostState::default();
    for _ in 0..10 {
        state_short.record_block();
    }
    state_short.last_success = Some(Technique::PayloadEncoding("CaseAlternation".to_string()));

    let result_short = evade(&req, &state_short, &no_fingerprint_config());
    assert!(
        result_short
            .techniques
            .iter()
            .any(|t| { matches!(t, Technique::PayloadEncoding(s) if s == "CaseAlternation") }),
        "short-circuit must apply last_success technique"
    );

    // Remaining heavy-escalation encoders must NOT run.
    assert!(
        !result_short
            .techniques
            .iter()
            .any(|t| matches!(t, Technique::RequestSmuggling(_))),
        "remaining encoders must NOT run after short-circuit"
    );
    assert!(
        !result_short
            .techniques
            .iter()
            .any(|t| matches!(t, Technique::H2Evasion(_))),
        "remaining encoders must NOT run after short-circuit"
    );
    assert!(
        !result_short
            .techniques
            .iter()
            .any(|t| matches!(t, Technique::ContentTypeSwitch(_))),
        "remaining encoders must NOT run after short-circuit"
    );
}

// ── Positive: proven winner short-circuits before last_success ────────────

#[test]
fn proven_winner_takes_precedence_over_last_success() {
    let req = Request::post("https://example.com/api", b"q=test".to_vec())
        .header("Content-Type", "application/x-www-form-urlencoded");

    let mut state = HostState::default();
    state.proven_winners.push("encoding:UrlEncode".to_string());
    state.discovery_complete = true;
    state.last_success = Some(Technique::PayloadEncoding("CaseAlternation".to_string()));

    let result = evade(&req, &state, &no_fingerprint_config());

    // proven_winners is checked BEFORE last_success in evade().
    assert!(
        result
            .techniques
            .iter()
            .any(|t| { matches!(t, Technique::PayloadEncoding(s) if s == "UrlEncode") }),
        "proven winner must take precedence over last_success"
    );
    assert!(
        !result
            .techniques
            .iter()
            .any(|t| { matches!(t, Technique::PayloadEncoding(s) if s == "CaseAlternation") }),
        "last_success must not run when proven winner exists"
    );
}

// ── Negative: no short-circuit runs full escalation ───────────────────────

#[test]
fn no_short_circuit_runs_full_escalation() {
    let req = Request::post("https://example.com/api", b"q=test".to_vec())
        .header("Content-Type", "application/x-www-form-urlencoded");

    let mut state = HostState::default();
    for _ in 0..10 {
        state.record_block();
    }

    let result = evade(&req, &state, &no_fingerprint_config());

    assert!(
        result
            .techniques
            .iter()
            .any(|t| matches!(t, Technique::RequestSmuggling(_))),
        "full escalation must include smuggling"
    );
    assert!(
        result
            .techniques
            .iter()
            .any(|t| matches!(t, Technique::H2Evasion(_))),
        "full escalation must include h2 evasion"
    );
}
