//! Tests for `wafrift_strategy::strategy::evade_smart` — the active-loop
//! evade that switches between MCTS and the classic pipeline based on
//! per-host block telemetry.

use wafrift_strategy::{HostState, evade_smart};
use wafrift_types::{EvasionConfig, Request};

fn sample_request() -> Request {
    Request::post("https://target.example/post", b"q=admin' OR 1=1--".to_vec())
}

#[test]
fn evade_smart_with_zero_blocks_uses_classic_pipeline() {
    // Zero block telemetry -> falls through to classic evade(). The
    // result should still be an EvasionResult (not None) — classic
    // evade() always returns Some.
    let req = sample_request();
    let state = HostState::default();
    let config = EvasionConfig::default();
    let result = evade_smart(&req, &state, &config);
    assert_eq!(
        result.request.url, req.url,
        "URL must be preserved by classic-pipeline path"
    );
}

#[test]
fn evade_smart_with_blocks_engages_mcts_or_falls_back() {
    let req = sample_request();
    let mut state = HostState::default();
    // Bump blocks so MCTS path is engaged in evade_smart.
    for _ in 0..3 {
        state.record_block();
    }
    let config = EvasionConfig::maximum();
    let result = evade_smart(&req, &state, &config);
    // Either MCTS produced a transformation or it bailed and we fell back
    // to classic evade(); either way we get a valid EvasionResult.
    assert!(!result.request.url.is_empty());
}

#[test]
fn evade_smart_at_zero_blocks_gives_same_url_as_classic_evade() {
    let req = sample_request();
    let state = HostState::default();
    let config = EvasionConfig::default();
    let smart = evade_smart(&req, &state, &config);
    let classic = wafrift_strategy::strategy::evade(&req, &state, &config);
    // With zero blocks the smart variant goes through classic, so the
    // URL component must be identical (only body / headers may transform).
    assert_eq!(smart.request.url, classic.request.url);
}

#[test]
fn evade_smart_depth_caps_at_5() {
    // Even with very high block count, MCTS depth is clamped so it
    // doesn't blow up the search budget. We can't directly observe
    // depth from outside but we can verify the call doesn't hang.
    let req = sample_request();
    let mut state = HostState::default();
    for _ in 0..200 {
        state.record_block();
    }
    let config = EvasionConfig::maximum();
    let _ = evade_smart(&req, &state, &config);
}
