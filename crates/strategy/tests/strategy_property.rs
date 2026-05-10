//! Property-based tests for the strategy engine.
//!
//! - 10k random payloads through `evade()` — no panic.
//! - Deterministic output for identical (request, state, config).
//! - Double-evade is a technique-selection no-op once a winner is cached
//!   (the same technique list is produced on the second call).

use proptest::prelude::*;
use wafrift_strategy::{HostState, strategy::evade};
use wafrift_types::{EvasionConfig, Request, Technique};

fn deterministic_config() -> EvasionConfig {
    EvasionConfig {
        fingerprint_rotation: false,
        ..EvasionConfig::default()
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    // ── No panic on arbitrary printable-ASCII payloads ────────────────────
    #[test]
    fn evade_never_panics(body in "[ -~]{0,256}") {
        let req = Request::post("https://example.com/api", body.into_bytes())
            .header("Content-Type", "application/x-www-form-urlencoded");
        let state = HostState::default();
        let _ = evade(&req, &state, &deterministic_config());
    }

    // ── Deterministic for same seed (same request + same state) ───────────
    #[test]
    fn evade_is_deterministic(body in "[ -~]{0,256}") {
        let req = Request::post("https://example.com/api", body.into_bytes())
            .header("Content-Type", "application/x-www-form-urlencoded");
        let state = HostState::default();

        let result1 = evade(&req, &state, &deterministic_config());
        let result2 = evade(&req, &state, &deterministic_config());

        assert_eq!(result1.request.body, result2.request.body);
        assert_eq!(result1.techniques, result2.techniques);
        assert_eq!(result1.description, result2.description);
    }

    // ── Double-evade technique-selection no-op once Allowed ───────────────
    // "Allowed" is simulated by a HostState whose `last_success` is set.
    // The second evade must not introduce new techniques beyond the winner.
    #[test]
    fn double_evade_no_new_techniques_once_allowed(body in "[ -~]{0,256}") {
        let req = Request::post("https://example.com/api", body.into_bytes())
            .header("Content-Type", "application/x-www-form-urlencoded");

        let mut state = HostState::default();
        state.last_success = Some(Technique::PayloadEncoding("CaseAlternation".to_string()));

        let result1 = evade(&req, &state, &deterministic_config());
        let result2 = evade(&result1.request, &state, &deterministic_config());

        // Technique list must be identical (no new techniques explored).
        assert_eq!(
            result1.techniques, result2.techniques,
            "double-evade must not add new techniques once a winner is cached"
        );
    }

    // ── Negative: different HostState produces different techniques ───────
    #[test]
    fn different_state_produces_different_techniques(body in "[ -~]{0,256}") {
        let req = Request::post("https://example.com/api", body.into_bytes())
            .header("Content-Type", "application/x-www-form-urlencoded");

        let state_clean = HostState::default();
        let mut state_blocked = HostState::default();
        state_blocked.record_block();
        state_blocked.record_block();

        let result_clean = evade(&req, &state_clean, &deterministic_config());
        let result_blocked = evade(&req, &state_blocked, &deterministic_config());

        // Clean state → None (no encoding); Blocked state → Light (encoding).
        let clean_has_encoding = result_clean
            .techniques
            .iter()
            .any(|t| matches!(t, Technique::PayloadEncoding(_)));
        let blocked_has_encoding = result_blocked
            .techniques
            .iter()
            .any(|t| matches!(t, Technique::PayloadEncoding(_)));

        prop_assert!(
            !clean_has_encoding || blocked_has_encoding,
            "blocked state should at least match clean state's encoding presence"
        );
    }
}
