use super::*;

#[test]
fn default_state_no_evasion() {
    let state = HostState::default();
    assert_eq!(state.escalation_level(), EscalationLevel::None);
}

#[test]
fn light_after_two_blocks() {
    let mut state = HostState::default();
    state.record_block();
    state.record_block();
    assert_eq!(state.escalation_level(), EscalationLevel::Light);
}

#[test]
fn medium_after_four_blocks() {
    let mut state = HostState::default();
    for _ in 0..4 {
        state.record_block();
    }
    assert_eq!(state.escalation_level(), EscalationLevel::Medium);
}

#[test]
fn heavy_after_many_blocks() {
    let mut state = HostState::default();
    for _ in 0..10 {
        state.record_block();
    }
    assert_eq!(state.escalation_level(), EscalationLevel::Heavy);
}

#[test]
fn record_success_tracks_technique() {
    let mut state = HostState::default();
    state.record_success(Technique::PayloadEncoding("CaseAlternation".into()));
    assert_eq!(state.successes, 1);
    assert!(state.last_success.is_some());
}

#[test]
fn record_block_for_tracks_technique() {
    let mut state = HostState::default();
    state.record_block_for("CaseAlternation");
    state.record_block_for("CaseAlternation");
    assert_eq!(state.blocks, 2);
    assert_eq!(state.technique_stats[0].2, 2); // 2 attempts
}

#[test]
fn record_block_for_many_one_http_block_multi_technique() {
    let mut state = HostState::default();
    state.record_block_for_many(&["a".to_string(), "b".to_string()]);
    assert_eq!(state.blocks, 1);
    assert_eq!(state.technique_stats.len(), 2);
    assert_eq!(
        state
            .technique_stats
            .iter()
            .find(|(n, _, _)| n == "a")
            .unwrap()
            .2,
        1
    );
    assert_eq!(
        state
            .technique_stats
            .iter()
            .find(|(n, _, _)| n == "b")
            .unwrap()
            .2,
        1
    );
}

#[test]
fn record_success_for_many_compound() {
    let mut state = HostState::default();
    state.record_success_for_many(&[
        Technique::PayloadEncoding("A".into()),
        Technique::PayloadEncoding("B".into()),
    ]);
    assert_eq!(state.successes, 1);
    let sa = state
        .technique_stats
        .iter()
        .find(|(n, _, _)| n == "encoding:A")
        .unwrap();
    assert_eq!(sa.1, 1);
    assert_eq!(sa.2, 1);
}

#[test]
fn best_technique_needs_two_attempts() {
    let mut state = HostState::default();
    state.record_success(Technique::PayloadEncoding("DoubleUrlEncode".into()));
    // One attempt — should not be returned
    assert!(state.best_technique().is_none());
}

#[test]
fn needs_evasion_default() {
    let state = HostState::default();
    assert!(state.needs_evasion()); // Safe default
}

#[test]
fn needs_evasion_after_success_no_blocks() {
    let state = HostState {
        successes: 5,
        ..Default::default()
    };
    assert!(!state.needs_evasion());
}

#[test]
fn confirm_waf_sets_flag() {
    let mut state = HostState::default();
    state.confirm_waf(Some("Cloudflare".into()));
    assert!(state.waf_confirmed);
    assert_eq!(state.waf_name.as_deref(), Some("Cloudflare"));
    assert!(state.needs_evasion());
}

// ── Adaptive rotation tests ─────────────────────────────────────

#[test]
fn no_winners_before_discovery() {
    let state = HostState::default();
    assert!(!state.has_winners());
    assert!(state.proven_winners.is_empty());
}

#[test]
fn evaluate_pools_promotes_winners() {
    let mut state = HostState {
        technique_stats: vec![
            ("GoodTech".into(), 9, 10), // 90% — should be winner
            ("OkTech".into(), 7, 10),   // 70% — should be winner
            ("BadTech".into(), 1, 10),  // 10% — should be blocklisted
            ("TooFew".into(), 2, 2),    // 100% but only 2 attempts — skip
        ],
        ..Default::default()
    };
    state.evaluate_pools();
    assert!(state.discovery_complete);
    assert!(state.proven_winners.contains(&"GoodTech".to_string()));
    assert!(state.proven_winners.contains(&"OkTech".to_string()));
    assert!(!state.proven_winners.contains(&"BadTech".to_string()));
    assert!(!state.proven_winners.contains(&"TooFew".to_string()));
    assert!(state.blocklisted.contains(&"BadTech".to_string()));
}

#[test]
fn evaluate_pools_skips_insufficient_data() {
    // Only 5 total attempts — not enough to declare discovery.
    let mut state = HostState {
        technique_stats: vec![("T1".into(), 3, 5)],
        ..Default::default()
    };
    state.evaluate_pools();
    assert!(!state.discovery_complete);
    assert!(state.proven_winners.is_empty());
}

#[test]
fn next_winner_round_robins() {
    let mut state = HostState {
        proven_winners: vec!["A".into(), "B".into(), "C".into()],
        discovery_complete: true,
        ..Default::default()
    };

    assert_eq!(state.next_winner().as_deref(), Some("A"));
    assert_eq!(state.next_winner().as_deref(), Some("B"));
    assert_eq!(state.next_winner().as_deref(), Some("C"));
    assert_eq!(state.next_winner().as_deref(), Some("A"));
}

#[test]
fn next_winner_returns_none_when_empty() {
    let mut state = HostState::default();
    assert!(state.next_winner().is_none());
}

#[test]
fn drift_detection_evicts_winner() {
    let mut state = HostState {
        proven_winners: vec!["WinTech".into(), "StillGood".into()],
        discovery_complete: true,
        ..Default::default()
    };

    // Two consecutive blocks on WinTech triggers eviction.
    state.record_block_for("WinTech");
    state.record_block_for("WinTech");

    assert!(!state.proven_winners.contains(&"WinTech".to_string()));
    assert!(state.blocklisted.contains(&"WinTech".to_string()));
    // StillGood survives.
    assert!(state.proven_winners.contains(&"StillGood".to_string()));
}

#[test]
fn success_resets_drift_counter() {
    let mut state = HostState {
        proven_winners: vec!["encoding:Tech".into()],
        discovery_complete: true,
        ..Default::default()
    };

    // One block.
    state.record_block_for("encoding:Tech");
    // Then a success — should reset the drift counter.
    state.record_success(Technique::PayloadEncoding("Tech".into()));

    // Another block — should NOT evict because counter was reset.
    state.record_block_for("encoding:Tech");
    assert!(state.proven_winners.contains(&"encoding:Tech".to_string()));
}

#[test]
fn all_winners_evicted_triggers_rediscovery() {
    let mut state = HostState {
        proven_winners: vec!["OnlyWinner".into()],
        discovery_complete: true,
        blocklisted: vec!["PrevBad".into()],
        technique_stats: vec![("OnlyWinner".into(), 5, 10)],
        ..Default::default()
    };

    // Evict the only winner.
    state.record_block_for("OnlyWinner");
    state.record_block_for("OnlyWinner");

    // Should re-enter discovery mode.
    assert!(!state.discovery_complete);
    assert!(state.proven_winners.is_empty());
    // Blocklist and stats are cleared for a clean re-discovery.
    assert!(state.blocklisted.is_empty());
    assert!(state.technique_stats.is_empty());
}

#[test]
fn all_winners_evicted_simultaneously_triggers_rediscovery() {
    let mut state = HostState {
        proven_winners: vec!["WinnerA".into(), "WinnerB".into()],
        discovery_complete: true,
        ..Default::default()
    };

    // Both winners get blocked twice — should evict both at once.
    state.record_block_for("WinnerA");
    state.record_block_for("WinnerB");
    state.record_block_for("WinnerA");
    state.record_block_for("WinnerB");

    // All winners gone → re-enter discovery.
    assert!(!state.discovery_complete);
    assert!(state.proven_winners.is_empty());
    assert!(state.blocklisted.is_empty());
    assert!(state.technique_stats.is_empty());
}

#[test]
fn full_lifecycle_discover_rotate_drift_rediscover() {
    let mut state = HostState::default();

    // Phase 1: Discovery — simulate 15 technique observations.
    for _ in 0..5 {
        state.record_success(Technique::PayloadEncoding("Winner".into()));
    }
    for _ in 0..5 {
        state.record_block_for("Loser");
    }
    // Add some more to reach threshold.
    for _ in 0..5 {
        state.record_success(Technique::PayloadEncoding("AlsoGood".into()));
    }

    // Should have promoted winners.
    assert!(state.discovery_complete);
    assert!(state.has_winners());
    assert!(
        state
            .proven_winners
            .contains(&"encoding:Winner".to_string())
            || state
                .proven_winners
                .contains(&"encoding:AlsoGood".to_string())
    );

    // Phase 2: Rotation — get next winner.
    let w = state.next_winner();
    assert!(w.is_some());

    // Phase 3: Drift — block a winner twice.
    let winner_name = state.proven_winners[0].clone();
    state.record_block_for(&winner_name);
    state.record_block_for(&winner_name);

    // Winner should be evicted.
    assert!(!state.proven_winners.contains(&winner_name));
}

#[test]
fn blocklisted_encoding_not_suggested() {
    let mut state = HostState::default();
    // Blocklist a known encoding strategy name.
    state.blocklisted.push("CaseAlternation".into());
    // next_encoding should skip it.
    if let Some(strategy) = state.next_encoding() {
        assert_ne!(format!("{strategy:?}"), "CaseAlternation");
    }
}
