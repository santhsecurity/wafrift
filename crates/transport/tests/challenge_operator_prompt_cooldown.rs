//! Integration: `OPERATOR_PROMPT_COOLDOWN` — one prompt slot per normalized host,
//! no burst re-prompts inside the window.

use wafrift_transport::challenge::{
    ChallengeKind, ChallengeStore, OPERATOR_PROMPT_COOLDOWN, OPERATOR_PROMPT_GLOBAL_CAP_PER_MIN,
};

#[test]
fn distinct_hosts_emit_up_to_global_cap_then_zero_in_cooldown_window() {
    // The global rolling-window cap (default 30/min) throttles a
    // simultaneous storm of distinct hosts so the operator isn't
    // overwhelmed. The first N (≤ cap) prompt; subsequent first-
    // contact hosts are silently suppressed for the same window;
    // and within the per-host cooldown, none of the originals
    // re-prompt either.
    let store = ChallengeStore::new();
    let hosts: Vec<String> = (0..100)
        .map(|i| format!("prompt-isolated-{i}.challenge.test"))
        .collect();

    let mut first_round_prompts = 0usize;
    for h in &hosts {
        if store.should_prompt_operator(h) {
            first_round_prompts += 1;
        }
    }
    assert_eq!(
        first_round_prompts, OPERATOR_PROMPT_GLOBAL_CAP_PER_MIN,
        "Fix: global cap must throttle the storm to {} prompts per 60s",
        OPERATOR_PROMPT_GLOBAL_CAP_PER_MIN
    );

    let mut second_round_prompts = 0usize;
    for h in &hosts {
        if store.should_prompt_operator(h) {
            second_round_prompts += 1;
        }
    }
    assert_eq!(
        second_round_prompts, 0,
        "Fix: inside OPERATOR_PROMPT_COOLDOWN ({:?}) no host should re-prompt, \
         AND the global cap is also still saturated",
        OPERATOR_PROMPT_COOLDOWN
    );
}

#[test]
fn operator_prompt_throttle_collapses_host_case_and_port_to_one_logical_host() {
    let store = ChallengeStore::new();
    assert!(
        store.should_prompt_operator("Example.COM"),
        "first prompt for canonical host"
    );
    assert!(
        !store.should_prompt_operator("example.com:443"),
        "Fix: DNS case + :port must normalize to the same operator-prompt key — \
         second call must throttle within cooldown"
    );
    assert!(
        !store.should_prompt_operator("EXAMPLE.COM"),
        "Fix: repeated casing variants must not emit extra prompts"
    );
}

#[test]
fn distinct_hosts_do_not_share_each_others_cooldown_buckets() {
    // Distinct hosts have INDEPENDENT per-host cooldowns — host A's
    // prompt doesn't blow host B's window. Verified by interleaving
    // up to the global cap so neither test arm hits the storm
    // throttle.
    let store = ChallengeStore::new();
    // OPERATOR_PROMPT_GLOBAL_CAP_PER_MIN is the upper bound; halve
    // and use 14 of each to stay safely under it (28 < 30).
    let n = OPERATOR_PROMPT_GLOBAL_CAP_PER_MIN / 2 - 1;
    let mut prompted = 0usize;
    for i in 0..n {
        let a = format!("bucket-a-{i}.t");
        let b = format!("bucket-b-{i}.t");
        if store.should_prompt_operator(&a) {
            prompted += 1;
        }
        if store.should_prompt_operator(&b) {
            prompted += 1;
        }
    }
    assert_eq!(
        prompted,
        n * 2,
        "Fix: interleaved distinct hosts (under the global cap) must each get their first prompt"
    );
}

#[test]
fn purge_expired_does_not_reset_operator_prompt_window_early() {
    let store = ChallengeStore::new();
    assert!(store.should_prompt_operator("purge-coalesce.test"));
    assert!(!store.should_prompt_operator("purge-coalesce.test"));
    store.purge_expired();
    assert!(
        !store.should_prompt_operator("purge-coalesce.test"),
        "Fix: purge_expired must not clear operator_prompted while cooldown still active"
    );
}

#[test]
fn record_auto_purge_does_not_erase_active_operator_prompt_bookkeeping_prematurely() {
    let store = ChallengeStore::new();
    assert!(store.should_prompt_operator("record-side-effect.test"));
    assert!(!store.should_prompt_operator("record-side-effect.test"));
    store.record(
        "other-host-insert.test",
        "cf_clearance=side",
        ChallengeKind::CloudflareManaged,
        None,
    );
    assert!(
        !store.should_prompt_operator("record-side-effect.test"),
        "Fix: opportunistic GC on record must retain operator_prompted entries inside cooldown"
    );
}
