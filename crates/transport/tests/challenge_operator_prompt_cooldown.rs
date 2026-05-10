//! Integration: `OPERATOR_PROMPT_COOLDOWN` — one prompt slot per normalized host,
//! no burst re-prompts inside the window.

use wafrift_transport::challenge::{ChallengeKind, ChallengeStore, OPERATOR_PROMPT_COOLDOWN};

#[test]
fn hundred_distinct_hosts_emit_exactly_one_prompt_each_then_zero_in_cooldown_window() {
    let store = ChallengeStore::new();
    let hosts: Vec<String> = (0..100)
        .map(|i| format!("prompt-isolated-{i}.challenge.test"))
        .collect();

    let mut first_round_prompts = 0u32;
    for h in &hosts {
        if store.should_prompt_operator(h) {
            first_round_prompts += 1;
        }
    }
    assert_eq!(
        first_round_prompts, 100,
        "Fix: each host must see should_prompt_operator == true exactly once on first contact"
    );

    let mut second_round_prompts = 0u32;
    for h in &hosts {
        if store.should_prompt_operator(h) {
            second_round_prompts += 1;
        }
    }
    assert_eq!(
        second_round_prompts, 0,
        "Fix: inside OPERATOR_PROMPT_COOLDOWN ({:?}), no host should re-prompt",
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
    let store = ChallengeStore::new();
    let mut prompted = 0usize;
    for i in 0..50 {
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
        prompted, 100,
        "Fix: interleaved distinct hosts must each get their first prompt"
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
