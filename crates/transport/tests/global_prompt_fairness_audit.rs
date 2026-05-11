//! Regression coverage for the 2026-05-10 swarm-audit HIGH:
//!   `global_prompt_window` was first-come-first-served — one chatty
//!   host could fill the 30-prompt window inside its cooldown and
//!   starve every other host's prompt for 60 seconds. Per-host cap
//!   added at `OPERATOR_PROMPT_PER_HOST_CAP_PER_MIN` = 8.

use wafrift_transport::challenge::{
    ChallengeStore, OPERATOR_PROMPT_GLOBAL_CAP_PER_MIN, OPERATOR_PROMPT_PER_HOST_CAP_PER_MIN,
};

#[test]
fn one_chatty_host_cannot_starve_other_hosts() {
    let store = ChallengeStore::new();
    // The chatty host hits the per-host cap and is then suppressed.
    // Other hosts (one prompt each) must still get through up to the
    // remaining global slack.
    let chatty = "noisy.example.com";
    let mut chatty_allowed = 0;
    for _ in 0..50 {
        if store.should_prompt_operator(chatty) {
            chatty_allowed += 1;
        }
    }
    assert!(
        chatty_allowed <= OPERATOR_PROMPT_PER_HOST_CAP_PER_MIN,
        "chatty host took {chatty_allowed} prompts; per-host cap is {OPERATOR_PROMPT_PER_HOST_CAP_PER_MIN}"
    );

    // After the chatty host is suppressed, distinct other hosts must
    // still get through (each takes one slot).
    let mut others_allowed = 0;
    for i in 0..50 {
        let host = format!("victim-{i}.example.com");
        if store.should_prompt_operator(&host) {
            others_allowed += 1;
        }
    }
    let global_remaining =
        OPERATOR_PROMPT_GLOBAL_CAP_PER_MIN - chatty_allowed;
    assert!(
        others_allowed > 0,
        "other hosts must not be starved by the chatty one (chatty took {chatty_allowed}, \
         global remaining is {global_remaining}, others got {others_allowed})"
    );
    // We should be able to take up to the remaining global capacity.
    assert!(
        others_allowed >= global_remaining.min(50) - 5,
        "other hosts should fill most of the remaining {global_remaining} slots, got {others_allowed}"
    );
}

#[test]
fn per_host_cap_applies_per_host() {
    let store = ChallengeStore::new();
    for host_idx in 0..3 {
        let host = format!("victim-{host_idx}.example.com");
        let mut taken = 0;
        for _ in 0..20 {
            if store.should_prompt_operator(&host) {
                taken += 1;
            }
        }
        assert!(
            taken <= OPERATOR_PROMPT_PER_HOST_CAP_PER_MIN,
            "host {host_idx} took {taken} prompts; per-host cap is {OPERATOR_PROMPT_PER_HOST_CAP_PER_MIN}"
        );
    }
}

#[test]
fn global_cap_still_terminates_storm() {
    // Defence-in-depth: even with per-host fairness, the global cap
    // still applies. 100 distinct hosts must not all get through.
    let store = ChallengeStore::new();
    let mut allowed = 0;
    for i in 0..200 {
        let host = format!("flood-{i}.example.com");
        if store.should_prompt_operator(&host) {
            allowed += 1;
        }
    }
    assert!(
        allowed <= OPERATOR_PROMPT_GLOBAL_CAP_PER_MIN,
        "global cap of {OPERATOR_PROMPT_GLOBAL_CAP_PER_MIN} breached: {allowed}"
    );
}
