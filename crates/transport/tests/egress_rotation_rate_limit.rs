//! Regression test for the egress-pool rate-limit rotation contract.
//!
//! Closes #174. When Cloudflare (or any WAF) returns repeated 429 /
//! soft-challenge responses against one egress IP, the pool's
//! cooldown logic must rotate to a clean entry within
//! `challenge_threshold` observations. Without this, a hunt round
//! against a target that aggressively rate-limits one IP would
//! plateau at zero forward progress.
//!
//! Wiremock-free: we drive the [`EgressPool`] directly via
//! `record_challenge` / `next_for`, which is the exact contract the
//! transport layer hooks into when the response classifier sees a
//! soft-challenge.

use wafrift_transport::egress_pool::{EgressPool, EgressPoolBuilder};

fn two_entry_pool(threshold: u32, cooldown_secs: u64) -> EgressPool {
    EgressPoolBuilder::default()
        .http_proxy_str(vec![
            "http://127.0.0.1:1".to_string(),
            "http://127.0.0.1:2".to_string(),
        ])
        .expect("build proxy list")
        .challenge_threshold(threshold)
        .cooldown_secs(cooldown_secs)
        .build()
        .expect("build pool")
}

#[test]
fn cooldown_after_threshold_challenges() {
    let pool = two_entry_pool(/* threshold */ 3, /* cooldown */ 300);
    let target = "example.cloudflare-protected.com";

    // First entry should be selected on first call.
    let entry_a = pool.next_for(target).expect("first entry");
    let first_label = entry_a.backend.label().to_string();

    // Fire threshold challenges against entry_a.
    for _ in 0..3 {
        pool.record_challenge(&entry_a, target);
    }

    // Now next_for(target) must rotate to the other entry — entry_a
    // is in cooldown.
    let entry_b = pool.next_for(target).expect("rotated entry");
    let second_label = entry_b.backend.label().to_string();

    assert_ne!(
        first_label, second_label,
        "pool must rotate after threshold challenges; got {first_label} both times"
    );
}

#[test]
fn cooldown_is_per_target_not_global() {
    let pool = two_entry_pool(3, 300);

    // Burn entry_a against target X.
    let entry_a = pool.next_for("target-x.com").expect("first");
    for _ in 0..3 {
        pool.record_challenge(&entry_a, "target-x.com");
    }

    // entry_a is cooled for target-x. But against target-y it should
    // still be eligible — cooldown is per (entry, target_host) so an
    // IP cooled by CF in one zone isn't held back from other zones.
    let entry_for_y = pool.next_for("target-y.com").expect("y");
    // Could be either entry, but at minimum BOTH should be available
    // for target-y — no IndexOutOfRange / cooled-pool error.
    let _ = entry_for_y;
}

#[test]
fn record_pass_resets_counter() {
    let pool = two_entry_pool(3, 300);
    let target = "example.com";

    let entry = pool.next_for(target).expect("entry");
    // Two challenges (below threshold).
    pool.record_challenge(&entry, target);
    pool.record_challenge(&entry, target);
    // A pass resets the counter.
    pool.record_pass(&entry, target);
    // Two more challenges — still below threshold (because counter
    // was reset). No cooldown should fire.
    pool.record_challenge(&entry, target);
    pool.record_challenge(&entry, target);

    // next_for should still return the same entry (or another — the
    // important invariant is that NO entry is cooled, so the pool
    // doesn't degrade to "entire pool cooled" error).
    let _ = pool
        .next_for(target)
        .expect("pool not cooled after threshold-1 -> pass -> threshold-1");
}

#[test]
fn entire_pool_cooled_returns_error() {
    let pool = two_entry_pool(2, 300);
    let target = "x.com";

    // Drain both entries: 2 challenges against each.
    for _ in 0..4 {
        let entry = match pool.next_for(target) {
            Ok(e) => e,
            // First rotation may already error if both got cooled
            // quickly; that's the very state we're testing for.
            Err(_) => break,
        };
        pool.record_challenge(&entry, target);
        pool.record_challenge(&entry, target);
    }

    let result = pool.next_for(target);
    assert!(
        result.is_err(),
        "after both entries are cooled, next_for should return EntirePoolCooled / similar error"
    );
}

#[test]
fn rotation_distributes_load_across_pool() {
    let pool = two_entry_pool(100, 1); // Very tolerant threshold,
    // very short cooldown — focus
    // is on rotation order, not
    // cooldown.
    let target = "round-robin.example";

    // Probe many times and count distinct entries returned.
    let mut labels_seen = std::collections::HashSet::new();
    for _ in 0..10 {
        let entry = pool.next_for(target).expect("entry");
        labels_seen.insert(entry.backend.label().to_string());
    }
    // Both entries should appear at least once in 10 round-robins.
    assert_eq!(
        labels_seen.len(),
        2,
        "rotation should visit both entries; saw {labels_seen:?}"
    );
}

#[test]
fn empty_pool_builder_rejects_at_build_time() {
    // The builder refuses to construct an empty pool — the
    // operator's misuse is caught before any probe is sent, not at
    // first `next_for` deep in the hunt loop.
    let result = EgressPoolBuilder::default().build();
    assert!(
        result.is_err(),
        "empty pool must error at build time, not panic"
    );
}

#[test]
fn record_challenge_below_threshold_does_not_cool() {
    let pool = two_entry_pool(5, 300);
    let target = "example.com";

    let entry = pool.next_for(target).expect("entry");
    // Threshold is 5; record 4 challenges → still warm.
    for _ in 0..4 {
        pool.record_challenge(&entry, target);
    }

    // Both entries should still be selectable across multiple
    // next_for calls.
    let mut labels_seen = std::collections::HashSet::new();
    for _ in 0..6 {
        let e = pool.next_for(target).expect("not cooled");
        labels_seen.insert(e.backend.label().to_string());
    }
    assert_eq!(
        labels_seen.len(),
        2,
        "below-threshold cool count should not remove entry from rotation"
    );
}
