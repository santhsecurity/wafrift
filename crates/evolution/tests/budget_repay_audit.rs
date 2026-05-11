//! Regression coverage for the 2026-05-10 swarm-audit (kimi
//! evolution sub-batch):
//!   `in_flight` grew without TTL — every dropped evaluation
//!   permanently consumed a `max_requests` budget slot. Long scans
//!   would terminate prematurely with budget exhausted while the
//!   `in_flight` map silently accumulated zombie entries.
//!
//! `prune_stale_in_flight` now drops entries older than the threshold
//! AND repays `request_count` for the pruned entries.

use std::time::Duration;
use wafrift_evolution::evolution::EvolutionEngine;

fn engine() -> EvolutionEngine {
    // The default `new` builds with a 100-chromosome population,
    // hill-climbing algorithm, and the default budget (max_requests
    // is large enough that the prune assertions below don't trip
    // budget exhaustion).
    EvolutionEngine::new_seeded(100, 42)
}

#[test]
fn prune_repays_budget_for_dropped_evals() {
    let mut e = engine();
    // Burn through a chunk of the budget.
    let _ = e.batch_candidates(50);
    let consumed_before_prune = e.request_count;
    assert!(
        consumed_before_prune > 0,
        "batch_candidates must consume some budget"
    );
    // Pretend ALL outstanding evals are stale.
    let pruned = e.prune_stale_in_flight(Duration::from_nanos(0));
    assert_eq!(
        pruned, consumed_before_prune,
        "every in-flight slot was just registered, all should be pruned"
    );
    assert_eq!(
        e.request_count, 0,
        "request_count must drop back to 0 once every in-flight is pruned"
    );
}

#[test]
fn prune_does_not_repay_recent_evals() {
    let mut e = engine();
    let _ = e.batch_candidates(20);
    // A 1-hour TTL leaves all entries alive.
    let pruned = e.prune_stale_in_flight(Duration::from_secs(3600));
    assert_eq!(pruned, 0);
}

#[test]
fn prune_returns_zero_on_empty_in_flight() {
    let mut e = engine();
    let pruned = e.prune_stale_in_flight(Duration::from_nanos(0));
    assert_eq!(pruned, 0);
}
