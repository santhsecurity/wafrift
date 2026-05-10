//! Regression test for the 2026-05-10 audit finding:
//! "Stagnation termination is completely dead — evolve() updates
//!  self.stagnation_counter, but should_terminate() reads
//!  self.stats.stagnation_counter which is initialized to 0 and never
//!  written again. budget.stagnation_limit is therefore never enforced."
//!
//! Pre-fix the test fails because should_terminate() never returns
//! true even when 50 generations have passed without improvement.

use wafrift_evolution::evolution::EvolutionEngine;
use wafrift_evolution::types::{Budget, OracleVerdict};

fn flat_evolve(engine: &mut EvolutionEngine, n: usize) {
    for _ in 0..n {
        let candidates = engine.batch_candidates(8);
        if candidates.is_empty() {
            return;
        }
        let results: Vec<(usize, OracleVerdict)> = candidates
            .into_iter()
            .map(|(id, _)| (id, OracleVerdict::from_bool(true)))
            .collect();
        engine.submit_batch(results).expect("submit_batch");
        engine.evolve();
    }
}

#[test]
fn stagnation_counter_is_mirrored_into_stats() {
    let mut engine = EvolutionEngine::new(8);

    // Burn through the warmup window first (need >= 10 generations
    // for the stagnation detector to have a window to look at).
    flat_evolve(&mut engine, 15);

    // After 15 stagnant generations the counter must have advanced
    // AND the mirror must reflect it. Pre-fix the second assert fails
    // (stats.stagnation_counter stays at 0 forever).
    assert!(
        engine.stagnation_counter > 0,
        "expected the engine's own counter to advance under flat fitness"
    );
    assert_eq!(
        engine.stats.stagnation_counter, engine.stagnation_counter,
        "stats.stagnation_counter must mirror engine.stagnation_counter — \
         without this sync should_terminate() never sees stagnation"
    );
}

#[test]
fn should_terminate_fires_when_stagnation_limit_reached() {
    let mut budget = Budget::default();
    budget.stagnation_limit = 3;
    budget.max_requests = 1_000_000;

    let mut engine = EvolutionEngine::with_algorithm(
        "hill_climbing",
        GenePool::default_wafrift(),
        StdRng::seed_from_u64(0),
        budget,
    )
    .expect("hill_climbing");

    for _ in 0..50 {
        if engine.should_terminate() {
            // Pre-fix: never reaches this branch because the budget's
            // stagnation_limit is read against an unsynced field.
            assert!(
                engine.stats.stagnation_counter >= budget.stagnation_limit,
                "should_terminate fired but stats.stagnation_counter ({}) < limit ({})",
                engine.stats.stagnation_counter,
                budget.stagnation_limit
            );
            return;
        }
        flat_evolve(&mut engine, 1);
    }

    panic!(
        "30 flat-fitness generations passed but should_terminate never fired \
         (stats.stagnation_counter = {}, limit = {}). The stats sync regressed.",
        engine.stats.stagnation_counter, budget.stagnation_limit
    );
}
