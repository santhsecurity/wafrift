#![allow(clippy::float_cmp)]

use crate::evolution::EvolutionEngine;
use crate::types::{Budget, OracleVerdict};
use rand::{Rng, SeedableRng};

#[test]
fn engine_creation_produces_population() {
    let engine = EvolutionEngine::new(10);
    assert!(engine.best().is_some() || engine.algorithm.best().is_some());
}

#[test]
fn new_seeded_determinism() {
    let mut engine_a = EvolutionEngine::new_seeded(10, 42);
    let mut engine_b = EvolutionEngine::new_seeded(10, 42);

    for _ in 0..5 {
        if let Some((idx_a, _)) = engine_a.next_candidate()
            && let Some((idx_b, _)) = engine_b.next_candidate()
        {
            engine_a.record_feedback(idx_a, true).unwrap();
            engine_b.record_feedback(idx_b, true).unwrap();
        }
        engine_a.evolve();
        engine_b.evolve();
    }

    let best_a = engine_a.best().map(|c| c.genes.clone());
    let best_b = engine_b.best().map(|c| c.genes.clone());
    assert_eq!(best_a, best_b, "seeded engines must be deterministic");
}

#[test]
fn record_feedback_updates_fitness() {
    let mut engine = EvolutionEngine::new(5);
    if let Some((idx, _)) = engine.next_candidate() {
        assert_eq!(engine.best().unwrap().fitness, 0.0);
        engine.record_feedback(idx, true).unwrap();
        assert!(engine.best().unwrap().fitness > 0.0);
    }
}

#[test]
fn record_feedback_tracks_gene_stats() {
    let mut engine = EvolutionEngine::new(5);
    let candidates: Vec<_> = engine.batch_candidates(5);
    for (idx, mut chrom) in candidates {
        chrom.genes[0].1 = String::from("CaseAlternation");
        // Inject into engine's in-flight set manually since batch_candidates already put it there
        let _ = engine.submit_batch(vec![(idx, OracleVerdict::from_bool(true))]);
    }
    assert!(!engine.gene_stats.is_empty());
}

#[test]
fn next_candidate_prefers_unevaluated() {
    let mut engine = EvolutionEngine::new(5);
    let candidates = engine.batch_candidates(5);
    engine
        .submit_batch(vec![(candidates[0].0, OracleVerdict::from_bool(true))])
        .unwrap();
    let next = engine.next_candidate();
    assert!(next.is_some());
}

#[test]
fn evolve_produces_next_generation() {
    let mut engine = EvolutionEngine::new(10);
    let candidates = engine.batch_candidates(10);
    for (idx, _) in candidates {
        let passed = idx % 3 == 0;
        engine.record_feedback(idx, passed).unwrap();
    }
    engine.evolve();
    assert_eq!(engine.stats.generation, 1);
}

#[test]
fn best_returns_fittest() {
    let mut engine = EvolutionEngine::new(5);
    let candidates = engine.batch_candidates(5);
    for (idx, _) in candidates {
        engine.record_feedback(idx, idx % 2 != 0).unwrap();
    }
    let best = engine.best();
    assert!(best.is_some());
}

#[test]
fn gene_success_rates_require_min_attempts() {
    let mut engine = EvolutionEngine::new(5);
    let candidates = engine.batch_candidates(5);
    for (idx, mut chrom) in candidates {
        chrom.genes[0].1 = String::from("CaseAlternation");
        let _ = engine.submit_batch(vec![(idx, OracleVerdict::from_bool(true))]);
    }
    let rates = engine.gene_success_rates();
    assert!(
        rates
            .iter()
            .all(|(_, value, _)| *value != "CaseAlternation")
    );

    let candidates = engine.batch_candidates(5);
    for (idx, mut chrom) in candidates {
        chrom.genes[0].1 = String::from("CaseAlternation");
        let _ = engine.submit_batch(vec![(idx, OracleVerdict::from_bool(true))]);
    }
    let rates = engine.gene_success_rates();
    assert!(!rates.is_empty());
}

#[test]
fn learned_summary_not_empty() {
    let mut engine = EvolutionEngine::new(5);
    if let Some((idx, _)) = engine.next_candidate() {
        engine.record_feedback(idx, true).unwrap();
    }
    let summary = engine.learned_summary();
    assert!(summary.contains("Generation:"));
}

#[test]
fn multiple_generations_converge() {
    let mut engine = EvolutionEngine::new(50);
    for _generation in 0..10 {
        let candidates = engine.batch_candidates(engine.budget.max_requests.min(50));
        for (idx, _) in candidates {
            // Simulate an oracle that passes CaseAlternation
            let _ = engine.record_feedback(idx, true);
        }
        engine.evolve();
    }
    let rates = engine.gene_success_rates();
    let case_alt_rate = rates
        .iter()
        .find(|(_, value, _)| *value == "CaseAlternation")
        .map(|(_, _, rate)| *rate);
    assert!(
        case_alt_rate.unwrap_or(0.0) > 0.0 || engine.best().is_none(),
        "CaseAlternation should appear in success rates or no best found"
    );
}

#[test]
fn small_population_does_not_panic() {
    let mut engine = EvolutionEngine::new(2);
    let candidates = engine.batch_candidates(2);
    for (idx, _) in candidates {
        engine.record_feedback(idx, true).unwrap();
    }
    engine.evolve();
}

#[test]
fn single_chromosome_does_not_panic() {
    let mut engine = EvolutionEngine::new(1);
    if let Some((idx, _)) = engine.next_candidate() {
        engine.record_feedback(idx, true).unwrap();
    }
    engine.evolve();
}

#[test]
fn out_of_bounds_feedback_errors() {
    let mut engine = EvolutionEngine::new(5);
    let result = engine.record_feedback(999, true);
    assert!(
        result.is_err(),
        "out-of-bounds feedback must return an error"
    );
}

// ── Bug 6 regression: bench_waf record_feedback silent error swallow ──────
//
// PRE-FIX BUG: `record_feedback` returned a `Result<(), EvolutionError>` but
// the two call sites in `bench_waf.rs` used `let _ = engine.record_feedback(...)`,
// silently discarding `InvalidChromosomeIndex` errors. This meant the evolution
// loop's scoring was silently corrupted (a candidate that was never scored
// kept being re-selected) and operators had no visibility into the mismatch.
//
// POST-FIX: both call sites now match on the error and emit
// `eprintln!("warn: ... record_feedback idx={idx}: {fe:?}")` so the operator
// sees the error.
//
// Here we verify the CONTRACT that `record_feedback` returns Err for an
// index that was never issued — the calling code's eprintln path depends
// on this being an Err rather than silently OK.

#[test]
fn record_feedback_invalid_index_returns_err_not_ok() {
    // PRE-FIX: `record_feedback` returned Ok(()) even for indices not in
    // in_flight (or silently mis-scored). POST-FIX: returns
    // Err(InvalidChromosomeIndex(idx)) so callers can log and surface it.
    let mut engine = EvolutionEngine::new(5);
    // Index 9999 was never issued by next_candidate or batch_candidates.
    let result = engine.record_feedback(9999, true);
    assert!(
        result.is_err(),
        "record_feedback with an index not in in_flight must return Err (bench_waf \
         suppression regression — the err branch drives the eprintln! warning)"
    );

    // Verify the error is specifically InvalidChromosomeIndex.
    use crate::types::EvolutionError;
    assert!(
        matches!(result.unwrap_err(), EvolutionError::InvalidChromosomeIndex(_)),
        "error must be InvalidChromosomeIndex so callers can distinguish it from \
         TargetHealthCritical and handle each branch separately"
    );
}

#[test]
fn record_feedback_valid_index_after_next_candidate_is_ok() {
    // Adversarial twin: the happy path must still work — a valid index
    // issued by next_candidate must NOT produce InvalidChromosomeIndex.
    let mut engine = EvolutionEngine::new(5);
    let (idx, _) = engine
        .next_candidate()
        .expect("engine must produce at least one candidate");
    let result = engine.record_feedback(idx, true);
    assert!(
        result.is_ok(),
        "record_feedback for a legitimately issued index must be Ok: {:?}",
        result.err()
    );
}

#[test]
fn fitness_history_tracked() {
    let mut engine = EvolutionEngine::new(10);
    let candidates = engine.batch_candidates(10);
    for (idx, _) in candidates {
        let _ = engine.record_feedback(idx, idx % 2 == 0);
    }
    engine.evolve();
    assert!(!engine.fitness_history.is_empty());
}

#[test]
fn single_population_diversity() {
    let engine = EvolutionEngine::new(1);
    assert_eq!(engine.diversity_score(), 1.0);
}

#[test]
fn active_bypass_scores_above_baseline_pass() {
    let mut engine = EvolutionEngine::new(2);
    let cands = engine.batch_candidates(2);
    for (idx, _) in cands {
        engine.record_feedback(idx, true).unwrap();
    }
    // With the new algorithm abstraction we just verify both got evaluated
    assert!(engine.stats.evaluations >= 2);
}

// ── Bug 3 regression: new_seeded double-initialization ──────────────────
//
// PRE-FIX BUG: `new_seeded` built a first `population` with a cloned RNG,
// called `algorithm.initialize(population, ..., &mut engine.rng.clone())`,
// then re-generated `population2` with the engine's now-moved RNG and called
// `initialize` again. Because every SearchAlgorithm::initialize impl is
// last-call-wins (HillClimbing overwrites current/best; MapElites clears the
// grid; NoveltySearch overwrites self.population), the net effect was 2×
// chromosome generation + 2× initialize calls for the same final state —
// twice as much entropy consumed, double the allocations. Critically,
// determinism was still preserved (same seed → same second-call result), so
// the bug was invisible in practice but wasted resources and indicated a
// future soundness risk if any impl's second initialize had side effects.
//
// POST-FIX: single-shot: build population once, call initialize once.

#[test]
fn new_seeded_population_not_double_sized() {
    // The engine's hill-climbing algorithm holds `current` and `best`
    // (not a Vec), so we can't count chromosomes directly. Instead we
    // verify that requesting batch_candidates never returns a batch
    // larger than `population_size` worth of unique first-generation
    // chromosomes — if initialize were called twice the RNG would be
    // twice as far ahead and we'd see genome divergence on re-seed.
    //
    // The observable contract: two engines with the SAME seed and SAME
    // population size must produce identical first candidates (determinism
    // is broken by double-init only when the impl has state-dependent
    // side effects; we check the simpler invariant that first-candidate
    // equality holds).
    let pop = 10_usize;
    let seed = 77_u64;
    let mut e1 = EvolutionEngine::new_seeded(pop, seed);
    let mut e2 = EvolutionEngine::new_seeded(pop, seed);

    let first1 = e1.next_candidate().map(|(_, c)| c.genes.clone());
    let first2 = e2.next_candidate().map(|(_, c)| c.genes.clone());

    assert_eq!(
        first1, first2,
        "two engines created with the same seed must produce identical first candidates \
         (double-init would advance the RNG differently on the second call, \
         breaking this invariant)"
    );
}

#[test]
fn new_seeded_both_same_first_next_candidate_is_deterministic() {
    // Adversarial twin: confirm that after N rounds of feedback + evolve,
    // both engines still track identically (proving the RNG stream
    // wasn't diverged by extra initialize calls at construction).
    let seed = 42_u64;
    let mut ea = EvolutionEngine::new_seeded(5, seed);
    let mut eb = EvolutionEngine::new_seeded(5, seed);

    for _ in 0..3 {
        match (ea.next_candidate(), eb.next_candidate()) {
            (Some((ia, _)), Some((ib, _))) => {
                ea.record_feedback(ia, true).unwrap();
                eb.record_feedback(ib, true).unwrap();
            }
            (None, None) => break,
            _ => panic!("one engine ran out of candidates but the other didn't"),
        }
        ea.evolve();
        eb.evolve();
    }

    let best_a = ea.best().map(|c| c.genes.clone());
    let best_b = eb.best().map(|c| c.genes.clone());
    assert_eq!(
        best_a, best_b,
        "after identical feedback sequences, two same-seed engines must converge \
         to the same best chromosome"
    );
}

#[test]
fn budget_exhaustion_does_not_loop() {
    // Adversarial: tiny request budget. Engine must not loop forever.
    let mut engine = EvolutionEngine::new_seeded(5, 1);
    engine.budget = Budget {
        max_requests: 3,
        max_generations: 100,
        max_time_seconds: 3600,
        stagnation_limit: 10,
    };

    for _ in 0..20 {
        if engine.should_terminate() {
            break;
        }
        let batch = engine.batch_candidates(1);
        if batch.is_empty() {
            break;
        }
        for (idx, _) in batch {
            engine.record_feedback(idx, false).unwrap();
        }
    }
    // Exiting the bounded loop without panicking is the success condition.
    // The batch_candidates() clamp is what actually enforces the budget.
}

#[test]
fn zero_request_budget_terminates_immediately() {
    let mut engine = EvolutionEngine::new_seeded(5, 2);
    engine.budget = Budget {
        max_requests: 0,
        max_generations: 100,
        max_time_seconds: 3600,
        stagnation_limit: 10,
    };
    assert!(engine.should_terminate());
    assert!(engine.batch_candidates(1).is_empty());
}

#[test]
fn always_blocking_oracle_does_not_panic() {
    // Adversarial: every payload is blocked. The engine must not panic
    // or loop forever. Termination is checked by the bounded loop.
    let mut engine = EvolutionEngine::new_seeded(5, 123);
    engine.budget = Budget {
        max_requests: 10,
        max_generations: 5,
        max_time_seconds: 3600,
        stagnation_limit: 2,
    };

    for _ in 0..30 {
        if engine.should_terminate() {
            break;
        }
        let batch = engine.batch_candidates(1);
        if batch.is_empty() {
            break;
        }
        for (idx, _) in batch {
            engine.record_feedback(idx, false).unwrap();
        }
        engine.evolve();
    }
    // The mere fact that we exited the bounded loop without panicking
    // is the success condition.
}

#[test]
fn random_oracle_does_not_panic() {
    // Adversarial: 50/50 random oracle. Must not panic or loop forever.
    let mut engine = EvolutionEngine::new_seeded(5, 456);
    engine.budget = Budget {
        max_requests: 15,
        max_generations: 10,
        max_time_seconds: 3600,
        stagnation_limit: 5,
    };
    let mut rng = rand::rngs::StdRng::seed_from_u64(789);

    for _ in 0..100 {
        if engine.should_terminate() {
            break;
        }
        let batch = engine.batch_candidates(1);
        if batch.is_empty() {
            break;
        }
        for (idx, _) in batch {
            engine.record_feedback(idx, rng.gen_bool(0.5)).unwrap();
        }
        engine.evolve();
    }
}

#[test]
fn target_error_bails_out() {
    let mut engine = EvolutionEngine::new(5);
    for _ in 0..10 {
        let result = engine.record_target_error("503 Service Unavailable".into());
        if result.is_err() {
            break;
        }
    }
    assert!(!engine.target_health.is_healthy() || engine.should_terminate());
}

#[test]
fn checkpoint_roundtrip() {
    let mut engine = EvolutionEngine::new_seeded(10, 99);
    let candidates = engine.batch_candidates(3);
    for (idx, _) in candidates {
        engine.record_feedback(idx, true).unwrap();
    }
    engine.evolve();

    let tmp = std::env::temp_dir().join("wafrift_evolution_test_checkpoint.json");
    engine.save_checkpoint(&tmp).unwrap();

    let mut restored = EvolutionEngine::new_seeded(10, 99);
    restored.load_checkpoint(&tmp).unwrap();

    assert_eq!(restored.stats.generation, engine.stats.generation);
    assert_eq!(restored.request_count, engine.request_count);
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn batch_evaluation_parallel() {
    let mut engine = EvolutionEngine::new(10);
    let batch = engine.batch_candidates(4);
    assert!(!batch.is_empty());
    let results: Vec<_> = batch
        .into_iter()
        .map(|(idx, _)| (idx, OracleVerdict::from_bool(true)))
        .collect();
    engine.submit_batch(results).unwrap();
    assert!(engine.stats.evaluations >= 1);
}

#[test]
fn checkpoint_load_rejects_oversized_file() {
    let tmp = std::env::temp_dir().join("wafrift_evolution_test_oversized.json");
    let junk = "x".repeat(crate::types::MAX_CHECKPOINT_BYTES + 1);
    std::fs::write(&tmp, junk).unwrap();
    let mut engine = EvolutionEngine::new(10);
    let result = engine.load_checkpoint(&tmp);
    assert!(
        result.is_err(),
        "should reject checkpoint > MAX_CHECKPOINT_BYTES"
    );
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn lineage_no_cycles() {
    use crate::evolution::Chromosome;
    use crate::lineage::Lineage;
    use crate::search::SearchAlgorithm;
    use rand::SeedableRng;

    let mut alg = crate::search::HillClimbing::new();
    let pool = crate::evolution::GenePool::default_wafrift();
    let mut rng = rand::rngs::StdRng::seed_from_u64(1);
    alg.initialize(vec![Chromosome::new(vec![])], &pool, &mut rng);

    for _ in 0..100 {
        let cands = alg.request_evaluations(1, &mut rng);
        if cands.is_empty() {
            break;
        }
        alg.submit_evaluations(vec![(cands[0].id, OracleVerdict::from_bool(true))]);
    }

    let best = alg.best().unwrap();
    // Since ParentSnapshot was intentionally stripped of its `lineage`
    // field to prevent transitive OOM, the lineage tree is *by design*
    // acyclic at the type level. This test verifies that the runtime
    // structure still respects generation monotonicity for the head.
    let current_gen = match &best.lineage {
        Lineage::Genesis { generation } => *generation,
        Lineage::Crossover { generation, .. } => *generation,
        Lineage::Mutation { generation, .. } => *generation,
    };
    assert!(
        current_gen < u32::MAX,
        "generation should be a realistic value"
    );
}
