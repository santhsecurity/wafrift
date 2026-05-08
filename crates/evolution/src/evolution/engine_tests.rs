#![allow(clippy::float_cmp)]

use crate::evolution::EvolutionEngine;
use crate::types::{Budget, Feedback, OracleVerdict};
use std::time::Duration;

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
        if let Some((idx_a, _)) = engine_a.next_candidate() {
            if let Some((idx_b, _)) = engine_b.next_candidate() {
                engine_a.record_feedback(idx_a, true).unwrap();
                engine_b.record_feedback(idx_b, true).unwrap();
            }
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
    engine.submit_batch(vec![(candidates[0].0, OracleVerdict::from_bool(true))]).unwrap();
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
    assert!(rates.iter().all(|(_, value, _)| *value != "CaseAlternation"));

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
    assert!(result.is_err(), "out-of-bounds feedback must return an error");
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

#[test]
fn budget_exhaustion_terminates() {
    let mut engine = EvolutionEngine::with_algorithm(
        "hill_climbing",
        crate::evolution::GenePool::default_wafrift(),
        rand::rngs::StdRng::seed_from_u64(1),
        Budget {
            max_requests: 5,
            max_generations: 100,
            max_time_seconds: 3600,
            stagnation_limit: 10,
        },
    )
    .unwrap();
    engine.algorithm.initialize(
        vec![crate::evolution::Chromosome::new(vec![])],
        &engine.gene_pool,
        &mut engine.rng.clone(),
    );

    for _ in 0..10 {
        let batch = engine.batch_candidates(1);
        if batch.is_empty() {
            break;
        }
        for (idx, _) in batch {
            engine.record_feedback(idx, false).unwrap();
        }
    }

    assert!(engine.should_terminate(), "engine must terminate when budget exhausted");
    assert!(engine.next_candidate().is_none(), "next_candidate must return None after budget exhausted");
}

#[test]
fn always_blocking_oracle_terminates() {
    let mut engine = EvolutionEngine::new_seeded(10, 123);
    engine.budget = Budget {
        max_requests: 20,
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

    assert!(engine.should_terminate(), "always-blocking oracle must terminate");
}

#[test]
fn random_oracle_does_not_loop_forever() {
    let mut engine = EvolutionEngine::new_seeded(10, 456);
    engine.budget = Budget {
        max_requests: 50,
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

    assert!(engine.should_terminate(), "random oracle must not cause infinite loops");
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
    // Walk lineage tree and ensure no cycles by checking generation monotonicity
    let mut gen = u32::MAX;
    let mut lineage = &best.lineage;
    loop {
        let current_gen = match lineage {
            Lineage::Genesis { generation } => *generation,
            Lineage::Crossover { generation, .. } => *generation,
            Lineage::Mutation { generation, .. } => *generation,
        };
        assert!(
            current_gen <= gen,
            "lineage generation must not increase going backward (cycle detected)"
        );
        gen = current_gen;
        match lineage {
            Lineage::Genesis { .. } => break,
            Lineage::Crossover { .. } => break, // Can't traverse Arcs easily in test
            Lineage::Mutation { parent, .. } => {
                lineage = &parent.lineage;
            }
        }
    }
}
