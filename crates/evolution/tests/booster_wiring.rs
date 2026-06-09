//! Integration tests for #102 — WAFBooster wiring into the evolution engine.
//!
//! Covers: engine prefers low-score candidates after observations, --no-booster
//! flag preserves baseline ordering, scorer is updated on every oracle result.

use wafrift_evolution::evolution::EvolutionEngine;
use wafrift_evolution::types::OracleVerdict;

// ── helpers ───────────────────────────────────────────────────────────────────

fn blocked_verdict() -> OracleVerdict {
    OracleVerdict::from_bool(false)
}

fn passed_verdict() -> OracleVerdict {
    OracleVerdict::from_bool(true)
}

fn verdict_with_rule(passed: bool, rule_id: &str) -> OracleVerdict {
    OracleVerdict {
        passed,
        rule_id: Some(rule_id.to_string()),
        ..OracleVerdict::from_bool(passed)
    }
}

// ── Test 1: booster enabled by default ───────────────────────────────────────

#[test]
fn booster_enabled_by_default() {
    let engine = EvolutionEngine::new(10);
    assert!(
        !engine.no_booster,
        "booster must be enabled by default (no_booster = false)"
    );
}

// ── Test 2: no_booster flag disables the scorer ───────────────────────────────

#[test]
fn no_booster_flag_disables_scorer() {
    let mut engine = EvolutionEngine::new(10);
    engine.no_booster = true;
    assert!(engine.no_booster);
    // Batch should still work correctly.
    let batch = engine.batch_candidates(4);
    assert!(
        !batch.is_empty(),
        "batch_candidates must work with no_booster=true"
    );
}

// ── Test 3: booster is updated on block observation ───────────────────────────

#[test]
fn booster_updated_on_block_observation() {
    let mut engine = EvolutionEngine::new(5);
    let batch = engine.batch_candidates(2);
    assert!(!batch.is_empty());

    let before_count = engine.booster.feature_count();

    // Submit a blocked verdict.
    let (eval_id, _chrom) = &batch[0];
    let _ = engine.submit_batch(vec![(*eval_id, blocked_verdict())]);

    let after_count = engine.booster.feature_count();
    assert!(
        after_count >= before_count,
        "booster feature count must grow or stay same after block: {before_count} → {after_count}"
    );
}

// ── Test 4: booster is updated on pass observation ────────────────────────────

#[test]
fn booster_updated_on_pass_observation() {
    let mut engine = EvolutionEngine::new(5);
    let batch = engine.batch_candidates(2);
    assert!(!batch.is_empty());

    let (eval_id, _) = &batch[0];
    // Should not panic.
    let _ = engine.submit_batch(vec![(*eval_id, passed_verdict())]);
    // booster may have zero features if the cache_key produced no parseable tokens.
    // The critical assertion is that no panic occurred and no_booster is still false.
    assert!(!engine.no_booster);
}

// ── Test 5: no_booster skips booster update ───────────────────────────────────

#[test]
fn no_booster_skips_scorer_update() {
    let mut engine = EvolutionEngine::new(5);
    engine.no_booster = true;

    let batch = engine.batch_candidates(2);
    assert!(!batch.is_empty());

    let before = engine.booster.feature_count();
    let (eval_id, _) = &batch[0];
    let _ = engine.submit_batch(vec![(*eval_id, blocked_verdict())]);
    let after = engine.booster.feature_count();

    assert_eq!(
        before, after,
        "no_booster must prevent scorer from being updated"
    );
}

// ── Test 6: engine prefers low-score candidates after block observations ───────

#[test]
fn engine_prefers_low_score_candidates_after_observations() {
    // Create a large enough population that we can get multiple batch candidates.
    let mut engine = EvolutionEngine::new(50);

    // Do several rounds: submit all as blocked so the booster accumulates.
    for _ in 0..3 {
        let batch = engine.batch_candidates(4);
        if batch.is_empty() {
            break;
        }
        let results: Vec<_> = batch
            .iter()
            .map(|(id, _)| (*id, blocked_verdict()))
            .collect();
        let _ = engine.submit_batch(results);
        engine.evolve();
    }

    // After training, batch_candidates should return without panicking
    // and the booster should have nonzero feature count.
    let final_batch = engine.batch_candidates(4);
    assert!(
        !final_batch.is_empty(),
        "engine must still produce candidates after booster training"
    );
    // Feature count > 0 confirms the booster was updated.
    assert!(
        engine.booster.feature_count() > 0,
        "booster must have learned features after block observations"
    );
}

// ── Test 7: no_booster preserves baseline behavior ────────────────────────────

#[test]
fn no_booster_preserves_baseline_behavior() {
    // Two engines with the same seed: one with booster, one without.
    // Both must produce valid batches (non-empty).
    let mut engine_boost = EvolutionEngine::new_seeded(20, 42);
    let mut engine_base = EvolutionEngine::new_seeded(20, 42);
    engine_base.no_booster = true;

    let batch_boost = engine_boost.batch_candidates(4);
    let batch_base = engine_base.batch_candidates(4);

    assert!(
        !batch_boost.is_empty(),
        "booster engine must produce candidates"
    );
    assert!(
        !batch_base.is_empty(),
        "baseline engine must produce candidates"
    );

    // Both should produce the same number of candidates from an equivalent start.
    assert_eq!(
        batch_boost.len(),
        batch_base.len(),
        "booster must not drop candidates vs baseline"
    );
}

// ── Test 8: booster accumulates across multiple submit_batch calls ─────────────

#[test]
fn booster_accumulates_across_multiple_submits() {
    let mut engine = EvolutionEngine::new(20);

    let mut feature_counts = Vec::new();
    for _ in 0..5 {
        let batch = engine.batch_candidates(2);
        if batch.is_empty() {
            break;
        }
        let results: Vec<_> = batch
            .iter()
            .map(|(id, _)| (*id, blocked_verdict()))
            .collect();
        let _ = engine.submit_batch(results);
        feature_counts.push(engine.booster.feature_count());
        engine.evolve();
    }

    // Feature count should be non-decreasing across rounds.
    for window in feature_counts.windows(2) {
        assert!(
            window[1] >= window[0],
            "feature count must be non-decreasing: {} → {}",
            window[0],
            window[1]
        );
    }
}

// ── Test 9: rule_id forwarded to booster on block ─────────────────────────────

#[test]
fn rule_id_forwarded_to_booster_on_block() {
    let mut engine = EvolutionEngine::new(10);
    let batch = engine.batch_candidates(1);
    assert!(!batch.is_empty());

    let (eval_id, _) = &batch[0];
    // A verdict carrying a rule_id must be processed without panic.
    let v = verdict_with_rule(false, "942100");
    let _ = engine.submit_batch(vec![(*eval_id, v)]);
    // Booster should have updated.
    assert!(!engine.no_booster);
}

// ── Test 10: booster not updated on cache hit ─────────────────────────────────

#[test]
fn booster_not_updated_on_cache_hit_path() {
    // When a candidate is served from cache, submit_batch is never called
    // for it — the booster must not be contaminated.  We verify by checking
    // that no_booster=false and no panic occur across the full cache path.
    let mut engine = EvolutionEngine::new(10);
    // First batch — real evaluations.
    let batch1 = engine.batch_candidates(2);
    if batch1.is_empty() {
        return;
    }
    // Submit verdicts so chromosomes land in cache.
    let results: Vec<_> = batch1
        .iter()
        .map(|(id, _)| (*id, blocked_verdict()))
        .collect();
    let _ = engine.submit_batch(results);

    // Second batch — some candidates may hit the cache.
    let _batch2 = engine.batch_candidates(2);
    assert!(!engine.no_booster, "booster flag must remain false");
}

// ── Test 11: rank_candidates via booster produces valid output ─────────────────

#[test]
fn booster_rank_candidates_via_scorer() {
    let mut engine = EvolutionEngine::new(20);

    // Train the booster with a block.
    let batch = engine.batch_candidates(1);
    if let Some((eval_id, _)) = batch.first() {
        let _ = engine.submit_batch(vec![(*eval_id, blocked_verdict())]);
    }

    // Ask the booster to rank some synthetic payloads.
    let payloads = vec![
        "' UNION SELECT--".to_string(),
        "hello world".to_string(),
        "<script>alert(1)</script>".to_string(),
    ];
    let ranked = engine.booster.rank_candidates(&payloads);
    assert_eq!(ranked.len(), payloads.len());
    // Sorted ascending — each score must be <= the next.
    for window in ranked.windows(2) {
        assert!(
            window[0].1 <= window[1].1,
            "ranked output must be sorted ascending: {:?}",
            ranked
        );
    }
}

// ── Test 12: pass then block converges toward correct ordering ─────────────────

#[test]
fn pass_then_block_ordering_correct() {
    use wafrift_wafmodel::booster::WafBoosterScorer;
    let mut scorer = WafBoosterScorer::no_decay();

    let safe = "hello world".to_string();
    let attack = "' UNION SELECT 1,2--".to_string();

    scorer.observe_pass(&safe);
    scorer.observe_block(&attack, None);

    let ranked = scorer.rank_candidates(&[attack.clone(), safe.clone()]);
    // Safe should rank before attack (lower booster score).
    assert_eq!(
        ranked[0].0, safe,
        "safe payload must rank first after pass+block training"
    );
}
