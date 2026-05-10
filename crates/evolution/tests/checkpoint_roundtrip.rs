//! Regression test for the 2026-05-10 audit finding:
//!
//!   save_checkpoint hardcoded rng_seed: 0 and EngineState omitted
//!   corpus, in_flight, cache, next_id, generation_evals,
//!   target_health, checkpoint_path, pending_single. A restored
//!   engine lost ALL bypass discoveries and reset its eval-id counter
//!   to 0 — mid-run crashes silently destroyed work.
//!
//! Schema bumped to v2: corpus + next_id + generation_evals are now
//! captured. v1 checkpoints still load via `#[serde(default)]`.

use rand::Rng;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::path::PathBuf;
use wafrift_evolution::evolution::{EvolutionEngine, GenePool};
use wafrift_evolution::lineage::BypassEntry;
use wafrift_evolution::types::{Budget, OracleVerdict};

fn tmp_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let mut rng = StdRng::seed_from_u64(0xC0FFEE);
    let nonce: u64 = rng.r#gen();
    p.push(format!("wafrift_checkpoint_{name}_{nonce:x}.bin"));
    p
}

fn engine_with_chromosome_run() -> EvolutionEngine {
    let mut engine = EvolutionEngine::new(8);
    // Drive a few rounds so next_id, gene_stats, fitness_history all
    // accumulate non-default values.
    for _ in 0..5 {
        let batch = engine.batch_candidates(4);
        if batch.is_empty() {
            break;
        }
        let results: Vec<(usize, OracleVerdict)> = batch
            .into_iter()
            .map(|(id, _)| (id, OracleVerdict::from_bool(true)))
            .collect();
        engine.submit_batch(results).expect("submit");
        engine.evolve();
    }
    engine
}

#[test]
fn checkpoint_preserves_corpus() {
    let path = tmp_path("corpus");
    let mut engine = engine_with_chromosome_run();

    // Inject a known bypass into the corpus.
    let pool = GenePool::default_wafrift();
    let baseline = wafrift_evolution::evolution::population::baseline_chromosome(&pool);
    let entry = BypassEntry::from_chromosome(&baseline, Some("smoke-target".to_string()));
    engine.corpus.add(entry.clone());
    let pre_count = engine.corpus.entries.len();
    assert!(pre_count > 0, "corpus should have at least the injected entry");

    engine.save_checkpoint(&path).expect("save");

    // Fresh engine — corpus must be empty until load.
    let mut restored = EvolutionEngine::new(8);
    assert_eq!(restored.corpus.entries.len(), 0);

    restored.load_checkpoint(&path).expect("load");
    assert_eq!(
        restored.corpus.entries.len(),
        pre_count,
        "corpus must survive checkpoint roundtrip; pre-fix this was 0"
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn checkpoint_preserves_next_id() {
    let path = tmp_path("next_id");
    let engine = engine_with_chromosome_run();
    let pre_next_id = engine.next_id();
    assert!(
        pre_next_id > 0,
        "after 5 rounds of batch_candidates next_id must have advanced"
    );

    engine.save_checkpoint(&path).expect("save");

    let mut restored = EvolutionEngine::new(8);
    assert_eq!(restored.next_id(), 0);
    restored.load_checkpoint(&path).expect("load");
    assert_eq!(
        restored.next_id(), pre_next_id,
        "next_id must survive checkpoint roundtrip; pre-fix it reset to 0 \
         and could collide with an in-flight eval that survived the crash"
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn checkpoint_preserves_request_count_and_stats() {
    // Spot-check fields that WERE serialized in v1 to make sure we
    // didn't regress any of them while adding v2 fields.
    let path = tmp_path("stats");
    let engine = engine_with_chromosome_run();
    let pre_requests = engine.request_count;
    let pre_evals = engine.stats.evaluations;
    let pre_gen = engine.stats.generation;
    assert!(pre_requests > 0);
    assert!(pre_evals > 0);

    engine.save_checkpoint(&path).expect("save");
    let mut restored = EvolutionEngine::new(8);
    restored.load_checkpoint(&path).expect("load");

    assert_eq!(restored.request_count, pre_requests);
    assert_eq!(restored.stats.evaluations, pre_evals);
    assert_eq!(restored.stats.generation, pre_gen);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn v1_checkpoint_loads_into_v2_engine_with_default_corpus() {
    // Backwards-compat: a v1 checkpoint payload (no corpus / next_id
    // / generation_evals fields) must still load. We forge the v1
    // shape directly via serde_json instead of writing a v1 binary.
    let path = tmp_path("v1_compat");

    // Take a real engine, save it, then re-open the file and
    // serialize a stripped-down v1 shape over it.
    let engine = engine_with_chromosome_run();
    engine.save_checkpoint(&path).expect("save");
    let raw = std::fs::read(&path).expect("read");

    let mut value: serde_json::Value = serde_json::from_slice(&raw).expect("parse json");
    if let Some(obj) = value.as_object_mut() {
        obj.remove("corpus");
        obj.remove("next_id");
        obj.remove("generation_evals");
        obj.insert(
            "schema_version".into(),
            serde_json::Value::from(1u32),
        );
    }
    let v1_bytes = serde_json::to_vec(&value).expect("reserialize");
    std::fs::write(&path, v1_bytes).expect("write v1");

    let mut restored = EvolutionEngine::new(8);
    restored
        .load_checkpoint(&path)
        .expect("v1 checkpoint must load via serde defaults");
    assert_eq!(
        restored.corpus.entries.len(),
        0,
        "v1 checkpoint has no corpus → empty corpus after load"
    );
    assert_eq!(restored.next_id(), 0, "v1 checkpoint has no next_id → 0");

    let _ = std::fs::remove_file(&path);
}
