//! Comprehensive coverage for `EvolutionEngine::clone` and the new
//! `SharedEngine` shared-access pattern.
//!
//! Closes blocker #113: previously `clone` round-tripped through
//! serde_json (`checkpoint` → `restore`), spiking allocations on
//! populated MapElites grids and novelty archives. The refactor uses
//! the trait's `clone_box` method (each in-tree algorithm overrides
//! with a direct `Clone`) and exposes `SharedEngine` for the proper
//! shared-state pattern.

use std::time::Instant;

use rand::SeedableRng;
use rand::rngs::StdRng;
use wafrift_evolution::evolution::{
    Chromosome, EvolutionEngine, GenePool, baseline_chromosome, random_chromosome,
};
use wafrift_evolution::types::{Budget, OracleVerdict};

fn engine_with(algo: &str, seed: u64) -> EvolutionEngine {
    let pool = GenePool::default_wafrift();
    let rng = StdRng::seed_from_u64(seed);
    EvolutionEngine::with_algorithm(algo, pool, rng, Budget::default())
        .expect("registered algorithm")
}

fn random_population(pool: &GenePool, n: usize, seed: u64) -> Vec<Chromosome> {
    let mut rng = StdRng::seed_from_u64(seed);
    (0..n).map(|_| random_chromosome(pool, &mut rng)).collect()
}

// ── correctness ─────────────────────────────────────────────────────

#[test]
fn clone_preserves_algorithm_best_chromosome() {
    let mut engine = engine_with("novelty_search", 1);
    let pool = engine.gene_pool.clone();
    engine.seed_population(random_population(&pool, 8, 7));
    let original_best = engine.population_snapshot();
    let cloned = engine.clone();
    let cloned_best = cloned.population_snapshot();
    assert_eq!(
        original_best.len(),
        cloned_best.len(),
        "cloned snapshot must have the same chromosome count"
    );
    for (a, b) in original_best.iter().zip(cloned_best.iter()) {
        assert_eq!(a.genes, b.genes, "clone must preserve gene contents");
    }
}

#[test]
fn clone_preserves_gene_stats_and_corpus_state() {
    let mut engine = engine_with("hill_climbing", 2);
    engine.gene_stats = vec![
        ("encoder".into(), "url".into(), 7, 10),
        ("padding".into(), "low".into(), 3, 6),
    ];
    engine.request_count = 42;
    engine.stagnation_counter = 3;
    let cloned = engine.clone();
    assert_eq!(cloned.gene_stats, engine.gene_stats);
    assert_eq!(cloned.request_count, engine.request_count);
    assert_eq!(cloned.stagnation_counter, engine.stagnation_counter);
}

#[test]
fn clone_starts_with_empty_in_flight_set() {
    let mut engine = engine_with("hill_climbing", 3);
    let pool = engine.gene_pool.clone();
    let chromosome = baseline_chromosome(&pool);
    engine
        .in_flight
        .insert(99, (99, chromosome, std::time::Instant::now()));
    let cloned = engine.clone();
    assert_eq!(
        cloned.in_flight.len(),
        0,
        "in_flight is per-engine and must not survive a clone"
    );
}

#[test]
fn clone_starts_with_empty_cache_at_same_capacity() {
    let mut engine = engine_with("hill_climbing", 4);
    engine
        .cache
        .put("hot".into(), OracleVerdict::from_bool(true));
    engine
        .cache
        .put("warm".into(), OracleVerdict::from_bool(false));
    assert_eq!(engine.cache.len(), 2);
    let cloned = engine.clone();
    assert_eq!(
        cloned.cache.len(),
        0,
        "cache is intentionally drained on clone — use SharedEngine for sharing"
    );
    assert_eq!(
        cloned.cache.cap(),
        engine.cache.cap(),
        "cache capacity must be preserved"
    );
}

#[test]
fn clone_is_independent_of_original_for_subsequent_writes() {
    let mut engine = engine_with("novelty_search", 5);
    let pool = engine.gene_pool.clone();
    engine.seed_population(random_population(&pool, 4, 11));
    let mut cloned = engine.clone();

    // Mutate the original — the clone's snapshot must not change.
    let snapshot_before = cloned.population_snapshot();
    engine.seed_population(random_population(&pool, 12, 99));
    let snapshot_after = cloned.population_snapshot();
    assert_eq!(
        snapshot_before, snapshot_after,
        "mutating the original must not leak into the clone"
    );

    // Mutate the clone — the original's snapshot must not change.
    let original_before = engine.population_snapshot();
    cloned.seed_population(random_population(&pool, 1, 33));
    let original_after = engine.population_snapshot();
    assert_eq!(
        original_before, original_after,
        "mutating the clone must not leak into the original"
    );
}

// ── perf gate ───────────────────────────────────────────────────────

#[test]
fn clone_of_populated_map_elites_engine_under_50ms() {
    // The original blocker called out clone spikes on populated state.
    // Seed a MapElites grid with 100 distinct chromosomes and gate
    // clone time at 50ms — the serde_json path used to take 200ms+
    // for similar payloads.
    let mut engine = engine_with("map_elites", 6);
    let pool = engine.gene_pool.clone();
    engine.seed_population(random_population(&pool, 100, 0));

    // Warm up — first clone may include cache effects we don't care
    // about for the perf gate.
    let _warmup = engine.clone();

    let t = Instant::now();
    let _cloned = engine.clone();
    let elapsed = t.elapsed();
    assert!(
        elapsed.as_millis() < 50,
        "populated MapElites clone took {elapsed:?}, must be <50ms"
    );
}

#[test]
fn clone_of_populated_novelty_engine_under_100ms() {
    let mut engine = engine_with("novelty_search", 7);
    let pool = engine.gene_pool.clone();
    engine.seed_population(random_population(&pool, 100, 0));
    let _warmup = engine.clone();

    let t = Instant::now();
    let _cloned = engine.clone();
    let elapsed = t.elapsed();
    assert!(
        elapsed.as_millis() < 100,
        "populated novelty clone took {elapsed:?}, must be <100ms"
    );
}

#[test]
fn many_sequential_clones_do_not_accumulate_state() {
    let mut engine = engine_with("novelty_search", 8);
    let pool = engine.gene_pool.clone();
    engine.seed_population(random_population(&pool, 16, 0));
    let baseline_population = engine.population_snapshot();

    // Cascade clone N times — final clone's snapshot must match
    // the original's, byte-for-byte.
    let mut tip = engine.clone();
    for _ in 0..32 {
        tip = tip.clone();
    }
    assert_eq!(
        tip.population_snapshot(),
        baseline_population,
        "32 sequential clones must not drift the population"
    );
}

// ── SharedEngine semantics ──────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_engine_concurrent_readers_do_not_block_each_other() {
    let engine = engine_with("hill_climbing", 9);
    let shared = engine.into_shared();

    let s1 = shared.clone();
    let s2 = shared.clone();
    let s3 = shared.clone();

    let h1 = tokio::spawn(async move {
        let g = s1.read().await;
        let _ = g.population_snapshot();
        std::thread::sleep(std::time::Duration::from_millis(20));
        g.request_count
    });
    let h2 = tokio::spawn(async move {
        let g = s2.read().await;
        let _ = g.population_snapshot();
        std::thread::sleep(std::time::Duration::from_millis(20));
        g.request_count
    });
    let h3 = tokio::spawn(async move {
        let g = s3.read().await;
        let _ = g.population_snapshot();
        std::thread::sleep(std::time::Duration::from_millis(20));
        g.request_count
    });

    let t = Instant::now();
    let r = tokio::join!(h1, h2, h3);
    let elapsed = t.elapsed();
    let (a, b, c) = (r.0.unwrap(), r.1.unwrap(), r.2.unwrap());
    assert_eq!(a, 0);
    assert_eq!(b, 0);
    assert_eq!(c, 0);
    // Concurrent readers should overlap — total wall time must be
    // closer to 20ms (one reader's hold time) than 60ms (three
    // serialised holds). Allow a generous buffer for scheduler
    // jitter under load.
    assert!(
        elapsed.as_millis() < 50,
        "concurrent readers serialised — took {elapsed:?} for three 20ms holds"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_engine_writer_excludes_readers() {
    let engine = engine_with("hill_climbing", 10);
    let shared = engine.into_shared();

    let writer_started = std::sync::Arc::new(tokio::sync::Notify::new());
    let writer_started_clone = writer_started.clone();
    let writer = {
        let s = shared.clone();
        let n = writer_started_clone.clone();
        tokio::spawn(async move {
            let mut g = s.write().await;
            n.notify_one();
            // Hold the write lock briefly.
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            g.request_count = 999;
        })
    };

    // Wait for the writer to grab the lock first.
    writer_started.notified().await;

    let t = Instant::now();
    let read_value = {
        let g = shared.read().await;
        g.request_count
    };
    let elapsed = t.elapsed();

    writer.await.unwrap();
    assert_eq!(
        read_value, 999,
        "reader saw stale state — write didn't take effect before read"
    );
    assert!(
        elapsed.as_millis() >= 15,
        "reader didn't actually wait on the writer — got {elapsed:?}"
    );
}

#[tokio::test]
async fn shared_engine_arc_clone_is_cheap() {
    // Sanity: cloning an Arc<RwLock<EvolutionEngine>> must not
    // duplicate engine state — that's the whole point of the
    // SharedEngine type.
    let engine = engine_with("novelty_search", 11);
    let shared = engine.into_shared();

    let snapshot = shared.read().await.population_snapshot();
    let s2 = shared.clone();
    let snapshot2 = s2.read().await.population_snapshot();
    assert_eq!(
        snapshot, snapshot2,
        "cloning the Arc must produce a pointer to the same state"
    );

    // Mutating through one handle must be visible through the other.
    {
        let mut g = shared.write().await;
        g.request_count = 7;
    }
    assert_eq!(s2.read().await.request_count, 7);
}

// ── file-checkpoint round trip still works (unchanged path) ────────

#[test]
fn save_load_checkpoint_round_trip_unchanged_by_clone_refactor() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "wafrift-engine-clone-test-{}.ckpt.json",
        std::process::id()
    ));
    {
        let mut engine = engine_with("hill_climbing", 12);
        engine.request_count = 17;
        engine.stagnation_counter = 4;
        engine
            .save_checkpoint(&path)
            .expect("save_checkpoint must succeed");
    }
    let mut restored = engine_with("hill_climbing", 13);
    restored
        .load_checkpoint(&path)
        .expect("load_checkpoint must succeed");
    assert_eq!(restored.request_count, 17);
    assert_eq!(restored.stagnation_counter, 4);
    let _ = std::fs::remove_file(&path);
}
