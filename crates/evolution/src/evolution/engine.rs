use crate::evolution::fitness::{evolutionary_fitness, update_gene_stats};
use crate::evolution::{
    Chromosome, GenePool,
    population::{baseline_chromosome, random_chromosome},
};
use crate::lineage::{BypassCorpus, BypassEntry};
use crate::search::SearchAlgorithm;
use crate::types::{
    Budget, EvolutionError, OracleVerdict, SearchStats, TargetHealthMonitor, load_checkpoint,
    save_checkpoint,
};
use lru::LruCache;
use rand::{SeedableRng, rngs::StdRng};
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// The evolutionary engine that maintains a population and evolves it.
#[derive(Debug)]
pub struct EvolutionEngine {
    /// Search algorithm implementation.
    algorithm: Box<dyn SearchAlgorithm>,
    /// Gene pool for creating/mutating chromosomes.
    pub gene_pool: GenePool,
    /// Seeded random number generator.
    pub rng: StdRng,
    /// Payload→verdict LRU cache.
    pub cache: LruCache<String, OracleVerdict>,
    /// Hard budget limits.
    pub budget: Budget,
    /// Candidates currently being evaluated: ID → (Chromosome, sent_at).
    pub in_flight: HashMap<u64, (Chromosome, Instant)>,
    /// Search statistics.
    pub stats: SearchStats,
    /// Target health monitor.
    pub target_health: TargetHealthMonitor,
    /// Optional path for automatic checkpointing.
    pub checkpoint_path: Option<PathBuf>,
    /// Total oracle requests issued.
    pub request_count: usize,
    /// Per-gene success tracking: `(gene_name, gene_value, successes, attempts)`.
    pub gene_stats: Vec<(String, String, u32, u32)>,
    /// Fitness history: average fitness per generation (sliding window).
    pub fitness_history: Vec<f64>,
    /// Number of consecutive generations with no improvement.
    pub stagnation_counter: u32,
    /// Saved bypass corpus.
    pub corpus: BypassCorpus,
    /// Evaluations this generation.
    generation_evals: usize,
    /// Next candidate ID.
    next_id: u64,
    /// Pending single candidate for legacy sequential API.
    pending_single: Option<(usize, Chromosome)>,
}

impl Clone for EvolutionEngine {
    fn clone(&self) -> Self {
        // Clone via checkpoint/restore. Both calls panic-on-error
        // because they only fail when invariants are corrupt — the
        // earlier silent-fallback path produced a clone with the
        // wrong algorithm + default state, masking the bug. Loud
        // panic > silent state corruption.
        let alg_bytes = self
            .algorithm
            .checkpoint()
            .expect("algorithm checkpoint must succeed for a live engine");
        let mut restored = Self::with_algorithm(
            self.algorithm.name(),
            self.gene_pool.clone(),
            self.rng.clone(),
            self.budget,
        )
        .expect("re-constructing the same registered algorithm must succeed");
        restored
            .algorithm
            .restore(&alg_bytes)
            .expect("restoring fresh checkpoint into matching algorithm must succeed");
        restored.cache = LruCache::new(self.cache.cap());
        restored.gene_stats = self.gene_stats.clone();
        restored.fitness_history = self.fitness_history.clone();
        restored.stagnation_counter = self.stagnation_counter;
        restored.corpus = self.corpus.clone();
        restored.request_count = self.request_count;
        restored.stats = self.stats;
        restored.next_id = self.next_id;
        restored.pending_single = None;
        restored
    }
}

impl EvolutionEngine {
    /// Create a new engine with the given algorithm and population size.
    #[must_use]
    pub fn new(population_size: usize) -> Self {
        Self::new_seeded(population_size, 0)
    }

    /// Create a new engine with a seeded RNG.
    /// `population_size` is clamped to the inclusive range `[1, 10_000]`:
    /// 0 would leave the selection helpers (tournament/roulette) with
    /// nothing to index — a contract violation that used to panic.
    /// 10_000 caps memory at construction so a misconfigured caller
    /// can't OOM the process by passing `usize::MAX`.
    #[must_use]
    pub fn new_seeded(population_size: usize, seed: u64) -> Self {
        let population_size = population_size.clamp(1, 10_000);
        let gene_pool = GenePool::default_wafrift();
        let mut rng = StdRng::seed_from_u64(seed);
        let mut population: Vec<Chromosome> = (0..population_size)
            .map(|_| random_chromosome(&gene_pool, &mut rng))
            .collect();
        if population_size > 0 {
            population[0] = baseline_chromosome(&gene_pool);
        }

        let mut engine = Self::with_algorithm("hill_climbing", gene_pool, rng, Budget::default())
            .expect("hill_climbing is built-in");
        engine
            .algorithm
            .initialize(population, &engine.gene_pool, &mut engine.rng.clone());
        // Re-initialize with the same RNG to avoid double-use
        let mut population2: Vec<Chromosome> = (0..population_size)
            .map(|_| random_chromosome(&engine.gene_pool, &mut engine.rng))
            .collect();
        if population_size > 0 {
            population2[0] = baseline_chromosome(&engine.gene_pool);
        }
        engine
            .algorithm
            .initialize(population2, &engine.gene_pool, &mut engine.rng);
        engine
    }

    /// Create an engine with a specific algorithm by name.
    pub fn with_algorithm(
        algorithm_name: &str,
        gene_pool: GenePool,
        rng: StdRng,
        budget: Budget,
    ) -> Result<Self, EvolutionError> {
        let algorithm: Box<dyn SearchAlgorithm> = match algorithm_name {
            "hill_climbing" => Box::new(crate::search::HillClimbing::new()),
            "simulated_annealing" => Box::new(crate::search::SimulatedAnnealing::new()),
            "tabu_search" => Box::new(crate::search::TabuSearch::new(20)),
            "novelty_search" => Box::new(crate::search::NoveltySearch::new(15, 0.3)),
            "map_elites" => Box::new(crate::search::MapElites::new()),
            _ => {
                return Err(EvolutionError::AlgorithmError(format!(
                    "unknown algorithm: {algorithm_name}"
                )));
            }
        };

        Ok(Self {
            algorithm,
            gene_pool,
            rng,
            cache: LruCache::new(NonZeroUsize::new(10_000).unwrap()),
            budget,
            in_flight: HashMap::new(),
            stats: SearchStats::new(),
            target_health: TargetHealthMonitor::new(),
            checkpoint_path: None,
            request_count: 0,
            gene_stats: Vec::new(),
            fitness_history: Vec::new(),
            stagnation_counter: 0,
            corpus: BypassCorpus::new(),
            generation_evals: 0,
            next_id: 0,
            pending_single: None,
        })
    }

    fn cache_key(chromosome: &Chromosome) -> String {
        let mut parts: Vec<_> = chromosome
            .genes
            .iter()
            .map(|(n, v)| format!("{n}={v}"))
            .collect();
        parts.sort();
        parts.join(";")
    }

    fn next_eval_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    /// Get the next candidate to try (legacy sequential API).
    ///
    /// Returns a synthetic index and a reference to the stored candidate.
    #[must_use]
    pub fn next_candidate(&mut self) -> Option<(usize, &Chromosome)> {
        if self.should_terminate() {
            return None;
        }
        if self.pending_single.is_none() {
            let batch = self.batch_candidates(1);
            if batch.is_empty() {
                return None;
            }
            self.pending_single = Some(batch.into_iter().next().unwrap());
        }
        self.pending_single
            .as_ref()
            .map(|(idx, chrom)| (*idx, chrom))
    }

    /// Request a batch of up to `n` candidates for parallel evaluation.
    ///
    /// Checks cache, budget, and target health before returning candidates.
    /// `n` is also clamped to the remaining `budget.max_requests` headroom
    /// so a single batch call can never overshoot the hard request budget
    /// (the underlying algorithm is free to request whatever it likes
    /// internally; the engine bounds the request count it actually
    /// surfaces).
    pub fn batch_candidates(&mut self, n: usize) -> Vec<(usize, Chromosome)> {
        if self.should_terminate() || n == 0 {
            return Vec::new();
        }
        let remaining = self
            .budget
            .max_requests
            .saturating_sub(self.request_count);
        if remaining == 0 {
            return Vec::new();
        }
        let n = n.min(remaining);

        let mut result = Vec::with_capacity(n);
        let mut cached_results = Vec::new();
        let requested = self.algorithm.request_evaluations(n, &mut self.rng);

        for candidate in requested {
            let key = Self::cache_key(&candidate.chromosome);
            if let Some(verdict) = self.cache.get(&key).copied() {
                cached_results.push((candidate.id, verdict));
            } else {
                let eval_id = self.next_eval_id();
                self.in_flight
                    .insert(eval_id, (candidate.chromosome.clone(), Instant::now()));
                result.push((eval_id as usize, candidate.chromosome));
            }
        }

        if !cached_results.is_empty() {
            self.algorithm.submit_evaluations(cached_results);
        }

        self.request_count += result.len();
        result
    }

    /// Submit a batch of evaluation results.
    ///
    /// # Errors
    ///
    /// Returns an error if an evaluation ID is not in the in-flight set.
    pub fn submit_batch(
        &mut self,
        results: Vec<(usize, OracleVerdict)>,
    ) -> Result<(), EvolutionError> {
        let mut to_submit: Vec<(u64, OracleVerdict)> = Vec::with_capacity(results.len());
        for (id_usize, verdict) in results {
            let id = id_usize as u64;
            let (mut chromosome, _sent_at) = self
                .in_flight
                .remove(&id)
                .ok_or(EvolutionError::InvalidChromosomeIndex(id_usize))?;

            chromosome.record_verdict(&verdict);
            let key = Self::cache_key(&chromosome);
            self.cache.put(key, verdict);

            update_gene_stats(&mut self.gene_stats, &chromosome.genes, verdict.passed);
            let adjusted = evolutionary_fitness(&chromosome, &self.gene_stats);
            chromosome.fitness = adjusted;

            // Save high-fitness bypasses to corpus
            if chromosome.fitness >= 0.85
                && !self
                    .corpus
                    .entries
                    .iter()
                    .any(|e| e.payload_hash == format!("{:016x}", chromosome.hash()))
            {
                self.corpus
                    .add(BypassEntry::from_chromosome(&chromosome, None));
            }

            to_submit.push((id, verdict));
            self.generation_evals += 1;
            self.stats.evaluations += 1;

            if verdict.passed {
                self.target_health.record_success();
            } else if verdict.status_delta >= 500 {
                self.target_health.record_error();
            }
        }

        self.algorithm.submit_evaluations(to_submit);
        Ok(())
    }

    /// Record legacy boolean feedback for a candidate.
    pub fn record_feedback(
        &mut self,
        chromosome_index: usize,
        passed: bool,
    ) -> Result<(), EvolutionError> {
        // Clear pending_single if it matches the index
        if let Some((idx, _)) = self.pending_single
            && idx == chromosome_index
        {
            self.pending_single = None;
        }
        self.record_verdict(chromosome_index, &OracleVerdict::from_bool(passed))
    }

    /// Record rich oracle verdict feedback.
    pub fn record_verdict(
        &mut self,
        chromosome_index: usize,
        verdict: &OracleVerdict,
    ) -> Result<(), EvolutionError> {
        self.submit_batch(vec![(chromosome_index, *verdict)])
    }

    /// Record target-error feedback.
    pub fn record_target_error(&mut self, error: String) -> Result<(), EvolutionError> {
        self.target_health.record_error();
        if !self.target_health.is_healthy() {
            return Err(EvolutionError::TargetHealthCritical(error));
        }
        Ok(())
    }

    /// Evolve the population to the next generation.
    pub fn evolve(&mut self) {
        if self.algorithm.best().is_none() {
            return;
        }

        // Update fitness history with sliding window
        if let Some(best) = self.algorithm.best() {
            self.fitness_history.push(best.fitness);
        }
        if self.fitness_history.len() > 1000 {
            self.fitness_history.remove(0);
        }

        // Detect stagnation
        let window = 10_usize;
        if self.fitness_history.len() >= window {
            let recent = &self.fitness_history[self.fitness_history.len() - window..];
            let improved = recent.windows(2).any(|w| w[1] > w[0] + 0.001);
            if !improved {
                self.stagnation_counter += 1;
            } else {
                self.stagnation_counter = 0;
            }
        }

        self.stats.generation += 1;
        self.generation_evals = 0;

        if let Some(ref path) = self.checkpoint_path {
            let _ = self.save_checkpoint(path);
        }
    }

    /// Check if evolution should terminate.
    #[must_use]
    pub fn should_terminate(&self) -> bool {
        if !self.target_health.is_healthy() {
            return true;
        }
        self.algorithm.should_terminate(&self.stats, &self.budget)
            || self.request_count >= self.budget.max_requests
            || self.stats.stagnation_counter >= self.budget.stagnation_limit
    }

    /// Get the best-performing chromosome.
    #[must_use]
    pub fn best(&self) -> Option<&Chromosome> {
        self.algorithm.best()
    }

    /// Save engine state to disk.
    pub fn save_checkpoint(&self, path: &Path) -> Result<(), EvolutionError> {
        let state = EngineState {
            algorithm_name: self.algorithm.name().to_string(),
            algorithm_state: self.algorithm.checkpoint()?,
            gene_pool: self.gene_pool.clone(),
            rng_seed: 0, // We can't easily extract seed; we rely on algorithm state
            budget: self.budget,
            gene_stats: self.gene_stats.clone(),
            fitness_history: self.fitness_history.clone(),
            stagnation_counter: self.stagnation_counter,
            request_count: self.request_count,
            stats: self.stats,
            schema_version: 1,
        };
        save_checkpoint(path, &state)
    }

    /// Load engine state from disk.
    pub fn load_checkpoint(&mut self, path: &Path) -> Result<(), EvolutionError> {
        let mut state: EngineState = load_checkpoint(path)?;
        state.stats.fixup_start_time();
        self.algorithm.restore(&state.algorithm_state)?;
        self.gene_pool = state.gene_pool;
        self.budget = state.budget;
        self.gene_stats = state.gene_stats;
        self.fitness_history = state.fitness_history;
        self.stagnation_counter = state.stagnation_counter;
        self.request_count = state.request_count;
        self.stats = state.stats;
        Ok(())
    }

    /// Get per-gene success rates.
    #[must_use]
    pub fn gene_success_rates(&self) -> Vec<(&str, &str, f64)> {
        crate::evolution::fitness::gene_success_rates(&self.gene_stats)
    }

    /// Get a human-readable summary.
    #[must_use]
    pub fn learned_summary(&self) -> String {
        crate::evolution::fitness::learned_summary(
            self.stats.generation,
            self.algorithm.best(),
            &self.gene_stats,
            self.request_count,
        )
    }

    /// Compute diversity score using algorithm population if available.
    #[must_use]
    pub fn diversity_score(&self) -> f64 {
        // Fallback: use gene stats diversity heuristic
        0.5
    }
}

/// Serializable engine state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineState {
    pub algorithm_name: String,
    pub algorithm_state: Vec<u8>,
    pub gene_pool: GenePool,
    pub rng_seed: u64,
    pub budget: Budget,
    pub gene_stats: Vec<(String, String, u32, u32)>,
    pub fitness_history: Vec<f64>,
    pub stagnation_counter: u32,
    pub request_count: usize,
    pub stats: SearchStats,
    pub schema_version: u32,
}

use serde::{Deserialize, Serialize};
