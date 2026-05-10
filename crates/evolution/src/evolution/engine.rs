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
use std::collections::{HashMap, VecDeque};
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
    pub fitness_history: VecDeque<f64>,
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
            cache: LruCache::new(NonZeroUsize::new(10_000).expect("10_000 is non-zero")),
            budget,
            in_flight: HashMap::new(),
            stats: SearchStats::new(),
            target_health: TargetHealthMonitor::new(),
            checkpoint_path: None,
            request_count: 0,
            gene_stats: Vec::new(),
            fitness_history: VecDeque::new(),
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
            self.pending_single = self.batch_candidates(1).into_iter().next();
        }
        self.pending_single.as_ref().map(|(idx, chrom)| (*idx, chrom))
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
        let remaining = self.budget.max_requests.saturating_sub(self.request_count);
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
            let hash_str = format!("{:016x}", chromosome.hash());
            if chromosome.fitness >= 0.85
                && !self
                    .corpus
                    .entries
                    .iter()
                    .any(|e| e.payload_hash == hash_str)
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
            self.fitness_history.push_back(best.fitness);
        }
        if self.fitness_history.len() > 1000 {
            self.fitness_history.pop_front();
        }

        // Detect stagnation
        let window = 10_usize;
        if self.fitness_history.len() >= window {
            let skip = self.fitness_history.len().saturating_sub(window);
            let recent: Vec<f64> = self.fitness_history.iter().skip(skip).copied().collect();
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

    /// Seed the underlying algorithm with an explicit population —
    /// the public path callers use to warm-start search from a known
    /// good corpus (or to inject a synthetic population from tests).
    pub fn seed_population(&mut self, population: Vec<Chromosome>) {
        let mut rng = self.rng.clone();
        self.algorithm
            .initialize(population, &self.gene_pool, &mut rng);
    }

    /// Snapshot the algorithm's live population (test/diagnostic
    /// surface). Population-based algorithms return their full pool;
    /// single-state algorithms return the singleton current/best.
    #[must_use]
    pub fn population_snapshot(&self) -> Vec<Chromosome> {
        self.algorithm.population_snapshot()
    }

    /// Population diversity in `[0.0, 1.0]` — drives adaptive mutation
    /// pressure (see `crossover::diversity::adaptive_mutation_rate`).
    ///
    /// Strategy:
    /// 1. Snapshot the algorithm's live population and union it with
    ///    the engine's `in_flight` candidates.
    /// 2. If `len() >= 2`, return mean pairwise gene-mismatch ratio
    ///    via `crossover::diversity::diversity_score`.
    /// 3. Otherwise (single-state algorithm with nothing in-flight),
    ///    fall back to gene-pool exploration entropy from
    ///    [`Self::gene_stats_diversity`] — measures how broadly the
    ///    engine has *explored* the gene space rather than how varied
    ///    the *current* population is. With no exploration history
    ///    either, return 1.0 (max-safe default — keeps mutation
    ///    pressure conservative on a fresh engine).
    #[must_use]
    pub fn diversity_score(&self) -> f64 {
        let mut population = self.algorithm.population_snapshot();
        for (chromosome, _) in self.in_flight.values() {
            population.push(chromosome.clone());
        }
        if population.len() >= 2 {
            return crate::evolution::crossover::diversity::diversity_score(&population);
        }
        let gene_div = self.gene_stats_diversity();
        if gene_div > 0.0 { gene_div } else { 1.0 }
    }

    /// Shannon-entropy style diversity over the engine's per-gene
    /// exploration history.
    ///
    /// For each unique gene name in `gene_stats`, computes the
    /// normalised entropy of its value distribution weighted by
    /// `attempts`. The per-gene entropies are averaged. Range
    /// `[0.0, 1.0]`: 0.0 means we tried only one value for every
    /// gene (no exploration), 1.0 means a uniform distribution
    /// across the maximum-cardinality gene's value space.
    ///
    /// Useful as a fallback signal when the active search algorithm
    /// is single-state (e.g. simulated annealing) and the population
    /// snapshot is too small to give meaningful pairwise distance.
    #[must_use]
    pub fn gene_stats_diversity(&self) -> f64 {
        if self.gene_stats.is_empty() {
            return 0.0;
        }
        // Bucket per-gene attempt counts.
        let mut by_gene: HashMap<&str, Vec<u32>> = HashMap::new();
        for (name, _value, _successes, attempts) in &self.gene_stats {
            if *attempts == 0 {
                continue;
            }
            by_gene.entry(name.as_str()).or_default().push(*attempts);
        }
        if by_gene.is_empty() {
            return 0.0;
        }
        let mut entropy_sum = 0.0_f64;
        let mut counted = 0_usize;
        for attempts in by_gene.values() {
            let total: u64 = attempts.iter().map(|a| u64::from(*a)).sum();
            if total == 0 || attempts.len() < 2 {
                // Single value tried — zero entropy contribution. Still
                // counted so the per-gene mean isn't biased by skipping.
                counted += 1;
                continue;
            }
            #[allow(clippy::cast_precision_loss)]
            let total_f = total as f64;
            let mut h = 0.0_f64;
            for a in attempts {
                #[allow(clippy::cast_precision_loss)]
                let p = f64::from(*a) / total_f;
                if p > 0.0 {
                    h -= p * p.log2();
                }
            }
            // Normalise by max entropy log2(k) where k is the number of
            // distinct values tried for this gene. Falls in `[0, 1]`.
            #[allow(clippy::cast_precision_loss)]
            let h_max = (attempts.len() as f64).log2();
            let normalised = if h_max > 0.0 { h / h_max } else { 0.0 };
            entropy_sum += normalised;
            counted += 1;
        }
        if counted == 0 {
            0.0
        } else {
            #[allow(clippy::cast_precision_loss)]
            let avg = entropy_sum / counted as f64;
            avg.clamp(0.0, 1.0)
        }
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
    pub fitness_history: VecDeque<f64>,
    pub stagnation_counter: u32,
    pub request_count: usize,
    pub stats: SearchStats,
    pub schema_version: u32,
}

use serde::{Deserialize, Serialize};
