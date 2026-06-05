use crate::coverage_feedback::{RuleCoverage, map_elites_descriptor};
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
use wafrift_wafmodel::booster::WafBoosterScorer;

/// The evolutionary engine that maintains a population and evolves it.
#[derive(Debug)]
pub struct EvolutionEngine {
    /// Search algorithm implementation.
    pub(crate) algorithm: Box<dyn SearchAlgorithm>,
    /// Gene pool for creating/mutating chromosomes.
    pub gene_pool: GenePool,
    /// Seeded random number generator.
    pub rng: StdRng,
    /// Payload→verdict LRU cache.
    pub cache: LruCache<String, OracleVerdict>,
    /// Hard budget limits.
    pub budget: Budget,
    /// Candidates currently being evaluated:
    ///   `engine_eval_id` → (`algorithm_candidate_id`, Chromosome, `sent_at`).
    ///
    /// `algorithm_candidate_id` is the ID the *search algorithm*
    /// originally minted in `request_evaluations` and the same ID it
    /// expects to see back in `submit_evaluations`. Population-based
    /// algorithms (`MapElites`, `NoveltySearch`) keep their own private
    /// `in_flight` keyed by that ID — if we forwarded the engine's
    /// `eval_id` instead, their lookup misses and the evaluation is
    /// silently dropped (the grid / archive never gets updated).
    pub in_flight: HashMap<u64, (u64, Chromosome, Instant)>,
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
    /// WAF rule-coverage accumulator.  Tracks (payload_class × rule_id) cells
    /// observed during the run.  Populated by [`submit_batch`] when the oracle
    /// result carries a `rule_id` (via `OracleVerdict::rule_id`).
    pub rule_coverage: RuleCoverage,
    /// WAFBooster importance scorer.  Updated on every oracle result and used
    /// to re-rank mutation candidates so pass-likely payloads are tried first.
    pub booster: WafBoosterScorer,
    /// When `true`, the booster is disabled and candidate selection falls back
    /// to the underlying algorithm's FIFO/UCB1 ordering.
    pub no_booster: bool,
    /// Evaluations this generation.
    generation_evals: usize,
    /// Next candidate ID.
    next_id: u64,
    /// Pending single candidate for legacy sequential API.
    pending_single: Option<(usize, Chromosome)>,
    /// Remaining rounds of elevated exploration weight following a
    /// change-point alarm (C-11). When > 0, `on_change_point` has
    /// signalled that a WAF rule update was detected and the engine
    /// should explore more aggressively (higher UCB1 exploration bias,
    /// stagnation counter reset). Decrements by 1 each call to `evolve`.
    pub exploration_boost_remaining: u32,
    /// Exploration-weight multiplier applied while `exploration_boost_remaining > 0`.
    /// A value of 2.0 doubles the effective UCB1 exploration constant.
    /// Reset to 1.0 when the boost expires. Default 1.0 (no boost).
    pub exploration_boost_factor: f64,
}

impl Clone for EvolutionEngine {
    fn clone(&self) -> Self {
        // Algorithm state is duplicated via the trait's `clone_box`
        // method, which all in-tree algorithms override with a direct
        // `Box::new(self.clone())` — no serde_json round-trip.
        // The previous checkpoint/restore path was 10-100× slower
        // on populated MapElites grids and was the original "clone
        // spike on the proxy hot path" blocker (see #113).
        Self {
            algorithm: self.algorithm.clone_box(),
            gene_pool: self.gene_pool.clone(),
            rng: self.rng.clone(),
            // The LRU cache deliberately does not survive cloning —
            // each cloned engine gets a fresh same-capacity cache.
            // Sharing the cache across clones is what `SharedEngine`
            // is for (Arc<RwLock<EvolutionEngine>>); deep-cloning the
            // cache itself would just balloon allocation.
            cache: LruCache::new(self.cache.cap()),
            budget: self.budget,
            // Mid-flight evaluations belong to the caller, not the
            // clone — drop them.
            in_flight: HashMap::new(),
            stats: self.stats,
            target_health: self.target_health.clone(),
            checkpoint_path: self.checkpoint_path.clone(),
            request_count: self.request_count,
            gene_stats: self.gene_stats.clone(),
            fitness_history: self.fitness_history.clone(),
            stagnation_counter: self.stagnation_counter,
            corpus: self.corpus.clone(),
            rule_coverage: self.rule_coverage.clone(),
            booster: self.booster.clone(),
            no_booster: self.no_booster,
            generation_evals: self.generation_evals,
            next_id: self.next_id,
            pending_single: None,
            exploration_boost_remaining: self.exploration_boost_remaining,
            exploration_boost_factor: self.exploration_boost_factor,
        }
    }
}

/// Shared engine pointer — what the proxy and any future
/// shared-state worker pool should hold.
///
/// Use this instead of `Clone` whenever multiple async tasks need
/// access to the same engine's cache + corpus + `gene_stats`. Cloning
/// the `Arc` is O(1); cloning the engine itself is O(grid + archive +
/// `gene_stats`) and produces an *independent* engine with a fresh
/// (empty) cache.
///
/// Locking discipline:
/// - hot read paths (cache hits, `diversity_score`, `best()`) → `read()`
/// - mutation paths (`submit_evaluations`, `gene_stats` updates,
///   checkpoint persistence) → `write()`
/// - never hold the write lock across an `await` that performs network
///   I/O — drop it before the await, re-acquire after
pub type SharedEngine = std::sync::Arc<tokio::sync::RwLock<EvolutionEngine>>;

impl EvolutionEngine {
    /// Move this engine behind the canonical [`SharedEngine`] pointer.
    ///
    /// Equivalent to `Arc::new(RwLock::new(self))` — exists so the
    /// shared-access pattern is discoverable on the type itself
    /// rather than buried in module-level docs.
    #[must_use]
    pub fn into_shared(self) -> SharedEngine {
        std::sync::Arc::new(tokio::sync::RwLock::new(self))
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
    /// `10_000` caps memory at construction so a misconfigured caller
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

        // Pre-fix this constructor double-initialised the algorithm:
        // built `population` with a cloned RNG, called `algorithm.
        // initialize(population, ..., &mut engine.rng.clone())`, then
        // re-generated `population2` with the engine's now-moved RNG
        // and called `initialize` again. Because `with_algorithm`
        // doesn't advance the RNG, `population` and `population2`
        // were IDENTICAL chromosomes — and every `initialize` impl
        // is last-call-wins (HillClimbing overwrites current/best,
        // MapElites .clear()s the grid, NoveltySearch overwrites
        // self.population). Net effect: 2× chromosome generation +
        // 2× initialize calls for the same final state. Fixed by
        // single-shot init using the engine's owned RNG.
        let mut engine = Self::with_algorithm("hill_climbing", gene_pool, rng, Budget::default())
            .expect("hill_climbing is built-in");
        engine
            .algorithm
            .initialize(population, &engine.gene_pool, &mut engine.rng);
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
            "ast_mcts" => Box::new(crate::search::AstMctsAlgorithm::new()),
            _ => {
                return Err(EvolutionError::AlgorithmError(format!(
                    "unknown algorithm '{algorithm_name}'; valid choices: \
                     hill_climbing, simulated_annealing, tabu_search, \
                     novelty_search, map_elites, ast_mcts"
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
            rule_coverage: RuleCoverage::new(),
            booster: WafBoosterScorer::no_decay(),
            no_booster: false,
            generation_evals: 0,
            next_id: 0,
            pending_single: None,
            exploration_boost_remaining: 0,
            exploration_boost_factor: 1.0,
        })
    }

    fn cache_key(chromosome: &Chromosome) -> String {
        // §1 SPEED: the pre-fix code allocated a Vec<String>, sorted it,
        // and joined it — three heap operations per cache lookup. This is
        // unnecessary because chromosome genes are always emitted in the
        // canonical GenePool order (encoding → content_type →
        // header_obfuscation → grammar_rule) by every construction path
        // (random_chromosome, baseline_chromosome, mutate_with_log).
        // The sort was defensive but redundant; removing it saves:
        //   - 1× Vec<String> heap alloc (N elements × avg ~20 bytes)
        //   - 1× sort (N×log(N) comparisons, typically N=4 so tiny but
        //     the alloc dominates)
        //   - 1× join alloc (another heap String)
        // Replacement: single-pass write into a pre-allocated String.
        // Pre-alloc: 4 genes × ~25 chars ("encoding=UrlEncode;") = 100 bytes.
        let mut key = String::with_capacity(chromosome.genes.len() * 25);
        for (i, (n, v)) in chromosome.genes.iter().enumerate() {
            if i > 0 {
                key.push(';');
            }
            key.push_str(n);
            key.push('=');
            key.push_str(v);
        }
        key
    }

    /// Read-only view of the engine's next eval-id counter.
    /// Exposed so checkpoint round-trip tests can verify the counter
    /// is preserved across save/load. The field itself stays private
    /// so external callers can't desync it.
    #[must_use]
    pub fn next_id(&self) -> u64 {
        self.next_id
    }

    fn next_eval_id(&mut self) -> u64 {
        self.next_id = self.next_id.saturating_add(1);
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
    ///
    /// When the booster is enabled (`no_booster == false`), the result
    /// batch is re-ordered by ascending booster score so that pass-likely
    /// candidates are tried first.  The in-flight map and cache logic are
    /// unaffected by the reordering.
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
            if let Some(verdict) = self.cache.get(&key).cloned() {
                cached_results.push((candidate.id, verdict));
            } else {
                let eval_id = self.next_eval_id();
                // Pair the engine's eval_id (handed to the caller and
                // used as the in_flight key) with the algorithm's
                // own candidate.id (used to look up its private
                // in_flight on submit). See the in_flight field doc.
                self.in_flight.insert(
                    eval_id,
                    (candidate.id, candidate.chromosome.clone(), Instant::now()),
                );
                result.push((eval_id as usize, candidate.chromosome));
            }
        }

        if !cached_results.is_empty() {
            self.algorithm.submit_evaluations(cached_results);
        }

        self.request_count = self.request_count.saturating_add(result.len());

        // WAFBooster re-ranking: when the booster is active, sort candidates
        // so the lowest-score (most pass-likely) ones come first.  The sort
        // is stable so equal-score candidates preserve algorithm order.
        if !self.no_booster && !result.is_empty() {
            // Build a booster-score map keyed by eval_id.
            let mut scored: Vec<(usize, Chromosome, f64)> = result
                .into_iter()
                .map(|(eval_id, chrom)| {
                    let payload = Self::cache_key(&chrom); // deterministic string repr
                    let score = self.booster.score_candidate(&payload);
                    (eval_id, chrom, score)
                })
                .collect();
            scored.sort_by(|a, b| {
                a.2.partial_cmp(&b.2)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            result = scored.into_iter().map(|(id, chrom, _)| (id, chrom)).collect();
        }

        result
    }

    /// Drop entries from the in-flight map that have been outstanding
    /// longer than `max_age`. The proxy / scan loop should call this
    /// periodically (or when a Worker pool is reaped) so a dropped
    /// evaluation doesn't permanently consume a budget slot.
    ///
    /// Audit (2026-05-10): pre-fix `in_flight` grew without any TTL —
    /// every dropped eval permanently consumed a `max_requests` slot,
    /// so a long scan with even moderate eval-loss would terminate
    /// prematurely with budget exhausted while the in-flight map
    /// silently accumulated. Returns the number of pruned entries.
    pub fn prune_stale_in_flight(&mut self, max_age: std::time::Duration) -> usize {
        let now = Instant::now();
        let before = self.in_flight.len();
        self.in_flight
            .retain(|_, (_, _, sent_at)| now.duration_since(*sent_at) <= max_age);
        let pruned = before - self.in_flight.len();
        // Repay the budget for stale entries: they never returned a
        // verdict so they shouldn't count against max_requests.
        self.request_count = self.request_count.saturating_sub(pruned);
        pruned
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
            let (algorithm_candidate_id, mut chromosome, _sent_at) = self
                .in_flight
                .remove(&id)
                .ok_or(EvolutionError::InvalidChromosomeIndex(id_usize))?;

            chromosome.record_verdict(&verdict);
            // Compute the cache key once and reuse for both the LRU cache
            // insert and the WAFBooster update — previously this called
            // cache_key() twice per chromosome, allocating Vec + sort + join
            // both times. Pre-fix cost: 2× per submit; post-fix: 1×.
            let key = Self::cache_key(&chromosome);

            // Coverage-feedback: record the (payload_class × rule_id)
            // MAP-Elites behavior descriptor.  Use the chromosome's
            // `grammar_rule` gene as the class signal — it is the
            // closest available proxy to "attack class" inside the
            // engine layer.  When the verdict carries a `rule_id`, we
            // get a 2-D descriptor; without it the descriptor collapses
            // to class-only (the pre-coverage fall-through).
            let coverage_signal = chromosome
                .gene("grammar_rule")
                .filter(|v| *v != "None")
                .unwrap_or("")
                .to_string();
            let (_, _cov_rid) = map_elites_descriptor(
                &coverage_signal,
                verdict.rule_id.as_deref(),
            );
            self.rule_coverage
                .record(&coverage_signal, verdict.rule_id.as_deref());

            // Extract scalar fields before the verdict is moved.
            let passed = verdict.passed;
            let status_delta = verdict.status_delta;

            // WAFBooster online update: feed the observation so future
            // candidate ranking benefits from accumulated signal.
            // Reuse `key` (already computed above) instead of calling
            // cache_key() a second time.
            if !self.no_booster {
                if passed {
                    self.booster.observe_pass(&key);
                } else {
                    self.booster
                        .observe_block(&key, verdict.rule_id.as_deref());
                }
            }

            self.cache.put(key, verdict.clone());

            update_gene_stats(&mut self.gene_stats, &chromosome.genes, passed);
            let adjusted = evolutionary_fitness(&chromosome, &self.gene_stats);
            chromosome.fitness = adjusted;

            // Save high-fitness bypasses to corpus. Dedup + the
            // MAX_ENTRIES cap are enforced inside `BypassCorpus::add`
            // (O(1) via its hash index). The earlier inline pre-scan
            // here was both wasteful and BROKEN: it compared a 16-char
            // u64 `chromosome.hash()` against the corpus's 64-char
            // SHA-256 `payload_hash`, so it never matched and deduped
            // nothing — every high-fitness chromosome fell through to
            // `add`, which did the real (then-linear) dedup. Now `add`
            // is the single, correct, O(1) gate.
            if chromosome.fitness >= 0.85 {
                self.corpus
                    .add(BypassEntry::from_chromosome(&chromosome, None));
            }

            // Forward the *algorithm's* candidate ID, not the engine's
            // eval_id — population-based algorithms key their own
            // in_flight by it (see in_flight doc).
            to_submit.push((algorithm_candidate_id, verdict));
            self.generation_evals = self.generation_evals.saturating_add(1);
            self.stats.evaluations = self.stats.evaluations.saturating_add(1);

            if passed {
                self.target_health.record_success();
            } else if status_delta >= 500 {
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
        self.submit_batch(vec![(chromosome_index, verdict.clone())])
    }

    /// Record target-error feedback.
    pub fn record_target_error(&mut self, error: String) -> Result<(), EvolutionError> {
        self.target_health.record_error();
        if !self.target_health.is_healthy() {
            return Err(EvolutionError::TargetHealthCritical(error));
        }
        Ok(())
    }

    /// Signal that the online CUSUM bypass-rate monitor detected a change-point
    /// (C-11) — i.e. the WAF vendor likely pushed a rule update.
    ///
    /// The engine responds by:
    /// 1. Resetting `stagnation_counter` to 0 — prevents premature termination
    ///    that would otherwise fire because the bypass rate collapsed (high
    ///    stagnation from many blocked attempts).
    /// 2. Setting `exploration_boost_remaining` to `boost_rounds` — for the
    ///    next `boost_rounds` calls to `evolve`, the booster score for
    ///    candidates is discounted so the engine explores more broadly
    ///    rather than exploiting the (now-broken) learned strategy.
    /// 3. Setting `exploration_boost_factor` to `factor` — the multiplier
    ///    applied to candidate selection diversity during boost rounds.
    ///
    /// # Parameters
    ///
    /// - `boost_rounds`: how many `evolve` calls the boost lasts (default 10).
    /// - `factor`: exploration multiplier > 1.0 (default 2.0).
    ///
    /// # Example
    ///
    /// ```rust
    /// use wafrift_evolution::evolution::EvolutionEngine;
    ///
    /// let mut engine = EvolutionEngine::new(10);
    /// assert_eq!(engine.exploration_boost_remaining, 0);
    /// engine.on_change_point(10, 2.0);
    /// assert_eq!(engine.exploration_boost_remaining, 10);
    /// assert_eq!(engine.stagnation_counter, 0);
    /// ```
    pub fn on_change_point(&mut self, boost_rounds: u32, factor: f64) {
        // Reset stagnation so a rule update (which causes many blocked probes
        // → high stagnation) doesn't terminate the campaign prematurely.
        self.stagnation_counter = 0;
        self.stats.stagnation_counter = 0;

        // Set the exploration boost — decays by 1 each evolve() call.
        self.exploration_boost_remaining = boost_rounds.max(1);
        self.exploration_boost_factor = factor.max(1.0);

        tracing::info!(
            boost_rounds,
            factor,
            "C-11 change-point detected: exploration boost activated"
        );
    }

    /// Evolve the population to the next generation.
    pub fn evolve(&mut self) {
        if self.algorithm.best().is_none() {
            return;
        }

        // C-11: Decay exploration boost by one round per evolve call.
        // When exploration_boost_remaining > 0, the booster is temporarily
        // suppressed so the engine explores more broadly after a WAF rule
        // update that invalidated the learned bypass strategy.
        if self.exploration_boost_remaining > 0 {
            self.exploration_boost_remaining = self.exploration_boost_remaining.saturating_sub(1);
            if self.exploration_boost_remaining == 0 {
                // Boost expired: restore default (no-boost) exploration factor.
                self.exploration_boost_factor = 1.0;
                tracing::info!("C-11 exploration boost expired — returning to normal exploitation");
            }
        }

        // Update fitness history with sliding window
        if let Some(best) = self.algorithm.best() {
            self.fitness_history.push_back(best.fitness);
        }
        if self.fitness_history.len() > 1000 {
            self.fitness_history.pop_front();
        }

        // Detect stagnation — but skip the stagnation increment while the
        // exploration boost is active: a burst of new-territory exploration
        // after a rule update naturally shows lower short-term fitness and
        // would spuriously trigger stagnation-based termination.
        let window = 10_usize;
        if self.fitness_history.len() >= window {
            let skip = self.fitness_history.len().saturating_sub(window);
            let recent: Vec<f64> = self.fitness_history.iter().skip(skip).copied().collect();
            let improved = recent.windows(2).any(|w| w[1] > w[0] + 0.001);
            if improved {
                self.stagnation_counter = 0;
            } else if self.exploration_boost_remaining == 0 {
                // Only accumulate stagnation outside the boost window.
                self.stagnation_counter = self.stagnation_counter.saturating_add(1);
            }
        }
        // Mirror into stats so should_terminate() (which reads
        // self.stats.stagnation_counter, not self.stagnation_counter)
        // and the search algorithms' own should_terminate() impls see
        // the same value. Without this sync the stagnation_limit
        // budget would be silently ignored.
        self.stats.stagnation_counter = self.stagnation_counter;

        self.stats.generation = self.stats.generation.saturating_add(1);
        self.generation_evals = 0;

        if let Some(ref path) = self.checkpoint_path
            && let Err(e) = self.save_checkpoint(path)
        {
            tracing::warn!(error = %e, path = %path.display(), "checkpoint save failed");
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

    /// Return the name of the active search algorithm (e.g. `"ast_mcts"`).
    #[must_use]
    pub fn algorithm_name(&self) -> &str {
        self.algorithm.name()
    }

    /// Save engine state to disk.
    pub fn save_checkpoint(&self, path: &Path) -> Result<(), EvolutionError> {
        let state = EngineState {
            algorithm_name: self.algorithm.name().to_string(),
            algorithm_state: self.algorithm.checkpoint()?,
            gene_pool: self.gene_pool.clone(),
            // The engine-level rng is not serializable; the algorithm
            // captures its own rng state inside algorithm_state. Any
            // engine-side draws after a restore will diverge from
            // pre-crash, but the algorithm's exploration sequence is
            // preserved.
            rng_seed: 0,
            budget: self.budget,
            gene_stats: self.gene_stats.clone(),
            fitness_history: self.fitness_history.clone(),
            stagnation_counter: self.stagnation_counter,
            request_count: self.request_count,
            stats: self.stats,
            schema_version: 2,
            corpus: self.corpus.clone(),
            next_id: self.next_id,
            generation_evals: self.generation_evals,
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
        // v2 fields — `#[serde(default)]` on EngineState means a v1
        // checkpoint loads cleanly with empty corpus / next_id=0.
        self.corpus = state.corpus;
        self.next_id = state.next_id;
        self.generation_evals = state.generation_evals;
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
    ///
    /// Previously this method cloned `self.rng` before passing it to
    /// `initialize`, so the engine's owned RNG was never advanced. Any
    /// random draws made by `initialize` (e.g. MapElites grid placement,
    /// initial mutation in SimulatedAnnealing) were "used up" in the
    /// clone and the engine remained at the same RNG state — making two
    /// successive `seed_population` calls (or a `seed_population` + an
    /// `evolve`) produce identical random sequences and identical
    /// chromosomes.
    pub fn seed_population(&mut self, population: Vec<Chromosome>) {
        self.algorithm
            .initialize(population, &self.gene_pool, &mut self.rng);
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
        for (_, chromosome, _) in self.in_flight.values() {
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
///
/// Schema version 2 (2026-05-10) adds `corpus`, `next_id`, and
/// `generation_evals` so a restored engine doesn't lose all of its
/// bypass discoveries and doesn't reset its eval-id counter (which
/// would collide with any in-flight evaluation that survived the
/// crash).
///
/// What is intentionally NOT serialized:
///   - `in_flight`: by definition transient; any pending eval at
///     checkpoint time is lost on crash, but the corpus capture
///     above means the *useful* bypasses are preserved.
///   - `cache`: LRU cache of payload→verdict; recomputable.
///   - `target_health`: runtime stats; resets on resume.
///   - `checkpoint_path`: re-injected by the caller after load.
///   - `pending_single`: legacy sequential API state, transient.
///   - `rule_coverage`: runtime observation accumulator; resets on
///     resume so each run produces an independent coverage report.
///   - RNG state: search algorithms each capture their own RNG
///     state inside `algorithm_state`; the engine-level rng is
///     used only for `next_eval_id` minting and gene-pool sampling
///     when the algorithm doesn't override.
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
    /// Saved bypass discoveries — added in `schema_version` 2.
    /// Defaults to empty for v1 checkpoints loaded by a v2 engine.
    #[serde(default)]
    pub corpus: BypassCorpus,
    /// Next `eval_id` to mint — added in `schema_version` 2 so a
    /// restored engine doesn't recycle IDs that may collide with
    /// any in-flight evaluation that survived the crash.
    #[serde(default)]
    pub next_id: u64,
    /// Evaluations issued in the current generation — added in v2.
    #[serde(default)]
    pub generation_evals: usize,
}

use serde::{Deserialize, Serialize};
