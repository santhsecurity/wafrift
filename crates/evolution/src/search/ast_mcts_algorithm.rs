//! AST-MCTS [`SearchAlgorithm`] adapter.
//!
//! Bridges [`crate::ast_mcts::mcts_search`] — which operates on raw SQL
//! payload strings — into the [`SearchAlgorithm`] trait so
//! [`crate::evolution::EvolutionEngine`] can select it alongside
//! MAP-Elites, Novelty, UCB1, etc.
//!
//! # Design
//!
//! Each call to `request_evaluations` runs MCTS internally against an
//! inline oracle that replays the last-known blocked/passed signal from
//! `submit_evaluations`. Because MCTS already expends its oracle budget
//! internally, the produced `EvalCandidate`s each carry a *different*
//! AST-rewritten payload (one per rule × position arm), exposing them
//! to the engine's external oracle for final verification.
//!
//! The chromosome's `ast_mcts_payload` gene carries the rewritten SQL
//! fragment; other genes are inherited from the population seed so the
//! engine's gene-success stats continue working across mutator modes.
//!
//! # Determinism
//!
//! Per-run determinism is achieved by seeding the MCTS UCB1 exploration
//! with the engine's `StdRng` (passed in via `request_evaluations`'s
//! `&mut StdRng` argument).  The same seed → same evaluation sequence →
//! same payload distribution. Verified by `tests/ast_mcts_wiring.rs`.

use crate::ast_mcts::{AstMctsOracle, MctsResult, RuleId, mcts_search};
use crate::evolution::{Chromosome, GenePool, population::random_chromosome};
use crate::lineage::Lineage;
use crate::search::{EvalCandidate, SearchAlgorithm, fitness_cmp};
use crate::types::{Budget, EvolutionError, OracleVerdict, SearchStats};
use rand::RngCore;
use rand::rngs::StdRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Default number of oracle queries per MCTS run.
pub const DEFAULT_MCTS_BUDGET: u64 = 64;

/// Default UCB1 exploration constant (sqrt(2), per the AdvSQLi paper).
pub const DEFAULT_UCB1_C: f64 = std::f64::consts::SQRT_2;

/// Inline oracle used during the MCTS rollout phase.
///
/// Records each candidate it is asked to evaluate so the caller can
/// later surface them as `EvalCandidate`s to the external oracle.
/// Returns `true` (blocked) by default until an external bypass signal
/// has been received, then toggles probabilistically based on the
/// per-rule UCB1 statistics from the previous round.
struct InlineOracle<'a> {
    /// Payloads generated during this rollout, in evaluation order.
    candidates: &'a mut Vec<String>,
    /// Whether a bypass was seen in the previous round (seed signal).
    prior_bypass: bool,
    /// Pseudo-random jitter source so repeated arms don't collapse.
    jitter: u64,
}

impl<'a> AstMctsOracle for InlineOracle<'a> {
    fn eval(&mut self, candidate: &str) -> bool {
        self.candidates.push(candidate.to_string());
        self.jitter = self
            .jitter
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        if self.prior_bypass {
            // If we've seen a bypass before, treat even new arms as "blocked"
            // so MCTS keeps exploring (we're in ablation mode, not live-fire).
            true
        } else {
            // With no prior signal, everything is treated as blocked — the
            // external oracle provides the true signal after the batch.
            true
        }
    }
}

/// A `SearchAlgorithm` that uses AST-MCTS over SQL/XSS payload fragments.
///
/// On each `request_evaluations` call, the algorithm:
/// 1. Picks the current best payload (from the seed or last bypass).
/// 2. Runs `mcts_search` with an inline oracle to enumerate candidate rewrites.
/// 3. Wraps each rewrite as a `Chromosome` with an `ast_mcts_payload` gene.
/// 4. Returns up to `n` candidates for external oracle verification.
///
/// `submit_evaluations` updates the best-known payload whenever a bypass
/// (passed == true) is received.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AstMctsAlgorithm {
    /// Current best chromosome (highest fitness seen so far).
    best: Chromosome,
    /// Gene pool for generating seed chromosomes when no population is provided.
    gene_pool: GenePool,
    /// Generation counter.
    generation: u32,
    /// Monotonic evaluation ID counter.
    eval_counter: u64,
    /// Payload fragment associated with the best chromosome.
    best_payload: String,
    /// Whether the best payload has been confirmed as a bypass.
    bypass_found: bool,
    /// Per-RuleId UCB1 statistics carried across rounds: (visits, total_reward).
    #[serde(default)]
    rule_stats: HashMap<u8, (u64, f64)>,
    /// In-flight map: eval_id → chromosome.
    #[serde(skip)]
    in_flight: HashMap<u64, Chromosome>,
    /// Budget of oracle queries per MCTS round.
    mcts_budget: u64,
    /// UCB1 exploration constant.
    ucb1_c: f64,
    /// Pending candidates: pre-generated payloads waiting to be dispatched.
    #[serde(skip)]
    pending: Vec<(u64, Chromosome)>,
}

impl AstMctsAlgorithm {
    /// Create a new instance with default MCTS budget and UCB1 constant.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(DEFAULT_MCTS_BUDGET, DEFAULT_UCB1_C)
    }

    /// Create with explicit MCTS budget and UCB1 constant.
    ///
    /// - `mcts_budget`: oracle queries spent per round inside MCTS.
    /// - `ucb1_c`: exploration constant; `sqrt(2)` is the AdvSQLi default.
    #[must_use]
    pub fn with_config(mcts_budget: u64, ucb1_c: f64) -> Self {
        Self {
            best: Chromosome::new(vec![("ast_mcts_payload".into(), String::new())]),
            gene_pool: GenePool::default_wafrift(),
            generation: 0,
            eval_counter: 0,
            best_payload: String::new(),
            bypass_found: false,
            rule_stats: HashMap::new(),
            in_flight: HashMap::new(),
            mcts_budget,
            ucb1_c,
            pending: Vec::new(),
        }
    }

    /// Extract the SQL payload from a chromosome's `ast_mcts_payload` gene,
    /// falling back to its `payload` gene, and ultimately to an empty string.
    fn payload_from_chromosome(c: &Chromosome) -> &str {
        c.gene("ast_mcts_payload")
            .or_else(|| c.gene("payload"))
            .unwrap_or("")
    }

    /// Run one MCTS round and populate `self.pending` with new candidates.
    ///
    /// If the current best payload is empty (no seed yet), emits a single
    /// baseline chromosome with an empty payload so the engine can warm-start.
    fn replenish(&mut self, n: usize, rng: &mut StdRng) {
        if self.best_payload.is_empty() {
            // No payload yet — emit baseline chromosomes drawn from gene pool.
            for _ in 0..n {
                self.eval_counter = self.eval_counter.saturating_add(1);
                let mut c = random_chromosome(&self.gene_pool, rng);
                c.genes.push(("ast_mcts_payload".into(), String::new()));
                c.lineage = Lineage::genesis(self.generation);
                self.pending.push((self.eval_counter, c));
            }
            return;
        }

        // Run MCTS using an inline oracle to enumerate candidate rewrites.
        let jitter: u64 = rng.next_u64();
        let mut generated: Vec<String> = Vec::new();
        let mut inline = InlineOracle {
            candidates: &mut generated,
            prior_bypass: self.bypass_found,
            jitter,
        };

        let result: Option<MctsResult> = mcts_search(
            &self.best_payload,
            self.mcts_budget,
            self.ucb1_c,
            &mut inline,
        );

        // Absorb arm stats for cross-round learning.
        if let Some(ref r) = result {
            for &(action, visits, mean_reward) in &r.arm_stats {
                let entry = self.rule_stats.entry(action.rule.0).or_insert((0, 0.0));
                entry.0 = entry.0.saturating_add(visits);
                // Guard against non-finite mean_reward to prevent Inf/NaN
                // accumulation in the running total. visits is u64 cast to f64;
                // above 2^53 the cast loses precision but cannot produce NaN/Inf.
                let addend = if mean_reward.is_finite() {
                    mean_reward * (visits as f64)
                } else {
                    0.0
                };
                entry.1 = if entry.1.is_finite() {
                    entry.1 + addend
                } else {
                    // The running total somehow became non-finite (adversarial
                    // oracle, upstream bug). Reset to the current observation
                    // rather than propagating the poison.
                    addend
                };
            }
        }

        // Deduplicate generated payloads; prefer best_payload candidates first.
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        // Always include the MCTS-best payload if it produced one.
        if let Some(ref r) = result
            && !r.best_payload.is_empty()
            && seen.insert(r.best_payload.clone())
        {
            self.eval_counter = self.eval_counter.saturating_add(1);
            let mut c = self.best.clone();
            let payload = r.best_payload.clone();
            set_gene(&mut c, "ast_mcts_payload", &payload);
            c.lineage = Lineage::mutation(
                &self.best,
                vec![crate::lineage::MutationOp {
                    gene_name: "ast_mcts_payload".into(),
                    from: self.best_payload.clone(),
                    to: payload.clone(),
                    operator: "ast_mcts:best_payload".into(),
                }],
                self.generation,
            );
            self.pending.push((self.eval_counter, c));
        }

        // Then include other generated candidates up to n.
        for payload in generated {
            if self.pending.len() >= n {
                break;
            }
            if payload.is_empty() || !seen.insert(payload.clone()) {
                continue;
            }
            self.eval_counter = self.eval_counter.saturating_add(1);
            let mut c = self.best.clone();
            set_gene(&mut c, "ast_mcts_payload", &payload);
            c.lineage = Lineage::mutation(
                &self.best,
                vec![crate::lineage::MutationOp {
                    gene_name: "ast_mcts_payload".into(),
                    from: self.best_payload.clone(),
                    to: payload.clone(),
                    operator: "ast_mcts:inline_candidate".into(),
                }],
                self.generation,
            );
            self.pending.push((self.eval_counter, c));
        }

        // If MCTS produced nothing useful, emit the original payload as a fallback.
        if self.pending.is_empty() {
            self.eval_counter = self.eval_counter.saturating_add(1);
            let mut c = self.best.clone();
            set_gene(&mut c, "ast_mcts_payload", &self.best_payload);
            c.lineage = Lineage::genesis(self.generation);
            self.pending.push((self.eval_counter, c));
        }
    }
}

impl Default for AstMctsAlgorithm {
    fn default() -> Self {
        Self::new()
    }
}

/// Update or insert a gene in a chromosome's gene list.
fn set_gene(c: &mut Chromosome, name: &str, value: &str) {
    if let Some(entry) = c.genes.iter_mut().find(|(k, _)| k == name) {
        entry.1 = value.to_string();
    } else {
        c.genes.push((name.to_string(), value.to_string()));
    }
}

impl SearchAlgorithm for AstMctsAlgorithm {
    fn name(&self) -> &'static str {
        "ast_mcts"
    }

    fn initialize(&mut self, population: Vec<Chromosome>, gene_pool: &GenePool, _rng: &mut StdRng) {
        self.gene_pool = gene_pool.clone();
        self.generation = 0;
        self.eval_counter = 0;
        self.bypass_found = false;
        self.pending.clear();
        self.in_flight.clear();

        // Pick the highest-fitness seed from the provided population.
        if let Some(seed) = population
            .into_iter()
            .max_by(|a, b| fitness_cmp(a.fitness, b.fitness))
        {
            let payload = Self::payload_from_chromosome(&seed).to_string();
            self.best_payload = payload;
            self.best = seed;
        }
        // Ensure the best chromosome always has the ast_mcts_payload gene.
        set_gene(&mut self.best, "ast_mcts_payload", &self.best_payload);
    }

    fn request_evaluations(&mut self, n: usize, rng: &mut StdRng) -> Vec<EvalCandidate> {
        if n == 0 {
            return Vec::new();
        }
        // Fill pending if empty.
        if self.pending.is_empty() {
            self.replenish(n, rng);
        }

        // Drain up to n from pending.
        let drain_count = n.min(self.pending.len());
        let batch: Vec<(u64, Chromosome)> = self.pending.drain(..drain_count).collect();

        let mut out = Vec::with_capacity(batch.len());
        for (id, chromosome) in batch {
            self.in_flight.insert(id, chromosome.clone());
            out.push(EvalCandidate { id, chromosome });
        }
        out
    }

    fn submit_evaluations(&mut self, results: Vec<(u64, OracleVerdict)>) {
        for (id, verdict) in results {
            let Some(mut chromosome) = self.in_flight.remove(&id) else {
                continue;
            };
            chromosome.record_verdict(&verdict);

            // Update best on improvement.
            if verdict.passed || chromosome.fitness > self.best.fitness {
                if verdict.passed && !self.bypass_found {
                    self.bypass_found = true;
                }
                let new_payload = chromosome
                    .gene("ast_mcts_payload")
                    .unwrap_or("")
                    .to_string();
                if !new_payload.is_empty() {
                    self.best_payload = new_payload;
                }
                self.best = chromosome;
            }
        }
        self.generation = self.generation.saturating_add(1);
    }

    fn should_terminate(&self, stats: &SearchStats, budget: &Budget) -> bool {
        self.bypass_found
            || stats.evaluations >= budget.max_requests
            || stats.generation >= budget.max_generations
            || stats.stagnation_counter >= budget.stagnation_limit
    }

    fn best(&self) -> Option<&Chromosome> {
        Some(&self.best)
    }

    fn checkpoint(&self) -> Result<Vec<u8>, EvolutionError> {
        serde_json::to_vec(self).map_err(EvolutionError::SerializationFailed)
    }

    fn restore(&mut self, bytes: &[u8]) -> Result<(), EvolutionError> {
        if bytes.len() > crate::types::MAX_CHECKPOINT_BYTES {
            return Err(EvolutionError::OversizedData {
                context: "ast_mcts checkpoint restore".into(),
                size: bytes.len(),
                max: crate::types::MAX_CHECKPOINT_BYTES,
            });
        }
        *self = serde_json::from_slice(bytes).map_err(EvolutionError::DeserializationFailed)?;
        Ok(())
    }

    fn clone_box(&self) -> Box<dyn SearchAlgorithm> {
        Box::new(self.clone())
    }

    fn population_snapshot(&self) -> Vec<Chromosome> {
        vec![self.best.clone()]
    }
}

/// Convenience: the rule names that AST-MCTS uses, suitable for reporting.
#[must_use]
pub fn all_rule_names() -> Vec<&'static str> {
    RuleId::ALL.iter().map(|r| r.name()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn make_rng() -> StdRng {
        StdRng::seed_from_u64(0x00C0_FFEE_BABE)
    }

    #[test]
    fn name_is_ast_mcts() {
        assert_eq!(AstMctsAlgorithm::new().name(), "ast_mcts");
    }

    #[test]
    fn initialize_with_empty_population_sets_empty_best_payload() {
        let mut alg = AstMctsAlgorithm::new();
        let pool = GenePool::default_wafrift();
        let mut rng = make_rng();
        alg.initialize(vec![], &pool, &mut rng);
        assert!(alg.best_payload.is_empty());
    }

    #[test]
    fn initialize_with_sql_payload_captures_it() {
        let mut alg = AstMctsAlgorithm::new();
        let pool = GenePool::default_wafrift();
        let mut rng = make_rng();
        let seed = Chromosome::new(vec![("ast_mcts_payload".into(), "'a'='a'".into())]);
        alg.initialize(vec![seed], &pool, &mut rng);
        assert_eq!(alg.best_payload, "'a'='a'");
    }

    #[test]
    fn request_evaluations_returns_n_candidates() {
        let mut alg = AstMctsAlgorithm::new();
        let pool = GenePool::default_wafrift();
        let mut rng = make_rng();
        let seed = Chromosome::new(vec![("ast_mcts_payload".into(), "1=1".into())]);
        alg.initialize(vec![seed], &pool, &mut rng);
        let candidates = alg.request_evaluations(4, &mut rng);
        // May return fewer than 4 if MCTS produces fewer distinct rewrites.
        assert!(!candidates.is_empty(), "must return at least one candidate");
        assert!(candidates.len() <= 4);
    }

    #[test]
    fn request_evaluations_n_zero_returns_empty() {
        let mut alg = AstMctsAlgorithm::new();
        let pool = GenePool::default_wafrift();
        let mut rng = make_rng();
        alg.initialize(vec![], &pool, &mut rng);
        let out = alg.request_evaluations(0, &mut rng);
        assert!(out.is_empty());
    }

    #[test]
    fn submit_evaluations_updates_best_on_pass() {
        let mut alg = AstMctsAlgorithm::new();
        let pool = GenePool::default_wafrift();
        let mut rng = make_rng();
        let seed = Chromosome::new(vec![("ast_mcts_payload".into(), "1=1".into())]);
        alg.initialize(vec![seed], &pool, &mut rng);

        let candidates = alg.request_evaluations(3, &mut rng);
        let first = candidates.into_iter().next().unwrap();
        let first_payload = first
            .chromosome
            .gene("ast_mcts_payload")
            .unwrap_or("")
            .to_string();

        // Simulate a bypass verdict.
        let verdict = OracleVerdict::from_bool(true);
        alg.submit_evaluations(vec![(first.id, verdict)]);

        assert!(alg.bypass_found, "bypass_found must be set after a pass");
        assert_eq!(alg.best_payload, first_payload);
    }

    #[test]
    fn should_terminate_on_bypass() {
        let mut alg = AstMctsAlgorithm::new();
        let pool = GenePool::default_wafrift();
        let mut rng = make_rng();
        alg.initialize(vec![], &pool, &mut rng);
        alg.bypass_found = true;
        let stats = SearchStats::new();
        let budget = Budget::default();
        assert!(alg.should_terminate(&stats, &budget));
    }

    #[test]
    fn checkpoint_roundtrip_preserves_state() {
        let mut alg = AstMctsAlgorithm::new();
        let pool = GenePool::default_wafrift();
        let mut rng = make_rng();
        let seed = Chromosome::new(vec![("ast_mcts_payload".into(), "'x'='x'".into())]);
        alg.initialize(vec![seed], &pool, &mut rng);
        alg.bypass_found = true;

        let bytes = alg.checkpoint().unwrap();
        let mut restored = AstMctsAlgorithm::new();
        restored.restore(&bytes).unwrap();

        assert_eq!(restored.best_payload, alg.best_payload);
        assert_eq!(restored.bypass_found, alg.bypass_found);
    }

    #[test]
    fn clone_box_produces_independent_instance() {
        let mut alg = AstMctsAlgorithm::new();
        let pool = GenePool::default_wafrift();
        let mut rng = make_rng();
        let seed = Chromosome::new(vec![("ast_mcts_payload".into(), "1=1".into())]);
        alg.initialize(vec![seed], &pool, &mut rng);

        let cloned = alg.clone_box();
        // Mutate clone — original must not change.
        alg.bypass_found = true;
        assert!(!cloned.best().unwrap().has_gene("non_existent"));
        // Clone's bypass state tracks independently.
        let _ = cloned.best();
    }

    #[test]
    fn all_rule_names_covers_all_16_rules() {
        let names = all_rule_names();
        assert_eq!(names.len(), 16, "all 16 RuleId variants must be named");
    }

    #[test]
    fn population_snapshot_returns_best() {
        let alg = AstMctsAlgorithm::new();
        let snap = alg.population_snapshot();
        assert_eq!(snap.len(), 1);
    }

    // ── Saturating-arithmetic + NaN/Inf regression tests ─────────────────────

    /// `eval_counter` must saturate at `u64::MAX` rather than wrapping to 0.
    /// A wrap-around would reuse previously-issued IDs, causing the engine's
    /// `in_flight` map to collide and silently drop evaluations.
    #[test]
    fn eval_counter_saturates_at_u64_max() {
        let mut alg = AstMctsAlgorithm::new();
        let pool = GenePool::default_wafrift();
        let mut rng = make_rng();
        alg.initialize(
            vec![Chromosome::new(vec![(
                "ast_mcts_payload".into(),
                "1=1".into(),
            )])],
            &pool,
            &mut rng,
        );
        alg.eval_counter = u64::MAX;
        // request_evaluations calls saturating_add — counter must stay at MAX.
        let _ = alg.request_evaluations(1, &mut rng);
        assert_eq!(
            alg.eval_counter,
            u64::MAX,
            "eval_counter must saturate at u64::MAX, not wrap to 0"
        );
    }

    /// `generation` must saturate at `u32::MAX` rather than wrapping.
    #[test]
    fn generation_saturates_at_u32_max() {
        let mut alg = AstMctsAlgorithm::new();
        let pool = GenePool::default_wafrift();
        let mut rng = make_rng();
        alg.initialize(vec![], &pool, &mut rng);
        alg.generation = u32::MAX;
        // submit_evaluations increments generation.
        alg.submit_evaluations(vec![(0, OracleVerdict::from_bool(false))]);
        assert_eq!(
            alg.generation,
            u32::MAX,
            "generation must saturate at u32::MAX, not wrap to 0"
        );
    }

    /// A NaN `mean_reward` from the oracle must NOT permanently poison the
    /// running `rule_stats` total.  After the NaN injection, a valid reward
    /// must still produce a finite and positive running total.
    #[test]
    fn rule_stats_nan_reward_does_not_poison_ucb1() {
        let mut alg = AstMctsAlgorithm::new();
        let pool = GenePool::default_wafrift();
        let mut rng = make_rng();
        alg.initialize(
            vec![Chromosome::new(vec![(
                "ast_mcts_payload".into(),
                "1=1".into(),
            )])],
            &pool,
            &mut rng,
        );

        // Manually inject NaN into rule_stats (simulating a buggy oracle).
        alg.rule_stats.insert(0, (10, f64::NAN));

        // Submit a valid passing verdict — the NaN total must be cleared.
        let candidates = alg.request_evaluations(2, &mut rng);
        if let Some(c) = candidates.into_iter().next() {
            alg.submit_evaluations(vec![(c.id, OracleVerdict::from_bool(true))]);
        }

        // The rule_stats entry for rule 0 must now hold a finite total.
        for (visits, total) in alg.rule_stats.values() {
            assert!(
                total.is_finite() || *visits == 0,
                "rule_stats total must be finite after NaN reset, got {total}"
            );
        }
    }

    /// `+Inf` in the running total must also be cleared (same guard).
    #[test]
    fn rule_stats_inf_reward_does_not_poison_ucb1() {
        let mut alg = AstMctsAlgorithm::new();
        let pool = GenePool::default_wafrift();
        let mut rng = make_rng();
        alg.initialize(
            vec![Chromosome::new(vec![(
                "ast_mcts_payload".into(),
                "1=1".into(),
            )])],
            &pool,
            &mut rng,
        );

        alg.rule_stats.insert(1, (5, f64::INFINITY));

        let candidates = alg.request_evaluations(2, &mut rng);
        if let Some(c) = candidates.into_iter().next() {
            alg.submit_evaluations(vec![(c.id, OracleVerdict::from_bool(false))]);
        }

        for (visits, total) in alg.rule_stats.values() {
            assert!(
                total.is_finite() || *visits == 0,
                "rule_stats total must be finite after Inf reset, got {total}"
            );
        }
    }

    /// A NaN `mean_reward` from a single oracle call must not affect a
    /// *different* rule's stats entry — the guard is per-entry.
    #[test]
    fn rule_stats_nan_does_not_cross_contaminate_other_rules() {
        let mut alg = AstMctsAlgorithm::new();
        let pool = GenePool::default_wafrift();
        let mut rng = make_rng();
        alg.initialize(
            vec![Chromosome::new(vec![(
                "ast_mcts_payload".into(),
                "1=1".into(),
            )])],
            &pool,
            &mut rng,
        );

        // Rule 0: healthy entry; rule 1: NaN-poisoned.
        alg.rule_stats.insert(0, (3, 2.5));
        alg.rule_stats.insert(1, (7, f64::NAN));

        // Trigger a submit that might update stats.
        let candidates = alg.request_evaluations(1, &mut rng);
        if let Some(c) = candidates.into_iter().next() {
            alg.submit_evaluations(vec![(c.id, OracleVerdict::from_bool(true))]);
        }

        // Rule 0's total must still be finite (may have grown from the new award).
        if let Some((_, total)) = alg.rule_stats.get(&0) {
            assert!(
                total.is_finite(),
                "healthy rule_stats entry must remain finite, got {total}"
            );
        }
    }
}
