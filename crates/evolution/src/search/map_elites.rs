use crate::evolution::crossover::mutation::mutate_with_log;
use crate::evolution::{Chromosome, GenePool, population::random_chromosome};
use crate::lineage::Lineage;
use crate::search::{EvalCandidate, SearchAlgorithm, comparable_fitness, fitness_cmp};
use crate::types::{Budget, EvolutionError, OracleVerdict, SearchStats};
use rand::Rng;
use rand::rngs::StdRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use wafrift_types::pick::pick_from_rng;

/// Feature descriptor for MAP-Elites grid binning.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FeatureDescriptor {
    pub encoding: String,
    pub grammar: String,
    pub content_type: String,
}

impl FeatureDescriptor {
    #[must_use]
    pub fn from_chromosome(chromosome: &Chromosome) -> Self {
        Self {
            encoding: chromosome.gene("encoding").unwrap_or("None").to_string(),
            grammar: chromosome
                .gene("grammar_rule")
                .unwrap_or("None")
                .to_string(),
            content_type: chromosome
                .gene("content_type")
                .unwrap_or("None")
                .to_string(),
        }
    }
}

/// MAP-Elites quality-diversity search.
///
/// # Grid representation
///
/// `grid` is a `HashMap<FeatureDescriptor, Chromosome>` so every
/// insert/lookup/replace is O(1) instead of the O(n) linear scan the
/// original `Vec<(FeatureDescriptor, Chromosome)>` required.  With a
/// grid that can hold hundreds of cells, the three O(n) scans in
/// `submit_evaluations` (check-exists → compare fitness → replace/push)
/// collapsed from 3 × n to 3 × 1 per verdict.  `population_snapshot`
/// remains O(n) (unavoidable; the whole grid is collected), and
/// `best()` stays O(n) (one linear max scan is correct there).
///
/// The serde representation is preserved as a JSON array of `[desc, chrom]`
/// pairs (see the `grid_as_pairs` module) even though the in-memory form
/// is now a `HashMap`: a map keyed by the `FeatureDescriptor` struct
/// cannot serialize to a JSON object, and the pair-array form keeps v1
/// checkpoints loadable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapElites {
    #[serde(with = "grid_as_pairs")]
    grid: HashMap<FeatureDescriptor, Chromosome>,
    gene_pool: GenePool,
    generation: u32,
    eval_counter: u64,
    #[serde(skip)]
    in_flight: HashMap<u64, Chromosome>,
}

/// Serialize/deserialize the MAP-Elites `grid` as a JSON array of
/// `[descriptor, chromosome]` pairs rather than a JSON object. A
/// `HashMap` keyed by the `FeatureDescriptor` struct cannot serialize to
/// a JSON object — JSON object keys must be strings, so the derived map
/// serialization fails with "key must be a string". The pair-array form
/// fixes that and matches the byte layout of the original
/// `Vec<(FeatureDescriptor, Chromosome)>` checkpoint, so v1 checkpoints
/// still round-trip.
mod grid_as_pairs {
    use super::{Chromosome, FeatureDescriptor};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::HashMap;

    pub(super) fn serialize<S: Serializer>(
        grid: &HashMap<FeatureDescriptor, Chromosome>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let pairs: Vec<(&FeatureDescriptor, &Chromosome)> = grid.iter().collect();
        pairs.serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<HashMap<FeatureDescriptor, Chromosome>, D::Error> {
        let pairs: Vec<(FeatureDescriptor, Chromosome)> = Vec::deserialize(deserializer)?;
        Ok(pairs.into_iter().collect())
    }
}

impl MapElites {
    #[must_use]
    pub fn new() -> Self {
        Self {
            grid: HashMap::new(),
            gene_pool: GenePool::default_wafrift(),
            generation: 0,
            eval_counter: 0,
            in_flight: HashMap::new(),
        }
    }

    fn sample_parent(&self, rng: &mut StdRng) -> Option<Chromosome> {
        if self.grid.is_empty() {
            return None;
        }
        // 50% of the time sample from under-filled regions (random bin)
        // 50% of the time sample uniformly from existing elites
        if rng.gen_bool(0.5) {
            // O(n) random-index sample from a HashMap: collect keys into a
            // temp slice, pick by index. This path is 50%-frequency and n is
            // bounded by the number of distinct (encoding × grammar × content_type)
            // cells (< 1000 in practice), so the allocation is tiny.
            let values: Vec<&Chromosome> = self.grid.values().collect();
            Some((*pick_from_rng(&values, values[0], rng)).clone())
        } else {
            // Try to fill a random feature combination. O(1) HashMap lookup
            // replaces the O(n) Vec::iter().find() that existed before.
            let encoding = self
                .gene_pool
                .random_value("encoding", rng)
                .unwrap_or_else(|| "None".into());
            let grammar = self
                .gene_pool
                .random_value("grammar_rule", rng)
                .unwrap_or_else(|| "None".into());
            let content_type = self
                .gene_pool
                .random_value("content_type", rng)
                .unwrap_or_else(|| "None".into());
            let descriptor = FeatureDescriptor {
                encoding,
                grammar,
                content_type,
            };
            // O(1) lookup — if the cell exists, clone its elite; otherwise
            // fall back to a uniform random sample (same semantics as before).
            if let Some(c) = self.grid.get(&descriptor) {
                Some(c.clone())
            } else {
                let values: Vec<&Chromosome> = self.grid.values().collect();
                Some((*pick_from_rng(&values, values[0], rng)).clone())
            }
        }
    }

    fn generate_individual(&self, rng: &mut StdRng) -> Chromosome {
        match self.sample_parent(rng) {
            Some(parent) => {
                let mut child = parent.clone();
                let log = mutate_with_log(&mut child, &self.gene_pool, 0.25, rng);
                child.lineage = Lineage::mutation(&parent, log, self.generation);
                child
            }
            None => random_chromosome(&self.gene_pool, rng),
        }
    }
}

impl Default for MapElites {
    fn default() -> Self {
        Self::new()
    }
}

impl SearchAlgorithm for MapElites {
    fn name(&self) -> &'static str {
        "map_elites"
    }

    fn initialize(&mut self, population: Vec<Chromosome>, gene_pool: &GenePool, _rng: &mut StdRng) {
        self.gene_pool = gene_pool.clone();
        self.grid.clear();
        self.in_flight.clear();
        for chromosome in population {
            let descriptor = FeatureDescriptor::from_chromosome(&chromosome);
            // O(1) HashMap entry: first chromosome for a descriptor wins
            // (same semantics as before). `entry().or_insert` avoids the
            // previous O(n) `iter().any()` contains-check.
            self.grid.entry(descriptor).or_insert(chromosome);
        }
    }

    fn request_evaluations(&mut self, n: usize, rng: &mut StdRng) -> Vec<EvalCandidate> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            self.eval_counter = self.eval_counter.saturating_add(1);
            let candidate = self.generate_individual(rng);
            self.in_flight.insert(self.eval_counter, candidate.clone());
            out.push(EvalCandidate {
                id: self.eval_counter,
                chromosome: candidate,
            });
        }
        out
    }

    fn submit_evaluations(&mut self, results: Vec<(u64, OracleVerdict)>) {
        for (id, verdict) in results {
            if let Some(mut candidate) = self.in_flight.remove(&id) {
                candidate.record_verdict(&verdict);
                let descriptor = FeatureDescriptor::from_chromosome(&candidate);
                // F144: route through comparable_fitness so a NaN / ±inf cell
                // never becomes permanently inelastic — mapping non-finite
                // fitness to NEG_INFINITY makes any finite candidate strictly
                // better and evicts the poisoned cell.
                //
                // §1 SPEED: previously this called `grid.iter().find(…)` twice
                // (once for the fitness comparison, once for the index lookup)
                // = 2 × O(n) per verdict. Now a single `entry()` call is O(1).
                use std::collections::hash_map::Entry;
                match self.grid.entry(descriptor) {
                    Entry::Vacant(e) => {
                        e.insert(candidate);
                    }
                    Entry::Occupied(mut e) => {
                        if comparable_fitness(candidate.fitness)
                            > comparable_fitness(e.get().fitness)
                        {
                            *e.get_mut() = candidate;
                        }
                    }
                }
            }
        }
        self.generation = self.generation.saturating_add(1);
    }

    fn should_terminate(&self, stats: &SearchStats, budget: &Budget) -> bool {
        stats.evaluations >= budget.max_requests
            || stats.generation >= budget.max_generations
            || stats.stagnation_counter >= budget.stagnation_limit
    }

    fn best(&self) -> Option<&Chromosome> {
        // F144: use fitness_cmp (which routes through comparable_fitness)
        // so a NaN-fitness cell can never be returned as "best" just
        // because every partial_cmp against it returned `None` and
        // got mapped to `Equal`. A finite-fitness cell always wins
        // against a NaN cell after the mapping.
        self.grid
            .values()
            .max_by(|a, b| fitness_cmp(a.fitness, b.fitness))
    }

    fn checkpoint(&self) -> Result<Vec<u8>, EvolutionError> {
        serde_json::to_vec(self).map_err(EvolutionError::SerializationFailed)
    }

    fn restore(&mut self, bytes: &[u8]) -> Result<(), EvolutionError> {
        if bytes.len() > crate::types::MAX_CHECKPOINT_BYTES {
            return Err(EvolutionError::OversizedData {
                context: "map_elites checkpoint restore".into(),
                size: bytes.len(),
                max: crate::types::MAX_CHECKPOINT_BYTES,
            });
        }
        *self = serde_json::from_slice(bytes).map_err(EvolutionError::DeserializationFailed)?;
        self.in_flight.clear();
        Ok(())
    }

    /// Every grid cell holds an elite chromosome —
    /// the elite set IS the live population for diversity purposes.
    fn population_snapshot(&self) -> Vec<Chromosome> {
        self.grid.values().cloned().collect()
    }

    fn clone_box(&self) -> Box<dyn SearchAlgorithm> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn dummy_chromosome(encoding: &str, grammar: &str, content_type: &str) -> Chromosome {
        Chromosome::new(vec![
            ("encoding".into(), encoding.into()),
            ("grammar_rule".into(), grammar.into()),
            ("content_type".into(), content_type.into()),
        ])
    }

    #[test]
    fn initialize_populates_grid() {
        let mut alg = MapElites::new();
        let pool = GenePool::default_wafrift();
        let mut rng = StdRng::seed_from_u64(1);
        let pop = vec![
            dummy_chromosome("UrlEncode", "sqli", "json"),
            dummy_chromosome("CaseAlternation", "cmdi", "form"),
        ];
        alg.initialize(pop, &pool, &mut rng);
        assert_eq!(alg.grid.len(), 2);
    }

    #[test]
    fn request_evaluations_returns_unique_ids() {
        let mut alg = MapElites::new();
        let pool = GenePool::default_wafrift();
        let mut rng = StdRng::seed_from_u64(2);
        alg.initialize(
            vec![dummy_chromosome("UrlEncode", "sqli", "json")],
            &pool,
            &mut rng,
        );

        let c1 = alg.request_evaluations(2, &mut rng);
        let c2 = alg.request_evaluations(2, &mut rng);
        let ids: Vec<_> = c1.iter().chain(c2.iter()).map(|c| c.id).collect();
        let unique: std::collections::HashSet<_> = ids.iter().copied().collect();
        assert_eq!(ids.len(), unique.len());
    }

    #[test]
    fn submit_evaluation_inserts_into_grid() {
        let mut alg = MapElites::new();
        let pool = GenePool::default_wafrift();
        let mut rng = StdRng::seed_from_u64(3);
        alg.initialize(vec![], &pool, &mut rng);

        let candidates = alg.request_evaluations(1, &mut rng);
        let id = candidates[0].id;

        alg.submit_evaluations(vec![(
            id,
            OracleVerdict {
                passed: true,
                status_delta: 1,
                body_delta: 1,
                latency_ms: 10,
                confidence: 0.9,
                triggered_rules: 0,
                ..Default::default()
            },
        )]);

        assert!(!alg.grid.is_empty());
        assert!(alg.best().is_some());
        assert!(alg.best().unwrap().fitness > 0.0);
    }

    #[test]
    fn higher_fitness_replaces_existing_grid_cell() {
        let mut alg = MapElites::new();
        let pool = GenePool::default_wafrift();
        let mut rng = StdRng::seed_from_u64(4);
        let mut low = dummy_chromosome("UrlEncode", "sqli", "json");
        low.fitness = 0.1;
        alg.initialize(vec![low], &pool, &mut rng);

        // Force a candidate with the same descriptor but higher fitness
        let mut high = dummy_chromosome("UrlEncode", "sqli", "json");
        high.fitness = 0.9;
        alg.in_flight.insert(42, high);
        alg.submit_evaluations(vec![(
            42,
            OracleVerdict {
                passed: true,
                status_delta: 1,
                body_delta: 1,
                latency_ms: 10,
                confidence: 0.9,
                triggered_rules: 0,
                ..Default::default()
            },
        )]);

        assert!(alg.best().unwrap().fitness > 0.5);
    }

    #[test]
    fn nan_poisoned_grid_cell_can_still_be_replaced() {
        // F144 regression: pre-fix `candidate.fitness > existing.fitness`
        // returned false for ANY candidate when existing.fitness was
        // NaN (every comparison with NaN is false in IEEE-754), so a
        // single bad eval poisoned the cell PERMANENTLY — every future
        // candidate landing in that feature region was rejected and
        // the search effectively lost that descriptor forever. Post-
        // fix the comparison routes through comparable_fitness, which
        // maps NaN to NEG_INFINITY so a finite-fitness candidate
        // always strictly beats the poisoned cell.
        let mut alg = MapElites::new();
        let pool = GenePool::default_wafrift();
        let mut rng = StdRng::seed_from_u64(7);
        // Seed the grid with a NaN-fitness chromosome at a known descriptor.
        let mut poisoned = dummy_chromosome("UrlEncode", "sqli", "json");
        poisoned.fitness = f64::NAN;
        alg.initialize(vec![poisoned], &pool, &mut rng);
        assert_eq!(alg.grid.len(), 1);

        // Fire a candidate with the same descriptor and a finite, low
        // fitness. Pre-fix this was rejected (NaN > 0 is false ⇒
        // `candidate.fitness > existing.fitness` is also false).
        let mut healer = dummy_chromosome("UrlEncode", "sqli", "json");
        healer.fitness = 0.0; // start at zero; record_verdict will push it up.
        alg.in_flight.insert(99, healer);
        alg.submit_evaluations(vec![(
            99,
            OracleVerdict {
                passed: true,
                status_delta: 0,
                body_delta: 0,
                latency_ms: 0,
                confidence: 1.0,
                triggered_rules: 0,
                ..Default::default()
            },
        )]);

        // The grid cell at that descriptor should now hold the
        // finite-fitness chromosome, not the NaN one.
        // grid is now a HashMap<FeatureDescriptor, Chromosome>; find via values().
        let cell_fitness = alg
            .grid
            .iter()
            .find(|(d, _)| d.encoding == "UrlEncode")
            .map(|(_, c)| c.fitness)
            .expect("descriptor must still exist");
        assert!(
            cell_fitness.is_finite(),
            "NaN cell must be evictable: got {cell_fitness}"
        );
        assert!(
            cell_fitness > 0.0,
            "healer must have replaced poisoned cell"
        );
    }

    #[test]
    fn checkpoint_roundtrip_clears_in_flight() {
        let mut alg = MapElites::new();
        let pool = GenePool::default_wafrift();
        let mut rng = StdRng::seed_from_u64(5);
        alg.initialize(
            vec![dummy_chromosome("UrlEncode", "sqli", "json")],
            &pool,
            &mut rng,
        );
        let _ = alg.request_evaluations(3, &mut rng);
        assert!(!alg.in_flight.is_empty());

        let bytes = alg.checkpoint().expect("checkpoint must serialize");
        let mut restored = MapElites::new();
        restored.restore(&bytes).expect("restore must succeed");
        assert!(restored.in_flight.is_empty());
        assert_eq!(restored.grid.len(), alg.grid.len());
    }

    #[test]
    fn should_terminate_respects_budget() {
        let alg = MapElites::new();
        let budget = Budget::default_wafrift();
        let stats = SearchStats {
            evaluations: budget.max_requests - 1,
            ..SearchStats::default()
        };
        assert!(!alg.should_terminate(&stats, &budget));
        let stats = SearchStats {
            evaluations: budget.max_requests,
            ..SearchStats::default()
        };
        assert!(alg.should_terminate(&stats, &budget));
    }

    #[test]
    fn best_returns_none_for_empty_grid() {
        let alg = MapElites::new();
        assert!(alg.best().is_none());
    }

    // ── Saturating-arithmetic regression tests ────────────────────────────────

    /// `eval_counter` must saturate at `u64::MAX` rather than wrapping to 0.
    /// A wrap-around would collide with existing in-flight IDs and silently
    /// drop grid updates.
    #[test]
    fn eval_counter_saturates_at_u64_max() {
        let mut alg = MapElites::new();
        let pool = GenePool::default_wafrift();
        let mut rng = StdRng::seed_from_u64(99);
        alg.initialize(
            vec![dummy_chromosome("UrlEncode", "sqli", "json")],
            &pool,
            &mut rng,
        );
        alg.eval_counter = u64::MAX;
        // request_evaluations must use saturating_add — counter must stay at MAX.
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
        let mut alg = MapElites::new();
        let pool = GenePool::default_wafrift();
        let mut rng = StdRng::seed_from_u64(100);
        alg.initialize(vec![], &pool, &mut rng);
        alg.generation = u32::MAX;
        // submit_evaluations increments generation.
        alg.submit_evaluations(vec![]);
        assert_eq!(
            alg.generation,
            u32::MAX,
            "generation must saturate at u32::MAX, not wrap to 0"
        );
    }

    /// Across many `request_evaluations` + `submit_evaluations` cycles,
    /// the `eval_counter` must always increment monotonically and IDs must
    /// never collide.
    #[test]
    fn eval_counter_is_strictly_increasing() {
        let mut alg = MapElites::new();
        let pool = GenePool::default_wafrift();
        let mut rng = StdRng::seed_from_u64(101);
        alg.initialize(
            vec![dummy_chromosome("CaseAlternation", "xss", "json")],
            &pool,
            &mut rng,
        );
        let mut all_ids: Vec<u64> = Vec::new();
        for _ in 0..5 {
            let batch = alg.request_evaluations(3, &mut rng);
            for c in &batch {
                all_ids.push(c.id);
            }
            let verdicts: Vec<_> = batch
                .into_iter()
                .map(|c| (c.id, OracleVerdict::from_bool(false)))
                .collect();
            alg.submit_evaluations(verdicts);
        }
        let unique: std::collections::HashSet<_> = all_ids.iter().copied().collect();
        assert_eq!(
            unique.len(),
            all_ids.len(),
            "all eval_counter-derived IDs must be unique across generations"
        );
    }
}
