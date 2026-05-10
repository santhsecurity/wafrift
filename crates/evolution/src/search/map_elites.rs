use crate::evolution::crossover::mutation::mutate_with_log;
use crate::evolution::{Chromosome, GenePool, population::random_chromosome};
use crate::lineage::Lineage;
use crate::search::{EvalCandidate, SearchAlgorithm};
use crate::types::{Budget, EvolutionError, OracleVerdict, SearchStats};
use rand::Rng;
use rand::rngs::StdRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapElites {
    grid: Vec<(FeatureDescriptor, Chromosome)>,
    gene_pool: GenePool,
    generation: u32,
    eval_counter: u64,
    #[serde(skip)]
    in_flight: HashMap<u64, Chromosome>,
}

impl MapElites {
    #[must_use]
    pub fn new() -> Self {
        Self {
            grid: Vec::new(),
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
            let idx = rng.gen_range(0..self.grid.len());
            Some(self.grid[idx].1.clone())
        } else {
            // Try to fill a random feature combination
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
            self.grid
                .iter()
                .find(|(d, _)| *d == descriptor)
                .map(|(_, c)| c.clone())
                .or_else(|| {
                    let idx = rng.gen_range(0..self.grid.len());
                    Some(self.grid[idx].1.clone())
                })
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
            if !self.grid.iter().any(|(d, _)| *d == descriptor) {
                self.grid.push((descriptor, chromosome));
            }
        }
    }

    fn request_evaluations(&mut self, n: usize, rng: &mut StdRng) -> Vec<EvalCandidate> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            self.eval_counter += 1;
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
                let should_insert = match self.grid.iter().find(|(d, _)| *d == descriptor) {
                    Some((_, existing)) => candidate.fitness > existing.fitness,
                    None => true,
                };
                if should_insert {
                    if let Some((idx, _)) = self
                        .grid
                        .iter()
                        .enumerate()
                        .find(|(_, (d, _))| *d == descriptor)
                    {
                        self.grid[idx] = (descriptor, candidate);
                    } else {
                        self.grid.push((descriptor, candidate));
                    }
                }
            }
        }
        self.generation += 1;
    }

    fn should_terminate(&self, stats: &SearchStats, budget: &Budget) -> bool {
        stats.evaluations >= budget.max_requests
            || stats.generation >= budget.max_generations
            || stats.stagnation_counter >= budget.stagnation_limit
    }

    fn best(&self) -> Option<&Chromosome> {
        self.grid.iter().map(|(_, c)| c).max_by(|a, b| {
            a.fitness
                .partial_cmp(&b.fitness)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
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

    /// Every grid cell holds a (descriptor, elite chromosome) pair —
    /// the elite set IS the live population for diversity purposes.
    fn population_snapshot(&self) -> Vec<Chromosome> {
        self.grid.iter().map(|(_, c)| c.clone()).collect()
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
            },
        )]);

        assert!(alg.best().unwrap().fitness > 0.5);
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
}
