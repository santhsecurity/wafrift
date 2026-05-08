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
    grid: HashMap<FeatureDescriptor, Chromosome>,
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
            let values: Vec<&Chromosome> = self.grid.values().collect();
            Some(values[rng.gen_range(0..values.len())].clone())
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
            self.grid.get(&descriptor).cloned().or_else(|| {
                let values: Vec<&Chromosome> = self.grid.values().collect();
                Some(values[rng.gen_range(0..values.len())].clone())
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
            self.grid.entry(descriptor).or_insert(chromosome);
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
                let should_insert = match self.grid.get(&descriptor) {
                    Some(existing) => candidate.fitness > existing.fitness,
                    None => true,
                };
                if should_insert {
                    self.grid.insert(descriptor, candidate);
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
        self.grid.values().max_by(|a, b| {
            a.fitness
                .partial_cmp(&b.fitness)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    }

    fn checkpoint(&self) -> Result<Vec<u8>, EvolutionError> {
        serde_json::to_vec(self).map_err(|e| EvolutionError::SerializationFailed(e.to_string()))
    }

    fn restore(&mut self, bytes: &[u8]) -> Result<(), EvolutionError> {
        *self = serde_json::from_slice(bytes)
            .map_err(|e| EvolutionError::DeserializationFailed(e.to_string()))?;
        self.in_flight.clear();
        Ok(())
    }
}
