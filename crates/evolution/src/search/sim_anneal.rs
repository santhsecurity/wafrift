use crate::evolution::crossover::mutation::mutate_with_log;
use crate::evolution::{Chromosome, GenePool, population::random_chromosome};
use crate::lineage::Lineage;
use crate::search::{EvalCandidate, SearchAlgorithm};
use crate::types::{Budget, EvolutionError, OracleVerdict, SearchStats};
use rand::rngs::StdRng;
use serde::{Deserialize, Serialize};

/// Simulated annealing search.
///
/// Uses a temperature schedule to occasionally accept worse candidates,
/// helping escape local optima.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulatedAnnealing {
    current: Chromosome,
    best: Chromosome,
    gene_pool: GenePool,
    generation: u32,
    eval_counter: u64,
    temperature: f64,
    cooling_rate: f64,
    min_temperature: f64,
}

impl SimulatedAnnealing {
    #[must_use]
    pub fn new() -> Self {
        Self {
            current: Chromosome::new(vec![]),
            best: Chromosome::new(vec![]),
            gene_pool: GenePool::default_wafrift(),
            generation: 0,
            eval_counter: 0,
            temperature: 1.0,
            cooling_rate: 0.95,
            min_temperature: 0.01,
        }
    }

    fn neighbor(&self, rng: &mut StdRng) -> Chromosome {
        let mut child = self.current.clone();
        let log = mutate_with_log(&mut child, &self.gene_pool, 0.25, rng);
        child.lineage = Lineage::mutation(&self.current, log, self.generation);
        child
    }
}

impl Default for SimulatedAnnealing {
    fn default() -> Self {
        Self::new()
    }
}

impl SearchAlgorithm for SimulatedAnnealing {
    fn name(&self) -> &'static str {
        "simulated_annealing"
    }

    fn initialize(&mut self, population: Vec<Chromosome>, gene_pool: &GenePool, rng: &mut StdRng) {
        self.gene_pool = gene_pool.clone();
        if let Some(best) = population.iter().max_by(|a, b| {
            a.fitness
                .partial_cmp(&b.fitness)
                .unwrap_or(std::cmp::Ordering::Equal)
        }) {
            self.current = best.clone();
            self.best = best.clone();
        } else {
            self.current = random_chromosome(gene_pool, rng);
            self.best = self.current.clone();
        }
    }

    fn request_evaluations(&mut self, n: usize, rng: &mut StdRng) -> Vec<EvalCandidate> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            self.eval_counter += 1;
            out.push(EvalCandidate {
                id: self.eval_counter,
                chromosome: self.neighbor(rng),
            });
        }
        out
    }

    fn submit_evaluations(&mut self, results: Vec<(u64, OracleVerdict)>) {
        for (_id, verdict) in results {
            let mut candidate = self.current.clone();
            candidate.record_verdict(&verdict);
            let delta = candidate.fitness - self.current.fitness;
            let accepted = if delta > 0.0 {
                true
            } else {
                let p = (delta / self.temperature.max(1e-9)).exp();
                // Deterministic acceptance using eval_counter as jitter source
                let threshold = ((self.eval_counter % 1000) as f64) / 1000.0;
                p > threshold
            };
            if accepted {
                self.current = candidate;
                if self.current.fitness > self.best.fitness {
                    self.best = self.current.clone();
                }
            }
        }
        self.generation += 1;
        self.temperature = (self.temperature * self.cooling_rate).max(self.min_temperature);
    }

    fn should_terminate(&self, stats: &SearchStats, budget: &Budget) -> bool {
        stats.evaluations >= budget.max_requests
            || stats.generation >= budget.max_generations
            || stats.stagnation_counter >= budget.stagnation_limit
            || self.temperature <= self.min_temperature
    }

    fn best(&self) -> Option<&Chromosome> {
        Some(&self.best)
    }

    fn checkpoint(&self) -> Result<Vec<u8>, EvolutionError> {
        serde_json::to_vec(self).map_err(|e| EvolutionError::SerializationFailed(e.to_string()))
    }

    fn restore(&mut self, bytes: &[u8]) -> Result<(), EvolutionError> {
        *self = serde_json::from_slice(bytes)
            .map_err(|e| EvolutionError::DeserializationFailed(e.to_string()))?;
        Ok(())
    }
}
