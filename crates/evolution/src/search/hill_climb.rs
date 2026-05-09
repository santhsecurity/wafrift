use crate::evolution::crossover::mutation::mutate_with_log;
use crate::evolution::{Chromosome, GenePool};
use crate::lineage::Lineage;
use crate::search::{EvalCandidate, SearchAlgorithm, comparable_fitness, fitness_cmp};
use crate::types::{Budget, EvolutionError, OracleVerdict, SearchStats};
use rand::rngs::StdRng;
use serde::{Deserialize, Serialize};

/// Simple hill-climbing search.
///
/// Maintains a current best and greedily moves to better neighbors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HillClimbing {
    current: Chromosome,
    gene_pool: GenePool,
    generation: u32,
    eval_counter: u64,
    best: Chromosome,
}

impl HillClimbing {
    #[must_use]
    pub fn new() -> Self {
        Self {
            current: Chromosome::new(vec![]),
            gene_pool: GenePool::default_wafrift(),
            generation: 0,
            eval_counter: 0,
            best: Chromosome::new(vec![]),
        }
    }

    fn neighbor(&self, rng: &mut StdRng) -> Chromosome {
        let mut child = self.current.clone();
        let log = mutate_with_log(&mut child, &self.gene_pool, 0.25, rng);
        child.lineage = Lineage::mutation(&self.current, log, self.generation);
        child
    }
}

impl Default for HillClimbing {
    fn default() -> Self {
        Self::new()
    }
}

impl SearchAlgorithm for HillClimbing {
    fn name(&self) -> &'static str {
        "hill_climbing"
    }

    fn initialize(&mut self, population: Vec<Chromosome>, gene_pool: &GenePool, _rng: &mut StdRng) {
        self.gene_pool = gene_pool.clone();
        if let Some(best) = population
            .iter()
            .max_by(|a, b| fitness_cmp(a.fitness, b.fitness))
        {
            self.current = best.clone();
            self.best = best.clone();
        } else {
            self.current = baseline(gene_pool);
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
            // Record the verdict on a clone first, then compare the
            // resulting EMA-smoothed fitness — this keeps both sides
            // of the comparison in the same units. The earlier
            // approach compared raw verdict.to_fitness() against
            // self.current.fitness (an EMA), which made the
            // accept threshold drift higher as `current` accumulated
            // evaluations and rejected good candidates arbitrarily.
            let mut next = self.current.clone();
            next.record_verdict(&verdict);
            if comparable_fitness(next.fitness) >= comparable_fitness(self.current.fitness) {
                self.current = next;
                if comparable_fitness(self.current.fitness) > comparable_fitness(self.best.fitness)
                {
                    self.best = self.current.clone();
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

fn baseline(gene_pool: &GenePool) -> Chromosome {
    let genes = gene_pool
        .gene_names()
        .into_iter()
        .map(|name| (name.to_string(), String::from("None")))
        .collect();
    Chromosome::new(genes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn non_finite_verdict_fitness_does_not_poison_acceptance() {
        let mut alg = HillClimbing::new();
        let pool = GenePool::default_wafrift();
        let mut rng = StdRng::seed_from_u64(7);
        alg.initialize(vec![Chromosome::new(vec![])], &pool, &mut rng);

        alg.submit_evaluations(vec![(
            1,
            OracleVerdict {
                passed: false,
                status_delta: 0,
                body_delta: 0,
                latency_ms: 0,
                confidence: f64::NAN,
                triggered_rules: 1,
            },
        )]);
        let best_after_nan = comparable_fitness(alg.best().expect("best must exist").fitness);

        alg.submit_evaluations(vec![(2, OracleVerdict::from_bool(true))]);
        let best_after_valid = comparable_fitness(alg.best().expect("best must exist").fitness);
        assert!(best_after_valid > best_after_nan);
    }
}
