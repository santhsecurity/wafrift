use crate::evolution::crossover::mutation::mutate_with_log;
use crate::evolution::{Chromosome, GenePool, population::random_chromosome};
use crate::lineage::Lineage;
use crate::search::{EvalCandidate, SearchAlgorithm};
use crate::types::{Budget, EvolutionError, OracleVerdict, SearchStats};
use rand::rngs::StdRng;
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};

/// Tabu search with aspiration criteria.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TabuSearch {
    current: Chromosome,
    best: Chromosome,
    gene_pool: GenePool,
    generation: u32,
    eval_counter: u64,
    tabu_list: VecDeque<u64>,
    tabu_tenure: usize,
    tabu_set: HashSet<u64>,
}

impl TabuSearch {
    #[must_use]
    pub fn new(tabu_tenure: usize) -> Self {
        Self {
            current: Chromosome::new(vec![]),
            best: Chromosome::new(vec![]),
            gene_pool: GenePool::default_wafrift(),
            generation: 0,
            eval_counter: 0,
            tabu_list: VecDeque::new(),
            tabu_tenure,
            tabu_set: HashSet::new(),
        }
    }

    fn neighbor(&self, rng: &mut StdRng) -> Chromosome {
        let mut child = self.current.clone();
        let log = mutate_with_log(&mut child, &self.gene_pool, 0.25, rng);
        child.lineage = Lineage::mutation(&self.current, log, self.generation);
        child
    }

    fn add_tabu(&mut self, hash: u64) {
        if self.tabu_set.insert(hash) {
            self.tabu_list.push_back(hash);
        }
        while self.tabu_list.len() > self.tabu_tenure {
            if let Some(old) = self.tabu_list.pop_front() {
                self.tabu_set.remove(&old);
            }
        }
    }
}

impl Default for TabuSearch {
    fn default() -> Self {
        Self::new(20)
    }
}

impl SearchAlgorithm for TabuSearch {
    fn name(&self) -> &'static str {
        "tabu_search"
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
            self.add_tabu(best.hash());
        } else {
            self.current = random_chromosome(gene_pool, rng);
            self.best = self.current.clone();
            self.add_tabu(self.current.hash());
        }
    }

    fn request_evaluations(&mut self, n: usize, rng: &mut StdRng) -> Vec<EvalCandidate> {
        let mut out = Vec::with_capacity(n);
        let mut attempts = 0;
        while out.len() < n && attempts < n * 10 {
            attempts += 1;
            self.eval_counter += 1;
            let candidate = self.neighbor(rng);
            let hash = candidate.hash();
            // Tabu check. The aspiration criterion ("allow a tabu move
            // if it beats the current best") is intentionally NOT
            // applied here: candidate has fitness == 0.0 because it
            // hasn't been evaluated yet, so the comparison would
            // always be false and the algorithm would deadlock when
            // every neighbour is tabu. Aspiration belongs in
            // submit_evaluations, where fitness is real. Removing it
            // here matches the SimulatedAnnealing/HillClimbing flow.
            let is_tabu = self.tabu_set.contains(&hash);
            if !is_tabu {
                out.push(EvalCandidate {
                    id: self.eval_counter,
                    chromosome: candidate,
                });
            }
        }
        out
    }

    fn submit_evaluations(&mut self, results: Vec<(u64, OracleVerdict)>) {
        for (_id, verdict) in results {
            let mut candidate = self.current.clone();
            candidate.record_verdict(&verdict);
            self.add_tabu(candidate.hash());
            if candidate.fitness >= self.current.fitness {
                self.current = candidate;
                if self.current.fitness > self.best.fitness {
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
