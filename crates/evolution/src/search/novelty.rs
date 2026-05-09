use crate::evolution::crossover::mutation::mutate_with_log;
use crate::evolution::{Chromosome, GenePool, population::random_chromosome};
use crate::lineage::Lineage;
use crate::search::{EvalCandidate, SearchAlgorithm};
use crate::types::{Budget, EvolutionError, OracleVerdict, SearchStats};
use rand::Rng;
use rand::rngs::StdRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Novelty search with k-NN behavioral distance archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoveltySearch {
    population: Vec<Chromosome>,
    archive: Vec<Chromosome>,
    gene_pool: GenePool,
    generation: u32,
    eval_counter: u64,
    k: usize,
    threshold: f64,
    #[serde(skip)]
    in_flight: HashMap<u64, Chromosome>,
}

impl NoveltySearch {
    #[must_use]
    pub fn new(k: usize, threshold: f64) -> Self {
        Self {
            population: Vec::new(),
            archive: Vec::new(),
            gene_pool: GenePool::default_wafrift(),
            generation: 0,
            eval_counter: 0,
            k,
            threshold,
            in_flight: HashMap::new(),
        }
    }

    fn phenotypic_distance(a: &Chromosome, b: &Chromosome) -> f64 {
        let genes_a: Vec<_> = a.genes.iter().map(|(n, v)| format!("{n}={v}")).collect();
        let genes_b: Vec<_> = b.genes.iter().map(|(n, v)| format!("{n}={v}")).collect();
        levenshtein_distance(&genes_a.join("|"), &genes_b.join("|")) as f64
            / (genes_a.len().max(genes_b.len()).max(1) as f64)
    }

    fn novelty_score(&self, chromosome: &Chromosome) -> f64 {
        let mut neighbors: Vec<f64> = self
            .archive
            .iter()
            .chain(self.population.iter())
            .map(|other| Self::phenotypic_distance(chromosome, other))
            .collect();
        neighbors.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        neighbors.truncate(self.k);
        if neighbors.is_empty() {
            return f64::INFINITY;
        }
        neighbors.iter().sum::<f64>() / neighbors.len() as f64
    }

    fn generate_individual(&self, rng: &mut StdRng) -> Chromosome {
        if self.population.is_empty() {
            return random_chromosome(&self.gene_pool, rng);
        }
        let parent = &self.population[rng.gen_range(0..self.population.len())];
        let mut child = parent.clone();
        let log = mutate_with_log(&mut child, &self.gene_pool, 0.3, rng);
        child.lineage = Lineage::mutation(parent, log, self.generation);
        child
    }
}

impl Default for NoveltySearch {
    fn default() -> Self {
        Self::new(15, 0.3)
    }
}

impl SearchAlgorithm for NoveltySearch {
    fn name(&self) -> &'static str {
        "novelty_search"
    }

    fn initialize(&mut self, population: Vec<Chromosome>, gene_pool: &GenePool, _rng: &mut StdRng) {
        self.gene_pool = gene_pool.clone();
        self.population = population;
        self.archive.clear();
        self.in_flight.clear();
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
        let mut evaluated: Vec<Chromosome> = Vec::with_capacity(results.len());
        for (id, verdict) in results {
            if let Some(mut candidate) = self.in_flight.remove(&id) {
                candidate.record_verdict(&verdict);
                evaluated.push(candidate);
            }
        }

        // Add to archive based on novelty. Cap the archive at 10_000
        // to prevent unbounded growth on long-running scans (every
        // novel candidate would otherwise stay alive forever, leaking
        // memory until OOM). When full, evict the least-novel entry
        // by score so the highest-novelty history is retained.
        const ARCHIVE_CAP: usize = 10_000;
        for candidate in evaluated {
            let score = self.novelty_score(&candidate);
            if score > self.threshold {
                if self.archive.len() >= ARCHIVE_CAP
                    && let Some((min_idx, _)) = self
                        .archive
                        .iter()
                        .enumerate()
                        .map(|(i, c)| (i, self.novelty_score(c)))
                        .min_by(|(_, a), (_, b)| {
                            a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal)
                        })
                {
                    self.archive.swap_remove(min_idx);
                }
                self.archive.push(candidate.clone());
            }
            self.population.push(candidate);
        }

        // Cull population to reasonable size, keeping most novel
        if self.population.len() > 100 {
            let temp: Vec<Chromosome> = self.population.drain(..).collect();
            let mut scored: Vec<(f64, Chromosome)> = temp
                .into_iter()
                .map(|c| (self.novelty_score(&c), c))
                .collect();
            scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
            scored.truncate(100);
            self.population = scored.into_iter().map(|(_, c)| c).collect();
        }

        self.generation += 1;
    }

    fn should_terminate(&self, stats: &SearchStats, budget: &Budget) -> bool {
        stats.evaluations >= budget.max_requests
            || stats.generation >= budget.max_generations
            || stats.stagnation_counter >= budget.stagnation_limit
    }

    fn best(&self) -> Option<&Chromosome> {
        self.population
            .iter()
            .chain(self.archive.iter())
            .max_by(|a, b| {
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

fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let mut prev = vec![0; b_chars.len() + 1];
    let mut curr = vec![0; b_chars.len() + 1];
    for (j, slot) in prev.iter_mut().enumerate().take(b_chars.len() + 1) {
        *slot = j;
    }
    for i in 1..=a_chars.len() {
        curr[0] = i;
        for j in 1..=b_chars.len() {
            let cost = if a_chars[i - 1] == b_chars[j - 1] {
                0
            } else {
                1
            };
            curr[j] = (curr[j - 1] + 1).min(prev[j] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b_chars.len()]
}
