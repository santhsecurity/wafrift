//! Search algorithms for evolutionary WAF bypass discovery.

use crate::evolution::{Chromosome, GenePool};
use crate::types::{Budget, EvolutionError, OracleVerdict, SearchStats};
use rand::rngs::StdRng;

/// A candidate requested for evaluation, with a stable evaluation ID.
#[derive(Debug, Clone)]
pub struct EvalCandidate {
    /// Stable ID used to correlate results.
    pub id: u64,
    /// The chromosome to evaluate.
    pub chromosome: Chromosome,
}

/// Result of submitting evaluations back to the algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitResult {
    /// The algorithm accepted all results.
    Accepted,
    /// Some evaluation IDs were unknown.
    UnknownIds(usize),
}

/// Core trait implemented by all search algorithms.
///
/// Each algorithm manages its own internal state (population, archive,
/// temperature, tabu list, etc.). The [`EvolutionEngine`](crate::evolution::EvolutionEngine)
/// handles caching, budgeting, and batching on top of this trait.
pub trait SearchAlgorithm: Send + Sync + std::fmt::Debug {
    /// Algorithm name.
    fn name(&self) -> &'static str;

    /// Initialize the algorithm with a seed population.
    fn initialize(&mut self, population: Vec<Chromosome>, gene_pool: &GenePool, rng: &mut StdRng);

    /// Request up to `n` candidates for parallel evaluation.
    ///
    /// Returns candidates with stable IDs. The caller evaluates them and
    /// later calls [`submit_evaluations`](SearchAlgorithm::submit_evaluations).
    fn request_evaluations(&mut self, n: usize, rng: &mut StdRng) -> Vec<EvalCandidate>;

    /// Submit evaluation results.
    ///
    /// The ID in each tuple must match an ID previously returned by
    /// `request_evaluations`.
    fn submit_evaluations(&mut self, results: Vec<(u64, OracleVerdict)>);

    /// Check whether the algorithm thinks search should stop.
    fn should_terminate(&self, stats: &SearchStats, budget: &Budget) -> bool;

    /// Get the best chromosome found so far.
    fn best(&self) -> Option<&Chromosome>;

    /// Serialize internal state to bytes.
    fn checkpoint(&self) -> Result<Vec<u8>, EvolutionError>;

    /// Restore internal state from bytes.
    fn restore(&mut self, bytes: &[u8]) -> Result<(), EvolutionError>;
}

pub mod hill_climb;
pub mod map_elites;
pub mod novelty;
pub mod sim_anneal;
pub mod tabu;

pub use hill_climb::HillClimbing;
pub use map_elites::MapElites;
pub use novelty::NoveltySearch;
pub use sim_anneal::SimulatedAnnealing;
pub use tabu::TabuSearch;
