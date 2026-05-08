use crate::evolution::Chromosome;
use rand::Rng;

/// Selection strategy for tournament selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionStrategy {
    Standard,
    Adaptive,
    Roulette,
}

/// Tournament selection with configurable tournament size.
#[must_use]
pub fn tournament_select<'a>(population: &'a [Chromosome], rng: &mut impl Rng) -> &'a Chromosome {
    let tournament_size = 3_usize.min(population.len());
    tournament_select_with_size(population, tournament_size, rng)
}

/// Tournament selection with explicit tournament size.
#[must_use]
pub fn tournament_select_with_size<'a>(
    population: &'a [Chromosome],
    tournament_size: usize,
    rng: &mut impl Rng,
) -> &'a Chromosome {
    let size = tournament_size.min(population.len());
    let mut best_idx = rng.gen_range(0..population.len());
    for _ in 1..size {
        let candidate_idx = rng.gen_range(0..population.len());
        if population[candidate_idx].fitness > population[best_idx].fitness {
            best_idx = candidate_idx;
        }
    }
    &population[best_idx]
}

/// Roulette wheel selection (fitness proportionate selection).
#[must_use]
pub fn roulette_select<'a>(population: &'a [Chromosome], rng: &mut impl Rng) -> &'a Chromosome {
    if population.len() <= 1 {
        return &population[0];
    }
    let total_fitness: f64 = population.iter().map(|c| c.fitness.max(0.0)).sum();
    if total_fitness <= 0.0 {
        return &population[rng.gen_range(0..population.len())];
    }
    let mut spin = rng.gen_range(0.0..total_fitness);
    for chromosome in population {
        spin -= chromosome.fitness.max(0.0);
        if spin <= 0.0 {
            return chromosome;
        }
    }
    &population[population.len() - 1]
}

/// Adaptive selection that adjusts tournament size based on population diversity.
#[must_use]
pub fn adaptive_select<'a>(
    population: &'a [Chromosome],
    diversity: f64,
    rng: &mut impl Rng,
) -> &'a Chromosome {
    let base_size = 3_usize;
    let max_size = (population.len() / 3).max(base_size);
    let adjusted_size = base_size + ((max_size - base_size) as f64 * (1.0 - diversity)) as usize;
    tournament_select_with_size(population, adjusted_size, rng)
}
