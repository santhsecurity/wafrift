use crate::evolution::Chromosome;
use rand::Rng;
use wafrift_types::pick::pick_ref_from_rng;

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
///
/// # Panics
/// Panics with a clear contract message if `population` is empty —
/// silently returning a "default" Chromosome would mask the caller's
/// state-machine bug. Callers that may have an empty population
/// should guard before invoking this helper.
#[must_use]
pub fn tournament_select_with_size<'a>(
    population: &'a [Chromosome],
    tournament_size: usize,
    rng: &mut impl Rng,
) -> &'a Chromosome {
    assert!(
        !population.is_empty(),
        "tournament_select_with_size called with empty population — caller bug"
    );
    let size = tournament_size.min(population.len());
    let mut best = pick_ref_from_rng(population, rng).unwrap_or(&population[0]);
    for _ in 1..size {
        let candidate = pick_ref_from_rng(population, rng).unwrap_or(&population[0]);
        if candidate.fitness > best.fitness {
            best = candidate;
        }
    }
    best
}

/// Roulette wheel selection (fitness proportionate selection).
///
/// # Panics
/// Panics if `population` is empty (see `tournament_select_with_size`).
#[must_use]
pub fn roulette_select<'a>(population: &'a [Chromosome], rng: &mut impl Rng) -> &'a Chromosome {
    assert!(
        !population.is_empty(),
        "roulette_select called with empty population — caller bug"
    );
    if population.len() == 1 {
        return &population[0];
    }
    let total_fitness: f64 = population.iter().map(|c| c.fitness.max(0.0)).sum();
    if total_fitness <= 0.0 {
        return pick_ref_from_rng(population, rng).unwrap_or(&population[0]);
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

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn tournament_select_single_chromosome_returns_it() {
        let population = vec![Chromosome::new(vec![("encoding".into(), "None".into())])];
        let mut rng = StdRng::seed_from_u64(29);
        let selected = tournament_select(&population, &mut rng);
        assert_eq!(selected.genes, population[0].genes);
    }
}
