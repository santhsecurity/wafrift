#![allow(clippy::float_cmp)]

use crate::evolution::Chromosome;
use crate::evolution::fitness::stats::GeneStatRecord;

/// Calculate weighted fitness of a chromosome.
#[must_use]
pub fn weighted_fitness(chromosome: &Chromosome) -> f64 {
    if chromosome.evaluations == 0 {
        return 0.0;
    }
    let confidence = 1.0 - (-f64::from(chromosome.evaluations) / 10.0).exp();
    chromosome.fitness * confidence
}

/// Calculate engine-level fitness that rewards bypass signal while
/// discounting no-op chromosomes.
#[must_use]
pub fn evolutionary_fitness(chromosome: &Chromosome, gene_stats: &[GeneStatRecord]) -> f64 {
    if chromosome.evaluations == 0 {
        return 0.0;
    }

    let active_genes: Vec<_> = chromosome
        .genes
        .iter()
        .filter(|(_, value)| value != "None")
        .collect();

    if active_genes.is_empty() {
        return (chromosome.fitness * 0.35).min(0.35);
    }

    let historical_support = active_genes
        .iter()
        .map(|(name, value)| smoothed_gene_success_rate(gene_stats, name, value))
        .sum::<f64>()
        / active_genes.len() as f64;
    let confidence = (1.0 - (-f64::from(chromosome.evaluations) / 6.0).exp()).clamp(0.6, 1.0);
    let modifier = 0.80 + (historical_support * 0.30);

    (chromosome.fitness * modifier * confidence).clamp(0.0, 1.0)
}

fn smoothed_gene_success_rate(gene_stats: &[GeneStatRecord], name: &str, value: &str) -> f64 {
    gene_stats
        .iter()
        .find(|(stat_name, stat_value, _, _)| stat_name == name && stat_value == value)
        .map_or(0.5, |(_, _, successes, attempts)| {
            f64::from(*successes + 1) / f64::from(*attempts + 2)
        })
}

/// Calculate confidence-weighted average fitness for a population.
#[must_use]
pub fn confidence_weighted_average_fitness(population: &[Chromosome]) -> f64 {
    let mut weighted_sum = 0.0;
    let mut total_weight = 0.0;
    for chromosome in population {
        if chromosome.evaluations > 0 {
            let weight = f64::from(chromosome.evaluations).sqrt();
            weighted_sum += chromosome.fitness * weight;
            total_weight += weight;
        }
    }
    if total_weight == 0.0 {
        0.0
    } else {
        weighted_sum / total_weight
    }
}

/// Calculate simple average fitness for evaluated chromosomes.
#[must_use]
pub fn average_evaluated_fitness(population: &[Chromosome]) -> f64 {
    let mut total_fitness = 0.0;
    let mut evaluated_count = 0_u32;
    for chromosome in population {
        if chromosome.evaluations > 0 {
            total_fitness += chromosome.fitness;
            evaluated_count += 1;
        }
    }
    if evaluated_count == 0 {
        0.0
    } else {
        total_fitness / f64::from(evaluated_count)
    }
}

/// Detect if the population has converged (low fitness variance).
#[must_use]
pub fn has_converged(population: &[Chromosome], threshold: f64) -> bool {
    if population.is_empty() {
        return false;
    }
    let stats = crate::evolution::fitness::summary::fitness_statistics(population);
    stats.std_dev < threshold
}

/// Identify stagnation in the evolutionary process.
#[must_use]
pub fn is_stagnant(fitness_history: &[f64], window_size: usize, threshold: f64) -> bool {
    if fitness_history.len() < window_size {
        return false;
    }
    let recent = &fitness_history[fitness_history.len().saturating_sub(window_size)..];
    if recent.len() < 2 {
        return false;
    }
    let max_change = recent
        .windows(2)
        .map(|w| (w[1] - w[0]).abs())
        .fold(0.0_f64, |a: f64, b: f64| a.max(b));
    max_change < threshold
}

/// Calculate fitness improvement rate.
#[must_use]
pub fn fitness_improvement_rate(current: f64, previous: f64) -> f64 {
    if previous.abs() < f64::EPSILON {
        if current > 0.0 { f64::INFINITY } else { 0.0 }
    } else {
        (current - previous) / previous
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chrom(fitness: f64, evaluations: u32) -> Chromosome {
        Chromosome {
            genes: vec![],
            fitness,
            evaluations,
            lineage: crate::lineage::Lineage::genesis(0),
        }
    }

    #[test]
    fn weighted_fitness_zero_evaluations() {
        let c = chrom(0.5, 0);
        assert_eq!(weighted_fitness(&c), 0.0);
    }

    #[test]
    fn weighted_fitness_increases_with_evaluations() {
        let c1 = chrom(0.5, 1);
        let c2 = chrom(0.5, 10);
        assert!(weighted_fitness(&c2) > weighted_fitness(&c1));
    }

    #[test]
    fn evolutionary_fitness_zero_evaluations() {
        let c = chrom(0.5, 0);
        assert_eq!(evolutionary_fitness(&c, &[]), 0.0);
    }

    #[test]
    fn evolutionary_fitness_no_active_genes() {
        let mut c = chrom(0.5, 1);
        c.genes = vec![("a".into(), "None".into())];
        let f = evolutionary_fitness(&c, &[]);
        assert!(f <= 0.35);
    }

    #[test]
    fn confidence_weighted_average_empty() {
        assert_eq!(confidence_weighted_average_fitness(&[]), 0.0);
    }

    #[test]
    fn confidence_weighted_average_single() {
        let pop = vec![chrom(0.5, 4)];
        assert_eq!(confidence_weighted_average_fitness(&pop), 0.5);
    }

    #[test]
    fn average_evaluated_fitness_empty() {
        assert_eq!(average_evaluated_fitness(&[]), 0.0);
    }

    #[test]
    fn average_evaluated_fitness_ignores_unevaluated() {
        let pop = vec![chrom(0.0, 0), chrom(0.5, 1), chrom(1.0, 1)];
        assert_eq!(average_evaluated_fitness(&pop), 0.75);
    }

    #[test]
    fn has_converged_empty_population() {
        assert!(!has_converged(&[], 0.01));
    }

    #[test]
    fn is_stagnant_short_history() {
        assert!(!is_stagnant(&[0.1, 0.2], 5, 0.01));
    }

    #[test]
    fn is_stagnant_flatline() {
        let hist = vec![0.5, 0.5, 0.5, 0.5, 0.5];
        assert!(is_stagnant(&hist, 3, 0.01));
    }

    #[test]
    fn is_stagnant_improving() {
        let hist = vec![0.1, 0.2, 0.3, 0.4, 0.5];
        assert!(!is_stagnant(&hist, 3, 0.01));
    }

    #[test]
    fn fitness_improvement_rate_from_zero() {
        assert_eq!(fitness_improvement_rate(0.0, 0.0), 0.0);
        assert_eq!(fitness_improvement_rate(0.5, 0.0), f64::INFINITY);
    }

    #[test]
    fn fitness_improvement_rate_normal() {
        assert!((fitness_improvement_rate(0.6, 0.5) - 0.2).abs() < 0.0001);
        assert!((fitness_improvement_rate(0.4, 0.5) - (-0.2)).abs() < 0.0001);
    }
}
