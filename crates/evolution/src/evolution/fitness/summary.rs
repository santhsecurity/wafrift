use crate::evolution::Chromosome;
use crate::evolution::fitness::stats::GeneStatRecord;

/// Calculate population fitness statistics.
#[derive(Debug, Clone, Copy)]
pub struct FitnessStats {
    pub min: f64,
    pub max: f64,
    pub mean: f64,
    pub median: f64,
    pub std_dev: f64,
}

/// Calculate comprehensive fitness statistics for the population.
#[must_use]
pub fn fitness_statistics(population: &[Chromosome]) -> FitnessStats {
    let evaluated: Vec<f64> = population
        .iter()
        .filter(|c| c.evaluations > 0)
        .map(|c| c.fitness)
        .collect();

    if evaluated.is_empty() {
        return FitnessStats {
            min: 0.0,
            max: 0.0,
            mean: 0.0,
            median: 0.0,
            std_dev: 0.0,
        };
    }

    let min = *evaluated
        .iter()
        .min_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
        .unwrap_or(&0.0);
    let max = *evaluated
        .iter()
        .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
        .unwrap_or(&0.0);
    let mean = evaluated.iter().sum::<f64>() / evaluated.len() as f64;

    let mut sorted = evaluated.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let median = if sorted.len().is_multiple_of(2) {
        f64::midpoint(sorted[sorted.len() / 2 - 1], sorted[sorted.len() / 2])
    } else {
        sorted[sorted.len() / 2]
    };

    let variance: f64 =
        evaluated.iter().map(|f| (f - mean).powi(2)).sum::<f64>() / evaluated.len() as f64;
    let std_dev = variance.sqrt();

    FitnessStats {
        min,
        max,
        mean,
        median,
        std_dev,
    }
}

/// Find the best chromosome in the population.
#[must_use]
pub fn best(population: &[Chromosome]) -> Option<&Chromosome> {
    population
        .iter()
        .filter(|chromosome| chromosome.evaluations > 0)
        .max_by(|left, right| {
            left.fitness
                .partial_cmp(&right.fitness)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
}

/// Find the worst chromosome in the population.
#[must_use]
pub fn worst(population: &[Chromosome]) -> Option<&Chromosome> {
    population
        .iter()
        .filter(|chromosome| chromosome.evaluations > 0)
        .min_by(|left, right| {
            left.fitness
                .partial_cmp(&right.fitness)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
}

/// Rank chromosomes by fitness (best first).
#[must_use]
pub fn rank_by_fitness(population: &[Chromosome]) -> Vec<(usize, f64)> {
    let mut ranked: Vec<(usize, f64)> = population
        .iter()
        .enumerate()
        .filter(|(_, c)| c.evaluations > 0)
        .map(|(i, c)| (i, c.fitness))
        .collect();
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    ranked
}

/// Calculate the fitness percentile of a specific chromosome.
#[must_use]
pub fn fitness_percentile(population: &[Chromosome], chromosome_index: usize) -> f64 {
    if chromosome_index >= population.len() || population.is_empty() {
        return 0.0;
    }
    let target_fitness = population[chromosome_index].fitness;
    let evaluated: Vec<f64> = population
        .iter()
        .filter(|c| c.evaluations > 0)
        .map(|c| c.fitness)
        .collect();
    if evaluated.is_empty() {
        return 0.0;
    }
    let worse_or_equal = evaluated.iter().filter(|&&f| f <= target_fitness).count();
    (worse_or_equal as f64 / evaluated.len() as f64) * 100.0
}

/// Generate a human-readable summary of what the engine has learned.
#[must_use]
pub fn learned_summary(
    generation: u32,
    best_chrom: Option<&Chromosome>,
    gene_stats: &[GeneStatRecord],
    request_count: usize,
) -> String {
    let mut lines = Vec::new();
    lines.push(format!("Generation: {generation}"));
    lines.push(format!("Requests: {request_count}"));

    if let Some(best) = best_chrom {
        lines.push(format!(
            "Best fitness: {:.2} ({}+ evaluations)",
            best.fitness, best.evaluations
        ));
        lines.push(String::from("Best genes:"));
        for (name, value) in &best.genes {
            if value != "None" {
                lines.push(format!("  {name} = {value}"));
            }
        }
    }

    let top_genes = crate::evolution::fitness::stats::gene_success_rates(gene_stats);
    if !top_genes.is_empty() {
        lines.push(String::from("Top-performing genes:"));
        for (name, value, rate) in top_genes.iter().take(5) {
            lines.push(format!("  {name}/{value}: {:.0}% success", rate * 100.0));
        }
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chrom(fitness: f64, evaluations: u32) -> Chromosome {
        Chromosome {
            genes: vec![
                ("encoding".into(), "UrlEncode".into()),
                ("content_type".into(), "None".into()),
            ],
            fitness,
            evaluations,
            lineage: crate::lineage::Lineage::genesis(0),
        }
    }

    #[test]
    fn fitness_statistics_empty() {
        let s = fitness_statistics(&[]);
        assert_eq!(s.min, 0.0);
        assert_eq!(s.max, 0.0);
        assert_eq!(s.mean, 0.0);
        assert_eq!(s.median, 0.0);
        assert_eq!(s.std_dev, 0.0);
    }

    #[test]
    fn fitness_statistics_basic() {
        let pop = vec![
            chrom(0.1, 1),
            chrom(0.5, 1),
            chrom(0.9, 1),
        ];
        let s = fitness_statistics(&pop);
        assert_eq!(s.min, 0.1);
        assert_eq!(s.max, 0.9);
        assert!((s.mean - 0.5).abs() < 0.01);
        assert_eq!(s.median, 0.5);
        assert!(s.std_dev > 0.0);
    }

    #[test]
    fn fitness_statistics_ignores_unevaluated() {
        let pop = vec![chrom(0.0, 0), chrom(0.5, 1)];
        let s = fitness_statistics(&pop);
        assert_eq!(s.min, 0.5);
        assert_eq!(s.max, 0.5);
    }

    #[test]
    fn best_returns_highest_fitness() {
        let pop = vec![chrom(0.1, 1), chrom(0.9, 1), chrom(0.5, 1)];
        assert_eq!(best(&pop).unwrap().fitness, 0.9);
    }

    #[test]
    fn worst_returns_lowest_fitness() {
        let pop = vec![chrom(0.1, 1), chrom(0.9, 1), chrom(0.5, 1)];
        assert_eq!(worst(&pop).unwrap().fitness, 0.1);
    }

    #[test]
    fn rank_by_fitness_best_first() {
        let pop = vec![chrom(0.1, 1), chrom(0.9, 1), chrom(0.5, 1)];
        let ranked = rank_by_fitness(&pop);
        assert_eq!(ranked[0].1, 0.9);
        assert_eq!(ranked[1].1, 0.5);
        assert_eq!(ranked[2].1, 0.1);
    }

    #[test]
    fn fitness_percentile_out_of_range() {
        let pop = vec![chrom(0.5, 1)];
        assert_eq!(fitness_percentile(&pop, 99), 0.0);
    }

    #[test]
    fn fitness_percentile_worst_is_zero() {
        let pop = vec![chrom(0.1, 1), chrom(0.5, 1), chrom(0.9, 1)];
        let idx = pop.iter().position(|c| c.fitness == 0.1).unwrap();
        let p = fitness_percentile(&pop, idx);
        assert!((0.0..=40.0).contains(&p));
    }

    #[test]
    fn learned_summary_includes_generation() {
        let c = chrom(0.8, 5);
        let summary = learned_summary(7, Some(&c), &[], 100);
        assert!(summary.contains("Generation: 7"));
        assert!(summary.contains("Requests: 100"));
        assert!(summary.contains("Best fitness:"));
        assert!(summary.contains("encoding = UrlEncode"));
    }

    #[test]
    fn learned_summary_no_best() {
        let summary = learned_summary(0, None, &[], 0);
        assert!(summary.contains("Generation: 0"));
        assert!(!summary.contains("Best fitness:"));
    }
}
