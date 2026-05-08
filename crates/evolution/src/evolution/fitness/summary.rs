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
