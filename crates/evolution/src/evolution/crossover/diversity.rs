use crate::evolution::Chromosome;
use crate::evolution::GenePool;
use crate::evolution::population::random_chromosome;
use rand::Rng;

/// Inject diversity by replacing low-fitness chromosomes.
pub fn inject_diversity(
    population: &mut [Chromosome],
    gene_pool: &GenePool,
    diversity_rate: f64,
    rng: &mut impl Rng,
) {
    if population.is_empty() {
        return;
    }
    let replace_count = ((population.len() as f64 * diversity_rate) as usize)
        .max(1)
        .min(population.len());
    let mut ranked_indices: Vec<usize> = (0..population.len()).collect();
    ranked_indices.sort_by(|left, right| {
        population[*left]
            .fitness
            .partial_cmp(&population[*right].fitness)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    for index in ranked_indices.into_iter().take(replace_count) {
        population[index] = random_chromosome(gene_pool, rng);
    }
}

/// Calculate population diversity score.
#[must_use]
pub fn diversity_score(population: &[Chromosome]) -> f64 {
    if population.len() < 2 {
        return 1.0;
    }
    let mut total_distance = 0_u64;
    let mut pair_count = 0_u64;
    for (index, chromosome) in population.iter().enumerate() {
        for other in &population[(index + 1)..] {
            let scaled_distance = (chromosome_distance(chromosome, other) * 1000.0).round() as u64;
            total_distance += scaled_distance;
            pair_count += 1;
        }
    }
    if pair_count == 0 {
        1.0
    } else {
        total_distance as f64 / (pair_count as f64 * 1000.0)
    }
}

/// Calculate gene-level diversity: diversity per gene type.
#[must_use]
pub fn gene_diversity_scores(population: &[Chromosome]) -> Vec<(String, f64)> {
    if population.len() < 2 {
        return Vec::new();
    }
    let gene_names: Vec<String> = population[0]
        .genes
        .iter()
        .map(|(name, _)| name.clone())
        .collect();
    let mut scores: Vec<(String, f64)> = Vec::new();
    let pair_count = (population.len() * (population.len() - 1)) / 2;
    for name in gene_names {
        let mut different_count = 0;
        for (i, chrom_a) in population.iter().enumerate() {
            for chrom_b in &population[(i + 1)..] {
                let val_a = chrom_a.gene(&name);
                let val_b = chrom_b.gene(&name);
                if val_a != val_b {
                    different_count += 1;
                }
            }
        }
        let score = f64::from(different_count) / pair_count as f64;
        scores.push((name, score));
    }
    scores
}

fn chromosome_distance(left: &Chromosome, right: &Chromosome) -> f64 {
    let mut names: Vec<&str> = left.genes.iter().map(|(name, _)| name.as_str()).collect();
    for (name, _) in &right.genes {
        if !names.contains(&name.as_str()) {
            names.push(name);
        }
    }
    if names.is_empty() {
        return 0.0;
    }
    let different = names
        .iter()
        .filter(|name| left.gene(name) != right.gene(name))
        .count();
    different as f64 / names.len() as f64
}

/// Adaptive mutation rate based on population stagnation.
#[must_use]
pub fn adaptive_mutation_rate(
    base_rate: f64,
    stagnation_counter: u32,
    diversity_score: f64,
) -> f64 {
    let stagnation_factor = 1.0 + (f64::from(stagnation_counter) * 0.2);
    let diversity_factor = 1.0 - (diversity_score * 0.3);
    let rate = base_rate * stagnation_factor * diversity_factor;
    rate.clamp(0.01, 0.5)
}

/// Bias injection: injects successful gene values into a chromosome.
pub fn bias_inject(
    chromosome: &mut Chromosome,
    top_genes: &[(&str, &str, f64)],
    rng: &mut impl Rng,
) {
    for (name, value, rate) in top_genes {
        let injection_probability = rate * 0.6;
        if *rate > 0.3
            && rng.gen_bool(injection_probability)
            && let Some(gene) = chromosome
                .genes
                .iter_mut()
                .find(|(gene_name, _)| gene_name == *name)
        {
            gene.1 = (*value).to_string();
        }
    }
}

/// Synergy bias injection: injects gene pairs that work well together.
pub type SynergyPair = ((String, String), (String, String), f64);

pub fn synergy_bias_inject(
    chromosome: &mut Chromosome,
    gene_pairs: &[SynergyPair],
    rng: &mut impl Rng,
) {
    for ((name1, value1), (name2, value2), success_rate) in gene_pairs {
        if *success_rate > 0.7 && rng.gen_bool(0.4) {
            if let Some(gene1) = chromosome.genes.iter_mut().find(|(n, _)| n == name1) {
                gene1.1 = value1.clone();
            }
            if let Some(gene2) = chromosome.genes.iter_mut().find(|(n, _)| n == name2) {
                gene2.1 = value2.clone();
            }
        }
    }
}
