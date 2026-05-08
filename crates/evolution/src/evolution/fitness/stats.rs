use crate::evolution::Chromosome;

pub type GeneStatRecord = (String, String, u32, u32);
pub type GenePair = ((String, String), (String, String));
pub type GenePairStat = ((String, String), (String, String), f64);

/// Update gene statistics with a new evaluation result.
pub fn update_gene_stats(
    gene_stats: &mut Vec<GeneStatRecord>,
    genes: &[(String, String)],
    passed: bool,
) {
    for (name, value) in genes {
        if value == "None" {
            continue;
        }
        if let Some(stat) = gene_stats
            .iter_mut()
            .find(|(stat_name, stat_value, _, _)| stat_name == name && stat_value == value)
        {
            if passed {
                stat.2 += 1;
            }
            stat.3 += 1;
        } else {
            gene_stats.push((name.clone(), value.clone(), u32::from(passed), 1));
        }
    }

    // Prune to top 500 most-attempted entries to prevent unbounded growth
    if gene_stats.len() > 500 {
        gene_stats.sort_by_key(|a| std::cmp::Reverse(a.3));
        gene_stats.truncate(500);
    }
}

/// Calculate success rates for all tracked genes.
#[must_use]
pub fn gene_success_rates(gene_stats: &[GeneStatRecord]) -> Vec<(&str, &str, f64)> {
    gene_success_rates_with_threshold(gene_stats, 2)
}

/// Calculate success rates with configurable minimum attempts.
#[must_use]
pub fn gene_success_rates_with_threshold(
    gene_stats: &[GeneStatRecord],
    min_attempts: u32,
) -> Vec<(&str, &str, f64)> {
    let mut rates: Vec<(&str, &str, f64)> = gene_stats
        .iter()
        .filter(|(_, _, _, attempts)| *attempts >= min_attempts)
        .map(|(name, value, successes, attempts)| {
            (
                name.as_str(),
                value.as_str(),
                f64::from(*successes) / f64::from(*attempts),
            )
        })
        .collect();
    rates.sort_by(|left, right| {
        right
            .2
            .partial_cmp(&left.2)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    rates
}

/// Calculate co-occurrence statistics for gene pairs.
#[must_use]
pub fn gene_cooccurrence_stats(
    population: &[Chromosome],
    min_cooccurrence: usize,
) -> Vec<GenePairStat> {
    use std::collections::HashMap;

    let mut pair_counts: HashMap<GenePair, (u32, u32)> = HashMap::new();

    for chromosome in population {
        if chromosome.evaluations == 0 {
            continue;
        }
        let active_genes: Vec<_> = chromosome
            .genes
            .iter()
            .filter(|(_, v)| v != "None")
            .cloned()
            .collect();

        for (i, gene_a) in active_genes.iter().enumerate() {
            for gene_b in &active_genes[(i + 1)..] {
                let pair = if gene_a.0 < gene_b.0 {
                    (gene_a.clone(), gene_b.clone())
                } else {
                    (gene_b.clone(), gene_a.clone())
                };

                let entry = pair_counts.entry(pair).or_insert((0, 0));
                entry.1 += 1;
                if chromosome.fitness > 0.5 {
                    entry.0 += 1;
                }
            }
        }
    }

    let mut results: Vec<GenePairStat> = pair_counts
        .into_iter()
        .filter(|(_, (_, total))| *total as usize >= min_cooccurrence)
        .map(|(pair, (success, total))| (pair.0, pair.1, f64::from(success) / f64::from(total)))
        .collect();

    results.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
    results
}
