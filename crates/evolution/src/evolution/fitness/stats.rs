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
                if *attempts == 0 {
                    0.0
                } else {
                    f64::from(*successes) / f64::from(*attempts)
                },
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
        .map(|(pair, (success, total))| {
            let rate = if total == 0 { 0.0 } else { f64::from(success) / f64::from(total) };
            (pair.0, pair.1, rate)
        })
        .collect();

    results.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chrom(fitness: f64, evaluations: u32, genes: Vec<(String, String)>) -> Chromosome {
        Chromosome {
            genes,
            fitness,
            evaluations,
            lineage: crate::lineage::Lineage::genesis(0),
        }
    }

    #[test]
    fn update_gene_stats_tracks_attempts() {
        let mut stats = Vec::new();
        update_gene_stats(&mut stats, &[("a".into(), "1".into())], true);
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0], ("a".into(), "1".into(), 1, 1));
        update_gene_stats(&mut stats, &[("a".into(), "1".into())], false);
        assert_eq!(stats[0], ("a".into(), "1".into(), 1, 2));
    }

    #[test]
    fn update_gene_stats_skips_none() {
        let mut stats = Vec::new();
        update_gene_stats(&mut stats, &[("a".into(), "None".into())], true);
        assert!(stats.is_empty());
    }

    #[test]
    fn update_gene_stats_multiple_genes() {
        let mut stats = Vec::new();
        update_gene_stats(
            &mut stats,
            &[("a".into(), "1".into()), ("b".into(), "2".into())],
            true,
        );
        assert_eq!(stats.len(), 2);
    }

    #[test]
    fn gene_success_rates_filters_threshold() {
        let stats = vec![
            ("a".into(), "1".into(), 1, 1),
            ("b".into(), "2".into(), 5, 10),
        ];
        let rates = gene_success_rates(&stats);
        // min_attempts = 2, so only b qualifies
        assert_eq!(rates.len(), 1);
        assert_eq!(rates[0].0, "b");
        assert!((rates[0].2 - 0.5).abs() < 0.01);
    }

    #[test]
    fn gene_success_rates_sorted_descending() {
        let stats = vec![
            ("a".into(), "1".into(), 1, 10),
            ("b".into(), "2".into(), 9, 10),
        ];
        let rates = gene_success_rates_with_threshold(&stats, 0);
        assert_eq!(rates[0].0, "b");
        assert_eq!(rates[1].0, "a");
    }

    #[test]
    fn gene_cooccurrence_empty_population() {
        let result = gene_cooccurrence_stats(&[], 1);
        assert!(result.is_empty());
    }

    #[test]
    fn gene_cooccurrence_finds_pairs() {
        let pop = vec![
            chrom(0.8, 1, vec![
                ("a".into(), "1".into()),
                ("b".into(), "2".into()),
            ]),
            chrom(0.9, 1, vec![
                ("a".into(), "1".into()),
                ("b".into(), "2".into()),
            ]),
        ];
        let result = gene_cooccurrence_stats(&pop, 1);
        assert_eq!(result.len(), 1);
        assert!((result[0].2 - 1.0).abs() < 0.01); // both fitness > 0.5
    }

    #[test]
    fn gene_cooccurrence_respects_min_cooccurrence() {
        let pop = vec![
            chrom(0.8, 1, vec![
                ("a".into(), "1".into()),
                ("b".into(), "2".into()),
            ]),
        ];
        let result = gene_cooccurrence_stats(&pop, 2);
        assert!(result.is_empty());
    }
}
