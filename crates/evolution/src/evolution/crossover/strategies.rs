use crate::evolution::Chromosome;
use rand::Rng;

/// Crossover strategy for breeding chromosomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossoverStrategy {
    Uniform,
    SinglePoint,
    MultiPoint(usize),
    OrderBased,
}

fn canonical_gene_names(parent_a: &Chromosome, parent_b: &Chromosome) -> Vec<String> {
    let mut names = Vec::new();
    for (name, _) in &parent_a.genes {
        if !names.contains(name) {
            names.push(name.clone());
        }
    }
    for (name, _) in &parent_b.genes {
        if !names.contains(name) {
            names.push(name.clone());
        }
    }
    names
}

fn gene_value_for(parent: &Chromosome, name: &str) -> Option<String> {
    parent
        .genes
        .iter()
        .find(|(gene_name, _)| gene_name == name)
        .map(|(_, value)| value.clone())
}

fn value_from_parent(primary: &Chromosome, secondary: &Chromosome, name: &str) -> String {
    gene_value_for(primary, name)
        .or_else(|| gene_value_for(secondary, name))
        .unwrap_or_else(|| String::from("None"))
}

fn build_child<F>(parent_a: &Chromosome, parent_b: &Chromosome, mut choose_a: F) -> Chromosome
where
    F: FnMut(usize, &str) -> bool,
{
    let child_genes = canonical_gene_names(parent_a, parent_b)
        .into_iter()
        .enumerate()
        .map(|(index, name)| {
            let value = if choose_a(index, &name) {
                value_from_parent(parent_a, parent_b, &name)
            } else {
                value_from_parent(parent_b, parent_a, &name)
            };
            (name, value)
        })
        .collect();
    Chromosome::new(child_genes)
}

/// Uniform crossover: each gene independently from either parent.
#[must_use]
pub fn uniform_crossover(
    parent_a: &Chromosome,
    parent_b: &Chromosome,
    rng: &mut impl Rng,
) -> Chromosome {
    build_child(parent_a, parent_b, |_, _| rng.gen_bool(0.5))
}

/// Single-point crossover: split genes at one point and swap tails.
#[must_use]
pub fn single_point_crossover(
    parent_a: &Chromosome,
    parent_b: &Chromosome,
    rng: &mut impl Rng,
) -> Chromosome {
    let gene_names = canonical_gene_names(parent_a, parent_b);
    let max_len = gene_names.len();
    if max_len == 0 {
        return Chromosome::new(Vec::new());
    }
    let point = rng.gen_range(1..=max_len);
    build_child(parent_a, parent_b, |index, _| index < point)
}

/// Multi-point crossover: split at multiple points.
#[must_use]
pub fn multi_point_crossover(
    parent_a: &Chromosome,
    parent_b: &Chromosome,
    num_points: usize,
    rng: &mut impl Rng,
) -> Chromosome {
    let gene_names = canonical_gene_names(parent_a, parent_b);
    let max_len = gene_names.len();
    if max_len == 0 {
        return Chromosome::new(Vec::new());
    }
    // gen_range(1..max_len) panics on empty range when max_len == 1
    // (single distinct gene shared between both parents). Single-gene
    // parents have no meaningful split point — fall back to a clone of
    // parent_a, same shape as max_len == 0.
    if max_len == 1 {
        return build_child(parent_a, parent_b, |_, _| true);
    }
    let mut points: Vec<usize> = (0..num_points.min(max_len))
        .map(|_| rng.gen_range(1..max_len))
        .collect();
    points.sort_unstable();
    points.dedup();
    build_child(parent_a, parent_b, |index, _| {
        points.iter().filter(|point| index >= **point).count() % 2 == 0
    })
}

/// Order-based crossover: preserves relative ordering of genes.
#[must_use]
pub fn order_based_crossover(
    parent_a: &Chromosome,
    parent_b: &Chromosome,
    rng: &mut impl Rng,
) -> Chromosome {
    build_child(parent_a, parent_b, |_, name| {
        let prefer_a = parent_a
            .genes
            .iter()
            .position(|(gene_name, _)| gene_name == name)
            .unwrap_or(usize::MAX);
        let prefer_b = parent_b
            .genes
            .iter()
            .position(|(gene_name, _)| gene_name == name)
            .unwrap_or(usize::MAX);
        if prefer_a == prefer_b {
            rng.gen_bool(0.5)
        } else {
            prefer_a < prefer_b
        }
    })
}

/// Perform crossover using a specified strategy.
#[must_use]
pub fn crossover_with_strategy(
    parent_a: &Chromosome,
    parent_b: &Chromosome,
    strategy: CrossoverStrategy,
    rng: &mut impl Rng,
) -> Chromosome {
    match strategy {
        CrossoverStrategy::Uniform => uniform_crossover(parent_a, parent_b, rng),
        CrossoverStrategy::SinglePoint => single_point_crossover(parent_a, parent_b, rng),
        CrossoverStrategy::MultiPoint(points) => {
            multi_point_crossover(parent_a, parent_b, points, rng)
        }
        CrossoverStrategy::OrderBased => order_based_crossover(parent_a, parent_b, rng),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn empty_chromosome_crossover_returns_empty() {
        let parent_a = Chromosome::new(Vec::new());
        let parent_b = Chromosome::new(Vec::new());
        let mut rng = StdRng::seed_from_u64(13);
        let child = single_point_crossover(&parent_a, &parent_b, &mut rng);
        assert!(child.genes.is_empty());
    }

    #[test]
    fn single_gene_single_point_crossover_returns_valid_clone_shape() {
        let parent_a = Chromosome::new(vec![("encoding".into(), "UrlEncode".into())]);
        let parent_b = Chromosome::new(vec![("encoding".into(), "None".into())]);
        let mut rng = StdRng::seed_from_u64(17);
        let child = single_point_crossover(&parent_a, &parent_b, &mut rng);
        assert_eq!(child.genes.len(), 1);
        assert_eq!(child.genes[0].0, "encoding");
    }

    #[test]
    fn crossover_with_identical_parents_matches_parent() {
        let parent_a = Chromosome::new(vec![
            ("encoding".into(), "UrlEncode".into()),
            ("content_type".into(), "JsonNested".into()),
        ]);
        let parent_b = parent_a.clone();
        let mut rng = StdRng::seed_from_u64(19);
        let child = uniform_crossover(&parent_a, &parent_b, &mut rng);
        assert_eq!(child.genes, parent_a.genes);
        assert_eq!(child.genes, parent_b.genes);
    }
}
