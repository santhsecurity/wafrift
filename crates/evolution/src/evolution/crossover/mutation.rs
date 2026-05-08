use crate::evolution::{Chromosome, GenePool};
use crate::lineage::MutationOp;
use rand::Rng;

/// Mutate a chromosome and return a log of applied mutations.
pub fn mutate_with_log(
    chromosome: &mut Chromosome,
    gene_pool: &GenePool,
    mutation_rate: f64,
    rng: &mut impl Rng,
) -> Vec<MutationOp> {
    let mut log = Vec::new();
    for gene in &mut chromosome.genes {
        if rng.gen_bool(mutation_rate)
            && let Some(value) = gene_pool.random_value(&gene.0, rng)
            && value != gene.1
        {
            log.push(MutationOp {
                gene_name: gene.0.clone(),
                from: std::mem::replace(&mut gene.1, value.clone()),
                to: value,
                operator: "value_mutation".into(),
            });
        }
    }
    log
}

/// Basic mutation: randomly changes gene values.
pub fn mutate(
    chromosome: &mut Chromosome,
    gene_pool: &GenePool,
    mutation_rate: f64,
    rng: &mut impl Rng,
) {
    let _ = mutate_with_log(chromosome, gene_pool, mutation_rate, rng);
}

/// Structural mutation: add new genes from the gene pool.
pub fn structural_add_mutation(
    chromosome: &mut Chromosome,
    gene_pool: &GenePool,
    add_rate: f64,
    rng: &mut impl Rng,
) {
    let pool_names: Vec<&str> = gene_pool.gene_names();
    let missing_names: Vec<&str> = pool_names
        .into_iter()
        .filter(|name| !chromosome.has_gene(name))
        .collect();

    if !missing_names.is_empty() && rng.gen_bool(add_rate) {
        let name = missing_names[rng.gen_range(0..missing_names.len())];
        if let Some(value) = gene_pool.random_value(name, rng) {
            chromosome.genes.push((name.to_string(), value));
        }
    }
}

/// Essential gene names that should not be removed.
pub const ESSENTIAL_GENES: &[&str] = &["encoding"];

/// Structural mutation: remove genes from the chromosome.
pub fn structural_remove_mutation(
    chromosome: &mut Chromosome,
    remove_rate: f64,
    min_genes: usize,
    rng: &mut impl Rng,
) {
    if chromosome.genes.len() > min_genes && rng.gen_bool(remove_rate) {
        let removable: Vec<usize> = chromosome
            .genes
            .iter()
            .enumerate()
            .filter(|(_, (name, _))| !ESSENTIAL_GENES.contains(&name.as_str()))
            .map(|(i, _)| i)
            .collect();

        if !removable.is_empty() {
            let idx = removable[rng.gen_range(0..removable.len())];
            chromosome.genes.remove(idx);
        }
    }
}

/// Swap mutation: exchanges values between two genes.
pub fn swap_mutation(chromosome: &mut Chromosome, swap_rate: f64, rng: &mut impl Rng) {
    if chromosome.genes.len() < 2 || !rng.gen_bool(swap_rate) {
        return;
    }
    let idx_a = rng.gen_range(0..chromosome.genes.len());
    let idx_b = rng.gen_range(0..chromosome.genes.len());
    if idx_a != idx_b {
        chromosome.genes.swap(idx_a, idx_b);
    }
}

/// Scramble mutation: randomly shuffles a subset of genes.
pub fn scramble_mutation(chromosome: &mut Chromosome, scramble_rate: f64, rng: &mut impl Rng) {
    if chromosome.genes.len() < 3 || !rng.gen_bool(scramble_rate) {
        return;
    }
    let start = rng.gen_range(0..chromosome.genes.len() - 1);
    let end = rng.gen_range(start + 1..chromosome.genes.len());
    for i in (start + 1..end).rev() {
        let j = rng.gen_range(start..=i);
        chromosome.genes.swap(i, j);
    }
}

/// Complete mutation operator applying all mutation types.
pub fn comprehensive_mutate(
    chromosome: &mut Chromosome,
    gene_pool: &GenePool,
    value_mutation_rate: f64,
    structural_add_rate: f64,
    structural_remove_rate: f64,
    min_genes: usize,
    rng: &mut impl Rng,
) -> Vec<MutationOp> {
    let log = mutate_with_log(chromosome, gene_pool, value_mutation_rate, rng);
    structural_add_mutation(chromosome, gene_pool, structural_add_rate, rng);
    structural_remove_mutation(chromosome, structural_remove_rate, min_genes, rng);
    swap_mutation(chromosome, 0.1, rng);
    scramble_mutation(chromosome, 0.05, rng);
    log
}
