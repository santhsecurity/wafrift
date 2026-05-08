//! Lineage tracking for replayable bypass discovery.

use crate::evolution::Chromosome;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// A single mutation operation log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationOp {
    /// Gene name that was mutated.
    pub gene_name: String,
    /// Previous value.
    pub from: String,
    /// New value.
    pub to: String,
    /// Mutation operator name.
    pub operator: String,
}

/// Lineage of a chromosome: how it was derived from seeds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Lineage {
    /// Original randomly-generated chromosome.
    Genesis {
        /// Generation when created.
        generation: u32,
    },
    /// Created via crossover of two parents.
    Crossover {
        /// Parent A snapshot.
        parent_a: Arc<Chromosome>,
        /// Parent B snapshot.
        parent_b: Arc<Chromosome>,
        /// Strategy used.
        strategy: String,
        /// Generation when created.
        generation: u32,
    },
    /// Created via mutation of a single parent.
    Mutation {
        /// Parent snapshot.
        parent: Arc<Chromosome>,
        /// Log of applied mutation operations.
        log: Vec<MutationOp>,
        /// Generation when created.
        generation: u32,
    },
}

impl Lineage {
    /// Create a genesis lineage.
    #[must_use]
    pub fn genesis(generation: u32) -> Self {
        Self::Genesis { generation }
    }

    /// Create a crossover lineage.
    #[must_use]
    pub fn crossover(
        parent_a: &Chromosome,
        parent_b: &Chromosome,
        strategy: &str,
        generation: u32,
    ) -> Self {
        Self::Crossover {
            parent_a: Arc::new(parent_a.clone()),
            parent_b: Arc::new(parent_b.clone()),
            strategy: strategy.to_string(),
            generation,
        }
    }

    /// Create a mutation lineage.
    #[must_use]
    pub fn mutation(parent: &Chromosome, log: Vec<MutationOp>, generation: u32) -> Self {
        Self::Mutation {
            parent: Arc::new(parent.clone()),
            log,
            generation,
        }
    }

    /// Serialize lineage to a compact string representation.
    #[must_use]
    pub fn to_trace(&self) -> String {
        match self {
            Self::Genesis { generation } => format!("genesis[gen={generation}]"),
            Self::Crossover {
                parent_a,
                parent_b,
                strategy,
                generation,
            } => {
                format!(
                    "crossover[gen={generation},strategy={strategy},a={{{}}},b={{{}}}]",
                    genes_to_string(&parent_a.genes),
                    genes_to_string(&parent_b.genes)
                )
            }
            Self::Mutation {
                parent,
                log,
                generation,
            } => {
                let ops: Vec<String> = log
                    .iter()
                    .map(|op| format!("{}:{}->{}[{}]", op.gene_name, op.from, op.to, op.operator))
                    .collect();
                format!(
                    "mutation[gen={generation},parent={{{}}},ops=[{}]]",
                    genes_to_string(&parent.genes),
                    ops.join(",")
                )
            }
        }
    }
}

fn genes_to_string(genes: &[(String, String)]) -> String {
    genes
        .iter()
        .map(|(n, v)| format!("{n}={v}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// Serialize a bypass corpus including full lineage trees.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassEntry {
    /// Payload hash (SHA-256 hex of serialized genes).
    pub payload_hash: String,
    /// Genes that produced the bypass.
    pub genes: Vec<(String, String)>,
    /// Full lineage trace.
    pub lineage_trace: String,
    /// Final fitness score.
    pub fitness: f64,
    /// Number of evaluations.
    pub evaluations: u32,
    /// Target WAF identifier (optional).
    pub target_waf: Option<String>,
    /// Whether this bypass was verified.
    pub verified: bool,
    /// Schema version for forward/backward compatibility.
    pub schema_version: u32,
}

impl BypassEntry {
    pub const CURRENT_SCHEMA: u32 = 1;

    #[must_use]
    pub fn from_chromosome(chromosome: &Chromosome, target_waf: Option<String>) -> Self {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        chromosome.genes.hash(&mut hasher);
        let hash = hasher.finish();

        Self {
            payload_hash: format!("{:016x}", hash),
            genes: chromosome.genes.clone(),
            lineage_trace: chromosome.lineage.to_trace(),
            fitness: chromosome.fitness,
            evaluations: chromosome.evaluations,
            target_waf,
            verified: true,
            schema_version: Self::CURRENT_SCHEMA,
        }
    }
}

/// A serializable bypass corpus.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BypassCorpus {
    pub entries: Vec<BypassEntry>,
    pub schema_version: u32,
}

impl BypassCorpus {
    pub const CURRENT_SCHEMA: u32 = 1;

    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            schema_version: Self::CURRENT_SCHEMA,
        }
    }

    /// Add a bypass entry.
    pub fn add(&mut self, entry: BypassEntry) {
        // Deduplicate by payload hash
        if !self
            .entries
            .iter()
            .any(|e| e.payload_hash == entry.payload_hash)
        {
            self.entries.push(entry);
        }
    }

    /// Save corpus to disk as JSONL (one JSON object per line).
    pub fn save(&self, path: &std::path::Path) -> Result<(), crate::types::EvolutionError> {
        use crate::types::EvolutionError;
        let mut lines = Vec::new();
        for entry in &self.entries {
            let json = serde_json::to_string(entry)
                .map_err(|e| EvolutionError::SerializationFailed(e.to_string()))?;
            lines.push(json);
        }
        std::fs::write(path, lines.join("\n"))
            .map_err(|e| EvolutionError::SerializationFailed(e.to_string()))?;
        Ok(())
    }

    /// Load corpus from JSONL.
    pub fn load(path: &std::path::Path) -> Result<Self, crate::types::EvolutionError> {
        use crate::types::EvolutionError;
        let content = std::fs::read_to_string(path)
            .map_err(|e| EvolutionError::DeserializationFailed(e.to_string()))?;
        let mut entries = Vec::new();
        for line in content.lines().filter(|l| !l.trim().is_empty()) {
            let entry: BypassEntry = serde_json::from_str(line)
                .map_err(|e| EvolutionError::DeserializationFailed(e.to_string()))?;
            entries.push(entry);
        }
        Ok(Self {
            entries,
            schema_version: Self::CURRENT_SCHEMA,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evolution::Chromosome;

    #[test]
    fn bypass_entry_deduplicates() {
        let mut corpus = BypassCorpus::new();
        let chrom = Chromosome::new(vec![("encoding".into(), "UrlEncode".into())]);
        let entry = BypassEntry::from_chromosome(&chrom, None);
        corpus.add(entry.clone());
        corpus.add(entry);
        assert_eq!(corpus.entries.len(), 1);
    }

    #[test]
    fn lineage_trace_roundtrips() {
        let chrom = Chromosome::new(vec![("a".into(), "1".into())]);
        let lineage = Lineage::genesis(0);
        assert!(lineage.to_trace().contains("genesis"));

        let cross = Lineage::crossover(&chrom, &chrom, "uniform", 1);
        assert!(cross.to_trace().contains("crossover"));

        let mutation = Lineage::mutation(&chrom, vec![], 2);
        assert!(mutation.to_trace().contains("mutation"));
    }
}
