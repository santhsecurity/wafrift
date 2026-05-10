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

/// Compact, transitive-closure-safe snapshot of a parent chromosome's
/// gene tuple. Stored inside `Lineage::Crossover` / `Lineage::Mutation`
/// instead of `Arc<Chromosome>` so the lineage tree of a long-running
/// scan is bounded by `O(genes per chromosome)` per ancestor instead
/// of `O(full ancestry chain)` — the earlier full-Chromosome arcs
/// transitively dragged the parent's own `Lineage` field along, so
/// every grandchild kept its grandparents alive forever and a long
/// scan would OOM.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParentSnapshot {
    pub genes: Vec<(String, String)>,
}

impl ParentSnapshot {
    fn from_chromosome(c: &Chromosome) -> Self {
        Self {
            genes: c.genes.clone(),
        }
    }
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
        /// Parent A snapshot — genes only, breaks ancestry chain.
        parent_a: Arc<ParentSnapshot>,
        /// Parent B snapshot — genes only, breaks ancestry chain.
        parent_b: Arc<ParentSnapshot>,
        /// Strategy used.
        strategy: String,
        /// Generation when created.
        generation: u32,
    },
    /// Created via mutation of a single parent.
    Mutation {
        /// Parent snapshot — genes only, breaks ancestry chain.
        parent: Arc<ParentSnapshot>,
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
            parent_a: Arc::new(ParentSnapshot::from_chromosome(parent_a)),
            parent_b: Arc::new(ParentSnapshot::from_chromosome(parent_b)),
            strategy: strategy.to_string(),
            generation,
        }
    }

    /// Create a mutation lineage.
    #[must_use]
    pub fn mutation(parent: &Chromosome, log: Vec<MutationOp>, generation: u32) -> Self {
        Self::Mutation {
            parent: Arc::new(ParentSnapshot::from_chromosome(parent)),
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
        // SHA-256 over a deterministic gene encoding. Earlier versions
        // used the 64-bit DefaultHasher, which collides via birthday
        // attack at roughly 2^32 chromosomes — well within reach of a
        // long-running scan, causing BypassCorpus::add to silently
        // dedupe distinct bypass discoveries.
        //
        // Important: gene order is part of the payload identity. Two
        // chromosomes with the same set of genes in different order
        // intentionally produce different hashes.
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        for (k, v) in &chromosome.genes {
            hasher.update(k.as_bytes());
            hasher.update([0u8]); // delimiter so ("ab", "c") != ("a", "bc")
            hasher.update(v.as_bytes());
            hasher.update([0u8]);
        }
        let digest = hasher.finalize();
        let payload_hash = digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();

        Self {
            payload_hash,
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

    /// Maximum corpus file size (bytes). Prevents OOM from
    /// maliciously large JSONL files.
    const MAX_CORPUS_BYTES: usize = 256 * 1024 * 1024;

    /// Maximum individual JSONL line length (bytes).
    const MAX_JSONL_LINE_BYTES: usize = 16 * 1024 * 1024;

    /// Save corpus to disk as JSONL (one JSON object per line).
    pub fn save(&self, path: &std::path::Path) -> Result<(), crate::types::EvolutionError> {
        use crate::types::EvolutionError;
        let mut buf = Vec::new();
        for entry in &self.entries {
            let json = serde_json::to_string(entry).map_err(EvolutionError::SerializationFailed)?;
            if json.len() > Self::MAX_JSONL_LINE_BYTES {
                tracing::warn!(
                    line_len = json.len(),
                    max = Self::MAX_JSONL_LINE_BYTES,
                    "skipping oversized corpus entry"
                );
                continue;
            }
            if !buf.is_empty() {
                buf.push(b'\n');
            }
            buf.extend_from_slice(json.as_bytes());
            if buf.len() > Self::MAX_CORPUS_BYTES {
                return Err(EvolutionError::OversizedData {
                    context: format!("corpus {}", path.display()),
                    size: buf.len(),
                    max: Self::MAX_CORPUS_BYTES,
                });
            }
        }
        std::fs::write(path, buf)?;
        Ok(())
    }

    /// Load corpus from JSONL.
    pub fn load(path: &std::path::Path) -> Result<Self, crate::types::EvolutionError> {
        use crate::types::EvolutionError;
        let meta = std::fs::metadata(path)?;
        let len = meta.len() as usize;
        if len > Self::MAX_CORPUS_BYTES {
            return Err(EvolutionError::OversizedData {
                context: format!("corpus {}", path.display()),
                size: len,
                max: Self::MAX_CORPUS_BYTES,
            });
        }
        let content = std::fs::read_to_string(path)?;
        let mut entries = Vec::new();
        for line in content.lines().filter(|l| !l.trim().is_empty()) {
            if line.len() > Self::MAX_JSONL_LINE_BYTES {
                tracing::warn!(
                    line_len = line.len(),
                    max = Self::MAX_JSONL_LINE_BYTES,
                    "skipping oversized corpus line"
                );
                continue;
            }
            let entry: BypassEntry =
                serde_json::from_str(line).map_err(EvolutionError::DeserializationFailed)?;
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

    #[test]
    fn empty_lineage_trace_is_serializable() {
        let chrom = Chromosome::new(Vec::new());
        let cross = Lineage::crossover(&chrom, &chrom, "single_point", 1);
        let trace = cross.to_trace();
        assert!(trace.contains("crossover"));
        assert!(trace.contains("a={}"));
        assert!(trace.contains("b={}"));
    }

    #[test]
    fn payload_hash_is_order_sensitive() {
        let chrom_a = Chromosome::new(vec![
            ("encoding".into(), "UrlEncode".into()),
            ("content_type".into(), "JsonNested".into()),
        ]);
        let chrom_b = Chromosome::new(vec![
            ("content_type".into(), "JsonNested".into()),
            ("encoding".into(), "UrlEncode".into()),
        ]);
        let a = BypassEntry::from_chromosome(&chrom_a, None);
        let b = BypassEntry::from_chromosome(&chrom_b, None);
        assert_ne!(a.payload_hash, b.payload_hash);
    }
}
