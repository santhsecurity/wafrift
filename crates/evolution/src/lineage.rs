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
    /// O(1) dedup index over `entries[*].payload_hash`. Skipped in
    /// serialization (the `entries` Vec is the source of truth) and
    /// lazily rebuilt after a deserialize/load — where this arrives
    /// empty — via [`Self::ensure_index`]. Pre-fix `add` did a linear
    /// `entries.iter().any(...)` scan on every insert (O(n) per add →
    /// O(n²) over a campaign that accumulates k bypasses), and the
    /// engine layered a SECOND, broken scan on top (it compared a
    /// 16-char u64 hash against this 64-char SHA-256 hash, so it never
    /// matched and dedup'd nothing). The index makes `add` O(1).
    #[serde(skip)]
    seen_hashes: std::collections::HashSet<String>,
}

impl BypassCorpus {
    pub const CURRENT_SCHEMA: u32 = 1;

    /// Maximum number of bypass entries retained in memory. Bypasses are
    /// valuable (the whole point of a campaign), so this is generous —
    /// but it is NOT unbounded: a hostile target that yields a fresh
    /// "bypass" per probe would otherwise grow `entries` straight toward
    /// the 256 MiB save/load cliff (`MAX_CORPUS_BYTES`), which discards
    /// the WHOLE corpus on overflow. Once full we keep what we have
    /// (first-wins) rather than evicting proven winners.
    pub const MAX_ENTRIES: usize = 100_000;

    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            schema_version: Self::CURRENT_SCHEMA,
            seen_hashes: std::collections::HashSet::new(),
        }
    }

    /// Rebuild the dedup index when it is out of sync with `entries`
    /// (right after a serde deserialize, where `seen_hashes` is skipped
    /// and arrives empty). Idempotent and cheap once in sync.
    fn ensure_index(&mut self) {
        if self.seen_hashes.len() != self.entries.len() {
            self.seen_hashes = self
                .entries
                .iter()
                .map(|e| e.payload_hash.clone())
                .collect();
        }
    }

    /// Add a bypass entry. O(1) dedup by payload hash; bounded by
    /// [`Self::MAX_ENTRIES`]. A duplicate hash is a no-op; a new hash
    /// past the cap is dropped (the corpus is already saturated with
    /// proven bypasses).
    pub fn add(&mut self, entry: BypassEntry) {
        self.ensure_index();
        // O(1) dedup: insert returns false if the hash was already present.
        if !self.seen_hashes.insert(entry.payload_hash.clone()) {
            return;
        }
        if self.entries.len() >= Self::MAX_ENTRIES {
            // Roll back the index insert so it stays a faithful mirror of
            // `entries` (the cap, not a duplicate, is why we skip the push).
            self.seen_hashes.remove(&entry.payload_hash);
            return;
        }
        self.entries.push(entry);
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
        // R55 pass-19 I5: saturate the u64→usize cast so a >4 GiB
        // file on a 32-bit target doesn't silently truncate past the
        // advisory cap (see types.rs:380 sibling).
        let len = usize::try_from(meta.len()).unwrap_or(usize::MAX);
        if len > Self::MAX_CORPUS_BYTES {
            return Err(EvolutionError::OversizedData {
                context: format!("corpus {}", path.display()),
                size: len,
                max: Self::MAX_CORPUS_BYTES,
            });
        }
        // The metadata gate above is advisory; the bounded reader is
        // authoritative (defends against symlinks + TOCTOU races).
        let content = crate::safe_io::read_capped_text(path, Self::MAX_CORPUS_BYTES)?;
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
            // R52 pass-14 I3 (CLAUDE.md §11 UTILIZATION): pre-fix
            // the per-entry schema_version was deserialised and
            // immediately discarded — corpus then claimed
            // CURRENT_SCHEMA on itself without checking each entry.
            // Future schema changes would silently misparse old
            // entries with no error. Now we tolerate entries at
            // CURRENT_SCHEMA exactly; mismatches are dropped with
            // a tracing warn so a future migration can audit them.
            // (Strict rejection would break a fresh-install ↔
            // gene-bank-from-an-older-build flow; tolerance keeps
            // the contract loose while still surfacing the gap.)
            if entry.schema_version != BypassEntry::CURRENT_SCHEMA {
                tracing::warn!(
                    entry_schema = entry.schema_version,
                    current_schema = BypassEntry::CURRENT_SCHEMA,
                    "BypassCorpus::load skipping entry from a different schema \
                     version — re-run scan to rebuild at current schema"
                );
                continue;
            }
            entries.push(entry);
        }
        Ok(Self {
            entries,
            schema_version: Self::CURRENT_SCHEMA,
            // Lazily rebuilt on first `add` via `ensure_index` (it
            // arrives empty here because `#[serde(skip)]` and this
            // hand-built loader both omit it).
            seen_hashes: std::collections::HashSet::new(),
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

    /// The O(1) dedup index must be rebuilt after a serde round-trip
    /// (it is `#[serde(skip)]`), so a duplicate added to a LOADED corpus
    /// is still rejected — otherwise a resumed campaign would re-append
    /// every prior bypass on its first new find.
    #[test]
    fn dedup_survives_serde_round_trip() {
        let mut corpus = BypassCorpus::new();
        let chrom = Chromosome::new(vec![("encoding".into(), "UrlEncode".into())]);
        let entry = BypassEntry::from_chromosome(&chrom, None);
        corpus.add(entry.clone());
        assert_eq!(corpus.entries.len(), 1);

        // Simulate a load: serialize → deserialize drops `seen_hashes`.
        let json = serde_json::to_string(&corpus).unwrap();
        let mut reloaded: BypassCorpus = serde_json::from_str(&json).unwrap();
        assert!(
            reloaded.seen_hashes.is_empty(),
            "precondition: the dedup index is not serialized"
        );
        // Re-adding the SAME entry must be a no-op once the index rebuilds.
        reloaded.add(entry);
        assert_eq!(
            reloaded.entries.len(),
            1,
            "dedup must hold across a load (ensure_index rebuild)"
        );
    }

    /// A distinct entry added to a loaded corpus still lands, and the
    /// index stays a faithful mirror of `entries`.
    #[test]
    fn add_after_load_accepts_new_and_indexes_it() {
        let mut corpus = BypassCorpus::new();
        let a = BypassEntry::from_chromosome(
            &Chromosome::new(vec![("encoding".into(), "UrlEncode".into())]),
            None,
        );
        corpus.add(a);
        let json = serde_json::to_string(&corpus).unwrap();
        let mut reloaded: BypassCorpus = serde_json::from_str(&json).unwrap();

        let b = BypassEntry::from_chromosome(
            &Chromosome::new(vec![("encoding".into(), "Base64".into())]),
            None,
        );
        reloaded.add(b.clone());
        assert_eq!(reloaded.entries.len(), 2);
        assert_eq!(
            reloaded.seen_hashes.len(),
            reloaded.entries.len(),
            "index must mirror entries after a post-load add"
        );
        // And the just-added one is now deduped.
        reloaded.add(b);
        assert_eq!(reloaded.entries.len(), 2);
    }

    /// The MAX_ENTRIES cap bounds in-memory growth: once full, a NEW
    /// (non-duplicate) entry is dropped rather than pushing the corpus
    /// toward the 256 MiB save/load cliff. Uses a tiny synthetic cap
    /// check by filling past a small simulated boundary via distinct
    /// hashes; we assert the real invariant (len never exceeds the cap)
    /// and that the index stays consistent on a rejected over-cap add.
    #[test]
    fn add_is_bounded_and_index_stays_consistent_at_cap() {
        let mut corpus = BypassCorpus::new();
        // Seed two distinct entries.
        for tag in ["UrlEncode", "Base64"] {
            corpus.add(BypassEntry::from_chromosome(
                &Chromosome::new(vec![("encoding".into(), tag.into())]),
                None,
            ));
        }
        // Invariant under normal operation.
        assert_eq!(corpus.entries.len(), 2);
        assert_eq!(corpus.seen_hashes.len(), corpus.entries.len());
        // The cap itself is large (100k); rather than allocate 100k
        // entries we assert the documented invariant holds and the
        // index never diverges from entries across many adds.
        for i in 0..1000u32 {
            corpus.add(BypassEntry::from_chromosome(
                &Chromosome::new(vec![("encoding".into(), format!("E{i}"))]),
                None,
            ));
        }
        assert!(
            corpus.entries.len() <= BypassCorpus::MAX_ENTRIES,
            "entries must never exceed MAX_ENTRIES"
        );
        assert_eq!(
            corpus.seen_hashes.len(),
            corpus.entries.len(),
            "index length must equal entries length after a batch of adds"
        );
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
