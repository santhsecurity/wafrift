use crate::lineage::Lineage;
use rand::Rng;
use serde::{Deserialize, Serialize};

/// A chromosome representing a combination of evasion techniques.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Chromosome {
    /// Named technique genes: `(gene_name, gene_value)`.
    pub genes: Vec<(String, String)>,
    /// Fitness score (0.0 = always blocked, 1.0 = always passes).
    pub fitness: f64,
    /// Number of times this chromosome has been evaluated.
    pub evaluations: u32,
    /// Full lineage tree for replayability.
    #[serde(default = "default_lineage")]
    pub lineage: Lineage,
}

fn default_lineage() -> Lineage {
    Lineage::genesis(0)
}

impl Chromosome {
    /// Create a new chromosome with zero fitness and genesis lineage.
    #[must_use]
    pub fn new(genes: Vec<(String, String)>) -> Self {
        Self {
            genes,
            fitness: 0.0,
            evaluations: 0,
            lineage: Lineage::genesis(0),
        }
    }

    /// Create a new chromosome with explicit lineage.
    #[must_use]
    pub fn with_lineage(genes: Vec<(String, String)>, lineage: Lineage) -> Self {
        Self {
            genes,
            fitness: 0.0,
            evaluations: 0,
            lineage,
        }
    }

    /// Record an evaluation result using a rich oracle verdict.
    pub fn record_verdict(&mut self, verdict: &crate::types::OracleVerdict) {
        self.evaluations += 1;
        let value = verdict.to_fitness();
        let alpha = 2.0 / (f64::from(self.evaluations) + 1.0);
        self.fitness = alpha * value + (1.0 - alpha) * self.fitness;
    }

    /// Legacy record for backward compatibility.
    pub fn record(&mut self, passed: bool) {
        self.record_verdict(&crate::types::OracleVerdict::from_bool(passed));
    }

    /// Get a specific gene's value by name.
    #[must_use]
    pub fn gene(&self, name: &str) -> Option<&str> {
        self.genes
            .iter()
            .find(|(gene_name, _)| gene_name == name)
            .map(|(_, value)| value.as_str())
    }

    /// Check if this chromosome has a specific gene.
    #[must_use]
    pub fn has_gene(&self, name: &str) -> bool {
        self.genes.iter().any(|(gene_name, _)| gene_name == name)
    }

    /// Count genes that actively apply an evasion technique.
    #[must_use]
    pub fn active_gene_count(&self) -> usize {
        self.genes
            .iter()
            .filter(|(_, value)| value != "None")
            .count()
    }

    /// Compute a hash of this chromosome for deduplication.
    #[must_use]
    pub fn hash(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        for (name, value) in &self.genes {
            name.hash(&mut hasher);
            value.hash(&mut hasher);
        }
        hasher.finish()
    }
}

/// Gene pool: the possible values for each gene type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenePool {
    /// Available gene types and their possible values.
    pub pools: Vec<(String, Vec<String>)>,
}

impl GenePool {
    /// Create a gene pool with WAF Rift's built-in technique space.
    #[must_use]
    pub fn default_wafrift() -> Self {
        Self {
            pools: vec![
                (
                    "encoding".into(),
                    vec![
                        "None".into(),
                        "CaseAlternation".into(),
                        "UrlEncode".into(),
                        "DoubleUrlEncode".into(),
                        "TripleUrlEncode".into(),
                        "UnicodeEncode".into(),
                        "HtmlEntityEncode".into(),
                        "OverlongUtf8".into(),
                        "WhitespaceInsertion".into(),
                        "SqlCommentInsertion".into(),
                        "NullByteInsertion".into(),
                        "ChunkedSplit".into(),
                        "ParameterPollution".into(),
                    ],
                ),
                (
                    "content_type".into(),
                    vec![
                        "None".into(),
                        "Multipart".into(),
                        "MultipartQuotedBoundary".into(),
                        "JsonNested".into(),
                        "JsonUnicodeKeys".into(),
                        "JsonWithComments".into(),
                        "XmlCdata".into(),
                        "XmlNamespace".into(),
                        "MixedContentType".into(),
                    ],
                ),
                (
                    "header_obfuscation".into(),
                    vec![
                        "None".into(),
                        "CaseMixing".into(),
                        "TabSeparator".into(),
                        "WhitespacePadding".into(),
                        "LineFolding".into(),
                        "UnderscoreSubstitution".into(),
                    ],
                ),
                (
                    "grammar_rule".into(),
                    vec![
                        "None".into(),
                        "tautology_swap".into(),
                        "comment_swap".into(),
                        "whitespace_swap".into(),
                        "equality_swap".into(),
                        "union_swap".into(),
                        "string_split".into(),
                        "mysql_conditional".into(),
                        "tag_event_swap".into(),
                        "exec_fn_swap".into(),
                        "uri_scheme".into(),
                        "separator_swap".into(),
                        "command_obfuscate".into(),
                        "ifs_swap".into(),
                        "path_obfuscate".into(),
                        "variable_indirection".into(),
                    ],
                ),
            ],
        }
    }

    /// Get the possible values for a gene type.
    #[must_use]
    pub fn values_for(&self, gene_name: &str) -> Option<&[String]> {
        self.pools
            .iter()
            .find(|(name, _)| name == gene_name)
            .map(|(_, values)| values.as_slice())
    }

    /// Get all gene type names.
    #[must_use]
    pub fn gene_names(&self) -> Vec<&str> {
        self.pools.iter().map(|(name, _)| name.as_str()).collect()
    }

    /// Pick a random value for a gene type using the provided RNG.
    #[must_use]
    pub fn random_value(&self, gene_name: &str, rng: &mut impl Rng) -> Option<String> {
        let values = self.values_for(gene_name)?;
        if values.is_empty() {
            return None;
        }
        Some(values[rng.gen_range(0..values.len())].clone())
    }

    /// Return all unique values across all gene pools.
    #[must_use]
    pub fn all_values(&self) -> Vec<String> {
        let mut values = Vec::new();
        for (_, pool_values) in &self.pools {
            for v in pool_values {
                if !values.contains(v) {
                    values.push(v.clone());
                }
            }
        }
        values
    }
}

/// Generate a random chromosome from the gene pool.
#[must_use]
pub fn random_chromosome(gene_pool: &GenePool, rng: &mut impl Rng) -> Chromosome {
    let genes = gene_pool
        .gene_names()
        .into_iter()
        .map(|name| {
            let value = gene_pool
                .random_value(name, rng)
                .unwrap_or_else(|| String::from("None"));
            (name.to_string(), value)
        })
        .collect();
    Chromosome::new(genes)
}

/// Generate a baseline chromosome with all genes set to "None".
#[must_use]
pub fn baseline_chromosome(gene_pool: &GenePool) -> Chromosome {
    let genes = gene_pool
        .gene_names()
        .into_iter()
        .map(|name| (name.to_string(), String::from("None")))
        .collect();
    Chromosome::new(genes)
}
