//! Cross-target gene bank — persistent WAF evasion memory.
//!
//! Stores per-WAF evasion genomes to `~/.wafrift/genomes/<waf_name>.json`.
//! When a new scan targets a known WAF, the gene bank pre-populates the
//! winner pool with historically effective techniques — eliminating the
//! discovery phase entirely for previously-encountered WAFs.
//!
//! This is **horizontal gene transfer**: knowledge gained against one
//! Cloudflare site immediately benefits all future Cloudflare scans.
//!
//! # Corruption resilience
//!
//! All writes use **atomic rename** (`write` → `.tmp` → `rename`).
//! A crash at any point leaves either the old file intact or the new
//! file fully written — never a truncated/corrupt state.
//!
//! Corrupt files encountered on load are quarantined to
//! `<name>.json.corrupt.<timestamp>` and a warning is emitted.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

/// A single technique's historical performance record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechniqueRecord {
    /// Technique name (e.g., `"DoubleUrlEncode"`).
    pub name: String,
    /// Total successes across all targets with this WAF.
    pub total_successes: u32,
    /// Total attempts across all targets with this WAF.
    pub total_attempts: u32,
    /// Number of distinct targets where this technique succeeded.
    pub target_count: u32,
    /// Unix timestamp of last successful use.
    pub last_success_epoch: u64,
}

impl TechniqueRecord {
    /// Success rate (0.0–1.0) across all historical data.
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        if self.total_attempts == 0 {
            return 0.0;
        }
        f64::from(self.total_successes) / f64::from(self.total_attempts)
    }
}

/// A WAF-specific genome — the accumulated knowledge for one WAF vendor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafGenome {
    /// WAF name (e.g., `"Cloudflare"`, `"ModSecurity"`).
    pub waf_name: String,
    /// Per-technique performance records.
    pub techniques: Vec<TechniqueRecord>,
    /// Total targets scanned with this WAF.
    pub targets_scanned: u32,
    /// Last update timestamp (unix epoch seconds).
    pub updated_at: u64,
}

impl WafGenome {
    /// Create a new empty genome for a WAF.
    #[must_use]
    pub fn new(waf_name: &str) -> Self {
        Self {
            waf_name: waf_name.to_string(),
            techniques: Vec::new(),
            targets_scanned: 0,
            updated_at: current_epoch(),
        }
    }

    /// Get the top N techniques by success rate, sorted best-first.
    ///
    /// Only returns techniques with at least `min_attempts` historical
    /// data points to avoid recommending under-tested techniques.
    #[must_use]
    pub fn top_techniques(&self, n: usize, min_attempts: u32) -> Vec<&TechniqueRecord> {
        let mut eligible: Vec<&TechniqueRecord> = self
            .techniques
            .iter()
            .filter(|t| t.total_attempts >= min_attempts)
            .collect();
        eligible.sort_by(|a, b| {
            b.success_rate()
                .partial_cmp(&a.success_rate())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        eligible.truncate(n);
        eligible
    }

    /// Merge results from a scan session into the genome.
    ///
    /// Takes a set of technique stats `(name, successes, attempts)` from
    /// a single scan and folds them into historical records.
    pub fn merge_session(&mut self, stats: &[(String, u32, u32)]) {
        let now = current_epoch();
        self.targets_scanned += 1;
        self.updated_at = now;

        for (name, successes, attempts) in stats {
            if let Some(existing) = self.techniques.iter_mut().find(|t| t.name == *name) {
                existing.total_successes += successes;
                existing.total_attempts += attempts;
                if *successes > 0 {
                    existing.target_count += 1;
                    existing.last_success_epoch = now;
                }
            } else {
                self.techniques.push(TechniqueRecord {
                    name: name.clone(),
                    total_successes: *successes,
                    total_attempts: *attempts,
                    target_count: u32::from(*successes > 0),
                    last_success_epoch: if *successes > 0 { now } else { 0 },
                });
            }
        }
    }

    /// Get technique names that should pre-populate the winner pool.
    ///
    /// Returns techniques with ≥60% historical success rate and ≥5
    /// total attempts, sorted by success rate descending.
    #[must_use]
    pub fn seed_winners(&self) -> Vec<String> {
        self.top_techniques(20, 5)
            .iter()
            .filter(|t| t.success_rate() >= 0.60)
            .map(|t| t.name.clone())
            .collect()
    }
}

/// The gene bank — manages all WAF genomes on disk.
pub struct GeneBank {
    /// Root directory for genome storage.
    root: PathBuf,
    /// In-memory cache of loaded genomes.
    cache: HashMap<String, WafGenome>,
}

impl GeneBank {
    /// Open or create the gene bank at the default location (`~/.wafrift/genomes/`).
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created.
    pub fn open_default() -> Result<Self, GeneBankError> {
        let root = default_genome_dir()?;
        Self::open(root)
    }

    /// Open or create the gene bank at a specific directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created.
    pub fn open(root: impl AsRef<std::path::Path>) -> Result<Self, GeneBankError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root).map_err(|e| GeneBankError::Io {
            path: root.clone(),
            source: e,
        })?;
        Ok(Self {
            root,
            cache: HashMap::new(),
        })
    }

    /// Load a WAF genome from disk (or return a cached copy).
    ///
    /// Returns `None` if no genome exists for this WAF yet.
    ///
    /// If the genome file exists but contains corrupt JSON, the file is
    /// quarantined (renamed to `<name>.json.corrupt.<timestamp>`) and
    /// a warning is emitted.  This prevents a single corrupt file from
    /// silently destroying accumulated knowledge — the quarantined file
    /// can be inspected and recovered manually.
    pub fn load(&mut self, waf_name: &str) -> Option<&WafGenome> {
        let key = normalize_name(waf_name);
        if self.cache.contains_key(&key) {
            return self.cache.get(&key);
        }

        let path = self.genome_path(&key);
        if !path.exists() {
            return None;
        }

        match fs::read_to_string(&path) {
            Ok(contents) => match serde_json::from_str::<WafGenome>(&contents) {
                Ok(genome) => {
                    self.cache.insert(key.clone(), genome);
                    self.cache.get(&key)
                }
                Err(e) => {
                    // Quarantine corrupt file instead of silently dropping it.
                    Self::quarantine_corrupt(&path, &e);
                    None
                }
            },
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "failed to read genome file"
                );
                None
            }
        }
    }

    /// Save a WAF genome to disk using atomic write.
    ///
    /// Writes to a `.tmp` file first, then renames it to the final
    /// path.  A crash at any point leaves either the old file intact
    /// or the new file fully committed — never a truncated state.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written.
    pub fn save(&mut self, genome: &WafGenome) -> Result<(), GeneBankError> {
        let key = normalize_name(&genome.waf_name);
        let path = self.genome_path(&key);
        let tmp_path = path.with_extension("json.tmp");

        let json = serde_json::to_string_pretty(genome).map_err(|e| GeneBankError::Serialize {
            waf: genome.waf_name.clone(),
            source: e,
        })?;

        // Phase 1: Write to temp file.
        fs::write(&tmp_path, &json).map_err(|e| GeneBankError::Io {
            path: tmp_path.clone(),
            source: e,
        })?;

        // Phase 2: Atomic rename.
        //
        // On POSIX, rename(2) is atomic within the same filesystem.
        // On Windows, this is not strictly atomic but is still
        // crash-safe — the old file is replaced in a single operation.
        fs::rename(&tmp_path, &path).map_err(|e| {
            // Clean up the temp file if rename fails.
            let _ = fs::remove_file(&tmp_path);
            GeneBankError::Io {
                path: path.clone(),
                source: e,
            }
        })?;

        self.cache.insert(key, genome.clone());
        Ok(())
    }

    /// Merge a scan session's results into the appropriate WAF genome.
    ///
    /// If no genome exists for this WAF yet, one is created.
    /// If the existing genome file is corrupt, it is quarantined and
    /// a fresh genome is created from this session's data.
    ///
    /// # Errors
    ///
    /// Returns an error if the genome cannot be saved to disk.
    pub fn merge_and_save(
        &mut self,
        waf_name: &str,
        stats: &[(String, u32, u32)],
    ) -> Result<(), GeneBankError> {
        let key = normalize_name(waf_name);
        let mut genome = self
            .cache
            .remove(&key)
            .or_else(|| {
                let path = self.genome_path(&key);
                if path.exists() {
                    match fs::read_to_string(&path) {
                        Ok(contents) => match serde_json::from_str(&contents) {
                            Ok(g) => Some(g),
                            Err(e) => {
                                // Quarantine and start fresh.
                                Self::quarantine_corrupt(&path, &e);
                                None
                            }
                        },
                        Err(e) => {
                            tracing::warn!(
                                path = %path.display(),
                                error = %e,
                                "failed to read genome for merge"
                            );
                            None
                        }
                    }
                } else {
                    None
                }
            })
            .unwrap_or_else(|| WafGenome::new(waf_name));

        genome.merge_session(stats);
        self.save(&genome)
    }

    /// List all known WAF genomes.
    #[must_use]
    pub fn list_wafs(&self) -> Vec<String> {
        let Ok(entries) = fs::read_dir(&self.root) else {
            return Vec::new();
        };
        entries
            .filter_map(|e| {
                let e = e.ok()?;
                let name = e.file_name().to_string_lossy().to_string();
                if name.ends_with(".json") && !name.contains(".corrupt.") && !name.ends_with(".tmp")
                {
                    Some(name.trim_end_matches(".json").to_string())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Path to a specific genome file.
    fn genome_path(&self, normalized_name: &str) -> PathBuf {
        self.root.join(format!("{normalized_name}.json"))
    }

    /// Quarantine a corrupt genome file by renaming it.
    ///
    /// The corrupt file is moved to `<name>.json.corrupt.<epoch>` so it
    /// can be inspected and potentially recovered.
    fn quarantine_corrupt(path: &std::path::Path, error: &serde_json::Error) {
        let epoch = current_epoch();
        let quarantine = path.with_extension(format!("json.corrupt.{epoch}"));
        tracing::warn!(
            path = %path.display(),
            quarantine = %quarantine.display(),
            error = %error,
            "corrupt genome file — quarantining for inspection"
        );
        if let Err(e) = fs::rename(path, &quarantine) {
            tracing::error!(
                error = %e,
                "failed to quarantine corrupt genome, removing instead"
            );
            let _ = fs::remove_file(path);
        }
    }
}

/// Errors from gene bank operations.
#[derive(Debug)]
pub enum GeneBankError {
    /// I/O error reading/writing genome files.
    Io {
        /// Path that caused the error.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// Serialization error.
    Serialize {
        /// WAF name being serialized.
        waf: String,
        /// Underlying serde error.
        source: serde_json::Error,
    },
    /// No home directory found.
    NoHomeDir,
}

impl std::fmt::Display for GeneBankError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "gene bank I/O error at {}: {source}", path.display())
            }
            Self::Serialize { waf, source } => {
                write!(f, "failed to serialize genome for {waf}: {source}")
            }
            Self::NoHomeDir => write!(f, "cannot determine home directory for gene bank storage"),
        }
    }
}

impl std::error::Error for GeneBankError {}

/// Normalize a WAF name to a filesystem-safe key.
fn normalize_name(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Default genome storage directory.
fn default_genome_dir() -> Result<PathBuf, GeneBankError> {
    let home = dirs::home_dir().ok_or(GeneBankError::NoHomeDir)?;
    Ok(home.join(".wafrift").join("genomes"))
}

/// Current unix epoch seconds.
fn current_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn technique_record_success_rate() {
        let rec = TechniqueRecord {
            name: "DoubleUrlEncode".into(),
            total_successes: 8,
            total_attempts: 10,
            target_count: 3,
            last_success_epoch: 0,
        };
        assert!((rec.success_rate() - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn technique_record_zero_attempts() {
        let rec = TechniqueRecord {
            name: "Test".into(),
            total_successes: 0,
            total_attempts: 0,
            target_count: 0,
            last_success_epoch: 0,
        };
        assert!((rec.success_rate()).abs() < f64::EPSILON);
    }

    #[test]
    fn genome_merge_session_new_techniques() {
        let mut genome = WafGenome::new("TestWAF");
        let stats = vec![
            ("DoubleUrlEncode".into(), 8, 10),
            ("OverlongUtf8".into(), 5, 10),
        ];
        genome.merge_session(&stats);
        assert_eq!(genome.techniques.len(), 2);
        assert_eq!(genome.targets_scanned, 1);
        assert_eq!(genome.techniques[0].total_successes, 8);
    }

    #[test]
    fn genome_merge_session_accumulates() {
        let mut genome = WafGenome::new("TestWAF");
        let stats1 = vec![("DoubleUrlEncode".into(), 5, 10)];
        let stats2 = vec![("DoubleUrlEncode".into(), 3, 5)];
        genome.merge_session(&stats1);
        genome.merge_session(&stats2);
        assert_eq!(genome.targets_scanned, 2);
        assert_eq!(genome.techniques[0].total_successes, 8);
        assert_eq!(genome.techniques[0].total_attempts, 15);
        assert_eq!(genome.techniques[0].target_count, 2);
    }

    #[test]
    fn genome_seed_winners_filters_low_rate() {
        let mut genome = WafGenome::new("TestWAF");
        genome.techniques.push(TechniqueRecord {
            name: "Good".into(),
            total_successes: 9,
            total_attempts: 10,
            target_count: 5,
            last_success_epoch: 100,
        });
        genome.techniques.push(TechniqueRecord {
            name: "Bad".into(),
            total_successes: 1,
            total_attempts: 10,
            target_count: 1,
            last_success_epoch: 50,
        });
        let winners = genome.seed_winners();
        assert_eq!(winners, vec!["Good".to_string()]);
    }

    #[test]
    fn gene_bank_roundtrip() {
        let tmp = std::env::temp_dir().join("wafrift_test_genebank");
        let _ = fs::remove_dir_all(&tmp);
        let mut bank = GeneBank::open(tmp.clone()).unwrap();

        let mut genome = WafGenome::new("Cloudflare");
        genome.merge_session(&[("OverlongUtf8".into(), 9, 10)]);
        bank.save(&genome).unwrap();

        // Re-open and load
        let mut bank2 = GeneBank::open(tmp.clone()).unwrap();
        let loaded = bank2.load("Cloudflare").unwrap();
        assert_eq!(loaded.techniques[0].name, "OverlongUtf8");
        assert_eq!(loaded.techniques[0].total_successes, 9);

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn gene_bank_list_wafs() {
        let tmp = std::env::temp_dir().join("wafrift_test_list");
        let _ = fs::remove_dir_all(&tmp);
        let mut bank = GeneBank::open(tmp.clone()).unwrap();

        bank.save(&WafGenome::new("Cloudflare")).unwrap();
        bank.save(&WafGenome::new("AWS WAF")).unwrap();

        let wafs = bank.list_wafs();
        assert!(wafs.contains(&"cloudflare".to_string()));
        assert!(wafs.contains(&"aws_waf".to_string()));

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn normalize_name_handles_special_chars() {
        assert_eq!(normalize_name("AWS WAF"), "aws_waf");
        assert_eq!(normalize_name("Cloudflare (Pro)"), "cloudflare__pro_");
        assert_eq!(normalize_name("ModSecurity/CRS"), "modsecurity_crs");
    }

    // ── Corruption resilience tests ──

    #[test]
    fn corrupt_genome_is_quarantined_on_load() {
        let tmp = std::env::temp_dir().join("wafrift_test_corrupt_load");
        let _ = fs::remove_dir_all(&tmp);
        let _ = fs::create_dir_all(&tmp);

        // Write corrupt JSON to the genome file.
        let corrupt_path = tmp.join("cloudflare.json");
        fs::write(&corrupt_path, "{ this is not valid json!!!").unwrap();

        let mut bank = GeneBank::open(tmp.clone()).unwrap();
        let result = bank.load("Cloudflare");

        // Should return None (corrupt file).
        assert!(result.is_none());

        // Original file should be quarantined (renamed).
        assert!(
            !corrupt_path.exists(),
            "corrupt file should have been renamed"
        );

        // A .corrupt. file should exist.
        let quarantined: Vec<_> = fs::read_dir(&tmp)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".corrupt."))
            .collect();
        assert_eq!(
            quarantined.len(),
            1,
            "expected exactly one quarantined file"
        );

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn corrupt_genome_is_quarantined_on_merge() {
        let tmp = std::env::temp_dir().join("wafrift_test_corrupt_merge");
        let _ = fs::remove_dir_all(&tmp);
        let _ = fs::create_dir_all(&tmp);

        // Write corrupt JSON.
        let corrupt_path = tmp.join("cloudflare.json");
        fs::write(&corrupt_path, "GARBAGE").unwrap();

        let mut bank = GeneBank::open(tmp.clone()).unwrap();

        // merge_and_save should quarantine the corrupt file and create
        // a fresh genome from the session data.
        bank.merge_and_save("Cloudflare", &[("DoubleUrlEncode".into(), 5, 10)])
            .unwrap();

        // The genome should now be loadable with the new data.
        let mut bank2 = GeneBank::open(tmp.clone()).unwrap();
        let loaded = bank2.load("Cloudflare").unwrap();
        assert_eq!(loaded.techniques.len(), 1);
        assert_eq!(loaded.techniques[0].name, "DoubleUrlEncode");
        assert_eq!(loaded.techniques[0].total_successes, 5);

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn atomic_write_no_temp_file_left() {
        let tmp = std::env::temp_dir().join("wafrift_test_atomic");
        let _ = fs::remove_dir_all(&tmp);
        let mut bank = GeneBank::open(tmp.clone()).unwrap();

        bank.save(&WafGenome::new("TestWAF")).unwrap();

        // No .tmp files should remain.
        let tmp_files: Vec<_> = fs::read_dir(&tmp)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(
            tmp_files.is_empty(),
            "no .tmp files should remain after save"
        );

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn list_wafs_excludes_corrupt_and_tmp_files() {
        let tmp = std::env::temp_dir().join("wafrift_test_list_filter");
        let _ = fs::remove_dir_all(&tmp);
        let _ = fs::create_dir_all(&tmp);

        // Create valid, corrupt, and tmp files.
        fs::write(tmp.join("cloudflare.json"), "{}").unwrap();
        fs::write(tmp.join("aws.json.corrupt.12345"), "GARBAGE").unwrap();
        fs::write(tmp.join("modsec.json.tmp"), "{}").unwrap();

        let bank = GeneBank::open(tmp.clone()).unwrap();
        let wafs = bank.list_wafs();

        assert_eq!(wafs, vec!["cloudflare"]);

        let _ = fs::remove_dir_all(&tmp);
    }
}
