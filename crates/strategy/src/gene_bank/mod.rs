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
//! # Concurrency
//!
//! Per-genome **advisory file locks** (`~/.wafrift/genomes/<waf>.lock`)
//! ensure that concurrent writers (e.g. multiple `wafrift-scan`
//! processes, or scan while proxy is active) serialize safely.
//! The lock is tied to the file descriptor and is released automatically
//! by the kernel on process exit; a stale `.lock` file on disk is
//! harmless and is cleaned up on successful write.

use fs4::FileExt;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::PathBuf;

/// Per-payload-class (sql / xss / cmdi / …) success/attempt totals
/// for a single technique. Persisted as part of [`TechniqueRecord`]
/// so a future scan against `(waf, payload_class)` can warm-start
/// from the class-specific winners instead of the global average.
///
/// Why a separate struct: the JSON shape is forward-compatible —
/// adding a new field here doesn't change the parent
/// `TechniqueRecord` schema, and old genomes (pre-per-class) still
/// deserialise via `#[serde(default)]` on the parent's `per_class`
/// map.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClassStat {
    /// Successes for this technique on this payload class.
    #[serde(default)]
    pub successes: u32,
    /// Attempts for this technique on this payload class.
    #[serde(default)]
    pub attempts: u32,
}

impl ClassStat {
    /// Success rate (0.0–1.0) for this technique on this class. Zero
    /// attempts -> 0.0 (callers should also check `attempts >=
    /// min_attempts` before recommending).
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        if self.attempts == 0 {
            return 0.0;
        }
        f64::from(self.successes) / f64::from(self.attempts)
    }
}

/// A single technique's historical performance record.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TechniqueRecord {
    /// Technique name (e.g., `"DoubleUrlEncode"`).
    #[serde(default)]
    pub name: String,
    /// Total successes across all targets with this WAF.
    #[serde(default)]
    pub total_successes: u32,
    /// Total attempts across all targets with this WAF.
    #[serde(default)]
    pub total_attempts: u32,
    /// Number of distinct targets where this technique succeeded.
    #[serde(default)]
    pub target_count: u32,
    /// Unix timestamp of last successful use.
    #[serde(default)]
    pub last_success_epoch: u64,
    /// Per-payload-class breakdown of this technique's track record.
    /// Empty for genomes saved before the per-class warm-start feature
    /// landed (those still load + merge cleanly; the class-specific
    /// `seed_winners_for_class` falls back to the global record when
    /// a class has no per-class history yet).
    #[serde(default)]
    pub per_class: BTreeMap<String, ClassStat>,
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

    /// Success rate for this technique on the named payload class
    /// (`sql`, `xss`, `cmdi`, …). Returns `None` when this technique
    /// has no per-class history yet — caller should fall back to the
    /// global [`Self::success_rate`].
    #[must_use]
    pub fn success_rate_for_class(&self, class: &str) -> Option<f64> {
        self.per_class
            .get(&class.to_ascii_lowercase())
            .filter(|s| s.attempts > 0)
            .map(ClassStat::success_rate)
    }

    /// Attempt count for this technique on the named payload class.
    /// Zero when the class has never been exercised.
    #[must_use]
    pub fn attempts_for_class(&self, class: &str) -> u32 {
        self.per_class
            .get(&class.to_ascii_lowercase())
            .map_or(0, |s| s.attempts)
    }
}

/// A WAF-specific genome — the accumulated knowledge for one WAF vendor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafGenome {
    /// WAF name (e.g., `"Cloudflare"`, `"ModSecurity"`).
    #[serde(default)]
    pub waf_name: String,
    /// Per-technique performance records.
    #[serde(default)]
    pub techniques: Vec<TechniqueRecord>,
    /// Total targets scanned with this WAF.
    #[serde(default)]
    pub targets_scanned: u32,
    /// Last update timestamp (unix epoch seconds).
    #[serde(default)]
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
    ///
    /// # Edge case
    ///
    /// If no technique meets the `min_attempts` threshold, returns an
    /// empty vector.  Callers must handle this gracefully (e.g. fall
    /// back to untested techniques or continue discovery).
    #[must_use]
    pub fn top_techniques(&self, n: usize, min_attempts: u32) -> Vec<&TechniqueRecord> {
        let mut eligible: Vec<&TechniqueRecord> = self
            .techniques
            .iter()
            .filter(|t| t.total_attempts >= min_attempts)
            .collect();
        // R51 pass-13 I4 (CLAUDE.md §11 UTILIZATION): wire
        // target_count into the rank as a tiebreaker. A technique
        // with 100% on ONE target is less trustworthy than one
        // with 95% across five targets — the latter generalises;
        // the former is likely a fluke or fixture artifact.
        // target_count was previously written by merge_session
        // but never consulted; this turns it into a real signal.
        // Primary key remains success_rate so existing semantics
        // don't shift; target_count breaks ties.
        eligible.sort_by(|a, b| {
            b.success_rate()
                .partial_cmp(&a.success_rate())
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.target_count.cmp(&a.target_count))
                .then_with(|| b.last_success_epoch.cmp(&a.last_success_epoch))
        });
        eligible.truncate(n);
        eligible
    }

    /// Hard cap on `techniques.len()` so a long-running scan ingesting
    /// many adversarial profiles cannot grow the genome on disk
    /// without bound. Audit (2026-05-10).
    const MAX_TECHNIQUES: usize = 1024;

    /// Merge results from a scan session into the genome.
    ///
    /// Takes a set of technique stats `(name, successes, attempts)` from
    /// a single scan and folds them into historical records.
    pub fn merge_session(&mut self, stats: &[(String, u32, u32)]) {
        let now = current_epoch();
        self.targets_scanned = self.targets_scanned.saturating_add(1);
        self.updated_at = now;
        for (name, successes, attempts) in stats {
            self.merge_one_technique(name, *successes, *attempts, now, None);
        }
    }

    /// Per-technique merge — shared by [`Self::merge_session`] and
    /// [`Self::merge_session_for_class`]. Folds `(successes, attempts)`
    /// into the matching record (creating one if absent and the
    /// MAX_TECHNIQUES cap allows), and optionally folds into the
    /// per-class breakdown when `class_key` is `Some`.
    ///
    /// R51 pass-13 I5 (CLAUDE.md §7 DEDUP): pre-fix the 15-line
    /// inner loop was duplicated across both merge functions; any
    /// scoring-formula change (e.g. wiring target_count into rank)
    /// had to be applied twice. Single source of truth now.
    fn merge_one_technique(
        &mut self,
        name: &str,
        successes: u32,
        attempts: u32,
        now: u64,
        class_key: Option<&str>,
    ) {
        if let Some(existing) = self.techniques.iter_mut().find(|t| t.name == *name) {
            existing.total_successes = existing.total_successes.saturating_add(successes);
            existing.total_attempts = existing.total_attempts.saturating_add(attempts);
            if successes > 0 {
                existing.target_count = existing.target_count.saturating_add(1);
                existing.last_success_epoch = now;
            }
            if let Some(ck) = class_key {
                let entry = existing.per_class.entry(ck.to_string()).or_default();
                entry.successes = entry.successes.saturating_add(successes);
                entry.attempts = entry.attempts.saturating_add(attempts);
            }
        } else if self.techniques.len() < Self::MAX_TECHNIQUES {
            let mut per_class = BTreeMap::new();
            if let Some(ck) = class_key {
                per_class.insert(
                    ck.to_string(),
                    ClassStat {
                        successes,
                        attempts,
                    },
                );
            }
            self.techniques.push(TechniqueRecord {
                name: name.to_string(),
                total_successes: successes,
                total_attempts: attempts,
                target_count: u32::from(successes > 0),
                last_success_epoch: if successes > 0 { now } else { 0 },
                per_class,
            });
        }
        // Beyond the cap, novel technique names are silently
        // dropped. The fix-it for the operator: if MAX_TECHNIQUES
        // is genuinely too small for their corpus, raise it and
        // re-seed.
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

    /// Class-aware variant of [`Self::merge_session`]: every technique
    /// stat is also folded into the per-class breakdown so subsequent
    /// `seed_winners_for_class(class)` calls bias the variant order
    /// toward what historically beat this specific WAF on this
    /// specific payload class — the warm-start that makes a repeat
    /// SQLi scan against Cloudflare start from "the chains that beat
    /// CF on SQLi yesterday", not "the chains that beat anything on
    /// anything."
    ///
    /// Class is normalised to lowercase for stable lookups. Pass
    /// `""` or any whitespace-only string to fall through to the
    /// class-less [`Self::merge_session`] — the per-class breakdown
    /// then stays untouched, which is what callers want when they
    /// don't know the class (e.g. a generic scan against an unknown
    /// endpoint).
    pub fn merge_session_for_class(&mut self, class: &str, stats: &[(String, u32, u32)]) {
        let class_key = class.trim().to_ascii_lowercase();
        if class_key.is_empty() {
            self.merge_session(stats);
            return;
        }
        let now = current_epoch();
        self.targets_scanned = self.targets_scanned.saturating_add(1);
        self.updated_at = now;
        for (name, successes, attempts) in stats {
            self.merge_one_technique(name, *successes, *attempts, now, Some(&class_key));
        }
    }

    /// Class-aware variant of [`Self::seed_winners`]: returns the
    /// techniques whose per-class success rate (for `class`) meets
    /// the ≥60% / ≥5-attempt floor, sorted best-first. Falls back to
    /// the class-less [`Self::seed_winners`] when:
    ///
    /// - `class` is empty/whitespace, OR
    /// - no technique has enough per-class history yet.
    ///
    /// The fallback is the load-bearing property: a fresh genome (or
    /// a genome saved before the per-class field landed) still warm-
    /// starts the scan with the global winners; only when meaningful
    /// per-class data accumulates does the class-aware path take over.
    #[must_use]
    pub fn seed_winners_for_class(&self, class: &str) -> Vec<String> {
        let class_key = class.trim().to_ascii_lowercase();
        if class_key.is_empty() {
            return self.seed_winners();
        }
        let mut eligible: Vec<(&TechniqueRecord, f64)> = self
            .techniques
            .iter()
            .filter_map(|t| {
                let s = t.per_class.get(&class_key)?;
                if s.attempts < 5 || s.success_rate() < 0.60 {
                    return None;
                }
                Some((t, s.success_rate()))
            })
            .collect();
        if eligible.is_empty() {
            return self.seed_winners();
        }
        eligible.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        eligible
            .into_iter()
            .take(20)
            .map(|(t, _)| t.name.clone())
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

/// Bundled default genome: proven *generic* technique-records (delivery-vector
/// + encoding confusion) that warm-start a COLD bank, so the first scan against
/// a WAF fires known winners instead of discovering from zero — the warm-start
/// pentesters want. These are generic recipes (technique-keys + priors), NOT
/// target-specific payloads (those stay in the private per-target corpus, never
/// shipped). Sourced from real bench/cumulus runs; a test pins that it parses.
const DEFAULT_GENERIC_GENOME: &str = include_str!("default_genomes/generic.json");

/// Cloudflare-class default genome: the delivery-vector + encoding techniques
/// proven most effective against Cloudflare-fronted WAFs (content-type
/// confusion — JSON dup-key / multipart / CBOR / YAML — plus overlong-UTF8 /
/// hex). A pentester hitting a Cloudflare target warm-starts from these instead
/// of the broad generic encodings. Generic technique-keys + priors, not
/// target-specific payloads (those stay in the private per-target corpus).
const DEFAULT_CLOUDFLARE_GENOME: &str = include_str!("default_genomes/cloudflare.json");

/// Pick the bundled default genome best-matched to the detected WAF class.
/// Cloudflare-fronted targets (managed-rules or bot-management) warm-start from
/// the delivery-vector-heavy Cloudflare set; everything else (CRS / ModSec /
/// Coraza / naxsi / unknown) gets the broadly-effective generic encodings.
/// (§6 GENERALIZATION: routed by `WafClass`, never a hardcoded literal name.)
fn bundled_default_for(waf_name: &str) -> &'static str {
    use wafrift_types::WafClass;
    match WafClass::from_waf_name(waf_name) {
        WafClass::CloudflareManagedRules | WafClass::CloudflareBotMgmt => {
            DEFAULT_CLOUDFLARE_GENOME
        }
        _ => DEFAULT_GENERIC_GENOME,
    }
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
    /// Maximum genome file size we will load into memory (F137).
    /// Mirrors the `LearningCache` cap (16 MiB) — a crafted or
    /// corrupted genome file that exceeds this is quarantined, not
    /// read. Without the cap, `fs::read_to_string` on a multi-GB file
    /// causes an OOM abort before any JSON-parse error can fire.
    const MAX_GENOME_FILE_BYTES: u64 = 16 * 1024 * 1024;

    pub fn load(&mut self, waf_name: &str) -> Option<&WafGenome> {
        let key = normalize_name(waf_name);
        if self.cache.contains_key(&key) {
            return self.cache.get(&key);
        }

        let path = self.genome_path(&key);

        // R59 pass-21 §15 audit-hunts: open-then-stat instead of
        // stat-exists-then-stat-then-open. Pre-fix had three serialised
        // filesystem calls (`exists()`, `metadata()`, `read_to_string()`)
        // between each of which a concurrent agent on the shared NFS mount
        // could swap the file (delete, replace with symlink, truncate).
        // Opening once and using the file handle's metadata closes the
        // TOCTOU window — the kernel guarantees the stat we read describes
        // the file we will then read from. NFS-correct because every
        // wafrift agent operates on the same `/media/.../Santh/` share.
        let mut file = match fs::File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "failed to open genome file"
                );
                return None;
            }
        };

        // F137 + R59: size cap from the OPEN file handle's metadata, not a
        // separate stat call. fstat on the same handle is atomic with the
        // open above.
        if let Ok(meta) = file.metadata()
            && meta.len() > Self::MAX_GENOME_FILE_BYTES
        {
            tracing::warn!(
                path = %path.display(),
                bytes = meta.len(),
                cap = Self::MAX_GENOME_FILE_BYTES,
                "genome file exceeds size cap — quarantining to prevent OOM"
            );
            let fake_err = serde_json::from_str::<WafGenome>("").unwrap_err();
            Self::quarantine_corrupt(&path, &fake_err);
            return None;
        }

        let mut contents = String::new();
        use std::io::Read;
        match (&mut file)
            .take(Self::MAX_GENOME_FILE_BYTES)
            .read_to_string(&mut contents)
        {
            Ok(_) => match serde_json::from_str::<WafGenome>(&contents) {
                Ok(genome) => {
                    self.cache.insert(key.clone(), genome);
                    self.cache.get(&key)
                }
                Err(e) => {
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
    /// Writes to a `.tmp` file first, fsyncs it, renames it to the final
    /// path, then fsyncs the parent directory.  A crash at any point
    /// leaves either the old file intact or the new file fully committed
    /// — never a truncated state.
    ///
    /// An exclusive advisory lock is acquired for the duration of the
    /// operation to serialize concurrent writers.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written.
    /// The bundled default genome's technique names — the warm-start seed pool
    /// for a brand-new (cold) install with no per-WAF history yet. Empty only
    /// if the embedded default fails to parse (a build-time invariant pinned by
    /// a test, so in practice this always yields the proven generic set).
    #[must_use]
    pub fn default_seed_winners() -> Vec<String> {
        serde_json::from_str::<WafGenome>(DEFAULT_GENERIC_GENOME)
            .map(|g| g.seed_winners())
            .unwrap_or_default()
    }

    /// Like [`load`](Self::load), but on a COLD bank (no genome yet for this
    /// WAF) it materializes the bundled default best-matched to the WAF class
    /// (Cloudflare-fronted → the delivery-vector set, else the generic
    /// encodings) — stamping it with the detected `waf_name` and writing it
    /// through to disk — so the
    /// FIRST scan warm-starts from proven techniques instead of discovering from
    /// zero. An existing genome is returned untouched (the default never
    /// clobbers accumulated knowledge).
    ///
    /// Write-through is best-effort: a read-only `$HOME` falls back to an
    /// in-memory seed so the scan still warm-starts — this never fails a scan.
    /// Returns `None` only if there's no existing genome AND the bundled default
    /// fails to parse (a build-time invariant pinned by a test, so in practice
    /// a known WAF always warm-starts).
    pub fn load_or_default(&mut self, waf_name: &str) -> Option<&WafGenome> {
        let key = normalize_name(waf_name);
        if self.load(waf_name).is_some() {
            return self.cache.get(&key);
        }
        // Cold start — seed from the bundled default for this WAF.
        let mut default: WafGenome = serde_json::from_str(bundled_default_for(waf_name)).ok()?;
        default.waf_name = waf_name.to_string();
        if self.save(&default).is_err() {
            self.cache.insert(key.clone(), default);
        }
        self.cache.get(&key)
    }

    pub fn save(&mut self, genome: &WafGenome) -> Result<(), GeneBankError> {
        let key = normalize_name(&genome.waf_name);
        let path = self.genome_path(&key);
        let (lock_file, lock_path) = Self::acquire_lock(&path)?;
        Self::write_genome(&path, genome)?;
        drop(lock_file);
        let _ = fs::remove_file(&lock_path);
        self.cache.insert(key, genome.clone());
        Ok(())
    }

    /// Merge a scan session's results into the appropriate WAF genome.
    ///
    /// If no genome exists for this WAF yet, one is created.
    /// If the existing genome file is corrupt, it is quarantined and
    /// a fresh genome is created from this session's data.
    ///
    /// An exclusive advisory lock is acquired for the full
    /// read-modify-write cycle to prevent lost updates.
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
        let path = self.genome_path(&key);
        let (lock_file, lock_path) = Self::acquire_lock(&path)?;

        let mut genome = self
            .cache
            .remove(&key)
            .or_else(|| Self::read_genome_from_disk(&path))
            .unwrap_or_else(|| WafGenome::new(waf_name));

        genome.merge_session(stats);
        Self::write_genome(&path, &genome)?;
        drop(lock_file);
        let _ = fs::remove_file(&lock_path);
        self.cache.insert(key, genome);
        Ok(())
    }

    /// Class-aware variant of [`Self::merge_and_save`]: stats are
    /// recorded both globally AND under the named payload class so
    /// the next scan against `(waf_name, class)` warm-starts from the
    /// class-specific winners. Same atomic-write + advisory-lock
    /// guarantees as the class-less path.
    ///
    /// Pass `""` for `class` to fall through to [`Self::merge_and_save`]
    /// — the per-class breakdown stays untouched.
    ///
    /// # Errors
    ///
    /// Returns an error if the genome cannot be saved to disk.
    pub fn merge_and_save_for_class(
        &mut self,
        waf_name: &str,
        class: &str,
        stats: &[(String, u32, u32)],
    ) -> Result<(), GeneBankError> {
        if class.trim().is_empty() {
            return self.merge_and_save(waf_name, stats);
        }
        let key = normalize_name(waf_name);
        let path = self.genome_path(&key);
        let (lock_file, lock_path) = Self::acquire_lock(&path)?;

        let mut genome = self
            .cache
            .remove(&key)
            .or_else(|| Self::read_genome_from_disk(&path))
            .unwrap_or_else(|| WafGenome::new(waf_name));

        genome.merge_session_for_class(class, stats);
        Self::write_genome(&path, &genome)?;
        drop(lock_file);
        let _ = fs::remove_file(&lock_path);
        self.cache.insert(key, genome);
        Ok(())
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

    /// Acquire an exclusive advisory lock for a genome file.
    ///
    /// Returns the locked file handle and the lock file path.
    /// The caller must drop the handle to release the lock.
    fn acquire_lock(path: &std::path::Path) -> Result<(fs::File, PathBuf), GeneBankError> {
        let lock_path = path.with_extension("lock");
        let lock_file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&lock_path)
            .map_err(|e| GeneBankError::Io {
                path: lock_path.clone(),
                source: e,
            })?;
        // Advisory lock via fs4 (works on stable Rust). std::fs::File::lock
        // is gated behind unstable `file_lock` (Rust 1.89+) which our
        // workspace MSRV (1.85) doesn't have.
        FileExt::lock(&lock_file).map_err(|e| GeneBankError::Io {
            path: lock_path.clone(),
            source: e,
        })?;
        Ok((lock_file, lock_path))
    }

    /// Atomic write of a genome to disk.
    ///
    /// Does NOT acquire locks — the caller must hold the advisory lock.
    /// Delegates the crash-safe write dance to
    /// [`wafrift_types::loaders::write_atomic`], which is shared with
    /// `proxy::gene_bank_io` and `cli::seed` so a fsync-policy tweak
    /// lives in one place.
    fn write_genome(path: &std::path::Path, genome: &WafGenome) -> Result<(), GeneBankError> {
        let json = serde_json::to_string_pretty(genome).map_err(|e| GeneBankError::Serialize {
            waf: genome.waf_name.clone(),
            source: e,
        })?;
        wafrift_types::loaders::write_atomic(path, json.as_bytes()).map_err(|e| GeneBankError::Io {
            path: path.to_path_buf(),
            source: e,
        })
    }

    /// Read a genome from disk, quarantining if corrupt.
    fn read_genome_from_disk(path: &std::path::Path) -> Option<WafGenome> {
        if !path.exists() {
            return None;
        }
        // F137: same OOM guard as `load` — an adversarial file here
        // would be consumed by the merge_and_save / merge_and_save_for_class
        // path, which is equally reachable from the scan loop.
        if let Ok(meta) = fs::metadata(path)
            && meta.len() > Self::MAX_GENOME_FILE_BYTES
        {
            tracing::warn!(
                path = %path.display(),
                bytes = meta.len(),
                cap = Self::MAX_GENOME_FILE_BYTES,
                "genome file exceeds size cap during merge — quarantining to prevent OOM"
            );
            let fake_err = serde_json::from_str::<WafGenome>("").unwrap_err();
            Self::quarantine_corrupt(path, &fake_err);
            return None;
        }
        match fs::read_to_string(path) {
            Ok(contents) => match serde_json::from_str(&contents) {
                Ok(g) => Some(g),
                Err(e) => {
                    Self::quarantine_corrupt(path, &e);
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
#[derive(Debug, thiserror::Error)]
pub enum GeneBankError {
    /// I/O error reading/writing genome files.
    #[error("gene bank I/O error at {}: {source}", path.display())]
    Io {
        /// Path that caused the error.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// Serialization error.
    #[error("failed to serialize genome for {waf}: {source}")]
    Serialize {
        /// WAF name being serialized.
        waf: String,
        /// Underlying serde error.
        source: serde_json::Error,
    },
    /// No home directory found.
    #[error("cannot determine home directory for gene bank storage")]
    NoHomeDir,
}

/// Normalize a WAF name to a filesystem-safe key.
pub(crate) fn normalize_name(name: &str) -> String {
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
mod tests;
