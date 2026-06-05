//! Learning cache — persistent per-WAF, per-payload-type pipeline memory.
//!
//! After a successful bypass, the winning pipeline is cached to disk
//! and re-used on subsequent scans of the same WAF + payload type.

use crate::pipeline::EvasionPipeline;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Cache key: WAF fingerprint + payload type.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CacheKey {
    pub waf_fingerprint: String,
    pub payload_type: String,
}

impl CacheKey {
    #[must_use]
    pub fn new(waf: impl Into<String>, payload: impl Into<String>) -> Self {
        Self {
            waf_fingerprint: waf.into(),
            payload_type: payload.into(),
        }
    }
}

/// A single cached entry: the winning pipeline and its success stats.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheEntry {
    pub pipeline: EvasionPipeline,
    pub successes: u32,
    pub attempts: u32,
    pub last_success_epoch: u64,
}

impl CacheEntry {
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        if self.attempts == 0 {
            0.0
        } else {
            f64::from(self.successes) / f64::from(self.attempts)
        }
    }
}

/// On-disk learning cache.
///
/// Keys are JSON-serialized [`CacheKey`] strings because JSON object keys must be strings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LearningCache {
    #[serde(skip)]
    path: Option<PathBuf>,
    entries: HashMap<String, CacheEntry>,
}

fn cache_key_str(k: &CacheKey) -> String {
    serde_json::to_string(k).unwrap_or_else(|_| {
        format!(
            "{{\"waf_fingerprint\":{},\"payload_type\":{}}}",
            serde_json::to_string(&k.waf_fingerprint).unwrap_or_else(|_| "\"\"".to_string()),
            serde_json::to_string(&k.payload_type).unwrap_or_else(|_| "\"\"".to_string()),
        )
    })
}

impl LearningCache {
    /// Open the default cache at `~/.wafrift/learning_cache.json`.
    ///
    /// # Errors
    ///
    /// Returns an error if the home directory cannot be determined.
    pub fn open_default() -> Result<Self, LearningCacheError> {
        let home = dirs::home_dir().ok_or(LearningCacheError::NoHomeDir)?;
        let path = home.join(".wafrift").join("learning_cache.json");
        Self::open(path)
    }

    /// Open or create a cache at a specific path.
    ///
    /// A corrupted cache file (kill-9 mid-save, disk corruption, partial
    /// flush) is moved aside to `<path>.corrupt-<epoch>` and a fresh
    /// empty cache is returned. Crashing the whole strategy engine on
    /// one bad JSON file would lose all subsequent learning — better to
    /// surface the corruption via `tracing::warn` and keep going.
    ///
    /// # Errors
    ///
    /// Returns an error only if the file exists, looks fine, and the
    /// underlying I/O still fails (permission denied, etc.).
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LearningCacheError> {
        let path = path.as_ref();
        if path.exists() {
            // Audit (2026-05-10): pre-fix the cache was loaded with no
            // size or depth limit on the JSON. A maliciously crafted
            // ~/.wafrift/learning_cache.json could exhaust memory
            // (multi-GB file) or stack (deeply nested arrays). Cap the
            // file at MAX_CACHE_FILE_BYTES; the JSON parser then has
            // a bounded heap and stack via that bound.
            //
            // Audit (2026-05-27): the previous fix used metadata().len()
            // followed by read_to_string() — a TOCTOU window where a
            // symlink swap or file growth between the two calls could
            // bypass the cap. Use File::open() + take(cap+1) instead:
            // the cap is enforced DURING the read on the same open
            // descriptor, closing the race.
            const MAX_CACHE_FILE_BYTES: u64 = 16 * 1024 * 1024;
            let f = fs::File::open(path).map_err(LearningCacheError::Io)?;
            let mut limited = f.take(MAX_CACHE_FILE_BYTES + 1);
            let mut raw = Vec::new();
            limited.read_to_end(&mut raw).map_err(LearningCacheError::Io)?;
            if raw.len() as u64 > MAX_CACHE_FILE_BYTES {
                tracing::warn!(
                    path = %path.display(),
                    cap = MAX_CACHE_FILE_BYTES,
                    "learning cache file exceeds size cap; moving aside and starting fresh"
                );
                let backup = path.with_extension(format!("oversize-{}", current_epoch()));
                let _ = fs::rename(path, &backup);
                return Ok(Self {
                    path: Some(path.to_path_buf()),
                    entries: HashMap::new(),
                });
            }
            let contents = String::from_utf8(raw).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("{}: learning cache is not valid UTF-8: {e}", path.display()),
                )
            }).map_err(LearningCacheError::Io)?;
            match serde_json::from_str::<LearningCache>(&contents) {
                Ok(mut cache) => {
                    cache.path = Some(path.to_path_buf());
                    Ok(cache)
                }
                Err(e) => {
                    let backup = path.with_extension(format!("corrupt-{}", current_epoch()));
                    let backup_msg = match fs::rename(path, &backup) {
                        Ok(()) => format!("moved aside to {}", backup.display()),
                        Err(rename_err) => {
                            format!("could not rename ({rename_err}); leaving file in place")
                        }
                    };
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        backup = %backup_msg,
                        "learning cache file corrupted; starting fresh"
                    );
                    Ok(Self {
                        path: Some(path.to_path_buf()),
                        entries: HashMap::new(),
                    })
                }
            }
        } else {
            Ok(Self {
                path: Some(path.to_path_buf()),
                entries: HashMap::new(),
            })
        }
    }

    /// Look up a cached pipeline.
    #[must_use]
    pub fn get(&self, key: &CacheKey) -> Option<&CacheEntry> {
        self.entries.get(&cache_key_str(key))
    }

    /// Record a successful bypass.
    ///
    /// The stored pipeline is ALWAYS overwritten with the
    /// just-succeeded pipeline. Pre-fix this used `or_insert`
    /// which left the existing entry's pipeline untouched — if
    /// the first interaction for a key was a `record_failure`,
    /// the failing pipeline got stored permanently and every
    /// subsequent `record_success` (with a DIFFERENT, working
    /// pipeline) silently kept the loser as the cached winner.
    /// The planner then promoted the known-failing pipeline to
    /// the top of every future scan.
    pub fn record_success(&mut self, key: CacheKey, pipeline: EvasionPipeline) {
        let now = current_epoch();
        let entry = self
            .entries
            .entry(cache_key_str(&key))
            .or_insert_with(|| CacheEntry {
                pipeline: pipeline.clone(),
                successes: 0,
                attempts: 0,
                last_success_epoch: 0,
            });
        // Always update to the just-succeeded pipeline — even if
        // it's the same shape as the cached one, this is cheap.
        entry.pipeline = pipeline;
        entry.successes = entry.successes.saturating_add(1);
        entry.attempts = entry.attempts.saturating_add(1);
        entry.last_success_epoch = now;
    }

    /// Record a failed attempt.
    ///
    /// Failures DO NOT overwrite the stored pipeline — the cached
    /// winner is set by `record_success`. If no success has been
    /// recorded yet, the failing pipeline is what's stored, but
    /// the next success will replace it.
    pub fn record_failure(&mut self, key: CacheKey, pipeline: EvasionPipeline) {
        let entry = self
            .entries
            .entry(cache_key_str(&key))
            .or_insert(CacheEntry {
                pipeline,
                successes: 0,
                attempts: 0,
                last_success_epoch: 0,
            });
        entry.attempts = entry.attempts.saturating_add(1);
    }

    /// Persist the cache to disk atomically.
    ///
    /// Writes to a sibling `<path>.tmp.<pid>.<epoch>` file, fsyncs it,
    /// then renames over the target path. A kill-9 between `write` and
    /// `rename` leaves the previous good cache file untouched instead
    /// of producing the half-written JSON that was poisoning subsequent
    /// `open` calls.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written or renamed.
    pub fn save(&self) -> Result<(), LearningCacheError> {
        let path = self.path.as_ref().ok_or(LearningCacheError::NoPath)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(LearningCacheError::Io)?;
        }
        let json = serde_json::to_string_pretty(self).map_err(LearningCacheError::Serde)?;

        // Sibling tmp file in the same directory so `rename` is atomic
        // (cross-FS rename on /tmp would silently fall back to copy).
        let tmp = path.with_extension(format!("tmp.{}.{}", std::process::id(), current_epoch()));
        // Scope the file handle so the OS releases its descriptor before
        // we rename — Windows would otherwise refuse the rename.
        {
            use std::io::Write;
            let mut f = fs::File::create(&tmp).map_err(LearningCacheError::Io)?;
            f.write_all(json.as_bytes())
                .map_err(LearningCacheError::Io)?;
            f.sync_all().map_err(LearningCacheError::Io)?;
        }
        if let Err(e) = fs::rename(&tmp, path) {
            // Clean up the orphaned tmp file before propagating.
            let _ = fs::remove_file(&tmp);
            return Err(LearningCacheError::Io(e));
        }
        Ok(())
    }

    /// All cached keys.
    #[must_use]
    pub fn keys(&self) -> Vec<CacheKey> {
        self.entries
            .keys()
            .filter_map(|s| match serde_json::from_str(s) {
                Ok(k) => Some(k),
                Err(e) => {
                    tracing::warn!(key = %s, error = %e, "learning cache key parse failed");
                    None
                }
            })
            .collect()
    }
}

/// Errors from learning cache operations.
#[derive(Debug, thiserror::Error)]
pub enum LearningCacheError {
    #[error("learning cache I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("learning cache serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("cannot determine home directory")]
    NoHomeDir,
    #[error("no path set for learning cache")]
    NoPath,
}

fn current_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::EvasionStage;
    use wafrift_types::Technique;

    #[test]
    fn cache_roundtrip() {
        let tmp = std::env::temp_dir().join("wafrift_learning_cache_test.json");
        let _ = fs::remove_file(&tmp);

        let mut cache = LearningCache::open(&tmp).unwrap();
        let pipeline = EvasionPipeline::new(
            "test",
            vec![EvasionStage {
                technique: Technique::UserAgentRotation,
                context: None,
            }],
            1,
        );
        cache.record_success(CacheKey::new("cloudflare", "sql"), pipeline);
        cache.save().unwrap();

        let cache2 = LearningCache::open(&tmp).unwrap();
        let entry = cache2.get(&CacheKey::new("cloudflare", "sql")).unwrap();
        assert_eq!(entry.successes, 1);
        assert_eq!(entry.attempts, 1);

        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn cache_persists_across_process_restarts() {
        let tmp = std::env::temp_dir().join("wafrift_learning_cache_restart.json");
        let _ = fs::remove_file(&tmp);

        // Process 1
        {
            let mut cache = LearningCache::open(&tmp).unwrap();
            let pipeline = EvasionPipeline::new(
                "win",
                vec![EvasionStage {
                    technique: Technique::GrammarMutation("sql".into()),
                    context: None,
                }],
                2,
            );
            cache.record_success(CacheKey::new("aws_waf", "xss"), pipeline);
            cache.save().unwrap();
        }

        // Process 2
        {
            let cache = LearningCache::open(&tmp).unwrap();
            let entry = cache.get(&CacheKey::new("aws_waf", "xss")).unwrap();
            assert_eq!(entry.successes, 1);
            assert!(entry.last_success_epoch > 0);
        }

        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn cache_failure_tracking() {
        let tmp = std::env::temp_dir().join("wafrift_learning_cache_fail.json");
        let _ = fs::remove_file(&tmp);

        let mut cache = LearningCache::open(&tmp).unwrap();
        let pipeline = EvasionPipeline::new("lose", vec![], 1);
        let key = CacheKey::new("modsecurity", "cmdi");
        cache.record_failure(key.clone(), pipeline);
        cache.save().unwrap();

        let cache2 = LearningCache::open(&tmp).unwrap();
        let entry = cache2.get(&key).unwrap();
        assert_eq!(entry.successes, 0);
        assert_eq!(entry.attempts, 1);

        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn record_success_after_failure_overwrites_stored_pipeline() {
        // Regression for F44: pre-fix record_success used
        // or_insert which left the existing entry's pipeline
        // untouched. If the first call was record_failure with a
        // losing pipeline, the loser became permanent — the
        // planner promoted it to every future scan.
        let mut cache = LearningCache::default();
        let loser = EvasionPipeline::new("LOSER", vec![], 1);
        let winner = EvasionPipeline::new("WINNER", vec![], 1);
        let key = CacheKey::new("cloudflare", "xss");
        cache.record_failure(key.clone(), loser);
        cache.record_success(key.clone(), winner);
        let entry = cache.get(&key).expect("entry present");
        assert_eq!(
            entry.pipeline.name, "WINNER",
            "post-success the winning pipeline must be cached"
        );
        assert_eq!(entry.successes, 1);
        assert_eq!(entry.attempts, 2);
    }

    #[test]
    fn second_record_success_overwrites_first_pipeline() {
        // Newer better pipeline must replace the older one.
        let mut cache = LearningCache::default();
        let first = EvasionPipeline::new("FIRST", vec![], 1);
        let second = EvasionPipeline::new("SECOND", vec![], 1);
        let key = CacheKey::new("awswaf", "sql");
        cache.record_success(key.clone(), first);
        cache.record_success(key.clone(), second);
        let entry = cache.get(&key).unwrap();
        assert_eq!(entry.pipeline.name, "SECOND");
        assert_eq!(entry.successes, 2);
    }

    /// Anti-regression: a cache file exceeding the size cap must be moved aside
    /// and a fresh empty cache returned, not OOM-crash the process.
    /// Also validates that the cap is enforced during the read (not via a
    /// pre-check metadata() call that a file swap could race).
    #[test]
    fn oversized_cache_file_is_moved_aside_and_returns_empty_cache() {
        use std::io::Write;

        let tmp = std::env::temp_dir().join(format!(
            "wafrift_learning_cache_oversize_{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&tmp);

        // Write a file larger than the 16 MiB cap (17 MiB of spaces, which is
        // valid UTF-8 but exceeds the limit before JSON parsing even starts).
        {
            let mut f = fs::File::create(&tmp).unwrap();
            let chunk = vec![b' '; 64 * 1024];
            for _ in 0..(17 * 1024 * 1024 / chunk.len()) {
                f.write_all(&chunk).unwrap();
            }
            f.sync_all().unwrap();
        }

        // Must not panic; returns an empty cache.
        let cache = LearningCache::open(&tmp).expect("open must succeed (not Err) for oversize");
        assert!(
            cache.keys().is_empty(),
            "oversize cache must be treated as empty"
        );

        // Original path must have been moved aside (an .oversize-* sibling
        // should now exist in the temp dir).
        assert!(
            !tmp.exists(),
            "oversize file must be moved aside, not left at the original path"
        );

        // Cleanup any oversize-* sibling.
        if let Ok(entries) = fs::read_dir(tmp.parent().unwrap_or(std::path::Path::new("."))) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.starts_with(&format!(
                    "wafrift_learning_cache_oversize_{}.json.oversize",
                    std::process::id()
                )) {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
    }
}
