//! Learning cache — persistent per-WAF, per-payload-type pipeline memory.
//!
//! After a successful bypass, the winning pipeline is cached to disk
//! and re-used on subsequent scans of the same WAF + payload type.

use crate::pipeline::EvasionPipeline;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
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
    /// # Errors
    ///
    /// Returns an error if the file cannot be read.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LearningCacheError> {
        let path = path.as_ref();
        if path.exists() {
            let contents = fs::read_to_string(path).map_err(LearningCacheError::Io)?;
            let mut cache: LearningCache =
                serde_json::from_str(&contents).map_err(LearningCacheError::Serde)?;
            cache.path = Some(path.to_path_buf());
            Ok(cache)
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
    pub fn record_success(&mut self, key: CacheKey, pipeline: EvasionPipeline) {
        let now = current_epoch();
        let entry = self
            .entries
            .entry(cache_key_str(&key))
            .or_insert(CacheEntry {
                pipeline,
                successes: 0,
                attempts: 0,
                last_success_epoch: 0,
            });
        entry.successes = entry.successes.saturating_add(1);
        entry.attempts = entry.attempts.saturating_add(1);
        entry.last_success_epoch = now;
    }

    /// Record a failed attempt.
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

    /// Persist the cache to disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written.
    pub fn save(&self) -> Result<(), LearningCacheError> {
        let path = self.path.as_ref().ok_or(LearningCacheError::NoPath)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(LearningCacheError::Io)?;
        }
        let json = serde_json::to_string_pretty(self).map_err(LearningCacheError::Serde)?;
        fs::write(path, json).map_err(LearningCacheError::Io)
    }

    /// All cached keys.
    #[must_use]
    pub fn keys(&self) -> Vec<CacheKey> {
        self.entries
            .keys()
            .filter_map(|s| serde_json::from_str(s).ok())
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
}
