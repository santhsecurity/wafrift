//! Per-host publisher allowlist for genome bundles.
//!
//! Default location: `~/.wafrift/trusted-keys.toml`. Operators add
//! publishers either by editing the TOML directly or via
//! [`TrustList::allow_hex`] / [`TrustList::save`].

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::signing::{RegistryError, VerifyingKeyHex};

/// One trusted publisher.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Publisher {
    pub name: String,
    pub public_key_hex: VerifyingKeyHex,
    /// Optional free-form note (URL, contact, source).
    #[serde(default)]
    pub note: String,
}

/// In-memory trust list.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TrustList {
    #[serde(default, rename = "publishers")]
    publishers: Vec<Publisher>,
    #[serde(skip)]
    by_key: HashMap<VerifyingKeyHex, usize>,
}

impl TrustList {
    /// Empty trust list — every bundle will be rejected as untrusted.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a publisher by hex-encoded public key.
    pub fn allow_hex(&mut self, public_key_hex: &str, name: &str) {
        let lower = public_key_hex.to_ascii_lowercase();
        if self.by_key.contains_key(&lower) {
            return;
        }
        let idx = self.publishers.len();
        self.publishers.push(Publisher {
            name: name.to_string(),
            public_key_hex: lower.clone(),
            note: String::new(),
        });
        self.by_key.insert(lower, idx);
    }

    /// Drop a publisher by hex public key. Idempotent.
    pub fn revoke_hex(&mut self, public_key_hex: &str) {
        let lower = public_key_hex.to_ascii_lowercase();
        self.publishers.retain(|p| p.public_key_hex != lower);
        self.rebuild_index();
    }

    fn rebuild_index(&mut self) {
        self.by_key.clear();
        for (i, p) in self.publishers.iter().enumerate() {
            self.by_key.insert(p.public_key_hex.clone(), i);
        }
    }

    /// True if `public_key_hex` is in the allowlist (case-insensitive).
    #[must_use]
    pub fn contains(&self, public_key_hex: &str) -> bool {
        let lower = public_key_hex.to_ascii_lowercase();
        self.by_key.contains_key(&lower)
    }

    pub fn publishers(&self) -> &[Publisher] {
        &self.publishers
    }

    /// Default trust-list path: `$HOME/.wafrift/trusted-keys.toml` on
    /// Unix, `%USERPROFILE%\.wafrift\trusted-keys.toml` on Windows.
    /// Returns `None` if no home directory is available.
    #[must_use]
    pub fn default_path() -> Option<PathBuf> {
        std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(|h| PathBuf::from(h).join(".wafrift").join("trusted-keys.toml"))
    }

    /// Load from a file. Missing file → empty trust list (not an error).
    pub fn load(path: &Path) -> Result<Self, RegistryError> {
        let body = match std::fs::read_to_string(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::new());
            }
            Err(e) => return Err(RegistryError::Io(e)),
        };
        let mut tl: Self = toml::from_str(&body)
            .map_err(|e| RegistryError::TrustListParse(e.to_string()))?;
        tl.rebuild_index();
        Ok(tl)
    }

    /// Persist the trust list to disk, creating parent directories
    /// as needed.
    pub fn save(&self, path: &Path) -> Result<(), RegistryError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let body = toml::to_string_pretty(self)
            .map_err(|e| RegistryError::TrustListParse(e.to_string()))?;
        std::fs::write(path, body)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_trust_list_contains_nothing() {
        let t = TrustList::new();
        assert!(!t.contains("abc"));
        assert!(t.publishers().is_empty());
    }

    #[test]
    fn allow_hex_registers_publisher() {
        let mut t = TrustList::new();
        t.allow_hex("ABCDEF", "alice");
        assert!(t.contains("abcdef"), "case-insensitive lookup");
        assert!(t.contains("ABCDEF"), "uppercase still matches");
        assert_eq!(t.publishers().len(), 1);
        assert_eq!(t.publishers()[0].name, "alice");
    }

    #[test]
    fn allow_hex_is_idempotent_for_repeat_keys() {
        let mut t = TrustList::new();
        t.allow_hex("abc", "alice");
        t.allow_hex("abc", "alice-again");
        assert_eq!(t.publishers().len(), 1, "repeat allow must not duplicate");
    }

    #[test]
    fn revoke_drops_publisher() {
        let mut t = TrustList::new();
        t.allow_hex("abc", "alice");
        t.allow_hex("def", "bob");
        t.revoke_hex("abc");
        assert!(!t.contains("abc"));
        assert!(t.contains("def"));
        assert_eq!(t.publishers().len(), 1);
    }

    #[test]
    fn save_then_load_round_trip() {
        let mut t = TrustList::new();
        t.allow_hex("abc", "alice");
        t.allow_hex("def", "bob");
        let path = std::env::temp_dir()
            .join(format!("wafrift-trust-test-{}.toml", std::process::id()));
        t.save(&path).expect("save");
        let loaded = TrustList::load(&path).expect("load");
        assert_eq!(loaded.publishers().len(), 2);
        assert!(loaded.contains("abc"));
        assert!(loaded.contains("def"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_missing_file_returns_empty_trust_list() {
        let path = std::env::temp_dir().join("wafrift-trust-missing-XYZ.toml");
        let _ = std::fs::remove_file(&path);
        let t = TrustList::load(&path).expect("missing-as-empty");
        assert!(t.publishers().is_empty());
    }

    #[test]
    fn default_path_uses_home_subdir() {
        // Don't mutate the process env (forbid(unsafe_code) blocks
        // set_var on 2024 edition). Just assert the suffix and the
        // .wafrift segment when default_path returns Some.
        if let Some(p) = TrustList::default_path() {
            assert!(p.ends_with("trusted-keys.toml"));
            assert!(p
                .components()
                .any(|c| c.as_os_str() == ".wafrift"));
        }
    }
}
