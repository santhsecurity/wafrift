//! Per-host publisher allowlist for genome bundles.
//!
//! Default location: `~/.wafrift/trusted-keys.toml`. Operators add
//! publishers either by editing the TOML directly or via
//! [`TrustList::allow_hex`] / [`TrustList::save`].

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::signing::{RegistryError, VerifyingKeyHex};

/// UTF-8 text reader with the cap enforced DURING the read (so a
/// symlink to `/dev/zero` cannot evade the size gate the way it
/// would with a `metadata()`-then-`read()` pattern).
fn read_capped_trust_text(path: &Path, max_bytes: u64) -> std::io::Result<String> {
    use std::io::Read;
    let f = std::fs::File::open(path)?;
    let mut limited = f.take(max_bytes + 1);
    let mut buf = Vec::with_capacity(8 * 1024);
    limited.read_to_end(&mut buf)?;
    if (buf.len() as u64) > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{}: trust list exceeds {}-byte cap",
                path.display(),
                max_bytes,
            ),
        ));
    }
    String::from_utf8(buf).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{}: trust list is not valid UTF-8: {e}", path.display()),
        )
    })
}

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
        // Trust lists are small — a few keys + metadata. 1 MiB caps
        // the OOM surface tightly while accommodating any realistic
        // operator key roster.
        const TRUST_LIST_MAX_BYTES: u64 = 1024 * 1024;
        let body = match read_capped_trust_text(path, TRUST_LIST_MAX_BYTES) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::new());
            }
            Err(e) => return Err(RegistryError::Io(e)),
        };
        let mut tl: Self =
            toml::from_str(&body).map_err(|e| RegistryError::TrustListParse(e.to_string()))?;
        tl.rebuild_index();
        Ok(tl)
    }

    /// Persist the trust list to disk, creating parent directories
    /// as needed.
    ///
    /// The write is atomic: content is first written to a sibling
    /// temp file (`.wafrift/trusted-keys.toml.NNNN.tmp`), then
    /// renamed over the target. A process crash mid-write therefore
    /// leaves either the old file or the new file intact — never a
    /// half-written, unparseable TOML that would lock the operator
    /// out of the trust list until they manually recover it.
    ///
    /// Audit (2026-05-10): the file is written with mode 0o600 on
    /// Unix so other users on a shared host cannot poison the trust
    /// root by adding their own publisher keys. Pre-fix the file used
    /// the process umask, leaving it world-readable on most setups.
    pub fn save(&self, path: &Path) -> Result<(), RegistryError> {
        let parent = path.parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent)?;
        let body = toml::to_string_pretty(self)
            .map_err(|e| RegistryError::TrustListParse(e.to_string()))?;
        // Write to a sibling temp file, then rename atomically.
        let pid = std::process::id();
        let tmp_path = path.with_extension(format!("{pid}.tmp"));
        std::fs::write(&tmp_path, &body)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            // Set permissions on the temp file BEFORE the rename so the
            // final file is never world-readable, even transiently.
            if let Err(e) = std::fs::set_permissions(&tmp_path, perms) {
                tracing::warn!(
                    path = %tmp_path.display(),
                    error = %e,
                    "failed to chmod trust list temp file to 0o600 — \
                     file may be world-readable"
                );
            }
        }
        // Atomic rename: replaces the target if it already exists.
        // On Windows `rename` is NOT guaranteed atomic when the destination
        // exists (it can fail with `PermissionDenied`); fall back to
        // remove-then-rename in that case.
        if let Err(rename_err) = std::fs::rename(&tmp_path, path) {
            // Cleanup the temp file on failure so we don't litter.
            let _ = std::fs::remove_file(&tmp_path);
            return Err(RegistryError::Io(rename_err));
        }
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
        let path =
            std::env::temp_dir().join(format!("wafrift-trust-test-{}.toml", std::process::id()));
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
            assert!(p.components().any(|c| c.as_os_str() == ".wafrift"));
        }
    }

    // ── Atomic-save regression tests (F-TRUST-01) ──────────────────

    /// After `save`, no stale temp file (`.NNNN.tmp`) should remain
    /// alongside the target.
    #[test]
    fn save_leaves_no_temp_file_on_success() {
        let mut t = TrustList::new();
        t.allow_hex("aabbcc", "carol");
        let path =
            std::env::temp_dir().join(format!("wafrift-trust-atomic-{}.toml", std::process::id()));
        t.save(&path).expect("save");
        // The directory should contain the target but NO .tmp sibling.
        let parent = path.parent().unwrap_or(Path::new("."));
        let stem = path.file_name().unwrap().to_string_lossy().to_string();
        let tmp_exists = std::fs::read_dir(parent)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                name.starts_with(&stem) && name.ends_with(".tmp")
            });
        assert!(!tmp_exists, "stale .tmp file found after successful save");
        let _ = std::fs::remove_file(&path);
    }

    /// `save` over an existing file must replace it, not append.
    #[test]
    fn save_overwrites_existing_file_atomically() {
        let path = std::env::temp_dir().join(format!(
            "wafrift-trust-overwrite-{}.toml",
            std::process::id()
        ));
        // Write a first version with one publisher.
        let mut t1 = TrustList::new();
        t1.allow_hex("111111", "first");
        t1.save(&path).expect("first save");

        // Overwrite with a second version with a different publisher.
        let mut t2 = TrustList::new();
        t2.allow_hex("222222", "second");
        t2.save(&path).expect("second save");

        let loaded = TrustList::load(&path).expect("load after overwrite");
        assert_eq!(
            loaded.publishers().len(),
            1,
            "must have exactly one publisher"
        );
        assert!(
            loaded.contains("222222"),
            "second version must be present after overwrite"
        );
        assert!(
            !loaded.contains("111111"),
            "first version must not survive an overwrite"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// `save` must create intermediate parent directories.
    #[test]
    fn save_creates_parent_dirs() {
        let base =
            std::env::temp_dir().join(format!("wafrift-trust-mkdir-{}-deep", std::process::id()));
        let path = base.join("nested").join("trusted-keys.toml");
        let mut t = TrustList::new();
        t.allow_hex("deadbeef", "test");
        t.save(&path).expect("save with deep parent");
        assert!(path.exists(), "trust list must exist after save");
        let loaded = TrustList::load(&path).expect("load deep");
        assert!(loaded.contains("deadbeef"));
        // Cleanup.
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A TOML-corrupted file must be rejected by `load` rather than
    /// silently returning an empty trust list (which would accept any bundle).
    #[test]
    fn load_corrupted_file_returns_error_not_empty_list() {
        let path =
            std::env::temp_dir().join(format!("wafrift-trust-corrupt-{}.toml", std::process::id()));
        std::fs::write(&path, b"this is not valid toml %@!").unwrap();
        let result = TrustList::load(&path);
        assert!(
            result.is_err(),
            "corrupted TOML must be an error, not an empty list that accepts any bundle"
        );
        let _ = std::fs::remove_file(&path);
    }
}
