//! Gene-bank persistence — load / save / restore the proxy's
//! per-host discovery state to disk across restarts.
//!
//! The proxy accumulates valuable discovery signal as it forwards
//! traffic: proven evasion winners per host, blocklisted techniques
//! the WAF reliably catches, identified WAF vendor names. Losing
//! that on every restart would force the operator to re-pay the
//! discovery cost every session — instead this module persists it
//! to `~/.wafrift/gene-bank.json` (or the operator-supplied path).
//!
//! Crash-safe writes via tempfile + fsync + rename + parent-dir
//! fsync. Concurrent writers from two proxy instances are handled
//! by per-writer PID + nanosecond tempfile names — the last rename
//! wins, matching the existing single-writer semantics.
//!
//! Schema-versioned for forward / backward compat: a v0.1 flat
//! HashMap genebank loads cleanly (auto-migrated to schema 1), a
//! future schema bump can be detected at load time.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::ProxyState;

/// Subset of `HostState` worth persisting across proxy restarts.
/// Block counts and pending discovery state re-accumulate naturally;
/// what we don't want to lose is the painstakingly-discovered winners
/// pool and the per-host blocklist.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PersistedHostState {
    pub proven_winners: Vec<String>,
    pub blocklisted: Vec<String>,
    pub waf_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PersistedGeneBank {
    /// Format version so future schema changes can be detected.
    pub schema: u32,
    pub hosts: HashMap<String, PersistedHostState>,
}

/// Resolve the operator's `--gene-bank` flag value to a concrete
/// path, or `None` to disable persistence. The default (empty
/// string) lands at `$HOME/.wafrift/gene-bank.json` when `$HOME` is
/// set; `off` / `-` disables explicitly.
#[must_use]
pub fn default_gene_bank_path(supplied: &str) -> Option<PathBuf> {
    if supplied.is_empty() {
        let home = std::env::var_os("HOME")?;
        let p = PathBuf::from(home).join(".wafrift").join("gene-bank.json");
        Some(p)
    } else if supplied == "off" || supplied == "-" {
        None
    } else {
        Some(PathBuf::from(supplied))
    }
}

/// Load the persisted gene bank from disk. Never errors — a missing
/// file returns an empty bank, a malformed file gets logged + a
/// fresh bank returned, an old v0.1 flat-HashMap file is auto-
/// migrated to schema 1. The "always succeed" contract is
/// deliberate: proxy startup must not be blocked by a corrupt
/// gene-bank.
pub fn load(path: &Path) -> PersistedGeneBank {
    match std::fs::read_to_string(path) {
        Ok(s) => {
            if s.trim().is_empty() {
                info!(path = %path.display(), "gene bank file is empty; starting fresh");
                return PersistedGeneBank::default();
            }
            match serde_json::from_str::<PersistedGeneBank>(&s) {
                Ok(bank) => {
                    if bank.schema > 1 {
                        warn!(
                            path = %path.display(),
                            schema = bank.schema,
                            "gene bank has newer schema than expected (1); data may be incomplete"
                        );
                    }
                    bank
                }
                Err(e) => {
                    // Backward-compat: v0.1 gene-bank was a flat HashMap without
                    // the schema wrapper. Don't discard a practitioner's saved
                    // discovery just because they upgraded from an older build.
                    if let Ok(flat) =
                        serde_json::from_str::<HashMap<String, PersistedHostState>>(&s)
                    {
                        warn!(
                            path = %path.display(),
                            "loaded v0.1 gene-bank (flat HashMap); migrating to schema 1"
                        );
                        return PersistedGeneBank {
                            schema: 1,
                            hosts: flat,
                        };
                    }
                    warn!(
                        path = %path.display(),
                        error = %e,
                        "gene bank malformed (invalid JSON); starting fresh. Fix: inspect the file and fix the JSON syntax, or delete it to start over."
                    );
                    PersistedGeneBank::default()
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            info!(path = %path.display(), "gene bank not found; starting fresh");
            PersistedGeneBank::default()
        }
        Err(e) => {
            warn!(
                path = %path.display(),
                error = %e,
                "gene bank unreadable; starting fresh. Fix: check file permissions."
            );
            PersistedGeneBank::default()
        }
    }
}

/// Snapshot the in-memory proxy state to disk via atomic-rename.
/// Returns an `io::Result` so the caller can decide whether to log,
/// retry, or escalate.
pub fn save(state: &ProxyState, path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut bank = PersistedGeneBank {
        schema: 1,
        hosts: HashMap::new(),
    };
    for (host, hs) in &state.hosts {
        // Persist any host where the proxy has accumulated discovery
        // signal — proven winners, blocklisted techniques, identified
        // WAF, OR observed blocks. The earlier "skip empty hosts to
        // keep the file small" rule dropped hosts with only
        // block-count telemetry, so a practitioner who left the proxy
        // running through 100 blocked attempts and then SIGTERM'd
        // would lose every bit of discovery progress on restart.
        // A host with non-zero blocks is a host worth remembering.
        if hs.proven_winners.is_empty()
            && hs.blocklisted.is_empty()
            && hs.waf_name.is_none()
            && hs.blocks == 0
        {
            continue; // truly empty — skip
        }
        bank.hosts.insert(
            host.clone(),
            PersistedHostState {
                proven_winners: hs.proven_winners.clone(),
                blocklisted: hs.blocklisted.clone(),
                waf_name: hs.waf_name.clone(),
            },
        );
    }
    let json = serde_json::to_string_pretty(&bank)?;
    // Atomic, durable write (tempfile + fsync + rename + parent
    // fsync) via the shared helper — same dance as
    // `strategy::gene_bank::write_genome` and `cli::seed`, lifted
    // to wafrift_types so the multi-writer tmp-suffix policy stays
    // in lock-step.
    wafrift_types::loaders::write_atomic(path, json.as_bytes())?;
    Ok(())
}

/// Restore persisted host states from disk into the in-memory proxy state.
///
/// # Concurrency safety
///
/// This function must be called while holding the `ProxyState` mutex.
/// In `main()` the load+restore is performed before the accept loop
/// begins, and the mutex is held for the entire operation, so no
/// request can interleave and create host entries during restore.
/// The `HashMap::entry` call would merge with (and partially
/// overwrite) any existing entry, which is why the atomic load+restore
/// under the lock matters.
pub fn restore(state: &mut ProxyState, bank: PersistedGeneBank) -> usize {
    let mut restored = 0usize;
    // Track FIFO membership in a HashSet — pre-fix this used
    // `host_fifo.contains(&host)` which is O(n) on VecDeque, so a
    // gene-bank with N hosts forced N² scans during restore. For
    // a corrupted-or-large bank (millions of hosts) the proxy
    // would take minutes to come up. The set is built once from
    // the existing fifo (typically empty on cold start) and kept
    // in lockstep with push_back.
    let mut fifo_seen: std::collections::HashSet<String> =
        state.host_fifo.iter().cloned().collect();
    for (host, persisted) in bank.hosts {
        let hs = state.hosts.entry(host.clone()).or_default();
        if !persisted.proven_winners.is_empty() {
            hs.proven_winners = persisted.proven_winners;
            hs.discovery_complete = true;
            restored += 1;
        }
        if !persisted.blocklisted.is_empty() {
            hs.blocklisted = persisted.blocklisted;
        }
        if persisted.waf_name.is_some() {
            hs.waf_name = persisted.waf_name;
            hs.waf_confirmed = true;
        }
        if fifo_seen.insert(host.clone()) {
            state.host_fifo.push_back(host);
        }
    }
    // Enforce the same runtime cap that applies during request processing.
    // A malicious or corrupted gene-bank with millions of hosts must not
    // exhaust proxy RAM on startup.
    while state.hosts.len() > 10_000 {
        if let Some(oldest) = state.host_fifo.pop_front() {
            state.hosts.remove(&oldest);
        } else {
            break;
        }
    }
    restored
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_path_off_returns_none() {
        assert_eq!(default_gene_bank_path("off"), None);
        assert_eq!(default_gene_bank_path("-"), None);
    }

    #[test]
    fn default_path_explicit_returns_pathbuf() {
        let p = default_gene_bank_path("/tmp/custom.json").expect("explicit ok");
        assert_eq!(p, PathBuf::from("/tmp/custom.json"));
    }

    #[test]
    fn load_missing_file_returns_empty_bank() {
        let path = std::env::temp_dir().join(format!(
            "wafrift-genebank-load-missing-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let bank = load(&path);
        assert_eq!(bank.schema, 0); // default
        assert!(bank.hosts.is_empty());
    }

    #[test]
    fn load_empty_file_returns_empty_bank() {
        let path = std::env::temp_dir().join(format!(
            "wafrift-genebank-load-empty-{}",
            std::process::id()
        ));
        std::fs::write(&path, "").unwrap();
        let bank = load(&path);
        assert!(bank.hosts.is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_v01_flat_format_migrates_to_schema_1() {
        let path =
            std::env::temp_dir().join(format!("wafrift-genebank-load-v01-{}", std::process::id()));
        // Pre-schema flat HashMap format — no `schema` field, no
        // `hosts` wrapper. The auto-migration must recognise this
        // shape and convert without dropping any host.
        let legacy = r#"{
            "example.com": {
                "proven_winners": ["encoding::Double"],
                "blocklisted": [],
                "waf_name": "Cloudflare"
            }
        }"#;
        std::fs::write(&path, legacy).unwrap();
        let bank = load(&path);
        assert_eq!(bank.schema, 1);
        let host = bank.hosts.get("example.com").expect("example.com migrated");
        assert_eq!(host.proven_winners, vec!["encoding::Double".to_string()]);
        assert_eq!(host.waf_name.as_deref(), Some("Cloudflare"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_malformed_json_returns_empty_bank_does_not_panic() {
        let path = std::env::temp_dir().join(format!(
            "wafrift-genebank-load-malformed-{}",
            std::process::id()
        ));
        std::fs::write(&path, "{ not valid json").unwrap();
        let bank = load(&path);
        assert!(bank.hosts.is_empty());
        let _ = std::fs::remove_file(&path);
    }
}
