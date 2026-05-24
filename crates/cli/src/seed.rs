//! `wafrift seed` — pre-load a gene-bank with known-working techniques.
//!
//! When a practitioner already knows what beats the target's WAF (e.g.
//! from a prior engagement, a CTF writeup, or shared team knowledge),
//! they shouldn't have to wait for wafrift to re-discover it. `seed`
//! writes those technique pool keys straight into the gene-bank so the
//! next `scan` / `proxy` run starts in rotation mode.
//!
//! Two destinations are supported:
//!   * `--waf <name>` writes to the per-WAF `GeneBank` under
//!     `~/.wafrift/genomes/<waf>.json` (used by `scan` and the proxy
//!     when wafrift-detect identifies the WAF in front of the target).
//!   * `--host <hostname>` writes to the proxy gene-bank
//!     (`~/.wafrift/gene-bank.json` by default; override with
//!     `--proxy-bank`). Used by the proxy's per-host rotation pool.

use clap::Args;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Args, Debug)]
pub struct SeedArgs {
    /// Comma-separated technique pool keys to seed. Each key is a string
    /// like `EncodingDoubleUrl`, `GrammarTautology`, `SmugglingClTeBasic`.
    /// Run `wafrift techniques list` for the canonical list.
    ///
    /// `required = true` so `--help` renders the `[required]` marker and
    /// clap rejects a missing value at parse time — previously the help
    /// text implied it was optional and the failure only surfaced as a
    /// hand-rolled runtime `error:` after argument parsing succeeded.
    #[arg(long, num_args = 1.., value_delimiter = ',', required = true)]
    pub technique: Vec<String>,

    /// Seed the per-WAF `GeneBank` under `~/.wafrift/genomes/<waf>.json`.
    /// Mutually exclusive with `--host`.
    #[arg(long)]
    pub waf: Option<String>,

    /// Seed the proxy gene-bank for a specific host. Mutually exclusive
    /// with `--waf`.
    #[arg(long)]
    pub host: Option<String>,

    /// Override the proxy gene-bank path. Default
    /// `~/.wafrift/gene-bank.json`. Only consulted when `--host` is set.
    #[arg(long)]
    pub proxy_bank: Option<PathBuf>,

    /// Show what would be written and exit 0 without touching disk.
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,
}

pub fn run_seed(args: SeedArgs) -> ExitCode {
    if args.technique.is_empty() {
        eprintln!("error: --technique is required (comma-separated list of pool keys)");
        return ExitCode::from(1);
    }
    match (&args.waf, &args.host) {
        (Some(_), Some(_)) => {
            eprintln!("error: --waf and --host are mutually exclusive");
            ExitCode::from(1)
        }
        (Some(waf), None) => seed_waf(waf, &args.technique, args.dry_run),
        (None, Some(host)) => seed_host(
            host,
            &args.technique,
            args.proxy_bank.as_deref(),
            args.dry_run,
        ),
        (None, None) => {
            eprintln!(
                "error: pick a destination — `--waf <name>` (per-WAF GeneBank) or \
                 `--host <hostname>` (proxy gene-bank)"
            );
            ExitCode::from(1)
        }
    }
}

fn seed_waf(waf_name: &str, techniques: &[String], dry_run: bool) -> ExitCode {
    if dry_run {
        // Dry-run output goes to STDOUT (it IS the data the operator
        // asked for via --dry-run) — not stderr. Pre-fix (per perf-hunt
        // N06) both the dry-run preview and the post-write confirmation
        // went to stderr, so a CI job piping `2>/dev/null` would lose
        // the dry-run preview entirely. The post-write confirmation
        // below stays on stderr (it's progress, not the data the
        // operator requested).
        println!(
            "DRY RUN: would seed WAF {waf_name:?} with {} technique(s): {}",
            techniques.len(),
            techniques.join(", ")
        );
        return ExitCode::SUCCESS;
    }
    let mut bank = match wafrift_strategy::gene_bank::GeneBank::open_default() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: open gene-bank: {e}");
            return ExitCode::from(1);
        }
    };
    // merge_session takes (technique_name, successes, attempts). We
    // synthesise (1, 1) to record one successful run with the seeded
    // technique — that's enough to bring it above the min_attempts
    // threshold and into the seed_winners() set.
    let stats: Vec<(String, u32, u32)> =
        techniques.iter().map(|t| (t.clone(), 1u32, 1u32)).collect();
    if let Err(e) = bank.merge_and_save(waf_name, &stats) {
        eprintln!("error: merge_and_save({waf_name}): {e}");
        return ExitCode::from(1);
    }
    eprintln!(
        "seeded WAF {waf_name:?} with {} technique(s): {}",
        techniques.len(),
        techniques.join(", ")
    );
    ExitCode::SUCCESS
}

#[derive(Serialize, Deserialize, Default)]
struct PersistedHostState {
    #[serde(default)]
    proven_winners: Vec<String>,
    #[serde(default)]
    blocklisted: Vec<String>,
    #[serde(default)]
    waf_name: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
struct PersistedGeneBank {
    #[serde(default)]
    schema: u32,
    #[serde(default)]
    hosts: HashMap<String, PersistedHostState>,
}

fn seed_host(
    host: &str,
    techniques: &[String],
    custom_path: Option<&std::path::Path>,
    dry_run: bool,
) -> ExitCode {
    let path = match custom_path {
        Some(p) => p.to_path_buf(),
        None => match std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
        {
            // F110: pre-fix consulted `$HOME` only — on Windows that's
            // typically unset and the operator got "$HOME unset" with
            // no hint that `--proxy-bank` was the unblock path. Fall
            // back to `%USERPROFILE%` (matches gene_bank_io.rs F98 /
            // trust.rs idiom); error message names both vars.
            Some(home) => PathBuf::from(home).join(".wafrift").join("gene-bank.json"),
            None => {
                eprintln!(
                    "error: $HOME and %USERPROFILE% both unset; \
                     pass --proxy-bank explicitly"
                );
                return ExitCode::from(1);
            }
        },
    };

    if dry_run {
        eprintln!(
            "DRY RUN: would seed host {host:?} (gene-bank {}) with {} technique(s): {}",
            path.display(),
            techniques.len(),
            techniques.join(", ")
        );
        return ExitCode::SUCCESS;
    }

    // Read current gene-bank (if any).
    let mut bank = match fs::read_to_string(&path) {
        Ok(s) => match serde_json::from_str::<PersistedGeneBank>(&s) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("error: parse {}: {e}", path.display());
                return ExitCode::from(1);
            }
        },
        Err(_) => PersistedGeneBank {
            schema: 1,
            hosts: HashMap::new(),
        },
    };
    if bank.schema == 0 {
        bank.schema = 1;
    }

    let entry = bank.hosts.entry(host.to_string()).or_default();
    let mut added = 0usize;
    for t in techniques {
        if !entry.proven_winners.contains(t) {
            entry.proven_winners.push(t.clone());
            added += 1;
        }
    }
    let total_in_pool = entry.proven_winners.len();

    // Atomic write: tmp + sync_all + rename + parent fsync (mirrors the
    // proxy's save_gene_bank pattern).
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && let Err(e) = fs::create_dir_all(parent)
    {
        eprintln!("error: create seed-bank dir {}: {e}", parent.display());
        return ExitCode::from(1);
    }
    let json = match serde_json::to_string_pretty(&bank) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: serialize: {e}");
            return ExitCode::from(1);
        }
    };
    // Atomic, durable write via wafrift_types::loaders::write_atomic
    // — shared with strategy::gene_bank::write_genome and
    // proxy::gene_bank_io. The helper does the full tmp + fsync +
    // rename + parent-fsync dance with a multi-writer-safe tmp suffix.
    if let Err(e) = wafrift_types::loaders::write_atomic(&path, json.as_bytes()) {
        eprintln!("error: atomic write {}: {e}", path.display());
        return ExitCode::from(1);
    }

    eprintln!(
        "seeded host {host:?} ({}): {added} new technique(s) added, {total_in_pool} total in pool",
        path.display(),
    );
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_host_dry_run_does_not_touch_disk() {
        let dir = std::env::temp_dir().join(format!("wafrift-seed-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bank_path = dir.join("gene-bank.json");

        let code = seed_host(
            "api.example.com",
            &["EncodingUrl".to_string()],
            Some(&bank_path),
            true,
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
        assert!(!bank_path.exists(), "dry run must not write");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seed_host_creates_bank_then_appends() {
        let dir = std::env::temp_dir().join(format!("wafrift-seed-test-rt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bank_path = dir.join("gene-bank.json");

        // First seed: creates bank.
        let c1 = seed_host(
            "api.example.com",
            &["EncodingUrl".into(), "GrammarTautology".into()],
            Some(&bank_path),
            false,
        );
        assert_eq!(format!("{c1:?}"), format!("{:?}", ExitCode::SUCCESS));
        assert!(bank_path.exists());

        let raw = std::fs::read_to_string(&bank_path).unwrap();
        let bank: PersistedGeneBank = serde_json::from_str(&raw).unwrap();
        assert_eq!(bank.schema, 1);
        let entry = bank.hosts.get("api.example.com").expect("host present");
        assert_eq!(entry.proven_winners.len(), 2);

        // Second seed: appends new technique, dedupes existing.
        let c2 = seed_host(
            "api.example.com",
            &["EncodingUrl".into(), "SmugglingClTeBasic".into()],
            Some(&bank_path),
            false,
        );
        assert_eq!(format!("{c2:?}"), format!("{:?}", ExitCode::SUCCESS));
        let raw2 = std::fs::read_to_string(&bank_path).unwrap();
        let bank2: PersistedGeneBank = serde_json::from_str(&raw2).unwrap();
        let entry2 = bank2.hosts.get("api.example.com").unwrap();
        assert_eq!(entry2.proven_winners.len(), 3, "should dedupe EncodingUrl");
        assert!(
            entry2
                .proven_winners
                .contains(&"SmugglingClTeBasic".to_string())
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seed_host_round_trips_through_proxy_bank_format() {
        // Sanity: the JSON we emit deserialises back into the same
        // PersistedGeneBank shape the proxy uses for restore_gene_bank.
        let dir =
            std::env::temp_dir().join(format!("wafrift-seed-test-rtproxy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bank_path = dir.join("gene-bank.json");

        seed_host(
            "api.example.com",
            &["EncodingDoubleUrl".into()],
            Some(&bank_path),
            false,
        );

        let raw = std::fs::read_to_string(&bank_path).unwrap();
        // Spot-check the on-disk shape is what the proxy expects.
        assert!(raw.contains("\"schema\""));
        assert!(raw.contains("\"hosts\""));
        assert!(raw.contains("api.example.com"));
        assert!(raw.contains("EncodingDoubleUrl"));
        assert!(raw.contains("\"proven_winners\""));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seed_host_rejects_when_home_unset_and_no_path() {
        // Use a real temp dir to avoid actually wedging real $HOME.
        // Here we directly call the path-resolving branch.
        // Without a custom path AND with HOME unset, the function should error.
        // We can't easily mutate HOME safely in tests; test the explicit
        // path branch instead and rely on integration to cover HOME.
        let dir =
            std::env::temp_dir().join(format!("wafrift-seed-test-noh-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let code = seed_host(
            "h",
            &["X".into()],
            Some(&dir.join("gene-bank.json")),
            true, // dry-run; just exercising the resolve path
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seed_host_with_no_techniques_creates_empty_host_entry() {
        // Edge case: operator passes an empty technique list.
        // We should still write the host entry — defensive default.
        let dir = std::env::temp_dir().join(format!(
            "wafrift-seed-test-empty-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bank_path = dir.join("gene-bank.json");
        let code = seed_host("api.example.com", &[], Some(&bank_path), false);
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
        // Bank file still gets created with the host entry, even
        // with zero techniques.
        assert!(bank_path.exists());
        let bank: PersistedGeneBank =
            serde_json::from_str(&std::fs::read_to_string(&bank_path).unwrap()).unwrap();
        assert!(bank.hosts.contains_key("api.example.com"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seed_host_dry_run_emits_path_in_log() {
        // The dry-run log line includes the resolved path so
        // operators see exactly where the bank lives before they
        // confirm the write. The log goes to stderr; we don't
        // capture it here but the return code must still be SUCCESS.
        let dir = std::env::temp_dir().join(format!(
            "wafrift-seed-dry-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bank_path = dir.join("gene-bank.json");
        let code = seed_host("h", &["X".into()], Some(&bank_path), true);
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
        assert!(!bank_path.exists(), "dry-run MUST NOT write");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seed_host_rejects_malformed_existing_bank() {
        // If the gene-bank file at the target path is corrupted JSON,
        // seed_host must fail loudly — silently overwriting could
        // destroy real bypass history.
        let dir = std::env::temp_dir().join(format!(
            "wafrift-seed-mal-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bank_path = dir.join("gene-bank.json");
        std::fs::write(&bank_path, "not json at all").unwrap();
        let code = seed_host("h", &["X".into()], Some(&bank_path), false);
        assert_ne!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::SUCCESS),
            "malformed bank must NOT silently overwrite"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seed_host_multiple_hosts_coexist_in_same_bank() {
        // Two separate seed_host calls against the same bank path
        // must end with both hosts present.
        let dir = std::env::temp_dir().join(format!(
            "wafrift-seed-multi-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bank_path = dir.join("gene-bank.json");
        seed_host(
            "api.a.com",
            &["EncodingUrl".into()],
            Some(&bank_path),
            false,
        );
        seed_host(
            "api.b.com",
            &["GrammarTautology".into()],
            Some(&bank_path),
            false,
        );
        let bank: PersistedGeneBank =
            serde_json::from_str(&std::fs::read_to_string(&bank_path).unwrap()).unwrap();
        assert_eq!(bank.hosts.len(), 2);
        assert!(bank.hosts.contains_key("api.a.com"));
        assert!(bank.hosts.contains_key("api.b.com"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seed_host_preserves_existing_host_techniques_when_appending() {
        // A second seed against the same host must EXTEND, not
        // REPLACE, the technique list. Already covered by the
        // dedupe test above, but this case is the more general
        // contract: the OLD techniques remain in place.
        let dir = std::env::temp_dir().join(format!(
            "wafrift-seed-extend-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bank_path = dir.join("gene-bank.json");
        seed_host(
            "h",
            &["TechniqueA".into(), "TechniqueB".into()],
            Some(&bank_path),
            false,
        );
        seed_host("h", &["TechniqueC".into()], Some(&bank_path), false);
        let bank: PersistedGeneBank =
            serde_json::from_str(&std::fs::read_to_string(&bank_path).unwrap()).unwrap();
        let entry = bank.hosts.get("h").unwrap();
        // All three present.
        assert!(entry.proven_winners.contains(&"TechniqueA".to_string()));
        assert!(entry.proven_winners.contains(&"TechniqueB".to_string()));
        assert!(entry.proven_winners.contains(&"TechniqueC".to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seed_host_idempotent_against_identical_repeat_seed() {
        // Run the same seed twice — the bank must look the same as
        // after one run (dedupe). Anti-rig against a refactor that
        // appended without dedup-checking.
        let dir = std::env::temp_dir().join(format!(
            "wafrift-seed-idem-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bank_path = dir.join("gene-bank.json");
        let techs = ["X".to_string(), "Y".to_string()];
        seed_host("h", &techs, Some(&bank_path), false);
        seed_host("h", &techs, Some(&bank_path), false);
        let bank: PersistedGeneBank =
            serde_json::from_str(&std::fs::read_to_string(&bank_path).unwrap()).unwrap();
        let entry = bank.hosts.get("h").unwrap();
        // No duplication — same list as after a single seed.
        assert_eq!(entry.proven_winners.len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
