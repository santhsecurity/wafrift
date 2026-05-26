//! `wafrift bank` — list / export / import gene-banks.
//!
//! Practitioners share gene-banks across machines and teammates today
//! by copying JSON files by hand. This subcommand surfaces the
//! operations as first-class verbs so the workflow becomes:
//!
//!   * `wafrift bank list` — show every WAF / host with proven techniques.
//!   * `wafrift bank export --output bundle.json` — pack the proxy
//!     gene-bank + every per-WAF `GeneBank` into a single self-describing
//!     JSON envelope (`schema_version`, source paths, contents).
//!   * `wafrift bank import bundle.json` — restore an envelope onto
//!     this machine.

use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Args, Debug)]
pub struct BankArgs {
    #[command(subcommand)]
    pub action: BankAction,
}

#[derive(Subcommand, Debug)]
pub enum BankAction {
    /// List every WAF / host that has proven techniques recorded.
    List(BankListArgs),
    /// Export the entire local gene-bank corpus (proxy + per-WAF) into a single JSON file.
    Export(BankExportArgs),
    /// Restore a previously-exported envelope onto this machine.
    Import(BankImportArgs),
    /// Generate a fresh ed25519 signing keypair.
    GenKey(crate::bank_registry::GenKeyArgs),
    /// Sign a bank-export envelope.
    Sign(crate::bank_registry::SignArgs),
    /// Verify a `*.signed.json` against the trust list.
    Verify(crate::bank_registry::VerifyArgs),
    /// HTTP GET a signed bundle, verify, write to disk.
    Pull(crate::bank_registry::PullArgs),
    /// Sign a local envelope and HTTP POST to a registry URL.
    Submit(crate::bank_registry::SubmitArgs),
    /// Manage `~/.wafrift/trusted-keys.toml`.
    Trust(crate::bank_registry::TrustArgs),
}

#[derive(Args, Debug)]
pub struct BankListArgs {
    /// Output format: `text` (default, human-readable table) or `json`.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,
    /// Override the proxy gene-bank path. Default `~/.wafrift/gene-bank.json`.
    #[arg(long)]
    pub proxy_bank: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct BankExportArgs {
    /// Path to write the envelope JSON to. Use `-` for stdout.
    #[arg(long)]
    pub output: PathBuf,
    /// Override the proxy gene-bank path. Default `~/.wafrift/gene-bank.json`.
    #[arg(long)]
    pub proxy_bank: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct BankImportArgs {
    /// Path to an envelope JSON produced by `wafrift bank export`.
    /// Use `-` to read from stdin.
    pub input: PathBuf,
    /// Merge mode (default) keeps existing entries and adds new ones.
    /// Override with `--replace` to overwrite host/waf entries that
    /// already exist locally.
    #[arg(long, default_value_t = false)]
    pub replace: bool,
    /// Override the proxy gene-bank path. Default `~/.wafrift/gene-bank.json`.
    #[arg(long)]
    pub proxy_bank: Option<PathBuf>,
    /// Override the per-WAF genome dir. Default `~/.wafrift/genomes/`.
    #[arg(long)]
    pub genome_dir: Option<PathBuf>,
}

const ENVELOPE_SCHEMA_VERSION: u32 = 1;

/// Self-describing export envelope. The `source_paths` field is purely
/// informational — import never trusts the path data, only the
/// content. `wafrift_version` lets a future tool detect drift.
#[derive(Debug, Serialize, Deserialize)]
struct BankEnvelope {
    schema_version: u32,
    wafrift_version: String,
    /// Proxy gene-bank contents, indexed by host.
    proxy: PersistedGeneBank,
    /// Per-WAF genomes, indexed by normalised WAF name.
    waf_genomes: BTreeMap<String, serde_json::Value>,
    /// Original on-disk paths the export was produced from.
    /// Recorded so the operator can check provenance, not for restore.
    source_paths: SourcePaths,
}

#[derive(Debug, Serialize, Deserialize)]
struct SourcePaths {
    proxy_bank: String,
    genome_dir: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedHostState {
    #[serde(default)]
    proven_winners: Vec<String>,
    #[serde(default)]
    blocklisted: Vec<String>,
    #[serde(default)]
    waf_name: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedGeneBank {
    #[serde(default)]
    schema: u32,
    #[serde(default)]
    hosts: BTreeMap<String, PersistedHostState>,
}

pub fn run_bank(args: BankArgs) -> ExitCode {
    use crate::bank_registry;
    match args.action {
        BankAction::List(a) => run_list(a),
        BankAction::Export(a) => run_export(a),
        BankAction::Import(a) => run_import(a),
        BankAction::GenKey(a) => bank_registry::run(bank_registry::BankRegistryArgs {
            action: bank_registry::RegistryAction::GenKey(a),
        }),
        BankAction::Sign(a) => bank_registry::run(bank_registry::BankRegistryArgs {
            action: bank_registry::RegistryAction::Sign(a),
        }),
        BankAction::Verify(a) => bank_registry::run(bank_registry::BankRegistryArgs {
            action: bank_registry::RegistryAction::Verify(a),
        }),
        BankAction::Pull(a) => bank_registry::run(bank_registry::BankRegistryArgs {
            action: bank_registry::RegistryAction::Pull(a),
        }),
        BankAction::Submit(a) => bank_registry::run(bank_registry::BankRegistryArgs {
            action: bank_registry::RegistryAction::Submit(a),
        }),
        BankAction::Trust(a) => bank_registry::run(bank_registry::BankRegistryArgs {
            action: bank_registry::RegistryAction::Trust(a),
        }),
    }
}

fn default_proxy_bank() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".wafrift").join("gene-bank.json"))
}

fn default_genome_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".wafrift").join("genomes"))
}

fn read_proxy_bank(path: &std::path::Path) -> Result<PersistedGeneBank, String> {
    if !path.exists() {
        return Ok(PersistedGeneBank::default());
    }
    let raw = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    serde_json::from_str(&raw).map_err(|e| format!("parse {}: {e}", path.display()))
}

fn read_genome_dir(dir: &std::path::Path) -> Result<BTreeMap<String, serde_json::Value>, String> {
    let mut out = BTreeMap::new();
    if !dir.is_dir() {
        return Ok(out);
    }
    let entries = fs::read_dir(dir).map_err(|e| format!("read_dir {}: {e}", dir.display()))?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .map_or_else(|| "unknown".into(), std::string::ToString::to_string);
        let raw = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("warn: skip {}: {e}", path.display());
                continue;
            }
        };
        match serde_json::from_str::<serde_json::Value>(&raw) {
            Ok(v) => {
                out.insert(stem, v);
            }
            Err(e) => {
                eprintln!("warn: skip {} (parse error): {e}", path.display());
            }
        }
    }
    Ok(out)
}

fn run_list(args: BankListArgs) -> ExitCode {
    let proxy_path = args
        .proxy_bank
        .or_else(default_proxy_bank)
        .unwrap_or_else(|| PathBuf::from("gene-bank.json"));
    let genome_dir = match default_genome_dir() {
        Some(p) => p,
        None => {
            eprintln!("error: $HOME unset; cannot locate genome dir");
            return ExitCode::from(1);
        }
    };

    let proxy_bank = match read_proxy_bank(&proxy_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(1);
        }
    };
    let waf_genomes = match read_genome_dir(&genome_dir) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(1);
        }
    };

    if args.format == "json" {
        // Per perf-hunt N05: previously this output only the summary
        // counters; downstream automation (red-team scripts that
        // enumerate proven techniques before a scan) had nothing
        // actionable. Now emit a `hosts` array with per-host detail
        // matching the text path. Additive — no schema bump.
        let mut hosts: Vec<(&String, &PersistedHostState)> = proxy_bank
            .hosts
            .iter()
            .filter(|(_, hs)| !hs.proven_winners.is_empty())
            .collect();
        hosts.sort_by(|a, b| a.0.cmp(b.0));
        let host_array: Vec<serde_json::Value> = hosts
            .iter()
            .map(|(host, hs)| {
                serde_json::json!({
                    "host": host,
                    "winner_count": hs.proven_winners.len(),
                    "blocklisted_count": hs.blocklisted.len(),
                    "waf": hs.waf_name.as_deref().unwrap_or(""),
                })
            })
            .collect();
        let out = serde_json::json!({
            "schema_version": ENVELOPE_SCHEMA_VERSION,
            "wafrift_version": env!("CARGO_PKG_VERSION"),
            "proxy_bank_path": proxy_path.display().to_string(),
            "genome_dir": genome_dir.display().to_string(),
            "proxy_hosts_with_bypasses": host_array.len(),
            "waf_genome_count": waf_genomes.len(),
            "hosts": host_array,
        });
        // Pre-fix this used `unwrap_or_default()` which would emit
        // an EMPTY STRING on serialization failure — operator gets
        // `wafrift bank list --json` exit 0 with empty stdout,
        // downstream automation parses nothing as "no entries"
        // instead of "serialization failed." Surface the error.
        match serde_json::to_string_pretty(&out) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("error: serialize bank list JSON: {e}");
                return ExitCode::from(1);
            }
        }
        return ExitCode::SUCCESS;
    }

    println!("Proxy gene-bank ({})", proxy_path.display());
    let mut hosts: Vec<(&String, &PersistedHostState)> = proxy_bank
        .hosts
        .iter()
        .filter(|(_, hs)| !hs.proven_winners.is_empty())
        .collect();
    hosts.sort_by(|a, b| a.0.cmp(b.0));
    if hosts.is_empty() {
        println!("  (no hosts with proven bypasses)");
    } else {
        for (host, hs) in hosts {
            println!(
                "  {host}  ({} winner(s), {} blocklisted, waf={})",
                hs.proven_winners.len(),
                hs.blocklisted.len(),
                hs.waf_name.as_deref().unwrap_or("?")
            );
        }
    }

    println!();
    println!("Per-WAF genomes ({})", genome_dir.display());
    if waf_genomes.is_empty() {
        println!("  (no per-WAF genomes recorded)");
    } else {
        for waf in waf_genomes.keys() {
            println!("  {waf}");
        }
    }
    ExitCode::SUCCESS
}

fn run_export(args: BankExportArgs) -> ExitCode {
    let proxy_path = args
        .proxy_bank
        .or_else(default_proxy_bank)
        .unwrap_or_else(|| PathBuf::from("gene-bank.json"));
    let genome_dir = match default_genome_dir() {
        Some(p) => p,
        None => {
            eprintln!("error: $HOME unset");
            return ExitCode::from(1);
        }
    };
    let proxy = match read_proxy_bank(&proxy_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(1);
        }
    };
    let waf_genomes = match read_genome_dir(&genome_dir) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(1);
        }
    };

    let envelope = BankEnvelope {
        schema_version: ENVELOPE_SCHEMA_VERSION,
        wafrift_version: env!("CARGO_PKG_VERSION").to_string(),
        proxy,
        waf_genomes,
        source_paths: SourcePaths {
            proxy_bank: proxy_path.display().to_string(),
            genome_dir: genome_dir.display().to_string(),
        },
    };
    let json = match serde_json::to_string_pretty(&envelope) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: serialize envelope: {e}");
            return ExitCode::from(1);
        }
    };

    if args.output.to_str() == Some("-") {
        println!("{json}");
        return ExitCode::SUCCESS;
    }

    if let Some(parent) = args.output.parent()
        && !parent.as_os_str().is_empty()
        && let Err(e) = fs::create_dir_all(parent)
    {
        eprintln!("error: create output dir {}: {e}", parent.display());
        return ExitCode::from(1);
    }
    // Atomic write: tmp file → fsync → rename → parent fsync. Pre-fix
    // a power loss / signal mid-`fs::write` left the destination
    // truncated and the JSON invalid — silently destroying the only
    // off-host backup of the gene bank. seed.rs already uses this
    // helper for the same reason; keep behaviour consistent.
    if let Err(e) = wafrift_types::loaders::write_atomic(&args.output, json.as_bytes()) {
        eprintln!("error: write {}: {e}", args.output.display());
        return ExitCode::from(1);
    }
    eprintln!(
        "exported envelope ({} hosts, {} per-WAF genomes, {} bytes) → {}",
        envelope.proxy.hosts.len(),
        envelope.waf_genomes.len(),
        json.len(),
        args.output.display()
    );
    ExitCode::SUCCESS
}

fn run_import(args: BankImportArgs) -> ExitCode {
    let raw = if args.input.to_str() == Some("-") {
        use std::io::Read;
        let mut s = String::new();
        if let Err(e) = std::io::stdin().read_to_string(&mut s) {
            eprintln!("error: read stdin: {e}");
            return ExitCode::from(1);
        }
        s
    } else {
        match fs::read_to_string(&args.input) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error: read {}: {e}", args.input.display());
                return ExitCode::from(1);
            }
        }
    };
    let envelope: BankEnvelope = match serde_json::from_str(&raw) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error: parse envelope: {e}");
            return ExitCode::from(1);
        }
    };
    if envelope.schema_version != ENVELOPE_SCHEMA_VERSION {
        eprintln!(
            "warning: envelope schema_version={} but this wafrift expects {}; \
             field-by-field merge proceeds best-effort",
            envelope.schema_version, ENVELOPE_SCHEMA_VERSION
        );
    }

    let proxy_path = args
        .proxy_bank
        .or_else(default_proxy_bank)
        .unwrap_or_else(|| PathBuf::from("gene-bank.json"));
    let genome_dir = args
        .genome_dir
        .or_else(default_genome_dir)
        .unwrap_or_else(|| PathBuf::from("genomes"));

    // ── Proxy gene-bank merge ───────────────────────────────────────
    let mut current = match read_proxy_bank(&proxy_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(1);
        }
    };
    if current.schema == 0 {
        current.schema = 1;
    }
    let mut hosts_added = 0usize;
    let mut hosts_replaced = 0usize;
    for (host, incoming) in envelope.proxy.hosts {
        if let Some(existing) = current.hosts.get_mut(&host) {
            if args.replace {
                *existing = incoming;
                hosts_replaced += 1;
            } else {
                // Merge — union of proven_winners + blocklisted, prefer
                // existing waf_name.
                for t in incoming.proven_winners {
                    if !existing.proven_winners.contains(&t) {
                        existing.proven_winners.push(t);
                    }
                }
                for t in incoming.blocklisted {
                    if !existing.blocklisted.contains(&t) {
                        existing.blocklisted.push(t);
                    }
                }
                if existing.waf_name.is_none() && incoming.waf_name.is_some() {
                    existing.waf_name = incoming.waf_name;
                }
            }
        } else {
            current.hosts.insert(host, incoming);
            hosts_added += 1;
        }
    }
    if let Some(parent) = proxy_path.parent()
        && !parent.as_os_str().is_empty()
        && let Err(e) = fs::create_dir_all(parent)
    {
        eprintln!("error: create proxy-bank dir {}: {e}", parent.display());
        return ExitCode::from(1);
    }
    let proxy_json = match serde_json::to_string_pretty(&current) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: serialize proxy bank: {e}");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = fs::write(&proxy_path, &proxy_json) {
        eprintln!("error: write {}: {e}", proxy_path.display());
        return ExitCode::from(1);
    }

    // ── Per-WAF genome merge ────────────────────────────────────────
    if let Err(e) = fs::create_dir_all(&genome_dir) {
        eprintln!("error: create genome dir {}: {e}", genome_dir.display());
        return ExitCode::from(1);
    }
    let mut wafs_written = 0usize;
    for (waf, contents) in envelope.waf_genomes {
        let path = genome_dir.join(format!("{waf}.json"));
        if path.exists() && !args.replace {
            // Conservative default: don't overwrite a per-WAF genome
            // unless --replace, since per-WAF stats are
            // attempt-weighted and a naive merge would distort rates.
            continue;
        }
        let serialised = match serde_json::to_string_pretty(&contents) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("warn: skip {waf}: {e}");
                continue;
            }
        };
        if let Err(e) = fs::write(&path, &serialised) {
            eprintln!("warn: write {}: {e}", path.display());
            continue;
        }
        wafs_written += 1;
    }

    eprintln!(
        "import OK: proxy hosts +{hosts_added} new, {hosts_replaced} replaced; \
         per-WAF genomes {wafs_written} written to {}",
        genome_dir.display()
    );
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_envelope() -> String {
        let hs = PersistedHostState {
            proven_winners: vec!["EncodingUrl".into()],
            waf_name: Some("ModSec".into()),
            ..Default::default()
        };
        let mut hosts = BTreeMap::new();
        hosts.insert("api.example.com".to_string(), hs);

        let envelope = BankEnvelope {
            schema_version: ENVELOPE_SCHEMA_VERSION,
            wafrift_version: "0.0.0-test".into(),
            proxy: PersistedGeneBank { schema: 1, hosts },
            waf_genomes: BTreeMap::new(),
            source_paths: SourcePaths {
                proxy_bank: "/tmp/test-proxy.json".into(),
                genome_dir: "/tmp/test-genomes".into(),
            },
        };
        serde_json::to_string_pretty(&envelope).unwrap()
    }

    #[test]
    fn import_into_empty_creates_proxy_bank() {
        let dir = std::env::temp_dir().join(format!("wafrift-bank-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let envelope_path = dir.join("envelope.json");
        let proxy_path = dir.join("gene-bank.json");
        let genome_dir = dir.join("genomes");
        fs::write(&envelope_path, fixture_envelope()).unwrap();

        let code = run_import(BankImportArgs {
            input: envelope_path,
            replace: false,
            proxy_bank: Some(proxy_path.clone()),
            genome_dir: Some(genome_dir),
        });
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
        assert!(proxy_path.exists());

        let raw = fs::read_to_string(&proxy_path).unwrap();
        let bank: PersistedGeneBank = serde_json::from_str(&raw).unwrap();
        assert!(bank.hosts.contains_key("api.example.com"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn import_merge_unions_techniques_without_dupes() {
        let dir =
            std::env::temp_dir().join(format!("wafrift-bank-test-merge-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let proxy_path = dir.join("gene-bank.json");
        // Pre-existing entry with one technique.
        let pre = PersistedGeneBank {
            schema: 1,
            hosts: {
                let mut m = BTreeMap::new();
                let hs = PersistedHostState {
                    proven_winners: vec!["EncodingUrl".into(), "GrammarTautology".into()],
                    ..Default::default()
                };
                m.insert("api.example.com".into(), hs);
                m
            },
        };
        fs::write(&proxy_path, serde_json::to_string_pretty(&pre).unwrap()).unwrap();

        let envelope_path = dir.join("envelope.json");
        fs::write(&envelope_path, fixture_envelope()).unwrap();

        let code = run_import(BankImportArgs {
            input: envelope_path,
            replace: false,
            proxy_bank: Some(proxy_path.clone()),
            genome_dir: Some(dir.join("genomes")),
        });
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));

        let raw = fs::read_to_string(&proxy_path).unwrap();
        let bank: PersistedGeneBank = serde_json::from_str(&raw).unwrap();
        let entry = bank.hosts.get("api.example.com").unwrap();
        // EncodingUrl was already there → must NOT duplicate.
        let count = entry
            .proven_winners
            .iter()
            .filter(|t| *t == "EncodingUrl")
            .count();
        assert_eq!(
            count, 1,
            "EncodingUrl dedup failed: {:?}",
            entry.proven_winners
        );
        // GrammarTautology preserved from local.
        assert!(
            entry
                .proven_winners
                .contains(&"GrammarTautology".to_string())
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn import_replace_overwrites_existing_entry() {
        let dir =
            std::env::temp_dir().join(format!("wafrift-bank-test-replace-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let proxy_path = dir.join("gene-bank.json");
        let pre = PersistedGeneBank {
            schema: 1,
            hosts: {
                let mut m = BTreeMap::new();
                let hs = PersistedHostState {
                    proven_winners: vec!["LocalOnly".into()],
                    ..Default::default()
                };
                m.insert("api.example.com".into(), hs);
                m
            },
        };
        fs::write(&proxy_path, serde_json::to_string_pretty(&pre).unwrap()).unwrap();

        let envelope_path = dir.join("envelope.json");
        fs::write(&envelope_path, fixture_envelope()).unwrap();

        let code = run_import(BankImportArgs {
            input: envelope_path,
            replace: true,
            proxy_bank: Some(proxy_path.clone()),
            genome_dir: Some(dir.join("genomes")),
        });
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));

        let raw = fs::read_to_string(&proxy_path).unwrap();
        let bank: PersistedGeneBank = serde_json::from_str(&raw).unwrap();
        let entry = bank.hosts.get("api.example.com").unwrap();
        assert!(!entry.proven_winners.contains(&"LocalOnly".to_string()));
        assert!(entry.proven_winners.contains(&"EncodingUrl".to_string()));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn export_then_import_round_trip() {
        let dir = std::env::temp_dir().join(format!("wafrift-bank-test-rt-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let proxy_path = dir.join("gene-bank.json");
        let envelope_path = dir.join("envelope.json");
        let pre = PersistedGeneBank {
            schema: 1,
            hosts: {
                let mut m = BTreeMap::new();
                let hs = PersistedHostState {
                    proven_winners: vec!["A".into(), "B".into()],
                    waf_name: Some("Cloudflare".into()),
                    ..Default::default()
                };
                m.insert("h1.example.com".into(), hs);
                m
            },
        };
        fs::write(&proxy_path, serde_json::to_string_pretty(&pre).unwrap()).unwrap();

        // Export.
        let code = run_export(BankExportArgs {
            output: envelope_path.clone(),
            proxy_bank: Some(proxy_path.clone()),
        });
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
        assert!(envelope_path.exists());

        // Wipe target proxy bank, import.
        let restore_path = dir.join("restore.json");
        let code2 = run_import(BankImportArgs {
            input: envelope_path,
            replace: false,
            proxy_bank: Some(restore_path.clone()),
            genome_dir: Some(dir.join("genomes-restore")),
        });
        assert_eq!(format!("{code2:?}"), format!("{:?}", ExitCode::SUCCESS));

        let raw = fs::read_to_string(&restore_path).unwrap();
        let bank: PersistedGeneBank = serde_json::from_str(&raw).unwrap();
        let entry = bank.hosts.get("h1.example.com").expect("host restored");
        assert_eq!(entry.proven_winners, vec!["A", "B"]);
        assert_eq!(entry.waf_name.as_deref(), Some("Cloudflare"));
        let _ = fs::remove_dir_all(&dir);
    }
}
