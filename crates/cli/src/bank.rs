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
#[cfg(test)]
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

/// Permit only safe filename chars in a WAF name pulled out of an
/// imported envelope. Pre-fix the name flowed unsanitised into
/// `genome_dir.join(format!("{waf}.json"))`, so an envelope with
/// `waf = "../../etc/cron.d/evil"` wrote OUTSIDE `genome_dir` to
/// any user-writable path. The validator runs BEFORE the path is
/// constructed and applies the same portable-filename alphabet as
/// `hunt_cmd::validate_campaign_id`.
fn validate_waf_name(waf: &str) -> Result<(), String> {
    if waf.is_empty() {
        return Err("empty WAF name".to_string());
    }
    if waf.len() > 128 {
        return Err(format!("WAF name is {} chars; maximum is 128", waf.len()));
    }
    if waf == "." || waf == ".." {
        return Err(format!("WAF name '{waf}' is reserved"));
    }
    if waf.starts_with('-') {
        return Err(format!("WAF name '{waf}' cannot start with '-'"));
    }
    for ch in waf.chars() {
        let ok = ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.';
        if !ok {
            return Err(format!(
                "WAF name '{waf}' contains invalid character {ch:?}; \
                 allowed: [A-Za-z0-9_-.]"
            ));
        }
    }
    Ok(())
}

#[derive(Args, Debug)]
pub(crate) struct BankArgs {
    #[command(subcommand)]
    pub action: BankAction,
}

#[derive(Subcommand, Debug)]
pub(crate) enum BankAction {
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
pub(crate) struct BankListArgs {
    /// Output format: `text` (default, human-readable table) or `json`.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,
    /// Override the proxy gene-bank path. Default `~/.wafrift/gene-bank.json`.
    #[arg(long)]
    pub proxy_bank: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub(crate) struct BankExportArgs {
    /// Path to write the envelope JSON to. Use `-` for stdout.
    #[arg(long)]
    pub output: PathBuf,
    /// Override the proxy gene-bank path. Default `~/.wafrift/gene-bank.json`.
    #[arg(long)]
    pub proxy_bank: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub(crate) struct BankImportArgs {
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

// R77 pass-21 §7 DEDUP: route through the canonical schema in
// `wafrift_types::gene_bank_io` so a future field addition / schema
// bump propagates to every consumer at compile-time. Pre-fix five
// crates each carried their own struct; cli::replay's was missing
// `schema`, `blocklisted`, and `waf_name` — silent narrowing.
use wafrift_types::gene_bank_io::{PersistedGeneBank, PersistedHostState};

pub(crate) fn run_bank(args: BankArgs) -> ExitCode {
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
    // §15 TOCTOU: read_bounded_text_file is one open()+read() — no symlink race.
    let raw =
        crate::safe_body::read_bounded_text_file(path, crate::safe_body::GENE_BANK_FILE_MAX_BYTES)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
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
        // §15 OOM / TOCTOU fix: use read_bounded_text_file instead of
        // fs::read_to_string — a single fd open+read, no stat() race, and
        // a hard byte cap prevents a crafted genome file from OOMing the CLI.
        let raw = match crate::safe_body::read_bounded_text_file(
            &path,
            crate::safe_body::GENE_BANK_FILE_MAX_BYTES,
        ) {
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
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
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
        // §15 OOM guard: unbounded stdin read would OOM on `cat /dev/zero | wafrift bank import -`.
        match crate::safe_body::read_bounded_text_stdin(crate::safe_body::GENE_BANK_FILE_MAX_BYTES)
        {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error: read stdin: {e}");
                return ExitCode::from(1);
            }
        }
    } else {
        match crate::safe_body::read_bounded_text_file(
            &args.input,
            crate::safe_body::GENE_BANK_FILE_MAX_BYTES,
        ) {
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
            // R48-I6 fix (dogfood pass 9): parse failure is an
            // input/validation error, exit 2 (clap convention).
            eprintln!("error: parse envelope: {e}");
            return ExitCode::from(2);
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
    let mut wafs_rejected = 0usize;
    for (waf, contents) in envelope.waf_genomes {
        if let Err(reason) = validate_waf_name(&waf) {
            // Pre-fix a malicious envelope with `waf` set to
            // `"../../etc/cron.d/evil"` wrote `<genome_dir>/../../etc/...`
            // — outside `genome_dir`. The validator rejects any
            // traversal / non-portable-filename character before the
            // path is ever constructed.
            eprintln!("warn: skip WAF entry {waf:?}: {reason}");
            wafs_rejected += 1;
            continue;
        }
        let path = genome_dir.join(format!("{waf}.json"));
        let serialised = match serde_json::to_string_pretty(&contents) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("warn: skip {waf}: {e}");
                continue;
            }
        };
        // R49 tail3 (CLAUDE.md §15 AUDIT/TOCTOU): the prior
        // exists() + fs::write was racy on shared NFS. Use
        // create_new(true) for the no-overwrite branch; --replace
        // keeps the legacy clobber semantic.
        let write_result = if args.replace {
            fs::write(&path, &serialised)
        } else {
            use std::io::Write;
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut f) => f.write_all(serialised.as_bytes()),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Conservative default: skip without --replace
                    // (per-WAF stats are attempt-weighted; naive
                    // merge distorts rates).
                    continue;
                }
                Err(e) => Err(e),
            }
        };
        if let Err(e) = write_result {
            eprintln!("warn: write {}: {e}", path.display());
            continue;
        }
        wafs_written += 1;
    }
    if wafs_rejected > 0 {
        eprintln!(
            "warn: rejected {wafs_rejected} WAF entries with unsafe names \
             (possible hostile envelope)"
        );
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
        // R77 pass-21 §7 DEDUP: canonical `PersistedGeneBank::hosts`
        // is `HashMap` (matches 4 of 5 prior consumers); was locally
        // `BTreeMap` here.
        let mut hosts = std::collections::HashMap::new();
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
                let mut m = HashMap::new();
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
                let mut m = HashMap::new();
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
                let mut m = HashMap::new();
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

    // ── Round 23: path traversal via WAF-name filename ───────────────

    #[test]
    fn validate_waf_name_accepts_real_wafs() {
        for name in [
            "Cloudflare",
            "AWS-WAF",
            "ModSecurity",
            "Imperva.SecureSphere",
            "azure_app_gw",
            "F5_BIG-IP",
            "ipfilter.v2",
            "a",
        ] {
            assert!(
                super::validate_waf_name(name).is_ok(),
                "real WAF name rejected: {name}"
            );
        }
    }

    #[test]
    fn validate_waf_name_rejects_traversal() {
        for bad in [
            "../../etc/cron.d/evil",
            "..",
            ".",
            "..\\\\windows\\\\system32",
            "/etc/passwd",
            "a/b",
            "a\\b",
            "name with spaces",
            "name\nwith\nnewlines",
            "name\0null",
            "",
        ] {
            assert!(
                super::validate_waf_name(bad).is_err(),
                "traversal/unsafe WAF name accepted: {bad:?}"
            );
        }
    }

    #[test]
    fn validate_waf_name_rejects_leading_dash() {
        assert!(super::validate_waf_name("-x").is_err());
        assert!(super::validate_waf_name("--evil").is_err());
    }

    #[test]
    fn malicious_envelope_cannot_escape_genome_dir() {
        // End-to-end: feed run_import an envelope whose waf_genomes
        // key escapes via "..". The validator must reject it and
        // refuse to create any file outside genome_dir.
        let parent = std::env::temp_dir().join(format!(
            "wafrift-bank-traversal-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&parent).expect("mkdir parent");
        let genome_dir = parent.join("genomes");
        let escape_target = parent.join("pwned.json");

        let envelope_json = serde_json::json!({
            "schema_version": ENVELOPE_SCHEMA_VERSION,
            "exported_at_unix": 0,
            "wafrift_version": "test",
            "proxy": { "schema": 1, "hosts": {} },
            "waf_genomes": {
                "../pwned": { "ok": true }
            },
            "source_paths": { "proxy_bank": "", "genome_dir": "" }
        });
        let envelope_path = parent.join("envelope.json");
        fs::write(&envelope_path, envelope_json.to_string()).expect("write envelope");

        let proxy_path = parent.join("proxy.json");
        let _ = fs::write(&proxy_path, r#"{"schema":1,"hosts":{}}"#);

        let args = BankImportArgs {
            input: envelope_path,
            proxy_bank: Some(proxy_path),
            genome_dir: Some(genome_dir.clone()),
            replace: true,
        };
        let _exit = run_import(args);

        // The validator rejects "../pwned" so neither
        // "<genome_dir>/../pwned.json" (= parent/pwned.json) nor
        // any sibling-of-genome-dir file may exist.
        assert!(
            !escape_target.exists(),
            "traversal target {} was written — validator failed",
            escape_target.display()
        );
        let _ = fs::remove_dir_all(&parent);
    }
}
