//! `wafrift report` — generate a pentest-ready markdown writeup from
//! the proxy gene bank.
//!
//! The proxy gene bank is a JSON ledger of which evasion technique
//! pools work against which hosts (plus identified WAF). For a
//! practitioner finishing an engagement, the natural artefact to deliver
//! is one markdown file per host (or one combined report), with every
//! finding paired with the exact `wafrift replay` command that
//! reproduces it. Report turns the ledger into that artefact in one
//! shot — no manual transcription.

use clap::Args;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Args, Debug)]
pub struct ReportArgs {
    /// Path to the proxy gene bank JSON. Repeatable: pass `--proxy-bank a.json
    /// --proxy-bank b.json` to merge multiple banks (engagement teams running
    /// several wafrift-proxies). Hosts are unioned; per-host proven_winners /
    /// blocklisted are unioned; the first non-null waf_name wins.
    /// Default (no flag) `~/.wafrift/gene-bank.json`.
    #[arg(long)]
    pub proxy_bank: Vec<PathBuf>,

    /// Restrict the report to hosts matching this glob (`*.example.com`).
    /// Repeatable / comma-separated. Empty = all hosts.
    #[arg(long, num_args = 1.., value_delimiter = ',')]
    pub only_host: Vec<String>,

    /// Write the markdown to this file instead of stdout.
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// Suggested target URL for replay commands (e.g. `https://api.example.com/search`).
    /// If omitted, replay snippets use `https://{host}/<PATH>` where `<PATH>` is a
    /// literal placeholder — it is printed verbatim and must be replaced by the
    /// operator with the actual endpoint path. Passing a target that literally
    /// contains `<PATH>` is allowed and will be reproduced as-is.
    #[arg(long)]
    pub target_template: Option<String>,

    /// Suggested param name for replay commands.
    #[arg(long, default_value = "q")]
    pub param: String,

    /// Suggested payload for replay commands. Quote-escape carefully.
    #[arg(long, default_value = "PAYLOAD-HERE")]
    pub payload: String,

    /// Output format. `markdown` (default) is the pentest-shaped writeup;
    /// `json` is a stable, machine-parseable surface for CI gating and
    /// downstream report tooling. Both honour `--only-host`.
    #[arg(long, default_value = "markdown", value_parser = ["markdown", "json"])]
    pub format: String,
}

/// Stable JSON shape for `--format json`. The schema_version field
/// mirrors `_wafrift/status` and lets downstream tools detect format
/// drift across wafrift releases.
#[derive(Serialize)]
struct JsonReport<'a> {
    schema_version: u32,
    wafrift_version: &'static str,
    source_schema: u32,
    total_hosts: usize,
    hosts_with_bypasses: usize,
    findings: Vec<JsonFinding<'a>>,
}

#[derive(Serialize)]
struct JsonFinding<'a> {
    host: &'a str,
    waf: Option<&'a str>,
    proven_techniques: &'a [String],
    blocklisted_techniques: &'a [String],
    replay_command: String,
}

const REPORT_SCHEMA_VERSION: u32 = 1;

#[derive(Deserialize, Debug, Default)]
struct PersistedHostState {
    #[serde(default)]
    proven_winners: Vec<String>,
    #[serde(default)]
    blocklisted: Vec<String>,
    #[serde(default)]
    waf_name: Option<String>,
}

#[derive(Deserialize, Debug, Default)]
struct PersistedGeneBank {
    #[serde(default)]
    schema: u32,
    #[serde(default)]
    hosts: HashMap<String, PersistedHostState>,
}

/// Union two banks: `dst` is mutated in place with the host union from `src`.
/// Per host: proven_winners and blocklisted are union-merged (preserving
/// dst's order, then appending unseen entries from src). The first non-null
/// waf_name wins. Schema becomes max(dst, src).
fn merge_banks(dst: &mut PersistedGeneBank, src: PersistedGeneBank) {
    dst.schema = dst.schema.max(src.schema);
    for (host, src_state) in src.hosts {
        let entry = dst
            .hosts
            .entry(host)
            .or_insert_with(PersistedHostState::default);
        for w in src_state.proven_winners {
            if !entry.proven_winners.contains(&w) {
                entry.proven_winners.push(w);
            }
        }
        for b in src_state.blocklisted {
            if !entry.blocklisted.contains(&b) {
                entry.blocklisted.push(b);
            }
        }
        if entry.waf_name.is_none() {
            entry.waf_name = src_state.waf_name;
        }
    }
}

pub fn run_report(args: ReportArgs) -> ExitCode {
    let paths = match resolve_paths(&args.proxy_bank) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("error: {msg}");
            return ExitCode::from(1);
        }
    };

    let mut merged = PersistedGeneBank::default();
    for path in &paths {
        let raw = match fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                eprintln!(
                    "error: gene bank not found: {}\n\n\
                     hint: the gene bank is created automatically by wafrift-proxy.\n\
                     Run `wafrift-proxy --listen 127.0.0.1:8080 --mitm` and browse\n\
                     through it, then re-run `wafrift report`.\n\
                     Or pass `--proxy-bank <path>` to use a specific file.",
                    path.display()
                );
                return ExitCode::from(1);
            }
            Err(e) => {
                eprintln!("error: read {}: {e}", path.display());
                return ExitCode::from(1);
            }
        };
        let bank: PersistedGeneBank = match serde_json::from_str(&raw) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("error: parse {}: {e}", path.display());
                return ExitCode::from(1);
            }
        };
        merge_banks(&mut merged, bank);
    }
    let bank = merged;

    let mut hosts: Vec<(&String, &PersistedHostState)> = bank
        .hosts
        .iter()
        .filter(|(name, hs)| {
            !hs.proven_winners.is_empty()
                && (args.only_host.is_empty()
                    || args.only_host.iter().any(|p| host_matches(p, name)))
        })
        .collect();
    hosts.sort_by(|a, b| a.0.cmp(b.0));

    let body = match args.format.as_str() {
        "json" => match render_json(&bank, &hosts, &args) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error: serialize json: {e}");
                return ExitCode::from(1);
            }
        },
        _ => render_markdown(&bank, &hosts, &args),
    };

    match args.output.as_ref() {
        Some(p) => match fs::write(p, &body) {
            Ok(()) => {
                eprintln!(
                    "wrote {} report ({} hosts, {} bytes) → {}",
                    args.format,
                    hosts.len(),
                    body.len(),
                    p.display()
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: write {}: {e}", p.display());
                ExitCode::from(1)
            }
        },
        None => {
            print!("{body}");
            // JSON consumers expect a trailing newline; markdown already
            // provides its own.
            if args.format == "json" {
                println!();
            }
            ExitCode::SUCCESS
        }
    }
}

fn render_json(
    bank: &PersistedGeneBank,
    hosts: &[(&String, &PersistedHostState)],
    args: &ReportArgs,
) -> Result<String, serde_json::Error> {
    let findings: Vec<JsonFinding<'_>> = hosts
        .iter()
        .map(|(name, hs)| {
            let target = args
                .target_template
                .clone()
                .unwrap_or_else(|| format!("https://{name}/<PATH>"));
            let replay_command = format!(
                "wafrift replay --target '{target}' --param {param} --payload '{payload}' --from-host '{name}'",
                target = shell_escape(&target),
                param = args.param,
                payload = shell_escape(&args.payload),
                name = shell_escape(name),
            );
            JsonFinding {
                host: name.as_str(),
                waf: hs.waf_name.as_deref(),
                proven_techniques: &hs.proven_winners,
                blocklisted_techniques: &hs.blocklisted,
                replay_command,
            }
        })
        .collect();
    let report = JsonReport {
        schema_version: REPORT_SCHEMA_VERSION,
        wafrift_version: env!("CARGO_PKG_VERSION"),
        source_schema: bank.schema,
        total_hosts: bank.hosts.len(),
        hosts_with_bypasses: hosts.len(),
        findings,
    };
    serde_json::to_string_pretty(&report)
}

fn render_markdown(
    bank: &PersistedGeneBank,
    hosts: &[(&String, &PersistedHostState)],
    args: &ReportArgs,
) -> String {
    let mut out = String::new();
    out.push_str("# wafrift findings report\n\n");
    out.push_str(&format!(
        "Source: proxy gene bank schema v{} · {} host(s) with bypasses · {} host(s) total\n\n",
        bank.schema,
        hosts.len(),
        bank.hosts.len()
    ));

    if hosts.is_empty() {
        out.push_str("_No bypasses recorded yet — run wafrift-proxy in front of a target so it can learn._\n");
        return out;
    }

    out.push_str("## Summary\n\n");
    out.push_str("| Host | WAF | Proven techniques | Blocklisted |\n");
    out.push_str("|------|-----|-------------------|-------------|\n");
    for (name, hs) in hosts {
        out.push_str(&format!(
            "| `{}` | {} | {} | {} |\n",
            name,
            hs.waf_name.as_deref().unwrap_or("-"),
            hs.proven_winners.len(),
            hs.blocklisted.len()
        ));
    }
    out.push('\n');

    out.push_str("## Findings\n\n");
    for (name, hs) in hosts {
        out.push_str(&format!("### `{name}`\n\n"));
        if let Some(waf) = &hs.waf_name {
            out.push_str(&format!("**Identified WAF:** {waf}\n\n"));
        }
        out.push_str(&format!(
            "**Bypass count:** {} proven technique(s)\n\n",
            hs.proven_winners.len()
        ));

        out.push_str("**Working techniques:**\n\n");
        for t in &hs.proven_winners {
            out.push_str(&format!("- `{t}`\n"));
        }
        out.push('\n');

        if !hs.blocklisted.is_empty() {
            out.push_str("**Techniques the WAF reliably blocks** (do not use):\n\n");
            for t in &hs.blocklisted {
                out.push_str(&format!("- `{t}`\n"));
            }
            out.push('\n');
        }

        let target = args
            .target_template
            .clone()
            .unwrap_or_else(|| format!("https://{name}/<PATH>"));
        out.push_str("**Reproduce:**\n\n```sh\n");
        out.push_str(&format!(
            "wafrift replay \\\n  --target '{target}' \\\n  --param {param} \\\n  --payload '{payload}' \\\n  --from-host '{name}'\n",
            target = shell_escape(&target),
            param = args.param,
            payload = shell_escape(&args.payload),
            name = shell_escape(name),
        ));
        out.push_str("```\n\n");
    }

    out.push_str("## Methodology\n\n");
    out.push_str(
        "Each \"bypass\" entry above is a technique pool that produced a non-blocked HTTP \
         response (status not in 403/406 and no WAF-block body fragments) against the target \
         host while wafrift-proxy was in front of the practitioner's HTTP client. Replay the \
         finding via `wafrift replay --from-host <host>` to reproduce on demand.\n\n",
    );
    out.push_str(
        "Authorisation: only run replay against hosts you own or have explicit written \
         authorisation to test. The proxy will refuse private/loopback/RFC1918 destinations \
         unless `--allow-private-upstream` is set.\n",
    );
    out
}

fn host_matches(pattern: &str, host: &str) -> bool {
    // Tiny ASCII glob grammar — `*` matches any run, `?` matches one
    // byte, case-insensitive literal otherwise. Same semantics as the
    // proxy's `--only-host` matcher; intentionally duplicated rather
    // than depending on the proxy crate from the CLI.
    glob_match(pattern, host)
}

fn glob_match(pattern: &str, s: &str) -> bool {
    glob_recurse(pattern.as_bytes(), s.as_bytes())
}

fn glob_recurse(p: &[u8], s: &[u8]) -> bool {
    match (p.first(), s.first()) {
        (None, None) => true,
        (Some(b'*'), _) => glob_recurse(&p[1..], s) || (!s.is_empty() && glob_recurse(p, &s[1..])),
        (Some(b'?'), Some(_)) => glob_recurse(&p[1..], &s[1..]),
        (Some(a), Some(b)) if a.eq_ignore_ascii_case(b) => glob_recurse(&p[1..], &s[1..]),
        _ => false,
    }
}

fn shell_escape(s: &str) -> String {
    // Single-quote escape for sh: replace ' with '\''.
    s.replace('\'', "'\\''")
}

fn resolve_paths(custom: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    if !custom.is_empty() {
        return Ok(custom.to_vec());
    }
    let home = std::env::var_os("HOME")
        .ok_or_else(|| "$HOME not set; pass --proxy-bank explicitly".to_string())?;
    Ok(vec![
        PathBuf::from(home).join(".wafrift").join("gene-bank.json"),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_bank() -> PersistedGeneBank {
        let mut hosts = HashMap::new();
        hosts.insert(
            "api.example.com".into(),
            PersistedHostState {
                proven_winners: vec!["EncodingUrl".into(), "GrammarTautology".into()],
                blocklisted: vec!["XssTagScript".into()],
                waf_name: Some("ModSecurity-CRS".into()),
            },
        );
        hosts.insert(
            "no-finds.example.com".into(),
            PersistedHostState {
                proven_winners: vec![],
                blocklisted: vec![],
                waf_name: None,
            },
        );
        PersistedGeneBank { schema: 1, hosts }
    }

    #[test]
    fn report_omits_hosts_with_no_bypasses() {
        let bank = fake_bank();
        let hosts: Vec<_> = bank
            .hosts
            .iter()
            .filter(|(_, hs)| !hs.proven_winners.is_empty())
            .collect();
        let args = ReportArgs {
            proxy_bank: vec![],
            only_host: vec![],
            output: None,
            target_template: None,
            param: "q".into(),
            payload: "x".into(),
            format: "markdown".into(),
        };
        let md = render_markdown(&bank, &hosts, &args);
        assert!(md.contains("api.example.com"));
        assert!(!md.contains("no-finds.example.com"));
        assert!(md.contains("ModSecurity-CRS"));
        assert!(md.contains("EncodingUrl"));
        assert!(md.contains("XssTagScript"));
        assert!(md.contains("wafrift replay"));
    }

    #[test]
    fn shell_escape_handles_single_quote() {
        assert_eq!(shell_escape("a'b"), "a'\\''b");
    }

    #[test]
    fn shell_escape_roundtrips_through_bash() {
        // Every printable ASCII character plus some Unicode.
        let inputs = [
            "hello world",
            "it's working",
            "'\''",
            "foo;bar|baz",
            "$(danger)",
            "`backtick`",
            "emoji: 🚀",
        ];
        for raw in &inputs {
            let escaped = shell_escape(raw);
            let script = format!("echo '{}'", escaped);
            let output = std::process::Command::new("bash")
                .arg("-c")
                .arg(&script)
                .output()
                .expect("bash must be available");
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert_eq!(
                stdout.trim_end(),
                *raw,
                "shell_escape round-trip failed for {raw:?}: script={script:?}"
            );
        }
    }

    #[test]
    fn host_matches_glob_pattern() {
        assert!(host_matches("*.example.com", "api.example.com"));
        assert!(!host_matches("*.example.com", "elsewhere.tld"));
    }

    #[test]
    fn report_with_no_findings_uses_friendly_empty_state() {
        let bank = PersistedGeneBank {
            schema: 1,
            hosts: HashMap::new(),
        };
        let args = ReportArgs {
            proxy_bank: vec![],
            only_host: vec![],
            output: None,
            target_template: None,
            param: "q".into(),
            payload: "x".into(),
            format: "markdown".into(),
        };
        let md = render_markdown(&bank, &[], &args);
        assert!(md.contains("No bypasses recorded yet"));
    }

    #[test]
    fn json_format_emits_stable_schema() {
        let bank = fake_bank();
        let mut hosts: Vec<_> = bank
            .hosts
            .iter()
            .filter(|(_, hs)| !hs.proven_winners.is_empty())
            .collect();
        hosts.sort_by(|a, b| a.0.cmp(b.0));
        let args = ReportArgs {
            proxy_bank: vec![],
            only_host: vec![],
            output: None,
            target_template: None,
            param: "q".into(),
            payload: "x".into(),
            format: "json".into(),
        };
        let json = render_json(&bank, &hosts, &args).expect("json must serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        // Stable top-level keys.
        assert_eq!(parsed["schema_version"], REPORT_SCHEMA_VERSION);
        assert_eq!(parsed["source_schema"], 1);
        assert_eq!(parsed["total_hosts"], 2);
        assert_eq!(parsed["hosts_with_bypasses"], 1);
        // Finding payload.
        let findings = parsed["findings"].as_array().expect("findings array");
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f["host"], "api.example.com");
        assert_eq!(f["waf"], "ModSecurity-CRS");
        assert_eq!(f["proven_techniques"][0], "EncodingUrl");
        assert_eq!(f["blocklisted_techniques"][0], "XssTagScript");
        // Replay command must round-trip the host literally.
        let cmd = f["replay_command"].as_str().expect("replay_command string");
        assert!(cmd.contains("--from-host 'api.example.com'"));
        assert!(cmd.contains("--target 'https://api.example.com/<PATH>'"));
    }

    #[test]
    fn json_format_serializes_empty_findings_array() {
        // No bypasses: findings must be [], not null. Downstream tooling
        // that does `len(findings)` would crash on null.
        let bank = PersistedGeneBank {
            schema: 1,
            hosts: HashMap::new(),
        };
        let args = ReportArgs {
            proxy_bank: vec![],
            only_host: vec![],
            output: None,
            target_template: None,
            param: "q".into(),
            payload: "x".into(),
            format: "json".into(),
        };
        let json = render_json(&bank, &[], &args).expect("json must serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert!(parsed["findings"].is_array());
        assert_eq!(parsed["findings"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn merge_banks_unions_hosts_and_techniques() {
        // bank A: api.example.com with WAF + one winner
        let mut a_hosts = HashMap::new();
        a_hosts.insert(
            "api.example.com".into(),
            PersistedHostState {
                proven_winners: vec!["EncodingUrl".into()],
                blocklisted: vec!["XssTagScript".into()],
                waf_name: Some("ModSecurity".into()),
            },
        );
        let mut a = PersistedGeneBank {
            schema: 1,
            hosts: a_hosts,
        };

        // bank B: same host with a different winner + new host
        let mut b_hosts = HashMap::new();
        b_hosts.insert(
            "api.example.com".into(),
            PersistedHostState {
                proven_winners: vec!["EncodingUrl".into(), "GrammarTautology".into()],
                blocklisted: vec!["CmdSubshell".into()],
                waf_name: None,
            },
        );
        b_hosts.insert(
            "edge.example.com".into(),
            PersistedHostState {
                proven_winners: vec!["HeaderHostShard".into()],
                blocklisted: vec![],
                waf_name: Some("Cloudflare".into()),
            },
        );
        let b = PersistedGeneBank {
            schema: 2,
            hosts: b_hosts,
        };

        merge_banks(&mut a, b);

        // schema becomes max
        assert_eq!(a.schema, 2);
        // host union
        assert_eq!(a.hosts.len(), 2);
        assert!(a.hosts.contains_key("edge.example.com"));
        // techniques unioned + dedup'd, dst order preserved then src appended
        let api = a.hosts.get("api.example.com").unwrap();
        assert_eq!(
            api.proven_winners,
            vec!["EncodingUrl".to_string(), "GrammarTautology".to_string()]
        );
        assert_eq!(
            api.blocklisted,
            vec!["XssTagScript".to_string(), "CmdSubshell".to_string()]
        );
        // first non-null waf_name wins (dst's ModSecurity beats src's None)
        assert_eq!(api.waf_name.as_deref(), Some("ModSecurity"));
        // edge picked up Cloudflare from src since dst had no entry
        let edge = a.hosts.get("edge.example.com").unwrap();
        assert_eq!(edge.waf_name.as_deref(), Some("Cloudflare"));
    }
}
