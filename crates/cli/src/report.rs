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
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use crate::helpers::shell_single_quote;
use crate::raw_request::RawRequest;

#[derive(Args, Debug)]
pub struct ReportArgs {
    /// Path to the proxy gene bank JSON. Repeatable: pass `--proxy-bank a.json
    /// --proxy-bank b.json` to merge multiple banks (engagement teams running
    /// several wafrift-proxies). Hosts are unioned; per-host `proven_winners` /
    /// blocklisted are unioned; the first non-null `waf_name` wins.
    /// Default (no flag) `~/.wafrift/gene-bank.json`.
    ///
    /// Also accepts `--gene-bank` as an alias — dogfood sonnet 3 (2026-05)
    /// flagged that operators reach for "gene bank" naming
    /// (`--gene-bank-dir` was tried) and got `unexpected argument` with no
    /// hint. The alias closes the muscle-memory gap.
    #[arg(long, visible_alias = "gene-bank")]
    pub proxy_bank: Vec<PathBuf>,

    /// One or more `wafrift scan --format json` output files to fold
    /// into the report. This is what makes `scan` → `report` compose:
    /// previously `report` only read the proxy gene bank, so a user who
    /// ran `scan` then `report` got "No bypasses recorded yet" even
    /// with findings in hand. Repeatable.
    #[arg(long)]
    pub scan_json: Vec<PathBuf>,

    /// Read a `wafrift scan --format json` blob from stdin, so
    /// `wafrift scan ... --format json | wafrift report --scan-stdin`
    /// works as a one-liner.
    #[arg(long, default_value_t = false)]
    pub scan_stdin: bool,

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

/// Stable JSON shape for `--format json`. The `schema_version` field
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
    /// Concrete bypass payloads + reproducers, carried over from
    /// scan-JSON ingestion. Empty when only the proxy bank was the
    /// source. The shape mirrors `BypassFinding` so a downstream
    /// tool deserialising this report can use the same struct as
    /// the raw scan JSON.
    bypass_findings: &'a [BypassFinding],
    /// `wafrift replay` invocation that re-runs the finding through
    /// the wafrift evasion engine — drives the gene bank, picks fresh
    /// variants, surfaces a verdict.
    replay_command: String,
    /// Raw `curl -i` invocation that fires the equivalent HTTP request
    /// shape (GET ?param=payload) directly at the target — for
    /// hand-off to a client who does not (yet) have wafrift installed.
    /// Built via [`RawRequest::to_curl`] so the shell escape matches
    /// the one used everywhere else in the CLI.
    curl_command: String,
}

const REPORT_SCHEMA_VERSION: u32 = 2;

#[derive(Deserialize, Debug, Default)]
struct PersistedHostState {
    #[serde(default)]
    proven_winners: Vec<String>,
    #[serde(default)]
    blocklisted: Vec<String>,
    #[serde(default)]
    waf_name: Option<String>,
    /// Concrete bypass payloads carried over from `wafrift scan
    /// --format json` ingestion. Empty on the legacy proxy-bank-only
    /// load path (the proxy stores only the technique chain it
    /// proved out, not the original payload it succeeded with).
    /// Populated by [`ingest_scan_json`] and rendered as a "Bypass
    /// payloads" section per host so the pentest report carries the
    /// exact bytes that beat the WAF — not just the strategy class.
    /// Backwards-compat-safe: `serde(default)` means existing
    /// gene-bank JSON deserialises to an empty Vec.
    #[serde(default)]
    bypass_findings: Vec<BypassFinding>,
}

/// One concrete bypass surfaced from a scan JSON. Mirrors the shape
/// emitted by `scan/mod.rs` under `--format json` so a future code
/// path could deserialise straight from the raw scan output without
/// the manual `ingest_scan_json` extraction.
#[derive(Deserialize, serde::Serialize, Debug, Clone)]
struct BypassFinding {
    /// 1-based variant ID, same numbering scheme as the scan output.
    variant: u64,
    /// Concrete payload bytes that bypassed.
    payload: String,
    /// Strategy chain that produced the payload, joined for display.
    techniques: Vec<String>,
    /// Oracle confidence (0.0–1.0).
    confidence: f64,
    /// Operator-pasteable curl reproducer. Populated when the source
    /// scan JSON included `repro_curl` (the URL-query + raw-runner
    /// paths now both emit it); `None` for older scan JSON that
    /// predates the field.
    #[serde(default)]
    repro_curl: Option<String>,
    /// ddmin-distilled smallest variant (`scan --auto-distill`).
    /// `None` for runs without that flag.
    #[serde(default)]
    minimal_payload: Option<String>,
}

#[derive(Deserialize, Debug, Default)]
struct PersistedGeneBank {
    #[serde(default)]
    schema: u32,
    #[serde(default)]
    hosts: HashMap<String, PersistedHostState>,
}

pub fn run_report(args: ReportArgs, quiet: bool) -> ExitCode {
    let path = match resolve_path(args.proxy_bank.clone()) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("error: {msg}. Fix: pass --proxy-bank with a valid path, or ensure ~/.wafrift/gene-bank.json exists.");
            return ExitCode::from(1);
        }
    };
    let raw = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: read {}: {e}. Fix: verify the file path and permissions.", path.display());
            return ExitCode::from(1);
        }
    };
    let bank: PersistedGeneBank = match serde_json::from_str(&raw) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: parse gene bank at {}: {e}. Fix: verify the file contains valid JSON.", path.display());
            return ExitCode::from(1);
        }
    }

    // ── proxy gene bank sources ──
    // Load when explicitly requested, or as the sole source when no
    // scan JSON was supplied (preserves the original default). When
    // scan JSON IS supplied and no bank is explicitly named, don't
    // hard-fail on a missing default bank — the scan data stands alone.
    let load_proxy = !args.proxy_bank.is_empty() || !has_scan_src;
    if load_proxy {
        let paths = match resolve_paths(&args.proxy_bank) {
            Ok(p) => p,
            Err(msg) => {
                eprintln!("error: {msg}");
                return ExitCode::from(1);
            }
        };
        for path in &paths {
            let raw = match fs::read_to_string(path) {
                Ok(s) => s,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    if has_scan_src {
                        // Scan data already loaded; a missing default
                        // bank is not an error in that mode.
                        continue;
                    }
                    eprintln!(
                        "error: gene bank not found: {}\n\n\
                         hint: the gene bank is created automatically by wafrift-proxy.\n\
                         Run `wafrift-proxy --listen 127.0.0.1:8080 --mitm` and browse\n\
                         through it, then re-run `wafrift report`.\n\
                         Or pass `--scan-json <file>` / `--scan-stdin` to report from\n\
                         `wafrift scan --format json` output instead.",
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

    if quiet {
        let summary: Vec<_> = hosts
            .iter()
            .map(|(name, hs)| {
                json!({
                    "host": name,
                    "waf": hs.waf_name,
                    "proven_winners": hs.proven_winners,
                    "blocklisted": hs.blocklisted,
                })
            })
            .collect();
        println!("{}", json!({ "schema_version": 1, "hosts": summary }));
        return ExitCode::SUCCESS;
    }

    let md = render_markdown(&bank, &hosts, &args);

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
                "wafrift replay --target {target} --param {param} --payload {payload} --from-host {name}",
                target = shell_single_quote(&target),
                param = args.param,
                payload = shell_single_quote(&args.payload),
                name = shell_single_quote(name),
            );
            let curl_command = curl_reproducer(&target, &args.param, &args.payload);
            JsonFinding {
                host: name.as_str(),
                waf: hs.waf_name.as_deref(),
                proven_techniques: &hs.proven_winners,
                blocklisted_techniques: &hs.blocklisted,
                bypass_findings: &hs.bypass_findings,
                replay_command,
                curl_command,
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
            out.push_str(&format!("**Identified WAF:** {}\n\n", md_escape(waf)));
        }
        out.push_str(&format!(
            "**Bypass count:** {} proven technique(s)\n\n",
            hs.proven_winners.len()
        ));

        out.push_str("**Working techniques:**\n\n");
        for t in &hs.proven_winners {
            out.push_str(&format!("- `{}`\n", md_escape(t)));
        }
        out.push('\n');

        if !hs.blocklisted.is_empty() {
            out.push_str("**Techniques the WAF reliably blocks** (do not use):\n\n");
            for t in &hs.blocklisted {
                out.push_str(&format!("- `{}`\n", md_escape(t)));
            }
            out.push('\n');
        }

        // Concrete bypass payloads — present only when the report
        // was fed scan JSON (proxy-bank-only loads carry technique
        // strings, not the original exploit bytes). The pentest-
        // report deliverable lives here: the exact payload the
        // client engineer can paste into Burp, sqlmap, or curl.
        if !hs.bypass_findings.is_empty() {
            out.push_str(&format!(
                "**Bypass payloads ({} variant{}):**\n\n",
                hs.bypass_findings.len(),
                if hs.bypass_findings.len() == 1 {
                    ""
                } else {
                    "s"
                }
            ));
            for f in &hs.bypass_findings {
                out.push_str(&format!(
                    "- **Variant #{}** · confidence {:.2} · techniques: {}\n",
                    f.variant,
                    f.confidence,
                    if f.techniques.is_empty() {
                        "_(none recorded)_".to_string()
                    } else {
                        f.techniques
                            .iter()
                            .map(|t| format!("`{}`", md_escape(t)))
                            .collect::<Vec<_>>()
                            .join(" → ")
                    }
                ));
                out.push_str(&format!(
                    "\n  ```\n  {}\n  ```\n",
                    f.payload.replace('\n', "\n  ")
                ));
                if let Some(min) = &f.minimal_payload {
                    out.push_str(&format!(
                        "\n  _Distilled minimum ({} bytes):_ `{}`\n",
                        min.len(),
                        min
                    ));
                }
                if let Some(curl) = &f.repro_curl {
                    out.push_str(&format!("\n  Reproduce:\n  ```sh\n  {curl}\n  ```\n"));
                }
            }
            out.push('\n');
        }

        let target = args
            .target_template
            .clone()
            .unwrap_or_else(|| format!("https://{name}/<PATH>"));
        out.push_str("**Reproduce via wafrift replay:**\n\n```sh\n");
        out.push_str(&format!(
            "wafrift replay \\\n  --target {target} \\\n  --param {param} \\\n  --payload {payload} \\\n  --from-host {name}\n",
            target = shell_single_quote(&target),
            param = args.param,
            payload = shell_single_quote(&args.payload),
            name = shell_single_quote(name),
        ));
        out.push_str("```\n\n");

        out.push_str("**Reproduce via raw curl:**\n\n```sh\n");
        out.push_str(&curl_reproducer(&target, &args.param, &args.payload));
        out.push_str("\n```\n\n");
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

/// Build the `curl -i …` reproducer for a finding. Mirrors the
/// canonical GET-shape probe `scan` fires for every variant:
/// `target?param=urlencoded(payload)` with no body and no extra
/// headers (the operator brings their own session via Burp / curl
/// `-b cookie.jar`). Returns a single-line, ready-to-paste curl
/// command — escaping handled by [`RawRequest::to_curl`], which
/// shares the canonical shell escape with [`crate::helpers::shell_single_quote`].
///
/// Why a helper instead of inline format! magic: routes through the
/// SAME `RawRequest`/`to_curl` path the scan engine uses to surface
/// reproducers, so a fix to one curl-shape rule applies everywhere.
/// Escape a user-controlled string for safe embedding in a markdown document.
///
/// Strips backticks (which would break code fences) and escapes angle
/// brackets (which GitHub / Notion render as HTML). Both are injection
/// vectors: a technique name containing triple-backticks closes the fence;
/// a name containing `<script>` executes in HTML-mode markdown renderers.
fn md_escape(s: &str) -> String {
    s.chars()
        .filter(|c| *c != '`')
        .map(|c| match c {
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '&' => "&amp;".to_string(),
            c => c.to_string(),
        })
        .collect()
}

fn curl_reproducer(target: &str, param: &str, payload: &str) -> String {
    let url = match reqwest::Url::parse(target) {
        Ok(mut url) => {
            url.query_pairs_mut().append_pair(param, payload);
            url.to_string()
        }
        // Falls back when `target_template` contains the literal
        // `<PATH>` placeholder (not a valid URL): emit the obvious
        // shape and let the operator hand-edit before running.
        Err(_) => format!(
            "{target}?{param}={payload_enc}",
            payload_enc = urlencoding_query(payload)
        ),
    };
    RawRequest {
        method: "GET".to_string(),
        url,
        headers: Vec::new(),
        body: Vec::new(),
    }
    .to_curl()
}

/// Minimal application/x-www-form-urlencoded escape for the query-
/// string fallback above. `reqwest::Url::parse` does the real thing
/// when the target IS a valid URL; this fallback covers the
/// `<PATH>` placeholder case only.
fn urlencoding_query(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn resolve_paths(custom: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    if !custom.is_empty() {
        return Ok(custom.to_vec());
    }
    // $HOME on POSIX; %USERPROFILE% on Windows (cmd / PowerShell ship
    // it; Git Bash / WSL set $HOME so this still works there too).
    // Pre-fix, bare-Windows operators saw `$HOME not set` and had to
    // pass --proxy-bank explicitly — the hint message didn't mention
    // %USERPROFILE% so they assumed wafrift was broken.
    let home_dir = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"));
    let home = home_dir.ok_or_else(|| {
        "neither $HOME nor %USERPROFILE% set; pass --proxy-bank explicitly".to_string()
    })?;
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
                bypass_findings: Vec::new(),
            },
        );
        hosts.insert(
            "no-finds.example.com".into(),
            PersistedHostState {
                proven_winners: vec![],
                blocklisted: vec![],
                waf_name: None,
                bypass_findings: Vec::new(),
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
            scan_json: vec![],
            scan_stdin: false,
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

    // shell_escape lived here until 2026-05-20; the canonical
    // implementation is now `helpers::shell_single_quote` and the
    // round-trip-through-bash test moved with it. Single source of
    // truth — one fix, every caller benefits.

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
            scan_json: vec![],
            scan_stdin: false,
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
            scan_json: vec![],
            scan_stdin: false,
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
        // Curl reproducer must be a single-line `curl -i …` invocation
        // pointing at the same host with the param/payload baked in.
        let curl = f["curl_command"].as_str().expect("curl_command string");
        assert!(curl.starts_with("curl -i"), "got: {curl}");
        assert!(curl.contains("api.example.com"), "host present: {curl}");
        assert!(curl.contains("q=x"), "param=payload present: {curl}");
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
            scan_json: vec![],
            scan_stdin: false,
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
                bypass_findings: Vec::new(),
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
                bypass_findings: Vec::new(),
            },
        );
        b_hosts.insert(
            "edge.example.com".into(),
            PersistedHostState {
                proven_winners: vec!["HeaderHostShard".into()],
                blocklisted: vec![],
                waf_name: Some("Cloudflare".into()),
                bypass_findings: Vec::new(),
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

    // ── host_from_target ──────────────────────────────────────

    #[test]
    fn host_from_target_extracts_host_from_full_url() {
        assert_eq!(host_from_target("http://example.com/api"), "example.com");
        assert_eq!(
            host_from_target("https://api.example.com/"),
            "api.example.com"
        );
    }

    #[test]
    fn host_from_target_strips_port() {
        assert_eq!(
            host_from_target("http://example.com:8080/api"),
            "example.com"
        );
        assert_eq!(host_from_target("https://example.com:443/"), "example.com");
    }

    #[test]
    fn host_from_target_strips_userinfo() {
        assert_eq!(
            host_from_target("http://user:pass@example.com/admin"),
            "example.com"
        );
    }

    #[test]
    fn host_from_target_lowercases_host() {
        assert_eq!(
            host_from_target("https://API.EXAMPLE.COM/path"),
            "api.example.com"
        );
    }

    #[test]
    fn host_from_target_handles_no_scheme() {
        assert_eq!(host_from_target("example.com/api"), "example.com");
    }

    #[test]
    fn host_from_target_handles_query_string() {
        assert_eq!(host_from_target("http://x.com/api?a=1"), "x.com");
    }

    #[test]
    fn host_from_target_handles_fragment() {
        assert_eq!(host_from_target("http://x.com/api#frag"), "x.com");
    }

    #[test]
    fn host_from_target_empty_host_falls_back_to_unknown() {
        assert_eq!(host_from_target(""), "unknown-host");
        assert_eq!(host_from_target("http:///path"), "unknown-host");
    }

    // ── glob_match ────────────────────────────────────────────

    #[test]
    fn glob_match_literal_string_matches() {
        assert!(glob_match("example.com", "example.com"));
        assert!(!glob_match("example.com", "other.com"));
    }

    #[test]
    fn glob_match_is_case_insensitive() {
        assert!(glob_match("Example.Com", "example.COM"));
    }

    #[test]
    fn glob_match_star_matches_zero_or_more_chars() {
        assert!(glob_match("*.example.com", "api.example.com"));
        assert!(glob_match("*.example.com", "deep.api.example.com"));
        // Zero-char match.
        assert!(glob_match("api*.example.com", "api.example.com"));
    }

    #[test]
    fn glob_match_question_matches_exactly_one() {
        assert!(glob_match("?", "a"));
        assert!(!glob_match("?", ""));
        assert!(!glob_match("?", "ab"));
    }

    #[test]
    fn glob_match_double_star_collapses() {
        // `**` should match anything (zero or more chars). The recurse
        // logic handles this naturally — verify it doesn't blow up.
        assert!(glob_match("**", "any.host.here"));
        assert!(glob_match("a**b", "axxxxxxb"));
    }

    #[test]
    fn glob_match_empty_pattern_only_matches_empty_string() {
        assert!(glob_match("", ""));
        assert!(!glob_match("", "x"));
    }

    #[test]
    fn glob_match_no_partial_match() {
        // The glob is anchored — no prefix/suffix match unless `*`.
        assert!(!glob_match("api", "api.example.com"));
        assert!(glob_match("api*", "api.example.com"));
    }

    // ── ingest_scan_json ──────────────────────────────────────

    #[test]
    fn ingest_scan_json_parses_bare_scan_object() {
        let json = r#"{
            "target": "http://example.com",
            "waf": "ModSecurity",
            "bypass_variants": [
                {"techniques": ["EncodingUrl", "GrammarTautology"]}
            ]
        }"#;
        let bank = ingest_scan_json(json, "stdin").unwrap();
        let host = bank.hosts.get("example.com").expect("host present");
        assert_eq!(host.proven_winners.len(), 2);
        assert!(host.proven_winners.contains(&"EncodingUrl".to_string()));
        assert_eq!(host.waf_name.as_deref(), Some("ModSecurity"));
    }

    #[test]
    fn ingest_scan_json_unwraps_report_layers_envelope() {
        // The `--report-layers` JSON nests the scan object under
        // `"scan"`. ingest_scan_json should unwrap that.
        let json = r#"{
            "scan": {
                "target": "http://example.com",
                "waf": "ModSecurity",
                "bypass_variants": []
            }
        }"#;
        let bank = ingest_scan_json(json, "stdin").unwrap();
        assert!(bank.hosts.contains_key("example.com"));
    }

    #[test]
    fn ingest_scan_json_dedupes_repeated_techniques() {
        let json = r#"{
            "target": "http://example.com",
            "bypass_variants": [
                {"techniques": ["EncodingUrl", "EncodingUrl", "GrammarTautology"]},
                {"techniques": ["GrammarTautology", "EncodingHex"]}
            ]
        }"#;
        let bank = ingest_scan_json(json, "stdin").unwrap();
        let host = bank.hosts.get("example.com").unwrap();
        // EncodingUrl and GrammarTautology de-duped; total = 3 unique.
        assert_eq!(host.proven_winners.len(), 3);
        let mut sorted = host.proven_winners.clone();
        sorted.sort();
        assert_eq!(
            sorted,
            vec![
                "EncodingHex".to_string(),
                "EncodingUrl".to_string(),
                "GrammarTautology".to_string(),
            ]
        );
    }

    #[test]
    fn ingest_scan_json_treats_waf_none_as_no_waf_name() {
        // The scan JSON emits `"waf": "None"` when no WAF detected.
        // ingest_scan_json should NOT set a waf_name in that case —
        // matched waf_name: None.
        let json = r#"{
            "target": "http://example.com",
            "waf": "None",
            "bypass_variants": []
        }"#;
        let bank = ingest_scan_json(json, "stdin").unwrap();
        let host = bank.hosts.get("example.com").unwrap();
        assert!(host.waf_name.is_none());
    }

    #[test]
    fn ingest_scan_json_rejects_input_without_target_field() {
        let json = r#"{"bypass_variants": []}"#;
        let err = ingest_scan_json(json, "stdin").unwrap_err();
        assert!(err.contains("target"));
    }

    #[test]
    fn ingest_scan_json_rejects_malformed_json() {
        let err = ingest_scan_json("not json", "stdin").unwrap_err();
        assert!(err.contains("parse"));
    }

    // ── curl_reproducer ──────────────────────────────────────

    #[test]
    fn curl_reproducer_builds_a_well_formed_curl_for_real_url() {
        let out = curl_reproducer("https://example.com/api", "q", "test");
        // Starts with the canonical `curl -i` (no -X for GET).
        assert!(out.starts_with("curl -i "), "got: {out}");
        // URL is single-quoted (via shell_single_quote) and carries
        // the query.
        assert!(
            out.contains("'https://example.com/api?q=test'"),
            "got: {out}"
        );
        // No body flag for GET.
        assert!(!out.contains("--data-binary"), "got: {out}");
    }

    #[test]
    fn curl_reproducer_url_encodes_special_chars_in_payload_via_url_parser() {
        let out = curl_reproducer("https://x.example/", "q", "' OR 1=1--");
        // reqwest's Url::query_pairs_mut applies form-urlencoding.
        // The apostrophe rides through (form-urlencoding only encodes
        // a small set), but spaces become `+`.
        assert!(out.contains("q="), "got: {out}");
        assert!(out.contains("OR+1%3D1"), "got: {out}");
    }

    #[test]
    fn curl_reproducer_shell_quotes_payload_for_safety() {
        // A payload with apostrophes must arrive escaped — single-
        // quote shell escape becomes `'\''`. The outer URL is wrapped
        // in `'…'` so the inner `'` MUST be split out.
        let out = curl_reproducer("https://x.example/", "q", "a'b");
        // The escape produces `'\''` between two surrounding apostrophes.
        // We just assert the dangerous raw `'a'b'` form is NEVER present.
        assert!(!out.contains("'a'b'"), "raw apostrophe leaked: {out}");
    }

    #[test]
    fn curl_reproducer_handles_path_placeholder_target_via_url_encoding() {
        // The default report target is `https://{host}/<PATH>` —
        // reqwest::Url::parse accepts it by URL-encoding `<` and `>`
        // to `%3C` / `%3E`. Operator hand-edits the path before
        // running. Still produces a usable curl line.
        let out = curl_reproducer("https://api.example/<PATH>", "q", "x");
        assert!(out.starts_with("curl -i "), "got: {out}");
        assert!(out.contains("api.example"), "got: {out}");
        // `<PATH>` is URL-encoded by reqwest — operator un-escapes
        // before running.
        assert!(out.contains("%3CPATH%3E"), "got: {out}");
        assert!(out.contains("q=x"), "got: {out}");
    }

    #[test]
    fn curl_reproducer_url_path_encodes_payload_via_form_urlencoding() {
        // reqwest::Url::query_pairs_mut uses application/x-www-form-
        // urlencoded: spaces become `+`, apostrophes get %-encoded
        // (`%27`). The fallback path is only reached on a TRULY
        // unparseable target (see `curl_reproducer_fallback_*` below).
        let out = curl_reproducer("https://x/<PATH>", "q", "a b'");
        assert!(out.contains("q=a+b%27"), "got: {out}");
    }

    #[test]
    fn curl_reproducer_fallback_handles_truly_malformed_target() {
        // Target with no scheme — reqwest::Url::parse rejects (it
        // demands an absolute URL). Falls into the manual encoding
        // path. Confirms the function never panics on adversarial
        // operator input.
        let out = curl_reproducer("noscheme.example/<PATH>", "q", "a b");
        assert!(out.starts_with("curl -i "), "got: {out}");
        // Manual encoder uses %20 for spaces (not `+`).
        assert!(out.contains("q=a%20b"), "got: {out}");
    }

    #[test]
    fn curl_reproducer_fallback_url_encodes_metachars_in_payload() {
        // Same fallback path — confirms `'` and `=` are %-encoded
        // when the target is unparseable.
        let out = curl_reproducer("badtarget", "q", "a=b'");
        assert!(out.contains("q=a%3Db%27"), "got: {out}");
    }

    // ── render_markdown — curl + replay blocks both present ──

    #[test]
    fn render_markdown_emits_both_replay_and_curl_reproducer_blocks() {
        let bank = fake_bank();
        let hosts: Vec<_> = bank
            .hosts
            .iter()
            .filter(|(_, hs)| !hs.proven_winners.is_empty())
            .collect();
        let args = ReportArgs {
            proxy_bank: vec![],
            scan_json: vec![],
            scan_stdin: false,
            only_host: vec![],
            output: None,
            target_template: None,
            param: "q".into(),
            payload: "PAYLOAD".into(),
            format: "markdown".into(),
        };
        let md = render_markdown(&bank, &hosts, &args);
        assert!(
            md.contains("Reproduce via wafrift replay"),
            "missing replay heading"
        );
        assert!(
            md.contains("Reproduce via raw curl"),
            "missing curl heading"
        );
        // Curl invocation must appear inside the markdown.
        assert!(md.contains("curl -i "), "curl block missing: {md}");
    }

    // ── urlencoding_query ────────────────────────────────────

    #[test]
    fn urlencoding_query_passes_unreserved_chars_through() {
        assert_eq!(
            urlencoding_query("HelloWorld-123_test.~"),
            "HelloWorld-123_test.~"
        );
    }

    #[test]
    fn urlencoding_query_percent_encodes_specials() {
        assert_eq!(urlencoding_query(" "), "%20");
        assert_eq!(urlencoding_query("'"), "%27");
        assert_eq!(urlencoding_query("="), "%3D");
        assert_eq!(urlencoding_query("&"), "%26");
    }

    // ── bypass_findings end-to-end ─────────────────────────────────

    fn fixture_scan_json_with_two_bypasses() -> String {
        // Mirrors the shape `scan/mod.rs` emits under --format json,
        // including the new `repro_curl` field on each variant.
        serde_json::json!({
            "scan_schema_version": 1,
            "target": "https://example.com/api",
            "waf": "Cloudflare",
            "total_variants": 30,
            "bypassed": 2,
            "blocked": 28,
            "errors": 0,
            "bypass_rate_pct": 6.7,
            "bypass_variants": [
                {
                    "variant": 1,
                    "payload": "%27%20OR%201%3D1--",
                    "techniques": ["url", "case_swap"],
                    "confidence": 0.93,
                    "repro_curl": "curl -G --data-urlencode 'q=%27 OR 1=1--' 'https://example.com/api'",
                    "minimal_payload": null
                },
                {
                    "variant": 17,
                    "payload": "/**/UNION/**/SELECT",
                    "techniques": ["sql_comment"],
                    "confidence": 0.81,
                    "repro_curl": "curl -G --data-urlencode 'q=/**/UNION/**/SELECT' 'https://example.com/api'",
                    "minimal_payload": "UNION SELECT"
                }
            ]
        })
        .to_string()
    }

    #[test]
    fn ingest_scan_json_captures_bypass_findings_not_just_techniques() {
        let raw = fixture_scan_json_with_two_bypasses();
        let bank = ingest_scan_json(&raw, "fixture").expect("ingest");
        let state = bank
            .hosts
            .get("example.com")
            .expect("host present after ingestion");
        assert_eq!(state.bypass_findings.len(), 2);
        assert_eq!(state.bypass_findings[0].variant, 1);
        assert_eq!(state.bypass_findings[0].payload, "%27%20OR%201%3D1--");
        assert_eq!(
            state.bypass_findings[0].techniques,
            vec!["url", "case_swap"]
        );
        assert!(state.bypass_findings[0].repro_curl.is_some());
        assert!(state.bypass_findings[0].minimal_payload.is_none());
        // The distilled payload of the second finding must round-
        // trip through serde unchanged.
        assert_eq!(
            state.bypass_findings[1].minimal_payload.as_deref(),
            Some("UNION SELECT")
        );
    }

    #[test]
    fn render_markdown_emits_actual_bypass_payloads_when_present() {
        let raw = fixture_scan_json_with_two_bypasses();
        let bank = ingest_scan_json(&raw, "fixture").expect("ingest");
        let hosts: Vec<(&String, &PersistedHostState)> = bank.hosts.iter().collect();
        let args = ReportArgs {
            output: None,
            scan_json: Vec::new(),
            scan_stdin: false,
            proxy_bank: Vec::new(),
            target_template: Some("https://example.com/api".into()),
            param: "q".into(),
            payload: "placeholder".into(),
            only_host: Vec::new(),
            format: "markdown".into(),
        };
        let md = render_markdown(&bank, &hosts, &args);
        // Both concrete payloads must appear in the rendered
        // markdown — not just the technique labels.
        assert!(
            md.contains("%27%20OR%201%3D1--"),
            "first concrete payload missing from markdown:\n{md}"
        );
        assert!(
            md.contains("/**/UNION/**/SELECT"),
            "second concrete payload missing from markdown:\n{md}"
        );
        // The repro_curl line must surface so the report is
        // copy-pasteable into a pentest deliverable.
        assert!(
            md.contains("curl -G --data-urlencode"),
            "repro_curl missing from markdown:\n{md}"
        );
        // Distilled-minimum callout must surface when present.
        assert!(
            md.contains("Distilled minimum"),
            "minimal_payload callout missing:\n{md}"
        );
    }

    #[test]
    fn render_markdown_omits_payloads_section_for_proxy_bank_only_input() {
        // When only a proxy gene bank is loaded (no scan JSON), the
        // bypass_findings list is empty and the "Bypass payloads"
        // section must not appear — preserves the historical
        // proxy-bank-only report shape exactly.
        let mut bank = PersistedGeneBank::default();
        bank.hosts.insert(
            "x.test".into(),
            PersistedHostState {
                proven_winners: vec!["url".into()],
                blocklisted: Vec::new(),
                waf_name: Some("Akamai".into()),
                bypass_findings: Vec::new(),
            },
        );
        let hosts: Vec<(&String, &PersistedHostState)> = bank.hosts.iter().collect();
        let args = ReportArgs {
            output: None,
            scan_json: Vec::new(),
            scan_stdin: false,
            proxy_bank: Vec::new(),
            target_template: None,
            param: "q".into(),
            payload: "x".into(),
            only_host: Vec::new(),
            format: "markdown".into(),
        };
        let md = render_markdown(&bank, &hosts, &args);
        assert!(
            !md.contains("Bypass payloads"),
            "proxy-bank-only render must NOT show the bypass-payloads section:\n{md}"
        );
    }

    #[test]
    fn merge_banks_uniques_findings_on_variant_and_payload() {
        // Two ingestions of the same scan must NOT double-list the
        // same bypass.
        let raw = fixture_scan_json_with_two_bypasses();
        let bank_a = ingest_scan_json(&raw, "a").expect("ingest a");
        let bank_b = ingest_scan_json(&raw, "b").expect("ingest b");
        let mut merged = PersistedGeneBank::default();
        merge_banks(&mut merged, bank_a);
        merge_banks(&mut merged, bank_b);
        let state = merged
            .hosts
            .get("example.com")
            .expect("host present after merge");
        assert_eq!(
            state.bypass_findings.len(),
            2,
            "merged bypasses must not duplicate on identical input"
        );
    }

    #[test]
    fn render_json_includes_bypass_findings_in_findings_array() {
        let raw = fixture_scan_json_with_two_bypasses();
        let bank = ingest_scan_json(&raw, "fixture").expect("ingest");
        let hosts: Vec<(&String, &PersistedHostState)> = bank.hosts.iter().collect();
        let args = ReportArgs {
            output: None,
            scan_json: Vec::new(),
            scan_stdin: false,
            proxy_bank: Vec::new(),
            target_template: Some("https://example.com/api".into()),
            param: "q".into(),
            payload: "placeholder".into(),
            only_host: Vec::new(),
            format: "json".into(),
        };
        let body = render_json(&bank, &hosts, &args).expect("render");
        let v: serde_json::Value = serde_json::from_str(&body).expect("parse");
        let findings = v["findings"].as_array().expect("findings array");
        assert_eq!(findings.len(), 1);
        let bf = findings[0]["bypass_findings"]
            .as_array()
            .expect("bypass_findings array");
        assert_eq!(bf.len(), 2);
        assert_eq!(bf[0]["payload"], "%27%20OR%201%3D1--");
        assert_eq!(bf[1]["payload"], "/**/UNION/**/SELECT");
    }
}
