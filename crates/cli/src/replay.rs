//! `wafrift replay` — fire a saved bypass against a target to prove
//! reproducibility.
//!
//! A practitioner runs wafrift-proxy in front of Burp, the proxy
//! discovers a bypass on `api.example.com`, the gene bank persists the
//! winning technique pool keys for that host. To put the finding in a
//! report (or a regression test), they need to reproduce it deterministi-
//! cally with one command — not by re-pointing Burp at the target and
//! hoping the proxy re-derives the same chain.
//!
//! Replay is fully self-contained: it builds an EvasionResult by feeding
//! the saved technique keys into `wafrift_strategy::evade` as proven
//! winners, then sends the resulting request via reqwest and classifies
//! the response. JSON output is stable for CI gating.

use clap::Args;
use colored::Colorize;
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;
use wafrift_strategy::strategy::evade;
use wafrift_strategy::{EvasionConfig, HostState};
use wafrift_transport::is_waf_block;
use wafrift_types::{Method, Request};

/// Arguments for `wafrift replay`.
#[derive(Args, Debug)]
pub struct ReplayArgs {
    /// Target URL, e.g. `https://api.example.com/search`.
    #[arg(long)]
    pub target: String,

    /// Query/body parameter name to inject the payload into.
    #[arg(long, default_value = "q")]
    pub param: String,

    /// Raw payload to mutate via the saved technique chain. The same
    /// payload that produced the original bypass — the engine reapplies
    /// the same encoding pipeline to it.
    #[arg(long)]
    pub payload: String,

    /// HTTP method to use for the replay (GET / POST / PUT / ...).
    #[arg(long, default_value = "GET")]
    pub method: String,

    /// Technique pool keys to replay, e.g. `EncodingUrl,GrammarTautology`.
    /// Comma-separated. At least one of `--technique` /
    /// `--from-host` / `--from-waf` must be set.
    #[arg(long, num_args = 1.., value_delimiter = ',')]
    pub technique: Vec<String>,

    /// Pull the technique list from the proxy gene bank by host.
    /// Default file: `~/.wafrift/gene-bank.json`. Override with
    /// `--proxy-bank`.
    #[arg(long)]
    pub from_host: Option<String>,

    /// Path to the proxy gene bank JSON file (used by `--from-host`).
    #[arg(long)]
    pub proxy_bank: Option<PathBuf>,

    /// Pull the technique list from the per-WAF GeneBank by WAF name.
    /// Reads from `~/.wafrift/genomes/`.
    #[arg(long)]
    pub from_waf: Option<String>,

    /// Disable TLS verification (lab targets only).
    #[arg(long, default_value_t = false)]
    pub insecure: bool,

    /// Request timeout in seconds.
    #[arg(long, default_value_t = 30)]
    pub timeout_secs: u64,

    /// Output format: `text` (default) or `json` (machine-parseable).
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    /// Optional Host header override (defaults to URL host).
    #[arg(long)]
    pub host: Option<String>,
}

#[derive(Debug, Serialize)]
struct ReplayResult {
    target: String,
    param: String,
    method: String,
    payload: String,
    techniques: Vec<String>,
    final_url: String,
    status: u16,
    blocked: bool,
    response_bytes: usize,
    elapsed_ms: u128,
}

pub fn run_replay(args: ReplayArgs, quiet: bool) -> ExitCode {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("failed to start tokio runtime for replay: {e}. Fix: verify system resources and try again.");
            return ExitCode::from(1);
        }
    };
    rt.block_on(async { run_replay_inner(args, quiet).await })
}

async fn run_replay_inner(args: ReplayArgs, quiet: bool) -> ExitCode {
    // Resolve technique list. Order: explicit --technique > --from-host >
    // --from-waf. If the resolved list is empty we error out instead of
    // silently sending an unmodified payload — that would be a
    // false-positive "bypass".
    let techniques = match resolve_techniques(&args) {
        Ok(t) => t,
        Err(msg) => {
            eprintln!("{} {msg}", "error:".red().bold());
            return ExitCode::from(1);
        }
    };
    if techniques.is_empty() {
        eprintln!(
            "{} no techniques resolved — supply --technique, --from-host, or --from-waf",
            "error:".red().bold()
        );
        return ExitCode::from(1);
    }

    // Build the base request. The payload goes into `?param=...` for
    // GET-like methods and stays in the URL — body-injected replay is a
    // future expansion (POST forms aren't reconstructible from a host
    // gene bank entry without remembering form structure).
    let target_url = match build_url_with_param(&args.target, &args.param, &args.payload) {
        Ok(u) => u,
        Err(msg) => {
            eprintln!("{} {msg}", "error:".red().bold());
            return ExitCode::from(1);
        }
    };
    let method = Method::from(args.method.to_ascii_uppercase().as_str());
    let host_header = args
        .host
        .clone()
        .or_else(|| extract_host_from_url(&args.target))
        .unwrap_or_default();

    let req = Request {
        method: method.clone(),
        url: target_url,
        headers: vec![
            (
                "User-Agent".into(),
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36".into(),
            ),
            ("Accept".into(), "*/*".into()),
        ],
        body: None,
    };

    // Drive the existing evasion engine in "rotation" mode by stamping
    // the saved keys onto a fresh HostState as proven winners. This is
    // exactly how the proxy replays a discovered chain — same code
    // path, no replay-specific reimplementation that could drift.
    let host_state = HostState {
        proven_winners: techniques.clone(),
        discovery_complete: true,
        ..HostState::default()
    };
    let config = EvasionConfig::default();
    let evasion = evade(&req, &host_state, &config);

    let applied: Vec<String> = if evasion.techniques.is_empty() {
        techniques.clone()
    } else {
        evasion.techniques.iter().map(ToString::to_string).collect()
    };

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout_secs))
        .danger_accept_invalid_certs(args.insecure)
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{} Failed to build HTTP client for replay (check --timeout-secs, --insecure, and system TLS). Fix: verify the target URL and network settings. {e}", "error:".red().bold());
            return ExitCode::from(1);
        }
    };

    let reqwest_method = match reqwest::Method::from_bytes(evasion.request.method.as_str().as_bytes())
    {
        Ok(m) => m,
        Err(_) => {
            eprintln!("{} invalid HTTP method", "error:".red().bold());
            return ExitCode::from(1);
        }
    };
    let mut builder = client.request(reqwest_method, &evasion.request.url);
    if !host_header.is_empty() {
        builder = builder.header("Host", &host_header);
    }
    for (k, v) in &evasion.request.headers {
        if k.eq_ignore_ascii_case("host") {
            continue;
        }
        builder = builder.header(k.as_str(), v.as_str());
    }
    if let Some(b) = evasion.request.body.clone() {
        builder = builder.body(b);
    }

    let started = std::time::Instant::now();
    let resp = match builder.send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "{} Request to {} failed: {e}. Fix: verify the target is reachable and the URL is correct.",
                "error:".red().bold(),
                evasion.request.url
            );
            return ExitCode::from(1);
        }
    };
    let status = resp.status().as_u16();
    let body = resp.bytes().await.unwrap_or_default();
    let elapsed = started.elapsed();
    let blocked = is_waf_block(status, &body);

    let result = ReplayResult {
        target: args.target.clone(),
        param: args.param.clone(),
        method: args.method.to_ascii_uppercase(),
        payload: args.payload.clone(),
        techniques: applied,
        final_url: evasion.request.url.clone(),
        status,
        blocked,
        response_bytes: body.len(),
        elapsed_ms: elapsed.as_millis(),
    };

    if quiet || args.format == "json" {
        let mut json_result = serde_json::to_value(&result).unwrap_or_default();
        if let Some(obj) = json_result.as_object_mut() {
            obj.insert("schema_version".to_string(), json!(1));
        }
        println!("{}", serde_json::to_string_pretty(&json_result).unwrap_or_default());
    } else {
        let verdict = if blocked {
            format!("{} (status {status})", "BLOCKED".red().bold())
        } else {
            format!("{} (status {status})", "BYPASS".green().bold())
        };
        println!();
        println!("{}", "── wafrift replay ──".bold().cyan());
        println!("  {} {}", "target:".bold(), args.target);
        println!("  {} {}", "method:".bold(), result.method);
        println!("  {} {}", "param:".bold(), args.param);
        println!("  {} {}", "payload:".bold(), args.payload);
        println!(
            "  {} {}",
            "techniques:".bold(),
            result.techniques.join(" → ").yellow()
        );
        println!("  {} {}", "final URL:".bold(), result.final_url.bright_black());
        println!(
            "  {} {} ({} bytes, {} ms)",
            "verdict:".bold(),
            verdict,
            result.response_bytes,
            result.elapsed_ms
        );
        println!();
    }

    if blocked {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn resolve_techniques(args: &ReplayArgs) -> Result<Vec<String>, String> {
    if !args.technique.is_empty() {
        return Ok(args.technique.clone());
    }
    if let Some(host) = &args.from_host {
        return load_from_proxy_bank(host, args.proxy_bank.as_ref());
    }
    if let Some(waf) = &args.from_waf {
        return load_from_waf_genome(waf);
    }
    Ok(Vec::new())
}

#[derive(serde::Deserialize)]
struct PersistedHostState {
    #[serde(default)]
    proven_winners: Vec<String>,
}

#[derive(serde::Deserialize)]
struct PersistedGeneBank {
    #[serde(default)]
    hosts: HashMap<String, PersistedHostState>,
}

fn load_from_proxy_bank(host: &str, custom_path: Option<&PathBuf>) -> Result<Vec<String>, String> {
    let path = match custom_path {
        Some(p) => p.clone(),
        None => {
            let home = std::env::var_os("HOME")
                .ok_or_else(|| "cannot resolve $HOME for default --proxy-bank path".to_string())?;
            PathBuf::from(home).join(".wafrift").join("gene-bank.json")
        }
    };
    let raw = fs::read_to_string(&path)
        .map_err(|e| format!("read proxy gene bank {}: {e}", path.display()))?;
    let bank: PersistedGeneBank = serde_json::from_str(&raw)
        .map_err(|e| format!("parse proxy gene bank: {e}"))?;
    let host_entry = bank
        .hosts
        .get(host)
        .ok_or_else(|| format!("host '{host}' not found in proxy gene bank"))?;
    if host_entry.proven_winners.is_empty() {
        return Err(format!("host '{host}' has no proven winners yet"));
    }
    Ok(host_entry.proven_winners.clone())
}

fn load_from_waf_genome(waf_name: &str) -> Result<Vec<String>, String> {
    let bank = wafrift_strategy::gene_bank::GeneBank::open_default()
        .map_err(|e| format!("open gene bank: {e}"))?;
    let mut bank = bank;
    let genome = bank
        .load(waf_name)
        .ok_or_else(|| format!("no genome found for WAF '{waf_name}'"))?;
    let seeds = genome.seed_winners();
    if seeds.is_empty() {
        return Err(format!("WAF '{waf_name}' genome has no seed winners"));
    }
    Ok(seeds)
}

fn build_url_with_param(base: &str, param: &str, payload: &str) -> Result<String, String> {
    if !(base.starts_with("http://") || base.starts_with("https://")) {
        return Err("invalid --target URL: must start with http:// or https://".to_string());
    }
    // Strip the fragment first — it never reaches the server, and
    // leaving it in path_part would let `#frag` round-trip past the
    // evasion engine.
    let (base_no_frag, _frag) = match base.find('#') {
        Some(i) => (&base[..i], Some(&base[i + 1..])),
        None => (base, None),
    };
    let (path_part, query_only) = match base_no_frag.find('?') {
        Some(i) => (&base_no_frag[..i], &base_no_frag[i + 1..]),
        None => (base_no_frag, ""),
    };

    let mut kept = Vec::new();
    if !query_only.is_empty() {
        for pair in query_only.split('&') {
            if pair.is_empty() {
                continue;
            }
            let key = pair.split('=').next().unwrap_or("");
            let key_decoded = urlencoding::decode(key).unwrap_or_else(|_| key.into()).into_owned();
            if key_decoded == param {
                continue;
            }
            kept.push(pair.to_string());
        }
    }
    kept.push(format!(
        "{}={}",
        urlencoding::encode(param),
        urlencoding::encode(payload)
    ));

    Ok(format!("{}?{}", path_part, kept.join("&")))
}

fn extract_host_from_url(s: &str) -> Option<String> {
    let after_scheme = s.strip_prefix("https://").or_else(|| s.strip_prefix("http://"))?;
    let host = after_scheme
        .split('/')
        .next()?
        .split('?')
        .next()?;
    // Drop port if present.
    let host_only = host.split(':').next()?;
    if host_only.is_empty() {
        None
    } else {
        Some(host_only.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_url_appends_param() {
        let u = build_url_with_param("https://x/y", "q", "1=1").unwrap();
        assert_eq!(u, "https://x/y?q=1%3D1");
    }

    #[test]
    fn build_url_replaces_existing_param() {
        let u = build_url_with_param("https://x/y?q=stale&keep=me", "q", "fresh").unwrap();
        assert!(u.contains("keep=me"));
        assert!(u.contains("q=fresh"));
        assert!(!u.contains("q=stale"));
    }

    #[test]
    fn build_url_rejects_garbage() {
        assert!(build_url_with_param("not a url", "q", "x").is_err());
    }

    #[test]
    fn build_url_drops_fragment() {
        let u = build_url_with_param("https://x/y#frag", "q", "1").unwrap();
        assert!(!u.contains('#'));
        assert!(u.ends_with("q=1"));
    }

    #[test]
    fn extract_host_from_url_strips_port_and_path() {
        assert_eq!(
            extract_host_from_url("https://api.example.com:8443/v1/x?z=1"),
            Some("api.example.com".to_string())
        );
    }

    #[test]
    fn extract_host_from_url_returns_none_for_garbage() {
        assert_eq!(extract_host_from_url("ftp://x"), None);
    }
}
