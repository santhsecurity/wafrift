//! WAF benchmark: send raw + (optionally) wafrift-evaded variants of each
//! case against a WAF target, report per-class bypass rates.
//!
//! With `--evade`, the bench is honest: for every case it sends the raw
//! payload (baseline = should be blocked) AND then runs wafrift's
//! evasion engine N times and measures how many variants slipped past
//! the WAF. Without `--evade`, only the baseline is measured (no claim
//! about wafrift's bypass rate is made).
//!
//! Corpus is one or more TOML files under `wafrift-bench/corpus/` with
//! attack-class subdirs (sql/, xss/, cmdi/, ssti/, path/, ...). Each
//! case carries `id`, `class`, `payload`, optional `mode` + `description`.

use colored::Colorize;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;
use wafrift_content_type::generate_variants_from_body;
use wafrift_grammar::grammar::PayloadType;
use wafrift_smuggling::smuggling::all_payloads as smuggling_all_payloads;
use wafrift_strategy::{EvasionConfig, evade_mcts};
use wafrift_transport::is_waf_block;
use wafrift_types::{Method, Request};

use crate::Level;
use crate::helpers::{Variant, build_variants, max_mutations_for_level, strategies_for_level};

#[derive(Debug, clap::Args)]
pub struct BenchWafArgs {
    /// Base URL of the WAF target (e.g. http://127.0.0.1:18081).
    /// If omitted, uses `WAFRIFT_BENCH_URL` or `http://127.0.0.1:18081`.
    #[arg(long)]
    pub base_url: Option<String>,

    /// Single TOML corpus file OR directory of TOML files (recursive).
    /// Defaults to the bundled bench corpus.
    #[arg(long, default_value = "wafrift-bench/corpus")]
    pub corpus: PathBuf,

    /// Restrict to one or more attack classes (sql, xss, cmdi, ssti, path,
    /// ldap, xxe, ssrf, nosql, log4shell, cve_pocs). Comma-separated.
    /// Default: all classes found.
    #[arg(long, value_delimiter = ',')]
    pub class: Vec<String>,

    /// Run wafrift evasion engine and measure bypass rate.
    /// Without this flag, only the baseline raw-block rate is measured.
    #[arg(long)]
    pub evade: bool,

    /// Variants per case to try in `--evade` mode (per strategy).
    #[arg(long, default_value_t = 5)]
    pub variants: usize,

    /// Comma-separated list of evasion strategies. Default: heavy.
    /// Available:
    ///   light / medium / heavy   — payload-string mutation via build_variants
    ///   mcts                      — Monte Carlo Tree Search over actions (mctrust)
    ///   smuggling                 — HTTP request smuggling variants (CL.TE / TE.CL / TE.TE / dual-CL)
    ///   content-type              — Content-Type confusion variants (multipart/json/xml/...)
    ///   redos                     — wrap payload in catastrophic-backtracking patterns,
    ///                              attempting to trigger WAF regex timeout fail-open
    #[arg(long, value_delimiter = ',', default_value = "heavy")]
    pub strategies: Vec<String>,

    /// Delay between requests (ms) for rate-limit avoidance.
    #[arg(long, default_value_t = 25)]
    pub delay_ms: u64,

    /// Per-request timeout in seconds.
    #[arg(long, default_value_t = 15)]
    pub timeout_secs: u64,

    /// Disable TLS cert verification (for self-signed test stacks).
    #[arg(long, default_value_t = false)]
    pub insecure: bool,

    /// Output format on stdout.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    /// Also write the JSON result blob to this file.
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct CorpusFile {
    #[allow(dead_code)]
    #[serde(default = "default_schema")]
    schema: u32,
    #[serde(default, rename = "case")]
    cases: Vec<BenchCase>,
}

#[derive(Debug, Deserialize, Clone)]
struct BenchCase {
    id: String,
    class: String,
    payload: String,
    /// Where to inject the payload. Default `body_form_q` (POST /post with
    /// body `q=<urlenc payload>`). Alternatives: `url_query_q`, `raw_body`.
    #[serde(default = "default_mode")]
    mode: String,
    #[serde(default)]
    #[allow(dead_code)]
    description: String,
}

fn default_schema() -> u32 {
    1
}
fn default_mode() -> String {
    "body_form_q".into()
}

#[derive(Debug, Serialize, Clone)]
struct CaseResult {
    id: String,
    class: String,
    raw_blocked: bool,
    raw_status: u16,
    raw_latency_ms: f64,
    evaded: Option<EvadeResult>,
}

#[derive(Debug, Serialize, Clone)]
struct EvadeResult {
    variants_total: usize,
    variants_bypassed: usize,
    bypass_rate: f64,
    /// Per-strategy breakdown.
    by_strategy: BTreeMap<String, StrategyStat>,
    /// Sample of techniques that produced bypasses (one per variant).
    bypass_techniques: Vec<String>,
}

#[derive(Debug, Serialize, Clone, Default)]
struct StrategyStat {
    variants: usize,
    bypassed: usize,
    bypass_rate: f64,
}

pub fn run_bench_waf(args: BenchWafArgs) -> ExitCode {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    match rt.block_on(run_bench_waf_async(args)) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{} {e}", "error:".red().bold());
            ExitCode::from(1)
        }
    }
}

fn resolve_base_url(args: &BenchWafArgs) -> String {
    if let Some(ref u) = args.base_url {
        return u.clone();
    }
    std::env::var("WAFRIFT_BENCH_URL")
        .or_else(|_| std::env::var("WAFRIFT_MODSEC_URL"))
        .unwrap_or_else(|_| "http://127.0.0.1:18081".into())
}

fn load_corpus(path: &Path) -> Result<Vec<BenchCase>, String> {
    let mut all = Vec::new();
    walk_corpus(path, &mut all)?;
    if all.is_empty() {
        return Err(format!(
            "no cases found at {} (expected *.toml files)",
            path.display()
        ));
    }
    Ok(all)
}

fn walk_corpus(path: &Path, out: &mut Vec<BenchCase>) -> Result<(), String> {
    if path.is_file() {
        return load_one(path, out);
    }
    let entries = fs::read_dir(path).map_err(|e| format!("read_dir {}: {e}", path.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let p = entry.path();
        if p.is_dir() {
            walk_corpus(&p, out)?;
        } else if p.extension().and_then(|s| s.to_str()) == Some("toml") {
            load_one(&p, out)?;
        }
    }
    Ok(())
}

fn load_one(path: &Path, out: &mut Vec<BenchCase>) -> Result<(), String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let file: CorpusFile = toml::from_str(&raw).map_err(|e| format!("{}: {e}", path.display()))?;
    out.extend(file.cases);
    Ok(())
}

fn build_request(base_url: &str, case: &BenchCase) -> Request {
    let payload = &case.payload;
    match case.mode.as_str() {
        "url_query_q" => {
            let url = format!(
                "{}/get?q={}",
                base_url.trim_end_matches('/'),
                urlencoding::encode(payload)
            );
            Request::get(url)
        }
        "raw_body" => {
            let url = format!("{}/post", base_url.trim_end_matches('/'));
            let mut r = Request::post(url, payload.as_bytes().to_vec());
            r.add_header("content-type", "text/plain");
            r
        }
        _ => {
            // body_form_q (default): POST /post with form-encoded body q=<payload>
            let url = format!("{}/post", base_url.trim_end_matches('/'));
            let body = format!("q={}", urlencoding::encode(payload));
            let mut r = Request::post(url, body.into_bytes());
            r.add_header("content-type", "application/x-www-form-urlencoded");
            r
        }
    }
}

async fn send(
    client: &Client,
    req: &Request,
    timeout_secs: u64,
) -> Result<(u16, bool, f64), String> {
    let start = Instant::now();
    let mut builder = match req.method {
        Method::Get => client.get(&req.url),
        Method::Post => client.post(&req.url),
        Method::Put => client.put(&req.url),
        Method::Delete => client.delete(&req.url),
        Method::Patch => client.patch(&req.url),
        _ => client.get(&req.url),
    };
    for (k, v) in &req.headers {
        builder = builder.header(k, v);
    }
    if let Some(body) = &req.body {
        builder = builder.body(body.clone());
    }
    builder = builder.timeout(std::time::Duration::from_secs(timeout_secs));
    let resp = builder.send().await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let body = resp.bytes().await.map_err(|e| e.to_string())?;
    let blocked = is_waf_block(status, &body);
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    Ok((status, blocked, elapsed_ms))
}

fn pick_level(name: &str) -> Option<Level> {
    match name {
        "light" => Some(Level::Light),
        "medium" => Some(Level::Medium),
        "heavy" => Some(Level::Heavy),
        _ => None,
    }
}

fn class_to_payload_type(class: &str) -> PayloadType {
    match class {
        "sql" => PayloadType::Sql,
        "xss" => PayloadType::Xss,
        "cmdi" => PayloadType::CommandInjection,
        "ssti" => PayloadType::TemplateInjection,
        "path" => PayloadType::PathTraversal,
        "ldap" => PayloadType::Ldap,
        "ssrf" => PayloadType::Ssrf,
        "nosql" => PayloadType::NoSql,
        // xxe / log4shell / cve_pocs have no wafrift mutator yet — fall back
        // to encoding-only mutations so the bench still runs.
        _ => PayloadType::Unknown,
    }
}

fn build_request_for_payload(base_url: &str, mode: &str, payload: &str) -> Request {
    match mode {
        "url_query_q" => {
            let url = format!(
                "{}/get?q={}",
                base_url.trim_end_matches('/'),
                urlencoding::encode(payload)
            );
            Request::get(url)
        }
        "raw_body" => {
            let url = format!("{}/post", base_url.trim_end_matches('/'));
            let mut r = Request::post(url, payload.as_bytes().to_vec());
            r.add_header("content-type", "text/plain");
            r
        }
        _ => {
            let url = format!("{}/post", base_url.trim_end_matches('/'));
            let body = format!("q={}", urlencoding::encode(payload));
            let mut r = Request::post(url, body.into_bytes());
            r.add_header("content-type", "application/x-www-form-urlencoded");
            r
        }
    }
}

async fn run_bench_waf_async(args: BenchWafArgs) -> Result<ExitCode, String> {
    let base_url = resolve_base_url(&args);
    let mut cases = load_corpus(&args.corpus)?;

    if !args.class.is_empty() {
        let want: std::collections::HashSet<&str> = args.class.iter().map(String::as_str).collect();
        cases.retain(|c| want.contains(c.class.as_str()));
    }
    if cases.is_empty() {
        return Err("no cases match the requested classes".into());
    }

    let mut client_builder = Client::builder()
        .timeout(std::time::Duration::from_secs(args.timeout_secs))
        .user_agent("wafrift-bench/0.1");
    if args.insecure {
        client_builder = client_builder.danger_accept_invalid_certs(true);
    }
    let client = client_builder
        .build()
        .map_err(|e| format!("HTTP client: {e}"))?;

    let mut results: Vec<CaseResult> = Vec::with_capacity(cases.len());

    for (idx, case) in cases.iter().enumerate() {
        if idx > 0 && args.delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(args.delay_ms)).await;
        }
        let req = build_request(&base_url, case);
        let (raw_status, raw_blocked, raw_latency_ms) = send(&client, &req, args.timeout_secs)
            .await
            .map_err(|e| format!("{} (raw): {e}", case.id))?;

        let evaded = if args.evade {
            Some(run_evade(&client, case, &base_url, &args).await?)
        } else {
            None
        };

        results.push(CaseResult {
            id: case.id.clone(),
            class: case.class.clone(),
            raw_blocked,
            raw_status,
            raw_latency_ms,
            evaded,
        });
    }

    emit_report(&base_url, &args, &results)?;

    // Exit code:
    //   0 — clean run
    //   2 — wafrift achieved zero bypasses on any case (in --evade mode only)
    let code = if args.evade
        && results
            .iter()
            .filter_map(|r| r.evaded.as_ref())
            .all(|e| e.variants_bypassed == 0)
    {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    };
    Ok(code)
}

async fn run_evade(
    client: &Client,
    case: &BenchCase,
    base_url: &str,
    args: &BenchWafArgs,
) -> Result<EvadeResult, String> {
    let mut by_strategy: BTreeMap<String, StrategyStat> = BTreeMap::new();
    let mut total = 0;
    let mut bypassed = 0;
    let mut bypass_techs: Vec<String> = Vec::new();

    let payload_type = class_to_payload_type(&case.class);

    for strat in &args.strategies {
        let stat = match strat.as_str() {
            "light" | "medium" | "heavy" => {
                run_payload_strategy(
                    client,
                    case,
                    base_url,
                    args,
                    strat,
                    payload_type,
                    &mut total,
                    &mut bypassed,
                    &mut bypass_techs,
                )
                .await
            }
            "mcts" => {
                run_mcts_strategy(
                    client,
                    case,
                    base_url,
                    args,
                    strat,
                    &mut total,
                    &mut bypassed,
                    &mut bypass_techs,
                )
                .await
            }
            "smuggling" => {
                run_smuggling_strategy(
                    client,
                    case,
                    base_url,
                    args,
                    strat,
                    &mut total,
                    &mut bypassed,
                    &mut bypass_techs,
                )
                .await
            }
            "content-type" => {
                run_content_type_strategy(
                    client,
                    case,
                    base_url,
                    args,
                    strat,
                    &mut total,
                    &mut bypassed,
                    &mut bypass_techs,
                )
                .await
            }
            "redos" => {
                run_redos_strategy(
                    client,
                    case,
                    base_url,
                    args,
                    strat,
                    &mut total,
                    &mut bypassed,
                    &mut bypass_techs,
                )
                .await
            }
            other => {
                eprintln!(
                    "warn: unknown strategy {other:?} (use light/medium/heavy/mcts/smuggling/content-type/redos)"
                );
                StrategyStat::default()
            }
        };
        by_strategy.insert(strat.clone(), stat);
    }

    let bypass_rate = if total > 0 {
        bypassed as f64 / total as f64
    } else {
        0.0
    };

    Ok(EvadeResult {
        variants_total: total,
        variants_bypassed: bypassed,
        bypass_rate,
        by_strategy,
        bypass_techniques: bypass_techs,
    })
}

/// Strategy: payload-string mutation (light/medium/heavy via build_variants).
#[allow(clippy::too_many_arguments)]
async fn run_payload_strategy(
    client: &Client,
    case: &BenchCase,
    base_url: &str,
    args: &BenchWafArgs,
    strat: &str,
    payload_type: PayloadType,
    total: &mut usize,
    bypassed: &mut usize,
    bypass_techs: &mut Vec<String>,
) -> StrategyStat {
    let mut stat = StrategyStat::default();
    let Some(level) = pick_level(strat) else {
        return stat;
    };
    let encoding_only = matches!(payload_type, PayloadType::Unknown);
    let variants: Vec<Variant> = build_variants(
        &case.payload,
        payload_type,
        encoding_only,
        &strategies_for_level(level),
        max_mutations_for_level(level),
    )
    .into_iter()
    .take(args.variants)
    .collect();

    for variant in &variants {
        if *total > 0 && args.delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(args.delay_ms)).await;
        }
        let req = build_request_for_payload(base_url, &case.mode, &variant.payload);
        stat.variants += 1;
        *total += 1;
        match send(client, &req, args.timeout_secs).await {
            Ok((_s, blocked, _l)) if !blocked => {
                stat.bypassed += 1;
                *bypassed += 1;
                bypass_techs.push(format!("{}:{}", strat, variant.techniques.join("+")));
            }
            Ok(_) => {}
            Err(e) => eprintln!("warn: {} ({}) send: {e}", case.id, strat),
        }
    }
    if stat.variants > 0 {
        stat.bypass_rate = stat.bypassed as f64 / stat.variants as f64;
    }
    stat
}

/// Strategy: MCTS — wafrift::strategy::evade_mcts learns the WAF mid-run by
/// playing N games against it (depth-bounded action search with mctrust 0.4).
async fn run_mcts_strategy(
    client: &Client,
    case: &BenchCase,
    base_url: &str,
    args: &BenchWafArgs,
    strat: &str,
    total: &mut usize,
    bypassed: &mut usize,
    bypass_techs: &mut Vec<String>,
) -> StrategyStat {
    let mut stat = StrategyStat::default();
    let config = EvasionConfig::maximum();
    let base_req = build_request(base_url, case);

    // MCTS is deterministic per (request, config, depth). Sweep depths so we
    // produce up to args.variants distinct samples.
    for depth_idx in 0..args.variants {
        if *total > 0 && args.delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(args.delay_ms)).await;
        }
        let depth = 2 + (depth_idx % 5);
        let Some(evaded) = evade_mcts(&base_req, &config, depth) else {
            continue;
        };
        stat.variants += 1;
        *total += 1;
        match send(client, &evaded.request, args.timeout_secs).await {
            Ok((_s, blocked, _l)) if !blocked => {
                stat.bypassed += 1;
                *bypassed += 1;
                bypass_techs.push(format!("{strat}:depth{depth}:{}", evaded.description));
            }
            Ok(_) => {}
            Err(e) => eprintln!("warn: {} ({}) send: {e}", case.id, strat),
        }
    }
    if stat.variants > 0 {
        stat.bypass_rate = stat.bypassed as f64 / stat.variants as f64;
    }
    stat
}

/// Strategy: HTTP request smuggling — CL.TE / TE.CL / TE.TE / dual-CL / etc.
/// Sends a smuggled payload via raw socket so the WAF parser sees harmless
/// data while the backend parser ingests the smuggled-prefix payload.
async fn run_smuggling_strategy(
    client: &Client,
    case: &BenchCase,
    base_url: &str,
    args: &BenchWafArgs,
    strat: &str,
    total: &mut usize,
    bypassed: &mut usize,
    bypass_techs: &mut Vec<String>,
) -> StrategyStat {
    let mut stat = StrategyStat::default();
    let host = base_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_string();
    // Build the smuggled prefix as a POST containing the payload.
    let smuggled = format!(
        "POST /post HTTP/1.1\r\nHost: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\nq={}",
        host,
        case.payload.len() + 2,
        urlencoding::encode(&case.payload)
    );
    let payloads = smuggling_all_payloads(&host, &smuggled);
    for sp in payloads.iter().take(args.variants) {
        if *total > 0 && args.delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(args.delay_ms)).await;
        }
        // Send the raw smuggled bytes as a POST body — this is a synthetic
        // probe (not real wire-level smuggling), but it exercises the WAF's
        // parser for the smuggling shapes wafrift knows how to construct.
        let url = format!("{}/post", base_url.trim_end_matches('/'));
        let mut req = Request::post(url, sp.raw_bytes.clone());
        req.add_header("content-type", "application/octet-stream");
        stat.variants += 1;
        *total += 1;
        match send(client, &req, args.timeout_secs).await {
            Ok((_s, blocked, _l)) if !blocked => {
                stat.bypassed += 1;
                *bypassed += 1;
                bypass_techs.push(format!("{strat}:{:?}", sp.variant));
            }
            Ok(_) => {}
            Err(e) => eprintln!("warn: {} ({}) send: {e}", case.id, strat),
        }
    }
    if stat.variants > 0 {
        stat.bypass_rate = stat.bypassed as f64 / stat.variants as f64;
    }
    stat
}

/// Strategy: Content-Type confusion — wrap payload in many Content-Types so
/// WAF parser disagrees with backend parser.
async fn run_content_type_strategy(
    client: &Client,
    case: &BenchCase,
    base_url: &str,
    args: &BenchWafArgs,
    strat: &str,
    total: &mut usize,
    bypassed: &mut usize,
    bypass_techs: &mut Vec<String>,
) -> StrategyStat {
    let mut stat = StrategyStat::default();
    let form_body = format!("q={}", urlencoding::encode(&case.payload));
    let variants = generate_variants_from_body(form_body.as_bytes());
    for v in variants.iter().take(args.variants) {
        if *total > 0 && args.delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(args.delay_ms)).await;
        }
        let url = format!("{}/post", base_url.trim_end_matches('/'));
        let mut req = Request::post(url, v.body.clone());
        req.add_header("content-type", v.content_type.clone());
        stat.variants += 1;
        *total += 1;
        match send(client, &req, args.timeout_secs).await {
            Ok((_s, blocked, _l)) if !blocked => {
                stat.bypassed += 1;
                *bypassed += 1;
                bypass_techs.push(format!("{strat}:{:?}", v.technique));
            }
            Ok(_) => {}
            Err(e) => eprintln!("warn: {} ({}) send: {e}", case.id, strat),
        }
    }
    if stat.variants > 0 {
        stat.bypass_rate = stat.bypassed as f64 / stat.variants as f64;
    }
    stat
}

/// Strategy: ReDoS — wrap payload in catastrophic-backtracking patterns.
///
/// Goal is to force the WAF's regex engine into exponential evaluation time
/// so it hits its per-rule timeout. Some WAFs fail-OPEN on rule timeout,
/// passing the request through; others fail-closed. This strategy is most
/// useful against legacy/embedded WAFs with PCRE engines that lack timeouts.
async fn run_redos_strategy(
    client: &Client,
    case: &BenchCase,
    base_url: &str,
    args: &BenchWafArgs,
    strat: &str,
    total: &mut usize,
    bypassed: &mut usize,
    bypass_techs: &mut Vec<String>,
) -> StrategyStat {
    let mut stat = StrategyStat::default();
    let p = &case.payload;
    // Wrap shapes: each is a string designed to force exponential backtracking
    // when matched by a naive regex engine. Suffix the actual payload after
    // the trigger so semantic meaning survives.
    let shapes: Vec<(&str, String)> = vec![
        ("classic_aabb", format!("{}{}", "a".repeat(50), p)),
        ("group_plus", format!("{}{}", "a".repeat(40), p)),
        (
            "alternation_overlap",
            format!("{}{}", "ab".repeat(30), p),
        ),
        (
            "nested_quantifier",
            format!("{}{}", "x".repeat(80), p),
        ),
        (
            "evil_email_shape",
            format!("a@{}.{}", "a".repeat(50), p),
        ),
        // Long Unicode escape sequence — most regex implementations slow down
        // on large surrogate-pair sequences.
        (
            "unicode_storm",
            format!("{}{}", "\\u00ff".repeat(40), p),
        ),
        // Repeated backslash quoting — known historical CRS slowdown.
        ("backslash_storm", format!("{}{}", "\\\\".repeat(60), p)),
        // Many word-boundary anchors — \b matching forces re-evaluation.
        (
            "word_boundary_storm",
            format!("{}{}", " a ".repeat(40), p),
        ),
    ];

    for (label, blob) in shapes.iter().take(args.variants) {
        if *total > 0 && args.delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(args.delay_ms)).await;
        }
        let req = build_request_for_payload(base_url, &case.mode, blob);
        stat.variants += 1;
        *total += 1;
        match send(client, &req, args.timeout_secs).await {
            Ok((_s, blocked, _l)) if !blocked => {
                stat.bypassed += 1;
                *bypassed += 1;
                bypass_techs.push(format!("{strat}:{label}"));
            }
            Ok(_) => {}
            Err(e) => eprintln!("warn: {} ({}) send: {e}", case.id, strat),
        }
    }
    if stat.variants > 0 {
        stat.bypass_rate = stat.bypassed as f64 / stat.variants as f64;
    }
    stat
}

fn emit_report(base_url: &str, args: &BenchWafArgs, results: &[CaseResult]) -> Result<(), String> {
    // Aggregate by class.
    let mut by_class: BTreeMap<String, Vec<&CaseResult>> = BTreeMap::new();
    for r in results {
        by_class.entry(r.class.clone()).or_default().push(r);
    }

    let aggregate = serde_json::json!({
        "base_url": base_url,
        "evade_mode": args.evade,
        "strategies": args.strategies,
        "variants_per_case_per_strategy": args.variants,
        "total_cases": results.len(),
        "raw_blocked": results.iter().filter(|r| r.raw_blocked).count(),
        "raw_block_rate": results.iter().filter(|r| r.raw_blocked).count() as f64
            / results.len() as f64,
        "evaded_summary": args.evade.then(|| {
            let total: usize = results.iter().filter_map(|r| r.evaded.as_ref()).map(|e| e.variants_total).sum();
            let bypassed: usize = results.iter().filter_map(|r| r.evaded.as_ref()).map(|e| e.variants_bypassed).sum();
            serde_json::json!({
                "total_variants_sent": total,
                "total_variants_bypassed": bypassed,
                "overall_bypass_rate": if total > 0 { bypassed as f64 / total as f64 } else { 0.0 },
                "cases_with_at_least_one_bypass": results.iter().filter_map(|r| r.evaded.as_ref()).filter(|e| e.variants_bypassed > 0).count(),
            })
        }),
        "by_class": by_class.iter().map(|(class, rs)| {
            let raw_blocked = rs.iter().filter(|r| r.raw_blocked).count();
            let evaded_total: usize = rs.iter().filter_map(|r| r.evaded.as_ref()).map(|e| e.variants_total).sum();
            let evaded_bypassed: usize = rs.iter().filter_map(|r| r.evaded.as_ref()).map(|e| e.variants_bypassed).sum();
            (class.clone(), serde_json::json!({
                "cases": rs.len(),
                "raw_blocked": raw_blocked,
                "raw_block_rate": raw_blocked as f64 / rs.len() as f64,
                "evaded_total": evaded_total,
                "evaded_bypassed": evaded_bypassed,
                "bypass_rate": if evaded_total > 0 { evaded_bypassed as f64 / evaded_total as f64 } else { 0.0 },
            }))
        }).collect::<serde_json::Map<_, _>>(),
        "results": results,
    });

    if let Some(path) = &args.output {
        fs::write(
            path,
            serde_json::to_string_pretty(&aggregate).map_err(|e| e.to_string())?,
        )
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    }

    if args.format == "json" {
        println!(
            "{}",
            serde_json::to_string_pretty(&aggregate).map_err(|e| e.to_string())?
        );
    } else {
        println!(
            "{}",
            format!("WAF bench — {base_url} ({} cases)", results.len()).bold()
        );
        println!();
        println!(
            "{:<28} {:<8} {:>5} {:>9} {:>9} {:>9}",
            "id", "class", "raw", "ev_sent", "ev_pass", "rate"
        );
        println!("{}", "—".repeat(78));
        for r in results {
            let raw = if r.raw_blocked {
                "blk".red().to_string()
            } else {
                "ok ".yellow().to_string()
            };
            let (sent, passed, rate) = if let Some(e) = &r.evaded {
                (
                    e.variants_total.to_string(),
                    e.variants_bypassed.to_string(),
                    format!("{:.1}%", e.bypass_rate * 100.0),
                )
            } else {
                ("—".into(), "—".into(), "—".into())
            };
            println!(
                "{:<28} {:<8} {:>5} {:>9} {:>9} {:>9}",
                truncate(&r.id, 28),
                truncate(&r.class, 8),
                raw,
                sent,
                passed,
                rate,
            );
        }
        println!("{}", "—".repeat(78));
        println!();
        println!("{}", "by class:".bold());
        for (class, rs) in &by_class {
            let raw_blocked = rs.iter().filter(|r| r.raw_blocked).count();
            let raw_rate = raw_blocked as f64 / rs.len() as f64;
            let evaded_total: usize = rs
                .iter()
                .filter_map(|r| r.evaded.as_ref())
                .map(|e| e.variants_total)
                .sum();
            let evaded_bypassed: usize = rs
                .iter()
                .filter_map(|r| r.evaded.as_ref())
                .map(|e| e.variants_bypassed)
                .sum();
            let bypass_pct = if evaded_total > 0 {
                evaded_bypassed as f64 / evaded_total as f64 * 100.0
            } else {
                0.0
            };
            if args.evade {
                println!(
                    "  {:<10} {:>3} cases  raw-block {:>5.1}%  bypass {:>5.1}% ({}/{})",
                    class,
                    rs.len(),
                    raw_rate * 100.0,
                    bypass_pct,
                    evaded_bypassed,
                    evaded_total
                );
            } else {
                println!(
                    "  {:<10} {:>3} cases  raw-block {:>5.1}%",
                    class,
                    rs.len(),
                    raw_rate * 100.0
                );
            }
        }
    }
    Ok(())
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n.saturating_sub(1)])
    }
}
