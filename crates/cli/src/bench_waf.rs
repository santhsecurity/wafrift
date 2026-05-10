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

#![allow(clippy::too_many_arguments)]

use colored::Colorize;
use rand::SeedableRng;
use rand::rngs::StdRng;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;
use wafrift_content_type::generate_variants_from_body;
use wafrift_evolution::differential::{Probe, ProbeTarget, generate_probes};
use wafrift_evolution::evolution::{EvolutionEngine, GenePool};
use wafrift_evolution::lineage::{BypassCorpus, BypassEntry};
use wafrift_evolution::types::Budget;
use wafrift_grammar::grammar::{self, PayloadType};
use wafrift_oracle::cmdi::CmdiOracle;
use wafrift_oracle::ldap::LdapOracle;
use wafrift_oracle::path::PathOracle;
use wafrift_oracle::sql::{self as sql_oracle, DatabaseDialect};
use wafrift_oracle::ssrf::SsrfOracle;
use wafrift_oracle::ssti::SstiOracle;
use wafrift_oracle::traits::PayloadOracle;
use wafrift_oracle::xss::XssOracle;
use wafrift_smuggling::smuggling::all_payloads as smuggling_all_payloads;
use wafrift_strategy::{EvasionConfig, evade_mcts};
use wafrift_transport::is_waf_block;
use wafrift_types::{Method, Request};

use crate::Level;
use crate::helpers::{Variant, build_variants, max_mutations_for_level, strategies_for_level};

/// Canonical list of every selectable bench strategy. `--strategies all`
/// expands to this. Keep in dependency-light → expensive order so that
/// output JSON has a sensible default sort.
const ALL_STRATEGIES: &[&str] = &[
    "heavy",
    "mcts",
    "smuggling",
    "content-type",
    "redos",
    "hill-climb",
    "sim-anneal",
    "tabu",
    "novelty",
    "map-elites",
    "differential",
];

#[derive(Debug, clap::Args)]
pub struct BenchWafArgs {
    /// Base URL of the WAF target (e.g. http://127.0.0.1:18081).
    /// If omitted, uses `WAFRIFT_BENCH_URL` or `http://127.0.0.1:18081`.
    #[arg(long)]
    pub base_url: Option<String>,

    /// Single TOML corpus file OR directory of TOML files (recursive).
    /// Defaults to the in-tree bench corpus path; if you installed
    /// wafrift via `cargo install` (no checkout), pass `--corpus` to a
    /// directory you cloned from
    /// https://github.com/santhsecurity/wafrift/tree/main/wafrift-bench/corpus
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
    /// Pass `--strategies all` to run the full set in one shot.
    /// Available:
    ///   light / medium / heavy   — payload-string mutation via build_variants
    ///   mcts                      — Monte Carlo Tree Search over actions (mctrust)
    ///   smuggling                 — HTTP request smuggling variants (CL.TE / TE.CL / TE.TE / dual-CL)
    ///   content-type              — Content-Type confusion variants (multipart/json/xml/...)
    ///   redos                     — wrap payload in catastrophic-backtracking patterns
    ///   hill-climb / sim-anneal / tabu / novelty / map-elites
    ///                              — feedback-driven search via wafrift-evolution
    ///   differential              — class-filtered probes from wafrift-evolution::differential
    ///                              (rule-fingerprint coverage; "what does this WAF NOT block")
    #[arg(long, value_delimiter = ',', default_value = "heavy")]
    pub strategies: Vec<String>,

    /// Gate bypass count by oracle (per-class semantic validity check).
    /// When set, a "bypassed" variant is only counted if the corresponding
    /// payload oracle agrees the variant is structurally a valid attack
    /// (i.e. would actually trigger the vulnerability server-side, not
    /// garbage that slipped past because nothing parsed it).
    #[arg(long, default_value_t = false)]
    pub oracle_gate: bool,

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

    /// Emit only the aggregate summary (skip per-case details). Cuts JSON
    /// output by 100x for CI gating.
    #[arg(long, default_value_t = false)]
    pub summary_only: bool,

    /// Skip the upstream healthcheck before benching. By default the bench
    /// pings the WAF target's /get endpoint first and fails fast with an
    /// actionable error if the target isn't responding (so 30k connection
    /// errors don't masquerade as 100% block rate).
    #[arg(long, default_value_t = false)]
    pub skip_healthcheck: bool,

    /// Adaptive throttle: if this many consecutive sends fail at the
    /// connection level (target is overwhelmed), pause for 2s and continue
    /// at half-speed. 0 disables. Default 50.
    #[arg(long, default_value_t = 50)]
    pub adaptive_pause_after_errors: u32,

    /// Just validate the corpus and exit — load every TOML, check every
    /// case has a unique id + non-empty payload + a known class, then
    /// report counts and exit. Doesn't connect to the WAF target. Useful
    /// in CI to catch corpus drift without standing a WAF up.
    #[arg(long, default_value_t = false)]
    pub validate_only: bool,

    /// Persist successful evolution-strategy bypasses (genes + lineage trace)
    /// to this JSON file as a `BypassCorpus`. Each entry is replayable: the
    /// gene tuple is enough to reconstruct the exact wire payload, and the
    /// lineage trace records every mutation step that led to it. When unset,
    /// bypasses still count toward the headline rate but are not persisted.
    /// Only the search-loop strategies (hill-climb / sim-anneal / tabu /
    /// novelty / map-elites) populate lineage — the static strategies have
    /// no chromosome.
    #[arg(long)]
    pub lineage_output: Option<PathBuf>,
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
    /// Variants the oracle confirmed were semantically valid (only when
    /// --oracle-gate is on). 0 if oracle gating disabled.
    variants_oracle_valid: usize,
    oracle_valid_rate: f64,
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
    oracle_valid: usize,
}

/// Returns true if the variant retains the exploit semantics of the original
/// payload for `class`. Per-class structural validity check via the
/// corresponding oracle in wafrift-oracle. Falls back to true only for
/// classes that genuinely have no oracle (cve_pocs is held-out test data).
fn oracle_valid(class: &str, original: &str, transformed: &str) -> bool {
    match class {
        "sql" => sql_oracle::is_valid_expression_injection(transformed, DatabaseDialect::Generic),
        "xss" => XssOracle.is_semantically_valid(original, transformed),
        "cmdi" => CmdiOracle.is_semantically_valid(original, transformed),
        "ssti" => SstiOracle.is_semantically_valid(original, transformed),
        "path" => PathOracle.is_semantically_valid(original, transformed),
        "ldap" => LdapOracle.is_semantically_valid(original, transformed),
        "ssrf" => SsrfOracle.is_semantically_valid(original, transformed),
        "nosql" => is_valid_nosql(original, transformed),
        "xxe" => is_valid_xxe(original, transformed),
        "log4shell" => is_valid_log4shell(original, transformed),
        // cve_pocs is the held-out test set — accept on faith and let the
        // per-payload oracle (if applicable based on payload content) gate.
        _ => true,
    }
}

/// NoSQL injection structural validity: the variant must still contain at
/// least one MongoDB operator marker ($ne / $gt / $regex / $where / $or /
/// $in / $exists / $type) OR a MongoDB-style operator-key bracket form
/// (`[$op]=`). Without these the parser won't see it as a NoSQL filter.
fn is_valid_nosql(_original: &str, transformed: &str) -> bool {
    const MONGO_OPS: &[&str] = &[
        "$ne",
        "$gt",
        "$lt",
        "$gte",
        "$lte",
        "$regex",
        "$where",
        "$or",
        "$and",
        "$in",
        "$nin",
        "$exists",
        "$type",
        "$elemMatch",
        "$all",
    ];
    MONGO_OPS.iter().any(|op| transformed.contains(op)) || transformed.contains("[$")
}

/// XXE structural validity: the transformed payload must still parse as XML
/// with at least one ENTITY / DOCTYPE / XInclude marker. Otherwise it's just
/// a string with `<` characters, not an XML attack.
fn is_valid_xxe(_original: &str, transformed: &str) -> bool {
    let lower = transformed.to_ascii_lowercase();
    let has_xml_decl_or_root = lower.contains("<?xml")
        || lower.contains("<!doctype")
        || lower.contains("<soap:")
        || lower.contains("<svg")
        || (lower.contains('<') && lower.contains("xmlns"));
    let has_xxe_marker = lower.contains("<!entity")
        || lower.contains("system ")
        || lower.contains("xi:include")
        || lower.contains("file://")
        || lower.contains("php://");
    has_xml_decl_or_root && has_xxe_marker
}

/// Log4Shell structural validity: must still contain a JNDI lookup expression.
/// Common shapes: `${jndi:`, obfuscated `${${lower:j}ndi:`, `${${env:NaN:-j}ndi:`,
/// percent-encoded `%24%7Bjndi`. We accept anything that resolves to a JNDI
/// scheme on lookup.
fn is_valid_log4shell(_original: &str, transformed: &str) -> bool {
    let lower = transformed.to_ascii_lowercase();
    // Direct or partially-obfuscated forms.

    lower.contains("${jndi:")
        || lower.contains("ndi:ldap")
        || lower.contains("ndi:rmi")
        || lower.contains("ndi:dns")
        || lower.contains("ndi:iiop")
        || lower.contains("ndi:corba")
        || lower.contains("ndi:nis")
        || lower.contains("ndi:nds")
        || lower.contains("ndi:ldaps")
        // URL-encoded ${
        || lower.contains("%24%7bjndi")
        || lower.contains("%2524%257bjndi")
}

pub fn run_bench_waf(args: BenchWafArgs) -> ExitCode {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "{} failed to start tokio runtime: {e}",
                "error:".red().bold()
            );
            return ExitCode::from(1);
        }
    };
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

/// Static set of attack classes accepted in the bench corpus. Anything else
/// is treated as a typo (better to fail loud than silently miscategorize).
const KNOWN_CLASSES: &[&str] = &[
    "sql",
    "xss",
    "cmdi",
    "ssti",
    "path",
    "ldap",
    "ssrf",
    "nosql",
    "xxe",
    "log4shell",
    "cve_pocs",
];

fn validate_corpus_and_exit(cases: &[BenchCase]) -> Result<ExitCode, String> {
    use std::collections::{BTreeMap, HashSet};
    let mut seen: HashSet<&str> = HashSet::new();
    let mut by_class: BTreeMap<&str, usize> = BTreeMap::new();
    let mut errors: Vec<String> = Vec::new();
    for case in cases {
        if !seen.insert(&case.id) {
            errors.push(format!("duplicate id: {}", case.id));
        }
        if case.payload.is_empty() {
            errors.push(format!("empty payload: {}", case.id));
        }
        if !KNOWN_CLASSES.contains(&case.class.as_str()) {
            errors.push(format!(
                "unknown class {:?} on {} (must be one of {:?})",
                case.class, case.id, KNOWN_CLASSES
            ));
        }
        *by_class.entry(case.class.as_str()).or_insert(0) += 1;
    }
    println!("corpus integrity:");
    println!("  total cases: {}", cases.len());
    for (cls, n) in &by_class {
        println!("  {:>10}: {n}", cls);
    }
    if errors.is_empty() {
        println!("OK ({} cases)", cases.len());
        Ok(ExitCode::SUCCESS)
    } else {
        for e in &errors {
            eprintln!("  ERROR: {e}");
        }
        eprintln!("{} corpus error(s)", errors.len());
        Ok(ExitCode::from(4))
    }
}

fn load_corpus(path: &Path) -> Result<Vec<BenchCase>, String> {
    let mut all = Vec::new();
    walk_corpus(path, &mut all)?;
    if all.is_empty() {
        return Err(format!(
            "no cases found at {} (expected *.toml files).\n  \
             Hint: clone the bundled corpus from \
             https://github.com/santhsecurity/wafrift/tree/main/wafrift-bench/corpus \
             or pass --corpus PATH to a directory of TOML files matching the schema in \
             wafrift-bench/corpus/sql/blind.toml.",
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

async fn run_bench_waf_async(mut args: BenchWafArgs) -> Result<ExitCode, String> {
    // `--strategies all` expands to every selectable strategy. Lets a user
    // type one keyword instead of remembering the 11-element list. Keeps
    // user-supplied order otherwise (output ordering matters for diffs).
    if args.strategies.iter().any(|s| s == "all") {
        args.strategies = ALL_STRATEGIES.iter().map(|s| s.to_string()).collect();
    }

    let base_url = resolve_base_url(&args);
    let mut cases = load_corpus(&args.corpus)?;

    // --validate-only: run corpus integrity checks then exit. Doesn't
    // need a live WAF target; intended for CI gating on corpus PRs.
    if args.validate_only {
        return validate_corpus_and_exit(&cases);
    }

    if !args.class.is_empty() {
        let want: std::collections::HashSet<&str> = args.class.iter().map(String::as_str).collect();
        cases.retain(|c| want.contains(c.class.as_str()));
    }
    if cases.is_empty() {
        return Err(format!(
            "no cases match the requested classes {:?}. \
             Hint: omit --class to run every class, or pick from the set printed by \
             `wafrift bench-waf --validate-only --corpus {}` (look at the per-class counts).",
            args.class,
            args.corpus.display()
        ));
    }

    // Pick a randomized real-browser User-Agent (vs. the obvious
    // wafrift-bench/0.1 marker) so the WAF doesn't have a free signal.
    let ua = wafrift_fingerprint::fingerprint::random_profile()
        .map(|p| p.user_agent.to_string())
        .unwrap_or_else(|| "Mozilla/5.0".into());

    let mut client_builder = Client::builder()
        .timeout(std::time::Duration::from_secs(args.timeout_secs))
        .user_agent(ua);
    if args.insecure {
        client_builder = client_builder.danger_accept_invalid_certs(true);
    }
    let client = client_builder
        .build()
        .map_err(|e| format!("HTTP client: {e}"))?;

    // Healthcheck: make sure the target is even reachable before we
    // queue 30k probes that would all "fail" with connection errors.
    if !args.skip_healthcheck {
        let probe_url = format!("{}/get", base_url.trim_end_matches('/'));
        match client
            .get(&probe_url)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
        {
            Ok(_) => {}
            Err(e) => {
                return Err(format!(
                    "healthcheck failed: cannot reach {probe_url}: {e}\n\
                     Hint: bring the WAF stack up first. \
                     For the bundled stacks, e.g. `wafrift-bench/scripts/up.sh modsec-pl1`. \
                     Pass --skip-healthcheck to override."
                ));
            }
        }
    }

    // Adaptive throttle state: consecutive connection errors -> pause + slow down.
    let consecutive_errors = std::sync::atomic::AtomicU32::new(0);
    let extra_delay_ms = std::sync::atomic::AtomicU64::new(0);

    let mut results: Vec<CaseResult> = Vec::with_capacity(cases.len());

    // Bypass corpus: collected when --lineage-output is set. Flushed once at
    // end of bench so a partial-run kill still loses only the in-flight case.
    let mut bypass_corpus: Option<BypassCorpus> =
        args.lineage_output.as_ref().map(|_| BypassCorpus::new());

    use std::sync::atomic::Ordering;

    for (idx, case) in cases.iter().enumerate() {
        if idx > 0 {
            let total_delay = args.delay_ms + extra_delay_ms.load(Ordering::Relaxed);
            if total_delay > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(total_delay)).await;
            }
        }
        let req = build_request(&base_url, case);
        let (raw_status, raw_blocked, raw_latency_ms) = match send(&client, &req, args.timeout_secs)
            .await
        {
            Ok(t) => {
                consecutive_errors.store(0, Ordering::Relaxed);
                t
            }
            Err(e) => {
                eprintln!("warn: {} (raw): {e}", case.id);
                let n = consecutive_errors.fetch_add(1, Ordering::Relaxed) + 1;
                if args.adaptive_pause_after_errors > 0 && n == args.adaptive_pause_after_errors {
                    eprintln!(
                        "warn: {n} consecutive connection errors — pausing 2s and \
                             doubling per-request delay (target may be choked)"
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    let prev = extra_delay_ms.load(Ordering::Relaxed);
                    extra_delay_ms.store(prev.max(50) + args.delay_ms, Ordering::Relaxed);
                    consecutive_errors.store(0, Ordering::Relaxed);
                }
                (0, true, 0.0)
            }
        };

        let evaded = if args.evade {
            Some(run_evade(&client, case, &base_url, &args, &mut bypass_corpus).await?)
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

    // Persist evolution-strategy bypass corpus (lineage-replayable). Single
    // atomic write at end so a torn run never leaves a half-corpus on disk.
    if let (Some(path), Some(corpus)) = (args.lineage_output.as_ref(), bypass_corpus.as_ref()) {
        if let Err(e) = corpus.save(path) {
            eprintln!(
                "warn: lineage corpus write to {} failed: {e:?}",
                path.display()
            );
        } else {
            eprintln!(
                "wrote {} bypass entries (lineage-traced) to {}",
                corpus.entries.len(),
                path.display()
            );
        }
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
    bypass_corpus: &mut Option<BypassCorpus>,
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
            "hill-climb" | "sim-anneal" | "tabu" | "novelty" | "map-elites" => {
                run_evolution_strategy(
                    client,
                    case,
                    base_url,
                    args,
                    strat,
                    &mut total,
                    &mut bypassed,
                    &mut bypass_techs,
                    bypass_corpus,
                )
                .await
            }
            "differential" => {
                run_differential_strategy(
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
                    "warn: unknown strategy {other:?} (light/medium/heavy/mcts/smuggling/content-type/redos/hill-climb/sim-anneal/tabu/novelty/map-elites/differential)"
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
    let oracle_valid_total: usize = by_strategy.values().map(|s| s.oracle_valid).sum();
    let oracle_valid_rate = if total > 0 {
        oracle_valid_total as f64 / total as f64
    } else {
        0.0
    };
    // Compute per-strategy bypass+oracle rates (was missing on stats produced
    // by some branches; redundant when already set, idempotent).
    for s in by_strategy.values_mut() {
        if s.variants > 0 {
            s.bypass_rate = s.bypassed as f64 / s.variants as f64;
        }
    }

    Ok(EvadeResult {
        variants_total: total,
        variants_bypassed: bypassed,
        bypass_rate,
        variants_oracle_valid: oracle_valid_total,
        oracle_valid_rate,
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
                if oracle_valid(&case.class, &case.payload, &variant.payload) {
                    stat.oracle_valid += 1;
                }
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

/// Strategy: feedback-driven evolution search — wafrift_evolution::EvolutionEngine
/// runs one of {hill_climbing, simulated_annealing, tabu_search, novelty_search,
/// map_elites}. For each round we get a candidate chromosome, render it to a
/// payload (apply the chromosome's grammar + encoding genes to case.payload),
/// send it, and feed the WAF's verdict back. The algorithm learns which gene
/// combos beat *this* WAF as the round progresses — same loop the production
/// `wafrift scan` uses, just headless against a corpus instead of a live host.
async fn run_evolution_strategy(
    client: &Client,
    case: &BenchCase,
    base_url: &str,
    args: &BenchWafArgs,
    strat: &str,
    total: &mut usize,
    bypassed: &mut usize,
    bypass_techs: &mut Vec<String>,
    bypass_corpus: &mut Option<BypassCorpus>,
) -> StrategyStat {
    let mut stat = StrategyStat::default();
    let algo_name = match strat {
        "hill-climb" => "hill_climbing",
        "sim-anneal" => "simulated_annealing",
        "tabu" => "tabu_search",
        "novelty" => "novelty_search",
        "map-elites" => "map_elites",
        _ => return stat,
    };
    let payload_type = class_to_payload_type(&case.class);
    let rng = StdRng::seed_from_u64(0xC0FFEE);
    let gene_pool = GenePool::default_wafrift();
    let budget = Budget {
        max_requests: args.variants.saturating_mul(4),
        ..Default::default()
    };

    let mut engine = match EvolutionEngine::with_algorithm(algo_name, gene_pool, rng, budget) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("warn: {} ({strat}) engine init: {e:?}", case.id);
            return stat;
        }
    };

    for _ in 0..args.variants {
        if *total > 0 && args.delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(args.delay_ms)).await;
        }
        let (idx, rendered_payload, technique_label, chromosome_snapshot) =
            match engine.next_candidate() {
                Some((i, c)) => {
                    let (p, l) = render_chromosome(c, &case.payload, payload_type);
                    // Snapshot the chromosome (genes + lineage) for replay
                    // before we lose the borrow on the next loop iteration.
                    // Only when corpus collection is on — saves a clone otherwise.
                    let snap = bypass_corpus.as_ref().map(|_| c.clone());
                    (i, p, l, snap)
                }
                None => break,
            };
        let req = build_request_for_payload(base_url, &case.mode, &rendered_payload);
        stat.variants += 1;
        *total += 1;
        let blocked_actual = match send(client, &req, args.timeout_secs).await {
            Ok((_s, blocked, _l)) => blocked,
            Err(e) => {
                eprintln!("warn: {} ({strat}) send: {e}", case.id);
                let _ = engine.record_feedback(idx, false);
                continue;
            }
        };
        let _ = engine.record_feedback(idx, !blocked_actual);
        if !blocked_actual {
            stat.bypassed += 1;
            *bypassed += 1;
            if oracle_valid(&case.class, &case.payload, &rendered_payload) {
                stat.oracle_valid += 1;
            }
            bypass_techs.push(format!("{strat}:{technique_label}"));
            if let (Some(corpus), Some(chromo)) =
                (bypass_corpus.as_mut(), chromosome_snapshot.as_ref())
            {
                let entry =
                    BypassEntry::from_chromosome(chromo, Some(format!("{strat}::{}", case.id)));
                corpus.add(entry);
            }
        }
    }
    if stat.variants > 0 {
        stat.bypass_rate = stat.bypassed as f64 / stat.variants as f64;
    }
    stat
}

/// Render a chromosome to a wire payload by applying its grammar + encoding genes
/// to the original payload. Mirrors the renderer in `wafrift scan`'s intel loop.
fn render_chromosome(
    chromosome: &wafrift_evolution::evolution::Chromosome,
    base_payload: &str,
    payload_type: PayloadType,
) -> (String, String) {
    use wafrift_encoding::encoding;

    let has_grammar = chromosome.genes.iter().any(|(k, _)| k == "grammar");
    let mut techniques: Vec<String> = Vec::new();
    let intel_payload = if has_grammar {
        let muts = grammar::mutate_as(base_payload, payload_type, 1);
        if let Some(m) = muts.first() {
            techniques.push("grammar".into());
            m.payload.clone()
        } else {
            base_payload.to_string()
        }
    } else {
        base_payload.to_string()
    };
    let encoded = chromosome
        .genes
        .iter()
        .find(|(k, _)| k == "encoding")
        .and_then(|(_, v)| {
            if v == "None" {
                return None;
            }
            encoding::all_strategies()
                .iter()
                .find(|s| s.as_str() == v.as_str())
                .copied()
                .and_then(|s| {
                    encoding::encode(&intel_payload, s).ok().inspect(|_enc| {
                        techniques.push(format!("enc:{}", s.as_str()));
                    })
                })
        })
        .unwrap_or(intel_payload);
    let label = if techniques.is_empty() {
        "raw".into()
    } else {
        techniques.join("+")
    };
    (encoded, label)
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
                // MCTS preserves payload semantics by construction (it's
                // selecting actions that wrap the same payload, not mutating it).
                stat.oracle_valid += 1;
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
    let payloads = match smuggling_all_payloads(&host, &smuggled) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("warn: {} (smuggling) payload generation: {e}", case.id);
            return stat;
        }
    };
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
                // Smuggling preserves the payload bytes exactly — they're
                // wrapped in a smuggled HTTP request, not mutated.
                stat.oracle_valid += 1;
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
                // Content-Type confusion changes the wrapper, not the payload —
                // semantics preserved.
                stat.oracle_valid += 1;
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
        ("alternation_overlap", format!("{}{}", "ab".repeat(30), p)),
        ("nested_quantifier", format!("{}{}", "x".repeat(80), p)),
        ("evil_email_shape", format!("a@{}.{}", "a".repeat(50), p)),
        // Long Unicode escape sequence — most regex implementations slow down
        // on large surrogate-pair sequences.
        ("unicode_storm", format!("{}{}", "\\u00ff".repeat(40), p)),
        // Repeated backslash quoting — known historical CRS slowdown.
        ("backslash_storm", format!("{}{}", "\\\\".repeat(60), p)),
        // Many word-boundary anchors — \b matching forces re-evaluation.
        ("word_boundary_storm", format!("{}{}", " a ".repeat(40), p)),
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
                if oracle_valid(&case.class, &case.payload, blob) {
                    stat.oracle_valid += 1;
                }
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

/// Filter `wafrift-evolution` differential probes to those that target the
/// rule family for `class`. Returns the static probe set on first call.
fn class_probes(class: &str) -> Vec<Probe> {
    generate_probes()
        .into_iter()
        .filter(|p| {
            matches!(
                (&p.tests, class),
                (
                    ProbeTarget::SqlKeyword(_)
                        | ProbeTarget::SqlOperator(_)
                        | ProbeTarget::SqlComment(_)
                        | ProbeTarget::SqlQuote
                        | ProbeTarget::SqlTautology(_),
                    "sql" | "nosql"
                ) | (
                    ProbeTarget::XssTag(_)
                        | ProbeTarget::XssEvent(_)
                        | ProbeTarget::XssExecFunction(_),
                    "xss"
                ) | (
                    ProbeTarget::CmdSeparator(_) | ProbeTarget::CmdCommand(_),
                    "cmdi" | "ssti"
                ) | (ProbeTarget::CmdPath(_), "path" | "cmdi")
                    | (ProbeTarget::Baseline, _)
            )
        })
        .collect()
}

/// `differential`: probe the WAF with class-relevant rule-fingerprint
/// payloads from `wafrift-evolution::differential::generate_probes`. A
/// probe that comes back unblocked tells you which signature your WAF
/// does NOT have — the inverse of bypass-rate measurement, useful for
/// rule-coverage gap analysis.
async fn run_differential_strategy(
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
    let probes = class_probes(&case.class);
    if probes.is_empty() {
        // No probe family for this class (e.g. xxe, log4shell). Don't lie
        // with a 0/0 bypass rate — return an empty stat.
        return stat;
    }

    for probe in probes.iter().take(args.variants.max(1)) {
        if *total > 0 && args.delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(args.delay_ms)).await;
        }
        let req = build_request_for_payload(base_url, &case.mode, &probe.payload);
        stat.variants += 1;
        *total += 1;
        match send(client, &req, args.timeout_secs).await {
            Ok((_s, blocked, _l)) if !blocked => {
                stat.bypassed += 1;
                *bypassed += 1;
                // Probes are class-fingerprint payloads, not full attacks —
                // oracle validity is not the right gate. Count probe
                // identification instead.
                bypass_techs.push(format!("{strat}:{}", probe.description));
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

    // Aggregate by strategy across all cases.
    let mut by_strategy_acc: BTreeMap<String, (usize, usize, usize)> = BTreeMap::new();
    for r in results {
        if let Some(e) = &r.evaded {
            for (name, stat) in &e.by_strategy {
                let entry = by_strategy_acc.entry(name.clone()).or_insert((0, 0, 0));
                entry.0 += stat.variants;
                entry.1 += stat.bypassed;
                entry.2 += stat.oracle_valid;
            }
        }
    }
    let by_strategy_json: serde_json::Map<String, serde_json::Value> = by_strategy_acc
        .iter()
        .map(|(name, (variants, bypassed, oracle_valid))| {
            (
                name.clone(),
                serde_json::json!({
                    "variants": variants,
                    "bypassed": bypassed,
                    "bypass_rate": if *variants > 0 { *bypassed as f64 / *variants as f64 } else { 0.0 },
                    "oracle_valid": oracle_valid,
                }),
            )
        })
        .collect();

    let aggregate = serde_json::json!({
        // Schema version for downstream consumers (bench-diff, dashboards,
        // CI parsers). Bump when the JSON shape changes incompatibly so
        // tooling can detect drift instead of silently mis-reading.
        "schema_version": 1u32,
        "wafrift_version": env!("CARGO_PKG_VERSION"),
        "base_url": base_url,
        "evade_mode": args.evade,
        "strategies": args.strategies,
        "variants_per_case_per_strategy": args.variants,
        "lineage_output": args.lineage_output.as_ref().map(|p| p.display().to_string()),
        "total_cases": results.len(),
        "raw_blocked": results.iter().filter(|r| r.raw_blocked).count(),
        "raw_block_rate": results.iter().filter(|r| r.raw_blocked).count() as f64
            / results.len() as f64,
        "evaded_summary": args.evade.then(|| {
            let total: usize = results.iter().filter_map(|r| r.evaded.as_ref()).map(|e| e.variants_total).sum();
            let bypassed: usize = results.iter().filter_map(|r| r.evaded.as_ref()).map(|e| e.variants_bypassed).sum();
            let oracle_valid: usize = results.iter().filter_map(|r| r.evaded.as_ref()).map(|e| e.variants_oracle_valid).sum();
            serde_json::json!({
                "total_variants_sent": total,
                "total_variants_bypassed": bypassed,
                "overall_bypass_rate": if total > 0 { bypassed as f64 / total as f64 } else { 0.0 },
                "total_variants_oracle_valid": oracle_valid,
                "oracle_valid_rate": if total > 0 { oracle_valid as f64 / total as f64 } else { 0.0 },
                "oracle_valid_share_of_bypasses": if bypassed > 0 { oracle_valid as f64 / bypassed as f64 } else { 0.0 },
                "cases_with_at_least_one_bypass": results.iter().filter_map(|r| r.evaded.as_ref()).filter(|e| e.variants_bypassed > 0).count(),
                "cases_with_at_least_one_oracle_valid_bypass": results.iter().filter_map(|r| r.evaded.as_ref()).filter(|e| e.variants_oracle_valid > 0).count(),
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
        "by_strategy": by_strategy_json,
        "results": if args.summary_only { serde_json::Value::Null } else { serde_json::to_value(results).map_err(|e| e.to_string())? },
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

        // Per-strategy breakdown — answers "which of the 10 strategies
        // is doing work and which is dead weight on this WAF?"
        if args.evade && !by_strategy_acc.is_empty() {
            println!();
            println!("{}", "by strategy:".bold());
            for (name, (variants, bypassed, oracle_valid)) in &by_strategy_acc {
                let rate = if *variants > 0 {
                    *bypassed as f64 / *variants as f64 * 100.0
                } else {
                    0.0
                };
                let valid_rate = if *bypassed > 0 {
                    *oracle_valid as f64 / *bypassed as f64 * 100.0
                } else {
                    0.0
                };
                println!(
                    "  {:<14} variants {:>6}  bypass {:>5.1}%  oracle-valid {:>5.1}% of bypass",
                    name, variants, rate, valid_rate
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_probes_sql_has_keywords_and_baseline() {
        let probes = class_probes("sql");
        assert!(!probes.is_empty(), "sql class must have probes");
        assert!(
            probes
                .iter()
                .any(|p| matches!(p.tests, ProbeTarget::SqlKeyword(_))),
            "sql probes must include keyword family"
        );
        assert!(
            probes
                .iter()
                .any(|p| matches!(p.tests, ProbeTarget::Baseline)),
            "every class probe set must include a baseline so unblock=baseline-passes is recorded"
        );
        // Negative — sql probe set must NOT contain xss or cmd probes.
        assert!(
            !probes.iter().any(|p| matches!(
                p.tests,
                ProbeTarget::XssTag(_) | ProbeTarget::CmdSeparator(_)
            )),
            "sql probe set must not bleed xss/cmd families"
        );
    }

    #[test]
    fn class_probes_xss_only_returns_xss_family() {
        let probes = class_probes("xss");
        assert!(!probes.is_empty());
        for p in &probes {
            assert!(
                matches!(
                    p.tests,
                    ProbeTarget::XssTag(_)
                        | ProbeTarget::XssEvent(_)
                        | ProbeTarget::XssExecFunction(_)
                        | ProbeTarget::Baseline
                ),
                "xss probes must be xss-family + baseline only, got {:?}",
                p.tests
            );
        }
    }

    #[test]
    fn all_strategies_constant_includes_every_dispatched_arm() {
        // If a new strategy is added to the dispatch match in `run_evade`
        // but not to `ALL_STRATEGIES`, `--strategies all` would silently
        // omit it. This guards that.
        for required in &[
            "heavy",
            "mcts",
            "smuggling",
            "content-type",
            "redos",
            "hill-climb",
            "sim-anneal",
            "tabu",
            "novelty",
            "map-elites",
            "differential",
        ] {
            assert!(
                ALL_STRATEGIES.contains(required),
                "ALL_STRATEGIES is missing {required:?} — `--strategies all` would skip it"
            );
        }
    }

    fn case(id: &str, class: &str, payload: &str) -> BenchCase {
        BenchCase {
            id: id.into(),
            class: class.into(),
            payload: payload.into(),
            mode: "body_form_q".into(),
            description: String::new(),
        }
    }

    #[test]
    fn validate_corpus_flags_duplicate_id() {
        let cases = vec![case("a", "sql", "1=1"), case("a", "xss", "<script>")];
        let code = validate_corpus_and_exit(&cases).unwrap();
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(4)));
    }

    #[test]
    fn validate_corpus_flags_unknown_class() {
        let cases = vec![case("a", "definitelynot", "x")];
        let code = validate_corpus_and_exit(&cases).unwrap();
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(4)));
    }

    #[test]
    fn validate_corpus_flags_empty_payload() {
        let cases = vec![case("a", "sql", "")];
        let code = validate_corpus_and_exit(&cases).unwrap();
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(4)));
    }

    #[test]
    fn validate_corpus_passes_clean_set() {
        let cases = vec![
            case("a", "sql", "1=1"),
            case("b", "xss", "<script>"),
            case("c", "log4shell", "${jndi:ldap://x}"),
        ];
        let code = validate_corpus_and_exit(&cases).unwrap();
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    #[test]
    fn class_probes_unknown_class_yields_only_baseline() {
        // Classes with no rule-fingerprint family (xxe / log4shell / ssrf)
        // should fall through to baseline-only — never zero, so the
        // strategy doesn't divide-by-zero downstream.
        let probes = class_probes("log4shell");
        assert!(
            probes
                .iter()
                .all(|p| matches!(p.tests, ProbeTarget::Baseline)),
            "unknown classes must yield only baseline probes"
        );
    }
}
