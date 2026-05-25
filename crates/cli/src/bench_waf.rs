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
use wafrift_content_type::generate_variants_from_body;
use wafrift_evolution::differential::{Probe, ProbeTarget, generate_probes};
use wafrift_evolution::evolution::{EvolutionEngine, GenePool};
use wafrift_evolution::lineage::{BypassCorpus, BypassEntry};
use wafrift_evolution::types::Budget;
use wafrift_grammar::grammar::{self, PayloadType};
use wafrift_smuggling::smuggling::all_payloads as smuggling_all_payloads;
use wafrift_strategy::{EvasionConfig, evade_mcts};
use wafrift_strategy::gene_bank::GeneBank;
use wafrift_types::Request;

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
    "equiv",
    "equiv-adaptive",
    "equiv-cegis",
];

#[derive(Debug, clap::Args)]
pub struct BenchWafArgs {
    /// Base URL of the WAF target (e.g. <http://127.0.0.1:18081>).
    /// If omitted, uses `WAFRIFT_BENCH_URL` or `http://127.0.0.1:18081`.
    #[arg(long)]
    pub base_url: Option<String>,

    /// Single TOML corpus file OR directory of TOML files (recursive).
    /// Defaults to the in-tree bench corpus path; if you installed
    /// wafrift via `cargo install` (no checkout), pass `--corpus` to a
    /// directory you cloned from
    /// <https://github.com/santhsecurity/wafrift/tree/main/wafrift-bench/corpus>
    #[arg(long, default_value = "wafrift-bench/corpus")]
    pub corpus: PathBuf,

    /// Restrict to one or more attack classes (sql, xss, cmdi, ssti, path,
    /// ldap, xxe, ssrf, nosql, log4shell, `cve_pocs`). Comma-separated.
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

    /// Comma-separated list of evasion strategies.
    /// Default: `heavy,equiv-cegis` — payload-string mutation PLUS the
    /// flagship B→C→A equivalence moat (the same engine `wafrift scan`
    /// ships), so the headline bypass number measures what the product
    /// actually does out of the box, not a strategy a user must opt in.
    /// Pass `--strategies all` to run the full set in one shot.
    /// Available:
    ///   light / medium / heavy   — payload-string mutation via `build_variants`
    ///   equiv / equiv-adaptive / equiv-cegis
    ///                              — sound `(payload×delivery)` moat (B / B+bandit /
    ///                                B→C→A + active L*-style WAF-boundary learning).
    ///                                Token `equiv-cegis` is the stable public name;
    ///                                algorithm is active WAF-boundary learning
    ///                                (Angluin 1987), not CEGIS.
    ///   mcts                      — Monte Carlo Tree Search over actions (mctrust)
    ///   smuggling                 — HTTP request smuggling variants (CL.TE / TE.CL / TE.TE / dual-CL)
    ///   content-type              — Content-Type confusion variants (multipart/json/xml/...)
    ///   redos                     — wrap payload in catastrophic-backtracking patterns
    ///   hill-climb / sim-anneal / tabu / novelty / map-elites
    ///                              — feedback-driven search via wafrift-evolution
    ///   differential              — class-filtered probes from `wafrift-evolution::differential`
    ///                              (rule-fingerprint coverage; "what does this WAF NOT block")
    #[arg(long, value_delimiter = ',', default_value = "heavy,equiv-cegis")]
    pub strategies: Vec<String>,

    /// DEPRECATED / NO-OP. Oracle gating is now ALWAYS on and cannot be
    /// disabled — a "bypass" only counts if the per-class oracle agrees
    /// the effective payload is still a working attack. The previous
    /// opt-in default (off) meant the headline counted every non-blocked
    /// response, including mutations that destroyed the payload into
    /// harmless garbage. That was a rigged metric; honesty is no longer
    /// optional. Flag retained so existing scripts don't error.
    #[arg(long, default_value_t = false, hide = true)]
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
    /// connection level (target is overwhelmed), pause for
    /// `--adaptive-pause-secs` and continue at half-speed. 0 disables.
    /// Default 50.
    #[arg(long, default_value_t = 50)]
    pub adaptive_pause_after_errors: u32,

    /// Pause duration in seconds when the adaptive throttle trips.
    /// Pre-flag this was hardcoded `2`; against cloud WAFs with longer
    /// lockout windows (Akamai's 60 s, some Cloudflare custom rules),
    /// 2 s is too short and the bench falls right back into the
    /// throttled regime. Raise to match the WAF's published cooldown.
    /// Default 2 s preserves the prior behaviour.
    #[arg(long, default_value_t = 2)]
    pub adaptive_pause_secs: u64,

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

    /// Restrict gene-bank writes to this payload class (sql, xss, cmdi, ...).
    /// When set, persists stats under this class key so future scans
    /// warm-start from class-specific winners. Uses per-case class from
    /// the corpus when unset. Only effective when --evade + --waf-name are set.
    #[arg(long)]
    pub payload_class: Option<String>,

    /// WAF vendor name for gene-bank persistence (e.g. "Cloudflare",
    /// "ModSecurity"). When set with --evade, per-class bypass stats
    /// are merged into the gene bank after the bench completes.
    #[arg(long)]
    pub waf_name: Option<String>,

    /// B6: Skip loading the persisted WAF boundary model (warm-start).
    /// Use for reproducible benchmarks. Default false (warm-start on)
    /// preserves the product behaviour. When a model IS loaded, the
    /// JSON output contains warm_state_hash for audit.
    #[arg(long, default_value_t = false)]
    pub no_warm_start: bool,
}

#[derive(Debug, Deserialize)]
struct CorpusFile {
    // Corpus YAML/JSON may carry a `schema:` key for forward compat
    // — serde drops unknown fields by default, so it rides through
    // silently. When a real consumer (e.g. format-version gating)
    // appears, re-add the field then.
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
    /// Free-form one-line documentation of what the case exercises —
    /// rides through to the per-case [`CaseResult`] output so an
    /// operator scanning bench results sees WHY the case exists.
    #[serde(default)]
    description: String,
}

fn default_mode() -> String {
    "body_form_q".into()
}

#[derive(Debug, Serialize, Clone)]
struct CaseResult {
    id: String,
    class: String,
    /// Mirror of [`BenchCase::description`] — surfaces in the JSON
    /// bench output so an operator inspecting `case_id` knows what
    /// the case was MEANT to test (regression-context for a future
    /// debugger).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    description: String,
    raw_blocked: bool,
    raw_status: u16,
    raw_latency_ms: f64,
    /// B2: true when the HTTP request itself failed (network error / timeout).
    /// Excluded from raw_block_rate denominator to avoid inflating with infra failures.
    #[serde(default)]
    raw_error: bool,
    evaded: Option<EvadeResult>,
}

#[derive(Debug, Serialize, Clone)]
struct EvadeResult {
    variants_total: usize,
    /// VERIFIED bypasses: WAF passed it AND the oracle confirms a still-
    /// working attack. This is the only honest headline number.
    variants_bypassed: usize,
    bypass_rate: f64,
    /// == `variants_bypassed` (every bypass is oracle-verified now).
    variants_oracle_valid: usize,
    oracle_valid_rate: f64,
    /// WAF did not block, but the oracle says it was NOT a working
    /// attack (destroyed by mutation, or a fingerprint probe). The OLD
    /// bench reported THIS as the bypass rate. Surfaced so the inflation
    /// is visible, never folded into the headline.
    variants_unverified_not_blocked: usize,
    /// Per-strategy breakdown.
    by_strategy: BTreeMap<String, StrategyStat>,
    /// Sample of techniques that produced bypasses (one per variant).
    bypass_techniques: Vec<String>,
}

#[derive(Debug, Serialize, Clone, Default)]
struct StrategyStat {
    variants: usize,
    /// VERIFIED bypasses only: WAF did not block AND the oracle confirms
    /// the effective payload is still a working attack of its class.
    /// This is the honest headline number.
    bypassed: usize,
    bypass_rate: f64,
    /// Kept == `bypassed` (every counted bypass is oracle-verified now).
    /// Retained as a separate JSON key for output-schema stability.
    oracle_valid: usize,
    /// WAF did not block, but the oracle says what got through is NOT a
    /// working attack (mutation destroyed it, or it was a fingerprint
    /// probe, not an exploit). The OLD code counted every one of these
    /// as a "bypass" — that was the rig. Surfaced, never hidden.
    unverified_not_blocked: usize,
}

// The verified-bypass oracle + per-class structural validators are
// the SINGLE SOURCE in `crate::equiv_engine` — the corpus bench and
// the shipped `wafrift scan` share exactly one definition of "bypass",
// so a de-rig fix can never apply to one and not the other. Re-exported
// here so existing call sites and the pinned anti-rig tests resolve.
use crate::equiv_engine::{build_request_for_delivery, run_equiv_cegis, send, verified_bypass};

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
    "graphql",
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
        println!("  {cls:>10}: {n}");
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

/// Resolve `--corpus` to a path that actually exists.
///
/// The default `wafrift-bench/corpus` is relative to the *current
/// directory*, so it only works when run from the repo root — a
/// `cargo install`ed binary, or `bench-waf` run from anywhere else,
/// fails with a bare `read_dir ...: No such file or directory`. Try a
/// sequence of sensible locations and, on total failure, name every
/// path tried so the operator knows exactly what to do.
fn resolve_corpus_path(requested: &Path) -> Result<PathBuf, String> {
    // An existing path (explicit or default) is honoured verbatim.
    if requested.exists() {
        return Ok(requested.to_path_buf());
    }

    // Auto-discovery is ONLY for the compiled default. If the operator
    // explicitly passed `--corpus <X>` and X does not exist, silently
    // scanning some *other* corpus found via exe-relative walking is a
    // correctness footgun (you'd benchmark a corpus you didn't choose
    // and never know). Fail loudly instead.
    let default_corpus = Path::new("wafrift-bench/corpus");
    if requested != default_corpus {
        return Err(format!(
            "--corpus path does not exist: {}\n  \
             (an explicit --corpus is used as-is; only the default is \
             auto-located. Point it at a directory of TOML files matching \
             wafrift-bench/corpus/sql/blind.toml.)",
            requested.display()
        ));
    }

    let mut tried: Vec<PathBuf> = vec![requested.to_path_buf()];
    let mut candidates: Vec<PathBuf> = Vec::new();

    // 1. $WAFRIFT_CORPUS explicit env override.
    if let Ok(env_path) = std::env::var("WAFRIFT_CORPUS") {
        candidates.push(PathBuf::from(env_path));
    }
    // 2. Relative to the current working directory (the documented
    //    repo-root case) — already covered by `requested` if relative,
    //    but also try the bare default name explicitly.
    candidates.push(PathBuf::from("wafrift-bench/corpus"));
    // 3. Relative to the executable: <exe_dir>/.. walked up a few
    //    levels (covers target/release/, target/debug/, and an
    //    installed layout that ships the corpus alongside the binary).
    if let Ok(exe) = std::env::current_exe() {
        let mut dir = exe.parent().map(Path::to_path_buf);
        for _ in 0..5 {
            let Some(d) = dir else { break };
            candidates.push(d.join("wafrift-bench/corpus"));
            candidates.push(d.join("corpus"));
            dir = d.parent().map(Path::to_path_buf);
        }
    }
    // 4. XDG data dir / well-known install location.
    if let Some(data) = dirs::data_dir() {
        candidates.push(data.join("wafrift/corpus"));
    }
    candidates.push(PathBuf::from("/usr/share/wafrift/corpus"));

    for cand in candidates {
        if cand.exists() {
            return Ok(cand);
        }
        tried.push(cand);
    }

    Err(format!(
        "could not locate a bench corpus. Tried:\n{}\n\n  \
         Fix: pass `--corpus <DIR>` to a directory of TOML files, set \
         $WAFRIFT_CORPUS, or run from a wafrift checkout (the bundled \
         corpus lives at wafrift-bench/corpus/). Schema reference: \
         wafrift-bench/corpus/sql/blind.toml.",
        tried
            .iter()
            .map(|p| format!("  - {}", p.display()))
            .collect::<Vec<_>>()
            .join("\n")
    ))
}

fn load_corpus(path: &Path) -> Result<Vec<BenchCase>, String> {
    let path = resolve_corpus_path(path)?;
    let path = path.as_path();
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

// `send` (reqwest + `wafrift_types::Request`) is the single shared
// transport in `crate::equiv_engine` — imported above.

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
        // B3: graphql has no PayloadType variant yet; warn so the gap
        // is visible in traces rather than silently falling through.
        "graphql" => {
            tracing::warn!("class=graphql: no grammar mutator, using encoding-only (B3)");
            PayloadType::Unknown
        }
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
        args.strategies = ALL_STRATEGIES
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
    }

    let base_url = resolve_base_url(&args);
    // Load corpus; in --validate-only mode, parse/schema errors are
    // themselves corpus integrity violations and must exit 4 (the
    // documented "corpus integrity error" code), not 1 (generic).
    let mut cases = match load_corpus(&args.corpus) {
        Ok(cs) => cs,
        Err(e) if args.validate_only => {
            eprintln!("  ERROR: {e}");
            eprintln!("1 corpus error(s)");
            return Ok(ExitCode::from(4));
        }
        Err(e) => return Err(e),
    };

    // Apply --class filter BEFORE the validate-only early return so
    // operators can validate just a slice (was: filter silently
    // ignored, validated the full corpus regardless).
    if !args.class.is_empty() {
        let want: std::collections::HashSet<&str> = args.class.iter().map(String::as_str).collect();
        cases.retain(|c| want.contains(c.class.as_str()));
        if cases.is_empty() && !args.validate_only {
            return Err(format!(
                "no cases match the requested classes {:?}. \
                 Hint: omit --class to run every class, or pick from the set printed by \
                 `wafrift bench-waf --validate-only --corpus {}` (look at the per-class counts).",
                args.class,
                args.corpus.display()
            ));
        }
    }

    // --validate-only: run corpus integrity checks then exit. Doesn't
    // need a live WAF target; intended for CI gating on corpus PRs.
    if args.validate_only {
        return validate_corpus_and_exit(&cases);
    }

    // Pick a randomized real-browser User-Agent (vs. the obvious
    // wafrift-bench/0.1 marker) so the WAF doesn't have a free signal.
    let ua = wafrift_fingerprint::fingerprint::random_profile()
        .map_or_else(|| "Mozilla/5.0".into(), |p| p.user_agent.to_string());

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
    //
    // Use the operator's `--timeout-secs` (clamped to a hard floor of
    // 5 s so a pathologically-low operator setting can't shorten the
    // healthcheck below useful — many slow-starting WAF stacks need
    // at least that). Pre-fix the timeout was hardcoded `10` and
    // ignored `--timeout-secs`, producing false "healthcheck failed"
    // on slow stacks the operator had legitimately budgeted for.
    if !args.skip_healthcheck {
        let probe_url = format!("{}/get", base_url.trim_end_matches('/'));
        let healthcheck_timeout = std::time::Duration::from_secs(args.timeout_secs.max(5));
        match client
            .get(&probe_url)
            .timeout(healthcheck_timeout)
            .send()
            .await
        {
            Ok(_) => {}
            Err(e) => {
                return Err(format!(
                    "healthcheck failed: cannot reach {probe_url} within {}s: {e}\n\
                     Hint: bring the WAF stack up first. \
                     For the bundled stacks, e.g. `wafrift-bench/scripts/up.sh modsec-pl1`. \
                     Pass --skip-healthcheck to override, or raise --timeout-secs.",
                    healthcheck_timeout.as_secs()
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
                    tokio::time::sleep(std::time::Duration::from_secs(args.adaptive_pause_secs))
                        .await;
                    let prev = extra_delay_ms.load(Ordering::Relaxed);
                    extra_delay_ms.store(prev.max(50) + args.delay_ms, Ordering::Relaxed);
                    consecutive_errors.store(0, Ordering::Relaxed);
                }
                // B2: push error record and skip; do not map to (0, true, 0.0)
                // because that would count infra failures as WAF blocks.
                results.push(CaseResult {
                    id: case.id.clone(),
                    class: case.class.clone(),
                    description: case.description.clone(),
                    raw_blocked: false,
                    raw_status: 0,
                    raw_latency_ms: 0.0,
                    raw_error: true,
                    evaded: None,
                });
                continue;
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
            description: case.description.clone(),
            raw_blocked,
            raw_status,
            raw_latency_ms,
            raw_error: false, // B2: successful HTTP send
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

    // Gene Bank (C1): persist per-class bypass stats so subsequent bench/scan
    // runs against the same WAF warm-start from class-specific winners.
    // Runs only when --evade AND --waf-name are both set; skips silently otherwise.
    if args.evade {
        if let Some(waf_name) = args.waf_name.as_deref() {
            let mut class_stats: std::collections::HashMap<
                String,
                std::collections::HashMap<String, (u32, u32)>,
            > = std::collections::HashMap::new();

            for result in &results {
                if let Some(evaded) = &result.evaded {
                    let class = args
                        .payload_class
                        .as_deref()
                        .unwrap_or(result.class.as_str())
                        .to_string();
                    let class_map = class_stats.entry(class).or_default();
                    for (strat, stat) in &evaded.by_strategy {
                        if stat.variants == 0 {
                            continue;
                        }
                        let e = class_map.entry(strat.clone()).or_insert((0u32, 0u32));
                        e.0 = e.0.saturating_add(stat.bypassed as u32);
                        e.1 = e.1.saturating_add(stat.variants as u32);
                    }
                }
            }

            match GeneBank::open_default() {
                Ok(mut bank) => {
                    for (class, tech_map) in &class_stats {
                        let stats: Vec<(String, u32, u32)> = tech_map
                            .iter()
                            .map(|(name, (s, a))| (name.clone(), *s, *a))
                            .collect();
                        if stats.is_empty() {
                            continue;
                        }
                        match bank.merge_and_save_for_class(waf_name, class, &stats) {
                            Ok(()) => eprintln!(
                                "gene bank: {} technique(s) saved for {waf_name}/{class}",
                                stats.len()
                            ),
                            Err(e) => eprintln!(
                                "warn: gene bank save failed for {waf_name}/{class}: {e}"
                            ),
                        }
                    }
                }
                Err(e) => eprintln!("warn: could not open gene bank: {e}"),
            }
        }
    }

    emit_report(&base_url, &args, &results)?;

    // Exit code:
    //   0 — clean run
    //   2 — wafrift achieved zero bypasses across ALL cases (in --evade mode only)
    //       i.e. not a single variant bypassed the WAF on any of the corpus cases.
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
            "equiv" => {
                run_equiv_strategy(
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
            "equiv-adaptive" => {
                run_equiv_adaptive_strategy(
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
            "equiv-cegis" => {
                run_equiv_cegis_strategy(
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
                    "warn: unknown strategy {other:?} (light/medium/heavy/mcts/smuggling/content-type/redos/hill-climb/sim-anneal/tabu/novelty/map-elites/differential/equiv)"
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
    let unverified_total: usize = by_strategy.values().map(|s| s.unverified_not_blocked).sum();
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
        variants_unverified_not_blocked: unverified_total,
        by_strategy,
        bypass_techniques: bypass_techs,
    })
}

/// Strategy: payload-string mutation (light/medium/heavy via `build_variants`).
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
            Ok((status, blocked, _l)) => {
                if verified_bypass(
                    &case.class,
                    &case.payload,
                    &variant.payload,
                    blocked,
                    status,
                ) {
                    stat.bypassed += 1;
                    stat.oracle_valid += 1;
                    *bypassed += 1;
                    bypass_techs.push(format!("{}:{}", strat, variant.techniques.join("+")));
                } else if !blocked {
                    // Not blocked, but either the mutation destroyed the
                    // attack OR the request was malformed (400/etc) and
                    // never executed — the case the rig scored as a win.
                    stat.unverified_not_blocked += 1;
                }
            }
            Err(e) => eprintln!("warn: {} ({}) send: {e}", case.id, strat),
        }
    }
    if stat.variants > 0 {
        stat.bypass_rate = stat.bypassed as f64 / stat.variants as f64;
    }
    stat
}

// `json_escape` and `build_request_for_delivery` (testbed shapes) are
// the single source in `crate::equiv_engine` — imported above. The
// pinned `delivery_shapes_build_correct_requests` test exercises that
// one definition through `use super::*`.

/// Strategy: Phase-B joint `(payload × delivery)` equivalence generator.
/// Draws members of the (effectively infinite) equivalence class —
/// every one sound-by-construction — and delivers each via its
/// WAF-blind shape. Still gated by the INDEPENDENT `verified_bypass`
/// oracle (defense in depth: a member counts only if equiv's generator
/// AND the external sqlparser oracle AND "reached the app" AND "not
/// blocked" all agree). No rigging — this only makes the engine
/// genuinely better, never the scoreboard.
#[allow(clippy::too_many_arguments)]
async fn run_equiv_strategy(
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
    // The equivalence model is SQL-complete today; other classes have
    // no sound model yet, so emit nothing rather than guess (anti-rig).
    if !grammar::equiv::supports_class(&case.class) {
        return stat;
    }
    // Deterministic per-case seed (FNV-1a of the case id) — reproducible
    // runs, distinct streams per case.
    let mut seed: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in case.id.bytes() {
        seed ^= u64::from(byte);
        seed = seed.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let cfg = grammar::equiv::EquivConfig {
        seed,
        max: args.variants.max(1),
        verify: true,
        vary_delivery: true,
        param: "q".to_string(),
        force_delivery: None,
    };
    let members = grammar::equiv::equiv_for(&case.class, &case.payload, &cfg);
    for m in &members {
        if *total > 0 && args.delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(args.delay_ms)).await;
        }
        let req = build_request_for_delivery(base_url, &m.delivery, &m.payload);
        stat.variants += 1;
        *total += 1;
        match send(client, &req, args.timeout_secs).await {
            Ok((status, blocked, _l)) => {
                if verified_bypass(&case.class, &case.payload, &m.payload, blocked, status) {
                    stat.bypassed += 1;
                    stat.oracle_valid += 1;
                    *bypassed += 1;
                    bypass_techs.push(format!(
                        "{}:{}|{}",
                        strat,
                        m.delivery.label(),
                        m.rules.join("+")
                    ));
                } else if !blocked {
                    stat.unverified_not_blocked += 1;
                }
            }
            Err(e) => eprintln!("warn: {} ({}) send: {e}", case.id, strat),
        }
    }
    if stat.variants > 0 {
        stat.bypass_rate = stat.bypassed as f64 / stat.variants as f64;
    }
    stat
}

/// Strategy: Phase-C adaptive feedback search. A UCB1 bandit over the
/// delivery-shape arms is played against the LIVE WAF; the verified-
/// bypass signal is the reward. Within a few rounds the request budget
/// concentrates on exactly the shapes that beat THIS WAF instead of
/// blindly sampling shapes it blocks — per-target learning over the
/// provably-sound equivalence space (no round wasted on a destroyed
/// payload). Still gated by the independent `verified_bypass` oracle.
#[allow(clippy::too_many_arguments)]
async fn run_equiv_adaptive_strategy(
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
    if !grammar::equiv::supports_class(&case.class) {
        return stat;
    }
    let mut case_seed: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in case.id.bytes() {
        case_seed ^= u64::from(byte);
        case_seed = case_seed.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let mut bandit = grammar::equiv::adaptive::Bandit::new(grammar::equiv::sql::DELIVERY_ARMS);
    // At least one full explore pass over every arm before exploiting.
    let rounds = args.variants.max(grammar::equiv::sql::DELIVERY_ARMS);
    for round in 0..rounds {
        let arm = bandit.select();
        let cfg = grammar::equiv::EquivConfig {
            seed: case_seed ^ (round as u64).wrapping_mul(0x9E37_79B1_85EB_CA87),
            max: 2,
            verify: true,
            vary_delivery: false,
            param: "q".to_string(),
            force_delivery: Some(arm),
        };
        let members = grammar::equiv::equiv_for(&case.class, &case.payload, &cfg);
        if members.is_empty() {
            bandit.update(arm, 0.0);
            continue;
        }
        let mut hit = 0usize;
        for m in &members {
            if *total > 0 && args.delay_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(args.delay_ms)).await;
            }
            let req = build_request_for_delivery(base_url, &m.delivery, &m.payload);
            stat.variants += 1;
            *total += 1;
            match send(client, &req, args.timeout_secs).await {
                Ok((status, blocked, _l)) => {
                    if verified_bypass(&case.class, &case.payload, &m.payload, blocked, status) {
                        stat.bypassed += 1;
                        stat.oracle_valid += 1;
                        *bypassed += 1;
                        hit += 1;
                        bypass_techs.push(format!(
                            "{}:{}|{}",
                            strat,
                            grammar::equiv::sql::delivery_kind_label(arm),
                            m.rules.join("+")
                        ));
                    } else if !blocked {
                        stat.unverified_not_blocked += 1;
                    }
                }
                Err(e) => eprintln!("warn: {} ({}) send: {e}", case.id, strat),
            }
        }
        let reward = hit as f64 / members.len() as f64;
        bandit.update(arm, reward);
    }
    if stat.variants > 0 {
        stat.bypass_rate = stat.bypassed as f64 / stat.variants as f64;
    }
    stat
}

/// Strategy: Phase-A active L*-style boundary learning. Learn the WAF's decision boundary as a
/// linear model from labelled probes, then *synthesize* the member the
/// model predicts is most-allowed from the sound equivalence space,
/// confirm it live, and refit on every counterexample. Generalises to
/// unseen payloads and the learned model is a compounding artefact.
/// Still gated by the independent `verified_bypass` oracle.
#[allow(clippy::too_many_arguments)]
async fn run_equiv_cegis_strategy(
    client: &Client,
    case: &BenchCase,
    base_url: &str,
    args: &BenchWafArgs,
    strat: &str,
    total: &mut usize,
    bypassed: &mut usize,
    bypass_techs: &mut Vec<String>,
) -> StrategyStat {
    // Thin adapter over the SINGLE shared moat engine. The corpus
    // bench drives `equiv_engine::run_equiv_cegis` with the
    // httpbin-testbed request builder; `wafrift scan` drives the same
    // function with the live-target builder. One B→C→A loop, one model
    // path, one oracle — measured here, shipped there.
    let mut stat = StrategyStat::default();
    let outcome = run_equiv_cegis(
        client,
        |d, p| build_request_for_delivery(base_url, d, p),
        &case.class,
        &case.payload,
        &case.id,
        "q",
        args.variants,
        args.delay_ms,
        args.timeout_secs,
        base_url,
        args.no_warm_start, // B6: pass through --no-warm-start flag
    )
    .await;

    stat.variants = outcome.variants;
    stat.unverified_not_blocked = outcome.unverified_not_blocked;
    stat.bypassed = outcome.bypasses.len();
    stat.oracle_valid = outcome.bypasses.len();
    *total += outcome.variants;
    *bypassed += outcome.bypasses.len();
    for b in &outcome.bypasses {
        bypass_techs.push(format!(
            "{strat}:{}:{}|{}",
            b.phase,
            b.delivery_label,
            b.rules.join("+")
        ));
    }
    if stat.variants > 0 {
        stat.bypass_rate = stat.bypassed as f64 / stat.variants as f64;
    }
    stat
}

/// Strategy: feedback-driven evolution search — `wafrift_evolution::EvolutionEngine`
/// runs one of {`hill_climbing`, `simulated_annealing`, `tabu_search`, `novelty_search`,
/// `map_elites`}. For each round we get a candidate chromosome, render it to a
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
    // B5: deterministic per-case seed via FNV-1a over case.id bytes.
    // The old constant 0xC0FFEE made every run pick identical variants
    // regardless of case identity, masking coverage gaps.
    let mut case_seed: u64 = 0xcbf2_9ce4_8422_2325; // FNV offset basis
    for byte in case.id.bytes() {
        case_seed ^= u64::from(byte);
        case_seed = case_seed.wrapping_mul(0x0000_0100_0000_01b3); // FNV prime
    }
    let rng = StdRng::seed_from_u64(case_seed);
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
        let (status_actual, blocked_actual) = match send(client, &req, args.timeout_secs).await {
            Ok((s, blocked, _l)) => (s, blocked),
            Err(e) => {
                eprintln!("warn: {} ({strat}) send: {e}", case.id);
                if let Err(fe) = engine.record_feedback(idx, false) {
                    // InvalidChromosomeIndex would silently bias the
                    // evolution loop; TargetHealthCritical means the
                    // target is so unhealthy the engine wants to stop.
                    // Either way the operator needs to see it.
                    eprintln!(
                        "warn: {} ({strat}) record_feedback (failed-send branch) idx={idx}: {fe:?}",
                        case.id
                    );
                }
                continue;
            }
        };
        if let Err(fe) = engine.record_feedback(idx, !blocked_actual) {
            eprintln!(
                "warn: {} ({strat}) record_feedback idx={idx}: {fe:?}",
                case.id
            );
        }
        if verified_bypass(
            &case.class,
            &case.payload,
            &rendered_payload,
            blocked_actual,
            status_actual,
        ) {
            stat.bypassed += 1;
            stat.oracle_valid += 1;
            *bypassed += 1;
            bypass_techs.push(format!("{strat}:{technique_label}"));
            if let (Some(corpus), Some(chromo)) =
                (bypass_corpus.as_mut(), chromosome_snapshot.as_ref())
            {
                let entry =
                    BypassEntry::from_chromosome(chromo, Some(format!("{strat}::{}", case.id)));
                corpus.add(entry);
            }
        } else if !blocked_actual {
            stat.unverified_not_blocked += 1;
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

/// Strategy: MCTS — `wafrift::strategy::evade_mcts` learns the WAF mid-run by
/// playing N games against it (depth-bounded action search with mctrust 0.4).
async fn run_mcts_strategy(
    client: &Client,
    case: &BenchCase,
    base_url: &str,
    args: &BenchWafArgs,
    strat: &str,
    total: &mut usize,
    // MCTS never contributes to the VERIFIED headline (its transformed
    // payload is buried in the request with no recoverable plaintext to
    // oracle-check) — unused by design, not an oversight.
    _bypassed: &mut usize,
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
                // MCTS applies grammar/encoding ACTIONS to the request —
                // it does NOT provably preserve the payload (the old
                // "preserves semantics by construction" comment was an
                // unverified assertion used to fake `oracle_valid += 1`).
                // The transformed payload is buried in `evaded.request`
                // with no recoverable plaintext to oracle-check, so we
                // CANNOT claim a verified bypass here. Count it honestly
                // as unverified rather than rig the headline.
                stat.unverified_not_blocked += 1;
                bypass_techs.push(format!(
                    "UNVERIFIED {strat}:depth{depth}:{}",
                    evaded.description
                ));
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
    // Content-Length must reflect the BYTE LENGTH of the body
    // actually on the wire — `q=` + URL-encoded payload. Pre-fix
    // the CL was computed on the RAW payload length (`+ 2` for
    // `q=`), but the body sent was URL-encoded: every `<`, `>`,
    // `&`, `"`, space, and non-ASCII byte expanded to 3-byte
    // `%XX`. A `<script>` payload (raw 8 bytes) URL-encodes to
    // 28 bytes, so CL would be 10 while body was 30 — server
    // truncates the body mid-payload AND falsely records a WAF
    // block in the bench score.
    let encoded_body = format!("q={}", urlencoding::encode(&case.payload));
    let smuggled = format!(
        "POST /post HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{encoded_body}",
        encoded_body.len()
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
            Ok((status, blocked, _l)) => {
                // Smuggling wraps `q=<urlencode(case.payload)>` in the
                // smuggled request — the backend URL-decodes back to the
                // exact original attack, so the oracle gate is on the
                // ORIGINAL payload (it really is transmitted intact).
                if verified_bypass(&case.class, &case.payload, &case.payload, blocked, status) {
                    stat.bypassed += 1;
                    stat.oracle_valid += 1;
                    *bypassed += 1;
                    bypass_techs.push(format!("{strat}:{:?}", sp.variant));
                } else if !blocked {
                    stat.unverified_not_blocked += 1;
                }
            }
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
            Ok((status, blocked, _l)) => {
                // Content-Type confusion reformats the wrapper, the
                // `q=<urlencode(case.payload)>` value is preserved — the
                // backend parses back to the original attack. Oracle gate
                // on the original (genuinely transmitted intact).
                if verified_bypass(&case.class, &case.payload, &case.payload, blocked, status) {
                    stat.bypassed += 1;
                    stat.oracle_valid += 1;
                    *bypassed += 1;
                    bypass_techs.push(format!("{strat}:{:?}", v.technique));
                } else if !blocked {
                    stat.unverified_not_blocked += 1;
                }
            }
            Err(e) => eprintln!("warn: {} ({}) send: {e}", case.id, strat),
        }
    }
    if stat.variants > 0 {
        stat.bypass_rate = stat.bypassed as f64 / stat.variants as f64;
    }
    stat
}

/// Strategy: `ReDoS` — wrap payload in catastrophic-backtracking patterns.
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
            Ok((status, blocked, _l)) => {
                // The redos `blob` is `<storm-prefix><original payload>` —
                // the attack is still present, so oracle-gate on the blob.
                if verified_bypass(&case.class, &case.payload, blob, blocked, status) {
                    stat.bypassed += 1;
                    stat.oracle_valid += 1;
                    *bypassed += 1;
                    bypass_techs.push(format!("{strat}:{label}"));
                } else if !blocked {
                    stat.unverified_not_blocked += 1;
                }
            }
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
    // Differential probes are WAF-rule FINGERPRINTS, not exploits — they
    // never count as bypasses, so the shared accumulator is unused here
    // by design.
    _bypassed: &mut usize,
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
                // Differential probes are WAF-rule FINGERPRINTS, not
                // exploits ("what does this WAF NOT inspect"). The old
                // code fed them straight into the bypass headline — by
                // its own admission ("not full attacks"). That is the
                // rig. They are a separate measurement and never count
                // as a bypass.
                stat.unverified_not_blocked += 1;
                bypass_techs.push(format!("FINGERPRINT {strat}:{}", probe.description));
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
    let mut by_strategy_acc: BTreeMap<String, (usize, usize, usize, usize)> = BTreeMap::new();
    for r in results {
        if let Some(e) = &r.evaded {
            for (name, stat) in &e.by_strategy {
                let entry = by_strategy_acc.entry(name.clone()).or_insert((0, 0, 0, 0));
                entry.0 += stat.variants;
                entry.1 += stat.bypassed;
                entry.2 += stat.oracle_valid;
                entry.3 += stat.unverified_not_blocked;
            }
        }
    }
    let by_strategy_json: serde_json::Map<String, serde_json::Value> = by_strategy_acc
        .iter()
        .map(|(name, (variants, bypassed, oracle_valid, unverified))| {
            (
                name.clone(),
                serde_json::json!({
                    "variants": variants,
                    "bypassed": bypassed,
                    "bypass_rate": if *variants > 0 { *bypassed as f64 / *variants as f64 } else { 0.0 },
                    "oracle_valid": oracle_valid,
                    "unverified_not_blocked": unverified,
                }),
            )
        })
        .collect();

    // B2: compute block rate excluding network-error cases so infra
    // failures do not inflate the block denominator.
    let raw_error_count = results.iter().filter(|r| r.raw_error).count();
    let raw_valid_count = results.len().saturating_sub(raw_error_count);
    let raw_blocked_count = results.iter().filter(|r| r.raw_blocked).count();
    let raw_block_rate_val = if raw_valid_count > 0 {
        raw_blocked_count as f64 / raw_valid_count as f64
    } else {
        0.0
    };

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
        "raw_error_cases": raw_error_count,
        "raw_blocked": raw_blocked_count,
        "raw_block_rate": raw_block_rate_val,
        "evaded_summary": args.evade.then(|| {
            let total: usize = results.iter().filter_map(|r| r.evaded.as_ref()).map(|e| e.variants_total).sum();
            let bypassed: usize = results.iter().filter_map(|r| r.evaded.as_ref()).map(|e| e.variants_bypassed).sum();
            let oracle_valid: usize = results.iter().filter_map(|r| r.evaded.as_ref()).map(|e| e.variants_oracle_valid).sum();
            let unverified: usize = results.iter().filter_map(|r| r.evaded.as_ref()).map(|e| e.variants_unverified_not_blocked).sum();
            serde_json::json!({
                "metric_definition": "bypassed = WAF did NOT block AND the per-class oracle confirms the effective payload is still a working attack. 'unverified_not_blocked' = WAF passed it but it is NOT a working attack (the OLD bench reported this as 'bypassed' — that was the rig).",
                "total_variants_sent": total,
                "total_variants_bypassed": bypassed,
                "overall_bypass_rate": if total > 0 { bypassed as f64 / total as f64 } else { 0.0 },
                "total_variants_oracle_valid": oracle_valid,
                "oracle_valid_rate": if total > 0 { oracle_valid as f64 / total as f64 } else { 0.0 },
                "total_unverified_not_blocked": unverified,
                "unverified_not_blocked_rate": if total > 0 { unverified as f64 / total as f64 } else { 0.0 },
                "legacy_inflated_rate_DO_NOT_USE": if total > 0 { (bypassed + unverified) as f64 / total as f64 } else { 0.0 },
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
            for (name, (variants, bypassed, _oracle_valid, unverified)) in &by_strategy_acc {
                let rate = if *variants > 0 {
                    *bypassed as f64 / *variants as f64 * 100.0
                } else {
                    0.0
                };
                let unver_rate = if *variants > 0 {
                    *unverified as f64 / *variants as f64 * 100.0
                } else {
                    0.0
                };
                println!(
                    "  {name:<14} variants {variants:>6}  VERIFIED bypass {rate:>5.1}%  \
                     (not-blocked-but-not-an-attack {unver_rate:>5.1}%)"
                );
            }
        }
    }
    Ok(())
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        return s.to_string();
    }
    // n.saturating_sub(1) is a BYTE cap, but slicing `&s[..i]` is
    // a panic point if i lands mid-codepoint. Walk char_indices()
    // and stop at the last boundary ≤ cap. Old code `&s[..n-1]`
    // panicked on multi-byte UTF-8 inputs (e.g. truncate("café", 5)
    // sliced 4 bytes — splitting `é`'s two-byte UTF-8 sequence).
    let cap = n.saturating_sub(1);
    let mut end = 0;
    for (i, _) in s.char_indices() {
        if i > cap {
            break;
        }
        end = i;
    }
    format!("{}…", &s[..end])
}

#[cfg(test)]
#[path = "bench_waf_tests.rs"]
mod tests;
