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

/// Bench corpus TOMLs in `wafrift-bench/corpus/` are kilobytes today
/// (a few hundred attack cases each). 16 MiB is generous and catches
/// `--corpus /dev/zero`, symlink traps, and runaway-generated files
/// while comfortably exceeding any legitimate corpus growth.
const BENCH_CORPUS_FILE_MAX_BYTES: usize = 16 * 1024 * 1024;
use wafrift_content_type::generate_all_variants_from_body;
use wafrift_evolution::differential::{Probe, ProbeTarget, generate_probes};
use wafrift_evolution::evolution::{EvolutionEngine, GenePool};
use wafrift_evolution::lineage::{BypassCorpus, BypassEntry};
use wafrift_evolution::min_bypass_set::{
    BypassPayload, compute_min_bypass_set, format_min_bypass_summary,
};
use wafrift_evolution::types::Budget;
use wafrift_grammar::grammar::{self, PayloadType};
use wafrift_smuggling::smuggling::all_payloads as smuggling_all_payloads;
use wafrift_strategy::evade_mcts;
// §8 ARCHITECTURE: EvasionConfig lives in wafrift_types; import from there
// so all usages are reachable from a single grep rather than two paths.
use wafrift_types::hash::{FNV_OFFSET_64, FNV_PRIME_64};
use wafrift_types::{EvasionConfig, Request};

use crate::Level;
use crate::helpers::{Variant, build_variants, max_mutations_for_level, strategies_for_level};

/// Convert days since the Unix epoch (1970-01-01) to a `(year, month, day)`
/// Gregorian triple.  Pure arithmetic — no std::time dependency beyond what
/// the caller already holds.
///
/// Algorithm: proleptic Gregorian calendar via the civil-date formula from
/// Howard Hinnant's "chrono-Compatible Low-Level Date Algorithms"
/// (public domain).
fn days_to_ymd(z: u64) -> (u32, u32, u32) {
    // Shift epoch from 1970-01-01 to 0000-03-01 for the algorithm.
    let z = z as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y as u32, m as u32, d as u32)
}

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

#[derive(Debug, Default, clap::Args)]
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
    ///                              — sound `(payload×delivery)` moat (B / B+bandit / B→C→A+learned-WAF)
    ///   mcts                      — Monte Carlo Tree Search over actions (mctrust)
    ///   smuggling                 — HTTP request smuggling variants (CL.TE / TE.CL / TE.TE / dual-CL)
    ///   content-type              — Content-Type confusion variants (multipart/json/xml/...)
    ///   redos                     — wrap payload in catastrophic-backtracking patterns
    ///   hill-climb / sim-anneal / tabu / novelty / map-elites
    ///                              — feedback-driven search via wafrift-evolution
    ///   differential              — class-filtered probes from `wafrift-evolution::differential`
    ///                              (rule-fingerprint coverage; "what does this WAF NOT block")
    ///   ml-evasion                — manifold-projected structural mutation for ML-backed WAFs,
    ///                              verified live (needs `--waf-name`; clean no-op on rule WAFs)
    ///
    /// NOTE: `--strategies all` expands to the broad rule-WAF set and
    /// intentionally EXCLUDES `ml-evasion` (it is ML-WAF-specific and needs
    /// `--waf-name`) as well as `light` / `medium` — pass those explicitly.
    #[arg(long, value_delimiter = ',', default_value = "heavy,equiv-cegis")]
    pub strategies: Vec<String>,

    /// Detected/known WAF class name, consumed by the `ml-evasion` strategy
    /// to decide whether the target is ML-backed (AWS/Cloudflare/Akamai
    /// bot-management, Datadome) and route through the manifold-projected
    /// structural mutator. Matched case-insensitively by substring (e.g.
    /// "Cloudflare Bot Management"). Omit, or pass a rule-based name, and
    /// `ml-evasion` is a clean no-op — that paradigm is wrong for rule WAFs.
    #[arg(long)]
    pub waf_name: Option<String>,

    /// Authorization acknowledgement for firing attack payloads at a
    /// non-allowlisted `--base-url`. Like `scan` / `hunt`, `bench-waf` refuses
    /// (exit 2) to attack a host that isn't on the built-in allowlist
    /// (CumulusFire, RFC1918 / loopback, …) unless you pass a reason here. Lab
    /// and CI targets are allowlisted, so this is only needed for external
    /// hosts; enforced only for an explicit `--base-url`.
    #[arg(long)]
    pub i_have_permission: Option<String>,

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

    /// Also write the JSON result blob to this file. Refuses to
    /// clobber an existing file unless `--force-overwrite` is set —
    /// CLAUDE.md §7 + §11: two back-to-back bench-waf runs with the
    /// same --output silently wiped the first result before R48.
    /// `-`, `/dev/stdout`, and `/dev/fd/N` are always permitted (not
    /// user data).
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// Override the --output overwrite guard. R48 fix (dogfood
    /// pass 9 I4): match the evade --force-overwrite shape.
    #[arg(long, default_value_t = false)]
    pub force_overwrite: bool,

    /// Emit only the aggregate summary (skip per-case details). Cuts JSON
    /// output by 100x for CI gating.
    #[arg(long, default_value_t = false)]
    pub summary_only: bool,

    /// Prove EXECUTION, not just bypass: for each verified bypass whose response
    /// is HTML, detonate the response body via the `detonate` tool and count how
    /// many actually EXECUTE (`alert(1)` fires) vs merely bypass-and-reflect.
    /// This is the honest bypass-vs-exploit split — the headline `bypassed` rate
    /// counts WAF passes; `executed` counts confirmed XSS. Needs `detonate` on
    /// PATH (or `$WAFRIFT_DETONATE_BIN`) and a reflective HTML origin behind the
    /// WAF (a JSON-echo backend like httpbin can never execute, so it reports 0
    /// by construction). Pair with `--detonate-engine chrome` for mutation-XSS.
    /// Covers the `heavy`/`light`/`medium` payload-mutation strategies.
    #[arg(long, default_value_t = false)]
    pub prove_execution: bool,

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

    // ─── Info-gain scheduling (limited-budget assessments) ───────────────────
    /// Cap the number of bench cases to actually run, scheduling the
    /// most informative ones first. Without this flag every case in
    /// the (post --class-filter) corpus is run. With `--budget N`,
    /// the corpus is sorted by descending expected information gain
    /// from `--history-file` (cold-start when absent) and only the
    /// top N cases are sent against the WAF.
    ///
    /// "Information gain" is the binary Shannon entropy of the
    /// current block-probability estimate for the case — peaks at
    /// 1 bit when the WAF blocks 50% of the time (maximally
    /// discriminating) and drops to 0 at the endpoints (trivial
    /// block or trivial pass). High-entropy cases teach the operator
    /// the most about the rule set per request sent.
    #[arg(long, value_name = "N")]
    pub budget: Option<usize>,

    /// JSON history file used by `--budget` to warm-start the
    /// schedule and accumulate observations across runs. The format
    /// is `wafrift_cli::info_gain_sched::History`: a map from case
    /// id to `{n_blocked, n_passed}`. Missing file → cold start; the
    /// file is rewritten atomically at the end of the run with the
    /// observations from this invocation accumulated in.
    ///
    /// Without `--budget` the file is still updated if specified,
    /// so an operator can build up history across full-corpus runs
    /// and then later use `--budget` to scope down.
    #[arg(long, value_name = "PATH")]
    pub history_file: Option<PathBuf>,

    /// Merge an additional history file into the working history
    /// before scheduling. Repeatable: `--history-merge h1.json
    /// --history-merge h2.json` folds both into the working
    /// history. Useful for operators running parallel WAF assessments
    /// who want to aggregate posteriors before a follow-up bench.
    ///
    /// Saturating arithmetic per `History::merge` — overflow on a
    /// single payload caps at `u32::MAX` rather than wrapping. Paths
    /// that fail to read are reported as warnings on stderr; benching
    /// continues with whatever histories did load.
    #[arg(long = "history-merge", value_name = "PATH", num_args = 0..)]
    pub history_merge: Vec<PathBuf>,

    /// Enforce per-class fairness when scheduling under `--budget`.
    /// Without this flag, the scheduler is class-blind — a corpus
    /// dominated by one class (e.g. 95% sql) will return an all-sql
    /// schedule. With `--fair-class`, every class receives roughly
    /// `budget / num_classes` slots, then within each class payloads
    /// are ordered by descending expected info gain. Classes with
    /// fewer payloads than their allocation contribute what they have
    /// (honest under-fill — see `info_gain_sched::schedule_per_class`
    /// for the contract).
    ///
    /// Independent of `--budget`: with no `--budget`, fairness has no
    /// trimming effect because the full corpus is run anyway.
    #[arg(long, default_value_t = false)]
    pub fair_class: bool,

    /// Preview the schedule without firing any requests. After
    /// `--budget` (and optionally `--fair-class`) apply, print the
    /// scheduled case ids in run order along with their `info_gain`
    /// bits, `theta_estimate` block probability, and `n_trials` prior
    /// observations, then exit 0. Pairs with `--history-file` to
    /// debug "what would the next real bench actually run?" without
    /// spending request budget.
    ///
    /// Output format follows `--format`: `text` emits a fixed-width
    /// table to stdout; `json` emits a JSON array of
    /// `info_gain_sched::ScheduleEntry` objects.
    #[arg(long, default_value_t = false)]
    pub list_schedule: bool,

    // ─── Egress rotation (multi-IP evasion of bot-reputation engines) ────────
    /// SOCKS5 proxy URL for egress rotation (repeatable).
    /// Example: `--socks5 socks5://user:pass@10.8.0.1:1080`
    #[arg(long = "socks5", value_name = "URL", num_args = 0..)]
    pub egress_socks5: Vec<String>,

    /// HTTP proxy URL for egress rotation (repeatable).
    /// Example: `--http-proxy http://burp.internal:8080`
    #[arg(long = "http-proxy", value_name = "URL", num_args = 0..)]
    pub egress_http_proxy: Vec<String>,

    /// Tailscale exit-node name for egress rotation (repeatable).
    #[arg(long = "tailscale-exit-node", value_name = "NODE", num_args = 0..)]
    pub egress_tailscale_nodes: Vec<String>,

    /// Tailscale SOCKS listener address. Default: `127.0.0.1:1055`.
    #[arg(long = "tailscale-socks-addr", value_name = "ADDR", default_value = crate::config::DEFAULT_TAILSCALE_SOCKS_ADDR)]
    pub egress_tailscale_socks_addr: String,

    /// Consecutive challenges before cooling an egress entry. Default: 3.
    #[arg(long = "egress-challenge-threshold", default_value_t = wafrift_types::DEFAULT_EGRESS_CHALLENGE_THRESHOLD)]
    pub egress_challenge_threshold: u32,

    /// Seconds a cooled egress entry stays out of rotation. Default: 300.
    #[arg(long = "egress-cooldown-secs", default_value_t = 300u64)]
    pub egress_cooldown_secs: u64,

    /// Pin the evolution-strategy mutator to a specific algorithm for ablation.
    /// `default` uses the strategy name (hill-climb, sim-anneal, etc.).
    /// `ast-mcts` forces AST Monte-Carlo Tree Search for every evolution case.
    #[arg(long, default_value = "default", value_parser = ["default", "ast-mcts"])]
    pub mutator: String,

    /// Global RNG seed for reproducible runs. When set, User-Agent selection
    /// and evolution-strategy RNGs are seeded deterministically so that
    /// `bench-waf --seed <N> … > run1.json` and a second identical invocation
    /// produce byte-identical JSON. Without this flag the bench is
    /// non-deterministic (random UA, random evolution trajectories).
    #[arg(long)]
    pub seed: Option<u64>,

    /// Weight for ensemble-dilution score in evolutionary fitness (0.0–1.0).
    ///
    /// When targeting a multi-rule-group ensemble WAF (Cloudflare Managed
    /// Ruleset, AWS Core Rule Set), the evolution engine blends the oracle
    /// bypass signal with a dilution score that estimates how well the
    /// current chromosome keeps the WAF's total anomaly score below the
    /// block threshold.
    ///
    /// 0.0 = pure oracle fitness (default, safe for all WAF types).
    /// 0.3 = recommended for known ensemble targets.
    /// 1.0 = pure dilution score (use only when oracle signal is noisy).
    ///
    /// Has no effect when targeting rule-based or ML-backed WAFs.
    #[arg(long, default_value_t = 0.0, value_parser = parse_dilution_weight)]
    pub dilution_weight: f64,

    /// Path to write the per-rule bypass corpus on completion.
    /// When set, the bench captures full response envelopes for
    /// confirmed bypasses (via `send_with_envelope`), routes them
    /// through `parse_cf_block` to derive the CF rule attribution
    /// + edge POP, and persists to this path. Combine with
    /// `--coverage-out` for the cross-region POP coverage map.
    /// Omitting both flags keeps the legacy hot-path send() that
    /// drops headers/body for slightly lower per-probe latency.
    #[arg(long)]
    pub corpus_out: Option<std::path::PathBuf>,

    /// Path to write the edge-POP coverage map on completion.
    /// See `--corpus-out`.
    #[arg(long)]
    pub coverage_out: Option<std::path::PathBuf>,

    /// Target fingerprint string the corpus is keyed under.
    /// Defaults to `bench:<base_url>` so each target gets a stable
    /// per-target corpus. Operators recording against CumulusFire
    /// can pass an explicit `cf:cumulusfire:<host>` so multiple
    /// runs accumulate into one file.
    #[arg(long, default_value = "")]
    pub corpus_fingerprint: String,

    /// CI pass threshold: the top-level `ci_pass` field in the bench JSON
    /// is set to `true` when `overall_bypass_rate >= --ci-threshold`.
    /// Default 0.0 means any bypass (≥ 1 successful bypass) passes.
    /// Set higher to enforce a minimum bypass rate on your lab target:
    /// `--ci-threshold 0.10` fails CI when fewer than 10% of variants bypass.
    ///
    /// `ci_pass` is also emitted at the top level of the JSON for easy
    /// `jq '.ci_pass'` gating in GitHub Actions / GitLab CI.
    #[arg(long, default_value_t = 0.0, value_parser = parse_ci_threshold)]
    pub ci_threshold: f64,

    /// C-11: exploration boost rounds injected by the hunt campaign when the
    /// CUSUM bypass-rate monitor fires a change-point alarm.
    ///
    /// When > 0, each evolutionary-search engine created for this bench round
    /// calls `EvolutionEngine::on_change_point(exploration_boost_rounds, 2.0)`
    /// immediately after construction so it explores more aggressively — the
    /// WAF rule update invalidated the learned strategy and re-exploration is
    /// exactly the right response.
    ///
    /// Default 0 (no boost). Not exposed as a CLI flag — set programmatically
    /// by `hunt_cmd` when the CUSUM alarm fires.
    #[arg(skip)]
    pub exploration_boost_rounds: u32,
}

fn parse_dilution_weight(s: &str) -> std::result::Result<f64, String> {
    let v: f64 = s
        .parse()
        .map_err(|_| format!("expected a float, got {s:?}"))?;
    if !(0.0..=1.0).contains(&v) {
        return Err(format!("--dilution-weight must be in [0.0, 1.0], got {v}"));
    }
    Ok(v)
}

fn parse_ci_threshold(s: &str) -> std::result::Result<f64, String> {
    let v: f64 = s
        .parse()
        .map_err(|_| format!("--ci-threshold: expected a float in [0.0, 1.0], got {s:?}"))?;
    if !(0.0..=1.0).contains(&v) {
        return Err(format!("--ci-threshold must be in [0.0, 1.0], got {v}"));
    }
    Ok(v)
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

/// Bench case loaded from a corpus TOML file.
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct BenchCase {
    pub(crate) id: String,
    pub(crate) class: String,
    pub(crate) payload: String,
    /// Where to inject the payload. Default `body_form_q` (POST /post with
    /// body `q=<urlenc payload>`). Alternatives: `url_query_q`, `raw_body`.
    #[serde(default = "default_mode")]
    pub(crate) mode: String,
    /// Free-form one-line documentation of what the case exercises —
    /// rides through to the per-case [`CaseResult`] output so an
    /// operator scanning bench results sees WHY the case exists.
    #[serde(default)]
    pub(crate) description: String,
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
    evaded: Option<EvadeResult>,
    /// Mirror of [`BenchCase::payload`] — kept on the result so the
    /// C-15 minimum-bypass-set computation (and any future post-hoc
    /// analysis like the info-gain scheduler's history replay) can
    /// recover the actual wire payload without re-indexing the corpus
    /// by id. Empty for pre-fix runs; serde skip_serializing_if keeps
    /// legacy JSON output stable.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    payload: String,
    /// C-14 rule-quality classification. Lets an operator filter the
    /// corpus down to the cases that actually discriminate between
    /// WAFs ("signal" only). Cases that are `trivial_block` (WAF
    /// blocks every variant) or `trivial_pass` (WAF blocks nothing)
    /// carry no information about THIS run — they're redundant for
    /// regression tracking. `baseline_failed` cases never had an
    /// attack to evade in the first place.
    case_quality: CaseQuality,
    /// C-14 discriminative score in [0.0, 1.0]. Defined as the binary
    /// Shannon entropy of (bypass_rate, 1-bypass_rate) — peaks at 1.0
    /// when bypass_rate == 0.5 (maximum information), 0.0 at the
    /// endpoints. Only meaningful when `case_quality == Signal`;
    /// reported as 0.0 otherwise.
    quality_score: f64,
}

/// C-14 case-quality classification. A bench case is "signal" iff
/// the WAF rule discriminates between attack variants — some pass
/// and some are blocked. Pinned-at-0% (trivial_block) and
/// pinned-at-100% (trivial_pass) cases tell the operator NOTHING
/// new about the WAF on a re-run; filtering them out shrinks the
/// regression corpus to the load-bearing cases.
#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum CaseQuality {
    /// Baseline (raw) payload was NOT blocked — WAF has no rule on
    /// this attack at all; no bypass to find, no quality to score.
    BaselineFailed,
    /// WAF blocks the raw payload AND every variant. Strong rule
    /// against this exact case; no signal about WAF brittleness.
    TrivialBlock,
    /// WAF blocks the raw payload but EVERY variant passes. The
    /// rule is byte-anchored to the exact attack string and is a
    /// completeness gap — useful signal that the rule needs
    /// widening, but redundant across many similar cases.
    TrivialPass,
    /// WAF blocks the raw payload AND blocks SOME variants while
    /// letting others through (0 < bypass_rate < 1). This is where
    /// the WAF is making a real differentiation call; future bench
    /// runs that change the bypass count here are the ones an
    /// operator actually needs to look at.
    Signal,
    /// Case never ran the evasion engine (no --evade). Baseline-only
    /// runs can't compute case quality; reported faithfully.
    NotMeasured,
}

/// Compute case-quality classification + discriminative score from
/// the bench outcome. Pure — no allocation, no I/O. The threshold
/// constants are pinned by `case_quality_pinned_constants` so a
/// silent re-tuning of "signal" boundary is impossible.
fn classify_case_quality(raw_blocked: bool, evaded: Option<&EvadeResult>) -> (CaseQuality, f64) {
    let Some(e) = evaded else {
        return (CaseQuality::NotMeasured, 0.0);
    };
    if !raw_blocked {
        return (CaseQuality::BaselineFailed, 0.0);
    }
    if e.variants_total == 0 {
        // Nothing was tested even though raw blocked — treat as no
        // measurement rather than guessing a class.
        return (CaseQuality::NotMeasured, 0.0);
    }
    let p = e.bypass_rate;
    // Strict equality at 0.0/1.0 catches the pinned-at-endpoints
    // cases; anything else is signal (no margin band — we don't want
    // a `signal_threshold` knob that could be retuned silently).
    if p <= 0.0 {
        (CaseQuality::TrivialBlock, 0.0)
    } else if p >= 1.0 {
        (CaseQuality::TrivialPass, 0.0)
    } else {
        // Binary Shannon entropy in [0, 1]. Shared with the info-gain
        // scheduler — single canonical home at
        // `wafrift_types::entropy::binary_shannon`.
        (CaseQuality::Signal, wafrift_types::binary_shannon(p))
    }
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
    /// PROVEN-EXECUTING bypasses (only populated under `--prove-execution`):
    /// of the verified bypasses, how many were detonated and actually fired a
    /// sink (`alert(1)`) — confirmed XSS, not just a WAF pass. The honest
    /// bypass-vs-exploit split. `0` when `--prove-execution` is off.
    variants_executed: usize,
    /// `variants_executed / variants_bypassed` — fraction of bypasses that are
    /// confirmed exploits. `0.0` when nothing was proven.
    executed_rate: f64,
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
    /// PROVEN-EXECUTING bypasses under `--prove-execution`: bypasses whose
    /// response body detonated to a fired sink (confirmed XSS). `0` otherwise.
    executed: usize,
}

// The verified-bypass oracle + per-class structural validators are
// the SINGLE SOURCE in `crate::equiv_engine` — the corpus bench and
// the shipped `wafrift scan` share exactly one definition of "bypass",
// so a de-rig fix can never apply to one and not the other. Re-exported
// here so existing call sites and the pinned anti-rig tests resolve.
use crate::equiv_engine::{build_request_for_delivery, run_equiv_cegis, send, verified_bypass};

pub fn run_bench_waf(args: BenchWafArgs) -> ExitCode {
    // R48-I4 fix (dogfood pass 9): shared overwrite guard (also
    // used by evade --output). Pre-fix two back-to-back bench-waf
    // runs with the same --output silently wiped the first.
    if let Some(ref path) = args.output
        && let Err(msg) = crate::helpers::confirm_output_overwrite_safe(path, args.force_overwrite)
    {
        eprintln!("{} {msg}", "Output error:".red().bold());
        return ExitCode::from(2);
    }
    // §13 dogfood (round 2, DEFECT 1): an unusable `--corpus` is an INPUT
    // error, not a runtime error. The bench cannot start without a corpus,
    // and the exit-code contract (see main.rs `after_help`) reserves 2 for
    // argument/input errors ("malformed value, missing required field") —
    // exactly what a nonexistent `--corpus <path>` is. Pre-validate the
    // path here (reusing `resolve_corpus_path`, no §7 fork) so the failure
    // returns 2 consistently for BOTH `bench-waf` and `scan --corpus`,
    // matching every sibling input error (`--payload ""`, unknown flag).
    // Pre-fix this fell into the async runtime-error arm below, which maps
    // every Err → exit 1 — so `scan --corpus /typo` returned 1 while
    // `scan --payload ""` returned 2. (exit 2 is already overloaded with
    // bench-waf "zero bypasses"; CI scripts disambiguate via stderr, which
    // carries an explicit "Input error:" line here.)
    if let Err(msg) = resolve_corpus_path(&args.corpus) {
        eprintln!("{} {msg}", "Input error:".red().bold());
        return ExitCode::from(2);
    }
    crate::helpers::block_on_with_runtime(async move {
        match run_bench_waf_async(args).await {
            Ok(code) => code,
            Err(e) => {
                eprintln!("{} {e}", "error:".red().bold());
                ExitCode::from(1)
            }
        }
    })
}

fn resolve_base_url(args: &BenchWafArgs) -> String {
    if let Some(ref u) = args.base_url {
        return crate::helpers::normalize_target_url(u);
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
    "ssi",
    "xxe",
    "log4shell",
    "cve_pocs",
    "graphql",
];

fn validate_corpus_and_exit(cases: &[BenchCase], format: &str) -> Result<ExitCode, String> {
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
    let ok = errors.is_empty();
    if format == "json" {
        let by_class_json: BTreeMap<&str, usize> = by_class.clone();
        let payload = serde_json::json!({
            "ok": ok,
            "total_cases": cases.len(),
            "by_class": by_class_json,
            "errors": errors,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload)
                .unwrap_or_else(|_| r#"{"ok":false,"error":"serialization failed"}"#.into())
        );
    } else {
        println!("corpus integrity:");
        println!("  total cases: {}", cases.len());
        for (cls, n) in &by_class {
            println!("  {cls:>10}: {n}");
        }
        if ok {
            println!("OK ({} cases)", cases.len());
        } else {
            for e in &errors {
                eprintln!("  ERROR: {e}");
            }
            eprintln!("{} corpus error(s)", errors.len());
        }
    }
    if ok {
        Ok(ExitCode::SUCCESS)
    } else {
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
    // Collect + sort so corpus order is deterministic across OS/FS.
    // `fs::read_dir` returns entries in arbitrary filesystem order; two runs
    // on the same seed would process cases in a different order → different
    // JSON output even when nothing changed. Sort lexicographically by path.
    let mut sorted: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
    sorted.sort();
    for p in sorted {
        if p.is_dir() {
            walk_corpus(&p, out)?;
        } else if p.extension().and_then(|s| s.to_str()) == Some("toml") {
            load_one(&p, out)?;
        }
    }
    Ok(())
}

fn load_one(path: &Path, out: &mut Vec<BenchCase>) -> Result<(), String> {
    let raw = crate::safe_body::read_bounded_text_file(path, BENCH_CORPUS_FILE_MAX_BYTES)
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    let file: CorpusFile = toml::from_str(&raw).map_err(|e| format!("{}: {e}", path.display()))?;
    out.extend(file.cases);
    Ok(())
}

/// Build an HTTP [`Request`] for a single bench case.
pub(crate) fn build_request(base_url: &str, case: &BenchCase) -> Request {
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
        "ssi" => PayloadType::Ssi,
        "log4shell" => PayloadType::Jndi,
        // xxe / cve_pocs have no wafrift grammar mutator yet — fall back
        // to encoding-only mutations so the bench still runs.
        _ => PayloadType::Unknown,
    }
}

pub(crate) fn build_request_for_payload(base_url: &str, mode: &str, payload: &str) -> Request {
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
    // R53 pass-15 §11-A (CLAUDE.md §11 UTILIZATION): warn operators
    // who still pass --oracle-gate=true that the flag is a no-op
    // (oracle gating is always-on since R32). Silent-no-op is worse
    // than the flag absence — operators reading their command line
    // believe they enabled something. Tracing warn on stderr so JSON
    // consumers are unaffected.
    if args.oracle_gate {
        tracing::warn!(
            "--oracle-gate is DEPRECATED and a no-op. Oracle validation has \
             been mandatory since R32. Remove the flag from your command \
             line; the behaviour you wanted is the default."
        );
    }
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
        return validate_corpus_and_exit(&cases, &args.format);
    }

    // ─── Info-gain scheduler: optional budget-aware case filter ──────────
    //
    // Load the history file (if any) before either the budget filter
    // or the bench loop so a single mutable handle survives end-to-end.
    // Cold start when the file is missing — that is the documented
    // first-run path and must not error.
    // §15 OOM / TOCTOU fix: use read_bounded_text_file instead of
    // std::fs::read_to_string — single fd open+read, no stat() race,
    // hard cap prevents a crafted history file from OOMing the bench run.
    // Cold start when the file is absent preserves the documented first-run
    // behaviour without calling read_bounded_text_file on a non-existent
    // path (the function propagates the IO error but we want a clean cold-
    // start for "not found" — check existence first, which is fine because
    // the file is created and owned by wafrift itself, not a symlink target).
    // §7 DEDUP: the load (bounded read, cold-start-on-absent, warn-on-parse-error,
    // hard-error-on-IO) is the canonical `info_gain_sched::load_history` — the same
    // loader `fingerprint --filter-history` uses, so warm-start semantics never drift.
    let mut sched_history = match args.history_file.as_ref() {
        Some(path) => crate::info_gain_sched::load_history(path)?,
        None => crate::info_gain_sched::History::new(),
    };

    // --history-merge: fold zero-or-more additional history files
    // into the working history before scheduling. Each file is
    // read+parsed independently; a malformed or missing file emits
    // a warning and is skipped (benching continues with whatever
    // did load — same robustness convention as --history-file).
    // §15 OOM fix: same read_bounded_text_file treatment as --history-file.
    for merge_path in &args.history_merge {
        match crate::safe_body::read_bounded_text_file(
            merge_path,
            crate::safe_body::GENE_BANK_FILE_MAX_BYTES,
        ) {
            Ok(text) => match serde_json::from_str::<crate::info_gain_sched::History>(&text) {
                Ok(extra) => {
                    let prior_len = sched_history.len();
                    sched_history.merge(&extra);
                    eprintln!(
                        "info-gain scheduler: merged {} payload entries from {} ({} ⇒ {})",
                        extra.len(),
                        merge_path.display(),
                        prior_len,
                        sched_history.len()
                    );
                }
                Err(e) => eprintln!(
                    "warn: --history-merge {} parse error ({e}); skipped",
                    merge_path.display()
                ),
            },
            Err(e) => eprintln!(
                "warn: --history-merge {} unreadable ({e}); skipped",
                merge_path.display()
            ),
        }
    }

    if let Some(budget) = args.budget {
        // budget == 0 is treated as a no-op rather than an error so
        // operators can disable the scheduler with `--budget 0` in
        // scripted dry-runs. Anything > 0 trims the corpus to the
        // top-N most informative cases (cold-start payloads land
        // first under the n_trials tiebreak — see schedule docs).
        if budget == 0 {
            eprintln!("info-gain scheduler: --budget 0 → scheduler disabled");
        } else if budget >= cases.len() {
            eprintln!(
                "info-gain scheduler: --budget {budget} ≥ corpus size {} — no filter applied",
                cases.len()
            );
        } else if budget > 0 && budget < cases.len() {
            let original_count = cases.len();
            // Get diagnostic entries so the eprintln can surface the
            // mean info_gain of the kept set — operators see the
            // schedule's actual quality, not just its cardinality.
            let entries: Vec<crate::info_gain_sched::ScheduleEntry> = if args.fair_class {
                // Per-class fairness: every class gets roughly equal
                // slots. BTreeMap so per-class iteration order is
                // deterministic (alphabetical), satisfying
                // schedule_per_class_with_diagnostics's contract.
                let mut by_class: std::collections::BTreeMap<String, Vec<String>> =
                    std::collections::BTreeMap::new();
                for c in &cases {
                    by_class
                        .entry(c.class.clone())
                        .or_default()
                        .push(c.id.clone());
                }
                // Operator-clarity warning: when budget < num_classes,
                // some classes get zero slots under integer division.
                // Operators who expected "fair" to mean "every class
                // represented" should see this upfront, not in the
                // schedule table.
                if budget < by_class.len() {
                    eprintln!(
                        "warn: --fair-class with budget={budget} < num_classes={} \
                         means {} classes get no slots (base = budget/num_classes = 0). \
                         Either raise --budget to ≥ num_classes or drop --fair-class.",
                        by_class.len(),
                        by_class.len() - budget,
                    );
                }
                crate::info_gain_sched::schedule_per_class_with_diagnostics(
                    &sched_history,
                    &by_class,
                    budget,
                )
            } else {
                let case_ids: Vec<&str> = cases.iter().map(|c| c.id.as_str()).collect();
                crate::info_gain_sched::schedule_with_diagnostics(&sched_history, &case_ids, budget)
            };
            let mean_info_gain = if entries.is_empty() {
                0.0
            } else {
                entries.iter().map(|e| e.info_gain).sum::<f64>() / entries.len() as f64
            };
            // Preserve schedule order in the bench loop: operators
            // who Ctrl-C mid-bench get the most-informative results
            // first. Record the schedule rank per id BEFORE consuming
            // entries into the keep set.
            let order: std::collections::HashMap<String, usize> = entries
                .iter()
                .enumerate()
                .map(|(i, e)| (e.id.clone(), i))
                .collect();
            // Drop the schedule's owning Vec into a HashSet for O(1)
            // membership lookup during the retain pass.
            let keep: std::collections::HashSet<String> =
                entries.into_iter().map(|e| e.id).collect();
            cases.retain(|c| keep.contains(c.id.as_str()));
            cases.sort_by_key(|c| order.get(&c.id).copied().unwrap_or(usize::MAX));
            // Under --fair-class, also surface the per-class breakdown
            // so operators can verify the fairness allocation worked
            // (i.e. budget=10 with 5 classes shows roughly 2 each).
            let class_breakdown = if args.fair_class {
                let mut by_class: std::collections::BTreeMap<&str, usize> =
                    std::collections::BTreeMap::new();
                for c in &cases {
                    *by_class.entry(c.class.as_str()).or_insert(0) += 1;
                }
                // Shannon entropy of the class-frequency distribution
                // in the kept schedule: measures fairness diversity.
                // log2(num_classes) at perfectly uniform; lower if
                // some classes were starved by under-fill. Operators
                // can spot "the corpus has 13 classes but the
                // diversity is only 2.8 bits, not log2(13)=3.7" =
                // some classes contributed less than their slot.
                let total = cases.len() as f64;
                let class_probs: Vec<f64> = by_class.values().map(|&v| v as f64 / total).collect();
                let class_diversity_bits = wafrift_types::shannon(&class_probs);
                let parts: Vec<String> = by_class.iter().map(|(k, v)| format!("{k}={v}")).collect();
                format!(
                    ", classes=[{}], class_diversity={class_diversity_bits:.4} bits",
                    parts.join(", ")
                )
            } else {
                String::new()
            };
            eprintln!(
                "info-gain scheduler: kept {} of {} cases \
                 (budget={budget}{}, mean info_gain={mean_info_gain:.4} bits{class_breakdown})",
                cases.len(),
                original_count,
                if args.fair_class {
                    ", fair_class=true"
                } else {
                    ""
                }
            );
        }
    }

    // --list-schedule: emit the run-order schedule and exit BEFORE
    // any HTTP traffic. Operators use this to audit what the next
    // real bench would actually fire — saves the budget pain of
    // realising mid-run that --class or --budget excluded the wrong
    // payloads. Honours --format (text by default, json if asked).
    if args.list_schedule {
        let effective_budget = args.budget.unwrap_or(cases.len()).min(cases.len());
        // Re-derive diagnostics from the (already-filtered) case list
        // so the preview reflects --class, --budget, and --fair-class
        // exactly — the cases that survived all filters above ARE
        // the cases that will run, in the order they will run.
        let entries = if args.fair_class {
            let mut by_class: std::collections::BTreeMap<String, Vec<String>> =
                std::collections::BTreeMap::new();
            for c in &cases {
                by_class
                    .entry(c.class.clone())
                    .or_default()
                    .push(c.id.clone());
            }
            crate::info_gain_sched::schedule_per_class_with_diagnostics(
                &sched_history,
                &by_class,
                effective_budget,
            )
        } else {
            let case_ids: Vec<&str> = cases.iter().map(|c| c.id.as_str()).collect();
            crate::info_gain_sched::schedule_with_diagnostics(
                &sched_history,
                &case_ids,
                effective_budget,
            )
        };
        if args.format == "json" {
            match serde_json::to_string_pretty(&entries) {
                Ok(text) => println!("{text}"),
                Err(e) => return Err(format!("serialise schedule: {e}")),
            }
        } else {
            println!(
                "{:>5}  {:<40}  {:>10}  {:>6}  {:>18}  {:>10}",
                "rank", "id", "info_gain", "theta", "theta_ci_95", "n_trials"
            );
            for (rank, entry) in entries.iter().enumerate() {
                println!(
                    "{:>5}  {:<40}  {:>10.6}  {:>6.4}  [{:>6.4}, {:>6.4}]  {:>10}",
                    rank + 1,
                    entry.id,
                    entry.info_gain,
                    entry.theta_estimate,
                    entry.theta_ci_95_lo,
                    entry.theta_ci_95_hi,
                    entry.n_trials
                );
            }
            println!(
                "({} cases, budget={}, fair_class={})",
                entries.len(),
                args.budget.map_or("none".to_string(), |b| b.to_string()),
                args.fair_class
            );
        }
        return Ok(ExitCode::SUCCESS);
    }

    // R48 pass-10 I8 fix (CLAUDE.md §9 WIRING): if the operator
    // installed an explicit User-Agent via `.wafrift.toml`'s
    // `http.user_agent`, honour it. Otherwise bench-waf keeps its
    // seeded/random profile policy for reproducible WAF-lab runs.
    let browser_identity =
        bench_waf_browser_identity(args.seed, crate::config::shared_user_agent_explicit())
            .map_err(|e| format!("resolve bench browser identity: {e}"))?;

    // R53 pass-15 §9-A (CLAUDE.md §9 WIRING): go through
    // wafrift_transport::base_client_builder so the workspace-wide
    // MIN_TIMEOUT_SECS clamp applies. Pre-fix `--timeout-secs 0`
    // built a client with a zero-second deadline; every request
    // failed immediately at connect time, masquerading as a
    // 100% block rate.
    // R56 pass-20 §15 AUDIT (SSRF redirect): apply the SSRF-safe
    // redirect policy so a hostile bench target that returns
    // `302 → http://169.254.169.254/latest/meta-data/` can't
    // ferry bench-waf to the cloud metadata endpoint.
    // bench-waf always fires at operator-specified docker/local
    // targets, so cross-origin redirect stops are safe (the bench
    // never chases redirects off the target host anyway).
    let mut client_builder =
        wafrift_transport::base_client_builder(args.timeout_secs, args.insecure, None)
            .default_headers(browser_identity.headers)
            .redirect(crate::helpers::safe_redirect_policy(5));
    // R52 pass-14 I1 fix (CLAUDE.md §9 WIRING): apply --socks5 +
    // --http-proxy egress rotation to the client. Pre-fix the
    // fields were parsed by clap, stored in BenchWafArgs, and
    // silently discarded — every operator-supplied proxy request
    // routed direct. Build a single-entry-per-URL EgressPool and
    // apply the first entry to the bench client; rotation across
    // probes requires per-probe client construction; this builder still
    // ensures the operator-specified egress path is honoured.
    let want_egress = !args.egress_socks5.is_empty()
        || !args.egress_http_proxy.is_empty()
        || !args.egress_tailscale_nodes.is_empty();
    if want_egress {
        let mut pool_builder = wafrift_transport::egress_pool::EgressPool::builder();
        if !args.egress_socks5.is_empty() {
            pool_builder = pool_builder
                .socks5_str(args.egress_socks5.clone())
                .map_err(|e| format!("--socks5: {e}"))?;
        }
        if !args.egress_http_proxy.is_empty() {
            pool_builder = pool_builder
                .http_proxy_str(args.egress_http_proxy.clone())
                .map_err(|e| format!("--http-proxy: {e}"))?;
        }
        // R53 pass-15 §11-B (CLAUDE.md §11 UTILIZATION): wire
        // --tailscale-exit-node + --tailscale-socks-addr too.
        // Pre-fix both args were declared, populated, persisted —
        // and silently ignored by the pool build.
        if !args.egress_tailscale_nodes.is_empty() {
            let socks = if args.egress_tailscale_socks_addr.is_empty() {
                None
            } else {
                Some(args.egress_tailscale_socks_addr.clone())
            };
            pool_builder = pool_builder.tailscale_nodes(args.egress_tailscale_nodes.clone(), socks);
        }
        let pool = pool_builder
            .build()
            .map_err(|e| format!("egress pool: {e}"))?;
        // Use the first entry of the pool — bench-waf currently
        // builds one client for the run, so we can't rotate
        // mid-bench without restructuring. Operator-supplied
        // --socks5 / --http-proxy NOW affects requests; rotation
        // is a separate follow-up.
        if let Ok(target_host) = reqwest::Url::parse(&base_url)
            && let Some(host) = target_host.host_str()
            && let Ok(entry) = pool.next_for(host)
        {
            client_builder = entry.apply_to_builder(client_builder);
        }
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

    // CorpusRecorder: collected when --corpus-out OR --coverage-out is set.
    // Captures full response envelopes per probe so the per-rule bypass
    // corpus + edge-POP coverage map can be populated end-to-end. Wrapped
    // in Arc<Mutex<>> so it can cross await points without changing the
    // strategy function signatures to async-bounded references.
    let recorder: Option<std::sync::Arc<std::sync::Mutex<crate::corpus_recorder::CorpusRecorder>>> =
        if args.corpus_out.is_some() || args.coverage_out.is_some() {
            let fingerprint = if args.corpus_fingerprint.is_empty() {
                format!("bench:{}", base_url)
            } else {
                args.corpus_fingerprint.clone()
            };
            // Default to side-by-side paths if only one was set so we
            // never write a half-state where corpus exists but coverage
            // doesn't (or vice-versa).
            let corpus_path = args
                .corpus_out
                .clone()
                .unwrap_or_else(|| std::path::PathBuf::from("wafrift-corpus.json"));
            let coverage_path = args
                .coverage_out
                .clone()
                .unwrap_or_else(|| std::path::PathBuf::from("wafrift-coverage.json"));
            Some(std::sync::Arc::new(std::sync::Mutex::new(
                crate::corpus_recorder::CorpusRecorder::new(
                    fingerprint,
                    corpus_path,
                    coverage_path,
                    None,
                ),
            )))
        } else {
            None
        };

    use std::sync::atomic::Ordering;

    for (idx, case) in cases.iter().enumerate() {
        if idx > 0 {
            let total_delay = args.delay_ms + extra_delay_ms.load(Ordering::Relaxed);
            if total_delay > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(total_delay)).await;
            }
        }
        let req = build_request(&base_url, case);
        let (raw_status, raw_blocked, _raw_latency_ms) =
            match send(&client, &req, args.timeout_secs).await {
                Ok(t) => {
                    consecutive_errors.store(0, Ordering::Relaxed);
                    t
                }
                Err(e) => {
                    eprintln!("warn: {} (raw): {e}", case.id);
                    let n = consecutive_errors.fetch_add(1, Ordering::Relaxed) + 1;
                    if args.adaptive_pause_after_errors > 0 && n == args.adaptive_pause_after_errors
                    {
                        eprintln!(
                            "warn: {n} consecutive connection errors — pausing 2s and \
                             doubling per-request delay (target may be choked)"
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(
                            args.adaptive_pause_secs,
                        ))
                        .await;
                        let prev = extra_delay_ms.load(Ordering::Relaxed);
                        extra_delay_ms.store(prev.max(50) + args.delay_ms, Ordering::Relaxed);
                        consecutive_errors.store(0, Ordering::Relaxed);
                    }
                    (0, true, 0.0)
                }
            };

        let evaded = if args.evade {
            Some(
                run_evade(
                    &client,
                    case,
                    &base_url,
                    &args,
                    &mut bypass_corpus,
                    recorder.as_ref(),
                )
                .await?,
            )
        } else {
            None
        };

        let (case_quality, quality_score) = classify_case_quality(raw_blocked, evaded.as_ref());
        results.push(CaseResult {
            id: case.id.clone(),
            class: case.class.clone(),
            description: case.description.clone(),
            raw_blocked,
            raw_status,
            evaded,
            payload: case.payload.clone(),
            case_quality,
            quality_score,
        });
    }

    // ─── Info-gain scheduler: accumulate observations + persist history ──
    //
    // Even when --budget was not set, --history-file may be specified
    // on its own to build up history across full-corpus runs (which a
    // later run can use with --budget to scope down). So this write
    // path is independent of `args.budget` — it fires whenever the
    // file is set.
    for r in &results {
        sched_history.observe(r.id.clone(), r.raw_blocked);
    }
    if let Some(path) = args.history_file.as_ref() {
        // §7 DEDUP: serialize + atomic write is the canonical
        // `info_gain_sched::save_history`; only the operator messaging is local.
        match crate::info_gain_sched::save_history(path, &sched_history) {
            Ok(()) => {
                eprintln!(
                    "info-gain scheduler: wrote {} payload entries to {} ({})",
                    sched_history.len(),
                    path.display(),
                    if sched_history.is_empty() {
                        "empty history — first run"
                    } else {
                        "ready for warm-start on the next run"
                    }
                );
            }
            Err(e) => {
                eprintln!(
                    "warn: scheduler history write to {} failed: {e}",
                    path.display()
                );
            }
        }
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

    // Persist the per-rule bypass corpus + edge-POP coverage map if the
    // operator asked for them via --corpus-out / --coverage-out. Same
    // single-atomic-write pattern as the lineage corpus above.
    if let Some(rec) = recorder.as_ref() {
        match rec.lock() {
            Ok(guard) => {
                if let Err(e) = guard.flush() {
                    eprintln!("warn: corpus flush failed: {e}");
                } else {
                    eprintln!(
                        "wrote {} probes ({} novel bypasses) to corpus + coverage files",
                        guard.probe_count(),
                        guard.novel_bypass_count(),
                    );
                }
            }
            Err(e) => eprintln!("warn: corpus recorder poisoned: {e}"),
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
    recorder: Option<&std::sync::Arc<std::sync::Mutex<crate::corpus_recorder::CorpusRecorder>>>,
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
                    recorder,
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
                    recorder,
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
                    recorder,
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
                    recorder,
                )
                .await
            }
            "ml-evasion" => {
                run_ml_evasion_strategy(
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
                    "warn: unknown strategy {other:?} (light/medium/heavy/mcts/smuggling/content-type/redos/ml-evasion/hill-climb/sim-anneal/tabu/novelty/map-elites/differential/equiv)"
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
    let executed_total: usize = by_strategy.values().map(|s| s.executed).sum();
    let executed_rate = if bypassed > 0 {
        executed_total as f64 / bypassed as f64
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
        variants_unverified_not_blocked: unverified_total,
        variants_executed: executed_total,
        executed_rate,
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
    recorder: Option<&std::sync::Arc<std::sync::Mutex<crate::corpus_recorder::CorpusRecorder>>>,
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
        // When a recorder is wired OR we must prove execution, capture the full
        // envelope (headers + body): the recorder routes it through
        // parse_cf_block → rule_corpus, and `--prove-execution` detonates the
        // body to confirm real XSS. Otherwise drop to the legacy hot-path
        // send() that throws headers + body away. The optional third element is
        // the (body, headers) kept ONLY when proving execution, so a normal run
        // pays no extra clone.
        let probe_result = if recorder.is_some() || args.prove_execution {
            match crate::equiv_engine::send_with_envelope(client, &req, args.timeout_secs).await {
                Ok(env) => {
                    let is_bypass = verified_bypass(
                        &case.class,
                        &case.payload,
                        &variant.payload,
                        env.blocked,
                        env.status,
                    );
                    if let Some(rec) = recorder {
                        let outcome = if is_bypass {
                            wafrift_evolution::hunt_corpus_bridge::ProbeOutcome::Bypass
                        } else if env.blocked {
                            wafrift_evolution::hunt_corpus_bridge::ProbeOutcome::Block
                        } else {
                            // Unverified-not-blocked: don't record — the oracle
                            // wasn't certain and corpus dedup would treat this
                            // as noise.
                            wafrift_evolution::hunt_corpus_bridge::ProbeOutcome::Ambiguous
                        };
                        if matches!(
                            outcome,
                            wafrift_evolution::hunt_corpus_bridge::ProbeOutcome::Bypass
                                | wafrift_evolution::hunt_corpus_bridge::ProbeOutcome::Block
                        ) {
                            let chain: Vec<String> = variant
                                .techniques
                                .iter()
                                .map(std::string::ToString::to_string)
                                .collect();
                            let class = wafrift_evolution::coverage_feedback::PayloadClass::new(
                                &case.class,
                            );
                            if let Ok(mut guard) = rec.lock() {
                                // Payload-mutation strategies deliver via a fixed
                                // shape (no equivalence-shape choice), so no
                                // delivery is recorded; harvest re-verifies these
                                // via the standard delivery shapes.
                                let _ = guard.record(
                                    &env,
                                    &variant.payload,
                                    class,
                                    chain,
                                    "direct",
                                    base_url,
                                    outcome,
                                    None,
                                );
                            }
                        }
                    }
                    // Retain body + headers for detonation only on a verified
                    // bypass we intend to prove (bounded: one clone per bypass).
                    let proof_io = (args.prove_execution && is_bypass)
                        .then(|| (env.body.clone(), env.headers.clone()));
                    Ok((env.status, env.blocked, proof_io))
                }
                Err(e) => Err(e),
            }
        } else {
            match send(client, &req, args.timeout_secs).await {
                Ok((status, blocked, _l)) => Ok((status, blocked, None)),
                Err(e) => Err(e),
            }
        };

        match probe_result {
            Ok((status, blocked, proof_io)) => {
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
                    // Prove EXECUTION (honest bypass-vs-exploit split): detonate
                    // the reflected response body. Counts only a fired sink as
                    // executed — a WAF pass that reflects inert does not.
                    if let Some((body, headers)) = proof_io
                        && detonate_bypass_body(&body, &headers, base_url)
                    {
                        stat.executed += 1;
                    }
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

/// Detonate a verified-bypass response `body` and report whether its injected
/// JavaScript actually EXECUTED (a sink fired). Gated on the response being
/// HTML — a JSON/text echo backend (e.g. httpbin) reflects the payload inertly
/// and can never execute, which is exactly the bypass-vs-exploit distinction
/// this measures. Best-effort: a missing `detonate` tool / non-HTML body / parse
/// failure yields `false` (counted as bypass-only, never a false exploit).
/// Honours the run's `--detonate-engine` selector via `exec_proof`.
fn detonate_bypass_body(body: &[u8], headers: &[(String, String)], url: &str) -> bool {
    let is_html = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .is_some_and(|(_, v)| {
            let v = v.to_ascii_lowercase();
            v.contains("text/html") || v.contains("application/xhtml") || v.contains("image/svg")
        });
    if !is_html {
        return false;
    }
    let body = String::from_utf8_lossy(body);
    crate::exec_proof::prove_execution(&body, url).is_some_and(|p| p.executed)
}

// `json_escape` and `build_request_for_delivery` (testbed shapes) are
// the single source in `crate::equiv_engine` — imported above. The
// pinned `delivery_shapes_build_correct_requests` test exercises that
// one definition through `use super::*`.

/// Record one verified equiv-family bypass (winning wire payload +
/// response envelope, with H1 dedup) to the corpus recorder. Shared by
/// the equiv / equiv-adaptive / equiv-cegis strategies so the record call
/// lives in ONE place (§7) — the concrete payload is what makes a hunt
/// corpus re-verifiable and submittable (`wafrift harvest`).
fn record_equiv_bypass(
    recorder: &std::sync::Arc<std::sync::Mutex<crate::corpus_recorder::CorpusRecorder>>,
    env: &crate::equiv_engine::ProbeEnvelope,
    payload: &str,
    class: &str,
    rules: &[&str],
    base_url: &str,
    delivery: &grammar::equiv::DeliveryShape,
) {
    if let Ok(mut guard) = recorder.lock() {
        let chain: Vec<String> = rules.iter().map(|r| (*r).to_string()).collect();
        let pc = wafrift_evolution::coverage_feedback::PayloadClass::new(class);
        // Persist the EXACT delivery shape so `wafrift harvest` re-fires
        // the identical request that beat the WAF (the difference between
        // a recorded number and a submittable bypass). If serialization
        // somehow failed we still record the bypass without it — harvest
        // falls back to standard shapes — rather than drop a real bypass.
        let delivery_json = serde_json::to_string(delivery).ok();
        let _ = guard.record(
            env,
            payload,
            pc,
            chain,
            "direct",
            base_url,
            wafrift_evolution::hunt_corpus_bridge::ProbeOutcome::Bypass,
            delivery_json.as_deref(),
        );
    }
}

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
    recorder: Option<&std::sync::Arc<std::sync::Mutex<crate::corpus_recorder::CorpusRecorder>>>,
) -> StrategyStat {
    let mut stat = StrategyStat::default();
    // Only classes with a sound equivalence model are handled — see
    // `grammar::equiv::supports_class` (sql, xss, cmdi, path, ssti, ldap,
    // ssrf, nosql, log4shell, xxe). Anything else emits nothing rather
    // than guess (anti-rig).
    if !grammar::equiv::supports_class(&case.class) {
        return stat;
    }
    // Deterministic per-case seed (FNV-1a of the case id) — reproducible
    // runs, distinct streams per case.
    let mut seed: u64 = FNV_OFFSET_64;
    for byte in case.id.bytes() {
        seed ^= u64::from(byte);
        seed = seed.wrapping_mul(FNV_PRIME_64);
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
        let probe = if let Some(rec) = recorder {
            match crate::equiv_engine::send_with_envelope(client, &req, args.timeout_secs).await {
                Ok(env) => {
                    let (status, blocked) = (env.status, env.blocked);
                    if verified_bypass(&case.class, &case.payload, &m.payload, blocked, status) {
                        record_equiv_bypass(
                            rec,
                            &env,
                            &m.payload,
                            &case.class,
                            &m.rules,
                            base_url,
                            &m.delivery,
                        );
                    }
                    Ok((status, blocked))
                }
                Err(e) => Err(e),
            }
        } else {
            send(client, &req, args.timeout_secs)
                .await
                .map(|(s, b, _l)| (s, b))
        };
        match probe {
            Ok((status, blocked)) => {
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
    recorder: Option<&std::sync::Arc<std::sync::Mutex<crate::corpus_recorder::CorpusRecorder>>>,
) -> StrategyStat {
    let mut stat = StrategyStat::default();
    if !grammar::equiv::supports_class(&case.class) {
        return stat;
    }
    let mut case_seed: u64 = FNV_OFFSET_64;
    for byte in case.id.bytes() {
        case_seed ^= u64::from(byte);
        case_seed = case_seed.wrapping_mul(FNV_PRIME_64);
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
            let probe = if let Some(rec) = recorder {
                match crate::equiv_engine::send_with_envelope(client, &req, args.timeout_secs).await
                {
                    Ok(env) => {
                        let (status, blocked) = (env.status, env.blocked);
                        if verified_bypass(&case.class, &case.payload, &m.payload, blocked, status)
                        {
                            record_equiv_bypass(
                                rec,
                                &env,
                                &m.payload,
                                &case.class,
                                &m.rules,
                                base_url,
                                &m.delivery,
                            );
                        }
                        Ok((status, blocked))
                    }
                    Err(e) => Err(e),
                }
            } else {
                send(client, &req, args.timeout_secs)
                    .await
                    .map(|(s, b, _l)| (s, b))
            };
            match probe {
                Ok((status, blocked)) => {
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

/// Strategy: Phase-A CEGIS. Learn the WAF's decision boundary as a
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
    recorder: Option<&std::sync::Arc<std::sync::Mutex<crate::corpus_recorder::CorpusRecorder>>>,
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
        // Persist the concrete winning wire payload + its response
        // envelope to the rule-bypass corpus (with H1 dedup) so a hunt
        // campaign yields a re-verifiable, submittable bypass set —
        // technique tags alone can't reconstruct the payload.
        if let Some(rec) = recorder {
            record_equiv_bypass(
                rec,
                &b.envelope,
                &b.payload,
                &case.class,
                &b.rules,
                base_url,
                &b.delivery,
            );
        }
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
    // `--mutator ast-mcts` overrides the per-strategy algorithm selection so
    // every evolution case runs through AST-MCTS for ablation comparison.
    let algo_name = if args.mutator == "ast-mcts" {
        "ast_mcts"
    } else {
        match strat {
            "hill-climb" => "hill_climbing",
            "sim-anneal" => "simulated_annealing",
            "tabu" => "tabu_search",
            "novelty" => "novelty_search",
            "map-elites" => "map_elites",
            _ => return stat,
        }
    };
    let payload_type = class_to_payload_type(&case.class);
    // Derive a per-(case, strategy) seed so different cases produce
    // independent RNG streams while still being reproducible when a
    // global --seed is provided.
    //
    // R54 pass-16 I2 fix (CLAUDE.md §10 COHERENCE + §11 UTILIZATION):
    // pre-fix the unseeded path used a hardcoded constant 0xC0FFEE
    // so every "non-deterministic" run produced byte-identical
    // evolution trajectories — directly contradicting --help's claim
    // that without --seed the bench is non-deterministic. Now: when
    // --seed is absent we draw from the OS entropy source per
    // invocation. Each bench run gets its own base_seed; reruns are
    // genuinely independent. To reproduce a specific run, pass the
    // base_seed back via --seed.
    //
    // R55 pass-17 I2 (CLAUDE.md §13 DOGFOOD): the derived seed is
    // emitted UNCONDITIONALLY on stderr (not via tracing::info!,
    // which the default `warn` filter swallows). Without this an
    // unseeded run produces a bypass the operator wants to re-pin and
    // has no way to recover the seed — directly defeating R54's
    // reproducibility promise.
    let base_seed: u64 = match args.seed {
        Some(s) => s,
        None => {
            use rand::RngCore;
            let mut osrng = rand::rngs::OsRng;
            let s = osrng.next_u64();
            eprintln!(
                "bench-waf: unseeded run, derived base_seed={s} from OsRng \
                 (pass `--seed {s}` to reproduce)"
            );
            s
        }
    };
    // FNV-1a mix of the case id into the base seed gives each case its
    // own stream; XOR with the strategy name hash ensures hill-climb and
    // sim-anneal on the same case explore different trajectories.
    let mut case_mix: u64 = base_seed ^ FNV_OFFSET_64;
    for byte in case.id.bytes() {
        case_mix ^= u64::from(byte);
        case_mix = case_mix.wrapping_mul(FNV_PRIME_64);
    }
    let mut strat_mix: u64 = case_mix;
    for byte in strat.bytes() {
        strat_mix ^= u64::from(byte);
        strat_mix = strat_mix.wrapping_mul(FNV_PRIME_64);
    }
    let rng = StdRng::seed_from_u64(strat_mix);
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

    // C-11: If the hunt CUSUM alarm fired, activate exploration boost so this
    // engine explores more broadly instead of exploiting the now-invalidated
    // learned bypass strategy from before the WAF rule update.
    if args.exploration_boost_rounds > 0 {
        engine.on_change_point(args.exploration_boost_rounds, 2.0);
    }

    // When using AST-MCTS, seed the engine with a chromosome that carries the
    // raw payload so the MCTS rollout starts from a meaningful rewrite context.
    if algo_name == "ast_mcts" {
        use wafrift_evolution::evolution::Chromosome;
        let seed = Chromosome::new(vec![("ast_mcts_payload".into(), case.payload.clone())]);
        engine.seed_population(vec![seed]);
    }

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
    let mut config = EvasionConfig::maximum();
    config.dilution_weight = args.dilution_weight;
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
    // §9 WIRING — `generate_all_variants_from_body` is the full sweep
    // (WAFFLED set interleaved with preamble/epilogue/nested-envelope
    // multipart-smuggle shapes). The interleave guarantees that even a
    // small `--variants N` cap exercises at least one shape from each
    // family rather than dark-coding the smuggle path.
    let variants = generate_all_variants_from_body(form_body.as_bytes());
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

/// Strategy: `ml-evasion` — route ML-backed WAFs (AWS/Cloudflare/Akamai
/// bot-management, Datadome) through a manifold-projected structural mutator
/// (`ml_evasion_probe_payload`) instead of rule-decompilation. Each seed
/// yields a semantics-preserving structural mutation of the payload that
/// stays a *working* attack (anti-rig is structural: a mutation that leaves
/// the executable-attack manifold is a discarded sample, never a "bypass");
/// the mutated payload is fired at the live target and only verified bypasses
/// are credited.
///
/// Gated on `--waf-name`: a non-ML-backed name (or none) yields zero
/// candidates, so this is a clean no-op on rule-based targets — correct, since
/// rule-decompilation is the wrong paradigm for a learned classifier. This is
/// the forward-paradigm tool for the next-gen ML-WAF threat, reachable from the
/// autonomous loop (`bench-waf` / `hunt`), not just `scan`. (The full
/// *adaptive* decision-boundary descent — `wafmodel::evade_ml` driven by live
/// feedback — is a tracked frontier upgrade in docs/legendary-todo.md.)
async fn run_ml_evasion_strategy(
    client: &Client,
    case: &BenchCase,
    base_url: &str,
    args: &BenchWafArgs,
    strat: &str,
    total: &mut usize,
    bypassed: &mut usize,
    bypass_techs: &mut Vec<String>,
) -> StrategyStat {
    use wafrift_strategy::ml_evasion::{DEFAULT_ML_BUDGET, ml_evasion_probe_payload};
    let mut stat = StrategyStat::default();
    let waf_name = args.waf_name.as_deref().unwrap_or("");
    // Different seeds → diverse on-manifold mutations of the payload, each fired
    // live + oracle-verified. `ml_evasion_probe_payload` owns the probe/extract
    // wiring (shared with `wafrift scan`); it returns `None` on a non-ML-backed
    // `--waf-name`, so a rule-based bench is a true no-op here — never warns,
    // never counts, no denominator pollution.
    for seed in 0..args.variants as u64 {
        let Some((mutated_payload, techs)) =
            ml_evasion_probe_payload(&case.payload, waf_name, DEFAULT_ML_BUDGET, seed)
        else {
            break;
        };
        if *total > 0 && args.delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(args.delay_ms)).await;
        }
        let req = build_request_for_payload(base_url, &case.mode, &mutated_payload);
        stat.variants += 1;
        *total += 1;
        match send(client, &req, args.timeout_secs).await {
            Ok((status, blocked, _l)) => {
                // The manifold projection guarantees the mutated payload is
                // still a working attack — oracle-gate on the mutated form.
                if verified_bypass(
                    &case.class,
                    &case.payload,
                    &mutated_payload,
                    blocked,
                    status,
                ) {
                    stat.bypassed += 1;
                    stat.oracle_valid += 1;
                    *bypassed += 1;
                    bypass_techs.push(format!(
                        "{strat}:{}",
                        techs
                            .iter()
                            .map(|t| format!("{t:?}"))
                            .collect::<Vec<_>>()
                            .join("+")
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
    // Tuple: (variants, bypassed, oracle_valid, unverified_not_blocked, executed).
    let mut by_strategy_acc: BTreeMap<String, (usize, usize, usize, usize, usize)> =
        BTreeMap::new();
    for r in results {
        if let Some(e) = &r.evaded {
            for (name, stat) in &e.by_strategy {
                let entry = by_strategy_acc
                    .entry(name.clone())
                    .or_insert((0, 0, 0, 0, 0));
                entry.0 += stat.variants;
                entry.1 += stat.bypassed;
                entry.2 += stat.oracle_valid;
                entry.3 += stat.unverified_not_blocked;
                entry.4 += stat.executed;
            }
        }
    }
    let by_strategy_json: serde_json::Map<String, serde_json::Value> = by_strategy_acc
        .iter()
        .map(|(name, (variants, bypassed, oracle_valid, unverified, executed))| {
            (
                name.clone(),
                serde_json::json!({
                    "variants": variants,
                    "bypassed": bypassed,
                    "bypass_rate": if *variants > 0 { *bypassed as f64 / *variants as f64 } else { 0.0 },
                    "oracle_valid": oracle_valid,
                    "unverified_not_blocked": unverified,
                    "executed": executed,
                    "executed_rate": if *bypassed > 0 { *executed as f64 / *bypassed as f64 } else { 0.0 },
                }),
            )
        })
        .collect();

    // Fix #6: compute top-level overall_bypass_rate so CI consumers can
    // reach it as `.overall_bypass_rate` without needing to drill into
    // `.evaded_summary.overall_bypass_rate`.
    let evade_total: usize = results
        .iter()
        .filter_map(|r| r.evaded.as_ref())
        .map(|e| e.variants_total)
        .sum();
    let evade_bypassed: usize = results
        .iter()
        .filter_map(|r| r.evaded.as_ref())
        .map(|e| e.variants_bypassed)
        .sum();
    let overall_bypass_rate: f64 = if evade_total > 0 {
        evade_bypassed as f64 / evade_total as f64
    } else {
        0.0
    };
    // Honest bypass-vs-exploit split (populated only under --prove-execution):
    // of the bypasses, how many were detonated to a fired sink (confirmed XSS).
    let evade_executed: usize = results
        .iter()
        .filter_map(|r| r.evaded.as_ref())
        .map(|e| e.variants_executed)
        .sum();
    let overall_executed_rate: f64 = if evade_bypassed > 0 {
        evade_executed as f64 / evade_bypassed as f64
    } else {
        0.0
    };
    // ci_pass = bypass_rate meets or exceeds the operator's threshold.
    // Default threshold 0.0 means any bypass (at least one) passes.
    let ci_pass: bool = overall_bypass_rate >= args.ci_threshold;

    // RFC 3339 UTC timestamp — use SystemTime to avoid pulling chrono.
    let run_timestamp: String = {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // Format as YYYY-MM-DDTHH:MM:SSZ (ISO 8601 / RFC 3339 subset).
        let s = secs % 60;
        let m = (secs / 60) % 60;
        let h = (secs / 3600) % 24;
        let days = secs / 86400; // days since Unix epoch (1970-01-01)
        // Compute year/month/day from days since epoch (Gregorian).
        let (yr, mo, dy) = days_to_ymd(days);
        format!("{yr:04}-{mo:02}-{dy:02}T{h:02}:{m:02}:{s:02}Z")
    };

    let aggregate = serde_json::json!({
        // Schema version for downstream consumers (bench-diff, dashboards,
        // CI parsers). Bump when the JSON shape changes incompatibly so
        // tooling can detect drift instead of silently mis-reading.
        "schema_version": 2u32,  // bumped: new top-level fields (overall_bypass_rate, run_timestamp, ci_pass, legacy)
        "wafrift_version": env!("CARGO_PKG_VERSION"),
        "run_timestamp": run_timestamp,
        // Fix #6: overall_bypass_rate hoisted to top level for O(1) CI access.
        // Also retained under evaded_summary.overall_bypass_rate for LAW 2.
        "overall_bypass_rate": overall_bypass_rate,
        // Honest bypass-vs-exploit split (only meaningful with --prove-execution;
        // 0 otherwise). `overall_executed` = bypasses detonated to a fired sink
        // (confirmed XSS); `overall_executed_rate` = executed / bypassed.
        "prove_execution": args.prove_execution,
        "overall_executed": evade_executed,
        "overall_executed_rate": overall_executed_rate,
        // ci_pass = overall_bypass_rate >= --ci-threshold (default 0.0).
        "ci_pass": ci_pass,
        "base_url": base_url,
        "evade_mode": args.evade,
        "strategies": args.strategies,
        "variants_per_case_per_strategy": args.variants,
        "lineage_output": args.lineage_output.as_ref().map(|p| p.display().to_string()),
        // §10 COHERENCE: echo the scheduler-arg shape so postmortem
        // tooling can tell "was --budget set?" "did --fair-class fire?"
        // without re-parsing the original argv. None / false fields
        // serialise as JSON null / false so consumers can branch on
        // their presence.
        "scheduler_args": serde_json::json!({
            "budget": args.budget,
            "fair_class": args.fair_class,
            "list_schedule": args.list_schedule,
            "history_file": args.history_file.as_ref().map(|p| p.display().to_string()),
            "history_merge": args.history_merge.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        }),
        "total_cases": results.len(),
        "raw_blocked": results.iter().filter(|r| r.raw_blocked).count(),
        "raw_block_rate": results.iter().filter(|r| r.raw_blocked).count() as f64
            / results.len() as f64,
        // Fix #6: legacy sub-object.  The inflated rate is preserved under
        // `legacy.inflated_rate_DO_NOT_USE` (still emitted for LAW 2
        // backwards-compat; downstream tooling that reads this field will
        // still find it).  Deprecated as of wafrift 0.6.x; target removal
        // in 1.0.0 once all known consumers have migrated to
        // `evaded_summary.overall_bypass_rate` or top-level
        // `overall_bypass_rate`.
        "legacy": args.evade.then(|| {
            let total: usize = results.iter().filter_map(|r| r.evaded.as_ref()).map(|e| e.variants_total).sum();
            let bypassed: usize = results.iter().filter_map(|r| r.evaded.as_ref()).map(|e| e.variants_bypassed).sum();
            let unverified: usize = results.iter().filter_map(|r| r.evaded.as_ref()).map(|e| e.variants_unverified_not_blocked).sum();
            serde_json::json!({
                // deprecated 2026-05-27; target removal wafrift 1.0.0
                "inflated_rate_DO_NOT_USE": if total > 0 { (bypassed + unverified) as f64 / total as f64 } else { 0.0 },
            })
        }),
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
                // RETAINED for LAW 2 backwards-compat; moved to `legacy.inflated_rate_DO_NOT_USE`.
                // Deprecated 2026-05-27; target removal wafrift 1.0.0.
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
        // C-14 rule-quality aggregate: per-class and overall counts of
        // each case_quality variant + mean quality_score over the
        // signal cases. Operators tracking a regression-test corpus
        // use this to compute "what fraction of my corpus actually
        // discriminates this WAF" — `signal/total` is the load-bearing
        // ratio. Mean score over Signal cases tells you how close to
        // p=0.5 (max entropy) the surviving signal is.
        "quality_summary": args.evade.then(|| {
            let mut by_class_q: BTreeMap<String, [usize; 5]> = BTreeMap::new();
            let mut overall = [0usize; 5];
            let mut signal_scores: Vec<f64> = Vec::new();
            for r in results.iter() {
                let idx = match r.case_quality {
                    CaseQuality::BaselineFailed => 0,
                    CaseQuality::TrivialBlock => 1,
                    CaseQuality::TrivialPass => 2,
                    CaseQuality::Signal => 3,
                    CaseQuality::NotMeasured => 4,
                };
                overall[idx] += 1;
                by_class_q.entry(r.class.clone()).or_insert([0; 5])[idx] += 1;
                if matches!(r.case_quality, CaseQuality::Signal) {
                    signal_scores.push(r.quality_score);
                }
            }
            let mean_signal_score = if signal_scores.is_empty() {
                0.0
            } else {
                signal_scores.iter().sum::<f64>() / signal_scores.len() as f64
            };
            serde_json::json!({
                "metric_definition": "case_quality classifies each case: baseline_failed (WAF didn't block raw — no attack to evade), trivial_block (WAF blocked every variant — no signal about brittleness), trivial_pass (every variant slipped — completeness gap), signal (some variants blocked, some passed — discriminative), not_measured (no --evade or zero variants). quality_score = binary Shannon entropy of bypass_rate, peaks at 1.0 when p=0.5.",
                "overall": {
                    "baseline_failed": overall[0],
                    "trivial_block": overall[1],
                    "trivial_pass": overall[2],
                    "signal": overall[3],
                    "not_measured": overall[4],
                    "mean_signal_score": mean_signal_score,
                    "signal_fraction": if results.is_empty() { 0.0 } else { overall[3] as f64 / results.len() as f64 },
                },
                "by_class": by_class_q.iter().map(|(c, q)| (c.clone(), serde_json::json!({
                    "baseline_failed": q[0],
                    "trivial_block": q[1],
                    "trivial_pass": q[2],
                    "signal": q[3],
                    "not_measured": q[4],
                }))).collect::<serde_json::Map<_, _>>(),
            })
        }),
        // C-15 minimum bypass set: given all bypassing payloads across the
        // bench, which smallest subset covers every WAF rule class that any
        // bypass touches? Used to produce forensically minimal payload lists
        // for security reports — one payload per distinct detection surface.
        "min_bypass_set": if args.evade {
            let bypass_payloads: Vec<BypassPayload> = results.iter()
                .filter_map(|r| {
                    let ev = r.evaded.as_ref()?;
                    if ev.variants_bypassed == 0 {
                        return None;
                    }
                    // Use the bypass techniques as the rule-class labels
                    let classes: Vec<String> = if ev.bypass_techniques.is_empty() {
                        vec![r.class.clone()]
                    } else {
                        ev.bypass_techniques.clone()
                    };
                    Some(BypassPayload {
                        id: r.id.clone(),
                        payload: r.payload.clone(),
                        rule_classes: classes,
                        score: ev.bypass_rate,
                    })
                })
                .collect();
            let mbs = compute_min_bypass_set(&bypass_payloads);
            serde_json::json!({
                "summary": format_min_bypass_summary(&mbs),
                "min_set_size": mbs.min_set.len(),
                "input_bypasses": mbs.input_count,
                "classes_covered": mbs.classes_covered,
                "compression_ratio": mbs.compression_ratio,
                "likely_optimal": mbs.likely_optimal,
                "min_set": mbs.min_set.iter().map(|p| serde_json::json!({
                    "id": p.id,
                    "payload": p.payload,
                    "rule_classes": p.rule_classes,
                    "score": p.score,
                })).collect::<Vec<_>>(),
            })
        } else {
            serde_json::Value::Null
        },
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
            for (name, (variants, bypassed, _oracle_valid, unverified, executed)) in
                &by_strategy_acc
            {
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
                // Honest bypass-vs-exploit split under --prove-execution.
                if args.prove_execution {
                    let exec_rate = if *bypassed > 0 {
                        *executed as f64 / *bypassed as f64 * 100.0
                    } else {
                        0.0
                    };
                    println!(
                        "  {:<14} {}",
                        "",
                        format!(
                            "└─ EXECUTING {executed}/{bypassed} bypasses ({exec_rate:.1}%) — \
                             confirmed XSS; the rest bypass but reflect inert"
                        )
                        .dimmed()
                    );
                }
            }
        }

        // Headline bypass-vs-exploit split across all strategies.
        if args.prove_execution {
            println!();
            println!(
                "{} {evade_executed}/{evade_bypassed} verified bypasses EXECUTE ({:.1}%) — \
                 confirmed XSS (alert fired). The remaining {} bypass the WAF but reflect inert: \
                 WAF bypasses, not proven exploits.",
                "EXECUTION:".bold(),
                overall_executed_rate * 100.0,
                evade_bypassed.saturating_sub(evade_executed),
            );
        }
    }
    Ok(())
}

/// Delegates to the workspace-canonical [`crate::probe_classify::truncate`].
/// The implementation (byte-cap + char-boundary walk) originated here and
/// was lifted to `probe_classify` so `legendary.rs` could share it without
/// duplicating the char-boundary fix.
fn truncate(s: &str, n: usize) -> String {
    crate::probe_classify::truncate(s, n)
}

fn bench_waf_browser_identity(
    seed: Option<u64>,
    explicit: Option<String>,
) -> Result<crate::config::ScanBrowserHeaders, String> {
    if let Some(explicit) = explicit {
        return crate::config::resolve_scan_browser_headers(Some(&explicit), None);
    }

    // No operator override: keep the bench-waf-specific fingerprint rotation
    // policy while still using the shared browser-shaped default if the
    // profile pool is unavailable.
    let profile = match seed {
        Some(seed) => guise::fingerprint::browser_catalog::seeded_profile(seed),
        None => guise::fingerprint::browser_catalog::random_profile(),
    };
    browser_identity_for_catalog_profile(profile)
}

fn browser_identity_for_catalog_profile(
    profile: Option<&'static guise::fingerprint::browser_catalog::HeaderProfile>,
) -> Result<crate::config::ScanBrowserHeaders, String> {
    crate::config::resolve_scan_browser_headers(None, profile.map(|profile| profile.name))
}

#[cfg(test)]
#[path = "bench_waf_tests.rs"]
mod tests;
