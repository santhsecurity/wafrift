//! `wafrift hunt` — long-running autonomous bypass campaign.
//!
//! Repeatedly runs `bench-waf --evade` rounds against a target, rotating
//! mutators/strategies each round. Every confirmed bypass is saved to a
//! campaign JSON file at `~/.wafrift/hunt-<campaign-id>.json`. The campaign
//! survives Ctrl-C and can be resumed by re-running with the same
//! `--campaign-id`.
//!
//! ## Scheduling
//!
//! Tokio drives the outer scheduling loop. A round starts every
//! `--interval-secs` seconds (wall time); if a round takes longer than the
//! interval the next round starts immediately. The loop exits when:
//!
//! - `--max-duration-secs` wall time has elapsed, OR
//! - Ctrl-C is received (graceful — finishes the current in-flight round
//!   before persisting and exiting).
//!
//! ## Bypass corpus (consumed by `wafrift harvest`)
//!
//! Every round runs `bench-waf` with a per-target `--corpus-out` under
//! `~/.wafrift`, so a campaign accumulates the concrete winning payload +
//! response evidence for each confirmed bypass. `wafrift harvest` later
//! reads that corpus, re-verifies each candidate live, and writes
//! review-ready reports. `hunt` itself NEVER submits anything — filing is
//! a deliberate, one-at-a-time manual step via `wafrift submit`. (Auto-
//! submitting machine-generated reports at a bounty program is a ban risk,
//! so wafrift has no automatic or batch submission path.)
//!
//! ## CumulusFire preset (--target cumulusfire)
//!
//! Pre-fills `--base-url` with the CumulusFire testing endpoint and sets
//! the `--i-have-permission` reason to the pre-registered CF scope
//! identifier. Then `wafrift harvest --target cumulusfire` turns the
//! accumulated corpus into review-ready bounty reports.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use clap::Args;
use colored::Colorize;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use wafrift_strategy::drift_window::{BypassRateMonitor, ChangePointEvent};

// ─── Preset ──────────────────────────────────────────────────────────────────

/// Known target presets.
const CUMULUSFIRE_BASE_URL: &str = "https://waf.cumulusfire.net";
const CUMULUSFIRE_PERMISSION: &str =
    "CumulusFire public bug bounty scope — wafrift hunt --target cumulusfire";

/// Hunt round writes a `bench-waf --output` JSON to a tmp file then
/// reads it back. Even though the path is owned by wafrift, a tmpdir
/// race (other process replacing the tmp inode with a multi-GB
/// symlink between `run_bench_waf` returning and the read) can OOM
/// the process. 64 MiB matches bench-diff: enough for 10k+ cases,
/// not enough to OOM.
const HUNT_BENCH_OUTPUT_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Campaign state JSON in `~/.wafrift/hunt-<id>.json` is small (a
/// list of round counts + bypass list). 16 MiB catches any
/// runaway-write accident and hostile symlinks pointed at
/// arbitrary files.
const HUNT_CAMPAIGN_STATE_MAX_BYTES: usize = 16 * 1024 * 1024;

// ─── Campaign state ──────────────────────────────────────────────────────────

/// A single confirmed bypass recorded by the campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CampaignBypass {
    /// Wall-clock timestamp (Unix seconds) when the bypass was confirmed.
    pub discovered_at: u64,
    /// Round index in which this bypass was found.
    pub round: u64,
    /// Attack class (e.g. `sql`, `xss`).
    pub class: String,
    /// Bypass technique signature.
    pub technique: String,
    /// True if this bypass was submitted (or queued for submission) to H1.
    pub submitted: bool,
}

/// A change-point event detected by the CUSUM bypass-rate monitor (C-11).
///
/// Recorded when the online CUSUM detector fires — indicating a statistically
/// significant drop in bypass rate, likely caused by a WAF vendor rule update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ChangePointMarker {
    /// Wall-clock timestamp (Unix seconds) when the alarm fired.
    pub detected_at: u64,
    /// Round in which the alarm fired.
    pub round: u64,
    /// Windowed bypass rate at alarm time (fraction in `[0.0, 1.0]`).
    pub observed_rate: f64,
    /// Baseline bypass rate just before the alarm (fraction in `[0.0, 1.0]`).
    pub baseline_rate: f64,
    /// Absolute drop expressed in percentage points.
    pub drop_pp: f64,
}

/// Persisted campaign state.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct CampaignState {
    /// Stable campaign identifier (matches the filename stem).
    pub campaign_id: String,
    /// Target base URL.
    pub target_url: String,
    /// Wall-clock timestamp (Unix seconds) when the campaign started.
    pub started_at: u64,
    /// Total rounds completed.
    pub rounds_completed: u64,
    /// Total bypasses confirmed.
    pub total_bypasses: u64,
    /// Schema version for forward compat.
    pub schema_version: u32,
    /// All confirmed bypasses.
    pub bypasses: Vec<CampaignBypass>,
    /// Change-point events detected by the CUSUM bypass-rate monitor.
    /// Empty in campaigns run without `--change-point-alarm`.
    /// Added in schema_version 2; defaults to empty for v1 state files.
    #[serde(default)]
    pub change_points: Vec<ChangePointMarker>,
}

impl CampaignState {
    /// Schema version 2 adds `change_points` (C-11 CUSUM alarm log).
    /// v1 state files load cleanly via `#[serde(default)]` on the field.
    pub const SCHEMA_VERSION: u32 = 2;
}

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub(crate) struct HuntArgs {
    /// Base URL of the WAF target. Overridden by `--target cumulusfire`.
    #[arg(long)]
    pub base_url: Option<String>,

    /// Named target preset. Currently only `cumulusfire` is defined.
    /// Pre-fills `--base-url` and `--i-have-permission`.
    #[arg(long, value_name = "PRESET", value_parser = ["cumulusfire"])]
    pub target: Option<String>,

    /// Corpus directory (TOML files). Passed through to each bench-waf round.
    #[arg(long, default_value = "wafrift-bench/corpus")]
    pub corpus: PathBuf,

    /// Attack classes to include. Comma-separated. Default: all.
    #[arg(long, value_delimiter = ',')]
    pub class: Vec<String>,

    /// Evasion strategies, comma-separated.
    /// Default: `heavy,equiv-cegis` (same default as bench-waf).
    #[arg(long, value_delimiter = ',', default_value = "heavy,equiv-cegis")]
    pub strategies: Vec<String>,

    /// Known WAF class of the target (e.g. "Cloudflare Bot Management",
    /// "AWS Bot Control"). When it names an ML-backed WAF, the campaign
    /// adds the `ml-evasion` decision-boundary strategy to its rotation and
    /// passes the name through to each bench round. Omit for rule-based
    /// targets — `ml-evasion` would be a no-op there.
    #[arg(long)]
    pub waf_name: Option<String>,

    /// Variants per corpus case per strategy per round.
    #[arg(long, default_value_t = 5)]
    pub variants: usize,

    /// Inter-round interval (seconds). The next round starts this many
    /// seconds after the previous round BEGINS. If a round takes longer
    /// than the interval, the next round starts immediately (no backlog).
    #[arg(long, default_value_t = 60)]
    pub interval_secs: u64,

    /// Maximum campaign wall-clock duration (seconds). 0 = run forever
    /// until Ctrl-C. Default 0.
    #[arg(long, default_value_t = 0)]
    pub max_duration_secs: u64,

    /// Per-round variant budget (max variants to try across all cases in
    /// one round before stopping early). 0 = unlimited. Default 0.
    #[arg(long, default_value_t = 0)]
    pub round_budget: usize,

    /// Stable campaign identifier — used as the output filename stem
    /// (`~/.wafrift/hunt-<id>.json`). If a file for this id already
    /// exists, the campaign is resumed from where it left off.
    /// Default: a UUID generated from the current timestamp.
    #[arg(long)]
    pub campaign_id: Option<String>,

    /// Authorization statement for non-allowlisted targets. Required for
    /// any target outside localhost / RFC1918 / wafrift's built-in list
    /// (unless `--target cumulusfire` is used, which has a built-in reason).
    #[arg(long, value_name = "REASON")]
    pub i_have_permission: Option<String>,

    /// Delay between requests inside each round (ms).
    #[arg(long, default_value_t = 0)]
    pub delay_ms: u64,

    /// Enable CUSUM bypass-rate change-point alarm (C-11).
    ///
    /// When set, the campaign monitors the bypass rate online and emits a
    /// warning to stderr when a statistically significant drop is detected
    /// (indicating a likely WAF rule update). The alarm is also recorded in
    /// the campaign state file under `change_points`.
    #[arg(long, default_value_t = false)]
    pub change_point_alarm: bool,

    /// Sliding window size for the bypass-rate CUSUM detector (samples).
    ///
    /// Larger windows provide a smoother rate estimate but slower detection.
    /// Applies only when `--change-point-alarm` is set.
    #[arg(long, default_value_t = 50)]
    pub change_point_window: usize,

    /// CUSUM slack parameter k for the bypass-rate change-point detector.
    ///
    /// Controls the per-sample allowable drift before the CUSUM accumulates.
    /// Typical value: 0.5 × the minimum detectable rate drop (fraction).
    /// Applies only when `--change-point-alarm` is set.
    #[arg(long, default_value_t = 0.05)]
    pub change_point_k: f64,

    /// CUSUM decision threshold h for the bypass-rate change-point detector.
    ///
    /// The CUSUM accumulator must exceed this value before an alarm fires.
    /// Higher values = fewer false positives but slower detection.
    /// Applies only when `--change-point-alarm` is set.
    #[arg(long, default_value_t = 0.5)]
    pub change_point_h: f64,
}

// ─── Entry point ─────────────────────────────────────────────────────────────

pub(crate) fn run_hunt(args: HuntArgs) -> ExitCode {
    // §7 DEDUPLICATION: delegate to the canonical runtime helper.
    crate::helpers::block_on_with_runtime(run_hunt_async(args))
}

async fn run_hunt_async(mut args: HuntArgs) -> ExitCode {
    // Apply --target preset.
    if let Some(ref preset) = args.target.clone()
        && preset == "cumulusfire"
    {
        if args.base_url.is_none() {
            args.base_url = Some(CUMULUSFIRE_BASE_URL.to_string());
        }
        if args.i_have_permission.is_none() {
            args.i_have_permission = Some(CUMULUSFIRE_PERMISSION.to_string());
        }
    }

    // Paradigm-aware routing: if the operator names an ML-backed WAF
    // (AWS/Cloudflare/Akamai bot-management, Datadome), add the `ml-evasion`
    // decision-boundary strategy to the rotation — rule-decompilation
    // (equiv-cegis) is the wrong paradigm for a learned classifier.
    if let Some(wn) = &args.waf_name
        && wafrift_types::WafClass::from_waf_name(wn).is_ml_backed()
        && !args.strategies.iter().any(|s| s == "ml-evasion")
    {
        args.strategies.push("ml-evasion".to_string());
    }

    let base_url = match args.base_url.clone() {
        Some(u) => u,
        None => {
            // Fall back to WAFRIFT_BENCH_URL or default.
            std::env::var("WAFRIFT_BENCH_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:18081".to_string())
        }
    };

    let campaign_id = args.campaign_id.clone().unwrap_or_else(|| {
        // Stable ID from current wall time (seconds).
        let ts = crate::helpers::now_unix_secs();
        format!("{ts}")
    });
    if let Err(e) = validate_campaign_id(&campaign_id) {
        eprintln!("error: {e}");
        return ExitCode::from(2);
    }

    // N7 fix (dogfood R29 cohort): pre-fix hunt would launch with a
    // missing corpus path, fail per-round inside bench_waf with an
    // error buried in round-1 output, then proceed to "complete"
    // with exit 0. A CI smoke test (`wafrift hunt … --max-duration-
    // secs 30 && echo ok`) printed "ok" even though no round had
    // ever processed a case. Catch the missing-corpus state at the
    // top level BEFORE round 1 starts so the operator sees the
    // failure as a top-level error and the exit code reflects it.
    if !args.corpus.exists() {
        eprintln!(
            "error: corpus path {} does not exist. Default is `wafrift-bench/corpus` \
             relative to CWD; either `cd` into the wafrift repo root before running \
             hunt, or pass `--corpus PATH` explicitly. Hunt aborted before round 1 \
             so the failure is visible to CI.",
            args.corpus.display()
        );
        return ExitCode::from(2);
    }
    // R47 fix (dogfood pass 8 I3): pre-fix hunt would loop forever
    // on an empty corpus directory (every round failed with "no
    // cases found" inside bench_waf but the campaign continued).
    // Walk the corpus path once at startup; if zero .toml files
    // exist, abort with exit 2 — a corpus-less hunt produces zero
    // signal by construction. Recursive walk matches bench_waf's
    // own corpus-loading rule.
    fn has_any_toml(path: &std::path::Path) -> bool {
        if path.is_file() {
            return path
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("toml"));
        }
        let Ok(entries) = std::fs::read_dir(path) else {
            return false;
        };
        for ent in entries.flatten() {
            if has_any_toml(&ent.path()) {
                return true;
            }
        }
        false
    }
    if !has_any_toml(&args.corpus) {
        eprintln!(
            "error: corpus path {} contains no `*.toml` files. An empty corpus \
             produces zero signal per round — the campaign would loop forever \
             burning rate-limit budget. Add at least one corpus TOML before \
             launching hunt.",
            args.corpus.display()
        );
        return ExitCode::from(2);
    }

    let state_path = campaign_state_path(&campaign_id);
    let state = load_or_init_state(&state_path, &campaign_id, &base_url);
    let state = Arc::new(Mutex::new(state));

    eprintln!(
        "{} campaign {} targeting {}",
        "[wafrift hunt]".bright_cyan().bold(),
        campaign_id.bright_white(),
        base_url.bright_yellow(),
    );
    // Ctrl-C → set shutdown flag and cancel the inner token.
    let shutdown = Arc::new(AtomicBool::new(false));
    let cancel = CancellationToken::new();
    {
        let shutdown = shutdown.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                eprintln!(
                    "\n{} Ctrl+C — finishing current round then saving…",
                    "⚠".yellow().bold()
                );
                shutdown.store(true, Ordering::SeqCst);
                cancel.cancel();
            }
        });
    }

    let campaign_start = crate::helpers::now_unix_secs();

    let max_duration = if args.max_duration_secs == 0 {
        None
    } else {
        Some(Duration::from_secs(args.max_duration_secs))
    };
    let interval = Duration::from_secs(args.interval_secs);

    let mut round: u64 = {
        let s = state.lock().await;
        s.rounds_completed
    };

    // C-11: CUSUM bypass-rate change-point monitor.
    // Constructed once and owned by the campaign loop; persists CUSUM
    // accumulator state across rounds so the detector integrates evidence
    // continuously rather than resetting every round.
    let mut cp_monitor = args.change_point_alarm.then(|| {
        BypassRateMonitor::new(
            args.change_point_window,
            args.change_point_k,
            args.change_point_h,
        )
    });

    // C-11: How many remaining rounds of exploration boost to pass to bench_waf.
    // Starts at 0; set to 10 when a change-point alarm fires, decremented
    // each round until it reaches 0 again.
    let mut pending_exploration_boost: u32 = 0;

    loop {
        if shutdown.load(Ordering::SeqCst) || cancel.is_cancelled() {
            break;
        }
        if let Some(max) = max_duration {
            let elapsed = crate::helpers::now_unix_secs().saturating_sub(campaign_start);
            if elapsed >= max.as_secs() {
                eprintln!(
                    "{} max-duration {}s reached — stopping.",
                    "[wafrift hunt]".bright_cyan(),
                    args.max_duration_secs
                );
                break;
            }
        }

        round += 1;
        let round_start = std::time::Instant::now();

        eprintln!(
            "{} round {} — strategies: {}",
            "[wafrift hunt]".bright_cyan(),
            round.to_string().bright_white(),
            args.strategies.join(",").dimmed(),
        );

        // Run one bench-waf round and collect any new bypasses.
        // Pass the pending exploration boost so evolutionary-search engines
        // created inside this round call on_change_point() and explore broadly.
        let boost_this_round = pending_exploration_boost;
        pending_exploration_boost = pending_exploration_boost.saturating_sub(1);
        let round_summary = run_one_round(&args, &base_url, round, boost_this_round).await;
        let new_bypasses = &round_summary.bypasses;

        // §13 dogfood round-2 DEFECT 6 (platform UX): a hunt round can run
        // for minutes inside run_one_round; pre-fix the operator saw the
        // "round N — strategies:" start line and then total silence until the
        // next round (or the wall-clock budget), with no signal the campaign
        // was making progress. Emit a per-round completion summary with the
        // elapsed time + fire/bypass counts so each round visibly closes.
        eprintln!(
            "{} round {} done in {:.1}s — fired {} variant(s), {} new verified bypass(es)",
            "[wafrift hunt]".bright_cyan(),
            round,
            round_start.elapsed().as_secs_f64(),
            round_summary.total_variants_sent,
            new_bypasses.len(),
        );

        // C-11: Feed per-variant bypass outcomes into the CUSUM monitor.
        // We synthesise individual observations from the aggregate counts:
        // `total_variants_bypassed` samples of `true` followed by
        // `total_variants_sent - total_variants_bypassed` samples of `false`.
        // This is statistically equivalent to the round's actual distribution
        // and keeps the CUSUM accumulator calibrated to attempt-level granularity
        // rather than round-level (1 observation/round = too coarse for CUSUM).
        let mut change_point_event: Option<ChangePointEvent> = None;
        if let Some(ref mut monitor) = cp_monitor {
            let sent = round_summary.total_variants_sent;
            let bypassed = round_summary.total_variants_bypassed.min(sent);
            let blocked = sent.saturating_sub(bypassed);

            // Feed bypassed attempts first (true), then blocked (false).
            for _ in 0..bypassed {
                monitor.observe(true);
            }
            for _ in 0..blocked {
                let evt = monitor.observe(false);
                if matches!(evt, ChangePointEvent::AlarmFired { .. }) {
                    // Record the first alarm in this round (subsequent ones
                    // in the same round are noise from baseline re-adaptation).
                    if change_point_event.is_none() {
                        change_point_event = Some(evt);
                    }
                }
            }

            // If no alarm fired on the blocked observations, check the last
            // bypassed observation pass as well (needed when ALL attempts bypass).
            if change_point_event.is_none() && bypassed > 0 {
                // Already called observe above; nothing more needed here.
            }
        }

        // Persist new bypasses.
        {
            let mut s = state.lock().await;
            s.rounds_completed = round;
            let now_ts = crate::helpers::now_unix_secs();
            for bp in new_bypasses {
                // Deduplicate by technique+class.
                let already = s.bypasses.iter().any(|existing| {
                    existing.technique == bp.technique && existing.class == bp.class
                });
                if !already {
                    s.bypasses.push(CampaignBypass {
                        discovered_at: now_ts,
                        round,
                        class: bp.class.clone(),
                        technique: bp.technique.clone(),
                        submitted: false,
                    });
                    s.total_bypasses += 1;
                }
            }

            // C-11: Record change-point alarm in campaign state and emit stderr warning.
            // Also activate an exploration boost for the next 10 bench rounds so
            // evolutionary-search engines discard their learned (now-invalidated)
            // strategy and explore the changed WAF landscape broadly.
            if let Some(ChangePointEvent::AlarmFired {
                observed_rate,
                baseline_rate,
                drop_pp,
            }) = change_point_event
            {
                eprintln!(
                    "  {} CHANGE POINT: bypass rate dropped from {:.0}% to {:.0}% — WAF rule update likely",
                    "⚠".yellow().bold(),
                    baseline_rate * 100.0,
                    observed_rate * 100.0,
                );
                s.change_points.push(ChangePointMarker {
                    detected_at: now_ts,
                    round,
                    observed_rate,
                    baseline_rate,
                    drop_pp,
                });
                // Activate exploration boost for the next 10 rounds.
                // The boost is passed to run_one_round → bench_waf → EvolutionEngine
                // so future bench rounds explore more broadly after the rule update.
                pending_exploration_boost = 10;
            }

            if let Err(e) = persist_state(&state_path, &s) {
                eprintln!("{} persist state: {e}", "error:".red());
            }

            eprintln!(
                "  round {} done — new bypasses: {}  total: {}",
                round,
                new_bypasses.len().to_string().bright_green(),
                s.total_bypasses.to_string().bright_green(),
            );
        }

        if shutdown.load(Ordering::SeqCst) || cancel.is_cancelled() {
            break;
        }

        // Wait for the next interval, honouring Ctrl-C.
        let elapsed = round_start.elapsed();
        if elapsed < interval {
            let remaining = interval - elapsed;
            tokio::select! {
                _ = tokio::time::sleep(remaining) => {}
                _ = cancel.cancelled() => { break; }
            }
        }
    }

    // Final persist.
    {
        let s = state.lock().await;
        if let Err(e) = persist_state(&state_path, &s) {
            eprintln!("{} final persist: {e}", "error:".red());
        }
        eprintln!(
            "{} campaign {} stopped. Total rounds: {}  Total bypasses: {}  State: {}",
            "[wafrift hunt]".bright_cyan().bold(),
            campaign_id.bright_white(),
            s.rounds_completed.to_string().bright_white(),
            s.total_bypasses.to_string().bright_green(),
            state_path.display().to_string().dimmed(),
        );
    }

    ExitCode::SUCCESS
}

// ─── Round runner ─────────────────────────────────────────────────────────────

/// A minimal bypass observation returned from a round.
struct RoundBypass {
    class: String,
    technique: String,
}

/// Summary counts returned from a bench-waf round, used by the CUSUM
/// bypass-rate monitor to feed per-attempt observations.
struct RoundSummary {
    bypasses: Vec<RoundBypass>,
    /// Total variant attempts sent in this round (across all corpus cases).
    total_variants_sent: u64,
    /// Total variants confirmed as bypasses in this round.
    total_variants_bypassed: u64,
}

/// Run one round of bench-waf evasion and collect newly confirmed bypasses.
///
/// We invoke the bench logic by constructing `BenchWafArgs` and passing it
/// directly to the bench runner rather than spawning a subprocess — this
/// keeps the campaign in-process and avoids serialization overhead.
///
/// Returns a [`RoundSummary`] containing the bypasses plus total variant
/// counts, which the CUSUM bypass-rate monitor uses to feed per-attempt
/// observations without requiring access to bench-waf's internal state.
///
/// `exploration_boost_rounds > 0` signals to evolutionary-search strategies
/// that a change-point alarm fired in the previous round and they should
/// explore more broadly (see `EvolutionEngine::on_change_point`).
async fn run_one_round(
    args: &HuntArgs,
    base_url: &str,
    round: u64,
    exploration_boost_rounds: u32,
) -> RoundSummary {
    use crate::bench_waf::{BenchWafArgs, run_bench_waf};

    // Persist every confirmed bypass's winning payload + response evidence
    // to a per-target rule-bypass corpus under ~/.wafrift, so a campaign
    // accumulates a re-verifiable, submittable bypass set across rounds
    // (consumed by `wafrift harvest`). Pre-fix hunt passed corpus_out:None,
    // discarding every winning payload the strategies found — only
    // technique tags survived in the campaign state, which can't
    // reconstruct the wire payload. The path is computed by the SINGLE
    // shared helper `harvest` also reads from, so the two can't diverge.
    let (corpus_path, coverage_path) = crate::corpus_recorder::default_corpus_paths(base_url);

    let bench_args = BenchWafArgs {
        base_url: Some(base_url.to_string()),
        corpus: args.corpus.clone(),
        class: args.class.clone(),
        evade: true, // hunt always evades
        variants: args.variants,
        strategies: rotate_strategies(&args.strategies, round),
        // Paradigm-aware routing: the campaign-level `--waf-name` flows to
        // each bench round so the `ml-evasion` strategy (added to the
        // rotation above when the WAF is ML-backed) routes through the
        // manifold-projected ML-evasion structural mutator.
        waf_name: args.waf_name.clone(),
        // hunt gates at the campaign level (--i-have-permission / cumulus
        // preset); its internal bench rounds don't re-gate — the CLI bench-waf
        // arm is what gates direct invocations.
        i_have_permission: None,
        oracle_gate: false, // no-op flag
        delay_ms: args.delay_ms,
        timeout_secs: 15,
        insecure: false,
        output: None, // we handle persistence ourselves
        // Overwrite REQUIRED: run_one_round pre-claims the per-round tmp
        // output path via O_CREAT|O_EXCL (the TOCTOU/symlink defense
        // below), so the file already exists when bench_waf opens it.
        // Without force_overwrite, bench_waf's no-clobber guard rejects
        // EVERY round's output ("already exists … --force-overwrite") and
        // the whole campaign records 0 bypasses. We own the freshly
        // claimed regular file, so overwriting it is correct + safe.
        force_overwrite: true,
        format: "json".into(),
        summary_only: true, // don't print per-case noise
        prove_execution: false,
        skip_healthcheck: true,
        adaptive_pause_after_errors: 50,
        adaptive_pause_secs: 2,
        validate_only: false,
        lineage_output: None,
        // Info-gain scheduling: hunt manages its own round budget via
        // exploration_boost_rounds + per-strategy rotation, so the
        // per-bench-waf scheduler stays off here. If a future tweak
        // ever wants hunt to feed the scheduler with cross-round
        // history, surface a HuntArgs flag and plumb it through.
        budget: None,
        history_file: None,
        history_merge: Vec::new(),
        fair_class: false,
        list_schedule: false,
        egress_socks5: Vec::new(),
        egress_http_proxy: Vec::new(),
        egress_tailscale_nodes: Vec::new(),
        egress_tailscale_socks_addr: crate::config::DEFAULT_TAILSCALE_SOCKS_ADDR.into(),
        egress_challenge_threshold: crate::config::DEFAULT_EGRESS_CHALLENGE_THRESHOLD,
        egress_cooldown_secs: crate::config::DEFAULT_EGRESS_COOLDOWN_SECS,
        mutator: "default".into(),
        seed: None,
        dilution_weight: 0.0,
        corpus_out: Some(corpus_path),
        coverage_out: Some(coverage_path),
        corpus_fingerprint: String::new(),
        ci_threshold: 0.0, // hunt doesn't use CI gating; pass-through default
        exploration_boost_rounds, // C-11: injected by hunt when CUSUM alarm fires
    };

    // Capture stdout temporarily to intercept the bench JSON output.
    // We run bench_waf on a thread (it has its own tokio runtime) and
    // collect the results via the JSON output path written to a temp file.
    //
    // The tmp filename includes the process PID + a nanosecond timestamp
    // to defeat the predictable-tmp-path symlink attack: pre-fix the
    // path was `/tmp/wafrift-hunt-round-{round}.json`, which an attacker
    // on a shared box could pre-create as `ln -s /etc/cron.d/evil <path>`
    // BEFORE hunt started — bench_waf's `fs::write` would then follow
    // the symlink and clobber the attacker-chosen target.
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let tmp = std::env::temp_dir().join(format!(
        "wafrift-hunt-round-{}-{nanos}-{round}.json",
        std::process::id()
    ));
    // Belt + braces: claim the inode atomically via O_CREAT|O_EXCL
    // BEFORE handing the path to bench_waf. If anything (including a
    // symlink) already sits at the path, this errors and we skip the
    // round — much safer than truncating a victim file. Once claimed,
    // bench_waf's fs::write (O_CREAT|O_TRUNC) reopens OUR regular
    // file and proceeds normally.
    if let Err(e) = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
    {
        eprintln!(
            "warn: hunt round {round} could not claim {} ({e}); skipping round",
            tmp.display()
        );
        return RoundSummary {
            bypasses: Vec::new(),
            total_variants_sent: 0,
            total_variants_bypassed: 0,
        };
    }
    let tmp_clone = tmp.clone();

    let bench_args_with_output = BenchWafArgs {
        output: Some(tmp_clone),
        summary_only: false, // need results array
        ..bench_args
    };

    let exit = tokio::task::spawn_blocking(move || run_bench_waf(bench_args_with_output))
        .await
        .unwrap_or(ExitCode::from(1));

    // Exit code 2 means zero bypasses — that's fine; read the file anyway.
    let _ = exit;

    // Parse the output file.
    let raw = match crate::safe_body::read_bounded_text_file(&tmp, HUNT_BENCH_OUTPUT_MAX_BYTES) {
        Ok(s) => s,
        Err(_) => {
            return RoundSummary {
                bypasses: Vec::new(),
                total_variants_sent: 0,
                total_variants_bypassed: 0,
            };
        }
    };
    let _ = std::fs::remove_file(&tmp);

    let json: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => {
            return RoundSummary {
                bypasses: Vec::new(),
                total_variants_sent: 0,
                total_variants_bypassed: 0,
            };
        }
    };

    // Extract top-level summary variant counts for the CUSUM monitor.
    let total_variants_sent = json
        .get("total_variants_sent")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let total_variants_bypassed = json
        .get("total_variants_bypassed")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    // Collect confirmed bypasses from the results array.
    let mut bypasses = Vec::new();
    if let Some(results) = json.get("results").and_then(|v| v.as_array()) {
        for result in results {
            let class = result
                .get("class")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            if let Some(evaded) = result.get("evaded").and_then(|v| v.as_object()) {
                let bypassed = evaded
                    .get("variants_bypassed")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                if bypassed > 0 {
                    if let Some(techs) = evaded.get("bypass_techniques").and_then(|v| v.as_array())
                    {
                        for t in techs {
                            if let Some(s) = t.as_str() {
                                bypasses.push(RoundBypass {
                                    class: class.clone(),
                                    technique: s.to_string(),
                                });
                            }
                        }
                    } else {
                        bypasses.push(RoundBypass {
                            class: class.clone(),
                            technique: "unknown".to_string(),
                        });
                    }
                }
            }
        }
    }
    RoundSummary {
        bypasses,
        total_variants_sent,
        total_variants_bypassed,
    }
}

/// Rotate strategy list each round — cycle through subsets to explore the
/// strategy space over many rounds rather than hammering the same set.
fn rotate_strategies(strategies: &[String], round: u64) -> Vec<String> {
    if strategies.len() <= 1 {
        return strategies.to_vec();
    }
    // Offset the strategy list by the round index (wrapping).
    let offset = (round as usize) % strategies.len();
    let mut rotated = strategies.to_vec();
    rotated.rotate_left(offset);
    // Use the first min(2, len) strategies for this round.
    let take = 2.min(rotated.len());
    rotated.truncate(take);
    rotated
}

// ─── Persistence ─────────────────────────────────────────────────────────────

/// Permit only safe filename chars in `--campaign-id`. Pre-fix the
/// id was interpolated raw into `hunt-{id}.json`, so an operator
/// passing `--campaign-id ../../tmp/pwn` (whether by mistake or in a
/// scripted pipeline) escaped `~/.wafrift/` and could overwrite
/// arbitrary user-writable files. The allowed alphabet is the
/// portable-filename set plus dash and dot.
fn validate_campaign_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("--campaign-id cannot be empty".to_string());
    }
    if id.len() > 128 {
        return Err(format!(
            "--campaign-id is {} chars; maximum is 128",
            id.len()
        ));
    }
    if id == "." || id == ".." {
        return Err(format!("--campaign-id '{id}' is reserved"));
    }
    if id.starts_with('-') {
        // Defends against a campaign-id that looks like a CLI flag if
        // the value ever flows back into a subprocess argv.
        return Err(format!("--campaign-id '{id}' cannot start with '-'"));
    }
    for ch in id.chars() {
        let ok = ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.';
        if !ok {
            return Err(format!(
                "--campaign-id '{id}' contains invalid character {ch:?}; \
                 allowed: [A-Za-z0-9_-.]"
            ));
        }
    }
    Ok(())
}

fn campaign_state_path(campaign_id: &str) -> PathBuf {
    // Caller MUST have already validated campaign_id via
    // validate_campaign_id; in release we still defence-in-depth by
    // accepting only the validator's alphabet via the format string
    // (any traversal char would already have been rejected upstream).
    let base = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".wafrift");
    let _ = std::fs::create_dir_all(&base);
    base.join(format!("hunt-{campaign_id}.json"))
}

fn load_or_init_state(
    path: &std::path::Path,
    campaign_id: &str,
    target_url: &str,
) -> CampaignState {
    if let Ok(raw) = crate::safe_body::read_bounded_text_file(path, HUNT_CAMPAIGN_STATE_MAX_BYTES)
        && let Ok(s) = serde_json::from_str::<CampaignState>(&raw)
    {
        eprintln!(
            "{} resuming campaign {} (round {}, {} bypasses so far)",
            "[wafrift hunt]".bright_cyan(),
            campaign_id.bright_white(),
            s.rounds_completed,
            s.total_bypasses
        );
        return s;
    }
    let started_at = crate::helpers::now_unix_secs();
    CampaignState {
        campaign_id: campaign_id.to_string(),
        target_url: target_url.to_string(),
        started_at,
        rounds_completed: 0,
        total_bypasses: 0,
        schema_version: CampaignState::SCHEMA_VERSION,
        bypasses: vec![],
        change_points: vec![],
    }
}

fn persist_state(path: &std::path::Path, state: &CampaignState) -> Result<(), String> {
    let json = serde_json::to_string_pretty(state).map_err(|e| e.to_string())?;
    // R49 tail (CLAUDE.md §7 DEDUPLICATION): use the canonical
    // wafrift_types::loaders::write_atomic helper instead of the
    // ad-hoc tmp+rename dance. Same semantics, one source of truth,
    // matches seed.rs / bank.rs callers. The helper also handles
    // parent-fsync for crash durability which the ad-hoc version
    // skipped.
    wafrift_types::loaders::write_atomic(path, json.as_bytes())
        .map_err(|e| format!("atomic write {}: {e}", path.display()))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Regression: hunt round runner must overwrite its pre-claimed tmp ──

    #[test]
    fn round_runner_overwrites_its_preclaimed_tmp_output() {
        // run_one_round pre-claims the per-round tmp output path via
        // O_CREAT|O_EXCL (the TOCTOU/symlink defense), so the file already
        // exists when bench_waf opens it. bench_waf MUST be told to
        // overwrite it — otherwise its no-clobber guard rejects EVERY
        // round's output ("already exists … --force-overwrite") and the
        // campaign records 0 bypasses (the hunt was entirely non-functional
        // against the live edge until this was fixed; caught by dogfooding
        // a real CumulusFire campaign).
        // This test greps its OWN source via include_str!, so neither the
        // wanted nor the forbidden setting may appear here as a contiguous
        // literal — that would self-match and defeat the check. Both needles
        // are assembled at runtime from split pieces; the only contiguous
        // `force_overwrite: <bool>` in this file is the production assignment
        // in run_one_round above.
        let src = include_str!("hunt_cmd.rs");
        let field = "force_overwrite:";
        let want = format!("{field} {}", "true");
        let forbidden = format!("{field} {}", "false");
        assert!(
            src.contains(&want),
            "run_one_round must keep overwrite enabled — it pre-claims the tmp output inode, so \
             bench_waf's no-clobber guard would reject every round otherwise (0 bypasses)"
        );
        assert!(
            !src.contains(&forbidden),
            "hunt overwrite flag reverted to disabled — every round's output is rejected (0 bypasses)"
        );
    }

    // ── Test 1: rotate_strategies wraps at length ─────────────────────────

    #[test]
    fn rotate_strategies_wraps() {
        let strats = vec![
            "heavy".to_string(),
            "equiv-cegis".to_string(),
            "mcts".to_string(),
        ];
        let r0 = rotate_strategies(&strats, 0);
        let r1 = rotate_strategies(&strats, 1);
        let r3 = rotate_strategies(&strats, 3); // wraps back to 0
        assert_eq!(r0, r3);
        assert_ne!(r0, r1);
    }

    // ── Test 2: rotate_strategies single-element is stable ────────────────

    #[test]
    fn rotate_strategies_single_element() {
        let strats = vec!["heavy".to_string()];
        let r = rotate_strategies(&strats, 42);
        assert_eq!(r, vec!["heavy"]);
    }

    // ── Test 3: rotate_strategies takes at most 2 ─────────────────────────

    #[test]
    fn rotate_strategies_max_two() {
        let strats: Vec<String> = ["a", "b", "c", "d", "e"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let r = rotate_strategies(&strats, 0);
        assert!(r.len() <= 2);
    }

    // ── Test 4: campaign state round-trips through JSON ────────────────────

    #[test]
    fn campaign_state_roundtrip() {
        let state = CampaignState {
            campaign_id: "test-001".into(),
            target_url: "http://localhost:18081".into(),
            started_at: 1_000_000,
            rounds_completed: 5,
            total_bypasses: 3,
            schema_version: CampaignState::SCHEMA_VERSION,
            bypasses: vec![CampaignBypass {
                discovered_at: 1_000_100,
                round: 3,
                class: "sql".into(),
                technique: "tamper/comment".into(),
                submitted: false,
            }],
            change_points: vec![],
        };
        let json = serde_json::to_string(&state).unwrap();
        let de: CampaignState = serde_json::from_str(&json).unwrap();
        assert_eq!(de.campaign_id, "test-001");
        assert_eq!(de.rounds_completed, 5);
        assert_eq!(de.total_bypasses, 3);
        assert_eq!(de.bypasses.len(), 1);
        assert_eq!(de.bypasses[0].technique, "tamper/comment");
    }

    // ── Test 5: load_or_init_state creates fresh when no file ─────────────

    #[test]
    fn init_state_when_no_file() {
        let tmp = std::env::temp_dir().join("wafrift-hunt-test-nonexistent-99999.json");
        let _ = std::fs::remove_file(&tmp);
        let state = load_or_init_state(&tmp, "nonexistent-99999", "http://localhost");
        assert_eq!(state.rounds_completed, 0);
        assert_eq!(state.total_bypasses, 0);
        assert!(state.bypasses.is_empty());
    }

    // ── Test 6: persist_state writes valid JSON ────────────────────────────

    #[test]
    fn persist_state_writes_valid_json() {
        let tmp = std::env::temp_dir().join("wafrift-hunt-persist-test.json");
        let state = CampaignState {
            campaign_id: "persist-test".into(),
            target_url: "http://localhost".into(),
            started_at: 0,
            rounds_completed: 1,
            total_bypasses: 0,
            schema_version: CampaignState::SCHEMA_VERSION,
            bypasses: vec![],
            change_points: vec![],
        };
        persist_state(&tmp, &state).unwrap();
        let raw = std::fs::read_to_string(&tmp).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["campaign_id"], "persist-test");
        let _ = std::fs::remove_file(&tmp);
    }

    // ── Test 7: load_or_init_state resumes from file ──────────────────────

    #[test]
    fn resume_state_from_file() {
        let tmp = std::env::temp_dir().join("wafrift-hunt-resume-test.json");
        let state = CampaignState {
            campaign_id: "resume-test".into(),
            target_url: "http://localhost".into(),
            started_at: 12345,
            rounds_completed: 7,
            total_bypasses: 2,
            schema_version: CampaignState::SCHEMA_VERSION,
            bypasses: vec![],
            change_points: vec![],
        };
        persist_state(&tmp, &state).unwrap();
        let loaded = load_or_init_state(&tmp, "resume-test", "http://localhost");
        assert_eq!(loaded.rounds_completed, 7);
        assert_eq!(loaded.total_bypasses, 2);
        let _ = std::fs::remove_file(&tmp);
    }

    // ── Test 8: bypass dedup logic ────────────────────────────────────────

    #[test]
    fn bypass_dedup() {
        let mut state = CampaignState {
            schema_version: CampaignState::SCHEMA_VERSION,
            ..Default::default()
        };
        let bp = CampaignBypass {
            discovered_at: 0,
            round: 1,
            class: "sql".into(),
            technique: "tamper/comment".into(),
            submitted: false,
        };
        // Insert same bypass twice via the dedup guard.
        for _ in 0..2 {
            let already = state
                .bypasses
                .iter()
                .any(|e| e.technique == bp.technique && e.class == bp.class);
            if !already {
                state.bypasses.push(bp.clone());
                state.total_bypasses += 1;
            }
        }
        assert_eq!(state.bypasses.len(), 1);
        assert_eq!(state.total_bypasses, 1);
    }

    // ── Test 9: cumulusfire preset sets url and permission ────────────────

    #[test]
    fn cumulusfire_preset_constants() {
        assert!(!CUMULUSFIRE_BASE_URL.is_empty());
        assert!(!CUMULUSFIRE_PERMISSION.is_empty());
        assert!(CUMULUSFIRE_BASE_URL.starts_with("https://"));
    }

    // ── Test 10: schema_version constant is stable ────────────────────────
    // Schema version 2 added the `change_points` field (C-11 CUSUM alarm log).

    #[test]
    fn schema_version_constant() {
        assert_eq!(CampaignState::SCHEMA_VERSION, 2);
    }

    // ── Test 11: persist_state is atomic — no orphaned .tmp on success ───
    // After a successful persist_state call, the sibling `.json.tmp` file
    // must NOT exist (it was renamed into the final path).

    #[test]
    fn persist_state_no_orphaned_tmp_file() {
        let tmp_dir = std::env::temp_dir();
        let path = tmp_dir.join("wafrift-hunt-atomic-test.json");
        let tmp_sibling = tmp_dir.join("wafrift-hunt-atomic-test.json.tmp");
        // Clean up any leftovers from previous runs.
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&tmp_sibling);

        let state = CampaignState {
            campaign_id: "atomic-test".into(),
            target_url: "http://localhost".into(),
            started_at: 0,
            rounds_completed: 3,
            total_bypasses: 1,
            schema_version: CampaignState::SCHEMA_VERSION,
            bypasses: vec![],
            change_points: vec![],
        };
        persist_state(&path, &state).unwrap();

        // Destination file must exist and be valid JSON.
        let raw = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["campaign_id"], "atomic-test");

        // The .tmp sibling must be gone — rename succeeded.
        assert!(
            !tmp_sibling.exists(),
            ".json.tmp sibling was not cleaned up: {:?}",
            tmp_sibling
        );

        let _ = std::fs::remove_file(&path);
    }

    // ── Test 14: persist_state destination file contains all state fields ─
    // A round-trip through persist + load must preserve every field.

    #[test]
    fn persist_state_round_trip_all_fields() {
        let path = std::env::temp_dir().join("wafrift-hunt-roundtrip-test.json");
        let _ = std::fs::remove_file(&path);

        let bypass = CampaignBypass {
            discovered_at: 999,
            round: 5,
            class: "xss".into(),
            technique: "tamper/unicode".into(),
            submitted: true,
        };
        let state = CampaignState {
            campaign_id: "roundtrip-id".into(),
            target_url: "https://example.com/path?foo=bar".into(),
            started_at: 1_700_000_000,
            rounds_completed: 42,
            total_bypasses: 1,
            schema_version: CampaignState::SCHEMA_VERSION,
            bypasses: vec![bypass],
            change_points: vec![],
        };
        persist_state(&path, &state).unwrap();

        let loaded = load_or_init_state(&path, "roundtrip-id", "https://example.com/path?foo=bar");
        assert_eq!(loaded.campaign_id, "roundtrip-id");
        assert_eq!(loaded.rounds_completed, 42);
        assert_eq!(loaded.total_bypasses, 1);
        assert_eq!(loaded.bypasses.len(), 1);
        assert_eq!(loaded.bypasses[0].technique, "tamper/unicode");
        assert!(loaded.bypasses[0].submitted);

        let _ = std::fs::remove_file(&path);
    }

    // ── Test 15: persist_state overwrites existing content atomically ─────
    // A second persist must fully replace the first write, not append to it.

    #[test]
    fn persist_state_overwrites_previous_content() {
        let path = std::env::temp_dir().join("wafrift-hunt-overwrite-test.json");
        let _ = std::fs::remove_file(&path);

        let mk_state = |rounds: u64, bypasses: u64| CampaignState {
            campaign_id: "overwrite-test".into(),
            target_url: "http://localhost".into(),
            started_at: 0,
            rounds_completed: rounds,
            total_bypasses: bypasses,
            schema_version: CampaignState::SCHEMA_VERSION,
            bypasses: vec![],
            change_points: vec![],
        };

        persist_state(&path, &mk_state(1, 0)).unwrap();
        persist_state(&path, &mk_state(7, 3)).unwrap();

        // Only the second write's values must be present.
        let raw = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["rounds_completed"], 7, "stale content from first write");
        assert_eq!(v["total_bypasses"], 3, "stale content from first write");

        let _ = std::fs::remove_file(&path);
    }

    // ── Test 16: persist_state returns Err for unwritable directory ───────

    #[test]
    fn persist_state_returns_err_for_bad_path() {
        // A path whose parent does not exist must produce an Err, not a panic.
        let bad_path = std::path::PathBuf::from("/this/directory/does/not/exist/campaign.json");
        let state = CampaignState::default();
        let result = persist_state(&bad_path, &state);
        assert!(result.is_err(), "expected Err for non-existent parent dir");
    }

    // ── Round 22: path-traversal defence on --campaign-id ─────────────
    //
    // Pre-fix, `--campaign-id "../../tmp/pwn"` formatted into
    // `~/.wafrift/hunt-../../tmp/pwn.json` which path-resolves
    // outside `.wafrift/`. The validator now rejects any character
    // outside the safe portable-filename alphabet.

    #[test]
    fn validate_campaign_id_accepts_safe_ids() {
        for id in [
            "default",
            "campaign-001",
            "campaign_001",
            "2026-05-26",
            "abc.def",
            "A1B2C3",
        ] {
            assert!(
                super::validate_campaign_id(id).is_ok(),
                "safe id rejected: {id}"
            );
        }
    }

    #[test]
    fn validate_campaign_id_rejects_traversal() {
        for bad in [
            "../../tmp/pwn",
            "..",
            ".",
            "a/b",
            "a\\b",
            "/etc/passwd",
            "campaign with spaces",
            "campaign\nwith\nnewlines",
            "campaign\0null",
            "",
        ] {
            assert!(
                super::validate_campaign_id(bad).is_err(),
                "traversal/unsafe id accepted: {bad:?}"
            );
        }
    }

    #[test]
    fn validate_campaign_id_rejects_leading_dash() {
        // A campaign-id like "--evil" could be reinterpreted as a
        // CLI flag if it ever flows into a subprocess argv.
        assert!(super::validate_campaign_id("-x").is_err());
        assert!(super::validate_campaign_id("--evil").is_err());
    }

    #[test]
    fn validate_campaign_id_rejects_oversize() {
        let long = "a".repeat(129);
        assert!(super::validate_campaign_id(&long).is_err());
        let exact = "a".repeat(128);
        assert!(super::validate_campaign_id(&exact).is_ok());
    }

    #[test]
    fn campaign_state_path_stays_under_dot_wafrift() {
        // Sanity: for every validator-allowed campaign id, the
        // resolved state path must remain a child of the .wafrift
        // base directory.
        let base = dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(".wafrift");
        for id in ["default", "campaign-001", "x.y_z"] {
            let p = super::campaign_state_path(id);
            assert!(
                p.starts_with(&base),
                "campaign state path {p:?} escaped {base:?} for id {id}"
            );
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // C-11: Change-point alarm tests (LAW 9 — pinned JSON shape + wiring)
    // ══════════════════════════════════════════════════════════════════════

    // ── CP-1: ChangePointMarker round-trips through JSON with correct fields.
    // Pins the JSON schema so downstream consumers notice if it changes.

    #[test]
    fn change_point_marker_json_shape() {
        let marker = ChangePointMarker {
            detected_at: 1_700_000_042,
            round: 7,
            observed_rate: 0.05,
            baseline_rate: 0.30,
            drop_pp: 25.0,
        };
        let json = serde_json::to_string(&marker).expect("must serialize");
        let v: serde_json::Value = serde_json::from_str(&json).expect("must deserialize");
        assert_eq!(v["detected_at"], 1_700_000_042u64, "detected_at field");
        assert_eq!(v["round"], 7u64, "round field");
        assert!(
            (v["observed_rate"].as_f64().unwrap() - 0.05).abs() < 1e-9,
            "observed_rate field"
        );
        assert!(
            (v["baseline_rate"].as_f64().unwrap() - 0.30).abs() < 1e-9,
            "baseline_rate field"
        );
        assert!(
            (v["drop_pp"].as_f64().unwrap() - 25.0).abs() < 1e-9,
            "drop_pp field"
        );
    }

    // ── CP-2: CampaignState with change_points persists and reloads correctly.
    // Verifies the new field survives the persist → load round trip.

    #[test]
    fn campaign_state_change_points_persist_roundtrip() {
        let path = std::env::temp_dir().join("wafrift-hunt-cp-roundtrip-test.json");
        let _ = std::fs::remove_file(&path);

        let state = CampaignState {
            campaign_id: "cp-test".into(),
            target_url: "http://localhost".into(),
            started_at: 0,
            rounds_completed: 10,
            total_bypasses: 2,
            schema_version: CampaignState::SCHEMA_VERSION,
            bypasses: vec![],
            change_points: vec![ChangePointMarker {
                detected_at: 99999,
                round: 5,
                observed_rate: 0.0,
                baseline_rate: 0.35,
                drop_pp: 35.0,
            }],
        };
        persist_state(&path, &state).unwrap();

        let loaded = load_or_init_state(&path, "cp-test", "http://localhost");
        assert_eq!(
            loaded.change_points.len(),
            1,
            "one change_point must survive round-trip"
        );
        assert_eq!(loaded.change_points[0].round, 5);
        assert!((loaded.change_points[0].baseline_rate - 0.35).abs() < 1e-9);
        assert!((loaded.change_points[0].drop_pp - 35.0).abs() < 1e-9);

        let _ = std::fs::remove_file(&path);
    }

    // ── CP-3: v1 state file (no change_points field) loads cleanly into v2.
    // Backwards-compat: campaigns started before C-11 must not fail to load.

    #[test]
    fn change_points_defaults_to_empty_on_v1_state_file() {
        let path = std::env::temp_dir().join("wafrift-hunt-v1-compat-test.json");
        let _ = std::fs::remove_file(&path);

        // Write a v1-style JSON that has no change_points key.
        let v1_json = r#"{
            "campaign_id": "v1-compat",
            "target_url": "http://localhost",
            "started_at": 0,
            "rounds_completed": 3,
            "total_bypasses": 1,
            "schema_version": 1,
            "bypasses": []
        }"#;
        std::fs::write(&path, v1_json).unwrap();

        let loaded = load_or_init_state(&path, "v1-compat", "http://localhost");
        assert_eq!(
            loaded.change_points.len(),
            0,
            "v1 state file must deserialize with empty change_points"
        );
        assert_eq!(loaded.rounds_completed, 3);

        let _ = std::fs::remove_file(&path);
    }

    // ── CP-4: change_point_alarm flag is available on HuntArgs with defaults.

    #[test]
    fn change_point_alarm_flags_have_correct_defaults() {
        let args = HuntArgs {
            base_url: None,
            target: None,
            corpus: PathBuf::from("corpus"),
            class: vec![],
            strategies: vec!["heavy".into()],
            waf_name: None,
            variants: 5,
            interval_secs: 60,
            max_duration_secs: 0,
            round_budget: 0,
            campaign_id: None,
            i_have_permission: None,
            delay_ms: 0,
            change_point_alarm: false,
            change_point_window: 50,
            change_point_k: 0.05,
            change_point_h: 0.5,
        };
        assert!(!args.change_point_alarm, "default alarm is off");
        assert_eq!(args.change_point_window, 50);
        assert!((args.change_point_k - 0.05).abs() < 1e-9);
        assert!((args.change_point_h - 0.5).abs() < 1e-9);
    }
}
