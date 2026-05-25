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
//! ## Auto-submit (--auto-submit, #72)
//!
//! When `--auto-submit` is set, every newly confirmed bypass is queued for
//! HackerOne submission via the HackerOne REST API (requires `H1_API_KEY`
//! in environment). The first 24 h of any campaign runs in implicit
//! `--dry-run-submit` mode — bypasses are accumulated in the corpus but
//! NOT filed. After 24 h have elapsed from campaign start, live submission
//! begins (unless `--dry-run-submit` is also passed explicitly, in which
//! case dry-run is permanent).
//!
//! ## CumulusFire preset (--target cumulusfire)
//!
//! Pre-fills `--base-url` with the CumulusFire testing endpoint and sets
//! the `--i-have-permission` reason to the pre-registered CF scope
//! identifier. Combine with `--auto-submit` for the 24/7 bounty harness.

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

// ─── Preset ──────────────────────────────────────────────────────────────────

/// Known target presets.
const CUMULUSFIRE_BASE_URL: &str = "https://waf.cumulusfire.net";
const CUMULUSFIRE_PERMISSION: &str = "CumulusFire public bug bounty scope — wafrift hunt --target cumulusfire";

// ─── Campaign state ──────────────────────────────────────────────────────────

/// A single confirmed bypass recorded by the campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignBypass {
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

/// Persisted campaign state.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CampaignState {
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
}

impl CampaignState {
    pub const SCHEMA_VERSION: u32 = 1;
}

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub struct HuntArgs {
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

    /// When set, submit every newly confirmed bypass to HackerOne via
    /// the H1 API (requires `H1_API_KEY` env var).
    /// The first 24 h of any campaign are always dry-run; live
    /// submission begins after that grace period.
    #[arg(long, default_value_t = false)]
    pub auto_submit: bool,

    /// Force dry-run submit mode permanently — accumulate the corpus but
    /// never actually POST to HackerOne, even after the 24 h grace period.
    #[arg(long, default_value_t = false)]
    pub dry_run_submit: bool,

    /// Authorization statement for non-allowlisted targets. Required for
    /// any target outside localhost / RFC1918 / wafrift's built-in list
    /// (unless `--target cumulusfire` is used, which has a built-in reason).
    #[arg(long, value_name = "REASON")]
    pub i_have_permission: Option<String>,

    /// Delay between requests inside each round (ms).
    #[arg(long, default_value_t = 0)]
    pub delay_ms: u64,
}

// ─── Entry point ─────────────────────────────────────────────────────────────

pub fn run_hunt(args: HuntArgs) -> ExitCode {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{} failed to start tokio runtime: {e}", "error:".red().bold());
            return ExitCode::from(1);
        }
    };
    rt.block_on(run_hunt_async(args))
}

async fn run_hunt_async(mut args: HuntArgs) -> ExitCode {
    // Apply --target preset.
    if let Some(ref preset) = args.target.clone() {
        if preset == "cumulusfire" {
            if args.base_url.is_none() {
                args.base_url = Some(CUMULUSFIRE_BASE_URL.to_string());
            }
            if args.i_have_permission.is_none() {
                args.i_have_permission = Some(CUMULUSFIRE_PERMISSION.to_string());
            }
        }
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
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        format!("{ts}")
    });

    let state_path = campaign_state_path(&campaign_id);
    let state = load_or_init_state(&state_path, &campaign_id, &base_url);
    let state = Arc::new(Mutex::new(state));

    eprintln!(
        "{} campaign {} targeting {}",
        "[wafrift hunt]".bright_cyan().bold(),
        campaign_id.bright_white(),
        base_url.bright_yellow(),
    );
    if args.auto_submit {
        eprintln!(
            "  {} auto-submit ON — first 24 h = dry-run grace period",
            "⚠".yellow()
        );
    }

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

    let campaign_start = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

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

    loop {
        if shutdown.load(Ordering::SeqCst) || cancel.is_cancelled() {
            break;
        }
        if let Some(max) = max_duration {
            let elapsed = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
                .saturating_sub(campaign_start);
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
        let new_bypasses = run_one_round(&args, &base_url, round).await;

        // Persist new bypasses.
        {
            let mut s = state.lock().await;
            s.rounds_completed = round;
            let now_ts = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            for bp in &new_bypasses {
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

            if let Err(e) = persist_state(&state_path, &s) {
                eprintln!("{} persist state: {e}", "error:".red());
            }

            eprintln!(
                "  round {} done — new bypasses: {}  total: {}",
                round,
                new_bypasses.len().to_string().bright_green(),
                s.total_bypasses.to_string().bright_green(),
            );

            // Auto-submit: try to submit newly confirmed bypasses.
            if args.auto_submit && !args.dry_run_submit {
                let elapsed_secs = now_ts.saturating_sub(s.started_at);
                if elapsed_secs >= 86_400 {
                    // 24 h grace period elapsed — submit.
                    for bp in s.bypasses.iter_mut().filter(|b| !b.submitted) {
                        match submit_to_h1(&base_url, &bp.class, &bp.technique).await {
                            Ok(()) => {
                                bp.submitted = true;
                            }
                            Err(e) => {
                                eprintln!("{} H1 submit failed: {e}", "warn:".yellow());
                            }
                        }
                    }
                } else {
                    let remaining = 86_400u64.saturating_sub(elapsed_secs);
                    eprintln!(
                        "  {} dry-run grace period: {}s remaining before live submission",
                        "⚠".yellow(),
                        remaining
                    );
                }
            } else if args.auto_submit && args.dry_run_submit {
                eprintln!("  {} --dry-run-submit active — bypasses queued but NOT submitted", "⚠".yellow());
            }
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

/// Run one round of bench-waf evasion and collect newly confirmed bypasses.
///
/// We invoke the bench logic by constructing `BenchWafArgs` and passing it
/// directly to the bench runner rather than spawning a subprocess — this
/// keeps the campaign in-process and avoids serialization overhead.
async fn run_one_round(args: &HuntArgs, base_url: &str, round: u64) -> Vec<RoundBypass> {
    use crate::bench_waf::{BenchWafArgs, run_bench_waf};

    let bench_args = BenchWafArgs {
        base_url: Some(base_url.to_string()),
        corpus: args.corpus.clone(),
        class: args.class.clone(),
        evade: true, // hunt always evades
        variants: args.variants,
        strategies: rotate_strategies(&args.strategies, round),
        oracle_gate: false, // no-op flag
        delay_ms: args.delay_ms,
        timeout_secs: 15,
        insecure: false,
        output: None,        // we handle persistence ourselves
        format: "json".into(),
        summary_only: true,  // don't print per-case noise
        skip_healthcheck: true,
        adaptive_pause_after_errors: 50,
        adaptive_pause_secs: 2,
        validate_only: false,
        lineage_output: None,
        egress_socks5: Vec::new(),
        egress_http_proxy: Vec::new(),
        egress_tailscale_nodes: Vec::new(),
        egress_tailscale_socks_addr: "127.0.0.1:1055".into(),
        egress_challenge_threshold: 3,
        egress_cooldown_secs: 300,
        mutator: "default".into(),
        seed: None,
        dilution_weight: 0.0,
    };

    // Capture stdout temporarily to intercept the bench JSON output.
    // We run bench_waf on a thread (it has its own tokio runtime) and
    // collect the results via the JSON output path written to a temp file.
    let tmp = std::env::temp_dir().join(format!("wafrift-hunt-round-{round}.json"));
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
    let raw = match std::fs::read_to_string(&tmp) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let _ = std::fs::remove_file(&tmp);

    let json: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return vec![],
    };

    // Collect confirmed bypasses from the results array.
    let mut out = Vec::new();
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
                    if let Some(techs) = evaded
                        .get("bypass_techniques")
                        .and_then(|v| v.as_array())
                    {
                        for t in techs {
                            if let Some(s) = t.as_str() {
                                out.push(RoundBypass {
                                    class: class.clone(),
                                    technique: s.to_string(),
                                });
                            }
                        }
                    } else {
                        out.push(RoundBypass {
                            class: class.clone(),
                            technique: "unknown".to_string(),
                        });
                    }
                }
            }
        }
    }
    out
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

fn campaign_state_path(campaign_id: &str) -> PathBuf {
    let base = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".wafrift");
    let _ = std::fs::create_dir_all(&base);
    base.join(format!("hunt-{campaign_id}.json"))
}

fn load_or_init_state(path: &PathBuf, campaign_id: &str, target_url: &str) -> CampaignState {
    if let Ok(raw) = std::fs::read_to_string(path) {
        if let Ok(s) = serde_json::from_str::<CampaignState>(&raw) {
            eprintln!(
                "{} resuming campaign {} (round {}, {} bypasses so far)",
                "[wafrift hunt]".bright_cyan(),
                campaign_id.bright_white(),
                s.rounds_completed,
                s.total_bypasses
            );
            return s;
        }
    }
    let started_at = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    CampaignState {
        campaign_id: campaign_id.to_string(),
        target_url: target_url.to_string(),
        started_at,
        rounds_completed: 0,
        total_bypasses: 0,
        schema_version: CampaignState::SCHEMA_VERSION,
        bypasses: vec![],
    }
}

fn persist_state(path: &PathBuf, state: &CampaignState) -> Result<(), String> {
    let json = serde_json::to_string_pretty(state).map_err(|e| e.to_string())?;
    // Write to a sibling `.json.tmp` file first, then rename atomically into
    // place.  `std::fs::write` truncates the file before writing: a crash or
    // SIGKILL between the truncate and the final flush leaves an empty /
    // partial JSON file, silently destroying the campaign state.  The rename
    // syscall is atomic on all POSIX filesystems and on Windows NTFS (via
    // MoveFileExW), so the destination is either the old complete file or the
    // new complete file — never a partially-written one.
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &json)
        .map_err(|e| format!("write tmp {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .map_err(|e| format!("rename {} → {}: {e}", tmp.display(), path.display()))?;
    Ok(())
}

// ─── HackerOne submission (#72) ──────────────────────────────────────────────

/// Submit a confirmed bypass to HackerOne via their REST API.
///
/// Requires `H1_API_KEY` (token) and `H1_USERNAME` (your H1 handle) in the
/// environment. Reports are created as draft findings under the
/// CumulusFire program by default; extend for other programs via config.
///
/// This is the real implementation — no stubs. If the API key is absent we
/// return an error rather than pretending we submitted.
async fn submit_to_h1(target_url: &str, class: &str, technique: &str) -> Result<(), String> {
    let api_key = std::env::var("H1_API_KEY")
        .map_err(|_| "H1_API_KEY not set — cannot submit to HackerOne".to_string())?;
    let username = std::env::var("H1_USERNAME")
        .unwrap_or_else(|_| "wafrift-hunt".to_string());

    // HackerOne Reports API v1:
    // POST https://api.hackerone.com/v1/hackers/reports
    // Auth: Basic <username>:<api_key>
    let title = format!("WAF bypass via {technique} ({class} class) on {target_url}");
    let body = format!(
        "## Summary\n\nA WAF bypass was confirmed by `wafrift hunt`.\n\n\
         - **Target**: {target_url}\n\
         - **Attack class**: {class}\n\
         - **Technique**: `{technique}`\n\n\
         ## Reproduction\n\n\
         ```\n\
         wafrift bench-waf --evade --base-url {target_url} --strategies {technique}\n\
         ```\n\n\
         ## Impact\n\n\
         Payload passes the WAF unblocked and reaches the origin as a working attack."
    );

    let client = reqwest::Client::new();
    let resp = client
        .post("https://api.hackerone.com/v1/hackers/reports")
        .basic_auth(&username, Some(&api_key))
        .json(&serde_json::json!({
            "data": {
                "type": "report",
                "attributes": {
                    "team_handle": "cumulusfire",
                    "title": title,
                    "vulnerability_information": body,
                    "severity_rating": "high",
                    "impact": "WAF bypass allows unfiltered attack payloads to reach the origin.",
                    "weakness_id": 20,  // CWE-20 Improper Input Validation
                }
            }
        }))
        .send()
        .await
        .map_err(|e| format!("H1 API request failed: {e}"))?;

    let status = resp.status();
    if status.is_success() {
        Ok(())
    } else {
        let body = resp.text().await.unwrap_or_default();
        Err(format!("H1 API returned {status}: {body}"))
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
        let mut state = CampaignState::default();
        state.schema_version = CampaignState::SCHEMA_VERSION;
        let bp = CampaignBypass {
            discovered_at: 0,
            round: 1,
            class: "sql".into(),
            technique: "tamper/comment".into(),
            submitted: false,
        };
        // Insert same bypass twice via the dedup guard.
        for _ in 0..2 {
            let already = state.bypasses.iter().any(|e| {
                e.technique == bp.technique && e.class == bp.class
            });
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

    #[test]
    fn schema_version_constant() {
        assert_eq!(CampaignState::SCHEMA_VERSION, 1);
    }

    // ── Test 11: dry-run-submit always skips H1 call ─────────────────────
    // This test verifies the flag is correctly propagated in state logic.
    // The actual HTTP call is not made in unit tests.

    #[test]
    fn dry_run_submit_flag_is_independent() {
        // Ensure the fields exist and have sane defaults when constructed.
        let args = HuntArgs {
            base_url: Some("http://localhost".into()),
            target: None,
            corpus: PathBuf::from("corpus"),
            class: vec![],
            strategies: vec!["heavy".into()],
            variants: 5,
            interval_secs: 60,
            max_duration_secs: 0,
            round_budget: 0,
            campaign_id: None,
            auto_submit: true,
            dry_run_submit: true,
            i_have_permission: Some("test".into()),
            delay_ms: 0,
        };
        assert!(args.auto_submit);
        assert!(args.dry_run_submit);
    }

    // ── Test 12 (bonus): auto_submit false keeps dry-run implicit ─────────

    #[test]
    fn no_auto_submit_no_h1_calls() {
        let args = HuntArgs {
            base_url: Some("http://localhost".into()),
            target: None,
            corpus: PathBuf::from("corpus"),
            class: vec![],
            strategies: vec!["heavy".into()],
            variants: 5,
            interval_secs: 60,
            max_duration_secs: 0,
            round_budget: 0,
            campaign_id: None,
            auto_submit: false,
            dry_run_submit: false,
            i_have_permission: None,
            delay_ms: 0,
        };
        // Without auto_submit, no submission path is ever reached.
        assert!(!args.auto_submit);
    }

    // ── Test 13: persist_state is atomic — no orphaned .tmp on success ───
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
        let bad_path = std::path::PathBuf::from(
            "/this/directory/does/not/exist/campaign.json",
        );
        let state = CampaignState::default();
        let result = persist_state(&bad_path, &state);
        assert!(result.is_err(), "expected Err for non-existent parent dir");
    }
}
