//! `wafrift legendary` — the one-shot demo command.
//!
//! Runs `detect` -> `fingerprint` -> `bypass-probe` against a single
//! target, with an optional `scan` phase when `--payload` is given,
//! and stitches the results into one polished markdown writeup. The
//! pitch: a stakeholder asks "what does wafrift do?" — you answer with
//! one command and hand them the markdown.
//!
//! Design notes:
//!
//! - Every phase is **best-effort**: a network blip in one phase
//!   doesn't kill the others. The report calls out which phases ran,
//!   which were skipped, and which errored.
//! - Output is deterministic ordering (detect, fingerprint,
//!   bypass-probe, scan) so two runs against the same target produce
//!   comparable diffs.
//! - No new evasion logic lives here — it composes the existing
//!   `waf_detect`, `bypass_probe`, and `scan` paths so the demo can
//!   never drift from real wafrift behaviour. Anything the demo
//!   reports is something the operator could verify with the
//!   underlying subcommand.
//! - Bounded by default: scan caps at 30 variants and bypass-probe
//!   uses the same sensible default concurrency as the standalone
//!   command. The demo must be fast or no one runs it twice.

use clap::Args;
use colored::Colorize;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;
use wafrift_detect::waf_detect;

use crate::bypass_probe::{BypassProbeArgs, run_bypass_probe};
use crate::detect_cmd::{fetch_differential, fetch_for_detect, infra_markers};
use crate::helpers::shell_single_quote;

#[derive(Args, Debug)]
pub struct LegendaryArgs {
    /// Target URL — the surface to probe end-to-end.
    pub target: String,

    /// Payload to mutate and fire through the scan phase. When omitted,
    /// the scan phase is skipped and the report contains only detect /
    /// fingerprint / bypass-probe.
    #[arg(long)]
    pub payload: Option<String>,

    /// Parameter name for the scan phase. Ignored when `--payload` is
    /// not given.
    #[arg(long, default_value = "q")]
    pub param: String,

    /// Path to a file of one URL path per line for the bypass-probe
    /// phase to sweep (defaults to single-URL mode).
    #[arg(long)]
    pub paths_file: Option<String>,

    /// Write the rendered markdown report to this file in addition to
    /// stdout. Conventional name: `legendary-<host>-<date>.md`.
    #[arg(long, short)]
    pub output: Option<PathBuf>,

    /// HTTP timeout in seconds for each phase.
    #[arg(long, default_value_t = 12)]
    pub timeout_secs: u64,

    /// Skip TLS cert verification (lab targets only).
    #[arg(long)]
    pub insecure: bool,

    /// Skip the bypass-probe phase. Useful when the target's rate
    /// limiter makes a 150-probe sweep noisy.
    #[arg(long)]
    pub skip_bypass_probe: bool,

    /// Skip the scan phase even if `--payload` is given.
    #[arg(long)]
    pub skip_scan: bool,

    /// Hard cap on the variant set fired by the scan phase. Passed
    /// through to `wafrift scan --variants-cap N`; the lower-
    /// confidence tail is dropped first. Also tunes `--level`
    /// (≤15 → light, ≤25 → medium, otherwise heavy) so smaller
    /// values run the lighter build pipeline. Default 30 keeps the
    /// demo command fast; raise for a deeper sweep.
    #[arg(long, default_value_t = 30)]
    pub scan_variants: usize,

    /// Inter-request delay (ms) for both bypass-probe and scan — the
    /// shared politeness knob.
    #[arg(long, default_value_t = 25)]
    pub delay_ms: u64,

    /// Concurrent in-flight probes for the bypass-probe phase.
    #[arg(long, default_value_t = 8)]
    pub concurrency: usize,

    /// Output format: `markdown` (default) renders the full writeup;
    /// `text` collapses to a terminal-friendly summary; `json` emits
    /// the structured report for CI consumers.
    #[arg(long, default_value = "markdown", value_parser = ["markdown", "text", "json"])]
    pub format: String,
}

/// Aggregated per-phase results — the input to the renderer.
#[derive(Debug, Default, serde::Serialize)]
struct LegendaryReport {
    target: String,
    started_at: String,
    /// Total wall-clock elapsed for the whole run, in milliseconds.
    elapsed_ms: u128,
    detect: PhaseDetect,
    fingerprint: PhaseFingerprint,
    bypass_probe: PhaseBypassProbe,
    scan: PhaseScan,
}

#[derive(Debug, Default, serde::Serialize)]
struct PhaseDetect {
    ran: bool,
    error: Option<String>,
    baseline_status: Option<u16>,
    baseline_body_len: Option<usize>,
    detected: Vec<DetectedWaf>,
    /// Differential-probe verdict when the static-signature corpus
    /// came back empty: `Some(reason)` when a benign vs attack
    /// probe diverged enough to infer a WAF, `None` otherwise.
    /// Skipped entirely when the static corpus DID identify a WAF
    /// (no need to double-fire).
    differential: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct DetectedWaf {
    name: String,
    confidence: f64,
    indicators: Vec<String>,
}

#[derive(Debug, Default, serde::Serialize)]
struct PhaseFingerprint {
    ran: bool,
    markers: Vec<(String, String)>,
}

#[derive(Debug, Default, serde::Serialize)]
struct PhaseBypassProbe {
    ran: bool,
    skipped_reason: Option<String>,
    error: Option<String>,
    /// Rendered text output of the underlying `bypass-probe` command
    /// — embedded verbatim into the markdown report so the writeup is
    /// self-contained.
    raw_text: Option<String>,
    /// Structured findings drained from the `bypass-probe --format
    /// json --output <tmp>` capture. Empty when the phase was
    /// skipped, errored, or genuinely found no divergences. Each
    /// entry has the divergence-bearing fields the renderer needs:
    /// family/label/severity/status/curl. Mirrors what the operator
    /// would see in JSON mode of `wafrift bypass-probe`.
    divergences: Vec<DivergenceSummary>,
    /// Per-URL counters carried over from the JSON capture so the
    /// markdown section 3 can show a one-liner like "10/191 probes
    /// flagged" without the operator scrolling.
    total_probes: Option<u64>,
    total_divergences: Option<u64>,
}

/// One bypass-probe finding row. Matches the shape `bypass_probe.rs`
/// emits per-divergence under `--format json`. Narrow on purpose —
/// the demo report keeps the executive view; full details live in
/// the underlying JSON capture.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DivergenceSummary {
    /// Probe family: `headers`, `paths`, `methods`.
    family: String,
    /// Specific probe label within the family.
    label: String,
    /// Probe description (human-readable).
    #[serde(default)]
    description: String,
    /// Baseline HTTP status code.
    baseline_status: u16,
    /// Probe response HTTP status code.
    probe_status: u16,
    /// Body-length delta in percent vs baseline.
    body_delta_pct: f64,
    /// Curl reproducer for this specific probe.
    curl_cmd: String,
    /// Severity guess: `LOW` / `MEDIUM` / `HIGH`.
    severity: String,
}

#[derive(Debug, Default, serde::Serialize)]
struct PhaseScan {
    ran: bool,
    skipped_reason: Option<String>,
    error: Option<String>,
    payload: Option<String>,
    param: Option<String>,
    /// Operator-pasteable re-run command — emitted into the markdown so
    /// the reader can reproduce the inline scan independently. Distinct
    /// from `bypass_variants` below, which carries the actual findings
    /// produced by the inline scan that ran during this `legendary`.
    raw_text: Option<String>,
    /// Structured fields populated by the inline scan subprocess. All
    /// `Option`s because the scan may have errored, been skipped, or
    /// returned partial output; the markdown renderer guards on
    /// presence before emitting the table.
    waf_name: Option<String>,
    /// `total_variants` from the scan JSON — this is `total_fired`
    /// across ALL scan phases (explore + exploit + multi-vector +
    /// header-obf + intel loop), NOT the initial variant pool size.
    /// Misleading-looking but kept to mirror the scan JSON's
    /// historical field name; the renderer labels it correctly
    /// as "Total requests fired" + adds a separate "Explore pool"
    /// row populated from `explore_variants`.
    total_variants: Option<u64>,
    /// `explore_variants` from the scan JSON — the initial variant
    /// pool size, which `--scan-variants` / `--variants-cap` bounds.
    /// This is the number the operator EXPECTS to see when they
    /// pass `--scan-variants 5`.
    explore_variants: Option<u64>,
    bypassed: Option<u64>,
    blocked: Option<u64>,
    errors: Option<u64>,
    bypass_rate_pct: Option<f64>,
    elapsed_ms: Option<f64>,
    /// The bypass-variant findings, deserialised verbatim from the
    /// inline scan's JSON output. Empty when the scan ran but found
    /// no bypasses. The renderer treats empty-vs-absent identically.
    bypass_variants: Vec<BypassVariantSummary>,
}

/// One row of the bypass-variants table embedded in the markdown
/// report. Mirrors the shape emitted by `scan` under `--format json`
/// (see `scan/mod.rs` ~line 1897). Kept narrow on purpose: the demo
/// report is the operator-facing summary, not a full scan record —
/// extra fields belong in the underlying scan JSON.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct BypassVariantSummary {
    variant: u64,
    payload: String,
    techniques: Vec<String>,
    confidence: f64,
    /// Populated only when the inline scan ran with `--auto-distill`
    /// (which legendary does NOT do today, but downstream tooling that
    /// constructs a `LegendaryReport` directly may set).
    #[serde(default)]
    minimal_payload: Option<String>,
    /// Operator-pasteable curl reproducer emitted by scan itself.
    /// When present, the markdown renderer prefers this over a
    /// re-synthesised one — keeps the report consistent with what
    /// the scan JSON exports, and preserves repro accuracy for the
    /// raw-runner shape where the reproducer has full
    /// method/header/body context the renderer can't reconstruct.
    #[serde(default)]
    repro_curl: Option<String>,
    /// Distilled-minimum repro_curl, populated when both
    /// `--auto-distill` ran AND the minimum bypass survived.
    #[serde(default)]
    minimal_repro_curl: Option<String>,
}

/// Entry point.
///
/// # Errors
/// Returns a non-zero `ExitCode` only for terminal failures — bad CLI
/// input or an unwritable `--output` path. Per-phase errors are
/// surfaced in the report itself, not propagated as an exit code,
/// because the demo's value is showing **what wafrift saw**, including
/// "we tried this and the target threw a 503."
pub fn run_legendary(args: LegendaryArgs) -> ExitCode {
    let start = Instant::now();
    let started_at = unix_now_iso8601();
    let mut report = LegendaryReport {
        target: args.target.clone(),
        started_at,
        ..Default::default()
    };

    // Phase 1: detect — baseline GET, fingerprint the WAF.
    eprintln!("{} GET {}", "[1/4] detect:".bright_black(), args.target);
    let (status, headers, body) =
        match fetch_for_detect(&args.target, args.timeout_secs, args.insecure) {
            Ok(v) => v,
            Err(e) => {
                report.detect.error = Some(e.clone());
                eprintln!("       {} {}", "error:".red(), e);
                // Mark downstream phases as not-reached so the renderer
                // surfaces explicit "Not reached — detect phase failed"
                // notes instead of emitting bare section headers with
                // no body. Pre-fix the markdown was a parade of empty
                // section 2/3/4 headers that read like rendering bugs.
                let why = "detect phase failed — phases 2–4 not reached".to_string();
                report.bypass_probe.skipped_reason = Some(why.clone());
                report.scan.skipped_reason = Some(why);
                report.elapsed_ms = start.elapsed().as_millis();
                return emit(report, args).unwrap_or(ExitCode::from(1));
            }
        };
    report.detect.ran = true;
    report.detect.baseline_status = Some(status);
    report.detect.baseline_body_len = Some(body.len());

    let detected = waf_detect::detect(status, &headers, &body);
    for d in &detected {
        report.detect.detected.push(DetectedWaf {
            name: d.name.clone(),
            confidence: d.confidence,
            indicators: d.indicators.clone(),
        });
    }
    if detected.is_empty() {
        eprintln!(
            "       baseline HTTP {status}, {} bytes; no WAF confidently identified",
            body.len()
        );
        // Static-signature corpus came back empty. Auto-run the
        // differential probe — legendary is the one-shot demo
        // command, the operator expects it to do the right thing
        // without flags. The differential probe sends an attack-
        // shaped string (per Authorisation note at the bottom of
        // the report), so it's documented and surfaced loudly.
        match fetch_differential(&args.target, args.timeout_secs, args.insecure) {
            Ok(Some(ev)) => {
                eprintln!(
                    "       {} {}",
                    "differential probe: WAF INFERRED".bright_green(),
                    ev.reasons.join("; ").yellow()
                );
                report.detect.differential = Some(format!(
                    "WAF inferred via differential probe: {}",
                    ev.reasons.join("; ")
                ));
            }
            Ok(None) => {
                eprintln!(
                    "       {} differential probe: no significant divergence",
                    "(also)".bright_black()
                );
            }
            Err(e) => {
                eprintln!("       {} differential probe error: {e}", "warn:".yellow());
            }
        }
    } else {
        let summary: Vec<_> = detected
            .iter()
            .map(|d| format!("{} ({:.0}%)", d.name, d.confidence * 100.0))
            .collect();
        eprintln!(
            "       baseline HTTP {status}, {} bytes; WAF(s): {}",
            body.len(),
            summary.join(", ")
        );
    }

    // Phase 2: fingerprint — surface infra markers (CDN, server, etc.)
    eprintln!(
        "{} reading infra markers",
        "[2/4] fingerprint:".bright_black()
    );
    report.fingerprint.ran = true;
    report.fingerprint.markers = infra_markers(&headers);
    if report.fingerprint.markers.is_empty() {
        eprintln!("       no infrastructure markers visible");
    } else {
        eprintln!(
            "       {} marker(s): {}",
            report.fingerprint.markers.len(),
            report
                .fingerprint
                .markers
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    // Phase 3: bypass-probe.
    if args.skip_bypass_probe {
        report.bypass_probe.skipped_reason = Some("--skip-bypass-probe set".into());
        eprintln!(
            "{} skipped (--skip-bypass-probe set)",
            "[3/4] bypass-probe:".bright_black()
        );
    } else {
        eprintln!(
            "{} 150-probe sweep against {}",
            "[3/4] bypass-probe:".bright_black(),
            args.target
        );
        // Capture the JSON output to a tmpfile so the legendary
        // markdown can embed structured divergences (pre-fix the
        // probe streamed text to the terminal and ONLY the re-run
        // command landed in the markdown — section 3 was unusable
        // as a client deliverable). Same pattern as the scan phase.
        use std::time::{SystemTime, UNIX_EPOCH};
        let bp_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let bp_tmp = std::env::temp_dir().join(format!(
            "wafrift-legendary-bp-{}-{bp_nanos}.json",
            std::process::id()
        ));
        let bp_args = BypassProbeArgs {
            url: args.target.clone(),
            paths_file: args.paths_file.clone(),
            timeout_secs: args.timeout_secs,
            delay_ms: args.delay_ms,
            concurrency: args.concurrency.max(1),
            insecure: args.insecure,
            // JSON + --output for structured capture; bypass-probe
            // still emits per-result text to stderr in this mode so
            // the operator's terminal isn't silent during the sweep.
            format: "json".into(),
            output: Some(bp_tmp.clone()),
            skip_headers: false,
            skip_paths: false,
            skip_methods: false,
            body_diff_threshold_pct: 10.0,
            min_severity: "low".into(),
            // Quiet suppresses the per-probe progress bar — we keep
            // the summary eprintlns that surface "X/N probes diverged"
            // since those are operator-load-bearing.
            quiet: false,
        };
        report.bypass_probe.ran = true;
        report.bypass_probe.raw_text = Some(format!(
            "wafrift bypass-probe {target} \\\n    --format json \\\n    --concurrency 8 \\\n    --delay-ms 25 --output bypass-probe.json",
            target = args.target,
        ));
        match run_bypass_probe(bp_args) {
            Ok(()) => {
                // Drain the captured JSON into structured findings.
                match std::fs::read_to_string(&bp_tmp) {
                    Ok(body) => match serde_json::from_str::<serde_json::Value>(&body) {
                        Ok(v) => apply_bypass_probe_json(&mut report.bypass_probe, &v),
                        Err(e) => {
                            report.bypass_probe.error =
                                Some(format!("parse bypass-probe JSON: {e}"));
                        }
                    },
                    Err(e) => {
                        report.bypass_probe.error = Some(format!(
                            "read bypass-probe JSON from {}: {e}",
                            bp_tmp.display()
                        ));
                    }
                }
            }
            Err(e) => {
                report.bypass_probe.error = Some(e.clone());
                eprintln!("       {} {}", "error:".red(), e);
            }
        }
        let _ = std::fs::remove_file(&bp_tmp);
    }

    // Phase 4: scan (only when --payload was given).
    match (&args.payload, args.skip_scan) {
        (None, _) => {
            report.scan.skipped_reason = Some("no --payload given".into());
            eprintln!(
                "{} skipped (no --payload given)",
                "[4/4] scan:".bright_black()
            );
        }
        (Some(_), true) => {
            report.scan.skipped_reason = Some("--skip-scan set".into());
            eprintln!("{} skipped (--skip-scan set)", "[4/4] scan:".bright_black());
        }
        (Some(payload), false) => {
            report.scan.payload = Some(payload.clone());
            report.scan.param = Some(args.param.clone());
            // Map operator-supplied scan_variants to the closest
            // `--level` setting (light/medium/heavy), AND pass it
            // through as the actual `--variants-cap` so the initial
            // variant pool is bounded. The level mapping still
            // matters because it selects which encoding strategies
            // get tried in the first place; the cap then trims the
            // tail of the resulting pool.
            let level = scan_level_for_variants(args.scan_variants);
            eprintln!(
                "{} firing up to ~{} variants of `{}` at param `{}` (--level {level})",
                "[4/4] scan:".bright_black(),
                args.scan_variants,
                truncate(payload, 40),
                args.param,
            );
            // Inline scan, for-real this time. The previous cut
            // embedded only a copy-paste re-run command and called it
            // a day; the markdown report had zero actual findings,
            // which made the deliverable useless to a client. We now
            // shell out to our own binary (current_exe), drive scan
            // with --format json --output <tmp>, and parse the
            // bypass_variants back into structured fields the
            // markdown renderer emits as a table.
            //
            // Subprocess (rather than calling scan::run_scan
            // directly) for three reasons:
            //   1. scan owns a tokio runtime, gene-bank file locks,
            //      and a learning-cache background task; embedding
            //      it would couple legendary to scan's internal
            //      state machine.
            //   2. The CLI surface IS our contract (LAW 2), so
            //      shelling out can't break out from under us
            //      without breaking every other downstream caller.
            //   3. Process isolation: if scan crashes the legendary
            //      command still produces a partial markdown.
            report.scan.ran = true;
            report.scan.raw_text = Some(format!(
                "wafrift scan --target {target} \\\n    --param {param} \\\n    --payload {payload:?} \\\n    --level {level} \\\n    --delay-ms {delay} \\\n    --format json --output legendary-scan.json",
                target = args.target,
                param = args.param,
                payload = payload,
                level = level,
                delay = args.delay_ms,
            ));
            // Scale the exploit-chain cap to the scan_variants knob
            // so a "fast demo" invocation doesn't quietly fire
            // hundreds of extra exploit-chain requests via scan's
            // default --exploit-cap 500. The 4× multiplier keeps
            // the exploit chain meaningful (deeper than the explore
            // pool) without ballooning wall-clock against permissive
            // targets. Floor of 10 so scan_variants=1 still has a
            // chance to chain a few bypasses.
            let exploit_cap = (args.scan_variants.saturating_mul(4)).max(10);
            match run_inline_scan(InlineScanArgs {
                target: &args.target,
                payload,
                param: &args.param,
                level,
                delay_ms: args.delay_ms,
                timeout_secs: args.timeout_secs,
                insecure: args.insecure,
                variants_cap: args.scan_variants,
                exploit_cap,
            }) {
                Ok(scan_json) => apply_scan_json(&mut report.scan, &scan_json),
                Err(e) => {
                    eprintln!("       {} {}", "error:".red(), e);
                    report.scan.error = Some(e);
                }
            }
        }
    }

    report.elapsed_ms = start.elapsed().as_millis();
    emit(report, args).unwrap_or(ExitCode::from(1))
}

/// Arguments to `run_inline_scan` — kept narrow on purpose. Every
/// field maps 1:1 onto a `wafrift scan` CLI flag so the subprocess
/// invocation is auditable: if the operator can't tell which scan
/// invocation legendary fired, the report stops being reproducible.
struct InlineScanArgs<'a> {
    target: &'a str,
    payload: &'a str,
    param: &'a str,
    level: &'static str,
    delay_ms: u64,
    timeout_secs: u64,
    insecure: bool,
    /// Hard cap on the initial variant set — passed through to
    /// `wafrift scan --variants-cap N`. Mirrors
    /// `LegendaryArgs::scan_variants` so the operator-facing flag
    /// actually bounds the scan now (it was historically advisory).
    variants_cap: usize,
    /// Cap on the exploit-chain phase fires. Scaled to
    /// `scan_variants` (≈4× the initial pool) so a small
    /// `--scan-variants 5` doesn't quietly fire 500 extra exploit-
    /// chain requests via the scan default — which the dogfood pass
    /// caught producing 200+ second runs against permissive targets
    /// despite the small cap.
    exploit_cap: usize,
}

/// Shell out to `wafrift scan` (via `current_exe`) with `--format
/// json --output <tmp>`, then read + parse the JSON back. Returns the
/// raw `serde_json::Value` so `apply_scan_json` can pluck the fields
/// it needs without forcing every caller to re-define the scan output
/// schema. The tmp file is removed on success AND failure paths so
/// repeated legendary runs don't leak files into `$TMPDIR`.
fn run_inline_scan(a: InlineScanArgs<'_>) -> Result<serde_json::Value, String> {
    let exe = std::env::current_exe().map_err(|e| format!("locate own binary: {e}"))?;
    // Unique-per-process tmp path; collisions across concurrent
    // `legendary` runs on the same host would otherwise corrupt the
    // JSON capture. Nanos guard against the edge case of two PID-1
    // hosts (containers) racing.
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let tmp = std::env::temp_dir().join(format!(
        "wafrift-legendary-scan-{}-{nanos}.json",
        std::process::id()
    ));

    let mut cmd = std::process::Command::new(&exe);
    cmd.arg("scan")
        .arg(a.target)
        .arg("--payload")
        .arg(a.payload)
        .arg("--param")
        .arg(a.param)
        .arg("--level")
        .arg(a.level)
        .arg("--delay-ms")
        .arg(a.delay_ms.to_string())
        .arg("--timeout-secs")
        .arg(a.timeout_secs.to_string())
        .arg("--variants-cap")
        .arg(a.variants_cap.to_string())
        .arg("--exploit-cap")
        .arg(a.exploit_cap.to_string())
        .arg("--format")
        .arg("json")
        .arg("--output")
        .arg(&tmp)
        .arg("--quiet");
    if a.insecure {
        cmd.arg("--insecure");
    }

    let status = cmd.status().map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("spawn `wafrift scan`: {e}")
    })?;
    // Exit 5 = aborted because the target rate-limited us. Treat as
    // recoverable: the JSON file IS still written, so we read it and
    // surface a softer note in the markdown via the scan's own
    // `aborted_rate_limited` field. Anything else non-zero is fatal
    // for this phase.
    let exit_code = status.code().unwrap_or(-1);
    if !status.success() && exit_code != 5 {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!(
            "`wafrift scan` exited with status {exit_code} (no JSON captured)"
        ));
    }

    let body = std::fs::read_to_string(&tmp)
        .map_err(|e| format!("read scan JSON from {}: {e}", tmp.display()))?;
    let _ = std::fs::remove_file(&tmp);
    serde_json::from_str(&body).map_err(|e| format!("parse scan JSON: {e}"))
}

/// Drain a scan JSON envelope (the shape emitted by `scan/mod.rs`
/// when `--format json` is set) into the legendary report's
/// `PhaseScan`. Tolerant of missing fields — the operator may run
/// legendary against a future scan binary that adds fields, or a past
/// one that doesn't yet emit them; either way the report renders.
///
/// Handles both shapes scan emits:
///   - bare scan object (default `--format json`)
///   - `{"layer_report": {...}, "scan": {...}}` (with `--report-layers`)
///
/// The unwrap mirrors `report::ingest_scan_json` so a single change
/// to the scan shape doesn't have to be propagated to two readers.
fn apply_scan_json(phase: &mut PhaseScan, root: &serde_json::Value) {
    let v = root.get("scan").filter(|s| s.is_object()).unwrap_or(root);
    phase.waf_name = v.get("waf").and_then(|x| x.as_str()).map(str::to_string);
    phase.total_variants = v.get("total_variants").and_then(|x| x.as_u64());
    phase.explore_variants = v.get("explore_variants").and_then(|x| x.as_u64());
    phase.bypassed = v.get("bypassed").and_then(|x| x.as_u64());
    phase.blocked = v.get("blocked").and_then(|x| x.as_u64());
    phase.errors = v.get("errors").and_then(|x| x.as_u64());
    phase.bypass_rate_pct = v.get("bypass_rate_pct").and_then(|x| x.as_f64());
    phase.elapsed_ms = v.get("elapsed_ms").and_then(|x| x.as_f64());
    if let Some(arr) = v.get("bypass_variants").and_then(|x| x.as_array()) {
        phase.bypass_variants = arr
            .iter()
            .filter_map(|row| serde_json::from_value::<BypassVariantSummary>(row.clone()).ok())
            .collect();
    }
}

/// Drain a bypass-probe JSON envelope (the shape emitted by
/// `bypass_probe.rs` under `--format json`) into the legendary
/// report's `PhaseBypassProbe`. The JSON has shape
/// `{"results": [{"target":..., "divergences":[...], ...}]}` —
/// we flatten across URL results so the renderer sees a single
/// divergence list. Tolerant of missing fields, same as the scan
/// drain.
fn apply_bypass_probe_json(phase: &mut PhaseBypassProbe, root: &serde_json::Value) {
    let mut total_probes: u64 = 0;
    let mut all_divergences: Vec<DivergenceSummary> = Vec::new();
    if let Some(results) = root.get("results").and_then(|x| x.as_array()) {
        for r in results {
            if let Some(p) = r.get("probes_fired").and_then(|x| x.as_u64()) {
                total_probes = total_probes.saturating_add(p);
            }
            if let Some(divs) = r.get("divergences").and_then(|x| x.as_array()) {
                for d in divs {
                    if let Ok(summary) = serde_json::from_value::<DivergenceSummary>(d.clone()) {
                        all_divergences.push(summary);
                    }
                }
            }
        }
    }
    phase.total_probes = (total_probes > 0).then_some(total_probes);
    phase.total_divergences = Some(all_divergences.len() as u64);
    phase.divergences = all_divergences;
}

/// Map operator-supplied `--scan-variants N` onto the closest
/// `--level` setting. Honest about being approximate (scan derives
/// variant count from `--level` × tamper set, with no operator cap).
/// Thresholds chosen to keep the historical default `--scan-variants
/// 30` → `--level heavy` mapping byte-for-byte while making smaller
/// values yield smaller campaigns.
fn scan_level_for_variants(n: usize) -> &'static str {
    if n <= 15 {
        "light"
    } else if n <= 25 {
        "medium"
    } else {
        "heavy"
    }
}

/// Pick a renderer based on `--format` and write to stdout + optional
/// `--output`. Returns the process exit code: 0 on success, 1 if the
/// output file could not be written.
fn emit(report: LegendaryReport, args: LegendaryArgs) -> Result<ExitCode, ExitCode> {
    let rendered = match args.format.as_str() {
        "json" => serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string()),
        "text" => render_text(&report),
        _ => render_markdown(&report),
    };
    println!("{rendered}");
    if let Some(path) = &args.output {
        std::fs::write(path, &rendered).map_err(|e| {
            eprintln!("{} write {}: {e}", "error:".red(), path.display());
            ExitCode::from(1)
        })?;
        eprintln!("{} {}", "wrote".bright_black(), path.display());
    }
    Ok(ExitCode::SUCCESS)
}

/// One-paragraph executive verdict embedded near the top of the
/// legendary markdown. Reads off the per-phase counters and renders
/// a single skimmable sentence per axis (detection / bypass-probe /
/// scan). Pure — no side effects, no I/O — so the renderer stays
/// deterministic across runs and the rendering is easy to unit-test.
fn render_verdict_paragraph(r: &LegendaryReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();

    // Detection axis.
    if let Some(diff) = r.detect.differential.as_ref() {
        let _ = write!(
            out,
            "**WAF detection:** present (differential-probe verdict; vendor not pinned — _{diff}_)\n\n"
        );
    } else if !r.detect.detected.is_empty() {
        let names: Vec<String> = r
            .detect
            .detected
            .iter()
            .map(|d| format!("{} ({:.0}%)", d.name, d.confidence * 100.0))
            .collect();
        let _ = write!(out, "**WAF detection:** {}\n\n", names.join(", "));
    } else if r.detect.error.is_some() {
        let _ = write!(out, "**WAF detection:** _phase errored_\n\n");
    } else if r.detect.ran {
        let _ = write!(
            out,
            "**WAF detection:** no WAF identified (origin appears direct)\n\n"
        );
    }

    // Bypass-probe axis.
    if r.bypass_probe.skipped_reason.is_some() {
        let _ = write!(out, "**Auth / path / method probe:** skipped\n\n");
    } else if r.bypass_probe.error.is_some() {
        let _ = write!(out, "**Auth / path / method probe:** _phase errored_\n\n");
    } else if r.bypass_probe.ran {
        let probes = r.bypass_probe.total_probes.unwrap_or(0);
        let divs = r.bypass_probe.total_divergences.unwrap_or(0);
        if divs == 0 {
            let _ = write!(
                out,
                "**Auth / path / method probe:** {probes} probes fired, no divergences from baseline\n\n"
            );
        } else {
            let highs = r
                .bypass_probe
                .divergences
                .iter()
                .filter(|d| d.severity.eq_ignore_ascii_case("HIGH"))
                .count();
            if highs > 0 {
                let _ = write!(
                    out,
                    "**Auth / path / method probe:** {probes} probes fired, **{divs} divergences** ({highs} HIGH severity — see section 3)\n\n"
                );
            } else {
                let _ = write!(
                    out,
                    "**Auth / path / method probe:** {probes} probes fired, **{divs} divergences** (see section 3)\n\n"
                );
            }
        }
    }

    // Scan axis.
    if r.scan.skipped_reason.is_some() {
        let _ = write!(
            out,
            "**Payload mutation scan:** skipped (pass `--payload` to run)\n\n"
        );
    } else if r.scan.error.is_some() {
        let _ = write!(out, "**Payload mutation scan:** _phase errored_\n\n");
    } else if r.scan.ran {
        let bypassed = r.scan.bypassed.unwrap_or(0);
        let total = r.scan.total_variants.unwrap_or(0);
        if bypassed == 0 {
            let _ = write!(
                out,
                "**Payload mutation scan:** {total} variants fired, **0 bypasses** (WAF held)\n\n"
            );
        } else if let Some(rate) = r.scan.bypass_rate_pct {
            let _ = write!(
                out,
                "**Payload mutation scan:** {total} variants fired, **{bypassed} bypassed** ({rate:.1}%; see section 4)\n\n"
            );
        } else {
            let _ = write!(
                out,
                "**Payload mutation scan:** {total} variants fired, **{bypassed} bypassed** (see section 4)\n\n"
            );
        }
    }

    // Trim trailing whitespace so the caller controls the final
    // newlines exactly (avoids double-blank lines in the markdown).
    out.trim_end().to_string()
}

fn render_markdown(r: &LegendaryReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("# wafrift legendary: {}\n\n", r.target));
    out.push_str(&format!(
        "Generated {} ({} ms wall-clock).\n\n",
        r.started_at, r.elapsed_ms
    ));

    // Executive verdict — one paragraph the reader can skim in 5
    // seconds. Surfaces the only three numbers that matter:
    //   - which WAF (if any)
    //   - how many bypass payloads found (scan phase)
    //   - how many auth/path/method probes diverged (bypass-probe)
    // Everything else is the per-phase deep-dive below.
    out.push_str("## Verdict at a glance\n\n");
    out.push_str(&render_verdict_paragraph(r));
    out.push_str("\n\n");

    // Detect.
    out.push_str("## 1. WAF detection\n\n");
    if let Some(err) = &r.detect.error {
        out.push_str(&format!(
            "Detection phase **errored**: `{err}`. The rest of the\n\
             report is partial — re-run after the target is reachable.\n\n"
        ));
    } else if r.detect.ran {
        out.push_str(&format!(
            "- Baseline: HTTP `{}` ({} bytes)\n",
            r.detect.baseline_status.unwrap_or(0),
            r.detect.baseline_body_len.unwrap_or(0)
        ));
        if r.detect.detected.is_empty() {
            // Two cases:
            //   1. Static rule corpus AND differential probe both
            //      empty → really nothing in front of the origin.
            //   2. Static rule corpus empty BUT differential probe
            //      fired → a WAF IS present, it just strips its
            //      vendor markers. Pre-fix the report opened with
            //      "**none confidently identified**" then immediately
            //      followed with the differential verdict — internally
            //      contradictory ("none" vs "is intercepting"). Lead
            //      with the differential verdict when we have one;
            //      fall back to the "nothing detected" line otherwise.
            if let Some(diff) = r.detect.differential.as_ref() {
                out.push_str(&format!(
                    "- **WAF inferred via differential probe**: {diff}\n"
                ));
                out.push_str("  Static-signature corpus did not match a named vendor — the WAF is intercepting attack-shaped requests via a generic block page that strips its own marker headers. Treat the verdict as 'protected'; the specific vendor is not pinned.\n\n");
            } else {
                out.push_str("- WAF: **none confidently identified** at the baseline. The target may be unprotected, behind a CDN that's not surfacing rule fires on benign GETs, or fingerprinted via response signals our 160+ rule corpus doesn't cover. The bypass-probe phase below still runs.\n\n");
            }
        } else {
            out.push_str("- WAF candidate(s):\n");
            for d in &r.detect.detected {
                out.push_str(&format!(
                    "  - **{}** ({}% confidence) — indicators: {}\n",
                    d.name,
                    (d.confidence * 100.0).round() as u32,
                    d.indicators.join(", ")
                ));
            }
            out.push('\n');
        }
    }

    // Fingerprint.
    out.push_str("## 2. Infrastructure fingerprint\n\n");
    if !r.fingerprint.ran {
        // Phase never ran (typically because detect errored before
        // reaching it). Pre-fix the markdown said "No CDN / server
        // / cache markers surfaced…" which falsely implied a
        // connection was made — confusing on a dead-target report.
        if r.detect.error.is_some() {
            out.push_str("Not reached — detect phase failed.\n\n");
        } else {
            out.push_str("Not reached.\n\n");
        }
    } else if r.fingerprint.markers.is_empty() {
        out.push_str("No CDN / server / cache markers surfaced on the baseline response. The origin may be direct, or the markers may be stripped at the edge.\n\n");
    } else {
        out.push_str("| header | value |\n|---|---|\n");
        for (k, v) in &r.fingerprint.markers {
            out.push_str(&format!("| `{k}` | `{}` |\n", v.replace('|', "\\|")));
        }
        out.push('\n');
    }

    // Bypass-probe.
    out.push_str("## 3. Bypass probe (auth headers + path routing + method overrides)\n\n");
    if let Some(reason) = &r.bypass_probe.skipped_reason {
        out.push_str(&format!("Skipped: _{reason}_.\n\n"));
    } else if let Some(err) = &r.bypass_probe.error {
        out.push_str(&format!("Errored: `{err}`.\n\n"));
        if let Some(cmd) = &r.bypass_probe.raw_text {
            out.push_str(&format!("Reproduce / debug:\n\n```bash\n{cmd}\n```\n\n"));
        }
    } else if r.bypass_probe.ran {
        out.push_str(
            "Fires the full 136-probe auth-bypass set + path-routing-disagreement variants + 7 HTTP method overrides against the target, classifying each response vs the baseline.\n\n",
        );

        // Summary counters.
        let any_counter =
            r.bypass_probe.total_probes.is_some() || r.bypass_probe.total_divergences.is_some();
        if any_counter {
            out.push_str("### Probe summary\n\n");
            out.push_str("| metric | value |\n|---|---|\n");
            if let Some(p) = r.bypass_probe.total_probes {
                out.push_str(&format!("| Probes fired | {p} |\n"));
            }
            if let Some(d) = r.bypass_probe.total_divergences {
                out.push_str(&format!("| Divergences | **{d}** |\n"));
            }
            out.push('\n');
        }

        // Concrete divergences — same render-cap pattern as scan
        // section 4. Operators raising the body-diff threshold (or
        // scanning a permissive target) can see hundreds; render
        // the strongest 25 and footer the rest.
        if r.bypass_probe.divergences.is_empty() {
            out.push_str(
                "No probes diverged from the baseline. The target's \
                 auth/path/method axes appear consistent — re-run with \
                 `--body-diff-threshold-pct 5` for a tighter sweep, or \
                 try the scan phase below to attack the payload axis.\n\n",
            );
        } else {
            const RENDER_CAP: usize = 25;
            let total = r.bypass_probe.divergences.len();
            let shown = total.min(RENDER_CAP);
            out.push_str(&format!(
                "### Probe divergences ({} finding{})\n\n",
                total,
                if total == 1 { "" } else { "s" }
            ));
            if total > RENDER_CAP {
                out.push_str(&format!(
                    "_Showing top {shown} of {total} (ordered by scan output). \
                     Full set available in the JSON capture via the re-run \
                     command at the bottom of this section._\n\n"
                ));
            }
            // Group HIGH severity first, then MEDIUM, then LOW —
            // pentest deliverable readers want the alarming findings
            // up top.
            let mut ranked: Vec<&DivergenceSummary> = r.bypass_probe.divergences.iter().collect();
            ranked.sort_by_key(|d| match d.severity.to_uppercase().as_str() {
                "HIGH" => 0,
                "MEDIUM" => 1,
                _ => 2,
            });
            for d in ranked.iter().take(RENDER_CAP) {
                out.push_str(&format!(
                    "#### `{}/{}` · severity {}\n\n",
                    d.family, d.label, d.severity
                ));
                if !d.description.is_empty() {
                    out.push_str(&format!("{}\n\n", d.description));
                }
                out.push_str(&format!(
                    "- Baseline HTTP {} → probe HTTP {} (body Δ {:.1}%)\n",
                    d.baseline_status, d.probe_status, d.body_delta_pct
                ));
                out.push_str(&format!(
                    "- **Reproduce:**\n\n```bash\n{}\n```\n\n",
                    d.curl_cmd
                ));
            }
        }

        // Footer with re-run command so operators can capture the
        // full JSON for their pentest report.
        if let Some(cmd) = &r.bypass_probe.raw_text {
            out.push_str("### Reproduce the inline sweep\n\n");
            out.push_str(&format!("```bash\n{cmd}\n```\n\n"));
        }
    }

    // Scan.
    out.push_str("## 4. Live scan (payload mutation)\n\n");
    if let Some(reason) = &r.scan.skipped_reason {
        out.push_str(&format!("Skipped: _{reason}_.\n\n"));
    } else if let Some(err) = &r.scan.error {
        out.push_str(&format!(
            "The inline scan errored: `{err}`. Re-run the scan command below \
             to surface the underlying failure.\n\n"
        ));
        if let Some(cmd) = &r.scan.raw_text {
            out.push_str(&format!("```bash\n{cmd}\n```\n\n"));
        }
    } else if r.scan.ran {
        out.push_str(
            "Mutation variants of the payload are fired at the target, classified by the multi-signal oracle (block / bypass / challenge / rate-limit), with server `Retry-After` honoured via jittered backoff.\n\n",
        );

        // Headline counters — emit the table only when AT LEAST
        // one counter is present. A scan binary that drained empty
        // (e.g. partial-output mid-crash) shouldn't render a
        // header-only table that reads as a bug; instead, the
        // section flows straight into the per-variant findings (or
        // the no-bypasses note).
        let any_counter = r.scan.waf_name.is_some()
            || r.scan.total_variants.is_some()
            || r.scan.explore_variants.is_some()
            || r.scan.bypassed.is_some()
            || r.scan.blocked.is_some()
            || r.scan.errors.is_some()
            || r.scan.bypass_rate_pct.is_some()
            || r.scan.elapsed_ms.is_some();
        if any_counter {
            out.push_str("### Scan summary\n\n");
            out.push_str("| metric | value |\n|---|---|\n");
            if let Some(w) = &r.scan.waf_name {
                out.push_str(&format!("| WAF (chosen) | `{w}` |\n"));
            }
            // The explore pool is the number the operator set via
            // `--scan-variants` (mapped to `--variants-cap`); call
            // it out FIRST so the reader sees the cap honoured. The
            // separate "Total requests fired" row below covers the
            // (much larger) sum across all scan phases — pre-fix
            // these two were collapsed into one mislabelled row
            // saying "Variants fired" but showing the post-phase
            // total, contradicting `--scan-variants N`.
            if let Some(e) = r.scan.explore_variants {
                out.push_str(&format!(
                    "| Explore pool (variants tried initially) | {e} |\n"
                ));
            }
            if let Some(t) = r.scan.total_variants {
                out.push_str(&format!(
                    "| Total requests fired (across all phases) | {t} |\n"
                ));
            }
            if let Some(b) = r.scan.bypassed {
                out.push_str(&format!("| Bypassed | **{b}** |\n"));
            }
            if let Some(b) = r.scan.blocked {
                out.push_str(&format!("| Blocked | {b} |\n"));
            }
            if let Some(e) = r.scan.errors {
                out.push_str(&format!("| Errors | {e} |\n"));
            }
            if let Some(rate) = r.scan.bypass_rate_pct {
                out.push_str(&format!("| Bypass rate | {rate:.1}% |\n"));
            }
            if let Some(ms) = r.scan.elapsed_ms {
                out.push_str(&format!("| Wall-clock | {:.1}s |\n", ms / 1000.0));
            }
            out.push('\n');
        }

        // Per-variant payload table — the actual deliverable. When
        // there are no bypasses, name that too (the absence of a
        // table would otherwise read as "scan never ran").
        if r.scan.bypass_variants.is_empty() {
            out.push_str(
                "No variants bypassed the WAF in this run. The target held against \
                 every encoding × tamper × grammar mutation in the `--level` \
                 envelope. Two follow-ups worth considering before declaring victory:\n\n\
                 - Raise `--scan-variants` (currently maps to a `--level` setting; \
                   try a wider sweep).\n\
                 - Run `wafrift bypass-probe` (Section 3 above) to attack the \
                   auth/path/method axis, which is orthogonal to payload mutation.\n\n",
            );
        } else {
            // Render cap: at -scan-variants 30 the bypass set is
            // bounded to ~30, but operators raising the cap (or
            // running against a permissive target) can wind up with
            // hundreds of "successful" bypasses — rendering all of
            // them turns the report into a 10000-line wall that
            // nobody reads. Cap the rendered table at 25 and add a
            // footer pointing at the JSON output for the full list.
            const RENDER_CAP: usize = 25;
            let total = r.scan.bypass_variants.len();
            let shown = total.min(RENDER_CAP);
            out.push_str(&format!(
                "### Successful bypasses ({} variant{})\n\n",
                total,
                if total == 1 { "" } else { "s" }
            ));
            if total > RENDER_CAP {
                out.push_str(&format!(
                    "_Showing top {shown} of {total} (ordered by scan output). \
                     Full set available in the JSON output via the re-run \
                     command at the bottom of this section._\n\n"
                ));
            }
            for v in r.scan.bypass_variants.iter().take(RENDER_CAP) {
                out.push_str(&format!(
                    "#### Variant #{} · confidence {:.2}\n\n",
                    v.variant, v.confidence
                ));
                out.push_str(&format!(
                    "- **Techniques:** {}\n",
                    if v.techniques.is_empty() {
                        "_(none recorded)_".to_string()
                    } else {
                        v.techniques
                            .iter()
                            .map(|t| format!("`{t}`"))
                            .collect::<Vec<_>>()
                            .join(" → ")
                    }
                ));
                out.push_str(&format!(
                    "- **Payload** ({} bytes):\n\n```\n{}\n```\n",
                    v.payload.len(),
                    fence_escape(&v.payload)
                ));
                if let Some(min) = &v.minimal_payload {
                    out.push_str(&format!(
                        "- **Minimal payload** ({} bytes, via auto-distill):\n\n```\n{}\n```\n",
                        min.len(),
                        fence_escape(min)
                    ));
                }
                // Prefer the scan-supplied repro_curl when present
                // (it's wire-accurate for the raw-runner shape that
                // legendary can't reconstruct from target+param);
                // fall back to URL-query synthesis otherwise. Both
                // paths route through `shell_single_quote` so the
                // escape is consistent.
                let repro = v.repro_curl.clone().unwrap_or_else(|| {
                    let param = r.scan.param.as_deref().unwrap_or("q");
                    format!(
                        "curl -G --data-urlencode {param}={shell} {target}",
                        shell = shell_single_quote(&v.payload),
                        target = shell_single_quote(&r.target),
                    )
                });
                out.push_str(&format!("- **Reproduce:**\n\n```bash\n{repro}\n```\n\n"));
                if let Some(min_repro) = &v.minimal_repro_curl {
                    out.push_str(&format!(
                        "- **Reproduce (minimum):**\n\n```bash\n{min_repro}\n```\n\n"
                    ));
                }
            }
        }

        // Always footer the section with the re-run command so the
        // operator can reproduce the inline scan independently.
        if let Some(cmd) = &r.scan.raw_text {
            out.push_str("### Reproduce the inline scan\n\n");
            out.push_str(&format!("```bash\n{cmd}\n```\n\n"));
        }
    }

    // Footer.
    out.push_str("## Reproduce this whole report\n\n");
    out.push_str("```bash\n");
    out.push_str(&format!(
        "wafrift legendary {target}{payload}{paths_file} --output legendary-report.md\n",
        target = r.target,
        payload = r
            .scan
            .payload
            .as_ref()
            .map(|p| format!(
                " --payload {:?} --param {}",
                p,
                r.scan.param.as_deref().unwrap_or("q")
            ))
            .unwrap_or_default(),
        paths_file = "", // paths_file isn't echoed; user has the file
    ));
    out.push_str("```\n\n");
    out.push_str(
        "**Authorisation** — wafrift only runs against systems you own \
         or have written authorisation to test. The bypass-probe and \
         scan phases above send genuinely exploitable strings; verify \
         scope before each engagement.\n",
    );
    out
}

fn render_text(r: &LegendaryReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("=== wafrift legendary: {} ===\n", r.target));
    out.push_str(&format!(
        "elapsed: {} ms · started: {}\n\n",
        r.elapsed_ms, r.started_at
    ));
    if let Some(s) = r.detect.baseline_status {
        out.push_str(&format!(
            "[1/4] detect: HTTP {s} ({} bytes); {} WAF candidate(s)\n",
            r.detect.baseline_body_len.unwrap_or(0),
            r.detect.detected.len()
        ));
        for d in &r.detect.detected {
            out.push_str(&format!(
                "      - {} ({}%)\n",
                d.name,
                (d.confidence * 100.0).round() as u32
            ));
        }
    } else if let Some(e) = &r.detect.error {
        out.push_str(&format!("[1/4] detect: ERROR {e}\n"));
    }
    out.push_str(&format!(
        "[2/4] fingerprint: {} infra marker(s)\n",
        r.fingerprint.markers.len()
    ));
    match (&r.bypass_probe.skipped_reason, &r.bypass_probe.error) {
        (Some(why), _) => out.push_str(&format!("[3/4] bypass-probe: skipped ({why})\n")),
        (_, Some(e)) => out.push_str(&format!("[3/4] bypass-probe: ERROR {e}\n")),
        _ => out.push_str("[3/4] bypass-probe: see stream above\n"),
    }
    match (&r.scan.skipped_reason, &r.scan.error, &r.scan.raw_text) {
        (Some(why), _, _) => out.push_str(&format!("[4/4] scan: skipped ({why})\n")),
        (_, Some(e), _) => out.push_str(&format!("[4/4] scan: ERROR {e}\n")),
        (_, _, Some(_)) => out.push_str("[4/4] scan: invocation embedded in markdown report\n"),
        _ => {}
    }
    out
}

/// A bypass payload that contains literal triple-backticks would
/// break the markdown code fence around it. The standard escape is
/// to wrap the fence in MORE backticks than the payload contains —
/// computing the right delimiter is fiddly, so we take the simpler
/// path of inserting a zero-width space into the literal sequence
/// (the rendered text reads identically, but the fence parser no
/// longer terminates early). Idempotent: payloads without ``` are
/// returned unchanged.
fn fence_escape(s: &str) -> String {
    if s.contains("```") {
        s.replace("```", "`\u{200B}`\u{200B}`")
    } else {
        s.to_string()
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let take: String = s.chars().take(n).collect();
        format!("{take}…")
    }
}

fn unix_now_iso8601() -> String {
    // Avoids pulling chrono just to format one timestamp. ISO-8601
    // basic form: YYYY-MM-DDTHH:MM:SSZ. Computed from SystemTime so it
    // works on hosts where the wall clock has been set sanely.
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Civil-date conversion (Howard Hinnant's algorithm, public domain).
    let (year, month, day) = civil_from_days(days as i64);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    (year as i32, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso8601_round_trips_known_epoch() {
        // 2024-01-01T00:00:00Z = 1704067200 seconds since 1970-01-01.
        // Verify our civil-from-days computes the right calendar date.
        let (y, m, d) = civil_from_days(1704067200 / 86400);
        assert_eq!((y, m, d), (2024, 1, 1));
    }

    #[test]
    fn iso8601_round_trips_leap_year_feb_29() {
        // 2024-02-29 = day 1709164800 / 86400 = 19782.
        let (y, m, d) = civil_from_days(19782);
        assert_eq!((y, m, d), (2024, 2, 29));
    }

    #[test]
    fn truncate_ascii_short() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn truncate_ascii_long() {
        assert_eq!(truncate("hello world", 5), "hello…");
    }

    #[test]
    fn truncate_unicode_grapheme_safe_at_char_boundary() {
        // chars().take() is char-boundary safe; truncate must not panic
        // on multi-byte input.
        let s = "αβγδεζηθικλμ";
        let t = truncate(s, 3);
        assert_eq!(t, "αβγ…");
    }

    #[test]
    fn render_markdown_contains_all_section_headers() {
        let r = LegendaryReport {
            target: "https://example.com".into(),
            started_at: "2026-05-20T00:00:00Z".into(),
            elapsed_ms: 42,
            ..Default::default()
        };
        let md = render_markdown(&r);
        assert!(md.contains("# wafrift legendary: https://example.com"));
        assert!(md.contains("## 1. WAF detection"));
        assert!(md.contains("## 2. Infrastructure fingerprint"));
        assert!(md.contains("## 3. Bypass probe"));
        assert!(md.contains("## 4. Live scan"));
        assert!(md.contains("## Reproduce this whole report"));
    }

    #[test]
    fn render_text_compact_summary() {
        let mut r = LegendaryReport {
            target: "https://example.com".into(),
            started_at: "2026-05-20T00:00:00Z".into(),
            elapsed_ms: 100,
            ..Default::default()
        };
        r.detect.baseline_status = Some(403);
        r.detect.baseline_body_len = Some(512);
        r.detect.detected.push(DetectedWaf {
            name: "Cloudflare".into(),
            confidence: 0.92,
            indicators: vec!["cf-ray header".into()],
        });
        let txt = render_text(&r);
        assert!(txt.contains("=== wafrift legendary: https://example.com ==="));
        assert!(txt.contains("HTTP 403"));
        assert!(txt.contains("Cloudflare (92%)"));
    }

    #[test]
    fn render_markdown_marks_scan_skipped_when_no_payload() {
        let mut r = LegendaryReport {
            target: "https://example.com".into(),
            ..Default::default()
        };
        r.scan.skipped_reason = Some("no --payload given".into());
        let md = render_markdown(&r);
        assert!(
            md.contains("Skipped: _no --payload given_"),
            "scan-skipped reason should be present in markdown:\n{md}"
        );
    }

    // ── Deep render + I/O edge cases (added 2026-05-20).

    #[test]
    fn render_markdown_with_all_phases_errored_is_still_well_formed() {
        // Failure-mode soak: every phase errored. Markdown must
        // still contain all four sections — we never want a half-
        // rendered report just because one phase failed.
        let mut r = LegendaryReport {
            target: "https://example.com".into(),
            ..Default::default()
        };
        r.detect.error = Some("connection refused".into());
        r.fingerprint.ran = true; // even when detect errors, fingerprint can read headers it had
        r.bypass_probe.error = Some("rate-limited too hard".into());
        r.scan.error = Some("scan oracle blew up".into());
        let md = render_markdown(&r);
        for section in [
            "## 1. WAF detection",
            "## 2. Infrastructure fingerprint",
            "## 3. Bypass probe",
            "## 4. Live scan",
        ] {
            assert!(md.contains(section), "missing {section} in:\n{md}");
        }
        // The detect-error path must call out the error directly.
        assert!(md.contains("connection refused"));
    }

    #[test]
    fn render_json_round_trips_via_serde() {
        // serde-derived: any LegendaryReport must round-trip
        // through serde_json without information loss. A regression
        // that adds a non-Serialize field breaks this.
        let mut r = LegendaryReport {
            target: "https://x.com".into(),
            started_at: "2026-05-20T00:00:00Z".into(),
            elapsed_ms: 7,
            ..Default::default()
        };
        r.detect.baseline_status = Some(403);
        r.detect.baseline_body_len = Some(512);
        r.detect.detected.push(DetectedWaf {
            name: "Cloudflare".into(),
            confidence: 0.92,
            indicators: vec!["cf-ray".into()],
        });
        r.fingerprint
            .markers
            .push(("server".into(), "cloudflare".into()));
        r.scan.skipped_reason = Some("no --payload given".into());
        let json = serde_json::to_string(&r).expect("serialise");
        // Parse it back as a Value (struct can't be deserialised
        // because the impl is one-way). Sanity that key paths exist.
        let v: serde_json::Value = serde_json::from_str(&json).expect("re-parse");
        assert_eq!(v["target"], "https://x.com");
        assert_eq!(v["detect"]["baseline_status"], 403);
        assert_eq!(v["detect"]["detected"][0]["name"], "Cloudflare");
        assert_eq!(v["fingerprint"]["markers"][0][0], "server");
        assert_eq!(v["scan"]["skipped_reason"], "no --payload given");
    }

    #[test]
    fn render_markdown_pipe_character_in_marker_does_not_break_table() {
        // The fingerprint table uses pipe-separated columns. A header
        // value containing `|` would break the table rendering — the
        // renderer must escape pipes in marker values.
        let mut r = LegendaryReport {
            target: "https://x".into(),
            ..Default::default()
        };
        // Mark fingerprint as ran — post-dogfood-fix the renderer
        // guards on `ran` to avoid emitting "No CDN markers…" on a
        // dead target where the fingerprint phase never executed.
        r.fingerprint.ran = true;
        r.fingerprint
            .markers
            .push(("x-via".into(), "edge|cache|hit".into()));
        let md = render_markdown(&r);
        // Pipe characters in values must be escaped or otherwise
        // not produce additional table columns. The implementation
        // uses `v.replace('|', "\\|")` — verify the literal
        // appears in the output.
        assert!(
            md.contains(r"edge\|cache\|hit"),
            "pipe-bearing marker value must be escaped in markdown table:\n{md}"
        );
    }

    #[test]
    fn truncate_zero_length_input_is_empty_no_panic() {
        assert_eq!(truncate("", 10), "");
        assert_eq!(truncate("", 0), "");
    }

    #[test]
    fn truncate_at_exact_length_does_not_add_ellipsis() {
        assert_eq!(truncate("hello", 5), "hello");
    }

    #[test]
    fn iso8601_spans_year_boundary() {
        // 2025-12-31 23:59:59 UTC = 1767225599 seconds.
        let (y, m, d) = civil_from_days(1767225599 / 86400);
        assert_eq!((y, m, d), (2025, 12, 31));
        // 2026-01-01 00:00:00 UTC = 1767225600 seconds.
        let (y2, m2, d2) = civil_from_days(1767225600 / 86400);
        assert_eq!((y2, m2, d2), (2026, 1, 1));
    }

    #[test]
    fn iso8601_spans_century_boundary() {
        // 2099-12-31 → 2100-01-01 (centennial non-leap year).
        // 2100-01-01 00:00:00 UTC = 4102444800 seconds.
        let (y, m, d) = civil_from_days(4102444800 / 86400);
        assert_eq!((y, m, d), (2100, 1, 1));
        // 2100 is NOT a leap year (divisible by 100 but not 400).
        // So 2100-03-01 is day 4112380800 / 86400. Let's verify
        // 2100-02-28 is the last day of February.
        let feb28 = 4102444800 + 86400 * (31 + 27); // jan31 + feb1..28 days
        let (y, m, d) = civil_from_days(feb28 / 86400);
        assert_eq!((y, m, d), (2100, 2, 28));
        let mar1 = feb28 + 86400;
        let (y, m, d) = civil_from_days(mar1 / 86400);
        assert_eq!(
            (y, m, d),
            (2100, 3, 1),
            "2100 must NOT have a Feb 29 (not a leap year)"
        );
    }

    #[test]
    fn scan_level_for_variants_thresholds_match_help_text() {
        // The LegendaryArgs help text promises a specific mapping.
        // Pinning the boundaries so future tweaks don't silently
        // change operator-visible behaviour.
        assert_eq!(scan_level_for_variants(0), "light");
        assert_eq!(scan_level_for_variants(1), "light");
        assert_eq!(scan_level_for_variants(15), "light");
        assert_eq!(scan_level_for_variants(16), "medium");
        assert_eq!(scan_level_for_variants(25), "medium");
        assert_eq!(scan_level_for_variants(26), "heavy");
        assert_eq!(scan_level_for_variants(30), "heavy"); // historical default
        assert_eq!(scan_level_for_variants(1000), "heavy");
    }

    #[test]
    fn fence_escape_inserts_zwsp_around_inner_backticks() {
        let s = "before```after";
        let out = fence_escape(s);
        assert!(!out.contains("```"), "rendered: {out:?}");
        assert!(out.contains("before"));
        assert!(out.contains("after"));
    }

    #[test]
    fn fence_escape_leaves_safe_payload_unchanged() {
        let s = "SELECT 1 -- safe";
        assert_eq!(fence_escape(s), s);
    }

    #[test]
    fn apply_scan_json_populates_phase_fields_and_variants() {
        // Verifies that the JSON-shape contract between scan and
        // legendary doesn't drift: every documented field flows
        // through into PhaseScan, and bypass_variants deserialise
        // into the BypassVariantSummary rows the renderer expects.
        let json = serde_json::json!({
            "scan_schema_version": 1,
            "target": "https://example.com",
            "waf": "Cloudflare",
            "payload_type": "Sql",
            "total_variants": 47,
            "bypassed": 3,
            "blocked": 42,
            "errors": 2,
            "bypass_rate_pct": 6.4,
            "elapsed_ms": 18234.0,
            "bypass_variants": [
                {"variant": 1, "payload": "' OR 1=1--", "techniques": ["url"], "confidence": 0.91, "minimal_payload": null},
                {"variant": 17, "payload": "/**/UNION/**/SELECT", "techniques": ["sql_comment", "case_swap"], "confidence": 0.83, "minimal_payload": "UNION SELECT"},
            ],
        });
        let mut phase = PhaseScan::default();
        apply_scan_json(&mut phase, &json);
        assert_eq!(phase.waf_name.as_deref(), Some("Cloudflare"));
        assert_eq!(phase.total_variants, Some(47));
        assert_eq!(phase.bypassed, Some(3));
        assert_eq!(phase.blocked, Some(42));
        assert_eq!(phase.errors, Some(2));
        assert!((phase.bypass_rate_pct.unwrap() - 6.4).abs() < 1e-6);
        assert!((phase.elapsed_ms.unwrap() - 18234.0).abs() < 1e-6);
        assert_eq!(phase.bypass_variants.len(), 2);
        assert_eq!(phase.bypass_variants[0].variant, 1);
        assert_eq!(phase.bypass_variants[0].payload, "' OR 1=1--");
        assert!(phase.bypass_variants[0].minimal_payload.is_none());
        assert_eq!(phase.bypass_variants[1].variant, 17);
        assert_eq!(
            phase.bypass_variants[1].minimal_payload.as_deref(),
            Some("UNION SELECT")
        );
    }

    #[test]
    fn apply_scan_json_tolerates_missing_fields() {
        // A scan binary that omits some fields (e.g. an older
        // release, or a forward-compat newer one) must not panic.
        let json = serde_json::json!({"target": "x"});
        let mut phase = PhaseScan::default();
        apply_scan_json(&mut phase, &json);
        assert!(phase.waf_name.is_none());
        assert!(phase.total_variants.is_none());
        assert!(phase.bypass_variants.is_empty());
    }

    #[test]
    fn apply_scan_json_unwraps_layer_report_envelope() {
        // When the operator runs `wafrift scan --report-layers
        // --format json`, the JSON nests the scan body under a
        // top-level "scan" key. Before this fix, `apply_scan_json`
        // read fields directly off the root and silently produced
        // an all-None PhaseScan. The unwrap matches what
        // `report::ingest_scan_json` does — same primitive on both
        // readers means one fix point if the shape evolves.
        let layered = serde_json::json!({
            "layer_report": {
                "network": {"target": "https://x", "baseline_get_status": 200},
            },
            "scan": {
                "target": "https://x",
                "waf": "Cloudflare",
                "total_variants": 12,
                "bypassed": 2,
                "blocked": 10,
                "bypass_rate_pct": 16.7,
                "bypass_variants": [
                    {"variant": 1, "payload": "p", "techniques": [], "confidence": 0.9}
                ],
            },
        });
        let mut phase = PhaseScan::default();
        apply_scan_json(&mut phase, &layered);
        assert_eq!(phase.waf_name.as_deref(), Some("Cloudflare"));
        assert_eq!(phase.total_variants, Some(12));
        assert_eq!(phase.bypassed, Some(2));
        assert_eq!(phase.bypass_variants.len(), 1);
        assert_eq!(phase.bypass_variants[0].payload, "p");
    }

    #[test]
    fn apply_scan_json_preserves_repro_curl_and_minimal_repro_curl() {
        // The scan JSON now emits per-variant repro_curl; legendary
        // must round-trip both fields so the markdown renderer can
        // prefer the scan-supplied reproducer (raw-runner-accurate)
        // over a re-synthesised one.
        let json = serde_json::json!({
            "bypass_variants": [
                {
                    "variant": 1,
                    "payload": "p1",
                    "techniques": [],
                    "confidence": 0.9,
                    "repro_curl": "curl --header 'X: 1' https://x/",
                    "minimal_repro_curl": "curl -H X:1 https://x/m"
                }
            ]
        });
        let mut phase = PhaseScan::default();
        apply_scan_json(&mut phase, &json);
        assert_eq!(phase.bypass_variants.len(), 1);
        assert_eq!(
            phase.bypass_variants[0].repro_curl.as_deref(),
            Some("curl --header 'X: 1' https://x/")
        );
        assert_eq!(
            phase.bypass_variants[0].minimal_repro_curl.as_deref(),
            Some("curl -H X:1 https://x/m")
        );
    }

    #[test]
    fn render_markdown_prefers_scan_supplied_repro_curl_when_present() {
        let mut r = LegendaryReport {
            target: "https://example.com".into(),
            ..Default::default()
        };
        r.scan.ran = true;
        r.scan.bypass_variants = vec![BypassVariantSummary {
            variant: 1,
            payload: "evil".into(),
            techniques: vec![],
            confidence: 0.5,
            minimal_payload: None,
            repro_curl: Some("curl --data-binary '@payload.bin' https://x/api".into()),
            minimal_repro_curl: None,
        }];
        let md = render_markdown(&r);
        // The exact scan-supplied repro must surface verbatim.
        assert!(
            md.contains("curl --data-binary '@payload.bin' https://x/api"),
            "scan-supplied repro_curl missing or rewritten:\n{md}"
        );
        // The renderer must NOT also emit a synthesised
        // curl -G --data-urlencode line for this variant — would be
        // duplicated noise.
        let repro_section_start = md.find("**Reproduce:**").expect("repro header missing");
        let after = &md[repro_section_start..];
        let next_section = after.find("###").unwrap_or(after.len());
        let repro_block = &after[..next_section];
        assert!(
            !repro_block.contains("curl -G --data-urlencode"),
            "render must NOT also emit synthesised reproducer when scan provided one:\n{repro_block}"
        );
    }

    #[test]
    fn render_markdown_falls_back_to_synthesized_repro_when_scan_omitted_it() {
        let mut r = LegendaryReport {
            target: "https://example.com".into(),
            ..Default::default()
        };
        r.scan.ran = true;
        r.scan.param = Some("q".into());
        r.scan.bypass_variants = vec![BypassVariantSummary {
            variant: 1,
            payload: "evil".into(),
            techniques: vec![],
            confidence: 0.5,
            minimal_payload: None,
            repro_curl: None,
            minimal_repro_curl: None,
        }];
        let md = render_markdown(&r);
        assert!(
            md.contains("curl -G --data-urlencode q='evil' 'https://example.com'"),
            "fallback synthesised reproducer missing:\n{md}"
        );
    }

    #[test]
    fn render_markdown_caps_table_at_25_variants_with_footer() {
        // Permissive targets (or operators passing a huge cap) can
        // surface hundreds of bypasses. The markdown must render
        // only the top 25 + note the overflow.
        let mut r = LegendaryReport {
            target: "https://x".into(),
            ..Default::default()
        };
        r.scan.ran = true;
        r.scan.bypass_variants = (0..50)
            .map(|i| BypassVariantSummary {
                variant: i,
                payload: format!("v{i}"),
                techniques: vec![],
                confidence: 0.5,
                minimal_payload: None,
                repro_curl: None,
                minimal_repro_curl: None,
            })
            .collect();
        let md = render_markdown(&r);
        // First 25 must render.
        for i in 0..25 {
            assert!(
                md.contains(&format!("Variant #{i} ")),
                "variant {i} not rendered (should be in top 25)"
            );
        }
        // The 26th-and-beyond must NOT render.
        for i in 25..50 {
            assert!(
                !md.contains(&format!("Variant #{i} ")),
                "variant {i} rendered past the 25-cap"
            );
        }
        // The overflow footer must call out the truncation.
        assert!(
            md.contains("Showing top 25 of 50"),
            "render-cap footer missing or wrong count:\n{md}"
        );
    }

    #[test]
    fn render_markdown_omits_summary_table_when_no_counters_present() {
        // Partial scan output (binary mid-crash, future fields-only
        // emit) must not produce a header-only table.
        let mut r = LegendaryReport {
            target: "https://x".into(),
            ..Default::default()
        };
        r.scan.ran = true;
        r.scan.payload = Some("p".into());
        // No counters set, no bypasses.
        let md = render_markdown(&r);
        assert!(
            !md.contains("### Scan summary"),
            "must not emit header-only summary table:\n{md}"
        );
        assert!(
            md.contains("No variants bypassed"),
            "must still emit zero-bypasses note:\n{md}"
        );
    }

    // ── verdict paragraph ─────────────────────────────────────

    #[test]
    fn verdict_lists_detected_waf_with_confidence() {
        let mut r = LegendaryReport {
            target: "https://x".into(),
            ..Default::default()
        };
        r.detect.ran = true;
        r.detect.detected.push(DetectedWaf {
            name: "Cloudflare".into(),
            confidence: 0.92,
            indicators: vec![],
        });
        let v = render_verdict_paragraph(&r);
        assert!(
            v.contains("Cloudflare (92%)"),
            "verdict missing detected WAF:\n{v}"
        );
    }

    #[test]
    fn verdict_uses_differential_verdict_when_static_corpus_was_empty() {
        let mut r = LegendaryReport {
            target: "https://x".into(),
            ..Default::default()
        };
        r.detect.ran = true;
        r.detect.differential = Some("status flipped 200 → 403; server header changed".into());
        let v = render_verdict_paragraph(&r);
        assert!(
            v.contains("present (differential-probe verdict"),
            "verdict missing differential branch:\n{v}"
        );
        assert!(v.contains("status flipped"));
    }

    #[test]
    fn verdict_surfaces_high_severity_count_for_bypass_probe() {
        let mut r = LegendaryReport {
            target: "https://x".into(),
            ..Default::default()
        };
        r.bypass_probe.ran = true;
        r.bypass_probe.total_probes = Some(191);
        r.bypass_probe.total_divergences = Some(3);
        r.bypass_probe.divergences = vec![
            DivergenceSummary {
                family: "headers".into(),
                label: "x".into(),
                description: String::new(),
                baseline_status: 403,
                probe_status: 200,
                body_delta_pct: 90.0,
                curl_cmd: "c".into(),
                severity: "HIGH".into(),
            },
            DivergenceSummary {
                family: "f".into(),
                label: "y".into(),
                description: String::new(),
                baseline_status: 403,
                probe_status: 302,
                body_delta_pct: 30.0,
                curl_cmd: "c".into(),
                severity: "MEDIUM".into(),
            },
            DivergenceSummary {
                family: "f".into(),
                label: "z".into(),
                description: String::new(),
                baseline_status: 403,
                probe_status: 401,
                body_delta_pct: 5.0,
                curl_cmd: "c".into(),
                severity: "LOW".into(),
            },
        ];
        let v = render_verdict_paragraph(&r);
        assert!(
            v.contains("191 probes fired"),
            "verdict missing probes_fired count:\n{v}"
        );
        assert!(
            v.contains("3 divergences"),
            "verdict missing divergence count:\n{v}"
        );
        assert!(
            v.contains("1 HIGH severity"),
            "verdict missing HIGH-severity callout:\n{v}"
        );
    }

    #[test]
    fn verdict_calls_out_zero_bypass_when_scan_held() {
        let mut r = LegendaryReport {
            target: "https://x".into(),
            ..Default::default()
        };
        r.scan.ran = true;
        r.scan.total_variants = Some(30);
        r.scan.bypassed = Some(0);
        let v = render_verdict_paragraph(&r);
        assert!(
            v.contains("30 variants fired, **0 bypasses**"),
            "verdict missing 'WAF held' framing:\n{v}"
        );
    }

    #[test]
    fn verdict_surfaces_bypass_rate_when_scan_succeeded() {
        let mut r = LegendaryReport {
            target: "https://x".into(),
            ..Default::default()
        };
        r.scan.ran = true;
        r.scan.total_variants = Some(50);
        r.scan.bypassed = Some(3);
        r.scan.bypass_rate_pct = Some(6.0);
        let v = render_verdict_paragraph(&r);
        assert!(
            v.contains("3 bypassed**"),
            "verdict missing bypassed count:\n{v}"
        );
        assert!(v.contains("(6.0%"), "verdict missing bypass rate:\n{v}");
    }

    #[test]
    fn verdict_renders_skipped_phases_explicitly() {
        let mut r = LegendaryReport {
            target: "https://x".into(),
            ..Default::default()
        };
        r.bypass_probe.skipped_reason = Some("--skip-bypass-probe set".into());
        r.scan.skipped_reason = Some("no --payload given".into());
        let v = render_verdict_paragraph(&r);
        assert!(
            v.contains("Auth / path / method probe:** skipped"),
            "verdict missing bypass-probe-skipped line:\n{v}"
        );
        assert!(
            v.contains("Payload mutation scan:** skipped"),
            "verdict missing scan-skipped line:\n{v}"
        );
    }

    #[test]
    fn render_markdown_embeds_verdict_section_near_top() {
        let mut r = LegendaryReport {
            target: "https://x".into(),
            started_at: "2026-05-21T00:00:00Z".into(),
            elapsed_ms: 1,
            ..Default::default()
        };
        r.scan.ran = true;
        r.scan.total_variants = Some(30);
        r.scan.bypassed = Some(2);
        let md = render_markdown(&r);
        let verdict_pos = md
            .find("## Verdict at a glance")
            .expect("verdict header missing");
        let section1_pos = md
            .find("## 1. WAF detection")
            .expect("section 1 header missing");
        assert!(
            verdict_pos < section1_pos,
            "verdict must render BEFORE section 1 (skim-first ordering)"
        );
    }

    #[test]
    fn apply_bypass_probe_json_flattens_results_and_drains_divergences() {
        // The bypass-probe JSON is `{"results": [...]}` keyed by
        // URL; legendary flattens across URLs into one divergence
        // list so the renderer doesn't have to know about per-URL
        // grouping. Also sums probes_fired for the summary.
        let json = serde_json::json!({
            "results": [
                {
                    "target": "https://x/a",
                    "probes_fired": 191,
                    "divergences": [
                        {
                            "family": "headers",
                            "label": "X-Original-URL",
                            "description": "Override URL parser",
                            "baseline_status": 403,
                            "probe_status": 200,
                            "body_delta_pct": 87.4,
                            "curl_cmd": "curl -H 'X-Original-URL: /admin' https://x/a",
                            "severity": "HIGH"
                        }
                    ]
                },
                {
                    "target": "https://x/b",
                    "probes_fired": 8,
                    "divergences": [
                        {
                            "family": "methods",
                            "label": "X-HTTP-Method-Override",
                            "baseline_status": 403,
                            "probe_status": 401,
                            "body_delta_pct": 12.0,
                            "curl_cmd": "curl -X POST -H 'X-HTTP-Method-Override: GET' https://x/b",
                            "severity": "MEDIUM"
                        }
                    ]
                }
            ]
        });
        let mut phase = PhaseBypassProbe::default();
        apply_bypass_probe_json(&mut phase, &json);
        assert_eq!(phase.total_probes, Some(199));
        assert_eq!(phase.total_divergences, Some(2));
        assert_eq!(phase.divergences.len(), 2);
        // First finding's full payload round-tripped.
        assert_eq!(phase.divergences[0].family, "headers");
        assert_eq!(phase.divergences[0].severity, "HIGH");
        assert_eq!(phase.divergences[0].description, "Override URL parser");
        // Second finding has no description — must default to empty,
        // not panic.
        assert_eq!(phase.divergences[1].family, "methods");
        assert_eq!(phase.divergences[1].description, "");
    }

    #[test]
    fn apply_bypass_probe_json_tolerates_empty_results() {
        let json = serde_json::json!({"results": []});
        let mut phase = PhaseBypassProbe::default();
        apply_bypass_probe_json(&mut phase, &json);
        assert!(phase.total_probes.is_none());
        assert_eq!(phase.total_divergences, Some(0));
        assert!(phase.divergences.is_empty());
    }

    #[test]
    fn apply_bypass_probe_json_tolerates_missing_results_key() {
        // A future scan binary or a corrupted file could omit the
        // top-level "results" key. Must not panic — the renderer
        // already handles empty divergences gracefully.
        let json = serde_json::json!({"unrelated": "field"});
        let mut phase = PhaseBypassProbe::default();
        apply_bypass_probe_json(&mut phase, &json);
        assert!(phase.total_probes.is_none());
        assert_eq!(phase.total_divergences, Some(0));
        assert!(phase.divergences.is_empty());
    }

    #[test]
    fn render_markdown_bypass_probe_section_lists_high_severity_first() {
        let mut r = LegendaryReport {
            target: "https://x".into(),
            ..Default::default()
        };
        r.bypass_probe.ran = true;
        r.bypass_probe.total_probes = Some(191);
        r.bypass_probe.total_divergences = Some(3);
        r.bypass_probe.divergences = vec![
            DivergenceSummary {
                family: "methods".into(),
                label: "low-find".into(),
                description: String::new(),
                baseline_status: 403,
                probe_status: 401,
                body_delta_pct: 5.0,
                curl_cmd: "low-curl".into(),
                severity: "LOW".into(),
            },
            DivergenceSummary {
                family: "headers".into(),
                label: "high-find".into(),
                description: "smoking-gun".into(),
                baseline_status: 403,
                probe_status: 200,
                body_delta_pct: 90.0,
                curl_cmd: "high-curl".into(),
                severity: "HIGH".into(),
            },
            DivergenceSummary {
                family: "paths".into(),
                label: "mid-find".into(),
                description: String::new(),
                baseline_status: 403,
                probe_status: 302,
                body_delta_pct: 30.0,
                curl_cmd: "mid-curl".into(),
                severity: "MEDIUM".into(),
            },
        ];
        let md = render_markdown(&r);
        let high_pos = md.find("high-find").expect("HIGH find missing");
        let mid_pos = md.find("mid-find").expect("MEDIUM find missing");
        let low_pos = md.find("low-find").expect("LOW find missing");
        assert!(high_pos < mid_pos, "HIGH must render before MEDIUM:\n{md}");
        assert!(mid_pos < low_pos, "MEDIUM must render before LOW:\n{md}");
        // The probe summary surfaces both counts.
        assert!(md.contains("| 191 |"), "probes_fired count missing:\n{md}");
        assert!(md.contains("**3**"), "divergences count missing:\n{md}");
    }

    #[test]
    fn render_markdown_bypass_probe_section_calls_out_zero_divergences() {
        let mut r = LegendaryReport {
            target: "https://x".into(),
            ..Default::default()
        };
        r.bypass_probe.ran = true;
        r.bypass_probe.total_probes = Some(191);
        r.bypass_probe.total_divergences = Some(0);
        // divergences vec stays empty.
        let md = render_markdown(&r);
        assert!(
            md.contains("No probes diverged"),
            "zero-divergences note missing:\n{md}"
        );
    }

    #[test]
    fn render_markdown_bypass_probe_section_caps_at_25_with_footer() {
        let mut r = LegendaryReport {
            target: "https://x".into(),
            ..Default::default()
        };
        r.bypass_probe.ran = true;
        r.bypass_probe.divergences = (0..50)
            .map(|i| DivergenceSummary {
                family: "f".into(),
                label: format!("div-{i}"),
                description: String::new(),
                baseline_status: 403,
                probe_status: 200,
                body_delta_pct: 50.0,
                curl_cmd: format!("curl-{i}"),
                severity: "LOW".into(),
            })
            .collect();
        r.bypass_probe.total_divergences = Some(50);
        let md = render_markdown(&r);
        assert!(
            md.contains("Showing top 25 of 50"),
            "render-cap footer missing:\n{md}"
        );
        // First few must appear; tail must not.
        assert!(md.contains("div-0"), "first finding missing");
        assert!(!md.contains("div-49"), "tail finding leaked past cap");
    }

    #[test]
    fn apply_scan_json_skips_malformed_variants_without_aborting() {
        // A single bad row in bypass_variants must not throw away
        // the entire phase; downstream rendering still surfaces the
        // good rows.
        let json = serde_json::json!({
            "bypass_variants": [
                {"variant": "not-a-number"}, // malformed
                {"variant": 7, "payload": "good", "techniques": [], "confidence": 0.5},
            ],
        });
        let mut phase = PhaseScan::default();
        apply_scan_json(&mut phase, &json);
        assert_eq!(phase.bypass_variants.len(), 1);
        assert_eq!(phase.bypass_variants[0].variant, 7);
    }

    #[test]
    fn render_markdown_emits_bypass_variants_table_when_scan_ran() {
        let mut r = LegendaryReport {
            target: "https://example.com/search".into(),
            ..Default::default()
        };
        r.scan.ran = true;
        r.scan.payload = Some("' OR 1=1--".into());
        r.scan.param = Some("q".into());
        r.scan.waf_name = Some("Cloudflare".into());
        r.scan.total_variants = Some(50);
        r.scan.bypassed = Some(2);
        r.scan.blocked = Some(48);
        r.scan.bypass_rate_pct = Some(4.0);
        r.scan.elapsed_ms = Some(12_300.0);
        r.scan.bypass_variants = vec![BypassVariantSummary {
            variant: 5,
            payload: "%27 OR 1=1--".into(),
            techniques: vec!["url".into(), "case_swap".into()],
            confidence: 0.88,
            minimal_payload: None,
            repro_curl: None,
            minimal_repro_curl: None,
        }];
        let md = render_markdown(&r);
        // Summary table must surface counters with the post-dogfood
        // labels (pre-fix the row was misleadingly named "Variants
        // fired" — operator who set --scan-variants 5 saw 615 there).
        assert!(
            md.contains("Total requests fired"),
            "missing total_requests_fired row:\n{md}"
        );
        assert!(md.contains("| 50 |"), "total_variants value missing");
        assert!(md.contains("**2**"), "bypassed bolded count missing");
        // The variant payload must be in the rendered output —
        // this is the entire point of the fix.
        assert!(md.contains("Variant #5"), "variant header missing");
        assert!(md.contains("%27 OR 1=1--"), "variant payload missing");
        assert!(
            md.contains("`url` → `case_swap`"),
            "techniques chain missing"
        );
        // The curl repro must be parameter-aware.
        assert!(
            md.contains("curl -G --data-urlencode q=") && md.contains("example.com/search"),
            "curl reproducer missing or malformed:\n{md}"
        );
    }

    #[test]
    fn render_markdown_marks_section_2_not_reached_when_detect_errored() {
        // Pre-dogfood-fix: when detect errored, section 2 still
        // emitted "No CDN / server / cache markers surfaced…",
        // which falsely implied a connection succeeded. The guard
        // on fingerprint.ran must surface "Not reached" instead.
        let mut r = LegendaryReport {
            target: "https://x".into(),
            ..Default::default()
        };
        r.detect.error = Some("connection refused".into());
        // fingerprint.ran intentionally false.
        let md = render_markdown(&r);
        let s2_pos = md
            .find("## 2. Infrastructure fingerprint")
            .expect("section 2 header missing");
        let after = &md[s2_pos..];
        let next_section = after.find("\n## ").unwrap_or(after.len());
        let section_body = &after[..next_section];
        assert!(
            section_body.contains("Not reached"),
            "section 2 must surface Not reached when detect errored:\n{section_body}"
        );
        assert!(
            !section_body.contains("No CDN / server / cache markers surfaced"),
            "section 2 must NOT pretend a connection succeeded:\n{section_body}"
        );
    }

    #[test]
    fn render_markdown_scan_summary_uses_explore_pool_and_total_request_labels() {
        // Operator-facing label fix from dogfood: --scan-variants
        // bounds the explore pool, not the total fires. Section 4
        // must show BOTH numbers with unambiguous row labels so
        // pasting --scan-variants 5 doesn't produce a confusing
        // "Variants fired | 615" row.
        let mut r = LegendaryReport {
            target: "https://x".into(),
            ..Default::default()
        };
        r.scan.ran = true;
        r.scan.explore_variants = Some(5);
        r.scan.total_variants = Some(615);
        r.scan.bypassed = Some(0);
        let md = render_markdown(&r);
        assert!(
            md.contains("| Explore pool (variants tried initially) | 5 |"),
            "missing explore-pool row:\n{md}"
        );
        assert!(
            md.contains("| Total requests fired (across all phases) | 615 |"),
            "missing total-fired row:\n{md}"
        );
        // The old misleading "Variants fired" row must NOT appear.
        assert!(
            !md.contains("| Variants fired |"),
            "old misleading row label still present:\n{md}"
        );
    }

    #[test]
    fn render_markdown_calls_out_zero_bypasses_when_scan_ran_but_found_none() {
        let mut r = LegendaryReport {
            target: "https://example.com".into(),
            ..Default::default()
        };
        r.scan.ran = true;
        r.scan.payload = Some("payload".into());
        r.scan.bypassed = Some(0);
        r.scan.total_variants = Some(40);
        // bypass_variants intentionally empty.
        let md = render_markdown(&r);
        assert!(
            md.contains("No variants bypassed"),
            "must explicitly note zero-bypass outcome, not just elide the table:\n{md}"
        );
        // The summary table must still show the 40-variant fire.
        assert!(md.contains("| 40 |"));
    }

    #[test]
    fn render_markdown_with_scan_error_includes_rerun_command() {
        let mut r = LegendaryReport {
            target: "https://example.com".into(),
            ..Default::default()
        };
        r.scan.ran = true;
        r.scan.error = Some("connection refused".into());
        r.scan.raw_text = Some("wafrift scan ...".into());
        let md = render_markdown(&r);
        assert!(md.contains("connection refused"));
        assert!(
            md.contains("wafrift scan ..."),
            "re-run command must still appear when scan errored, so the operator can reproduce the failure"
        );
    }

    #[test]
    fn render_markdown_escapes_triple_backtick_in_payload() {
        let mut r = LegendaryReport {
            target: "https://x".into(),
            ..Default::default()
        };
        r.scan.ran = true;
        r.scan.bypass_variants = vec![BypassVariantSummary {
            variant: 1,
            payload: "evil```backtick".into(),
            techniques: vec![],
            confidence: 0.5,
            minimal_payload: None,
            repro_curl: None,
            minimal_repro_curl: None,
        }];
        let md = render_markdown(&r);
        // The literal ``` from the payload must not appear in the
        // final markdown — otherwise it closes the surrounding
        // code fence early.
        let payload_idx = md.find("evil").expect("payload missing");
        // Look for ``` AFTER "evil" but before the next \n```\n
        // section close (the legitimate end-of-fence).
        let after = &md[payload_idx..];
        let next_fence = after.find("\n```\n").unwrap_or(after.len());
        let payload_section = &after[..next_fence];
        assert!(
            !payload_section.contains("```"),
            "payload's literal ``` leaked into markdown — fence will break:\n{payload_section}"
        );
    }

    #[test]
    fn output_writes_file_to_disk() {
        use std::env::temp_dir;
        // emit() is a private fn that writes to args.output when
        // set. We exercise it via render_markdown + manual write
        // (mirrors emit's behaviour without the side effects of
        // run_legendary).
        let r = LegendaryReport {
            target: "https://example.com".into(),
            started_at: "2026-05-20T00:00:00Z".into(),
            elapsed_ms: 1,
            ..Default::default()
        };
        let rendered = render_markdown(&r);
        let path = temp_dir().join(format!("wafrift-legendary-out-{}.md", std::process::id()));
        std::fs::write(&path, &rendered).expect("write");
        let read_back = std::fs::read_to_string(&path).expect("read");
        assert_eq!(read_back, rendered);
        let _ = std::fs::remove_file(&path);
    }
}
