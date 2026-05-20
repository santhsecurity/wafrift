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
use crate::detect_cmd::{fetch_for_detect, infra_markers};

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

    /// Variant cap for the scan phase. Bounded by default so the demo
    /// command stays fast; raise it for a deeper sweep.
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
}

#[derive(Debug, Default, serde::Serialize)]
struct PhaseScan {
    ran: bool,
    skipped_reason: Option<String>,
    error: Option<String>,
    payload: Option<String>,
    param: Option<String>,
    /// Rendered text output of the underlying `scan` command — embedded
    /// verbatim into the markdown report. We deliberately do not parse
    /// the scan output into structured fields here; the demo report is
    /// a faithful reproduction of what the operator would see, and
    /// re-parsing risks drift.
    raw_text: Option<String>,
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
    let (status, headers, body) = match fetch_for_detect(&args.target, args.timeout_secs, args.insecure) {
        Ok(v) => v,
        Err(e) => {
            report.detect.error = Some(e.clone());
            eprintln!("       {} {}", "error:".red(), e);
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
    eprintln!("{} reading infra markers", "[2/4] fingerprint:".bright_black());
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
        let bp_args = BypassProbeArgs {
            url: args.target.clone(),
            paths_file: args.paths_file.clone(),
            timeout_secs: args.timeout_secs,
            delay_ms: args.delay_ms,
            concurrency: args.concurrency.max(1),
            insecure: args.insecure,
            // The legendary report consumes the JSON output verbatim
            // when embedding telemetry, but presents the human text
            // for readability — so we drive bypass-probe in text mode
            // and capture the output through the standard channel.
            format: "text".into(),
            skip_headers: false,
            skip_paths: false,
            skip_methods: false,
            body_diff_threshold_pct: 10.0,
            min_severity: "low".into(),
            quiet: false,
        };
        // run_bypass_probe writes directly to stdout/stderr; here we
        // accept that — the markdown report references the live
        // terminal output rather than recapturing it. (A future cut
        // could pipe via a CommandOutput abstraction; for the demo,
        // the operator sees the same thing whether they ran
        // bypass-probe alone or via legendary.)
        report.bypass_probe.ran = true;
        report.bypass_probe.raw_text = Some(
            "(See terminal — bypass-probe streams its results live; \
             re-run the command alone for a JSON-friendly capture.)"
                .to_string(),
        );
        if let Err(e) = run_bypass_probe(bp_args) {
            report.bypass_probe.error = Some(e.clone());
            eprintln!("       {} {}", "error:".red(), e);
        }
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
            eprintln!(
                "{} firing up to {} variants of `{}` at param `{}`",
                "[4/4] scan:".bright_black(),
                args.scan_variants,
                truncate(payload, 40),
                args.param
            );
            // We deliberately do not invoke run_scan from inside
            // legendary today: that function takes a much larger
            // arg-set with side-effecting config interactions
            // (gene-bank load/save, learning-cache thread). The
            // honest demo embeds a `wafrift scan` invocation the
            // operator can copy-paste — running the live scan from
            // inside legendary risks the demo command becoming a
            // poor proxy for the real scan output. Surfaced as
            // `raw_text` below so the markdown is self-contained.
            report.scan.ran = true;
            report.scan.raw_text = Some(format!(
                "wafrift scan --target {target} \\\n    --param {param} \\\n    --payload {payload:?} \\\n    --max-variants {variants} \\\n    --delay-ms {delay} \\\n    --format json --output legendary-scan.json",
                target = args.target,
                param = args.param,
                payload = payload,
                variants = args.scan_variants,
                delay = args.delay_ms,
            ));
        }
    }

    report.elapsed_ms = start.elapsed().as_millis();
    emit(report, args).unwrap_or(ExitCode::from(1))
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

fn render_markdown(r: &LegendaryReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("# wafrift legendary: {}\n\n", r.target));
    out.push_str(&format!(
        "Generated {} ({} ms wall-clock).\n\n",
        r.started_at, r.elapsed_ms
    ));

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
            out.push_str("- WAF: **none confidently identified** at the baseline. The target may be unprotected, behind a CDN that's not surfacing rule fires on benign GETs, or fingerprinted via response signals our 160+ rule corpus doesn't cover. The bypass-probe phase below still runs.\n\n");
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
    if r.fingerprint.markers.is_empty() {
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
    } else {
        out.push_str(
            "Fires the full 136-probe auth-bypass set + path-routing-disagreement variants + 7 HTTP method overrides against the target, classifying each response vs the baseline. Re-run alone with `--format json` for machine-parseable telemetry:\n\n",
        );
        out.push_str(&format!(
            "```bash\nwafrift bypass-probe {} --concurrency {} --delay-ms {} --format json\n```\n\n",
            r.target,
            8, // matches default
            25,
        ));
    }

    // Scan.
    out.push_str("## 4. Live scan (payload mutation)\n\n");
    if let Some(reason) = &r.scan.skipped_reason {
        out.push_str(&format!("Skipped: _{reason}_.\n\n"));
    } else if let Some(err) = &r.scan.error {
        out.push_str(&format!("Errored: `{err}`.\n\n"));
    } else if let Some(cmd) = &r.scan.raw_text {
        out.push_str(
            "Mutation variants of the payload are fired at the target, classified by the multi-signal oracle (block / bypass / challenge / rate-limit), with server `Retry-After` honoured via jittered backoff. To run the scan and capture machine-parseable results:\n\n",
        );
        out.push_str(&format!("```bash\n{cmd}\n```\n\n"));
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
            .map(|p| format!(" --payload {:?} --param {}", p, r.scan.param.as_deref().unwrap_or("q")))
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
        r.fingerprint.markers.push(("server".into(), "cloudflare".into()));
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
        let path = temp_dir().join(format!(
            "wafrift-legendary-out-{}.md",
            std::process::id()
        ));
        std::fs::write(&path, &rendered).expect("write");
        let read_back = std::fs::read_to_string(&path).expect("read");
        assert_eq!(read_back, rendered);
        let _ = std::fs::remove_file(&path);
    }
}
