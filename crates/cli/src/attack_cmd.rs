//! `wafrift attack` — unified parser-disagreement orchestrator.
//!
//! Runs all four members of the parser-diff family
//! (`parser-diff`, `header-diff`, `body-diff`, `query-diff`)
//! against ONE target URL in a single invocation and merges the
//! results into one structured report. This is the end-to-end
//! pentester command — operators don't have to remember which
//! subcommand probes which surface.
//!
//! ## Workflow
//!
//! ```text
//! $ wafrift attack https://target/admin --param q --format json | jq .
//! {
//!   "target": "https://target/admin",
//!   "param": "q",
//!   "probes": {
//!     "url_path":   { ... parser-diff results ... },
//!     "headers":    { ... header-diff results ... },
//!     "body":       { ... body-diff results ... },
//!     "query":      { ... query-diff results ... }
//!   },
//!   "divergences": { "high": 3, "medium": 7, "total": 10 }
//! }
//! ```
//!
//! Each sub-probe runs as a SUBPROCESS (`std::env::current_exe`
//! re-invokes the same wafrift binary with the appropriate subcommand
//! + `--format json --quiet`). This keeps the orchestrator decoupled
//! from each subcommand's internals — they evolve independently
//! and the orchestrator just merges JSON. Subprocesses run
//! CONCURRENTLY via `tokio::join!`.

use std::process::ExitCode;
use std::time::Duration;

use clap::Args;
use colored::Colorize;
use serde_json::{Value, json};

#[derive(Args, Debug)]
pub struct AttackArgs {
    /// Target URL — shared across all four sub-probes.
    pub url: String,

    /// Parameter name for `query-diff`. Other probes ignore.
    #[arg(long, default_value = "q")]
    pub param: String,

    /// Inter-request delay (ms) forwarded to every sub-probe.
    #[arg(long, default_value_t = 25)]
    pub delay_ms: u64,

    /// Max concurrent in-flight probes WITHIN each sub-probe.
    #[arg(long, default_value_t = 8)]
    pub concurrency: usize,

    /// HTTP timeout per probe (seconds).
    #[arg(long, default_value_t = 8)]
    pub timeout_secs: u64,

    /// Accept self-signed TLS certificates (lab targets).
    #[arg(long)]
    pub insecure: bool,

    /// HTTP proxy URL (Burp on `http://127.0.0.1:8080` is typical).
    #[arg(long, value_name = "URL")]
    pub proxy: Option<String>,

    /// Extra headers (`-H 'Name: Value'`, repeatable).
    #[arg(long, short = 'H', value_name = "HEADER", num_args = 0..)]
    pub header: Vec<String>,

    /// Output format: `text` (default — colored summary table) or
    /// `json` (machine-readable structured blob with per-family
    /// sub-objects).
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    /// Quiet mode — suppress per-probe progress (still emits the
    /// final summary / JSON).
    #[arg(long, default_value_t = false)]
    pub quiet: bool,

    /// Per-probe overall timeout (seconds). Any sub-probe that
    /// doesn't return within this budget is recorded as an error
    /// without taking down the rest of the run. Defaults to 60s.
    #[arg(long, default_value_t = 60)]
    pub probe_timeout_secs: u64,
}

/// Entry point for `wafrift attack`.
pub async fn run_attack(mut args: AttackArgs) -> ExitCode {
    args.url = crate::helpers::normalize_target_url(&args.url);
    let scan_text = args.format == "text";
    if scan_text && !args.quiet {
        eprintln!(
            "{} firing all four parser-diff probes against {} concurrently",
            "[wafrift attack]".bright_cyan().bold(),
            args.url.bright_white()
        );
    }

    // Bind each arg vec to a local so it outlives the tokio::join!
    // macro expansion (otherwise the Vec<String> is a temporary
    // dropped while spawn_subprobe still holds &[String] into it).
    let path_args = subprobe_args_path(&args);
    let header_args = subprobe_args_header(&args);
    let body_args = subprobe_args_body(&args);
    let query_args = subprobe_args_query(&args);
    let cache_args = subprobe_args_cache(&args);
    let h2_args = subprobe_args_h2(&args);
    let method_args = subprobe_args_method(&args);

    // Spawn each sub-probe concurrently.
    let (path_res, header_res, body_res, query_res, cache_res, h2_res, method_res) = tokio::join!(
        spawn_subprobe("parser-diff", &path_args, args.probe_timeout_secs),
        spawn_subprobe("header-diff", &header_args, args.probe_timeout_secs),
        spawn_subprobe("body-diff", &body_args, args.probe_timeout_secs),
        spawn_subprobe("query-diff", &query_args, args.probe_timeout_secs),
        spawn_subprobe("cache-diff", &cache_args, args.probe_timeout_secs),
        spawn_subprobe("h2-diff", &h2_args, args.probe_timeout_secs),
        spawn_subprobe("method-diff", &method_args, args.probe_timeout_secs),
    );

    let path = into_value("url_path", path_res);
    let headers = into_value("headers", header_res);
    let body = into_value("body", body_res);
    let query = into_value("query", query_res);
    let cache = into_value("cache", cache_res);
    let h2 = into_value("h2", h2_res);
    let method = into_value("method", method_res);

    let mut totals = DivergenceCount::default();
    totals.add_from_probe(&path);
    totals.add_from_probe(&headers);
    totals.add_from_probe(&body);
    totals.add_from_probe(&query);
    totals.add_from_probe(&cache);
    totals.add_from_probe(&h2);
    totals.add_from_probe(&method);

    let report = json!({
        "target": args.url,
        "param": args.param,
        "probes": {
            "url_path": path,
            "headers":  headers,
            "body":     body,
            "query":    query,
            "cache":    cache,
            "h2":       h2,
            "method":   method,
        },
        "divergences": {
            "high":   totals.high,
            "medium": totals.medium,
            "total":  totals.high + totals.medium,
        },
    });

    if args.format == "json" {
        match serde_json::to_string_pretty(&report) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("JSON serialize error: {e}");
                return ExitCode::from(1);
            }
        }
    } else {
        emit_text(
            &args, &totals, &path, &headers, &body, &query, &cache, &h2, &method,
        );
    }
    ExitCode::SUCCESS
}

#[derive(Default, Debug)]
struct DivergenceCount {
    high: u64,
    medium: u64,
}

impl DivergenceCount {
    fn add_from_probe(&mut self, probe: &Value) {
        // Each sub-probe's JSON carries `divergences.high` +
        // `divergences.medium` (the structured fields shared by all
        // parser-diff sub-commands).
        if let Some(d) = probe.get("divergences") {
            self.high += d.get("high").and_then(Value::as_u64).unwrap_or(0);
            self.medium += d.get("medium").and_then(Value::as_u64).unwrap_or(0);
        }
    }
}

fn subprobe_args_path(args: &AttackArgs) -> Vec<String> {
    let mut v = vec![args.url.clone()];
    push_common_flags(&mut v, args);
    v
}

fn subprobe_args_header(args: &AttackArgs) -> Vec<String> {
    let mut v = vec![args.url.clone()];
    push_common_flags(&mut v, args);
    v
}

fn subprobe_args_body(args: &AttackArgs) -> Vec<String> {
    let mut v = vec![args.url.clone()];
    push_common_flags(&mut v, args);
    v
}

fn subprobe_args_query(args: &AttackArgs) -> Vec<String> {
    let mut v = vec![args.url.clone(), "--param".into(), args.param.clone()];
    push_common_flags(&mut v, args);
    v
}

fn subprobe_args_cache(args: &AttackArgs) -> Vec<String> {
    let mut v = vec![args.url.clone(), "--param".into(), args.param.clone()];
    push_common_flags(&mut v, args);
    v
}

fn subprobe_args_h2(args: &AttackArgs) -> Vec<String> {
    // h2-diff is single-threaded by construction (H1 and H2 must
    // match request-shape exactly, no payload-axis fan-out), so it
    // accepts a NARROWER flag set than the other sub-probes —
    // notably no `--concurrency`, no `--proxy`, no `-H/--header`.
    // Before this filter, every `attack` invocation silently
    // dropped the H1/H2 differential probe (sonnet dogfood pass 3,
    // 2026-05): `attack` passed `--concurrency 8` and clap exited
    // h2-diff with code 2, the orchestrator catalogued the error
    // and continued.
    let mut v = vec![args.url.clone(), "--param".into(), args.param.clone()];
    push_h2_flags(&mut v, args);
    v
}

/// h2-diff's accepted-flags subset.  Run `wafrift h2-diff --help`
/// for the canonical list — keep this in sync.
fn push_h2_flags(out: &mut Vec<String>, args: &AttackArgs) {
    out.push("--format".into());
    out.push("json".into());
    out.push("--delay-ms".into());
    out.push(args.delay_ms.to_string());
    out.push("--timeout-secs".into());
    out.push(args.timeout_secs.to_string());
    if args.insecure {
        out.push("--insecure".into());
    }
}

fn subprobe_args_method(args: &AttackArgs) -> Vec<String> {
    // method-diff doesn't take --param; bare URL + common flags.
    let mut v = vec![args.url.clone()];
    push_common_flags(&mut v, args);
    v
}

/// Flags every sub-probe accepts identically. Centralised so a new
/// shared flag added to all four sub-commands lands here once.
fn push_common_flags(out: &mut Vec<String>, args: &AttackArgs) {
    out.push("--format".into());
    out.push("json".into());
    out.push("--quiet".into());
    out.push("--delay-ms".into());
    out.push(args.delay_ms.to_string());
    out.push("--concurrency".into());
    out.push(args.concurrency.to_string());
    out.push("--timeout-secs".into());
    out.push(args.timeout_secs.to_string());
    if args.insecure {
        out.push("--insecure".into());
    }
    if let Some(p) = &args.proxy {
        out.push("--proxy".into());
        out.push(p.clone());
    }
    for h in &args.header {
        out.push("-H".into());
        out.push(h.clone());
    }
}

/// Spawn one `wafrift <subcmd> ...` subprocess, await it under a
/// timeout, and parse the JSON output into a `Value`. On any
/// failure (subprocess didn't launch, returned non-JSON, timed out)
/// returns the error string — the orchestrator converts it into a
/// structured `{ "error": "..." }` value.
///
/// Exit code handling:
/// - 0 = success, parse JSON from stdout.
/// - 6 = `h2-diff` inconclusive (all H2 probes failed: H1-only
///   target, ALPN mismatch). stdout still carries valid JSON; parse
///   it. Do NOT treat this as an error — the operator should see
///   "H2 not reachable on this target" from the sub-probe's JSON,
///   not "subprobe h2-diff exited 6 — stderr: …".
/// - any other non-zero = genuine error; surface as Err.
async fn spawn_subprobe(subcmd: &str, args: &[String], timeout_secs: u64) -> Result<Value, String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("could not locate current wafrift exe: {e}"))?;
    let mut cmd = tokio::process::Command::new(exe);
    cmd.arg(subcmd);
    cmd.args(args);
    let task = cmd.output();
    let result = tokio::time::timeout(Duration::from_secs(timeout_secs), task)
        .await
        .map_err(|_| format!("subprobe {subcmd} timed out after {timeout_secs}s"))?
        .map_err(|e| format!("subprobe {subcmd} failed to launch: {e}"))?;
    let exit_code = result.status.code().unwrap_or(-1);
    let is_ok = result.status.success()
        // Exit 6 = h2-diff "inconclusive" (all H2 legs failed to negotiate).
        // The stdout still carries valid JSON; don't surface it as an error
        // to the `attack` orchestrator — let the sub-probe's JSON speak for
        // itself (it says "h2_errors == total_probes", which is informative,
        // not a subprobe crash).
        || exit_code == 6;
    if !is_ok {
        let stderr = String::from_utf8_lossy(&result.stderr).to_string();
        return Err(format!(
            "subprobe {subcmd} exited {} — stderr: {stderr}",
            result.status
        ));
    }
    let stdout = std::str::from_utf8(&result.stdout)
        .map_err(|e| format!("subprobe {subcmd} stdout not utf-8: {e}"))?;
    serde_json::from_str(stdout.trim()).map_err(|e| format!("subprobe {subcmd} json parse: {e}"))
}

fn into_value(family: &str, res: Result<Value, String>) -> Value {
    match res {
        Ok(v) => v,
        Err(e) => json!({
            "family": family,
            "error": e,
            "divergences": {"high": 0, "medium": 0},
            "results": [],
        }),
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_text(
    args: &AttackArgs,
    totals: &DivergenceCount,
    path: &Value,
    headers: &Value,
    body: &Value,
    query: &Value,
    cache: &Value,
    h2: &Value,
    method: &Value,
) {
    if !args.quiet {
        println!();
        println!(
            "  {} {} divergence(s) against {} — {} high, {} medium",
            "[wafrift attack summary]".bright_cyan().bold(),
            (totals.high + totals.medium).to_string().bold().yellow(),
            args.url.bright_white(),
            totals.high.to_string().bright_red().bold(),
            totals.medium.to_string().yellow(),
        );
    }
    for (label, probe) in [
        ("url-path", path),
        ("headers", headers),
        ("body", body),
        ("query", query),
        ("cache", cache),
        ("h2", h2),
        ("method", method),
    ] {
        let d = probe.get("divergences");
        let high = d
            .and_then(|x| x.get("high"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let med = d
            .and_then(|x| x.get("medium"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let err = probe.get("error").and_then(Value::as_str);
        match err {
            Some(e) => println!(
                "    {} {label} — {}: {e}",
                "✗".red().bold(),
                "subprobe error".red()
            ),
            None => println!(
                "    {} {label}: {} high, {} medium",
                "·".bright_black(),
                high.to_string().bright_red(),
                med.to_string().yellow(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Pure helper: DivergenceCount aggregation ──────────────

    #[test]
    fn divergence_count_starts_at_zero() {
        let d = DivergenceCount::default();
        assert_eq!(d.high, 0);
        assert_eq!(d.medium, 0);
    }

    #[test]
    fn divergence_count_adds_high_and_medium_from_probe() {
        let mut d = DivergenceCount::default();
        let probe = json!({
            "divergences": { "high": 3, "medium": 7 }
        });
        d.add_from_probe(&probe);
        assert_eq!(d.high, 3);
        assert_eq!(d.medium, 7);
    }

    #[test]
    fn divergence_count_handles_missing_divergences_block() {
        let mut d = DivergenceCount::default();
        let probe = json!({ "results": [] });
        d.add_from_probe(&probe);
        assert_eq!(d.high, 0);
        assert_eq!(d.medium, 0);
    }

    #[test]
    fn divergence_count_accumulates_across_probes() {
        let mut d = DivergenceCount::default();
        d.add_from_probe(&json!({ "divergences": { "high": 1, "medium": 2 }}));
        d.add_from_probe(&json!({ "divergences": { "high": 3, "medium": 4 }}));
        d.add_from_probe(&json!({ "divergences": { "high": 0, "medium": 5 }}));
        assert_eq!(d.high, 4);
        assert_eq!(d.medium, 11);
    }

    // ── into_value: error -> structured fallback ──────────────

    #[test]
    fn into_value_passes_ok_value_through() {
        let v = into_value("url_path", Ok(json!({"x": 1})));
        assert_eq!(v["x"], 1);
    }

    #[test]
    fn into_value_wraps_err_with_family_and_empty_divergences() {
        let v = into_value("body", Err("boom".to_string()));
        assert_eq!(v["family"], "body");
        assert_eq!(v["error"], "boom");
        // Even on error the family carries empty divergence counts —
        // keeps the orchestrator's totalling code branch-free.
        assert_eq!(v["divergences"]["high"], 0);
        assert_eq!(v["divergences"]["medium"], 0);
    }

    // ── push_common_flags: shared flag matrix ─────────────────

    fn min_args() -> AttackArgs {
        AttackArgs {
            url: "http://x/".into(),
            param: "q".into(),
            delay_ms: 25,
            concurrency: 8,
            timeout_secs: 8,
            insecure: false,
            proxy: None,
            header: Vec::new(),
            format: "json".into(),
            quiet: true,
            probe_timeout_secs: 60,
        }
    }

    #[test]
    fn push_common_flags_always_includes_format_json_quiet() {
        let mut v = Vec::new();
        push_common_flags(&mut v, &min_args());
        assert!(v.iter().any(|a| a == "--format"));
        assert!(v.iter().any(|a| a == "json"));
        assert!(v.iter().any(|a| a == "--quiet"));
    }

    #[test]
    fn push_common_flags_forwards_delay_and_concurrency_and_timeout() {
        let mut args = min_args();
        args.delay_ms = 100;
        args.concurrency = 4;
        args.timeout_secs = 12;
        let mut v = Vec::new();
        push_common_flags(&mut v, &args);
        let joined: String = v.join(" ");
        assert!(joined.contains("--delay-ms 100"), "got: {joined}");
        assert!(joined.contains("--concurrency 4"), "got: {joined}");
        assert!(joined.contains("--timeout-secs 12"), "got: {joined}");
    }

    #[test]
    fn push_common_flags_emits_insecure_flag_only_when_set() {
        let mut v = Vec::new();
        push_common_flags(&mut v, &min_args());
        assert!(!v.iter().any(|a| a == "--insecure"), "default off");
        let mut args2 = min_args();
        args2.insecure = true;
        let mut v2 = Vec::new();
        push_common_flags(&mut v2, &args2);
        assert!(v2.iter().any(|a| a == "--insecure"), "on when set");
    }

    #[test]
    fn push_common_flags_forwards_proxy_url_when_set() {
        let mut args = min_args();
        args.proxy = Some("http://127.0.0.1:8080".into());
        let mut v = Vec::new();
        push_common_flags(&mut v, &args);
        let joined: String = v.join(" ");
        assert!(
            joined.contains("--proxy http://127.0.0.1:8080"),
            "got: {joined}"
        );
    }

    #[test]
    fn push_common_flags_forwards_every_header_via_dash_h() {
        let mut args = min_args();
        args.header = vec!["X-A: 1".into(), "X-B: 2".into()];
        let mut v = Vec::new();
        push_common_flags(&mut v, &args);
        // Two -H flags + their values.
        let h_count = v.iter().filter(|a| *a == "-H").count();
        assert_eq!(h_count, 2);
        assert!(v.iter().any(|a| a == "X-A: 1"));
        assert!(v.iter().any(|a| a == "X-B: 2"));
    }

    #[test]
    fn subprobe_args_query_carries_param_flag() {
        let mut args = min_args();
        args.param = "search".into();
        let v = subprobe_args_query(&args);
        let joined: String = v.join(" ");
        assert!(joined.contains("--param search"), "got: {joined}");
    }

    #[test]
    fn subprobe_args_path_does_not_carry_param_flag() {
        // URL-path probe doesn't take --param (parser-diff CLI).
        // Confirm the orchestrator doesn't accidentally pass it.
        let v = subprobe_args_path(&min_args());
        assert!(!v.iter().any(|a| a == "--param"));
    }

    // ── h2-diff regression guard (P0 found by sonnet 2026-05) ──
    //
    // h2-diff doesn't accept --concurrency / --proxy / -H.  The
    // orchestrator was passing all three.  Result: every `attack`
    // run silently dropped the H1/H2 differential probe (clap
    // exited h2-diff with code 2; `into_value` turned the error
    // into `{ "error": "subprobe h2-diff exited 2 ..." }`).
    //
    // These guards prevent regression.

    #[test]
    fn subprobe_args_h2_does_not_pass_concurrency_flag() {
        let args = min_args();
        let v = subprobe_args_h2(&args);
        assert!(
            !v.iter().any(|a| a == "--concurrency"),
            "h2-diff doesn't accept --concurrency; got argv: {v:?}"
        );
    }

    #[test]
    fn subprobe_args_h2_does_not_pass_proxy_flag() {
        let mut args = min_args();
        args.proxy = Some("http://localhost:8080".into());
        let v = subprobe_args_h2(&args);
        assert!(
            !v.iter().any(|a| a == "--proxy"),
            "h2-diff doesn't accept --proxy; got argv: {v:?}"
        );
    }

    #[test]
    fn subprobe_args_h2_does_not_pass_dash_h_header_flag() {
        let mut args = min_args();
        args.header = vec!["X-Custom: 1".into()];
        let v = subprobe_args_h2(&args);
        assert!(
            !v.iter().any(|a| a == "-H"),
            "h2-diff doesn't accept -H; got argv: {v:?}"
        );
    }

    #[test]
    fn subprobe_args_h2_still_passes_format_delay_timeout() {
        // The narrower flag set must still include the flags
        // h2-diff DOES accept — without them the output isn't JSON
        // and the orchestrator can't parse it.
        let v = subprobe_args_h2(&min_args());
        let joined: String = v.join(" ");
        assert!(joined.contains("--format json"), "got: {joined}");
        assert!(joined.contains("--delay-ms"), "got: {joined}");
        assert!(joined.contains("--timeout-secs"), "got: {joined}");
    }

    #[test]
    fn subprobe_args_h2_carries_param_flag() {
        // h2-diff DOES accept --param (it's the only sub-probe
        // that takes it via push_h2_flags rather than
        // push_common_flags).  Confirm it's still wired.
        let mut args = min_args();
        args.param = "q".into();
        let v = subprobe_args_h2(&args);
        let joined: String = v.join(" ");
        assert!(joined.contains("--param q"), "got: {joined}");
    }

    #[test]
    fn subprobe_args_h2_carries_insecure_only_when_set() {
        let v = subprobe_args_h2(&min_args());
        assert!(!v.iter().any(|a| a == "--insecure"));
        let mut args2 = min_args();
        args2.insecure = true;
        let v2 = subprobe_args_h2(&args2);
        assert!(v2.iter().any(|a| a == "--insecure"));
    }
}
