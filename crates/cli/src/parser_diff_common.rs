//! Shared primitives across the parser-diff family
//! (`parser-diff`, `header-diff`, `body-diff`, `query-diff`,
//! `cache-diff`, `cors-diff`, `gql-diff`, `jwt-diff`, `method-diff`,
//! `h2-diff`).
//!
//! Every parser-diff subcommand classifies probe responses against
//! a baseline using the same rules:
//!
//! - `body_delta_pct(baseline_len, probe_len)` — signed percentage
//!   change in body length.
//! - `severity_of(baseline_status, probe_status, body_delta)` —
//!   `"high"` when the HTTP status class flipped (200 → 403, 200 →
//!   500, etc.), `"medium"` when the body shifted by more than 20%
//!   with status preserved, `"none"` otherwise.
//!
//! These functions are now thin local wrappers around the upstream
//! Santh-owned [`respdiff`] primitives (`body_size_delta_pct`,
//! `classify_severity`, `status_class`, `DiffPolicy`). Lifting them
//! means a fix to the classification logic reaches every subcommand
//! AND every other Santh scanner that consumes respdiff — the
//! architectural commitment from `feedback_architecture_and_dedup`.
//! The wrapper signatures are preserved verbatim so the 11
//! `*_diff_cmd.rs` call sites compile unchanged.
//!
//! Every parser-diff subcommand also builds its `reqwest::Client`
//! from the exact same recipe: operator timeout + `--insecure` +
//! limited-5 redirect + the shared `User-Agent` + `--proxy` /
//! `--header` plumbing via `pentest_client::apply_pentest_flags`.
//! Pre-extract, that was 22 lines copy-pasted across nine command
//! files — one line at a time, drifting each time someone tuned
//! e.g. the redirect limit in one file but not the others.

use std::process::ExitCode;
#[cfg(test)]
use std::time::Duration;

use colored::{ColoredString, Colorize};
use reqwest::Client;

/// Render a `"high"` / `"medium"` / `"none"` severity string as the
/// canonical coloured badge the parser-diff family prints in its
/// per-probe summary. Extracted from 9 identical `match r.severity
/// { "high" => bright_red.bold, "medium" => yellow.bold, _ =>
/// bright_black }` blocks so a future palette tweak lives in one
/// place.
#[must_use]
pub fn severity_badge(severity: &str) -> ColoredString {
    match severity {
        "high" => severity.bright_red().bold(),
        "medium" => severity.yellow().bold(),
        _ => severity.bright_black(),
    }
}

/// Test-harness settle delay — the time tests sleep between
/// spawning a mock TCP listener + invoking the wafrift binary so
/// the listener is reliably accepting before the first probe.
/// Hardcoded as `Duration::from_millis(40)` in 17 cli test sites
/// pre-extract; lifting the constant means tuning it (e.g. for
/// slower CI runners) is one edit instead of 17.
///
/// Gated `#[cfg(test)]` because every caller is in a test block;
/// without the gate the bin compilation flags this as dead code.
#[cfg(test)]
pub const TEST_SETTLE: Duration = Duration::from_millis(40);

/// Print `value` to stdout as 2-space-indented JSON, or on
/// serialisation failure print a `JSON error: {e}` line to stderr
/// (matching the contract every parser-diff `--format json` arm
/// shipped pre-extract). Lifting the 4-line match means a future
/// `--no-color` / structured-error policy lives in one place.
pub fn print_pretty_json(value: &serde_json::Value) {
    match serde_json::to_string_pretty(value) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("JSON error: {e}"),
    }
}

use crate::scan::pentest_client;

/// Build the canonical parser-diff HTTP client.
///
/// Centralises the exact recipe every parser-diff cmd was open-coding:
/// per-request timeout, `--insecure` TLS-cert-verify bypass, limited-5
/// redirect chain (parser-diff probes follow redirects so a routing
/// probe lands on the right origin), the shared
/// [`crate::config::shared_user_agent`] so the operator-configured UA
/// flows through, and finally the pentest-plumbing of `--proxy` +
/// `-H/--header` via [`pentest_client::apply_pentest_flags`]. Errors
/// emit a red diagnostic on stderr and return `ExitCode::from(1)` —
/// matching the prior copy-pasted behaviour byte-for-byte so existing
/// CI gates keep their exit-code contract.
pub fn build_diff_http_client(
    timeout_secs: u64,
    insecure: bool,
    proxy: Option<&str>,
    headers: &[String],
) -> Result<Client, ExitCode> {
    let ua = crate::config::shared_user_agent();
    let mut builder = wafrift_transport::base_client_builder(timeout_secs, insecure, Some(&ua))
        .redirect(reqwest::redirect::Policy::limited(5));
    builder = pentest_client::apply_pentest_flags_or_print(builder, proxy, headers, None)?;
    builder.build().map_err(|e| {
        eprintln!("  {} {e}", "✗ Failed to build HTTP client:".red().bold());
        ExitCode::from(1)
    })
}

/// `(probe_len - baseline_len) / max(baseline_len, 1)` as a signed
/// percentage. Negative when the probe yields a shorter body.
/// When `baseline_len == 0`, returns `0.0` for matching empty probe
/// and `100.0` for any non-empty probe (avoids divide-by-zero
/// while preserving the "anything from nothing" signal).
///
/// **Implementation**: delegates to `respdiff::body_size_delta_pct`
/// via a synthetic `ResponseDiff`. Kept as a thin wrapper so the 11
/// parser-diff subcommands' (`baseline_len`, `probe_len`) call sites
/// don't have to construct snapshots, while the actual % formula
/// lives in respdiff (shared with every other Santh scanner).
#[must_use]
pub fn body_delta_pct(baseline_len: usize, probe_len: usize) -> f64 {
    let diff = synthetic_size_diff(baseline_len, probe_len);
    respdiff::body_size_delta_pct(&diff)
}

/// Classify one probe outcome relative to its baseline. `"high"` =
/// HTTP status class flipped (2xx ↔ 4xx ↔ 5xx); `"medium"` = body
/// length shifted by more than 20% with the same status class;
/// `"none"` otherwise.
///
/// **Implementation**: delegates to `respdiff::classify_severity`
/// with the default `DiffPolicy` (medium-threshold = 20%). Wrapper
/// retained so the 11 parser-diff subcommands keep their existing
/// `(u16, u16, f64) -> &'static str` signature while the rule lives
/// upstream.
#[must_use]
pub fn severity_of(baseline_status: u16, probe_status: u16, body_delta_pct: f64) -> &'static str {
    // Synthesize a ResponseDiff carrying just the inputs respdiff's
    // classifier looks at. body_size_delta_pct grading uses
    // baseline_body_size + current_body_size to recompute the %; we
    // round-trip a normalized 100/(100 + delta) pair that produces
    // exactly `body_delta_pct` when fed to body_size_delta_pct, so
    // the legacy f64 input domain stays bit-for-bit compatible.
    let (baseline_body_size, current_body_size) = size_pair_for_pct(body_delta_pct);
    let diff = respdiff::ResponseDiff {
        status_changed: baseline_status != probe_status,
        old_status: baseline_status,
        new_status: probe_status,
        new_headers: Vec::new(),
        missing_headers: Vec::new(),
        changed_headers: Vec::new(),
        body_size_delta: current_body_size as i64 - baseline_body_size as i64,
        timing_delta_ms: 0,
        body_similarity: 1.0,
        baseline_body_size,
        current_body_size,
    };
    match respdiff::classify_severity(&diff, &respdiff::DiffPolicy::default()) {
        respdiff::DiffSeverity::High => "high",
        respdiff::DiffSeverity::Medium => "medium",
        respdiff::DiffSeverity::Low | respdiff::DiffSeverity::None => "none",
    }
}

/// Build a respdiff `ResponseDiff` carrying only the two body-size
/// fields — enough for `body_size_delta_pct` to reconstruct the %.
fn synthetic_size_diff(baseline_len: usize, current_len: usize) -> respdiff::ResponseDiff {
    respdiff::ResponseDiff {
        status_changed: false,
        old_status: 200,
        new_status: 200,
        new_headers: Vec::new(),
        missing_headers: Vec::new(),
        changed_headers: Vec::new(),
        body_size_delta: current_len as i64 - baseline_len as i64,
        timing_delta_ms: 0,
        body_similarity: 1.0,
        baseline_body_size: baseline_len,
        current_body_size: current_len,
    }
}

/// Pick (baseline_body_size, current_body_size) such that
/// `respdiff::body_size_delta_pct` recovers `pct` to four decimals.
/// Lets the legacy `severity_of(u16, u16, f64)` signature route
/// through the percentage-based upstream classifier without changing
/// its API.
///
/// Why scale 1_000_000:
///   delta_pct = (current - baseline) / baseline * 100
///   With baseline=1_000_000 and current = baseline + round(pct * 10_000),
///   delta_pct = round(pct * 10_000) / 10_000 — precise to 0.0001%,
///   which beats the 0.01% precision the legacy callers depended on
///   (see `severity_of_at_exactly_20_pct_body_shift_is_not_medium`).
fn size_pair_for_pct(pct: f64) -> (usize, usize) {
    const BASELINE: i64 = 1_000_000;
    const SCALE: f64 = 10_000.0;
    let delta = if pct.is_finite() {
        (pct * SCALE).round() as i64
    } else {
        0
    };
    let current = (BASELINE + delta).max(0) as usize;
    (BASELINE as usize, current)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── body_delta_pct ────────────────────────────────────────

    #[test]
    fn body_delta_pct_is_zero_for_identical_sizes() {
        assert!((body_delta_pct(1000, 1000) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn body_delta_pct_positive_for_larger_probe() {
        assert!((body_delta_pct(100, 200) - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn body_delta_pct_negative_for_smaller_probe() {
        assert!((body_delta_pct(100, 50) - (-50.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn body_delta_pct_handles_zero_baseline_with_empty_probe() {
        assert_eq!(body_delta_pct(0, 0), 0.0);
    }

    #[test]
    fn body_delta_pct_handles_zero_baseline_with_non_empty_probe() {
        assert_eq!(body_delta_pct(0, 500), 100.0);
        assert_eq!(body_delta_pct(0, 1), 100.0);
    }

    // ── severity_of ───────────────────────────────────────────

    #[test]
    fn severity_of_is_high_when_status_class_flips_up() {
        assert_eq!(severity_of(200, 403, 0.0), "high");
        assert_eq!(severity_of(200, 500, 0.0), "high");
    }

    #[test]
    fn severity_of_is_high_when_status_class_flips_down() {
        assert_eq!(severity_of(403, 200, 0.0), "high");
        assert_eq!(severity_of(500, 200, 0.0), "high");
    }

    #[test]
    fn severity_of_is_medium_when_body_shifts_with_status_preserved() {
        assert_eq!(severity_of(200, 200, 25.0), "medium");
        assert_eq!(severity_of(200, 200, -25.0), "medium");
    }

    #[test]
    fn severity_of_is_none_when_status_preserved_and_body_close() {
        assert_eq!(severity_of(200, 200, 5.0), "none");
        assert_eq!(severity_of(200, 200, -5.0), "none");
        assert_eq!(severity_of(200, 200, 0.0), "none");
    }

    #[test]
    fn severity_of_status_within_same_class_is_not_high() {
        // 200 → 204 stays 2xx; body_delta drives instead.
        assert_eq!(severity_of(200, 204, 5.0), "none");
        assert_eq!(severity_of(200, 204, 30.0), "medium");
    }

    #[test]
    fn severity_of_at_exactly_20_pct_body_shift_is_not_medium() {
        // The threshold is STRICTLY GREATER than 20.0 — exactly 20.0
        // stays "none". Anti-rig against off-by-one threshold drift.
        assert_eq!(severity_of(200, 200, 20.0), "none");
        assert_eq!(severity_of(200, 200, -20.0), "none");
        assert_eq!(severity_of(200, 200, 20.01), "medium");
    }

    // status_class lives upstream in respdiff (covered by
    // `respdiff::diff::tests::status_class_collapses_to_century`).
}
