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
//! - `status_class(status)` — `status / 100`.
//!
//! Every parser-diff subcommand also builds its `reqwest::Client`
//! from the exact same recipe: operator timeout + `--insecure` +
//! limited-5 redirect + the shared `User-Agent` + `--proxy` /
//! `--header` plumbing via `pentest_client::apply_pentest_flags`.
//! Pre-extract, that was 22 lines copy-pasted across nine command
//! files — one line at a time, drifting each time someone tuned
//! e.g. the redirect limit in one file but not the others.
//!
//! These rules live HERE so a fix to the classification logic
//! reaches all subcommands in one edit — the architectural
//! commitment from `feedback_architecture_and_dedup`.

use std::process::ExitCode;
use std::time::Duration;

use colored::Colorize;
use reqwest::Client;

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
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .danger_accept_invalid_certs(insecure)
        .redirect(reqwest::redirect::Policy::limited(5))
        .user_agent(crate::config::shared_user_agent());
    builder = match pentest_client::apply_pentest_flags(builder, proxy, headers, None) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("  {} {e}", "✗ pentest flag invalid:".red().bold());
            return Err(ExitCode::from(1));
        }
    };
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
#[must_use]
pub fn body_delta_pct(baseline_len: usize, probe_len: usize) -> f64 {
    if baseline_len == 0 {
        return if probe_len == 0 { 0.0 } else { 100.0 };
    }
    ((probe_len as f64 - baseline_len as f64) / baseline_len as f64) * 100.0
}

/// Classify one probe outcome relative to its baseline. `"high"` =
/// HTTP status class flipped (2xx ↔ 4xx ↔ 5xx); `"medium"` = body
/// length shifted by more than 20% with the same status class;
/// `"none"` otherwise.
#[must_use]
pub fn severity_of(baseline_status: u16, probe_status: u16, body_delta_pct: f64) -> &'static str {
    if status_class(baseline_status) != status_class(probe_status) {
        "high"
    } else if body_delta_pct.abs() > 20.0 {
        "medium"
    } else {
        "none"
    }
}

/// `status / 100` — the 1xx / 2xx / 3xx / 4xx / 5xx class.
#[must_use]
pub fn status_class(status: u16) -> u16 {
    status / 100
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

    // ── status_class ──────────────────────────────────────────

    #[test]
    fn status_class_buckets_by_hundreds() {
        assert_eq!(status_class(100), 1);
        assert_eq!(status_class(200), 2);
        assert_eq!(status_class(204), 2);
        assert_eq!(status_class(301), 3);
        assert_eq!(status_class(404), 4);
        assert_eq!(status_class(500), 5);
        assert_eq!(status_class(599), 5);
    }
}
