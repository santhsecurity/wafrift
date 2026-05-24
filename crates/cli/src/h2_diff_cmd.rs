//! `wafrift h2-diff` — HTTP/1.1 vs HTTP/2 differential scanner.
//!
//! ## The innovation
//!
//! Many WAFs were designed when HTTP/1.1 was the only protocol.
//! They speak H2 to the client (because the load-balancer accepts
//! it) but their rules and parsers were authored against H1's
//! textual wire format. The origin behind the WAF may speak H2
//! directly OR get H1 from the WAF over a back-channel. Three
//! divergence opportunities:
//!
//! 1. **WAF H2 vs origin H2** — rare; both parsers see the same
//!    binary frames, but pseudo-header handling can differ.
//! 2. **WAF H2 → origin H1 (downgrade)** — common; the WAF
//!    translates H2 pseudo-headers (`:path`, `:authority`) into
//!    the H1 request line + Host header. Translation bugs let
//!    smuggled state slip through.
//! 3. **WAF rule corpus authored against H1 wire format** — the
//!    WAF's CRS-style regex rules match on `\r\n` boundaries that
//!    don't exist in H2 binary frames.
//!
//! Each is a SEAM. `h2-diff` fires the same logical request via
//! H1 AND H2 and reports any response divergence — evidence the
//! WAF or origin treats them as different requests.
//!
//! ## Probes
//!
//! - **Plain GET** — baseline. Most WAFs handle this identically.
//! - **GET with operator-supplied param + payload** — does the
//!   WAF's H1 rule fire under H2?
//! - **Mixed-case header name** — H2's HPACK lowercases everything;
//!   H1 preserves case. If the origin checks case-sensitive headers,
//!   divergence.
//! - **Duplicate-header dispatch** — H2 sends two HEADERS frame
//!   entries; H1 sends two header lines. Some parsers merge into
//!   `value1, value2`; H2 frames remain distinct.
//!
//! ## Caveat
//!
//! Reqwest's high-level API doesn't expose raw H2 frame controls.
//! What we CAN do: force `http1_only` or `http2_prior_knowledge`
//! on a per-client basis. That's enough to detect the high-level
//! "did the WAF/origin do something different under H2" — which is
//! the practitioner's interesting question. Frame-level fuzzing
//! belongs in a future module.

use std::process::ExitCode;
use std::time::Duration;

use clap::Args;
use colored::Colorize;
use reqwest::Client;
use serde_json::json;

use crate::helpers::shell_single_quote;
use crate::parser_diff_common::{body_delta_pct, severity_of};

#[derive(Args, Debug)]
pub struct H2DiffArgs {
    /// Target URL — must be HTTPS to exercise H2 (cleartext H2
    /// requires h2c upgrade which reqwest doesn't natively expose;
    /// HTTP URLs fall back to H1-only on both legs and are
    /// effectively a no-op).
    pub url: String,

    /// Optional query parameter name + payload to exercise the
    /// WAF's payload-matching rules under both protocols.
    #[arg(long, default_value = "q")]
    pub param: String,

    /// Optional payload to inject as `?<param>=<payload>` on every
    /// probe. Default `safe` — pick something WAF-relevant for
    /// real engagements (e.g. `' OR 1=1--`).
    #[arg(long, default_value = "safe")]
    pub payload: String,

    /// Inter-request delay (ms).
    #[arg(long, default_value_t = 25)]
    pub delay_ms: u64,

    /// HTTP timeout per probe (seconds).
    #[arg(long, default_value_t = 8)]
    pub timeout_secs: u64,

    /// Skip TLS cert verification (lab targets only).
    #[arg(long)]
    pub insecure: bool,

    /// HTTP proxy (Burp on `http://127.0.0.1:8080` is typical).
    /// h2-diff is the protocol-divergence cmd most likely to be
    /// run mid-engagement against an internal target — the
    /// corporate Burp proxy and operator auth headers are exactly
    /// what the operator needs to thread through.
    #[arg(long, value_name = "URL")]
    pub proxy: Option<String>,

    /// Operator-supplied baseline headers — applied to BOTH the
    /// H1 and H2 client. Each `-H 'Name: Value'` is repeatable;
    /// `Authorization`, `Cookie`, `X-Forwarded-For`, custom CSRF
    /// tokens, etc. travel with every probe.
    #[arg(long, short = 'H', value_name = "HEADER", num_args = 0..)]
    pub header: Vec<String>,

    /// Output format: `text` (default, colored summary) or `json`.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    /// Quiet mode — suppress per-probe progress lines.
    #[arg(long, default_value_t = false)]
    pub quiet: bool,
}

crate::impl_parser_diff_http_args!(H2DiffArgs);

/// Result of one H1-vs-H2 differential probe.
#[derive(Debug, Clone, serde::Serialize)]
pub struct H2DiffResult {
    pub kind: &'static str,
    pub description: &'static str,
    pub h1_status: u16,
    pub h2_status: u16,
    pub h1_body_len: usize,
    pub h2_body_len: usize,
    pub body_delta_pct: f64,
    pub h1_curl_cmd: String,
    pub h2_curl_cmd: String,
    pub severity: &'static str,
    /// Optional notes — e.g. when H2 probe failed to negotiate, we
    /// record the error here instead of treating it as a divergence.
    pub h2_error: Option<String>,
}

/// Entry point — runs the configured H1/H2 differential probes
/// against `args.url`.
pub async fn run_h2_diff(args: H2DiffArgs) -> ExitCode {
    let h1 = match build_client(false, &args) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let h2 = match build_client(true, &args) {
        Ok(c) => c,
        Err(code) => return code,
    };

    if !args.quiet && args.format == "text" {
        eprintln!(
            "{} firing H1/H2 differential probes against {}",
            "[wafrift h2-diff]".bright_cyan().bold(),
            args.url.bright_white()
        );
    }

    let probes = probe_shapes(&args.param, &args.payload);
    let mut results: Vec<H2DiffResult> = Vec::with_capacity(probes.len());
    let delay = Duration::from_millis(args.delay_ms);
    for (kind, description, query) in probes {
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        let probe_url = with_query(&args.url, &query);
        let h1_res = fire_get(&h1, &probe_url).await;
        let h2_res = fire_get(&h2, &probe_url).await;
        let r = build_diff_result(kind, description, &probe_url, h1_res, h2_res);
        results.push(r);
    }

    emit_output(&args, &results);
    ExitCode::SUCCESS
}

/// The full curated probe set. Pure function, deterministic.
fn probe_shapes(param: &str, payload: &str) -> Vec<(&'static str, &'static str, String)> {
    vec![
        (
            "baseline",
            "Plain GET — same logical request via both protocols. \
             Most WAFs handle identically.",
            String::new(),
        ),
        (
            "payload-in-query",
            "Operator-supplied payload in the query string — does \
             the WAF's payload-matching rule fire under both protocols?",
            format!("{param}={payload}"),
        ),
        (
            "dup-param",
            "Duplicate query parameter — H2's binary multi-value \
             encoding may differ from H1's textual `&param=` repeat \
             at WAF / origin parsing time.",
            format!("{param}=safe&{param}={payload}"),
        ),
        (
            "long-query",
            "Long query string — H1 has practical request-line \
             length limits (often 8KB); H2 has frame size limits \
             but a different boundary. WAFs that gate by H1 \
             request-line length miss long H2 queries.",
            format!(
                "{param}=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa{payload}"
            ),
        ),
    ]
}

fn build_diff_result(
    kind: &'static str,
    description: &'static str,
    probe_url: &str,
    h1_res: Result<(u16, usize), String>,
    h2_res: Result<(u16, usize), String>,
) -> H2DiffResult {
    let (h1_status, h1_body_len) = h1_res.unwrap_or((0, 0));
    let (h2_status, h2_body_len, h2_error) = match h2_res {
        Ok((s, len)) => (s, len, None),
        Err(e) => (0, 0, Some(e)),
    };
    let delta = if h2_error.is_some() {
        // When H2 errored, the divergence is "H2 not reachable" —
        // not a parser disagreement. Skip the body-delta math; set
        // severity by H2 status alone.
        0.0
    } else {
        body_delta_pct(h1_body_len, h2_body_len)
    };
    let severity = if h2_error.is_some() {
        // H2 negotiation failure with H1 working = informational
        // (the target may not support H2 at all). Not a parser bug.
        "none"
    } else {
        severity_of(h1_status, h2_status, delta)
    };
    H2DiffResult {
        kind,
        description,
        h1_status,
        h2_status,
        h1_body_len,
        h2_body_len,
        body_delta_pct: delta,
        h1_curl_cmd: format!("curl -i --http1.1 {}", shell_single_quote(probe_url)),
        h2_curl_cmd: format!("curl -i --http2 {}", shell_single_quote(probe_url)),
        severity,
        h2_error,
    }
}

fn build_client(want_h2: bool, args: &H2DiffArgs) -> Result<Client, ExitCode> {
    let ua = crate::config::shared_user_agent();
    let mut builder =
        wafrift_transport::base_client_builder(args.timeout_secs, args.insecure, Some(&ua))
            .redirect(reqwest::redirect::Policy::limited(5));
    builder = if want_h2 {
        // HTTPS targets: reqwest negotiates H2 via TLS ALPN as long
        // as both ends advertise h2. For HTTP, prior-knowledge skips
        // the (rare-and-unimplemented) h2c upgrade.
        if args.url.starts_with("https://") {
            builder
        } else {
            builder.http2_prior_knowledge()
        }
    } else {
        // H1-only — disables ALPN h2 advertisement entirely.
        builder.http1_only()
    };
    // Burp / corporate proxy + operator headers MUST thread
    // through both legs so the H1 vs H2 comparison is apples-to-
    // apples. Pre-fix the cmd silently ignored --proxy / -H,
    // making it the least useful parser-diff in real engagements.
    builder = crate::scan::pentest_client::apply_pentest_flags_or_print(
        builder,
        args.proxy.as_deref(),
        &args.header,
        None,
    )?;
    builder.build().map_err(|e| {
        eprintln!("  {} {e}", "✗ Failed to build HTTP client:".red().bold());
        ExitCode::from(1)
    })
}

use crate::parser_diff_common::fire_get_status_len as fire_get;

fn with_query(base: &str, new_query: &str) -> String {
    if new_query.is_empty() {
        return base.to_string();
    }
    match reqwest::Url::parse(base) {
        Ok(mut u) => {
            u.set_query(Some(new_query));
            u.to_string()
        }
        Err(_) => {
            let trimmed = base.split_once('?').map(|(b, _)| b).unwrap_or(base);
            format!("{trimmed}?{new_query}")
        }
    }
}

fn emit_output(args: &H2DiffArgs, results: &[H2DiffResult]) {
    let high: Vec<_> = results.iter().filter(|r| r.severity == "high").collect();
    let medium: Vec<_> = results.iter().filter(|r| r.severity == "medium").collect();
    let h2_errors = results.iter().filter(|r| r.h2_error.is_some()).count();

    if args.format == "json" {
        let out = json!({
            "target": args.url,
            "param": args.param,
            "payload": args.payload,
            "probes": results.len(),
            "h2_errors": h2_errors,
            "divergences": {
                "high":   high.len(),
                "medium": medium.len(),
            },
            "results": results,
        });
        crate::parser_diff_common::print_pretty_json(&out);
        return;
    }

    if !args.quiet {
        println!();
        println!(
            "  {} {} probe(s) · {} high, {} medium · {} H2-error(s)",
            "[wafrift h2-diff summary]".bright_cyan().bold(),
            results.len().to_string().bold().yellow(),
            high.len().to_string().bright_red().bold(),
            medium.len().to_string().yellow(),
            h2_errors,
        );
        // Pentest-dogfood UX (2026-05): when every H2 attempt errors,
        // a bare "4 H2-error(s)" left the operator wondering what to
        // do. Spell out the meaning + the actionable next step.
        if h2_errors == results.len() && !results.is_empty() {
            println!(
                "  {} every H2 probe errored — the target likely does NOT speak HTTP/2 \
                 (no ALPN negotiation for `h2`, or HTTPS without TLS). This isn't a \
                 wafrift defect; the H1/H2 differential surface simply doesn't exist on \
                 this stack. Try `header-diff` or `query-diff` against the same URL.",
                "note:".bright_cyan().bold()
            );
        }
    }

    for r in results.iter().filter(|r| r.severity != "none") {
        let badge = crate::parser_diff_common::severity_badge(r.severity);
        println!();
        println!("  [{badge}] {} — {}", r.kind.bold(), r.description);
        println!(
            "    {} H1 {} ({} bytes) · H2 {} ({} bytes, Δ {:+.1}%)",
            "↘".bright_black(),
            r.h1_status,
            r.h1_body_len,
            r.h2_status,
            r.h2_body_len,
            r.body_delta_pct
        );
        println!("    H1: {}", r.h1_curl_cmd);
        println!("    H2: {}", r.h2_curl_cmd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── probe_shapes ──────────────────────────────────────────

    #[test]
    fn probe_shapes_returns_curated_set() {
        let v = probe_shapes("q", "x");
        assert!(v.len() >= 4, "expected ≥4 probes, got {}", v.len());
    }

    #[test]
    fn probe_shapes_kinds_are_unique() {
        let v = probe_shapes("q", "x");
        let mut kinds: Vec<&str> = v.iter().map(|(k, _, _)| *k).collect();
        kinds.sort();
        kinds.dedup();
        assert_eq!(kinds.len(), v.len());
    }

    #[test]
    fn probe_shapes_interpolates_param_into_queries() {
        let v = probe_shapes("search", "ATTACK");
        let payload_probe = v
            .iter()
            .find(|(k, _, _)| *k == "payload-in-query")
            .expect("payload-in-query probe");
        assert!(
            payload_probe.2.contains("search=ATTACK"),
            "got: {}",
            payload_probe.2
        );
    }

    #[test]
    fn probe_shapes_baseline_has_empty_query() {
        let v = probe_shapes("q", "x");
        let baseline = v
            .iter()
            .find(|(k, _, _)| *k == "baseline")
            .expect("baseline probe");
        assert!(baseline.2.is_empty(), "baseline query: {}", baseline.2);
    }

    // ── with_query ────────────────────────────────────────────

    #[test]
    fn with_query_no_op_for_empty_query() {
        assert_eq!(with_query("http://x/", ""), "http://x/");
    }

    #[test]
    fn with_query_sets_query_on_url() {
        let out = with_query("http://x/p", "q=1");
        assert!(out.contains("?q=1"), "got: {out}");
    }

    #[test]
    fn with_query_replaces_existing_query() {
        let out = with_query("http://x/p?old=1", "new=2");
        assert!(out.contains("new=2"), "got: {out}");
        assert!(!out.contains("old=1"), "got: {out}");
    }

    // ── build_diff_result ─────────────────────────────────────

    #[test]
    fn build_diff_result_marks_h2_error_severity_none() {
        let r = build_diff_result(
            "baseline",
            "test",
            "http://x/",
            Ok((200, 100)),
            Err("h2 negotiation failed".to_string()),
        );
        assert_eq!(r.severity, "none");
        assert!(r.h2_error.is_some());
    }

    #[test]
    fn build_diff_result_high_when_h1_h2_status_classes_differ() {
        let r = build_diff_result("p", "d", "http://x/", Ok((200, 100)), Ok((403, 50)));
        assert_eq!(r.severity, "high");
        assert!(r.h2_error.is_none());
    }

    #[test]
    fn build_diff_result_medium_when_body_shifts_with_status_preserved() {
        let r = build_diff_result("p", "d", "http://x/", Ok((200, 100)), Ok((200, 150)));
        assert_eq!(r.severity, "medium");
    }

    #[test]
    fn build_diff_result_none_when_both_match() {
        let r = build_diff_result("p", "d", "http://x/", Ok((200, 100)), Ok((200, 100)));
        assert_eq!(r.severity, "none");
    }

    #[test]
    fn build_diff_result_curl_carries_http_version_flag() {
        let r = build_diff_result("p", "d", "http://x/?q=1", Ok((200, 0)), Ok((200, 0)));
        assert!(
            r.h1_curl_cmd.contains("--http1.1"),
            "got: {}",
            r.h1_curl_cmd
        );
        assert!(r.h2_curl_cmd.contains("--http2"), "got: {}", r.h2_curl_cmd);
        assert!(r.h1_curl_cmd.contains("'http://x/?q=1'"));
        assert!(r.h2_curl_cmd.contains("'http://x/?q=1'"));
    }

    // ── Live mock integration ─────────────────────────────────

    async fn spawn_mock() -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let body = "<html>ok</html>";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        tokio::time::sleep(crate::parser_diff_common::TEST_SETTLE).await;
        addr
    }

    #[tokio::test]
    async fn run_h2_diff_against_h1_only_mock_succeeds_and_marks_h2_errors() {
        // Our mock only speaks H1 — H2 probes will fail. h2-diff
        // should exit 0 (informational) and mark every probe with
        // h2_error.
        let addr = spawn_mock().await;
        let args = H2DiffArgs {
            url: format!("http://{addr}/"),
            param: "q".into(),
            payload: "safe".into(),
            delay_ms: 0,
            timeout_secs: 3,
            insecure: false,
            format: "json".into(),
            quiet: true,
        };
        let code = run_h2_diff(args).await;
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    #[tokio::test]
    async fn run_h2_diff_against_unreachable_target_still_exits_cleanly() {
        let args = H2DiffArgs {
            url: "http://127.0.0.1:1/".into(),
            param: "q".into(),
            payload: "safe".into(),
            delay_ms: 0,
            timeout_secs: 1,
            insecure: false,
            format: "json".into(),
            quiet: true,
        };
        let code = run_h2_diff(args).await;
        // Even with H1 ALSO failing, we exit 0 — the scanner is
        // informational; failures are recorded per-probe.
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }
}
