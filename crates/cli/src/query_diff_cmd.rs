//! `wafrift query-diff` — WAF / origin parser-disagreement scanner
//! for URL QUERY STRINGS.
//!
//! ## The innovation
//!
//! Fourth command in the parser-diff family (after `parser-diff` for
//! URL paths, `header-diff` for headers, `body-diff` for request
//! bodies). Same idea, applied to the query-string: WAFs and origin
//! frameworks routinely DISAGREE on how to parse the bytes after
//! `?`. Each disagreement is a seam an operator can exploit.
//!
//! Examples of WAF↔origin query-parse disagreements:
//!
//! - **HPP — HTTP Parameter Pollution.** `?q=safe&q=attack` — PHP
//!   keeps the LAST occurrence; ASP.NET joins with comma; Java
//!   typically picks the FIRST. WAFs that scan only the first
//!   occurrence miss the attack value.
//! - **Array notation.** `?q[]=safe&q[]=attack` — PHP / Express
//!   parse as `q = ["safe", "attack"]`; many WAFs see a literal
//!   parameter name `q[]` and never match a `q` rule.
//! - **Comma split.** `?q=a,b,c` — some parsers expose as a single
//!   string, others split into a list. WAF rules that check the
//!   whole string miss attack-payload values hidden inside the
//!   comma-separated set.
//! - **Empty-value HPP.** `?q=&q=attack` — first occurrence is
//!   empty; WAFs that bail on empty values never see the attack.
//! - **Missing-value parameter.** `?q&attack=1` — depending on
//!   parser, `q` becomes `""`, `None`, or the next token. Some
//!   WAFs misparse and let `attack=1` ride through.
//! - **Percent-encoded key name.** `?%71=attack` (decoded as
//!   `q=attack`) — WAFs that match by raw key-string never see a
//!   `q` parameter; origins that URL-decode keys before lookup do.
//! - **Trailing percent + null in value.** `?q=safe%00.attack` —
//!   C-style truncation parsers see `safe`, Python sees `safe\0.attack`.
//! - **Fragment leak via percent-encoded `#`.** `?q=attack%23` —
//!   the literal `#` AFTER decoding can confuse parsers that
//!   re-encode + re-split.
//! - **Semicolon as separator.** `?a=1;b=2` — RFC 3986 reserves
//!   `;` in query; some parsers (notably old PHP, Tomcat
//!   defaults) split on it.
//!
//! ## Probe shape
//!
//! Each probe sends one HTTP GET to `<target>?<variant>` and
//! compares the response to a baseline probe `<target>?q=safe`.
//! Divergence in response status or body length is evidence the
//! WAF and origin treated the query string differently.

use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use clap::Args;
use colored::Colorize;
use serde_json::json;
use tokio::sync::Semaphore;

use crate::helpers::shell_single_quote;
use crate::parser_diff_common::{body_delta_pct, severity_of};

#[derive(Args, Debug)]
pub struct QueryDiffArgs {
    /// Target URL. The path is fixed; we vary only the query string.
    /// Pick a route the operator suspects the WAF gates via
    /// query-param inspection (search, lookup, login).
    pub url: String,

    /// Baseline parameter name — used both for the reference probe
    /// (`?<param>=safe`) and as the parameter the variants target.
    #[arg(long, default_value = "q")]
    pub param: String,

    /// Inter-request delay (ms).
    #[arg(long, default_value_t = 25)]
    pub delay_ms: u64,

    /// Max concurrent in-flight probes.
    #[arg(long, default_value_t = 8)]
    pub concurrency: usize,

    /// HTTP timeout per probe (seconds).
    #[arg(long, default_value_t = 8)]
    pub timeout_secs: u64,

    /// Skip TLS cert verification.
    #[arg(long)]
    pub insecure: bool,

    /// HTTP proxy (Burp).
    #[arg(long, value_name = "URL")]
    pub proxy: Option<String>,

    /// Extra headers (`-H 'Name: Value'`, repeatable).
    #[arg(long, short = 'H', value_name = "HEADER", num_args = 0..)]
    pub header: Vec<String>,

    /// Output format: `text` (default) or `json`.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    /// Quiet mode — suppress per-probe progress.
    #[arg(long, default_value_t = false)]
    pub quiet: bool,
}

/// One query-parse-disagreement probe.
#[derive(Debug, Clone)]
pub struct QueryDisagreement {
    /// Stable short identifier.
    pub kind: &'static str,
    /// Human description.
    pub description: &'static str,
    /// The literal query string (without the leading `?`).
    pub query: String,
}

/// Result of one query-diff probe.
#[derive(Debug, Clone, serde::Serialize)]
pub struct QueryDiffResult {
    pub kind: &'static str,
    pub description: &'static str,
    pub query: String,
    pub probe_status: u16,
    pub baseline_status: u16,
    pub body_delta_pct: f64,
    pub baseline_body_len: usize,
    pub probe_body_len: usize,
    pub curl_cmd: String,
    pub severity: &'static str,
}

/// Generate the query-disagreement variant set. Pure function.
/// `param` is the canonical parameter name; `attack_token` is
/// interpolated into the "attack" slot of every variant so the
/// operator can grep responses for it.
#[must_use]
pub fn generate_query_variants(param: &str, attack_token: &str) -> Vec<QueryDisagreement> {
    let mut out = Vec::new();

    // ── 1. HPP — duplicate parameter ─────────────────────────
    out.push(QueryDisagreement {
        kind: "hpp-last-wins",
        description: "Duplicate parameter — PHP / Express take the LAST occurrence; WAFs that \
             scan the first never see the attack value",
        query: format!("{param}=safe&{param}={attack_token}"),
    });
    out.push(QueryDisagreement {
        kind: "hpp-first-wins",
        description: "Duplicate parameter — Java Servlet / Tomcat take the FIRST; WAFs that \
             scan the last never see the attack value",
        query: format!("{param}={attack_token}&{param}=safe"),
    });

    // ── 2. Array notation ────────────────────────────────────
    out.push(QueryDisagreement {
        kind: "array-bracket-notation",
        description: "PHP / Express array notation: `q[]=safe&q[]=attack` parses to a list. \
             WAFs that match by exact key string see `q[]`, not `q`",
        query: format!("{param}[]=safe&{param}[]={attack_token}"),
    });

    // ── 3. Comma split ───────────────────────────────────────
    out.push(QueryDisagreement {
        kind: "comma-split",
        description: "Comma-separated values — some parsers expose as one string, others split \
             into a list; WAF substring rules miss attack hidden in a comma cell",
        query: format!("{param}=safe,{attack_token},neutral"),
    });

    // ── 4. Empty-value HPP ───────────────────────────────────
    out.push(QueryDisagreement {
        kind: "empty-value-hpp",
        description: "First occurrence is empty value; second carries the attack. WAFs that \
             bail on empty values short-circuit before scanning the second",
        query: format!("{param}=&{param}={attack_token}"),
    });

    // ── 5. Missing value ─────────────────────────────────────
    out.push(QueryDisagreement {
        kind: "missing-value",
        description: "Parameter without `=` — parsers disagree on whether the value is `\"\"`, \
             `None`, or the next token. Bypass via parser-confusion",
        query: format!("{param}&attack={attack_token}"),
    });

    // ── 6. Percent-encoded key name ─────────────────────────
    // `%71` decodes to 'q'. Test for `param=="q"` only; otherwise
    // emit a generic full-percent-encoded version of the key.
    let pct_key: String = if param == "q" {
        format!("%71={attack_token}")
    } else {
        let mut s = String::new();
        for b in param.bytes() {
            s.push_str(&format!("%{b:02X}"));
        }
        s.push('=');
        s.push_str(attack_token);
        s
    };
    out.push(QueryDisagreement {
        kind: "percent-encoded-key",
        description: "Key name is percent-encoded — origins URL-decode keys before lookup; \
             WAFs that match by raw key-string never see the canonical name",
        query: pct_key,
    });

    // ── 7. NUL truncation in value ───────────────────────────
    out.push(QueryDisagreement {
        kind: "nul-truncate-value",
        description: "Value contains NUL — C-style parsers truncate at NUL (see safe prefix); \
             Python / Java pass the full string with NUL embedded; the WAF sees the \
             attack and blocks if the rule fires, but the origin only processes \
             whatever comes BEFORE the NUL — a divergence-of-action seam",
        query: format!("{param}=safe%00.{attack_token}"),
    });

    // ── 8. Semicolon as separator ────────────────────────────
    out.push(QueryDisagreement {
        kind: "semicolon-separator",
        description: "`?a=1;b=2` — RFC 3986 reserves `;` in query; old PHP / Tomcat defaults \
             split on it. WAF rule scanning the literal `a=1;b=2` may miss `b=2`",
        query: format!("{param}=safe;attack={attack_token}"),
    });

    // ── 9. Fragment-style encoded `#` ────────────────────────
    out.push(QueryDisagreement {
        kind: "encoded-hash-leak",
        description: "Encoded `%23` (`#`) in value — origins that decode-then-re-split treat \
             it as a fragment delimiter; bypass for rules that match the literal \
             encoded form",
        query: format!("{param}={attack_token}%23frag"),
    });

    // ── 10. Trailing dot in key ──────────────────────────────
    out.push(QueryDisagreement {
        kind: "trailing-dot-key",
        description: "`q.=attack` — some frameworks (Django) collapse trailing dots in keys; \
             WAFs scanning raw `q.` miss the `q` lookup",
        query: format!("{param}.={attack_token}"),
    });

    out
}

pub async fn run_query_diff(args: QueryDiffArgs) -> ExitCode {
    let http = match crate::parser_diff_common::build_diff_http_client_for(&args) {
        Ok(c) => c,
        Err(code) => return code,
    };

    if !args.quiet && args.format == "text" {
        eprintln!(
            "{} probing {} query parser-disagreement families against {}",
            "[wafrift query-diff]".bright_cyan().bold(),
            generate_query_variants(&args.param, "WAFRIFT_ATTACK_TOKEN")
                .len()
                .to_string()
                .bold()
                .yellow(),
            args.url.bright_white()
        );
    }

    // Baseline: same URL with ?param=safe.
    // F80 retry-on-baseline-flake: a transient connection drop
    // (target exhausted its conn pool after a heavy scan, brief
    // network blip, WAF rate-limited the very first probe) used
    // to exit 1 immediately. In real CI the next-second probe
    // would have succeeded — pre-fix the operator saw a false
    // "tool failure". Retry up to 3 times with 200/400/800 ms
    // backoff before giving up.
    let baseline_url = format!("{}?{}=safe", args.url.trim_end_matches('?'), args.param);
    let baseline = {
        let mut last_err: Option<String> = None;
        let mut delay_ms = 200u64;
        let mut result: Option<(u16, usize)> = None;
        for attempt in 1..=3u32 {
            match fire_get(&http, &baseline_url).await {
                Ok(pair) => {
                    result = Some(pair);
                    break;
                }
                Err(e) => {
                    last_err = Some(e);
                    if attempt < 3 {
                        if !args.quiet && args.format == "text" {
                            eprintln!(
                                "  {} baseline attempt {attempt}/3 failed; retrying in {delay_ms}ms",
                                "…".yellow()
                            );
                        }
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                        delay_ms = delay_ms.saturating_mul(2);
                    }
                }
            }
        }
        match result {
            Some(pair) => pair,
            None => {
                eprintln!(
                    "  {} baseline probe failed after 3 attempts: {}",
                    "✗ Transport error:".red().bold(),
                    last_err.as_deref().unwrap_or("<no error>")
                );
                return ExitCode::from(1);
            }
        }
    };
    let (baseline_status, baseline_body_len) = baseline;
    if !args.quiet && args.format == "text" {
        eprintln!(
            "  {} baseline: HTTP {} ({} bytes)",
            "↘".bright_black(),
            baseline_status,
            baseline_body_len
        );
    }

    let variants = generate_query_variants(&args.param, "WAFRIFT_ATTACK_TOKEN");
    let sem = Arc::new(Semaphore::new(args.concurrency.max(1)));
    let http_arc = Arc::new(http);
    let url_arc = Arc::new(args.url.clone());
    let counter = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(variants.len());
    for v in variants {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let http = http_arc.clone();
        let url = url_arc.clone();
        let counter = counter.clone();
        let delay = Duration::from_millis(args.delay_ms);
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let probe_url = format!("{}?{}", url.trim_end_matches('?'), v.query);
            let result = fire_get(&http, &probe_url).await;
            counter.fetch_add(1, Ordering::SeqCst);
            (v, result)
        }));
    }

    let mut results: Vec<QueryDiffResult> = Vec::new();
    let mut errors = 0u32;
    for h in handles {
        let (variant, outcome) = h.await.unwrap_or_else(|e| {
            (
                QueryDisagreement {
                    kind: "join-error",
                    description: "tokio join failed",
                    query: String::new(),
                },
                Err(format!("{e}")),
            )
        });
        match outcome {
            Ok((probe_status, probe_body_len)) => {
                let body_delta = body_delta_pct(baseline_body_len, probe_body_len);
                let severity = severity_of(baseline_status, probe_status, body_delta);
                let probe_url = format!("{}?{}", args.url.trim_end_matches('?'), variant.query);
                let curl_cmd = render_curl(&probe_url);
                results.push(QueryDiffResult {
                    kind: variant.kind,
                    description: variant.description,
                    query: variant.query.clone(),
                    probe_status,
                    baseline_status,
                    body_delta_pct: body_delta,
                    baseline_body_len,
                    probe_body_len,
                    curl_cmd,
                    severity,
                });
            }
            Err(_) => errors += 1,
        }
    }

    emit_output(&args, &results, baseline_status, baseline_body_len, errors);
    ExitCode::SUCCESS
}

crate::impl_parser_diff_http_args!(QueryDiffArgs);

use crate::parser_diff_common::fire_get_status_len as fire_get;

fn render_curl(url: &str) -> String {
    format!("curl -i {}", shell_single_quote(url))
}

fn emit_output(
    args: &QueryDiffArgs,
    results: &[QueryDiffResult],
    baseline_status: u16,
    baseline_body_len: usize,
    errors: u32,
) {
    let high: Vec<_> = results.iter().filter(|r| r.severity == "high").collect();
    let medium: Vec<_> = results.iter().filter(|r| r.severity == "medium").collect();

    if args.format == "json" {
        let out = json!({
            "target": args.url,
            "param": args.param,
            "baseline_status": baseline_status,
            "baseline_body_len": baseline_body_len,
            "probes": results.len(),
            "errors": errors,
            "divergences": {
                "high": high.len(),
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
            "  {} {} divergence(s) — {} high, {} medium · {} error(s)",
            "[wafrift query-diff summary]".bright_cyan().bold(),
            (high.len() + medium.len()).to_string().bold().yellow(),
            high.len().to_string().bright_red().bold(),
            medium.len().to_string().yellow(),
            errors
        );
    }

    for r in results.iter().filter(|r| r.severity != "none") {
        let badge = crate::parser_diff_common::severity_badge(r.severity);
        println!();
        println!("  [{badge}] {} — {}", r.kind.bold(), r.description);
        println!(
            "    {} baseline HTTP {} ({} bytes) → probe HTTP {} ({} bytes, Δ {:+.1}%)",
            "↘".bright_black(),
            r.baseline_status,
            r.baseline_body_len,
            r.probe_status,
            r.probe_body_len,
            r.body_delta_pct
        );
        println!("    query: {}", r.query);
        println!("    {}", r.curl_cmd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── generate_query_variants ───────────────────────────────

    #[test]
    fn generate_query_variants_returns_non_empty_curated_set() {
        let v = generate_query_variants("q", "ATTACK");
        assert!(
            v.len() >= 10,
            "expected at least 10 probes, got {}",
            v.len()
        );
    }

    #[test]
    fn generate_query_variants_kinds_are_unique() {
        let v = generate_query_variants("q", "ATTACK");
        let mut kinds: Vec<&str> = v.iter().map(|p| p.kind).collect();
        kinds.sort();
        kinds.dedup();
        assert_eq!(kinds.len(), v.len());
    }

    #[test]
    fn generate_query_variants_every_probe_has_non_empty_query() {
        for p in generate_query_variants("q", "ATTACK") {
            assert!(!p.query.is_empty(), "probe {} query empty", p.kind);
        }
    }

    #[test]
    fn generate_query_variants_is_deterministic() {
        let a = generate_query_variants("q", "X");
        let b = generate_query_variants("q", "X");
        let a_kinds: Vec<&str> = a.iter().map(|p| p.kind).collect();
        let b_kinds: Vec<&str> = b.iter().map(|p| p.kind).collect();
        assert_eq!(a_kinds, b_kinds);
    }

    #[test]
    fn generate_query_variants_interpolates_param_name() {
        // Custom param name must appear in every variant query.
        let v = generate_query_variants("search", "ATTACK");
        for p in &v {
            // Either the literal `search` name appears, OR the
            // percent-encoded variant (the percent-encoded-key
            // probe). Both are valid presence forms.
            let has_param = p.query.contains("search") || p.query.contains("%73%65%61%72%63%68");
            assert!(
                has_param,
                "probe {} must reference the custom param name: query={}",
                p.kind, p.query
            );
        }
    }

    #[test]
    fn generate_query_variants_interpolates_attack_token() {
        let v = generate_query_variants("q", "WAFRIFT_ATTACK_TOKEN_XYZ");
        let any = v
            .iter()
            .any(|p| p.query.contains("WAFRIFT_ATTACK_TOKEN_XYZ"));
        assert!(any, "no probe carries attack token");
    }

    #[test]
    fn generate_query_variants_covers_hpp_family() {
        let kinds: Vec<&str> = generate_query_variants("q", "X")
            .iter()
            .map(|p| p.kind)
            .collect();
        assert!(
            kinds.iter().any(|k| k.starts_with("hpp")),
            "must cover HPP family"
        );
    }

    #[test]
    fn generate_query_variants_covers_array_notation() {
        let v = generate_query_variants("q", "X");
        let arr = v
            .iter()
            .find(|p| p.kind == "array-bracket-notation")
            .expect("array-bracket-notation probe");
        assert!(
            arr.query.contains("q[]"),
            "array probe must use bracket notation: {}",
            arr.query
        );
    }

    #[test]
    fn generate_query_variants_handles_custom_param_for_percent_encoded_key() {
        // When param != "q", the percent-encoded-key probe falls
        // back to fully percent-encoding every byte. Confirm.
        let v = generate_query_variants("user", "ATK");
        let p = v
            .iter()
            .find(|p| p.kind == "percent-encoded-key")
            .expect("percent-encoded-key probe");
        // Every char of "user" should be percent-encoded.
        assert!(p.query.contains("%75%73%65%72"), "got: {}", p.query);
    }

    // ── render_curl ───────────────────────────────────────────

    #[test]
    fn render_curl_emits_curl_dash_i_with_quoted_url() {
        let out = render_curl("http://x/?q=a");
        assert_eq!(out, "curl -i 'http://x/?q=a'");
    }

    #[test]
    fn render_curl_escapes_apostrophe_in_url() {
        let out = render_curl("http://x/?q=a'b");
        assert!(out.contains("'http://x/?q=a'\\''b'"), "got: {out}");
    }

    // ── Live mock integration ─────────────────────────────────

    async fn spawn_query_aware_mock() -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8 * 1024];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    // Simulate a parser that returns a long body
                    // when the request line contains the attack
                    // token anywhere.
                    let leaked = req.contains("WAFRIFT_ATTACK_TOKEN");
                    let body: String = if leaked {
                        "<html>attack token observed in query — long body</html>".into()
                    } else {
                        "<html>baseline</html>".into()
                    };
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
    async fn run_query_diff_against_mock_succeeds() {
        let addr = spawn_query_aware_mock().await;
        let args = QueryDiffArgs {
            url: format!("http://{addr}/"),
            param: "q".into(),
            delay_ms: 0,
            concurrency: 4,
            timeout_secs: 8,
            insecure: false,
            proxy: None,
            header: Vec::new(),
            format: "json".into(),
            quiet: true,
        };
        let code = run_query_diff(args).await;
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    #[tokio::test]
    async fn run_query_diff_against_unreachable_target_exits_1() {
        let args = QueryDiffArgs {
            url: "http://127.0.0.1:1/".into(),
            param: "q".into(),
            delay_ms: 0,
            concurrency: 4,
            timeout_secs: 2,
            insecure: false,
            proxy: None,
            header: Vec::new(),
            format: "json".into(),
            quiet: true,
        };
        let code = run_query_diff(args).await;
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(1)));
    }
}
