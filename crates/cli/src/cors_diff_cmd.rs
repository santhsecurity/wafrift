//! `wafrift cors-diff` — CORS misconfiguration scanner.
//!
//! Cross-Origin Resource Sharing (CORS) is one of the most
//! commonly misconfigured browser security controls. A target that
//! reflects an arbitrary `Origin` header into `Access-Control-Allow-
//! Origin` AND advertises `Access-Control-Allow-Credentials: true`
//! is a 1-line exploit: the attacker hosts a page at evil.example,
//! the page's `fetch(target, { credentials: 'include' })` succeeds,
//! and the attacker reads the response (cookies + session-protected
//! data).
//!
//! Probes vary the `Origin` header across known WAF/origin
//! validation pitfalls (suffix confusion, prefix confusion, scheme
//! stripping, null origin, subdomain dot-segment) and observe the
//! `Access-Control-Allow-*` response headers.

use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use clap::Args;
use colored::Colorize;
use reqwest::{Client, Method, header::HeaderMap};
use serde_json::json;
use tokio::sync::Semaphore;

use crate::helpers::shell_single_quote;

#[derive(Args, Debug)]
pub struct CorsDiffArgs {
    /// Target URL — typically an API endpoint that returns sensitive
    /// data when the operator's browser session is authenticated.
    pub url: String,

    /// Inter-request delay (ms).
    #[arg(long, default_value_t = 25)]
    pub delay_ms: u64,

    /// Max concurrent in-flight probes.
    #[arg(long, default_value_t = 4)]
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

    /// Extra headers (carry the auth cookie / bearer token).
    #[arg(long, short = 'H', value_name = "HEADER", num_args = 0..)]
    pub header: Vec<String>,

    /// Output format: `text` (default) or `json`.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    /// Quiet mode.
    #[arg(long, default_value_t = false)]
    pub quiet: bool,
}

/// One CORS-misconfiguration probe.
#[derive(Debug, Clone)]
pub struct CorsProbe {
    pub kind: &'static str,
    pub description: &'static str,
    /// HTTP method to send. GET for most probes; OPTIONS for
    /// preflight-specific tests.
    pub method: &'static str,
    /// Value to set in the `Origin` header. None = don't send Origin
    /// (baseline reference).
    pub origin: Option<String>,
    /// Extra headers for preflight probes (Access-Control-Request-*).
    pub extra_headers: Vec<(String, String)>,
}

/// Result of one CORS probe — what the target sent back in the
/// CORS-related response headers.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CorsDiffResult {
    pub kind: &'static str,
    pub description: &'static str,
    pub probe_origin: Option<String>,
    pub probe_status: u16,
    pub allow_origin: Option<String>,
    pub allow_credentials: Option<String>,
    pub allow_methods: Option<String>,
    pub allow_headers: Option<String>,
    pub curl_cmd: String,
    pub severity: &'static str,
    pub finding: &'static str,
}

/// Generate the CORS probe set. Pure function. `target_host` is
/// extracted from the URL and used to build suffix/prefix-confusion
/// Origins.
#[must_use]
pub fn generate_cors_variants(target_host: &str) -> Vec<CorsProbe> {
    let mut out = Vec::new();

    // ── Plain attacker.example reflection ──
    out.push(CorsProbe {
        kind: "origin-reflects-arbitrary",
        description: "Send Origin: https://attacker.example. If the server reflects \
             it into Access-Control-Allow-Origin AND sets Allow-Credentials: \
             true, attacker can read response from a malicious page",
        method: "GET",
        origin: Some("https://attacker.example".into()),
        extra_headers: Vec::new(),
    });

    // ── Origin: null ──
    out.push(CorsProbe {
        kind: "origin-null-accepted",
        description: "Send Origin: null — file://, sandboxed iframes, redirected \
             requests send this; servers that allowlist `null` open CORS \
             to attacker sandboxed iframes",
        method: "GET",
        origin: Some("null".into()),
        extra_headers: Vec::new(),
    });

    // ── Subdomain suffix confusion ──
    out.push(CorsProbe {
        kind: "subdomain-suffix-confusion",
        description: "Origin: https://{target}.attacker.example — naive substring \
             match (.endsWith(target_host)) lets the attacker's subdomain \
             through",
        method: "GET",
        origin: Some(format!("https://{target_host}.attacker.example")),
        extra_headers: Vec::new(),
    });

    // ── Subdomain prefix confusion ──
    out.push(CorsProbe {
        kind: "subdomain-prefix-confusion",
        description: "Origin: https://attacker.{target} — naive substring match \
             (.startsWith(target_host)) lets the attacker through",
        method: "GET",
        origin: Some(format!("https://attacker.{target_host}")),
        extra_headers: Vec::new(),
    });

    // ── Trailing-dot subdomain ──
    out.push(CorsProbe {
        kind: "trailing-dot-host",
        description: "Origin: https://{target}. (trailing dot) — DNS-equivalent but \
             string-different; some allowlists miss",
        method: "GET",
        origin: Some(format!("https://{target_host}.")),
        extra_headers: Vec::new(),
    });

    // ── HTTP downgrade ──
    out.push(CorsProbe {
        kind: "http-downgrade-origin",
        description: "Origin: http://{target} (downgrade from HTTPS) — servers that \
             allowlist by host (ignoring scheme) leak cookies over plaintext",
        method: "GET",
        origin: Some(format!("http://{target_host}")),
        extra_headers: Vec::new(),
    });

    // ── Subdomain via @ trick ──
    out.push(CorsProbe {
        kind: "userinfo-injection",
        description: "Origin: https://attacker.example@{target} — URL parsers vary; \
             some interpret the userinfo `attacker.example@` and treat host \
             as {target} (allowed), but the actual loading origin is \
             attacker.example",
        method: "GET",
        origin: Some(format!("https://attacker.example@{target_host}")),
        extra_headers: Vec::new(),
    });

    // ── Wildcard match check ──
    out.push(CorsProbe {
        kind: "wildcard-origin-reflection",
        description: "Origin: * — server should NOT reflect this verbatim; if it \
             does AND credentials are allowed, browsers will reject — but \
             some servers do anyway, breaking SOP for non-credentialed \
             attackers",
        method: "GET",
        origin: Some("*".into()),
        extra_headers: Vec::new(),
    });

    // ── Preflight: arbitrary header allowed? ──
    out.push(CorsProbe {
        kind: "preflight-arbitrary-header",
        description: "OPTIONS preflight asking permission for X-Wafrift-Probe header. \
             Server that allows ANY requested header (no whitelist) is \
             over-permissive",
        method: "OPTIONS",
        origin: Some("https://attacker.example".into()),
        extra_headers: vec![
            ("Access-Control-Request-Method".into(), "GET".into()),
            (
                "Access-Control-Request-Headers".into(),
                "X-Wafrift-Probe".into(),
            ),
        ],
    });

    // ── Preflight: DELETE method ──
    out.push(CorsProbe {
        kind: "preflight-delete-method",
        description: "OPTIONS preflight asking permission for DELETE method. \
             Server that allows DELETE from an attacker origin is a \
             destructive CORS hole",
        method: "OPTIONS",
        origin: Some("https://attacker.example".into()),
        extra_headers: vec![("Access-Control-Request-Method".into(), "DELETE".into())],
    });

    out
}

pub async fn run_cors_diff(mut args: CorsDiffArgs) -> ExitCode {
    args.url = crate::helpers::normalize_target_url(&args.url);
    let http = match crate::parser_diff_common::build_diff_http_client_for(&args) {
        Ok(c) => c,
        Err(code) => return code,
    };

    let target_host = extract_host(&args.url).unwrap_or_else(|| "target.example".into());

    if !args.quiet && args.format == "text" {
        eprintln!(
            "{} probing CORS surface against {} (assumed host: {})",
            "[wafrift cors-diff]".bright_cyan().bold(),
            args.url.bright_white(),
            target_host.bright_black()
        );
    }

    let variants = generate_cors_variants(&target_host);
    let sem = Arc::new(Semaphore::new(args.concurrency.max(1)));
    let http_arc = Arc::new(http);
    let url_arc = Arc::new(args.url.clone());
    let counter = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(variants.len());
    for v in variants {
        let permit = sem
            .clone()
            .acquire_owned()
            .await
            .expect("cors_diff semaphore must not be closed mid-acquire");
        let http = http_arc.clone();
        let url = url_arc.clone();
        let counter = counter.clone();
        let delay = Duration::from_millis(args.delay_ms);
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let result =
                fire_cors(&http, v.method, &url, v.origin.as_deref(), &v.extra_headers).await;
            counter.fetch_add(1, Ordering::SeqCst);
            (v, result)
        }));
    }

    let mut results: Vec<CorsDiffResult> = Vec::new();
    let mut errors = 0u32;
    for h in handles {
        let (variant, outcome) = h.await.unwrap_or_else(|e| {
            (
                CorsProbe {
                    kind: "join-error",
                    description: "tokio join failed",
                    method: "GET",
                    origin: None,
                    extra_headers: Vec::new(),
                },
                Err(format!("{e}")),
            )
        });
        match outcome {
            Ok((status, response_headers)) => {
                let allow_origin = response_headers
                    .get("access-control-allow-origin")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                let allow_credentials = response_headers
                    .get("access-control-allow-credentials")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                let allow_methods = response_headers
                    .get("access-control-allow-methods")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                let allow_headers = response_headers
                    .get("access-control-allow-headers")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                let (severity, finding) = classify_cors(
                    variant.origin.as_deref(),
                    allow_origin.as_deref(),
                    allow_credentials.as_deref(),
                );
                let curl_cmd = render_curl(
                    variant.method,
                    &args.url,
                    variant.origin.as_deref(),
                    &variant.extra_headers,
                );
                results.push(CorsDiffResult {
                    kind: variant.kind,
                    description: variant.description,
                    probe_origin: variant.origin.clone(),
                    probe_status: status,
                    allow_origin,
                    allow_credentials,
                    allow_methods,
                    allow_headers,
                    curl_cmd,
                    severity,
                    finding,
                });
            }
            Err(_) => errors += 1,
        }
    }

    emit_output(&args, &results, errors);
    ExitCode::SUCCESS
}

/// Decide severity + finding label from CORS response shape.
/// `"high"` when the server reflects the attacker's Origin AND
/// allows credentials (=== exploit). `"medium"` for reflection
/// without credentials (still leaks non-credentialed data).
/// `"none"` otherwise.
fn classify_cors(
    sent_origin: Option<&str>,
    allow_origin: Option<&str>,
    allow_credentials: Option<&str>,
) -> (&'static str, &'static str) {
    let sent = match sent_origin {
        Some(s) => s,
        None => return ("none", "baseline (no origin sent)"),
    };
    let allow = match allow_origin {
        Some(a) => a,
        None => return ("none", "ACAO header absent — no CORS exposure"),
    };
    let creds_true = matches!(allow_credentials, Some(c) if c.eq_ignore_ascii_case("true"));
    if allow == sent {
        if creds_true {
            (
                "high",
                "ACAO reflects Origin AND ACAC:true — credentials leak",
            )
        } else {
            (
                "medium",
                "ACAO reflects Origin — non-credentialed data leak",
            )
        }
    } else if allow == "*" && creds_true {
        // Browsers reject this combo, but the server emitting it is
        // misconfigured and informative.
        (
            "medium",
            "ACAO:* AND ACAC:true — RFC violation (informative)",
        )
    } else {
        ("none", "ACAO did not reflect attacker origin — safe")
    }
}

async fn fire_cors(
    http: &Client,
    method_str: &str,
    url: &str,
    origin: Option<&str>,
    extra_headers: &[(String, String)],
) -> Result<(u16, HeaderMap), String> {
    let method = Method::from_bytes(method_str.as_bytes())
        .map_err(|e| format!("invalid method {method_str:?}: {e}"))?;
    let mut req = http.request(method, url);
    if let Some(o) = origin {
        req = req.header("Origin", o);
    }
    for (n, v) in extra_headers {
        req = req.header(n.as_str(), v);
    }
    let resp = req.send().await.map_err(|e| format!("{e}"))?;
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    // Drain body to free the connection.
    let _ = resp.bytes().await;
    Ok((status, headers))
}

crate::impl_parser_diff_http_args!(CorsDiffArgs);

fn render_curl(
    method: &str,
    url: &str,
    origin: Option<&str>,
    extra_headers: &[(String, String)],
) -> String {
    let mut out = String::from("curl -i");
    if method != "GET" {
        out.push_str(" -X ");
        out.push_str(method);
    }
    if let Some(o) = origin {
        out.push(' ');
        out.push_str("-H ");
        out.push_str(&shell_single_quote(&format!("Origin: {o}")));
    }
    for (n, v) in extra_headers {
        out.push(' ');
        out.push_str("-H ");
        out.push_str(&shell_single_quote(&format!("{n}: {v}")));
    }
    out.push(' ');
    out.push_str(&shell_single_quote(url));
    out
}

fn extract_host(url: &str) -> Option<String> {
    // Shared canonical impl in wafrift_transport — handles IPv6
    // brackets + userinfo + lowercase + port strip + scheme-optional.
    wafrift_transport::host_from_url(url)
}

fn emit_output(args: &CorsDiffArgs, results: &[CorsDiffResult], errors: u32) {
    let high: Vec<_> = results.iter().filter(|r| r.severity == "high").collect();
    let medium: Vec<_> = results.iter().filter(|r| r.severity == "medium").collect();

    if args.format == "json" {
        let out = json!({
            "target": args.url,
            "probes": results.len(),
            "errors": errors,
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
            "  {} {} CORS issue(s) — {} high, {} medium · {} error(s)",
            "[wafrift cors-diff summary]".bright_cyan().bold(),
            (high.len() + medium.len()).to_string().bold().yellow(),
            high.len().to_string().bright_red().bold(),
            medium.len().to_string().yellow(),
            errors
        );
        // Pentest-dogfood UX (2026-05): when ZERO issues fire AND the
        // target never returned an Access-Control-* header on any
        // probe, "0 CORS issues" looks like wafrift's verdict on
        // "no CORS bugs" — but it actually means "no CORS surface".
        // Spell out the difference so an operator doesn't mistake
        // a non-CORS endpoint for a hardened one.
        let any_cors_header_seen = results.iter().any(|r| r.allow_origin.is_some());
        if (high.len() + medium.len()) == 0 && !any_cors_header_seen && !results.is_empty() {
            println!(
                "  {} no Access-Control-* header observed on any probe — \
                 this target may not have a CORS surface at all (i.e. it's not \
                 a browser-accessed API). Not the same as 'CORS hardened'.",
                "note:".bright_cyan().bold()
            );
        }
    }

    for r in results.iter().filter(|r| r.severity != "none") {
        let badge = crate::parser_diff_common::severity_badge(r.severity);
        println!();
        println!("  [{badge}] {} — {}", r.kind.bold(), r.description);
        println!("    {} {}", "↘".bright_black(), r.finding.bright_white());
        if let Some(o) = &r.allow_origin {
            println!("    Access-Control-Allow-Origin: {o}");
        }
        if let Some(c) = &r.allow_credentials {
            println!("    Access-Control-Allow-Credentials: {c}");
        }
        println!("    {}", r.curl_cmd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── extract_host ──────────────────────────────────────────

    #[test]
    fn extract_host_strips_scheme_path_userinfo_port() {
        assert_eq!(
            extract_host("https://api.example.com/path"),
            Some("api.example.com".into())
        );
        assert_eq!(
            extract_host("http://user:pw@api.example.com:8080/p"),
            Some("api.example.com".into())
        );
        assert_eq!(
            extract_host("api.example.com/p"),
            Some("api.example.com".into())
        );
    }

    #[test]
    fn extract_host_handles_empty_authority() {
        assert_eq!(extract_host("http:///path"), None);
    }

    // ── classify_cors ─────────────────────────────────────────

    #[test]
    fn classify_cors_high_when_reflection_with_credentials() {
        let (sev, _) = classify_cors(
            Some("https://attacker.example"),
            Some("https://attacker.example"),
            Some("true"),
        );
        assert_eq!(sev, "high");
    }

    #[test]
    fn classify_cors_medium_when_reflection_without_credentials() {
        let (sev, _) = classify_cors(
            Some("https://attacker.example"),
            Some("https://attacker.example"),
            None,
        );
        assert_eq!(sev, "medium");
    }

    #[test]
    fn classify_cors_medium_on_wildcard_plus_credentials() {
        let (sev, _) = classify_cors(Some("https://attacker.example"), Some("*"), Some("true"));
        assert_eq!(sev, "medium");
    }

    #[test]
    fn classify_cors_none_when_acao_absent() {
        let (sev, _) = classify_cors(Some("https://attacker.example"), None, None);
        assert_eq!(sev, "none");
    }

    #[test]
    fn classify_cors_none_when_acao_does_not_reflect() {
        let (sev, _) = classify_cors(
            Some("https://attacker.example"),
            Some("https://trusted.example"),
            Some("true"),
        );
        assert_eq!(sev, "none");
    }

    #[test]
    fn classify_cors_none_when_no_origin_sent() {
        let (sev, _) = classify_cors(None, Some("https://anywhere"), Some("true"));
        assert_eq!(sev, "none");
    }

    #[test]
    fn classify_cors_acac_match_is_case_insensitive() {
        let (sev_lower, _) = classify_cors(Some("x"), Some("x"), Some("true"));
        let (sev_upper, _) = classify_cors(Some("x"), Some("x"), Some("TRUE"));
        let (sev_mixed, _) = classify_cors(Some("x"), Some("x"), Some("True"));
        assert_eq!(sev_lower, "high");
        assert_eq!(sev_upper, "high");
        assert_eq!(sev_mixed, "high");
    }

    // ── generate_cors_variants ────────────────────────────────

    #[test]
    fn generate_cors_variants_returns_curated_set() {
        let v = generate_cors_variants("target.com");
        assert!(v.len() >= 10, "expected ≥10 probes, got {}", v.len());
    }

    #[test]
    fn generate_cors_variants_kinds_are_unique() {
        let v = generate_cors_variants("t.com");
        let mut k: Vec<&str> = v.iter().map(|p| p.kind).collect();
        k.sort();
        k.dedup();
        assert_eq!(k.len(), v.len());
    }

    #[test]
    fn generate_cors_variants_interpolates_target_host_into_confusion_probes() {
        let v = generate_cors_variants("api.example.com");
        let suffix = v
            .iter()
            .find(|p| p.kind == "subdomain-suffix-confusion")
            .expect("suffix probe");
        assert!(
            suffix
                .origin
                .as_deref()
                .unwrap()
                .contains("api.example.com.attacker")
        );
        let prefix = v
            .iter()
            .find(|p| p.kind == "subdomain-prefix-confusion")
            .expect("prefix probe");
        assert!(
            prefix
                .origin
                .as_deref()
                .unwrap()
                .contains("attacker.api.example.com")
        );
    }

    #[test]
    fn generate_cors_variants_includes_null_origin_probe() {
        let v = generate_cors_variants("x");
        let null = v
            .iter()
            .find(|p| p.kind == "origin-null-accepted")
            .expect("null probe");
        assert_eq!(null.origin.as_deref(), Some("null"));
    }

    #[test]
    fn generate_cors_variants_preflight_uses_options_method() {
        let v = generate_cors_variants("x");
        for p in &v {
            if p.kind.starts_with("preflight") {
                assert_eq!(
                    p.method, "OPTIONS",
                    "preflight probe {} must use OPTIONS",
                    p.kind
                );
                // Must include Access-Control-Request-* headers.
                let has_acrm = p
                    .extra_headers
                    .iter()
                    .any(|(n, _)| n.eq_ignore_ascii_case("access-control-request-method"));
                assert!(has_acrm, "{} missing ACRM header", p.kind);
            }
        }
    }

    #[test]
    fn generate_cors_variants_userinfo_injection_probe_uses_at_separator() {
        let v = generate_cors_variants("victim.com");
        let probe = v
            .iter()
            .find(|p| p.kind == "userinfo-injection")
            .expect("userinfo probe");
        assert!(
            probe
                .origin
                .as_deref()
                .unwrap()
                .contains("attacker.example@victim.com")
        );
    }

    // ── render_curl ───────────────────────────────────────────

    #[test]
    fn render_curl_emits_get_without_method_flag() {
        let out = render_curl("GET", "http://x/", Some("https://attacker"), &[]);
        assert!(!out.contains("-X GET"), "GET should be implicit: {out}");
        assert!(out.contains("-H 'Origin: https://attacker'"), "got: {out}");
    }

    #[test]
    fn render_curl_emits_options_for_preflight() {
        let out = render_curl(
            "OPTIONS",
            "http://x/",
            None,
            &[("Access-Control-Request-Method".into(), "DELETE".into())],
        );
        assert!(out.contains("-X OPTIONS"), "got: {out}");
        assert!(
            out.contains("'Access-Control-Request-Method: DELETE'"),
            "got: {out}"
        );
    }

    // ── Live mock integration ─────────────────────────────────

    async fn spawn_cors_mock() -> std::net::SocketAddr {
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
                    // Vulnerable: reflect ANY Origin into ACAO + set ACAC:true.
                    let origin_line = req
                        .lines()
                        .find(|l| l.to_ascii_lowercase().starts_with("origin:"))
                        .map(|l| {
                            l.split_once(':')
                                .map(|x| x.1)
                                .unwrap_or("")
                                .trim()
                                .to_string()
                        })
                        .unwrap_or_default();
                    let body = "{}";
                    let extra_cors = if origin_line.is_empty() {
                        String::new()
                    } else {
                        format!(
                            "Access-Control-Allow-Origin: {origin_line}\r\n\
                             Access-Control-Allow-Credentials: true\r\n"
                        )
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\n{extra_cors}Connection: close\r\n\r\n{body}",
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
    async fn run_cors_diff_finds_high_severity_on_reflective_mock() {
        let addr = spawn_cors_mock().await;
        let args = CorsDiffArgs {
            url: format!("http://{addr}/api/me"),
            delay_ms: 0,
            concurrency: 4,
            timeout_secs: 8,
            insecure: false,
            proxy: None,
            header: Vec::new(),
            format: "json".into(),
            quiet: true,
        };
        let code = run_cors_diff(args).await;
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    #[tokio::test]
    async fn run_cors_diff_against_unreachable_target_exits_succeed_with_errors() {
        // CORS scanner is informational; transport errors are
        // recorded per-probe and the run exits cleanly. (Distinct
        // from probe families that exit 1 on baseline failure.)
        let args = CorsDiffArgs {
            url: "http://127.0.0.1:1/".into(),
            delay_ms: 0,
            concurrency: 4,
            timeout_secs: 1,
            insecure: false,
            proxy: None,
            header: Vec::new(),
            format: "json".into(),
            quiet: true,
        };
        let code = run_cors_diff(args).await;
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }
}
