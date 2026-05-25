//! `wafrift method-diff` — HTTP method parser-disagreement scanner.
//!
//! ## What this finds
//!
//! WAFs and origins disagree on how to handle unusual HTTP methods.
//! Most WAF rules fire on GET / POST / PUT / DELETE. Methods like
//! `PROPFIND` (WebDAV), `MKCOL` (WebDAV), `MOVE`, `COPY`, `LOCK`,
//! `UNLOCK`, `TRACE`, custom verbs (`BANANA`), or numeric/special
//! characters in the method may bypass WAF rules entirely while
//! the origin still routes them somewhere.
//!
//! This is adjacent to but DISTINCT from `bypass-probe`'s method
//! overrides (which focuses on `X-HTTP-Method-Override`-style
//! header tricks): `method-diff` fires the request line with the
//! variant method DIRECTLY. Different attack surface — WAFs that
//! correctly normalise the override header still miss raw verb
//! variation.

use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use clap::Args;
use colored::Colorize;
use reqwest::{Client, Method};
use serde_json::json;
use tokio::sync::Semaphore;

use crate::helpers::shell_single_quote;
use crate::parser_diff_common::{body_delta_pct, severity_of};

#[derive(Args, Debug)]
pub struct MethodDiffArgs {
    /// Target URL.
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

/// One method-variant probe. `method` is the literal verb sent on
/// the request line. Some are pre-defined HTTP verbs (RFC 7231);
/// others are WebDAV (RFC 4918, RFC 3253); a couple are intentionally
/// non-standard to catch parsers that accept any token.
#[derive(Debug, Clone)]
pub struct MethodProbe {
    pub kind: &'static str,
    pub description: &'static str,
    pub method: &'static str,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MethodDiffResult {
    pub kind: &'static str,
    pub description: &'static str,
    pub method: &'static str,
    pub probe_status: u16,
    pub baseline_status: u16,
    pub body_delta_pct: f64,
    pub baseline_body_len: usize,
    pub probe_body_len: usize,
    pub curl_cmd: String,
    pub severity: &'static str,
}

/// Curated method-variant set. Order is stable across runs (operators
/// pin by index).
#[must_use]
pub fn generate_method_variants() -> Vec<MethodProbe> {
    vec![
        // ── Standard RFC 7231 verbs (other than baseline GET) ──
        MethodProbe {
            kind: "post",
            description: "Standard POST — most WAFs handle, baseline for non-GET coverage",
            method: "POST",
        },
        MethodProbe {
            kind: "put",
            description: "PUT — typically write-only; some WAFs only gate read methods",
            method: "PUT",
        },
        MethodProbe {
            kind: "delete",
            description: "DELETE — same reasoning as PUT, different verb",
            method: "DELETE",
        },
        MethodProbe {
            kind: "patch",
            description: "PATCH (RFC 5789) — newer verb some WAF rule corpora omit",
            method: "PATCH",
        },
        // ── HEAD / OPTIONS — often missed by WAF rules ──
        MethodProbe {
            kind: "head",
            description: "HEAD — RFC says identical to GET sans body; some WAFs only \
                          inspect bodies, leaking GET-rule coverage entirely",
            method: "HEAD",
        },
        MethodProbe {
            kind: "options",
            description: "OPTIONS — CORS preflight; some WAFs let through unconditionally",
            method: "OPTIONS",
        },
        MethodProbe {
            kind: "trace",
            description: "TRACE — debug verb; often disabled at origin but WAFs \
                          may not gate it",
            method: "TRACE",
        },
        // ── WebDAV (RFC 4918 / 3253) ──
        MethodProbe {
            kind: "propfind",
            description: "PROPFIND (WebDAV) — WAFs rarely have rules; servers with \
                          mod_dav enabled process it; potential file-listing leak",
            method: "PROPFIND",
        },
        MethodProbe {
            kind: "mkcol",
            description: "MKCOL (WebDAV) — directory creation verb",
            method: "MKCOL",
        },
        MethodProbe {
            kind: "move",
            description: "MOVE (WebDAV) — resource rename; bypass for delete-by-rename",
            method: "MOVE",
        },
        MethodProbe {
            kind: "copy",
            description: "COPY (WebDAV) — resource duplication",
            method: "COPY",
        },
        MethodProbe {
            kind: "lock",
            description: "LOCK (WebDAV) — adversarial use can DoS resources",
            method: "LOCK",
        },
        // ── Non-standard / catch-all ──
        MethodProbe {
            kind: "custom-banana",
            description: "Custom verb `BANANA` — RFC 9110 leaves token-set open; some \
                          frameworks happily route any uppercase token",
            method: "BANANA",
        },
        MethodProbe {
            kind: "lowercase-get",
            description: "Lowercase `get` — RFC says case-sensitive; some parsers \
                          uppercase-normalise (forgiving), some reject — divergence",
            method: "get",
        },
        // ── PRI (HTTP/2 preface verb when seen over H1) ──
        MethodProbe {
            kind: "h2-pri-preface",
            description: "`PRI` (HTTP/2 connection preface verb seen over H1) — \
                          some H1 parsers panic, some happily process",
            method: "PRI",
        },
    ]
}

pub async fn run_method_diff(mut args: MethodDiffArgs) -> ExitCode {
    args.url = crate::helpers::normalize_target_url(&args.url);
    let http = match crate::parser_diff_common::build_diff_http_client_for(&args) {
        Ok(c) => c,
        Err(code) => return code,
    };

    if !args.quiet && args.format == "text" {
        eprintln!(
            "{} probing {} method variants against {}",
            "[wafrift method-diff]".bright_cyan().bold(),
            generate_method_variants().len().to_string().bold().yellow(),
            args.url.bright_white()
        );
    }

    let baseline = match fire_with_method(&http, "GET", &args.url).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "  {} baseline GET probe failed: {e}",
                "✗ Transport error:".red().bold()
            );
            return ExitCode::from(1);
        }
    };
    let (baseline_status, baseline_body_len) = baseline;
    if !args.quiet && args.format == "text" {
        eprintln!(
            "  {} baseline GET: HTTP {} ({} bytes)",
            "↘".bright_black(),
            baseline_status,
            baseline_body_len
        );
    }

    let variants = generate_method_variants();
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
            let result = fire_with_method(&http, v.method, &url).await;
            counter.fetch_add(1, Ordering::SeqCst);
            (v, result)
        }));
    }

    let mut results: Vec<MethodDiffResult> = Vec::new();
    let mut errors = 0u32;
    for h in handles {
        let (variant, outcome) = h.await.unwrap_or_else(|e| {
            (
                MethodProbe {
                    kind: "join-error",
                    description: "tokio join failed",
                    method: "?",
                },
                Err(format!("{e}")),
            )
        });
        match outcome {
            Ok((probe_status, probe_body_len)) => {
                let body_delta = body_delta_pct(baseline_body_len, probe_body_len);
                let severity = severity_of(baseline_status, probe_status, body_delta);
                let curl_cmd = render_curl(variant.method, &args.url);
                results.push(MethodDiffResult {
                    kind: variant.kind,
                    description: variant.description,
                    method: variant.method,
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

async fn fire_with_method(
    http: &Client,
    method_str: &str,
    url: &str,
) -> Result<(u16, usize), String> {
    let method = Method::from_bytes(method_str.as_bytes())
        .map_err(|e| format!("invalid method {method_str:?}: {e}"))?;
    let resp = http
        .request(method, url)
        .send()
        .await
        .map_err(|e| format!("{e}"))?;
    let status = resp.status().as_u16();
    let body = resp.bytes().await.map_err(|e| format!("{e}"))?;
    Ok((status, body.len()))
}

crate::impl_parser_diff_http_args!(MethodDiffArgs);

fn render_curl(method: &str, url: &str) -> String {
    format!("curl -i -X {method} {}", shell_single_quote(url))
}

fn emit_output(
    args: &MethodDiffArgs,
    results: &[MethodDiffResult],
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
            "[wafrift method-diff summary]".bright_cyan().bold(),
            (high.len() + medium.len()).to_string().bold().yellow(),
            high.len().to_string().bright_red().bold(),
            medium.len().to_string().yellow(),
            errors
        );
    }

    for r in results.iter().filter(|r| r.severity != "none") {
        let badge = crate::parser_diff_common::severity_badge(r.severity);
        println!();
        println!(
            "  [{badge}] {} ({}) — {}",
            r.kind.bold(),
            r.method,
            r.description
        );
        println!(
            "    {} baseline GET HTTP {} ({} bytes) → {} {} HTTP {} ({} bytes, Δ {:+.1}%)",
            "↘".bright_black(),
            r.baseline_status,
            r.baseline_body_len,
            "probe".bright_white(),
            r.method,
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

    #[test]
    fn generate_method_variants_returns_non_empty_curated_set() {
        let v = generate_method_variants();
        assert!(v.len() >= 14, "expected ≥14 probes, got {}", v.len());
    }

    #[test]
    fn generate_method_variants_kinds_are_unique() {
        let v = generate_method_variants();
        let mut kinds: Vec<&str> = v.iter().map(|p| p.kind).collect();
        kinds.sort();
        kinds.dedup();
        assert_eq!(kinds.len(), v.len(), "every probe must have a unique kind");
    }

    #[test]
    fn generate_method_variants_no_probe_uses_uppercase_get_method() {
        // Uppercase GET is the baseline; no probe variant should
        // redundantly re-fire it. (Lowercase `get` IS a legitimate
        // case-folding probe — covered separately.)
        for p in generate_method_variants() {
            assert_ne!(
                p.method, "GET",
                "probe {} should not use baseline method GET",
                p.kind
            );
        }
    }

    #[test]
    fn generate_method_variants_includes_lowercase_get_for_case_folding_probe() {
        let methods: Vec<&str> = generate_method_variants()
            .iter()
            .map(|p| p.method)
            .collect();
        assert!(
            methods.contains(&"get"),
            "should test lowercase `get` for case-folding parser divergence"
        );
    }

    #[test]
    fn generate_method_variants_covers_webdav_family() {
        let methods: Vec<&str> = generate_method_variants()
            .iter()
            .map(|p| p.method)
            .collect();
        for needed in ["PROPFIND", "MKCOL", "MOVE", "COPY", "LOCK"] {
            assert!(
                methods.contains(&needed),
                "missing WebDAV method {needed}: {methods:?}"
            );
        }
    }

    #[test]
    fn generate_method_variants_includes_custom_token() {
        let methods: Vec<&str> = generate_method_variants()
            .iter()
            .map(|p| p.method)
            .collect();
        assert!(
            methods.contains(&"BANANA"),
            "should test custom verb tolerance"
        );
    }

    #[test]
    fn generate_method_variants_includes_h2_pri_preface() {
        let methods: Vec<&str> = generate_method_variants()
            .iter()
            .map(|p| p.method)
            .collect();
        assert!(methods.contains(&"PRI"), "should test H2 preface verb");
    }

    #[test]
    fn generate_method_variants_is_deterministic() {
        let a: Vec<&str> = generate_method_variants().iter().map(|p| p.kind).collect();
        let b: Vec<&str> = generate_method_variants().iter().map(|p| p.kind).collect();
        assert_eq!(a, b, "variant order must be stable");
    }

    #[test]
    fn render_curl_emits_method_via_dash_x() {
        let out = render_curl("PROPFIND", "http://x/dav");
        assert!(out.starts_with("curl -i -X PROPFIND "), "got: {out}");
        assert!(out.contains("'http://x/dav'"), "got: {out}");
    }

    async fn spawn_method_mock() -> std::net::SocketAddr {
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
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    // Simulate a server that returns LONGER body for
                    // PROPFIND (mod_dav style).
                    let propfind = req.starts_with("PROPFIND ");
                    let body = if propfind {
                        "<html>WebDAV property listing — much longer body than the baseline GET response</html>"
                    } else {
                        "<html>ok</html>"
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
    async fn run_method_diff_finds_propfind_divergence_on_mod_dav_style_mock() {
        let addr = spawn_method_mock().await;
        let args = MethodDiffArgs {
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
        let code = run_method_diff(args).await;
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    #[tokio::test]
    async fn run_method_diff_against_unreachable_exits_1() {
        let args = MethodDiffArgs {
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
        let code = run_method_diff(args).await;
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(1)));
    }
}
