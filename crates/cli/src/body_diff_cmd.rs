//! `wafrift body-diff` — WAF / origin parser-disagreement scanner
//! for REQUEST BODIES.
//!
//! ## The innovation
//!
//! Third command in the parser-diff family (after URL-path
//! `parser-diff` and `header-diff`). Same idea, applied to the
//! request body: WAFs and origin frameworks routinely DISAGREE on
//! how to parse `application/json`, `application/x-www-form-
//! urlencoded`, and `multipart/form-data` bodies. Each disagreement
//! is a seam an operator can exploit without payload-string mutation.
//!
//! Examples of WAF↔origin body-parser disagreements:
//!
//! - **JSON duplicate-key precedence.** `{"q":"safe","q":"attack"}`
//!   — RFC 8259 §4 declares dup-key behaviour undefined. Most
//!   parsers (Jackson, GSON, Python `json`, Node `JSON.parse`)
//!   take the LAST value. But some WAFs short-circuit at the FIRST
//!   key sighting and never see the attack value. WAF safe, origin
//!   attacked.
//! - **JSON5 / JSONC comment tolerance.** `{"q":"attack" /*safe*/}`
//!   — strict JSON parsers reject; the WAF that does strict JSON
//!   parsing and walks the AST sees nothing; an origin that uses a
//!   JSON5/JSONC parser (or just regex-strips comments before
//!   strict parse) sees the attack.
//! - **Charset smuggling.** `Content-Type: application/json;
//!   charset=utf-7` — origins that honour `charset=utf-7` decode
//!   first; payloads encoded as `+ADw-script+AD4-` materialise as
//!   `<script>` AFTER the WAF has scanned the raw UTF-8 bytes.
//! - **BOM-prefixed JSON.** `\xEF\xBB\xBF{"q":"attack"}` — some
//!   strict-JSON parsers (RFC 8259 forbids leading BOM) reject the
//!   body outright; the WAF skips parsing and lets the request
//!   through; an origin that accepts BOM-prefixed JSON (many do —
//!   it's the standard "UTF-8 with BOM" file format) processes
//!   the attack.
//! - **Form-urlencoded HPP.** `q=safe&q=attack` in the BODY (not
//!   the URL). Some WAFs check the first occurrence only; the
//!   origin's body parser dispatches to either first or last
//!   depending on framework (PHP last, ASP.NET concatenates, Java
//!   first).
//! - **Multipart boundary collision.** Body claims `Content-Type:
//!   multipart/form-data; boundary=X`, but the body USES boundary
//!   `Y`. Parsers disagree on whether to honour the declared
//!   boundary, the body's actual boundary, or treat the whole
//!   thing as malformed.
//! - **JSON-as-form.** `Content-Type: application/x-www-form-
//!   urlencoded` but the body is `{"q":"attack"}`. A WAF that
//!   parses by content-type sees no `q=` key; an origin that
//!   sniffs content-by-shape may parse the JSON.
//!
//! ## Probe shape
//!
//! Each probe sends one HTTP POST to the target URL with a
//! variant body block. The baseline is the same URL POST'd with
//! the operator-supplied safe body (`--baseline-body`). Divergence
//! in response status or body length is evidence the WAF and
//! origin treated the body differently — investigate as a
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
pub struct BodyDiffArgs {
    /// Target URL. We POST every variant body to this URL. Pick a
    /// route the operator SUSPECTS the WAF guards via body
    /// inspection (login, search, RPC endpoints).
    pub url: String,

    /// Baseline body — sent as the reference probe with
    /// `Content-Type: application/json`. Default is a benign JSON
    /// object so the operator can immediately see the divergence
    /// vector. Customise via `--baseline-body '{"q":"safe"}'`.
    /// Accepts `--body` as a shorter alias.
    #[arg(long, alias = "body", default_value = "{\"q\":\"safe\"}")]
    pub baseline_body: String,

    /// Inter-request delay (ms) — honour rate limits.
    #[arg(long, default_value_t = 25)]
    pub delay_ms: u64,

    /// Max concurrent in-flight probes.
    #[arg(long, default_value_t = 4)]
    pub concurrency: usize,

    /// HTTP timeout per probe (seconds).
    #[arg(long, default_value_t = 8)]
    pub timeout_secs: u64,

    /// Skip TLS cert verification (lab targets only).
    #[arg(long)]
    pub insecure: bool,

    /// HTTP proxy (Burp on `http://127.0.0.1:8080` is typical).
    #[arg(long, value_name = "URL")]
    pub proxy: Option<String>,

    /// Operator-supplied baseline headers — applied to BOTH baseline
    /// and probes (so an auth cookie or bearer token rides through).
    #[arg(long, short = 'H', value_name = "HEADER", num_args = 0..)]
    pub header: Vec<String>,

    /// Output format. `text` (default) prints a summary table;
    /// `json` emits a structured blob.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    /// Quiet mode — suppress per-probe progress (still emits
    /// final summary / JSON).
    #[arg(long, default_value_t = false)]
    pub quiet: bool,
}

/// One body-parse-disagreement probe.
#[derive(Debug, Clone)]
pub struct BodyDisagreement {
    /// Stable short identifier (`json-dup-key-last-wins`,
    /// `json-bom-prefix`, `charset-utf7`, `form-hpp-body`,
    /// `multipart-boundary-collision`, `json-as-form`,
    /// `json-comments-jsonc`, `form-as-json`).
    pub kind: &'static str,
    /// Human-readable description.
    pub description: &'static str,
    /// `Content-Type` header value to send (overrides the default).
    pub content_type: String,
    /// Raw body bytes.
    pub body: Vec<u8>,
}

/// Result of one body-diff probe.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BodyDiffResult {
    pub kind: &'static str,
    pub description: &'static str,
    pub content_type: String,
    pub body_bytes: usize,
    pub probe_status: u16,
    pub baseline_status: u16,
    pub body_delta_pct: f64,
    pub baseline_body_len: usize,
    pub probe_body_len: usize,
    pub curl_cmd: String,
    pub severity: &'static str,
}

/// Generate the body-disagreement variant set. Pure function — no
/// I/O, deterministic. The `attack_token` is interpolated into
/// every variant body so the operator can grep the response /
/// reflection for it.
#[must_use]
pub fn generate_body_variants(attack_token: &str) -> Vec<BodyDisagreement> {
    let mut out = Vec::new();

    // ── 1. JSON dup-key precedence ────────────────────────────
    out.push(BodyDisagreement {
        kind: "json-dup-key-last-wins",
        description: "JSON with duplicate `q` keys — RFC 8259 §4 leaves order undefined; \
             most parsers (Jackson, GSON, Python json, Node) take the LAST value; \
             some WAFs short-circuit at first sighting and never see the attack",
        content_type: "application/json".into(),
        body: format!(r#"{{"q":"safe","q":"{attack_token}"}}"#).into_bytes(),
    });
    out.push(BodyDisagreement {
        kind: "json-dup-key-first-wins",
        description: "Same dup-key idea, swapped order — covers the FIRST-WINS dispatch parser",
        content_type: "application/json".into(),
        body: format!(r#"{{"q":"{attack_token}","q":"safe"}}"#).into_bytes(),
    });

    // ── 2. BOM-prefixed JSON ──────────────────────────────────
    let mut bom_body = vec![0xEF_u8, 0xBB, 0xBF];
    bom_body.extend(format!(r#"{{"q":"{attack_token}"}}"#).as_bytes());
    out.push(BodyDisagreement {
        kind: "json-bom-prefix",
        description: "UTF-8 BOM prefix before `{` — RFC 8259 forbids; strict parsers reject \
             (WAF treats body as malformed → no parse → pass), lenient parsers \
             (text editors, JSON5) accept",
        content_type: "application/json".into(),
        body: bom_body,
    });

    // ── 3. UTF-7 charset smuggling ────────────────────────────
    out.push(BodyDisagreement {
        kind: "charset-utf7",
        description: "Content-Type advertises charset=utf-7. Origins that honour the charset \
             decode `+ADw-script+AD4-` into `<script>` AFTER the WAF has scanned \
             the raw UTF-8 bytes",
        content_type: "application/json; charset=utf-7".into(),
        body: format!(r#"{{"q":"+ADw-{attack_token}+AD4-"}}"#).into_bytes(),
    });

    // ── 4. Form-urlencoded HPP in body ────────────────────────
    out.push(BodyDisagreement {
        kind: "form-hpp-body",
        description: "Form body with two `q` parameters — PHP keeps the last, ASP.NET \
             concatenates with comma, Java keeps the first; WAFs that scan only \
             the first key miss the attack",
        content_type: "application/x-www-form-urlencoded".into(),
        body: format!("q=safe&q={attack_token}").into_bytes(),
    });

    // ── 5. JSON-as-form ───────────────────────────────────────
    out.push(BodyDisagreement {
        kind: "json-as-form",
        description: "Content-Type says form-urlencoded but body is JSON. WAF parsing by \
             content-type sees no `q=` key; origins that sniff-by-shape \
             (Hapi.js, some Spring configs) parse the JSON",
        content_type: "application/x-www-form-urlencoded".into(),
        body: format!(r#"{{"q":"{attack_token}"}}"#).into_bytes(),
    });

    // ── 6. Form-as-JSON (inverse) ─────────────────────────────
    out.push(BodyDisagreement {
        kind: "form-as-json",
        description: "Content-Type says JSON but body is form. WAF that JSON-parses bails \
             (no recognised fields); origins with lenient body parsing may still \
             see the form key",
        content_type: "application/json".into(),
        body: format!("q={attack_token}").into_bytes(),
    });

    // ── 7. JSON with JSONC comments ──────────────────────────
    out.push(BodyDisagreement {
        kind: "json-comments-jsonc",
        description: "JSON body with inline comment containing the attack. Strict JSON \
             parsers (WAF) reject or strip comments; JSONC parsers (VS Code \
             config, Hjson) read inside",
        content_type: "application/json".into(),
        body: format!(r#"{{"safe":1 /* {attack_token} */}}"#).into_bytes(),
    });

    // ── 8. Multipart boundary collision ──────────────────────
    // Declared boundary "WAF_BOUNDARY"; body uses "REAL_BOUNDARY".
    // Parsers disagree on which boundary wins.
    let multipart_body = format!(
        "--REAL_BOUNDARY\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n{attack_token}\r\n--REAL_BOUNDARY--\r\n"
    );
    out.push(BodyDisagreement {
        kind: "multipart-boundary-collision",
        description: "Multipart header declares boundary=WAF_BOUNDARY but body uses \
             REAL_BOUNDARY. WAFs that strictly honour the declared boundary see \
             no parts (= treat as malformed = pass); origins that scan-for-actual \
             boundary parse the form normally",
        content_type: "multipart/form-data; boundary=WAF_BOUNDARY".into(),
        body: multipart_body.into_bytes(),
    });

    out
}

/// Run the body-diff scanner.
pub async fn run_body_diff(args: BodyDiffArgs) -> ExitCode {
    let http = match crate::parser_diff_common::build_diff_http_client_for(&args) {
        Ok(c) => c,
        Err(code) => return code,
    };

    if !args.quiet && args.format == "text" {
        eprintln!(
            "{} probing {} body parser-disagreement families against {}",
            "[wafrift body-diff]".bright_cyan().bold(),
            generate_body_variants("WAFRIFT_ATTACK_TOKEN")
                .len()
                .to_string()
                .bold()
                .yellow(),
            args.url.bright_white()
        );
    }

    let (baseline_status, baseline_body_len) = match fire_body(
        &http,
        &args.url,
        "application/json",
        args.baseline_body.as_bytes(),
    )
    .await
    {
        Ok((s, len, _)) => (s, len),
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

    let variants = generate_body_variants("WAFRIFT_ATTACK_TOKEN");
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
            let result = fire_body(&http, &url, &v.content_type, &v.body).await;
            counter.fetch_add(1, Ordering::SeqCst);
            (v, result)
        }));
    }

    let mut results: Vec<BodyDiffResult> = Vec::new();
    let mut errors = 0u32;
    for h in handles {
        let (variant, outcome) = h.await.unwrap_or_else(|e| {
            (
                BodyDisagreement {
                    kind: "join-error",
                    description: "tokio join failed",
                    content_type: String::new(),
                    body: Vec::new(),
                },
                Err(format!("{e}")),
            )
        });
        match outcome {
            Ok((probe_status, probe_body_len, _)) => {
                let body_delta = body_delta_pct(baseline_body_len, probe_body_len);
                let severity = severity_of(baseline_status, probe_status, body_delta);
                let curl_cmd = render_curl(&args.url, &variant.content_type, &variant.body);
                results.push(BodyDiffResult {
                    kind: variant.kind,
                    description: variant.description,
                    content_type: variant.content_type.clone(),
                    body_bytes: variant.body.len(),
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

crate::impl_parser_diff_http_args!(BodyDiffArgs);

async fn fire_body(
    http: &Client,
    url: &str,
    content_type: &str,
    body: &[u8],
) -> Result<(u16, usize, Vec<u8>), String> {
    let resp = http
        .post(url)
        .header("Content-Type", content_type)
        .body(body.to_vec())
        .send()
        .await
        .map_err(|e| format!("{e}"))?;
    let status = resp.status().as_u16();
    let body = resp.bytes().await.map_err(|e| format!("{e}"))?.to_vec();
    Ok((status, body.len(), body))
}

fn render_curl(url: &str, content_type: &str, body: &[u8]) -> String {
    let mut out = String::from("curl -i -X POST ");
    out.push_str("-H ");
    out.push_str(&shell_single_quote(&format!(
        "Content-Type: {content_type}"
    )));
    out.push(' ');
    out.push_str("--data-binary ");
    out.push_str(&shell_single_quote(&String::from_utf8_lossy(body)));
    out.push(' ');
    out.push_str(&shell_single_quote(url));
    out
}

fn emit_output(
    args: &BodyDiffArgs,
    results: &[BodyDiffResult],
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
            "[wafrift body-diff summary]".bright_cyan().bold(),
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
        println!("    Content-Type: {}", r.content_type);
        println!("    {}", r.curl_cmd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── generate_body_variants ────────────────────────────────

    #[test]
    fn generate_body_variants_returns_non_empty_curated_set() {
        let v = generate_body_variants("ATTACK");
        assert!(!v.is_empty(), "must have ≥1 variant");
        assert!(v.len() >= 8, "expected at least 8 probes, got {}", v.len());
    }

    #[test]
    fn generate_body_variants_kinds_are_unique() {
        let v = generate_body_variants("ATTACK");
        let mut kinds: Vec<&str> = v.iter().map(|p| p.kind).collect();
        kinds.sort();
        kinds.dedup();
        assert_eq!(kinds.len(), v.len());
    }

    #[test]
    fn generate_body_variants_every_probe_has_non_empty_body() {
        for p in generate_body_variants("ATTACK") {
            assert!(!p.body.is_empty(), "probe {} body empty", p.kind);
            assert!(
                !p.content_type.is_empty(),
                "probe {} content_type empty",
                p.kind
            );
        }
    }

    #[test]
    fn generate_body_variants_is_deterministic() {
        let a = generate_body_variants("X");
        let b = generate_body_variants("X");
        let a_kinds: Vec<&str> = a.iter().map(|p| p.kind).collect();
        let b_kinds: Vec<&str> = b.iter().map(|p| p.kind).collect();
        assert_eq!(a_kinds, b_kinds);
    }

    #[test]
    fn generate_body_variants_interpolates_attack_token_into_bodies() {
        let v = generate_body_variants("WAFRIFT_TOKEN_XYZ");
        // At least one probe body must contain the token verbatim.
        let any_carries_token = v
            .iter()
            .any(|p| String::from_utf8_lossy(&p.body).contains("WAFRIFT_TOKEN_XYZ"));
        assert!(any_carries_token, "no probe body carries the attack token");
    }

    #[test]
    fn generate_body_variants_covers_json_dup_key_family() {
        let kinds: Vec<&str> = generate_body_variants("X").iter().map(|p| p.kind).collect();
        assert!(
            kinds.iter().any(|k| k.contains("dup-key")),
            "must cover JSON dup-key family: {kinds:?}"
        );
    }

    #[test]
    fn generate_body_variants_covers_multipart_boundary() {
        let kinds: Vec<&str> = generate_body_variants("X").iter().map(|p| p.kind).collect();
        assert!(
            kinds.iter().any(|k| k.contains("multipart")),
            "must cover multipart boundary family: {kinds:?}"
        );
    }

    #[test]
    fn generate_body_variants_covers_charset_utf7_smuggling() {
        let v = generate_body_variants("X");
        let charset = v
            .iter()
            .find(|p| p.kind.contains("utf7"))
            .expect("charset-utf7 probe must exist");
        assert!(
            charset.content_type.contains("utf-7"),
            "charset-utf7 must advertise utf-7 in content type"
        );
    }

    #[test]
    fn generate_body_variants_includes_bom_prefix_probe() {
        let v = generate_body_variants("X");
        let bom = v
            .iter()
            .find(|p| p.kind.contains("bom"))
            .expect("json-bom-prefix probe must exist");
        // First 3 bytes are the UTF-8 BOM.
        assert_eq!(&bom.body[..3], b"\xEF\xBB\xBF");
    }

    // body_delta_pct / severity_of / status_class are tested in
    // their canonical home — crate::parser_diff_common. Probe-shape
    // tests live here.

    // ── render_curl ───────────────────────────────────────────

    #[test]
    fn render_curl_emits_post_with_content_type_and_data_binary() {
        let out = render_curl("http://x/", "application/json", b"{\"q\":1}");
        assert!(out.starts_with("curl -i -X POST "), "got: {out}");
        assert!(
            out.contains("'Content-Type: application/json'"),
            "got: {out}"
        );
        assert!(out.contains("--data-binary '{\"q\":1}'"), "got: {out}");
        assert!(out.contains("'http://x/'"), "got: {out}");
    }

    #[test]
    fn render_curl_escapes_apostrophe_in_body() {
        let out = render_curl("http://x/", "application/json", b"a'b");
        assert!(out.contains("'a'\\''b'"), "got: {out}");
    }

    // ── Live mock integration ─────────────────────────────────

    async fn spawn_body_aware_mock() -> std::net::SocketAddr {
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
                    // Mock: returns LONGER body if the request body
                    // contains the literal attack token.
                    let leaked = req.contains("WAFRIFT_ATTACK_TOKEN");
                    let body: String = if leaked {
                        "<html>parsed attack token — origin saw it (long body)</html>".into()
                    } else {
                        "<html>baseline body</html>".into()
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
    async fn run_body_diff_against_mock_succeeds() {
        let addr = spawn_body_aware_mock().await;
        let args = BodyDiffArgs {
            url: format!("http://{addr}/"),
            baseline_body: r#"{"q":"safe"}"#.into(),
            delay_ms: 0,
            concurrency: 4,
            timeout_secs: 8,
            insecure: false,
            proxy: None,
            header: Vec::new(),
            format: "json".into(),
            quiet: true,
        };
        let code = run_body_diff(args).await;
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::SUCCESS),
            "body-diff should exit 0"
        );
    }

    #[tokio::test]
    async fn run_body_diff_against_unreachable_target_exits_1() {
        let args = BodyDiffArgs {
            url: "http://127.0.0.1:1/".into(),
            baseline_body: "{}".into(),
            delay_ms: 0,
            concurrency: 4,
            timeout_secs: 2,
            insecure: false,
            proxy: None,
            header: Vec::new(),
            format: "json".into(),
            quiet: true,
        };
        let code = run_body_diff(args).await;
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(1)));
    }
}
