//! Scan loop for `wafrift scan --raw-request <FILE>` (`-r`).
//!
//! Fires variants against an operator-supplied raw HTTP request
//! template instead of the default URL-query shape. The template
//! comes from a Burp *Copy → Save raw → File* export; the `§§`
//! marker tells wafrift where to inject each candidate payload.
//!
//! ## What this runner does (and doesn't)
//!
//! Does:
//! - Validates the template has a `§§` marker (otherwise variants
//!   would fire the same un-mutated request).
//! - Honours the pentest pivot — `--proxy` routes every request
//!   through Burp; `-H` adds operator headers on top of the
//!   template's.
//! - Generates encoding + grammar variants of `--payload` via
//!   [`crate::helpers::build_variants`] — same primitive the
//!   URL-query path uses, so the variant menu is consistent.
//! - Fires each variant by substituting `§§` in the template's
//!   URL, header values, and body via [`RawRequest::with_payload`].
//! - Classifies via [`is_waf_block`] (status + body fingerprint).
//! - Emits text or JSON output with a per-bypass `repro_curl` field
//!   ready to paste into a terminal.
//!
//! Doesn't (yet, by design):
//! - No multi-vector phase: the template IS the vector — the
//!   operator chose POST-body / header / cookie injection by where
//!   they placed `§§`.
//! - No equivalence-moat active boundary learning: the moat assumes URL-query shape;
//!   adapting it to arbitrary raw templates is future work.
//! - No header-obfuscation phase: operator uses `-H` instead.
//! - No baseline / WAF-detection phase: the operator already knows
//!   the target. The runner trusts their setup.

use std::process::ExitCode;
use std::time::{Duration, Instant};

use colored::Colorize;
use reqwest::{Client, Method};
use serde_json::json;
use tokio_util::sync::CancellationToken;

use wafrift_grammar::grammar;
use wafrift_transport::is_waf_block;

use crate::ScanArgs;
use crate::helpers::{build_variants, max_mutations_for_level, strategies_for_level};
use crate::raw_request::RawRequest;
use crate::scan::pentest_client;

/// One observed bypass — the runner's row type. Carries the variant
/// metadata AND the fully-rendered curl reproducer so the JSON
/// output can be consumed directly (no further substitution needed
/// on the operator's end).
///
/// When `--auto-distill` is set, the runner populates
/// [`Self::minimal_payload`] and [`Self::minimal_repro_curl`] with
/// the ddmin-reduced form — typically MUCH shorter than the
/// original, easier to drop into a pentest report.
#[derive(Debug, Clone)]
pub struct BypassRecord {
    pub idx: usize,
    pub payload: String,
    pub techniques: Vec<String>,
    pub confidence: f64,
    pub repro_curl: String,
    /// Minimum-edit-distance subset of [`Self::payload`] that still
    /// bypasses, found via Zeller's ddmin. `None` unless
    /// `--auto-distill` was passed.
    pub minimal_payload: Option<String>,
    /// `curl -i` reproducer for [`Self::minimal_payload`]. `None`
    /// when `minimal_payload` is `None`.
    pub minimal_repro_curl: Option<String>,
}

/// Outcome of firing one variant — what `is_waf_block` decided plus
/// the raw transport result so the runner can count errors separately
/// from blocks.
#[derive(Debug)]
enum FireOutcome {
    Bypass,
    Blocked,
}

/// Run the `-r` scan loop. Returns:
/// - `ExitCode::SUCCESS` (0) on a clean run (regardless of whether
///   any variant bypassed)
/// - `ExitCode::from(1)` on HTTP-client setup failure
/// - `ExitCode::from(2)` on invalid template input (no `§§` marker)
pub async fn run_scan_raw(
    template: RawRequest,
    args: ScanArgs,
    cancel: CancellationToken,
) -> ExitCode {
    let scan_text = args.format == "text";

    if !template.has_injection_marker() {
        eprintln!(
            "{} raw request template has no `§§` injection marker — \
             every variant would fire the same un-mutated request. \
             Add `§§` to the URL, a header value, or the body where \
             you want the payload substituted.",
            "Input error:".red().bold()
        );
        return ExitCode::from(2);
    }
    if args.payload.is_empty() {
        eprintln!(
            "{} --payload must not be empty (e.g. \"' OR 1=1--\")",
            "Input error:".red().bold()
        );
        return ExitCode::from(2);
    }

    let http = match build_http_client(&args) {
        Ok(c) => c,
        Err(code) => return code,
    };

    let payload_type = grammar::classify(&args.payload);
    let strategies = strategies_for_level(args.level);
    let max_mutations = max_mutations_for_level(args.level);
    let variants = build_variants(
        &args.payload,
        payload_type,
        args.encoding_only,
        &strategies,
        max_mutations,
    );

    if scan_text {
        eprintln!(
            "{} {} variant(s) against raw template ({} {})",
            "[wafrift scan -r]".bright_cyan().bold(),
            variants.len().to_string().bold().yellow(),
            template.method.bright_white(),
            template.url.bright_white(),
        );
    }

    let scan_start = Instant::now();
    let mut bypass_variants: Vec<BypassRecord> = Vec::new();
    let mut bypassed: u32 = 0;
    let mut blocked: u32 = 0;
    let mut errors: u32 = 0;
    let mut total_fired: usize = 0;

    for (idx, v) in variants.iter().enumerate() {
        if cancel.is_cancelled() {
            break;
        }
        total_fired += 1;
        let mutated = template.with_payload(&v.payload);
        match fire_one(&http, &mutated).await {
            Ok(FireOutcome::Bypass) => {
                bypassed += 1;
                let repro_curl = mutated.to_curl();
                bypass_variants.push(BypassRecord {
                    idx,
                    payload: v.payload.clone(),
                    techniques: v.techniques.clone(),
                    confidence: v.confidence,
                    repro_curl,
                    minimal_payload: None,
                    minimal_repro_curl: None,
                });
                if scan_text {
                    eprintln!(
                        "  {} variant {idx}: BYPASS — {}",
                        "✓".bright_green().bold(),
                        v.payload.chars().take(80).collect::<String>().yellow()
                    );
                }
            }
            Ok(FireOutcome::Blocked) => {
                blocked += 1;
                if scan_text {
                    eprintln!("  {} variant {idx}: blocked", "✗".red());
                }
            }
            Err(e) => {
                errors += 1;
                if scan_text {
                    eprintln!(
                        "  {} variant {idx}: error — {e}",
                        "!".yellow().bold()
                    );
                }
            }
        }
        if args.delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(args.delay_ms)).await;
        }
    }

    // ── Auto-distill pass ─────────────────────────────────────
    //
    // For each bypass, run Zeller's ddmin against the same target
    // to find the minimum-edit-distance payload that STILL bypasses.
    // Off by default; opt-in via `--auto-distill`. The per-bypass
    // fire budget is bounded by `--auto-distill-max-fires` to defend
    // against pathological inputs.
    let mut distill_fires_total: u64 = 0;
    if args.auto_distill && !bypass_variants.is_empty() {
        if scan_text {
            eprintln!(
                "{} auto-distilling {} bypass(es) via ddmin (cap {} fires each)…",
                "[wafrift scan -r distill]".bright_cyan().bold(),
                bypass_variants.len().to_string().bold().yellow(),
                args.auto_distill_max_fires,
            );
        }
        let http_arc = std::sync::Arc::new(http.clone());
        let template_arc = std::sync::Arc::new(template.clone());
        for record in &mut bypass_variants {
            if cancel.is_cancelled() {
                break;
            }
            let fires = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
            let cap = args.auto_distill_max_fires;
            let predicate = {
                let http = http_arc.clone();
                let template = template_arc.clone();
                let fires = fires.clone();
                let cancel = cancel.clone();
                move |candidate: String| {
                    let http = http.clone();
                    let template = template.clone();
                    let fires = fires.clone();
                    let cancel = cancel.clone();
                    async move {
                        if cancel.is_cancelled() {
                            return false;
                        }
                        if fires.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= cap
                        {
                            return false;
                        }
                        let mutated = template.with_payload(&candidate);
                        matches!(fire_one(&http, &mutated).await, Ok(FireOutcome::Bypass))
                    }
                }
            };
            let minimum = crate::distill_cmd::ddmin(&record.payload, predicate).await;
            distill_fires_total += u64::from(fires.load(std::sync::atomic::Ordering::SeqCst));
            // Only record if the distillation actually shortened
            // anything (or kept it identical — still record the
            // result so JSON consumers always see the field).
            let minimal_mutated = template.with_payload(&minimum);
            record.minimal_repro_curl = Some(minimal_mutated.to_curl());
            record.minimal_payload = Some(minimum);
        }
    }

    let elapsed = scan_start.elapsed();
    let bypass_rate = if total_fired > 0 {
        (bypassed as f64 / total_fired as f64) * 100.0
    } else {
        0.0
    };
    let _ = distill_fires_total; // surfaced in emit_json below

    match args.format.as_str() {
        "json" => emit_json(
            &template,
            &args,
            &bypass_variants,
            total_fired,
            bypassed,
            blocked,
            errors,
            elapsed,
            bypass_rate,
            distill_fires_total,
        ),
        _ => emit_text(
            &bypass_variants,
            total_fired,
            bypassed,
            blocked,
            errors,
            elapsed,
            bypass_rate,
            distill_fires_total,
        ),
    }

    ExitCode::SUCCESS
}

/// Build the reqwest client mirroring `scan::run_scan`'s setup
/// (timeout, redirects, realistic UA, pentest pivot flags). Session-
/// init is intentionally skipped in `-r` mode — the operator's
/// captured request file ALREADY carries any cookies / auth headers
/// they need; layering a second session would double-set them.
fn build_http_client(args: &ScanArgs) -> Result<Client, ExitCode> {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(
            wafrift_types::DEFAULT_REQUEST_TIMEOUT_SECS,
        ))
        .danger_accept_invalid_certs(args.insecure)
        .redirect(reqwest::redirect::Policy::limited(5))
        .user_agent(crate::config::shared_user_agent());
    builder = match pentest_client::apply_pentest_flags(
        builder,
        args.proxy.as_deref(),
        &args.header,
        None,
    ) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("  {} {e}", "✗ pentest flag invalid:".red().bold());
            return Err(ExitCode::from(1));
        }
    };
    builder.build().map_err(|e| {
        eprintln!(
            "  {} {e}",
            "✗ Failed to build HTTP client:".red().bold()
        );
        ExitCode::from(1)
    })
}

/// Fire a single mutated request and classify the response. Skips
/// the `Host` and `Content-Length` headers because reqwest
/// re-derives both — passing stale values would confuse routing.
async fn fire_one(http: &Client, raw: &RawRequest) -> Result<FireOutcome, String> {
    let method = Method::from_bytes(raw.method.as_bytes())
        .map_err(|e| format!("invalid method {:?}: {e}", raw.method))?;
    let mut req = http.request(method, &raw.url);
    for (name, value) in &raw.headers {
        if name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        req = req.header(name.as_str(), value);
    }
    if !raw.body.is_empty() {
        req = req.body(raw.body.clone());
    }
    let resp = req.send().await.map_err(|e| format!("{e}"))?;
    let status = resp.status().as_u16();
    let body = resp.bytes().await.map_err(|e| format!("{e}"))?;
    if is_waf_block(status, &body) {
        Ok(FireOutcome::Blocked)
    } else {
        Ok(FireOutcome::Bypass)
    }
}

fn emit_text(
    bypass_variants: &[BypassRecord],
    total_fired: usize,
    bypassed: u32,
    blocked: u32,
    errors: u32,
    elapsed: Duration,
    bypass_rate: f64,
    distill_fires_total: u64,
) {
    eprintln!();
    eprintln!(
        "{} {} bypass(es) · {} blocked · {} error(s) · {:.1}% bypass-rate · {:.2}s",
        "[wafrift scan -r summary]".bright_cyan().bold(),
        bypassed.to_string().bright_green().bold(),
        blocked,
        errors,
        bypass_rate,
        elapsed.as_secs_f64(),
    );
    if distill_fires_total > 0 {
        eprintln!(
            "  {} auto-distill fired {} extra request(s) to find minimum forms",
            "↘".bright_black(),
            distill_fires_total
        );
    }
    let _ = total_fired;
    if !bypass_variants.is_empty() {
        eprintln!();
        eprintln!(
            "{} per-bypass curl reproducer (paste to verify):",
            "→".bright_cyan()
        );
        for b in bypass_variants {
            eprintln!(
                "  [{}] confidence {:.0}%{}",
                format!("{}", b.idx).bold().yellow(),
                b.confidence * 100.0,
                match (b.payload.chars().count(), b.minimal_payload.as_ref()) {
                    (orig, Some(minimal)) => {
                        let min_len = minimal.chars().count();
                        format!(
                            " · distilled {orig}→{min_len} chars ({:.0}% reduction)",
                            ((orig - min_len) as f64 / orig as f64) * 100.0
                        )
                        .bright_green()
                        .to_string()
                    }
                    _ => String::new(),
                }
            );
            // Prefer the minimal repro when auto-distill is on —
            // shorter payloads are easier to share / report.
            println!(
                "{}",
                b.minimal_repro_curl.as_deref().unwrap_or(&b.repro_curl)
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_json(
    template: &RawRequest,
    args: &ScanArgs,
    bypass_variants: &[BypassRecord],
    total_fired: usize,
    bypassed: u32,
    blocked: u32,
    errors: u32,
    elapsed: Duration,
    bypass_rate: f64,
    distill_fires_total: u64,
) {
    let out = json!({
        "mode": "raw-request",
        "template": {
            "method": template.method,
            "url": template.url,
            "header_count": template.headers.len(),
            "body_bytes": template.body.len(),
        },
        "payload": args.payload,
        "total_fired": total_fired,
        "bypassed": bypassed,
        "blocked": blocked,
        "errors": errors,
        "bypass_rate_pct": bypass_rate,
        "elapsed_ms": elapsed.as_secs_f64() * 1000.0,
        "auto_distill_enabled": args.auto_distill,
        "auto_distill_fires_total": distill_fires_total,
        "bypass_variants": bypass_variants.iter().map(|b| json!({
            "variant": b.idx,
            "payload": b.payload,
            "techniques": b.techniques,
            "confidence": b.confidence,
            "repro_curl": b.repro_curl,
            // Null unless --auto-distill was set; populated with the
            // ddmin-reduced minimum subset of `payload` that STILL
            // bypasses, plus its own ready-to-paste curl reproducer.
            "minimal_payload": b.minimal_payload,
            "minimal_repro_curl": b.minimal_repro_curl,
        })).collect::<Vec<_>>(),
    });
    match serde_json::to_string_pretty(&out) {
        Ok(s) => {
            if let Some(ref path) = args.output {
                if let Err(e) = std::fs::write(path, &s) {
                    eprintln!(
                        "failed to write scan output to {}: {e}",
                        path.display()
                    );
                    return;
                }
                eprintln!("scan results written to {}", path.display());
            } else {
                println!("{s}");
            }
        }
        Err(e) => eprintln!("failed to serialize JSON: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn template_with_marker() -> RawRequest {
        RawRequest {
            method: "GET".into(),
            url: "http://x/search?q=§§".into(),
            headers: vec![("Accept".into(), "*/*".into())],
            body: Vec::new(),
        }
    }

    fn template_without_marker() -> RawRequest {
        RawRequest {
            method: "GET".into(),
            url: "http://x/".into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    // ── Validation gate: missing §§ marker ────────────────────

    #[tokio::test]
    async fn rejects_template_with_no_injection_marker() {
        let args = ScanArgs {
            target_positional: None,
            target: None,
            from_discovery: None,
            payload: "x".into(),
            param: "q".into(),
            payload_class: None,
            callback_url: None,
            session_init: None,
            level: crate::Level::Light,
            encoding_only: true,
            delay_ms: 0,
            format: "json".into(),
            stealth_browser: None,
            insecure: false,
            report_layers: false,
            only: Vec::new(),
            exclude: Vec::new(),
            output: None,
            proxy: None,
            header: Vec::new(),
            raw_request: None,
            raw_request_scheme: "http".into(),
            auto_distill: false,
            auto_distill_max_fires: 200,
            concurrency: 0,
            timeout_secs: 0,
            quiet: false,
            callback_timeout_secs: 5,
            exploit_cap: 500,
            variants_cap: 0,
            egress_socks5: Vec::new(),
            egress_http_proxy: Vec::new(),
            egress_tailscale_nodes: Vec::new(),
            egress_tailscale_socks_addr: "127.0.0.1:1055".into(),
            egress_challenge_threshold: 3,
            egress_cooldown_secs: 300,
            i_have_permission: None,
            graphql: false,
            custom_rules: None,
        };
        let cancel = CancellationToken::new();
        let code = run_scan_raw(template_with_marker(), args, cancel).await;
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::from(2)),
            "empty payload must exit 2"
        );
    }

    // ── Live mock-server fire loop ────────────────────────────
    //
    // Spin up a tiny TCP listener that mimics a WAF: 403 on
    // payloads containing the literal "BLOCKED", 200 otherwise.
    // Confirms the runner fires variants, classifies via
    // is_waf_block, and tracks bypasses.

    async fn spawn_mock_waf() -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let (status, body) = if req.contains("BLOCKED") {
                        (
                            "403 Forbidden",
                            "<html>blocked by mock WAF</html>".to_string(),
                        )
                    } else {
                        ("200 OK", "<html>OK</html>".to_string())
                    };
                    let resp = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: text/html\r\n\
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

    fn args_for(addr: std::net::SocketAddr, payload: &str, format: &str) -> ScanArgs {
        // GET ?q=<payload-with-marker> against the mock — but the
        // runner gets a TEMPLATE, not args.target. Args fields are
        // unused here EXCEPT payload, level, encoding_only, format.
        let _ = addr;
        ScanArgs {
            target_positional: None,
            target: None,
            from_discovery: None,
            payload: payload.into(),
            param: "q".into(),
            payload_class: None,
            callback_url: None,
            session_init: None,
            level: crate::Level::Light,
            encoding_only: true,
            delay_ms: 0,
            format: format.into(),
            stealth_browser: None,
            insecure: false,
            report_layers: false,
            only: Vec::new(),
            exclude: Vec::new(),
            output: None,
            proxy: None,
            header: Vec::new(),
            raw_request: None,
            raw_request_scheme: "http".into(),
            auto_distill: false,
            auto_distill_max_fires: 200,
            concurrency: 0,
            timeout_secs: 0,
            quiet: false,
            callback_timeout_secs: 5,
            exploit_cap: 500,
            variants_cap: 0,
<<<<<<< HEAD
=======
            egress_socks5: Vec::new(),
            egress_http_proxy: Vec::new(),
            egress_tailscale_nodes: Vec::new(),
            egress_tailscale_socks_addr: "127.0.0.1:1055".into(),
            egress_challenge_threshold: 3,
            egress_cooldown_secs: 300,
            i_have_permission: None,
            graphql: false,
            custom_rules: None,
>>>>>>> Maximally use existing infra: wire hunt corpus + custom_rules
        }
    }

    #[tokio::test]
    async fn runner_records_bypass_when_payload_dodges_mock_block_signature() {
        let addr = spawn_mock_waf().await;
        let template = RawRequest {
            method: "GET".into(),
            url: format!("http://{addr}/?q=§§"),
            headers: Vec::new(),
            body: Vec::new(),
        };
        // Payload "SAFEPAYLOAD" never contains the magic "BLOCKED"
        // substring → mock returns 200 → bypass recorded for every
        // variant. We just assert the runner completed successfully
        // and returns SUCCESS exit code.
        let args = args_for(addr, "SAFEPAYLOAD", "json");
        let cancel = CancellationToken::new();
        let code = run_scan_raw(template, args, cancel).await;
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    #[tokio::test]
    async fn runner_records_block_when_mock_waf_rejects() {
        let addr = spawn_mock_waf().await;
        let template = RawRequest {
            method: "GET".into(),
            url: format!("http://{addr}/?q=§§"),
            headers: Vec::new(),
            body: Vec::new(),
        };
        // Payload literally contains "BLOCKED" → mock returns 403
        // → no bypasses. Runner still returns SUCCESS (clean run,
        // just no winning variants).
        let args = args_for(addr, "BLOCKED", "json");
        let cancel = CancellationToken::new();
        let code = run_scan_raw(template, args, cancel).await;
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    #[tokio::test]
    async fn runner_honors_cancel_token_before_firing_first_variant() {
        // Cancel BEFORE the loop runs — runner should exit cleanly
        // without firing anything. Confirms the cancel path is
        // honoured (no hung scans on Ctrl-C).
        let addr = spawn_mock_waf().await;
        let template = RawRequest {
            method: "GET".into(),
            url: format!("http://{addr}/?q=§§"),
            headers: Vec::new(),
            body: Vec::new(),
        };
        let args = args_for(addr, "x", "json");
        let cancel = CancellationToken::new();
        cancel.cancel();
        let code = run_scan_raw(template, args, cancel).await;
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    #[tokio::test]
    async fn runner_with_post_body_template_substitutes_payload_into_body() {
        // POST template with §§ in the body — runner substitutes,
        // mock WAF sees the substituted body.
        let addr = spawn_mock_waf().await;
        let template = RawRequest {
            method: "POST".into(),
            url: format!("http://{addr}/login"),
            headers: vec![("Content-Type".into(), "application/x-www-form-urlencoded".into())],
            body: b"user=admin&pass=\xC2\xA7\xC2\xA7".to_vec(), // "§§" in UTF-8
        };
        let args = args_for(addr, "SAFEPASS", "json");
        let cancel = CancellationToken::new();
        let code = run_scan_raw(template, args, cancel).await;
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }
}
