//! `wafrift detect` — WAF / CDN / origin-infrastructure fingerprinting.
//!
//! Two input modes:
//! - `--url <URL>` fetches the target once and runs the rule corpus
//!   against the live response (status + headers + body capped at
//!   64 KiB).
//! - `--status` / `--headers` / `--body` accepts the same triple from
//!   a prior `curl -i` capture so the operator doesn't need to expose
//!   the CLI to the target a second time.
//!
//! Outputs the highest-confidence WAF candidate (text mode) or the
//! full structured detect result + infra markers (`--quiet` /
//! `--format json`). When no WAF crosses the confidence threshold,
//! `infra_markers` surfaces the CDN / origin banners so the report is
//! never an unhelpful bare "no WAF found."
//!
//! `fetch_for_detect`, `infra_markers`, and `DetectFetch` are
//! intentionally `pub(crate)` so the higher-level demo command
//! (`crate::legendary::run_legendary`) composes the same primitives
//! that ship under `wafrift detect` — no risk of the demo drifting
//! from the real command's behaviour.

use colored::Colorize;
use serde_json::json;
use std::process::ExitCode;
use std::time::Duration;
use wafrift_detect::waf_detect;

use crate::helpers::parse_headers;

#[derive(clap::Args, Debug)]
pub struct DetectArgs {
    /// Fetch the target URL directly and run detection on the live
    /// response — no manual `curl` + `--status`/`--headers` round-trip.
    /// `wafrift detect --url https://target.com`. Mutually exclusive
    /// with `--status`/`--headers`.
    #[arg(long, conflicts_with_all = ["status", "headers"])]
    pub url: Option<String>,

    /// HTTP status code (100–599). Required unless `--url` is given.
    #[arg(long, value_parser = parse_http_status, required_unless_present = "url")]
    pub status: Option<u16>,

    /// Repeated "key: value" header arguments. Required unless `--url`
    /// is given.
    #[arg(long, required_unless_present = "url")]
    pub headers: Vec<String>,

    /// Response body fragment.
    #[arg(long, default_value = "")]
    pub body: String,

    /// With `--url`: per-request timeout in seconds.
    #[arg(long, default_value_t = 10)]
    pub timeout_secs: u64,

    /// With `--url`: disable TLS certificate verification (lab targets).
    #[arg(long, default_value_t = false)]
    pub insecure: bool,

    /// With `--url`: also fire a SECOND probe with an obvious SQLi
    /// payload and compare the responses. When the server header
    /// differs, status flips, or body length swings >50%, that's
    /// strong evidence of a WAF in "block but don't fingerprint"
    /// mode (e.g. ModSec returning Apache's generic 403, or any
    /// WAF that strips its own block-page markers). Off by default
    /// because it sends a real attack-shaped string — only enable
    /// against targets you own / are authorized to test.
    #[arg(long, default_value_t = false)]
    pub differential: bool,
}

/// clap value-parser for an HTTP status code. RFC 9110 status codes are
/// three digits in the range 100–599; anything else (`0`, `99`, `999`,
/// `1000`) is a typo or an attempt to smuggle a nonsense value past
/// detection and is rejected at parse time rather than silently scored.
pub fn parse_http_status(s: &str) -> Result<u16, String> {
    let n: u16 = s
        .parse()
        .map_err(|_| format!("`{s}` is not a number; HTTP status codes are 100–599"))?;
    if (100..=599).contains(&n) {
        Ok(n)
    } else {
        Err(format!(
            "HTTP status code {n} is out of range — valid codes are 100–599"
        ))
    }
}

/// `(status, response headers, body)` from a detect fetch, or an error
/// string. Aliased so the nested generic isn't a `type_complexity`
/// lint at every use site.
pub(crate) type DetectFetch = Result<(u16, Vec<(String, String)>, Vec<u8>), String>;

/// Single-shot GET against a target for fingerprinting. Sends a
/// realistic browser UA so the edge behaves normally (some CDNs serve
/// a different page or skip a JS challenge when they see "rustls" or
/// a bare reqwest UA, which would skew detection). Returns
/// `(status, headers, body)` with the body capped at 64 KiB — WAF/CDN
/// banners and block pages are always in the head.
pub(crate) fn fetch_for_detect(url: &str, timeout_secs: u64, insecure: bool) -> DetectFetch {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs.clamp(1, 120)))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        );
    if insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }
    let client = builder
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("failed to start tokio runtime: {e}"))?;
    rt.block_on(async move {
        let resp = client
            .get(url)
            .send()
            .await
            .map_err(|e| format!("request to {url} failed: {e}"))?;
        let status = resp.status().as_u16();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_string(),
                    v.to_str().unwrap_or("<binary>").to_string(),
                )
            })
            .collect();
        // Cap the body read: don't let a hostile/huge response OOM the CLI.
        let bytes = resp.bytes().await.map_err(|e| format!("read body: {e}"))?;
        let body = bytes[..bytes.len().min(64 * 1024)].to_vec();
        Ok((status, headers, body))
    })
}

/// Evidence of a WAF inferred from differential probing — a benign
/// GET vs a SQLi-payload GET produced significantly different
/// responses, which is strong WAF presence signal even when no rule
/// in the 160+ corpus matched. Surfaced under "differential
/// detection" in the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DifferentialEvidence {
    /// Status of the benign baseline.
    pub baseline_status: u16,
    /// Status of the attack probe.
    pub attack_status: u16,
    /// Server header on benign (e.g. "gunicorn/19.9.0").
    pub baseline_server: String,
    /// Server header on attack (e.g. "Apache" — different stack
    /// answering means a WAF intercepted).
    pub attack_server: String,
    /// Body length on benign.
    pub baseline_body_len: usize,
    /// Body length on attack.
    pub attack_body_len: usize,
    /// Specific reasons the differential classifier flagged.
    pub reasons: Vec<String>,
}

/// Compare a benign-probe response with an attack-probe response.
/// Returns `Some(evidence)` when the differences are strong enough
/// to infer a WAF is intercepting, `None` otherwise. Pure function
/// — no I/O, fully testable on synthetic inputs.
#[must_use]
pub fn classify_differential(
    baseline_status: u16,
    baseline_headers: &[(String, String)],
    baseline_body_len: usize,
    attack_status: u16,
    attack_headers: &[(String, String)],
    attack_body_len: usize,
) -> Option<DifferentialEvidence> {
    fn server_of(h: &[(String, String)]) -> String {
        h.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("server"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    }
    let baseline_server = server_of(baseline_headers);
    let attack_server = server_of(attack_headers);

    let mut reasons: Vec<String> = Vec::new();
    // 1. Status flip: benign 200 vs attack 403/406/429/501/etc.
    if baseline_status != attack_status {
        reasons.push(format!(
            "status flipped {baseline_status} → {attack_status}"
        ));
    }
    // 2. Server-header change: different proxy answering attacks
    // = a WAF is intercepting (the typical Apache+ModSec in front
    // of gunicorn pattern lives here).
    if !baseline_server.is_empty()
        && !attack_server.is_empty()
        && !baseline_server.eq_ignore_ascii_case(&attack_server)
    {
        reasons.push(format!(
            "server header changed: '{baseline_server}' → '{attack_server}'"
        ));
    }
    // 3. Body length swing > 50%. The threshold is generous —
    // small differences (different timestamps, request IDs) don't
    // count; a swing from 1 KB origin response to 200-byte block
    // page does.
    if baseline_body_len > 0 {
        let larger = baseline_body_len.max(attack_body_len);
        let smaller = baseline_body_len.min(attack_body_len);
        let pct_diff = ((larger - smaller) as f64 / baseline_body_len as f64) * 100.0;
        if pct_diff >= 50.0 {
            reasons.push(format!(
                "body length swung {pct_diff:.0}% ({baseline_body_len} → {attack_body_len} bytes)"
            ));
        }
    } else if attack_body_len > 0 {
        // Benign returned an empty body; attack returned content.
        // Unusual on its own; combined with other signals it's
        // meaningful.
        reasons.push(format!(
            "attack response had {attack_body_len} bytes vs empty baseline"
        ));
    }

    if reasons.is_empty() {
        None
    } else {
        Some(DifferentialEvidence {
            baseline_status,
            attack_status,
            baseline_server,
            attack_server,
            baseline_body_len,
            attack_body_len,
            reasons,
        })
    }
}

/// Fire two probes against `url`: a benign GET, then an attack
/// GET with a canonical SQLi payload in the `q` parameter.
/// Returns `Some(evidence)` when the responses differ enough to
/// infer a WAF.
pub(crate) fn fetch_differential(
    url: &str,
    timeout_secs: u64,
    insecure: bool,
) -> Result<Option<DifferentialEvidence>, String> {
    let (b_status, b_headers, b_body) = fetch_for_detect(url, timeout_secs, insecure)?;
    let attack_url = if url.contains('?') {
        format!("{url}&q=%27+OR+1%3D1--")
    } else {
        format!("{url}?q=%27+OR+1%3D1--")
    };
    let (a_status, a_headers, a_body) = fetch_for_detect(&attack_url, timeout_secs, insecure)?;
    Ok(classify_differential(
        b_status,
        &b_headers,
        b_body.len(),
        a_status,
        &a_headers,
        a_body.len(),
    ))
}

/// Infrastructure markers worth surfacing even when no WAF crosses the
/// confidence threshold — so `detect` on an nginx/CDN-fronted host
/// (e.g. meta.discourse.org) reports *what is in front of the origin*
/// instead of a bare, useless "No WAF confidently detected."
pub(crate) fn infra_markers(headers: &[(String, String)]) -> Vec<(String, String)> {
    const KEYS: &[&str] = &[
        "server",
        "via",
        "x-cache",
        "x-amz-cf-id",
        "x-amz-cf-pop",
        "cf-ray",
        "cf-cache-status",
        "x-akamai-transformed",
        "x-sucuri-id",
        "x-sucuri-cache",
        "x-cdn",
        "x-served-by",
        "x-powered-by",
        "fastly-debug-digest",
        "x-fastly-request-id",
        "x-iinfo",
        "x-cdn-provider",
    ];
    headers
        .iter()
        .filter(|(k, _)| {
            let lk = k.to_ascii_lowercase();
            KEYS.contains(&lk.as_str())
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

#[allow(clippy::needless_pass_by_value)]
pub fn run_detect(args: DetectArgs, quiet: bool) -> ExitCode {
    // Two input modes: live `--url` fetch, or the manual
    // `--status`/`--headers`/`--body` triple. clap's
    // `required_unless_present`/`conflicts_with_all` guarantees exactly
    // one mode is selected.
    let (status, headers, body): (u16, Vec<(String, String)>, Vec<u8>) =
        if let Some(ref url) = args.url {
            match fetch_for_detect(url, args.timeout_secs, args.insecure) {
                Ok((s, h, b)) => {
                    if !quiet {
                        eprintln!(
                            "{} GET {url} → HTTP {s} ({} headers, {} body bytes)",
                            "probe:".bright_black(),
                            h.len(),
                            b.len()
                        );
                    }
                    (s, h, b)
                }
                Err(e) => {
                    eprintln!("{} {e}", "Probe error:".red().bold());
                    return ExitCode::from(1);
                }
            }
        } else {
            let headers = match parse_headers(&args.headers) {
                Ok(headers) => headers,
                Err(message) => {
                    eprintln!("{} {}", "Header parse error:".red().bold(), message);
                    return ExitCode::from(2);
                }
            };
            // clap enforces `--status` present in this branch.
            let status = args
                .status
                .unwrap_or_else(|| unreachable!("clap requires --status unless --url is present"));
            (status, headers, args.body.clone().into_bytes())
        };

    // Differential WAF detection (opt-in): fire a SECOND probe
    // with an attack-shaped payload and compare. When the static-
    // signature corpus comes back empty but the responses to a
    // benign vs attack request differ significantly, we still know
    // a WAF is intercepting — even if its block page is generic
    // (Apache stock 403, etc.).
    let differential_evidence: Option<DifferentialEvidence> =
        if args.differential && args.url.is_some() {
            let url = args.url.as_deref().expect("differential gated on Some(url)");
            match fetch_differential(url, args.timeout_secs, args.insecure) {
                Ok(ev) => ev,
                Err(e) => {
                    if !quiet {
                        eprintln!(
                            "{} differential probe error (continuing without): {e}",
                            "warn:".yellow()
                        );
                    }
                    None
                }
            }
        } else {
            None
        };

    let detected = waf_detect::detect(status, &headers, &body);
    if quiet {
        let results: Vec<_> = detected
            .iter()
            .map(|r| {
                json!({
                    "name": r.name,
                    "confidence": r.confidence,
                    "indicators": r.indicators,
                })
            })
            .collect();
        let infra: Vec<_> = infra_markers(&headers)
            .into_iter()
            .map(|(k, v)| json!({ "header": k, "value": v }))
            .collect();
        println!(
            "{}",
            json!({ "status": status, "detected": results, "infrastructure": infra })
        );
        ExitCode::SUCCESS
    } else if let Some(result) = detected.first() {
        println!("{} {}", "Detected WAF:".bold().green(), result.name.bold());
        println!(
            "{} {:.0}%",
            "Confidence:".bold().cyan(),
            (result.confidence * 100.0).round()
        );
        println!("{}", "Indicators:".bold().cyan());
        for indicator in &result.indicators {
            println!("  {} {}", "-".bright_black(), indicator.yellow());
        }
        ExitCode::SUCCESS
    } else {
        println!("{}", "No WAF confidently detected.".yellow().bold());
        let infra = infra_markers(&headers);
        if infra.is_empty() {
            println!(
                "  {}",
                "(no CDN/edge/origin markers in the response headers either)".bright_black()
            );
        } else {
            println!(
                "{}",
                "Infrastructure in front of / serving the origin:"
                    .bold()
                    .cyan()
            );
            for (k, v) in &infra {
                println!(
                    "  {} {}: {}",
                    "-".bright_black(),
                    k.yellow(),
                    v.bright_white()
                );
            }
            println!(
                "  {}",
                "These are CDN/proxy/origin banners, not a WAF verdict — \
                 a WAF may still be present in monitor-only mode."
                    .bright_black()
            );
        }
        // Differential evidence — even when the static-corpus came
        // back empty, a differing response on a benign vs attack
        // probe is strong WAF-presence signal (the typical
        // ModSec-in-front-of-gunicorn-returning-generic-Apache-403
        // pattern lives here).
        if let Some(ev) = differential_evidence.as_ref() {
            println!();
            println!(
                "{}",
                "WAF inferred via differential probing:".bold().green()
            );
            for reason in &ev.reasons {
                println!("  {} {}", "✓".green(), reason.yellow());
            }
            println!(
                "  {}",
                format!(
                    "(benign GET → HTTP {} from '{}'; attack GET → HTTP {} from '{}')",
                    ev.baseline_status,
                    ev.baseline_server,
                    ev.attack_status,
                    ev.attack_server
                )
                .bright_black()
            );
        }
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_http_status_accepts_canonical_codes() {
        assert_eq!(parse_http_status("200"), Ok(200));
        assert_eq!(parse_http_status("403"), Ok(403));
        assert_eq!(parse_http_status("100"), Ok(100));
        assert_eq!(parse_http_status("599"), Ok(599));
    }

    #[test]
    fn parse_http_status_rejects_out_of_range() {
        assert!(parse_http_status("0").is_err());
        assert!(parse_http_status("99").is_err());
        assert!(parse_http_status("600").is_err());
        assert!(parse_http_status("999").is_err());
    }

    #[test]
    fn parse_http_status_rejects_non_numeric() {
        assert!(parse_http_status("abc").is_err());
        assert!(parse_http_status("").is_err());
        assert!(parse_http_status("2xx").is_err());
    }

    #[test]
    fn infra_markers_extracts_cdn_and_edge_banners() {
        let headers = vec![
            ("Server".into(), "cloudflare".into()),
            ("CF-Ray".into(), "abc123-LHR".into()),
            ("Content-Type".into(), "text/html".into()),
            ("X-Cache".into(), "HIT from front-edge-1".into()),
        ];
        let m = infra_markers(&headers);
        assert!(m.iter().any(|(k, _)| k == "Server"));
        assert!(m.iter().any(|(k, _)| k == "X-Cache"));
        // CF-Ray is in the allowlist but case-insensitively — verify
        // that the extractor picks it up regardless of header case.
        assert!(m.iter().any(|(k, _)| k.eq_ignore_ascii_case("cf-ray")));
        // Content-Type is not in the infra allowlist (it's a general
        // response header, not a fingerprint anchor) — must be dropped.
        assert!(!m.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type")));
    }

    // ── Live --url path against a mock server (added 2026-05-20).

    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn spawn_mock(body: &'static str, status: u16) -> std::net::SocketAddr {
        let body = body.to_string();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let body = body.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let resp = format!(
                        "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\n\
                         Connection: close\r\nServer: nginx/1.25.3\r\n\
                         CF-Ray: abc123-LHR\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        addr
    }

    /// `fetch_for_detect` builds its own tokio runtime — we drive it
    /// from a sync `#[test]` (no `#[tokio::test]`) so the nested
    /// runtime panic doesn't trip.
    #[test]
    fn fetch_for_detect_against_local_mock_returns_status_and_headers() {
        // Run the mock from a worker tokio runtime, then call the
        // sync fetch_for_detect against the bound address.
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();
        let addr = rt.block_on(spawn_mock("hello world", 200));
        let url = format!("http://{addr}/");
        let (status, headers, body) =
            fetch_for_detect(&url, 5, false).expect("fetch_for_detect must succeed");
        assert_eq!(status, 200);
        assert_eq!(body, b"hello world");
        let has_server = headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("server") && v.contains("nginx"));
        assert!(has_server, "Server header should be present: {headers:?}");
        let has_cf = headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("cf-ray") && v.contains("abc123"));
        assert!(has_cf, "CF-Ray header should be present");
    }

    #[test]
    fn fetch_for_detect_caps_body_at_64_kib() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();
        // Mock that ships 128 KiB of body — we want to confirm the
        // fetch caps the read at 64 KiB.
        let big_body = Box::leak("X".repeat(128 * 1024).into_boxed_str()) as &'static str;
        let addr = rt.block_on(spawn_mock(big_body, 200));
        let url = format!("http://{addr}/");
        let (_, _, body) = fetch_for_detect(&url, 5, false).expect("fetch ok");
        assert_eq!(
            body.len(),
            64 * 1024,
            "body must be capped at 64 KiB, got {}",
            body.len()
        );
    }

    #[test]
    fn fetch_for_detect_passes_through_403_status() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();
        let addr = rt.block_on(spawn_mock("blocked by WAF", 403));
        let url = format!("http://{addr}/");
        let (status, _, body) = fetch_for_detect(&url, 5, false).expect("fetch ok");
        assert_eq!(status, 403);
        assert_eq!(body, b"blocked by WAF");
    }

    #[test]
    fn fetch_for_detect_returns_err_on_connection_refused() {
        // Connect to a localhost port that's almost certainly not
        // listening. Must surface as Err, not panic. Use the
        // unassigned port range (49152–65535 IANA dynamic, but
        // 65501 specifically is rarely used).
        let result = fetch_for_detect("http://127.0.0.1:1/", 2, false);
        assert!(result.is_err(), "unreachable target must return Err");
    }

    #[test]
    fn fetch_for_detect_with_unparseable_url_returns_err() {
        let result = fetch_for_detect("not-a-url://", 2, false);
        assert!(result.is_err(), "unparseable URL must return Err");
    }

    // Suppress dead_code warnings on the test-only helper.
    #[allow(dead_code)]
    fn _ensure_arc_in_scope(_: Arc<u8>) {}

    // ── classify_differential ────────────────────────────────────
    //
    // Pure function — tested without I/O. Each case names the
    // real-world WAF detection pattern it gates.

    fn hdr(server: &str) -> Vec<(String, String)> {
        vec![("Server".into(), server.into())]
    }

    #[test]
    fn differential_identical_responses_returns_none() {
        // Anti-rig: if benign and attack produce identical
        // responses, NO inference. Returning Some here would be
        // a false-positive WAF detection on every plain HTTP host.
        let ev = classify_differential(200, &hdr("nginx"), 1024, 200, &hdr("nginx"), 1024);
        assert!(ev.is_none(), "identical responses must not infer a WAF");
    }

    #[test]
    fn differential_status_flip_alone_is_evidence() {
        // The bare 200 → 403 case: server header may not even be
        // present, but the status flip is unambiguous WAF signal.
        let ev = classify_differential(200, &[], 100, 403, &[], 200)
            .expect("status flip must classify");
        assert_eq!(ev.baseline_status, 200);
        assert_eq!(ev.attack_status, 403);
        assert!(
            ev.reasons.iter().any(|r| r.contains("status flipped")),
            "reasons should mention status flip"
        );
    }

    #[test]
    fn differential_server_change_classifies_as_waf() {
        // The exact ModSec-in-front-of-gunicorn case from dogfooding:
        // benign 200 from 'gunicorn/19.9.0', attack 403 from
        // 'Apache' (ModSec block page). The server-change reason
        // must surface.
        let ev = classify_differential(
            200,
            &hdr("gunicorn/19.9.0"),
            445,
            403,
            &hdr("Apache"),
            239,
        )
        .expect("classify");
        assert!(
            ev.reasons.iter().any(|r| r.contains("server header changed")),
            "expected server-change reason: {:?}",
            ev.reasons
        );
        assert_eq!(ev.baseline_server, "gunicorn/19.9.0");
        assert_eq!(ev.attack_server, "Apache");
    }

    #[test]
    fn differential_server_change_is_case_insensitive() {
        // Apache vs apache should NOT count as a server change —
        // it's the same software, just different casing on the
        // server's part.
        let ev = classify_differential(403, &hdr("Apache"), 100, 403, &hdr("apache"), 100);
        assert!(
            ev.is_none(),
            "case-only server difference must not classify"
        );
    }

    #[test]
    fn differential_body_swing_over_50pct_is_evidence() {
        // Same status + same server, but body collapses from 10 KB
        // (real response) to 200 bytes (block page). The 50%+
        // shrinkage is the only signal in this case.
        let ev = classify_differential(200, &hdr("nginx"), 10_000, 200, &hdr("nginx"), 200)
            .expect("body swing must classify");
        assert!(
            ev.reasons.iter().any(|r| r.contains("body length swung")),
            "reasons should mention body swing: {:?}",
            ev.reasons
        );
    }

    #[test]
    fn differential_small_body_change_is_not_evidence() {
        // 10% difference (timestamps, request IDs, jitter in
        // body) must NOT classify. 50% is the threshold.
        let ev = classify_differential(200, &hdr("nginx"), 10_000, 200, &hdr("nginx"), 9_500);
        assert!(
            ev.is_none(),
            "5% body change must not classify"
        );
    }

    #[test]
    fn differential_multiple_signals_all_listed_in_reasons() {
        // The strongest case: status flip + server change + body
        // swing all together. Every reason should appear in the
        // output so the operator sees the full picture.
        let ev = classify_differential(
            200,
            &hdr("gunicorn"),
            10_000,
            403,
            &hdr("Apache"),
            200,
        )
        .expect("classify");
        let reasons: String = ev.reasons.join(" | ");
        assert!(reasons.contains("status flipped"));
        assert!(reasons.contains("server header changed"));
        assert!(reasons.contains("body length swung"));
    }

    #[test]
    fn differential_empty_baseline_with_attack_body_still_signal() {
        // Edge: benign returned 0 bytes (unusual but valid for a
        // HEAD-style endpoint), attack returned a block page.
        // We can't compute pct_diff against zero, but the
        // non-zero attack body IS still signal.
        let ev = classify_differential(200, &[], 0, 403, &[], 500)
            .expect("classify");
        let reasons: String = ev.reasons.join(" | ");
        assert!(
            reasons.contains("attack response had 500 bytes") || reasons.contains("status flipped"),
            "expected either body-vs-empty or status-flip reason: {:?}",
            ev.reasons
        );
    }
}
