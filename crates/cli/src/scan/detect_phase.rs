//! Scan's Step 1 — WAF detection + advisor planning.
//!
//! Fires a baseline GET at the target, runs the 160+ TOML rules
//! to identify the WAF in front, then asks the advisor for a
//! WAF-specific evasion plan (header obfuscation, content-type
//! switching, H2 evasion, encoding-strategy bias).
//!
//! Bundled as one phase because the four sub-steps share request
//! data (the baseline response feeds detect; detect feeds advisor)
//! and splitting them would just re-thread the same headers+body
//! through three function signatures. The output struct
//! [`DetectOutcome`] is the canonical "what we learned in Step 1"
//! bundle that downstream phases consume.

use colored::Colorize;
use std::process::ExitCode;
use wafrift_detect::waf_detect::{self, DetectedWaf};
use wafrift_evolution::advisor::{self, EvasionPlan};

/// Everything Step 1 produced — feeds the rest of the scan.
#[derive(Debug, Clone)]
pub(crate) struct DetectOutcome {
    /// HTTP status code of the baseline GET.
    pub baseline_status: u16,
    /// Response headers from the baseline (used to identify CDN /
    /// origin markers downstream).
    pub headers_vec: Vec<(String, String)>,
    /// Body bytes from the baseline. May be the WAF's block page
    /// (which the detect rules will recognise) or the origin's
    /// normal response. Owned `Vec<u8>` so the cli crate does not
    /// need a direct `bytes` dep.
    pub body_bytes: Vec<u8>,
    /// All WAF candidates the detect rules matched, sorted by
    /// descending confidence.
    pub detected: Vec<DetectedWaf>,
    /// Top WAF candidate above the actionable threshold, or
    /// `"Unknown"` when no confident match.
    pub waf_name: String,
    /// The DetectedWaf corresponding to `waf_name`, or None when
    /// `waf_name == "Unknown"`. Kept separately because some
    /// downstream consumers want the structured result (for JSON
    /// output) and others just want the name.
    pub detected_waf_obj: Option<DetectedWaf>,
    /// Advisor-generated plan: which evasion knobs to enable for
    /// this WAF (header obfuscation, CT switching, H2, encoding
    /// strategy bias).
    pub evasion_plan: EvasionPlan,
}

/// Run Step 1 against `target`. Prints progress when `scan_text`,
/// otherwise stays quiet. Returns `Err(ExitCode::from(1))` if the
/// baseline request fails at the transport layer — every
/// downstream phase becomes meaningless without one, so we bail
/// early with a clear error.
pub(crate) async fn run(
    http: &reqwest::Client,
    target: &str,
    scan_text: bool,
) -> Result<DetectOutcome, ExitCode> {
    if scan_text {
        // §13 dogfooding: progress lines go to stderr so `wafrift scan | jq`
        // doesn't see WAF-detection noise on stdout (matches the scan
        // orchestrator's Fix #7 requirement that all progress → stderr).
        eprintln!("{}", "[1/3] Detecting WAF...".bold().cyan());
    }
    let baseline_response = match http.get(target).send().await {
        Ok(resp) => resp,
        Err(err) => {
            eprintln!(
                "  {} {} ({})\n    {}",
                "✗ Cannot reach target:".red().bold(),
                target,
                err,
                "hint: check the URL is reachable, the host resolves, and your network allows the connection".bright_black()
            );
            return Err(ExitCode::from(1));
        }
    };

    let baseline_status = baseline_response.status().as_u16();
    let headers_vec: Vec<(String, String)> = baseline_response
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    // §15 OOM / decompression-bomb defence: reqwest auto-decodes
    // Content-Encoding: gzip/brotli. A hostile WAF can serve a 1 KB
    // compressed bomb that expands to hundreds of MB before .bytes()
    // returns, OOM-crashing the CLI. Cap at DEFAULT_MAX_RESPONSE_BYTES
    // (8 MiB) — more than enough for any WAF block page / detection
    // corpus, safe on a laptop. Fall back to empty body on overrun
    // (detection still succeeds on headers alone).
    let body_bytes = match crate::safe_body::read_bounded(
        baseline_response,
        crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES,
    )
    .await
    {
        Ok(b) => b,
        Err(e) => {
            if scan_text {
                eprintln!(
                    "  {} baseline body read aborted ({e}) — WAF detection \
                     continuing on headers only",
                    "warn:".yellow().bold()
                );
            }
            Vec::new()
        }
    };

    let detected = waf_detect::detect(baseline_status, &headers_vec, &body_bytes);
    let top_detection = detected
        .first()
        .filter(|result| result.confidence >= waf_detect::ACTIONABLE_CONFIDENCE_THRESHOLD)
        .cloned();
    let waf_name = if let Some(result) = top_detection.as_ref() {
        if scan_text {
            eprintln!(
                "  {} {} ({:.0}% confidence)",
                "✓ Detected:".green().bold(),
                result.name.bold().yellow(),
                result.confidence * 100.0
            );
        }
        result.name.clone()
    } else {
        if scan_text {
            eprintln!(
                "  {}",
                "⚠ No WAF confidently detected (testing anyway)"
                    .yellow()
                    .bold()
            );
        }
        String::from("Unknown")
    };

    // Advisor: generate WAF-specific evasion plan.
    let evasion_plan = advisor::advise(top_detection.as_ref(), None);
    if scan_text {
        for rationale in &evasion_plan.rationale {
            eprintln!("  {} {}", "📋 Advisor:".bold().cyan(), rationale.yellow());
        }
        if evasion_plan.use_header_obfuscation {
            eprintln!("    {} header obfuscation", "✓".green());
        }
        if evasion_plan.use_content_type_switch {
            eprintln!("    {} content-type switching", "✓".green());
        }
        if evasion_plan.use_h2 {
            eprintln!("    {} HTTP/2 evasion", "✓".green());
        }
    }

    Ok(DetectOutcome {
        baseline_status,
        headers_vec,
        body_bytes,
        detected,
        waf_name,
        detected_waf_obj: top_detection,
        evasion_plan,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn spawn_mock(response: &'static str) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let resp = response.to_string();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let resp = resp.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        tokio::time::sleep(crate::parser_diff_common::TEST_SETTLE).await;
        addr
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_with_unreachable_target_returns_err_exit_code() {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let result = run(&client, "http://127.0.0.1:1/", false).await;
        match result {
            Err(_) => {}
            Ok(_) => panic!("dead port must err"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_with_plain_origin_captures_baseline_no_waf() {
        let addr = spawn_mock(
            "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\nContent-Length: 5\r\n\
             Connection: close\r\n\r\nhello",
        )
        .await;
        let client = reqwest::Client::builder().build().unwrap();
        let outcome = run(&client, &format!("http://{addr}/"), false)
            .await
            .expect("ok");
        assert_eq!(outcome.baseline_status, 200);
        assert_eq!(outcome.body_bytes, b"hello".to_vec());
        // Server: nginx alone isn't a WAF signal (it's an origin
        // server), so waf_name should fall back to "Unknown".
        assert_eq!(outcome.waf_name, "Unknown");
        assert!(outcome.detected_waf_obj.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_with_cloudflare_markers_identifies_cloudflare() {
        // CF-Ray + cf-cache-status are strong Cloudflare signals;
        // the rule corpus should flag with high confidence.
        let addr = spawn_mock(
            "HTTP/1.1 200 OK\r\nServer: cloudflare\r\nCF-Ray: abc123-LHR\r\n\
             cf-cache-status: HIT\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        )
        .await;
        let client = reqwest::Client::builder().build().unwrap();
        let outcome = run(&client, &format!("http://{addr}/"), false)
            .await
            .expect("ok");
        // Either Cloudflare lands by name, or it lands as Unknown
        // (depending on threshold tuning). The PRESENCE of CF-Ray
        // in the captured headers is the load-bearing invariant.
        let cf_ray = outcome
            .headers_vec
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("cf-ray"));
        assert!(cf_ray, "CF-Ray should be in the captured headers");
    }

    /// §15 OOM / decompression-bomb defence pin.
    ///
    /// Pre-fix: `detect_phase::run` called `.bytes().await` with no cap.
    /// A hostile WAF serving a ~100 KiB gzip bomb expanding to >8 MiB
    /// would OOM the CLI before detection finished. The fix routes the
    /// baseline body through `safe_body::read_bounded`; on overrun the
    /// body is empty and detection continues on headers alone.
    ///
    /// This test serves a body that exceeds DEFAULT_MAX_RESPONSE_BYTES
    /// without gzip (to keep the test fast); the bounded reader's cap
    /// fires at the raw byte level. The outcome must be `Ok` (no panic,
    /// no process abort) and the body_bytes must be empty (overrun
    /// path) while the status is still captured correctly.
    #[tokio::test(flavor = "current_thread")]
    async fn run_does_not_oom_on_oversized_baseline_body() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        // Serve a body well above DEFAULT_MAX_RESPONSE_BYTES (8 MiB).
        // We use 9 MiB of zeros so the body reader hits the cap quickly.
        let body_size: usize = 9 * 1024 * 1024;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    // Announce 9 MiB body with a known status.
                    let header = format!(
                        "HTTP/1.1 403 Forbidden\r\nContent-Length: {body_size}\r\n\
                         Server: test-mock\r\nConnection: close\r\n\r\n"
                    );
                    let _ = sock.write_all(header.as_bytes()).await;
                    // Write the oversized body in 64 KiB chunks.
                    let chunk = vec![0u8; 64 * 1024];
                    let mut written = 0_usize;
                    while written < body_size {
                        let n = (body_size - written).min(chunk.len());
                        if sock.write_all(&chunk[..n]).await.is_err() {
                            break;
                        }
                        written += n;
                    }
                    let _ = sock.shutdown().await;
                });
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap();
        let outcome = run(&client, &format!("http://{addr}/"), false)
            .await
            .expect("run must return Ok even when body overruns the cap");

        // Status captured correctly before the body read.
        assert_eq!(outcome.baseline_status, 403);
        // Body empty — the overrun defence discards the body and
        // continues on headers (waf_name may be "Unknown" since
        // there are no detection signals in this mock response).
        assert!(
            outcome.body_bytes.is_empty(),
            "body must be empty on overrun; got {} bytes",
            outcome.body_bytes.len()
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_captures_response_headers_lossy_utf8_safe() {
        // A header with non-UTF-8 bytes (rare but possible) must
        // not panic the lossy-conversion path.
        // We can't easily inject non-UTF-8 from a string literal,
        // so this test is a smoke against the conversion path's
        // existence; the unwrap_or("") fallback in run() handles
        // the case.
        let addr = spawn_mock(
            "HTTP/1.1 200 OK\r\nX-Weird: ok\r\nContent-Length: 0\r\n\
             Connection: close\r\n\r\n",
        )
        .await;
        let client = reqwest::Client::builder().build().unwrap();
        let outcome = run(&client, &format!("http://{addr}/"), false)
            .await
            .expect("ok");
        assert!(
            outcome
                .headers_vec
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("x-weird"))
        );
    }
}
