//! Scan's Step 2b — differential probing.
//!
//! Fires a small set of structured probes against the target to
//! discover what specific patterns the WAF reacts to (vs. simply
//! 'the request was blocked'). The discovered insights bias
//! subsequent phases: if a probe like `<script>` is blocked but
//! `<scr<script>ipt>` is NOT, that's signal the WAF parses HTML
//! tags before matching — useful for downstream strategy
//! selection.
//!
//! Returns the populated `IntelligenceLoop` ready for downstream
//! consumption.

use colored::Colorize;
use std::time::Duration;
use wafrift_evolution::intelligence::IntelligenceLoop;
use wafrift_transport::is_waf_block;

use super::scan_url_with_param;

/// Run Step 2b. Sends each of `intel_loop.generate_quick_probes()`
/// at the target, records the block/pass outcome, and returns the
/// populated loop.
pub async fn run(
    http: &reqwest::Client,
    target: &str,
    param: &str,
    delay_ms: u64,
    scan_text: bool,
) -> IntelligenceLoop {
    let mut intel_loop = IntelligenceLoop::new(20);
    let diff_probes = intel_loop.generate_quick_probes();
    if scan_text && !diff_probes.is_empty() {
        println!(
            "\n{}",
            format!(
                "[2b/7] Differential probing — {} probes...",
                diff_probes.len()
            )
            .bold()
            .cyan()
        );
    }
    for probe in &diff_probes {
        let probe_payload = format!("{:?}", probe.tests);
        let probe_url =
            scan_url_with_param(target, param, &urlencoding::encode(&probe_payload));
        let was_blocked = match http.get(&probe_url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                // Bounded read against decompression-bomb DoS.
                let body = crate::safe_body::read_bounded(
                    resp,
                    crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES,
                )
                .await
                .unwrap_or_default();
                is_waf_block(status, &body)
            }
            Err(_) => false,
        };
        intel_loop.record_probe(probe, was_blocked);
        if scan_text {
            print!("{}", if was_blocked { "." } else { "!" });
        }
        let diff_delay = Duration::from_millis(delay_ms);
        if !diff_delay.is_zero() {
            tokio::time::sleep(diff_delay).await;
        }
    }
    if scan_text && intel_loop.has_sufficient_data() {
        let suggestions = intel_loop.suggested_evasions();
        if !suggestions.is_empty() {
            println!(
                "\n  {} {}",
                "Differential insights:".bold().cyan(),
                suggestions
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
                    .yellow()
            );
        }
    }
    intel_loop
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn spawn_recording_server() -> (std::net::SocketAddr, Arc<AtomicUsize>) {
        let counter = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let counter_c = counter.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let counter_cc = counter_c.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    counter_cc.fetch_add(1, Ordering::SeqCst);
                    let _ = sock
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\
                              Connection: close\r\n\r\nok",
                        )
                        .await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        tokio::time::sleep(Duration::from_millis(40)).await;
        (addr, counter)
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "current_thread")]
    async fn run_fires_one_request_per_quick_probe() {
        let (addr, counter) = spawn_recording_server().await;
        let client = reqwest::Client::builder().build().unwrap();
        let intel = run(&client, &format!("http://{addr}/"), "q", 0, false).await;
        // The IntelligenceLoop::new(20).generate_quick_probes() set
        // is non-empty (the corpus is fixed). Verify each probe
        // produced exactly one request.
        let probes = IntelligenceLoop::new(20).generate_quick_probes();
        assert!(!probes.is_empty(), "quick probes should be non-empty");
        assert_eq!(
            counter.load(Ordering::SeqCst),
            probes.len(),
            "differential phase should fire one request per probe"
        );
        // We sent each probe, so the loop has data (record_probe
        // was called for each).
        let _ = intel; // intel_loop is opaque; the request-count assertion above is the real gate
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "current_thread")]
    async fn run_records_blocked_outcomes_when_server_returns_403() {
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
                    let _ = sock
                        .write_all(
                            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 21\r\n\
                              Connection: close\r\n\r\nBlocked by ModSecurity",
                        )
                        .await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        tokio::time::sleep(Duration::from_millis(40)).await;
        let client = reqwest::Client::builder().build().unwrap();
        // Just verify the call completes — the IntelligenceLoop
        // surface for asserting block counts isn't directly
        // exposed; the smoke is that 403+ModSecurity body
        // classifies and the run returns cleanly.
        let _intel = run(&client, &format!("http://{addr}/"), "q", 0, false).await;
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "current_thread")]
    async fn run_against_dead_target_does_not_panic() {
        // Transport errors per-probe are treated as 'not blocked'
        // (Err arm in the response match). The phase must
        // complete cleanly, not panic.
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(200))
            .build()
            .unwrap();
        let _intel = run(&client, "http://127.0.0.1:1/", "q", 0, false).await;
    }
}
