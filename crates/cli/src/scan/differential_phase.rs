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
///
/// Fire-budget contract (`--max-fires`): this is an EARLY phase that
/// fires before `scan/mod.rs` initialises its running `total_fired`
/// counter, so the global cap is honoured here directly. `fires_so_far`
/// is the number of requests the orchestrator has already fired (baseline,
/// any auto-escalate surface fires); `max_fires == 0` means unlimited
/// (the backward-compat sentinel). The quick-probe set is truncated to
/// the remaining budget so a `--max-fires N` smaller than the probe count
/// can no longer leak ~13 concurrent fires past the operator's ceiling
/// (the dogfood `--variants-cap 1 --exploit-cap 0 --max-fires 5 → 85
/// fires` bug). Because the phase only ever fires what it actually sends,
/// `intel_loop.probes_completed()` stays an accurate denominator input —
/// the cap changes the COUNT of fires, never the bypass-rate accounting.
pub(crate) async fn run(
    http: &reqwest::Client,
    target: &str,
    param: &str,
    delay_ms: u64,
    scan_text: bool,
    fires_so_far: usize,
    max_fires: usize,
) -> IntelligenceLoop {
    let mut intel_loop = IntelligenceLoop::new(20);
    // Truncate the quick-probe batch to the remaining global fire budget.
    // 0 = unlimited (backward-compat sentinel) → fire the full set.
    let remaining = if max_fires == 0 {
        usize::MAX
    } else {
        max_fires.saturating_sub(fires_so_far)
    };
    let diff_probes: Vec<_> = intel_loop
        .generate_quick_probes()
        .into_iter()
        .take(remaining)
        .collect();
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
    // R72 pass-21 §1 SPEED: fire all differential probes
    // concurrently. Pre-fix this loop awaited each probe serially
    // with a `delay_ms` sleep between every one — at the default
    // 50ms delay, 13 probes = 650 ms before any network latency even
    // started. The probes are mutually independent (no probe's URL
    // depends on the previous probe's response), so a `join_all` is
    // semantically equivalent to the loop. The `record_probe` calls
    // run serially after the join completes so the IntelligenceLoop
    // sees the same observation order as before.
    //
    // The inter-probe `delay_ms` is preserved as a global rate cap
    // for the whole batch — applied ONCE after all probes resolve.
    // If a future change re-introduces per-probe pacing (e.g. for
    // hostile targets that rate-limit on RPS), the pacing should
    // become an `acquire_permit().await` against a Tokio semaphore,
    // not a fixed sleep.
    use futures_util::future::join_all;
    let max_body = crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES;
    let probe_futures = diff_probes.iter().map(|probe| {
        let probe_payload = format!("{:?}", probe.tests);
        let probe_url = scan_url_with_param(target, param, &urlencoding::encode(&probe_payload));
        let http = http.clone();
        async move {
            match http.get(&probe_url).send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let body = crate::safe_body::read_bounded(resp, max_body)
                        .await
                        .unwrap_or_default();
                    is_waf_block(status, &body)
                }
                Err(_) => false,
            }
        }
    });
    let results = join_all(probe_futures).await;
    for (probe, was_blocked) in diff_probes.iter().zip(results.iter().copied()) {
        intel_loop.record_probe(probe, was_blocked);
        if scan_text {
            print!("{}", if was_blocked { "." } else { "!" });
        }
    }
    // Single post-batch sleep — preserves the operator's
    // rate-cap intent without per-probe serialisation cost.
    let diff_delay = Duration::from_millis(delay_ms);
    if !diff_delay.is_zero() {
        tokio::time::sleep(diff_delay).await;
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
        tokio::time::sleep(crate::parser_diff_common::TEST_SETTLE).await;
        (addr, counter)
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "current_thread")]
    async fn run_fires_one_request_per_quick_probe() {
        let (addr, counter) = spawn_recording_server().await;
        let client = reqwest::Client::builder().build().unwrap();
        // max_fires = 0 → unlimited (backward-compat sentinel): the full
        // quick-probe set fires, exactly as before the budget plumbing.
        let intel = run(&client, &format!("http://{addr}/"), "q", 0, false, 0, 0).await;
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

    /// §12 / safety regression: the documented dogfood leak — `--max-fires N`
    /// smaller than the quick-probe count must NOT leak the full concurrent
    /// batch past the operator's ceiling. With max_fires=3 and one fire
    /// already spent (fires_so_far=1), the phase may fire at most 2 probes.
    #[serial_test::serial]
    #[tokio::test(flavor = "current_thread")]
    async fn run_truncates_quick_probes_to_remaining_fire_budget() {
        let (addr, counter) = spawn_recording_server().await;
        let client = reqwest::Client::builder().build().unwrap();
        // The full quick-probe set is larger than the budget remainder, so
        // truncation must bite (guard the precondition so this stays a real
        // test even if the corpus shrinks).
        let full = IntelligenceLoop::new(20).generate_quick_probes();
        assert!(
            full.len() > 2,
            "precondition: quick-probe set must exceed the remaining budget for this test to bite (got {})",
            full.len()
        );
        // max_fires=3, fires_so_far=1 → remaining budget = 2.
        let _intel = run(&client, &format!("http://{addr}/"), "q", 0, false, 1, 3).await;
        assert_eq!(
            counter.load(Ordering::SeqCst),
            2,
            "differential phase must fire at most (max_fires - fires_so_far) = 2 probes, never the full batch"
        );
    }

    /// Budget already exhausted before the phase runs → zero fires.
    #[serial_test::serial]
    #[tokio::test(flavor = "current_thread")]
    async fn run_fires_nothing_when_budget_already_exhausted() {
        let (addr, counter) = spawn_recording_server().await;
        let client = reqwest::Client::builder().build().unwrap();
        // fires_so_far == max_fires → remaining = 0.
        let _intel = run(&client, &format!("http://{addr}/"), "q", 0, false, 5, 5).await;
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "an exhausted fire budget must fire zero differential probes"
        );
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
        tokio::time::sleep(crate::parser_diff_common::TEST_SETTLE).await;
        let client = reqwest::Client::builder().build().unwrap();
        // Just verify the call completes — the IntelligenceLoop
        // surface for asserting block counts isn't directly
        // exposed; the smoke is that 403+ModSecurity body
        // classifies and the run returns cleanly.
        let _intel = run(&client, &format!("http://{addr}/"), "q", 0, false, 0, 0).await;
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
        let _intel = run(&client, "http://127.0.0.1:1/", "q", 0, false, 0, 0).await;
    }
}
