//! Scan's Step 2 — baseline fire of the raw payload.
//!
//! Before any evasion, hit the target with the unmodified payload
//! and observe what happens. The result is the load-bearing pivot
//! for everything downstream:
//!
//! - WAF blocks (the typical case) — confirms WAF is active on
//!   this parameter; the variant loop is meaningful.
//! - WAF passes through — the parameter isn't inspected; the
//!   scan should still proceed but warn the operator that
//!   "evasion" against an unguarded parameter is a noise-floor
//!   measurement, not a finding.
//! - Transport error — the target isn't reachable at all;
//!   nothing downstream will work.
//!
//! Lives in its own module so scan/mod.rs reads as "0, 1, 2, …"
//! orchestration with each phase named, not 50 lines of inline
//! request-classify-print per phase.

use colored::Colorize;
use wafrift_transport::is_waf_block;

use super::scan_url_with_param;

/// Outcome of the baseline fire. `transport_ok = false` means we
/// couldn't reach the target at all (DNS / connect / TLS) — every
/// downstream phase becomes meaningless, but we don't bail outright
/// because the operator may want to see the variant build output
/// anyway (useful for debugging filter / strategy selection without
/// a live target).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaselineOutcome {
    pub status: u16,
    pub blocked: bool,
    pub transport_ok: bool,
}

/// Fire the raw payload at the target's `param` and classify the
/// response.
pub async fn run(
    http: &reqwest::Client,
    target: &str,
    param: &str,
    payload: &str,
    scan_text: bool,
) -> BaselineOutcome {
    if scan_text {
        println!(
            "\n{}",
            "[2/7] Testing baseline (raw payload)...".bold().cyan()
        );
    }
    let raw_url = scan_url_with_param(target, param, &urlencoding::encode(payload));
    let outcome = match http.get(&raw_url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.bytes().await.unwrap_or_default();
            let blocked = is_waf_block(status, &body);
            BaselineOutcome {
                status,
                blocked,
                transport_ok: true,
            }
        }
        Err(e) => {
            eprintln!(
                "  {} {}",
                "✗ Baseline request failed (transport):".red().bold(),
                e
            );
            BaselineOutcome {
                status: 0,
                blocked: false,
                transport_ok: false,
            }
        }
    };
    if scan_text {
        render_text(&outcome);
    }
    outcome
}

fn render_text(outcome: &BaselineOutcome) {
    if !outcome.transport_ok {
        println!(
            "  {}",
            "⚠ Baseline inconclusive — fix connectivity and re-run"
                .yellow()
                .bold()
        );
        return;
    }
    if outcome.blocked {
        println!(
            "  {} (HTTP {})",
            "✓ Raw payload BLOCKED — WAF is active".green().bold(),
            outcome.status
        );
    } else {
        println!(
            "  {} (HTTP {})",
            "⚠ Raw payload PASSED — WAF may not inspect this parameter"
                .yellow()
                .bold(),
            outcome.status
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Spin a tiny mock server that returns the given response to
    /// every request.
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
        tokio::time::sleep(Duration::from_millis(40)).await;
        addr
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_with_blocked_response_returns_blocked_true() {
        let addr = spawn_mock(
            "HTTP/1.1 403 Forbidden\r\nContent-Length: 30\r\nConnection: close\r\n\r\n\
             <html>Blocked by ModSecurity</html>",
        )
        .await;
        let client = reqwest::Client::builder().build().unwrap();
        let outcome = run(&client, &format!("http://{addr}"), "q", "<script>", false).await;
        assert!(outcome.transport_ok);
        assert_eq!(outcome.status, 403);
        assert!(outcome.blocked, "ModSecurity body should classify as block");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_with_200_response_returns_blocked_false() {
        let addr = spawn_mock(
            "HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello world",
        )
        .await;
        let client = reqwest::Client::builder().build().unwrap();
        let outcome = run(&client, &format!("http://{addr}"), "q", "harmless", false).await;
        assert!(outcome.transport_ok);
        assert_eq!(outcome.status, 200);
        assert!(!outcome.blocked, "plain 200 should NOT classify as block");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_against_dead_port_returns_transport_failure() {
        // 127.0.0.1:1 is almost certainly nothing-is-listening.
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let outcome = run(&client, "http://127.0.0.1:1", "q", "payload", false).await;
        assert!(!outcome.transport_ok);
        assert_eq!(outcome.status, 0);
        assert!(!outcome.blocked);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_passes_payload_through_query_string() {
        // The baseline request must inject the payload into the
        // `param` query — sanity for the URL shape downstream
        // phases assume.
        let received = Arc::new(std::sync::Mutex::new(String::new()));
        let received_c = received.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _counter = Arc::new(AtomicUsize::new(0));
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let received_cc = received_c.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    *received_cc.lock().unwrap() =
                        String::from_utf8_lossy(&buf[..n]).to_string();
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
        let client = reqwest::Client::builder().build().unwrap();
        let _ = run(&client, &format!("http://{addr}"), "id", "victim123", false).await;
        let req = received.lock().unwrap().clone();
        assert!(
            req.contains("id=victim123") || req.contains("id=victim123"),
            "URL should carry id=victim123: {req}"
        );
    }
}
