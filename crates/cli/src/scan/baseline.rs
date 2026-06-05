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

/// Outcome of the baseline fire. `transport_ok = false` means we
/// couldn't reach the target at all (DNS / connect / TLS) — every
/// downstream phase becomes meaningless, but we don't bail outright
/// because the operator may want to see the variant build output
/// anyway (useful for debugging filter / strategy selection without
/// a live target).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BaselineOutcome {
    pub status: u16,
    pub blocked: bool,
    pub transport_ok: bool,
    /// Response fingerprint of the raw-payload baseline GET (for engagement checks).
    pub fingerprint: Option<super::waf_engagement::ResponseFingerprint>,
}

/// Fire the raw payload at the target's `param` and classify the
/// response (GET query string).
pub(crate) async fn run(
    http: &reqwest::Client,
    target: &str,
    param: &str,
    payload: &str,
    scan_text: bool,
) -> BaselineOutcome {
    run_with_delivery(
        http,
        target,
        param,
        payload,
        scan_text,
        super::injection_delivery::InjectionDelivery::GetQuery,
    )
    .await
}

/// Fire baseline using the same delivery mode as the variant loop.
pub(crate) async fn run_with_delivery(
    http: &reqwest::Client,
    target: &str,
    param: &str,
    payload: &str,
    scan_text: bool,
    delivery: super::injection_delivery::InjectionDelivery,
) -> BaselineOutcome {
    if scan_text {
        let mode = match delivery {
            super::injection_delivery::InjectionDelivery::GetQuery => "GET",
            super::injection_delivery::InjectionDelivery::PostForm => "POST form",
        };
        println!(
            "\n{}",
            format!("[2/7] Testing baseline (raw payload, {mode})...")
                .bold()
                .cyan()
        );
    }
    let outcome =
        match super::injection_delivery::fire_raw_payload(http, delivery, target, param, payload)
            .await
        {
            Some((status, body, blocked)) => {
                let fingerprint = Some(super::waf_engagement::ResponseFingerprint::from_parts(
                    status, &body,
                ));
                BaselineOutcome {
                    status,
                    blocked,
                    transport_ok: true,
                    fingerprint,
                }
            }
            None => {
                eprintln!("  {}", "✗ Baseline request failed (transport)".red().bold(),);
                BaselineOutcome {
                    status: 0,
                    blocked: false,
                    transport_ok: false,
                    fingerprint: None,
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
    use crate::scan::waf_engagement::ResponseFingerprint;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
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
        tokio::time::sleep(crate::parser_diff_common::TEST_SETTLE).await;
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
    async fn run_with_200_response_captures_fingerprint() {
        let addr = spawn_mock(
            "HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello world",
        )
        .await;
        let client = reqwest::Client::builder().build().unwrap();
        let outcome = run(&client, &format!("http://{addr}"), "q", "harmless", false).await;
        let fp = outcome.fingerprint.expect("200 response must fingerprint");
        assert_eq!(fp.status, 200);
        assert_eq!(fp.body_len, 11);
        assert_eq!(
            fp.body_digest,
            ResponseFingerprint::from_parts(200, b"hello world").body_digest
        );
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
                    *received_cc.lock().unwrap() = String::from_utf8_lossy(&buf[..n]).to_string();
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
        let client = reqwest::Client::builder().build().unwrap();
        let _ = run(&client, &format!("http://{addr}"), "id", "victim123", false).await;
        let req = received.lock().unwrap().clone();
        // The payload "victim123" is all unreserved ASCII, so it must
        // appear verbatim in the query string (no encoding artifacts).
        // Also check that a second encoding pass did NOT happen — if
        // scan_url_with_param double-encoded, "%" would appear in the
        // raw request (there are no percent chars in "victim123" so
        // any "%" means an encoding pass ran on an already-plain value).
        assert!(
            req.contains("id=victim123"),
            "URL should carry id=victim123 (singly-encoded): {req}"
        );
        assert!(
            !req.contains("id=%"),
            "id= must not be percent-escaped (would indicate double-encoding): {req}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_encodes_special_chars_exactly_once() {
        // A payload with special characters must arrive singly-encoded.
        // The baseline module calls `urlencoding::encode(payload)` and
        // passes it to `scan_url_with_param`, which must NOT re-encode.
        // Concrete contract: `<script>` → wire carries `%3Cscript%3E`,
        // NOT `%253Cscript%253E` (double-encoded `%` → `%25`).
        let received = Arc::new(std::sync::Mutex::new(String::new()));
        let received_c = received.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let received_cc = received_c.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    *received_cc.lock().unwrap() = String::from_utf8_lossy(&buf[..n]).to_string();
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
        let client = reqwest::Client::builder().build().unwrap();
        let _ = run(&client, &format!("http://{addr}"), "q", "<script>", false).await;
        let req = received.lock().unwrap().clone();
        // Single-encoded: `<` = %3C, `>` = %3E.
        assert!(
            req.contains("%3Cscript%3E") || req.contains("%3cscript%3e"),
            "payload must be singly percent-encoded on the wire: {req}"
        );
        // Double-encoded: `%` → %25, so `%3C` would become `%253C`.
        assert!(
            !req.contains("%253C") && !req.contains("%253c"),
            "double-encoding detected — scan_url_with_param re-encoded an already-encoded value: {req}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_with_sql_payload_encodes_single_quote_once() {
        // SQL injection payloads routinely contain `'` (apostrophe, %27).
        // Double-encoding would send `%2527` — a wasted probe that no
        // WAF could mistake for a SQL injection.
        let received = Arc::new(std::sync::Mutex::new(String::new()));
        let received_c = received.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let received_cc = received_c.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    *received_cc.lock().unwrap() = String::from_utf8_lossy(&buf[..n]).to_string();
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
        let client = reqwest::Client::builder().build().unwrap();
        let _ = run(
            &client,
            &format!("http://{addr}"),
            "q",
            "' OR '1'='1",
            false,
        )
        .await;
        let req = received.lock().unwrap().clone();
        // Single-encoded apostrophe is %27; double-encoded would be %2527.
        assert!(
            req.contains("%27") || req.contains("q='"),
            "apostrophe must arrive singly-encoded: {req}"
        );
        assert!(
            !req.contains("%2527"),
            "double-encoded apostrophe detected: {req}"
        );
    }

    #[test]
    fn render_text_transport_failure_path_does_not_panic() {
        // Non-async unit test for the render_text branch that handles
        // transport_ok=false (the "fix connectivity and re-run" banner).
        // Previously untested — ensures `render_text` handles the sad
        // path without unwrapping or panicking.
        let outcome = BaselineOutcome {
            status: 0,
            blocked: false,
            transport_ok: false,
            fingerprint: None,
        };
        // Should not panic.
        render_text(&outcome);
    }
}
