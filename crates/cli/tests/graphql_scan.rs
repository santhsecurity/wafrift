//! End-to-end tests for `wafrift scan --graphql` and GraphQL auto-detection.
//!
//! Tests spawn raw TCP mock servers that speak a minimal subset of HTTP/1.1,
//! then drive the `wafrift` binary as a subprocess to assert:
//!
//! - Auto-detection: the scan finds `/graphql` on a server that returns
//!   a GraphQL-shaped response.
//! - `--graphql` flag: forces injection even without detection.
//! - Payload classes: alias-flood, introspection, op-name-mismatch payloads
//!   are all present in the request log.
//! - Content-Type routing (strategy crate): `application/graphql` body
//!   triggers the GraphQL battery; form-urlencoded does not.

use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ─── Helpers ────────────────────────────────────────────────────────────────

fn wafrift_bin(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_wafrift"))
        .args(args)
        .output()
        .expect("spawn wafrift binary");
    let code = output.status.code().unwrap_or(-1);
    (
        code,
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

/// Minimal GraphQL mock server.
///
/// - `GET /` → 200 "ok" (baseline)
/// - `POST /graphql` with `{"query":"{__typename}"}` probe → GraphQL response
/// - `POST /graphql` all others → 200 with a logged body
/// - All other paths → 404
///
/// Returns `(addr, request_log)` where `request_log` accumulates every POST
/// body received at `/graphql`.
async fn spawn_graphql_mock() -> (std::net::SocketAddr, Arc<tokio::sync::Mutex<Vec<String>>>) {
    let log: Arc<tokio::sync::Mutex<Vec<String>>> = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let log_c = log.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let log_cc = log_c.clone();
            tokio::spawn(async move {
                // Read the full request (simple Content-Length reader).
                let mut buf: Vec<u8> = Vec::with_capacity(8192);
                let mut tmp = [0u8; 4096];
                let mut headers_done = false;
                let mut content_length: usize = 0;
                let mut header_end: usize = 0;
                loop {
                    let n = match sock.read(&mut tmp).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    buf.extend_from_slice(&tmp[..n]);
                    if !headers_done {
                        if let Some(pos) = find_double_crlf(&buf) {
                            headers_done = true;
                            header_end = pos + 4;
                            let hdr = String::from_utf8_lossy(&buf[..pos]);
                            for line in hdr.lines() {
                                let lower = line.to_ascii_lowercase();
                                if let Some(v) = lower.strip_prefix("content-length:") {
                                    content_length = v.trim().parse().unwrap_or(0);
                                }
                            }
                        }
                    }
                    if headers_done && buf.len() >= header_end + content_length {
                        break;
                    }
                }

                let req_str = String::from_utf8_lossy(&buf).to_string();
                let is_post_graphql = req_str.starts_with("POST /graphql");
                let is_get_root = req_str.starts_with("GET /");

                // Extract body for POST requests.
                let body_bytes = if headers_done && header_end < buf.len() {
                    &buf[header_end..]
                } else {
                    &[]
                };
                let body_str = String::from_utf8_lossy(body_bytes).to_string();

                // Log every POST body to /graphql.
                if is_post_graphql && !body_str.trim().is_empty() {
                    log_cc.lock().await.push(body_str.clone());
                }

                let response = if is_get_root {
                    // Baseline GET → plain 200 (not GraphQL).
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_string()
                } else if is_post_graphql {
                    // Respond as a GraphQL endpoint.
                    let resp_body = r#"{"data":{"__typename":"Query"}}"#;
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_body}",
                        resp_body.len()
                    )
                } else {
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
                };

                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, log)
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
}

// ─── Tests ───────────────────────────────────────────────────────────────────

/// Test 1: `--graphql` flag in `wafrift scan --help`.
#[test]
fn scan_help_documents_graphql_flag() {
    let (code, stdout, _) = wafrift_bin(&["scan", "--help"]);
    assert_eq!(code, 0, "scan --help must exit 0");
    assert!(
        stdout.contains("--graphql"),
        "--graphql flag must appear in `wafrift scan --help`:\n{stdout}"
    );
}

/// Test 2: Auto-detection — when a target has `/graphql` that returns GraphQL
/// responses, the scan must find it and fire GraphQL payloads.
#[test]
fn auto_detection_fires_graphql_payloads_when_endpoint_found() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let (addr, log) = rt.block_on(spawn_graphql_mock());

    // Run a minimal scan: --encoding-only so the main variant loop is cheap,
    // but GraphQL detection still runs. Use --delay-ms 0 for speed.
    let target = format!("http://{addr}");
    let (_code, _stdout, stderr) = wafrift_bin(&[
        "scan",
        &target,
        "--payload",
        "test",
        "--param",
        "q",
        "--encoding-only",
        "--level",
        "light",
        "--delay-ms",
        "0",
        "--format",
        "text",
        "--quiet",
        "--i-have-permission",
        "test",
    ]);

    // The scan must have reached the GraphQL detection phase.
    // Check the request log — the probe body `{"query":"{__typename}"}` must appear.
    let received = rt.block_on(async { log.lock().await.clone() });
    let has_typename_probe = received.iter().any(|b| b.contains(r#"__typename"#));
    assert!(
        has_typename_probe,
        "GraphQL auto-detection probe `{{\"query\":\"{{__typename}}\"}}` must be fired; stderr:\n{stderr}\nreceived bodies: {received:?}"
    );
}

/// Test 3: `--graphql` flag forces payload injection at the BASE URL even
/// without a detected `/graphql` path.
#[test]
fn graphql_flag_forces_injection_at_base_url() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let (addr, log) = rt.block_on(spawn_graphql_mock());

    let target = format!("http://{addr}/graphql");
    let (_code, _stdout, stderr) = wafrift_bin(&[
        "scan",
        &target,
        "--payload",
        "test",
        "--param",
        "q",
        "--encoding-only",
        "--level",
        "light",
        "--delay-ms",
        "0",
        "--graphql",
        "--format",
        "text",
        "--quiet",
        "--i-have-permission",
        "test",
    ]);

    let received = rt.block_on(async { log.lock().await.clone() });
    // With --graphql the evasion payloads fire; assert at least one GraphQL
    // evasion body (not just the detection probe) landed.
    let evasion_fired = received.iter().any(|b| {
        b.contains("AliasFlood") || b.contains("__schema") || b.contains("operationName")
    });
    assert!(
        evasion_fired,
        "--graphql flag must inject alias-flood/introspection/op-name-mismatch payloads; stderr:\n{stderr}\nbodies: {received:?}"
    );
}

/// Test 4: All three payload classes — alias-flood, introspection, op-name-mismatch —
/// appear in the bodies logged by the mock when `--graphql` is active.
#[test]
fn graphql_payload_set_covers_all_three_classes() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let (addr, log) = rt.block_on(spawn_graphql_mock());

    let target = format!("http://{addr}/graphql");
    let (_code, _stdout, _stderr) = wafrift_bin(&[
        "scan",
        &target,
        "--payload",
        "test",
        "--param",
        "q",
        "--encoding-only",
        "--level",
        "light",
        "--delay-ms",
        "0",
        "--graphql",
        "--quiet",
        "--i-have-permission",
        "test",
    ]);

    let received = rt.block_on(async { log.lock().await.clone() });
    let has_alias = received.iter().any(|b| b.contains("AliasFlood"));
    let has_intro = received.iter().any(|b| b.contains("__schema"));
    let has_mismatch = received.iter().any(|b| b.contains("operationName"));
    assert!(
        has_alias,
        "alias-flood payloads must appear in request log; bodies: {received:?}"
    );
    assert!(
        has_intro,
        "introspection payloads must appear in request log; bodies: {received:?}"
    );
    assert!(
        has_mismatch,
        "op-name-mismatch payloads must appear in request log; bodies: {received:?}"
    );
}

/// Test 5: Content-Type routing in the strategy crate.
/// `application/graphql` is recognised as a GraphQL request.
#[test]
fn strategy_content_type_routing_application_graphql() {
    // This is a pure-logic unit test — no network.
    use wafrift_strategy::{graphql_payloads_for_request, is_graphql_request};
    use wafrift_types::Request;

    let req = Request::post(
        "https://example.com/graphql",
        b"{ user { id name } }".to_vec(),
    )
    .header("Content-Type", "application/graphql");

    assert!(
        is_graphql_request(&req),
        "application/graphql Content-Type must be detected as GraphQL"
    );
    let payloads = graphql_payloads_for_request(&req);
    assert!(
        !payloads.is_empty(),
        "graphql_payloads_for_request must return battery for application/graphql requests"
    );
}

/// Test 6: JSON body routing in the strategy crate.
/// `{"query": "..."}` body is recognised as a GraphQL request.
#[test]
fn strategy_json_body_routing() {
    use wafrift_strategy::{graphql_payloads_for_request, is_graphql_request};
    use wafrift_types::Request;

    let body = br#"{"query":"{ user { id name } }","variables":{}}"#;
    let req = Request::post("https://example.com/graphql", body.to_vec())
        .header("Content-Type", "application/json");

    assert!(
        is_graphql_request(&req),
        "JSON body with \"query\": key must be detected as GraphQL"
    );
    let payloads = graphql_payloads_for_request(&req);
    assert!(!payloads.is_empty());
    // Verify all three classes are present.
    assert!(payloads.iter().any(|p| p.contains("AliasFlood")));
    assert!(payloads.iter().any(|p| p.contains("__schema")));
    assert!(payloads.iter().any(|p| p.contains("operationName")));
}

/// Test 7: Form-urlencoded body is NOT routed to GraphQL battery.
#[test]
fn strategy_form_body_not_routed_to_graphql() {
    use wafrift_strategy::{graphql_payloads_for_request, is_graphql_request};
    use wafrift_types::Request;

    let req = Request::post(
        "https://example.com/api",
        b"q=SELECT+1+FROM+users".to_vec(),
    )
    .header("Content-Type", "application/x-www-form-urlencoded");

    assert!(
        !is_graphql_request(&req),
        "form-urlencoded body must NOT be detected as GraphQL"
    );
    let payloads = graphql_payloads_for_request(&req);
    assert!(
        payloads.is_empty(),
        "graphql_payloads_for_request must return empty Vec for form-urlencoded requests"
    );
}

/// Test 8: GET request without body is not routed to GraphQL battery.
#[test]
fn strategy_get_without_body_not_graphql() {
    use wafrift_strategy::is_graphql_request;
    use wafrift_types::Request;

    let req = Request::get("https://example.com/graphql?query={__typename}");
    assert!(
        !is_graphql_request(&req),
        "GET without body must not be detected as GraphQL"
    );
}
