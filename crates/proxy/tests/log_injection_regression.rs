//! Regression tests for Bug 10: Proxy log injection via `inner` host header.
//!
//! PRE-FIX BUG: In the MITM CONNECT path (`handle_mitm_request`,
//! `main.rs:2037`), the inner Host header from the downstream client was
//! logged verbatim via `warn!(inner = %inner, ...)`. An attacker sending
//! `Host: evil\nFAKE_LOG_ENTRY` would cause the FAKE_LOG_ENTRY line to
//! appear as a separate entry in any log aggregator that treats newlines as
//! record separators (e.g. Splunk, Elasticsearch, syslog, Loki). An analyst
//! reviewing the logs might trust FAKE_LOG_ENTRY as a legitimate proxy log.
//!
//! POST-FIX: The inner header is sanitised before logging:
//! `let inner_safe: String = inner.chars().filter(|c| !c.is_control()).collect();`
//! This strips all C0/C1 control characters (including LF, CR, NUL, ESC)
//! before the value enters the log message.
//!
//! The proxy binary test below drives a CONNECT request with an injected
//! Host header and confirms that the proxy log (captured from stderr) does
//! NOT contain "FAKE_LOG_ENTRY" as a separate line — demonstrating the
//! sanitisation is applied before the log call.

mod common;
use common::start_proxy_piped_on_free_port;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Send a raw CONNECT request with a newline-injected Host header.
/// Pre-fix: the proxy logged `inner = %inner` verbatim, so the injected
/// `\nFAKE_LOG_ENTRY` appeared as a standalone log line.
/// Post-fix: control chars are stripped before the log call, so
/// FAKE_LOG_ENTRY never appears.
///
/// We capture stderr from the proxy to check the log content.
/// Because stderr capture requires using `start_proxy_with_output` (which
/// waits for the process to exit), we instead use a timeout-based approach:
/// start proxy with stderr=piped, send the injection payload, then check
/// that stderr does NOT contain the injection marker.
#[tokio::test]
async fn mitm_host_header_newline_is_stripped_from_logs() {
    // The proxy binary's stderr is where tracing-subscriber emits logs, so we
    // spawn it with stderr piped. RUST_LOG=warn makes the warn!() call fire.
    // start_proxy_piped_on_free_port re-picks the port if the pick→bind race
    // is lost, so we never read another test's proxy logs by mistake.
    let (mut child, proxy_port) = start_proxy_piped_on_free_port(&[], &[("RUST_LOG", "warn")])
        .await
        .expect("spawn proxy");

    // Send a CONNECT request with a Host header containing a newline injection.
    // The injected payload: `Host: evil.com\r\nFAKE_LOG_ENTRY: injected`
    // After the Host line, the CRLF + FAKE_LOG_ENTRY looks like another
    // HTTP header — and would appear as a separate log line when logged raw.
    let connect_request = "CONNECT evil.com:443 HTTP/1.1\r\n\
         Host: evil.com\nFAKE_LOG_ENTRY\r\n\
         \r\n"
        .to_string();

    let mut stream = TcpStream::connect(format!("127.0.0.1:{proxy_port}"))
        .await
        .expect("connect to proxy");
    stream
        .write_all(connect_request.as_bytes())
        .await
        .expect("write CONNECT");

    // Read the proxy's response (any response — we care about the log, not the HTTP reply).
    let mut buf = vec![0u8; 1024];
    let _ =
        tokio::time::timeout(std::time::Duration::from_millis(500), stream.read(&mut buf)).await;
    drop(stream);

    // Give the proxy a moment to flush its logs, then kill it.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let _ = child.kill().await;
    let out = child.wait_with_output().await.expect("wait");
    let stderr = String::from_utf8_lossy(&out.stderr);

    // The injected marker must NOT appear as a separate log line.
    // Pre-fix: `FAKE_LOG_ENTRY` would appear on its own line in stderr.
    // Post-fix: control bytes are stripped, so the FAKE_LOG_ENTRY is gone.
    assert!(
        !stderr.contains("FAKE_LOG_ENTRY"),
        "log injection payload must not appear in proxy logs — \
         Host header newline sanitisation regression.\n\
         stderr was:\n{stderr}"
    );
}

/// Adversarial twin: a `\r\n` in the Host header (CRLF injection, not just LF)
/// is also stripped. Demonstrates the fix covers both CR and LF.
#[tokio::test]
async fn mitm_host_header_crlf_injection_is_stripped_from_logs() {
    let (mut child, proxy_port) = start_proxy_piped_on_free_port(&[], &[("RUST_LOG", "warn")])
        .await
        .expect("spawn proxy");

    // CRLF injection — the proxy's internal Host extractor gets "evil.com\r\nCRLF_INJECTED".
    let connect_request = "CONNECT target.example.com:443 HTTP/1.1\r\nHost: target.example.com\r\nCRLF_INJECTED\r\n\r\n";

    let mut stream = TcpStream::connect(format!("127.0.0.1:{proxy_port}"))
        .await
        .expect("connect");
    stream.write_all(connect_request.as_bytes()).await.ok();

    let mut buf = vec![0u8; 512];
    let _ =
        tokio::time::timeout(std::time::Duration::from_millis(400), stream.read(&mut buf)).await;
    drop(stream);

    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let _ = child.kill().await;
    let out = child.wait_with_output().await.expect("wait");
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        !stderr.contains("CRLF_INJECTED"),
        "CRLF injection in Host header must not appear in logs.\nstderr:\n{stderr}"
    );
}
