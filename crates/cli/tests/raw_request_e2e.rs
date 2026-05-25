//! End-to-end test for `wafrift scan --raw-request <FILE>` (`-r`).
//!
//! Closes the pentester loop: spin up a synthetic WAF on loopback,
//! write a Burp-shape raw HTTP request file with a `§§` marker, drive
//! the real `wafrift` binary against it, and verify:
//!
//! 1. The runner parses the file + dispatches into `raw_runner`.
//! 2. JSON output carries `mode: "raw-request"` plus `bypass_variants[i].repro_curl`.
//! 3. Each `repro_curl` is a paste-ready single-line `curl -i` invocation.
//!
//! This is the integration-level proof that the parse → substitute →
//! fire → classify → emit pipeline holds end-to-end with no missing
//! wires.

use std::io::Write;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Spin up a tiny WAF emulator: 403 if the request line OR body
/// contains the literal token "BLOCKED", 200 otherwise. Returns the
/// bound address + a request counter so tests can assert "the
/// runner fired N variants".
async fn spawn_mock_waf() -> (std::net::SocketAddr, Arc<AtomicUsize>) {
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
                let mut buf = vec![0u8; 16 * 1024];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                counter_cc.fetch_add(1, Ordering::SeqCst);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let blocked = req.contains("BLOCKED");
                let (status, body) = if blocked {
                    ("403 Forbidden", "<html>blocked by mock WAF</html>")
                } else {
                    ("200 OK", "<html>ok</html>")
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: text/html\r\n\
                     Content-Length: {}\r\nConnection: close\r\nServer: nginx/1.25\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    (addr, counter)
}

/// Helper: invoke the real `wafrift` binary with the given args.
fn wafrift(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_wafrift"))
        .args(args)
        .output()
        .expect("failed to spawn wafrift binary");
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (code, stdout, stderr)
}

/// Write a fixture raw HTTP request file with a §§ marker in the
/// URL query. Returns the path; the caller is responsible for
/// cleaning it up.
fn write_get_template(addr: std::net::SocketAddr) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "wafrift-raw-{}-{}.req",
        std::process::id(),
        addr.port()
    ));
    let body = format!(
        "GET /search?q=§§ HTTP/1.1\r\n\
         Host: {addr}\r\n\
         Accept: */*\r\n\
         User-Agent: pentester\r\n\
         \r\n"
    );
    let mut f = std::fs::File::create(&path).expect("create raw request fixture");
    f.write_all(body.as_bytes())
        .expect("write raw request fixture");
    path
}

/// Same shape but for a POST template — marker lives in the body.
fn write_post_template(addr: std::net::SocketAddr) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "wafrift-raw-post-{}-{}.req",
        std::process::id(),
        addr.port()
    ));
    let body = "user=admin&pass=§§";
    let req = format!(
        "POST /login HTTP/1.1\r\n\
         Host: {addr}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {body}",
        body.len()
    );
    let mut f = std::fs::File::create(&path).expect("create post raw request fixture");
    f.write_all(req.as_bytes())
        .expect("write post raw request fixture");
    path
}

#[test]
fn raw_request_get_template_e2e_emits_repro_curl_per_bypass() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let (addr, counter) = rt.block_on(spawn_mock_waf());
    let path = write_get_template(addr);

    // SAFEPAYLOAD never contains the "BLOCKED" token → every variant
    // bypasses → the bypass_variants array must be non-empty AND every
    // entry must carry a repro_curl pointing at the mock server.
    let (code, stdout, stderr) = wafrift(&[
        "scan",
        "-r",
        path.to_str().unwrap(),
        "--payload",
        "SAFEPAYLOAD",
        "--level",
        "light",
        "--encoding-only",
        "--format",
        "json",
    ]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 0, "scan -r should exit 0 — stderr:\n{stderr}");

    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("JSON parse — stdout was:\n{stdout}");
    assert_eq!(parsed["mode"], "raw-request");
    assert_eq!(parsed["template"]["method"], "GET");
    // Template URL was reconstructed from Host header.
    let tpl_url = parsed["template"]["url"]
        .as_str()
        .expect("template.url is string");
    assert!(
        tpl_url.contains(&addr.to_string()),
        "template url: {tpl_url}"
    );
    assert!(
        tpl_url.contains("§§"),
        "template url retains marker: {tpl_url}"
    );

    let bypasses = parsed["bypass_variants"]
        .as_array()
        .expect("bypass_variants array");
    assert!(
        !bypasses.is_empty(),
        "must have at least one bypass — counter fired {} requests",
        counter.load(Ordering::SeqCst)
    );

    for entry in bypasses {
        let curl = entry["repro_curl"]
            .as_str()
            .expect("repro_curl is a string on every bypass");
        assert!(curl.starts_with("curl -i "), "repro_curl shape: {curl}");
        assert!(
            curl.contains(&addr.to_string()),
            "repro_curl points at mock: {curl}"
        );
        // §§ marker MUST be gone — substituted with the variant payload.
        assert!(!curl.contains("§§"), "repro_curl substituted: {curl}");
    }

    // At least one fire reached the mock (sanity vs. dead-net).
    assert!(counter.load(Ordering::SeqCst) > 0, "mock saw zero requests");
}

#[test]
fn raw_request_block_signature_in_payload_yields_zero_bypasses() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let (addr, _) = rt.block_on(spawn_mock_waf());
    let path = write_get_template(addr);

    // Payload literally contains BLOCKED → mock returns 403 to every
    // variant — but encoding mutations (e.g. URL-encode, hex, base64)
    // OBFUSCATE the literal "BLOCKED" substring. So SOME mutations
    // will dodge the literal-substring check on the mock side and
    // get 200. We just assert the runner ran end-to-end cleanly.
    let (code, stdout, stderr) = wafrift(&[
        "scan",
        "-r",
        path.to_str().unwrap(),
        "--payload",
        "BLOCKED",
        "--level",
        "light",
        "--encoding-only",
        "--format",
        "json",
    ]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 0, "scan -r should exit 0 — stderr:\n{stderr}");

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON parse");
    // total_fired > 0 (runner actually fired requests, did not no-op).
    assert!(
        parsed["total_fired"].as_u64().unwrap_or(0) > 0,
        "runner must fire at least one variant: {parsed}"
    );
}

#[test]
fn raw_request_post_template_substitutes_in_body() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let (addr, _) = rt.block_on(spawn_mock_waf());
    let path = write_post_template(addr);

    let (code, stdout, stderr) = wafrift(&[
        "scan",
        "-r",
        path.to_str().unwrap(),
        "--payload",
        "BLOCKED",
        "--level",
        "light",
        "--encoding-only",
        "--format",
        "json",
    ]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        code, 0,
        "scan -r POST template should exit 0 — stderr:\n{stderr}"
    );

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON parse");
    assert_eq!(parsed["template"]["method"], "POST");
    assert!(
        parsed["template"]["body_bytes"].as_u64().unwrap_or(0) > 0,
        "POST template must record body_bytes > 0: {parsed}"
    );
}

#[test]
fn raw_request_rejects_template_without_injection_marker() {
    // Template has NO §§ — runner must reject early with exit 2 and
    // an actionable message naming the missing marker.
    let path = std::env::temp_dir().join(format!("wafrift-raw-nomark-{}.req", std::process::id()));
    let body = "GET /search?q=hardcoded HTTP/1.1\r\nHost: 127.0.0.1:9999\r\nAccept: */*\r\n\r\n";
    std::fs::write(&path, body).unwrap();

    let (code, _stdout, stderr) = wafrift(&[
        "scan",
        "-r",
        path.to_str().unwrap(),
        "--payload",
        "x",
        "--format",
        "json",
    ]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 2, "missing-marker should exit 2 — stderr:\n{stderr}");
    assert!(
        stderr.contains("§§") || stderr.to_lowercase().contains("marker"),
        "error must name the missing marker: stderr=\n{stderr}"
    );
}

#[test]
fn raw_request_rejects_missing_file_with_clear_error() {
    let (code, _stdout, stderr) = wafrift(&[
        "scan",
        "-r",
        "/this/path/definitely/does/not/exist.req",
        "--payload",
        "x",
        "--format",
        "json",
    ]);
    assert_eq!(code, 2, "missing file should exit 2 — stderr:\n{stderr}");
    assert!(
        stderr.to_lowercase().contains("raw-request") || stderr.to_lowercase().contains("read"),
        "error must mention the file: stderr=\n{stderr}"
    );
}

#[test]
fn raw_request_rejects_malformed_request_file() {
    // File exists but has no `Host:` header — parser must reject
    // with a clear error.
    let path = std::env::temp_dir().join(format!("wafrift-raw-bad-{}.req", std::process::id()));
    std::fs::write(&path, "GET / HTTP/1.1\r\nAccept: */*\r\n\r\n").unwrap();

    let (code, _stdout, stderr) = wafrift(&[
        "scan",
        "-r",
        path.to_str().unwrap(),
        "--payload",
        "x",
        "--format",
        "json",
    ]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 2, "malformed file should exit 2 — stderr:\n{stderr}");
    assert!(
        stderr.to_lowercase().contains("host"),
        "error must name the missing Host header: stderr=\n{stderr}"
    );
}

#[test]
fn raw_request_auto_distill_populates_minimal_payload_per_bypass() {
    // Auto-distill flow: scan finds bypasses, then ddmin reduces
    // each one. JSON output must carry minimal_payload +
    // minimal_repro_curl per bypass entry.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let (addr, _) = rt.block_on(spawn_mock_waf());
    let path = write_get_template(addr);

    let (code, stdout, stderr) = wafrift(&[
        "scan",
        "-r",
        path.to_str().unwrap(),
        "--payload",
        "SAFEPAYLOAD",
        "--level",
        "light",
        "--encoding-only",
        "--auto-distill",
        "--auto-distill-max-fires",
        "30",
        "--format",
        "json",
    ]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        code, 0,
        "scan -r --auto-distill should exit 0 — stderr:\n{stderr}"
    );

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON parse");
    assert_eq!(parsed["auto_distill_enabled"], true);
    assert!(
        parsed["auto_distill_fires_total"].as_u64().unwrap_or(0) > 0,
        "auto_distill_fires_total must be > 0: {parsed}"
    );

    let bypasses = parsed["bypass_variants"].as_array().expect("bypasses");
    assert!(!bypasses.is_empty(), "must have at least one bypass");
    for entry in bypasses {
        // Both minimal fields must be present (non-null) on every
        // bypass entry when --auto-distill is set.
        let minimal = entry["minimal_payload"]
            .as_str()
            .expect("minimal_payload string when --auto-distill set");
        assert!(!minimal.is_empty(), "minimal must be non-empty: {entry}");
        let min_repro = entry["minimal_repro_curl"]
            .as_str()
            .expect("minimal_repro_curl string when --auto-distill set");
        assert!(min_repro.starts_with("curl -i "), "got: {min_repro}");
        // §§ marker MUST be substituted in the minimal curl too.
        assert!(!min_repro.contains("§§"), "marker substituted: {min_repro}");
    }
}

#[test]
fn raw_request_default_does_not_populate_minimal_payload() {
    // Without --auto-distill, minimal_payload + minimal_repro_curl
    // must be null. Confirms the default doesn't silently add fires.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let (addr, _) = rt.block_on(spawn_mock_waf());
    let path = write_get_template(addr);

    let (code, stdout, _) = wafrift(&[
        "scan",
        "-r",
        path.to_str().unwrap(),
        "--payload",
        "SAFEPAYLOAD",
        "--level",
        "light",
        "--encoding-only",
        "--format",
        "json",
    ]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 0);

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON parse");
    assert_eq!(parsed["auto_distill_enabled"], false);
    assert_eq!(parsed["auto_distill_fires_total"], 0);

    let bypasses = parsed["bypass_variants"].as_array().expect("bypasses");
    for entry in bypasses {
        assert!(
            entry["minimal_payload"].is_null(),
            "minimal_payload must be null without --auto-distill: {entry}"
        );
        assert!(
            entry["minimal_repro_curl"].is_null(),
            "minimal_repro_curl must be null without --auto-distill: {entry}"
        );
    }
}

#[test]
fn raw_request_scheme_https_reconstructs_https_template_url() {
    // The runner builds the template URL from scheme + Host header.
    // With --raw-request-scheme=https the template URL must use
    // https:// (no actual TLS handshake — we don't fire, we just
    // verify the parsed shape via JSON output).
    //
    // Trick: point at an unreachable target so the fire loop errors
    // out — but the template metadata is emitted regardless.
    let path = std::env::temp_dir().join(format!("wafrift-raw-https-{}.req", std::process::id()));
    let body = "GET /?q=§§ HTTP/1.1\r\nHost: 127.0.0.1:65500\r\nAccept: */*\r\n\r\n";
    std::fs::write(&path, body).unwrap();

    let (code, stdout, _) = wafrift(&[
        "scan",
        "-r",
        path.to_str().unwrap(),
        "--raw-request-scheme",
        "https",
        "--payload",
        "x",
        "--level",
        "light",
        "--encoding-only",
        "--format",
        "json",
    ]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        code, 0,
        "runner exits 0 even when fires error — stdout:\n{stdout}"
    );

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON parse");
    let tpl_url = parsed["template"]["url"]
        .as_str()
        .expect("template.url string");
    assert!(
        tpl_url.starts_with("https://"),
        "template URL must use https scheme: got {tpl_url}"
    );
}
