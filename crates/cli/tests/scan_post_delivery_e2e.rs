//! POST form injection delivery — variants fire as POST body (not ?param=).

use serial_test::serial;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod common;
use common::wafrift;

const FORM_HTML: &[u8] =
    br#"<html><form method="post" action="/register.php"><input name="username"></form></html>"#;

/// Same selective WAF as `scan_surface_probe_e2e`, but the guarded sink is POST form.
async fn spawn_post_register_mock() -> std::net::SocketAddr {
    let handler: Arc<dyn Fn(&[u8]) -> (u16, Vec<u8>) + Send + Sync> = Arc::new(|req| {
        let req = String::from_utf8_lossy(req);
        if req.starts_with("GET / ") || req.starts_with("GET / HTTP") {
            return (200, FORM_HTML.to_vec());
        }
        if req.contains("/register.php") {
            if req.contains("wafrift_benign_probe0") {
                return (200, b"REGISTER_BENIGN".to_vec());
            }
            if req.contains("SqlKeyword")
                || req.contains("XssTag")
                || req.contains("XssEvent")
                || req.contains("SqlTautology")
            {
                return (403, b"blocked by waf".to_vec());
            }
            return (200, b"REGISTER_ATTACK_BODY".to_vec());
        }
        (200, b"STATIC_SHELL".to_vec())
    });
    spawn_handler(handler).await
}

type MockHandler = Arc<dyn Fn(&[u8]) -> (u16, Vec<u8>) + Send + Sync>;

fn status_line(code: u16) -> &'static str {
    match code {
        200 => "HTTP/1.1 200 OK",
        403 => "HTTP/1.1 403 Forbidden",
        _ => "HTTP/1.1 500 Internal Server Error",
    }
}

async fn spawn_handler(handler: MockHandler) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let handler = handler.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 32 * 1024];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let (status, body) = handler(&buf[..n]);
                let resp = format!(
                    "{}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    status_line(status),
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.write_all(&body).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    common::wait_for_server(addr);
    addr
}

#[test]
#[serial]
fn scan_post_delivery_confirms_waf_bypass_on_form_surface() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_post_register_mock());
    let url = format!("http://{addr}/");

    let (code, stdout, stderr) = wafrift(&[
        "scan",
        url.as_str(),
        "--payload",
        "' OR 1=1--",
        "--param",
        "q",
        "--payload-class",
        "sql",
        "--level",
        "light",
        "--format",
        "json",
        "--quiet",
        "--delay-ms",
        "0",
        "--max-fires",
        "200",
        "--auto-escalate",
        "--probe-surfaces",
    ]);
    assert_eq!(code, 0, "POST form WAF bypass; stderr: {stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(
        v["injection_delivery"].as_str().unwrap(),
        "post_form",
        "{v}"
    );
    assert!(
        v["effective_url"]
            .as_str()
            .unwrap()
            .contains("register.php"),
        "{v}"
    );
    assert_eq!(v["effective_param"].as_str().unwrap(), "username");
    assert_eq!(
        v["waf_bypass"]["verdict"].as_str().unwrap(),
        "bypass_confirmed"
    );
    let repro = v["bypass_variants"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|r| r["repro_curl"].as_str())
        .unwrap_or("");
    assert!(
        repro.contains("-X POST") || repro.to_ascii_uppercase().contains("POST"),
        "repro must be POST: {repro}"
    );
}
