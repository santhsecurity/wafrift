//! E2E: surface probe + auto-escalate pivot to a guarded alternative surface.

use serial_test::serial;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod common;
use common::wafrift;

const STATIC_SHELL: &[u8] = b"STATIC_WAF_ENGAGEMENT_SHELL_v1";

/// Primary `?q=` is unguarded (identical shell). `/register.php?username=` is selective.
async fn spawn_escalate_mock() -> std::net::SocketAddr {
    let handler: Arc<dyn Fn(&[u8]) -> (u16, Vec<u8>) + Send + Sync> = Arc::new(|req| {
        let req = String::from_utf8_lossy(req);
        if (req.contains("/register.php") || req.contains("POST /register.php"))
            && (req.contains("username=") || req.contains("username%3D"))
        {
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
        (200, STATIC_SHELL.to_vec())
    });
    spawn_handler_mock(handler).await
}

type MockHandler = Arc<dyn Fn(&[u8]) -> (u16, Vec<u8>) + Send + Sync>;

fn status_line(code: u16) -> &'static str {
    match code {
        200 => "HTTP/1.1 200 OK",
        403 => "HTTP/1.1 403 Forbidden",
        _ => "HTTP/1.1 500 Internal Server Error",
    }
}

async fn spawn_handler_mock(handler: MockHandler) -> std::net::SocketAddr {
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
                    "{}\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n",
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

fn test_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap()
}

#[test]
#[serial]
fn scan_auto_escalate_pivots_to_guarded_register_surface() {
    let rt = test_runtime();
    let addr = rt.block_on(spawn_escalate_mock());
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
    assert_eq!(
        code, 0,
        "selective surface with bypass path → exit 0; stderr: {stderr}"
    );
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("scan must emit valid JSON");

    assert_eq!(
        v["effective_param"].as_str().unwrap(),
        "username",
        "must pivot to register.php username param: {v}"
    );
    assert!(
        v["effective_url"]
            .as_str()
            .unwrap()
            .contains("register.php"),
        "effective_url must be register.php: {v}"
    );
    assert!(
        v["surface_probe"]["escalated_to"].is_object(),
        "must record escalation: {v}"
    );
    assert_eq!(
        v["waf_engagement"]["level"].as_str().unwrap(),
        "selective",
        "escalated surface must classify selective: {v}"
    );
    assert!(v["waf_bypass"]["waf_in_play"].as_bool().unwrap());
    assert_eq!(
        v["waf_bypass"]["verdict"].as_str().unwrap(),
        "bypass_confirmed"
    );
    assert!(v["waf_bypass"]["bypass_confirmed"].as_u64().unwrap() > 0);
}
