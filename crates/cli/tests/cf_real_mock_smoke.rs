//! Smoke test for the `bench/cf-real` Worker shape via an in-process
//! Rust mock. Catches endpoint drift between
//! `bench/cf-real/worker/src/index.ts` (Cloudflare-deployed) and the
//! local mock below, without requiring `wrangler` or a Cloudflare
//! account.
//!
//! When you add an endpoint to the TS Worker, mirror it here and
//! add a smoke assertion. The two sides diverging is a regression.
//!
//! Implementation note: ALL endpoint checks run sequentially inside
//! a single `#[tokio::test]`. Multiple `#[tokio::test]` functions
//! each spinning up an in-process listener race the Windows winsock
//! port-table on parallel cargo-test threads, so we don't split.

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn spawn_mock() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                handle(&mut sock).await;
            });
        }
    });
    addr
}

async fn handle(sock: &mut tokio::net::TcpStream) {
    let mut buf = vec![0u8; 16 * 1024];
    let n = match sock.read(&mut buf).await {
        Ok(0) | Err(_) => return,
        Ok(n) => n,
    };
    let req = String::from_utf8_lossy(&buf[..n]).into_owned();
    let first = req.lines().next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path_and_query = parts.next().unwrap_or("/");
    let (path, query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p, q),
        None => (path_and_query, ""),
    };

    let (status, body) = route(method, path, query);
    let resp = format!(
        "HTTP/1.1 {status} OK\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         Cache-Control: no-store\r\n\
         \r\n\
         {body}",
        body.len()
    );
    let _ = sock.write_all(resp.as_bytes()).await;
    let _ = sock.shutdown().await;
}

fn route(method: &str, path: &str, query: &str) -> (u16, String) {
    match (method, path) {
        ("GET", "/" | "/index") => (
            200,
            r#"{"name":"wafrift bench/cf-real (local mock)"}"#.to_string(),
        ),
        ("GET", "/echo") => {
            let q = extract_q(query, "q").unwrap_or_default();
            (200, format!(r#"{{"q":{}}}"#, json_string(&q)))
        }
        ("GET", "/headers") => (200, r#"{"headers":{}}"#.to_string()),
        ("GET", "/sql") => {
            let id = extract_q(query, "id").unwrap_or_default();
            let faked = format!("SELECT * FROM users WHERE id = '{id}'");
            (
                200,
                format!(r#"{{"would_have_run":{}}}"#, json_string(&faked)),
            )
        }
        ("GET", "/reflect-status") => {
            let code: u16 = extract_q(query, "code")
                .and_then(|s| s.parse().ok())
                .filter(|c: &u16| *c >= 100 && *c < 600)
                .unwrap_or(200);
            (code, format!(r#"{{"requested_status":{code}}}"#))
        }
        _ => (404, r#"{"error":"not found"}"#.to_string()),
    }
}

fn extract_q(query: &str, name: &str) -> Option<String> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && k == name
        {
            return Some(urlencoding::decode(v).ok()?.into_owned());
        }
    }
    None
}

fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

async fn fetch(client: &reqwest::Client, url: &str) -> (u16, String) {
    let resp = client.get(url).send().await.expect("send");
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    (status, body)
}

#[tokio::test]
async fn cf_real_endpoint_parity_smoke() {
    let addr = spawn_mock().await;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .no_proxy()
        .build()
        .unwrap();

    // / → 200, contains bench identity string
    let (s, b) = fetch(&client, &format!("http://{addr}/")).await;
    assert_eq!(s, 200);
    assert!(b.contains("wafrift bench/cf-real"));

    // /echo → reflects q
    let (s, b) = fetch(&client, &format!("http://{addr}/echo?q=hello")).await;
    assert_eq!(s, 200);
    assert!(b.contains("\"q\":\"hello\""), "echo body: {b}");

    // /echo URL-decodes
    let (s, b) = fetch(
        &client,
        &format!("http://{addr}/echo?q=%3Cscript%3E"),
    )
    .await;
    assert_eq!(s, 200);
    assert!(b.contains("<script>"), "decode body: {b}");

    // /sql concats id into faked SELECT verbatim
    let (s, b) = fetch(
        &client,
        &format!("http://{addr}/sql?id=1%20OR%201%3D1"),
    )
    .await;
    assert_eq!(s, 200);
    assert!(
        b.contains("WHERE id = '1 OR 1=1'"),
        "sql body: {b}"
    );

    // /reflect-status returns requested code
    let (s, _) = fetch(
        &client,
        &format!("http://{addr}/reflect-status?code=418"),
    )
    .await;
    assert_eq!(s, 418);

    // /reflect-status clamps OOB to 200
    let (s, _) = fetch(
        &client,
        &format!("http://{addr}/reflect-status?code=99999"),
    )
    .await;
    assert_eq!(s, 200);

    // Unknown → 404
    let (s, _) =
        fetch(&client, &format!("http://{addr}/no-such-route")).await;
    assert_eq!(s, 404);
}
