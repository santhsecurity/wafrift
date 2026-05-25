//! End-to-end test for `wafrift gql-diff`.

use std::process::Command;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn spawn_gql_mock() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                // Permissive mock: leaks much-longer body on __schema.
                let leaked = req.contains("__schema");
                let body = if leaked {
                    r#"{"data":{"__schema":{"types":[{"name":"Query","fields":[{"name":"secret"}]},{"name":"AdminQuery","fields":[{"name":"users"},{"name":"passwords"}]}]}}}"#
                } else {
                    r#"{"data":{"__typename":"Query"}}"#
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            match std::net::TcpStream::connect_timeout(
                &addr,
                std::time::Duration::from_millis(100),
            ) {
                Ok(_) => break,
                Err(_) => {
                    if std::time::Instant::now() >= deadline {
                        panic!("mock server at {addr} never became ready within 30s");
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
        }
    }
    addr
}

fn wafrift(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_wafrift"))
        .args(args)
        .output()
        .expect("spawn wafrift");
    let code = output.status.code().unwrap_or(-1);
    (
        code,
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

#[test]
fn gql_diff_finds_introspection_leak_on_permissive_mock() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_gql_mock());
    let (code, stdout, stderr) = wafrift(&[
        "gql-diff",
        &format!("http://{addr}/graphql"),
        "--format",
        "json",
        "--quiet",
        "--delay-ms",
        "0",
    ]);
    assert_eq!(code, 0, "gql-diff exit 0 — stderr:\n{stderr}");
    let p: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON parse");
    let total = p["divergences"]["high"].as_u64().unwrap_or(0)
        + p["divergences"]["medium"].as_u64().unwrap_or(0);
    assert!(
        total > 0,
        "introspection-permissive mock must yield ≥1 divergence: {p}"
    );
    let results = p["results"].as_array().expect("results");
    for r in results {
        let curl = r["curl_cmd"].as_str().expect("curl_cmd");
        assert!(curl.starts_with("curl -i -X POST "), "got: {curl}");
    }
}

#[test]
fn gql_diff_against_unreachable_target_exits_1() {
    let (code, _stdout, _stderr) = wafrift(&[
        "gql-diff",
        "http://127.0.0.1:1/graphql",
        "--format",
        "json",
        "--quiet",
        "--timeout-secs",
        "2",
    ]);
    assert_eq!(code, 1);
}

#[test]
fn gql_diff_help_documents_options() {
    let (code, stdout, _) = wafrift(&["gql-diff", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("--format"), "stdout:\n{stdout}");
}

#[test]
fn gql_diff_appears_in_main_help_listing() {
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("gql-diff"));
}
