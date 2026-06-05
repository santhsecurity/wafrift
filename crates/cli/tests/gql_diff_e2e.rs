//! End-to-end test for `wafrift gql-diff`.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod common;
use common::wafrift;

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
    common::wait_for_server(addr);
    addr
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
        // gql-diff probes BOTH transports: POST (canonical) and
        // GraphQL-over-GET (a real CSRF/cache divergence). The reproducer curl
        // must faithfully match the transport the tool used — `-X POST` for the
        // POST variants, a plain `curl -i '<url?query=…>'` for the GET variant.
        // Asserting POST-only would reject the legitimate GET repro.
        let is_post = curl.starts_with("curl -i -X POST ");
        let is_get = curl.starts_with("curl -i '") && curl.contains("query=");
        assert!(
            is_post || is_get,
            "curl_cmd must be a faithful POST or GraphQL-over-GET reproducer; got: {curl}"
        );
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
// gql-diff consolidated under `wafrift diff gql` (2026-05). LAW 2: flat
// alias must keep working forever.
fn gql_diff_is_grouped_under_diff_with_working_alias() {
    // 1. The unified `diff` command is discoverable in top-level help.
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("\n  diff"),
        "`diff` must appear as a top-level command in --help: {stdout}"
    );

    // 2. Canonical new path exits 0.
    let (code2, _stdout2, stderr2) = wafrift(&["diff", "gql", "--help"]);
    assert_eq!(
        code2, 0,
        "`wafrift diff gql --help` must exit 0 — stderr:\n{stderr2}"
    );

    // 3. Deprecated flat alias still runs (LAW 2 backwards-compat).
    let (code3, _stdout3, stderr3) = wafrift(&["gql-diff", "--help"]);
    assert_eq!(
        code3, 0,
        "`wafrift gql-diff --help` must still exit 0 — stderr:\n{stderr3}"
    );
}
