//! End-to-end tests for `wafrift smuggle-chain`.

mod common;
use common::wafrift;

#[test]
fn smuggle_chain_help_lists_family_and_cap_flags() {
    let (code, stdout, _stderr) = wafrift(&["smuggle-chain", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("--family"));
    assert!(stdout.contains("--cap"));
    assert!(stdout.contains("--canary-header"));
}

#[test]
fn smuggle_chain_requires_at_least_two_families() {
    // One --family alone is not a chain — exit 2 (clap requires
    // at least one via required=true, then our own check
    // requires >=2).
    let (code, _stdout, stderr) = wafrift(&["smuggle-chain", "--family", "cookie"]);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("at least 2 --family"),
        "stderr must explain: {stderr}"
    );
}

#[test]
fn smuggle_chain_two_families_emits_pairs() {
    let (code, stdout, stderr) = wafrift(&[
        "smuggle-chain",
        "--family",
        "cookie",
        "--family",
        "auth",
        "--cap",
        "5",
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert!(!lines.is_empty());
    assert!(lines.len() <= 5);
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).expect("JSON");
        let techs = v["techniques"].as_array().expect("techniques");
        assert_eq!(techs.len(), 2, "2 families -> 2 techniques per artifact");
        assert!(techs[0].as_str().unwrap().starts_with("cookie."));
        assert!(techs[1].as_str().unwrap().starts_with("auth."));
    }
}

#[test]
fn smuggle_chain_three_families_emits_triples() {
    let (code, stdout, _stderr) = wafrift(&[
        "smuggle-chain",
        "--family",
        "cookie",
        "--family",
        "auth",
        "--family",
        "range",
        "--cap",
        "8",
    ]);
    assert_eq!(code, 0);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert!(!lines.is_empty());
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).expect("JSON");
        let techs = v["techniques"].as_array().expect("techniques");
        assert_eq!(techs.len(), 3, "3 families -> 3 techniques per artifact");
        let canaries = v["canaries"].as_array().expect("canaries");
        assert_eq!(canaries.len(), 3, "3 families -> 3 canaries per artifact");
        assert!(techs[0].as_str().unwrap().starts_with("cookie."));
        assert!(techs[1].as_str().unwrap().starts_with("auth."));
        assert!(techs[2].as_str().unwrap().starts_with("range."));
    }
}

#[test]
fn smuggle_chain_unknown_family_exits_2() {
    let (code, _stdout, stderr) = wafrift(&[
        "smuggle-chain",
        "--family",
        "cookie",
        "--family",
        "nonexistent-family-xyz",
    ]);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("matched zero probes"),
        "stderr must explain: {stderr}"
    );
}

#[test]
fn smuggle_chain_canary_header_propagates_to_all_n_canaries() {
    let (code, stdout, _stderr) = wafrift(&[
        "smuggle-chain",
        "--family",
        "cookie",
        "--family",
        "auth",
        "--family",
        "range",
        "--cap",
        "2",
        "--canary-header",
        "X-Wafrift-Canary",
    ]);
    assert_eq!(code, 0);
    let line = stdout.lines().find(|l| !l.is_empty()).expect("at least 1");
    let v: serde_json::Value = serde_json::from_str(line).expect("JSON");
    let headers = v["headers"].as_array().expect("headers");
    let canary_pairs: Vec<&serde_json::Value> = headers
        .iter()
        .filter(|h| {
            h.as_array()
                .and_then(|a| a.first())
                .and_then(|n| n.as_str())
                == Some("X-Wafrift-Canary")
        })
        .collect();
    // 3 families -> 3 canary pairs spliced.
    assert_eq!(canary_pairs.len(), 3);
}

#[test]
fn smuggle_chain_cap_zero_means_unlimited() {
    let (code, stdout, _stderr) = wafrift(&[
        "smuggle-chain",
        "--family",
        "cookie",
        "--family",
        "auth",
        "--cap",
        "0",
    ]);
    assert_eq!(code, 0);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    // 7 cookie × 8 auth = 56 composed artifacts.
    assert!(
        lines.len() >= 40,
        "cap=0 must emit full product: got {}",
        lines.len()
    );
}

#[test]
fn smuggle_chain_fire_target_emits_composed_fire_reports_with_n_techniques() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8 * 1024];
                    let _ = sock.read(&mut buf).await;
                    let body = "default";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        loop {
            if std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(100))
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        addr
    });
    let url = format!("http://{addr}/");
    let (code, stdout, stderr) = wafrift(&[
        "smuggle-chain",
        "--family",
        "cookie",
        "--family",
        "auth",
        "--family",
        "range",
        "--cap",
        "2",
        "--fire-target",
        &url,
        "--delay-ms",
        "0",
        "--timeout-secs",
        "5",
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 2);
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).expect("JSON");
        let techs = v["techniques"].as_array().expect("techniques array");
        assert_eq!(techs.len(), 3, "3 families -> 3 techniques per report");
        let canaries = v["canaries"].as_array().expect("canaries array");
        assert_eq!(canaries.len(), 3);
        assert_eq!(v["status"].as_u64().unwrap(), 200);
    }
}

#[test]
fn smuggle_chain_pretty_flag_produces_indented_json() {
    let (code, stdout, _stderr) = wafrift(&[
        "smuggle-chain",
        "--family",
        "cookie",
        "--family",
        "auth",
        "--cap",
        "2",
        "--pretty",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.lines().any(|l| l.starts_with("  \"")));
}
