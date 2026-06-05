//! End-to-end tests for `wafrift smuggle-cross-product`.

mod common;
use common::wafrift;

#[test]
fn cross_product_help_lists_lhs_rhs_and_cap_flags() {
    let (code, stdout, _stderr) = wafrift(&["smuggle-cross-product", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("--lhs"), "stdout: {stdout}");
    assert!(stdout.contains("--rhs"), "stdout: {stdout}");
    assert!(stdout.contains("--cap"), "stdout: {stdout}");
    assert!(stdout.contains("--pretty"), "stdout: {stdout}");
}

#[test]
fn cross_product_emits_at_least_one_composed_artifact_under_cap() {
    let (code, stdout, stderr) = wafrift(&[
        "smuggle-cross-product",
        "--lhs",
        "cookie",
        "--rhs",
        "auth",
        "--cap",
        "12",
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert!(!lines.is_empty(), "expected >=1 composed artifact");
    assert!(
        lines.len() <= 12,
        "cap=12 must truncate; got {} lines",
        lines.len()
    );
}

#[test]
fn cross_product_each_composed_carries_two_techniques() {
    let (code, stdout, _stderr) = wafrift(&[
        "smuggle-cross-product",
        "--lhs",
        "cookie",
        "--rhs",
        "auth",
        "--cap",
        "8",
    ]);
    assert_eq!(code, 0);
    for line in stdout.lines().filter(|l| !l.is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line).expect("JSON parse");
        let techs = v["techniques"].as_array().expect("techniques array");
        assert_eq!(
            techs.len(),
            2,
            "each composed must carry exactly 2 techniques: {line}"
        );
        let lhs_tech = techs[0].as_str().expect("lhs tech str");
        let rhs_tech = techs[1].as_str().expect("rhs tech str");
        assert!(
            lhs_tech.starts_with("cookie."),
            "lhs must be cookie.*: {lhs_tech}"
        );
        assert!(
            rhs_tech.starts_with("auth."),
            "rhs must be auth.*: {rhs_tech}"
        );
    }
}

#[test]
fn cross_product_composed_artifact_has_documented_shape() {
    let (code, stdout, _stderr) = wafrift(&[
        "smuggle-cross-product",
        "--lhs",
        "cookie",
        "--rhs",
        "auth",
        "--cap",
        "2",
    ]);
    assert_eq!(code, 0);
    let line = stdout
        .lines()
        .find(|l| !l.is_empty())
        .expect("at least 1 line");
    let v: serde_json::Value = serde_json::from_str(line).expect("JSON");
    // Documented contract: techniques, headers, body, frames.
    assert!(v.get("techniques").is_some(), "missing techniques");
    assert!(v.get("headers").is_some(), "missing headers");
    assert!(v.get("body").is_some(), "missing body field (may be null)");
    assert!(v.get("frames").is_some(), "missing frames");
    // headers must be a JSON array.
    assert!(v["headers"].is_array(), "headers must be array");
    // frames must be a JSON array.
    assert!(v["frames"].is_array(), "frames must be array");
}

#[test]
fn cross_product_zero_match_on_either_side_exits_2() {
    let (code, _stdout, stderr) = wafrift(&[
        "smuggle-cross-product",
        "--lhs",
        "nonexistent-family-xyz",
        "--rhs",
        "cookie",
    ]);
    assert_eq!(code, 2, "exit 2 expected when lhs filter matches zero");
    assert!(
        stderr.contains("matched no probes"),
        "stderr must explain: {stderr}"
    );
}

#[test]
fn cross_product_cap_zero_means_unlimited_emission() {
    // cap=0 should emit every composed artifact — pin this so a
    // regression that treats 0 as "emit nothing" surfaces here.
    let (code, stdout, _stderr) = wafrift(&[
        "smuggle-cross-product",
        "--lhs",
        "cookie",
        "--rhs",
        "auth",
        "--cap",
        "0",
    ]);
    assert_eq!(code, 0);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    // 7 cookie × 8 auth = 56 composed artifacts.
    assert!(
        lines.len() >= 40,
        "cap=0 must emit the full product (>=40); got {} lines",
        lines.len()
    );
}

#[test]
fn cross_product_pretty_flag_produces_indented_json() {
    let (code, stdout, _stderr) = wafrift(&[
        "smuggle-cross-product",
        "--lhs",
        "cookie",
        "--rhs",
        "auth",
        "--cap",
        "2",
        "--pretty",
    ]);
    assert_eq!(code, 0);
    assert!(
        stdout
            .lines()
            .any(|l| l.starts_with("  \"") || l.starts_with("    \"")),
        "pretty flag must produce indented JSON; got: {stdout}"
    );
}

#[test]
fn cross_product_default_lhs_rhs_emit_full_product_capped() {
    // Empty --lhs / --rhs defaults mean "every family" on both
    // sides. The default --cap is 64 so the output should be
    // capped.
    let (code, stdout, _stderr) = wafrift(&["smuggle-cross-product"]);
    assert_eq!(code, 0);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert!(!lines.is_empty());
    assert!(
        lines.len() <= 64,
        "default cap=64 must truncate; got {}",
        lines.len()
    );
}

#[test]
fn cross_product_path_family_appears_in_default_emission() {
    // Anti-rig: when --lhs is empty, the lhs should include path
    // family probes (the 8th family). A regression that drops the
    // path family from the aggregator must surface here.
    let (code, stdout, _stderr) = wafrift(&[
        "smuggle-cross-product",
        "--lhs",
        "path",
        "--rhs",
        "cookie",
        "--cap",
        "8",
    ]);
    assert_eq!(code, 0);
    for line in stdout.lines().filter(|l| !l.is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line).expect("JSON");
        let techs = v["techniques"].as_array().expect("techniques");
        let lhs_tech = techs[0].as_str().expect("lhs tech");
        assert!(
            lhs_tech.starts_with("path."),
            "lhs must be path.* with --lhs path: {lhs_tech}"
        );
    }
}

#[test]
fn cross_product_custom_credential_appears_in_output() {
    let token = "uniqtoken-xy-1828374";
    let (code, stdout, _stderr) = wafrift(&[
        "smuggle-cross-product",
        "--lhs",
        "cookie",
        "--rhs",
        "auth",
        "--cap",
        "16",
        "--credential",
        token,
    ]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains(token),
        "custom credential {token:?} must appear in output"
    );
}

#[test]
fn cross_product_canary_header_flag_splices_pair_per_merged_canary() {
    let (code, stdout, _stderr) = wafrift(&[
        "smuggle-cross-product",
        "--lhs",
        "cookie",
        "--rhs",
        "auth",
        "--cap",
        "4",
        "--canary-header",
        "X-Wafrift-Canary",
    ]);
    assert_eq!(code, 0);
    let line = stdout.lines().find(|l| !l.is_empty()).expect("at least 1");
    let v: serde_json::Value = serde_json::from_str(line).expect("JSON");
    let headers = v["headers"].as_array().expect("headers array");
    let canary_pairs: Vec<&serde_json::Value> = headers
        .iter()
        .filter(|h| {
            h.as_array()
                .and_then(|a| a.first())
                .and_then(|n| n.as_str())
                == Some("X-Wafrift-Canary")
        })
        .collect();
    // Each composed merges 2 probes -> 2 canary pairs spliced.
    assert_eq!(
        canary_pairs.len(),
        2,
        "expected 2 canary header pairs (one per merged technique): {line}"
    );
    // Both pairs must hold non-empty 16-char tokens.
    for pair in canary_pairs {
        let token = pair.as_array().unwrap()[1].as_str().unwrap();
        assert_eq!(token.len(), 16, "canary token must be 16 chars: {token:?}");
    }
}

#[test]
fn cross_product_curl_target_mode_emits_curl_per_composed_artifact() {
    let (code, stdout, _stderr) = wafrift(&[
        "smuggle-cross-product",
        "--lhs",
        "cookie",
        "--rhs",
        "auth",
        "--cap",
        "4",
        "--curl-target",
        "https://example.com/admin",
    ]);
    assert_eq!(code, 0);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert!(!lines.is_empty());
    for line in &lines {
        assert!(line.starts_with("curl -X "), "expected curl: {line}");
        assert!(line.contains("https://example.com/admin"));
        // Composed cookie × auth carries BOTH Cookie and Authorization headers.
        assert!(line.contains("-H 'Cookie:"), "missing Cookie: {line}");
        assert!(
            line.contains("-H 'Authorization:"),
            "missing Authorization: {line}"
        );
    }
}

#[test]
fn cross_product_curl_target_renders_body_when_composed_has_body() {
    let (code, stdout, _stderr) = wafrift(&[
        "smuggle-cross-product",
        "--lhs",
        "cookie",
        "--rhs",
        "content-type",
        "--cap",
        "4",
        "--curl-target",
        "https://example.com/admin",
    ]);
    assert_eq!(code, 0);
    for line in stdout.lines().filter(|l| !l.is_empty()) {
        // Composed cookie + multipart body -> POST + --data-binary.
        assert!(line.starts_with("curl -X POST "), "expected POST: {line}");
        assert!(line.contains("--data-binary"));
        assert!(line.contains("multipart/"));
    }
}

#[test]
fn cross_product_fire_target_emits_composed_fire_reports() {
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
                    let body = "blocked";
                    let resp = format!(
                        "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        // Probe-until-ready before returning.
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
        "smuggle-cross-product",
        "--lhs",
        "cookie",
        "--rhs",
        "auth",
        "--cap",
        "3",
        "--fire-target",
        &url,
        "--delay-ms",
        "0",
        "--timeout-secs",
        "5",
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 3);
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).expect("JSON");
        // ComposedFireReport carries arrays, not scalars.
        let techs = v["techniques"].as_array().expect("techniques array");
        assert_eq!(techs.len(), 2, "cookie × auth -> 2 techniques");
        let canaries = v["canaries"].as_array().expect("canaries array");
        assert_eq!(canaries.len(), 2);
        assert!(v["status"].is_u64());
        assert!(v["bypass_signal"].is_string());
        // Mock always returns 403 + same body -> no divergence.
        assert_eq!(v["bypass_signal"].as_str().unwrap(), "none");
    }
}

#[test]
fn cross_product_fire_target_reports_canary_reflected_when_echoed() {
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
                    let mut buf = vec![0u8; 16 * 1024];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    // Echo the X-Wafrift-Canary value into the body.
                    let token = req.lines().find_map(|l| {
                        let (name, val) = l.split_once(':')?;
                        name.trim()
                            .eq_ignore_ascii_case("x-wafrift-canary")
                            .then(|| val.trim().to_string())
                    });
                    let body = match token {
                        Some(t) => format!("echo:{t}"),
                        None => "blocked".to_string(),
                    };
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
        "smuggle-cross-product",
        "--lhs",
        "cookie",
        "--rhs",
        "auth",
        "--cap",
        "3",
        "--fire-target",
        &url,
        "--canary-header",
        "X-Wafrift-Canary",
        "--delay-ms",
        "0",
        "--timeout-secs",
        "5",
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 3);
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).expect("JSON");
        // One canary echoed -> composed report flips to canary-reflected.
        assert_eq!(
            v["bypass_signal"].as_str().unwrap(),
            "canary-reflected",
            "line: {line}"
        );
        // reflected_canaries must be a subset of the composed canaries.
        let reflected = v["reflected_canaries"]
            .as_array()
            .expect("reflected_canaries");
        assert!(
            !reflected.is_empty(),
            "expected >=1 reflected token: {line}"
        );
        let all: Vec<&str> = v["canaries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap())
            .collect();
        for r in reflected {
            assert!(
                all.contains(&r.as_str().unwrap()),
                "reflected token must be one of the composed canaries: {line}"
            );
        }
    }
    // Composed summary must tally the reflection too.
    let summary_line = stderr
        .lines()
        .find(|l| l.contains("\"kind\":\"summary\""))
        .expect("summary on stderr");
    let summary: serde_json::Value = serde_json::from_str(summary_line).unwrap();
    assert!(summary["canary_reflected"].as_u64().unwrap() >= 1);
}

#[test]
fn cross_product_fire_refuses_non_allowlist_target() {
    let (code, _stdout, stderr) = wafrift(&[
        "smuggle-cross-product",
        "--lhs",
        "cookie",
        "--rhs",
        "auth",
        "--fire-target",
        "https://random-non-allowlist.example.com/",
    ]);
    assert_eq!(code, 2);
    assert!(stderr.contains("wafrift refuses"));
}

#[test]
fn cross_product_canaries_field_propagates_in_composed_output() {
    let (code, stdout, _stderr) = wafrift(&[
        "smuggle-cross-product",
        "--lhs",
        "cookie",
        "--rhs",
        "auth",
        "--cap",
        "2",
    ]);
    assert_eq!(code, 0);
    let line = stdout.lines().find(|l| !l.is_empty()).expect("at least 1");
    let v: serde_json::Value = serde_json::from_str(line).expect("JSON");
    let canaries = v["canaries"].as_array().expect("canaries array");
    assert_eq!(canaries.len(), 2, "two merged probes -> two canaries");
    for c in canaries {
        assert_eq!(c.as_str().unwrap().len(), 16);
    }
}

#[test]
fn cross_product_custom_protected_path_propagates_via_lhs_path_family() {
    // Pin: --protected-path must reach the path family when --lhs path.
    let (code, stdout, _stderr) = wafrift(&[
        "smuggle-cross-product",
        "--lhs",
        "path",
        "--rhs",
        "cookie",
        "--cap",
        "4",
        "--protected-path",
        "/wp-admin",
    ]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("wp-admin"),
        "custom protected_path must appear in lhs path artifacts; got: {stdout}"
    );
}
