//! End-to-end tests for `wafrift listener`.
//!
//! The listener is a long-running server.  Tests that need it to be
//! running start it as a child process, read its startup output (tokens
//! are printed immediately before the accept loop), then kill the child.
//! This avoids a fixed port conflict — every test binds to a different
//! ephemeral port (`127.0.0.1:0` is not directly supported by the CLI
//! so we pick unused high ports via `find_free_port`).
//!
//! Tests verify:
//! 1. help documents the CLI surface.
//! 2. listener appears in top-level help.
//! 3. Text format: startup advisory + tokens are emitted on stderr.
//! 4. JSON format: startup line is a valid JSON object with kind=listener_started.
//! 5. JSON tokens array has exactly --tokens entries.
//! 6. Each token is non-empty and unique.
//! 7. Callback from a matching GET request is logged (JSON NDJSON line).
//! 8. Invalid --bind address exits non-zero immediately.

mod common;
use common::wafrift;
use std::io::{BufRead, BufReader};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Spawn a listener child with piped stdout/stderr.  Returns the child
/// so the caller can read from stdout/stderr and then kill it.
fn spawn_listener(extra_args: &[&str]) -> Child {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_wafrift"));
    cmd.arg("listener")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for a in extra_args {
        cmd.arg(a);
    }
    cmd.spawn().expect("spawn listener child")
}

/// Pick a free TCP port on loopback by binding port 0 and reading the
/// assigned port number.  The OS won't reuse the port immediately after
/// the listener drops.
fn find_free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind 0");
    l.local_addr().unwrap().port()
}

/// Wait until a TCP connect to `addr` succeeds or the deadline passes.
fn wait_until_ready(addr: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        if Instant::now() >= deadline {
            panic!("listener at {addr} never became ready within {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

// ── Help surface ──────────────────────────────────────────────────────────

#[test]
fn listener_help_documents_options() {
    let (code, stdout, _) = wafrift(&["listener", "--help"]);
    assert_eq!(code, 0, "listener --help must exit 0");
    assert!(stdout.contains("--bind"), "stdout: {stdout}");
    assert!(stdout.contains("--tokens"), "stdout: {stdout}");
    assert!(stdout.contains("--format"), "stdout: {stdout}");
}

#[test]
fn listener_appears_in_main_help() {
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("listener"),
        "listener must appear in top-level help: {stdout}"
    );
}

// ── JSON startup line ─────────────────────────────────────────────────────

#[test]
fn listener_json_format_emits_listener_started_object() {
    let port = find_free_port();
    let bind = format!("127.0.0.1:{port}");

    let mut child = spawn_listener(&["--bind", &bind, "--tokens", "2", "--format", "json"]);
    let stdout = child.stdout.take().expect("piped stdout");
    let reader = BufReader::new(stdout);

    // Read the first line — it must be the JSON startup object.
    let first_line = reader
        .lines()
        .next()
        .expect("listener must emit at least one line")
        .expect("read line");
    child.kill().ok();
    let _ = child.wait();

    let v: serde_json::Value =
        serde_json::from_str(&first_line).expect("startup line must be valid JSON");
    assert_eq!(
        v["kind"].as_str().unwrap_or(""),
        "listener_started",
        "startup kind must be listener_started: {v}"
    );
    assert_eq!(
        v["bind"].as_str().unwrap_or(""),
        bind,
        "startup bind must match --bind: {v}"
    );
    assert!(
        v["tokens"].is_array(),
        "startup object must have tokens array: {v}"
    );
}

#[test]
fn listener_json_tokens_array_has_requested_count() {
    let port = find_free_port();
    let bind = format!("127.0.0.1:{port}");

    let mut child = spawn_listener(&["--bind", &bind, "--tokens", "5", "--format", "json"]);
    let stdout = child.stdout.take().expect("piped stdout");
    let reader = BufReader::new(stdout);

    let first_line = reader
        .lines()
        .next()
        .expect("at least one line")
        .expect("read line");
    child.kill().ok();
    let _ = child.wait();

    let v: serde_json::Value = serde_json::from_str(&first_line).expect("valid JSON");
    let tokens = v["tokens"].as_array().expect("tokens array");
    assert_eq!(
        tokens.len(),
        5,
        "tokens array must have exactly 5 entries (--tokens 5): {v}"
    );
}

#[test]
fn listener_json_tokens_are_non_empty_and_unique() {
    let port = find_free_port();
    let bind = format!("127.0.0.1:{port}");

    let mut child = spawn_listener(&["--bind", &bind, "--tokens", "4", "--format", "json"]);
    let stdout = child.stdout.take().expect("piped stdout");
    let reader = BufReader::new(stdout);

    let first_line = reader
        .lines()
        .next()
        .expect("at least one line")
        .expect("read line");
    child.kill().ok();
    let _ = child.wait();

    let v: serde_json::Value = serde_json::from_str(&first_line).expect("valid JSON");
    let tokens: Vec<&str> = v["tokens"]
        .as_array()
        .expect("tokens array")
        .iter()
        .map(|t| t.as_str().expect("token must be string"))
        .collect();

    for t in &tokens {
        assert!(!t.is_empty(), "every token must be non-empty: {v}");
    }

    // All tokens must be unique — a duplicate token would be a silent
    // collision bug (two embeds, one callback, wrong vuln is credited).
    let mut seen = std::collections::HashSet::new();
    for t in &tokens {
        assert!(
            seen.insert(*t),
            "duplicate token detected in startup set: {v}"
        );
    }
}

// ── Text format startup ───────────────────────────────────────────────────

#[test]
fn listener_text_format_emits_token_lines_on_stdout() {
    let port = find_free_port();
    let bind = format!("127.0.0.1:{port}");

    // In text mode, listener prints startup info to stdout via println!.
    let mut child = spawn_listener(&["--bind", &bind, "--tokens", "2"]);
    let stdout = child.stdout.take().expect("piped stdout");
    let reader = BufReader::new(stdout);

    // Read until we see at least one "token:" line or timeout.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut found_token = false;
    for line in reader.lines() {
        let Ok(l) = line else { break };
        if l.contains("token:") || l.contains("token") {
            found_token = true;
            break;
        }
        if Instant::now() >= deadline {
            break;
        }
    }
    child.kill().ok();
    let _ = child.wait();

    assert!(
        found_token,
        "text-format listener must emit 'token' lines on stdout within 5s"
    );
}

// ── Callback round-trip (JSON) ────────────────────────────────────────────

#[test]
fn listener_logs_callback_when_matching_token_is_sent() {
    let port = find_free_port();
    let bind = format!("127.0.0.1:{port}");

    let mut child = spawn_listener(&["--bind", &bind, "--tokens", "1", "--format", "json"]);
    let stdout = child.stdout.take().expect("piped stdout");
    let mut reader = BufReader::new(stdout);

    // Read the startup line to get the minted token.
    let mut startup_line = String::new();
    reader.read_line(&mut startup_line).expect("read startup");
    let v: serde_json::Value =
        serde_json::from_str(startup_line.trim()).expect("startup must be valid JSON");
    let token = v["tokens"][0].as_str().expect("first token").to_string();

    // Wait until the listener's accept loop is ready.
    wait_until_ready(&bind, Duration::from_secs(10));

    // Fire a GET request to a path that contains the minted token.
    let path = format!("/{token}");
    let req = format!("GET {path} HTTP/1.1\r\nHost: {bind}\r\nConnection: close\r\n\r\n");
    if let Ok(mut stream) = TcpStream::connect(&bind) {
        use std::io::Write;
        let _ = stream.write_all(req.as_bytes());
    }

    // Read the next NDJSON line — it should be the callback log.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut callback_line = String::new();
    loop {
        callback_line.clear();
        match reader.read_line(&mut callback_line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let trimmed = callback_line.trim();
                if !trimmed.is_empty() {
                    break;
                }
            }
        }
        if Instant::now() >= deadline {
            break;
        }
    }
    child.kill().ok();
    let _ = child.wait();

    assert!(
        !callback_line.trim().is_empty(),
        "listener must emit a callback log line when the token URL is fetched"
    );
    let cb: serde_json::Value =
        serde_json::from_str(callback_line.trim()).expect("callback line must be valid JSON");

    // The Callback struct serializes as a flat JSON object with:
    // received_at, source, method, path, matched_token, headers,
    // body_preview, body_truncated_bytes.
    assert!(
        cb["path"].is_string(),
        "callback must include path field: {cb}"
    );
    assert!(
        cb["method"].is_string(),
        "callback must include method field: {cb}"
    );
    // matched_token must be the pre-minted token (or null if path didn't
    // carry it — but our request path IS /{token}, so it should match).
    let matched = cb["matched_token"].as_str().unwrap_or("");
    assert_eq!(
        matched, token,
        "callback matched_token must equal the pre-minted token: {cb}"
    );
}

// ── Error paths ───────────────────────────────────────────────────────────

#[test]
fn listener_invalid_bind_address_exits_nonzero() {
    // An address that cannot be bound exits immediately with non-zero.
    // Port 1 requires root — will fail fast on all test platforms.
    let (code, _stdout, stderr) = wafrift(&["listener", "--bind", "127.0.0.1:1", "--tokens", "1"]);
    assert_ne!(
        code, 0,
        "binding to a privileged port must exit non-zero; stderr: {stderr}"
    );
}
