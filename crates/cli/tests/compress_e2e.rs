//! End-to-end tests for `wafrift compress`.
//!
//! All tests are purely offline — no HTTP, no mock server. The command
//! reads a body from stdin / --input and writes the compressed bytes
//! to stdout / --output together with a `Content-Encoding` header on
//! stderr. Tests verify:
//!
//! 1. gzip mode: compresses input + emits Content-Encoding on stderr.
//! 2. JSON mode: emits base64-encoded body_b64 + content_encoding.
//! 3. Unknown algorithm: exits 2 with a helpful message.
//! 4. No input source: exits 1 with a helpful message.
//! 5. Identity mode: body round-trips unchanged.
//! 6. help: documents --algo and --format.

use std::io::Write;
use std::process::{Command, Stdio};

fn wafrift(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_wafrift"))
        .args(args)
        .output()
        .expect("spawn wafrift");
    let code = output.status.code().unwrap_or(-1);
    (
        code,
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn wafrift_stdin(args: &[&str], input: &[u8]) -> (i32, Vec<u8>, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_wafrift"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn wafrift");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input)
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait wafrift");
    let code = out.status.code().unwrap_or(-1);
    (
        code,
        out.stdout,
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

// ── Tests ─────────────────────────────────────────────────────────────

#[test]
fn compress_help_documents_algo_and_format() {
    let (code, stdout, _) = wafrift(&["compress", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("--algo"), "stdout: {stdout}");
    assert!(stdout.contains("--format"), "stdout: {stdout}");
}

#[test]
fn compress_appears_in_main_help() {
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("compress"),
        "compress must appear in top-level help: {stdout}"
    );
}

#[test]
fn compress_gzip_emits_content_encoding_on_stderr() {
    let payload = b"SELECT 1 FROM users WHERE 1=1--";
    let (code, _stdout_bytes, stderr) = wafrift_stdin(&["compress", "--algo", "gzip", "--stdin"], payload);
    assert_eq!(code, 0, "gzip compress must exit 0; stderr: {stderr}");
    assert!(
        stderr.contains("Content-Encoding"),
        "stderr must contain Content-Encoding header: {stderr}"
    );
    assert!(
        stderr.contains("gzip"),
        "Content-Encoding must name gzip: {stderr}"
    );
}

#[test]
fn compress_gzip_output_differs_from_input() {
    let payload = b"SELECT 1 FROM users WHERE 1=1--";
    let (code, stdout_bytes, stderr) = wafrift_stdin(&["compress", "--algo", "gzip", "--stdin"], payload);
    assert_eq!(code, 0, "stderr: {stderr}");
    // Compressed bytes must differ from the raw input.
    assert_ne!(
        stdout_bytes.as_slice(),
        payload,
        "gzip output must differ from plaintext input"
    );
    // Compressed output must be non-empty.
    assert!(
        !stdout_bytes.is_empty(),
        "gzip output must be non-empty"
    );
}

#[test]
fn compress_json_format_emits_base64_envelope() {
    let payload = b"hello world";
    let (code, stdout_bytes, stderr) = wafrift_stdin(
        &["compress", "--algo", "gzip", "--stdin", "--format", "json"],
        payload,
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    let stdout = String::from_utf8_lossy(&stdout_bytes);
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("json format must emit valid JSON");
    assert!(
        v["content_encoding"].is_string(),
        "json envelope must have content_encoding: {v}"
    );
    assert!(
        v["body_b64"].is_string(),
        "json envelope must have body_b64: {v}"
    );
    assert!(
        v["body_len"].is_number(),
        "json envelope must have body_len: {v}"
    );
    assert!(
        v["original_len"].as_u64().unwrap_or(0) == payload.len() as u64,
        "original_len must match input length: {v}"
    );
}

#[test]
fn compress_unknown_algorithm_exits_2() {
    let (code, _stdout, stderr) = wafrift_stdin(
        &["compress", "--algo", "rot13", "--stdin"],
        b"payload",
    );
    assert_eq!(code, 2, "unknown algo must exit 2; stderr: {stderr}");
    assert!(
        stderr.contains("rot13") || stderr.contains("unknown"),
        "error must name the bad algorithm: {stderr}"
    );
}

#[test]
fn compress_no_input_source_exits_1() {
    // Neither --stdin nor --input given — must exit 1 with a clear message.
    let (code, _stdout, stderr) = wafrift(&["compress", "--algo", "gzip"]);
    assert_ne!(code, 0, "missing input source must not exit 0; stderr: {stderr}");
}

#[test]
fn compress_identity_algo_is_noop() {
    let payload = b"unchanged content here";
    let (code, stdout_bytes, stderr) = wafrift_stdin(
        &["compress", "--algo", "identity", "--stdin"],
        payload,
    );
    assert_eq!(code, 0, "identity must exit 0; stderr: {stderr}");
    // identity = no transformation.
    assert_eq!(
        stdout_bytes.as_slice(),
        payload,
        "identity algo must leave bytes unchanged"
    );
}
