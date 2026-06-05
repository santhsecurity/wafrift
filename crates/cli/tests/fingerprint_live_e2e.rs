//! End-to-end dogfood of the shipped `wafrift fingerprint` binary against a
//! REAL local target that exhibits a normalization-mismatch hole: it gates on
//! the raw (framework-url-decoded) parameter — blocking `<script` with 403 —
//! but its *origin* base64-decodes the same parameter before using it. So a
//! base64-wrapped payload sails past the gate and reconstitutes the attack at
//! the origin. This is exactly the class the live decompiler is built to find.
//!
//! The test exercises the full operator path through the compiled binary: arg
//! parsing, the live reflection probe (→ detects `base64_decode`), and the
//! `--attack` solve branch driving the detected pipeline into `solve_bypass`
//! against the live block/pass oracle (→ emits a verified bypass). The bypass
//! is re-verified by the solver's CEGIS gate, so a green result here is a
//! genuinely working bypass, not a claim.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::thread;

/// One-pass percent-decode — the framework's baseline query-string decode.
fn pct_decode_once(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%' && i + 2 < s.len() {
            let hi = (s[i + 1] as char).to_digit(16);
            let lo = (s[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(s[i]);
        i += 1;
    }
    out
}

/// Extract the raw (still percent-encoded) value of `q` from a request-line
/// path like `/?q=<value>&x=1`.
fn extract_q(path: &[u8]) -> Vec<u8> {
    let q = match path.iter().position(|&b| b == b'?') {
        Some(p) => &path[p + 1..],
        None => return Vec::new(),
    };
    for pair in q.split(|&b| b == b'&') {
        if let Some(eq) = pair.iter().position(|&b| b == b'=') {
            if &pair[..eq] == b"q" {
                return pair[eq + 1..].to_vec();
            }
        }
    }
    Vec::new()
}

fn handle(mut stream: TcpStream) {
    use base64::Engine;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 64 * 1024 {
                    break;
                }
            }
            Err(_) => return,
        }
    }
    let line_end = buf.windows(2).position(|w| w == b"\r\n").unwrap_or(buf.len());
    let path = buf[..line_end].split(|&b| b == b' ').nth(1).unwrap_or(b"");
    let raw = extract_q(path);
    let decoded = pct_decode_once(&raw); // framework baseline url-decode

    // WAF gate inspects the RAW (pre-origin-decode) value: block `<script`.
    let blocked = decoded
        .windows(7)
        .any(|w| w.eq_ignore_ascii_case(b"<script"));
    if blocked {
        let _ = stream.write_all(
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\nConnection: close\r\n\r\nblocked!!",
        );
        let _ = stream.flush();
        return;
    }

    // Origin normalization: base64-decode the parameter, then reflect it.
    let reflected = base64::engine::general_purpose::STANDARD
        .decode(&decoded)
        .unwrap_or(decoded);
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reflected.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&reflected);
    let _ = stream.flush();
}

#[test]
fn fingerprint_binary_detects_base64_origin_and_solves_verified_bypass() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local origin");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            // Sequential is fine: each probe / membership query is its own
            // short-lived connection (Connection: close).
            handle(stream);
        }
    });

    let url = format!("http://{addr}/");
    let bin = env!("CARGO_BIN_EXE_wafrift");
    let output = Command::new(bin)
        .args([
            "fingerprint",
            "--url",
            &url,
            "--param",
            "q",
            "--attack",
            "<script>alert(1)</script>",
            "--format",
            "json",
        ])
        .output()
        .expect("invoke wafrift fingerprint");

    assert!(
        output.status.success(),
        "fingerprint exited non-zero: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    let report: serde_json::Value =
        serde_json::from_str(stdout.trim()).unwrap_or_else(|e| panic!("bad JSON {e}: {stdout}"));

    // The origin's base64 normalization must be fingerprinted.
    let stages = report["detected_stages"]
        .as_array()
        .expect("detected_stages array");
    assert!(
        stages.iter().any(|s| s == "base64_decode"),
        "expected base64_decode in detected stages, got {stages:?}"
    );

    // The detected pipeline must drive the solver to a live-verified bypass.
    let bypass = &report["bypass"];
    assert!(
        !bypass.is_null(),
        "expected a verified bypass for the base64 normalization hole, got null. full report: {report}"
    );
    let payload_b64 = bypass["payload_base64"].as_str().expect("payload_base64");
    // The verified bypass payload, base64-decoded by the origin, must
    // reconstruct the attack — that is the whole point.
    use base64::Engine;
    let payload = base64::engine::general_purpose::STANDARD
        .decode(payload_b64)
        .expect("payload is valid base64");
    let sink_view = base64::engine::general_purpose::STANDARD
        .decode(&payload)
        .unwrap_or_default();
    assert!(
        sink_view
            .windows(7)
            .any(|w| w.eq_ignore_ascii_case(b"<script")),
        "the solved payload must base64-decode to the attack at the origin; \
         payload={:?} origin_view={:?}",
        String::from_utf8_lossy(&payload),
        String::from_utf8_lossy(&sink_view)
    );
}

/// A target that returns a fixed page and never echoes the parameter — the
/// inconclusive case. The binary must NOT report an empty pipeline as a clean
/// origin; it must signal "no reflection observed" (exit 3 / JSON flag false).
fn handle_non_reflecting(mut stream: TcpStream) {
    let mut tmp = [0u8; 1024];
    // Drain the request enough to be polite, then answer with a static page
    // that contains none of our probe content.
    let _ = stream.read(&mut tmp);
    let body = b"<html><body>welcome</body></html>";
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

/// A target whose origin reflects the (base64-)normalized parameter ONLY in a
/// `Location` response header — a 302 redirect with an empty body. A body-only
/// scan sees nothing here; the header-aware reflector must still fingerprint the
/// base64 normalization. Header values are gated to all-alphanumeric (our marker
/// is) so a non-base64 probe's residue can never inject CRLF or an invalid
/// header value that would break response framing.
fn handle_header_reflect(mut stream: TcpStream) {
    use base64::Engine;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 64 * 1024 {
                    break;
                }
            }
            Err(_) => return,
        }
    }
    let line_end = buf.windows(2).position(|w| w == b"\r\n").unwrap_or(buf.len());
    let path = buf[..line_end].split(|&b| b == b' ').nth(1).unwrap_or(b"");
    let raw = extract_q(path);
    let decoded = pct_decode_once(&raw); // framework baseline url-decode
    let reflected = base64::engine::general_purpose::STANDARD
        .decode(&decoded)
        .unwrap_or(decoded);
    // Only echo an all-alphanumeric normalized value (the base64 fold of our
    // marker qualifies; a url/hex/overlong probe's residue does not), so the
    // header value is always well-formed.
    let value = if !reflected.is_empty() && reflected.iter().all(u8::is_ascii_alphanumeric) {
        String::from_utf8_lossy(&reflected).into_owned()
    } else {
        String::new()
    };
    let resp = format!(
        "HTTP/1.1 302 Found\r\nLocation: /next?v={value}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();
}

#[test]
fn fingerprint_binary_detects_base64_origin_reflected_only_in_a_header() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local origin");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            handle_header_reflect(stream);
        }
    });

    let url = format!("http://{addr}/");
    let bin = env!("CARGO_BIN_EXE_wafrift");
    let output = Command::new(bin)
        .args(["fingerprint", "--url", &url, "--param", "q", "--format", "json"])
        .output()
        .expect("invoke wafrift fingerprint");

    assert!(
        output.status.success(),
        "header-reflection fingerprint exited non-zero: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    let report: serde_json::Value =
        serde_json::from_str(stdout.trim()).unwrap_or_else(|e| panic!("bad JSON {e}: {stdout}"));
    assert_eq!(
        report["reflection_observed"],
        serde_json::Value::Bool(true),
        "a header-only reflection must be observed (not mis-reported as no-echo): {report}"
    );
    let stages = report["detected_stages"]
        .as_array()
        .expect("detected_stages array");
    assert!(
        stages.iter().any(|s| s == "base64_decode"),
        "base64 normalization reflected in a Location header must be detected, got {stages:?}"
    );
}

/// A WAF-shaped origin for the differential filter-characterization path: it
/// BLOCKS (403) any request whose `q` value url-decodes to contain the literal
/// `<script>` token, and otherwise reflects the decoded value (200 echo). So the
/// `<script>` probe blocks while its signature-broken twin `<scrupt>` passes —
/// the differential must read `<script>` as Policed and leave the other-class
/// tokens (which never contain `<script>`) Unpoliced.
fn handle_script_blocking_waf(mut stream: TcpStream) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 64 * 1024 {
                    break;
                }
            }
            Err(_) => return,
        }
    }
    let line_end = buf.windows(2).position(|w| w == b"\r\n").unwrap_or(buf.len());
    let path = buf[..line_end].split(|&b| b == b' ').nth(1).unwrap_or(b"");
    let decoded = pct_decode_once(&extract_q(path));
    let blocked = decoded
        .windows(8)
        .any(|w| w.eq_ignore_ascii_case(b"<script>"));
    if blocked {
        let _ = stream.write_all(
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\nConnection: close\r\n\r\nblocked!!",
        );
        let _ = stream.flush();
        return;
    }
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        decoded.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&decoded);
    let _ = stream.flush();
}

/// A base64-normalizing origin that reflects the decoded value but NEVER blocks
/// anything (always 200). Its normalization stage is detectable, but since it
/// does not police the attack, a targeted solve must report `not_policed` — not
/// fabricate a "bypass" of a token the WAF never gated (#7).
fn handle_base64_reflect_no_block(mut stream: TcpStream) {
    use base64::Engine;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 64 * 1024 {
                    break;
                }
            }
            Err(_) => return,
        }
    }
    let line_end = buf.windows(2).position(|w| w == b"\r\n").unwrap_or(buf.len());
    let path = buf[..line_end].split(|&b| b == b' ').nth(1).unwrap_or(b"");
    let decoded = pct_decode_once(&extract_q(path));
    // Base64-decode the param (the detectable origin normalization), then echo —
    // but unconditionally 200: this origin gates nothing.
    let reflected = base64::engine::general_purpose::STANDARD
        .decode(&decoded)
        .unwrap_or(decoded);
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reflected.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&reflected);
    let _ = stream.flush();
}

#[test]
fn fingerprint_not_policed_attack_is_reported_distinctly_not_as_a_bypass() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local origin");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            handle_base64_reflect_no_block(stream);
        }
    });

    let url = format!("http://{addr}/");
    let bin = env!("CARGO_BIN_EXE_wafrift");
    let output = Command::new(bin)
        .args([
            "fingerprint",
            "--url",
            &url,
            "--param",
            "q",
            "--attack",
            "<script>alert(1)</script>",
            "--format",
            "json",
        ])
        .output()
        .expect("invoke wafrift fingerprint --attack");

    assert!(
        output.status.success(),
        "fingerprint exited non-zero: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    let report: serde_json::Value =
        serde_json::from_str(stdout.trim()).unwrap_or_else(|e| panic!("bad JSON {e}: {stdout}"));

    let bypass = &report["bypass"];
    assert_eq!(
        bypass["status"], "not_policed",
        "an origin that does not block the attack must report not_policed, not a bypass: {report}"
    );
    assert!(
        bypass.get("payload_base64").is_none(),
        "no fabricated payload may be emitted for a never-policed attack: {report}"
    );
}

#[test]
fn fingerprint_characterize_filter_isolates_the_policed_token() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local origin");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            handle_script_blocking_waf(stream);
        }
    });

    let url = format!("http://{addr}/");
    let bin = env!("CARGO_BIN_EXE_wafrift");
    let output = Command::new(bin)
        .args([
            "fingerprint",
            "--url",
            &url,
            "--param",
            "q",
            "--characterize-filter",
            "--format",
            "json",
        ])
        .output()
        .expect("invoke wafrift fingerprint --characterize-filter");

    assert!(
        output.status.success(),
        "fingerprint --characterize-filter exited non-zero: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    let report: serde_json::Value =
        serde_json::from_str(stdout.trim()).unwrap_or_else(|e| panic!("bad JSON {e}: {stdout}"));

    let fp = &report["filter_profile"];
    assert!(!fp.is_null(), "filter_profile must be present when requested: {report}");
    assert_eq!(fp["transport_errors"], serde_json::json!(0), "no transport errors expected");

    let policed: Vec<&str> = fp["policed"]
        .as_array()
        .expect("policed array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        policed.contains(&"<script>"),
        "the WAF policies `<script>` and its benign twin passes — must read as Policed, got {policed:?}"
    );

    let unpoliced: Vec<&str> = fp["unpoliced"]
        .as_array()
        .expect("unpoliced array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    // A token this WAF never inspects (no `<script>` substring) must surface as
    // a free, plaintext-usable token — the actionable other half of the result.
    assert!(
        unpoliced.contains(&"union select"),
        "an un-policed token must be reported unpoliced, got {unpoliced:?}"
    );
    assert!(
        !policed.contains(&"union select"),
        "a token the WAF never blocks must not be reported policed"
    );

    // Decode-gap surface: this single-decode origin does not decode the encoded
    // preimages of `<script>`, so they pass — each is a candidate decode-gap the
    // operator can try. The capability must reach the JSON end-to-end.
    let gaps = fp["decode_gaps"].as_array().expect("decode_gaps array");
    assert!(
        gaps.iter().any(|g| g["token"] == "<script>"),
        "decode-gaps for the policed token must be surfaced, got {gaps:?}"
    );
    assert!(
        gaps.iter()
            .all(|g| g["stage"].is_string() && g["encoded_preimage"].is_string()),
        "every decode-gap must carry its stage label and the encoded preimage to try"
    );
}

/// A WAF that blocks the literal custom token `EVILTAG` (and reflects otherwise)
/// — used to prove a `--filter-battery` override reaches live behavior.
fn handle_eviltag_blocking_waf(mut stream: TcpStream) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 64 * 1024 {
                    break;
                }
            }
            Err(_) => return,
        }
    }
    let line_end = buf.windows(2).position(|w| w == b"\r\n").unwrap_or(buf.len());
    let path = buf[..line_end].split(|&b| b == b' ').nth(1).unwrap_or(b"");
    let decoded = pct_decode_once(&extract_q(path));
    let blocked = decoded.windows(7).any(|w| w == b"EVILTAG");
    if blocked {
        let _ = stream.write_all(
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\nConnection: close\r\n\r\nblocked!!",
        );
        let _ = stream.flush();
        return;
    }
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        decoded.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&decoded);
    let _ = stream.flush();
}

#[test]
fn fingerprint_custom_filter_battery_overrides_the_default_token_set() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local origin");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            handle_eviltag_blocking_waf(stream);
        }
    });

    // A custom Tier-B battery with a single non-default token; the twin obeys the
    // structural invariant (same length, only letters differ).
    let battery_path = std::env::temp_dir().join(format!("wafrift_battery_{}.toml", addr.port()));
    std::fs::write(
        &battery_path,
        "[[probe]]\ntoken = \"EVILTAG\"\nbenign_twin = \"EVILTAX\"\nclass = \"xss\"\n",
    )
    .expect("write custom battery");

    let url = format!("http://{addr}/");
    let bin = env!("CARGO_BIN_EXE_wafrift");
    let output = Command::new(bin)
        .args([
            "fingerprint",
            "--url",
            &url,
            "--param",
            "q",
            "--characterize-filter",
            "--filter-battery",
            battery_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("invoke wafrift fingerprint --filter-battery");
    let _ = std::fs::remove_file(&battery_path);

    assert!(
        output.status.success(),
        "fingerprint --filter-battery exited non-zero: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    let report: serde_json::Value =
        serde_json::from_str(stdout.trim()).unwrap_or_else(|e| panic!("bad JSON {e}: {stdout}"));
    let policed: Vec<&str> = report["filter_profile"]["policed"]
        .as_array()
        .expect("policed array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(
        policed,
        vec!["EVILTAG"],
        "the custom battery's token (and only it) must drive the differential: {report}"
    );
}

/// A WAF that blocks attacks with a **200** body containing NO standard block
/// signature (`northstar gateway intercept …`) and reflects clean values
/// otherwise. The static classifier cannot recognise this block page; only
/// per-target calibration — which learns the shape from the malicious controls —
/// can. Proves the self-calibration path end-to-end.
fn handle_bespoke_200_block_waf(mut stream: TcpStream) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 64 * 1024 {
                    break;
                }
            }
            Err(_) => return,
        }
    }
    let line_end = buf.windows(2).position(|w| w == b"\r\n").unwrap_or(buf.len());
    let path = buf[..line_end].split(|&b| b == b' ').nth(1).unwrap_or(b"");
    let decoded = pct_decode_once(&extract_q(path));
    let lower = String::from_utf8_lossy(&decoded).to_ascii_lowercase();
    let attackish = ["<script", "passwd", "' or '", "cat /"]
        .iter()
        .any(|m| lower.contains(m));
    let body: Vec<u8> = if attackish {
        // No "access denied"/"blocked"/"forbidden" — unknown to any signature list.
        b"northstar gateway intercept reference 9931 contact your administrator".to_vec()
    } else {
        decoded
    };
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&body);
    let _ = stream.flush();
}

#[test]
fn fingerprint_calibration_detects_a_bespoke_200_block_with_no_signature() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local origin");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            handle_bespoke_200_block_waf(stream);
        }
    });

    let url = format!("http://{addr}/");
    let bin = env!("CARGO_BIN_EXE_wafrift");
    // NO --block-signatures: the default set cannot match this bespoke page, so a
    // positive result here is attributable to calibration alone.
    let output = Command::new(bin)
        .args([
            "fingerprint",
            "--url",
            &url,
            "--param",
            "q",
            "--characterize-filter",
            "--format",
            "json",
        ])
        .output()
        .expect("invoke wafrift fingerprint");

    assert!(output.status.success(), "stderr={}", String::from_utf8_lossy(&output.stderr));
    let report: serde_json::Value =
        serde_json::from_str(String::from_utf8(output.stdout).unwrap().trim())
            .expect("valid JSON");
    let policed: Vec<&str> = report["filter_profile"]["policed"]
        .as_array()
        .expect("policed array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        policed.contains(&"<script>"),
        "calibration must catch a bespoke 200 block page no signature lists: {report}"
    );
}

/// A WAF whose 200 block page carries a NON-default marker (`CUSTOM-WAF-WALL`),
/// used to prove a `--block-signatures` override reaches live classification.
fn handle_custom_marker_block_waf(mut stream: TcpStream) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 64 * 1024 {
                    break;
                }
            }
            Err(_) => return,
        }
    }
    let line_end = buf.windows(2).position(|w| w == b"\r\n").unwrap_or(buf.len());
    let path = buf[..line_end].split(|&b| b == b' ').nth(1).unwrap_or(b"");
    let decoded = pct_decode_once(&extract_q(path));
    let blocked = decoded.windows(8).any(|w| w.eq_ignore_ascii_case(b"<script>"));
    let body: Vec<u8> = if blocked {
        b"<html>CUSTOM-WAF-WALL: denied</html>".to_vec()
    } else {
        decoded
    };
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&body);
    let _ = stream.flush();
}

#[test]
fn fingerprint_custom_block_signature_overrides_default_detection() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local origin");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            handle_custom_marker_block_waf(stream);
        }
    });

    // A custom signature file naming this target's bespoke block marker.
    let sig_path = std::env::temp_dir().join(format!("wafrift_sigs_{}.toml", addr.port()));
    std::fs::write(&sig_path, "signature = [\"custom-waf-wall\"]\n").expect("write sigs");

    let url = format!("http://{addr}/");
    let bin = env!("CARGO_BIN_EXE_wafrift");
    let output = Command::new(bin)
        .args([
            "fingerprint",
            "--url",
            &url,
            "--param",
            "q",
            "--characterize-filter",
            "--block-signatures",
            sig_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("invoke wafrift fingerprint --block-signatures");
    let _ = std::fs::remove_file(&sig_path);

    assert!(output.status.success(), "stderr={}", String::from_utf8_lossy(&output.stderr));
    let report: serde_json::Value =
        serde_json::from_str(String::from_utf8(output.stdout).unwrap().trim())
            .expect("valid JSON");
    let policed: Vec<&str> = report["filter_profile"]["policed"]
        .as_array()
        .expect("policed array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        policed.contains(&"<script>"),
        "a custom block marker supplied via --block-signatures must be detected: {report}"
    );
}

/// A WAF that serves its block page with HTTP **200** (Cloudflare/Akamai/F5
/// style) when the decoded `q` contains `<script>`, and reflects cleanly
/// otherwise. A status-only oracle reads the block page as a PASS; the
/// content-aware oracle must read the body signature and classify it as a block.
fn handle_two_hundred_block_page_waf(mut stream: TcpStream) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 64 * 1024 {
                    break;
                }
            }
            Err(_) => return,
        }
    }
    let line_end = buf.windows(2).position(|w| w == b"\r\n").unwrap_or(buf.len());
    let path = buf[..line_end].split(|&b| b == b' ').nth(1).unwrap_or(b"");
    let decoded = pct_decode_once(&extract_q(path));
    let blocked = decoded.windows(8).any(|w| w.eq_ignore_ascii_case(b"<script>"));
    // ALWAYS HTTP 200 — the block is signalled only in the body.
    let body: Vec<u8> = if blocked {
        b"<html><h1>Access Denied</h1><p>This request was blocked.</p></html>".to_vec()
    } else {
        decoded
    };
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&body);
    let _ = stream.flush();
}

#[test]
fn fingerprint_detects_a_block_served_with_http_200() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local origin");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            handle_two_hundred_block_page_waf(stream);
        }
    });

    let url = format!("http://{addr}/");
    let bin = env!("CARGO_BIN_EXE_wafrift");
    let output = Command::new(bin)
        .args([
            "fingerprint",
            "--url",
            &url,
            "--param",
            "q",
            "--characterize-filter",
            "--format",
            "json",
        ])
        .output()
        .expect("invoke wafrift fingerprint --characterize-filter");

    assert!(
        output.status.success(),
        "fingerprint exited non-zero: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    let report: serde_json::Value =
        serde_json::from_str(stdout.trim()).unwrap_or_else(|e| panic!("bad JSON {e}: {stdout}"));
    let policed: Vec<&str> = report["filter_profile"]["policed"]
        .as_array()
        .expect("policed array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        policed.contains(&"<script>"),
        "a block served with HTTP 200 must be detected (not mistaken for a pass): {report}"
    );
}

#[test]
fn fingerprint_binary_reports_no_reflection_on_non_echoing_target() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local origin");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            handle_non_reflecting(stream);
        }
    });

    let url = format!("http://{addr}/");
    let bin = env!("CARGO_BIN_EXE_wafrift");
    let output = Command::new(bin)
        .args(["fingerprint", "--url", &url, "--param", "q", "--format", "json"])
        .output()
        .expect("invoke wafrift fingerprint");

    // Inconclusive ⇒ distinct non-zero exit (3), NOT success.
    assert_eq!(
        output.status.code(),
        Some(3),
        "non-reflecting target must exit 3 (inconclusive), got {:?}; stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    let report: serde_json::Value =
        serde_json::from_str(stdout.trim()).unwrap_or_else(|e| panic!("bad JSON {e}: {stdout}"));
    assert_eq!(
        report["reflection_observed"],
        serde_json::Value::Bool(false),
        "must report reflection_observed=false, got {report}"
    );
    assert!(
        report["detected_stages"].as_array().is_some_and(|a| a.is_empty()),
        "no stages may be reported when no reflection was observed: {report}"
    );
}

/// `--filter-budget N` must cap the probed token set to N (live-query
/// minimization for a rate-limited target), and `--filter-history` must persist
/// the per-token block/pass posterior so a later run warm-starts. Drives the
/// real binary against the `<script>`-blocking mock and asserts both the budget
/// truncation and the history round-trip.
#[test]
fn fingerprint_filter_budget_caps_probes_and_history_persists() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local origin");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            handle_script_blocking_waf(stream);
        }
    });

    let url = format!("http://{addr}/");
    let bin = env!("CARGO_BIN_EXE_wafrift");
    let hist = std::env::temp_dir().join(format!(
        "wafrift_filter_hist_{}_{}.json",
        std::process::id(),
        addr.port()
    ));
    let _ = std::fs::remove_file(&hist);

    let run = |budget: &str| {
        Command::new(bin)
            .args([
                "fingerprint",
                "--url",
                &url,
                "--param",
                "q",
                "--characterize-filter",
                "--filter-budget",
                budget,
                "--filter-history",
                hist.to_str().unwrap(),
                "--format",
                "json",
            ])
            .output()
            .expect("invoke fingerprint --filter-budget")
    };

    // Run 1: budget 3 — only 3 of the 12 battery tokens may be probed.
    let out = run("3");
    assert!(
        out.status.success(),
        "budget run exited non-zero: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--filter-budget 3") && stderr.contains("of 12"),
        "operator must be told the budget trimmed the battery: {stderr}"
    );
    let report: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).expect("json");
    let fp = &report["filter_profile"];
    let count = |k: &str| fp[k].as_array().map_or(0, Vec::len);
    let findings = count("policed") + count("unpoliced") + count("carrier_gated");
    assert!(
        findings <= 3 && findings >= 1,
        "budget 3 must yield at most 3 findings, got {findings}: {fp}"
    );

    // The history file must now exist and carry the probed tokens' posteriors.
    let text = std::fs::read_to_string(&hist).expect("history file written");
    let h: serde_json::Value = serde_json::from_str(&text).expect("history json");
    let by_id = h["by_id"].as_object().expect("by_id map");
    assert!(
        !by_id.is_empty() && by_id.len() <= 3,
        "history must record the (≤3) probed tokens, got {by_id:?}"
    );

    // Run 2: warm-start from the same history must not crash and must accumulate
    // (each probed token now has ≥1 more trial than after run 1).
    let out2 = run("3");
    assert!(out2.status.success(), "warm-start run failed: {}", String::from_utf8_lossy(&out2.stderr));
    let text2 = std::fs::read_to_string(&hist).expect("history persisted after run 2");
    let h2: serde_json::Value = serde_json::from_str(&text2).expect("history json 2");
    let total_trials = |v: &serde_json::Value| -> u64 {
        v["by_id"]
            .as_object()
            .unwrap()
            .values()
            .map(|s| s["n_blocked"].as_u64().unwrap_or(0) + s["n_passed"].as_u64().unwrap_or(0))
            .sum()
    };
    assert!(
        total_trials(&h2) > total_trials(&h),
        "warm-start run must accumulate observations: run1={} run2={}",
        total_trials(&h),
        total_trials(&h2)
    );

    let _ = std::fs::remove_file(&hist);
}
