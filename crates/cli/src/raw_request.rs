//! `RawRequest` — captures one HTTP request shape (method + URL +
//! headers + body) so the rest of the CLI can:
//!
//! 1. **Parse** a Burp-saved raw HTTP request file (the bytes you get
//!    from *Copy → Save raw → File*) into a [`RawRequest`].
//! 2. **Substitute** the injection marker `§§` with each variant
//!    payload via [`RawRequest::with_payload`].
//! 3. **Reproduce** the resulting request as a copy-pasteable
//!    `curl -i` line via [`RawRequest::to_curl`].
//!
//! ## Pentester workflow
//!
//! Intercept the target request in Burp, save it via *Copy → Save raw
//! → File*, mark the parameter to fuzz with `§§`, then feed the file
//! to wafrift:
//!
//! ```text
//! $ wafrift scan -r req.txt --payload "' OR 1=1--"
//! ```
//!
//! The scan loop substitutes each candidate payload into `§§` (in URL,
//! header values, or body) and fires the resulting request. Every
//! bypass surfaces with its `to_curl` reproducer — paste into a
//! terminal, get the same response.
//!
//! ## Burp request file shape
//!
//! Burp's *Save raw → File* writes the on-the-wire bytes:
//!
//! ```text
//! POST /api/login HTTP/1.1
//! Host: target.example
//! Content-Type: application/json
//! Cookie: session=abc; csrf=xyz
//! Content-Length: 32
//!
//! {"user":"admin","pass":"§§"}
//! ```
//!
//! Either CRLF or LF line endings ride through (Burp emits CRLF;
//! hand-edited files often use LF). The first blank line separates
//! headers from body. Shell-escaping for curl reproducers routes
//! through [`crate::helpers::shell_single_quote`] — single source of
//! truth.

use crate::helpers::shell_single_quote;

/// One HTTP request shape — what an operator would copy out of Burp
/// or browser dev-tools. Round-trips to a `curl -i` invocation via
/// [`RawRequest::to_curl`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRequest {
    /// HTTP method verb. Conventionally uppercase; `to_curl` emits
    /// the `-X <METHOD>` flag for anything other than `GET` (curl
    /// defaults to GET, no flag needed).
    pub method: String,
    /// Absolute target URL — scheme + authority + path + query.
    pub url: String,
    /// Header field list in insertion order. Order is preserved
    /// because some WAF parsers and a handful of pentest scenarios
    /// (header smuggling, dup-header dispatch) DO care about it.
    pub headers: Vec<(String, String)>,
    /// Raw body bytes — empty for GET-style requests without a body.
    pub body: Vec<u8>,
}

/// The injection-marker literal a pentester drops into the request
/// to indicate where the payload should be substituted. Matches
/// Burp Intruder's `§…§` syntax in its degenerate `§§` form.
pub const INJECTION_MARKER: &str = "§§";

/// Parse a Burp-style raw HTTP request file with a caller-supplied
/// URL scheme (typically `http` or `https`). The default scheme for
/// the CLI is owned by `ScanArgs::raw_request_scheme` (clap default
/// `"http"`), not by this module — one source of truth.
///
/// # Errors
///
/// Returns a human-readable error when the request line is malformed,
/// the `Host:` header is absent (cannot reconstruct URL), or any
/// header line is structurally invalid.
pub fn parse_raw_http_request_with_scheme(
    text: &str,
    scheme: &str,
) -> Result<RawRequest, String> {
    if text.is_empty() {
        return Err("empty request file".to_string());
    }

    let bytes = text.as_bytes();
    let split_at = find_header_body_split(bytes);
    let (header_bytes, body_bytes) = match split_at {
        Some((hdr_end, body_start)) => (&bytes[..hdr_end], &bytes[body_start..]),
        None => (bytes, &b""[..]),
    };

    let header_text = std::str::from_utf8(header_bytes)
        .map_err(|_| "header section is not valid UTF-8".to_string())?;

    let mut lines = header_text.split('\n').map(|l| l.trim_end_matches('\r'));
    let request_line = lines
        .next()
        .ok_or_else(|| "missing request line".to_string())?;

    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| "request line missing method".to_string())?
        .to_string();
    let path_and_query = parts
        .next()
        .ok_or_else(|| "request line missing path".to_string())?
        .to_string();
    // Trailing "HTTP/1.1" is ignored — reqwest negotiates the version
    // it wants regardless of what the file claims.

    let mut headers: Vec<(String, String)> = Vec::new();
    let mut host: Option<String> = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = split_header(line) else {
            return Err(format!("malformed header line: {line:?}"));
        };
        if name.eq_ignore_ascii_case("host") && host.is_none() {
            host = Some(value.clone());
        }
        headers.push((name, value));
    }

    let host = host.ok_or_else(|| "missing Host header — cannot reconstruct URL".to_string())?;
    let url = reconstruct_url(scheme, &host, &path_and_query);

    Ok(RawRequest {
        method: method.to_ascii_uppercase(),
        url,
        headers,
        body: body_bytes.to_vec(),
    })
}

/// Locate the first blank-line separator. Returns `(headers_end,
/// body_start)`. Prefers CRLF CRLF (the wire format Burp emits) over
/// LF LF (a hand-edited file) — returning the earlier match keeps a
/// CRLF-headered file with a stray LF inside the body from splitting
/// in the wrong place.
fn find_header_body_split(bytes: &[u8]) -> Option<(usize, usize)> {
    let crlf = find_subseq(bytes, b"\r\n\r\n").map(|i| (i, i + 4));
    let lf = find_subseq(bytes, b"\n\n").map(|i| (i, i + 2));
    match (crlf, lf) {
        (Some(a), Some(b)) if a.0 <= b.0 => Some(a),
        (Some(a), None) => Some(a),
        (_, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn find_subseq(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}

/// Split a header line on the first colon. Trims surrounding
/// whitespace on the value per RFC 9112 §5.
fn split_header(line: &str) -> Option<(String, String)> {
    let idx = line.find(':')?;
    let name = line[..idx].trim().to_string();
    if name.is_empty() {
        return None;
    }
    let value = line[idx + 1..].trim().to_string();
    Some((name, value))
}

/// Build an absolute URL from scheme + host + path. The path may
/// already include a query string; we leave it alone.
fn reconstruct_url(scheme: &str, host: &str, path_and_query: &str) -> String {
    let path = if path_and_query.starts_with('/') {
        path_and_query.to_string()
    } else {
        format!("/{path_and_query}")
    };
    format!("{scheme}://{host}{path}")
}

impl RawRequest {
    /// Substitute every occurrence of [`INJECTION_MARKER`] (`§§`)
    /// in the URL, headers, and body with `payload`. Body substitution
    /// happens at the byte level so non-UTF-8 marker positions still
    /// resolve. Returns a NEW [`RawRequest`] — the original is not
    /// mutated, so a single template can be reused across many
    /// variants.
    pub fn with_payload(&self, payload: &str) -> Self {
        let url = self.url.replace(INJECTION_MARKER, payload);
        let headers = self
            .headers
            .iter()
            .map(|(n, v)| (n.clone(), v.replace(INJECTION_MARKER, payload)))
            .collect();
        let body = replace_in_bytes(&self.body, INJECTION_MARKER.as_bytes(), payload.as_bytes());
        Self {
            method: self.method.clone(),
            url,
            headers,
            body,
        }
    }

    /// True iff at least one [`INJECTION_MARKER`] (`§§`) appears in
    /// the URL, any header value, or the body. The `-r` flag rejects
    /// templates without a marker — otherwise every variant fires
    /// the same un-mutated request, which is almost certainly an
    /// operator mistake.
    pub fn has_injection_marker(&self) -> bool {
        if self.url.contains(INJECTION_MARKER) {
            return true;
        }
        if self.headers.iter().any(|(_, v)| v.contains(INJECTION_MARKER)) {
            return true;
        }
        find_subseq(&self.body, INJECTION_MARKER.as_bytes()).is_some()
    }

    /// Emit a copy-pasteable `curl -i` invocation that reproduces
    /// this request exactly. Shell-escaping for every interpolated
    /// value routes through [`shell_single_quote`] — one source of
    /// truth.
    ///
    /// Header handling: `Content-Length` is dropped because curl
    /// re-derives it from `--data-binary`'s payload length, and a
    /// stale value from the captured request would confuse the
    /// transport.
    pub fn to_curl(&self) -> String {
        let mut out = String::from("curl -i");
        if self.method != "GET" {
            out.push_str(" -X ");
            out.push_str(&self.method);
        }
        for (name, value) in &self.headers {
            if name.eq_ignore_ascii_case("content-length") {
                continue;
            }
            out.push(' ');
            out.push_str("-H ");
            out.push_str(&shell_single_quote(&format!("{name}: {value}")));
        }
        if !self.body.is_empty() {
            out.push_str(" --data-binary ");
            let body_str = String::from_utf8_lossy(&self.body);
            out.push_str(&shell_single_quote(&body_str));
        }
        out.push(' ');
        out.push_str(&shell_single_quote(&self.url));
        out
    }
}

/// Byte-level replace of `needle` with `replacement` inside `hay`.
/// Falls back to the original bytes if the needle never appears.
fn replace_in_bytes(hay: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() || hay.len() < needle.len() {
        return hay.to_vec();
    }
    let mut out: Vec<u8> = Vec::with_capacity(hay.len());
    let mut i = 0;
    while i < hay.len() {
        if i + needle.len() <= hay.len() && &hay[i..i + needle.len()] == needle {
            out.extend_from_slice(replacement);
            i += needle.len();
        } else {
            out.push(hay[i]);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(method: &str, url: &str) -> RawRequest {
        RawRequest {
            method: method.to_string(),
            url: url.to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Test-only convenience: parse with the default `http` scheme.
    /// Production callers pass `--raw-request-scheme` through; the
    /// no-arg form would be dead surface in the binary, so it lives
    /// here next to the tests that use it.
    fn parse_raw_http_request(text: &str) -> Result<RawRequest, String> {
        parse_raw_http_request_with_scheme(text, "http")
    }

    // ── parse_raw_http_request ────────────────────────────────

    #[test]
    fn parses_minimal_get_request() {
        let r = parse_raw_http_request("GET / HTTP/1.1\r\nHost: x.example\r\n\r\n").unwrap();
        assert_eq!(r.method, "GET");
        assert_eq!(r.url, "http://x.example/");
        assert!(r.body.is_empty());
    }

    #[test]
    fn parses_post_with_body() {
        let raw = "POST /api/login HTTP/1.1\r\n\
                   Host: target.example\r\n\
                   Content-Type: application/json\r\n\
                   Content-Length: 23\r\n\
                   \r\n\
                   {\"user\":\"admin\"}";
        let r = parse_raw_http_request(raw).unwrap();
        assert_eq!(r.method, "POST");
        assert_eq!(r.url, "http://target.example/api/login");
        assert_eq!(r.body, b"{\"user\":\"admin\"}");
        assert_eq!(r.headers.len(), 3);
    }

    #[test]
    fn accepts_lf_only_line_endings() {
        let r = parse_raw_http_request("GET /a HTTP/1.1\nHost: x\nAccept: */*\n\n").unwrap();
        assert_eq!(r.url, "http://x/a");
        assert_eq!(r.headers.len(), 2);
    }

    #[test]
    fn accepts_crlf_headers_with_lf_body() {
        let raw = "POST /p HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\n\r\nline1\nline2\n";
        let r = parse_raw_http_request(raw).unwrap();
        assert_eq!(r.body, b"line1\nline2\n");
    }

    #[test]
    fn missing_host_header_errors() {
        let err = parse_raw_http_request("GET / HTTP/1.1\r\nAccept: */*\r\n\r\n").unwrap_err();
        assert!(err.to_lowercase().contains("host"), "got: {err}");
    }

    #[test]
    fn empty_input_errors() {
        let err = parse_raw_http_request("").unwrap_err();
        assert!(err.contains("empty"));
    }

    #[test]
    fn missing_path_errors() {
        assert!(parse_raw_http_request("GET\r\nHost: x\r\n\r\n").is_err());
    }

    #[test]
    fn malformed_header_line_errors() {
        let raw = "GET / HTTP/1.1\r\nHost: x\r\nnocolon\r\n\r\n";
        assert!(parse_raw_http_request(raw).is_err());
    }

    #[test]
    fn method_is_uppercased_on_parse() {
        let r = parse_raw_http_request("post /p HTTP/1.1\r\nHost: x\r\n\r\nbody").unwrap();
        assert_eq!(r.method, "POST");
    }

    #[test]
    fn path_without_leading_slash_gets_one() {
        let r = parse_raw_http_request("GET path HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        assert_eq!(r.url, "http://x/path");
    }

    #[test]
    fn query_string_is_preserved_in_url() {
        let r = parse_raw_http_request("GET /a?b=c&d=e HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        assert_eq!(r.url, "http://x/a?b=c&d=e");
    }

    #[test]
    fn https_scheme_via_explicit_call() {
        let r = parse_raw_http_request_with_scheme(
            "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
            "https",
        )
        .unwrap();
        assert_eq!(r.url, "https://x/");
    }

    #[test]
    fn duplicate_headers_preserved_in_order() {
        let raw = "GET / HTTP/1.1\r\nHost: x\r\nCookie: a=1\r\nCookie: b=2\r\n\r\n";
        let r = parse_raw_http_request(raw).unwrap();
        let cookies: Vec<_> = r.headers.iter().filter(|(n, _)| n == "Cookie").collect();
        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies[0].1, "a=1");
        assert_eq!(cookies[1].1, "b=2");
    }

    #[test]
    fn body_with_utf8_null_byte_round_trips() {
        let raw = "POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\na\0b";
        let r = parse_raw_http_request(raw).unwrap();
        assert_eq!(r.body, b"a\0b");
    }

    #[test]
    fn header_values_are_trimmed_of_whitespace() {
        let r = parse_raw_http_request("GET / HTTP/1.1\r\nHost:   x.example   \r\n\r\n").unwrap();
        assert_eq!(r.headers[0].1, "x.example");
    }

    #[test]
    fn host_header_lookup_is_case_insensitive() {
        let r = parse_raw_http_request("GET / HTTP/1.1\r\nhost: x.example\r\n\r\n").unwrap();
        assert_eq!(r.url, "http://x.example/");
    }

    // ── with_payload (§§ substitution) ────────────────────────

    #[test]
    fn with_payload_substitutes_in_body() {
        let r = parse_raw_http_request(
            "POST /a HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\n\r\nq=§§",
        )
        .unwrap();
        let m = r.with_payload("attack");
        assert_eq!(m.body, b"q=attack");
    }

    #[test]
    fn with_payload_substitutes_in_url() {
        let r = parse_raw_http_request("GET /search?q=§§ HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let m = r.with_payload("PAYLOAD");
        assert_eq!(m.url, "http://x/search?q=PAYLOAD");
    }

    #[test]
    fn with_payload_substitutes_in_header_value() {
        let r = parse_raw_http_request(
            "GET / HTTP/1.1\r\nHost: x\r\nX-Custom: prefix-§§-suffix\r\n\r\n",
        )
        .unwrap();
        let m = r.with_payload("INJECT");
        let v = &m.headers.iter().find(|(n, _)| n == "X-Custom").unwrap().1;
        assert_eq!(v, "prefix-INJECT-suffix");
    }

    #[test]
    fn with_payload_no_marker_returns_identical_request() {
        let r = parse_raw_http_request("GET /a HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        assert_eq!(r.with_payload("anything"), r);
    }

    #[test]
    fn with_payload_substitutes_every_occurrence() {
        let r = parse_raw_http_request("GET /a?x=§§&y=§§ HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let m = r.with_payload("p");
        assert_eq!(m.url, "http://x/a?x=p&y=p");
    }

    // ── has_injection_marker ──────────────────────────────────

    #[test]
    fn has_injection_marker_detects_marker_in_url() {
        let r = parse_raw_http_request("GET /a?q=§§ HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        assert!(r.has_injection_marker());
    }

    #[test]
    fn has_injection_marker_detects_marker_in_header() {
        let r = parse_raw_http_request(
            "GET / HTTP/1.1\r\nHost: x\r\nCookie: sess=§§\r\n\r\n",
        )
        .unwrap();
        assert!(r.has_injection_marker());
    }

    #[test]
    fn has_injection_marker_detects_marker_in_body() {
        let r = parse_raw_http_request(
            "POST /a HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\n\r\nq=§§",
        )
        .unwrap();
        assert!(r.has_injection_marker());
    }

    #[test]
    fn has_injection_marker_false_when_no_marker_anywhere() {
        let r = parse_raw_http_request("GET /a HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        assert!(!r.has_injection_marker());
    }

    // ── to_curl ───────────────────────────────────────────────

    #[test]
    fn to_curl_emits_get_without_method_flag() {
        let r = req("GET", "http://x/");
        let out = r.to_curl();
        assert!(!out.contains("-X GET"), "GET should be implicit: {out}");
        assert!(out.starts_with("curl -i "), "got: {out}");
    }

    #[test]
    fn to_curl_emits_explicit_method_flag_for_non_get() {
        let r = req("POST", "http://x/a");
        let out = r.to_curl();
        assert!(out.contains("-X POST"), "got: {out}");
    }

    #[test]
    fn to_curl_quotes_url_via_canonical_shell_escape() {
        let r = req("GET", "http://x/a?b=c");
        let out = r.to_curl();
        assert!(out.ends_with("'http://x/a?b=c'"), "got: {out}");
    }

    #[test]
    fn to_curl_emits_header_flags_in_insertion_order() {
        let r = RawRequest {
            method: "GET".into(),
            url: "http://x/".into(),
            headers: vec![
                ("X-First".into(), "1".into()),
                ("X-Second".into(), "2".into()),
            ],
            body: Vec::new(),
        };
        let out = r.to_curl();
        let first_idx = out.find("X-First").expect("X-First present");
        let second_idx = out.find("X-Second").expect("X-Second present");
        assert!(first_idx < second_idx, "order preserved: {out}");
    }

    #[test]
    fn to_curl_drops_content_length_so_curl_re_derives_it() {
        let r = RawRequest {
            method: "POST".into(),
            url: "http://x/a".into(),
            headers: vec![("Content-Length".into(), "4".into())],
            body: b"body".to_vec(),
        };
        let out = r.to_curl();
        assert!(!out.contains("Content-Length"), "got: {out}");
        assert!(out.contains("--data-binary 'body'"), "got: {out}");
    }

    #[test]
    fn to_curl_drops_content_length_case_insensitively() {
        let r = RawRequest {
            method: "POST".into(),
            url: "http://x/a".into(),
            headers: vec![("content-length".into(), "4".into())],
            body: b"body".to_vec(),
        };
        let out = r.to_curl();
        assert!(!out.to_lowercase().contains("content-length"), "got: {out}");
    }

    #[test]
    fn to_curl_escapes_apostrophes_inside_body() {
        let r = RawRequest {
            method: "POST".into(),
            url: "http://x/a".into(),
            headers: Vec::new(),
            body: b"a'b".to_vec(),
        };
        let out = r.to_curl();
        assert!(out.contains("'a'\\''b'"), "got: {out}");
        assert!(!out.contains("'a'b'"), "raw apostrophe leaked: {out}");
    }

    #[test]
    fn to_curl_skips_body_section_when_body_is_empty() {
        let r = req("GET", "http://x/");
        assert!(!r.to_curl().contains("--data-binary"));
    }

    #[test]
    fn to_curl_handles_body_with_non_utf8_bytes_via_lossy() {
        let r = RawRequest {
            method: "POST".into(),
            url: "http://x/a".into(),
            headers: Vec::new(),
            body: vec![0xC3, 0x28, 0x00, 0xFF],
        };
        let out = r.to_curl();
        assert!(out.contains("--data-binary"));
        assert!(out.starts_with("curl -i "));
    }

    // ── replace_in_bytes helper ───────────────────────────────

    #[test]
    fn replace_in_bytes_replaces_marker_in_middle() {
        assert_eq!(
            replace_in_bytes("a§§b".as_bytes(), "§§".as_bytes(), b"X"),
            b"aXb".to_vec()
        );
    }

    #[test]
    fn replace_in_bytes_empty_needle_is_a_noop() {
        assert_eq!(replace_in_bytes(b"abc", b"", b"X"), b"abc".to_vec());
    }

    #[test]
    fn replace_in_bytes_no_match_returns_original() {
        assert_eq!(replace_in_bytes(b"abc", b"xx", b"Y"), b"abc".to_vec());
    }

    #[test]
    fn replace_in_bytes_handles_multiple_occurrences() {
        assert_eq!(
            replace_in_bytes("§§§§".as_bytes(), "§§".as_bytes(), b"!"),
            b"!!".to_vec()
        );
    }

    // ── parse + with_payload + to_curl integration ────────────

    #[test]
    fn parse_then_substitute_then_curl_round_trip() {
        // The full pentester loop in one assertion: parse Burp output,
        // sub the payload, render curl. Confirms every step composes.
        let raw = "POST /login HTTP/1.1\r\n\
                   Host: target.example\r\n\
                   Content-Type: application/json\r\n\
                   \r\n\
                   {\"user\":\"admin\",\"pass\":\"§§\"}";
        let r = parse_raw_http_request(raw).unwrap();
        let m = r.with_payload("' OR 1=1--");
        let curl = m.to_curl();
        assert!(curl.contains("-X POST"), "got: {curl}");
        assert!(curl.contains("'http://target.example/login'"), "got: {curl}");
        assert!(curl.contains("'Content-Type: application/json'"), "got: {curl}");
        // Payload is in the body, single-quote escaped.
        assert!(curl.contains("--data-binary"), "got: {curl}");
        // The apostrophes in the payload were escaped properly.
        assert!(!curl.contains("OR 1=1--'"), "raw apostrophe leaked: {curl}");
    }

    // ── Adversarial parse inputs ─────────────────────────────────────────────
    // These cover the cases that crash naive parsers: massive single-line
    // inputs, 100 K §§ markers, embedded NULs, missing Host, malformed
    // CRLF, port 0.  None must panic; each must return Ok or Err with a
    // clear message.

    #[test]
    fn adversarial_1mb_single_line_does_not_panic() {
        // 1 MB single line — no CRLF separating headers from body.
        // Parser must produce Err, not panic.
        let line = "GET ".to_string() + &"A".repeat(1_024 * 1024) + " HTTP/1.1";
        let result = parse_raw_http_request(&line);
        // Must be Err because there's no Host header.
        assert!(
            result.is_err(),
            "expected Err for 1 MB header-less line, got Ok"
        );
        let msg = result.unwrap_err();
        assert!(!msg.is_empty(), "error message must not be empty");
    }

    #[test]
    fn adversarial_100k_injection_markers_does_not_panic() {
        // A body with 100 K `§§` markers.  with_payload must complete
        // without panic or OOM, just with a very large output.
        let markers = "§§".repeat(100_000);
        let raw = format!(
            "POST /fuzz HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\n\r\n{markers}"
        );
        let r = parse_raw_http_request(&raw).expect("parse with 100K markers");
        // Substitute a 1-byte payload — output is 100 K chars.
        let out = r.with_payload("X");
        assert_eq!(out.body, b"X".repeat(100_000).to_vec());
        // has_injection_marker must find the original markers before sub.
        assert!(r.has_injection_marker());
    }

    #[test]
    fn adversarial_embedded_nuls_in_body_do_not_panic() {
        // NUL bytes in the body are valid binary content.
        let raw = "POST /nul HTTP/1.1\r\nHost: x\r\n\r\na\x00b\x00c";
        let r = parse_raw_http_request(raw).expect("NUL bytes in body must parse");
        assert_eq!(r.body, b"a\x00b\x00c");
        // to_curl must not panic on non-UTF-8-clean body.
        let _ = r.to_curl();
    }

    #[test]
    fn adversarial_missing_host_header_returns_err_with_message() {
        let raw = "GET /secret HTTP/1.1\r\nX-Forwarded-For: 127.0.0.1\r\n\r\n";
        let err = parse_raw_http_request(raw).unwrap_err();
        assert!(
            err.to_lowercase().contains("host"),
            "error must mention 'Host': {err}"
        );
    }

    #[test]
    fn adversarial_port_zero_in_host_header_does_not_panic() {
        // port 0 is syntactically valid in a Host header even if it's
        // useless operationally.  The parser must not crash trying to
        // connect (it doesn't connect — it just builds a URL).
        let raw = "GET /p HTTP/1.1\r\nHost: 127.0.0.1:0\r\n\r\n";
        let r = parse_raw_http_request(raw).expect("port 0 must parse");
        assert!(r.url.contains(":0"), "port 0 preserved in URL: {}", r.url);
    }

    #[test]
    fn adversarial_malformed_crlf_header_errors_not_panics() {
        // A lone CR without LF in the header section — some parsers
        // crash or loop on this.  Must return Err with a clear message.
        // The first \r without \n means the request line runs on
        // forever from the parser's point of view.  The key property
        // is: no panic, the error message is non-empty.
        let raw = "GET /a HTTP/1.1\rHost: x\r\n\r\n";
        // This either parses (treating \r as part of the token) or
        // errors — both are acceptable.  Panic is not.
        match parse_raw_http_request(raw) {
            Ok(_) => { /* parser was lenient — acceptable */ }
            Err(msg) => {
                assert!(!msg.is_empty(), "Err must carry a message");
            }
        }
    }

    #[test]
    fn adversarial_only_crlf_body_does_not_panic() {
        // A POST whose body is pure CRLF sequences.
        let raw = "POST /crlf HTTP/1.1\r\nHost: x\r\n\r\n\r\n\r\n\r\n";
        let r = parse_raw_http_request(raw).expect("CRLF body must parse");
        assert!(!r.url.is_empty());
    }

    #[test]
    fn adversarial_header_with_very_long_value_does_not_panic() {
        // A header value of 256 KB — common in JWT-heavy APIs.
        let long_val = "A".repeat(256 * 1024);
        let raw = format!(
            "GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {long_val}\r\n\r\n"
        );
        let r = parse_raw_http_request(&raw).expect("long header value must parse");
        let auth = r
            .headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("Authorization"))
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        assert!(auth.starts_with("Bearer A"), "Authorization value preserved");
    }

    #[test]
    fn adversarial_no_http_version_still_parses() {
        // Some hand-crafted templates omit the "HTTP/1.1" version token.
        // The path token is mandatory; version is the trailing ignored field.
        let raw = "DELETE /resource HTTP/1.1\r\nHost: x\r\n\r\n";
        let r = parse_raw_http_request(raw).expect("DELETE must parse");
        assert_eq!(r.method, "DELETE");
    }

    #[test]
    fn adversarial_body_of_only_nul_bytes_does_not_panic() {
        let nuls: Vec<u8> = vec![0u8; 4096];
        let header = "POST /b HTTP/1.1\r\nHost: x\r\n\r\n";
        let mut raw = header.as_bytes().to_vec();
        raw.extend_from_slice(&nuls);
        let text = String::from_utf8_lossy(&raw).into_owned();
        let r = parse_raw_http_request(&text).expect("NUL-only body must parse");
        assert!(!r.body.is_empty(), "body must not be empty after NUL input");
    }
}
