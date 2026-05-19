#![allow(dead_code)]
// Shared helpers; each integration test binary only exercises a subset.

//! Shared helpers for integration tests: TCP capture + HTTP/1.1 framing parsers.
//!
//! Two body-framing modes model **desynchronization**:
//! - [`BodyFraming::Rfc7230`] — `Transfer-Encoding: chunked` overrides `Content-Length`.
//! - [`BodyFraming::ContentLengthOnly`] — ignore `Transfer-Encoding` and take exactly
//!   `Content-Length` octets (simulates a front-end that uses CL while the back-end uses TE).

use httparse::{EMPTY_HEADER, Header, Request};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;
use wafrift_smuggling::parser::{ChunkedParser, ParseError};

/// Error returned when wire bytes cannot be framed into complete HTTP messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireParseError {
    Incomplete,
    Httparse(httparse::Error),
    Chunked(ParseError),
    LeftoverGarbage(Vec<u8>),
}

impl std::fmt::Display for WireParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireParseError::Incomplete => write!(
                f,
                "Fix: buffer incomplete HTTP message — append bytes or close the socket."
            ),
            WireParseError::Httparse(e) => write!(f, "Fix: invalid HTTP — httparse: {e:?}"),
            WireParseError::Chunked(e) => write!(f, "Fix: malformed chunked body — {e}"),
            WireParseError::LeftoverGarbage(g) => write!(
                f,
                "Fix: trailing bytes are not consumed as HTTP ({:?})",
                &g[..g.len().min(32)]
            ),
        }
    }
}

impl std::error::Error for WireParseError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFraming {
    /// RFC 7230 Section 3.3.3: chunked Transfer-Encoding wins over Content-Length.
    Rfc7230,
    /// Consume exactly `Content-Length` octets; ignore Transfer-Encoding for sizing.
    ContentLengthOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

fn headers_from_httparse<'a>(src: &[Header<'a>]) -> Vec<(String, String)> {
    src.iter()
        .map(|h| {
            (
                String::from_utf8_lossy(h.name.as_bytes()).into_owned(),
                String::from_utf8_lossy(h.value).into_owned(),
            )
        })
        .collect()
}

fn header_names_contains_chunked(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked")
    })
}

fn last_content_length(headers: &[(String, String)]) -> Option<usize> {
    let mut last = None;
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("content-length")
            && let Ok(n) = v.trim().parse::<usize>()
        {
            last = Some(n);
        }
    }
    last
}

fn method_implies_body(method: &[u8]) -> bool {
    matches!(
        method,
        b"POST" | b"PUT" | b"PATCH" | b"DELETE" | b"OPTIONS" | b"QUERY"
    )
}

/// Decode chunked body; returns (`decoded_data`, `consumed_bytes_from_input`).
///
/// After the final `0` chunk line, consumes terminating CRLF blank lines that close the
/// chunked encoding (empty trailers).
pub fn chunked_decode_consume(data: &[u8]) -> Result<(Vec<u8>, usize), ParseError> {
    let parser = ChunkedParser::default();
    let mut buf = data;
    let start_len = buf.len();
    let mut out = Vec::new();
    let mut chunks = 0usize;
    loop {
        if chunks >= parser.max_chunk_count {
            return Err(ParseError::TooManyChunks);
        }
        let line_end = buf
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or(ParseError::Incomplete)?;
        let line = &buf[..line_end];
        buf = &buf[line_end + 2..];
        let hex = std::str::from_utf8(line)
            .map_err(|_| ParseError::InvalidChunkSize)?
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let size = usize::from_str_radix(hex, 16).map_err(|_| ParseError::InvalidChunkSize)?;
        if size == 0 {
            break;
        }
        if out.len().saturating_add(size) > parser.max_total_size {
            return Err(ParseError::BodyTooLarge);
        }
        if buf.len() < size.saturating_add(2) {
            return Err(ParseError::Incomplete);
        }
        out.extend_from_slice(&buf[..size]);
        buf = &buf[size + 2..];
        chunks += 1;
    }
    while buf.starts_with(b"\r\n") {
        buf = &buf[2..];
    }
    let consumed = start_len - buf.len();
    Ok((out, consumed))
}

fn consume_body(
    framing: BodyFraming,
    _method: &[u8],
    headers: &[(String, String)],
    body_slice: &[u8],
) -> Result<(Vec<u8>, usize), ParseError> {
    match framing {
        BodyFraming::Rfc7230 => {
            if header_names_contains_chunked(headers) {
                chunked_decode_consume(body_slice)
            } else if let Some(n) = last_content_length(headers) {
                if body_slice.len() < n {
                    return Err(ParseError::Incomplete);
                }
                Ok((body_slice[..n].to_vec(), n))
            } else {
                Ok((Vec::new(), 0))
            }
        }
        BodyFraming::ContentLengthOnly => {
            if let Some(n) = last_content_length(headers) {
                if body_slice.len() < n {
                    return Err(ParseError::Incomplete);
                }
                Ok((body_slice[..n].to_vec(), n))
            } else {
                Ok((Vec::new(), 0))
            }
        }
    }
}

/// Split `buf` into consecutive HTTP/1.x requests using the given framing rule.
///
/// # Errors
/// Returns [`WireParseError::Httparse`] if trailing bytes cannot start a valid request.
pub fn parse_http_requests(
    buf: &[u8],
    framing: BodyFraming,
) -> Result<Vec<ParsedRequest>, WireParseError> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset < buf.len() {
        let mut headers_buf = [EMPTY_HEADER; 64];
        let mut req = Request::new(&mut headers_buf);
        match req.parse(&buf[offset..]) {
            Ok(st) if st.is_complete() => {
                let header_end = st.unwrap();
                let method_bs = req.method.ok_or(WireParseError::Incomplete)?.as_bytes();
                let path_str = req.path.ok_or(WireParseError::Incomplete)?;
                let hdrs = headers_from_httparse(req.headers);
                let body_region = &buf[offset + header_end..];
                let (body, consumed) = consume_body(framing, method_bs, &hdrs, body_region)
                    .map_err(WireParseError::Chunked)?;
                out.push(ParsedRequest {
                    method: String::from_utf8_lossy(method_bs).into_owned(),
                    path: path_str.to_string(),
                    headers: hdrs,
                    body,
                });
                offset += header_end + consumed;
            }
            Ok(_) => return Err(WireParseError::Incomplete),
            Err(e) => return Err(WireParseError::Httparse(e)),
        }
    }
    Ok(out)
}

/// Like [`parse_http_requests`], but fails if any octet remains unconsumed (no tail garbage).
pub fn parse_http_requests_no_tail(
    buf: &[u8],
    framing: BodyFraming,
) -> Result<Vec<ParsedRequest>, WireParseError> {
    let requests = parse_http_requests(buf, framing)?;
    let mut offset = 0usize;
    for pr in &requests {
        let mut headers_buf = [EMPTY_HEADER; 64];
        let mut req = Request::new(&mut headers_buf);
        let st = req
            .parse(&buf[offset..])
            .map_err(WireParseError::Httparse)?;
        if !st.is_complete() {
            return Err(WireParseError::Incomplete);
        }
        let header_end = st.unwrap();
        let (_, consumed) = consume_body(
            framing,
            req.method.unwrap_or("").as_bytes(),
            &pr.headers,
            &buf[offset + header_end..],
        )
        .map_err(WireParseError::Chunked)?;
        offset += header_end + consumed;
    }
    if offset != buf.len() {
        return Err(WireParseError::LeftoverGarbage(buf[offset..].to_vec()));
    }
    Ok(requests)
}

/// Bind `127.0.0.1:0`, accept one connection, read until peer shuts down the write half.
pub fn tcp_capture_one_payload(payload: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;

    let handle = thread::spawn(move || -> Result<Vec<u8>, std::io::Error> {
        let (mut stream, _) = listener.accept()?;
        stream.set_read_timeout(Some(Duration::from_secs(4)))?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf)?;
        Ok(buf)
    });

    let mut client = TcpStream::connect(addr)?;
    client.set_write_timeout(Some(Duration::from_secs(4)))?;
    client.write_all(payload)?;
    client.shutdown(Shutdown::Write)?;

    handle
        .join()
        .map_err(|_| std::io::Error::other("server thread panicked"))?
}
