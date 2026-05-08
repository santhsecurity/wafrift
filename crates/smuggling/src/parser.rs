//! Minimal HTTP response parser, chunked-body validator, and differential comparator.

use std::collections::HashMap;

/// Parsed HTTP/1.1 response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub version: u8,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Parse a raw HTTP/1.x response from bytes.
    ///
    /// # Errors
    /// Returns an error if the response is malformed or incomplete.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut resp = httparse::Response::new(&mut headers);
        match resp.parse(data) {
            Ok(status) if status.is_complete() => {
                let header_end = status.unwrap();
                let version = resp.version.ok_or(ParseError::MissingVersion)?;
                let status = resp.code.ok_or(ParseError::MissingStatus)?;
                let headers: Vec<(String, String)> = resp
                    .headers
                    .iter()
                    .map(|h| {
                        (
                            String::from_utf8_lossy(h.name.as_bytes()).into_owned(),
                            String::from_utf8_lossy(h.value).into_owned(),
                        )
                    })
                    .collect();
                let body = data[header_end..].to_vec();
                Ok(Self {
                    version,
                    status,
                    headers,
                    body,
                })
            }
            Ok(_) => Err(ParseError::Incomplete),
            Err(e) => Err(ParseError::Httparse(e)),
        }
    }
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ParseError {
    #[error("incomplete response")]
    Incomplete,
    #[error("missing HTTP version")]
    MissingVersion,
    #[error("missing status code")]
    MissingStatus,
    #[error("httparse error: {0:?}")]
    Httparse(httparse::Error),
    #[error("too many chunks")]
    TooManyChunks,
    #[error("body exceeds maximum size")]
    BodyTooLarge,
    #[error("invalid chunk size")]
    InvalidChunkSize,
}

/// Bounded chunked-body parser to prevent OOM from infinite chunks.
#[derive(Debug, Clone)]
pub struct ChunkedParser {
    pub max_total_size: usize,
    pub max_chunk_count: usize,
}

impl Default for ChunkedParser {
    fn default() -> Self {
        Self {
            max_total_size: 16 * 1024 * 1024,
            max_chunk_count: 10_000,
        }
    }
}

fn find_crlf(data: &[u8]) -> Option<usize> {
    data.windows(2).position(|w| w == b"\r\n")
}

impl ChunkedParser {
    /// Parse a chunked transfer-encoded body.
    ///
    /// # Errors
    /// Returns an error on malformed chunks, overflow, or limit exceedance.
    pub fn parse(&self, mut data: &[u8]) -> Result<Vec<u8>, ParseError> {
        let mut out = Vec::new();
        let mut chunks = 0usize;
        loop {
            if chunks >= self.max_chunk_count {
                return Err(ParseError::TooManyChunks);
            }
            let line_end = find_crlf(data).ok_or(ParseError::Incomplete)?;
            let line = &data[..line_end];
            data = &data[line_end + 2..];
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
            if out.len().saturating_add(size) > self.max_total_size {
                return Err(ParseError::BodyTooLarge);
            }
            if data.len() < size.saturating_add(2) {
                return Err(ParseError::Incomplete);
            }
            out.extend_from_slice(&data[..size]);
            data = &data[size + 2..];
            chunks += 1;
        }
        Ok(out)
    }
}

/// Differential response comparator.
#[derive(Debug, Clone, PartialEq)]
pub struct ResponseDiff {
    pub status_differs: bool,
    pub header_differs: bool,
    pub body_differs: bool,
    pub similarity: f64,
}

impl ResponseDiff {
    /// Compare two HTTP responses.
    #[must_use]
    pub fn compare(a: &HttpResponse, b: &HttpResponse) -> Self {
        let status_differs = a.status != b.status;
        let body_differs = a.body != b.body;
        let header_differs = {
            let mut a_map: HashMap<String, String> = HashMap::new();
            let mut b_map: HashMap<String, String> = HashMap::new();
            for (k, v) in &a.headers {
                a_map.insert(k.to_ascii_lowercase(), v.clone());
            }
            for (k, v) in &b.headers {
                b_map.insert(k.to_ascii_lowercase(), v.clone());
            }
            a_map != b_map
        };
        let similarity = if body_differs { 0.0 } else { 1.0 };
        Self {
            status_differs,
            header_differs,
            body_differs,
            similarity,
        }
    }
}

/// Header canonicalization fingerprint.
#[derive(Debug, Clone, Default)]
pub struct HeaderFingerprint {
    pub lowercased: HashMap<String, String>,
    pub trimmed: HashMap<String, String>,
}

impl HeaderFingerprint {
    /// Build a fingerprint from a set of headers.
    #[must_use]
    pub fn from_headers(headers: &[(String, String)]) -> Self {
        let mut lowercased = HashMap::new();
        let mut trimmed = HashMap::new();
        for (k, v) in headers {
            lowercased.insert(k.to_ascii_lowercase(), v.clone());
            trimmed.insert(k.trim().to_string(), v.trim().to_string());
        }
        Self {
            lowercased,
            trimmed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_response() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let r = HttpResponse::parse(raw).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.version, 1);
        assert!(r.body.is_empty());
    }

    #[test]
    fn parse_incomplete_fails() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n";
        assert!(matches!(
            HttpResponse::parse(raw),
            Err(ParseError::Incomplete)
        ));
    }

    #[test]
    fn chunked_parser_valid() {
        let data = b"5\r\nhello\r\n0\r\n\r\n";
        let parser = ChunkedParser::default();
        let body = parser.parse(data).unwrap();
        assert_eq!(body, b"hello");
    }

    #[test]
    fn chunked_parser_extension_ignored() {
        let data = b"5;ext=foo\r\nhello\r\n0\r\n\r\n";
        let parser = ChunkedParser::default();
        let body = parser.parse(data).unwrap();
        assert_eq!(body, b"hello");
    }

    #[test]
    fn chunked_parser_malformed_size() {
        let data = b"ZZZ\r\nhello\r\n0\r\n\r\n";
        let parser = ChunkedParser::default();
        assert!(matches!(
            parser.parse(data),
            Err(ParseError::InvalidChunkSize)
        ));
    }

    #[test]
    fn chunked_parser_too_many_chunks() {
        let mut data = Vec::new();
        for _ in 0..15 {
            data.extend_from_slice(b"1\r\nA\r\n");
        }
        data.extend_from_slice(b"0\r\n\r\n");
        let parser = ChunkedParser {
            max_total_size: 1024 * 1024,
            max_chunk_count: 5,
        };
        assert!(matches!(
            parser.parse(&data),
            Err(ParseError::TooManyChunks)
        ));
    }

    #[test]
    fn response_diff_detects_changes() {
        let a = HttpResponse::parse(b"HTTP/1.1 200 OK\r\nX: 1\r\n\r\nbody").unwrap();
        let b = HttpResponse::parse(b"HTTP/1.1 404 Not Found\r\nX: 2\r\n\r\nother").unwrap();
        let diff = ResponseDiff::compare(&a, &b);
        assert!(diff.status_differs);
        assert!(diff.header_differs);
        assert!(diff.body_differs);
        assert_eq!(diff.similarity, 0.0);
    }

    #[test]
    fn response_diff_identical() {
        let a = HttpResponse::parse(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
        let b = HttpResponse::parse(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
        let diff = ResponseDiff::compare(&a, &b);
        assert!(!diff.status_differs);
        assert!(!diff.header_differs);
        assert!(!diff.body_differs);
        assert_eq!(diff.similarity, 1.0);
    }

    #[test]
    fn header_fingerprint_normalization() {
        let fp = HeaderFingerprint::from_headers(&[("Content-Type".into(), " text/html ".into())]);
        assert_eq!(fp.lowercased.get("content-type").unwrap(), " text/html ");
        assert_eq!(fp.trimmed.get("Content-Type").unwrap(), "text/html");
    }
}
