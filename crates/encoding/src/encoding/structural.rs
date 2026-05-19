//! Structural encoding strategies — byte-level and framing manipulations.

use base64::{Engine as _, engine::general_purpose};
use std::io::Write as _;

use crate::error::EncodeError;

/// Result of chunked transfer-encoding split.
///
/// This strategy is ONLY semantically correct when the body is sent as the body
/// of an HTTP request with `Transfer-Encoding: chunked`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkedBody {
    /// The chunked-encoded body as raw bytes.
    pub body: Vec<u8>,
    /// Required headers that must accompany this body.
    pub required_headers: Vec<(String, String)>,
}

/// Null byte injection — append `%00` to truncate strings in C-style parsers.
///
/// **Context**: `php`, `cgi` — only semantically correct for backends using
/// C-style null-terminated string handling.
pub fn null_byte_inject(payload: impl AsRef<[u8]>) -> Result<String, EncodeError> {
    let payload = payload.as_ref();
    let payload_str = std::str::from_utf8(payload).map_err(|_| EncodeError::InvalidUtf8)?;
    if payload.contains(&b'.') {
        Ok(format!("{payload_str}%00.jpg"))
    } else {
        Ok(format!("{payload_str}%00"))
    }
}

/// Overlong UTF-8 encoding (2-byte) — represent ASCII non-alphanumeric as 2-byte sequences.
///
/// **Context**: `iis-6` — only works against specific legacy WAFs/frontends that
/// normalize overlong sequences rather than rejecting them.
pub fn overlong_utf8(payload: impl AsRef<[u8]>) -> Result<String, EncodeError> {
    let text = std::str::from_utf8(payload.as_ref()).map_err(|_| EncodeError::InvalidUtf8)?;
    Ok(text
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_string()
            } else if ch.is_ascii() {
                let byte = ch as u8;
                format!("%{:02X}%{:02X}", 0xC0 | (byte >> 6), 0x80 | (byte & 0x3F))
            } else {
                ch.to_string()
            }
        })
        .collect())
}

/// Extended overlong UTF-8 encoding (3-byte) — broader coverage with 3-byte sequences.
///
/// **Context**: `iis-6` — some WAFs reject 2-byte overlongs but accept 3-byte overlongs.
pub fn overlong_utf8_more(payload: impl AsRef<[u8]>) -> Result<String, EncodeError> {
    let text = std::str::from_utf8(payload.as_ref()).map_err(|_| EncodeError::InvalidUtf8)?;
    Ok(text
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_string()
            } else if ch.is_ascii() {
                let byte = ch as u8;
                format!("%{:02X}%{:02X}%{:02X}", 0xE0, 0x80, 0x80 | byte)
            } else {
                ch.to_string()
            }
        })
        .collect())
}

/// Chunked transfer-encoding split — break payload across HTTP chunks.
///
/// **Context**: `http-request-body` — ONLY valid when sent with
/// `Transfer-Encoding: chunked`.
pub fn chunked_split(
    payload: impl AsRef<[u8]>,
    chunk_size: usize,
) -> Result<ChunkedBody, EncodeError> {
    let payload = payload.as_ref();
    if payload.is_empty() {
        return Ok(ChunkedBody {
            body: Vec::new(),
            required_headers: vec![("Transfer-Encoding".to_string(), "chunked".to_string())],
        });
    }
    let chunk_size = chunk_size.max(1);
    let mut result: Vec<u8> = Vec::with_capacity(payload.len() + 64);

    for chunk in payload.chunks(chunk_size) {
        let _ = write!(&mut result, "{:x}\r\n", chunk.len());
        result.extend_from_slice(chunk);
        result.extend_from_slice(b"\r\n");
    }
    result.extend_from_slice(b"0\r\n\r\n");

    Ok(ChunkedBody {
        body: result,
        required_headers: vec![("Transfer-Encoding".to_string(), "chunked".to_string())],
    })
}

/// HTTP parameter pollution — duplicate parameter with a benign first value.
///
/// Depending on the server framework, the last value wins (PHP, ASP.NET)
/// while many WAFs only inspect the first parameter occurrence.
pub fn parameter_pollute(payload: impl AsRef<[u8]>) -> Result<String, EncodeError> {
    let payload = payload.as_ref();
    let payload_str = std::str::from_utf8(payload).map_err(|_| EncodeError::InvalidUtf8)?;
    if let Some(eq_pos) = payload.iter().position(|byte| *byte == b'=') {
        let key = std::str::from_utf8(&payload[..eq_pos]).map_err(|_| EncodeError::InvalidUtf8)?;
        Ok(format!("{key}=safe&{payload_str}"))
    } else {
        // Deterministic decoy: a plausible 8-letter junk parameter name
        // derived from the payload via FNV-1a. Identical input ⇒
        // identical output — a non-deterministic encoder cannot be
        // regression-pinned and makes a successful bypass impossible to
        // reproduce (the rest of the evasion pipeline, e.g. the equiv
        // generator, is deterministic-seeded for exactly this reason).
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for &b in payload {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        let decoy: String = (0..8)
            .map(|i| (b'a' + (((h >> (i * 8)) as u8) % 26)) as char)
            .collect();
        Ok(format!("{decoy}=1&{payload_str}"))
    }
}

/// Base64 encoding — standard alphabet.
pub fn base64_encode(payload: impl AsRef<[u8]>) -> String {
    general_purpose::STANDARD.encode(payload)
}

/// Base64 URL-safe encoding — `-_` alphabet, no padding.
pub fn base64_url_encode(payload: impl AsRef<[u8]>) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(payload)
}

/// Hex encoding.
pub fn hex_encode(payload: impl AsRef<[u8]>) -> String {
    hex::encode(payload)
}

/// Encode a single Unicode scalar value to UTF-16 BE bytes.
fn char_to_utf16be(c: char) -> Vec<u8> {
    let mut buf = [0u16; 2];
    let enc = c.encode_utf16(&mut buf);
    let mut out = Vec::with_capacity(enc.len() * 2);
    for u in enc {
        out.push((*u >> 8) as u8);
        out.push((*u & 0xFF) as u8);
    }
    out
}

/// Modified Base64 for UTF-7 (RFC 2152) — standard alphabet without padding.
fn modified_base64(bytes: &[u8]) -> String {
    let mut b64 = general_purpose::STANDARD.encode(bytes);
    b64.retain(|c| c != '=');
    b64
}

/// RFC 2152 direct characters.
fn is_utf7_direct(ch: char) -> bool {
    matches!(
        ch,
        'A'..='Z'
            | 'a'..='z'
            | '0'..='9'
            | '\''
            | '('
            | ')'
            | ','
            | '-'
            | '.'
            | '/'
            | ':'
            | '?'
    )
}

/// UTF-7 encoding per RFC 2152.
///
/// **Context**: `iis`, `legacy-dotnet` — only safe where the target actually
/// decodes UTF-7.
pub fn utf7_encode(payload: &str) -> String {
    let mut out = String::new();
    let mut shift_buf: Vec<u8> = Vec::new();

    fn flush_shift(out: &mut String, buf: &mut Vec<u8>) {
        if !buf.is_empty() {
            out.push('+');
            out.push_str(&modified_base64(buf));
            out.push('-');
            buf.clear();
        }
    }

    for ch in payload.chars() {
        if ch == '+' {
            flush_shift(&mut out, &mut shift_buf);
            out.push_str("+-");
        } else if is_utf7_direct(ch) {
            flush_shift(&mut out, &mut shift_buf);
            out.push(ch);
        } else {
            shift_buf.extend_from_slice(&char_to_utf16be(ch));
        }
    }
    flush_shift(&mut out, &mut shift_buf);
    out
}

/// Gzip compression.
///
/// **Context**: `http-request-body` — ONLY valid with `Content-Encoding: gzip`.
pub fn gzip_encode(payload: impl AsRef<[u8]>) -> Result<String, EncodeError> {
    let payload = payload.as_ref();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(payload)
        .map_err(|e| EncodeError::InvalidConfig(format!("gzip failed: {e}")))?;
    let bytes = encoder
        .finish()
        .map_err(|e| EncodeError::InvalidConfig(format!("gzip failed: {e}")))?;
    Ok(general_purpose::STANDARD.encode(bytes))
}

/// Deflate compression.
///
/// **Context**: `http-request-body` — ONLY valid with `Content-Encoding: deflate`.
pub fn deflate_encode(payload: impl AsRef<[u8]>) -> Result<String, EncodeError> {
    let payload = payload.as_ref();
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(payload)
        .map_err(|e| EncodeError::InvalidConfig(format!("deflate failed: {e}")))?;
    let bytes = encoder
        .finish()
        .map_err(|e| EncodeError::InvalidConfig(format!("deflate failed: {e}")))?;
    Ok(general_purpose::STANDARD.encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_byte_with_extension() {
        assert_eq!(null_byte_inject("file.php").unwrap(), "file.php%00.jpg");
    }

    #[test]
    fn null_byte_without_extension() {
        assert_eq!(null_byte_inject("payload").unwrap(), "payload%00");
    }

    #[test]
    fn overlong_utf8_slash() {
        let result = overlong_utf8("/").unwrap();
        assert_eq!(result, "%C0%AF");
    }

    #[test]
    fn overlong_utf8_more_slash() {
        let result = overlong_utf8_more("/").unwrap();
        assert_eq!(result, "%E0%80%AF");
    }

    #[test]
    fn chunked_split_produces_valid_chunks() {
        let result = chunked_split("SELECT * FROM users", 3).unwrap();
        let body = String::from_utf8(result.body.clone()).unwrap();
        assert!(body.contains("\r\n"));
        assert!(body.ends_with("0\r\n\r\n"));
        assert_eq!(
            result.required_headers,
            vec![("Transfer-Encoding".to_string(), "chunked".to_string())]
        );
    }

    #[test]
    fn chunked_split_byte_lengths_correct() {
        let payload = b"abc\x80\x81defgh";
        let result = chunked_split(payload, 3).unwrap();
        // Parse the raw bytes: each chunk is "size\r\ndata\r\n"
        let mut i = 0;
        let mut chunk_count = 0;
        let expected_chunk_sizes = [3_usize, 3, 3, 1];
        while i < result.body.len() {
            // Find the \r\n after the size
            let size_end = result.body[i..]
                .windows(2)
                .position(|w| w == b"\r\n")
                .unwrap_or(result.body.len() - i)
                + i;
            let size_str = std::str::from_utf8(&result.body[i..size_end]).unwrap();
            if size_str == "0" {
                // Terminating chunk
                break;
            }
            let size = usize::from_str_radix(size_str, 16).unwrap();
            assert_eq!(size, expected_chunk_sizes[chunk_count]);
            // Data starts after \r\n and ends after size bytes
            let data_start = size_end + 2;
            let data_end = data_start + size;
            assert_eq!(
                &result.body[data_start..data_end],
                &payload[chunk_count * 3..chunk_count * 3 + size]
            );
            // Skip the trailing \r\n
            i = data_end + 2;
            chunk_count += 1;
        }
        assert_eq!(chunk_count, 4);
    }

    #[test]
    fn chunked_split_empty() {
        let result = chunked_split("", 3).unwrap();
        assert!(result.body.is_empty());
    }

    #[test]
    fn parameter_pollution_with_key_value() {
        let result = parameter_pollute("user=' OR 1=1--").unwrap();
        assert!(result.starts_with("user=safe&"));
        assert!(result.contains("user=' OR 1=1--"));
    }

    #[test]
    fn parameter_pollution_without_equals() {
        let result = parameter_pollute("payload").unwrap();
        assert!(result.ends_with("&payload"));
        assert!(!result.contains("_wafrift_decoy"));
        // The decoy is a deterministic 8-letter lowercase junk param.
        let decoy = result
            .strip_suffix("=1&payload")
            .expect("decoy=1&payload shape");
        assert_eq!(decoy.len(), 8, "decoy must be 8 chars: {result}");
        assert!(
            decoy.bytes().all(|b| b.is_ascii_lowercase()),
            "decoy must be [a-z]{{8}}: {result}"
        );
        // Deterministic: identical payload ⇒ byte-identical output, and
        // a different payload yields a different decoy.
        assert_eq!(result, parameter_pollute("payload").unwrap());
        assert_ne!(result, parameter_pollute("payloae").unwrap());
    }

    #[test]
    fn base64_standard() {
        assert_eq!(base64_encode("hello"), "aGVsbG8=");
    }

    #[test]
    fn base64_url_safe() {
        assert_eq!(base64_url_encode("hello+++"), "aGVsbG8rKys");
    }

    #[test]
    fn hex_encode_basic() {
        assert_eq!(hex_encode("ABC"), "414243");
    }

    #[test]
    fn utf7_rfc2152_basic() {
        // Direct chars pass through
        assert_eq!(utf7_encode("Hello"), "Hello");
        // Plus sign escaped
        assert_eq!(utf7_encode("A+B"), "A+-B");
        // Non-ASCII encoded
        assert!(utf7_encode("日本語").starts_with('+'));
    }

    #[test]
    fn utf7_rfc2152_decodeable() {
        // A+IBNg- is the standard UTF-7 for 日本語
        let encoded = utf7_encode("日本語");
        assert!(encoded.contains('+'));
        assert!(encoded.contains('-'));
    }

    #[test]
    fn gzip_roundtrip() {
        let original = b"SELECT * FROM users";
        let encoded = gzip_encode(original).unwrap();
        assert!(!encoded.is_empty());
        // Verify it's valid base64
        let decoded = general_purpose::STANDARD.decode(&encoded).unwrap();
        let mut decoder = flate2::read::GzDecoder::new(&decoded[..]);
        let mut decompressed = Vec::new();
        std::io::Read::read_to_end(&mut decoder, &mut decompressed).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn deflate_roundtrip() {
        let original = b"SELECT * FROM users";
        let encoded = deflate_encode(original).unwrap();
        assert!(!encoded.is_empty());
        let decoded = general_purpose::STANDARD.decode(&encoded).unwrap();
        let mut decoder = flate2::read::DeflateDecoder::new(&decoded[..]);
        let mut decompressed = Vec::new();
        std::io::Read::read_to_end(&mut decoder, &mut decompressed).unwrap();
        assert_eq!(decompressed, original);
    }
}
