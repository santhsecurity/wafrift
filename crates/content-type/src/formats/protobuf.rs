//! Minimal protobuf wire-format encoder for injection payloads.
//!
//! Wraps the payload as a single `bytes` field (field number 1, wire
//! type 2) and length-prefixes it with a real protobuf varint — not a
//! single u8 (the previous implementation silently truncated payloads
//! larger than 255 bytes, which is the hot SQL/XSS injection size range).

pub enum WireType {
    Varint = 0,
    I64 = 1,
    Len = 2,
    I32 = 5,
}

/// Serialise `payload` as a protobuf message: `field 1: bytes payload`.
///
/// Length prefix uses real varint encoding (1 byte per 7 bits of
/// length), so payloads of any size encode correctly.
pub fn serialize(payload: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 6);
    out.push(0x0A); // field 1 (tag << 3) | wire type 2 (Len)
    write_varint(&mut out, payload.len() as u64);
    out.extend_from_slice(payload.as_bytes());
    out
}

/// Deserialise a single-field protobuf message back to its string body.
/// Returns an empty string if the wire prefix is wrong or the buffer
/// is short. Lossy UTF-8 on the body — invalid bytes become U+FFFD.
pub fn deserialize(bytes: &[u8]) -> String {
    if bytes.is_empty() || bytes[0] != 0x0A {
        return String::new();
    }
    let Some((len, n_used)) = read_varint(&bytes[1..]) else {
        return String::new();
    };
    let start = 1 + n_used;
    let end = start + len as usize;
    if end > bytes.len() {
        return String::new();
    }
    String::from_utf8_lossy(&bytes[start..end]).into_owned()
}

fn write_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// Returns (value, bytes_consumed).
fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    for (i, &b) in buf.iter().enumerate().take(10) {
        result |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_small() {
        let s = serialize("' OR 1=1--");
        assert_eq!(deserialize(&s), "' OR 1=1--");
    }

    #[test]
    fn roundtrip_empty() {
        let s = serialize("");
        assert_eq!(deserialize(&s), "");
    }

    #[test]
    fn roundtrip_large_no_truncation() {
        // 256 chars: previous impl truncated to length byte 0 (256 % 256).
        // Real varint encoding handles arbitrary lengths.
        let payload = "x".repeat(2048);
        let s = serialize(&payload);
        assert_eq!(deserialize(&s), payload);
    }

    #[test]
    fn varint_round_trip_boundary_values() {
        for v in [0u64, 1, 127, 128, 16383, 16384, 0xffff_ffff] {
            let mut buf = Vec::new();
            write_varint(&mut buf, v);
            let (decoded, _used) = read_varint(&buf).unwrap();
            assert_eq!(decoded, v, "varint round-trip failed for {v}");
        }
    }

    #[test]
    fn deserialize_empty_input_safe() {
        assert_eq!(deserialize(&[]), "");
    }

    #[test]
    fn deserialize_wrong_wire_tag_returns_empty() {
        // Tag 0x12 (field 2, wire type 2) — wrong field number.
        let bytes = [0x12, 0x01, b'x'];
        assert_eq!(deserialize(&bytes), "");
    }

    #[test]
    fn deserialize_truncated_buffer_safe() {
        // Tag + claims-len-100 + 3 actual bytes — must not panic.
        let bytes = [0x0A, 100, b'a', b'b', b'c'];
        assert_eq!(deserialize(&bytes), "");
    }
}
