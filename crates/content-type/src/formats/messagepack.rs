//! Minimal MessagePack `fixmap(1) { "payload" => str }` codec used
//! by the bench/scan harness to encode arbitrary payload strings
//! into the content-type seam without pulling rmp-serde.
//!
//! Length encoding follows the MessagePack spec:
//! - `len ≤ 31` → fixstr (1-byte marker)
//! - `len ≤ 255` → str8 (0xD9 + 1-byte len)
//! - `len ≤ 65_535` → str16 (0xDA + 2-byte BE len)
//! - `len ≤ 2³²−1` → str32 (0xDB + 4-byte BE len)
//!
//! Pre-fix the str16 branch was the only fallback, with a silent
//! `(len as u16)` truncation for any payload ≥ 65_536 bytes — the
//! deserializer would then read a wildly wrong byte range. str32
//! coverage closes that hole; payloads above 4 GiB are rejected
//! by emitting an empty vec (also serialised as fixstr(0)) since
//! MessagePack itself has no encoding for them.

pub fn serialize(payload: &str) -> Vec<u8> {
    let mut out = vec![0x81, 0xA7];
    out.extend_from_slice(b"payload");
    let len = payload.len();
    if len <= 31 {
        out.push(0xA0 | (len as u8));
    } else if len <= 255 {
        out.push(0xD9); // str8
        out.push(len as u8);
    } else if len <= 65_535 {
        out.push(0xDA); // str16
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else if let Ok(len32) = u32::try_from(len) {
        // str32 — 0xDB + 4-byte BE length, covers up to ~4 GiB.
        out.push(0xDB);
        out.extend_from_slice(&len32.to_be_bytes());
    } else {
        // MessagePack tops out at 2³²−1 bytes. Inputs above that
        // are pathological for an in-memory codec; encode as a
        // zero-length fixstr instead of silently truncating to a
        // bogus length. Caller sees an empty round-trip and can
        // detect the loss.
        out.push(0xA0);
        return out;
    }
    out.extend_from_slice(payload.as_bytes());
    out
}

pub fn deserialize(bytes: &[u8]) -> String {
    // Parse fixmap(1) { fixstr(7)"payload" => str payload }
    if bytes.len() < 9 {
        return String::new();
    }
    // Skip: 0x81 (fixmap 1), 0xA7 (fixstr 7), "payload" (7 bytes)
    let mut idx = 9;
    if idx >= bytes.len() {
        return String::new();
    }
    let len = match bytes[idx] {
        b if b & 0xE0 == 0xA0 => {
            // fixstr
            idx += 1;
            (b & 0x1F) as usize
        }
        0xD9 => {
            // str8
            if idx + 1 >= bytes.len() {
                return String::new();
            }
            idx += 2;
            bytes[idx - 1] as usize
        }
        0xDA => {
            // str16
            if idx + 2 >= bytes.len() {
                return String::new();
            }
            idx += 3;
            u16::from_be_bytes([bytes[idx - 2], bytes[idx - 1]]) as usize
        }
        0xDB => {
            // str32 — added to round-trip payloads above 65_535
            // bytes that serialize() now encodes here. Without
            // this branch deserialize() would treat the 0xDB
            // marker as "unknown" and return empty.
            if idx + 4 >= bytes.len() {
                return String::new();
            }
            let len_bytes = [
                bytes[idx + 1],
                bytes[idx + 2],
                bytes[idx + 3],
                bytes[idx + 4],
            ];
            idx += 5;
            u32::from_be_bytes(len_bytes) as usize
        }
        _ => return String::new(),
    };
    // Saturating add guards against pathological idx + len wrap on
    // 32-bit platforms when bytes claim a near-usize::MAX length.
    if idx.saturating_add(len) > bytes.len() {
        return String::new();
    }
    String::from_utf8_lossy(&bytes[idx..idx + len]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(payload: &str) -> String {
        deserialize(&serialize(payload))
    }

    #[test]
    fn empty_payload_round_trips() {
        assert_eq!(round_trip(""), "");
    }

    #[test]
    fn short_payload_uses_fixstr() {
        let bytes = serialize("hi");
        // fixmap(1) + "payload" key + fixstr(2) marker + 2 body bytes.
        assert_eq!(bytes[9], 0xA0 | 2);
        assert_eq!(round_trip("hi"), "hi");
    }

    #[test]
    fn fixstr_boundary_31_bytes() {
        let s = "x".repeat(31);
        let bytes = serialize(&s);
        assert_eq!(bytes[9], 0xA0 | 31);
        assert_eq!(round_trip(&s), s);
    }

    #[test]
    fn str8_branch_32_to_255_bytes() {
        let s = "x".repeat(100);
        let bytes = serialize(&s);
        assert_eq!(bytes[9], 0xD9);
        assert_eq!(bytes[10], 100);
        assert_eq!(round_trip(&s), s);
    }

    #[test]
    fn str8_boundary_255_bytes() {
        let s = "x".repeat(255);
        let bytes = serialize(&s);
        assert_eq!(bytes[9], 0xD9);
        assert_eq!(bytes[10], 0xFF);
        assert_eq!(round_trip(&s), s);
    }

    #[test]
    fn str16_branch_256_to_65535_bytes() {
        let s = "x".repeat(1000);
        let bytes = serialize(&s);
        assert_eq!(bytes[9], 0xDA);
        assert_eq!(u16::from_be_bytes([bytes[10], bytes[11]]), 1000);
        assert_eq!(round_trip(&s), s);
    }

    #[test]
    fn str16_boundary_65535_bytes() {
        let s = "x".repeat(65_535);
        let bytes = serialize(&s);
        assert_eq!(bytes[9], 0xDA);
        assert_eq!(u16::from_be_bytes([bytes[10], bytes[11]]), 65_535);
        assert_eq!(round_trip(&s).len(), 65_535);
    }

    #[test]
    fn str32_branch_above_65535_bytes_round_trips() {
        // Regression test for the silent (len as u16) truncation
        // bug. Pre-fix this would serialise a 100_000-byte string
        // as str16 with length (100_000 & 0xFFFF) = 34_464, then
        // deserialize would return only the first 34_464 bytes.
        let s = "x".repeat(100_000);
        let bytes = serialize(&s);
        assert_eq!(bytes[9], 0xDB);
        assert_eq!(
            u32::from_be_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]),
            100_000
        );
        let back = round_trip(&s);
        assert_eq!(back.len(), 100_000);
        assert_eq!(back, s);
    }

    #[test]
    fn deserialize_rejects_truncated_buffer() {
        // Claim a 10-byte body but only ship 5. Expect empty
        // string (not a panic).
        let mut bytes = vec![0x81, 0xA7];
        bytes.extend_from_slice(b"payload");
        bytes.push(0xA0 | 10); // fixstr(10)
        bytes.extend_from_slice(b"short"); // 5 bytes
        assert_eq!(deserialize(&bytes), "");
    }

    #[test]
    fn deserialize_rejects_buffer_too_short_for_header() {
        // Less than 9 bytes — short-circuit.
        assert_eq!(deserialize(b"x"), "");
        assert_eq!(deserialize(b""), "");
    }

    #[test]
    fn deserialize_rejects_unknown_marker() {
        // 0xC0 (nil) where a str marker should be.
        let mut bytes = vec![0x81, 0xA7];
        bytes.extend_from_slice(b"payload");
        bytes.push(0xC0);
        assert_eq!(deserialize(&bytes), "");
    }

    #[test]
    fn deserialize_str16_with_missing_length_bytes_is_empty() {
        let mut bytes = vec![0x81, 0xA7];
        bytes.extend_from_slice(b"payload");
        bytes.push(0xDA);
        // No len bytes — truncated.
        assert_eq!(deserialize(&bytes), "");
    }

    #[test]
    fn deserialize_str32_with_missing_length_bytes_is_empty() {
        let mut bytes = vec![0x81, 0xA7];
        bytes.extend_from_slice(b"payload");
        bytes.push(0xDB);
        // Only one of four len bytes.
        bytes.push(0x00);
        assert_eq!(deserialize(&bytes), "");
    }
}
