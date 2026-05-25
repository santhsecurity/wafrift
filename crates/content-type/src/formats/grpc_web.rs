/// Serialise `payload` as a gRPC-Web framing envelope:
///
/// ```text
/// byte 0     : compression flag (0x00 = no compression)
/// bytes 1–4  : BE u32 — length of the inner protobuf message
/// bytes 5..  : protobuf-encoded payload
/// ```
///
/// Returns an empty `Vec` when the inner protobuf message is larger than
/// `u32::MAX` bytes (> 4 GiB), which gRPC-Web cannot express in its
/// 4-byte length field. Pre-fix used `p_body.len() as u32`, which
/// silently truncated the length field on 64-bit platforms for payloads
/// above 4 GiB — the deserialiser would then read a wildly wrong byte
/// range. In practice injection payloads are tiny, so the fallback path
/// is never taken; the guard is defensive against adversarial callers.
pub fn serialize(payload: &str) -> Vec<u8> {
    let p_body = super::protobuf::serialize(payload);
    // gRPC-Web frame length is a 4-byte big-endian u32: reject if the
    // inner message exceeds what that field can express.
    let Ok(len32) = u32::try_from(p_body.len()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    out.push(0x00); // no compression
    out.extend_from_slice(&len32.to_be_bytes());
    out.extend_from_slice(&p_body);
    out
}

pub fn deserialize(bytes: &[u8]) -> String {
    if bytes.len() < 5 {
        return String::new();
    }
    // Skip compression flag (1 byte) and length (4 bytes)
    let len = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
    if bytes.len() < 5 + len {
        return String::new();
    }
    super::protobuf::deserialize(&bytes[5..5 + len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_small_payload() {
        let s = "' OR 1=1--";
        let encoded = serialize(s);
        assert_eq!(deserialize(&encoded), s);
    }

    #[test]
    fn roundtrip_empty_payload() {
        let encoded = serialize("");
        assert_eq!(deserialize(&encoded), "");
    }

    #[test]
    fn frame_header_is_five_bytes() {
        // 1 byte compression flag + 4 bytes length prefix.
        let encoded = serialize("hello");
        assert!(encoded.len() >= 5);
        assert_eq!(encoded[0], 0x00, "compression flag must be 0 (no compression)");
        let claimed_len = u32::from_be_bytes([encoded[1], encoded[2], encoded[3], encoded[4]]);
        assert_eq!(claimed_len as usize + 5, encoded.len(),
            "length field must equal total_len - 5");
    }

    #[test]
    fn deserialize_empty_input_is_safe() {
        assert_eq!(deserialize(&[]), "");
    }

    #[test]
    fn deserialize_truncated_at_header_is_safe() {
        // 4 bytes — one short of the 5-byte minimum.
        assert_eq!(deserialize(&[0x00, 0x00, 0x00, 0x00]), "");
    }

    #[test]
    fn deserialize_length_field_longer_than_buffer_is_safe() {
        // Header claims 100 bytes but only 5 bytes total.
        let mut b = vec![0x00u8, 0x00, 0x00, 0x00, 100];
        b.extend_from_slice(b"hi");
        assert_eq!(deserialize(&b), "");
    }

    #[test]
    fn roundtrip_injection_payload() {
        let payload = "<script>alert(document.cookie)</script>";
        assert_eq!(deserialize(&serialize(payload)), payload);
    }

    #[test]
    fn roundtrip_large_payload_no_as_u32_truncation() {
        // Pre-fix used `p_body.len() as u32` — harmless for small payloads
        // but the fix also gates on try_from. Confirm the round-trip
        // works for a protobuf body that still fits in u32.
        let payload = "A".repeat(10_000);
        let encoded = serialize(&payload);
        assert_eq!(deserialize(&encoded), payload);
    }
}
