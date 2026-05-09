//! Modern format serialization tests — protobuf, messagepack, gRPC-Web.

use wafrift_content_type::formats::{deserialize, serialize};
use wafrift_types::format::BodyFormat;
use wafrift_types::injection_context::InjectionContext;

// ── Protobuf ───────────────────────────────────────────────────────────────

#[test]
fn protobuf_roundtrip_ascii() {
    let payload = "hello world";
    let bytes = serialize(payload, BodyFormat::Protobuf, InjectionContext::PlainBody).unwrap();
    let back = deserialize(&bytes, BodyFormat::Protobuf).unwrap();
    assert_eq!(back, payload);
}

#[test]
fn protobuf_roundtrip_unicode() {
    let payload = "Hello 世界 👋";
    let bytes = serialize(payload, BodyFormat::Protobuf, InjectionContext::PlainBody).unwrap();
    let back = deserialize(&bytes, BodyFormat::Protobuf).unwrap();
    assert_eq!(back, payload);
}

#[test]
fn protobuf_roundtrip_sql_payload() {
    let payload = "' UNION SELECT 1,2,3--";
    let bytes = serialize(payload, BodyFormat::Protobuf, InjectionContext::PlainBody).unwrap();
    let back = deserialize(&bytes, BodyFormat::Protobuf).unwrap();
    assert_eq!(back, payload);
}

#[test]
fn protobuf_structure_tag_and_length() {
    let payload = "hi";
    let bytes = serialize(payload, BodyFormat::Protobuf, InjectionContext::PlainBody).unwrap();
    // Field 1, wire type 2 (length-delimited) => (1 << 3) | 2 = 0x0A
    assert_eq!(bytes[0], 0x0A);
    // Length = 2 => varint 0x02
    assert_eq!(bytes[1], 0x02);
    // Payload
    assert_eq!(&bytes[2..], b"hi");
}

#[test]
fn protobuf_empty_string() {
    let bytes = serialize("", BodyFormat::Protobuf, InjectionContext::PlainBody).unwrap();
    assert_eq!(bytes, vec![0x0A, 0x00]);
    let back = deserialize(&bytes, BodyFormat::Protobuf).unwrap();
    assert_eq!(back, "");
}

// ── MessagePack ────────────────────────────────────────────────────────────

#[test]
fn messagepack_roundtrip_ascii() {
    let payload = "hello world";
    let bytes = serialize(payload, BodyFormat::MessagePack, InjectionContext::PlainBody).unwrap();
    let back = deserialize(&bytes, BodyFormat::MessagePack).unwrap();
    assert_eq!(back, payload);
}

#[test]
fn messagepack_roundtrip_unicode() {
    let payload = "Hello 世界 👋";
    let bytes = serialize(payload, BodyFormat::MessagePack, InjectionContext::PlainBody).unwrap();
    let back = deserialize(&bytes, BodyFormat::MessagePack).unwrap();
    assert_eq!(back, payload);
}

#[test]
fn messagepack_is_binary_not_text() {
    let payload = "hello";
    let bytes = serialize(payload, BodyFormat::MessagePack, InjectionContext::PlainBody).unwrap();
    // MessagePack encoding of a string is not plain text
    assert_ne!(bytes, payload.as_bytes());
}

// ── gRPC-Web ───────────────────────────────────────────────────────────────

#[test]
fn grpc_web_frame_structure() {
    let payload = "test";
    let bytes = serialize(payload, BodyFormat::GrpcWeb, InjectionContext::PlainBody).unwrap();
    // First byte: compression flag (0x00 = no compression)
    assert_eq!(bytes[0], 0x00);
    // Next 4 bytes: length (big-endian u32)
    let length = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
    // Remaining bytes should be the protobuf payload
    assert_eq!(length as usize, bytes.len() - 5);
    let proto_payload = &bytes[5..];
    let back = deserialize(proto_payload, BodyFormat::Protobuf).unwrap();
    assert_eq!(back, payload);
}

#[test]
fn grpc_web_roundtrip() {
    let payload = "grpc payload";
    let bytes = serialize(payload, BodyFormat::GrpcWeb, InjectionContext::PlainBody).unwrap();
    let back = deserialize(&bytes, BodyFormat::GrpcWeb).unwrap();
    assert_eq!(back, payload);
}

// ── Raw ────────────────────────────────────────────────────────────────────

#[test]
fn raw_passes_through() {
    let payload = "hello";
    let bytes = serialize(payload, BodyFormat::Raw, InjectionContext::PlainBody).unwrap();
    assert_eq!(bytes, payload.as_bytes());
    let back = deserialize(&bytes, BodyFormat::Raw).unwrap();
    assert_eq!(back, payload);
}

#[test]
fn raw_binary_data() {
    // Use valid UTF-8 that includes non-ASCII bytes (é = 0xC3 0xA9)
    let payload = b"\x00\xC3\xA9";
    let text = std::str::from_utf8(payload).unwrap();
    let bytes = serialize(text, BodyFormat::Raw, InjectionContext::PlainBody).unwrap();
    assert_eq!(bytes, payload);
}

// ── Unsupported formats ────────────────────────────────────────────────────

#[test]
fn xml_serialize_unsupported() {
    let err = serialize("hello", BodyFormat::Xml, InjectionContext::PlainBody).unwrap_err();
    assert!(err.to_string().contains("Unsupported"));
}

#[test]
fn multipart_serialize_unsupported() {
    let err = serialize("hello", BodyFormat::Multipart, InjectionContext::PlainBody).unwrap_err();
    assert!(err.to_string().contains("Unsupported"));
}

#[test]
fn json_serialize_unsupported() {
    let err = serialize("hello", BodyFormat::Json, InjectionContext::PlainBody).unwrap_err();
    assert!(err.to_string().contains("Unsupported"));
}

// ── Cross-format consistency ───────────────────────────────────────────────

#[test]
fn same_payload_different_formats() {
    let payload = "attack payload";
    let proto = serialize(payload, BodyFormat::Protobuf, InjectionContext::PlainBody).unwrap();
    let mp = serialize(payload, BodyFormat::MessagePack, InjectionContext::PlainBody).unwrap();
    let raw = serialize(payload, BodyFormat::Raw, InjectionContext::PlainBody).unwrap();

    // All should produce different byte representations
    assert_ne!(proto, mp);
    assert_ne!(proto, raw);
    assert_ne!(mp, raw);
}
