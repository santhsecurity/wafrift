//! Property-based + adversarial coverage for `wafrift_grpc_evasion`.
//!
//! The encoder/decoder pair must hold three invariants under any input
//! the hunt loop or fuzzer might pass:
//!
//! 1. **Round-trip preservation.** Every `embed_attack_in_message`,
//!    `embed_attack_in_nested`, and `split_attack_across_fields`
//!    output must decode back to the original payload bytes (after
//!    concatenating the split fragments). A regression here would
//!    silently drop bytes from the attack payload.
//! 2. **No panics on any input.** Hunt loops feed arbitrary UTF-8
//!    strings of arbitrary length. A panic in the encoder stops the
//!    entire bench round.
//! 3. **Decoder robustness.** `decode_grpc_frame` and
//!    `decode_varint` must return typed errors / `None`, never
//!    panic, on malformed input. This is the WAF inspection surface
//!    a hostile origin could exploit.

use proptest::prelude::*;
use wafrift_grpc_evasion::{
    GrpcFrameError, decode_grpc_frame, decode_string_fields, decode_varint,
    embed_attack_in_message, embed_attack_in_nested, split_attack_across_fields,
    wrap_in_grpc_frame,
};

// ── 1. Round-trip preservation ──────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, .. ProptestConfig::default() })]

    /// embed → decode → original.
    #[test]
    fn embed_message_round_trips(payload in ".*") {
        let frame = embed_attack_in_message(&payload);
        let (compression, _, proto_body) =
            decode_grpc_frame(&frame).expect("frame must decode");
        prop_assert_eq!(compression, 0u8);
        let fields = decode_string_fields(proto_body).expect("fields decode");
        prop_assert_eq!(fields.len(), 1);
        prop_assert_eq!(fields[0].0, 1u32);
        prop_assert_eq!(&fields[0].1, payload.as_bytes());
    }

    /// embed_nested(depth, payload) for any depth 0..=20 round-trips
    /// the payload after unwrapping `depth` levels of submessage.
    #[test]
    fn nested_round_trips(payload in "[a-zA-Z0-9 _',./\\\\<>(){}=*-]{0,80}", depth in 0u8..=20) {
        let frame = embed_attack_in_nested(&payload, depth);
        let (_, _, body) = decode_grpc_frame(&frame).expect("decode frame");
        // Own each level's bytes so the slice stays live across iterations.
        // Pre-fix this used `transmute::<&[u8], &[u8]>` to extend the
        // borrow lifetime of a `tmp` Vec that was overwritten on the
        // next iteration — undefined behaviour that the transmute
        // hid from the borrow checker.
        let mut current: Vec<u8> = body.to_vec();
        for _ in 0..depth {
            let fields = decode_string_fields(&current).expect("nested fields");
            prop_assert_eq!(fields.len(), 1);
            prop_assert_eq!(fields[0].0, 1u32);
            let next = fields[0].1.clone();
            let inner = decode_string_fields(&next).expect("inner decode");
            if inner.is_empty() {
                // Innermost level — verify the payload matches.
                prop_assert_eq!(String::from_utf8(next).unwrap_or_default(), payload.clone());
                return Ok(());
            }
            current = next;
        }
        // After unwrapping `depth` levels, we should be at the payload string.
        let final_fields = decode_string_fields(&current).expect("final fields");
        prop_assert_eq!(final_fields.len(), 1);
        prop_assert_eq!(&final_fields[0].1, payload.as_bytes());
    }

    /// split → decode → concatenated fragments equal original.
    /// Restricted to non-empty payloads because n_fields=0 + empty
    /// payload is a meaningless degenerate (no fields to put bytes in).
    #[test]
    fn split_concatenation_round_trips(
        payload in "[a-zA-Z0-9_]{1,200}",
        n_fields in 1u8..=10u8
    ) {
        let frame = split_attack_across_fields(&payload, n_fields);
        let (_, _, body) = decode_grpc_frame(&frame).expect("frame decode");
        let fields = decode_string_fields(body).expect("fields decode");
        let concat: Vec<u8> = fields
            .iter()
            .flat_map(|(_, b)| b.iter().copied())
            .collect();
        prop_assert_eq!(concat, payload.as_bytes().to_vec());
    }
}

// ── 2. No-panic invariants on encoder ───────────────────────

proptest! {
    #[test]
    fn embed_message_never_panics(payload in ".*") {
        let _ = embed_attack_in_message(&payload);
    }

    #[test]
    fn embed_nested_never_panics_for_any_depth(payload in ".*", depth in 0u8..=u8::MAX) {
        let _ = embed_attack_in_nested(&payload, depth);
    }

    #[test]
    fn split_never_panics_for_any_n_fields(payload in ".*", n in 0u8..=u8::MAX) {
        let _ = split_attack_across_fields(&payload, n);
    }

    #[test]
    fn wrap_grpc_frame_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..2000)) {
        let _ = wrap_in_grpc_frame(&bytes);
    }
}

// ── 3. Decoder robustness on adversarial input ──────────────

proptest! {
    /// Arbitrary byte slices must NEVER panic the decoder. Either it
    /// returns a typed error or it returns a valid (compression,len,body)
    /// tuple — but it must always return.
    #[test]
    fn decode_grpc_frame_total_function(bytes in proptest::collection::vec(any::<u8>(), 0..200)) {
        let _ = decode_grpc_frame(&bytes);
    }

    #[test]
    fn decode_varint_total_function(bytes in proptest::collection::vec(any::<u8>(), 0..32)) {
        let _ = decode_varint(&bytes, 0);
    }

    #[test]
    fn decode_string_fields_total_function(bytes in proptest::collection::vec(any::<u8>(), 0..500)) {
        let _ = decode_string_fields(&bytes);
    }
}

// ── 4. Specific decoder edge cases ──────────────────────────

#[test]
fn decode_grpc_frame_exactly_5_bytes_with_zero_body() {
    let frame = [0u8, 0, 0, 0, 0];
    let (comp, len, body) = decode_grpc_frame(&frame).unwrap();
    assert_eq!(comp, 0);
    assert_eq!(len, 0);
    assert!(body.is_empty());
}

#[test]
fn decode_grpc_frame_with_4_bytes_too_short() {
    let result = decode_grpc_frame(&[0u8, 0, 0, 0]);
    assert!(matches!(
        result,
        Err(GrpcFrameError::FrameTooShort { got: 4, need: 5 })
    ));
}

#[test]
fn decode_grpc_frame_with_zero_bytes_too_short() {
    let result = decode_grpc_frame(&[]);
    assert!(matches!(
        result,
        Err(GrpcFrameError::FrameTooShort { got: 0, need: 5 })
    ));
}

#[test]
fn decode_grpc_frame_max_u32_declared_len() {
    // Frame declares u32::MAX bytes but only ships 0 — must be a
    // length mismatch error, not an integer overflow / panic.
    let mut frame = vec![0u8];
    frame.extend_from_slice(&u32::MAX.to_be_bytes());
    let result = decode_grpc_frame(&frame);
    assert!(matches!(
        result,
        Err(GrpcFrameError::LengthMismatch { declared: u32::MAX, .. })
    ));
}

#[test]
fn decode_varint_truncated_continuation() {
    // 0x80 0x80 — continuation bit set, no terminator → None, no panic.
    let result = decode_varint(&[0x80, 0x80], 0);
    assert_eq!(result, None);
}

#[test]
fn decode_varint_pure_zero() {
    let result = decode_varint(&[0x00], 0);
    assert_eq!(result, Some((0u64, 1)));
}

#[test]
fn decode_varint_max_continuation_chain() {
    // 10 bytes of 0x80 (continuation) then 0x01 = u64::MAX-ish encoding.
    // Spec says 10 bytes max — verify we don't loop forever.
    let payload: Vec<u8> = (0..15).map(|_| 0x80).chain(std::iter::once(0x01)).collect();
    let result = decode_varint(&payload, 0);
    // Either decodes (10-byte varint valid) or returns None (overflow).
    // What matters is it terminates. No panic.
    let _ = result;
}

#[test]
fn decode_string_fields_skips_unknown_varint_wire_type() {
    // Field 1 varint (wire 0) = 0x08, then value varint 0x05.
    // Field 2 string (wire 2) = 0x12, len 3, "abc".
    let buf = vec![0x08, 0x05, 0x12, 0x03, b'a', b'b', b'c'];
    let fields = decode_string_fields(&buf).expect("decode");
    assert_eq!(fields.len(), 1, "varint field must be skipped");
    assert_eq!(fields[0].0, 2);
    assert_eq!(fields[0].1, b"abc");
}

#[test]
fn decode_string_fields_rejects_truncated_length_delim() {
    // Field 1 string (wire 2) = 0x0A, declared len 100, but only 2 bytes follow.
    let buf = vec![0x0A, 100u8, b'a', b'b'];
    assert!(decode_string_fields(&buf).is_none());
}

#[test]
fn decode_string_fields_rejects_unrecognized_wire_type() {
    // Wire type 3 = group start (deprecated) — should be None.
    let buf = vec![0x0B]; // field 1, wire 3
    assert!(decode_string_fields(&buf).is_none());
}

// ── 5. Encoder semantic invariants ──────────────────────────

#[test]
fn wrap_in_grpc_frame_always_5_byte_header() {
    for size in [0, 1, 100, 1024, 10_000, 100_000] {
        let payload = vec![0u8; size];
        let frame = wrap_in_grpc_frame(&payload);
        assert_eq!(frame.len(), 5 + size);
        assert_eq!(frame[0], 0); // compression flag
        let declared = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]);
        assert_eq!(declared as usize, size);
    }
}

#[test]
fn embed_attack_in_nested_depth_grows_frame_size() {
    let payload = "x";
    let mut prev_size = 0;
    for depth in 0..10 {
        let frame = embed_attack_in_nested(payload, depth);
        if depth > 0 {
            assert!(
                frame.len() > prev_size,
                "depth {depth} ({} bytes) should be larger than {prev_size}",
                frame.len()
            );
        }
        prev_size = frame.len();
    }
}

#[test]
fn split_with_n_fields_produces_exactly_n_fields() {
    let payload = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    for n in [2u8, 3, 5, 10, 25] {
        let frame = split_attack_across_fields(payload, n);
        let (_, _, body) = decode_grpc_frame(&frame).unwrap();
        let fields = decode_string_fields(body).unwrap();
        assert_eq!(
            fields.len(),
            n as usize,
            "n={n}: expected {n} fields, got {}",
            fields.len()
        );
    }
}

#[test]
fn split_emits_sequential_field_numbers() {
    let payload = "abcdef";
    let frame = split_attack_across_fields(payload, 3);
    let (_, _, body) = decode_grpc_frame(&frame).unwrap();
    let fields = decode_string_fields(body).unwrap();
    let nums: Vec<u32> = fields.iter().map(|(n, _)| *n).collect();
    assert_eq!(nums, vec![1, 2, 3]);
}

// ── 6. UTF-8 preservation in split ──────────────────────────

#[test]
fn split_emoji_payload_preserves_utf8() {
    // 4-byte emoji codepoints — char-boundary snap must keep them whole.
    let payload = "💀🦀🔥🌊🎯";
    for n in [1u8, 2, 3, 5] {
        let frame = split_attack_across_fields(payload, n);
        let (_, _, body) = decode_grpc_frame(&frame).unwrap();
        let fields = decode_string_fields(body).unwrap();
        // Each field's bytes MUST be valid UTF-8 (so the snap worked).
        for (_, bytes) in &fields {
            assert!(
                std::str::from_utf8(bytes).is_ok(),
                "split produced invalid UTF-8 chunk: {:?}",
                bytes
            );
        }
    }
}

#[test]
fn split_mixed_ascii_and_emoji_preserves_payload() {
    let payload = "abc💀def🦀ghi";
    let frame = split_attack_across_fields(payload, 4);
    let (_, _, body) = decode_grpc_frame(&frame).unwrap();
    let fields = decode_string_fields(body).unwrap();
    let concat: String = fields
        .iter()
        .map(|(_, b)| std::str::from_utf8(b).unwrap())
        .collect();
    assert_eq!(concat, payload);
}

// ── 7. Empty / degenerate inputs ────────────────────────────

#[test]
fn embed_empty_string_produces_valid_frame() {
    let frame = embed_attack_in_message("");
    let (comp, _, body) = decode_grpc_frame(&frame).unwrap();
    assert_eq!(comp, 0);
    let fields = decode_string_fields(body).unwrap();
    assert_eq!(fields.len(), 1);
    assert!(fields[0].1.is_empty());
}

#[test]
fn nested_empty_payload_max_depth_no_panic() {
    let _ = embed_attack_in_nested("", u8::MAX);
}

#[test]
fn split_one_byte_payload_into_max_fields() {
    // Edge: 1 byte across 255 fields — must not panic, must produce
    // exactly 255 fields (most empty).
    let frame = split_attack_across_fields("x", 255);
    let (_, _, body) = decode_grpc_frame(&frame).unwrap();
    let fields = decode_string_fields(body).unwrap();
    assert_eq!(fields.len(), 255);
    // Exactly one field has the byte (the last, by our distribution).
    let total: usize = fields.iter().map(|(_, b)| b.len()).sum();
    assert_eq!(total, 1);
}
