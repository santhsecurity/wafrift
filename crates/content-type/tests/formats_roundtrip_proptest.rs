//! Property tests for the binary body-format codecs (protobuf / messagepack /
//! grpc-web): `deserialize(serialize(s)) == s` for ALL strings `s`.
//!
//! WHY THIS IS A PROPERTY, NOT A FEW EXAMPLES (§ STANDARD.md testing bar):
//! these codecs are how wafrift smuggles an injection payload past a WAF that
//! inspects raw bytes while the origin decodes the body. If the round-trip
//! drops, truncates, or mangles even one byte, the WAF sees inert bytes but the
//! ORIGIN reconstructs the WRONG payload — the exploit silently mis-fires. The
//! per-codec unit tests only exercise a handful of hand-picked literals, none of
//! which straddle a length-class boundary:
//!   - messagepack switches encoding at 31 / 255 / 65535 (fixstr / str8 / str16
//!     / str32), each with its own length-byte width and `idx += N` decoder
//!     accounting — exactly where an off-by-one lives. The file's own header
//!     records a prior `(len as u16)` silent-truncation bug here.
//!   - protobuf length-prefixes with a varint that rolls over at 128 / 16384 /…
//!   - grpc-web frames with a big-endian u32 length.
//! A length-domain property is the only thing that drives every branch boundary.
//! These properties would have caught the prior truncation bug and guard the
//! `checked_add` overflow guards added to protobuf/grpc-web (a regressed guard
//! that wrapped to a tiny length would corrupt the body and fail round-trip).

use proptest::prelude::*;
use wafrift_content_type::formats::{grpc_web, messagepack, protobuf};

proptest! {
    #![proptest_config(ProptestConfig { cases: 1024, ..ProptestConfig::default() })]

    /// protobuf: round-trips any UTF-8 string. `s: String` is always valid
    /// UTF-8 so the decoder's lossy conversion is a no-op — equality is exact.
    #[test]
    fn protobuf_round_trips_any_string(s in ".*") {
        prop_assert_eq!(protobuf::deserialize(&protobuf::serialize(&s)), s);
    }

    /// messagepack: round-trips any UTF-8 string across every length class.
    #[test]
    fn messagepack_round_trips_any_string(s in ".*") {
        prop_assert_eq!(messagepack::deserialize(&messagepack::serialize(&s)), s);
    }

    /// grpc-web: round-trips any UTF-8 string (wraps protobuf in a frame).
    #[test]
    fn grpc_web_round_trips_any_string(s in ".*") {
        prop_assert_eq!(grpc_web::deserialize(&grpc_web::serialize(&s)), s);
    }
}

/// Deterministic boundary sweep: lengths that straddle every length-class
/// switch in the three codecs. messagepack is the strictest (fixstr→str8 at
/// 31/32, str8→str16 at 255/256, str16→str32 at 65535/65536); protobuf's
/// varint rolls 1→2 bytes at 127/128 and 2→3 at 16383/16384. A single ASCII
/// byte ('a') keeps byte-length == char-length so the boundary index is exact.
#[test]
fn all_codecs_round_trip_across_every_length_class_boundary() {
    let boundary_lengths = [
        0usize, 1, 31, 32, 33, // fixstr → str8
        126, 127, 128, 129, // protobuf varint 1→2
        254, 255, 256, 257, // str8 → str16
        16_383, 16_384, // protobuf varint 2→3
        65_534, 65_535, 65_536, 65_537, // str16 → str32
    ];
    for &len in &boundary_lengths {
        let payload = "a".repeat(len);

        let pb = protobuf::deserialize(&protobuf::serialize(&payload));
        assert_eq!(pb, payload, "protobuf round-trip failed at length {len}");

        let mp = messagepack::deserialize(&messagepack::serialize(&payload));
        assert_eq!(mp, payload, "messagepack round-trip failed at length {len}");

        let gw = grpc_web::deserialize(&grpc_web::serialize(&payload));
        assert_eq!(gw, payload, "grpc-web round-trip failed at length {len}");
    }
}

/// Multibyte UTF-8 must survive: the byte-length / char-length divergence is
/// where a length-class boundary computed in the wrong unit would corrupt the
/// body. Use a glyph that is 3 bytes in UTF-8 so byte-length ≠ char-count.
#[test]
fn all_codecs_round_trip_multibyte_across_boundaries() {
    // '✓' (U+2713) is 3 bytes; repeat to push the BYTE length across the
    // str8/str16 boundaries even though the char count is far smaller.
    for char_count in [11usize, 85, 86, 21_845] {
        let payload = "✓".repeat(char_count);
        assert!(
            payload.len() >= char_count,
            "sanity: multibyte expands bytes"
        );

        assert_eq!(
            protobuf::deserialize(&protobuf::serialize(&payload)),
            payload,
            "protobuf multibyte round-trip failed at {char_count} chars / {} bytes",
            payload.len()
        );
        assert_eq!(
            messagepack::deserialize(&messagepack::serialize(&payload)),
            payload,
            "messagepack multibyte round-trip failed at {char_count} chars / {} bytes",
            payload.len()
        );
        assert_eq!(
            grpc_web::deserialize(&grpc_web::serialize(&payload)),
            payload,
            "grpc-web multibyte round-trip failed at {char_count} chars / {} bytes",
            payload.len()
        );
    }
}
