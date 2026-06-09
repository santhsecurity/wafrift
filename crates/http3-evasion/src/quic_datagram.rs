//! QUIC unreliable datagram (RFC 9221) smuggling primitives.
//!
//! RFC 9221 — "An Unreliable Datagram Extension to QUIC" — adds two
//! new QUIC frame types (0x30 = DATAGRAM-without-length, 0x31 =
//! DATAGRAM-with-length) that carry application bytes **outside any
//! HTTP/3 stream**. Unlike STREAM frames (which carry the HTTP/3
//! data plane) DATAGRAMs are not associated with a request or
//! response — they are pure transport-layer mailboxes.
//!
//! That decoupling is the bypass surface. Real-world deployments
//! that rely on DATAGRAM frames:
//!
//! - **WebTransport over HTTP/3** (RFC 9484) — datagrams are a
//!   first-class low-latency channel between client and server,
//!   keyed to a session via `Quarter-Stream-ID`.
//! - **CONNECT-UDP** (RFC 9298) — UDP packets tunnel through HTTP/3
//!   as DATAGRAM frames (the in-stream capsule variant is the
//!   fallback when the path doesn't support datagrams).
//! - **MASQUE proxying** (CONNECT-IP, RFC 9484-bis) — IP-layer
//!   tunneling rides on datagrams when available.
//!
//! WAFs that inspect HTTP/3 at the HTTP semantic layer parse STREAM
//! frame contents (HEADERS, DATA) and ignore DATAGRAM frames. An
//! attacker can deliver payload bytes through a DATAGRAM that the
//! origin (CONNECT-UDP / WebTransport session terminator) reads as
//! application data while the WAF sees only an opaque transport
//! frame.
//!
//! ## Wire format
//!
//! ```text
//! DATAGRAM frame (RFC 9221 §4) — no length, frame fills the QUIC packet:
//!   Type (i = 0x30)
//!   Datagram Data (..)
//!
//! DATAGRAM frame with length:
//!   Type (i = 0x31)
//!   Length (i)
//!   Datagram Data (..Length)
//! ```
//!
//! Both forms ride alongside STREAM frames in the QUIC payload.
//!
//! ## Quarter-Stream-ID smuggling (WebTransport)
//!
//! WebTransport over HTTP/3 (RFC 9484 §6.2) prefixes each DATAGRAM
//! payload with a Quarter-Stream-ID varint that names which
//! WebTransport session the datagram belongs to. The mapping from
//! Quarter-Stream-ID `q` to actual stream ID is `q * 4`. A WAF that
//! tracks session attribution by Quarter-Stream-ID can be confused
//! by sending datagrams with a Quarter-Stream-ID that doesn't match
//! any open session, or matches a session the WAF thought closed.
//!
//! ## Safety
//!
//! Probe values are capped at [`MAX_DATAGRAM_PAYLOAD_BYTES`]. RFC 9000
//! §7.4 allows a max QUIC datagram of `1452 - overhead` bytes on a
//! typical Ethernet path; we cap below that so the frame stays
//! inside a single QUIC packet (no fragmentation issues to chase).

use crate::EvasionFrame;
use crate::EvasionFrameSet;
use crate::EvasionTechnique;
use crate::quic_cid::quic_varint;
use wafrift_types::canary::Canary;
use wafrift_types::probe::{SmuggleArtifact, SmuggleProbe};

/// Maximum datagram payload we'll emit. Picked to stay below the
/// typical Ethernet QUIC datagram ceiling (~1200 bytes after QUIC
/// overhead on the standard 1500-byte path MTU) so the frame is
/// guaranteed to ride inside a single QUIC packet without
/// fragmentation. WebTransport datagrams are usually well below this
/// for low-latency channels; the cap protects authorized targets
/// from accidental amplification.
pub const MAX_DATAGRAM_PAYLOAD_BYTES: usize = 1100;

/// QUIC frame type for DATAGRAM without explicit length (RFC 9221).
/// Frame extends to the end of the QUIC packet.
pub const DATAGRAM_TYPE_NO_LENGTH: u64 = 0x30;
/// QUIC frame type for DATAGRAM with explicit Length varint (RFC 9221).
/// Used when more frames follow in the same QUIC packet.
pub const DATAGRAM_TYPE_WITH_LENGTH: u64 = 0x31;

/// A QUIC DATAGRAM frame on the wire.
#[derive(Debug, Clone)]
pub struct QuicDatagramFrame {
    /// Frame type — either [`DATAGRAM_TYPE_NO_LENGTH`] or
    /// [`DATAGRAM_TYPE_WITH_LENGTH`].
    pub frame_type: u64,
    /// Payload bytes. Truncated to [`MAX_DATAGRAM_PAYLOAD_BYTES`] by
    /// the constructor.
    pub payload: Vec<u8>,
}

impl QuicDatagramFrame {
    /// New length-prefixed DATAGRAM (frame type 0x31). Use when the
    /// frame is followed by more QUIC frames in the same packet.
    #[must_use]
    pub fn with_length(payload: Vec<u8>) -> Self {
        let mut p = payload;
        if p.len() > MAX_DATAGRAM_PAYLOAD_BYTES {
            p.truncate(MAX_DATAGRAM_PAYLOAD_BYTES);
        }
        Self {
            frame_type: DATAGRAM_TYPE_WITH_LENGTH,
            payload: p,
        }
    }

    /// New no-length DATAGRAM (frame type 0x30). Frame consumes
    /// the rest of the QUIC packet. Use only when this is the
    /// last frame in the packet.
    #[must_use]
    pub fn no_length(payload: Vec<u8>) -> Self {
        let mut p = payload;
        if p.len() > MAX_DATAGRAM_PAYLOAD_BYTES {
            p.truncate(MAX_DATAGRAM_PAYLOAD_BYTES);
        }
        Self {
            frame_type: DATAGRAM_TYPE_NO_LENGTH,
            payload: p,
        }
    }

    /// Serialize to wire bytes per RFC 9221 §4.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.payload.len() + 16);
        out.extend_from_slice(&quic_varint(self.frame_type));
        if self.frame_type == DATAGRAM_TYPE_WITH_LENGTH {
            out.extend_from_slice(&quic_varint(self.payload.len() as u64));
        }
        out.extend_from_slice(&self.payload);
        out
    }
}

/// QUIC-datagram smuggle variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuicDatagramVariant {
    /// Payload rides in a single length-prefixed DATAGRAM. WAFs that
    /// only inspect STREAM frame contents miss the payload entirely.
    StreamlessPayload,
    /// Send the same payload as both 0x30 (no length) and 0x31 (with
    /// length) in different connections. Some receivers reject the
    /// no-length form mid-packet; others accept both. Fingerprint
    /// probe.
    TypeConfusion,
    /// WebTransport DATAGRAM with a Quarter-Stream-ID prefix that
    /// names a session ID outside any active range (well past
    /// `max_streams`). Some WAFs/origins reject; some forward.
    UnregisteredQuarterStream,
    /// Datagram payload sized exactly at the receiver's quote (1200
    /// bytes) — a one-past-the-boundary probe that exercises any
    /// hardcoded "max datagram size" assumption.
    AtBoundarySize,
}

/// A QUIC-datagram smuggle attack: one or more datagrams packed for
/// one logical bypass attempt.
#[derive(Debug, Clone)]
pub struct QuicDatagramAttack {
    /// Which smuggle shape this attack implements.
    pub variant: QuicDatagramVariant,
    /// Datagrams to send in order.
    pub datagrams: Vec<QuicDatagramFrame>,
    /// Telemetry description.
    pub description: String,
    /// Per-attack correlation token.
    pub canary: Canary,
}

impl QuicDatagramAttack {
    /// Payload bytes ride in a single length-prefixed DATAGRAM
    /// frame, decoupled from any HTTP/3 stream. WAFs inspecting at
    /// the HTTP semantic layer don't see the bytes.
    #[must_use]
    pub fn streamless_payload(payload: Vec<u8>) -> Self {
        let frame = QuicDatagramFrame::with_length(payload);
        Self {
            variant: QuicDatagramVariant::StreamlessPayload,
            datagrams: vec![frame],
            description: "DATAGRAM frame outside any HTTP/3 stream — WAF sees no HTTP semantic"
                .into(),
            canary: Canary::generate(),
        }
    }

    /// Send the same payload as both length-less (0x30) and
    /// length-prefixed (0x31) DATAGRAM frames in one packet. Some
    /// QUIC stacks reject the 0x30 form when followed by more
    /// frames; the test surfaces which side enforces the placement
    /// constraint.
    #[must_use]
    pub fn type_confusion(payload: Vec<u8>) -> Self {
        let with_len = QuicDatagramFrame::with_length(payload.clone());
        let no_len = QuicDatagramFrame::no_length(payload);
        Self {
            variant: QuicDatagramVariant::TypeConfusion,
            datagrams: vec![with_len, no_len],
            description:
                "DATAGRAM type confusion — 0x31 (with length) followed by 0x30 (no length, must be last)"
                    .into(),
            canary: Canary::generate(),
        }
    }

    /// WebTransport DATAGRAM with a Quarter-Stream-ID outside any
    /// open session range. `quarter_stream_id` is the WebTransport
    /// session identifier per RFC 9484 §6.2 — typically derived
    /// from the WT_STREAM-opening session's stream ID divided by 4.
    /// Pick a value above the connection's max_streams to make the
    /// frame "phantom."
    #[must_use]
    pub fn unregistered_quarter_stream(quarter_stream_id: u64, payload: Vec<u8>) -> Self {
        // WebTransport prefixes the datagram payload with the
        // Quarter-Stream-ID varint per RFC 9484 §6.2.
        let mut wt_payload = Vec::with_capacity(payload.len() + 8);
        wt_payload.extend_from_slice(&quic_varint(quarter_stream_id));
        wt_payload.extend_from_slice(&payload);
        let frame = QuicDatagramFrame::with_length(wt_payload);
        Self {
            variant: QuicDatagramVariant::UnregisteredQuarterStream,
            datagrams: vec![frame],
            description: format!(
                "WebTransport DATAGRAM for unregistered Quarter-Stream-ID {quarter_stream_id} — phantom session"
            ),
            canary: Canary::generate(),
        }
    }

    /// DATAGRAM sized at the [`MAX_DATAGRAM_PAYLOAD_BYTES`] ceiling.
    /// Boundary test for receivers with a hardcoded
    /// `max_datagram_size` parameter.
    #[must_use]
    pub fn at_boundary_size() -> Self {
        let payload = vec![0xA5; MAX_DATAGRAM_PAYLOAD_BYTES];
        let frame = QuicDatagramFrame::with_length(payload);
        Self {
            variant: QuicDatagramVariant::AtBoundarySize,
            datagrams: vec![frame],
            description: format!(
                "DATAGRAM at boundary size ({MAX_DATAGRAM_PAYLOAD_BYTES} bytes) — hardcoded-max-size probe"
            ),
            canary: Canary::generate(),
        }
    }

    /// Convert to `EvasionFrameSet` for the wafrift pipeline.
    #[must_use]
    pub fn to_frame_set(&self) -> EvasionFrameSet {
        let frames: Vec<EvasionFrame> = self
            .datagrams
            .iter()
            .map(|d| EvasionFrame {
                bytes: d.to_bytes(),
                description: format!(
                    "QUIC DATAGRAM type=0x{:x} len={}",
                    d.frame_type,
                    d.payload.len()
                ),
                technique: EvasionTechnique::QuicDatagramSmuggle,
                stream_id: 0, // DATAGRAM rides outside any stream
            })
            .collect();
        EvasionFrameSet {
            frames,
            technique: EvasionTechnique::QuicDatagramSmuggle,
            description: self.description.clone(),
        }
    }
}

impl SmuggleProbe for QuicDatagramAttack {
    fn canary(&self) -> &Canary {
        &self.canary
    }

    fn technique(&self) -> String {
        let suffix = match self.variant {
            QuicDatagramVariant::StreamlessPayload => "streamless-payload",
            QuicDatagramVariant::TypeConfusion => "type-confusion",
            QuicDatagramVariant::UnregisteredQuarterStream => "unregistered-quarter-stream",
            QuicDatagramVariant::AtBoundarySize => "at-boundary-size",
        };
        format!("quic-datagram.{suffix}")
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn artifact(&self) -> SmuggleArtifact {
        SmuggleArtifact::Frames(
            self.datagrams
                .iter()
                .map(QuicDatagramFrame::to_bytes)
                .collect(),
        )
    }
}

/// Enumerate one attack per variant, seeded with `payload`. Useful
/// for sweep probes.
#[must_use]
pub fn all_variants(payload: &[u8]) -> Vec<QuicDatagramAttack> {
    vec![
        QuicDatagramAttack::streamless_payload(payload.to_vec()),
        QuicDatagramAttack::type_confusion(payload.to_vec()),
        // Phantom Quarter-Stream-ID: pick a value past any plausible
        // max_streams setting. 1_000_000 quarter-streams = 4M stream
        // IDs, well beyond any real WebTransport session quota.
        QuicDatagramAttack::unregistered_quarter_stream(1_000_000, payload.to_vec()),
        QuicDatagramAttack::at_boundary_size(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic_cid::quic_varint_decode;

    #[test]
    fn frame_with_length_round_trips() {
        let f = QuicDatagramFrame::with_length(b"hello".to_vec());
        let bytes = f.to_bytes();
        let (t, n1) = quic_varint_decode(&bytes, 0).expect("type");
        let (l, n2) = quic_varint_decode(&bytes, n1).expect("length");
        assert_eq!(t, DATAGRAM_TYPE_WITH_LENGTH);
        assert_eq!(l, 5);
        assert_eq!(&bytes[n1 + n2..], b"hello");
    }

    #[test]
    fn frame_no_length_omits_length_varint() {
        let f = QuicDatagramFrame::no_length(b"abc".to_vec());
        let bytes = f.to_bytes();
        let (t, n1) = quic_varint_decode(&bytes, 0).expect("type");
        assert_eq!(t, DATAGRAM_TYPE_NO_LENGTH);
        // No length varint: payload follows the type immediately.
        assert_eq!(&bytes[n1..], b"abc");
    }

    #[test]
    fn frame_payload_truncated_at_cap() {
        let payload = vec![b'X'; MAX_DATAGRAM_PAYLOAD_BYTES * 2];
        let f = QuicDatagramFrame::with_length(payload);
        assert_eq!(f.payload.len(), MAX_DATAGRAM_PAYLOAD_BYTES);
    }

    #[test]
    fn streamless_payload_produces_one_with_length_datagram() {
        let attack = QuicDatagramAttack::streamless_payload(b"secret".to_vec());
        assert_eq!(attack.datagrams.len(), 1);
        assert_eq!(attack.datagrams[0].frame_type, DATAGRAM_TYPE_WITH_LENGTH);
        assert_eq!(attack.datagrams[0].payload, b"secret");
    }

    #[test]
    fn type_confusion_emits_both_frame_types_in_order() {
        let attack = QuicDatagramAttack::type_confusion(b"payload".to_vec());
        assert_eq!(attack.datagrams.len(), 2);
        // Per the description and RFC 9221 §4 placement constraint,
        // 0x31 (with-length) MUST come first; 0x30 (no-length) MUST
        // be last in the packet because it consumes remaining bytes.
        assert_eq!(attack.datagrams[0].frame_type, DATAGRAM_TYPE_WITH_LENGTH);
        assert_eq!(attack.datagrams[1].frame_type, DATAGRAM_TYPE_NO_LENGTH);
    }

    #[test]
    fn unregistered_quarter_stream_prefixes_payload_with_quarter_stream_varint() {
        let qs_id = 42_u64;
        let attack = QuicDatagramAttack::unregistered_quarter_stream(qs_id, b"x".to_vec());
        let frame = &attack.datagrams[0];
        // Payload = Quarter-Stream-ID varint + original payload.
        let (decoded_id, n) = quic_varint_decode(&frame.payload, 0).expect("qs-id varint");
        assert_eq!(decoded_id, qs_id);
        assert_eq!(&frame.payload[n..], b"x");
    }

    #[test]
    fn at_boundary_size_emits_max_size_payload() {
        let attack = QuicDatagramAttack::at_boundary_size();
        assert_eq!(
            attack.datagrams[0].payload.len(),
            MAX_DATAGRAM_PAYLOAD_BYTES
        );
    }

    #[test]
    fn all_variants_covers_every_smuggle_variant_exactly_once() {
        let v = all_variants(b"p");
        let mut seen: std::collections::HashSet<QuicDatagramVariant> =
            std::collections::HashSet::new();
        for a in &v {
            seen.insert(a.variant);
        }
        assert_eq!(seen.len(), v.len(), "no duplicate variants in sweep");
        assert_eq!(
            v.len(),
            4,
            "sweep must emit exactly 4 datagram smuggle shapes"
        );
    }

    #[test]
    fn evasion_frame_set_tags_quic_datagram_technique() {
        let attack = QuicDatagramAttack::streamless_payload(b"p".to_vec());
        let fs = attack.to_frame_set();
        assert_eq!(fs.technique, EvasionTechnique::QuicDatagramSmuggle);
        for frame in &fs.frames {
            assert_eq!(frame.technique, EvasionTechnique::QuicDatagramSmuggle);
        }
    }

    #[test]
    fn each_attack_carries_a_distinct_canary() {
        let a = QuicDatagramAttack::streamless_payload(b"p".to_vec());
        let b = QuicDatagramAttack::streamless_payload(b"p".to_vec());
        assert_ne!(a.canary.token, b.canary.token);
        assert_eq!(a.canary.token.len(), 16);
    }

    #[test]
    fn empty_payload_does_not_panic() {
        for attack in all_variants(b"") {
            let fs = attack.to_frame_set();
            assert!(!fs.frames.is_empty());
            for frame in &fs.frames {
                assert!(!frame.bytes.is_empty(), "type varint at minimum");
            }
        }
    }

    // ── NEW TESTS ─────────────────────────────────────────────────────────

    #[test]
    fn frame_payload_at_exact_cap_not_truncated() {
        // Boundary: payload of exactly MAX_DATAGRAM_PAYLOAD_BYTES must
        // pass through unchanged — not off-by-one truncation.
        let payload = vec![b'A'; MAX_DATAGRAM_PAYLOAD_BYTES];
        let f = QuicDatagramFrame::with_length(payload);
        assert_eq!(
            f.payload.len(),
            MAX_DATAGRAM_PAYLOAD_BYTES,
            "payload at exact cap must not be truncated"
        );
    }

    #[test]
    fn frame_payload_one_past_cap_truncates() {
        // One-past-max: payload of cap+1 must clamp to cap, not panic.
        let payload = vec![b'B'; MAX_DATAGRAM_PAYLOAD_BYTES + 1];
        let f = QuicDatagramFrame::no_length(payload);
        assert_eq!(
            f.payload.len(),
            MAX_DATAGRAM_PAYLOAD_BYTES,
            "payload one-past-cap must clamp to MAX_DATAGRAM_PAYLOAD_BYTES"
        );
    }

    #[test]
    fn to_frame_set_stream_id_sentinel_is_zero() {
        // §9 WIRING pin: DATAGRAM frames ride outside any HTTP/3 stream;
        // stream_id=0 is the "no specific stream" sentinel. Pin it so
        // a regression that sets a non-zero default breaks here.
        for attack in all_variants(b"payload") {
            let fs = attack.to_frame_set();
            for frame in &fs.frames {
                assert_eq!(
                    frame.stream_id, 0,
                    "QUIC DATAGRAM EvasionFrame must carry stream_id=0, got {} for {:?}",
                    frame.stream_id, attack.variant
                );
            }
        }
    }

    #[test]
    fn unregistered_quarter_stream_with_zero_id() {
        // Boundary: Quarter-Stream-ID = 0 is the minimum varint value.
        // It is the session ID that would correspond to stream 0 — which
        // is the QUIC control stream, not a valid WT stream. Some
        // receivers reject it; the probe surface is the divergence.
        let attack = QuicDatagramAttack::unregistered_quarter_stream(0, b"data".to_vec());
        let frame = &attack.datagrams[0];
        let (decoded_id, n) = quic_varint_decode(&frame.payload, 0).expect("qs-id varint");
        assert_eq!(decoded_id, 0, "zero Quarter-Stream-ID must be preserved");
        assert_eq!(&frame.payload[n..], b"data");
    }

    #[test]
    fn type_confusion_serialized_bytes_have_both_type_markers() {
        // Wire-format invariant: the type_confusion attack serializes
        // 2 frames; the first byte of each frame encodes its type varint.
        // Assert both type values are present in the serialized output.
        let attack = QuicDatagramAttack::type_confusion(b"x".to_vec());
        let frame0_bytes = attack.datagrams[0].to_bytes();
        let frame1_bytes = attack.datagrams[1].to_bytes();
        let (t0, _) = quic_varint_decode(&frame0_bytes, 0).unwrap();
        let (t1, _) = quic_varint_decode(&frame1_bytes, 0).unwrap();
        assert_eq!(t0, DATAGRAM_TYPE_WITH_LENGTH);
        assert_eq!(t1, DATAGRAM_TYPE_NO_LENGTH);
    }

    #[test]
    fn concurrent_attack_construction_yields_unique_canaries() {
        // §12 TESTING — concurrent: 50 threads each construct a
        // streamless_payload; canaries must all be distinct.
        use std::sync::{Arc, Mutex};
        use std::thread;

        let tokens: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let threads: Vec<_> = (0..50)
            .map(|_| {
                let tokens = Arc::clone(&tokens);
                thread::spawn(move || {
                    let a = QuicDatagramAttack::streamless_payload(vec![0xAB]);
                    tokens.lock().unwrap().push(a.canary.token);
                })
            })
            .collect();
        for t in threads {
            t.join().expect("thread panicked");
        }
        let toks = tokens.lock().unwrap();
        let unique: std::collections::HashSet<&String> = toks.iter().collect();
        assert_eq!(
            unique.len(),
            50,
            "50 concurrent constructions must produce 50 distinct canaries"
        );
    }

    #[test]
    fn at_boundary_size_payload_is_all_0xa5_fill() {
        // Anti-rig: pin the fill byte so a "performance optimisation"
        // that replaces the uniform fill with zeroes doesn't silently
        // change the probe's LZ77 fingerprint.
        let attack = QuicDatagramAttack::at_boundary_size();
        assert!(
            attack.datagrams[0].payload.iter().all(|&b| b == 0xA5),
            "at-boundary-size payload fill must be 0xA5 throughout"
        );
    }

    #[test]
    fn unregistered_quarter_stream_large_id_does_not_overflow_varint() {
        // Integer robustness: a very large Quarter-Stream-ID (u64::MAX)
        // must not overflow or panic — quic_varint handles up to 62-bit
        // values in the 8-byte form. u64::MAX (63-bit set) saturates to
        // the QUIC 8-byte varint ceiling 0x3FFF_FFFF_FFFF_FFFF.
        let attack = QuicDatagramAttack::unregistered_quarter_stream(u64::MAX, b"x".to_vec());
        let frame = &attack.datagrams[0];
        // 8-byte varint + 1 payload byte = 9 bytes total — well under cap.
        let (decoded_id, n) = quic_varint_decode(&frame.payload, 0).expect("large qs-id varint");
        // QUIC varint ceiling: 2^62 - 1 = 4611686018427387903
        const QUIC_VARINT_MAX: u64 = 0x3FFF_FFFF_FFFF_FFFF;
        assert_eq!(
            decoded_id, QUIC_VARINT_MAX,
            "u64::MAX Quarter-Stream-ID saturates to QUIC 8-byte varint ceiling"
        );
        assert_eq!(&frame.payload[n..], b"x");
    }

    #[test]
    fn frame_with_length_serialized_length_matches_payload_exactly() {
        // Wire-format invariant: the Length varint in a with_length frame
        // must equal the payload.len() exactly — any drift means the
        // receiver would read the wrong number of bytes.
        for size in [0, 1, 100, MAX_DATAGRAM_PAYLOAD_BYTES] {
            let payload = vec![0x42u8; size];
            let f = QuicDatagramFrame::with_length(payload.clone());
            let bytes = f.to_bytes();
            let (_t, n1) = quic_varint_decode(&bytes, 0).expect("type");
            let (l, n2) = quic_varint_decode(&bytes, n1).expect("length");
            assert_eq!(
                l as usize,
                payload.len(),
                "frame length varint must equal payload.len() for size={size}"
            );
            assert_eq!(
                bytes.len() - n1 - n2,
                payload.len(),
                "emitted bytes after header must equal payload for size={size}"
            );
        }
    }

    #[test]
    fn max_datagram_payload_bytes_is_sane_upper_bound() {
        // Anti-rig: if MAX_DATAGRAM_PAYLOAD_BYTES is raised beyond the
        // single-packet QUIC datagram ceiling, the "stays inside a single
        // QUIC packet" safety property documented in the module breaks.
        // RFC 9000 §7.4 path MTU: 1200 bytes is the minimum guaranteed
        // datagram size; our cap must stay below that.
        assert!(
            MAX_DATAGRAM_PAYLOAD_BYTES <= 1200,
            "MAX_DATAGRAM_PAYLOAD_BYTES={} exceeds RFC 9000 minimum path MTU ceiling of 1200",
            MAX_DATAGRAM_PAYLOAD_BYTES
        );
    }

    // ── Property tests ────────────────────────────────────────────────────
    // (quic_varint_decode is already imported at the top of this test module.)

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        /// A length-prefixed DATAGRAM (0x31) is faithful: the wire length varint
        /// equals the (possibly truncated) payload length and the payload bytes
        /// follow verbatim.
        #[test]
        fn prop_datagram_with_length_roundtrips(payload in proptest::collection::vec(any::<u8>(), 0..1500)) {
            let f = QuicDatagramFrame::with_length(payload);
            prop_assert!(f.payload.len() <= MAX_DATAGRAM_PAYLOAD_BYTES);
            let b = f.to_bytes();
            let (ty, n1) = quic_varint_decode(&b, 0).unwrap();
            prop_assert_eq!(ty, DATAGRAM_TYPE_WITH_LENGTH);
            let (len, n2) = quic_varint_decode(&b, n1).unwrap();
            prop_assert_eq!(len as usize, f.payload.len());
            prop_assert_eq!(&b[n1 + n2..], &f.payload[..]);
        }

        /// A no-length DATAGRAM (0x30) has no length field — the payload is the
        /// entire remainder of the frame, verbatim.
        #[test]
        fn prop_datagram_no_length_roundtrips(payload in proptest::collection::vec(any::<u8>(), 0..1500)) {
            let f = QuicDatagramFrame::no_length(payload);
            let b = f.to_bytes();
            let (ty, n1) = quic_varint_decode(&b, 0).unwrap();
            prop_assert_eq!(ty, DATAGRAM_TYPE_NO_LENGTH);
            prop_assert_eq!(&b[n1..], &f.payload[..]);
        }

        /// Any payload over the cap is truncated by the constructor — never
        /// emitted oversized (a frame past the cap would be dropped on the wire).
        #[test]
        fn prop_datagram_truncates_oversized_payload(extra in 0usize..512) {
            let big = vec![0xABu8; MAX_DATAGRAM_PAYLOAD_BYTES + extra];
            prop_assert_eq!(
                QuicDatagramFrame::with_length(big.clone()).payload.len(),
                MAX_DATAGRAM_PAYLOAD_BYTES
            );
            prop_assert_eq!(
                QuicDatagramFrame::no_length(big).payload.len(),
                MAX_DATAGRAM_PAYLOAD_BYTES
            );
        }
    }
}
