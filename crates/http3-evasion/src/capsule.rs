//! HTTP Capsule Protocol (RFC 9297) smuggling primitives.
//!
//! Capsules are a wire-format that runs **inside** HTTP message
//! bodies — HTTP/3 DATA frames, HTTP/2 DATA frames, or HTTP/1.1
//! chunked bodies. They give applications a way to multiplex
//! arbitrary framed data on a single HTTP exchange after the headers
//! have been processed. Three IETF protocols use them in production
//! today:
//!
//! - **CONNECT-UDP** (RFC 9298) — UDP packets wrapped in DATAGRAM
//!   capsules (type 0x00) so a client can tunnel UDP traffic over a
//!   firewall that only permits HTTPS.
//! - **CONNECT-IP** (RFC 9484) — IP-level VPN tunnels wrapped in
//!   ADDRESS_ASSIGN / ADDRESS_REQUEST / ROUTE_ADVERTISEMENT capsules.
//! - **WebTransport over HTTP/3** — uses capsules for the per-session
//!   handshake metadata (sessionEstablished, fin signals, etc.).
//!
//! The relevant property for WAF evasion is that a WAF deployed at the
//! HTTP semantic layer (headers, body bytes treated as one flat
//! buffer) typically does **not** parse capsules. The bytes inside a
//! `DATAGRAM` capsule are opaque UDP from the WAF's perspective; the
//! bytes inside an `ADDRESS_ASSIGN` capsule are opaque IP-tunnel
//! metadata. An origin server that terminates the CONNECT-UDP /
//! CONNECT-IP / WebTransport session, by contrast, runs a capsule
//! parser and surfaces every value.
//!
//! That parser-disagreement seam is the bypass: payload bytes
//! delivered as the value field of a known-but-WAF-unhandled capsule
//! type cross the WAF as opaque body bytes and surface at the origin
//! as the intended structured field.
//!
//! ## Wire format (RFC 9297 §3.2)
//!
//! ```text
//! Capsule {
//!   Type   (i),                 # QUIC varint
//!   Length (i),                 # QUIC varint — length of Value
//!   Value  (..Length * 8),      # opaque application bytes
//! }
//! ```
//!
//! Multiple capsules are concatenated back-to-back inside the HTTP
//! body. Receivers MUST skip unknown capsule types per RFC 9297
//! §3.2 — that "must skip" is the bypass surface this module
//! exercises.
//!
//! ## GREASE values
//!
//! RFC 9297 §3.4 reserves capsule type values of the form
//! `0x1f * N + 0x21` (i.e. `0x21, 0x40, 0x5f, 0x7e, …`) as forward-
//! compatibility GREASE. Conforming receivers MUST treat these as
//! unknown and skip; non-conforming receivers reject the whole
//! exchange. The GREASE probe surfaces which side of that fence the
//! target sits on.
//!
//! ## Safety
//!
//! This module is **pure data-plane**: it builds wire bytes. The
//! caller is responsible for inserting the bytes into an HTTP body
//! (DATA frame for HTTP/3, chunked body for HTTP/1.1, etc.) and for
//! ensuring the surrounding HTTP semantic layer allows capsule
//! transport (typically by setting `Capsule-Protocol: ?1` per RFC
//! 9297 §3.3 — caller's responsibility, not ours).

use crate::EvasionFrame;
use crate::EvasionFrameSet;
use crate::EvasionTechnique;
use crate::quic_cid::quic_varint;
use wafrift_types::canary::Canary;
use wafrift_types::probe::{SmuggleArtifact, SmuggleProbe};

/// Known capsule type registrations from RFC 9297 / 9298 / 9484.
/// Numbers come from the IANA "HTTP Capsule Types" registry.
pub mod capsule_type {
    /// DATAGRAM capsule — RFC 9297 §3.5 / RFC 9298 §5.2.
    /// Carries an opaque UDP-style payload over an HTTP CONNECT-UDP
    /// tunnel.
    pub const DATAGRAM: u64 = 0x00;
    /// ADDRESS_ASSIGN — RFC 9484 §4.1. Server tells client the IP
    /// addresses bound to its tunnel endpoint.
    pub const ADDRESS_ASSIGN: u64 = 0x01;
    /// ADDRESS_REQUEST — RFC 9484 §4.2. Client requests an address
    /// assignment.
    pub const ADDRESS_REQUEST: u64 = 0x02;
    /// ROUTE_ADVERTISEMENT — RFC 9484 §4.3. Either side advertises
    /// the routes it's willing to forward.
    pub const ROUTE_ADVERTISEMENT: u64 = 0x03;
    /// WT_RESET_STREAM — WebTransport over H3 (draft).
    pub const WT_RESET_STREAM: u64 = 0x190b4d39;
    /// WT_STOP_SENDING — WebTransport over H3 (draft).
    pub const WT_STOP_SENDING: u64 = 0x190b4d3a;
    /// WT_STREAM — WebTransport over H3 (draft, type for
    /// unidirectional opening).
    pub const WT_STREAM: u64 = 0x190b4d3b;
}

/// Maximum byte length we'll emit for a single capsule value. The
/// probe value is structural — a few KB exercises every parser
/// state-machine corner that matters. Capping protects callers from
/// being abused as a megabyte-amplifier downstream of `frames()`.
pub const MAX_CAPSULE_VALUE_BYTES: usize = 8 * 1024;

/// A single RFC 9297 capsule on the wire.
#[derive(Debug, Clone)]
pub struct CapsuleFrame {
    /// Capsule Type — RFC 9297 §3.2 varint.
    pub capsule_type: u64,
    /// Capsule Value — opaque bytes. The Length varint is computed
    /// from `value.len()` at serialization time unless
    /// [`overdeclared_length`](Self::overdeclared_length) is set.
    pub value: Vec<u8>,
    /// If `Some(n)`, the serialized Length varint declares `n` bytes
    /// of value, regardless of `value.len()`. Used to construct the
    /// over-declared-length and truncated-value probes. The caller
    /// guarantees `n` is reachable on the wire — we do not pad.
    pub overdeclared_length: Option<u64>,
}

impl CapsuleFrame {
    /// New capsule with auto-computed length. Value is truncated to
    /// [`MAX_CAPSULE_VALUE_BYTES`].
    #[must_use]
    pub fn new(capsule_type: u64, value: Vec<u8>) -> Self {
        let mut v = value;
        if v.len() > MAX_CAPSULE_VALUE_BYTES {
            v.truncate(MAX_CAPSULE_VALUE_BYTES);
        }
        Self {
            capsule_type,
            value: v,
            overdeclared_length: None,
        }
    }

    /// Mark this capsule for over-declared length serialization. The
    /// wire Length varint will say `declared_len` bytes follow, but
    /// only `value.len()` will actually be emitted. Some receivers
    /// stall waiting for the rest of the bytes; others reject the
    /// stream; others happily process the short value and ignore the
    /// discrepancy.
    #[must_use]
    pub fn with_overdeclared_length(mut self, declared_len: u64) -> Self {
        self.overdeclared_length = Some(declared_len);
        self
    }

    /// Serialize to bytes per RFC 9297 §3.2.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let declared = self
            .overdeclared_length
            .unwrap_or(self.value.len() as u64);
        // Saturating add: if `value` was constructed directly (bypassing
        // `new()`) with a pathologically large vec, adding 16 to
        // `value.len()` could wrap on 32-bit targets. Saturating keeps
        // the allocation legitimate; the extend_from_slice calls will still
        // copy all bytes regardless of the initial capacity hint.
        let cap = self.value.len().saturating_add(16);
        let mut out = Vec::with_capacity(cap);
        out.extend_from_slice(&quic_varint(self.capsule_type));
        out.extend_from_slice(&quic_varint(declared));
        out.extend_from_slice(&self.value);
        out
    }
}

/// Capsule-protocol smuggle variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CapsuleSmuggleVariant {
    /// Wrap the payload bytes inside a DATAGRAM capsule (type 0x00).
    /// A WAF inspecting HTTP/3 DATA frames at the HTTP semantic layer
    /// sees opaque bytes; a CONNECT-UDP-terminating origin parses the
    /// inner payload.
    OpaqueDatagramPayload,
    /// Use a capsule type that's syntactically valid (varint-encoded)
    /// but unknown to the IANA registry. RFC 9297 §3.2 says receivers
    /// MUST skip — divergent behavior between WAF and origin surfaces
    /// here.
    UnknownTypeSmuggle,
    /// Use a GREASE capsule type (`0x1f*N + 0x21`). All conforming
    /// receivers must skip. Non-conforming receivers blow up.
    GreaseTypeProbe,
    /// Declared Length varint > actual emitted value bytes. Some
    /// receivers block waiting for the remainder; others process the
    /// short value and move on.
    OverdeclaredLength,
    /// Outer capsule whose Value field is itself a complete capsule.
    /// Recursive parsers surface the inner value; flat parsers see
    /// one capsule.
    NestedCapsule,
    /// ADDRESS_ASSIGN capsule (CONNECT-IP) whose Value contains
    /// payload bytes shaped like a HTTP request line. CONNECT-IP
    /// terminators parse it as tunnel metadata; HTTP-semantic WAFs
    /// never look.
    ConnectIpMetadataChannel,
}

/// A capsule-smuggle attack: one or more capsule frames packed for a
/// single HTTP exchange.
#[derive(Debug, Clone)]
pub struct CapsuleSmuggleAttack {
    /// Which smuggle shape this attack belongs to.
    pub variant: CapsuleSmuggleVariant,
    /// Capsules in send order. The receiver concatenates them inside
    /// the HTTP body.
    pub capsules: Vec<CapsuleFrame>,
    /// Human-readable description for telemetry.
    pub description: String,
    /// Per-attack correlation token. Operators splice this into a
    /// custom header (`X-Probe-Id`, etc.) so server-side responses
    /// can be attributed to the specific variant that triggered them
    /// without leaking target identity. See [`wafrift_types::canary`].
    pub canary: Canary,
}

impl CapsuleSmuggleAttack {
    /// Build a DATAGRAM-wrapped payload smuggle. `payload` is the
    /// attacker's bytes; the WAF sees the capsule framing as opaque
    /// HTTP body, the CONNECT-UDP origin terminator unpacks the
    /// DATAGRAM and reads `payload`.
    #[must_use]
    pub fn opaque_datagram_payload(payload: Vec<u8>) -> Self {
        let cap = CapsuleFrame::new(capsule_type::DATAGRAM, payload);
        Self {
            variant: CapsuleSmuggleVariant::OpaqueDatagramPayload,
            capsules: vec![cap],
            description: "DATAGRAM capsule wraps payload — WAF sees opaque body, origin sees UDP-style frame".into(),
            canary: Canary::generate(),
        }
    }

    /// Build an unknown-type smuggle. `unknown_type` should be a
    /// varint-encodable value not currently in IANA's HTTP Capsule
    /// Types registry. Caller picks the value so the probe can sweep
    /// the type space.
    #[must_use]
    pub fn unknown_type_smuggle(unknown_type: u64, payload: Vec<u8>) -> Self {
        let cap = CapsuleFrame::new(unknown_type, payload);
        Self {
            variant: CapsuleSmuggleVariant::UnknownTypeSmuggle,
            capsules: vec![cap],
            description: format!(
                "Unknown capsule type 0x{unknown_type:x} — RFC 9297 §3.2 says skip; divergence likely"
            ),
            canary: Canary::generate(),
        }
    }

    /// Build a GREASE-type probe. `n` selects which GREASE slot —
    /// the type is computed as `0x1f * n + 0x21` per RFC 9297 §3.4.
    /// `n` is clamped to a sane range so the resulting type still
    /// fits in a 4-byte varint (i.e. `< 2^30`).
    #[must_use]
    pub fn grease_type_probe(n: u64, payload: Vec<u8>) -> Self {
        // 4-byte varint maxes out at 0x3FFF_FFFF; cap n so the
        // computed type stays inside that bound.
        let max_n = (0x3FFF_FFFF_u64 - 0x21) / 0x1f;
        let clamped_n = n.min(max_n);
        let grease_type = 0x1f * clamped_n + 0x21;
        let cap = CapsuleFrame::new(grease_type, payload);
        Self {
            variant: CapsuleSmuggleVariant::GreaseTypeProbe,
            capsules: vec![cap],
            description: format!(
                "GREASE capsule type 0x{grease_type:x} (n={clamped_n}) — must-skip per RFC 9297 §3.4"
            ),
            canary: Canary::generate(),
        }
    }

    /// Build an over-declared-length probe. The Length varint will
    /// claim `declared_extra` more bytes than are emitted; the
    /// receiver must decide whether to stall, reject, or process the
    /// short value.
    #[must_use]
    pub fn overdeclared_length(payload: Vec<u8>, declared_extra: u64) -> Self {
        let actual = payload.len() as u64;
        let declared = actual.saturating_add(declared_extra);
        let cap = CapsuleFrame::new(capsule_type::DATAGRAM, payload).with_overdeclared_length(declared);
        Self {
            variant: CapsuleSmuggleVariant::OverdeclaredLength,
            capsules: vec![cap],
            description: format!(
                "Length varint declares {declared} bytes; only {actual} emitted — receiver state-machine probe"
            ),
            canary: Canary::generate(),
        }
    }

    /// Build a nested-capsule probe. An outer DATAGRAM capsule's
    /// Value field is itself a complete inner capsule (UNKNOWN type
    /// carrying the real payload). Recursive parsers walk into the
    /// inner; flat parsers see one outer.
    #[must_use]
    pub fn nested_capsule(inner_type: u64, payload: Vec<u8>) -> Self {
        let inner = CapsuleFrame::new(inner_type, payload);
        let inner_bytes = inner.to_bytes();
        let outer = CapsuleFrame::new(capsule_type::DATAGRAM, inner_bytes);
        Self {
            variant: CapsuleSmuggleVariant::NestedCapsule,
            capsules: vec![outer],
            description: format!(
                "Outer DATAGRAM wraps inner capsule type 0x{inner_type:x} — recursive parsers diverge from flat"
            ),
            canary: Canary::generate(),
        }
    }

    /// Build a CONNECT-IP metadata-channel probe. ADDRESS_ASSIGN
    /// capsule's Value field carries the attacker's bytes shaped as
    /// HTTP request-line text — never inspected by HTTP-semantic
    /// WAFs because they don't speak CONNECT-IP metadata.
    #[must_use]
    pub fn connect_ip_metadata_channel(payload: Vec<u8>) -> Self {
        let cap = CapsuleFrame::new(capsule_type::ADDRESS_ASSIGN, payload);
        Self {
            variant: CapsuleSmuggleVariant::ConnectIpMetadataChannel,
            capsules: vec![cap],
            description:
                "ADDRESS_ASSIGN capsule (CONNECT-IP) carries payload as opaque tunnel metadata"
                    .into(),
            canary: Canary::generate(),
        }
    }

    /// Convert to an `EvasionFrameSet` for the rest of the wafrift
    /// pipeline.
    #[must_use]
    pub fn to_frame_set(&self) -> EvasionFrameSet {
        let frames: Vec<EvasionFrame> = self
            .capsules
            .iter()
            .map(|c| EvasionFrame {
                bytes: c.to_bytes(),
                description: format!(
                    "capsule type=0x{:x} value_len={} declared={}",
                    c.capsule_type,
                    c.value.len(),
                    c.overdeclared_length
                        .map_or_else(|| c.value.len().to_string(), |d| d.to_string()),
                ),
                technique: EvasionTechnique::CapsuleProtocolSmuggle,
                // Capsules ride inside DATA frames on a request stream;
                // stream_id is caller-chosen at injection time. 0 is the
                // "no specific stream" sentinel the rest of the crate
                // uses (see stream_priority.rs:230 control-stream
                // pattern for the convention).
                stream_id: 0,
            })
            .collect();
        EvasionFrameSet {
            frames,
            technique: EvasionTechnique::CapsuleProtocolSmuggle,
            description: self.description.clone(),
        }
    }
}

impl SmuggleProbe for CapsuleSmuggleAttack {
    fn canary(&self) -> &Canary {
        &self.canary
    }

    fn technique(&self) -> String {
        let suffix = match self.variant {
            CapsuleSmuggleVariant::OpaqueDatagramPayload => "opaque-datagram-payload",
            CapsuleSmuggleVariant::UnknownTypeSmuggle => "unknown-type-smuggle",
            CapsuleSmuggleVariant::GreaseTypeProbe => "grease-type-probe",
            CapsuleSmuggleVariant::OverdeclaredLength => "overdeclared-length",
            CapsuleSmuggleVariant::NestedCapsule => "nested-capsule",
            CapsuleSmuggleVariant::ConnectIpMetadataChannel => "connect-ip-metadata-channel",
        };
        format!("capsule.{suffix}")
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn artifact(&self) -> SmuggleArtifact {
        SmuggleArtifact::Frames(self.capsules.iter().map(CapsuleFrame::to_bytes).collect())
    }
}

/// Enumerate one attack per variant, seeded with `payload`. Useful
/// for sweep-style probes where the caller wants every shape exercised
/// in one pass.
///
/// **Type-value randomisation.** The `UnknownTypeSmuggle` and inner-
/// capsule type of `NestedCapsule` are drawn from
/// [`UNALLOCATED_TYPE_POOL`] per call rather than hardcoded — a WAF
/// that learns "block any capsule with type 0x2fffff" would otherwise
/// pin wafrift's signature after one observed run. The pool entries
/// all sit in the unallocated IANA capsule-type range and all fit
/// the 4-byte varint band so the wire encoding stays cheap.
#[must_use]
pub fn all_variants(payload: &[u8]) -> Vec<CapsuleSmuggleAttack> {
    use wafrift_types::pick::pick_from;
    let unknown_type = pick_from(UNALLOCATED_TYPE_POOL, 0x2f_ffff_u64);
    let inner_nested = pick_from(UNALLOCATED_TYPE_POOL, 0x4_2424_u64);
    vec![
        CapsuleSmuggleAttack::opaque_datagram_payload(payload.to_vec()),
        CapsuleSmuggleAttack::unknown_type_smuggle(unknown_type, payload.to_vec()),
        CapsuleSmuggleAttack::grease_type_probe(7, payload.to_vec()),
        CapsuleSmuggleAttack::overdeclared_length(payload.to_vec(), 64),
        CapsuleSmuggleAttack::nested_capsule(inner_nested, payload.to_vec()),
        CapsuleSmuggleAttack::connect_ip_metadata_channel(payload.to_vec()),
    ]
}

/// Unallocated capsule-type values used by [`all_variants`] for the
/// unknown-type and nested-inner probes. Every entry is currently
/// outside the IANA registry (RFC 9297 / 9298 / 9484) and fits the
/// 4-byte QUIC varint band (≤ 0x3FFF_FFFF). Picking per-call defeats
/// the trivial "pin 0x2fffff" signature pattern.
pub(crate) const UNALLOCATED_TYPE_POOL: &[u64] = &[
    0x2f_ffff,
    0x4_2424,
    0x10_0000,
    0x20_0000,
    0xab_cdef,
    0x3f_aaaa,
    0x05_dead,
    0x06_beef,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic_cid::quic_varint_decode;

    #[test]
    fn capsule_frame_round_trip_known_type() {
        let cap = CapsuleFrame::new(capsule_type::DATAGRAM, b"hello".to_vec());
        let bytes = cap.to_bytes();
        let (t, n1) = quic_varint_decode(&bytes, 0).expect("type varint");
        let (l, n2) = quic_varint_decode(&bytes, n1).expect("length varint");
        assert_eq!(t, capsule_type::DATAGRAM);
        assert_eq!(l, 5, "length must equal value byte count");
        assert_eq!(&bytes[n1 + n2..], b"hello");
    }

    #[test]
    fn capsule_value_is_truncated_at_cap() {
        let payload = vec![b'X'; MAX_CAPSULE_VALUE_BYTES * 2];
        let cap = CapsuleFrame::new(capsule_type::DATAGRAM, payload);
        // Anti-rig: builder must enforce the cap so downstream
        // serialization cannot be tricked into a megabyte-amplifier.
        assert_eq!(
            cap.value.len(),
            MAX_CAPSULE_VALUE_BYTES,
            "oversized value must be truncated by the constructor"
        );
        let bytes = cap.to_bytes();
        let (_t, n1) = quic_varint_decode(&bytes, 0).expect("type varint");
        let (l, _n2) = quic_varint_decode(&bytes, n1).expect("length varint");
        assert_eq!(
            l as usize,
            MAX_CAPSULE_VALUE_BYTES,
            "serialized length must match truncated value length"
        );
    }

    #[test]
    fn overdeclared_length_does_not_change_emitted_value_size() {
        // The probe's whole point: declared > actual. Make sure the
        // wire bytes still only carry `value.len()` bytes after the
        // length varint.
        let cap = CapsuleFrame::new(capsule_type::DATAGRAM, b"abc".to_vec())
            .with_overdeclared_length(1000);
        let bytes = cap.to_bytes();
        let (_t, n1) = quic_varint_decode(&bytes, 0).unwrap();
        let (l, n2) = quic_varint_decode(&bytes, n1).unwrap();
        assert_eq!(l, 1000, "declared length must be the overdeclared value");
        assert_eq!(
            bytes.len() - (n1 + n2),
            3,
            "actual emitted value bytes stay at value.len()"
        );
    }

    #[test]
    fn grease_type_formula_matches_rfc9297_section_3_4() {
        // RFC 9297 §3.4: GREASE values are 0x1f * N + 0x21.
        // For N=0..7 the values should be 0x21, 0x40, 0x5f, 0x7e,
        // 0x9d, 0xbc, 0xdb, 0xfa. Pin the formula here so any future
        // refactor that "simplifies" it (e.g. drops the 0x21 offset)
        // breaks the test, not production traffic.
        let probe = CapsuleSmuggleAttack::grease_type_probe(0, vec![1, 2, 3]);
        assert_eq!(probe.capsules[0].capsule_type, 0x21);
        let probe = CapsuleSmuggleAttack::grease_type_probe(1, vec![]);
        assert_eq!(probe.capsules[0].capsule_type, 0x40);
        let probe = CapsuleSmuggleAttack::grease_type_probe(7, vec![]);
        assert_eq!(probe.capsules[0].capsule_type, 0xfa);
    }

    #[test]
    fn grease_type_clamps_n_to_fit_4_byte_varint() {
        // A massive n must not produce a type that overflows the
        // varint range expected by RFC 9297. Clamp keeps us inside
        // the 4-byte varint band (0..=0x3FFF_FFFF).
        let probe = CapsuleSmuggleAttack::grease_type_probe(u64::MAX, vec![1]);
        let t = probe.capsules[0].capsule_type;
        assert!(
            t <= 0x3FFF_FFFF,
            "clamped grease type must fit in a 4-byte varint, got 0x{t:x}"
        );
    }

    #[test]
    fn nested_capsule_value_is_a_serialized_inner_capsule() {
        let attack = CapsuleSmuggleAttack::nested_capsule(0x4242, b"inner".to_vec());
        let outer = &attack.capsules[0];
        assert_eq!(outer.capsule_type, capsule_type::DATAGRAM);
        // The outer's value bytes are themselves a full capsule:
        // decode the inner type+length+value out of them and confirm.
        let (inner_type, n1) = quic_varint_decode(&outer.value, 0).expect("inner type");
        let (inner_len, n2) = quic_varint_decode(&outer.value, n1).expect("inner length");
        assert_eq!(inner_type, 0x4242);
        assert_eq!(inner_len, 5);
        assert_eq!(&outer.value[n1 + n2..], b"inner");
    }

    #[test]
    fn all_variants_covers_every_smuggle_variant_exactly_once() {
        let v = all_variants(b"x");
        let mut seen: std::collections::HashSet<CapsuleSmuggleVariant> =
            std::collections::HashSet::new();
        for a in &v {
            seen.insert(a.variant);
        }
        assert_eq!(seen.len(), v.len(), "no duplicate variants");
        // Pin the count so any silent removal breaks here.
        assert_eq!(v.len(), 6, "sweep must emit exactly 6 capsule smuggle shapes");
    }

    #[test]
    fn evasion_frame_set_tags_correct_technique() {
        let attack = CapsuleSmuggleAttack::opaque_datagram_payload(b"p".to_vec());
        let fs = attack.to_frame_set();
        assert_eq!(fs.technique, EvasionTechnique::CapsuleProtocolSmuggle);
        for frame in &fs.frames {
            assert_eq!(frame.technique, EvasionTechnique::CapsuleProtocolSmuggle);
        }
    }

    #[test]
    fn empty_payload_does_not_panic() {
        for attack in all_variants(b"") {
            let fs = attack.to_frame_set();
            assert!(
                !fs.frames.is_empty(),
                "even empty payload must produce a framed capsule"
            );
            for frame in &fs.frames {
                assert!(
                    !frame.bytes.is_empty(),
                    "capsule bytes must include the type+length varints even when value is empty"
                );
            }
        }
    }

    #[test]
    fn varint_boundary_capsule_type_round_trips() {
        // Test every QUIC varint length boundary as a capsule type
        // — 1-byte (63), 2-byte (16383), 4-byte (1073741823),
        // 8-byte. Anti-rig: a regression in varint encoding/decoding
        // would silently mis-frame every capsule.
        for &t in &[
            63_u64,
            16_383,
            1_073_741_823,
            4_611_686_018_427_387_903,
        ] {
            let cap = CapsuleFrame::new(t, b"v".to_vec());
            let bytes = cap.to_bytes();
            let (decoded, _) = quic_varint_decode(&bytes, 0).expect("type round-trip");
            assert_eq!(
                decoded, t,
                "varint round-trip lost type 0x{t:x} → 0x{decoded:x}"
            );
        }
    }

    #[test]
    fn opaque_datagram_value_bytes_are_preserved_verbatim() {
        // Payload bytes including control chars must reach the
        // serialized output unaltered — otherwise the smuggle is
        // useless. Caller-supplied payload is the *whole* point.
        let payload: Vec<u8> = (0..=255_u8).collect();
        let attack = CapsuleSmuggleAttack::opaque_datagram_payload(payload.clone());
        let bytes = attack.capsules[0].to_bytes();
        // Skip past the type+length varints to reach the value.
        let (_, n1) = quic_varint_decode(&bytes, 0).unwrap();
        let (_, n2) = quic_varint_decode(&bytes, n1).unwrap();
        assert_eq!(
            &bytes[n1 + n2..],
            &payload[..],
            "opaque payload must serialize byte-for-byte"
        );
    }

    #[test]
    fn each_constructor_gives_a_distinct_canary() {
        // Anti-rig: every CapsuleSmuggleAttack must carry a fresh
        // canary so the operator can correlate responses per probe.
        // A regression that hardcoded the canary (or seeded the RNG
        // to a constant) would collapse all attacks to one token and
        // defeat correlation.
        let a = CapsuleSmuggleAttack::opaque_datagram_payload(vec![1, 2, 3]);
        let b = CapsuleSmuggleAttack::opaque_datagram_payload(vec![1, 2, 3]);
        assert_ne!(
            a.canary.token, b.canary.token,
            "two attack constructions must produce distinct canaries"
        );
        assert_eq!(a.canary.token.len(), 16);
        assert!(a.canary.token.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn unallocated_type_pool_entries_fit_4_byte_varint() {
        // Anti-rig: every pool entry must encode in the 4-byte varint
        // band so `all_variants` doesn't accidentally widen the wire
        // format. RFC 9000 4-byte varint range is 16384..=1_073_741_823.
        for &t in UNALLOCATED_TYPE_POOL {
            assert!(
                t > 16_383 && t <= 0x3FFF_FFFF,
                "pool entry 0x{t:x} outside the 4-byte varint band"
            );
        }
    }

    #[test]
    fn unallocated_type_pool_has_no_duplicates() {
        // Duplicates would shrink the effective per-call entropy and
        // weaken the signature-defeating property of `all_variants`.
        let unique: std::collections::HashSet<&u64> = UNALLOCATED_TYPE_POOL.iter().collect();
        assert_eq!(
            unique.len(),
            UNALLOCATED_TYPE_POOL.len(),
            "UNALLOCATED_TYPE_POOL contains duplicate entries"
        );
    }

    #[test]
    fn connect_ip_metadata_channel_uses_address_assign_type() {
        let attack = CapsuleSmuggleAttack::connect_ip_metadata_channel(b"GET /admin".to_vec());
        assert_eq!(
            attack.capsules[0].capsule_type,
            capsule_type::ADDRESS_ASSIGN,
            "CONNECT-IP metadata smuggle must ride on ADDRESS_ASSIGN"
        );
    }

    // ── NEW TESTS ─────────────────────────────────────────────────────────

    #[test]
    fn wire_format_address_assign_capsule_starts_with_type_01() {
        // Wire-format invariant for ADDRESS_ASSIGN (type 0x01).
        // A regression that maps the constructor to a wrong type would
        // silently produce misframed bytes on the wire.
        let attack = CapsuleSmuggleAttack::connect_ip_metadata_channel(b"payload".to_vec());
        let bytes = attack.capsules[0].to_bytes();
        let (t, _) = quic_varint_decode(&bytes, 0).expect("type varint");
        assert_eq!(t, capsule_type::ADDRESS_ASSIGN);
    }

    #[test]
    fn wire_format_unknown_type_carries_caller_chosen_type() {
        // Wire-format: unknown_type_smuggle must use exactly the
        // caller-supplied type value on the wire. A regression that
        // rounds or remaps the type value would silently change the
        // probe semantics.
        let attack = CapsuleSmuggleAttack::unknown_type_smuggle(0xab_cdef, b"x".to_vec());
        let bytes = attack.capsules[0].to_bytes();
        let (t, _) = quic_varint_decode(&bytes, 0).expect("type varint");
        assert_eq!(t, 0xab_cdef, "unknown type must be preserved verbatim");
    }

    #[test]
    fn capsule_at_exact_max_value_bytes_not_truncated() {
        // Boundary: value of exactly MAX_CAPSULE_VALUE_BYTES must pass
        // through the constructor unchanged (not off-by-one truncation).
        let payload = vec![b'Z'; MAX_CAPSULE_VALUE_BYTES];
        let cap = CapsuleFrame::new(capsule_type::DATAGRAM, payload.clone());
        assert_eq!(
            cap.value.len(),
            MAX_CAPSULE_VALUE_BYTES,
            "value at exact cap must not be truncated"
        );
    }

    #[test]
    fn overdeclared_length_with_zero_actual_payload() {
        // Boundary: empty value + overdeclared > 0 is the extreme case.
        // Receiver sees a length varint claiming N bytes but finds 0.
        let cap = CapsuleFrame::new(capsule_type::DATAGRAM, vec![])
            .with_overdeclared_length(500);
        let bytes = cap.to_bytes();
        let (_t, n1) = quic_varint_decode(&bytes, 0).unwrap();
        let (l, n2) = quic_varint_decode(&bytes, n1).unwrap();
        assert_eq!(l, 500, "declared length must be 500");
        assert_eq!(
            bytes.len() - (n1 + n2),
            0,
            "zero actual bytes emitted after the length varint"
        );
    }

    #[test]
    fn all_variants_each_carries_a_distinct_canary() {
        // Anti-rig: every attack in the sweep must get its own canary
        // token so the operator can attribute server responses to a
        // specific variant. A regression that re-uses a canary across
        // all attacks would collapse correlation.
        let attacks = all_variants(b"probe-data");
        let tokens: std::collections::HashSet<String> =
            attacks.iter().map(|a| a.canary.token.clone()).collect();
        assert_eq!(
            tokens.len(),
            attacks.len(),
            "all_variants must assign a distinct canary to each attack"
        );
    }

    #[test]
    fn to_frame_set_stream_id_sentinel_is_zero() {
        // §9 WIRING pin: capsules ride outside any request stream;
        // stream_id=0 is the agreed sentinel for "no specific stream."
        // A regression that plumbs in a non-zero default would break
        // downstream routing logic that relies on this convention.
        for attack in all_variants(b"x") {
            let fs = attack.to_frame_set();
            for frame in &fs.frames {
                assert_eq!(
                    frame.stream_id, 0,
                    "capsule EvasionFrame must carry stream_id=0 sentinel, got {} for {:?}",
                    frame.stream_id, attack.variant
                );
            }
        }
    }

    #[test]
    fn concurrent_construction_no_panics_and_all_canaries_unique() {
        // §12 TESTING — concurrent: 50 threads each construct an
        // opaque_datagram_payload; canaries must all be distinct.
        use std::sync::{Arc, Mutex};
        use std::thread;

        let tokens: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let threads: Vec<_> = (0..50)
            .map(|_| {
                let tokens = Arc::clone(&tokens);
                thread::spawn(move || {
                    let a = CapsuleSmuggleAttack::opaque_datagram_payload(vec![1, 2, 3]);
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
            "50 concurrent attack constructions must each produce a unique canary"
        );
    }

    #[test]
    fn nested_capsule_outer_value_length_varint_matches_inner_byte_count() {
        // Wire-format invariant: the outer capsule's declared length
        // must exactly equal the byte count of the serialized inner
        // capsule. If it doesn't, the receiver will misparse the stream.
        let attack = CapsuleSmuggleAttack::nested_capsule(0x4242, b"hello".to_vec());
        let outer = &attack.capsules[0];
        let bytes = outer.to_bytes();
        let (_outer_type, n1) = quic_varint_decode(&bytes, 0).unwrap();
        let (outer_len, _n2) = quic_varint_decode(&bytes, n1).unwrap();
        assert_eq!(
            outer_len as usize,
            outer.value.len(),
            "outer capsule declared length must equal inner-capsule byte count"
        );
    }

    #[test]
    fn to_bytes_does_not_panic_on_direct_struct_construction_with_large_value() {
        // Robustness: CapsuleFrame fields are pub, so callers can bypass
        // CapsuleFrame::new() and set value to an arbitrarily large vec.
        // The saturating_add fix in to_bytes() must prevent a capacity
        // overflow panic. We use a moderately large value (not usize::MAX
        // because allocating that much memory is the test infrastructure's
        // problem) to verify the code path is exercised.
        // This test specifically protects the `with_capacity(saturating_add)` fix.
        let big_value = vec![0xAAu8; MAX_CAPSULE_VALUE_BYTES * 10];
        let frame = CapsuleFrame {
            capsule_type: capsule_type::DATAGRAM,
            value: big_value.clone(),
            overdeclared_length: None,
        };
        // Must not panic — capacity hint overflow was the old bug.
        let bytes = frame.to_bytes();
        // Type + length varints must precede the value bytes.
        let (t, n1) = quic_varint_decode(&bytes, 0).expect("type varint");
        let (l, _n2) = quic_varint_decode(&bytes, n1).expect("length varint");
        assert_eq!(t, capsule_type::DATAGRAM);
        assert_eq!(l as usize, big_value.len(), "direct-constructed frame length must reflect full value");
    }

    #[test]
    fn to_bytes_with_overdeclared_length_and_direct_struct_large_value() {
        // Anti-rig: overdeclared_length path through to_bytes encodes the
        // declared value as a QUIC varint. QUIC varints are 62-bit (max
        // encodable = 0x3FFF_FFFF_FFFF_FFFF = 4611686018427387903 for the
        // 8-byte form). u64::MAX (0xFFFF…) is truncated by the 2-bit
        // length-flag mask in the encoder. Pin the actual round-trip value
        // so a change to varint encoding surfaces here immediately.
        let big = vec![0xBBu8; MAX_CAPSULE_VALUE_BYTES * 5];
        let frame = CapsuleFrame {
            capsule_type: 0x10_0000,
            value: big.clone(),
            overdeclared_length: Some(u64::MAX),
        };
        let bytes = frame.to_bytes();
        let (_t, n1) = quic_varint_decode(&bytes, 0).expect("type varint");
        let (declared, n2) = quic_varint_decode(&bytes, n1).expect("length varint");
        // QUIC 8-byte varint max: 0xC0 prefix encodes the 62-bit payload;
        // u64::MAX round-trips as 0x3FFF_FFFF_FFFF_FFFF.
        const QUIC_VARINT_MAX: u64 = 0x3FFF_FFFF_FFFF_FFFF;
        assert_eq!(
            declared, QUIC_VARINT_MAX,
            "overdeclared u64::MAX saturates to QUIC 8-byte varint ceiling"
        );
        // Actual emitted value bytes = big.len() regardless of declared.
        assert_eq!(
            bytes.len() - n1 - n2,
            big.len(),
            "only actual value bytes are emitted after length varint"
        );
    }

    #[test]
    fn capsule_one_past_max_value_bytes_is_truncated() {
        // Off-by-one boundary: value.len() == MAX_CAPSULE_VALUE_BYTES + 1
        // must be truncated to MAX_CAPSULE_VALUE_BYTES. A > vs >= regression
        // in new() would let one extra byte through.
        let payload = vec![b'Y'; MAX_CAPSULE_VALUE_BYTES + 1];
        let cap = CapsuleFrame::new(capsule_type::DATAGRAM, payload);
        assert_eq!(
            cap.value.len(),
            MAX_CAPSULE_VALUE_BYTES,
            "value one past cap must be truncated to MAX_CAPSULE_VALUE_BYTES"
        );
    }

    // ── Property tests ────────────────────────────────────────────────────

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        /// An honest capsule is faithful: wire `type` and `length` varints decode
        /// to the capsule type and the (possibly truncated) value length, and the
        /// value bytes follow verbatim.
        #[test]
        fn prop_capsule_honest_roundtrips(
            ty in 0u64..(1u64 << 62),
            value in proptest::collection::vec(any::<u8>(), 0..1024),
        ) {
            let f = CapsuleFrame::new(ty, value);
            prop_assert!(f.value.len() <= MAX_CAPSULE_VALUE_BYTES);
            let b = f.to_bytes();
            let (t, n1) = quic_varint_decode(&b, 0).unwrap();
            prop_assert_eq!(t, ty);
            let (len, n2) = quic_varint_decode(&b, n1).unwrap();
            prop_assert_eq!(len as usize, f.value.len());
            prop_assert_eq!(&b[n1 + n2..], &f.value[..]);
        }

        /// An over-declared-length capsule is the smuggle: the wire `length`
        /// varint asserts MORE bytes than are present. The decoded length must
        /// equal the declared lie, while the real trailing bytes equal the
        /// (smaller) value — that gap is the attack and must be preserved exactly.
        #[test]
        fn prop_capsule_overdeclared_length_lies_on_the_wire(
            value in proptest::collection::vec(any::<u8>(), 0..512),
            declared in 0u64..(1u64 << 40),
        ) {
            let f = CapsuleFrame::new(capsule_type::DATAGRAM, value)
                .with_overdeclared_length(declared);
            let b = f.to_bytes();
            let (_t, n1) = quic_varint_decode(&b, 0).unwrap();
            let (wire_len, n2) = quic_varint_decode(&b, n1).unwrap();
            prop_assert_eq!(wire_len, declared, "wire length must carry the declared lie");
            prop_assert_eq!(&b[n1 + n2..], &f.value[..]);
        }

        /// Over-cap values are truncated by the constructor, never emitted oversized.
        #[test]
        fn prop_capsule_truncates_oversized_value(extra in 0usize..256) {
            let big = vec![0x5Au8; MAX_CAPSULE_VALUE_BYTES + extra];
            prop_assert_eq!(
                CapsuleFrame::new(capsule_type::DATAGRAM, big).value.len(),
                MAX_CAPSULE_VALUE_BYTES
            );
        }
    }
}
