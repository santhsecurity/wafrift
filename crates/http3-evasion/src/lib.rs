//! # wafrift-http3-evasion — HTTP/3 + QUIC WAF evasion primitives
//!
//! HTTP/3 (RFC 9114) and its QUIC transport (RFC 9000) introduce a new attack
//! surface that most WAFs handle poorly or not at all (2025 state of the art):
//!
//! - **QPACK dynamic table desync** — inject forged encoder instructions that
//!   corrupt the WAF's QPACK decoder table so header fields are misread
//! - **0-RTT replay attack** — replay application data before the TLS handshake
//!   completes; WAFs that enforce TLS-complete before inspecting HTTP are blind
//! - **Connection ID rotation** — rotate QUIC Connection IDs between requests
//!   to shard one logical session across multiple WAF connection-state buckets
//! - **Stream priority topology** — send PRIORITY_UPDATE frames (RFC 9218)
//!   in pathological orders that confuse WAF multiplexing reassemblers
//! - **Datagram path MTU games** — fragment QUIC CRYPTO frames across UDP
//!   packets at sizes that reassemble correctly at the server but confuse
//!   WAF deep-packet inspection that doesn't handle fragmented QUIC
//!
//! ## Architecture
//!
//! This crate is **pure data-plane**: it generates wire-format bytes and
//! structured evasion descriptors. It does NOT open sockets; the wafrift
//! transport layer or an external QUIC client (e.g. `quinn`, `msquic`)
//! handles the actual I/O.
//!
//! The design follows the same pattern as `wafrift-smuggling`:
//! - Builders produce `EvasionFrameSet` values
//! - Each `EvasionFrame` is a byte vector + metadata
//! - The caller feeds frames to the QUIC stack in order

pub mod capsule;
pub mod mtu_fragmentation;
pub mod qpack;
pub mod quic_cid;
pub mod quic_datagram;
pub mod stream_priority;
pub mod zero_rtt;

pub use capsule::{CapsuleFrame, CapsuleSmuggleAttack, CapsuleSmuggleVariant};
pub use mtu_fragmentation::{MtuFragmentationAttack, QuicCryptoFragment};
pub use qpack::{QpackDesyncAttack, QpackDesyncVariant, QpackEncoder};
pub use quic_cid::{CidRotationStrategy, ConnectionIdGenerator};
pub use quic_datagram::{QuicDatagramAttack, QuicDatagramFrame, QuicDatagramVariant};
pub use stream_priority::{H3PriorityAttack, H3PriorityVariant, PriorityUpdateFrame};
pub use zero_rtt::{ZeroRttPayload, ZeroRttReplayBuilder};

/// A single wire-format frame to inject into the QUIC/HTTP3 stream.
#[derive(Debug, Clone)]
pub struct EvasionFrame {
    /// Raw bytes to write to the QUIC stream or datagram socket.
    pub bytes: Vec<u8>,
    /// Human-readable description of what this frame does.
    pub description: String,
    /// Which evasion technique this frame belongs to.
    pub technique: EvasionTechnique,
    /// QUIC stream ID this frame belongs to (0 = control stream).
    pub stream_id: u64,
}

/// A complete set of evasion frames for one bypass attempt.
#[derive(Debug, Clone)]
pub struct EvasionFrameSet {
    pub frames: Vec<EvasionFrame>,
    pub technique: EvasionTechnique,
    pub description: String,
}

/// Enumeration of HTTP/3 + QUIC evasion techniques implemented in this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum EvasionTechnique {
    /// QPACK dynamic table poisoning via forged encoder instructions.
    QpackDesync,
    /// QUIC Connection ID rotation between requests to shard WAF state.
    CidRotation,
    /// 0-RTT early data replay — application data sent before handshake completes.
    ZeroRttReplay,
    /// HTTP/3 PRIORITY_UPDATE frame topology attacks (RFC 9218).
    StreamPriorityTopology,
    /// QUIC UDP fragmentation below WAF reassembly threshold.
    MtuFragmentation,
    /// HTTP Capsule Protocol (RFC 9297) smuggling — payload bytes
    /// ride inside capsules whose framing is opaque to HTTP-semantic
    /// WAFs but parsed by CONNECT-UDP / CONNECT-IP / WebTransport
    /// terminators on the origin side.
    CapsuleProtocolSmuggle,
    /// QUIC unreliable datagram (RFC 9221) smuggling — payload rides
    /// in DATAGRAM frames outside any HTTP/3 stream. WAFs that
    /// inspect HTTP/3 STREAM frames at the HTTP semantic layer don't
    /// see DATAGRAM bytes; WebTransport / CONNECT-UDP / MASQUE
    /// terminators on the origin parse them as application data.
    QuicDatagramSmuggle,
}

impl EvasionTechnique {
    pub fn all() -> &'static [EvasionTechnique] {
        &[
            Self::QpackDesync,
            Self::CidRotation,
            Self::ZeroRttReplay,
            Self::StreamPriorityTopology,
            Self::MtuFragmentation,
            Self::CapsuleProtocolSmuggle,
            Self::QuicDatagramSmuggle,
        ]
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::QpackDesync => {
                "QPACK dynamic table desync — forged encoder instructions corrupt WAF decoder"
            }
            Self::CidRotation => {
                "QUIC CID rotation — shards one session across multiple WAF state buckets"
            }
            Self::ZeroRttReplay => {
                "0-RTT replay — application data before TLS handshake; WAF inspection blind spot"
            }
            Self::StreamPriorityTopology => {
                "HTTP/3 PRIORITY_UPDATE topology — confuses WAF multiplexing reassemblers"
            }
            Self::MtuFragmentation => {
                "QUIC MTU fragmentation — below-threshold fragment sizes evade DPI reassembly"
            }
            Self::CapsuleProtocolSmuggle => {
                "HTTP Capsule Protocol (RFC 9297) — payload rides inside opaque capsules; WAF sees flat body, CONNECT-UDP/IP/WebTransport origin parses values"
            }
            Self::QuicDatagramSmuggle => {
                "QUIC DATAGRAM (RFC 9221) — payload outside any HTTP/3 stream; WAF inspecting HTTP semantic misses it entirely"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_techniques_have_descriptions() {
        for tech in EvasionTechnique::all() {
            assert!(!tech.description().is_empty());
        }
    }

    #[test]
    fn all_techniques_count() {
        assert_eq!(EvasionTechnique::all().len(), 7);
    }

    // ── descriptions are distinct ─────────────────────────────────────────

    #[test]
    fn all_techniques_descriptions_are_distinct() {
        let descs: Vec<&str> = EvasionTechnique::all()
            .iter()
            .map(|t| t.description())
            .collect();
        let mut seen = std::collections::HashSet::new();
        for desc in &descs {
            assert!(seen.insert(*desc), "duplicate description detected: {desc}");
        }
    }

    // ── all() covers every enum variant ──────────────────────────────────

    #[test]
    fn all_techniques_covers_every_variant() {
        // Anti-rig: if a new variant is added to EvasionTechnique but not
        // to all(), this test catches it via the count + exhaustive variant list.
        let all = EvasionTechnique::all();
        // Verify every concrete variant is present.
        let has = |t: EvasionTechnique| all.contains(&t);
        assert!(
            has(EvasionTechnique::QpackDesync),
            "QpackDesync missing from all()"
        );
        assert!(
            has(EvasionTechnique::CidRotation),
            "CidRotation missing from all()"
        );
        assert!(
            has(EvasionTechnique::ZeroRttReplay),
            "ZeroRttReplay missing from all()"
        );
        assert!(
            has(EvasionTechnique::StreamPriorityTopology),
            "StreamPriorityTopology missing from all()"
        );
        assert!(
            has(EvasionTechnique::MtuFragmentation),
            "MtuFragmentation missing from all()"
        );
        assert!(
            has(EvasionTechnique::CapsuleProtocolSmuggle),
            "CapsuleProtocolSmuggle missing from all()"
        );
        assert!(
            has(EvasionTechnique::QuicDatagramSmuggle),
            "QuicDatagramSmuggle missing from all()"
        );
    }

    // ── serde round-trip ──────────────────────────────────────────────────

    #[test]
    fn evasion_technique_serde_roundtrip() {
        for &tech in EvasionTechnique::all() {
            let json = serde_json::to_string(&tech).expect("serialize");
            let back: EvasionTechnique = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(tech, back, "serde roundtrip failed for {tech:?}: {json}");
        }
    }

    // ── EvasionFrame construction ─────────────────────────────────────────

    #[test]
    fn evasion_frame_fields_are_accessible() {
        let frame = EvasionFrame {
            bytes: vec![0x01, 0x02],
            description: "test frame".to_string(),
            technique: EvasionTechnique::QpackDesync,
            stream_id: 4,
        };
        assert_eq!(frame.bytes, &[0x01, 0x02]);
        assert_eq!(frame.description, "test frame");
        assert_eq!(frame.technique, EvasionTechnique::QpackDesync);
        assert_eq!(frame.stream_id, 4);
    }

    // ── EvasionFrameSet construction ──────────────────────────────────────

    #[test]
    fn evasion_frame_set_fields_are_accessible() {
        let fs = EvasionFrameSet {
            frames: vec![],
            technique: EvasionTechnique::CidRotation,
            description: "burst".to_string(),
        };
        assert!(fs.frames.is_empty());
        assert_eq!(fs.technique, EvasionTechnique::CidRotation);
        assert_eq!(fs.description, "burst");
    }

    // ── EvasionTechnique PartialEq / Hash ────────────────────────────────

    #[test]
    fn evasion_technique_eq_and_hash_are_consistent() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        for &t in EvasionTechnique::all() {
            set.insert(t);
        }
        assert_eq!(set.len(), 7, "all 7 variants must hash distinctly");
        // Inserting the same variant again must not grow the set.
        set.insert(EvasionTechnique::QpackDesync);
        assert_eq!(set.len(), 7);
    }
}
