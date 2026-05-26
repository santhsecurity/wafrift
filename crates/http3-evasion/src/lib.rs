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

pub mod qpack;
pub mod quic_cid;
pub mod zero_rtt;
pub mod stream_priority;
pub mod mtu_fragmentation;

pub use qpack::{QpackDesyncAttack, QpackDesyncVariant, QpackEncoder};
pub use quic_cid::{CidRotationStrategy, ConnectionIdGenerator};
pub use zero_rtt::{ZeroRttReplayBuilder, ZeroRttPayload};
pub use stream_priority::{H3PriorityAttack, H3PriorityVariant, PriorityUpdateFrame};
pub use mtu_fragmentation::{MtuFragmentationAttack, QuicCryptoFragment};

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
}

impl EvasionTechnique {
    pub fn all() -> &'static [EvasionTechnique] {
        &[
            Self::QpackDesync,
            Self::CidRotation,
            Self::ZeroRttReplay,
            Self::StreamPriorityTopology,
            Self::MtuFragmentation,
        ]
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::QpackDesync => "QPACK dynamic table desync — forged encoder instructions corrupt WAF decoder",
            Self::CidRotation => "QUIC CID rotation — shards one session across multiple WAF state buckets",
            Self::ZeroRttReplay => "0-RTT replay — application data before TLS handshake; WAF inspection blind spot",
            Self::StreamPriorityTopology => "HTTP/3 PRIORITY_UPDATE topology — confuses WAF multiplexing reassemblers",
            Self::MtuFragmentation => "QUIC MTU fragmentation — below-threshold fragment sizes evade DPI reassembly",
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
        assert_eq!(EvasionTechnique::all().len(), 5);
    }
}
