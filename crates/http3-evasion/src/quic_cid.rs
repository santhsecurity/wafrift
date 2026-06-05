//! QUIC Connection ID rotation for WAF session-state sharding.
//!
//! ## Attack surface
//!
//! QUIC (RFC 9000) uses Connection IDs (CIDs) to identify logical connections.
//! Unlike TCP, a single QUIC connection can have multiple active CIDs in flight
//! simultaneously (RFC 9000 §9.5 "Connection ID Migration").
//!
//! Many WAFs use the QUIC CID as a session-state key:
//! - Rate-limiting state is keyed on CID
//! - WAF inspection state (decoded headers, payload parsing context) is keyed on CID
//! - Bot detection heuristics track request patterns per-CID
//!
//! By rotating CIDs between requests (or even within a request burst), an
//! attacker can:
//!
//! 1. **Shard rate-limit state** across N CIDs, multiplying the effective
//!    rate limit by N
//! 2. **Reset WAF inspection context** — start fresh per-CID WAF state
//!    so sliding-window anomaly detectors see each request as the first
//! 3. **Confuse bot-score accumulators** — the WAF scores each CID
//!    independently; rotating resets the score to zero before threshold

use crate::{EvasionFrame, EvasionFrameSet, EvasionTechnique};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// Strategy for rotating QUIC Connection IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CidRotationStrategy {
    /// Rotate every N requests.
    EveryN(usize),
    /// Rotate before each request (maximum sharding).
    PerRequest,
    /// Rotate randomly with probability p (0.0–1.0).
    Probabilistic { p_hundredths: u8 },
    /// Rotate after sending a payload that would score high at the WAF.
    PostPayload,
}

/// QUIC Connection ID generator.
///
/// Produces RFC 9000-compliant Connection IDs (1–20 bytes).
/// The default length is 8 bytes, which is the length Chrome 131 uses
/// for initial CIDs and is statistically indistinguishable from real traffic.
#[derive(Debug, Clone)]
pub struct ConnectionIdGenerator {
    /// Length of generated CIDs in bytes (1–20 per RFC 9000).
    cid_len: usize,
    rng: StdRng,
    /// Sequence number for the next CID (embedded in the first 4 bytes
    /// to make CIDs traceable for the attacker without being guessable).
    seq: u32,
}

impl ConnectionIdGenerator {
    pub fn new(cid_len: usize, seed: u64) -> Self {
        assert!((1..=20).contains(&cid_len), "CID length must be 1-20 bytes");
        Self {
            cid_len,
            rng: StdRng::seed_from_u64(seed),
            seq: 0,
        }
    }

    /// Generate a new Connection ID.
    ///
    /// The first 4 bytes encode the sequence number (for attacker traceability)
    /// XOR'd with a random mask. Remaining bytes are random.
    pub fn generate(&mut self) -> ConnectionId {
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);
        let mut bytes = vec![0u8; self.cid_len];
        // Fill with random bytes first.
        for b in bytes.iter_mut() {
            *b = self.rng.r#gen::<u8>();
        }
        // Embed sequence number in first 4 bytes (if CID is long enough).
        if self.cid_len >= 4 {
            let seq_bytes = seq.to_be_bytes();
            // XOR with random so the sequence is not trivially visible.
            for (i, s) in seq_bytes.iter().enumerate() {
                bytes[i] ^= s;
            }
        }
        ConnectionId {
            bytes,
            sequence: seq,
        }
    }

    /// Generate a batch of N unique Connection IDs.
    pub fn generate_batch(&mut self, n: usize) -> Vec<ConnectionId> {
        (0..n).map(|_| self.generate()).collect()
    }

    /// Build a QUIC NEW_CONNECTION_ID frame (RFC 9000 §19.15) announcing a
    /// new CID to the peer.
    ///
    /// Frame type = 0x18.
    /// Format: type(1) | sequence_number(varint) | retire_prior_to(varint) |
    ///          length(1) | connection_id(len) | stateless_reset_token(16)
    pub fn new_connection_id_frame(&mut self, retire_prior_to: u64) -> EvasionFrame {
        let cid = self.generate();
        let seq = cid.sequence as u64;
        let mut bytes = Vec::new();
        bytes.push(0x18); // frame type
        bytes.extend_from_slice(&quic_varint(seq));
        bytes.extend_from_slice(&quic_varint(retire_prior_to));
        bytes.push(cid.bytes.len() as u8);
        bytes.extend_from_slice(&cid.bytes);
        // Stateless reset token: 16 random bytes (not used for actual reset here).
        let mut token = [0u8; 16];
        for b in token.iter_mut() {
            *b = self.rng.r#gen::<u8>();
        }
        bytes.extend_from_slice(&token);

        EvasionFrame {
            description: format!(
                "QUIC NEW_CONNECTION_ID seq={} retire_prior_to={} cid={}",
                seq,
                retire_prior_to,
                cid.hex()
            ),
            technique: EvasionTechnique::CidRotation,
            stream_id: 0,
            bytes,
        }
    }

    /// Build a QUIC RETIRE_CONNECTION_ID frame (RFC 9000 §19.16).
    ///
    /// Frame type = 0x19.
    /// Format: type(1) | sequence_number(varint)
    pub fn retire_connection_id_frame(&self, sequence: u64) -> EvasionFrame {
        let mut bytes = Vec::new();
        bytes.push(0x19); // frame type
        bytes.extend_from_slice(&quic_varint(sequence));
        EvasionFrame {
            bytes,
            description: format!("QUIC RETIRE_CONNECTION_ID seq={}", sequence),
            technique: EvasionTechnique::CidRotation,
            stream_id: 0,
        }
    }

    /// Build a CID rotation burst: N new CID announcements + retirement of
    /// the current CID, producing an `EvasionFrameSet`.
    pub fn rotation_burst(&mut self, n_new_cids: usize, current_cid_seq: u64) -> EvasionFrameSet {
        let mut frames = Vec::new();
        // Retire the current CID.
        frames.push(self.retire_connection_id_frame(current_cid_seq));
        // Announce N new CIDs.
        for _ in 0..n_new_cids {
            frames.push(self.new_connection_id_frame(current_cid_seq + 1));
        }
        EvasionFrameSet {
            frames,
            technique: EvasionTechnique::CidRotation,
            description: format!(
                "CID rotation burst: retire seq={}, announce {} new CIDs",
                current_cid_seq, n_new_cids
            ),
        }
    }
}

/// A QUIC Connection ID value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionId {
    pub bytes: Vec<u8>,
    pub sequence: u32,
}

impl ConnectionId {
    pub fn hex(&self) -> String {
        self.bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

// ── QUIC variable-length integer encoding (RFC 9000 §16) ─────────────────

/// Encode a QUIC variable-length integer.
///
/// Encoding:
/// - 0..=63: 1 byte, `00` prefix
/// - 64..=16383: 2 bytes, `01` prefix
/// - 16384..=1073741823: 4 bytes, `10` prefix
/// - 1073741824..=4611686018427387903: 8 bytes, `11` prefix
pub fn quic_varint(v: u64) -> Vec<u8> {
    if v < 64 {
        vec![v as u8]
    } else if v < 16384 {
        vec![0x40 | ((v >> 8) as u8), (v & 0xFF) as u8]
    } else if v < 1_073_741_824 {
        vec![
            0x80 | ((v >> 24) as u8),
            ((v >> 16) & 0xFF) as u8,
            ((v >> 8) & 0xFF) as u8,
            (v & 0xFF) as u8,
        ]
    } else {
        vec![
            0xC0 | ((v >> 56) as u8),
            ((v >> 48) & 0xFF) as u8,
            ((v >> 40) & 0xFF) as u8,
            ((v >> 32) & 0xFF) as u8,
            ((v >> 24) & 0xFF) as u8,
            ((v >> 16) & 0xFF) as u8,
            ((v >> 8) & 0xFF) as u8,
            (v & 0xFF) as u8,
        ]
    }
}

/// Decode a QUIC variable-length integer from `bytes` at `pos`.
/// Returns (value, bytes_consumed).
pub fn quic_varint_decode(bytes: &[u8], pos: usize) -> Option<(u64, usize)> {
    if pos >= bytes.len() {
        return None;
    }
    let first = bytes[pos];
    let len_flag = first >> 6;
    match len_flag {
        0 => Some(((first & 0x3F) as u64, 1)),
        1 => {
            if pos + 1 >= bytes.len() { return None; }
            let val = (((first & 0x3F) as u64) << 8) | bytes[pos + 1] as u64;
            Some((val, 2))
        }
        2 => {
            if pos + 3 >= bytes.len() { return None; }
            let val = (((first & 0x3F) as u64) << 24)
                | ((bytes[pos + 1] as u64) << 16)
                | ((bytes[pos + 2] as u64) << 8)
                | (bytes[pos + 3] as u64);
            Some((val, 4))
        }
        3 => {
            if pos + 7 >= bytes.len() { return None; }
            let val = (((first & 0x3F) as u64) << 56)
                | ((bytes[pos + 1] as u64) << 48)
                | ((bytes[pos + 2] as u64) << 40)
                | ((bytes[pos + 3] as u64) << 32)
                | ((bytes[pos + 4] as u64) << 24)
                | ((bytes[pos + 5] as u64) << 16)
                | ((bytes[pos + 6] as u64) << 8)
                | (bytes[pos + 7] as u64);
            Some((val, 8))
        }
        _ => None,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── QUIC varint encoding ──────────────────────────────────────────────

    #[test]
    fn quic_varint_1byte_range() {
        // 0..=63 → 1 byte with 00 prefix
        for v in [0u64, 1, 32, 63] {
            let enc = quic_varint(v);
            assert_eq!(enc.len(), 1, "v={} must encode as 1 byte", v);
            assert_eq!(enc[0] >> 6, 0, "1-byte varint must have 00 prefix");
            assert_eq!(enc[0], v as u8);
        }
    }

    #[test]
    fn quic_varint_2byte_range() {
        let enc = quic_varint(64);
        assert_eq!(enc.len(), 2);
        assert_eq!(enc[0] >> 6, 1, "2-byte varint must have 01 prefix");
    }

    #[test]
    fn quic_varint_4byte_range() {
        let enc = quic_varint(16384);
        assert_eq!(enc.len(), 4);
        assert_eq!(enc[0] >> 6, 2, "4-byte varint must have 10 prefix");
    }

    #[test]
    fn quic_varint_8byte_range() {
        let enc = quic_varint(1_073_741_824);
        assert_eq!(enc.len(), 8);
        assert_eq!(enc[0] >> 6, 3, "8-byte varint must have 11 prefix");
    }

    #[test]
    fn quic_varint_roundtrip_1byte() {
        for v in [0u64, 1, 63] {
            let enc = quic_varint(v);
            let (decoded, consumed) = quic_varint_decode(&enc, 0).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(consumed, 1);
        }
    }

    #[test]
    fn quic_varint_roundtrip_2byte() {
        let v = 1000u64;
        let enc = quic_varint(v);
        let (decoded, consumed) = quic_varint_decode(&enc, 0).unwrap();
        assert_eq!(decoded, v);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn quic_varint_roundtrip_4byte() {
        let v = 100_000u64;
        let enc = quic_varint(v);
        let (decoded, consumed) = quic_varint_decode(&enc, 0).unwrap();
        assert_eq!(decoded, v);
        assert_eq!(consumed, 4);
    }

    #[test]
    fn quic_varint_roundtrip_8byte() {
        let v = 2_000_000_000u64;
        let enc = quic_varint(v);
        let (decoded, consumed) = quic_varint_decode(&enc, 0).unwrap();
        assert_eq!(decoded, v);
        assert_eq!(consumed, 8);
    }

    // ── ConnectionIdGenerator ─────────────────────────────────────────────

    #[test]
    fn cid_generator_produces_correct_length() {
        let mut cid_gen = ConnectionIdGenerator::new(8, 42);
        let cid = cid_gen.generate();
        assert_eq!(cid.bytes.len(), 8);
    }

    #[test]
    fn cid_generator_sequences_increment() {
        let mut cid_gen = ConnectionIdGenerator::new(8, 0);
        let c1 = cid_gen.generate();
        let c2 = cid_gen.generate();
        assert_eq!(c1.sequence, 0);
        assert_eq!(c2.sequence, 1);
    }

    #[test]
    fn cid_generator_produces_unique_cids() {
        let mut cid_gen = ConnectionIdGenerator::new(8, 0);
        let c1 = cid_gen.generate();
        let c2 = cid_gen.generate();
        assert_ne!(c1.bytes, c2.bytes, "CIDs must be unique");
    }

    #[test]
    fn cid_hex_is_correct_length() {
        let cid = ConnectionId {
            bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
            sequence: 0,
        };
        assert_eq!(cid.hex(), "deadbeef");
    }

    #[test]
    fn cid_batch_size_matches_request() {
        let mut cid_gen = ConnectionIdGenerator::new(8, 77);
        let batch = cid_gen.generate_batch(10);
        assert_eq!(batch.len(), 10);
    }

    #[test]
    fn cid_batch_all_unique() {
        let mut cid_gen = ConnectionIdGenerator::new(8, 1);
        let batch = cid_gen.generate_batch(20);
        let hexes: Vec<_> = batch.iter().map(|c| c.hex()).collect();
        let unique: std::collections::HashSet<_> = hexes.iter().collect();
        assert_eq!(unique.len(), hexes.len(), "all CIDs in batch must be unique");
    }

    // ── NEW_CONNECTION_ID frame ───────────────────────────────────────────

    #[test]
    fn new_connection_id_frame_type_byte() {
        let mut cid_gen = ConnectionIdGenerator::new(8, 42);
        let frame = cid_gen.new_connection_id_frame(0);
        assert_eq!(frame.bytes[0], 0x18, "NEW_CONNECTION_ID frame type must be 0x18");
    }

    #[test]
    fn new_connection_id_frame_length() {
        let mut cid_gen = ConnectionIdGenerator::new(8, 42);
        let frame = cid_gen.new_connection_id_frame(0);
        // 1 type + varint(seq) + varint(retire) + 1 len + 8 cid + 16 token = 28+ bytes
        assert!(frame.bytes.len() >= 28, "frame must be at least 28 bytes");
    }

    #[test]
    fn retire_connection_id_frame_type_byte() {
        let cid_gen = ConnectionIdGenerator::new(8, 0);
        let frame = cid_gen.retire_connection_id_frame(5);
        assert_eq!(frame.bytes[0], 0x19, "RETIRE_CONNECTION_ID frame type must be 0x19");
    }

    // ── Rotation burst ────────────────────────────────────────────────────

    #[test]
    fn rotation_burst_frame_count() {
        let mut cid_gen = ConnectionIdGenerator::new(8, 42);
        let fs = cid_gen.rotation_burst(3, 0);
        // 1 retire + 3 new = 4 frames
        assert_eq!(fs.frames.len(), 4);
    }

    #[test]
    fn rotation_burst_first_frame_is_retire() {
        let mut cid_gen = ConnectionIdGenerator::new(8, 42);
        let fs = cid_gen.rotation_burst(2, 7);
        assert_eq!(fs.frames[0].bytes[0], 0x19, "first frame must be RETIRE_CONNECTION_ID");
    }

    #[test]
    fn rotation_burst_subsequent_frames_are_new_cid() {
        let mut cid_gen = ConnectionIdGenerator::new(8, 42);
        let fs = cid_gen.rotation_burst(3, 0);
        for frame in &fs.frames[1..] {
            assert_eq!(frame.bytes[0], 0x18, "subsequent frames must be NEW_CONNECTION_ID");
        }
    }

    #[test]
    fn cid_1_byte_is_allowed() {
        let mut cid_gen = ConnectionIdGenerator::new(1, 0);
        let cid = cid_gen.generate();
        assert_eq!(cid.bytes.len(), 1);
    }

    #[test]
    fn cid_20_bytes_is_allowed() {
        let mut cid_gen = ConnectionIdGenerator::new(20, 0);
        let cid = cid_gen.generate();
        assert_eq!(cid.bytes.len(), 20);
    }

    // ── quic_varint exact boundary values ─────────────────────────────────

    #[test]
    fn quic_varint_boundary_63_is_1byte() {
        // 63 is the maximum value for 1-byte encoding (0..=63).
        let enc = quic_varint(63);
        assert_eq!(enc.len(), 1, "63 must encode in 1 byte");
        assert_eq!(enc[0], 63);
        assert_eq!(enc[0] >> 6, 0, "must have 00 prefix");
    }

    #[test]
    fn quic_varint_boundary_64_is_2byte() {
        // 64 is the first value that requires 2-byte encoding.
        let enc = quic_varint(64);
        assert_eq!(enc.len(), 2, "64 must encode in 2 bytes");
        assert_eq!(enc[0] >> 6, 1, "must have 01 prefix");
    }

    #[test]
    fn quic_varint_boundary_16383_is_2byte() {
        // 16383 is the maximum value for 2-byte encoding.
        let enc = quic_varint(16383);
        assert_eq!(enc.len(), 2, "16383 must encode in 2 bytes");
        assert_eq!(enc[0] >> 6, 1, "must have 01 prefix");
    }

    #[test]
    fn quic_varint_boundary_16384_is_4byte() {
        // 16384 is the first value that requires 4-byte encoding.
        let enc = quic_varint(16384);
        assert_eq!(enc.len(), 4, "16384 must encode in 4 bytes");
        assert_eq!(enc[0] >> 6, 2, "must have 10 prefix");
    }

    #[test]
    fn quic_varint_boundary_1073741823_is_4byte() {
        // 1_073_741_823 = 2^30 - 1, maximum for 4-byte encoding.
        let enc = quic_varint(1_073_741_823);
        assert_eq!(enc.len(), 4, "1_073_741_823 must encode in 4 bytes");
        assert_eq!(enc[0] >> 6, 2, "must have 10 prefix");
    }

    #[test]
    fn quic_varint_boundary_1073741824_is_8byte() {
        // 1_073_741_824 = 2^30, first value requiring 8-byte encoding.
        let enc = quic_varint(1_073_741_824);
        assert_eq!(enc.len(), 8, "1_073_741_824 must encode in 8 bytes");
        assert_eq!(enc[0] >> 6, 3, "must have 11 prefix");
    }

    #[test]
    fn quic_varint_roundtrip_at_all_boundaries() {
        for v in [0u64, 1, 63, 64, 16383, 16384, 1_073_741_823, 1_073_741_824] {
            let enc = quic_varint(v);
            let (decoded, _) = quic_varint_decode(&enc, 0)
                .unwrap_or_else(|| panic!("roundtrip failed for v={v}"));
            assert_eq!(decoded, v, "boundary value {v} must roundtrip exactly");
        }
    }

    // ── quic_varint_decode error paths ────────────────────────────────────

    #[test]
    fn quic_varint_decode_empty_slice_returns_none() {
        assert!(quic_varint_decode(&[], 0).is_none(), "empty slice must return None");
    }

    #[test]
    fn quic_varint_decode_out_of_bounds_pos_returns_none() {
        let enc = quic_varint(100);
        assert!(
            quic_varint_decode(&enc, enc.len()).is_none(),
            "pos == len must return None"
        );
        assert!(
            quic_varint_decode(&enc, usize::MAX.wrapping_sub(1)).is_none(),
            "large pos must return None"
        );
    }

    #[test]
    fn quic_varint_decode_truncated_2byte_returns_none() {
        // A 2-byte varint (01 prefix) needs 2 bytes but we only give 1.
        let bytes = &[0x40u8]; // 01xxxxxx prefix → 2-byte, but no second byte
        assert!(
            quic_varint_decode(bytes, 0).is_none(),
            "truncated 2-byte varint must return None"
        );
    }

    #[test]
    fn quic_varint_decode_truncated_4byte_returns_none() {
        // A 4-byte varint (10 prefix) needs 4 bytes.
        let bytes = &[0x80u8, 0x00u8, 0x00u8]; // only 3 bytes
        assert!(
            quic_varint_decode(bytes, 0).is_none(),
            "truncated 4-byte varint must return None"
        );
    }

    #[test]
    fn quic_varint_decode_truncated_8byte_returns_none() {
        // An 8-byte varint (11 prefix) needs 8 bytes.
        let bytes = &[0xC0u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8]; // only 7 bytes
        assert!(
            quic_varint_decode(bytes, 0).is_none(),
            "truncated 8-byte varint must return None"
        );
    }

    // ── ConnectionIdGenerator sequence wrapping ───────────────────────────

    #[test]
    fn cid_generator_sequence_wraps_at_u32_max() {
        // Manually construct a generator with seq near u32::MAX.
        let mut cid_gen = ConnectionIdGenerator::new(8, 42);
        // Force the sequence to u32::MAX - 1.
        cid_gen.seq = u32::MAX - 1;
        let c1 = cid_gen.generate();
        assert_eq!(c1.sequence, u32::MAX - 1);
        let c2 = cid_gen.generate();
        assert_eq!(c2.sequence, u32::MAX);
        // wrapping_add must bring it back to 0, not panic.
        let c3 = cid_gen.generate();
        assert_eq!(c3.sequence, 0, "sequence must wrap from u32::MAX to 0");
    }

    // ── rotation_burst with 0 new CIDs ───────────────────────────────────

    #[test]
    fn rotation_burst_zero_new_cids_only_retire() {
        let mut cid_gen = ConnectionIdGenerator::new(8, 0);
        let fs = cid_gen.rotation_burst(0, 5);
        // 1 retire frame, 0 new CID frames.
        assert_eq!(fs.frames.len(), 1, "zero new CIDs → only one retire frame");
        assert_eq!(
            fs.frames[0].bytes[0],
            0x19,
            "the single frame must be RETIRE_CONNECTION_ID"
        );
    }

    // ── ConnectionId helpers ──────────────────────────────────────────────

    #[test]
    fn cid_is_empty_only_for_zero_length_bytes() {
        let empty = ConnectionId { bytes: vec![], sequence: 0 };
        let nonempty = ConnectionId { bytes: vec![0x00], sequence: 0 };
        assert!(empty.is_empty());
        assert!(!nonempty.is_empty());
    }

    #[test]
    fn cid_len_matches_bytes_len() {
        let cid = ConnectionId {
            bytes: vec![0xAA, 0xBB, 0xCC],
            sequence: 1,
        };
        assert_eq!(cid.len(), 3);
    }

    #[test]
    fn cid_hex_all_zeros() {
        let cid = ConnectionId {
            bytes: vec![0x00, 0x00, 0x00, 0x00],
            sequence: 0,
        };
        assert_eq!(cid.hex(), "00000000");
    }

    // ── CidRotationStrategy: anti-rig variant pins ────────────────────────

    #[test]
    fn cid_rotation_strategy_every_n_stores_value() {
        let s = CidRotationStrategy::EveryN(7);
        assert!(matches!(s, CidRotationStrategy::EveryN(7)));
    }

    #[test]
    fn cid_rotation_strategy_probabilistic_p_hundredths() {
        let s = CidRotationStrategy::Probabilistic { p_hundredths: 50 };
        assert!(matches!(s, CidRotationStrategy::Probabilistic { p_hundredths: 50 }));
    }

    // ── Property tests ────────────────────────────────────────────────────

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4000))]

        /// Every value in the full valid QUIC-varint domain (0..2^62) survives an
        /// encode→decode round-trip, and the chosen length is the canonical
        /// minimal one for its range (1/2/4/8 bytes per RFC 9000 §16).
        #[test]
        fn prop_varint_roundtrips_full_range(v in 0u64..(1u64 << 62)) {
            let enc = quic_varint(v);
            let (decoded, consumed) = quic_varint_decode(&enc, 0).expect("decode");
            prop_assert_eq!(decoded, v);
            prop_assert_eq!(consumed, enc.len());
            let expected_len = if v < 64 { 1 } else if v < 16384 { 2 }
                else if v < 1_073_741_824 { 4 } else { 8 };
            prop_assert_eq!(enc.len(), expected_len);
            // The 2-bit length prefix must agree with the length.
            let tag = enc[0] >> 6;
            prop_assert_eq!(1usize << tag, enc.len());
        }

        /// Decoding at a non-zero offset reads the varint at that position and
        /// reports bytes consumed relative to it — used by every frame parser.
        #[test]
        fn prop_varint_decode_at_offset(prefix in proptest::collection::vec(any::<u8>(), 0..8), v in 0u64..(1u64 << 62)) {
            let mut buf = prefix.clone();
            buf.extend_from_slice(&quic_varint(v));
            let (decoded, consumed) = quic_varint_decode(&buf, prefix.len()).expect("decode at offset");
            prop_assert_eq!(decoded, v);
            prop_assert_eq!(consumed, quic_varint(v).len());
        }

        /// A generated CID is exactly `cid_len` bytes and sequence numbers
        /// increment from 0; generation is fully determined by the seed.
        #[test]
        fn prop_cid_generate_length_and_sequence(cid_len in 1usize..=20, seed in any::<u64>(), n in 1usize..32) {
            let mut g = ConnectionIdGenerator::new(cid_len, seed);
            let batch = g.generate_batch(n);
            prop_assert_eq!(batch.len(), n);
            for (i, cid) in batch.iter().enumerate() {
                prop_assert_eq!(cid.len(), cid_len);
                prop_assert_eq!(cid.sequence as usize, i);
            }
            // Determinism: a fresh generator with the same seed reproduces it.
            let mut g2 = ConnectionIdGenerator::new(cid_len, seed);
            let batch2 = g2.generate_batch(n);
            prop_assert_eq!(
                batch.iter().map(|c| c.bytes.clone()).collect::<Vec<_>>(),
                batch2.iter().map(|c| c.bytes.clone()).collect::<Vec<_>>()
            );
        }

        /// A NEW_CONNECTION_ID frame is well-formed: type 0x18, decodable seq and
        /// retire_prior_to varints, a length byte matching the embedded CID, and a
        /// trailing 16-byte stateless-reset token.
        #[test]
        fn prop_new_connection_id_frame_is_parseable(cid_len in 1usize..=20, seed in any::<u64>(), retire in 0u64..(1u64 << 30)) {
            let mut g = ConnectionIdGenerator::new(cid_len, seed);
            let frame = g.new_connection_id_frame(retire);
            let b = &frame.bytes;
            prop_assert_eq!(b[0], 0x18);
            let (_seq, n1) = quic_varint_decode(b, 1).expect("seq");
            let (rp, n2) = quic_varint_decode(b, 1 + n1).expect("retire");
            prop_assert_eq!(rp, retire);
            let len_pos = 1 + n1 + n2;
            let cid_l = b[len_pos] as usize;
            prop_assert_eq!(cid_l, cid_len);
            // type + varints + len byte + cid + 16-byte token.
            prop_assert_eq!(b.len(), len_pos + 1 + cid_l + 16);
        }
    }

    #[test]
    #[should_panic(expected = "CID length must be 1-20")]
    fn cid_generator_rejects_zero_length() {
        let _ = ConnectionIdGenerator::new(0, 1);
    }

    #[test]
    #[should_panic(expected = "CID length must be 1-20")]
    fn cid_generator_rejects_over_20_length() {
        let _ = ConnectionIdGenerator::new(21, 1);
    }
}
