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
}
