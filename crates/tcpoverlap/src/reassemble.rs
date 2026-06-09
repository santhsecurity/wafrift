//! Segment model + policy-accurate reassembly simulation.

use serde::{Deserialize, Serialize};

use crate::policy::ReassemblyPolicy;

/// One TCP segment: its starting sequence number and its payload bytes.
///
/// The model uses absolute (non-wrapping) sequence offsets — real TCP sequence
/// numbers wrap at 2³², but an overlap plan operates within a tiny window where
/// wrap never occurs. `seq` is the sequence number of `data[0]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Segment {
    /// Sequence number of the first byte of `data`.
    pub seq: u32,
    /// Segment payload.
    pub data: Vec<u8>,
}

impl Segment {
    /// Construct a segment.
    #[must_use]
    pub fn new(seq: u32, data: impl Into<Vec<u8>>) -> Self {
        Self {
            seq,
            data: data.into(),
        }
    }

    /// Sequence number one past the last byte (exclusive end). Saturating: a
    /// segment crafted with `seq` near `u32::MAX` clamps at `u32::MAX` rather
    /// than overflowing (debug panic / release wrap) — `Segment::new` is public,
    /// so a hostile caller must not be able to drive `end()` to misbehave.
    #[must_use]
    pub fn end(&self) -> u32 {
        self.seq.saturating_add(self.data.len() as u32)
    }
}

/// Hard cap on the reassembly window (1 MiB). A real overlap plan spans a single
/// request — a few KiB at most. Without this, a segment set with a huge sequence
/// gap (or `u32`-scale `seq` values) would size the position buffer at up to
/// ~4 GiB and OOM the process. Positions past the cap are never part of a
/// legitimate plan, so clamping is both safe and sufficient.
pub const MAX_REASSEMBLY_SPAN: usize = 1 << 20;

/// Simulate in-order TCP reassembly of `segments` under `policy`.
///
/// Segments are processed in **arrival order** (their order in the slice). Each
/// byte position is resolved by [`ReassemblyPolicy::overwrites`]. The result is
/// the contiguous byte run starting at the lowest sequence number, stopping at
/// the first gap — exactly what an in-order TCP stack delivers to the
/// application (bytes past a hole are buffered, not delivered).
///
/// Deterministic and total: any segment set yields a defined stream (empty if
/// there are no segments, or if the lowest sequence number is not covered).
#[must_use]
pub fn reassemble(segments: &[Segment], policy: ReassemblyPolicy) -> Vec<u8> {
    if segments.is_empty() {
        return Vec::new();
    }
    let base = segments.iter().map(|s| s.seq).min().unwrap_or(0);
    let end = segments.iter().map(Segment::end).max().unwrap_or(base);
    // Clamp the window so a hostile sequence gap cannot drive a multi-GB
    // allocation; positions past the cap fall outside any real overlap plan.
    let span = (end.saturating_sub(base) as usize).min(MAX_REASSEMBLY_SPAN);

    // Per position: (byte, the seq of the segment that wrote it).
    let mut occ: Vec<Option<(u8, u32)>> = vec![None; span];
    for seg in segments {
        for (k, &b) in seg.data.iter().enumerate() {
            let pos = (seg.seq - base) as usize + k;
            // Skip bytes beyond the clamped window (saturating `end` + the span
            // cap mean `pos` is not guaranteed in-bounds for pathological input).
            if pos >= span {
                continue;
            }
            occ[pos] = match occ[pos] {
                None => Some((b, seg.seq)),
                Some((_, ex_seq)) if policy.overwrites(seg.seq, ex_seq) => Some((b, seg.seq)),
                some => some,
            };
        }
    }

    // Deliver the contiguous prefix from `base`, stopping at the first hole.
    let mut out = Vec::with_capacity(span);
    for cell in occ {
        match cell {
            Some((b, _)) => out.push(b),
            None => break,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::ReassemblyPolicy::{Bsd, First, Last, Linux};

    fn seg(seq: u32, s: &str) -> Segment {
        Segment::new(seq, s.as_bytes().to_vec())
    }

    #[test]
    fn non_overlapping_segments_concatenate_in_seq_order() {
        let segs = [seg(0, "GET "), seg(4, "/index")];
        for p in ReassemblyPolicy::all() {
            assert_eq!(reassemble(&segs, *p), b"GET /index", "policy {}", p.label());
        }
    }

    #[test]
    fn out_of_arrival_order_still_reassembles_by_seq() {
        // Arrive 2nd segment first.
        let segs = [seg(4, "/index"), seg(0, "GET ")];
        assert_eq!(reassemble(&segs, First), b"GET /index");
    }

    #[test]
    fn full_overlap_first_keeps_old_last_takes_new() {
        // Two segments at seq 0 with different bytes (same length).
        let segs = [seg(0, "AAAA"), seg(0, "BBBB")];
        assert_eq!(reassemble(&segs, First), b"AAAA", "first favors the older");
        assert_eq!(reassemble(&segs, Last), b"BBBB", "last favors the newer");
    }

    #[test]
    fn full_overlap_bsd_keeps_old_linux_takes_new_on_tie() {
        let segs = [seg(0, "AAAA"), seg(0, "BBBB")];
        // Equal left edge ⇒ BSD keeps old, Linux takes new (the documented split).
        assert_eq!(reassemble(&segs, Bsd), b"AAAA");
        assert_eq!(reassemble(&segs, Linux), b"BBBB");
    }

    #[test]
    fn partial_overlap_resolves_only_the_overlapping_region() {
        // seg1: pos 0..6 "GET /a"; seg2: pos 4..10 "XXevil" overlaps pos 4..6.
        let segs = [seg(0, "GET /a"), seg(4, "XXevil")];
        // First: pos 4,5 keep 'a'-segment bytes ("/a" → '/','a' at 4,5? indices:
        //   "GET /a" = G E T _ / a at 0..6 → pos4='/', pos5='a'.
        //   seg2 at pos4='X',5='X',6='e'... First keeps pos4='/',5='a'; pos6+ from seg2.
        // → "GET /a" + "evil" = "GET /aevil"
        assert_eq!(reassemble(&segs, First), b"GET /aevil");
        // Last: pos4,5 overwritten with 'X','X' → "GET XXevil"
        assert_eq!(reassemble(&segs, Last), b"GET XXevil");
    }

    #[test]
    fn lower_seq_segment_wins_under_bsd_regardless_of_arrival() {
        // A high-seq segment arrives first and writes; a lower-seq overlapping
        // segment arrives later. BSD favors the LOWER seq even though it's newer.
        let segs = [seg(2, "YYYY"), seg(0, "XXXXXX")];
        // base=0, span=6. seg(2,"YYYY") writes pos2..6. seg(0,"XXXXXX") writes 0..6.
        // BSD: at pos2..6, incoming seq 0 < existing seq 2 ⇒ overwrite ⇒ all X.
        assert_eq!(reassemble(&segs, Bsd), b"XXXXXX");
    }

    #[test]
    fn a_hole_truncates_delivery_at_the_gap() {
        // seg at 0 and seg at 5 leave pos... actually "GET" is 0..3, gap at 3,4.
        let segs = [seg(0, "GET"), seg(5, "/x")];
        // base=0, pos3,4 uncovered ⇒ delivery stops after "GET".
        assert_eq!(reassemble(&segs, First), b"GET");
    }

    #[test]
    fn empty_segment_set_reassembles_to_nothing() {
        assert!(reassemble(&[], First).is_empty());
    }

    #[test]
    fn base_not_at_zero_is_handled() {
        let segs = [seg(100, "AB"), seg(102, "CD")];
        assert_eq!(reassemble(&segs, First), b"ABCD");
    }

    #[test]
    fn segment_end_saturates_instead_of_overflowing() {
        // seq near the top of the u32 range with multi-byte data would overflow
        // `seq + len`; saturating keeps it at u32::MAX (no debug panic).
        let s = Segment::new(u32::MAX - 1, vec![b'x'; 8]);
        assert_eq!(s.end(), u32::MAX);
    }

    #[test]
    fn a_huge_sequence_gap_does_not_oom_and_truncates_at_the_gap() {
        // base=0 contiguous "GET", then a segment 3 GiB away. The window must be
        // clamped (no ~3 GiB allocation) and delivery stops at the first hole.
        let segs = [seg(0, "GET"), Segment::new(3_000_000_000, b"evil".to_vec())];
        let out = reassemble(&segs, First);
        assert_eq!(out, b"GET", "delivery truncates at the hole after 'GET'");
        assert!(out.len() <= MAX_REASSEMBLY_SPAN);
    }

    // ── Property tests ────────────────────────────────────────────────────

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(3000))]

        /// Reassembly never panics and never delivers more bytes than the covered
        /// span, for any segment set and policy.
        #[test]
        fn prop_reassemble_total_and_bounded(
            segs in proptest::collection::vec(
                (0u32..16, proptest::collection::vec(any::<u8>(), 0..8)),
                0..8,
            ),
            pol_idx in 0usize..4,
        ) {
            let segments: Vec<Segment> = segs.into_iter().map(|(s, d)| Segment::new(s, d)).collect();
            let policy = ReassemblyPolicy::all()[pol_idx];
            let out = reassemble(&segments, policy);
            if let (Some(base), Some(end)) = (
                segments.iter().map(|s| s.seq).min(),
                segments.iter().map(Segment::end).max(),
            ) {
                prop_assert!(out.len() <= end.saturating_sub(base) as usize);
            } else {
                prop_assert!(out.is_empty());
            }
        }

        /// Adversarial: extreme `u32` sequence numbers and large gaps must not
        /// panic (overflow in `end()`) nor attempt an unbounded allocation. The
        /// output is always bounded by the clamped reassembly window.
        #[test]
        fn prop_extreme_seq_never_panics_and_is_bounded(
            segs in proptest::collection::vec(
                (any::<u32>(), proptest::collection::vec(any::<u8>(), 0..16)),
                0..6,
            ),
            pol_idx in 0usize..4,
        ) {
            let segments: Vec<Segment> = segs.into_iter().map(|(s, d)| Segment::new(s, d)).collect();
            let policy = ReassemblyPolicy::all()[pol_idx];
            let out = reassemble(&segments, policy);
            prop_assert!(out.len() <= MAX_REASSEMBLY_SPAN);
        }

        /// Non-overlapping, gap-free segments concatenate identically under EVERY
        /// policy — overlap resolution can only matter where bytes overlap.
        #[test]
        fn prop_disjoint_segments_are_policy_invariant(
            chunks in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 1..6), 1..6),
        ) {
            // Lay chunks end to end with no gaps or overlaps.
            let mut segments = Vec::new();
            let mut seq = 0u32;
            let mut expected = Vec::new();
            for c in &chunks {
                segments.push(Segment::new(seq, c.clone()));
                seq += c.len() as u32;
                expected.extend_from_slice(c);
            }
            let first = reassemble(&segments, First);
            prop_assert_eq!(&first, &expected);
            for p in ReassemblyPolicy::all() {
                prop_assert_eq!(reassemble(&segments, *p), expected.clone(), "policy {}", p.label());
            }
        }
    }
}
