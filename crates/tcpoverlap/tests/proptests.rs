//! Property tests for sequence-overlap reassembly and differential planning.
//!
//! The centrepiece is a **differential** check: an independent reference
//! reassembler (iterating positions-outer with `u64` arithmetic) must agree with
//! the shipped engine (segments-outer, `u32`) on every random segment set and
//! policy. Two implementations sharing a bug is far less likely than one having
//! it, so agreement over tens of thousands of cases is strong evidence of
//! correctness. The planner is separately checked for its soundness contract:
//! every returned plan genuinely splits the two policies.

use proptest::prelude::*;
use wafrift_tcpoverlap::policy::ReassemblyPolicy;
use wafrift_tcpoverlap::reassemble::{MAX_REASSEMBLY_SPAN, Segment, reassemble};
use wafrift_tcpoverlap::{differential_matrix, differential_plan};

/// Independent reference reassembler. Iterates each absolute position and folds
/// the covering segments in arrival order under the policy — structurally
/// different from the production engine, so a shared bug is unlikely.
fn reference_reassemble(segments: &[Segment], policy: ReassemblyPolicy) -> Vec<u8> {
    if segments.is_empty() {
        return Vec::new();
    }
    let base = u64::from(segments.iter().map(|s| s.seq).min().unwrap());
    let end = segments
        .iter()
        .map(|s| u64::from(s.seq) + s.data.len() as u64)
        .max()
        .unwrap();
    let span = ((end - base) as usize).min(MAX_REASSEMBLY_SPAN);

    let mut out = Vec::new();
    for p in 0..span {
        let abs = base + p as u64;
        let mut winner: Option<(u8, u32)> = None;
        for seg in segments {
            let s = u64::from(seg.seq);
            let e = s + seg.data.len() as u64;
            if abs >= s && abs < e {
                let byte = seg.data[(abs - s) as usize];
                winner = match winner {
                    None => Some((byte, seg.seq)),
                    Some((_, w)) if policy.overwrites(seg.seq, w) => Some((byte, seg.seq)),
                    some => some,
                };
            }
        }
        match winner {
            Some((b, _)) => out.push(b),
            None => break,
        }
    }
    out
}

prop_compose! {
    /// Small overlapping segments: tight seq range maximises overlap density.
    fn small_segments()(
        segs in proptest::collection::vec(
            (0u32..24, proptest::collection::vec(any::<u8>(), 0..10)),
            0..10,
        ),
    ) -> Vec<Segment> {
        segs.into_iter().map(|(s, d)| Segment::new(s, d)).collect()
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8000))]

    /// The shipped engine and the independent reference agree for every policy.
    #[test]
    fn prop_engine_matches_independent_reference(segments in small_segments()) {
        for policy in ReassemblyPolicy::all() {
            prop_assert_eq!(
                reassemble(&segments, *policy),
                reference_reassemble(&segments, *policy),
                "disagreement under policy {}", policy.label()
            );
        }
    }

    /// Reassembly is total and the output never exceeds the clamped window, even
    /// for full-range `u32` sequence numbers and large gaps.
    #[test]
    fn prop_extreme_seq_total_and_bounded(
        segs in proptest::collection::vec(
            (any::<u32>(), proptest::collection::vec(any::<u8>(), 0..12)),
            0..8,
        ),
        pol in 0usize..4,
    ) {
        let segments: Vec<Segment> = segs.into_iter().map(|(s, d)| Segment::new(s, d)).collect();
        let out = reassemble(&segments, ReassemblyPolicy::all()[pol]);
        prop_assert!(out.len() <= MAX_REASSEMBLY_SPAN);
    }

    /// THEOREM (why unequal-length differentials are rejected, not a gap): the
    /// reassembled length is identical under every policy. A position is filled
    /// iff some segment covers it — coverage, and therefore the first hole and
    /// the delivered length, are policy-independent; policies differ only on
    /// WHICH byte wins a contested position, never on how many bytes are
    /// delivered. So no two policies can ever reassemble the same segments into
    /// different-length streams, which is exactly why `differential_plan`
    /// requires `benign.len() == attack.len()`.
    #[test]
    fn prop_reassembled_length_is_policy_independent(segments in small_segments()) {
        let lens: Vec<usize> = ReassemblyPolicy::all()
            .iter()
            .map(|p| reassemble(&segments, *p).len())
            .collect();
        prop_assert!(lens.windows(2).all(|w| w[0] == w[1]), "lengths diverged: {lens:?}");
    }

    /// Disjoint, gap-free segments are policy-invariant — overlap resolution can
    /// only matter where bytes actually overlap.
    #[test]
    fn prop_disjoint_is_policy_invariant(
        chunks in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 1..6), 1..8),
    ) {
        let mut segments = Vec::new();
        let mut seq = 0u32;
        let mut expected = Vec::new();
        for c in &chunks {
            segments.push(Segment::new(seq, c.clone()));
            seq += c.len() as u32;
            expected.extend_from_slice(c);
        }
        for policy in ReassemblyPolicy::all() {
            prop_assert_eq!(reassemble(&segments, *policy), expected.clone());
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    /// Soundness: every plan the matrix returns ACTUALLY splits — re-simulate
    /// both policies and confirm the claimed views, for random EQUAL-length pairs.
    #[test]
    fn prop_matrix_plans_are_genuine_differentials(
        pair in (proptest::collection::vec(any::<u8>(), 1..16)).prop_flat_map(|benign| {
            let n = benign.len();
            (Just(benign), proptest::collection::vec(any::<u8>(), n..=n))
        }),
    ) {
        let (benign, attack) = pair;
        for plan in differential_matrix(&benign, &attack) {
            prop_assert_eq!(reassemble(&plan.segments, plan.waf_policy), benign.clone());
            prop_assert_eq!(reassemble(&plan.segments, plan.origin_policy), attack.clone());
            prop_assert_ne!(plan.waf_policy, plan.origin_policy);
            // The split is a genuine same-sequence overlap of two segments.
            prop_assert_eq!(plan.segments.len(), 2);
            prop_assert_eq!(plan.segments[0].seq, plan.segments[1].seq);
        }
    }

    /// Unequal-length views never produce a (fabricated) differential.
    #[test]
    fn prop_unequal_length_has_no_differential(
        benign in proptest::collection::vec(any::<u8>(), 1..16),
        attack in proptest::collection::vec(any::<u8>(), 1..16),
    ) {
        prop_assume!(benign.len() != attack.len());
        prop_assert!(differential_matrix(&benign, &attack).is_empty());
        for &waf in ReassemblyPolicy::all() {
            for &origin in ReassemblyPolicy::all() {
                prop_assert!(differential_plan(&benign, &attack, waf, origin).is_none());
            }
        }
    }

    /// Identical views have nothing to hide — no differential exists.
    #[test]
    fn prop_identical_views_have_no_differential(data in proptest::collection::vec(any::<u8>(), 1..16)) {
        prop_assert!(differential_matrix(&data, &data).is_empty());
    }

    /// Identical policies can never disagree with themselves.
    #[test]
    fn prop_identical_policies_never_split(
        benign in proptest::collection::vec(any::<u8>(), 1..12),
        attack in proptest::collection::vec(any::<u8>(), 1..12),
        pol in 0usize..4,
    ) {
        let p = ReassemblyPolicy::all()[pol];
        prop_assert!(differential_plan(&benign, &attack, p, p).is_none());
    }
}
