//! Overlapping-segment planning, with self-verifying differential plans.
//!
//! The payoff: emit a set of overlapping TCP segments that a WAF (under its
//! reassembly policy) reads as **benign** while the origin (under a *different*
//! policy) reads as the **attack**. Every plan this module returns is verified by
//! simulating both policies before it is handed back — a returned plan is, by
//! construction, a working differential.

use crate::policy::ReassemblyPolicy;
use crate::reassemble::{reassemble, Segment};

/// A verified differential overlap plan.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DifferentialPlan {
    /// The segments to send, in arrival order.
    pub segments: Vec<Segment>,
    /// What the WAF reassembles (the benign view it inspects).
    pub waf_view: Vec<u8>,
    /// What the origin reassembles (the attack view it executes).
    pub origin_view: Vec<u8>,
    /// The WAF's modelled reassembly policy.
    pub waf_policy: ReassemblyPolicy,
    /// The origin's modelled reassembly policy.
    pub origin_policy: ReassemblyPolicy,
}

/// Two equal-length segments at the same sequence number: `arrives_first` then
/// `arrives_second`. A "favor old" receiver reassembles to `arrives_first`; a
/// "favor new" receiver reassembles to `arrives_second`.
#[must_use]
pub fn full_overlap(arrives_first: &[u8], arrives_second: &[u8]) -> Vec<Segment> {
    vec![
        Segment::new(0, arrives_first.to_vec()),
        Segment::new(0, arrives_second.to_vec()),
    ]
}

/// Construct a segment plan that the `waf_policy` receiver reassembles to
/// `benign` and the `origin_policy` receiver reassembles to `attack`, or `None`
/// when no full-overlap plan achieves the split (e.g. identical policies, or a
/// policy pair that cannot be made to disagree on this input).
///
/// **Sound by construction**: the returned plan is verified by simulating both
/// policies — `reassemble(plan, waf) == benign` and `reassemble(plan, origin) ==
/// attack` both hold, or `None` is returned. It never claims an unverified
/// differential.
#[must_use]
pub fn differential_plan(
    benign: &[u8],
    attack: &[u8],
    waf_policy: ReassemblyPolicy,
    origin_policy: ReassemblyPolicy,
) -> Option<DifferentialPlan> {
    // Identical views are not a differential — there is nothing to hide, and a
    // "split" would be vacuous (both sides read the same bytes).
    if benign == attack {
        return None;
    }
    // The full-overlap construction only resolves cleanly when both views are
    // the same length (every byte position is contested). Unequal lengths leave
    // a non-contested tail that both policies agree on, breaking the split.
    if benign.len() != attack.len() {
        return None;
    }
    // Try both arrival orders: (benign first, attack second) and the reverse.
    for plan in [full_overlap(benign, attack), full_overlap(attack, benign)] {
        let waf_view = reassemble(&plan, waf_policy);
        let origin_view = reassemble(&plan, origin_policy);
        if waf_view == benign && origin_view == attack {
            return Some(DifferentialPlan {
                segments: plan,
                waf_view,
                origin_view,
                waf_policy,
                origin_policy,
            });
        }
    }
    None
}

/// Sweep every ordered policy pair and return each pair for which a verified
/// differential plan exists for `(benign, attack)`. The operator picks the pair
/// matching the WAF and origin they're actually facing.
#[must_use]
pub fn differential_matrix(benign: &[u8], attack: &[u8]) -> Vec<DifferentialPlan> {
    let mut out = Vec::new();
    for &waf in ReassemblyPolicy::all() {
        for &origin in ReassemblyPolicy::all() {
            if waf == origin {
                continue; // identical stacks can never disagree
            }
            if let Some(plan) = differential_plan(benign, attack, waf, origin) {
                out.push(plan);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::ReassemblyPolicy::{Bsd, First, Last, Linux};

    #[test]
    fn first_vs_last_yields_a_verified_differential() {
        let plan = differential_plan(b"GET /safe", b"GET /evil", First, Last)
            .expect("first↔last must disagree on a full overlap");
        assert_eq!(plan.waf_view, b"GET /safe");
        assert_eq!(plan.origin_view, b"GET /evil");
        // The segments genuinely overlap at the same sequence number.
        assert_eq!(plan.segments.len(), 2);
        assert_eq!(plan.segments[0].seq, plan.segments[1].seq);
    }

    #[test]
    fn bsd_vs_linux_disagree_on_the_tie() {
        // BSD keeps old, Linux takes new on a full overlap → benign under BSD,
        // attack under Linux requires (benign first, attack second).
        let plan = differential_plan(b"AAAA", b"BBBB", Bsd, Linux)
            .expect("bsd↔linux disagree on the full-overlap tie");
        assert_eq!(plan.waf_view, b"AAAA");
        assert_eq!(plan.origin_view, b"BBBB");
    }

    #[test]
    fn identical_policies_have_no_differential() {
        for p in ReassemblyPolicy::all() {
            assert!(
                differential_plan(b"AAAA", b"BBBB", *p, *p).is_none(),
                "policy {} cannot disagree with itself",
                p.label()
            );
        }
    }

    #[test]
    fn unequal_length_views_are_rejected_not_faked() {
        // A shorter benign would leave an attack-only tail both policies agree on.
        assert!(differential_plan(b"short", b"longerattack", First, Last).is_none());
    }

    #[test]
    fn every_returned_plan_reverifies_under_simulation() {
        // Anti-rig: re-simulate each matrix plan independently and confirm the
        // claimed views. A plan that didn't actually split could never appear.
        let plans = differential_matrix(b"safe", b"evil");
        assert!(!plans.is_empty(), "some policy pair must disagree");
        for plan in &plans {
            assert_eq!(reassemble(&plan.segments, plan.waf_policy), plan.waf_view);
            assert_eq!(reassemble(&plan.segments, plan.origin_policy), plan.origin_view);
            assert_eq!(plan.waf_view, b"safe");
            assert_eq!(plan.origin_view, b"evil");
            assert_ne!(plan.waf_policy, plan.origin_policy);
        }
    }

    #[test]
    fn matrix_covers_the_classic_first_last_pair() {
        let plans = differential_matrix(b"GET /a", b"GET /b");
        assert!(
            plans.iter().any(|p| p.waf_policy == First && p.origin_policy == Last),
            "the canonical first↔last evasion must be in the matrix"
        );
    }

    // ── Property tests ────────────────────────────────────────────────────

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        /// Any differential plan this module returns ACTUALLY splits — re-simulate
        /// both policies and confirm. The soundness contract, over random inputs.
        #[test]
        fn prop_returned_plans_are_genuine_differentials(
            benign in proptest::collection::vec(any::<u8>(), 1..12),
            attack in proptest::collection::vec(any::<u8>(), 1..12),
        ) {
            for plan in differential_matrix(&benign, &attack) {
                prop_assert_eq!(reassemble(&plan.segments, plan.waf_policy), benign.clone());
                prop_assert_eq!(reassemble(&plan.segments, plan.origin_policy), attack.clone());
            }
        }

        /// When benign == attack there is nothing to hide, so no "differential"
        /// can exist (the two views would be identical).
        #[test]
        fn prop_no_differential_when_views_are_equal(data in proptest::collection::vec(any::<u8>(), 1..12)) {
            prop_assert!(differential_matrix(&data, &data).is_empty());
        }
    }
}
