//! Cost model for evasion techniques.
//!
//! Each technique has an associated request cost. The strategy engine
//! uses these costs to stay within a request budget.

use wafrift_types::Technique;

/// Base cost of a single technique application.
#[must_use]
pub fn technique_cost(technique: &Technique) -> u32 {
    match technique {
        Technique::PayloadEncoding(_) => 1,
        Technique::GrammarMutation(_) => 1,
        Technique::ContentTypeSwitch(_) => 1,
        Technique::HeaderObfuscation(_) => 1,
        Technique::UserAgentRotation => 1,
        Technique::TlsFingerprint(_) => 1,
        Technique::Http2Settings => 1,
        Technique::BoundaryManipulation => 1,
        Technique::JsonUnicodeEscape => 1,
        Technique::RequestSmuggling(_) => 3,
        Technique::H2Evasion(_) => 2,
        Technique::DifferentialProbe => 2,
        _ => 1,
    }
}

/// Total cost of a pipeline.
#[must_use]
pub fn pipeline_cost(techniques: &[Technique]) -> u32 {
    techniques.iter().map(technique_cost).sum()
}

/// Returns true if the cumulative cost fits within the budget.
#[must_use]
pub fn within_budget(cost: u32, budget: u32) -> bool {
    cost <= budget
}

/// Sort pipelines in place by cost-effectiveness: highest aggregate
/// success-weight first, ties broken by lowest cost first. Each
/// pipeline is a slice of `(Technique, success_weight)` pairs.
/// Success-weight is whatever the caller chose to encode (typical:
/// observed bypass count, or fitness × 1000). Cost comes from
/// `technique_cost`.
pub fn sort_by_cost_effectiveness<T: AsRef<[(Technique, u16)]>>(pipelines: &mut [T]) {
    pipelines.sort_by(|a, b| {
        let (cost_a, weight_a) = score(a.as_ref());
        let (cost_b, weight_b) = score(b.as_ref());
        // Primary: higher weight wins. Secondary: lower cost wins.
        weight_b.cmp(&weight_a).then(cost_a.cmp(&cost_b))
    });
}

fn score(pipeline: &[(Technique, u16)]) -> (u32, u32) {
    let cost = pipeline.iter().map(|(t, _)| technique_cost(t)).sum::<u32>();
    let weight = pipeline.iter().map(|(_, w)| u32::from(*w)).sum::<u32>();
    (cost, weight)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_cost_is_low() {
        let t = Technique::PayloadEncoding("UrlEncode".into());
        assert_eq!(technique_cost(&t), 1);
    }

    #[test]
    fn smuggling_cost_is_high() {
        let t = Technique::RequestSmuggling("CL.TE".into());
        assert_eq!(technique_cost(&t), 3);
    }

    #[test]
    fn pipeline_cost_sums() {
        let techniques = vec![
            Technique::PayloadEncoding("UrlEncode".into()),
            Technique::RequestSmuggling("CL.TE".into()),
        ];
        assert_eq!(pipeline_cost(&techniques), 4);
    }

    #[test]
    fn budget_check() {
        assert!(within_budget(5, 10));
        assert!(!within_budget(11, 10));
    }

    #[test]
    fn sort_picks_highest_weight_first() {
        let p_low = vec![(Technique::PayloadEncoding("a".into()), 1u16)];
        let p_high = vec![(Technique::PayloadEncoding("b".into()), 9u16)];
        let mut pipelines: Vec<Vec<(Technique, u16)>> = vec![p_low.clone(), p_high.clone()];
        sort_by_cost_effectiveness(&mut pipelines);
        assert_eq!(pipelines[0], p_high, "highest weight must come first");
        assert_eq!(pipelines[1], p_low);
    }

    #[test]
    fn sort_breaks_ties_by_lower_cost() {
        // Both have weight 5; the smuggling pipeline (cost 3) loses
        // to the encoding pipeline (cost 1).
        let cheap = vec![(Technique::PayloadEncoding("a".into()), 5u16)];
        let pricey = vec![(Technique::RequestSmuggling("CL.TE".into()), 5u16)];
        let mut pipelines: Vec<Vec<(Technique, u16)>> = vec![pricey.clone(), cheap.clone()];
        sort_by_cost_effectiveness(&mut pipelines);
        assert_eq!(pipelines[0], cheap, "tied weight: lower cost wins");
        assert_eq!(pipelines[1], pricey);
    }

    // ── Density ramp ─────────────────────────────────────

    #[test]
    fn h2_evasion_cost_is_medium() {
        let t = Technique::H2Evasion("setting".into());
        assert_eq!(technique_cost(&t), 2);
    }

    #[test]
    fn differential_probe_cost_is_medium() {
        assert_eq!(technique_cost(&Technique::DifferentialProbe), 2);
    }

    #[test]
    fn header_obfuscation_is_cheap() {
        assert_eq!(
            technique_cost(&Technique::HeaderObfuscation("X-Forwarded-For".into())),
            1
        );
    }

    #[test]
    fn user_agent_rotation_is_cheap() {
        assert_eq!(technique_cost(&Technique::UserAgentRotation), 1);
    }

    #[test]
    fn boundary_manipulation_is_cheap() {
        assert_eq!(technique_cost(&Technique::BoundaryManipulation), 1);
    }

    #[test]
    fn json_unicode_escape_is_cheap() {
        assert_eq!(technique_cost(&Technique::JsonUnicodeEscape), 1);
    }

    #[test]
    fn empty_pipeline_cost_is_zero() {
        assert_eq!(pipeline_cost(&[]), 0);
    }

    #[test]
    fn pipeline_cost_with_single_smuggle_is_three() {
        let t = vec![Technique::RequestSmuggling("CL.TE".into())];
        assert_eq!(pipeline_cost(&t), 3);
    }

    #[test]
    fn budget_check_at_exact_boundary_is_inclusive() {
        // Budget=10, cost=10 → fits (≤).
        assert!(within_budget(10, 10));
        assert!(within_budget(0, 0));
    }

    #[test]
    fn budget_check_zero_budget_excludes_any_cost() {
        assert!(within_budget(0, 0));
        assert!(!within_budget(1, 0));
    }

    #[test]
    fn sort_preserves_stable_order_on_full_tie() {
        // Two pipelines with identical (cost, weight) — sort
        // must not panic, and we trust slice::sort_by is stable.
        let p1 = vec![(Technique::PayloadEncoding("a".into()), 3u16)];
        let p2 = vec![(Technique::PayloadEncoding("b".into()), 3u16)];
        let mut pipelines: Vec<Vec<(Technique, u16)>> = vec![p1.clone(), p2.clone()];
        sort_by_cost_effectiveness(&mut pipelines);
        // Both still present, length preserved.
        assert_eq!(pipelines.len(), 2);
        assert!(pipelines.contains(&p1));
        assert!(pipelines.contains(&p2));
    }

    #[test]
    fn sort_empty_input_does_not_panic() {
        let mut pipelines: Vec<Vec<(Technique, u16)>> = vec![];
        sort_by_cost_effectiveness(&mut pipelines);
        assert!(pipelines.is_empty());
    }

    #[test]
    fn sort_handles_pipelines_of_different_lengths() {
        // 3-step pipeline vs 1-step — both eligible regardless
        // of length; cost-effectiveness compares totals.
        let long = vec![
            (Technique::PayloadEncoding("a".into()), 2u16),
            (Technique::HeaderObfuscation("b".into()), 1u16),
            (Technique::PayloadEncoding("c".into()), 5u16),
        ]; // weight sum = 8, cost = 3
        let short = vec![(Technique::PayloadEncoding("z".into()), 7u16)]; // weight 7, cost 1
        let mut pipelines: Vec<Vec<(Technique, u16)>> = vec![short.clone(), long.clone()];
        sort_by_cost_effectiveness(&mut pipelines);
        assert_eq!(pipelines[0], long, "higher weight (8) wins over (7)");
    }

    #[test]
    fn pipeline_cost_aggregates_across_mixed_techniques() {
        let mixed = vec![
            Technique::PayloadEncoding("a".into()),
            Technique::H2Evasion("b".into()),
            Technique::RequestSmuggling("c".into()),
            Technique::UserAgentRotation,
        ];
        // 1 + 2 + 3 + 1 = 7
        assert_eq!(pipeline_cost(&mixed), 7);
    }

    #[test]
    fn technique_cost_is_deterministic() {
        let t = Technique::PayloadEncoding("url".into());
        for _ in 0..10 {
            assert_eq!(technique_cost(&t), 1);
        }
    }

    #[test]
    fn budget_check_with_max_u32_values() {
        // Defensive: extreme values must not panic or overflow.
        assert!(within_budget(0, u32::MAX));
        assert!(within_budget(u32::MAX, u32::MAX));
        assert!(!within_budget(u32::MAX, u32::MAX - 1));
    }
}
