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
}
