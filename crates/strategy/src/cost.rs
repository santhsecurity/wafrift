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

/// Sort pipelines by cost-effectiveness: highest success rate first,
/// then lowest cost.
pub fn sort_by_cost_effectiveness<T: AsRef<[(Technique, u16)]>>(_pipelines: &mut [T]) {
    // This is a stub for the generic sort interface.
    // Real implementation lives in the planner.
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
}
