//! Evasion pipeline — an ordered sequence of techniques with a cost estimate.

use serde::{Deserialize, Serialize};
use wafrift_types::{Request, Technique};

use wafrift_types::injection_context::InjectionContext;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvasionStage {
    pub technique: Technique,
    pub context: Option<InjectionContext>,
}

/// A single evasion pipeline: an ordered list of techniques to apply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvasionPipeline {
    /// Human-readable identifier for this pipeline.
    pub name: String,
    /// Ordered techniques to apply.
    pub stages: Vec<EvasionStage>,
    /// Estimated cost in number of requests.
    pub cost: u32,
    /// Historical success rate (0–10000, where 10000 = 100%).
    pub success_bps: u16,
}

impl EvasionPipeline {
    /// Create a new pipeline.
    #[must_use]
    pub fn new(name: impl Into<String>, stages: Vec<EvasionStage>, cost: u32) -> Self {
        Self {
            name: name.into(),
            stages,
            cost,
            success_bps: 0,
        }
    }

    /// Set the historical success rate in basis points.
    pub fn with_success_rate(mut self, bps: u16) -> Self {
        self.success_bps = bps;
        self
    }

    /// Returns a cloned `Request` and the technique list this pipeline
    /// declares — it does NOT actually apply the techniques to the
    /// request bytes. The mutation logic lives in `strategy::evade*`
    /// (so the `Pipeline` value type stays I/O-free and trivially
    /// serializable). Call this when you want to surface "the plan"
    /// to a caller; call `evade_adaptive(&req, cfg, &plan, &state)` to
    /// actually execute it.
    #[must_use]
    pub fn apply_to(&self, req: &Request) -> (Request, Vec<EvasionStage>) {
        (req.clone(), self.stages.clone())
    }
}

/// An ordered list of evasion pipelines with metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvasionPlanOutput {
    /// Pipelines ordered by expected value (best first).
    pub pipelines: Vec<EvasionPipeline>,
    /// Total estimated cost if all pipelines are executed.
    pub total_cost: u32,
    /// WAF fingerprint that informed this plan (if any).
    pub waf_fingerprint: Option<String>,
    /// Payload type that informed this plan (if any).
    pub payload_type: Option<String>,
}

impl EvasionPlanOutput {
    /// Create a new plan output.
    #[must_use]
    pub fn new(pipelines: Vec<EvasionPipeline>) -> Self {
        // F83: widen to u64 mid-sum and saturate back to u32 so a
        // multi-thousand-entry learning cache can't silently wrap the
        // exposed budget. With cost u32 + 4B entries the worst-case
        // accumulator fits comfortably in u64.
        let total_cost: u32 = pipelines
            .iter()
            .map(|p| u64::from(p.cost))
            .sum::<u64>()
            .min(u64::from(u32::MAX)) as u32;
        Self {
            pipelines,
            total_cost,
            waf_fingerprint: None,
            payload_type: None,
        }
    }

    /// Returns the cheapest pipeline, if any.
    #[must_use]
    pub fn cheapest(&self) -> Option<&EvasionPipeline> {
        self.pipelines.iter().min_by_key(|p| p.cost)
    }

    /// Returns the highest-confidence pipeline, if any.
    #[must_use]
    pub fn best(&self) -> Option<&EvasionPipeline> {
        self.pipelines.first()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipeline_cost_tracking() {
        let p = EvasionPipeline::new(
            "test",
            vec![EvasionStage {
                technique: Technique::UserAgentRotation,
                context: None,
            }],
            3,
        );
        assert_eq!(p.cost, 3);
    }

    #[test]
    fn plan_total_cost() {
        let plan = EvasionPlanOutput::new(vec![
            EvasionPipeline::new("a", vec![], 2),
            EvasionPipeline::new("b", vec![], 3),
        ]);
        assert_eq!(plan.total_cost, 5);
    }

    #[test]
    fn plan_cheapest() {
        let plan = EvasionPlanOutput::new(vec![
            EvasionPipeline::new("a", vec![], 5),
            EvasionPipeline::new("b", vec![], 1),
        ]);
        assert_eq!(plan.cheapest().unwrap().name, "b");
    }

    #[test]
    fn plan_best_returns_first() {
        let plan = EvasionPlanOutput::new(vec![
            EvasionPipeline::new("first", vec![], 10),
            EvasionPipeline::new("second", vec![], 1),
        ]);
        assert_eq!(plan.best().unwrap().name, "first");
    }

    #[test]
    fn pipeline_with_success_rate() {
        let p = EvasionPipeline::new("test", vec![], 1).with_success_rate(5000);
        assert_eq!(p.success_bps, 5000);
    }

    #[test]
    fn apply_to_clones_request_and_stages() {
        let req = Request::get("http://example.com/");
        let pipeline = EvasionPipeline::new(
            "test",
            vec![EvasionStage {
                technique: Technique::UserAgentRotation,
                context: None,
            }],
            1,
        );
        let (cloned_req, stages) = pipeline.apply_to(&req);
        assert_eq!(cloned_req.method, req.method);
        assert_eq!(stages.len(), 1);
    }

    #[test]
    fn empty_plan_has_zero_cost() {
        let plan = EvasionPlanOutput::new(vec![]);
        assert_eq!(plan.total_cost, 0);
        assert!(plan.cheapest().is_none());
        assert!(plan.best().is_none());
    }
}
