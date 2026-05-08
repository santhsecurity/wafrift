//! Strategy planner — generates ordered lists of evasion pipelines.
//!
//! The planner consumes host state, WAF fingerprint, payload type, and
//! request budget to produce a ranked list of `EvasionPipeline`s.

use crate::cost::{pipeline_cost, within_budget};
use crate::learning_cache::{CacheKey, LearningCache};
use crate::pipeline::{EvasionPipeline, EvasionPlanOutput};
use wafrift_encoding::encoding;
use wafrift_types::{Technique, Verdict};

/// Plan evasion pipelines for a request.
///
/// # Arguments
///
/// * `waf_fingerprint` — Detected WAF name or fingerprint.
/// * `payload_type` — Detected payload type (e.g., "sql", "xss").
/// * `budget` — Maximum request budget.
/// * `cache` — Optional learning cache for historical winners.
/// * `verdict_history` — Recent verdicts to avoid repeating failed pipelines.
#[must_use]
pub fn plan_pipelines(
    waf_fingerprint: Option<&str>,
    payload_type: Option<&str>,
    budget: u32,
    cache: Option<&LearningCache>,
    verdict_history: &[Verdict],
) -> EvasionPlanOutput {
    let mut pipelines = Vec::new();

    // 1. Try cached winner first
    if let (Some(waf), Some(payload), Some(cache)) = (waf_fingerprint, payload_type, cache) {
        let key = CacheKey::new(waf, payload);
        if let Some(entry) = cache.get(&key) {
            let mut cached = entry.pipeline.clone();
            cached.success_bps = (entry.success_rate() * 10000.0) as u16;
            if within_budget(cached.cost, budget) {
                pipelines.push(cached);
            }
        }
    }

    // 2. Generate standard escalation pipelines
    let light = EvasionPipeline::new(
        "light",
        vec![
            Technique::UserAgentRotation,
            Technique::PayloadEncoding(encoding::Strategy::CaseAlternation.as_str().to_string()),
            Technique::HeaderObfuscation("CaseMixing".into()),
        ],
        pipeline_cost(&[
            Technique::UserAgentRotation,
            Technique::PayloadEncoding(encoding::Strategy::CaseAlternation.as_str().to_string()),
            Technique::HeaderObfuscation("CaseMixing".into()),
        ]),
    )
    .with_success_rate(1500);

    let medium = EvasionPipeline::new(
        "medium",
        vec![
            Technique::UserAgentRotation,
            Technique::GrammarMutation("auto".into()),
            Technique::PayloadEncoding(encoding::Strategy::DoubleUrlEncode.as_str().to_string()),
            Technique::HeaderObfuscation("CaseMixing".into()),
        ],
        pipeline_cost(&[
            Technique::UserAgentRotation,
            Technique::GrammarMutation("auto".into()),
            Technique::PayloadEncoding(encoding::Strategy::DoubleUrlEncode.as_str().to_string()),
            Technique::HeaderObfuscation("CaseMixing".into()),
        ]),
    )
    .with_success_rate(3500);

    let heavy = EvasionPipeline::new(
        "heavy",
        vec![
            Technique::UserAgentRotation,
            Technique::GrammarMutation("auto".into()),
            Technique::PayloadEncoding(encoding::Strategy::DoubleUrlEncode.as_str().to_string()),
            Technique::ContentTypeSwitch("Multipart".into()),
            Technique::HeaderObfuscation("CaseMixing".into()),
            Technique::RequestSmuggling("CL.TE".into()),
            Technique::H2Evasion("MixedCaseHeaders".into()),
        ],
        pipeline_cost(&[
            Technique::UserAgentRotation,
            Technique::GrammarMutation("auto".into()),
            Technique::PayloadEncoding(encoding::Strategy::DoubleUrlEncode.as_str().to_string()),
            Technique::ContentTypeSwitch("Multipart".into()),
            Technique::HeaderObfuscation("CaseMixing".into()),
            Technique::RequestSmuggling("CL.TE".into()),
            Technique::H2Evasion("MixedCaseHeaders".into()),
        ]),
    )
    .with_success_rate(5000);

    for p in [light, medium, heavy] {
        if within_budget(p.cost, budget)
            && !pipelines
                .iter()
                .any(|ep: &EvasionPipeline| ep.name == p.name)
        {
            pipelines.push(p);
        }
    }

    // 3. Deprioritize any pipeline whose last verdict in history was a block
    let _blocked_names: Vec<String> = verdict_history
        .iter()
        .filter(|v| v.is_blocked())
        .filter_map(|_| None) // We don't have pipeline names in verdicts yet
        .collect();

    // Sort: cached winner first, then by success_bps descending, then by cost ascending
    pipelines.sort_by(|a, b| {
        b.success_bps
            .cmp(&a.success_bps)
            .then_with(|| a.cost.cmp(&b.cost))
    });

    let mut output = EvasionPlanOutput::new(pipelines);
    output.waf_fingerprint = waf_fingerprint.map(String::from);
    output.payload_type = payload_type.map(String::from);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn planner_respects_budget() {
        let plan = plan_pipelines(None, None, 2, None, &[]);
        // Only the light pipeline (cost ~3) might exceed budget of 2
        assert!(plan.pipelines.iter().all(|p| p.cost <= 2));
    }

    #[test]
    fn planner_sorts_by_success_rate() {
        let plan = plan_pipelines(None, None, 100, None, &[]);
        for w in plan.pipelines.windows(2) {
            assert!(w[0].success_bps >= w[1].success_bps);
        }
    }

    #[test]
    fn planner_uses_cache() {
        let tmp = std::env::temp_dir().join("wafrift_planner_cache.json");
        let _ = std::fs::remove_file(&tmp);

        let mut cache = LearningCache::open(&tmp).unwrap();
        let pipeline = EvasionPipeline::new("cached", vec![Technique::UserAgentRotation], 1)
            .with_success_rate(9900);
        cache.record_success(CacheKey::new("cloudflare", "sql"), pipeline);
        cache.save().unwrap();

        let cache2 = LearningCache::open(&tmp).unwrap();
        let plan = plan_pipelines(Some("cloudflare"), Some("sql"), 100, Some(&cache2), &[]);
        assert_eq!(plan.pipelines.first().unwrap().name, "cached");
        // Planner derives `success_bps` from recorded successes / attempts (1/1 → 10000), not the seed rate.
        assert_eq!(plan.pipelines.first().unwrap().success_bps, 10000);

        let _ = std::fs::remove_file(&tmp);
    }
}
