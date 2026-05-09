use crate::Technique;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Explanation {
    pub original_payload: String,
    pub bypass_payload: String,
    pub technique_chain: Vec<Technique>,
    pub triggered_rules: Vec<RuleAttribution>,
    pub diff: Vec<DiffHunk>,
    pub human_summary: String,
    pub mode: ExplanationMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuleAttribution {
    pub rule_id: String,
    pub rule_name: String,
    pub matched_substring: String,
    pub matched_pattern: String,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DiffHunk {
    Equal(String),
    Delete(String),
    Insert(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum ExplanationMode {
    Minimal,
    #[default]
    Standard,
    Educational,
}
