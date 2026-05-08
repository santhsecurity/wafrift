//! wafrift-strategy — Evasion strategy pipeline.
//!
//! The orchestrator that wires all WAF Rift modules into a coherent
//! evasion flow: request → fingerprint → grammar → encoding →
//! header → content-type → result.

pub mod composition;
pub mod cost;
pub mod gene_bank;
pub mod host_state;
pub mod learning_cache;
/// MCTS bridge for intelligent evasion trajectory optimization.
pub mod mcts_bridge;
pub mod pipeline;
pub mod planner;
pub mod strategy;
/// WAF-specific evasion presets loaded from TOML rules.
pub mod waf_presets;

pub use pipeline::{EvasionPipeline, EvasionPlanOutput};
pub use planner::plan_pipelines;
pub use strategy::*;
