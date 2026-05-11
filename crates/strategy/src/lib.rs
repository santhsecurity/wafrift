//! wafrift-strategy — Evasion strategy pipeline.
//!
//! The orchestrator that wires all WAF Rift modules into a coherent
//! evasion flow: request → fingerprint → grammar → encoding →
//! header → content-type → result.
//!
//! # Examples
//!
//! Per-host adaptation: the strategy keeps a [`HostState`] for each
//! target. As blocks pile up the engine escalates encoding choices;
//! once a technique consistently bypasses, it gets promoted to a
//! "proven winner" and the engine rotates through the winner pool
//! instead of re-discovering from scratch.
//!
//! ```
//! use wafrift_strategy::HostState;
//! use wafrift_types::technique::Technique;
//!
//! let mut state = HostState::default();
//! assert!(!state.waf_confirmed);
//! assert_eq!(state.blocks, 0);
//!
//! // Three confirmed blocks — strategy now knows escalation is needed.
//! state.record_block();
//! state.record_block();
//! state.record_block();
//! assert_eq!(state.blocks, 3);
//! assert!(state.needs_evasion());
//!
//! // After a single technique succeeds, last_success is populated and
//! // the per-technique success rate gets tracked for future rotation.
//! state.record_success(Technique::HeaderObfuscation("uppercase".into()));
//! assert!(state.last_success.is_some());
//! ```

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

pub use host_state::HostState;
pub use learning_cache::LearningCache;
pub use pipeline::{EvasionPipeline, EvasionPlanOutput};
pub use planner::plan_pipelines;
pub use strategy::*;

pub mod explain;
