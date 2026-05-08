//! wafrift-evolution — Genetic algorithm, differential analysis, and WAF-aware advisor.
//!
//! The adaptive feedback loop: detect WAF → analyze differential responses →
//! evolve technique populations → recommend optimal evasion strategies.

pub mod advisor;
pub mod custom_rules;
pub mod differential;
pub mod evolution;
pub mod intelligence;
pub mod lineage;
pub mod search;
pub mod types;
