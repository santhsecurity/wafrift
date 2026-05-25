//! wafrift-evolution — Genetic algorithm, MCTS, differential analysis, and WAF-aware advisor.
//!
//! The adaptive feedback loop: detect WAF → analyze differential responses →
//! evolve technique populations → recommend optimal evasion strategies.
//!
//! Key modules:
//! - [`evolution`]    — genetic algorithm (crossover, mutation, fitness)
//! - [`ast_mcts`]     — MCTS over the technique action space
//! - [`differential`] — differential response analysis (surface divergences)
//! - [`advisor`]      — WAF-class-aware technique recommender
//! - [`body_padding`] — inspection-window evasion (pad JSON/form past WAF scan cap)
//! - [`dilution`]     — ensemble dilution for ML-WAF evasion
//! - [`intelligence`] — cross-scan intelligence aggregation
//! - [`lineage`]      — technique lineage tracking across generations
//! - [`search`]       — novelty search + MAP-Elites algorithm
//! - [`custom_rules`] — operator-supplied TOML evasion rules
//!
//! # Examples
//!
//! Inflate a JSON request body past a WAF's inspection-window cap.
//! Cloudflare and Akamai stop scanning after 8KB; AWS WAF after 16KB.
//! `body_padding::pad` produces a structure-preserving payload that
//! still parses on the origin while pushing the attack tokens past
//! the inspection ceiling:
//!
//! ```
//! use wafrift_evolution::body_padding::{PadOutcome, pad};
//!
//! let body = br#"{"q":"' OR 1=1 --"}"#;
//! let outcome = pad(body, "application/json", 9000);
//! match outcome {
//!     PadOutcome::Padded { bytes, added } => {
//!         assert!(added >= 9000, "padded by at least 9000 bytes");
//!         assert!(bytes.len() > body.len() + 8000);
//!         // Still parses as valid JSON — origin sees the same payload.
//!         let s = std::str::from_utf8(&bytes).unwrap();
//!         assert!(s.contains("' OR 1=1 --"), "attack payload preserved");
//!     }
//!     other => panic!("expected Padded, got {other:?}"),
//! }
//! ```
//!
//! Opaque content types (binary blobs) are left alone — padding
//! would corrupt them:
//!
//! ```
//! use wafrift_evolution::body_padding::{PadOutcome, pad};
//!
//! let outcome = pad(&[0u8; 64], "application/octet-stream", 9000);
//! assert_eq!(outcome, PadOutcome::SkippedOpaque);
//! ```

pub mod advisor;
pub mod ast_mcts;
pub mod body_padding;
pub mod coverage_feedback;
pub mod custom_rules;
pub mod differential;
pub mod dilution;
pub mod evolution;
pub mod intelligence;
pub mod lineage;
/// Persistent per-rule bypass corpus — accumulates rule-level bypass records
/// across hunt rounds and surfaces them to the genome-registry submission gate.
pub mod rule_corpus;
/// Single-call adapter from oracle verdicts → rule_corpus writes.
/// Hunt / bench / model-evade route every probe result through one
/// fn so corpus-key changes propagate without per-consumer churn.
pub mod hunt_corpus_bridge;
pub mod search;
pub mod types;
