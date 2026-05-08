//! wafrift-types — Core types shared by all WAF Rift crates.
//!
//! This crate contains the foundational types that every other wafrift
//! crate depends on: HTTP request representation, evasion technique
//! identifiers, result types, configuration, and error handling.

pub mod calibration;
pub mod config;
pub mod error;
pub mod escalation;
pub mod request;
pub mod result;
pub mod technique;
pub mod verdict;

// ──────────────────────────────────────────────
//  Public re-exports
// ──────────────────────────────────────────────

pub use calibration::CalibrationResult;
pub use config::EvasionConfig;
pub use error::{Result, WafRiftError};
pub use escalation::EscalationLevel;
pub use request::{Method, Request};
pub use result::EvasionResult;
pub use technique::Technique;
pub use verdict::{BlockReason, ConnectionBehavior, Signal, Verdict};
