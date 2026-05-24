//! wafrift-types — Core types shared by all WAF Rift crates.
//!
//! This crate contains the foundational types that every other wafrift
//! crate depends on: HTTP request representation, evasion technique
//! identifiers, result types, and configuration. (Each crate carries
//! its own domain error — a shared error was attempted and removed
//! 2026-05-23 because no caller wanted it.)

pub mod bogon;
pub mod calibration;
pub mod config;
pub mod discovery;
pub mod escalation;
pub mod explanation;
pub mod format;
pub mod injection_context;
pub mod loaders;
pub mod oob;
pub mod request;
pub mod result;
pub mod session;
pub mod technique;
pub mod verdict;

// ──────────────────────────────────────────────
//  Workspace-wide tunables (single source of truth so the proxy,
//  scan-side, and replay paths all agree on baseline timeouts).
// ──────────────────────────────────────────────

/// Default per-request HTTP timeout (seconds). Used by every reqwest
/// client builder in the workspace unless the caller explicitly opts
/// into a different value (e.g. `bench-waf --timeout-secs`).
///
/// Why 30s: the bench corpus includes deliberate ReDoS-style inputs
/// that may legitimately keep a backend busy for tens of seconds, and
/// a too-tight default turns slow-but-real bypasses into spurious
/// "blocked" verdicts. The CLI scan path historically used 10s — that
/// is now considered the override knob, not the floor.
pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;

/// Default redirect chain depth allowed when wafrift acts as an HTTP
/// client. Mirrors curl's default to minimise practitioner surprise.
pub const DEFAULT_MAX_REDIRECTS: usize = 5;

// ──────────────────────────────────────────────
//  Public re-exports
// ──────────────────────────────────────────────

pub use bogon::ip_addr_is_bogon;
pub use calibration::CalibrationResult;
pub use config::EvasionConfig;
pub use escalation::EscalationLevel;
// `WafRiftError` + `Result` alias removed 2026-05-23 (consolidation
// F09/F23) — no external caller; every other crate defines its own
// domain error. If a shared error is needed later, design it from
// actual call-site needs, not from a stub.
pub use request::{Method, Request};
pub use result::EvasionResult;
pub use technique::Technique;
pub use verdict::{BlockReason, ConnectionBehavior, Signal, Verdict};
