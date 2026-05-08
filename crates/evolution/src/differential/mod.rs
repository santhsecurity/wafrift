//! WAF rule differential analysis — reverse-engineer what a WAF blocks.
//!
//! Sends a matrix of carefully crafted probe payloads that isolate
//! individual WAF rule triggers. By observing which probes get blocked
//! vs. which pass through, we can infer the WAF's regex rules and
//! generate payloads that specifically avoid those patterns.
//!
//! # How it works
//!
//! ```text
//! 1. Send baseline (benign) request      → expect PASS
//! 2. Send known-malicious probe          → expect BLOCK
//! 3. Send focused probe batches          → observe which BLOCK
//! 4. Infer which components trigger the WAF
//! 5. Generate payloads that avoid those specific triggers
//! ```

pub mod analysis;
pub mod binary_search;
pub mod probe;
mod report;

pub use analysis::*;
pub use binary_search::*;
pub use probe::*;
