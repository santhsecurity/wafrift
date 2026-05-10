//! wafrift-encoding — Payload encoding strategies and header obfuscation.
//!
//! Transforms attack payloads using various encoding strategies
//! (URL, Unicode, HTML entity, SQL comments, etc.) and applies
//! header-level obfuscation techniques for WAF bypass.

#![forbid(unsafe_code)]

pub mod auth_bypass;
pub mod encoding;
pub mod error;
pub mod header;
pub mod tamper;
pub mod url_mutate;

// Re-export the encoding submodule's public API at crate root for ergonomics.
pub use encoding::{
    Strategy, aggressiveness, all_strategies, encode, encode_layered, layered_combinations,
};

// Re-export error types.
pub use error::EncodeError;

// Re-export tamper module for convenient access.
pub use tamper::{
    TamperConfig, TamperError, TamperRegistry, TamperStrategy, all_tamper_names, default_registry,
    tamper,
};

pub mod contextual;
