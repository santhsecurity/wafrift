//! wafrift-encoding — Payload encoding strategies and header obfuscation.
//!
//! Transforms attack payloads using various encoding strategies
//! (URL, Unicode, HTML entity, SQL comments, etc.) and applies
//! header-level obfuscation techniques for WAF bypass.
//!
//! # Examples
//!
//! Single-pass encoding with one strategy:
//!
//! ```
//! use wafrift_encoding::{Strategy, encode};
//!
//! let payload = "' OR 1=1--";
//! let url_encoded = encode(payload, Strategy::UrlEncode).unwrap();
//! assert!(url_encoded.contains("%27"));    // single quote
//! assert!(url_encoded.contains("%20"));    // space
//! assert!(url_encoded.contains("%3D"));    // equals
//!
//! // Same payload, double-encoded — bypasses single-decode WAFs.
//! let double = encode(payload, Strategy::DoubleUrlEncode).unwrap();
//! assert!(double.contains("%2527"));
//! ```
//!
//! Layered encoding for stronger evasion (HTML-entity-encode the
//! Unicode-escaped form):
//!
//! ```
//! use wafrift_encoding::{Strategy, encode_layered};
//!
//! let result = encode_layered(
//!     "<script>",
//!     &[Strategy::UnicodeEncode, Strategy::HtmlEntityEncode],
//! ).unwrap();
//! assert!(result.contains('&'));   // HTML entity encoded
//! ```

#![forbid(unsafe_code)]

pub mod auth_bypass;
pub mod compression;
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

/// Unified catalog of every attack-payload library — one call
/// returns all 18+ vuln-class fan-outs. The single registry consumers
/// (scan, model-evade, bench, hunt) hit to reach every shipped
/// attack surface.
pub mod payload_catalog;
