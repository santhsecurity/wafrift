//! Payload encoding strategies — transform payloads to bypass WAF keyword detection.
//!
//! Each strategy changes HOW the payload looks without changing WHAT it does.
//! The server decodes the payload back to its original form, but the WAF
//! fails to match it against its rules.
//!
//! # Module structure
//!
//! | Module | Responsibility |
//! |--------|---------------|
//! | [`strategy`] | `Strategy` enum and `encode()` dispatcher |
//! | [`url`] | URL, double-URL, and triple-URL encoding |
//! | [`unicode`] | Unicode `\uXXXX`, `%uXXXX`, JSON, and HTML entity encoding |
//! | [`keyword`] | Case alternation, whitespace/comment insertion, SQL obfuscation |
//! | [`structural`] | Null byte, overlong UTF-8, chunked split, HPP, compression |
//! | [`layered`] | Multi-strategy chaining and aggressiveness scoring |

/// Invisible-character & tag-character encoders (Plan 9 tag chars,
/// variation selectors, stylistic ligatures, enclosed alphanumerics,
/// soft hyphens, word joiners). Looks identical, normalizes identical,
/// byte stream is unrecognizable.
pub mod invisible;
/// Keyword manipulation strategies (case, whitespace, comments).
pub mod keyword;
/// Multi-strategy layering and aggressiveness scoring.
pub mod layered;
/// Strategy enum and encode() dispatcher.
pub mod strategy;
/// Structural encoding strategies (null byte, overlong UTF-8, chunked, HPP).
pub mod structural;
/// Unicode and HTML entity encoding strategies.
pub mod unicode;
/// URL-based encoding strategies (single, double, triple).
pub mod url;

#[cfg(test)]
mod tests;

// Re-export everything for backwards compatibility (LAW 2).
pub use layered::{aggressiveness, encode_layered, layered_combinations};
pub use strategy::{Strategy, all_strategies, encode};
