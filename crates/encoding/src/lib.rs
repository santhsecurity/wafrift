//! wafrift-encoding — Payload encoding strategies and header obfuscation.
//!
//! See [`cookie_smuggle`] for RFC 6265-vs-6265bis Cookie-header
//! parser-differential probes (prefix bypass, duplicate-name pairs,
//! quoted-semicolon values, empty-name pairs, control-byte injection,
//! whitespace around `=`).
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
pub mod auth_header_smuggle;
pub mod compression;
pub mod cookie_smuggle;
pub mod encoding;
pub mod error;
pub mod header;
pub mod host_header_smuggle;
pub mod jwt_smuggle;
pub mod path_normalize_smuggle;
pub mod path_prefix;
pub mod range_header_smuggle;
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

/// Largest UTF-8 char-boundary byte index `<= idx` in `s` (and `<= s.len()`).
///
/// §7 canonical home for the "snap a byte offset down to a char boundary"
/// primitive used across the header/cookie/range smuggle builders. These
/// builders cap header values with `String::truncate(N)` and split values at
/// computed byte offsets; their inputs (operator `--credential`, payload
/// seeds) pass through sanitisers that strip only CR/LF/NUL, so multibyte
/// UTF-8 survives and a raw byte index can land mid-codepoint — where
/// `String::truncate` / `&s[..idx]` PANIC. Routing every such site through
/// this one helper keeps them boundary-safe and prevents the three copies
/// (was: `header::char_boundary_near`, `cookie_smuggle`'s local copy, and the
/// open-coded walks) from drifting.
#[must_use]
pub(crate) fn floor_char_boundary(s: &str, idx: usize) -> usize {
    let mut i = idx.min(s.len());
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

#[cfg(test)]
mod floor_char_boundary_tests {
    use super::floor_char_boundary;

    #[test]
    fn snaps_down_to_boundary_and_clamps_to_len() {
        // "é" is 2 bytes (0xC3 0xA9). Index 1 is mid-codepoint → snap to 0.
        assert_eq!(floor_char_boundary("éa", 1), 0);
        // A boundary index is returned unchanged.
        assert_eq!(floor_char_boundary("éa", 2), 2); // after `é`
        assert_eq!(floor_char_boundary("éa", 3), 3); // after `a` (== len)
        // Past the end clamps to len (never panics, never exceeds).
        assert_eq!(floor_char_boundary("éa", 99), 3);
        // ASCII: every index is a boundary.
        assert_eq!(floor_char_boundary("abcd", 2), 2);
        // Empty string clamps to 0.
        assert_eq!(floor_char_boundary("", 5), 0);
        // 4-byte char (🦀) — every interior index snaps to the start.
        assert_eq!(floor_char_boundary("🦀", 1), 0);
        assert_eq!(floor_char_boundary("🦀", 3), 0);
        assert_eq!(floor_char_boundary("🦀", 4), 4);
    }
}
