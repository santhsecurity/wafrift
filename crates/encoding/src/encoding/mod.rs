//! Payload encoding strategies — transform payloads to bypass WAF keyword detection.
//!
//! Each strategy changes HOW the payload looks without changing WHAT it does.
//! The server decodes the payload back to its original form, but the WAF
//! fails to match it against its rules.
//!
//! # Scope
//!
//! Every module here is a **WAF-evasion primitive**: it transforms a payload
//! so the WAF's keyword / regex / signature matcher misses it while the
//! origin's normalizer / parser still recovers the original. Modules whose
//! attack target is the origin application (template engines, deserializers,
//! databases, etc) do NOT belong in `wafrift` — those are sibling Santh
//! tools.
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
//! | [`invisible`] | Plan 9 tag chars, variation selectors, ligatures, soft hyphens |
//! | [`path_norm`] | RFC 3986 §5.2.4 differential path-normalization variants |
//! | [`request_line`] | Method / version / URI-form tricks (WAF↔origin parser disagreement) |
//! | [`race`] | Single-packet attack frame builders (Kettle BH23) |
//! | [`method_override`] | `X-HTTP-Method-Override` / `_method` framework re-interpret tricks |
//! | [`cache_poison`] | `X-Forwarded-*` + web cache deception + Vary confusion |

/// Invisible-character & tag-character encoders (Plan 9 tag chars,
/// variation selectors, stylistic ligatures, enclosed alphanumerics,
/// soft hyphens, word joiners). Looks identical, normalizes identical,
/// byte stream is unrecognizable.
pub mod invisible;
/// Keyword manipulation strategies (case, whitespace, comments).
pub mod keyword;
/// Path-normalization differential encoders (dot-segment variants,
/// percent-encoded slash/dot, double-encoded, Tomcat semicolon,
/// IIS backslash, fullwidth slash, overlong UTF-8 dot). Each variant
/// is RFC 3986 §5.2.4-equivalent to the same target — but most WAFs
/// don't run that exact algorithm.
pub mod path_norm;
/// HTTP request-line differential tricks: exotic methods (WebDAV,
/// CalDAV, cache-private), method case/whitespace tricks, version
/// strings (HTTP/0.9, HTTP/1.99, HTTP/2.0-on-h1-wire), absolute-form
/// URI (RFC 7230 §5.3.2), asterisk-form, authority-form.
pub mod request_line;
/// Single-packet race-condition primitives (Kettle BH23 "Smashing the
/// State Machine"): HTTP/1.1 pipelined coalesce + HTTP/2 last-byte-sync
/// frame builders. Builds wire bytes only; the transport layer
/// handles the TCP_NODELAY-off + writev coalesce.
pub mod race;
/// HTTP method-override confusion: framework re-interprets the
/// request method from `X-HTTP-Method-Override` header (3 name
/// variants), `_method` form field / query / multipart, chunked
/// trailer, or header+form disagreement. Wire method shown to WAF
/// is POST; framework executes DELETE/PUT/PATCH/etc.
pub mod method_override;
/// HTTP cache poisoning payloads: X-Forwarded-Host/Scheme/Port,
/// X-Original-URL, X-Host (Akamai), Forwarded (RFC 7239),
/// X-Backend-Host, loopback-trust headers, web cache deception
/// paths (5 extensions × null-byte / semicolon / traversal forms),
/// cache key normalization variants, Vary header confusion, status
/// code poisoning, HTTP/2 :authority split.
pub mod cache_poison;
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
pub use crate::error::EncodeError;
pub use layered::{aggressiveness, encode_layered, layered_combinations};
pub use strategy::{Strategy, all_strategies, encode};
