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
/// Deserialization-vulnerability payload generators across Java, .NET,
/// Python, Ruby, PHP, YAML, Hessian. WAFs that scan for keywords miss
/// these because they don't carry keywords — the vulnerability is in
/// the receiving deserializer.
pub mod deserialization;
/// JWT-mutation attack library: alg:none family (4 case variants),
/// algorithm confusion (HS256-with-RSA-key, RS256-flip), embedded
/// JWK, jku/x5u SSRF, kid path-traversal + SQLi + log4shell, empty
/// signature, crit-header bypass, b64 padding tricks, duplicate alg.
pub mod jwt;
/// OAuth 2.0 / OIDC attack library: redirect_uri bypass (11 URL-confusion
/// variants — userinfo, subdomain prefix, path prefix, fragment, percent-encoded
/// dot, backslash parser disagreement, case-fold, port confusion, IP literal,
/// localhost alias, open-redirect chain), state CSRF / binding bugs, PKCE
/// downgrade / reuse / method confusion, scope injection / separator / upgrade,
/// token misuse and replay, response_type+response_mode hybrid-flow confusion,
/// and JWT bearer token mutation relay via the `jwt` module.
pub mod oauth;
/// Single-packet race-condition primitives (Kettle BH23 "Smashing the
/// State Machine"): HTTP/1.1 pipelined coalesce + HTTP/2 last-byte-sync
/// frame builders. Builds wire bytes only; the transport layer
/// handles the TCP_NODELAY-off + writev coalesce.
pub mod race;
/// DOM-clobbering payload library: HTML-only XSS primitives that
/// override JavaScript globals via `<a id=…>`, `<form name=…>`,
/// `<img name=…>`, `<base href=…>`, `<iframe name=…>`, HTMLCollection
/// twins, nested `<form><input>` chains. Defeats CSPs that allow
/// HTML but block `<script>`.
pub mod dom_clobber;
/// Server-side & client-side prototype-pollution payload library:
/// JSON `__proto__`, `constructor.prototype`, lodash-merge / qs-parse
/// bracket-notation, deep-nested-merge variants, MongoDB `$where`
/// gadget. Covers Express, lodash, jQuery, Mongoose, Hoek vulnerable
/// libraries.
pub mod proto_pollution;
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
