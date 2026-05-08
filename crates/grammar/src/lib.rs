//! wafrift-grammar — Grammar-aware payload mutation engine.
//!
//! Understands the semantics of SQL, XSS, CMD, LDAP, SSRF,
//! path traversal, and template injection payloads. Generates
//! semantically equivalent variants that bypass regex-based WAF rules.

pub mod grammar;

// Re-export the grammar module's public API at crate root.
pub use grammar::{GrammarMutation, PayloadType, classify, mutate, mutate_as};
