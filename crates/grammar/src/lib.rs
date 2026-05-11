//! wafrift-grammar — Grammar-aware payload mutation engine.
//!
//! Understands the semantics of SQL, XSS, CMD, LDAP, SSRF,
//! path traversal, and template injection payloads. Generates
//! semantically equivalent variants that bypass regex-based WAF rules.
//!
//! # Examples
//!
//! Classify a payload to its injection family, then mutate it
//! into semantically-equivalent variants:
//!
//! ```
//! use wafrift_grammar::{PayloadType, classify, mutate};
//!
//! let p = "' OR 1=1 --";
//! assert_eq!(classify(p), PayloadType::Sql);
//!
//! let variants = mutate(p, 5);
//! assert!(!variants.is_empty(), "SQL payload must yield mutations");
//! assert!(variants.len() <= 5, "max_mutations is honoured");
//! ```
//!
//! Force a specific grammar to mutate against (useful when the
//! classifier is ambiguous):
//!
//! ```
//! use wafrift_grammar::{PayloadType, mutate_as};
//!
//! let xss = mutate_as("<script>alert(1)</script>", PayloadType::Xss, 3);
//! assert!(!xss.is_empty());
//! assert!(xss.len() <= 3);
//! ```

pub mod grammar;

// Re-export the grammar module's public API at crate root.
pub use grammar::{GrammarMutation, PayloadType, classify, mutate, mutate_as};
