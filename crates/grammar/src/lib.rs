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
//!
//! Use coverage-guided diversity to avoid emitting duplicate rule combinations:
//!
//! ```
//! use wafrift_grammar::{DiversityPolicy, MutationRequest, PayloadType, mutate_request};
//!
//! let req = MutationRequest {
//!     max_count: 20,
//!     diversity: DiversityPolicy::CoverageGuided,
//!     exclude: Default::default(),
//! };
//! let variants = mutate_request("' OR 1=1--", PayloadType::Sql, &req);
//! // CoverageGuided deduplicates by rules_applied combination.
//! let mut rule_keys: Vec<String> = variants
//!     .iter()
//!     .map(|m| m.rules_applied.join(","))
//!     .collect();
//! rule_keys.sort();
//! rule_keys.dedup();
//! // Every rule combination appears at most once.
//! assert_eq!(rule_keys.len(), variants.len());
//! ```

pub mod grammar;

// Re-export the grammar module's public API at crate root.
//
// §9 WIRING: mutate_request / MutationRequest / DiversityPolicy are part of
// the documented API contract — scald-core calls them directly. Re-exporting
// from the crate root makes the canonical import path obvious and prevents
// consumer drift to the internal submodule path.
pub use grammar::{
    DiversityPolicy, GrammarMutation, MutationRequest, PayloadType, classify, feedback, mutate,
    mutate_as, mutate_as_with_state, mutate_request, mutate_streaming,
};
// Re-export CfgMutatorState so callers can construct persistent oracle state
// without importing the internal grammar::cfg_convergence submodule.
pub use grammar::cfg_convergence::CfgMutatorState;
