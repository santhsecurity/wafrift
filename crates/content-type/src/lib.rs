//! wafrift-content-type — WAFFLED Content-Type switching.
//!
//! Exploits parsing discrepancies between WAFs and web servers
//! by reformatting request bodies in different Content-Type formats.
//!
//! Reference: "WAFFLED: Exploiting Parsing Discrepancies to Bypass WAFs"
//!            Akhavani et al., IEEE S&P 2025
//!
//! # Examples
//!
//! Generate every Content-Type variant from a raw form body:
//!
//! ```
//! use wafrift_content_type::generate_variants_from_body;
//!
//! let body = b"user=admin&pass=' OR 1=1 --";
//! let variants = generate_variants_from_body(body);
//! assert!(variants.len() >= 5, "expect multiple Content-Type shapes");
//! for v in &variants {
//!     assert!(!v.body.is_empty());
//!     assert!(!v.content_type.is_empty());
//! }
//! ```
//!
//! `unique_boundary` takes the user-controlled values to be embedded
//! and returns a deterministic boundary (FNV-1a derived) that does not
//! appear inside any of them — preventing the body from looking like its
//! own delimiter and protecting against attacker-supplied boundary collision:
//!
//! ```
//! use wafrift_content_type::unique_boundary;
//!
//! let a = unique_boundary(&["admin", "' OR 1=1 --"]);
//! let b = unique_boundary(&["admin", "' OR 1=1 --"]);
//! assert_eq!(a, b, "boundaries are deterministic for the same inputs");
//! assert!(!a.contains(' '));
//! assert!(!a.contains("admin"));
//! // Different inputs produce different boundaries
//! let c = unique_boundary(&["root", "other value"]);
//! assert_ne!(a, c, "different inputs produce different boundaries");
//! ```

mod content_type;

pub use content_type::{
    ContentTypeTechnique, ContentTypeVariant, generate_variants, generate_variants_from_body,
    parse_form_body, unique_boundary, xml_safe_name,
};

pub mod formats;
pub mod multipart_enhanced;
