//! wafrift-content-type — WAFFLED Content-Type switching.
//!
//! Exploits parsing discrepancies between WAFs and web servers
//! by reformatting request bodies in different Content-Type formats.
//!
//! Reference: "WAFFLED: Exploiting Parsing Discrepancies to Bypass WAFs"
//!            Akhavani et al., IEEE S&P 2025

mod content_type;

pub use content_type::{
    ContentTypeTechnique, ContentTypeVariant, generate_variants, generate_variants_from_body,
    parse_form_body, unique_boundary, xml_safe_name,
};

pub mod formats;
pub mod multipart_enhanced;
