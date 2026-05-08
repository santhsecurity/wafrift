//! Payload oracles — semantic validation across injection types.
//!
//! The oracle system ensures that evasion transforms preserve exploit
//! semantics. Each oracle understands the structural invariants of a
//! specific injection type and rejects transforms that would render
//! the payload inert.
//!
//! # Architecture
//!
//! ```text
//! PayloadOracle (trait)
//! ├── SqlOracle       — SQL AST parsing via sqlparser
//! ├── XssOracle       — HTML tag/event/exec structure validation
//! ├── SstiOracle      — Template delimiter and expression validation
//! ├── CmdiOracle      — Shell separator + command validation
//! ├── PathOracle      — Directory traversal sequence validation
//! ├── LdapOracle      — LDAP filter syntax validation
//! └── SsrfOracle      — URL structure and host validation
//! ```
//!
//! # Usage
//!
//! ```rust
//! use wafrift_oracle::traits::PayloadOracle;
//! use wafrift_oracle::xss::XssOracle;
//!
//! let oracle = XssOracle;
//! assert!(oracle.is_semantically_valid(
//!     "<script>alert(1)</script>",
//!     "<ScRiPt>alert(1)</sCrIpT>",
//! ));
//! ```

/// Per-target calibration session.
pub mod calibration;
/// Command injection oracle.
pub mod cmdi;
/// LDAP injection oracle.
pub mod ldap;
/// Path traversal oracle.
pub mod path;
/// WAF response oracle.
pub mod response_oracle;
/// Body-marker signal extractor.
pub mod signal_body_marker;
/// Connection-behavior signal extractor.
pub mod signal_connection;
/// H2 GOAWAY signal extractor.
pub mod signal_h2_goaway;
/// Response-time signal extractor.
pub mod signal_response_time;
/// Status-code signal extractor.
pub mod signal_status_code;
/// Response header signal extractor.
pub mod signal_headers;
/// SQL AST oracle.
pub mod sql;
/// SSRF (Server-Side Request Forgery) oracle.
pub mod ssrf;
/// SSTI (Server-Side Template Injection) oracle.
pub mod ssti;
/// Oracle trait definition.
pub mod traits;
/// XSS (Cross-Site Scripting) oracle.
pub mod xss;

use traits::PayloadOracle;
use wafrift_grammar::grammar::PayloadType;

/// SQL oracle adapter that implements the `PayloadOracle` trait.
///
/// Wraps the existing `sql::is_valid_expression_injection` function
/// behind the unified trait interface.
pub struct SqlOracle {
    /// SQL dialect to validate against.
    pub dialect: sql::DatabaseDialect,
}

impl SqlOracle {
    /// Create an oracle for the given dialect.
    #[must_use]
    pub fn new(dialect: sql::DatabaseDialect) -> Self {
        Self { dialect }
    }

    /// Create an oracle using the generic ANSI SQL dialect.
    #[must_use]
    pub fn generic() -> Self {
        Self::new(sql::DatabaseDialect::Generic)
    }
}

impl PayloadOracle for SqlOracle {
    fn is_semantically_valid(&self, _original: &str, transformed: &str) -> bool {
        sql::is_valid_expression_injection(transformed, self.dialect)
    }

    fn name(&self) -> &'static str {
        "SQL"
    }
}

/// Select the appropriate oracle for a given payload type.
///
/// Returns a boxed trait object that can validate payload transforms
/// for the detected injection type.
///
/// # Returns
///
/// `None` for `PayloadType::Unknown` — no oracle can validate an
/// unknown payload type without risk of false positives.
#[must_use]
pub fn oracle_for(payload_type: PayloadType) -> Option<Box<dyn PayloadOracle>> {
    match payload_type {
        PayloadType::Sql => Some(Box::new(SqlOracle::generic())),
        PayloadType::Xss => Some(Box::new(xss::XssOracle)),
        PayloadType::TemplateInjection => Some(Box::new(ssti::SstiOracle)),
        PayloadType::CommandInjection => Some(Box::new(cmdi::CmdiOracle)),
        PayloadType::PathTraversal => Some(Box::new(path::PathOracle)),
        PayloadType::Ldap => Some(Box::new(ldap::LdapOracle)),
        PayloadType::Ssrf => Some(Box::new(ssrf::SsrfOracle)),
        // Future-proof: new payload types get oracles when they're built.
        // Until then, returning None means "don't validate" — safe default.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sql_oracle_adapter_valid() {
        let oracle = SqlOracle::generic();
        assert!(oracle.is_semantically_valid("1 OR 1=1 --", "1 OR 1=1 --",));
    }

    #[test]
    fn sql_oracle_adapter_invalid() {
        let oracle = SqlOracle::generic();
        assert!(!oracle.is_semantically_valid("1 OR 1=1 --", "1 O R 1=1 --",));
    }

    #[test]
    fn oracle_for_sql() {
        let oracle = oracle_for(PayloadType::Sql);
        assert!(oracle.is_some());
        assert_eq!(oracle.as_ref().map(|o| o.name()), Some("SQL"));
    }

    #[test]
    fn oracle_for_xss() {
        let oracle = oracle_for(PayloadType::Xss);
        assert!(oracle.is_some());
        assert_eq!(oracle.as_ref().map(|o| o.name()), Some("XSS"));
    }

    #[test]
    fn oracle_for_ssti() {
        let oracle = oracle_for(PayloadType::TemplateInjection);
        assert!(oracle.is_some());
        assert_eq!(oracle.as_ref().map(|o| o.name()), Some("SSTI"));
    }

    #[test]
    fn oracle_for_cmdi() {
        let oracle = oracle_for(PayloadType::CommandInjection);
        assert!(oracle.is_some());
        assert_eq!(oracle.as_ref().map(|o| o.name()), Some("CMDI"));
    }

    #[test]
    fn oracle_for_path() {
        let oracle = oracle_for(PayloadType::PathTraversal);
        assert!(oracle.is_some());
        assert_eq!(oracle.as_ref().map(|o| o.name()), Some("PathTraversal"));
    }

    #[test]
    fn oracle_for_unknown_is_none() {
        let oracle = oracle_for(PayloadType::Unknown);
        assert!(oracle.is_none());
    }

    #[test]
    fn oracle_for_ldap() {
        let oracle = oracle_for(PayloadType::Ldap);
        assert!(oracle.is_some());
        assert_eq!(oracle.as_ref().map(|o| o.name()), Some("LDAP"));
    }

    #[test]
    fn oracle_for_ssrf() {
        let oracle = oracle_for(PayloadType::Ssrf);
        assert!(oracle.is_some());
        assert_eq!(oracle.as_ref().map(|o| o.name()), Some("SSRF"));
    }

    #[test]
    fn ldap_oracle_validates_filter_structure() {
        let oracle = ldap::LdapOracle;
        // Valid LDAP filter
        assert!(oracle.is_semantically_valid("(uid=admin)", "(uid=admin)"));
        // Boolean operator
        assert!(
            oracle.is_semantically_valid("(|(uid=admin)(uid=root))", "(|(uid=admin)(uid=root))",)
        );
    }

    #[test]
    fn ldap_oracle_rejects_invalid() {
        let oracle = ldap::LdapOracle;
        // No parentheses
        assert!(!oracle.is_semantically_valid("(uid=admin)", "uid=admin"));
        // Empty
        assert!(!oracle.is_semantically_valid("(uid=admin)", ""));
    }

    #[test]
    fn ssrf_oracle_validates_url_structure() {
        let oracle = ssrf::SsrfOracle;
        // Valid SSRF URL
        assert!(oracle.is_semantically_valid("http://127.0.0.1/admin", "http://127.0.0.1/admin",));
        // AWS metadata
        assert!(
            oracle.is_semantically_valid("http://169.254.169.254/", "http://169.254.169.254/",)
        );
    }

    #[test]
    fn ssrf_oracle_rejects_invalid() {
        let oracle = ssrf::SsrfOracle;
        // No scheme
        assert!(!oracle.is_semantically_valid("http://127.0.0.1/", "127.0.0.1"));
        // Public URL
        assert!(!oracle.is_semantically_valid("http://127.0.0.1/", "http://example.com/"));
    }
}
