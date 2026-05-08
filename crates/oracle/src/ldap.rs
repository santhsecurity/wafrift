//! LDAP injection payload oracle.
//!
//! LDAP injection payloads manipulate directory search filters. A valid LDAP
//! injection must preserve:
//! 1. **Filter delimiters** — balanced parentheses `(` and `)`
//! 2. **Boolean operators** — `|` (OR), `&` (AND), `!` (NOT)
//! 3. **Attribute-value assertions** — `attr=value` pairs
//! 4. **Wildcard patterns** — `*` for substring matches
//!
//! If encoding destroys parentheses or operators, the filter becomes syntactically
//! invalid and the directory server will reject it.

use crate::traits::PayloadOracle;

/// LDAP injection oracle that validates filter structure preservation.
pub struct LdapOracle;

/// LDAP filter operators that control boolean logic.
const LDAP_OPERATORS: &[&str] = &["|", "&", "!"];

/// Common LDAP attribute names used in injections.
const LDAP_ATTRIBUTES: &[&str] = &[
    "uid=",
    "cn=",
    "dn=",
    "dc=",
    "ou=",
    "o=",
    "mail=",
    "objectClass=",
    "objectclass=",
    "memberOf=",
    "userPassword=",
    "sn=",
    "givenName=",
];

/// LDAP filter wildcards for substring searches.
const LDAP_WILDCARD: &str = "*";

/// Checks whether a payload contains LDAP filter structure.
fn has_ldap_structure(payload: &str) -> bool {
    let lower = payload.to_ascii_lowercase();

    // Must have balanced parentheses for valid filter syntax
    let paren_open_count = payload.matches('(').count();
    let paren_close_count = payload.matches(')').count();
    let has_parentheses = paren_open_count > 0 && paren_close_count > 0;

    // Check for LDAP operators
    let has_operator = LDAP_OPERATORS.iter().any(|op| payload.contains(*op));

    // Check for attribute=value patterns
    let has_attribute = LDAP_ATTRIBUTES.iter().any(|attr| lower.contains(attr));

    // Check for wildcards
    let has_wildcard = payload.contains(LDAP_WILDCARD);

    // Valid LDAP filter needs:
    // - Parentheses (required for filter structure)
    // - Plus at least one of: operator, attribute, or wildcard
    has_parentheses && (has_operator || has_attribute || has_wildcard)
}

/// Validates that parentheses are balanced (basic LDAP filter sanity check).
fn has_balanced_parentheses(payload: &str) -> bool {
    let mut depth = 0i32;
    for ch in payload.chars() {
        match ch {
            '(' => depth += 1,
            ')' => depth -= 1,
            _ => {}
        }
        if depth < 0 {
            return false; // Closing before opening
        }
    }
    depth == 0
}

impl PayloadOracle for LdapOracle {
    fn is_semantically_valid(&self, _original: &str, transformed: &str) -> bool {
        // Empty or whitespace-only is invalid
        if transformed.trim().is_empty() {
            return false;
        }

        // Must have LDAP structure
        if !has_ldap_structure(transformed) {
            return false;
        }

        // Parentheses must be balanced for valid filter syntax
        has_balanced_parentheses(transformed)
    }

    fn name(&self) -> &'static str {
        "LDAP"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uid_filter_valid() {
        let oracle = LdapOracle;
        assert!(oracle.is_semantically_valid("(uid=admin)", "(uid=admin)"));
    }

    #[test]
    fn cn_filter_valid() {
        let oracle = LdapOracle;
        assert!(oracle.is_semantically_valid("(cn=admin)", "(cn=admin)"));
    }

    #[test]
    fn boolean_or_filter_valid() {
        let oracle = LdapOracle;
        assert!(
            oracle.is_semantically_valid("(|(uid=admin)(uid=root))", "(|(uid=admin)(uid=root))",)
        );
    }

    #[test]
    fn boolean_and_filter_valid() {
        let oracle = LdapOracle;
        assert!(oracle.is_semantically_valid(
            "(&(uid=admin)(objectClass=person))",
            "(&(uid=admin)(objectClass=person))",
        ));
    }

    #[test]
    fn negation_filter_valid() {
        let oracle = LdapOracle;
        assert!(oracle.is_semantically_valid("(!(uid=admin))", "(!(uid=admin))",));
    }

    #[test]
    fn wildcard_filter_valid() {
        let oracle = LdapOracle;
        assert!(oracle.is_semantically_valid("(uid=*)", "(uid=*)"));
        assert!(oracle.is_semantically_valid("(cn=ad*)", "(cn=ad*)"));
        assert!(oracle.is_semantically_valid("(mail=*@domain.com)", "(mail=*@domain.com)"));
    }

    #[test]
    fn complex_nested_filter_valid() {
        let oracle = LdapOracle;
        assert!(oracle.is_semantically_valid(
            "(&(|(uid=admin)(uid=root))(objectClass=person))",
            "(&(|(uid=admin)(uid=root))(objectClass=person))",
        ));
    }

    #[test]
    fn injection_bypass_valid() {
        let oracle = LdapOracle;
        // Common LDAP injection pattern - balanced version
        // This pattern creates an always-true OR condition
        assert!(oracle.is_semantically_valid("(uid=admin)(|(uid=*))", "(uid=admin)(|(uid=*))",));
    }

    #[test]
    fn objectclass_filter_valid() {
        let oracle = LdapOracle;
        assert!(oracle.is_semantically_valid("(objectClass=*)", "(objectClass=*)",));
    }

    #[test]
    fn empty_string_invalid() {
        let oracle = LdapOracle;
        assert!(!oracle.is_semantically_valid("(uid=admin)", ""));
    }

    #[test]
    fn plain_text_invalid() {
        let oracle = LdapOracle;
        assert!(!oracle.is_semantically_valid("(uid=admin)", "hello world"));
    }

    #[test]
    fn missing_parentheses_invalid() {
        let oracle = LdapOracle;
        // No parentheses - not a valid LDAP filter
        assert!(!oracle.is_semantically_valid("(uid=admin)", "uid=admin"));
    }

    #[test]
    fn unbalanced_parens_invalid() {
        let oracle = LdapOracle;
        // Unbalanced parentheses
        assert!(!oracle.is_semantically_valid("(uid=admin)", "((uid=admin)"));
        assert!(!oracle.is_semantically_valid("(uid=admin)", "(uid=admin))"));
    }

    #[test]
    fn encoded_operators_still_valid() {
        let oracle = LdapOracle;
        // URL encoded operator is still preserved in structure
        // The oracle checks structure preservation, not encoding
        // %7C is '|' encoded - the structure still has parens and attribute
        assert!(
            oracle.is_semantically_valid("(|(uid=admin)(uid=root))", "(%7C(uid=admin)(uid=root))",)
        );
    }

    #[test]
    fn case_insensitive_attributes() {
        let oracle = LdapOracle;
        // LDAP attribute names are case-insensitive
        assert!(oracle.is_semantically_valid("(uid=admin)", "(UID=admin)"));
        assert!(oracle.is_semantically_valid("(cn=admin)", "(CN=admin)"));
        assert!(oracle.is_semantically_valid("(objectClass=*)", "(objectclass=*)"));
    }

    #[test]
    fn mail_attribute_valid() {
        let oracle = LdapOracle;
        assert!(
            oracle.is_semantically_valid("(mail=admin@example.com)", "(mail=admin@example.com)",)
        );
    }

    #[test]
    fn dc_attribute_valid() {
        let oracle = LdapOracle;
        assert!(oracle.is_semantically_valid("(dc=example,dc=com)", "(dc=example,dc=com)",));
    }

    #[test]
    fn dn_attribute_valid() {
        let oracle = LdapOracle;
        assert!(oracle.is_semantically_valid("(dn=cn=admin,dc=com)", "(dn=cn=admin,dc=com)",));
    }

    #[test]
    fn memberof_attribute_valid() {
        let oracle = LdapOracle;
        assert!(
            oracle.is_semantically_valid(
                "(memberOf=cn=admins,dc=com)",
                "(memberOf=cn=admins,dc=com)",
            )
        );
    }

    #[test]
    fn ou_attribute_valid() {
        let oracle = LdapOracle;
        assert!(oracle.is_semantically_valid("(ou=users)", "(ou=users)",));
    }

    #[test]
    fn adversarial_unicode_injection() {
        let oracle = LdapOracle;
        // Unicode lookalikes should be detected as invalid
        // (fullwidth parentheses don't count as real parens)
        assert!(!oracle.is_semantically_valid(
            "(uid=admin)",
            "（uid=admin）", // Fullwidth parentheses
        ));
    }

    #[test]
    fn adversarial_null_byte() {
        let oracle = LdapOracle;
        // Null byte injection attempt - structure should still be valid
        // (the oracle checks structure, not exploitability)
        assert!(oracle.is_semantically_valid("(uid=admin)", "(uid=admin)\x00",));
    }

    #[test]
    fn adversarial_comment_injection() {
        let oracle = LdapOracle;
        // Attempt to inject a comment-like sequence
        assert!(oracle.is_semantically_valid("(uid=admin)", "(uid=admin)/*comment*/",));
    }

    #[test]
    fn oracle_name_is_ldap() {
        let oracle = LdapOracle;
        assert_eq!(oracle.name(), "LDAP");
    }
}
