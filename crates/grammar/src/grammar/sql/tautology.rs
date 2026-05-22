//! Tautology-specific SQL mutation helpers.

/// Tautologies that always evaluate to true in SQL.
pub(crate) const TAUTOLOGIES: &[&str] = &[
    "1=1",
    "1 LIKE 1",
    "2>1",
    "'a'='a'",
    "1 IN(1)",
    "1 BETWEEN 0 AND 2",
    "1<2",
    "'a' LIKE 'a'",
    "1 IS NOT NULL",
    "NOT 1=0",
    "1 IN(1,2,3)",
    "ISNULL(NULL,1)=1",
    "CHAR(49)=CHAR(49)",
    "0x1=0x1",
    "1.0=1.0",
    "1e0=1e0",
    "CASE WHEN 1 THEN 1 END",
    "(CASE 1 WHEN 1 THEN 1 ELSE 0 END)",
    "IF(1,1,0)",
    "IIF(1=1,1,0)",
    "COS(0)=1",
    "POWER(1,1)=1",
    "N'a'=N'a'",
    "1&1=1",
    "NOT NOT 1",
];

/// Check whether the payload contains a recognizable SQL tautology.
///
/// This function checks against ALL 25 defined tautology patterns to ensure
/// comprehensive detection of always-true conditions in SQL injection payloads.
pub(crate) fn contains_tautology(payload: &str) -> bool {
    let lower = payload.to_ascii_lowercase();

    // Check all tautology patterns from the TAUTOLOGIES array
    for &tautology in TAUTOLOGIES {
        if lower.contains(&tautology.to_ascii_lowercase()) {
            return true;
        }
    }

    // Additional pattern checks for variations
    lower.contains("true")
        || lower.contains("1\x001")  // Null byte bypass attempt
        || lower.contains("'a'\x00='a'")
}

/// Replace the tautology portion of a payload with another tautology.
pub(crate) fn replace_tautology(payload: &str, replacement: &str) -> Option<String> {
    let lower = payload.to_ascii_lowercase();

    // Check all tautology patterns for replacement
    for &pattern in TAUTOLOGIES {
        if let Some(position) = lower.find(&pattern.to_ascii_lowercase()) {
            let mut result = String::with_capacity(payload.len() + replacement.len());
            result.push_str(&payload[..position]);
            result.push_str(replacement);
            result.push_str(&payload[position + pattern.len()..]);
            return Some(result);
        }
    }

    // Fallback patterns for common variations
    for pattern in ["true"] {
        if let Some(position) = lower.find(pattern) {
            let mut result = String::with_capacity(payload.len() + replacement.len());
            result.push_str(&payload[..position]);
            result.push_str(replacement);
            result.push_str(&payload[position + pattern.len()..]);
            return Some(result);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_all_defined_tautologies() {
        // Verify every tautology in the array is detected
        for &tautology in TAUTOLOGIES {
            let payload = format!("' OR {tautology}--");
            assert!(
                contains_tautology(&payload),
                "Failed to detect tautology: {tautology}"
            );
        }
    }

    #[test]
    fn detects_tautology_in_context() {
        assert!(contains_tautology("' OR 1=1--"));
        assert!(contains_tautology("admin' AND 1=1#"));
        assert!(contains_tautology("1' AND 'a'='a'"));
        assert!(contains_tautology("id=1 AND 2>1"));
    }

    #[test]
    fn detects_case_insensitive() {
        assert!(contains_tautology("' OR 1=1--"));
        assert!(contains_tautology("' OR 1=1--"));
        assert!(contains_tautology("' OR 'A'='A'--"));
        assert!(contains_tautology("' OR 1 LIKE 1--"));
    }

    #[test]
    fn detects_complex_tautologies() {
        assert!(contains_tautology("1 IN(1,2,3)"));
        assert!(contains_tautology("1 BETWEEN 0 AND 2"));
        assert!(contains_tautology("ISNULL(NULL,1)=1"));
        assert!(contains_tautology("CHAR(49)=CHAR(49)"));
        assert!(contains_tautology("0x1=0x1"));
        assert!(contains_tautology("1.0=1.0"));
        assert!(contains_tautology("1e0=1e0"));
        assert!(contains_tautology("CASE WHEN 1 THEN 1 END"));
        assert!(contains_tautology("(CASE 1 WHEN 1 THEN 1 ELSE 0 END)"));
        assert!(contains_tautology("IF(1,1,0)"));
        assert!(contains_tautology("IIF(1=1,1,0)"));
        assert!(contains_tautology("COS(0)=1"));
        assert!(contains_tautology("POWER(1,1)=1"));
        assert!(contains_tautology("N'a'=N'a'"));
        assert!(contains_tautology("1&1=1"));
        assert!(contains_tautology("NOT NOT 1"));
    }

    #[test]
    fn detects_true_keyword() {
        assert!(contains_tautology("' OR true--"));
        assert!(contains_tautology("WHERE true"));
    }

    #[test]
    fn rejects_non_tautologies() {
        assert!(!contains_tautology("' OR 1=2--"));
        assert!(!contains_tautology("id=123"));
        assert!(!contains_tautology("name='admin'"));
        assert!(!contains_tautology("SELECT * FROM users"));
    }

    #[test]
    fn replace_finds_and_replaces() {
        let result = replace_tautology("' OR 1=1--", "'a'='a'");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "' OR 'a'='a'--");
    }

    #[test]
    fn replace_handles_complex_patterns() {
        let result = replace_tautology("admin' AND 2>1#", "1=1");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "admin' AND 1=1#");
    }

    #[test]
    fn replace_returns_none_when_no_tautology() {
        let result = replace_tautology("SELECT * FROM users", "1=1");
        assert!(result.is_none());
    }

    #[test]
    fn tautology_count_is_25() {
        assert_eq!(TAUTOLOGIES.len(), 25, "Expected exactly 25 tautologies");
    }

    #[test]
    fn replace_with_complex_tautology_inserts_correctly() {
        // Replace with a string-form tautology — verifies the
        // replacement path handles quoted-string patterns
        // alongside numeric ones.
        let result = replace_tautology("' OR 1=1--", "'a'='a'");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "' OR 'a'='a'--");
    }

    #[test]
    fn detects_function_based_tautology() {
        assert!(contains_tautology("' OR IF(1,1,0)--"));
        assert!(contains_tautology("' OR CHAR(49)=CHAR(49)--"));
    }

    #[test]
    fn detects_unicode_string_tautology() {
        assert!(contains_tautology("' OR N'a'=N'a'--"));
    }

    #[test]
    fn detects_hex_literal_tautology() {
        assert!(contains_tautology("' OR 0x1=0x1--"));
    }

    #[test]
    fn detects_scientific_notation_tautology() {
        assert!(contains_tautology("' OR 1e0=1e0--"));
    }

    #[test]
    fn empty_input_is_not_a_tautology() {
        assert!(!contains_tautology(""));
    }

    #[test]
    fn whitespace_only_is_not_a_tautology() {
        assert!(!contains_tautology("   "));
    }

    #[test]
    fn replace_preserves_payload_around_tautology() {
        // Property: the prefix and suffix on either side of the
        // matched tautology are preserved byte-for-byte.
        let prefix = "admin' AND ";
        let suffix = " -- comment";
        let original = format!("{prefix}1=1{suffix}");
        let replaced = replace_tautology(&original, "0=0").expect("replaces");
        assert!(replaced.starts_with(prefix));
        assert!(replaced.ends_with(suffix));
        assert!(replaced.contains("0=0"));
    }

    #[test]
    fn detects_tautology_in_mixed_case() {
        // The detector lowercases first — UPPERCASE tautologies
        // should still register.
        assert!(contains_tautology("' OR 'A' LIKE 'A'--"));
        assert!(contains_tautology("' OR ISNULL(NULL,1)=1--"));
    }

    #[test]
    fn replace_no_change_when_replacement_equals_original() {
        // Idempotency boundary: replacing `1=1` with `1=1` returns
        // the original payload exactly.
        let result = replace_tautology("' OR 1=1--", "1=1").expect("replaces");
        assert_eq!(result, "' OR 1=1--");
    }
}
