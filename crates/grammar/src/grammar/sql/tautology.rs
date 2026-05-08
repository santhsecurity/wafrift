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

/// Get a random tautology for mutation purposes.
#[must_use]
#[allow(dead_code)]
pub(crate) fn random_tautology() -> &'static str {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    TAUTOLOGIES[rng.gen_range(0..TAUTOLOGIES.len())]
}

/// Get all tautologies matching a specific category.
#[must_use]
#[allow(dead_code)]
pub(crate) fn tautologies_by_category(category: TautologyCategory) -> &'static [&'static str] {
    match category {
        TautologyCategory::Numeric => &[
            "1=1",
            "2>1",
            "1<2",
            "1 BETWEEN 0 AND 2",
            "1 IN(1)",
            "1 IN(1,2,3)",
            "1 IS NOT NULL",
            "NOT 1=0",
            "0x1=0x1",
            "1.0=1.0",
            "1e0=1e0",
            "1&1=1",
            "NOT NOT 1",
            "ISNULL(NULL,1)=1",
            "COS(0)=1",
            "POWER(1,1)=1",
        ],
        TautologyCategory::String => &["'a'='a'", "'a' LIKE 'a'", "N'a'=N'a'", "CHAR(49)=CHAR(49)"],
        TautologyCategory::Function => &[
            "IF(1,1,0)",
            "IIF(1=1,1,0)",
            "ISNULL(NULL,1)=1",
            "COS(0)=1",
            "POWER(1,1)=1",
            "CHAR(49)=CHAR(49)",
            "CASE WHEN 1 THEN 1 END",
            "(CASE 1 WHEN 1 THEN 1 ELSE 0 END)",
        ],
        TautologyCategory::Operator => &[
            "1=1",
            "1 LIKE 1",
            "2>1",
            "1<2",
            "1 BETWEEN 0 AND 2",
            "1 IS NOT NULL",
            "NOT 1=0",
            "1&1=1",
            "NOT NOT 1",
        ],
        TautologyCategory::All => TAUTOLOGIES,
    }
}

/// Categories of tautologies for targeted selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum TautologyCategory {
    /// Numeric comparisons (1=1, 2>1, etc.)
    Numeric,
    /// String comparisons ('a'='a', etc.)
    String,
    /// Function-based tautologies (IF, CASE, etc.)
    Function,
    /// Operator-based tautologies (=, LIKE, etc.)
    Operator,
    /// All tautologies
    All,
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
    fn tautologies_by_category_returns_valid() {
        assert!(!tautologies_by_category(TautologyCategory::Numeric).is_empty());
        assert!(!tautologies_by_category(TautologyCategory::String).is_empty());
        assert!(!tautologies_by_category(TautologyCategory::Function).is_empty());
        assert!(!tautologies_by_category(TautologyCategory::Operator).is_empty());
        assert_eq!(
            tautologies_by_category(TautologyCategory::All).len(),
            TAUTOLOGIES.len()
        );
    }

    #[test]
    fn all_category_tautologies_exist_in_main_array() {
        for &tautology in tautologies_by_category(TautologyCategory::Numeric) {
            assert!(TAUTOLOGIES.contains(&tautology), "Missing: {tautology}");
        }
        for &tautology in tautologies_by_category(TautologyCategory::String) {
            assert!(TAUTOLOGIES.contains(&tautology), "Missing: {tautology}");
        }
        for &tautology in tautologies_by_category(TautologyCategory::Function) {
            assert!(TAUTOLOGIES.contains(&tautology), "Missing: {tautology}");
        }
        for &tautology in tautologies_by_category(TautologyCategory::Operator) {
            assert!(TAUTOLOGIES.contains(&tautology), "Missing: {tautology}");
        }
    }
}
