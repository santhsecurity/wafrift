//! Comment-based keyword strategies.

use std::fmt::Write as _;

const SQL_KEYWORDS: &[&str] = &[
    "SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP", "WHERE", "FROM", "ORDER", "GROUP",
    "HAVING",
];

/// Insert SQL comments (`/**/`) BETWEEN tokens by replacing spaces with comments.
///
/// Preserves keyword integrity while breaking WAF matching on space-separated tokens.
pub fn sql_comment_insert(payload: &str) -> String {
    payload.replace(' ', "/**/")
}

/// MySQL versioned comment (`/*!50000SELECT*/`) — executed by MySQL, ignored by WAFs.
pub fn mysql_versioned_comment(payload: &str, version: u32) -> String {
    let mut result = String::with_capacity(payload.len() * 2);
    let chars: Vec<char> = payload.chars().collect();
    let lower_chars: Vec<char> = chars.iter().map(|c| c.to_ascii_lowercase()).collect();

    let mut kw_data: Vec<(usize, Vec<char>)> = SQL_KEYWORDS
        .iter()
        .map(|kw| {
            (
                kw.chars().count(),
                kw.chars().map(|c| c.to_ascii_lowercase()).collect(),
            )
        })
        .collect();
    kw_data.sort_by_key(|t| std::cmp::Reverse(t.0));

    let mut i = 0;
    while i < chars.len() {
        let mut matched = false;
        for (kw_len, kw_lower) in &kw_data {
            if i + kw_len <= chars.len() && lower_chars[i..i + kw_len] == kw_lower[..] {
                let _ = write!(&mut result, "/*!{version}");
                for j in 0..*kw_len {
                    result.push(chars[i + j]);
                }
                result.push_str("*/");
                i += kw_len;
                matched = true;
                break;
            }
        }
        if !matched {
            result.push(chars[i]);
            i += 1;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sql_comment_insert_replaces_spaces() {
        assert_eq!(sql_comment_insert("SELECT * FROM"), "SELECT/**/*/**/FROM");
    }

    #[test]
    fn mysql_versioned_comment_wraps_keywords() {
        let result = mysql_versioned_comment("SELECT * FROM users", 50_000);
        assert!(result.contains("/*!50000SELECT*/"));
        assert!(result.contains("/*!50000FROM*/"));
    }
}
