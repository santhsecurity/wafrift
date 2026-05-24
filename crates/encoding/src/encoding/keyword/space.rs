//! Space-replacement strategies.

use rand::seq::SliceRandom as _;

const SQL_BLANK_CHARS: &[char] = &['\t', '\n', '\r', '\x0b', '\x0c'];

/// Insert tab characters BETWEEN tokens by replacing spaces with tabs.
///
/// Preserves keyword integrity while breaking WAF regex matching on space-separated tokens.
pub fn whitespace_insert(payload: &str) -> String {
    payload.replace(' ', "\t")
}

/// Replace spaces with SQL comments (`/**/`).
pub fn space_to_comment(payload: &str) -> String {
    payload.replace(' ', "/**/")
}

/// Replace spaces with dash comments (`--\n`).
pub fn space_to_dash(payload: &str) -> String {
    payload.replace(' ', "--\n")
}

/// Replace spaces with MySQL hash line comments (`#\n`).
///
/// `#` is MySQL's line-comment marker and extends to end-of-line.
/// Pre-fix this replaced spaces with bare `#`, which CONSUMED THE
/// REST OF THE PAYLOAD as a single comment — `SELECT * FROM users`
/// became `SELECT#*#FROM#users` which the SQL parser reads as just
/// `SELECT` followed by one giant comment to end-of-input. The
/// payload effectively shipped as `SELECT` (invalid SQL, no
/// injection delivered).
///
/// Adding the trailing `\n` makes `#\n` a zero-content line comment
/// that ends immediately, leaving the following token outside —
/// the same pattern `space_to_dash` uses with `--\n`. Result:
/// MySQL parses the payload as whitespace-separated tokens that
/// happen to have inline line-comment fillers between them.
pub fn space_to_hash(payload: &str) -> String {
    payload.replace(' ', "#\n")
}

/// Replace spaces with plus signs (`+`).
pub fn space_to_plus(payload: &str) -> String {
    payload.replace(' ', "+")
}

/// Replace spaces with random blank characters.
pub fn space_to_random_blank(payload: &str) -> String {
    let mut rng = rand::thread_rng();
    payload
        .chars()
        .map(|c| {
            if c == ' ' {
                *SQL_BLANK_CHARS.choose(&mut rng).unwrap_or(&'\t')
            } else {
                c
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitespace_insert_replaces_spaces() {
        assert_eq!(whitespace_insert("SELECT * FROM"), "SELECT\t*\tFROM");
    }

    #[test]
    fn space_to_comment_replaces_spaces() {
        assert_eq!(space_to_comment("SELECT * FROM"), "SELECT/**/*/**/FROM");
    }

    #[test]
    fn space_to_dash_replaces_spaces() {
        assert_eq!(space_to_dash("SELECT * FROM"), "SELECT--\n*--\nFROM");
    }

    #[test]
    fn space_to_hash_replaces_spaces_with_terminated_line_comment() {
        // Each space becomes `#\n` (hash + newline). The newline
        // terminates MySQL's line comment so subsequent tokens
        // survive — pre-fix this used bare `#` which consumed the
        // rest of the payload as a single comment, leaving only
        // the first token. Regression test for F53(b).
        assert_eq!(
            space_to_hash("SELECT * FROM"),
            "SELECT#\n*#\nFROM",
            "must end the # comment with a newline so * and FROM survive"
        );
        // Sanity: the output still contains every original keyword.
        let out = space_to_hash("UNION SELECT 1 FROM users");
        for kw in ["UNION", "SELECT", "1", "FROM", "users"] {
            assert!(out.contains(kw), "{kw} dropped from payload: {out}");
        }
    }

    #[test]
    fn space_to_plus_replaces_spaces() {
        assert_eq!(space_to_plus("SELECT * FROM"), "SELECT+*+FROM");
    }

    #[test]
    fn space_to_random_blank_replaces_spaces() {
        let result = space_to_random_blank("SELECT * FROM");
        assert!(!result.contains(' '));
        assert_eq!(result.len(), "SELECT * FROM".len());
    }
}
