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

/// Replace spaces with hash comments (`#`).
pub fn space_to_hash(payload: &str) -> String {
    payload.replace(' ', "#")
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
    fn space_to_hash_replaces_spaces() {
        assert_eq!(space_to_hash("SELECT * FROM"), "SELECT#*#FROM");
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
