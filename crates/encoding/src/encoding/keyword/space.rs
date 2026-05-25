//! Space-replacement strategies.

const SQL_BLANK_CHARS: &[char] = &['\t', '\n', '\r', '\x0b', '\x0c'];

/// FNV-1a hash of (byte index, payload bytes) for deterministic blank-char selection.
fn fnv1a_space_hash(space_idx: usize, payload: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in space_idx.to_le_bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3);
    }
    for b in payload.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

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

/// Replace spaces with a deterministic blank character derived from FNV-1a hash.
///
/// Each space's replacement is derived from `fnv1a_space_hash(space_index, payload)`,
/// making the output byte-identical for identical inputs across all runs.
pub fn space_to_random_blank(payload: &str) -> String {
    let mut space_idx = 0usize;
    payload
        .chars()
        .map(|c| {
            if c == ' ' {
                let h = fnv1a_space_hash(space_idx, payload);
                space_idx += 1;
                SQL_BLANK_CHARS[(h as usize) % SQL_BLANK_CHARS.len()]
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

    #[test]
    fn space_to_random_blank_is_deterministic() {
        let payload = "SELECT * FROM t WHERE a = 1";
        let a = space_to_random_blank(payload);
        let b = space_to_random_blank(payload);
        assert_eq!(a, b, "space_to_random_blank must be byte-identical for identical input");
    }
}
