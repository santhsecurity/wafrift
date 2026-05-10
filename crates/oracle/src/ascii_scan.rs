//! ASCII-only scans without allocating a lowercased copy of the full haystack.

/// Returns true if `haystack` contains `needle` as a substring, comparing bytes case-insensitively.
///
/// Both strings must be UTF-8; non-ASCII bytes are compared by lowercasing only when both codepoints
/// are ASCII letters (same behavior as `to_ascii_lowercase()` on mixed scripts).
pub(crate) fn contains_ascii_insensitive(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let hay = haystack.as_bytes();
    let nb = needle.as_bytes();
    if nb.len() > hay.len() {
        return false;
    }
    'outer: for i in 0..=hay.len() - nb.len() {
        for j in 0..nb.len() {
            if hay[i + j].to_ascii_lowercase() != nb[j].to_ascii_lowercase() {
                continue 'outer;
            }
        }
        return true;
    }
    false
}

/// Case-insensitive ASCII prefix check.
pub(crate) fn starts_with_ascii_insensitive(haystack: &str, prefix: &str) -> bool {
    let mut hi = haystack.chars();
    let mut pi = prefix.chars();
    loop {
        match (pi.next(), hi.next()) {
            (None, _) => return true,
            (Some(_), None) => return false,
            (Some(pc), Some(hc)) => {
                if !hc.eq_ignore_ascii_case(&pc) {
                    return false;
                }
            }
        }
    }
}
