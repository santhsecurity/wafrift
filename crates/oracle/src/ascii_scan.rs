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
            if !hay[i + j].eq_ignore_ascii_case(&nb[j]) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contains_ascii_insensitive_empty_needle_is_always_true() {
        assert!(contains_ascii_insensitive("anything", ""));
        assert!(contains_ascii_insensitive("", ""));
    }

    #[test]
    fn contains_ascii_insensitive_exact_case_match() {
        assert!(contains_ascii_insensitive("ERROR: SQL syntax", "SQL"));
    }

    #[test]
    fn contains_ascii_insensitive_different_case() {
        assert!(contains_ascii_insensitive("error: SQL syntax", "sql"));
        assert!(contains_ascii_insensitive("ERROR: SQL syntax", "sql"));
        assert!(contains_ascii_insensitive("ERROR: sql syntax", "SQL"));
    }

    #[test]
    fn contains_ascii_insensitive_returns_false_when_absent() {
        assert!(!contains_ascii_insensitive("nothing here", "xyz"));
        assert!(!contains_ascii_insensitive("short", "very long needle"));
    }

    #[test]
    fn contains_ascii_insensitive_empty_haystack_with_nonempty_needle() {
        assert!(!contains_ascii_insensitive("", "x"));
    }

    #[test]
    fn contains_ascii_insensitive_at_start_middle_end() {
        assert!(contains_ascii_insensitive("ABCDEF", "abc"));
        assert!(contains_ascii_insensitive("ABCDEF", "CDE"));
        assert!(contains_ascii_insensitive("ABCDEF", "def"));
    }

    #[test]
    fn contains_ascii_insensitive_non_alpha_chars_unchanged() {
        assert!(contains_ascii_insensitive("error 1=1 done", "1=1"));
        assert!(contains_ascii_insensitive("payload 'or'", "'OR'"));
    }

    #[test]
    fn contains_ascii_insensitive_unicode_does_not_panic() {
        let _ = contains_ascii_insensitive("café au lait", "AU");
        let _ = contains_ascii_insensitive("日本語", "日本");
    }

    #[test]
    fn contains_ascii_insensitive_haystack_shorter_than_needle() {
        assert!(!contains_ascii_insensitive("hi", "hello"));
    }

    #[test]
    fn contains_ascii_insensitive_overlapping_potential_matches() {
        // "aaab" contains "aab" — verify the search continues
        // past failed prefix matches without skipping valid ones.
        assert!(contains_ascii_insensitive("aaab", "AAB"));
    }

    #[test]
    fn starts_with_ascii_insensitive_empty_prefix_is_always_true() {
        assert!(starts_with_ascii_insensitive("anything", ""));
        assert!(starts_with_ascii_insensitive("", ""));
    }

    #[test]
    fn starts_with_ascii_insensitive_matches_case_insensitive() {
        assert!(starts_with_ascii_insensitive("HTTP/1.1 200 OK", "http"));
        assert!(starts_with_ascii_insensitive("http/1.1", "HTTP"));
    }

    #[test]
    fn starts_with_ascii_insensitive_no_match_returns_false() {
        assert!(!starts_with_ascii_insensitive("abc", "xyz"));
        assert!(!starts_with_ascii_insensitive("abc", "abcd"));
    }

    #[test]
    fn starts_with_ascii_insensitive_haystack_shorter_than_prefix_false() {
        assert!(!starts_with_ascii_insensitive("short", "shortest"));
    }

    #[test]
    fn starts_with_ascii_insensitive_exact_match() {
        // Prefix == haystack — should match (every char of prefix
        // consumed before haystack exhausts).
        assert!(starts_with_ascii_insensitive("HELLO", "hello"));
        assert!(starts_with_ascii_insensitive("hello", "HELLO"));
    }

    #[test]
    fn starts_with_ascii_insensitive_multibyte_does_not_panic() {
        let _ = starts_with_ascii_insensitive("café au lait", "cafe");
        let _ = starts_with_ascii_insensitive("日本語", "日");
    }

    #[test]
    fn starts_with_ascii_insensitive_partial_match_returns_false() {
        // "Authorization" doesn't start with "Authorize".
        assert!(!starts_with_ascii_insensitive("Authorization", "Authorize"));
    }

    #[test]
    fn ascii_helpers_treat_digits_and_punctuation_as_case_invariant() {
        // Non-alphabetic bytes compare equal regardless of case
        // folding — `1=1` matches itself, `?` matches itself.
        assert!(contains_ascii_insensitive("foo?1=1!bar", "?1=1!"));
        assert!(starts_with_ascii_insensitive("?123", "?123"));
    }

    #[test]
    fn contains_ascii_insensitive_full_haystack_is_match() {
        assert!(contains_ascii_insensitive("EXACT", "exact"));
    }

    #[test]
    fn ascii_helpers_handle_long_input_without_panic() {
        let long = "abcdef".repeat(10_000);
        assert!(contains_ascii_insensitive(&long, "ABCDEF"));
        assert!(starts_with_ascii_insensitive(&long, "abcdef"));
    }
}
