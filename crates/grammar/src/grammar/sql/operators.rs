//! Operator and delimiter mutation helpers.

/// Find all balanced string-literal regions in a payload.
///
/// Returns a list of `(start, end)` byte ranges for quoted regions.
/// Unbalanced quotes are ignored. SQL-style escaped quotes (`''`)
/// are treated as a single literal character, not a terminator.
fn quoted_regions(payload: &str) -> Vec<(usize, usize)> {
    let bytes = payload.as_bytes();
    let mut regions = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\'' || bytes[i] == b'"' {
            let quote = bytes[i];
            let start = i;
            i += 1;
            while i < bytes.len() {
                if bytes[i] == quote {
                    // SQL-style escaped quote: '' or "" — skip both.
                    if i + 1 < bytes.len() && bytes[i + 1] == quote {
                        i += 2;
                        continue;
                    }
                    regions.push((start, i));
                    i += 1;
                    break;
                }
                i += 1;
            }
            // If we reached the end without a closing quote, it's unbalanced.
            // Don't add a region — the remainder of the payload is treated as
            // outside a string literal (common in SQL injection break-out
            // payloads like `' OR 1=1`).
        } else {
            i += 1;
        }
    }
    regions
}

/// Replace the comment terminator at the end of the payload.
pub(crate) fn replace_comment_terminator(payload: &str, replacement: &str) -> Option<String> {
    for terminator in ["-- -", "--+", "-- ", "--", "#", "/*"] {
        if let Some(base) = payload.strip_suffix(terminator) {
            return Some(format!("{base}{replacement}"));
        }
    }

    None
}

/// Replace a logical operator with a dialect variant.
///
/// String-literal aware: will not replace ` or ` inside single- or double-quoted regions.
pub(crate) fn replace_logical_operator(
    payload: &str,
    alternatives: &[String],
    target: &str,
) -> Option<String> {
    if alternatives.is_empty() {
        return None;
    }

    let lower = payload.to_ascii_lowercase();
    let search = format!(" {} ", target.to_ascii_lowercase());

    let regions = quoted_regions(payload);
    let search_bytes = search.as_bytes();
    let lower_bytes = lower.as_bytes();

    for i in 0..lower.len().saturating_sub(search_bytes.len() - 1) {
        if regions.iter().any(|(s, e)| i > *s && i < *e) {
            continue;
        }
        if lower_bytes[i..].starts_with(search_bytes) {
            // F142: deterministic alternative pick via FNV-1a of
            // (payload + target). Pre-fix `rand::thread_rng()` meant
            // identical input produced different output across calls,
            // so a successful bypass discovered via this mutation
            // could not be replayed — same hazard fixed in
            // parameter_pollute (F114), whitespace_pad (F136), and
            // space_to_random_blank (F140). With more than one
            // alternative the picked variant matters; deterministic
            // picking keeps gene-bank replay byte-identical.
            let mut h: u64 = 0xcbf2_9ce4_8422_2325;
            for b in payload.bytes().chain(target.bytes()) {
                h ^= u64::from(b);
                h = h.wrapping_mul(0x0000_0100_0000_01b3);
            }
            let replacement = &alternatives[(h as usize) % alternatives.len()];
            let mut result = String::with_capacity(payload.len() + replacement.len());
            result.push_str(&payload[..i]);
            result.push(' ');
            result.push_str(replacement);
            result.push(' ');
            result.push_str(&payload[i + search.len()..]);
            return Some(result);
        }
    }

    None
}

/// Replace `=` with an alternative equality-style operator.
pub(crate) fn replace_equality(payload: &str, replacement: &str) -> Option<String> {
    let bytes = payload.as_bytes();
    let regions = quoted_regions(payload);

    for i in 0..bytes.len() {
        if bytes[i] != b'=' {
            continue;
        }
        if regions.iter().any(|(s, e)| i > *s && i < *e) {
            continue;
        }
        let previous = if i > 0 { bytes[i - 1] } else { b' ' };
        let next = bytes.get(i + 1).copied().unwrap_or(b' ');
        if previous != b'!'
            && previous != b'<'
            && previous != b'>'
            && previous != b'='
            && next != b'='
        {
            let before = &payload[..i];
            let after = &payload[i + 1..];
            return Some(format!("{before}{replacement}{after}"));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoted_regions_basic() {
        let r = quoted_regions("'hello' world");
        assert_eq!(r, vec![(0, 6)]);
    }

    #[test]
    fn quoted_regions_double_quotes() {
        let r = quoted_regions("\"hello\" world");
        assert_eq!(r, vec![(0, 6)]);
    }

    #[test]
    fn quoted_regions_ignores_unbalanced() {
        // Leading unbalanced quote (SQL injection break-out).
        let r = quoted_regions("' OR 1=1");
        assert!(r.is_empty());
    }

    #[test]
    fn quoted_regions_sql_escaped_quote() {
        // SQL-style escaped quote '' is treated as literal, not terminator.
        let r = quoted_regions("'It''s' OR 1=1");
        assert_eq!(r, vec![(0, 6)]);
    }

    #[test]
    fn quoted_regions_mixed_quotes() {
        // Single-quoted region and double-quoted region, separate.
        let r = quoted_regions("'a' \"b\" c");
        assert_eq!(r, vec![(0, 2), (4, 6)]);
    }

    #[test]
    fn replace_logical_operator_or_basic() {
        let alts = vec!["||".to_string()];
        assert_eq!(
            replace_logical_operator("1 or 1", &alts, "or"),
            Some("1 || 1".to_string())
        );
    }

    #[test]
    fn replace_logical_operator_and_basic() {
        let alts = vec!["&&".to_string()];
        assert_eq!(
            replace_logical_operator("1 and 1", &alts, "and"),
            Some("1 && 1".to_string())
        );
    }

    #[test]
    fn replace_logical_operator_skips_inside_single_quotes() {
        let alts = vec!["||".to_string()];
        let result = replace_logical_operator("'hello or world' or 1", &alts, "or");
        assert!(result.is_some());
        let result = result.unwrap();
        assert!(
            result.contains("'hello or world'"),
            "quoted OR preserved: {result}"
        );
        assert!(result.contains("||"), "unquoted OR replaced: {result}");
    }

    #[test]
    fn replace_logical_operator_skips_inside_double_quotes() {
        let alts = vec!["&&".to_string()];
        let result = replace_logical_operator("\"foo and bar\" and 1", &alts, "and");
        assert!(result.is_some());
        let result = result.unwrap();
        assert!(
            result.contains("\"foo and bar\""),
            "quoted AND preserved: {result}"
        );
    }

    #[test]
    fn replace_logical_operator_works_after_unbalanced_quote() {
        // SQL injection break-out: leading ' breaks out of app's string.
        let alts = vec!["||".to_string()];
        assert_eq!(
            replace_logical_operator("' or 1=1", &alts, "or"),
            Some("' || 1=1".to_string())
        );
    }

    #[test]
    fn replace_logical_operator_no_match() {
        let alts = vec!["||".to_string()];
        assert_eq!(replace_logical_operator("1 = 1", &alts, "or"), None);
    }

    #[test]
    fn replace_logical_operator_empty_alts() {
        assert_eq!(replace_logical_operator("1 or 1", &[], "or"), None);
    }

    #[test]
    fn replace_logical_operator_is_deterministic_across_calls() {
        // F142 regression: pre-fix rand::thread_rng() meant the same
        // input produced different output across calls when
        // alternatives.len() > 1, breaking gene-bank replay.
        let alts = vec![
            "||".to_string(),
            "OR".to_string(),
            "XOR".to_string(),
        ];
        let a = replace_logical_operator("1 or 1", &alts, "or").unwrap();
        let b = replace_logical_operator("1 or 1", &alts, "or").unwrap();
        let c = replace_logical_operator("1 or 1", &alts, "or").unwrap();
        assert_eq!(a, b, "identical input must produce identical output");
        assert_eq!(b, c);
    }

    #[test]
    fn replace_logical_operator_pick_varies_across_distinct_payloads() {
        // The deterministic-but-varied contract: different inputs
        // should NOT all collapse to the same alternative — that
        // would mean the FNV-1a mix is degenerate. Fire several
        // distinct payloads and assert ≥2 different alternatives
        // appear across them (with 3 alternatives and a real hash
        // mix, all-same is astronomically unlikely).
        let alts = vec![
            "||".to_string(),
            "OR".to_string(),
            "XOR".to_string(),
        ];
        let mut seen = std::collections::HashSet::new();
        for payload in [
            "1 or 1",
            "x or y",
            "abc or def",
            "name or value",
            "u or v",
            "1 or 2",
            "p or q",
            "alpha or beta",
        ] {
            if let Some(out) = replace_logical_operator(payload, &alts, "or") {
                for alt in &alts {
                    if out.contains(&format!(" {alt} ")) {
                        seen.insert(alt.clone());
                    }
                }
            }
        }
        assert!(
            seen.len() >= 2,
            "deterministic pick should still vary across distinct payloads, saw only {seen:?}"
        );
    }

    #[test]
    fn replace_equality_basic() {
        assert_eq!(
            replace_equality("1=1", " LIKE "),
            Some("1 LIKE 1".to_string())
        );
    }

    #[test]
    fn replace_equality_after_unbalanced_quote() {
        // SQL injection break-out payload.
        assert_eq!(
            replace_equality("' or 1=1", " LIKE "),
            Some("' or 1 LIKE 1".to_string())
        );
    }

    #[test]
    fn replace_equality_skips_inside_quotes() {
        let result = replace_equality("'a=b' or 1=1", " LIKE ");
        assert!(result.is_some());
        let result = result.unwrap();
        assert!(result.contains("'a=b'"), "quoted = preserved: {result}");
        assert!(result.contains(" LIKE "), "unquoted = replaced: {result}");
    }

    #[test]
    fn replace_equality_skips_compound_operators() {
        assert_eq!(replace_equality("1!=1", " LIKE "), None);
        assert_eq!(replace_equality("1<=1", " LIKE "), None);
        assert_eq!(replace_equality("1>=1", " LIKE "), None);
        assert_eq!(replace_equality("1==1", " LIKE "), None);
    }

    #[test]
    fn replace_equality_no_equals() {
        assert_eq!(replace_equality("1 and 1", " LIKE "), None);
    }

    #[test]
    fn replace_equality_first_equals_only() {
        let result = replace_equality("a=b=c", " LIKE ").unwrap();
        assert_eq!(result, "a LIKE b=c");
    }
}
