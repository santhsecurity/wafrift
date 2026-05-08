//! Operator and delimiter mutation helpers.

use rand::Rng;

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
    let lower = payload.to_ascii_lowercase();
    let search = format!(" {} ", target.to_ascii_lowercase());

    let mut in_single = false;
    let mut in_double = false;
    let search_bytes = search.as_bytes();
    let lower_bytes = lower.as_bytes();

    for i in 0..lower.len().saturating_sub(search_bytes.len() - 1) {
        let b = lower_bytes[i];
        if b == b'\'' && !in_double {
            in_single = !in_single;
            continue;
        }
        if b == b'"' && !in_single {
            in_double = !in_double;
            continue;
        }
        if in_single || in_double {
            continue;
        }
        if lower_bytes[i..].starts_with(search_bytes) {
            let mut rng = rand::thread_rng();
            let replacement = &alternatives[rng.r#gen_range(0..alternatives.len())];
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
    let chars: Vec<char> = payload.chars().collect();
    let mut in_string = false;
    let mut quote_char = '"';

    for (index, ch) in chars.iter().copied().enumerate() {
        if ch == '\'' || ch == '"' {
            if in_string && ch == quote_char {
                in_string = false;
            } else if !in_string {
                in_string = true;
                quote_char = ch;
            }
        }

        if ch == '=' && !in_string {
            let previous = if index > 0 { chars[index - 1] } else { ' ' };
            let next = chars.get(index + 1).copied().unwrap_or(' ');
            if previous != '!' && previous != '<' && previous != '>' && next != '=' {
                let before: String = chars[..index].iter().collect();
                let after: String = chars[index + 1..].iter().collect();
                return Some(format!("{before}{replacement}{after}"));
            }
        }
    }

    None
}
