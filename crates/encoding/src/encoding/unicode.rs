//! Unicode and HTML entity encoding strategies.
use std::fmt::Write as _;

/// Unicode encoding — each character becomes `\uXXXX`.
///
/// **Context**: ONLY safe when the target parser performs JSON/JavaScript decoding.
/// Using this on raw HTTP parameters will send a literal backslash-u sequence.
#[must_use]
pub fn unicode_encode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 6);
    for ch in payload.chars() {
        let _ = write!(&mut out, "\\u{:04X}", ch as u32);
    }
    out
}

/// IIS/ASP percent Unicode encoding — each character becomes `%uXXXX`.
///
/// **Context**: ONLY safe on IIS/ASP classic parsers.
#[must_use]
pub fn iis_unicode_encode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 6);
    for ch in payload.chars() {
        let _ = write!(&mut out, "%u{:04X}", ch as u32);
    }
    out
}

/// JSON string encoding — wraps the payload in a JSON string with proper escaping.
///
/// **Context**: ONLY safe when the target parser performs JSON decoding.
#[must_use]
pub fn json_string_encode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 2 + 2);
    out.push('"');
    for ch in payload.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(&mut out, "\\u{:04X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// HTML entity encoding — each character becomes `&#xXX;`.
///
/// **Context**: ONLY safe in HTML contexts where the browser decodes entities.
#[must_use]
pub fn html_entity_encode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 6);
    for ch in payload.chars() {
        let _ = write!(&mut out, "&#x{:X};", ch as u32);
    }
    out
}

/// HTML decimal entity encoding — each character becomes `&#DD;`.
///
/// **Context**: ONLY safe in HTML contexts where the browser decodes entities.
#[must_use]
pub fn html_entity_decimal_encode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 6);
    for ch in payload.chars() {
        let _ = write!(&mut out, "&#{};", ch as u32);
    }
    out
}

/// Fullwidth Unicode encoding — replaces ASCII with fullwidth equivalents.
///
/// Maps `!`–`~` (0x21–0x7E) to the fullwidth range `！`–`～` (0xFF01–0xFF5E).
/// Spaces become ideographic space (U+3000).
///
/// **Bypass mechanism**: Many WAFs regex against ASCII keywords like `SELECT`,
/// `UNION`, `<script>`, etc. Fullwidth characters are visually identical but
/// have different codepoints, so regex fails. However, backends that perform
/// Unicode NFKC normalization will convert them back to ASCII — meaning the
/// payload executes while the WAF never saw it.
///
/// **Context**: Effective against WAFs in front of servers that normalize Unicode
/// (Java/Spring, .NET, Python 3, Go, PostgreSQL, etc.).
#[must_use]
pub fn fullwidth_encode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 3);
    for ch in payload.chars() {
        let mapped = match ch {
            ' ' => '\u{3000}',  // Ideographic space
            c if ('\x21'..='\x7e').contains(&c) => {
                // Fullwidth offset: U+FF01 = U+0021 + 0xFEE0
                char::from_u32(c as u32 + 0xFEE0).unwrap_or(c)
            }
            c => c,
        };
        out.push(mapped);
    }
    out
}

/// Homoglyph substitution — replaces select ASCII characters with visually
/// identical Unicode characters from other scripts.
///
/// **Bypass mechanism**: WAFs match `'`, `"`, `<`, `>`, `=`, etc. as literal
/// bytes. Unicode homoglyphs look identical in logs but aren't matched by
/// byte-level regex. If the backend performs Unicode normalization (NFKC) or
/// accepts these codepoints in SQL/HTML contexts, the payload executes.
///
/// **Context**: Effective against byte-level WAFs. Requires backend Unicode
/// tolerance (common in modern frameworks).
#[must_use]
pub fn homoglyph_encode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 4);
    for ch in payload.chars() {
        let mapped = match ch {
            // Quotes and delimiters
            '\'' => '\u{2019}', // RIGHT SINGLE QUOTATION MARK (')
            '"'  => '\u{201D}', // RIGHT DOUBLE QUOTATION MARK (")
            // Comparison operators
            '<'  => '\u{FF1C}', // FULLWIDTH LESS-THAN SIGN (＜)
            '>'  => '\u{FF1E}', // FULLWIDTH GREATER-THAN SIGN (＞)
            '='  => '\u{FF1D}', // FULLWIDTH EQUALS SIGN (＝)
            // Punctuation
            '('  => '\u{FF08}', // FULLWIDTH LEFT PARENTHESIS (（)
            ')'  => '\u{FF09}', // FULLWIDTH RIGHT PARENTHESIS (）)
            ';'  => '\u{FF1B}', // FULLWIDTH SEMICOLON (；)
            '-'  => '\u{2010}', // HYPHEN (‐)
            '/'  => '\u{2215}', // DIVISION SLASH (∕)
            // Keep letters and digits unchanged for readability
            c => c,
        };
        out.push(mapped);
    }
    out
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unicode_encode_basic() {
        assert_eq!(unicode_encode("A"), "\\u0041");
        assert_eq!(unicode_encode("AB"), "\\u0041\\u0042");
    }

    #[test]
    fn unicode_encode_special_chars() {
        let encoded = unicode_encode("' OR 1=1--");
        assert!(encoded.contains("\\u0027")); // '
        assert!(encoded.contains("\\u003D")); // =
    }

    #[test]
    fn unicode_encode_unicode() {
        let encoded = unicode_encode("日本語");
        assert_eq!(encoded, "\\u65E5\\u672C\\u8A9E");
    }

    #[test]
    fn iis_unicode_encode_basic() {
        assert_eq!(iis_unicode_encode("A"), "%u0041");
        assert_eq!(iis_unicode_encode("AB"), "%u0041%u0042");
    }

    #[test]
    fn json_encode_basic() {
        assert_eq!(json_string_encode("A"), "\"A\"");
        assert_eq!(json_string_encode("A\\B"), "\"A\\\\B\"");
        assert_eq!(json_string_encode("A\"B"), "\"A\\\"B\"");
        assert_eq!(json_string_encode("A\nB"), "\"A\\nB\"");
    }

    #[test]
    fn json_encode_control_chars() {
        assert_eq!(json_string_encode("\x01"), "\"\\u0001\"");
    }

    #[test]
    fn html_entity_encode_basic() {
        assert_eq!(html_entity_encode("A"), "&#x41;");
        assert_eq!(html_entity_encode("AB"), "&#x41;&#x42;");
    }

    #[test]
    fn html_entity_encode_special_chars() {
        let encoded = html_entity_encode("<script>");
        assert_eq!(encoded, "&#x3C;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;");
    }

    #[test]
    fn html_entity_decimal_encode_basic() {
        assert_eq!(html_entity_decimal_encode("A"), "&#65;");
        assert_eq!(html_entity_decimal_encode("<"), "&#60;");
    }

    #[test]
    fn html_entity_encode_empty() {
        assert_eq!(html_entity_encode(""), "");
    }

    #[test]
    fn unicode_encode_empty() {
        assert_eq!(unicode_encode(""), "");
    }

    // ── Fullwidth encoding tests ───────────────────────────────────────

    #[test]
    fn fullwidth_encode_sql_keywords() {
        let encoded = fullwidth_encode("SELECT");
        assert_eq!(encoded, "ＳＥＬＥＣＴ");
        // Every ASCII letter should be in fullwidth range
        for ch in encoded.chars() {
            assert!(ch as u32 >= 0xFF01, "expected fullwidth char, got {ch} (U+{:04X})", ch as u32);
        }
    }

    #[test]
    fn fullwidth_encode_spaces() {
        let encoded = fullwidth_encode("A B");
        assert!(encoded.contains('\u{3000}'), "space should become ideographic space");
    }

    #[test]
    fn fullwidth_encode_preserves_non_ascii() {
        let encoded = fullwidth_encode("日本語");
        assert_eq!(encoded, "日本語", "non-ASCII should pass through unchanged");
    }

    #[test]
    fn fullwidth_encode_operators() {
        let encoded = fullwidth_encode("1=1");
        assert_eq!(encoded, "１＝１");
    }

    #[test]
    fn fullwidth_encode_sqli_payload() {
        let encoded = fullwidth_encode("' OR 1=1--");
        // Should contain fullwidth equivalents, not ASCII
        assert!(!encoded.contains("OR"), "should not contain ASCII 'OR'");
        assert!(encoded.contains("ＯＲ"), "should contain fullwidth 'ＯＲ'");
    }

    #[test]
    fn fullwidth_encode_empty() {
        assert_eq!(fullwidth_encode(""), "");
    }

    // ── Homoglyph encoding tests ───────────────────────────────────────

    #[test]
    fn homoglyph_replaces_quotes() {
        let encoded = homoglyph_encode("' OR '1'='1");
        assert!(!encoded.contains('\''), "ASCII single quote should be replaced");
        assert!(encoded.contains('\u{2019}'), "should contain RIGHT SINGLE QUOTATION MARK");
    }

    #[test]
    fn homoglyph_replaces_angle_brackets() {
        let encoded = homoglyph_encode("<script>");
        assert!(!encoded.contains('<'), "ASCII < should be replaced");
        assert!(!encoded.contains('>'), "ASCII > should be replaced");
        assert!(encoded.contains('\u{FF1C}'), "should contain fullwidth <");
        assert!(encoded.contains('\u{FF1E}'), "should contain fullwidth >");
    }

    #[test]
    fn homoglyph_replaces_equals() {
        let encoded = homoglyph_encode("1=1");
        assert!(!encoded.contains('='), "ASCII = should be replaced");
        assert!(encoded.contains('\u{FF1D}'), "should contain fullwidth =");
    }

    #[test]
    fn homoglyph_preserves_letters() {
        let encoded = homoglyph_encode("SELECT");
        assert_eq!(encoded, "SELECT", "letters should be preserved");
    }

    #[test]
    fn homoglyph_encode_empty() {
        assert_eq!(homoglyph_encode(""), "");
    }

    #[test]
    fn homoglyph_replaces_parens() {
        let encoded = homoglyph_encode("fn()");
        assert!(encoded.contains('\u{FF08}'), "should contain fullwidth (");
        assert!(encoded.contains('\u{FF09}'), "should contain fullwidth )");
    }
}
