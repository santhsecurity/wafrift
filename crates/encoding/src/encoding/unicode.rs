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
        let code = ch as u32;
        if code > 0xFFFF {
            // Non-BMP: emit surrogate pair (valid in JSON/JavaScript)
            let surrogate_base = code - 0x1_0000;
            let high = 0xD800 + ((surrogate_base >> 10) & 0x3FF);
            let low = 0xDC00 + (surrogate_base & 0x3FF);
            let _ = write!(&mut out, "\\u{high:04X}\\u{low:04X}");
        } else {
            let _ = write!(&mut out, "\\u{code:04X}");
        }
    }
    out
}

/// IIS/ASP percent Unicode encoding — each character becomes `%uXXXX`.
///
/// **Context**: ONLY safe on IIS/ASP classic parsers. IIS `%u` encoding
/// is bounded to BMP (U+0000–U+FFFF) — non-BMP code points must be
/// emitted as UTF-16 surrogate pairs (`%uD83D%uDE00` for 😀, NOT the
/// invalid `%u1F600`). Pre-fix the loop wrote `ch as u32` straight
/// into a 4-hex-wide format, silently truncating high bytes for any
/// supplementary plane char and producing output IIS rejects — which
/// looked encoded but bypassed nothing.
#[must_use]
pub fn iis_unicode_encode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 6);
    for ch in payload.chars() {
        let code = ch as u32;
        if code > 0xFFFF {
            let surrogate_base = code - 0x1_0000;
            let high = 0xD800 + ((surrogate_base >> 10) & 0x3FF);
            let low = 0xDC00 + (surrogate_base & 0x3FF);
            let _ = write!(&mut out, "%u{high:04X}%u{low:04X}");
        } else {
            let _ = write!(&mut out, "%u{code:04X}");
        }
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

/// HTML entity encoding with per-character variant rotation.
///
/// Cycles each character through four browser-tolerant forms that strict
/// WAF regexes (which typically anchor on `&#x[0-9a-f]+;` with a lowercase
/// `x` and required `;`) miss:
///
/// 1. `&#xHH;`     — canonical lowercase-x hex
/// 2. `&#XHH;`     — uppercase-X hex (browsers accept; case-sensitive regex misses)
/// 3. `&#DD;`      — decimal
/// 4. `&#000DD;`   — decimal with leading zeros (HTML5 spec allows arbitrary leading zeros)
///
/// Rotation is by character index (deterministic; same input always
/// produces the same output — important for proptest idempotency).
///
/// **Bypass mechanism**: a `ModSecurity` regex like
/// `@rx &#x([0-9a-f]+);.*&#x([0-9a-f]+);` won't match a payload of
/// `&#X3C;&#0060;&#x73;&#62;` (the same `<s` payload routed through all
/// four variants). The browser decodes all four; the regex anchored on
/// the canonical form sees a different shape.
///
/// **Context**: HTML body / attribute. Equivalent to `html_entity` /
/// `html_entity_decimal` for browser decoding; safer against
/// canonicalising WAFs that strip the trailing `;` only on the lowercase
/// form.
#[must_use]
pub fn html_entity_variants(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 8);
    for (idx, ch) in payload.chars().enumerate() {
        let code = ch as u32;
        match idx % 4 {
            0 => {
                let _ = write!(&mut out, "&#x{code:x};");
            }
            1 => {
                let _ = write!(&mut out, "&#X{code:X};");
            }
            2 => {
                let _ = write!(&mut out, "&#{code};");
            }
            _ => {
                let _ = write!(&mut out, "&#000{code};");
            }
        }
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
/// (Java/Spring, .NET, Python 3, Go, `PostgreSQL`, etc.).
#[must_use]
pub fn fullwidth_encode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 3);
    for ch in payload.chars() {
        let mapped = match ch {
            ' ' => '\u{3000}', // Ideographic space
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

/// Mathematical Alphanumeric Symbols encoding — replaces ASCII letters and
/// digits with their Math-Bold counterparts in the Unicode `U+1D400` block.
///
/// `A`–`Z` → `U+1D400`–`U+1D419` (Math Bold Capitals: 𝐀 𝐁 … 𝐙)
/// `a`–`z` → `U+1D41A`–`U+1D433` (Math Bold Smalls:   𝐚 𝐛 … 𝐳)
/// `0`–`9` → `U+1D7CE`–`U+1D7D7` (Math Bold Digits:   𝟎 𝟏 … 𝟗)
/// Everything else is passed through unchanged (punctuation, spaces, etc.,
/// keep working as SQL/HTML syntax).
///
/// **Bypass mechanism**: every codepoint in this range NFKC-normalises back
/// to its plain-ASCII counterpart. Databases / frameworks that perform NFKC
/// normalisation (`PostgreSQL` with ICU collations, `MySQL`
/// `utf8mb4_0900_ai_ci`, Java `Normalizer.normalize(s, NFKC)`, Python
/// `unicodedata.normalize('NFKC', s)`, Go `golang.org/x/text/unicode/norm`)
/// see the original `SELECT` / `UNION` / `script` keyword and execute /
/// render it. WAFs scanning bytes for ASCII keywords see codepoints in the
/// `U+1D400` block — no keyword match.
///
/// **Distinct from `fullwidth_encode`**: fullwidth uses the `U+FF00`
/// Halfwidth-and-Fullwidth-Forms block. Math Alphanumeric uses the
/// `U+1D400` block — different code range, different WAF coverage gap.
/// WAFs that block fullwidth (a common technique since 2020) often do not
/// also block Math Alphanumeric Symbols. Both encode-paths NFKC to ASCII.
///
/// **Context**: any target whose backend NFKC-normalises before parsing.
/// Confirmed targets: `PostgreSQL` ICU + `MySQL` `utf8mb4_0900_ai_ci`
/// SQL identifiers, Java/Spring Boot path matching, .NET `String.Normalize`.
#[must_use]
pub fn math_bold_encode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 4);
    for ch in payload.chars() {
        let mapped = match ch {
            'A'..='Z' => char::from_u32(0x1D400 + (ch as u32 - 'A' as u32)).unwrap_or(ch),
            'a'..='z' => char::from_u32(0x1D41A + (ch as u32 - 'a' as u32)).unwrap_or(ch),
            '0'..='9' => char::from_u32(0x1D7CE + (ch as u32 - '0' as u32)).unwrap_or(ch),
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
            '"' => '\u{201D}',  // RIGHT DOUBLE QUOTATION MARK (")
            // Comparison operators
            '<' => '\u{FF1C}', // FULLWIDTH LESS-THAN SIGN (＜)
            '>' => '\u{FF1E}', // FULLWIDTH GREATER-THAN SIGN (＞)
            '=' => '\u{FF1D}', // FULLWIDTH EQUALS SIGN (＝)
            // Punctuation
            '(' => '\u{FF08}', // FULLWIDTH LEFT PARENTHESIS (（)
            ')' => '\u{FF09}', // FULLWIDTH RIGHT PARENTHESIS (）)
            ';' => '\u{FF1B}', // FULLWIDTH SEMICOLON (；)
            '-' => '\u{2010}', // HYPHEN (‐)
            '/' => '\u{2215}', // DIVISION SLASH (∕)
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
    fn iis_unicode_encode_bmp_only_for_3byte_utf8() {
        // U+65E5 (日) is BMP — emits as a single %uXXXX, no
        // surrogate. This is the existing happy path.
        assert_eq!(iis_unicode_encode("日"), "%u65E5");
    }

    #[test]
    fn iis_unicode_encode_non_bmp_emits_surrogate_pair() {
        // U+1F600 (😀) is supplementary plane. Pre-fix this emitted
        // `%u1F600` (5 hex digits — invalid IIS %u, silently
        // unencodable, bypass-rate killer). Post-fix it MUST emit a
        // UTF-16 surrogate pair `%uD83D%uDE00`.
        assert_eq!(iis_unicode_encode("😀"), "%uD83D%uDE00");
    }

    #[test]
    fn iis_unicode_encode_mixed_bmp_and_non_bmp() {
        // Adversarial: a mix of plain ASCII + BMP + supplementary
        // must produce exactly one %uXXXX or %uXXXX%uXXXX per char.
        // No 5-digit %u sequences anywhere — pin the regression.
        let out = iis_unicode_encode("A日😀");
        assert_eq!(out, "%u0041%u65E5%uD83D%uDE00");
        // Anti-regression: scan for any 5-hex-digit %u sequence.
        // The fix would silently regress if someone widened the
        // format string to %u{:05X} thinking it "supports" non-BMP.
        for hex_run in out.split("%u").skip(1) {
            let hex_part: String =
                hex_run.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
            assert!(
                hex_part.len() == 4,
                "every %u sequence must be exactly 4 hex digits (IIS spec); \
                 got {hex_part:?} in output {out:?}"
            );
        }
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

    // ── html_entity_variants tests ─────────────────────────────────────

    #[test]
    fn html_entity_variants_cycles_four_forms() {
        // 'A'=0x41=65 — verify each of the four rotation slots
        let encoded = html_entity_variants("AAAA");
        assert_eq!(encoded, "&#x41;&#X41;&#65;&#00065;");
    }

    #[test]
    fn html_entity_variants_continues_rotation() {
        // 'A'=65 — fifth char returns to slot 0 (lowercase-x hex)
        let encoded = html_entity_variants("AAAAA");
        assert_eq!(encoded, "&#x41;&#X41;&#65;&#00065;&#x41;");
    }

    #[test]
    fn html_entity_variants_empty() {
        assert_eq!(html_entity_variants(""), "");
    }

    #[test]
    fn html_entity_variants_xss_payload() {
        // '<' = 0x3C = 60, 's'=0x73=115, '>'=0x3E=62
        // First three chars use slots 0, 1, 2:
        let encoded = html_entity_variants("<s>");
        assert_eq!(encoded, "&#x3c;&#X73;&#62;");
    }

    #[test]
    fn html_entity_variants_unicode_codepoint() {
        // emoji U+1F600 ('😀') — codepoint 128512 — exercises higher-bit chars
        let encoded = html_entity_variants("\u{1F600}");
        assert_eq!(encoded, "&#x1f600;");
    }

    #[test]
    fn html_entity_variants_distinct_from_canonical() {
        // 4+ char payload MUST differ from canonical html_entity_encode
        // (canonical is always lowercase-x hex with semicolon)
        let canon = html_entity_encode("ABCD");
        let var = html_entity_variants("ABCD");
        assert_ne!(canon, var);
    }

    #[test]
    fn html_entity_variants_deterministic() {
        // Same input → same output (no randomness; rotation is by index)
        assert_eq!(
            html_entity_variants("hello world"),
            html_entity_variants("hello world")
        );
    }

    // ── math_bold_encode tests ─────────────────────────────────────────

    #[test]
    fn math_bold_encode_uppercase() {
        assert_eq!(math_bold_encode("A"), "\u{1D400}"); // 𝐀
        assert_eq!(math_bold_encode("Z"), "\u{1D419}"); // 𝐙
    }

    #[test]
    fn math_bold_encode_lowercase() {
        assert_eq!(math_bold_encode("a"), "\u{1D41A}"); // 𝐚
        assert_eq!(math_bold_encode("z"), "\u{1D433}"); // 𝐳
    }

    #[test]
    fn math_bold_encode_digits() {
        assert_eq!(math_bold_encode("0"), "\u{1D7CE}"); // 𝟎
        assert_eq!(math_bold_encode("9"), "\u{1D7D7}"); // 𝟗
    }

    #[test]
    fn math_bold_encode_sql_keyword() {
        // SELECT → 𝐒𝐄𝐋𝐄𝐂𝐓
        let encoded = math_bold_encode("SELECT");
        assert_eq!(encoded.chars().count(), 6);
        for ch in encoded.chars() {
            assert!(
                (0x1D400..=0x1D419).contains(&(ch as u32)),
                "expected math bold capital, got U+{:04X}",
                ch as u32
            );
        }
    }

    #[test]
    fn math_bold_encode_preserves_punctuation() {
        // ' OR 1=1-- — only letters/digits transform; punctuation stays
        let encoded = math_bold_encode("' OR 1=1--");
        // ' space = = - - all unchanged
        assert!(encoded.starts_with('\''));
        assert!(encoded.contains('='));
        assert!(encoded.ends_with("--"));
    }

    #[test]
    fn math_bold_encode_mixed_alphanumeric() {
        let encoded = math_bold_encode("Aa0");
        // A → 𝐀, a → 𝐚, 0 → 𝟎
        let chars: Vec<char> = encoded.chars().collect();
        assert_eq!(chars.len(), 3);
        assert_eq!(chars[0] as u32, 0x1D400);
        assert_eq!(chars[1] as u32, 0x1D41A);
        assert_eq!(chars[2] as u32, 0x1D7CE);
    }

    #[test]
    fn math_bold_encode_distinct_from_fullwidth() {
        // Fullwidth uses U+FF00 block; math bold uses U+1D400 block
        // The same input must produce different bytes (proving they're not equivalent).
        assert_ne!(math_bold_encode("SELECT"), fullwidth_encode("SELECT"));
    }

    #[test]
    fn math_bold_encode_empty() {
        assert_eq!(math_bold_encode(""), "");
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
            assert!(
                ch as u32 >= 0xFF01,
                "expected fullwidth char, got {ch} (U+{:04X})",
                ch as u32
            );
        }
    }

    #[test]
    fn fullwidth_encode_spaces() {
        let encoded = fullwidth_encode("A B");
        assert!(
            encoded.contains('\u{3000}'),
            "space should become ideographic space"
        );
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
        assert!(
            !encoded.contains('\''),
            "ASCII single quote should be replaced"
        );
        assert!(
            encoded.contains('\u{2019}'),
            "should contain RIGHT SINGLE QUOTATION MARK"
        );
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

    // ── Bug 2 regression: iis_unicode_encode non-BMP adversarial twins ──
    //
    // PRE-FIX BUG: the loop body cast `ch as u32` into a %uXXXX format
    // without checking whether `code > 0xFFFF`. For supplementary-plane
    // characters (U+10000 and above) this produced a 5-digit hex sequence
    // like `%u1F600`, which IIS's %u decoder rejects (its format is
    // strictly 4 hex digits). The bypass looked encoded but was actually
    // undecodable on any real IIS target — a silent bypass-rate killer.
    // Fixed: emit a UTF-16 surrogate pair `%uHIGH%uLOW` for non-BMP chars.

    #[test]
    fn iis_unicode_encode_lowest_non_bmp_u10000() {
        // U+10000 is the very first supplementary-plane codepoint (LINEAR B
        // SYLLABLE B008 A). Pre-fix: emitted `%u10000` (5 hex digits —
        // invalid IIS format). Post-fix: must emit the surrogate pair
        // %uD800%uDC00 (high=0xD800, low=0xDC00 for U+10000).
        let ch = '\u{10000}'; // U+10000
        let encoded = iis_unicode_encode(&ch.to_string());
        assert_eq!(
            encoded, "%uD800%uDC00",
            "U+10000 (lowest non-BMP) must encode as surrogate pair %uD800%uDC00, \
             not the invalid %u10000"
        );
        // Anti-regression: no 5-digit %u sequence.
        for hex_run in encoded.split("%u").skip(1) {
            let hex_part: String =
                hex_run.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
            assert_eq!(
                hex_part.len(),
                4,
                "every %u sequence must be exactly 4 hex digits (IIS spec); \
                 got {hex_part:?} in {encoded:?}"
            );
        }
    }

    #[test]
    fn iis_unicode_encode_high_cjk_supplement_u20000() {
        // U+20000 is the first codepoint in CJK Unified Ideographs Extension
        // B (𠀀). Pre-fix: emitted `%u20000` (5 hex digits — IIS rejects).
        // Post-fix: surrogate pair calculation:
        //   surrogate_base = 0x20000 - 0x10000 = 0x10000
        //   high = 0xD800 + (0x10000 >> 10) = 0xD800 + 0x40 = 0xD840
        //   low  = 0xDC00 + (0x10000 & 0x3FF) = 0xDC00 + 0x00 = 0xDC00
        let ch = '\u{20000}';
        let encoded = iis_unicode_encode(&ch.to_string());
        assert_eq!(
            encoded, "%uD840%uDC00",
            "U+20000 (CJK Supplement) must encode as %uD840%uDC00"
        );
        for hex_run in encoded.split("%u").skip(1) {
            let hex_part: String =
                hex_run.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
            assert_eq!(
                hex_part.len(),
                4,
                "each %u group must be 4 hex digits; got {hex_part:?}"
            );
        }
    }
}
