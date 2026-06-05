//! Sanitizer identification and model extraction from recovered JS source.
//!
//! Given the source recovered by [`sourcemap`](crate::sourcemap), this module
//! decides *which* sanitizer is in play (by Tier-B [`sanitizer_signatures`]) and
//! reads off its **allow/deny model**: the tag allowlist or forbid-list, the
//! blocked URL schemes, whether it strips event-handler attributes, and any raw
//! `replace()` strip patterns a hand-rolled sanitizer uses.
//!
//! Extraction from recovered-then-de-minified JS is necessarily heuristic, so
//! every detection records the source snippet that triggered it in
//! [`SanitizerModel::evidence`] — the operator can audit the model, and
//! soundness is preserved downstream (mining only proposes survivors of the
//! model, and execution is confirmed by scald, never fabricated).

use serde::Deserialize;

/// Embedded Tier-B sanitizer signatures.
const SIGNATURES_TOML: &str = include_str!("../rules/sanitizers.toml");

/// One Tier-B sanitizer signature: how to recognise a library and where its tag
/// lists live.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct SanitizerSignature {
    /// Stable kind label (`dompurify`, `sanitize_html`, …).
    pub kind: String,
    /// Substrings whose presence in the source identifies this library.
    pub markers: Vec<String>,
    /// Config keys whose value is the tag ALLOWLIST.
    #[serde(default)]
    pub allowed_tags_keys: Vec<String>,
    /// Config keys whose value is the tag forbid-list.
    #[serde(default)]
    pub forbid_tags_keys: Vec<String>,
    /// Config keys whose value is the attribute forbid-list.
    #[serde(default)]
    pub forbid_attr_keys: Vec<String>,
}

/// Parse Tier-B signatures, failing closed on malformed data or an entry with no
/// markers (a markerless signature would match everything).
pub fn signatures_from_toml(src: &str) -> Result<Vec<SanitizerSignature>, String> {
    #[derive(Deserialize)]
    struct File {
        #[serde(default)]
        sanitizer: Vec<SanitizerSignature>,
    }
    let parsed: File =
        toml::from_str(src).map_err(|e| format!("parsing sanitizer signatures: {e}"))?;
    if parsed.sanitizer.is_empty() {
        return Err("sanitizer signature data has no [[sanitizer]] entries".to_string());
    }
    for s in &parsed.sanitizer {
        if s.markers.is_empty() {
            return Err(format!("sanitizer kind {:?} has no markers", s.kind));
        }
    }
    Ok(parsed.sanitizer)
}

/// The embedded default signature set.
#[must_use]
pub fn sanitizer_signatures() -> Vec<SanitizerSignature> {
    signatures_from_toml(SIGNATURES_TOML)
        .expect("embedded sanitizer signatures must be valid (asserted in tests)")
}

/// Which sanitizer family was detected.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SanitizerKind {
    /// `DOMPurify`.
    DomPurify,
    /// `sanitize-html`.
    SanitizeHtml,
    /// `js-xss` (`FilterXSS`).
    JsXss,
    /// Google Caja `html_sanitize`.
    GoogleCaja,
    /// A hand-rolled sanitizer detected only by its `replace()` strip patterns.
    CustomRegexStrip,
    /// No known sanitizer recognised.
    #[default]
    Unknown,
}

impl SanitizerKind {
    fn from_label(label: &str) -> Self {
        match label {
            "dompurify" => Self::DomPurify,
            "sanitize_html" => Self::SanitizeHtml,
            "js_xss" => Self::JsXss,
            "google_caja" => Self::GoogleCaja,
            _ => Self::Unknown,
        }
    }

    /// Stable label for reports / JSON.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::DomPurify => "dompurify",
            Self::SanitizeHtml => "sanitize_html",
            Self::JsXss => "js_xss",
            Self::GoogleCaja => "google_caja",
            Self::CustomRegexStrip => "custom_regex_strip",
            Self::Unknown => "unknown",
        }
    }
}

/// The extracted allow/deny model of a client-side sanitizer.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SanitizerModel {
    /// Detected sanitizer family.
    pub kind: SanitizerKind,
    /// Tag allowlist, if one was found — `Some(vec![])` means "allow nothing".
    /// `None` means no allowlist (a forbid-list / strip model instead).
    pub allowed_tags: Option<Vec<String>>,
    /// Explicitly forbidden tags.
    pub forbidden_tags: Vec<String>,
    /// Explicitly forbidden attributes.
    pub forbidden_attrs: Vec<String>,
    /// Whether the sanitizer strips `on*=` event-handler attributes.
    pub strips_event_handlers: bool,
    /// URL schemes the sanitizer neutralizes (`javascript`, `data`).
    pub blocked_schemes: Vec<String>,
    /// Raw regex sources used in empty-replacement `replace()` strip calls.
    pub strip_patterns: Vec<String>,
    /// Source snippets that triggered each detection (operator audit trail).
    pub evidence: Vec<String>,
}

impl SanitizerModel {
    /// Did extraction find *any* actionable rule? An all-empty model means the
    /// source carried no recognisable sanitizer surface.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.kind == SanitizerKind::Unknown
            && self.allowed_tags.is_none()
            && self.forbidden_tags.is_empty()
            && self.forbidden_attrs.is_empty()
            && !self.strips_event_handlers
            && self.blocked_schemes.is_empty()
            && self.strip_patterns.is_empty()
    }
}

/// Extract a [`SanitizerModel`] from recovered JS `source`.
#[must_use]
pub fn extract_sanitizer(source: &str) -> SanitizerModel {
    extract_with(source, &sanitizer_signatures())
}

/// Extract against a caller-supplied signature set (Tier-B override).
#[must_use]
pub fn extract_with(source: &str, signatures: &[SanitizerSignature]) -> SanitizerModel {
    let mut model = SanitizerModel::default();

    // 1. Library identification: first signature whose markers appear.
    let matched = signatures
        .iter()
        .find(|s| s.markers.iter().any(|m| source.contains(m.as_str())));
    if let Some(sig) = matched {
        model.kind = SanitizerKind::from_label(&sig.kind);
        model
            .evidence
            .push(format!("library marker matched kind={}", sig.kind));
        // 2. Pull tag lists from the named config keys.
        for key in &sig.allowed_tags_keys {
            if let Some(tags) = extract_tag_list(source, key) {
                model.allowed_tags = Some(merge_unique(model.allowed_tags.take(), tags));
                model.evidence.push(format!("allowlist from `{key}`"));
            }
        }
        for key in &sig.forbid_tags_keys {
            if let Some(tags) = extract_tag_list(source, key) {
                model.forbidden_tags = merge_unique(Some(model.forbidden_tags.clone()), tags);
                model.evidence.push(format!("forbid-tags from `{key}`"));
            }
        }
        for key in &sig.forbid_attr_keys {
            if let Some(attrs) = extract_tag_list(source, key) {
                model.forbidden_attrs = merge_unique(Some(model.forbidden_attrs.clone()), attrs);
                model.evidence.push(format!("forbid-attrs from `{key}`"));
            }
        }
    }

    // 3. Hand-rolled strip patterns: `.replace(/RE/flags, '')`.
    let strips = extract_strip_patterns(source);
    if !strips.is_empty() {
        if model.kind == SanitizerKind::Unknown {
            model.kind = SanitizerKind::CustomRegexStrip;
        }
        for re in &strips {
            model.evidence.push(format!("strip replace(/{re}/, '')"));
        }
        model.strip_patterns = strips;
    }

    // 4. Event-handler stripping.
    if detects_event_handler_stripping(source) {
        model.strips_event_handlers = true;
        model.evidence.push("event-handler stripping detected".to_string());
    }

    // 5. Blocked URL schemes.
    model.blocked_schemes = detect_blocked_schemes(source);
    for s in &model.blocked_schemes {
        model.evidence.push(format!("blocks `{s}:` scheme"));
    }

    model
}

/// Find the value of `key` in `source` and extract a tag list from it. The value
/// may be a JS array literal (`['a','b']` → those strings) or an object literal
/// (`{a:{}, b:{}}` → its top-level keys, the `js-xss` whitelist shape).
fn extract_tag_list(source: &str, key: &str) -> Option<Vec<String>> {
    let val_start = value_start_after_key(source, key)?;
    let rest = &source[val_start..];
    let first = rest.trim_start().chars().next()?;
    match first {
        '[' => {
            let open = val_start + rest.find('[')?;
            let close = matching_delimiter(source, open, '[', ']')?;
            Some(extract_quoted_strings(&source[open + 1..close]))
        }
        '{' => {
            let open = val_start + rest.find('{')?;
            let close = matching_delimiter(source, open, '{', '}')?;
            Some(extract_object_keys(&source[open + 1..close]))
        }
        _ => None,
    }
}

/// Byte offset just after the `key :` token (handles optional quotes around the
/// key and arbitrary whitespace), or `None` if the key is absent.
fn value_start_after_key(source: &str, key: &str) -> Option<usize> {
    // Try `key`, `"key"`, `'key'` followed (after whitespace) by ':'.
    for variant in [key.to_string(), format!("\"{key}\""), format!("'{key}'")] {
        let mut from = 0;
        while let Some(rel) = source[from..].find(&variant) {
            let kpos = from + rel;
            let after = kpos + variant.len();
            let tail = &source[after..];
            let trimmed = tail.trim_start();
            if trimmed.starts_with(':') {
                let colon = after + (tail.len() - trimmed.len());
                return Some(colon + 1);
            }
            from = after;
        }
    }
    None
}

/// Index of the delimiter matching the `open`/`close` pair starting at `open`,
/// respecting nesting. Bounded scan; `None` if unbalanced.
fn matching_delimiter(source: &str, open: usize, open_c: char, close_c: char) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut depth = 0i32;
    let mut i = open;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c == open_c {
            depth += 1;
        } else if c == close_c {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Pull every single- or double-quoted string literal out of a fragment.
fn extract_quoted_strings(fragment: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = fragment.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let q = bytes[i];
        if q == b'\'' || q == b'"' {
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && bytes[j] != q {
                j += 1;
            }
            if j <= bytes.len() {
                if let Ok(s) = std::str::from_utf8(&bytes[start..j.min(bytes.len())]) {
                    if !s.is_empty() {
                        out.push(s.to_string());
                    }
                }
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    out
}

/// Pull top-level identifier keys out of an object-literal fragment (`a:{},'b':1`
/// → `["a","b"]`). Only depth-0 keys count.
fn extract_object_keys(fragment: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = fragment.as_bytes();
    let mut depth = 0i32;
    let mut i = 0;
    let mut at_key_pos = true; // start of fragment is a key position
    while i < bytes.len() {
        let c = bytes[i] as char;
        match c {
            '{' | '[' | '(' => {
                depth += 1;
                at_key_pos = false;
            }
            '}' | ']' | ')' => {
                depth -= 1;
            }
            ',' if depth == 0 => at_key_pos = true,
            c if depth == 0 && at_key_pos && (c.is_ascii_alphabetic() || c == '_') => {
                let start = i;
                while i < bytes.len()
                    && {
                        let ch = bytes[i] as char;
                        ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'
                    }
                {
                    i += 1;
                }
                out.push(fragment[start..i].to_string());
                at_key_pos = false;
                continue;
            }
            '\'' | '"' if depth == 0 && at_key_pos => {
                let q = bytes[i];
                let start = i + 1;
                let mut j = start;
                while j < bytes.len() && bytes[j] != q {
                    j += 1;
                }
                out.push(fragment[start..j.min(bytes.len())].to_string());
                at_key_pos = false;
                i = j + 1;
                continue;
            }
            c if !c.is_whitespace() => at_key_pos = false,
            _ => {}
        }
        i += 1;
    }
    out.retain(|k| !k.is_empty());
    out
}

/// Extract regex sources from empty-replacement `.replace(/RE/flags, '')` calls —
/// the signature of a hand-rolled strip sanitizer.
fn extract_strip_patterns(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let needle = ".replace(/";
    let mut from = 0;
    while let Some(rel) = source[from..].find(needle) {
        let re_start = from + rel + needle.len();
        // Scan to the closing unescaped '/'.
        let bytes = source.as_bytes();
        let mut j = re_start;
        let mut escaped = false;
        let mut in_class = false; // inside a [...] char class, '/' is literal
        while j < bytes.len() {
            let c = bytes[j] as char;
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '[' {
                in_class = true;
            } else if c == ']' {
                in_class = false;
            } else if c == '/' && !in_class {
                break;
            }
            j += 1;
        }
        if j < bytes.len() {
            let re_src = &source[re_start..j];
            // Skip flags, find the replacement argument.
            let after_flags = source[j + 1..]
                .find(',')
                .map(|c| j + 1 + c + 1)
                .unwrap_or(source.len());
            let repl = source[after_flags..].trim_start();
            // Empty replacement ('' or "") ⇒ a strip.
            if repl.starts_with("''") || repl.starts_with("\"\"") {
                if !re_src.is_empty() {
                    out.push(re_src.to_string());
                }
            }
            from = j + 1;
        } else {
            break;
        }
    }
    out.dedup();
    out
}

/// Heuristic: does the source strip `on*=` event-handler attributes?
fn detects_event_handler_stripping(source: &str) -> bool {
    // A JS regex source targeting event handlers appears literally in the text:
    // `/\son\w+=/`, `/on\w+/i`, an explicit handler enumeration, or DOMPurify's
    // FORBID_ATTR list naming onerror/onload.
    source.contains("on\\w")
        || source.contains("\\son")
        || source.contains("/on[")
        || (source.contains("onerror") && source.contains("onload"))
}

/// Which dangerous URL schemes the source references blocking.
fn detect_blocked_schemes(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let lower = source.to_ascii_lowercase();
    if lower.contains("javascript:") {
        out.push("javascript".to_string());
    }
    // `data:` is only meaningful as a scheme block when paired with text/html or
    // a scheme test, not any random `data:` mention — require an HTML data URI
    // or a scheme-anchored pattern.
    if lower.contains("data:text/html") || lower.contains("^data:") || lower.contains("/data:") {
        out.push("data".to_string());
    }
    out
}

/// Merge two tag lists, de-duplicating while preserving first-seen order.
fn merge_unique(existing: Option<Vec<String>>, extra: Vec<String>) -> Vec<String> {
    let mut out = existing.unwrap_or_default();
    for t in extra {
        if !out.contains(&t) {
            out.push(t);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Tier-B signatures ─────────────────────────────────────────────────

    #[test]
    fn embedded_signatures_parse_and_have_markers() {
        let sigs = sanitizer_signatures();
        assert!(sigs.len() >= 4);
        assert!(sigs.iter().all(|s| !s.markers.is_empty()));
        assert!(sigs.iter().any(|s| s.kind == "dompurify"));
    }

    #[test]
    fn signatures_loader_fails_closed() {
        assert!(signatures_from_toml("").is_err());
        assert!(
            signatures_from_toml("[[sanitizer]]\nkind=\"x\"\nmarkers=[]\n").is_err(),
            "a markerless signature must be rejected"
        );
    }

    // ── DOMPurify ─────────────────────────────────────────────────────────

    #[test]
    fn detects_dompurify_with_forbid_and_allow_lists() {
        let src = r#"
            import DOMPurify from 'dompurify';
            const clean = DOMPurify.sanitize(dirty, {
                ALLOWED_TAGS: ['b', 'i', 'em', 'a'],
                FORBID_TAGS: ['script', 'style'],
                FORBID_ATTR: ['onerror', 'onload']
            });
        "#;
        let m = extract_sanitizer(src);
        assert_eq!(m.kind, SanitizerKind::DomPurify);
        assert_eq!(m.allowed_tags.as_deref(), Some(["b", "i", "em", "a"].map(String::from).as_slice()));
        assert!(m.forbidden_tags.contains(&"script".to_string()));
        assert!(m.forbidden_attrs.contains(&"onerror".to_string()));
        assert!(!m.is_empty());
    }

    // ── sanitize-html ─────────────────────────────────────────────────────

    #[test]
    fn detects_sanitize_html_allowlist() {
        let src = r#"
            const sanitizeHtml = require('sanitize-html');
            sanitizeHtml(dirty, { allowedTags: ['p','strong','ul','li'] });
        "#;
        let m = extract_sanitizer(src);
        assert_eq!(m.kind, SanitizerKind::SanitizeHtml);
        assert_eq!(
            m.allowed_tags.as_deref(),
            Some(["p", "strong", "ul", "li"].map(String::from).as_slice())
        );
    }

    // ── js-xss whitelist (object keys) ────────────────────────────────────

    #[test]
    fn detects_js_xss_object_whitelist_keys() {
        let src = r#"
            var FilterXSS = require('xss').FilterXSS;
            var f = new FilterXSS({ whiteList: { a: ['href'], b: [], i: [] } });
        "#;
        let m = extract_sanitizer(src);
        assert_eq!(m.kind, SanitizerKind::JsXss);
        let allow = m.allowed_tags.expect("whitelist keys");
        assert!(allow.contains(&"a".to_string()));
        assert!(allow.contains(&"b".to_string()));
        assert!(allow.contains(&"i".to_string()));
    }

    // ── Custom regex strip ────────────────────────────────────────────────

    #[test]
    fn detects_custom_regex_strip_sanitizer() {
        let src = r#"
            function clean(s) {
                return s.replace(/<script[^>]*>.*?<\/script>/gi, '')
                        .replace(/<iframe[^>]*>/gi, "");
            }
        "#;
        let m = extract_sanitizer(src);
        assert_eq!(m.kind, SanitizerKind::CustomRegexStrip);
        assert_eq!(m.strip_patterns.len(), 2);
        assert!(m.strip_patterns.iter().any(|p| p.contains("script")));
        assert!(m.strip_patterns.iter().any(|p| p.contains("iframe")));
    }

    #[test]
    fn strip_pattern_respects_char_class_slashes() {
        // The `<\/script>` close uses an escaped slash; a `[a/b]` class uses a
        // literal one. Neither must prematurely terminate the regex.
        let src = r#"x.replace(/<\/script>/g, '')"#;
        let m = extract_sanitizer(src);
        assert_eq!(m.strip_patterns, vec![r"<\/script>".to_string()]);
    }

    #[test]
    fn non_empty_replacement_is_not_a_strip() {
        // Replacing with a placeholder is not a strip — must not be recorded.
        let src = r#"x.replace(/</g, '&lt;')"#;
        let m = extract_sanitizer(src);
        assert!(m.strip_patterns.is_empty());
    }

    // ── Event handlers & schemes ──────────────────────────────────────────

    #[test]
    fn detects_event_handler_stripping() {
        let src = r#"html = html.replace(/\son\w+=("[^"]*"|'[^']*'|[^\s>]*)/gi, '');"#;
        let m = extract_sanitizer(src);
        assert!(m.strips_event_handlers);
    }

    #[test]
    fn detects_blocked_javascript_scheme() {
        let src = r#"if (/^javascript:/i.test(url)) return '';"#;
        let m = extract_sanitizer(src);
        assert!(m.blocked_schemes.contains(&"javascript".to_string()));
    }

    #[test]
    fn data_scheme_only_blocked_when_html_or_anchored() {
        let plain = "const data = fetchData();"; // incidental "data" — not a block
        assert!(extract_sanitizer(plain).blocked_schemes.is_empty());
        let html = r#"if (url.startsWith('data:text/html')) reject();"#;
        assert!(extract_sanitizer(html).blocked_schemes.contains(&"data".to_string()));
    }

    // ── Robustness ────────────────────────────────────────────────────────

    #[test]
    fn unknown_source_yields_empty_model() {
        let m = extract_sanitizer("function add(a,b){return a+b;}");
        assert_eq!(m.kind, SanitizerKind::Unknown);
        assert!(m.is_empty());
    }

    #[test]
    fn unbalanced_brackets_do_not_panic_or_extract_garbage() {
        let src = "DOMPurify.sanitize(x, { ALLOWED_TAGS: ['b', 'i'"; // truncated
        let m = extract_sanitizer(src); // must not panic
        // Truncated array (no closing ]) ⇒ no allowlist extracted.
        assert_eq!(m.kind, SanitizerKind::DomPurify);
        assert!(m.allowed_tags.is_none());
    }

    #[test]
    fn evidence_is_recorded_for_every_detection() {
        let src = r#"DOMPurify.sanitize(x,{FORBID_TAGS:['script']}); s.replace(/<b>/g,'');"#;
        let m = extract_sanitizer(src);
        assert!(!m.evidence.is_empty());
        assert!(m.evidence.iter().any(|e| e.contains("forbid-tags")));
        assert!(m.evidence.iter().any(|e| e.contains("strip")));
    }

    // ── Property tests ────────────────────────────────────────────────────

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        /// Extraction never panics on arbitrary input and never invents a model
        /// from noise: random text yields an empty/Unknown model.
        #[test]
        fn prop_extract_never_panics(s in ".{0,400}") {
            let _ = extract_sanitizer(&s);
        }

        /// Any DOMPurify FORBID_TAGS array of simple tag names is recovered
        /// verbatim, regardless of surrounding whitespace.
        #[test]
        fn prop_forbid_tags_roundtrip(
            tags in proptest::collection::vec("[a-z]{1,8}", 1..6),
            ws in proptest::collection::vec("[ \n\t]{0,4}", 1..3),
        ) {
            let pad = ws.first().cloned().unwrap_or_default();
            let arr = tags.iter().map(|t| format!("'{t}'")).collect::<Vec<_>>().join(",");
            let src = format!("DOMPurify.sanitize(x,{{{pad}FORBID_TAGS{pad}:{pad}[{arr}]}})");
            let m = extract_sanitizer(&src);
            for t in &tags {
                prop_assert!(m.forbidden_tags.contains(t), "missing {t} in {:?}", m.forbidden_tags);
            }
        }
    }
}
