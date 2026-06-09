//! Truth tests for sanitizer extraction: each asserts the *exact* model the
//! extractor recovers from a concrete recovered-source snippet — one named test
//! per family, per config key, per detector, with negative twins and adversarial
//! key-quoting / whitespace. These pin behaviour the proptests only bound.

use wafrift_sanitizer::extract::{SanitizerKind, extract_sanitizer};

fn has(v: &[String], needle: &str) -> bool {
    v.iter().any(|s| s == needle)
}

// ── DOMPurify ──────────────────────────────────────────────────────────────

#[test]
fn dompurify_marker_sets_kind() {
    let m = extract_sanitizer("const clean = DOMPurify.sanitize(dirty);");
    assert_eq!(m.kind, SanitizerKind::DomPurify);
    assert_eq!(m.kind.label(), "dompurify");
    assert!(!m.is_empty(), "a recognised library is not an empty model");
}

#[test]
fn dompurify_forbid_tags_extracted() {
    let m = extract_sanitizer("DOMPurify.sanitize(x, { FORBID_TAGS: ['script','style'] });");
    assert!(has(&m.forbidden_tags, "script"));
    assert!(has(&m.forbidden_tags, "style"));
}

#[test]
fn dompurify_forbid_tags_membership_is_exact() {
    let m = extract_sanitizer("DOMPurify.sanitize(x, { FORBID_TAGS: ['script'] });");
    assert!(has(&m.forbidden_tags, "script"));
    assert!(
        !has(&m.forbidden_tags, "div"),
        "must not invent tags not in the list"
    );
}

#[test]
fn dompurify_allowed_tags_extracted() {
    let m = extract_sanitizer("DOMPurify.sanitize(x, { ALLOWED_TAGS: ['b','i','em'] });");
    let allow = m.allowed_tags.expect("ALLOWED_TAGS yields an allowlist");
    assert!(has(&allow, "b") && has(&allow, "i") && has(&allow, "em"));
}

#[test]
fn dompurify_forbid_attr_extracted_without_implying_handler_strip() {
    let m = extract_sanitizer("DOMPurify.sanitize(x, { FORBID_ATTR: ['style','class'] });");
    assert!(has(&m.forbidden_attrs, "style") && has(&m.forbidden_attrs, "class"));
    assert!(
        !m.strips_event_handlers,
        "style/class are not handler-strip evidence"
    );
}

#[test]
fn dompurify_forbid_and_allow_extracted_together() {
    let m = extract_sanitizer(
        "DOMPurify.sanitize(x, { ALLOWED_TAGS: ['p'], FORBID_TAGS: ['script'] });",
    );
    assert!(has(&m.allowed_tags.unwrap(), "p"));
    assert!(has(&m.forbidden_tags, "script"));
}

#[test]
fn dompurify_library_marker_without_config_is_not_empty() {
    let m = extract_sanitizer("DOMPurify.sanitize(dirty)");
    assert_eq!(m.kind, SanitizerKind::DomPurify);
    assert!(m.forbidden_tags.is_empty() && m.allowed_tags.is_none());
    assert!(
        !m.is_empty(),
        "the recognised kind alone makes the model non-empty"
    );
}

#[test]
fn dompurify_multiline_config_is_extracted() {
    let src = "import DOMPurify from 'dompurify';\n\
               export function clean(d) {\n\
                 return DOMPurify.sanitize(d, { FORBID_TAGS: ['script','style'] });\n\
               }";
    let m = extract_sanitizer(src);
    assert_eq!(m.kind, SanitizerKind::DomPurify);
    assert!(has(&m.forbidden_tags, "script"));
}

// ── sanitize-html ────────────────────────────────────────────────────────────

#[test]
fn sanitize_html_kind_and_allowlist() {
    let m = extract_sanitizer("sanitizeHtml(dirty, { allowedTags: ['p','a','b'] });");
    assert_eq!(m.kind, SanitizerKind::SanitizeHtml);
    let allow = m.allowed_tags.expect("allowedTags yields an allowlist");
    assert!(has(&allow, "p") && has(&allow, "a") && has(&allow, "b"));
}

// ── js-xss (FilterXSS) ───────────────────────────────────────────────────────

#[test]
fn js_xss_kind_from_filterxss_marker() {
    let m = extract_sanitizer("const x = new FilterXSS({ whiteList: { a: ['href'] } });");
    assert_eq!(m.kind, SanitizerKind::JsXss);
}

#[test]
fn js_xss_whitelist_object_keys_become_allowlist() {
    let m = extract_sanitizer("new FilterXSS({ whiteList: { a: ['href'], img: ['src'] } });");
    let allow = m
        .allowed_tags
        .expect("whiteList object keys form the allowlist");
    assert!(
        has(&allow, "a"),
        "top-level whiteList key 'a' must be allowed"
    );
    assert!(
        has(&allow, "img"),
        "top-level whiteList key 'img' must be allowed"
    );
}

// ── Google Caja ──────────────────────────────────────────────────────────────

#[test]
fn google_caja_marker_sets_kind() {
    let m = extract_sanitizer("var out = html_sanitize(dirty, urlPolicy);");
    assert_eq!(m.kind, SanitizerKind::GoogleCaja);
}

// ── Custom regex strip ───────────────────────────────────────────────────────

#[test]
fn custom_strip_sets_kind_when_no_library_present() {
    let m = extract_sanitizer(r"out = html.replace(/<script[^>]*>/gi, '');");
    assert_eq!(m.kind, SanitizerKind::CustomRegexStrip);
    assert!(!m.strip_patterns.is_empty());
}

#[test]
fn custom_strip_pattern_value_is_captured() {
    let m = extract_sanitizer(r"x = s.replace(/<script[^>]*>/gi, '');");
    assert!(
        m.strip_patterns.iter().any(|p| p.contains("<script")),
        "captured patterns: {:?}",
        m.strip_patterns
    );
}

#[test]
fn custom_strip_char_class_slash_is_not_a_terminator() {
    // A '/' inside a [...] class must not end the regex early.
    let m = extract_sanitizer(r"x = s.replace(/[a-z/]+foo/g, '');");
    assert!(
        m.strip_patterns.iter().any(|p| p.contains("foo")),
        "the class-internal slash must not truncate the pattern: {:?}",
        m.strip_patterns
    );
}

#[test]
fn multiple_strip_patterns_are_all_captured() {
    let m = extract_sanitizer(r"y = s.replace(/<a>/g, '').replace(/<b>/g, '');");
    assert_eq!(
        m.strip_patterns.len(),
        2,
        "patterns: {:?}",
        m.strip_patterns
    );
}

// ── Event-handler stripping ──────────────────────────────────────────────────

#[test]
fn handler_strip_detected_via_backslash_s_on() {
    let m = extract_sanitizer(r"s = s.replace(/\son\w+=/gi, '');");
    assert!(m.strips_event_handlers);
}

#[test]
fn handler_strip_detected_via_on_w() {
    let m = extract_sanitizer(r"if (/on\w+/i.test(attr)) drop(attr);");
    assert!(m.strips_event_handlers);
}

#[test]
fn handler_strip_detected_via_onerror_onload_enumeration() {
    let m = extract_sanitizer("const bad = ['onerror','onload','onclick'];");
    assert!(m.strips_event_handlers);
}

#[test]
fn handler_strip_absent_is_false() {
    let m = extract_sanitizer("function clean(x){ return escapeHtml(x); }");
    assert!(!m.strips_event_handlers);
}

// ── Blocked URL schemes ──────────────────────────────────────────────────────

#[test]
fn javascript_scheme_blocked() {
    let m = extract_sanitizer("if (url.startsWith('javascript:')) return '';");
    assert!(has(&m.blocked_schemes, "javascript"));
}

#[test]
fn data_scheme_blocked_via_text_html() {
    let m = extract_sanitizer("if (/data:text\\/html/i.test(u)) reject(u);");
    assert!(has(&m.blocked_schemes, "data"));
}

#[test]
fn data_scheme_blocked_via_anchored_pattern() {
    let m = extract_sanitizer(r"if (/^data:/.test(scheme)) drop();");
    assert!(has(&m.blocked_schemes, "data"));
}

#[test]
fn bare_data_identifier_is_not_a_scheme_block() {
    // `data:` as a TS type annotation must NOT be read as a scheme block.
    let m = extract_sanitizer("function f(data: number) { return data + 1; }");
    assert!(
        !has(&m.blocked_schemes, "data"),
        "schemes: {:?}",
        m.blocked_schemes
    );
}

#[test]
fn no_schemes_blocked_when_none_referenced() {
    let m = extract_sanitizer("DOMPurify.sanitize(x, { ALLOWED_TAGS: ['b'] });");
    assert!(m.blocked_schemes.is_empty());
}

// ── Key-quoting / whitespace robustness ──────────────────────────────────────

#[test]
fn config_key_in_double_quotes_is_found() {
    let m = extract_sanitizer("DOMPurify.sanitize(x, { \"FORBID_TAGS\": ['script'] });");
    assert!(has(&m.forbidden_tags, "script"));
}

#[test]
fn config_key_in_single_quotes_is_found() {
    let m = extract_sanitizer("DOMPurify.sanitize(x, { 'FORBID_TAGS': ['script'] });");
    assert!(has(&m.forbidden_tags, "script"));
}

#[test]
fn whitespace_between_key_and_colon_is_tolerated() {
    let m = extract_sanitizer("DOMPurify.sanitize(x, { FORBID_TAGS   :   ['script'] });");
    assert!(has(&m.forbidden_tags, "script"));
}

// ── Negative / boundary ──────────────────────────────────────────────────────

#[test]
fn plain_arithmetic_function_is_an_empty_model() {
    let m = extract_sanitizer("function add(a, b) { return a + b; }");
    assert!(m.is_empty());
    assert_eq!(m.kind, SanitizerKind::Unknown);
}

#[test]
fn empty_source_is_an_empty_model() {
    let m = extract_sanitizer("");
    assert!(m.is_empty());
}

#[test]
fn a_recognised_model_records_an_evidence_trail() {
    let m = extract_sanitizer("DOMPurify.sanitize(x, { FORBID_TAGS: ['script'] });");
    // Truth, not shape: a populated trail is not enough — the evidence must point
    // at the EXACT detections an auditor needs to trust the model, namely the
    // library identification AND the specific config rule that fired. (The bare
    // `!is_empty()` check this replaced would pass even on misattributed evidence.)
    assert!(
        m.evidence.iter().any(|e| e.contains("kind=dompurify")),
        "evidence must record the library identification, got {:?}",
        m.evidence
    );
    assert!(
        m.evidence.iter().any(|e| e.contains("forbid-tags")),
        "evidence must record the forbid-tags rule that produced the model, got {:?}",
        m.evidence
    );
}
