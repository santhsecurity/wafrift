//! Truth tests for the sanitizer *model* — the membership predicate that the L*
//! learner and the CEGIS gate both depend on. Each test feeds a concrete model +
//! input and asserts the exact sanitization / executability outcome.

use wafrift_sanitizer::extract::SanitizerModel;
use wafrift_sanitizer::model::is_executable_html;

/// A model that forbids `forbidden`, optionally allowlists `allowed`, optionally
/// strips handlers, with `schemes` defanged and `strips` regex-stripped.
fn model(
    forbidden: &[&str],
    allowed: Option<&[&str]>,
    strip_handlers: bool,
    schemes: &[&str],
    strips: &[&str],
) -> SanitizerModel {
    SanitizerModel {
        forbidden_tags: forbidden.iter().map(|s| s.to_string()).collect(),
        allowed_tags: allowed.map(|a| a.iter().map(|s| s.to_string()).collect()),
        strips_event_handlers: strip_handlers,
        blocked_schemes: schemes.iter().map(|s| s.to_string()).collect(),
        strip_patterns: strips.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    }
}

// ── tag forbid / allow ───────────────────────────────────────────────────────

#[test]
fn a_forbidden_script_tag_is_dropped_and_not_executable() {
    let m = model(&["script"], None, false, &[], &[]);
    let out = m.sanitize("<script>alert(1)</script>");
    assert!(
        !is_executable_html(&out),
        "forbidden <script> must not survive: {out:?}"
    );
    assert!(!m.survives_executable("<script>alert(1)</script>"));
}

#[test]
fn an_unforbidden_script_tag_survives_and_is_executable() {
    let m = SanitizerModel::default(); // forbids nothing, strips nothing
    assert!(m.survives_executable("<script>alert(1)</script>"));
}

#[test]
fn an_allowlist_drops_a_non_allowlisted_tag() {
    let m = model(&[], Some(&["b", "i"]), false, &[], &[]);
    let out = m.sanitize("<svg onload=alert(1)>");
    assert!(
        !out.contains("<svg"),
        "non-allowlisted <svg> must be dropped: {out:?}"
    );
}

#[test]
fn an_allowlist_keeps_an_allowlisted_tag() {
    let m = model(&[], Some(&["b", "i"]), false, &[], &[]);
    let out = m.sanitize("<b>hi</b>");
    assert!(out.contains("<b>"), "allowlisted <b> must be kept: {out:?}");
}

#[test]
fn forbid_overrides_allow_for_the_same_tag() {
    // A tag that is both forbidden and allowlisted is dropped — forbid wins.
    let m = model(&["b"], Some(&["b"]), false, &[], &[]);
    let out = m.sanitize("<b>x</b>");
    assert!(!out.contains("<b>"), "forbid must win over allow: {out:?}");
}

// ── event handlers ───────────────────────────────────────────────────────────

#[test]
fn an_event_handler_is_stripped_when_the_model_strips_handlers() {
    let m = model(&[], None, true, &[], &[]);
    assert!(
        !m.survives_executable("<svg onload=alert(1)>"),
        "onload must be stripped"
    );
}

#[test]
fn an_event_handler_survives_when_the_model_does_not_strip() {
    let m = model(&[], None, false, &[], &[]);
    assert!(
        m.survives_executable("<svg onload=alert(1)>"),
        "unstripped onload is a bypass"
    );
}

#[test]
fn a_slash_separated_handler_is_also_stripped() {
    // `<svg/onload=...>` uses '/' as the attribute separator — must still strip.
    let m = model(&[], None, true, &[], &[]);
    assert!(!m.survives_executable("<svg/onload=alert(1)>"));
}

// ── URL schemes ──────────────────────────────────────────────────────────────

#[test]
fn a_blocked_javascript_scheme_is_defanged() {
    let m = model(&[], None, false, &["javascript"], &[]);
    let out = m.sanitize("<a href=javascript:alert(1)>x</a>");
    assert!(
        out.to_ascii_lowercase().contains("javascript%3a"),
        "the scheme colon must be defanged: {out:?}"
    );
}

// ── executability detector (the sink model) ──────────────────────────────────

#[test]
fn executable_detector_flags_a_script_tag() {
    assert!(is_executable_html("<script>x</script>"));
}

#[test]
fn executable_detector_flags_an_event_handler() {
    assert!(is_executable_html("<img src=x onerror=alert(1)>"));
}

#[test]
fn executable_detector_rejects_plain_text() {
    assert!(!is_executable_html("just some harmless text"));
}

#[test]
fn executable_detector_rejects_a_bare_javascript_scheme_string() {
    // A bare `javascript:` in text (no tag/handler) is inert in a markup sink —
    // flagging it would over-report. Documented soundness choice.
    assert!(!is_executable_html(
        "the string javascript:alert(1) as text"
    ));
}

#[test]
fn executable_detector_rejects_an_escaped_lt_script() {
    assert!(!is_executable_html("&lt;script&gt;alert(1)&lt;/script&gt;"));
}

// ── precompiled hot-path consistency (the hang-fix invariant) ────────────────

#[test]
fn sanitize_with_compiled_matches_on_the_fly_sanitize() {
    let m = model(
        &["script"],
        Some(&["b"]),
        true,
        &["javascript"],
        &[r#"\son\w+=("[^"]*"|'[^']*'|[^\s>]*)"#],
    );
    let compiled = m.compiled_strip_patterns();
    for input in [
        "<script>alert(1)</script>",
        "<svg onload=alert(1)>",
        "<b onclick=x>hi</b>",
        "<a href=javascript:alert(1)>",
        "plain text",
        "",
    ] {
        assert_eq!(
            m.sanitize_with(input, &compiled),
            m.sanitize(input),
            "hot-path sanitize_with must equal on-the-fly sanitize for {input:?}"
        );
        assert_eq!(
            m.survives_executable_with(input, &compiled),
            m.survives_executable(input),
        );
    }
}

#[test]
fn an_uncompilable_strip_pattern_is_dropped_not_panicked() {
    // A JS-only construct that Rust's regex rejects must be silently dropped
    // (the model keeps more input — the sound direction), never panic.
    let m = model(&[], None, false, &[], &["(?<=lookbehind)x"]);
    let compiled = m.compiled_strip_patterns();
    assert!(
        compiled.is_empty(),
        "an uncompilable pattern yields no compiled regex"
    );
    // sanitize still runs and is total.
    let _ = m.sanitize("<script>alert(1)</script>");
}
