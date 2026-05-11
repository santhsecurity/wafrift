//! Regression coverage for the 2026-05-10 swarm-audit HIGH:
//!   `xss::mutate` had a `has_xss_signals` gate that fired on benign
//!   substrings — `confirm(...)` in API docs, `window.onerror` in
//!   security write-ups, `<select>` HTML dropdowns. The mutator then
//!   emitted XSS variants from non-XSS input — wasted work the
//!   scanner reported as a real probe.
//!
//! Replaced with a 2-point threshold scoring scheme. Bare `confirm(`
//! or `alert(` no longer triggers; combination with a `<` tag or
//! `javascript:` URL does.

use wafrift_grammar::grammar::xss;

// ── Pre-fix FPs that must NOT generate XSS variants now ─────────────

#[test]
fn does_not_fire_on_bare_alert_in_docstring() {
    // Mutate returns empty when has_xss_signals returns false.
    let out = xss::mutate("calling alert(message) shows a popup", 10);
    assert!(
        out.is_empty(),
        "bare `alert(` in prose must not trigger XSS mutations: {out:?}"
    );
}

#[test]
fn does_not_fire_on_bare_confirm_in_apidoc() {
    let out = xss::mutate("confirm() requires user interaction", 10);
    assert!(out.is_empty());
}

#[test]
fn does_not_fire_on_window_onerror_in_writeup() {
    let out = xss::mutate("the window.onerror handler is global", 10);
    assert!(
        out.is_empty(),
        "bare `onerror` (no `=` to make it a tag attribute) must not trigger"
    );
}

#[test]
fn does_not_fire_on_html_dropdown_select() {
    // `<select>` is a real HTML element, not an XSS payload.
    let out = xss::mutate("<select><option>foo</option></select>", 10);
    // (select is not in the strong list — no JS context — so this
    // scores 0 and emits nothing.)
    assert!(out.is_empty());
}

#[test]
fn does_not_fire_on_lone_javascript_keyword() {
    // The word "javascript" without the colon scheme is not a vector.
    let out = xss::mutate("This page uses javascript", 10);
    assert!(out.is_empty());
}

// ── Real XSS payloads MUST still generate variants ──────────────────

#[test]
fn fires_on_full_script_tag() {
    let out = xss::mutate("<script>alert(1)</script>", 10);
    assert!(!out.is_empty(), "real XSS payload must still mutate");
}

#[test]
fn fires_on_img_onerror() {
    let out = xss::mutate("<img src=x onerror=alert(1)>", 10);
    assert!(!out.is_empty());
}

#[test]
fn fires_on_javascript_uri() {
    let out = xss::mutate("javascript:alert(1)", 10);
    assert!(!out.is_empty());
}

#[test]
fn fires_on_svg_onload() {
    let out = xss::mutate("<svg onload=alert(1)>", 10);
    assert!(!out.is_empty());
}

#[test]
fn fires_on_two_weak_signals_combined() {
    // Two weak signals combine to cross the threshold (1 + 1 = 2).
    // This catches payloads like "alert(document.cookie)" that have
    // no surrounding tag but ARE valid JS-execution snippets.
    let out = xss::mutate("alert(document.cookie)", 10);
    assert!(!out.is_empty(), "two weak signals together must trigger");
}
