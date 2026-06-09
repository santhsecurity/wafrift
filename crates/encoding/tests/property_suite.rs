//! Property-based test suite for WAF-evasion primitives.
//!
//! Each `proptest!` macro runs 256 cases by default — so this file
//! contributes thousands of effective test executions per
//! `cargo test` invocation. The properties enforce three invariants
//! every WAF-evasion primitive MUST hold:
//!
//! 1. **No panic on arbitrary string input.** Operator-supplied
//!    strings come from untrusted sources (request bodies, CLI
//!    args, captured tokens). Panicking on any of them is a
//!    DoS surface in our own engine.
//! 2. **Determinism.** Same input → same output. Required so
//!    `wafrift bench` results are reproducible and the genome
//!    registry can store stable hashes.
//! 3. **Wire-format invariants.** Per-primitive shape rules: no
//!    embedded CRLF in single-line outputs, balanced braces,
//!    output preserves the operator's target markers, etc.

use proptest::prelude::*;
use wafrift_encoding::encoding::{
    cache_poison, invisible, method_override, path_norm, race, request_line, unicode,
};

// ───────────────────────────────────────────────────────────────
// invisible.rs — keyword-bypass via codepoint substitution
// ───────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn invisible_tag_char_encode_no_panic(s in ".*") {
        let _ = invisible::tag_char_encode(&s);
    }

    #[test]
    fn invisible_tag_char_encode_deterministic(s in ".*") {
        prop_assert_eq!(
            invisible::tag_char_encode(&s),
            invisible::tag_char_encode(&s)
        );
    }

    #[test]
    fn invisible_tag_char_encode_preserves_length_for_ascii(s in "[A-Za-z0-9]{0,200}") {
        // Every ASCII byte becomes a 4-byte plane-14 codepoint, so
        // codepoint count equals input length.
        let out = invisible::tag_char_encode(&s);
        prop_assert_eq!(out.chars().count(), s.len());
    }

    #[test]
    fn invisible_ligature_encode_no_panic(s in ".*") {
        let _ = invisible::ligature_encode(&s);
    }

    #[test]
    fn invisible_ligature_encode_idempotent_on_no_match(s in "[^fis]*") {
        prop_assert_eq!(invisible::ligature_encode(&s), s);
    }

    #[test]
    fn invisible_soft_hyphen_inject_no_panic(s in ".*") {
        let _ = invisible::soft_hyphen_inject(&s);
    }

    #[test]
    fn invisible_word_joiner_wrap_no_panic(s in ".*") {
        let _ = invisible::word_joiner_wrap(&s);
    }

    #[test]
    fn invisible_circled_letter_no_panic(s in ".*") {
        let _ = invisible::circled_letter_encode(&s);
    }

    #[test]
    fn invisible_parenthesized_letter_no_panic(s in ".*") {
        let _ = invisible::parenthesized_letter_encode(&s);
    }

    #[test]
    fn invisible_variation_selector_pad_no_panic(s in ".*") {
        let _ = invisible::variation_selector_pad(&s, '\u{FE0F}');
    }
}

// ───────────────────────────────────────────────────────────────
// path_norm.rs — RFC 3986 §5.2.4 differential
// ───────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn path_norm_variants_no_panic(prefix in "/[A-Za-z0-9_-]{0,30}", target in "/[A-Za-z0-9_-]{1,30}") {
        let _ = path_norm::path_variants(&prefix, &target);
    }

    #[test]
    fn path_norm_variants_minimum_count(prefix in "/[A-Za-z]{0,10}", target in "/[A-Za-z]{1,10}") {
        let v = path_norm::path_variants(&prefix, &target);
        prop_assert!(v.len() >= 20);
    }

    #[test]
    fn path_norm_variants_deterministic(prefix in "/[A-Za-z]{0,10}", target in "/[A-Za-z]{1,10}") {
        prop_assert_eq!(
            path_norm::path_variants(&prefix, &target),
            path_norm::path_variants(&prefix, &target)
        );
    }

    #[test]
    fn path_norm_deep_collapse_no_panic(depth in 0u32..=200, target in "/[A-Za-z]{1,20}") {
        let _ = path_norm::deep_path_collapse(depth as usize, &target);
    }

    #[test]
    fn path_norm_rfc3986_no_panic(s in ".*") {
        let _ = path_norm::rfc3986_remove_dot_segments(&s);
    }

    #[test]
    fn path_norm_rfc3986_deterministic(s in "/[A-Za-z0-9./_-]{0,200}") {
        prop_assert_eq!(
            path_norm::rfc3986_remove_dot_segments(&s),
            path_norm::rfc3986_remove_dot_segments(&s)
        );
    }
}

// ───────────────────────────────────────────────────────────────
// request_line.rs — exotic methods / URI forms / version strings
// ───────────────────────────────────────────────────────────────

// Pure-determinism test — no strategy parameters, cannot live inside proptest!.
#[test]
fn request_line_exotic_methods_stable() {
    let a = request_line::exotic_methods();
    let b = request_line::exotic_methods();
    assert_eq!(a, b);
}

proptest! {
    #[test]
    fn request_line_absolute_uri_no_panic(
        method in "[A-Z]{1,10}",
        host in "[a-z]{1,20}\\.example",
        path in "/[a-zA-Z0-9/_-]{0,100}"
    ) {
        let _ = request_line::absolute_uri_request_line(&method, &host, &path);
    }

    #[test]
    fn request_line_authority_form_no_panic(
        method in "[A-Z]{1,10}",
        host in "[a-z]{1,20}",
        port in 1u16..=u16::MAX
    ) {
        let _ = request_line::authority_form_request_line(&method, &host, port);
    }

    #[test]
    fn request_line_no_crlf_in_output(
        method in "[A-Z]{1,5}",
        host in "[a-z]{1,10}",
        path in "/[a-z]{1,20}"
    ) {
        // Multi-line request-line outputs are smuggling-class, not
        // request_line-class. Keep the layer boundary clean.
        let outputs = vec![
            request_line::absolute_uri_request_line(&method, &host, &path),
            request_line::absolute_uri_https_request_line(&method, &host, &path),
            request_line::asterisk_form_request_line(&method),
            request_line::authority_form_request_line(&method, &host, 443),
            request_line::request_line_with_version(&method, &path, "HTTP/1.1"),
        ];
        for o in outputs {
            prop_assert!(!o.contains("\r\n"));
            prop_assert!(!o.contains('\n'));
        }
    }
}

// ───────────────────────────────────────────────────────────────
// race.rs — Kettle BH23 single-packet attack frame builders
// ───────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn race_pipelined_h1_no_panic(
        n in 0usize..=50,
        method in "[A-Z]{1,8}",
        path in "/[a-zA-Z0-9_-]{1,40}",
        host in "[a-z]{1,20}\\.example",
        body in "[a-zA-Z0-9=&]{0,200}"
    ) {
        let _ = race::pipelined_h1_coalesce(n, &method, &path, &host, &[], body.as_bytes());
    }

    #[test]
    fn race_h2_last_byte_sync_rejects_mismatched_lengths(n in 1usize..=10) {
        let stream_ids: Vec<u32> = (1..=n as u32).map(|i| i * 2 - 1).collect();
        let bytes: Vec<u8> = (0..n + 1).map(|i| i as u8).collect();
        // Mismatched lengths -> None.
        prop_assert!(race::h2_last_byte_sync_frames(&stream_ids, &bytes).is_none());
    }

    #[test]
    fn race_h2_last_byte_sync_accepts_odd_stream_ids(n in 1usize..=20) {
        let stream_ids: Vec<u32> = (1..=n as u32).map(|i| i * 2 - 1).collect();
        let bytes: Vec<u8> = (0..n).map(|i| i as u8).collect();
        prop_assert!(race::h2_last_byte_sync_frames(&stream_ids, &bytes).is_some());
    }

    #[test]
    fn race_h2_last_byte_sync_rejects_even_stream_ids(id in 2u32..=1000, even_step in 2u32..=10) {
        let id = id - (id % 2); // ensure even
        if id == 0 {
            prop_assert!(race::h2_last_byte_sync_frames(&[id], b"X").is_none());
        } else {
            let _ = even_step; // (parameter unused — proptest just shrinks both)
            prop_assert!(race::h2_last_byte_sync_frames(&[id], b"X").is_none());
        }
    }
}

// ───────────────────────────────────────────────────────────────
// method_override.rs — WAF↔framework method disagreement
// ───────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn method_override_header_no_panic(method in "[A-Z]{1,12}") {
        let _ = method_override::override_header(&method);
        let _ = method_override::override_header_alt(&method);
        let _ = method_override::override_header_express(&method);
        let _ = method_override::override_header_case_mix(&method);
        let _ = method_override::override_header_padded(&method);
    }

    #[test]
    fn method_override_form_field_basic(method in "[A-Z]{1,10}") {
        let p = method_override::form_field_method(&method);
        prop_assert!(p.starts_with("_method="));
        prop_assert!(p.contains(&method));
    }

    #[test]
    fn method_override_query_starts_with_question_mark(method in "[A-Z]{1,10}") {
        let p = method_override::query_method(&method);
        prop_assert!(p.starts_with('?'));
        prop_assert!(p.contains(&method));
    }

    #[test]
    fn method_override_all_variants_minimum(method in "[A-Z]{1,10}") {
        let v = method_override::all_override_variants(&method);
        prop_assert!(v.len() >= 10);
    }

    #[test]
    fn method_override_all_variants_carry_method(method in "[A-Z]{3,12}") {
        let v = method_override::all_override_variants(&method);
        for (name, payload) in &v {
            prop_assert!(
                payload.contains(&method.to_string())
                    || payload.contains(&method.to_lowercase())
                    || payload.contains(&method_override::override_header_case_mix(&method)),
                "{} dropped method: {}",
                name,
                payload
            );
        }
    }
}

// ───────────────────────────────────────────────────────────────
// cache_poison.rs — CDN/edge cache poisoning primitives
// ───────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn cache_poison_x_forwarded_host_no_panic(host in "[a-z0-9.-]{1,80}") {
        let _ = cache_poison::x_forwarded_host(&host);
    }

    #[test]
    fn cache_poison_x_forwarded_port_full_range(port in 0u16..=u16::MAX) {
        let p = cache_poison::x_forwarded_port(port);
        prop_assert!(p.starts_with("X-Forwarded-Port:"));
        prop_assert!(p.contains(&port.to_string()));
    }

    #[test]
    fn cache_poison_web_cache_deception_paths_count(prefix in "/[A-Za-z]{1,20}") {
        let v = cache_poison::web_cache_deception_paths(&prefix);
        prop_assert!(v.len() >= 10);
    }

    #[test]
    fn cache_poison_key_normalization_variants_count(base in "/[A-Za-z]{1,20}") {
        let v = cache_poison::cache_key_normalization_variants(&base);
        prop_assert!(v.len() >= 8);
    }

    #[test]
    fn cache_poison_all_variants_carry_marker(
        host in "[A-Z][A-Z_]{5,15}",
        path in "/[A-Z][A-Z_]{5,15}"
    ) {
        let v = cache_poison::all_cache_poison_payloads(&host, &path);
        let any_host = v.iter().any(|(_, p)| p.contains(&host));
        let any_path = v.iter().any(|(_, p)| p.contains(&path));
        prop_assert!(any_host || any_path);
    }
}

// ───────────────────────────────────────────────────────────────
// unicode.rs — Math/script/fraktur/double-struck/letterlike alphabet
// encoders and JSON/SQL evasion helpers.
//
// Each proptest asserts two invariants:
//   1. No panic on arbitrary UTF-8 input (".*").
//   2. Determinism: same input → same output.
// ───────────────────────────────────────────────────────────────

proptest! {
    // ── Mathematical alphabet encoders ────────────────────────

    #[test]
    fn unicode_math_italic_no_panic(s in ".*") {
        let a = unicode::math_italic_encode(&s);
        let b = unicode::math_italic_encode(&s);
        prop_assert_eq!(a, b);
    }

    #[test]
    fn unicode_math_script_no_panic(s in ".*") {
        let a = unicode::math_script_encode(&s);
        let b = unicode::math_script_encode(&s);
        prop_assert_eq!(a, b);
    }

    #[test]
    fn unicode_math_fraktur_no_panic(s in ".*") {
        let a = unicode::math_fraktur_encode(&s);
        let b = unicode::math_fraktur_encode(&s);
        prop_assert_eq!(a, b);
    }

    #[test]
    fn unicode_math_double_struck_no_panic(s in ".*") {
        let a = unicode::math_double_struck_encode(&s);
        let b = unicode::math_double_struck_encode(&s);
        prop_assert_eq!(a, b);
    }

    #[test]
    fn unicode_letterlike_no_panic(s in ".*") {
        let a = unicode::letterlike_encode(&s);
        let b = unicode::letterlike_encode(&s);
        prop_assert_eq!(a, b);
    }

    // ── JSON escape variants ────────────────────────────────────

    #[test]
    fn unicode_json_unicode_full_no_panic(s in ".*") {
        let a = unicode::json_unicode_full(&s);
        let b = unicode::json_unicode_full(&s);
        prop_assert_eq!(a, b);
    }

    #[test]
    fn unicode_json_unicode_mixed_case_no_panic(s in ".*") {
        let a = unicode::json_unicode_mixed_case(&s);
        let b = unicode::json_unicode_mixed_case(&s);
        prop_assert_eq!(a, b);
    }

    #[test]
    fn unicode_json_key_unicode_escape_no_panic(key in ".*", value in ".*") {
        let a = unicode::json_key_unicode_escape(&key, &value);
        let b = unicode::json_key_unicode_escape(&key, &value);
        prop_assert_eq!(a, b);
    }

    // ── Path traversal helper ──────────────────────────────────

    #[test]
    fn unicode_overlong_utf8_path_no_panic(path in ".*", width in 0u8..=5) {
        let a = unicode::overlong_utf8_path(&path, width);
        let b = unicode::overlong_utf8_path(&path, width);
        prop_assert_eq!(a, b);
    }

    // ── Invisible-char injectors ───────────────────────────────

    #[test]
    fn unicode_bidi_inject_no_panic(s in ".*") {
        let a = unicode::bidi_inject(&s);
        // Must start with RLO (U+202E) and end with PDF (U+202C).
        // Use char literals via named bindings to avoid `{...}` in format strings.
        let rlo: char = '\u{202E}';
        let pdf: char = '\u{202C}';
        prop_assert!(a.starts_with(rlo), "expected RLO at start of bidi_inject output");
        prop_assert!(a.ends_with(pdf), "expected PDF at end of bidi_inject output");
    }

    #[test]
    fn unicode_combining_mark_inject_no_panic(s in ".*") {
        let a = unicode::combining_mark_inject(&s, '\u{0308}');
        let b = unicode::combining_mark_inject(&s, '\u{0308}');
        prop_assert_eq!(a, b);
    }

    #[test]
    fn unicode_zero_width_inject_no_panic(s in ".*") {
        let a = unicode::zero_width_inject(&s, '\u{200B}');
        let b = unicode::zero_width_inject(&s, '\u{200B}');
        prop_assert_eq!(a, b);
    }

    // ── Script-homoglyph / locale-case encoders ────────────────

    #[test]
    fn unicode_script_homoglyph_no_panic(s in ".*") {
        let a = unicode::script_homoglyph_encode(&s);
        let b = unicode::script_homoglyph_encode(&s);
        prop_assert_eq!(a, b);
    }

    #[test]
    fn unicode_turkish_i_no_panic(s in ".*") {
        let a = unicode::turkish_i_encode(&s);
        let b = unicode::turkish_i_encode(&s);
        // Every char that was `i` or `I` must now be a dotless variant.
        for (orig, enc) in s.chars().zip(a.chars()) {
            if orig == 'i' {
                prop_assert_eq!(enc, '\u{0131}');
            } else if orig == 'I' {
                prop_assert_eq!(enc, '\u{0130}');
            }
        }
        prop_assert_eq!(a, b);
    }

    #[test]
    fn unicode_sharp_s_no_panic(s in ".*") {
        let a = unicode::sharp_s_encode(&s);
        let b = unicode::sharp_s_encode(&s);
        // Every `s` or `S` in the input must become ß (U+00DF).
        for (orig, enc) in s.chars().zip(a.chars()) {
            if orig == 's' || orig == 'S' {
                prop_assert_eq!(enc, '\u{00DF}');
            }
        }
        prop_assert_eq!(a, b);
    }

    // ── SQL evasion helpers ─────────────────────────────────────

    #[test]
    fn unicode_sql_concat_split_no_panic(s in ".*") {
        let a = unicode::sql_concat_split(&s);
        let b = unicode::sql_concat_split(&s);
        prop_assert_eq!(a, b);
    }

    #[test]
    fn unicode_sql_char_decompose_no_panic(s in ".*") {
        let a = unicode::sql_char_decompose(&s);
        let b = unicode::sql_char_decompose(&s);
        prop_assert_eq!(a, b);
    }

    #[test]
    fn unicode_pg_chr_decompose_no_panic(s in ".*") {
        let a = unicode::pg_chr_decompose(&s);
        let b = unicode::pg_chr_decompose(&s);
        prop_assert_eq!(a, b);
    }

    #[test]
    fn unicode_html_entity_variants_no_panic(s in ".*") {
        let a = unicode::html_entity_variants(&s);
        let b = unicode::html_entity_variants(&s);
        prop_assert_eq!(a, b);
    }

    #[test]
    fn unicode_sql_adjacent_string_concat_no_panic(s in ".*") {
        let a = unicode::sql_adjacent_string_concat(&s);
        let b = unicode::sql_adjacent_string_concat(&s);
        prop_assert_eq!(a, b);
    }
}
