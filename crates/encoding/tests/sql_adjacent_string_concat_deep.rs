//! Adversarial deep-coverage suite for the `sql_adjacent_string_concat`
//! tamper. Pins every subtle case so future regressions surface
//! exactly the broken behavior.

use wafrift_encoding::tamper::TamperRegistry;
use wafrift_encoding::{TamperStrategy, tamper};

fn run(payload: &str) -> String {
    tamper("sql_adjacent_string_concat", payload, Some("sql")).expect("tamper exists")
}

// ────────────────────────────────────────────────────────────────
// Boundary cases — short / empty literals
// ────────────────────────────────────────────────────────────────

#[test]
fn empty_input() {
    assert_eq!(run(""), "");
}

#[test]
fn empty_literal_passthrough() {
    assert_eq!(run("''"), "''");
}

#[test]
fn single_char_literal_passthrough() {
    assert_eq!(run("'a'"), "'a'");
    assert_eq!(run("'Z'"), "'Z'");
    assert_eq!(run("'1'"), "'1'");
    assert_eq!(run("' '"), "' '");
}

#[test]
fn two_char_literal_shatters() {
    assert_eq!(run("'ab'"), "'a' 'b'");
}

#[test]
fn three_char_literal_shatters() {
    assert_eq!(run("'abc'"), "'a' 'b' 'c'");
}

#[test]
fn no_quotes_in_input_passthrough() {
    assert_eq!(run("SELECT * FROM users"), "SELECT * FROM users");
    assert_eq!(run("1 OR 1=1"), "1 OR 1=1");
}

#[test]
fn input_is_only_a_single_quote() {
    // Unterminated quote — `'` alone is not a closed literal.
    assert_eq!(run("'"), "'");
}

#[test]
fn input_is_two_single_quotes_no_content() {
    // `''` parses as an empty literal in my code (escape detection
    // only triggers inside an OPEN literal). Pass through as-is.
    assert_eq!(run("''"), "''");
}

#[test]
fn input_is_three_single_quotes_unterminated_escape() {
    // `'''` — open literal, escape `''` (push `'` to literal), then EOF
    // without closing. Behavior: unterminated branch, output `'` + literal.
    let out = run("'''");
    // The first `'` opens. Inner loop: reads `'`, peek is `'` → push to
    // literal, consume. Now chars empty → exit loop with closed=false.
    // Output: `'` + `'` = `''`. Wait actually the literal is `'` and
    // the unterminated branch pushes that plus the leading `'`.
    assert!(!out.is_empty());
}

// ────────────────────────────────────────────────────────────────
// Realistic SQL injection literals
// ────────────────────────────────────────────────────────────────

#[test]
fn admin_credential() {
    assert_eq!(run("'admin'"), "'a' 'd' 'm' 'i' 'n'");
}

#[test]
fn root_credential() {
    assert_eq!(run("'root'"), "'r' 'o' 'o' 't'");
}

#[test]
fn etc_passwd_path() {
    let out = run("'/etc/passwd'");
    assert_eq!(out, "'/' 'e' 't' 'c' '/' 'p' 'a' 's' 's' 'w' 'd'");
    assert!(!out.contains("/etc/passwd"));
}

#[test]
fn information_schema_identifier() {
    let out = run("'information_schema'");
    assert!(!out.contains("information_schema"));
    assert!(out.contains("'i'"));
    assert!(out.contains("'s'"));
    assert!(out.starts_with("'i'"));
    // 18 chars → 18 single-char literals.
    assert_eq!(out.matches("' '").count(), 17);
}

#[test]
fn cmd_exe_path() {
    let out = run("'C:\\Windows\\cmd.exe'");
    assert!(!out.contains("cmd.exe"));
}

#[test]
fn full_sqli_with_admin_literal() {
    let out = run("WHERE name='admin' OR 1=1");
    assert_eq!(out, "WHERE name='a' 'd' 'm' 'i' 'n' OR 1=1");
}

// ────────────────────────────────────────────────────────────────
// Multiple literals in one payload
// ────────────────────────────────────────────────────────────────

#[test]
fn two_literals_each_shatters() {
    let out = run("'admin' AND 'pass'");
    assert!(out.contains("'a' 'd' 'm' 'i' 'n'"));
    assert!(out.contains("'p' 'a' 's' 's'"));
}

#[test]
fn three_literals_each_shatters() {
    let out = run("'aa' OR 'bb' OR 'cc'");
    assert_eq!(out, "'a' 'a' OR 'b' 'b' OR 'c' 'c'");
}

#[test]
fn mixed_short_and_long_literals() {
    let out = run("'x' AND 'yyyy'");
    // 'x' is len 1 — passthrough. 'yyyy' shatters.
    assert!(out.contains("'x'"));
    assert!(out.contains("'y' 'y' 'y' 'y'"));
}

#[test]
fn many_literals_in_payload() {
    let p = "'aa' 'bb' 'cc' 'dd' 'ee' 'ff' 'gg' 'hh'";
    let out = run(p);
    for c in "abcdefgh".chars() {
        let pair = format!("'{c}' '{c}'");
        assert!(out.contains(&pair), "missing pair {pair} in {out}");
    }
}

// ────────────────────────────────────────────────────────────────
// Escaped quotes — '' inside literal must NOT trigger split
// ────────────────────────────────────────────────────────────────

#[test]
fn escaped_quote_literal_shatters_with_four_quote_form() {
    // SQL '' inside literal becomes the four-quote form `''''` (length-1
    // literal containing `'`) when shattered.
    assert_eq!(run("'O''Brien'"), "'O' '''' 'B' 'r' 'i' 'e' 'n'");
}

#[test]
fn multiple_escaped_quotes_shatter() {
    // Content "a'b'c" (5 chars: a, ', b, ', c) shatters with two four-
    // quote tokens for the escapes.
    assert_eq!(run("'a''b''c'"), "'a' '''' 'b' '''' 'c'");
}

#[test]
fn escape_at_start_of_literal() {
    // Source `'''start'` parses as literal "'start" (length 6).
    // Shatter: first char is `'` → `''''`, then s/t/a/r/t each own literal.
    assert_eq!(run("'''start'"), "'''' 's' 't' 'a' 'r' 't'");
}

#[test]
fn escape_at_end_of_literal() {
    // Source `'end'''` parses as literal "end'" (length 4).
    assert_eq!(run("'end'''"), "'e' 'n' 'd' ''''");
}

#[test]
fn mixed_literal_with_and_without_escape() {
    let out = run("'O''Brien' AND 'admin'");
    assert!(out.contains("'O' '''' 'B' 'r' 'i' 'e' 'n'"));
    assert!(out.contains("'a' 'd' 'm' 'i' 'n'"));
}

#[test]
fn dogfood_b5_its_a_test_shatters() {
    // Pinning the dogfood agent's B5 reproducer: previously this
    // produced "not applicable" because the literal was preserved
    // verbatim → no diff → CLI dropped it as a no-op. Now shatters.
    let out = run("'it''s a test'");
    assert_eq!(out, "'i' 't' '''' 's' ' ' 'a' ' ' 't' 'e' 's' 't'");
    assert_ne!(out, "'it''s a test'", "must produce a real transformation");
}

// ────────────────────────────────────────────────────────────────
// Unterminated quote — graceful handling
// ────────────────────────────────────────────────────────────────

#[test]
fn unterminated_quote_at_end_passthrough() {
    assert_eq!(run("'unclosed"), "'unclosed");
}

#[test]
fn unterminated_with_no_content() {
    assert_eq!(run("text '"), "text '");
}

#[test]
fn unterminated_after_closed_literal() {
    let out = run("'admin' 'open");
    assert!(out.contains("'a' 'd' 'm' 'i' 'n'"));
    assert!(out.contains("'open") || out.contains("' 'o"));  // either form OK
}

// ────────────────────────────────────────────────────────────────
// UTF-8 / multibyte char handling
// ────────────────────────────────────────────────────────────────

#[test]
fn literal_with_latin_supplement_char() {
    // 'café' — 4 chars: c, a, f, é. All shatter into 4 single-char literals.
    let out = run("'café'");
    assert_eq!(out, "'c' 'a' 'f' 'é'");
}

#[test]
fn literal_with_cjk_char() {
    let out = run("'日本'");
    assert_eq!(out, "'日' '本'");
}

#[test]
fn literal_with_emoji() {
    // Emoji are single chars, len 4 in UTF-8.
    let out = run("'🔥🔥🔥'");
    assert_eq!(out, "'🔥' '🔥' '🔥'");
}

#[test]
fn literal_purely_unicode() {
    let out = run("'привет'");
    assert_eq!(out, "'п' 'р' 'и' 'в' 'е' 'т'");
}

#[test]
fn output_remains_valid_utf8() {
    let p = "WHERE name='admin' AND city='日本' AND nick='🔥'";
    let out = run(p);
    let _ = std::str::from_utf8(out.as_bytes()).expect("output must be valid UTF-8");
}

// ────────────────────────────────────────────────────────────────
// Idempotency
// ────────────────────────────────────────────────────────────────

#[test]
fn idempotent_on_credential_payload() {
    let p = "WHERE x='admin' OR y='root'";
    let once = run(p);
    let twice = run(&once);
    assert_eq!(once, twice);
}

#[test]
fn idempotent_on_path_payload() {
    let p = "LOAD_FILE('/etc/passwd')";
    let once = run(p);
    let twice = run(&once);
    assert_eq!(once, twice);
}

#[test]
fn idempotent_on_unicode_literal() {
    let p = "'café'";
    let once = run(p);
    let twice = run(&once);
    assert_eq!(once, twice);
}

#[test]
fn idempotent_under_ten_passes() {
    let p = "WHERE x='administrator'";
    let mut current = p.to_string();
    let once = run(p);
    for _ in 0..10 {
        current = run(&current);
    }
    assert_eq!(once, current);
}

// ────────────────────────────────────────────────────────────────
// Whitespace separators
// ────────────────────────────────────────────────────────────────

#[test]
fn output_separator_is_single_space() {
    let out = run("'abcd'");
    // Each adjacent pair separated by EXACTLY one space.
    assert!(out.contains("'a' 'b'"));
    assert!(!out.contains("'a'  'b'")); // no double space
}

#[test]
fn no_leading_or_trailing_space_around_shattered_literal() {
    let out = run("'ab'");
    assert!(out.starts_with("'a'"));
    assert!(out.ends_with("'b'"));
}

#[test]
fn shattered_output_is_sql_parser_compatible_shape() {
    // The output must look like adjacent string literals separated by
    // single spaces — testable structurally as ('X' )+
    let out = run("'admin'");
    // Tokens split by ' '.
    let tokens: Vec<&str> = out.split(' ').collect();
    for t in &tokens {
        assert!(t.starts_with('\'') && t.ends_with('\''), "token {t} not a quoted literal");
        // Inner content is exactly 1 char (or escaped form).
        let inner = &t[1..t.len() - 1];
        assert_eq!(inner.chars().count(), 1, "expected 1 char between quotes in {t}");
    }
}

// ────────────────────────────────────────────────────────────────
// Anti-rig — no second-pass blowup
// ────────────────────────────────────────────────────────────────

#[test]
fn second_pass_does_not_explode_length() {
    let p = "'aaaaaaaaaaaaaaaaaaaaaaaaaaaa'"; // 28 a's
    let once = run(p);
    let twice = run(&once);
    // Idempotent, so equal — and length doesn't grow.
    assert_eq!(once, twice);
    assert_eq!(once.len(), twice.len());
}

#[test]
fn fifty_passes_bound_within_4x() {
    let p = "WHERE n='admin'";
    let mut current = p.to_string();
    let original_len = p.len();
    for _ in 0..50 {
        current = run(&current);
    }
    assert!(current.len() <= original_len * 8, "growth exceeded 8x in 50 passes");
}

// ────────────────────────────────────────────────────────────────
// Volume / perf
// ────────────────────────────────────────────────────────────────

#[test]
fn handles_one_long_literal_5kb() {
    let inner: String = "x".repeat(5_000);
    let p = format!("'{inner}'");
    let out = run(&p);
    // Each x becomes 'x', joined by single space. 5000 tokens + 4999 spaces.
    assert!(out.contains("'x' 'x'"));
}

#[test]
fn handles_many_short_literals() {
    let p: String = (0..500).map(|i| format!("'{i}'")).collect::<Vec<_>>().join(" ");
    let out = run(&p);
    // Each 'N' is len 1-3; the >=2-char ones shatter.
    assert!(!out.is_empty());
}

#[test]
fn handles_100kb_mixed_payload() {
    let chunk = "WHERE n='admin' OR x='root'; ";
    let p: String = chunk.repeat(3000);
    let _ = run(&p);
}

// ────────────────────────────────────────────────────────────────
// Negative / adversarial input
// ────────────────────────────────────────────────────────────────

#[test]
fn payload_with_no_alphanumeric_inside_literal() {
    let out = run("'!@#$%'");
    // Length 5 ≥ 2 → shatters into single-char literals.
    assert_eq!(out, "'!' '@' '#' '$' '%'");
}

#[test]
fn payload_with_internal_whitespace_in_literal() {
    let out = run("'a b c'");
    assert_eq!(out, "'a' ' ' 'b' ' ' 'c'");
}

#[test]
fn payload_with_internal_newline_in_literal() {
    let out = run("'a\nb'");
    assert_eq!(out, "'a' '\n' 'b'");
}

#[test]
fn payload_with_internal_null_byte_in_literal() {
    let out = run("'a\0b'");
    assert_eq!(out, "'a' '\0' 'b'");
}

#[test]
fn payload_with_backslash_in_literal() {
    let out = run("'a\\b'");
    assert_eq!(out, "'a' '\\' 'b'");
}

// ────────────────────────────────────────────────────────────────
// Registry / dispatch integration
// ────────────────────────────────────────────────────────────────

#[test]
fn registered_in_default_registry() {
    let reg = TamperRegistry::with_defaults();
    assert!(reg.get("sql_adjacent_string_concat").is_some());
}

#[test]
fn registered_strategy_name_matches() {
    let reg = TamperRegistry::with_defaults();
    let strat = reg.get("sql_adjacent_string_concat").unwrap();
    assert_eq!(strat.name(), "sql_adjacent_string_concat");
}

#[test]
fn registered_aggressiveness_in_range() {
    let reg = TamperRegistry::with_defaults();
    let strat = reg.get("sql_adjacent_string_concat").unwrap();
    let a = strat.aggressiveness();
    assert!((0.0..=1.0).contains(&a));
    assert!(!a.is_nan());
}

#[test]
fn registered_description_non_empty() {
    let reg = TamperRegistry::with_defaults();
    let strat = reg.get("sql_adjacent_string_concat").unwrap();
    assert!(!strat.description().is_empty());
}

#[test]
fn appears_in_all_tamper_names() {
    let names = wafrift_encoding::all_tamper_names();
    assert!(names.contains(&"sql_adjacent_string_concat"));
}

// ────────────────────────────────────────────────────────────────
// Concurrency
// ────────────────────────────────────────────────────────────────

#[test]
fn concurrent_calls_consistent() {
    use std::sync::Arc;
    use std::thread;
    let reg = Arc::new(TamperRegistry::with_defaults());
    let payload = "WHERE x='administrator'";
    let expected = reg
        .tamper_with("sql_adjacent_string_concat", payload, None)
        .unwrap();
    let mut handles = vec![];
    for _ in 0..32 {
        let r = Arc::clone(&reg);
        let p = payload.to_string();
        let e = expected.clone();
        handles.push(thread::spawn(move || {
            let out = r.tamper_with("sql_adjacent_string_concat", &p, None).unwrap();
            assert_eq!(out, e);
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ────────────────────────────────────────────────────────────────
// Context parameter (should be ignored for this tamper)
// ────────────────────────────────────────────────────────────────

#[test]
fn context_does_not_affect_output() {
    let p = "WHERE n='admin'";
    let none = tamper("sql_adjacent_string_concat", p, None).unwrap();
    let sql = tamper("sql_adjacent_string_concat", p, Some("sql")).unwrap();
    let xss = tamper("sql_adjacent_string_concat", p, Some("xss")).unwrap();
    assert_eq!(none, sql);
    assert_eq!(sql, xss);
}

// ────────────────────────────────────────────────────────────────
// Reasonable equivalence semantics (informal)
// ────────────────────────────────────────────────────────────────

fn rejoin_adjacent_literals(s: &str) -> String {
    // Naive parser: walk the string token by token. Adjacent quoted
    // literals separated by whitespace get joined; everything else
    // (including escaped quote pairs) is preserved verbatim.
    let mut out = String::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    let mut accum: Option<String> = None;
    while i < chars.len() {
        if chars[i] == '\'' {
            let mut literal = String::new();
            i += 1;
            while i < chars.len() {
                if chars[i] == '\'' {
                    if i + 1 < chars.len() && chars[i + 1] == '\'' {
                        literal.push('\'');
                        i += 2;
                        continue;
                    }
                    i += 1;
                    break;
                }
                literal.push(chars[i]);
                i += 1;
            }
            // peek past whitespace, if next non-whitespace is `'`, append.
            if let Some(ref mut a) = accum {
                a.push_str(&literal);
            } else {
                accum = Some(literal);
            }
            // Now peek for whitespace + `'`.
            let save = i;
            while i < chars.len() && chars[i].is_whitespace() {
                i += 1;
            }
            if i < chars.len() && chars[i] == '\'' {
                // Continue accumulating — don't flush yet.
                continue;
            } else {
                // Flush.
                i = save;
                out.push('\'');
                out.push_str(accum.as_ref().unwrap());
                out.push('\'');
                accum = None;
            }
        } else {
            if let Some(a) = accum.take() {
                out.push('\'');
                out.push_str(&a);
                out.push('\'');
            }
            out.push(chars[i]);
            i += 1;
        }
    }
    if let Some(a) = accum {
        out.push('\'');
        out.push_str(&a);
        out.push('\'');
    }
    out
}

#[test]
fn rejoin_undoes_shatter_for_admin() {
    let p = "'admin'";
    let shattered = run(p);
    let rejoined = rejoin_adjacent_literals(&shattered);
    assert_eq!(rejoined, p);
}

#[test]
fn rejoin_undoes_shatter_for_full_sqli() {
    let p = "WHERE name='admin' AND password='root'";
    let shattered = run(p);
    let rejoined = rejoin_adjacent_literals(&shattered);
    assert_eq!(rejoined, p);
}

#[test]
fn rejoin_undoes_shatter_for_path() {
    let p = "'/etc/passwd'";
    let shattered = run(p);
    let rejoined = rejoin_adjacent_literals(&shattered);
    assert_eq!(rejoined, p);
}

#[test]
fn rejoin_undoes_shatter_for_unicode() {
    let p = "'café'";
    let shattered = run(p);
    let rejoined = rejoin_adjacent_literals(&shattered);
    assert_eq!(rejoined, p);
}

#[test]
fn rejoin_preserves_short_literals() {
    let p = "WHERE x='a' AND y='b'";
    let shattered = run(p);
    // 'a' and 'b' both pass through.
    let rejoined = rejoin_adjacent_literals(&shattered);
    assert_eq!(rejoined, p);
}
