//! Property tests for the `wafrift import-curl` shell tokeniser.
//!
//! The tokeniser handles attacker-shaped curl invocations (Burp's
//! "Copy as cURL" output is rarely sanitised; users pipe arbitrary
//! shell-quoted strings in). We check three invariants under random
//! input:
//!
//! 1. `shell_tokenize` never panics — even on garbage. It either
//!    parses or returns `Err`, never aborts the process.
//! 2. For tokens that survived parsing, the count is bounded by the
//!    input length (no exponential blowup).
//! 3. Round-trip on a synthesised curl line: build a curl invocation
//!    out of randomly-shaped pieces, then assert tokenisation
//!    recovers each piece.
//!
//! These tests run as part of the standard `cargo test -p wafrift-cli`
//! sweep, so the property surface is exercised on every PR.

use proptest::prelude::*;

// import_curl is a private mod inside the cli binary, so we duplicate
// the tokeniser here. This mirrors the production code in
// crates/cli/src/import_curl.rs:shell_tokenize. If you change one,
// change the other.
fn shell_tokenize(input: &str) -> Result<Vec<String>, String> {
    let cleaned = input.replace("\\\n", " ").replace("\\\r\n", " ");
    let mut out = Vec::new();
    let mut current = String::new();
    let mut chars = cleaned.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' | '\n' | '\r' => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
            '\'' => {
                for q in chars.by_ref() {
                    if q == '\'' {
                        break;
                    }
                    current.push(q);
                }
            }
            '"' => {
                while let Some(q) = chars.next() {
                    if q == '"' {
                        break;
                    }
                    if q == '\\' {
                        if let Some(esc) = chars.next() {
                            current.push(esc);
                        }
                    } else {
                        current.push(q);
                    }
                }
            }
            '\\' => {
                if let Some(esc) = chars.next() {
                    current.push(esc);
                }
            }
            other => current.push(other),
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    if out.is_empty() {
        return Err("empty curl invocation".to_string());
    }
    if out[0] != "curl" {
        return Err(format!("first token must be `curl`, got {:?}", out[0]));
    }
    Ok(out)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// Tokeniser must never panic on arbitrary byte strings — only
    /// return Ok or Err. A panic here turns `wafrift import-curl
    /// --from-stdin` into a denial-of-service against itself.
    #[test]
    fn tokenize_never_panics(input in ".{0,4096}") {
        let _ = shell_tokenize(&input);
    }

    /// Token count is linearly bounded by input length. If a future
    /// refactor introduces exponential blowup (e.g. nested-quote
    /// unrolling), this test catches the perf regression.
    #[test]
    fn token_count_is_bounded(input in r"[a-zA-Z0-9 _'\\\-:/]{0,1024}") {
        if let Ok(toks) = shell_tokenize(&input) {
            prop_assert!(toks.len() <= input.len() + 1);
        }
    }

    /// Round-trip: build a curl invocation from a list of
    /// single-quote-safe arguments, tokenise it, recover the args.
    /// Exercises the single-quote happy path which is the dominant
    /// shape from Burp's "Copy as cURL".
    #[test]
    fn single_quoted_args_round_trip(args in proptest::collection::vec(
        r"[a-zA-Z0-9 _\-:/=?&.,;+@]{0,64}", 0..6
    )) {
        let mut line = String::from("curl");
        for a in &args {
            line.push(' ');
            line.push('\'');
            line.push_str(a);
            line.push('\'');
        }
        let toks = shell_tokenize(&line).expect("synthesised curl must tokenise");
        prop_assert_eq!(toks[0].as_str(), "curl");
        prop_assert_eq!(toks.len(), 1 + args.len());
        for (i, a) in args.iter().enumerate() {
            prop_assert_eq!(&toks[i + 1], a);
        }
    }
}
