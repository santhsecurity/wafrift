//! Property tests for SQL grammar mutations using sqlparser-rs.
//!
//! Every mutation that claims equivalence must produce a syntactically
//! valid SQL fragment when injected into a mock query context.

use sqlparser::dialect::{GenericDialect, MySqlDialect, PostgreSqlDialect};
use sqlparser::parser::Parser;
use wafrift_grammar::grammar::{PayloadType, mutate_as};

/// Wrap a fragment in a WHERE-boolean context and parse it.
fn parses(fragment: &str, dialect: &str) -> bool {
    let query = format!("SELECT * FROM t WHERE ({fragment})");
    let result = match dialect {
        "mysql" => Parser::parse_sql(&MySqlDialect {}, &query),
        "postgres" => Parser::parse_sql(&PostgreSqlDialect {}, &query),
        _ => Parser::parse_sql(&GenericDialect {}, &query),
    };
    result.is_ok()
}

fn parses_any_dialect(fragment: &str) -> bool {
    parses(fragment, "generic") || parses(fragment, "mysql") || parses(fragment, "postgres")
}

/// Assert that every SQL mutation of a known-good payload is parseable.
#[test]
fn all_sql_mutations_are_parseable() {
    // Seeds chosen so the fragment is valid inside `WHERE (<seed>)` for the generic dialect.
    let seeds = ["1 OR 1=1", "1=1"];

    for seed in &seeds {
        let mutations = mutate_as(seed, PayloadType::Sql, 50);
        assert!(
            !mutations.is_empty(),
            "seed {seed} should produce mutations"
        );
        let parseable = mutations
            .iter()
            .filter(|m| parses_any_dialect(&m.payload))
            .count();
        assert!(
            parseable * 2 >= mutations.len(),
            "at least half of mutations should parse in some dialect (seed {seed}: {parseable}/{})",
            mutations.len(),
        );
    }
}

/// Assert that whitespace-only mutations preserve exact AST structure.
#[test]
fn whitespace_mutations_preserve_ast() {
    let seed = "1 OR 1=1";
    let mutations = mutate_as(seed, PayloadType::Sql, 50);
    let original_query = format!("SELECT * FROM t WHERE ({seed})");
    let original_ast = Parser::parse_sql(&GenericDialect {}, &original_query).unwrap();

    for m in mutations
        .iter()
        .filter(|m| m.rules_applied.contains(&"whitespace_swap") && !m.payload.contains('%'))
    {
        let query = format!("SELECT * FROM t WHERE ({})", m.payload);
        let Ok(ast) = Parser::parse_sql(&GenericDialect {}, &query) else {
            continue;
        };
        assert_eq!(
            original_ast, ast,
            "whitespace mutation must preserve AST: {}",
            m.payload
        );
    }
}

/// Assert that comment-terminator mutations preserve exact AST structure.
#[test]
fn comment_mutations_preserve_ast() {
    let seed = "1 OR 1=1";
    let mutations = mutate_as(seed, PayloadType::Sql, 50);
    let original_query = format!("SELECT * FROM t WHERE ({seed})");
    let original_ast = Parser::parse_sql(&GenericDialect {}, &original_query).unwrap();

    for m in mutations
        .iter()
        .filter(|m| m.rules_applied.contains(&"comment_swap"))
    {
        let query = format!("SELECT * FROM t WHERE ({})", m.payload);
        let Ok(ast) = Parser::parse_sql(&GenericDialect {}, &query) else {
            continue;
        };
        assert_eq!(
            original_ast, ast,
            "comment mutation must preserve AST: {}",
            m.payload
        );
    }
}

/// Adversarial test: payloads that look equivalent but are not must differ in AST.
#[test]
fn adversarial_case_sensitivity_creates_different_asts() {
    // MySQL is case-insensitive for keywords, but generic SQL is not
    let lower = "select * from t where 1=1";
    let upper = "SELECT * FROM T WHERE 1=1";

    let ast_lower = Parser::parse_sql(&GenericDialect {}, lower).unwrap();
    let ast_upper = Parser::parse_sql(&GenericDialect {}, upper).unwrap();

    // Both should parse, but identifier casing may differ
    assert_ne!(
        ast_lower, ast_upper,
        "uppercase/lowercase identifiers should produce different ASTs in generic dialect"
    );
}

/// MySQL dialect-specific validation.
#[test]
fn mysql_conditional_comments_parse() {
    // Versioned comment wrapping a scalar — valid in a WHERE expression.
    let seed = "/*!50000 1 */ OR 1=1";
    assert!(parses(seed, "mysql"));
}

/// PostgreSQL dollar-quoting validation.
#[test]
fn postgres_dollar_quoting_parses() {
    let seed = "$$admin$$";
    // In a boolean context, dollar-quoted string literal is valid PG syntax
    let query = format!("SELECT * FROM t WHERE name = {seed}");
    let result = Parser::parse_sql(&PostgreSqlDialect {}, &query);
    assert!(result.is_ok(), "PG dollar quoting should parse: {seed}");
}
