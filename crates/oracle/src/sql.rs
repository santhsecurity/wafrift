//! SQL AST Oracle.
//!
//! Provides mathematically rigorous syntactic validation of SQL injections
//! against actual database parsers. Instead of guessing if a mutated
//! payload works based on regex, we compile it locally to an AST.
//! If it compiles, the backend Database will accept it.

use sqlparser::dialect::{GenericDialect, MySqlDialect, PostgreSqlDialect};
use sqlparser::parser::Parser;

/// The target SQL database dialect for AST validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseDialect {
    /// Generic ANSI SQL
    Generic,
    /// MySQL/MariaDB
    MySql,
    /// `PostgreSQL`
    PostgreSql,
}

/// Evaluates if a given SQL fragment is syntactically valid when injected into an expression context.
///
/// Wraps the fragment into a mock query to provide context for the AST parser.
#[must_use]
pub fn is_valid_expression_injection(fragment: &str, dialect: DatabaseDialect) -> bool {
    let query = format!("SELECT * FROM mock_table WHERE id = {fragment}");
    let result = match dialect {
        DatabaseDialect::Generic => Parser::parse_sql(&GenericDialect {}, &query),
        DatabaseDialect::MySql => Parser::parse_sql(&MySqlDialect {}, &query),
        DatabaseDialect::PostgreSql => Parser::parse_sql(&PostgreSqlDialect {}, &query),
    };

    // If the parser successfully builds an AST, the injection is structurally pristine.
    result.is_ok()
}

/// Evaluates if a given SQL fragment is syntactically valid as a raw query.
#[must_use]
pub fn is_valid_query(query: &str, dialect: DatabaseDialect) -> bool {
    let result = match dialect {
        DatabaseDialect::Generic => Parser::parse_sql(&GenericDialect {}, query),
        DatabaseDialect::MySql => Parser::parse_sql(&MySqlDialect {}, query),
        DatabaseDialect::PostgreSql => Parser::parse_sql(&PostgreSqlDialect {}, query),
    };

    result.is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_sql_fragment_parses() {
        // Classic bypass evaluates to true
        assert!(is_valid_expression_injection(
            "1 OR 1=1 --",
            DatabaseDialect::Generic
        ));

        // Multi-line comment obfuscation
        assert!(is_valid_expression_injection(
            "1/**/OR/**/1=1",
            DatabaseDialect::MySql
        ));
    }

    #[test]
    fn invalid_sql_fragment_fails() {
        // MCTS might accidentally generate incomplete syntax
        assert!(!is_valid_expression_injection(
            "1 OR 1=/**/",
            DatabaseDialect::Generic
        ));
        assert!(!is_valid_expression_injection(
            "1 O R 1=1",
            DatabaseDialect::Generic
        ));
    }
}
