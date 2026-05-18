//! SQL AST Oracle.
//!
//! Mathematically rigorous syntactic validation of SQL injections
//! against real database parsers. A mutated payload is a *working
//! attack* iff, spliced into some realistic host-query context, it
//! parses AND it structurally changes the query's logic (injects a
//! boolean/UNION/stacked statement/comment-truncation/subquery) — not
//! merely supplies a different literal.
//!
//! The pre-2026-05 oracle modelled ONE context (`WHERE id = <f>`,
//! numeric). That wrongly rejected every quote-context injection
//! (`1' OR '1'='1`, `1' UNION SELECT …-- -`) — the dominant real-world
//! shape — so genuine bypasses scored 0. This models the full set of
//! contexts a real app exposes, while the structural-change predicate
//! keeps non-attacks (`'+0+'`, bare literals, junk) rejected. It is a
//! *correctness* fix, never a loosening: every MUST-REJECT in the test
//! battery still rejects.

use sqlparser::dialect::{Dialect, GenericDialect, MySqlDialect, PostgreSqlDialect};
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

fn parse_with(dialect: DatabaseDialect, q: &str) -> Result<Vec<sqlparser::ast::Statement>, ()> {
    fn go<D: Dialect>(d: D, q: &str) -> Result<Vec<sqlparser::ast::Statement>, ()> {
        Parser::parse_sql(&d, q).map_err(|_| ())
    }
    match dialect {
        DatabaseDialect::Generic => go(GenericDialect {}, q),
        DatabaseDialect::MySql => go(MySqlDialect {}, q),
        DatabaseDialect::PostgreSql => go(PostgreSqlDialect {}, q),
    }
}

/// Realistic host-query contexts an injectable parameter sits in.
/// `(prefix, suffix, benign)` — `benign` is a harmless value used to
/// build the structural baseline for that exact context.
const CONTEXTS: &[(&str, &str, &str)] = &[
    // numeric
    ("SELECT * FROM t WHERE id = ", "", "1"),
    ("SELECT * FROM t WHERE id = ", " LIMIT 1", "1"),
    ("SELECT * FROM t WHERE (id = ", ")", "1"),
    // single-quoted string
    ("SELECT * FROM t WHERE name = '", "'", "x"),
    ("SELECT * FROM t WHERE name = '", "' LIMIT 1", "x"),
    ("SELECT * FROM t WHERE name = '", "' AND active = 1", "x"),
    // paren-wrapped quoted column (common ORM / framework shape:
    // `WHERE (name = 'INJ')`) — needed for `1') OR ('1'='1`.
    ("SELECT * FROM t WHERE (name = '", "')", "x"),
    ("SELECT * FROM t WHERE (id = '", "')", "1"),
    // double-quoted string (MySQL ANSI off / MSSQL-ish)
    ("SELECT * FROM t WHERE name = \"", "\"", "x"),
    // IN list / LIKE / ORDER BY
    ("SELECT * FROM t WHERE id IN (", ")", "1"),
    ("SELECT * FROM t WHERE name LIKE '%", "%'", "x"),
    ("SELECT * FROM t ORDER BY ", "", "1"),
    // ORDER BY <col> <DIR> — the injection follows a named column, the
    // single most common ORDER BY shape (sort-direction params).
    ("SELECT * FROM t ORDER BY name ", "", "ASC"),
    // LIMIT / OFFSET — numeric param positions real apps expose.
    ("SELECT * FROM t WHERE a = 1 LIMIT ", "", "1"),
    ("SELECT * FROM t WHERE a = 1 LIMIT 1 OFFSET ", "", "0"),
    // numeric value with a trailing AND clause (extremely common:
    // `WHERE id = <INJ> AND tenant = 1`) — without this a sound
    // numeric break here is misjudged "not an attack".
    ("SELECT * FROM t WHERE id = ", " AND tenant = 1", "1"),
    // INSERT … VALUES (string + numeric) and UPDATE … SET (string):
    // write-path injections a query-only context set never models.
    ("INSERT INTO t (a) VALUES ('", "')", "x"),
    ("INSERT INTO t (a) VALUES (", ")", "1"),
    ("UPDATE t SET a = '", "' WHERE id = 1", "x"),
];

/// Injection constructs that mark a *structural* change to the query
/// (present in the spliced AST, absent from the benign baseline).
fn ast_has_injection_marker(dbg: &str) -> bool {
    // sqlparser's Debug rendering is stable enough to detect injected
    // logic. These never appear for a plain literal / arithmetic value.
    const MARKERS: &[&str] = &[
        "op: Or",
        "op: And",
        "op: Xor",
        "Union",
        "Subquery",
        "InSubquery",
        "InList",
        "Between {",
        "Like {",
        "ILike {",
        "AnyOp",
        "AllOp",
        "Exists",
        "CaseWhen",
        "Case {",
        "extractvalue",
        "updatexml",
        "Sleep",
        "sleep",
        "benchmark",
        "pg_sleep",
        "load_file",
        "information_schema",
        "GroupBy",
        "Having",
    ];
    MARKERS.iter().any(|m| dbg.contains(m))
}

fn comment_truncates(fragment: &str) -> bool {
    let f = fragment.to_ascii_lowercase();
    f.contains("--") || f.contains('#') || f.contains("/*")
}

/// Does `fragment`, spliced into `(prefix,suffix)`, structurally inject
/// (vs. the benign baseline for that exact context)?
fn structural_in_context(
    dialect: DatabaseDialect,
    prefix: &str,
    suffix: &str,
    benign: &str,
    fragment: &str,
) -> bool {
    let q = format!("{prefix}{fragment}{suffix}");
    let Ok(stmts) = parse_with(dialect, &q) else {
        return false;
    };
    if stmts.is_empty() {
        return false;
    }
    // Stacked queries: the fragment introduced extra statements.
    if stmts.len() > 1 {
        return true;
    }
    // Comment-truncation: the fragment commented the suffix away. Only
    // counts if there WAS a suffix to neutralise and the prefix-only
    // form (suffix dropped) still parses — i.e. the rest of the host
    // query is genuinely dead.
    if !suffix.trim().is_empty()
        && comment_truncates(fragment)
        && parse_with(dialect, &format!("{prefix}{fragment}")).is_ok()
    {
        return true;
    }
    // Structural logic injection: a construct present in the spliced
    // AST but NOT in the benign baseline for this exact context.
    let dbg = format!("{stmts:?}");
    let base = format!("{prefix}{benign}{suffix}");
    let base_dbg = parse_with(dialect, &base)
        .ok()
        .map(|s| format!("{s:?}"))
        .unwrap_or_default();
    ast_has_injection_marker(&dbg) && !ast_has_injection_marker(&base_dbg)
}

/// Evaluates if a SQL fragment is a *working injection* in some
/// realistic host context for `dialect`.
///
/// Accepts iff there exists a context where the fragment parses AND
/// structurally changes the query (boolean / UNION / stacked /
/// comment-truncation / subquery). A bare literal, arithmetic on
/// literals (`'+0+'`), or unparseable junk is rejected in EVERY
/// context — the anti-rig guarantee, pinned by the test battery.
#[must_use]
pub fn is_valid_expression_injection(fragment: &str, dialect: DatabaseDialect) -> bool {
    let f = fragment.trim();
    if f.is_empty() {
        return false;
    }
    CONTEXTS
        .iter()
        .any(|(p, s, b)| structural_in_context(dialect, p, s, b, f))
}

/// Evaluates if a given SQL fragment is syntactically valid as a raw query.
#[must_use]
pub fn is_valid_query(query: &str, dialect: DatabaseDialect) -> bool {
    parse_with(dialect, query).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── existing contract (must stay green) ─────────────────────────
    #[test]
    fn valid_sql_fragment_parses() {
        assert!(is_valid_expression_injection(
            "1 OR 1=1 --",
            DatabaseDialect::Generic
        ));
        assert!(is_valid_expression_injection(
            "1/**/OR/**/1=1",
            DatabaseDialect::MySql
        ));
    }

    #[test]
    fn invalid_sql_fragment_fails() {
        // Incomplete syntax / tokenised keyword: parses in no context.
        assert!(!is_valid_expression_injection(
            "1 OR 1=/**/",
            DatabaseDialect::Generic
        ));
        assert!(!is_valid_expression_injection(
            "1 O R 1=1",
            DatabaseDialect::Generic
        ));
    }

    // ── ANTI-RIG: non-attacks rejected in EVERY context ─────────────
    #[test]
    fn non_attacks_are_rejected() {
        for junk in [
            "1",
            "1234",
            "'abc'",
            "'+0+'",
            "'-0-'",
            "1+1",
            "0x1",
            "1e0",
            "\"\"",
            "   ",
            "",
            ")) not sql at all ((",
            "hello world",
            "/**/",
            "-- just a comment",
            "abc",
            "NULL",
        ] {
            for d in [
                DatabaseDialect::Generic,
                DatabaseDialect::MySql,
                DatabaseDialect::PostgreSql,
            ] {
                assert!(
                    !is_valid_expression_injection(junk, d),
                    "RIG: non-attack {junk:?} accepted as a valid injection ({d:?})"
                );
            }
        }
    }

    // ── correctness: real SQLi across REAL host contexts ────────────
    #[test]
    fn quote_context_injections_are_accepted() {
        for atk in [
            "1' OR '1'='1",
            "1' OR '1'='1'-- -",
            "1' OR '1'='1'#",
            "admin'-- -",
            "1') OR ('1'='1",
            "1'/**/OR/**/'1'='1",
            "x' UNION SELECT username,password FROM users-- -",
            "1' AND (SELECT 1 FROM users WHERE name='admin')-- -",
            "1' OR SLEEP(5)-- -",
            "1\" OR \"1\"=\"1",
        ] {
            assert!(
                is_valid_expression_injection(atk, DatabaseDialect::Generic)
                    || is_valid_expression_injection(atk, DatabaseDialect::MySql),
                "correctness: real quote-context SQLi {atk:?} wrongly rejected"
            );
        }
    }

    #[test]
    fn numeric_and_structured_injections_are_accepted() {
        for atk in [
            "1 OR 1=1",
            "1 OR 1=1-- -",
            "1 UNION SELECT username,password FROM users-- -",
            "1 UNION ALL SELECT NULL,version()-- -",
            "1 AND extractvalue(1,concat(0x7e,(SELECT version())))",
            "1 AND updatexml(1,concat(0x7e,(SELECT database())),1)",
            "1; DROP TABLE users-- -",
            "1 AND (SELECT 1 FROM (SELECT SLEEP(5))x)",
            "1 OR 1=1 LIMIT 1-- -",
            "1) OR (1=1",
            "1 AND 1=1 UNION SELECT 1,2,3-- -",
        ] {
            assert!(
                is_valid_expression_injection(atk, DatabaseDialect::Generic)
                    || is_valid_expression_injection(atk, DatabaseDialect::MySql),
                "correctness: structured SQLi {atk:?} wrongly rejected"
            );
        }
    }

    #[test]
    fn benign_literal_in_string_context_is_not_an_injection() {
        // `'+0+'` spliced into a string ctx is arithmetic on literals,
        // not injected logic — must stay rejected.
        assert!(!is_valid_expression_injection("'+0+'", DatabaseDialect::Generic));
        assert!(!is_valid_expression_injection("0+1", DatabaseDialect::Generic));
        assert!(!is_valid_expression_injection("1*1", DatabaseDialect::MySql));
    }

    #[test]
    fn is_valid_query_smoke() {
        assert!(is_valid_query("SELECT 1", DatabaseDialect::Generic));
        assert!(!is_valid_query("SELECT FROM", DatabaseDialect::Generic));
    }

    // ── recall: write-path + clause contexts (added 2026-05-18) ──────
    #[test]
    fn write_path_and_clause_context_injections_are_accepted() {
        // Each is a genuine structural injection that only resolves in
        // an INSERT/UPDATE/ORDER-BY-dir/LIMIT/trailing-AND host — shapes
        // a query-only context set misjudged as "not an attack".
        for atk in [
            "1) ; DROP TABLE users-- -",                  // INSERT VALUES stacked
            "x', 'pwned')-- -",                           // INSERT VALUES break+comment
            "x', role = 'admin'-- -",                     // UPDATE SET extra-column
            "; DROP TABLE users-- -",                     // ORDER BY <col> stacked
            "(CASE WHEN (1=1) THEN name ELSE id END)",     // ORDER BY blind CASE
            "1 OR 1=1",                                    // numeric + trailing AND
        ] {
            assert!(
                is_valid_expression_injection(atk, DatabaseDialect::Generic)
                    || is_valid_expression_injection(atk, DatabaseDialect::MySql),
                "recall: real context-specific SQLi {atk:?} wrongly rejected"
            );
        }
    }

    #[test]
    fn benign_values_in_the_new_contexts_stay_rejected() {
        // ANTI-RIG: the added contexts must not turn a harmless value
        // into an "injection". A plain string/number/sort-dir is inert
        // in INSERT/UPDATE/ORDER-BY/LIMIT just as in WHERE.
        for benign in ["admin", "ASC", "DESC", "42", "user@example.com", "'x'"] {
            for d in [
                DatabaseDialect::Generic,
                DatabaseDialect::MySql,
                DatabaseDialect::PostgreSql,
            ] {
                assert!(
                    !is_valid_expression_injection(benign, d),
                    "RIG: benign {benign:?} accepted via a new context ({d:?})"
                );
            }
        }
    }
}
