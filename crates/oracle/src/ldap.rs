//! LDAP-injection payload oracle.
//!
//! # Why this is context-splicing, not standalone-filter validation
//!
//! A real LDAP *injection* fragment is deliberately **unbalanced** in
//! isolation: the application builds `("(uid=" + INPUT + ")")`, and the
//! attacker supplies `*)(|(uid=*` so the *combined* filter becomes a
//! filter-break / always-true bypass. Judging the fragment `*)(|(uid=*`
//! on its own ("are its parentheses balanced?") rejects EVERY genuine
//! LDAP injection — including the unmodified attack — which silently
//! pinned the LDAP bypass rate at 0%, exactly the rig the SQL oracle
//! had before it was rebuilt.
//!
//! So, mirroring `sql::is_valid_expression_injection`: a fragment is a
//! valid injection iff there exists a realistic host filter context
//! where the assembled, server-effective filter
//!   1. is a balanced, RFC-4515-parseable `filterlist` (proof the
//!      break actually fits a real query — including the canonical
//!      *open-ended* breaks that rely on the host's own trailing
//!      parens, modelled by decoupling the count of host closing
//!      parens to the value's right from the host's prefix depth), and
//!   2. is **bypass-relevantly richer** than the benign baseline: the
//!      *fragment itself* introduced a boolean connective (`& | !`) or
//!      a match-all `*` value. A mere extra/duplicate leaf with no new
//!      operator and no wildcard (`bob)(uid=bob`) is NOT an injection —
//!      counting absolute leaves would re-introduce the rig via an
//!      AND-wrapped host whose own `&` is not the fragment's doing.
//!
//! The server-effective filter also models NUL / `%00` truncation
//! (`*))%00` discards everything the application appended after the
//! NUL — a real, documented LDAP auth-bypass), and the parser is
//! tolerant of RFC-4515 `\HH` escapes in the attribute descriptor so a
//! fully hex-escaped break (`\75\69\64=\2a`) still recognises.
//!
//! A benign literal (`alice`), a normal substring search (`al*`),
//! unparseable junk, SQL, or a structure-preserving duplicate is
//! rejected in EVERY context — the anti-rig guarantee, pinned by the
//! MUST-REJECT battery in the tests.

use crate::traits::PayloadOracle;

/// LDAP injection oracle: structural-injection-in-context validator.
pub struct LdapOracle;

/// Attribute descriptors a realistic injectable parameter is matched
/// against, with a context-appropriate benign baseline value.
const ATTRS: &[(&str, &str)] = &[
    ("uid", "alice"),
    ("cn", "alice"),
    ("mail", "a@b.example"),
    ("sAMAccountName", "alice"),
    ("userPassword", "secret"),
    ("objectClass", "person"),
];

// ── RFC 4515-tolerant filter recogniser ────────────────────────────
//
// Accepts a `filterlist` (1+ adjacent filters) at the top so a
// filter-break injection `(a)(b)` is recognised; rejects non-filter
// garbage, unbalanced parens, empty items. Tolerant of `\HH` escapes
// inside the attribute descriptor (some directories unescape it; the
// equiv generator emits it and the structural break is what matters).

fn is_attr_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ';' | ':' | '_')
}

/// If `b[i..]` starts with a `\HH` (backslash + 2 hex) escape, return
/// the index past it.
fn escape_at(b: &[char], i: usize) -> Option<usize> {
    if i + 2 < b.len()
        && b[i] == '\\'
        && b[i + 1].is_ascii_hexdigit()
        && b[i + 2].is_ascii_hexdigit()
    {
        Some(i + 3)
    } else {
        None
    }
}

/// Parse one `filter` = `(` filtercomp `)`. Returns the index just
/// past the closing `)`, or `None` on a structural error.
fn parse_filter(b: &[char], mut i: usize) -> Option<usize> {
    if i >= b.len() || b[i] != '(' {
        return None;
    }
    i += 1;
    if i >= b.len() {
        return None;
    }
    match b[i] {
        '&' | '|' => {
            i += 1;
            let mut count = 0;
            while i < b.len() && b[i] == '(' {
                i = parse_filter(b, i)?;
                count += 1;
            }
            if count == 0 {
                return None;
            }
        }
        '!' => {
            i += 1;
            i = parse_filter(b, i)?;
        }
        _ => {
            // item: attr op value  (op ∈ = ~= >= <= :=). The attribute
            // descriptor may carry `\HH` escapes (tolerant).
            let attr_start = i;
            loop {
                if let Some(j) = escape_at(b, i) {
                    i = j;
                } else if i < b.len() && is_attr_char(b[i]) && b[i] != ')' {
                    i += 1;
                } else {
                    break;
                }
            }
            if i == attr_start {
                return None; // empty attribute description
            }
            if i < b.len() && matches!(b[i], '~' | '>' | '<') {
                i += 1;
            }
            if i >= b.len() || b[i] != '=' {
                return None;
            }
            i += 1;
            // value: up to the matching ')' that is not an unescaped
            // paren (escapes `\28`/`\29`/`\2a` are value bytes).
            while i < b.len() && b[i] != ')' && b[i] != '(' {
                i += 1;
            }
        }
    }
    if i >= b.len() || b[i] != ')' {
        return None;
    }
    Some(i + 1)
}

/// Whole input parses as a `filterlist` (1+ adjacent filters), nothing
/// left over.
fn parses_as_filterlist(s: &str) -> bool {
    let b: Vec<char> = s.chars().collect();
    let mut i = 0;
    let mut n = 0;
    while i < b.len() {
        if b[i] != '(' {
            return false;
        }
        match parse_filter(&b, i) {
            Some(j) => {
                i = j;
                n += 1;
            }
            None => return false,
        }
    }
    n >= 1
}

fn balanced(s: &str) -> bool {
    let mut d = 0i32;
    for c in s.chars() {
        match c {
            '(' => d += 1,
            ')' => {
                d -= 1;
                if d < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    d == 0
}

/// Server-effective filter: a C-string-backed directory truncates at
/// the first NUL. The web layer delivers it as a literal `\0` or as
/// `%00`; both end the filter the server actually evaluates.
fn effective_filter(s: &str) -> &str {
    let mut cut = s.len();
    if let Some(p) = s.find('\u{0}') {
        cut = cut.min(p);
    }
    if let Some(p) = s.find("%00") {
        cut = cut.min(p);
    }
    &s[..cut]
}

/// Structural fingerprint used to decide whether the fragment did more
/// than substitute a literal value.
#[derive(PartialEq, Default)]
struct Skeleton {
    /// `&` / `|` / `!` boolean connective count.
    bool_ops: usize,
    /// number of leaf `(attr op value)` items.
    leaves: usize,
    /// a value that is exactly `*` (match-all → auth bypass).
    match_all: bool,
}

fn skeleton(s: &str) -> Skeleton {
    let b: Vec<char> = s.chars().collect();
    let mut k = Skeleton::default();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            '(' if i + 1 < b.len() && matches!(b[i + 1], '&' | '|' | '!') => {
                k.bool_ops += 1;
                i += 2;
            }
            '(' => {
                let mut j = i + 1;
                loop {
                    if let Some(n) = escape_at(&b, j) {
                        j = n;
                    } else if j < b.len() && is_attr_char(b[j]) {
                        j += 1;
                    } else {
                        break;
                    }
                }
                if j < b.len() && matches!(b[j], '~' | '>' | '<') {
                    j += 1;
                }
                if j < b.len() && b[j] == '=' {
                    j += 1;
                    let vstart = j;
                    while j < b.len() && b[j] != ')' && b[j] != '(' {
                        j += 1;
                    }
                    let val: String = b[vstart..j].iter().collect();
                    if val == "*" {
                        k.match_all = true;
                    }
                    k.leaves += 1;
                    i = j;
                    continue;
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    k
}

/// Did `fragment`, spliced into `(prefix,suffix)`, structurally inject
/// (vs. the benign baseline for that exact context)? Soundness: the
/// only accepted signals are ones the *fragment* is responsible for —
/// a boolean connective the baseline did not have, or a match-all `*`
/// where the baseline had a literal. Extra leaves alone never qualify
/// (a host's own `&` would otherwise launder a duplicate-literal).
fn structural_in_context(prefix: &str, suffix: &str, benign: &str, fragment: &str) -> bool {
    let spliced_raw = format!("{prefix}{fragment}{suffix}");
    let spliced = effective_filter(&spliced_raw);
    if !balanced(spliced) || !parses_as_filterlist(spliced) {
        return false;
    }
    let base_raw = format!("{prefix}{benign}{suffix}");
    let base = effective_filter(&base_raw);
    let (sk, bk) = (skeleton(spliced), skeleton(base));
    sk.bool_ops > bk.bool_ops || (sk.match_all && !bk.match_all)
}

/// Realistic host filter contexts. The injectable value sits inside
/// `(attr=…)`, itself nested under `opens` `(&` wrappers; the host
/// emits `k` closing parens to the value's right. `opens` and `k` are
/// **independent** (the host's closers may be lexically far from the
/// injection — that is precisely what lets an open-ended break such as
/// `*)(|(uid=*` resolve against a real query). Bounded small.
fn for_each_context(mut f: impl FnMut(&str, &str, &str) -> bool) -> bool {
    for &(attr, benign) in ATTRS {
        for opens in 0..=2usize {
            let pre = format!("{}({attr}=", "(&".repeat(opens));
            for k in 0..=4usize {
                let suf = ")".repeat(k);
                if f(&pre, &suf, benign) {
                    return true;
                }
                // AND/OR host with a benign neighbour clause before the
                // outer closers (very common: `(&(attr=…)(objectClass=…))`).
                if k >= 1 {
                    let suf2 = format!("){}{}", "(objectClass=person)", ")".repeat(k - 1));
                    if f(&pre, &suf2, benign) {
                        return true;
                    }
                }
            }
        }
        // substring search base: (attr=*<value>*)
        let subpre = format!("({attr}=*");
        for k in 1..=3usize {
            if f(&subpre, &format!("*{}", ")".repeat(k)), "smith") {
                return true;
            }
        }
    }
    false
}

/// A fragment is a working LDAP injection iff some realistic host
/// context turns its server-effective filter into a balanced,
/// parseable filter that the fragment made bypass-relevantly richer
/// (filter-break / added boolean clause / match-all wildcard).
#[must_use]
pub fn is_valid_ldap_injection(fragment: &str) -> bool {
    let f = fragment.trim();
    if f.is_empty() {
        return false;
    }
    for_each_context(|p, s, b| structural_in_context(p, s, b, f))
}

impl PayloadOracle for LdapOracle {
    fn is_semantically_valid(&self, _original: &str, transformed: &str) -> bool {
        is_valid_ldap_injection(transformed)
    }

    fn name(&self) -> &'static str {
        "LDAP"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(frag: &str) {
        assert!(
            is_valid_ldap_injection(frag),
            "MUST be a valid LDAP injection: {frag:?}"
        );
    }
    fn no(frag: &str) {
        assert!(
            !is_valid_ldap_injection(frag),
            "MUST NOT be accepted as an LDAP injection: {frag:?}"
        );
    }

    // ───────── MUST-ACCEPT: real injections ─────────

    #[test]
    fn filter_break_injections_are_accepted() {
        ok("*)(|(uid=*"); // classic open-ended OR break
        ok("*)(|(uid=*))(|(uid=*");
        ok("*))%00"); // wildcard match-all + NUL truncation
        ok("*)(uid=*"); // close app group, add a match-all clause
        ok("admin)(|(uid=*"); // value + break
        ok("*)(&(objectClass=*)"); // break into an AND
        ok("x)(!(uid=z)"); // injected NOT clause
    }

    #[test]
    fn wildcard_auth_bypass_is_accepted() {
        ok("*"); // (uid=*) matches every entry
    }

    #[test]
    fn rfc4515_hex_escaped_break_is_accepted() {
        ok("\\2a)(|(uid=\\2a");
        // fully hex-escaped attribute descriptor + value still injects
        // via the literal `)(|(` break.
        ok("admin)(|(\\75\\69\\64=\\2a");
    }

    #[test]
    fn oid_aliased_break_is_accepted() {
        ok("*)(|(0.9.2342.19200300.100.1.1=*");
    }

    // ───────── MUST-REJECT: anti-rig battery ─────────

    #[test]
    fn benign_values_are_rejected() {
        no("alice");
        no("alice123");
        no("a@b.example");
        no("");
        no("   ");
    }

    #[test]
    fn normal_substring_search_is_not_an_injection() {
        no("al");
        no("sm");
        no("al*"); // trailing-wildcard substring, no structural change
        no("*ith"); // leading-wildcard substring
    }

    #[test]
    fn non_ldap_garbage_is_rejected() {
        no("hello world");
        no("' OR 1=1 -- ");
        no("<script>alert(1)</script>");
        no("../../etc/passwd");
        no("just=a=value");
        no("(uid=admin"); // unbalanced in every context
    }

    #[test]
    fn structure_preserving_but_non_injecting_is_rejected() {
        // Adds a duplicate literal leaf but introduces NO boolean
        // connective and NO match-all wildcard — not a bypass. (A
        // leaf-count check would wrongly accept this through an
        // AND-wrapped host whose `&` is the host's, not the fragment's.)
        no("bob)(uid=bob");
    }

    // ───────── differential sanity ─────────

    #[test]
    fn the_oracle_gate_is_not_a_no_op() {
        assert!(is_valid_ldap_injection("*)(|(uid=*"));
        assert!(!is_valid_ldap_injection("alice"));
    }

    #[test]
    fn trait_impl_matches_free_function_and_names_ldap() {
        let o = LdapOracle;
        assert!(o.is_semantically_valid("(uid=x)", "*)(|(uid=*"));
        assert!(!o.is_semantically_valid("(uid=x)", "alice"));
        assert_eq!(o.name(), "LDAP");
    }
}
