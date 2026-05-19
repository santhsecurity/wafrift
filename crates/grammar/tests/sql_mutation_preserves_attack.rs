//! The core engine contract: a "mutation" of a SQL payload must still
//! BE that attack, not a canned fragment swapped in for it.
//!
//! The bug this pins: `keywordless`/`quote_free` substituted a fixed
//! library of `'+0+'` / `1 OR 1=1` fragments for the *whole* payload,
//! for EVERY sql input — so `1 AND extractvalue(1,concat(0x7e,(SELECT
//! version())))` (error-based data exfil) "mutated" into `'+0+'`,
//! which is a different, useless attack. The bench then scored the
//! non-attack as a bypass (the rig) or the operator shipped a dud.
//!
//! Proving side: non-tautology attacks keep their class-defining
//! construct in every variant. Adversarial twin: a genuine boolean
//! tautology IS still allowed keyword-free rewrites (the fix must not
//! lobotomise the legitimate equivalence).

use wafrift_grammar::grammar::sql;

/// The canned fragments the engine used to substitute wholesale.
const CANNED_NON_ATTACKS: &[&str] = &[
    "'+0+'",
    "'-0-'",
    "'*1*'",
    "'/1/'",
    "'%2b0%2b'",
    "1-0",
    "1*1",
    "0+1",
    "1/1",
    "1%1",
    "1-false",
    "1-true",
    "1%2b0",
];

#[test]
fn error_based_payload_is_never_replaced_by_a_canned_fragment() {
    let attack = "1 AND extractvalue(1,concat(0x7e,(SELECT version())))";
    let variants = sql::mutate(attack, 64);
    assert!(
        !variants.is_empty(),
        "engine produced zero variants for a real error-based SQLi"
    );
    for v in &variants {
        let p = &v.payload;
        assert!(
            !CANNED_NON_ATTACKS.contains(&p.as_str()),
            "error-based attack was REPLACED by canned non-attack {p:?} (technique {:?})",
            v.rules_applied
        );
        // Every variant must still carry the exfil construct (case/
        // comment/encoding transforms keep `extractvalue`; AST
        // metamorphism keeps a subquery/concat). A variant that has
        // none of these is not this attack any more.
        let lc = p.to_ascii_lowercase();
        let still_the_attack = lc.contains("extractvalue")
            || lc.contains("version")
            || lc.contains("concat")
            || lc.contains("select")
            || lc.contains("0x7e")
            || lc.contains("char(126")
            || lc.contains("chr(126");
        assert!(
            still_the_attack,
            "variant {p:?} (rules {:?}) no longer carries the error-based exfil",
            v.rules_applied
        );
    }
}

#[test]
fn union_and_stacked_and_blind_keep_their_construct() {
    let cases: &[(&str, &[&str])] = &[
        (
            "1 UNION SELECT username,password FROM users",
            &["union", "select"],
        ),
        ("1; DROP TABLE users; --", &["drop", ";"]),
        (
            "1 AND (SELECT 1 FROM (SELECT SLEEP(5))x)",
            &["sleep", "select"],
        ),
        ("1 AND IF(1=1,SLEEP(5),0)", &["sleep", "if("]),
    ];
    for (attack, must_have_any) in cases {
        let variants = sql::mutate(attack, 48);
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
fn adversarial_twin_genuine_tautology_still_gets_keyword_free_rewrites() {
    // The fix must NOT kill the legitimate case: a boolean auth-bypass
    // tautology IS semantically equivalent to a quote-free tautology,
    // so keyword-free / arithmetic rewrites SHOULD still be offered.
    for taut in ["1' OR '1'='1", "1' OR 1=1-- ", "admin' OR '1'='1'#"] {
        let variants = sql::mutate(taut, 64);
        assert!(!variants.is_empty(), "no variants for tautology {taut:?}");
        let has_keyword_free = variants.iter().any(|v| {
            v.rules_applied.iter().any(|r| {
                r.contains("keywordless") || r.contains("quote_free") || r.contains("arithmetic")
            })
        });
        assert!(
            has_keyword_free,
            "tautology {taut:?} lost its legitimate keyword-free rewrites — \
             the gate is too aggressive"
        );
    }
}

#[test]
fn evade_level_heavy_path_preserves_error_based_attack() {
    // Drive the same public path `wafrift evade` uses
    // (grammar::mutate_as on the classified type) and assert the
    // engine no longer emits the `'+0+'` family for an exfil payload.
    use wafrift_grammar::grammar::{PayloadType, mutate_as};
    let attack = "1 AND updatexml(1,concat(0x7e,(SELECT database())),1)";
    let out = mutate_as(attack, PayloadType::Sql, 80);
    assert!(!out.is_empty());
    for m in &out {
        assert!(
            !CANNED_NON_ATTACKS.contains(&m.payload.as_str()),
            "evade-path replaced updatexml exfil with canned {:?}",
            m.payload
        );
    }
}
