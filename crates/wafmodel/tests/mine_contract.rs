//! Truth contract for offline bypass mining.
//!
//! Anti-rig is the whole point: every mined "bypass" is **replayed
//! against the same real oracle** and must *actually* pass while
//! *actually* being an attack — exact strings and counts, with a
//! precision twin (no mined word is the blocked form) and a true
//! negative (a WAF that fully covers the class yields ZERO bypasses,
//! never a fabricated one).

use wafrift_types::Request;
use wafrift_wafmodel::canon::Channel;
use wafrift_wafmodel::{
    Alphabet, ChannelSet, Outcome, Rule, SimRegexWaf, WMethodEq, WafOracle, attack_grammar, l_star,
    mine_bypasses, minimal_bypass, waf_diff,
};

fn json_body(b: &[u8]) -> Request {
    Request::post("https://h/p", b.to_vec()).header("Content-Type", "application/json")
}
fn waf(pat: &str) -> SimRegexWaf {
    SimRegexWaf::new(
        vec![Rule {
            id: "r".into(),
            channels: ChannelSet::none().with(Channel::Body),
            transforms: vec![], // case-sensitive, no decoding
            pattern: regex::bytes::Regex::new(pat).unwrap(),
            score: 5,
        }],
        5,
    )
}
fn passes(w: &mut SimRegexWaf, bytes: &[u8]) -> bool {
    matches!(w.classify(&json_body(bytes)).unwrap(), Outcome::Pass)
}

#[test]
fn mining_issues_zero_live_queries() {
    // README/lib claim: "Mine bypasses offline … no further live
    // traffic." `mine_bypasses` takes no oracle by type, but assert the
    // behavioural contract end-to-end: after learning, the live-query
    // counter must NOT advance by a single query across mining — and
    // the step is non-vacuous (learning really queried; a real hole was
    // really mined).
    let alpha = Alphabet::new(vec![b'a', b'b', b'A'], b'Z');
    let mut w = waf("ab");
    let mut eq = WMethodEq { extra_states: 3 };
    let learned = l_star(&mut w, &json_body, &alpha, &mut eq).unwrap().sfa;

    let after_learn = w.queries();
    assert!(after_learn > 0, "learning must have issued live queries");

    let attack = attack_grammar(&alpha, &[b"ab".as_ref(), b"Ab".as_ref()]);
    let mined = mine_bypasses(&learned, &attack, 12, 8);
    assert!(
        !mined.is_empty(),
        "a real hole exists ⇒ mining is non-vacuous"
    );

    assert_eq!(
        w.queries(),
        after_learn,
        "mining issued live queries — the 'offline / no further live \
         traffic' claim is false"
    );
}

#[test]
fn mined_bypasses_are_real_against_the_same_oracle() {
    // WAF blocks the lowercase token `ab`. The attack class also
    // includes the case-variant `Ab` (still an attack); the WAF does
    // NOT cover it ⇒ a real hole exists.
    let alpha = Alphabet::new(vec![b'a', b'b', b'A'], b'Z');
    let mut w = waf("ab");
    let mut eq = WMethodEq { extra_states: 3 };
    let learned = l_star(&mut w, &json_body, &alpha, &mut eq).unwrap().sfa;

    let needles: [&[u8]; 2] = [b"ab", b"Ab"];
    let attack = attack_grammar(&alpha, &needles);

    let mined = mine_bypasses(&learned, &attack, 12, 8);
    assert!(!mined.is_empty(), "a real hole exists ⇒ miner must find it");

    let mut oracle = waf("ab");
    for b in &mined {
        // (1) The SAME real WAF actually passes it (no model gap).
        assert!(
            passes(&mut oracle, b),
            "mined bypass {b:?} does NOT actually pass the real WAF — rigged miner"
        );
        // (2) It is genuinely an attack (contains a needle).
        let s = String::from_utf8_lossy(b);
        assert!(
            s.contains("ab") || s.contains("Ab"),
            "mined word {b:?} is not in the attack class"
        );
        // (3) Precision twin: it is NOT the blocked form.
        assert!(
            !s.contains("ab"),
            "mined word {b:?} contains the blocked token — would be caught, not a bypass"
        );
    }

    // Minimality: the single minimal bypass is the length-then-lex
    // minimum and equals the first mined word.
    let minimal = minimal_bypass(&learned, &attack).unwrap();
    assert_eq!(&minimal, &mined[0], "minimal_bypass must be the shortest");
    // Concretely, the shortest attack the WAF misses is exactly "Ab".
    assert_eq!(minimal, b"Ab".to_vec());
}

#[test]
fn a_fully_covering_waf_yields_zero_bypasses() {
    // The attack class is EXACTLY what the WAF blocks (`ab`). There is
    // no hole; the miner must return nothing — never a false positive.
    let alpha = Alphabet::new(vec![b'a', b'b'], b'Z');
    let mut w = waf("ab");
    let mut eq = WMethodEq { extra_states: 3 };
    let learned = l_star(&mut w, &json_body, &alpha, &mut eq).unwrap().sfa;

    let needles: [&[u8]; 1] = [b"ab"];
    let attack = attack_grammar(&alpha, &needles);

    assert!(
        mine_bypasses(&learned, &attack, 10, 8).is_empty(),
        "WAF fully covers the class ⇒ ZERO mined bypasses"
    );
    assert!(minimal_bypass(&learned, &attack).is_none());
}

#[test]
fn waf_diff_is_a_real_transferable_hole_map() {
    // WAF-A blocks `ab`; WAF-B blocks `Ab`. Their learned models'
    // symmetric difference must be inputs the two REAL WAFs classify
    // differently — verified against both live oracles.
    let alpha = Alphabet::new(vec![b'a', b'b', b'A'], b'Z');
    let mut wa = waf("ab");
    let mut wb = waf("Ab");
    let mut eqa = WMethodEq { extra_states: 3 };
    let mut eqb = WMethodEq { extra_states: 3 };
    let la = l_star(&mut wa, &json_body, &alpha, &mut eqa).unwrap().sfa;
    let lb = l_star(&mut wb, &json_body, &alpha, &mut eqb).unwrap().sfa;

    let diff = waf_diff(&la, &lb, 10, 8);
    assert!(
        !diff.is_empty(),
        "two differently-configured WAFs must differ"
    );

    let (mut oa, mut ob) = (waf("ab"), waf("Ab"));
    for d in &diff {
        assert_ne!(
            passes(&mut oa, d),
            passes(&mut ob, d),
            "diff word {d:?} must be classified differently by the two real WAFs"
        );
    }
    // `ab` is blocked by A, passed by B; `Ab` the reverse — both must
    // surface in a sufficiently deep diff.
    let set: std::collections::HashSet<Vec<u8>> = diff.into_iter().collect();
    assert!(set.contains(b"ab".as_slice()) || set.contains(b"Ab".as_slice()));
}
