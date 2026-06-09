//! Exact-correctness + differential truth contract for the learners.
//!
//! The learner's correctness is asserted against a ground-truth WAF
//! whose language we control — *exactly*, not by `!is_empty()` and not
//! against itself:
//!
//! 1. **Exact recovery**: every abstract word up to a length well past
//!    the Myhill–Nerode bound is classified by the learned automaton
//!    identically to the real WAF.
//! 2. **Differential**: L\* and the KV discrimination-tree learner
//!    recover the *same language* (a bug in either splits them).
//! 3. **Negative twin**: the model learned for WAF-A is provably *not*
//!    equivalent to a different WAF-B (a real distinguishing input is
//!    exhibited and checked against both).
//! 4. **Query economy**: the tree learner spends no more membership
//!    queries than L\* (the property that matters against a live WAF).

use wafrift_types::Request;
use wafrift_wafmodel::canon::Channel;
use wafrift_wafmodel::{
    Alphabet, BoundedExhaustiveEq, ChannelSet, Outcome, Rule, SimRegexWaf, WafOracle, kv_learn,
    l_star, passive_learn,
};

/// Body-channel JSON skeleton ⇒ canonicalization yields exactly one
/// opaque `Body` segment equal to the learner's bytes (every byte is
/// expressible; nothing is split).
fn json_body(bytes: &[u8]) -> Request {
    Request::post("https://h/p", bytes.to_vec()).header("Content-Type", "application/json")
}

fn waf_with_pattern(pat: &str) -> SimRegexWaf {
    SimRegexWaf::new(
        vec![Rule {
            id: "gt".into(),
            channels: ChannelSet::none().with(Channel::Body),
            transforms: vec![],
            pattern: regex::bytes::Regex::new(pat).unwrap(),
            score: 5,
        }],
        5,
    )
}

/// Ground-truth language over the abstract alphabet, computed by the
/// real WAF (independent of the learner).
fn waf_passes(pat: &str, alpha: &Alphabet, word: &[usize]) -> bool {
    let mut w = waf_with_pattern(pat);
    matches!(
        w.classify(&json_body(&alpha.concretize(word))).unwrap(),
        Outcome::Pass
    )
}

fn all_words(k: usize, max_len: usize) -> Vec<Vec<usize>> {
    let mut out = vec![vec![]];
    let mut frontier = vec![vec![]];
    for _ in 0..max_len {
        let mut next = Vec::new();
        for w in &frontier {
            for s in 0..k {
                let mut e = w.clone();
                e.push(s);
                next.push(e.clone());
                out.push(e);
            }
        }
        frontier = next;
    }
    out
}

#[test]
fn lstar_recovers_the_exact_language() {
    // WAF blocks any body containing the substring `<s`; it PASSES
    // everything else. Learned language (accept ⇔ pass) is therefore
    // the exact complement of "contains <s".
    let alpha = Alphabet::new(vec![b'<', b's'], b'A');
    let mut waf = waf_with_pattern("<s");
    let mut eq = BoundedExhaustiveEq {
        max_len: 7,
        max_queries: None,
    };
    let rep = l_star(&mut waf, &json_body, &alpha, &mut eq).unwrap();

    // Exact recovery over a corpus far past the 3-state MN bound.
    for w in all_words(alpha.len(), 9) {
        assert_eq!(
            rep.sfa.accepts(&alpha.concretize(&w)),
            waf_passes("<s", &alpha, &w),
            "mismatch on abstract word {w:?}"
        );
    }
    // It is a non-trivial language: the empty body passes, `<s` blocks.
    assert!(rep.sfa.accepts(b""));
    assert!(!rep.sfa.accepts(b"<s"));
    assert!(rep.sfa.accepts(b"<A")); // `<` then catch-all ≠ `<s`
}

#[test]
fn kv_and_lstar_agree_exactly_and_kv_is_no_costlier() {
    let alpha = Alphabet::new(vec![b'<', b's', b'/'], b'A');
    let pat = "<s[^>]*/"; // a slightly richer regular language

    let mut wa = waf_with_pattern(pat);
    let mut eqa = BoundedExhaustiveEq {
        max_len: 7,
        max_queries: None,
    };
    let la = l_star(&mut wa, &json_body, &alpha, &mut eqa).unwrap();

    let mut wb = waf_with_pattern(pat);
    let mut eqb = BoundedExhaustiveEq {
        max_len: 7,
        max_queries: None,
    };
    let kv = kv_learn(&mut wb, &json_body, &alpha, &mut eqb).unwrap();

    // Differential: identical recognised language (exact automaton
    // equivalence — a distinguishing word would be returned if not).
    assert!(
        la.sfa.equivalent(&kv.sfa),
        "L* and KV learned different languages: {:?}",
        la.sfa.distinguishing_word(&kv.sfa)
    );
    // Both match the real WAF exactly.
    for w in all_words(alpha.len(), 8) {
        let truth = waf_passes(pat, &alpha, &w);
        assert_eq!(la.sfa.accepts(&alpha.concretize(&w)), truth);
        assert_eq!(kv.sfa.accepts(&alpha.concretize(&w)), truth);
    }
    // Query economy: the tree learner is never more expensive.
    assert!(
        kv.membership_queries <= la.membership_queries,
        "KV used {} MQs vs L* {}",
        kv.membership_queries,
        la.membership_queries
    );
}

#[test]
fn learned_model_is_not_equivalent_to_a_different_waf() {
    let alpha = Alphabet::new(vec![b'<', b's', b't'], b'A');
    let mut wa = waf_with_pattern("<s");
    let mut eq = BoundedExhaustiveEq {
        max_len: 7,
        max_queries: None,
    };
    let learned = l_star(&mut wa, &json_body, &alpha, &mut eq).unwrap().sfa;

    // WAF-B blocks `<t` instead of `<s`. There must exist an input the
    // learned model and WAF-B classify differently, and we exhibit it.
    let mut found_split = false;
    for w in all_words(alpha.len(), 6) {
        let model = learned.accepts(&alpha.concretize(&w));
        let other = waf_passes("<t", &alpha, &w);
        if model != other {
            found_split = true;
            // Sanity: the split is real — `<s` is one such witness
            // (blocked by A, passed by B).
            break;
        }
    }
    assert!(
        found_split,
        "model trained on WAF-A must NOT be equivalent to WAF-B"
    );
    // Concretely: body `<s` — WAF-A blocks (model rejects), WAF-B passes.
    let ws = vec![0usize, 1usize]; // `<`, `s`
    assert!(!learned.accepts(&alpha.concretize(&ws)));
    assert!(waf_passes("<t", &alpha, &ws));
}

/// E1/5 — triple-learner differential. Three independent inference
/// strategies (L* incremental table, KV discrimination tree, passive
/// fixed-suite) must recover the EXACT same language as the WAF, for a
/// battery of ground-truth rulesets. A bug in any one strategy is
/// caught by disagreement with the other two.
#[test]
fn lstar_kv_and_passive_learners_all_agree_with_the_waf() {
    let alpha = Alphabet::new(vec![b'<', b's', b'/'], b'A');
    for pat in ["<s", "<s[^>]*/", "s/<", "<s/s"] {
        let mut w1 = waf_with_pattern(pat);
        let mut w2 = waf_with_pattern(pat);
        let mut w3 = waf_with_pattern(pat);
        // A *sound* equivalence oracle is mandatory for an EXACTNESS
        // claim. `WMethodEq{extra_states:k}` only guarantees fault
        // discovery when (true_states − hyp_states) ≤ k; for `<s/s`
        // the very first hypothesis has 1 state, the target has 5, and
        // the shortest counterexample is `<s/s` itself (length 4) —
        // outside W-method{2}'s ≤3 horizon, so it silently certifies
        // the trivial 1-state "accept-all" automaton. That is not a
        // passive_learn bug (passive recovers the exact 5-state DFA);
        // it is the differential feeding L*/KV an oracle too weak to
        // prove the property it asserts. `BoundedExhaustiveEq` is
        // complete for every fault whose shortest witness ≤ max_len,
        // and max_len here covers the length-8 verification corpus
        // below — so all three learners are now genuinely exact.
        let mut eq1 = BoundedExhaustiveEq {
            max_len: 8,
            max_queries: None,
        };
        let mut eq2 = BoundedExhaustiveEq {
            max_len: 8,
            max_queries: None,
        };
        let a = l_star(&mut w1, &json_body, &alpha, &mut eq1).unwrap().sfa;
        let b = kv_learn(&mut w2, &json_body, &alpha, &mut eq2).unwrap().sfa;
        let c = passive_learn(&mut w3, &json_body, &alpha, 7).unwrap().sfa;

        assert!(
            a.equivalent(&b),
            "L*≠KV on {pat:?}: {:?}",
            a.distinguishing_word(&b)
        );
        assert!(
            a.equivalent(&c),
            "L*≠passive on {pat:?}: {:?}",
            a.distinguishing_word(&c)
        );
        // …and all three match the real WAF exactly on a corpus far
        // past the Myhill–Nerode bound.
        for word in all_words(alpha.len(), 8) {
            let truth = waf_passes(pat, &alpha, &word);
            let conc = alpha.concretize(&word);
            assert_eq!(a.accepts(&conc), truth, "L* {pat:?} {word:?}");
            assert_eq!(b.accepts(&conc), truth, "KV {pat:?} {word:?}");
            assert_eq!(c.accepts(&conc), truth, "passive {pat:?} {word:?}");
        }
        // The passive learner returns the *minimal* DFA; minimizing
        // the active hypotheses must agree with it state-for-state in
        // language (sanity that minimize ∘ L* ≡ passive).
        assert!(a.minimize().equivalent(&c));
    }
}

// ── E5 ratchet (learn.rs): the Alphabet accessors had NO behavioural
// test — `cargo-mutants` proved `is_empty -> true` and
// `raw_symbols -> Vec::leak(...)` survived. They are the abstraction
// every learner reasons over, so pin them exactly. (`is_empty ->
// false` is a documented provably-equivalent mutant: `Alphabet::new`
// always pushes the catch-all, so no constructible alphabet is empty.)
#[test]
fn alphabet_accessors_are_exact() {
    // `new` sorts+dedups the distinguished bytes then appends the
    // catch-all, so the table is deterministic and inspectable.
    let a = Alphabet::new(vec![b'b', b'a', b'b'], b'Z');
    assert_eq!(
        a.raw_symbols(),
        *b"abZ",
        "raw_symbols must be the exact sorted+dedup table then catch-all"
    );
    assert!(!a.is_empty(), "a constructed alphabet is never empty");
    assert_eq!(a.len(), 3, "2 distinguished + 1 catch-all");
    assert_eq!(a.catch_all(), 2, "catch-all is the last class");
    assert_eq!(a.byte_of(0), b'a');
    assert_eq!(a.byte_of(2), b'Z', "class 2 is the catch-all byte");
    // concretize maps indices through exactly that table.
    assert_eq!(a.concretize(&[1, 0, 2]), vec![b'b', b'a', b'Z']);
    // Round-trips through from_raw_symbols byte-identically.
    let b = Alphabet::from_raw_symbols(a.raw_symbols().to_vec());
    assert_eq!(b.raw_symbols(), a.raw_symbols());
    assert_eq!(b.concretize(&[0, 1, 2]), vec![b'a', b'b', b'Z']);
}

// ── E5 ratchet (learn.rs): `LearnReport.equivalence_rounds` is a
// PROVENANCE claim (the artifact records how many counterexample
// rounds the decompilation cost). It had no truthfulness test, so
// `rounds += 1 → *= 1` (stuck at 0) survived in BOTH l_star and
// kv_learn. Pin it: a target that needs refinement reports ≥1 round;
// a trivially-learnable target reports exactly 0 (non-vacuous — proves
// the counter both increments and can legitimately be 0).
#[test]
fn equivalence_rounds_is_truthful_provenance() {
    let alpha = Alphabet::new(vec![b'<', b's', b'/'], b'A');

    // `<s/s`: the first L*/KV hypothesis (1 state) is wrong; reaching
    // the exact 5-state DFA needs ≥1 equivalence/counterexample round.
    let mut w1 = waf_with_pattern("<s/s");
    let mut e1 = BoundedExhaustiveEq {
        max_len: 8,
        max_queries: None,
    };
    let la = l_star(&mut w1, &json_body, &alpha, &mut e1).unwrap();
    assert!(
        la.equivalence_rounds >= 1,
        "L* needed refinement for `<s/s` but reported {} rounds \
         (provenance is lying — rounds counter not incrementing)",
        la.equivalence_rounds
    );
    let mut w2 = waf_with_pattern("<s/s");
    let mut e2 = BoundedExhaustiveEq {
        max_len: 8,
        max_queries: None,
    };
    let kv = kv_learn(&mut w2, &json_body, &alpha, &mut e2).unwrap();
    assert!(
        kv.equivalence_rounds >= 1,
        "KV needed refinement for `<s/s` but reported {} rounds",
        kv.equivalence_rounds
    );

    // A pattern the small alphabet can NEVER spell (`xyz` over
    // {<,s,/,A}) ⇒ the WAF passes everything ⇒ the very first
    // 1-state accept-all hypothesis is already exact ⇒ the equivalence
    // oracle finds no counterexample ⇒ exactly 0 rounds. This proves
    // the assertions above are non-vacuous (0 is a legitimate value;
    // the counter is not merely "always ≥1").
    let mut w3 = waf_with_pattern("xyz");
    let mut e3 = BoundedExhaustiveEq {
        max_len: 6,
        max_queries: None,
    };
    let triv = l_star(&mut w3, &json_body, &alpha, &mut e3).unwrap();
    assert_eq!(
        triv.equivalence_rounds, 0,
        "an already-exact first hypothesis must report 0 rounds, got {}",
        triv.equivalence_rounds
    );
    // …and it genuinely is the accept-all language (anti-vacuous).
    assert!(triv.sfa.accepts(b"<s/s"));
    assert!(triv.sfa.accepts(b""));
}
