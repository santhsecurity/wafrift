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
    l_star,
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
    let mut eq = BoundedExhaustiveEq { max_len: 7 };
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
    let mut eqa = BoundedExhaustiveEq { max_len: 7 };
    let la = l_star(&mut wa, &json_body, &alpha, &mut eqa).unwrap();

    let mut wb = waf_with_pattern(pat);
    let mut eqb = BoundedExhaustiveEq { max_len: 7 };
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
    let mut eq = BoundedExhaustiveEq { max_len: 7 };
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
