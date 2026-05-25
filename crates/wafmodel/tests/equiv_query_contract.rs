//! Truth contract for the query-economical equivalence strategies.
//!
//! These prove the *guarantee* (W-method recovers the exact language
//! within its state bound) and the *economy* (the bandit costs no more
//! than random sampling) and the *honesty* (the PAC bound is a real,
//! monotone, sub-1 number that empirically holds) — never `!is_empty()`.

use wafrift_types::Request;
use wafrift_wafmodel::canon::Channel;
use wafrift_wafmodel::{
    Alphabet, BoundedExhaustiveEq, ChannelSet, EquivalenceOracle, Outcome, PacBound, Rule,
    SampledEq, SimRegexWaf, UcbBanditEq, WMethodEq, WafOracle, kv_learn, l_star,
};

fn json_body(b: &[u8]) -> Request {
    Request::post("https://h/p", b.to_vec()).header("Content-Type", "application/json")
}

fn waf(pat: &str) -> SimRegexWaf {
    SimRegexWaf::new(
        vec![Rule {
            id: "r".into(),
            channels: ChannelSet::none().with(Channel::Body),
            transforms: vec![],
            pattern: regex::bytes::Regex::new(pat).unwrap(),
            score: 5,
        }],
        5,
    )
}

fn passes(pat: &str, a: &Alphabet, w: &[usize]) -> bool {
    matches!(
        waf(pat).classify(&json_body(&a.concretize(w))).unwrap(),
        Outcome::Pass
    )
}

fn corpus(k: usize, max: usize) -> Vec<Vec<usize>> {
    let mut out = vec![vec![]];
    let mut fr = vec![vec![]];
    for _ in 0..max {
        let mut nx = Vec::new();
        for w in &fr {
            for s in 0..k {
                let mut e = w.clone();
                e.push(s);
                nx.push(e.clone());
                out.push(e);
            }
        }
        fr = nx;
    }
    out
}

#[test]
fn wmethod_recovers_exact_language_far_cheaper_than_exhaustive() {
    let alpha = Alphabet::new(vec![b'<', b's', b'/'], b'A');
    let pat = "<s[^>]*/";

    let mut w1 = waf(pat);
    let mut wm = WMethodEq { extra_states: 2 };
    let viaw = l_star(&mut w1, &json_body, &alpha, &mut wm).unwrap();

    let mut w2 = waf(pat);
    let mut ex = BoundedExhaustiveEq { max_len: 7, max_queries: None };
    let viax = l_star(&mut w2, &json_body, &alpha, &mut ex).unwrap();

    // Same exact language as the exhaustive baseline AND the WAF.
    assert!(viaw.sfa.equivalent(&viax.sfa));
    for c in corpus(alpha.len(), 8) {
        assert_eq!(
            viaw.sfa.accepts(&alpha.concretize(&c)),
            passes(pat, &alpha, &c)
        );
    }
    // The guarantee is *cheap*: W-method spends far fewer membership
    // queries than the exponential exhaustive certificate.
    assert!(
        viaw.membership_queries * 4 < viax.membership_queries,
        "W-method {} MQ vs exhaustive {} — expected ≥4× cheaper",
        viaw.membership_queries,
        viax.membership_queries
    );
}

#[test]
fn ucb_chain_recovers_exact_far_cheaper_than_exhaustive() {
    // A pure bandit/sampling EQ is provably *incomplete* — it cannot
    // certify equivalence. Completeness comes from the W-method tail;
    // the bandit front-loads informative queries. Honest claims:
    //   (1) UCB→W-method recovers the EXACT language (tail guarantees),
    //   (2) it costs ≪ the exponential exhaustive certificate (the
    //       real "decompiling a live WAF is affordable" claim — a
    //       cross-toy MQ micro-comparison vs random is noise, not a
    //       theorem, so it is deliberately NOT asserted).
    use wafrift_wafmodel::{BoundedExhaustiveEq, ChainedEq};
    let alpha = Alphabet::new(vec![b'<', b's', b'/'], b'A');
    let pat = "<s[^>]*/";

    let mut wu = waf(pat);
    let mut ucb_chain = ChainedEq::new(vec![
        Box::new(UcbBanditEq::new(48, 6, 0xC0FFEE)),
        Box::new(WMethodEq { extra_states: 2 }),
    ]);
    let viu = kv_learn(&mut wu, &json_body, &alpha, &mut ucb_chain).unwrap();

    let mut wm = waf(pat);
    let mut wmonly = WMethodEq { extra_states: 2 };
    let vim = kv_learn(&mut wm, &json_body, &alpha, &mut wmonly).unwrap();

    let mut wx = waf(pat);
    let mut ex = BoundedExhaustiveEq { max_len: 7, max_queries: None };
    let vix = kv_learn(&mut wx, &json_body, &alpha, &mut ex).unwrap();

    // (1) Exact recovery, and identical to the W-method-only result.
    for c in corpus(alpha.len(), 8) {
        let truth = passes(pat, &alpha, &c);
        assert_eq!(viu.sfa.accepts(&alpha.concretize(&c)), truth, "ucb {c:?}");
    }
    assert!(viu.sfa.equivalent(&vim.sfa));
    assert!(viu.sfa.equivalent(&vix.sfa));
    // (2) Affordable: ≥4× cheaper than the exponential certificate.
    assert!(
        viu.membership_queries * 4 < vix.membership_queries,
        "UCB-chain {} MQ vs exhaustive {} MQ — expected ≥4× cheaper",
        viu.membership_queries,
        vix.membership_queries
    );
}

#[test]
fn ucb_is_information_directed_covers_every_transition_before_repeating() {
    // The literal "ask the most informative query" guarantee: UCB1
    // gives an unvisited arm infinite priority, so within
    // states×symbols probes every transition has been exercised at
    // least once — deterministic, not statistical.
    let alpha = Alphabet::new(vec![b'<', b's'], b'A'); // 3 symbols
    // A concrete 2-state hypothesis: accept iff seen `<` (sym 0).
    let g0 = wafrift_wafmodel::BytePred::byte(b'<');
    let hyp = wafrift_wafmodel::Sfa::new(
        0,
        vec![false, true],
        vec![
            vec![(g0, 1), (!g0, 0)],
            vec![(wafrift_wafmodel::BytePred::any(), 1)],
        ],
    );
    let arms = 2 * alpha.len(); // 2 states × 3 symbols
    let mut ucb = UcbBanditEq::new(arms, 0, 99);
    // Oracle that always agrees with the hypothesis ⇒ no early CE
    // return ⇒ the full exploration budget is spent.
    let mut mq = |w: &[usize]| {
        Ok(hyp.is_accepting(
            // re-run hyp over the abstract word
            {
                let mut s = hyp.start_state();
                for &x in w {
                    s = hyp.step_byte(s, alpha.byte_of(x));
                }
                s
            },
        ))
    };
    let ce = ucb.find_counterexample(&hyp, &alpha, &mut mq).unwrap();
    assert!(ce.is_none(), "agreeing oracle yields no counterexample");
    assert_eq!(
        ucb.arms_explored(),
        arms,
        "UCB must cover every (state,symbol) transition before repeating any"
    );
}

#[test]
fn pac_bound_is_monotone_sub_one_and_empirically_holds() {
    // Monotonicity / soundness of the bound formula itself.
    let few = PacBound::compute(100, 0.05, 0);
    let many = PacBound::compute(10_000, 0.05, 0);
    assert!(few.epsilon > many.epsilon, "ε must shrink with samples");
    assert!(many.epsilon > 0.0 && many.epsilon < 1.0, "ε ∈ (0,1)");
    // More equivalence rounds ⇒ looser ε at equal samples (Angluin).
    assert!(PacBound::compute(1000, 0.05, 5).epsilon > PacBound::compute(1000, 0.05, 0).epsilon);

    // End-to-end: a clean SampledEq run ships a real bound and the
    // model's *measured* disagreement with the WAF is within it.
    let alpha = Alphabet::new(vec![b'<', b's', b'x'], b'A');
    let pat = "<sx*s";
    let mut wv = waf(pat);
    let mut smp = SampledEq::new(3000, 8, 0.02, 7);
    let rep = l_star(&mut wv, &json_body, &alpha, &mut smp).unwrap();
    let bound = smp
        .last_bound()
        .expect("a clean equivalence round must publish a PAC bound");
    assert!(bound.samples >= 3000, "anti-rig: samples actually drawn");
    assert!(bound.epsilon > 0.0 && bound.epsilon < 1.0);

    let test = corpus(alpha.len(), 7);
    let mut wrong = 0usize;
    for c in &test {
        if rep.sfa.accepts(&alpha.concretize(c)) != passes(pat, &alpha, c) {
            wrong += 1;
        }
    }
    let measured = wrong as f64 / test.len() as f64;
    assert!(
        measured <= bound.epsilon,
        "measured error {measured} exceeds PAC ε {}",
        bound.epsilon
    );
}

#[test]
fn chained_eq_finds_ce_when_any_member_does() {
    use wafrift_wafmodel::ChainedEq;
    let alpha = Alphabet::new(vec![b'<', b's'], b'A');
    let pat = "<s";

    // W-method (guaranteed) → bandit → sampling. End-to-end exact.
    let mut wv = waf(pat);
    let mut chain = ChainedEq::new(vec![
        Box::new(WMethodEq { extra_states: 2 }),
        Box::new(UcbBanditEq::new(32, 5, 1)),
        Box::new(SampledEq::new(500, 6, 0.05, 2)),
    ]);
    let rep = l_star(&mut wv, &json_body, &alpha, &mut chain).unwrap();
    for c in corpus(alpha.len(), 8) {
        assert_eq!(
            rep.sfa.accepts(&alpha.concretize(&c)),
            passes(pat, &alpha, &c)
        );
    }

    // A chained oracle over a deliberately-wrong constant hypothesis
    // must surface a counterexample (it cannot return None).
    let truth_waf = waf(pat);
    let reject_all = wafrift_wafmodel::Sfa::new(
        0,
        vec![false],
        vec![vec![(wafrift_wafmodel::BytePred::any(), 0)]],
    );
    let mut chain2 = ChainedEq::new(vec![Box::new(WMethodEq { extra_states: 1 })]);
    let mut tw = truth_waf;
    let mut mq = |w: &[usize]| {
        Ok(matches!(
            tw.classify(&json_body(&alpha.concretize(w))).unwrap(),
            Outcome::Pass
        ))
    };
    let ce = chain2
        .find_counterexample(&reject_all, &alpha, &mut mq)
        .unwrap();
    assert!(
        ce.is_some(),
        "reject-all vs a WAF that passes the empty body must yield a CE"
    );
}
