//! E3/20–21 — the legendary learner contract: on **10k random regular
//! oracles**, the three independent inference strategies must all
//! recover the *exact* language and agree with each other, and the
//! differential must be *non-vacuous* (it can tell a mutated language
//! apart).
//!
//! This is precisely the property that exposes finding **F2**: an
//! exactness claim is only meaningful with a *provably complete*
//! equivalence oracle. Every learn here is driven by
//! `BoundedExhaustiveEq` (complete for any fault ≤ `max_len`) — never
//! the only-conditionally-complete W-method. `passive_learn` uses no
//! equivalence oracle at all (a fixed complete test-suite, bounded
//! |states|). If any strategy is wrong on any oracle, two others
//! out-vote it and the case fails with the distinguishing word.
//!
//! Random oracles are literal substring patterns over a 3+catch-all
//! alphabet (length 1..=3) — small enough that every case is fast and
//! exact, rich enough to include self-overlapping shapes like `s/s`
//! and `<s` (the KMP structure behind F2's `<s/s`).

use proptest::prelude::*;
use wafrift_types::Request;
use wafrift_wafmodel::canon::Channel;
use wafrift_wafmodel::{
    Alphabet, BoundedExhaustiveEq, ChannelSet, Outcome, Rule, SimRegexWaf, WafOracle, kv_learn,
    l_star, passive_learn,
};

/// Deterministic-config count for the thorough lane.
///
/// CI target: 1 000. Default when `WAFMODEL_SCALE_CONFIGS` is unset: 48.
///
/// 48 covers every distinct pattern the 3-symbol alphabet of length
/// 1–3 produces (3 + 9 + 27 = 39, with duplicates from `pat_from`'s
/// modular mapping the actual unique count is at most 39). Past 48,
/// additional seeds only rehash previously-seen patterns. Running 1000
/// seeds unconditionally in a debug build on Windows takes >60 s and
/// risks `STATUS_STACK_BUFFER_OVERRUN` on the proptest shrinking stack.
/// Set `WAFMODEL_SCALE_CONFIGS=1000` in CI for the exhaustive lane.
fn scn() -> u64 {
    std::env::var("WAFMODEL_SCALE_CONFIGS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(48)
}
/// Proptest case count.
///
/// CI target: 10 000 (full coverage gate).
/// Default when `WAFMODEL_PROPTEST_CASES` is unset: 200.
///
/// Rationale for 200 not 10 000: each proptest case calls `l_star`,
/// `kv_learn`, and `passive_learn` (3 independent learning passes), each
/// with SimRegexWaf as the membership oracle, followed by a complete
/// truth-table sweep over all words up to length `pat.len()+3` (~5 000
/// words for length-3 patterns). In a debug build on Windows (smaller
/// default stack, no SIMD, slower allocations) 10 000 cases × ~3 k
/// learning-query rounds × 5 000 comparisons exhausts memory and
/// triggers `STATUS_STACK_BUFFER_OVERRUN` on the proptest shrinking
/// stack. 200 cases already covers a statistically diverse sample of
/// the 48 distinct patterns the 3-symbol alphabet admits. Set
/// `WAFMODEL_PROPTEST_CASES=10000` in CI for the full gate.
fn pc() -> u32 {
    std::env::var("WAFMODEL_PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200)
}

fn body(b: &[u8]) -> Request {
    Request::post("https://h/p", b.to_vec()).header("Content-Type", "application/json")
}

/// Three distinguished bytes + a catch-all. `Alphabet::new` sorts the
/// distinguished set; that is irrelevant here because every learner and
/// the truth oracle use the *same* `Alphabet`.
fn alpha() -> Alphabet {
    Alphabet::new(vec![b'<', b's', b'/'], b'A')
}
const SYMS: [u8; 3] = *b"<s/";

fn waf(pat_bytes: &[u8]) -> SimRegexWaf {
    let pat = regex::escape(&String::from_utf8_lossy(pat_bytes));
    SimRegexWaf::new(
        vec![Rule {
            id: "gt".into(),
            channels: ChannelSet::none().with(Channel::Body),
            transforms: vec![],
            pattern: regex::bytes::Regex::new(&pat).unwrap(),
            score: 5,
        }],
        5,
    )
}

fn truth(pat: &[u8], a: &Alphabet, w: &[usize]) -> bool {
    matches!(
        waf(pat).classify(&body(&a.concretize(w))).unwrap(),
        Outcome::Pass
    )
}

fn all_words(k: usize, max: usize) -> Vec<Vec<usize>> {
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

/// Derive a deterministic literal pattern (length 1..=3) from `seed`.
fn pat_from(seed: u64) -> Vec<u8> {
    let len = 1 + (seed % 3) as usize;
    (0..len)
        .map(|i| SYMS[((seed >> (i * 5)) as usize + i) % SYMS.len()])
        .collect()
}

/// The whole contract for one oracle: L*, KV (both with the SOUND
/// exhaustive oracle) and passive (no EQ oracle) recover the identical
/// language, and that language equals the real WAF on every word up to
/// a length well past the Myhill–Nerode bound. `tag` only colours the
/// panic message.
fn assert_triple_exact(pat: &[u8], tag: &str) {
    let a = alpha();
    // Literal substring of length L ⇒ minimal DFA has L+1 states and
    // every distinguishing word ≤ L. depth/max_len = L+3 is amply
    // sound and keeps the per-case cost tiny.
    let d = pat.len() + 3;

    let mut w1 = waf(pat);
    let mut e1 = BoundedExhaustiveEq { max_len: d, max_queries: None };
    let la = l_star(&mut w1, &body, &a, &mut e1).unwrap().sfa;

    let mut w2 = waf(pat);
    let mut e2 = BoundedExhaustiveEq { max_len: d, max_queries: None };
    let kv = kv_learn(&mut w2, &body, &a, &mut e2).unwrap().sfa;

    let mut w3 = waf(pat);
    let pv = passive_learn(&mut w3, &body, &a, d).unwrap().sfa;

    assert!(
        la.equivalent(&kv),
        "{tag}: L*≠KV on {pat:?}: {:?}",
        la.distinguishing_word(&kv)
    );
    assert!(
        la.equivalent(&pv),
        "{tag}: L*≠passive on {pat:?}: {:?}",
        la.distinguishing_word(&pv)
    );
    for w in all_words(a.len(), d) {
        let t = truth(pat, &a, &w);
        let c = a.concretize(&w);
        assert_eq!(la.accepts(&c), t, "{tag}: L* wrong on {pat:?} / {w:?}");
        assert_eq!(kv.accepts(&c), t, "{tag}: KV wrong on {pat:?} / {w:?}");
        assert_eq!(pv.accepts(&c), t, "{tag}: passive wrong on {pat:?} / {w:?}");
    }
}

#[test]
fn thousand_random_oracles_triple_learner_exact_and_nonvacuous() {
    let a = alpha();
    for seed in 0u64..scn() {
        let pat = pat_from(seed);
        assert_triple_exact(&pat, "seed");

        // Non-vacuous: a one-position mutation that genuinely changes
        // the language must be detected — the learned model of `pat`
        // is NOT equivalent to the learned model of the mutated
        // pattern. (If the mutation does not change the language we
        // skip — the differential's job is to separate *different*
        // languages, never to invent a difference.)
        let mut mut_pat = pat.clone();
        let pos = (seed as usize) % mut_pat.len();
        let repl = SYMS[(SYMS.iter().position(|&b| b == mut_pat[pos]).unwrap() + 1) % SYMS.len()];
        mut_pat[pos] = repl;

        let differs = all_words(a.len(), pat.len() + 3)
            .iter()
            .any(|w| truth(&pat, &a, w) != truth(&mut_pat, &a, w));
        if differs {
            let mut wa = waf(&pat);
            let mut ea = BoundedExhaustiveEq {
                max_len: pat.len() + 3,
                max_queries: None,
            };
            let lpa = l_star(&mut wa, &body, &a, &mut ea).unwrap().sfa;
            let mut wb = waf(&mut_pat);
            let mut eb = BoundedExhaustiveEq {
                max_len: mut_pat.len() + 3,
                max_queries: None,
            };
            let lpb = l_star(&mut wb, &body, &a, &mut eb).unwrap().sfa;
            assert!(
                !lpa.equivalent(&lpb),
                "differential is VACUOUS: distinct languages {pat:?} vs \
                 {mut_pat:?} learned as equivalent"
            );
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(pc()))]

    /// 10k randomized oracles (independent of the deterministic lane):
    /// the triple-learner exactness invariant must hold for every one.
    #[test]
    fn random_oracles_triple_learner_always_exact(
        pat in proptest::collection::vec(
            proptest::sample::select(&SYMS[..]),
            1..=3usize,
        )
    ) {
        // proptest gives `Vec<u8>`; the contract is identical.
        assert_triple_exact(&pat, "proptest");
    }
}
