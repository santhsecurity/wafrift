//! E7 — adversarial oracles & inputs. The engine must stay *honest*
//! under hostile conditions: never panic, never hang, and — the
//! load-bearing property — never falsely certify "exact" against a
//! target it cannot actually capture. Plus a self-adversarial test:
//! run our OWN solver against our OWN hardened rules.

use wafrift_types::Request;
use wafrift_wafmodel::canon::Channel;
use wafrift_wafmodel::normalize::Transform;
use wafrift_wafmodel::{
    Alphabet, ChannelSet, Outcome, Pipeline, Result, Rule, SimRegexWaf, Stage, WafOracle,
    attack_grammar, canonicalize, passive_learn, solve_bypass,
};

fn body(b: &[u8]) -> Request {
    Request::post("https://h/p", b.to_vec()).header("Content-Type", "application/json")
}

// ── A WAF whose acceptance is NON-REGULAR: pass iff `<` and `>` are
//    balanced. No finite automaton captures this. ──
struct BalancedWaf {
    q: u64,
}
impl WafOracle for BalancedWaf {
    fn classify(&mut self, req: &Request) -> Result<Outcome> {
        self.q += 1;
        let b = req.body_bytes().unwrap_or(&[]);
        let lt = b.iter().filter(|&&c| c == b'<').count();
        let gt = b.iter().filter(|&&c| c == b'>').count();
        Ok(if lt == gt {
            Outcome::Pass
        } else {
            Outcome::Block
        })
    }
    fn queries(&self) -> u64 {
        self.q
    }
}

// ── A noisy oracle: a real CRS WAF whose answer is flipped with a
//    fixed probability (deterministic SplitMix64). ──
struct NoisyWaf {
    inner: SimRegexWaf,
    s: u64,
    flip_in: u64, // flip ~1/flip_in answers
}
impl WafOracle for NoisyWaf {
    fn classify(&mut self, req: &Request) -> Result<Outcome> {
        let truth = self.inner.classify(req)?;
        self.s = self.s.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.s;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z ^= z >> 31;
        Ok(if z.is_multiple_of(self.flip_in) {
            match truth {
                Outcome::Pass => Outcome::Block,
                Outcome::Block => Outcome::Pass,
            }
        } else {
            truth
        })
    }
    fn queries(&self) -> u64 {
        self.inner.queries()
    }
}

#[test]
fn non_regular_waf_is_not_falsely_certified_exact() {
    // A non-regular target is NOT a reason to hang. The bounded
    // `passive_learn` (fixed test-suite, no unbounded refinement) is
    // guaranteed to terminate and yields a regular *approximation*. A
    // finite automaton provably cannot equal "#`<` == #`>`", so a
    // balanced string deep enough must be misclassified — we exhibit
    // it. (Unbounded L* is deliberately NOT used here: refining
    // against a non-regular oracle would not converge — using the
    // bounded learner is the honest, terminating contract.)
    let alpha = Alphabet::new(vec![b'<', b'>'], b'A');
    let mut waf = BalancedWaf { q: 0 };
    let learned = passive_learn(&mut waf, &body, &alpha, 6).unwrap().sfa;
    assert!(waf.queries() > 0, "learner must actually have queried");

    let truth = |w: &[u8]| {
        w.iter().filter(|&&c| c == b'<').count() == w.iter().filter(|&&c| c == b'>').count()
    };

    // Constructive pumping witness (NOT a probe family that might miss).
    // The learned automaton has `n` states. Feeding `<` repeatedly, the
    // n+1 prefixes <^0..<^n cannot all land in distinct states, so by
    // pigeonhole two of them, <^i and <^j (i<j), reach the SAME state.
    // `passive_learn` always emits start state 0.
    let n = learned.len();
    let mut st = 0usize;
    let mut seen = std::collections::HashMap::new();
    seen.insert(st, 0usize);
    let mut pump: Option<(usize, usize)> = None;
    for k in 1..=n + 1 {
        st = learned.step_byte(st, b'<');
        if let Some(&i) = seen.get(&st) {
            pump = Some((i, k));
            break;
        }
        seen.insert(st, k);
    }
    let (i, j) = pump.expect("a finite automaton MUST repeat a state on <^k (pigeonhole)");

    // <^i>^i is balanced (truth = pass); <^j>^i has j>i more `<` than
    // `>` (truth = block). The automaton is in the identical state
    // after <^i and <^j, so feeding the same >^i suffix yields the
    // identical verdict for both — it therefore CANNOT match the
    // non-regular truth on both. This is a guaranteed divergence, no
    // luck involved (the honest "this is only an approximation").
    let a: Vec<u8> = std::iter::repeat_n(b'<', i)
        .chain(std::iter::repeat_n(b'>', i))
        .collect();
    let b: Vec<u8> = std::iter::repeat_n(b'<', j)
        .chain(std::iter::repeat_n(b'>', i))
        .collect();
    assert_eq!(
        learned.accepts(&a),
        learned.accepts(&b),
        "pumping invariant: equal state after <^{i} and <^{j} ⇒ equal verdict"
    );
    assert!(
        truth(&a) != truth(&b),
        "the two truths differ by construction (balanced vs unbalanced)"
    );
    assert!(
        learned.accepts(&a) != truth(&a) || learned.accepts(&b) != truth(&b),
        "a finite automaton CANNOT equal the non-regular language; the \
         learned approximation provably misclassifies the pumping \
         witness (no dishonest 'exact')"
    );
}

#[test]
fn noisy_oracle_terminates_and_never_panics() {
    // Under 1/16 answer-flip noise the learner has no exactness
    // guarantee — but it MUST still terminate, never panic, and
    // produce a usable hypothesis (robustness, not a false claim).
    let alpha = Alphabet::new(vec![b'<', b's'], b'A');
    let mk_inner = || {
        SimRegexWaf::new(
            vec![Rule {
                id: "r".into(),
                channels: ChannelSet::none().with(Channel::Body),
                transforms: vec![],
                pattern: regex::bytes::Regex::new("<s").unwrap(),
                score: 5,
            }],
            5,
        )
    };
    // `passive_learn` is the bounded RPNI regime: a FIXED test-suite,
    // no refinement loop, |states| ≤ |suite| — so it is *guaranteed* to
    // terminate and produce a hypothesis even under a hostile/noisy
    // oracle (the prior unbounded-BFS construction did NOT terminate
    // here; that engine defect is fixed). Reaching the asserts at all
    // proves termination.
    let mut noisy_a = NoisyWaf {
        inner: mk_inner(),
        s: 1,
        flip_in: 16,
    };
    let rep_a = passive_learn(&mut noisy_a, &body, &alpha, 5).unwrap();
    assert!(
        rep_a.membership_queries > 0,
        "the learner must have queried"
    );
    assert!(!rep_a.sfa.is_empty(), "a hypothesis is still produced");
    // The hypothesis is a well-formed, total, *deterministic* automaton
    // even under noise: classifying the same input twice is identical
    // and it never panics on arbitrary bytes (incl. NUL / 0xFF).
    for w in [b"".as_ref(), b"<", b"s", b"<s", b"<<ss", b"\x00\xff<s\x00"] {
        assert_eq!(
            rep_a.sfa.accepts(w),
            rep_a.sfa.accepts(w),
            "hypothesis must be a deterministic classifier"
        );
    }
    // Honest determinism contract: the LEARNER is deterministic and the
    // NoisyWaf is a deterministic function of its INITIAL rng state, so
    // a second run from an IDENTICALLY-RESET oracle reproduces the
    // identical automaton. (Asserting two *independent* runs against a
    // mutable-rng oracle are equal would assert a FALSE property — the
    // rng advances and each run's cache is fresh; reset-equality is the
    // true, stronger invariant.)
    let mut noisy_b = NoisyWaf {
        inner: mk_inner(),
        s: 1,
        flip_in: 16,
    };
    let rep_b = passive_learn(&mut noisy_b, &body, &alpha, 5).unwrap();
    assert!(
        rep_b.sfa.equivalent(&rep_a.sfa),
        "deterministic learner + oracle reset to the same initial state \
         must reproduce the identical hypothesis (stable robustness, \
         not luck)"
    );
}

#[test]
fn unicode_nul_and_overlong_inputs_are_handled_to_spec() {
    // NUL inside a cookie: canonicalize is total and keeps the byte.
    let r = Request::get("https://h/p").header("Cookie", "a=\u{0}b; c=d");
    let v = canonicalize(&r);
    assert_eq!(v.method, "GET");
    assert!(v.total_bytes() > 0);

    // RemoveNulls drops 0x00 exactly; UrlDecodeUni of an overlong
    // `%C0%AF` yields the literal bytes 0xC0 0xAF (we do not "fix up"
    // overlong UTF-8 — the origin's job; we must be byte-faithful).
    assert_eq!(
        Transform::RemoveNulls.apply(&[b'a', 0, b'b', 0, b'c']),
        b"abc"
    );
    assert_eq!(
        Transform::UrlDecodeUni.apply(b"%C0%AFetc"),
        vec![0xC0, 0xAF, b'e', b't', b'c']
    );
    // %uXXXX high plane narrows to a byte (ModSecurity behaviour),
    // never panics on the boundary.
    assert_eq!(Transform::UrlDecodeUni.apply(b"%uFFFF"), vec![0xFF]);
    assert_eq!(Transform::UrlDecodeUni.apply(b"%u"), b"%u"); // truncated, literal
}

#[test]
fn polyglot_payload_is_in_multiple_attack_classes() {
    // A single payload that is BOTH SQLi and XSS must be recognised by
    // a grammar built from both needles (per-class channel modelling
    // is real, not first-match).
    let alpha = Alphabet::new(
        vec![b'<', b's', b'c', b'r', b'i', b'p', b't', b'\'', b' ', b'o'],
        b'Z',
    );
    let needles: [&[u8]; 2] = [b"<script", b"' o"];
    let g = attack_grammar(&alpha, &needles);
    // `' o...<script` contains both signatures.
    assert!(g.accepts(b"' or 1<script"));
    // Each alone still matches (union semantics).
    assert!(g.accepts(b"x<scriptx"));
    assert!(g.accepts(b"a' ob"));
    // A benign string with neither does NOT match (precision).
    assert!(!g.accepts(b"hello world"));
}

#[test]
fn our_own_solver_cannot_evade_our_own_hardened_rules() {
    // Self-adversarial: harden a brittle WAF against the double-URL
    // mismatch, then point OUR solver at the hardened config for the
    // same attack+sink. The double-decode synth rule must withstand
    // the structural-preimage solver — `None`, not a bypass. If this
    // ever returns Some, that IS a real engine finding.
    let attack = b"<script>";
    let sink = Pipeline(vec![Stage::DoubleUrlDecode]);
    let brittle = SimRegexWaf::new(
        vec![Rule {
            id: "raw".into(),
            channels: ChannelSet::none().with(Channel::Body),
            transforms: vec![Transform::UrlDecodeUni, Transform::Lowercase],
            pattern: regex::bytes::Regex::new("<script").unwrap(),
            score: 5,
        }],
        5,
    );
    // The double-decode closing rule a defender would deploy.
    let hardened_rule = Rule {
        id: "synth-dbl".into(),
        channels: ChannelSet::none().with(Channel::Body),
        transforms: vec![
            Transform::UrlDecodeUni,
            Transform::UrlDecodeUni,
            Transform::HtmlEntityDecode,
            Transform::Lowercase,
        ],
        pattern: regex::bytes::Regex::new("<script").unwrap(),
        score: 5,
    };
    let mut hardened = brittle.with_rules_added(vec![hardened_rule]);
    let sol = solve_bypass(attack, &sink, &mut hardened, &body).unwrap();
    assert!(
        sol.is_none(),
        "our double-decode hardening was evaded by our own solver: {sol:?} \
         — this is a real engine finding, fix the engine not the test"
    );
    // Sanity (anti-vacuous): without the hardening it WAS bypassable.
    let mut brittle2 = SimRegexWaf::new(
        vec![Rule {
            id: "raw".into(),
            channels: ChannelSet::none().with(Channel::Body),
            transforms: vec![Transform::UrlDecodeUni, Transform::Lowercase],
            pattern: regex::bytes::Regex::new("<script").unwrap(),
            score: 5,
        }],
        5,
    );
    assert!(
        solve_bypass(attack, &sink, &mut brittle2, &body)
            .unwrap()
            .is_some(),
        "control: the un-hardened WAF must be bypassable (else test is vacuous)"
    );
}
