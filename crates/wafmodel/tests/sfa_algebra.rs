//! Truth contract for the symbolic-automaton algebra.
//!
//! The learner and the bypass miner are only as sound as these
//! operations. Every Boolean op is checked against an independent
//! brute-force language oracle over thousands of proptest words; a
//! test here that passed on a no-op product construction is impossible
//! by construction (the brute oracle would diverge).

use proptest::prelude::*;
use wafrift_wafmodel::sfa::{BytePred, Sfa};

/// Proptest case count: full (10k) by default — the legendary lane —
/// scaled down per-push via `WAFMODEL_PROPTEST_CASES` so the CI gate
/// stays fast while the nightly `legendary` job runs the full count.
/// The *property* is identical at any count; only confidence scales.
fn pc() -> u32 {
    std::env::var("WAFMODEL_PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000)
}

// ── Reference automata (hand-built, language known exactly) ─────────

/// L = { w : w contains byte `<` (0x3C) }.
fn contains_lt() -> Sfa {
    let lt = BytePred::byte(b'<');
    Sfa::new(
        0,
        vec![false, true],
        vec![vec![(lt, 1), (!lt, 0)], vec![(BytePred::any(), 1)]],
    )
}
fn brute_contains_lt(w: &[u8]) -> bool {
    w.contains(&b'<')
}

/// L = { w : w ends with byte `a` (0x61) }.
fn ends_with_a() -> Sfa {
    let a = BytePred::byte(b'a');
    Sfa::new(
        0,
        vec![false, true],
        vec![vec![(a, 1), (!a, 0)], vec![(a, 1), (!a, 0)]],
    )
}
fn brute_ends_with_a(w: &[u8]) -> bool {
    w.last() == Some(&b'a')
}

#[test]
fn bytepred_is_an_exact_set_algebra() {
    let lower = BytePred::range(b'a', b'z');
    assert!(lower.contains(b'm'));
    assert!(!lower.contains(b'A'));
    assert_eq!(lower.count(), 26);
    assert_eq!(lower.witness(), Some(b'a')); // minimum byte
    // De Morgan, exactly, over the whole domain.
    let digits = BytePred::range(b'0', b'9');
    let demorgan = !lower.or(digits);
    let other = (!lower).and(!digits);
    for b in 0u8..=255 {
        assert_eq!(demorgan.contains(b), other.contains(b), "byte {b}");
    }
    assert!(BytePred::none().is_empty());
    assert!(!BytePred::any().is_empty());
    assert_eq!(BytePred::any().count(), 256);
    assert_eq!(BytePred::none().witness(), None);
}

#[test]
#[should_panic(expected = "non-deterministic")]
fn overlapping_guards_are_rejected() {
    // Guards [a..c] and [b..z] both contain `b`,`c` ⇒ nondeterministic
    // ⇒ must panic, never be silently "repaired".
    let _ = Sfa::new(
        0,
        vec![true],
        vec![vec![
            (BytePred::range(b'a', b'c'), 0),
            (BytePred::range(b'b', b'z'), 0),
        ]],
    );
}

#[test]
#[should_panic(expected = "not total")]
fn non_total_guards_are_rejected() {
    // Only `a` has a transition; the other 255 bytes have none.
    let _ = Sfa::new(0, vec![true], vec![vec![(BytePred::byte(b'a'), 0)]]);
}

#[test]
fn accepts_matches_the_known_language() {
    let s = contains_lt();
    assert!(s.accepts(b"ab<cd"));
    assert!(s.accepts(b"<"));
    assert!(!s.accepts(b""));
    assert!(!s.accepts(b"abcd"));

    let e = ends_with_a();
    assert!(e.accepts(b"bba"));
    assert!(e.accepts(b"a"));
    assert!(!e.accepts(b"ab"));
    assert!(!e.accepts(b""));
}

#[test]
fn shortest_accepted_is_the_length_then_lex_minimum() {
    // contains `<` ⇒ shortest accepted is exactly the single byte `<`.
    assert_eq!(contains_lt().shortest_accepted(), Some(vec![b'<']));
    // ends with `a` ⇒ shortest accepted is `a`.
    assert_eq!(ends_with_a().shortest_accepted(), Some(vec![b'a']));
    // An empty language (contains `<` AND ends with `a` is non-empty,
    // but contains `<` AND its own complement is empty).
    let empty = contains_lt().intersect(&contains_lt().complement());
    assert_eq!(empty.shortest_accepted(), None);
    assert!(empty.is_language_empty());
}

#[test]
fn distinguishing_word_is_none_iff_equivalent() {
    let a = contains_lt();
    assert!(a.equivalent(&a.clone()));
    assert_eq!(a.distinguishing_word(&a.clone()), None);

    // Double complement is the same language.
    assert!(a.equivalent(&a.complement().complement()));

    // contains-`<` vs ends-with-`a` differ; the witness must be
    // accepted by exactly one (verified independently).
    let b = ends_with_a();
    let w = a.distinguishing_word(&b).expect("the two languages differ");
    assert_ne!(
        a.accepts(&w),
        b.accepts(&w),
        "a distinguishing word must split the two languages"
    );
}

proptest! {
    // The product construction is exact: ∩ ∪ \ ¬ on automata equal the
    // matching Boolean combination of the brute language oracles, for
    // thousands of random byte words.
    #![proptest_config(ProptestConfig::with_cases(pc()))]

    #[test]
    fn boolean_ops_agree_with_brute_oracle(word in proptest::collection::vec(any::<u8>(), 0..24)) {
        let a = contains_lt();
        let b = ends_with_a();
        let w = &word[..];

        prop_assert_eq!(a.accepts(w), brute_contains_lt(w));
        prop_assert_eq!(b.accepts(w), brute_ends_with_a(w));
        prop_assert_eq!(a.intersect(&b).accepts(w), brute_contains_lt(w) && brute_ends_with_a(w));
        prop_assert_eq!(a.union(&b).accepts(w), brute_contains_lt(w) || brute_ends_with_a(w));
        prop_assert_eq!(a.difference(&b).accepts(w), brute_contains_lt(w) && !brute_ends_with_a(w));
        prop_assert_eq!(a.complement().accepts(w), !brute_contains_lt(w));
    }
}

// ── E3/19 + E13/91: minimization is language-preserving, monotone,
// and idempotent — 10k random automata over a 3-byte alphabet. ──
fn build_random_sfa(states: &[(bool, [u8; 4])]) -> Sfa {
    let n = states.len();
    let a = BytePred::byte(b'a');
    let b = BytePred::byte(b'b');
    let c = BytePred::byte(b'c');
    let other = !(a.or(b).or(c));
    let accept: Vec<bool> = states.iter().map(|s| s.0).collect();
    let delta: Vec<Vec<(BytePred, usize)>> = states
        .iter()
        .map(|(_, t)| {
            vec![
                (a, t[0] as usize % n),
                (b, t[1] as usize % n),
                (c, t[2] as usize % n),
                (other, t[3] as usize % n),
            ]
        })
        .collect();
    Sfa::new(0, accept, delta)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(pc()))]

    #[test]
    fn minimize_is_language_preserving_monotone_and_idempotent(
        states in proptest::collection::vec(
            (any::<bool>(), proptest::array::uniform4(0u8..5)),
            1..6usize,
        )
    ) {
        let sfa = build_random_sfa(&states);
        let min = sfa.minimize();
        // Language preserved (EXACT — distinguishing_word over bytes).
        prop_assert!(
            min.equivalent(&sfa),
            "minimize changed the language: {:?}",
            min.distinguishing_word(&sfa)
        );
        // Never larger than the input.
        prop_assert!(min.len() <= sfa.len());
        // Idempotent: re-minimizing a minimal machine neither shrinks
        // it nor changes its language.
        let min2 = min.minimize();
        prop_assert_eq!(min2.len(), min.len());
        prop_assert!(min2.equivalent(&min));
    }
}

// ── E3/18: the full Boolean-algebra laws hold for the SFA language
// operators — De Morgan, double-complement/involution, idempotence,
// and the complement laws — over 10k random *pairs* of automata. The
// operators are byte-exact (`equivalent` returns a distinguishing word
// on failure), so this is a truth contract, not a smoke test. ──
proptest! {
    #![proptest_config(ProptestConfig::with_cases(pc()))]

    #[test]
    fn sfa_language_operators_form_a_boolean_algebra(
        sa in proptest::collection::vec(
            (any::<bool>(), proptest::array::uniform4(0u8..5)), 1..6usize),
        sb in proptest::collection::vec(
            (any::<bool>(), proptest::array::uniform4(0u8..5)), 1..6usize),
    ) {
        let a = build_random_sfa(&sa);
        let b = build_random_sfa(&sb);

        // Involution: ¬¬a ≡ a.
        prop_assert!(
            a.complement().complement().equivalent(&a),
            "double-complement changed the language: {:?}",
            a.complement().complement().distinguishing_word(&a)
        );

        // De Morgan, both directions, byte-exact.
        let lhs1 = a.intersect(&b).complement();
        let rhs1 = a.complement().union(&b.complement());
        prop_assert!(
            lhs1.equivalent(&rhs1),
            "¬(a∩b) ≠ ¬a∪¬b: {:?}", lhs1.distinguishing_word(&rhs1)
        );
        let lhs2 = a.union(&b).complement();
        let rhs2 = a.complement().intersect(&b.complement());
        prop_assert!(
            lhs2.equivalent(&rhs2),
            "¬(a∪b) ≠ ¬a∩¬b: {:?}", lhs2.distinguishing_word(&rhs2)
        );

        // Idempotence: a∪a ≡ a, a∩a ≡ a.
        prop_assert!(a.union(&a).equivalent(&a), "a∪a ≠ a");
        prop_assert!(a.intersect(&a).equivalent(&a), "a∩a ≠ a");

        // Complement laws: a∪¬a is universal, a∩¬a is empty — checked
        // against the derived universe/empty (no constructor needed),
        // and `difference` agrees with intersect-with-complement.
        let universe = a.union(&a.complement());
        let empty = a.intersect(&a.complement());
        prop_assert!(
            b.union(&b.complement()).equivalent(&universe),
            "law of excluded middle is not universal"
        );
        prop_assert!(
            b.intersect(&b.complement()).equivalent(&empty),
            "law of non-contradiction is not empty"
        );
        prop_assert!(
            a.difference(&b).equivalent(&a.intersect(&b.complement())),
            "a\\b ≠ a∩¬b: {:?}",
            a.difference(&b).distinguishing_word(&a.intersect(&b.complement()))
        );
        // Absorption: a∪(a∩b) ≡ a and a∩(a∪b) ≡ a.
        prop_assert!(a.union(&a.intersect(&b)).equivalent(&a), "absorption ∪ failed");
        prop_assert!(a.intersect(&a.union(&b)).equivalent(&a), "absorption ∩ failed");
    }
}
