//! Truth contract for the symbolic-automaton algebra.
//!
//! The learner and the bypass miner are only as sound as these
//! operations. Every Boolean op is checked against an independent
//! brute-force language oracle over thousands of proptest words; a
//! test here that passed on a no-op product construction is impossible
//! by construction (the brute oracle would diverge).

use proptest::prelude::*;
use wafrift_wafmodel::sfa::{BytePred, Sfa};

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
    #![proptest_config(ProptestConfig::with_cases(4000))]

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
