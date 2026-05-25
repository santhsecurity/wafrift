//! SFA correctness suite -- 9 tests protecting the automaton algebra.
//! Mandated tests 1-9.

use wafrift_wafmodel::sfa::{BytePred, Sfa};

fn contains(b: u8) -> Sfa {
    let pred = BytePred::byte(b);
    Sfa::new(
        0,
        vec![false, true],
        vec![
            vec![(pred, 1), (!pred, 0)],
            vec![(BytePred::any(), 1)],
        ],
    )
}

fn universal() -> Sfa {
    Sfa::new(0, vec![true], vec![vec![(BytePred::any(), 0)]])
}

fn empty_lang() -> Sfa {
    Sfa::new(0, vec![false], vec![vec![(BytePred::any(), 0)]])
}

fn lang_eq(a: &Sfa, b: &Sfa) -> bool {
    a.equivalent(b)
}

fn words(max: usize) -> Vec<Vec<u8>> {
    let alphabet: &[u8] = b"ab<Z";
    let mut out = vec![vec![]];
    let mut frontier: Vec<Vec<u8>> = vec![vec![]];
    for _ in 0..max {
        let mut next = Vec::new();
        for w in &frontier {
            for &c in alphabet {
                let mut e = w.clone();
                e.push(c);
                next.push(e.clone());
                out.push(e);
            }
        }
        frontier = next;
    }
    out
}

#[test]
fn sfa_empty_accepts_nothing() {
    let sfa = empty_lang();
    assert!(!sfa.accepts(b""), "epsilon must be rejected");
    for w in words(4) {
        assert!(!sfa.accepts(&w), "empty-language SFA accepted a word");
    }
    assert!(sfa.is_language_empty());
    assert_eq!(sfa.shortest_accepted(), None);
}

#[test]
fn sfa_universal_accepts_everything() {
    let sfa = universal();
    assert!(sfa.accepts(b""), "epsilon must be accepted");
    for w in words(4) {
        assert!(sfa.accepts(&w), "universal SFA rejected a word");
    }
    assert!(!sfa.is_language_empty());
    assert_eq!(sfa.shortest_accepted(), Some(vec![]));
}

#[test]
fn sfa_complement_is_involution() {
    for sfa in [contains(b'<'), contains(b'a'), universal(), empty_lang()] {
        let double = sfa.complement().complement();
        assert!(
            lang_eq(&double, &sfa),
            "complement involution failed: {:?}",
            double.distinguishing_word(&sfa)
        );
        for w in words(4) {
            assert_eq!(double.accepts(&w), sfa.accepts(&w));
        }
    }
}

#[test]
fn sfa_intersect_idempotent() {
    for sfa in [contains(b'<'), contains(b's'), universal(), empty_lang()] {
        let intersected = sfa.intersect(&sfa);
        assert!(
            lang_eq(&intersected, &sfa),
            "intersect idempotence failed: {:?}",
            intersected.distinguishing_word(&sfa)
        );
    }
}

#[test]
fn sfa_intersect_with_empty_is_empty() {
    let e = empty_lang();
    for sfa in [contains(b'<'), contains(b's'), universal()] {
        assert!(sfa.intersect(&e).is_language_empty(), "X intersect empty is not empty");
        assert!(e.intersect(&sfa).is_language_empty(), "empty intersect X is not empty");
    }
}

#[test]
fn sfa_intersect_with_universal_is_x() {
    let u = universal();
    for sfa in [contains(b'<'), contains(b's'), empty_lang()] {
        assert!(lang_eq(&sfa.intersect(&u), &sfa), "X intersect Sigma* != X");
        assert!(lang_eq(&u.intersect(&sfa), &sfa), "Sigma* intersect X != X");
    }
}

#[test]
fn sfa_product_associative() {
    let x = contains(b'<');
    let y = contains(b's');
    let z = contains(b'Z');
    let lhs = x.intersect(&y).intersect(&z);
    let rhs = x.intersect(&y.intersect(&z));
    assert!(
        lang_eq(&lhs, &rhs),
        "intersect is not associative: {:?}",
        lhs.distinguishing_word(&rhs)
    );
    assert!(!lhs.is_language_empty(), "language must be non-empty");
    assert!(lhs.accepts(b"<sZ"));
    assert!(rhs.accepts(b"<sZ"));
    assert!(!lhs.accepts(b"<s"), "missing Z should reject");
    assert!(!rhs.accepts(b"<s"), "missing Z should reject");
}

#[test]
fn sfa_minimise_idempotent() {
    for sfa in [contains(b'<'), contains(b's'), universal(), empty_lang()] {
        let min1 = sfa.minimize();
        let min2 = min1.minimize();
        assert_eq!(min1.len(), min2.len(), "re-minimize changed state count");
        assert!(lang_eq(&min1, &min2), "re-minimize changed the language");
        assert!(lang_eq(&min1, &sfa), "minimize changed the language");
    }
}

#[test]
fn sfa_bfs_returns_shortest_path() {
    assert_eq!(
        contains(b'<').shortest_accepted(),
        Some(vec![b'<']),
        "shortest for contains-< must be the single byte <"
    );
    let ab_both = contains(b'a').intersect(&contains(b'b'));
    let s = ab_both.shortest_accepted().unwrap();
    assert_eq!(s.len(), 2, "shortest of contains-a AND contains-b has length 2");
    assert!(ab_both.accepts(&s), "shortest_accepted returned a word the SFA does not accept");
    assert_eq!(empty_lang().shortest_accepted(), None, "empty language: None");
    assert_eq!(universal().shortest_accepted(), Some(vec![]), "universal: epsilon");
}
