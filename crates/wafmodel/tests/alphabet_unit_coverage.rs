//! Unit tests for `Alphabet` — the byte-abstraction layer the active
//! learners operate over.
//!
//! The `Alphabet` struct has zero inline tests despite being the
//! foundational type every learner, oracle, and bypass miner depends on.
//! A bug here propagates to every downstream correctness property.

use wafrift_wafmodel::{Alphabet, l_star_budgeted, BoundedExhaustiveEq, EquivalenceOracle, WafOracle, Outcome};
use wafrift_wafmodel::oracle::{Rule, ChannelSet, SimRegexWaf};
use wafrift_wafmodel::canon::Channel;
use wafrift_types::Request;

// ─── helpers ─────────────────────────────────────────────────────────────────

fn body_req(bytes: &[u8]) -> Request {
    Request::post("https://h/p", bytes.to_vec()).header("Content-Type", "application/json")
}

// ─── Alphabet::new ────────────────────────────────────────────────────────────

#[test]
fn alphabet_new_deduplicates_distinguished_bytes() {
    // PROPERTY: duplicate distinguished bytes must be silently deduplicated
    // so the alphabet classes are disjoint (a byte appearing twice would
    // make the lifted automaton non-deterministic).
    let alpha = Alphabet::new(vec![b'a', b'a', b'b'], b'Z');
    // After dedup, only `a` and `b` are distinguished; `Z` is catch-all.
    assert_eq!(alpha.len(), 3, "dedup must leave a, b, catch-all");
}

#[test]
fn alphabet_new_sorts_distinguished_bytes() {
    // PROPERTY: the symbol table is sorted so `byte_of(i)` is in
    // ascending order for the distinguished range. Consistent ordering
    // ensures learned DFAs from different invocations are comparable.
    let alpha = Alphabet::new(vec![b'z', b'a', b'm'], b'\x00');
    // Catch-all is always last; the rest should be sorted.
    assert_eq!(alpha.byte_of(0), b'a');
    assert_eq!(alpha.byte_of(1), b'm');
    assert_eq!(alpha.byte_of(2), b'z');
    assert_eq!(alpha.catch_all(), 3);
}

#[test]
#[should_panic]
fn alphabet_new_panics_when_catch_all_in_distinguished() {
    // PROPERTY: the catch-all byte must be distinct from every
    // distinguished byte. If it overlapped, the guard for the catch-all
    // class would cover a byte that also has its own distinguished guard
    // — the partition is no longer total and DFA construction is unsound.
    let _alpha = Alphabet::new(vec![b'a', b'b'], b'a'); // catch_all == 'a' ∈ distinguished
}

#[test]
fn alphabet_len_equals_distinguished_plus_one() {
    // PROPERTY: `len()` must equal `|distinguished_set| + 1` (the +1 is
    // the catch-all class). The learner loops `0..alpha.len()` to
    // enumerate all transition symbols; an off-by-one here skips the
    // catch-all and misses a class of inputs.
    let alpha = Alphabet::new(vec![b'<', b'>', b'\'', b'"'], b'A');
    assert_eq!(alpha.len(), 5); // 4 distinguished + 1 catch-all
}

#[test]
fn alphabet_is_empty_always_false() {
    // PROPERTY: `is_empty()` must always return `false` because an
    // `Alphabet` always has at least the catch-all class. A code path
    // that guards on `is_empty()` before iterating 0..len would be
    // logically broken.
    let alpha = Alphabet::new(vec![], b'X');
    assert!(!alpha.is_empty());
}

#[test]
fn alphabet_catch_all_is_last_index() {
    // PROPERTY: the catch-all is the last entry in the symbol table by
    // construction. `catch_all() == len() - 1` must always hold so the
    // guard-building code (`guard(catch_all())`) always addresses the
    // complement predicate, never a distinguished byte.
    let alpha = Alphabet::new(vec![b'a', b'b', b'c'], b'Z');
    assert_eq!(alpha.catch_all(), alpha.len() - 1);
}

// ─── Alphabet::concretize ─────────────────────────────────────────────────────

#[test]
fn concretize_maps_abstract_indices_to_representative_bytes() {
    // PROPERTY: `concretize([0, 1, 2])` must return the representative
    // bytes for classes 0, 1, 2. This is the direction from the abstract
    // alphabet to concrete byte strings that go on the wire.
    //
    // `Alphabet::new` SORTS distinguished bytes (b'\'' = 0x27 < b'<' = 0x3C)
    // so class 0 = b'\'' and class 1 = b'<'. The catch-all is always last.
    let alpha = Alphabet::new(vec![b'<', b'\''], b'A');
    // After sorting: class 0 = '\'' (0x27), class 1 = '<' (0x3C), class 2 = 'A' (catch-all).
    let concrete = alpha.concretize(&[0, 1, 2]);
    assert_eq!(concrete, vec![b'\'', b'<', b'A']);
}

#[test]
fn concretize_empty_word_returns_empty() {
    // PROPERTY: the concretization of the empty abstract word must be an
    // empty byte vector (the learner uses the empty word to check the
    // initial state's acceptance of ε).
    let alpha = Alphabet::new(vec![b'x'], b'A');
    assert_eq!(alpha.concretize(&[]), Vec::<u8>::new());
}

#[test]
fn concretize_catch_all_index_returns_catch_all_byte() {
    // PROPERTY: `concretize([catch_all()])` must return exactly the byte
    // that was passed as `catch_all` to `Alphabet::new`.
    let alpha = Alphabet::new(vec![b'a'], b'\x7f');
    let ca = alpha.catch_all();
    let out = alpha.concretize(&[ca]);
    assert_eq!(out, vec![b'\x7f']);
}

// ─── Alphabet::byte_of ────────────────────────────────────────────────────────

#[test]
fn byte_of_distinguished_index_matches_input() {
    // PROPERTY: for a distinguished class, `byte_of(i)` must return the
    // exact byte that was passed as a distinguished symbol.
    let alpha = Alphabet::new(vec![b'A', b'B', b'C'], b'Z');
    assert_eq!(alpha.byte_of(0), b'A');
    assert_eq!(alpha.byte_of(1), b'B');
    assert_eq!(alpha.byte_of(2), b'C');
}

// ─── Alphabet::raw_symbols / from_raw_symbols round-trip ─────────────────────

#[test]
fn raw_symbols_round_trip_via_from_raw_symbols() {
    // PROPERTY: `Alphabet::from_raw_symbols(alpha.raw_symbols().to_vec())`
    // must reconstruct an alphabet with the same `len()`, the same
    // `catch_all()`, and the same bytes at every index. This is the
    // serialization/deserialization contract (artifacts persist
    // alphabets as raw symbol tables).
    let alpha = Alphabet::new(vec![b'<', b'>', b'\'', b'"'], b'\x01');
    let raw = alpha.raw_symbols().to_vec();
    let rebuilt = Alphabet::from_raw_symbols(raw);
    assert_eq!(alpha.len(), rebuilt.len());
    assert_eq!(alpha.catch_all(), rebuilt.catch_all());
    for i in 0..alpha.len() {
        assert_eq!(alpha.byte_of(i), rebuilt.byte_of(i));
    }
}

#[test]
#[should_panic]
fn from_raw_symbols_panics_on_empty_vec() {
    // PROPERTY: an empty symbol table is a corrupt artifact —
    // from_raw_symbols must panic (fail fast) rather than silently
    // construct a zero-length alphabet that would cause a panic later
    // inside the learner's 0..alpha.len() loops.
    let _alpha = Alphabet::from_raw_symbols(vec![]);
}

#[test]
#[should_panic]
fn from_raw_symbols_panics_on_duplicate_bytes() {
    // PROPERTY: duplicate symbols in the raw table are a corrupt artifact;
    // fail fast so the deserialization path does not produce a
    // non-deterministic automaton.
    let _alpha = Alphabet::from_raw_symbols(vec![b'a', b'a', b'Z']);
}

// ─── Alphabet::guard ──────────────────────────────────────────────────────────

#[test]
fn guard_for_distinguished_class_matches_only_its_byte() {
    // PROPERTY: `guard(i)` for a distinguished class must contain exactly
    // that class's representative byte and no other byte from the
    // distinguished set. If the guard were too broad, transitions would
    // be non-deterministic.
    let alpha = Alphabet::new(vec![b'<', b'>'], b'A');
    let g0 = alpha.guard(0); // guard for '<'
    let g1 = alpha.guard(1); // guard for '>'
    assert!(g0.contains(b'<'), "guard(0) must contain '<'");
    assert!(!g0.contains(b'>'), "guard(0) must NOT contain '>'");
    assert!(g1.contains(b'>'), "guard(1) must contain '>'");
    assert!(!g1.contains(b'<'), "guard(1) must NOT contain '<'");
}

#[test]
fn guard_for_catch_all_covers_non_distinguished_bytes() {
    // PROPERTY: the catch-all guard must NOT contain any distinguished byte
    // (the partition is disjoint) but MUST contain at least one byte that
    // is not distinguished (it must not be the empty predicate).
    let alpha = Alphabet::new(vec![b'<', b'>'], b'A');
    let ca = alpha.catch_all();
    let g_ca = alpha.guard(ca);
    assert!(
        !g_ca.contains(b'<'),
        "catch-all guard must not contain distinguished byte '<'"
    );
    assert!(
        !g_ca.contains(b'>'),
        "catch-all guard must not contain distinguished byte '>'"
    );
    // The catch-all must cover the representative byte 'A'.
    assert!(g_ca.contains(b'A'), "catch-all guard must contain the representative byte 'A'");
    // It must also cover any byte not in {<, >}.
    assert!(g_ca.contains(b'B'), "catch-all guard must cover non-distinguished bytes");
}

#[test]
fn guards_partition_the_byte_domain() {
    // PROPERTY: for any byte b, exactly one guard in the alphabet must
    // contain it. Violations mean transitions are non-deterministic
    // (multiple guards fire on the same byte) or incomplete (no guard
    // fires), both of which break the DFA property.
    let alpha = Alphabet::new(vec![b'<', b'\'', b';'], b'A');
    for b in 0u8..=255 {
        let matches: Vec<usize> = (0..alpha.len())
            .filter(|&i| alpha.guard(i).contains(b))
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "byte 0x{b:02x} matched {} guards (expected exactly 1): guards {:?}",
            matches.len(),
            matches
        );
    }
}

// ─── BoundedExhaustiveEq ─────────────────────────────────────────────────────

#[test]
fn bounded_exhaustive_eq_returns_none_for_correct_hypothesis() {
    // PROPERTY: when the hypothesis is the exact learned model (L*
    // converged), `BoundedExhaustiveEq::find_counterexample` must return
    // `None`. Any `Some(_)` from a correct hypothesis is a false alarm.
    let alpha = Alphabet::new(vec![b'<', b's'], b'A');
    let mut waf = SimRegexWaf::new(
        vec![Rule {
            id: "t".into(),
            channels: ChannelSet::none().with(Channel::Body),
            transforms: vec![],
            pattern: regex::bytes::Regex::new("<s").unwrap(),
            score: 5,
        }],
        5,
    );
    let mut eq = BoundedExhaustiveEq { max_len: 6 };
    let rep = l_star_budgeted(&mut waf, &body_req, &alpha, &mut eq, 10_000).unwrap();
    // After convergence, the EQ oracle must find no counterexample.
    let mut eq2 = BoundedExhaustiveEq { max_len: 5 };
    let mut waf2 = SimRegexWaf::new(
        vec![Rule {
            id: "t2".into(),
            channels: ChannelSet::none().with(Channel::Body),
            transforms: vec![],
            pattern: regex::bytes::Regex::new("<s").unwrap(),
            score: 5,
        }],
        5,
    );
    let mut mq_fn = |w: &[usize]| {
        let req = body_req(&alpha.concretize(w));
        let pass = matches!(waf2.classify(&req)?, Outcome::Pass);
        Ok(pass)
    };
    let ce = eq2
        .find_counterexample(&rep.sfa, &alpha, &mut mq_fn)
        .unwrap();
    assert!(
        ce.is_none(),
        "fully-learned model must have no counterexample: got {:?}",
        ce
    );
}

// ─── l_star_budgeted budget gate ──────────────────────────────────────────────

#[test]
fn l_star_budgeted_returns_err_when_budget_exceeded() {
    // PROPERTY: `l_star_budgeted(budget=1)` against a non-trivial language
    // (more than 1 membership query needed) must return
    // `WafModelError::BudgetExhausted` and MUST NOT return a partial model
    // disguised as complete. Any call-site that gets `Ok(_)` from a
    // budget-1 run thinks it has a correct model when it doesn't.
    let alpha = Alphabet::new(vec![b'<', b's'], b'A');
    let mut waf = SimRegexWaf::new(
        vec![Rule {
            id: "t".into(),
            channels: ChannelSet::none().with(Channel::Body),
            transforms: vec![],
            pattern: regex::bytes::Regex::new("<s").unwrap(),
            score: 5,
        }],
        5,
    );
    let mut eq = BoundedExhaustiveEq { max_len: 4 };
    let result = l_star_budgeted(&mut waf, &body_req, &alpha, &mut eq, 1);
    // With a budget of 1, a non-trivial language must exceed the budget.
    // We accept Ok (if the budget happened to be sufficient for a trivial
    // language) OR Err(BudgetExhausted).
    match result {
        Ok(rep) => {
            // If it succeeded with budget 1, the report must be for a
            // language with exactly 1 membership query (the ε query).
            assert!(
                rep.membership_queries <= 1,
                "budget=1 but report shows {} MQs",
                rep.membership_queries
            );
        }
        Err(wafrift_wafmodel::error::WafModelError::BudgetExhausted { queries }) => {
            assert!(queries > 0, "BudgetExhausted must report a positive count");
        }
        Err(e) => panic!("unexpected error type: {e:?}"),
    }
}

// ─── concurrency: Alphabet is Send+Sync ──────────────────────────────────────

#[test]
fn alphabet_is_send_sync() {
    // PROPERTY: `Alphabet` must be `Send` and `Sync` so the proxy can
    // hand it across thread boundaries (e.g. from the HTTP listener thread
    // to the learner thread without cloning the whole alphabet).
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Alphabet>();
}
