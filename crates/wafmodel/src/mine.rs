//! Offline bypass mining over the decompiled model.
//!
//! Once the WAF is an [`Sfa`] (accept ⇔ *passes*), finding a bypass is
//! no longer a search against a live target — it is a finite-automaton
//! intersection done at memory speed with **zero further queries**:
//!
//! ```text
//! bypasses(class) = L(learned_pass) ∩ L(attack_grammar)
//! ```
//!
//! The shortest member of that intersection is a *provably minimal*
//! bypass with respect to the learned model (length-then-lex minimum,
//! deterministic). The symmetric difference of two learned models is
//! the exact, transferable set of inputs one WAF blocks and the other
//! lets through — a Cloudflare-vs-CRS diff with no live traffic.
//!
//! Pure Rust, zero-config: this is automaton algebra, no GPU and no
//! network. (vyre/GPU acceleration of the intersection is an additive
//! feature, never a correctness dependency.)

use crate::learn::Alphabet;
use crate::sfa::{BytePred, Sfa, StateId};

/// KMP "contains `needle`" recognizer over the abstract alphabet,
/// lifted to an [`Sfa`] with exactly the learner's guard scheme (so
/// the product with a learned model is exact w.r.t. the abstraction).
fn kmp_sfa(alpha: &Alphabet, needle: &[u8]) -> Sfa {
    assert!(!needle.is_empty(), "attack needle must be non-empty");
    let m = needle.len();
    // KMP failure function.
    let mut fail = vec![0usize; m];
    let mut k = 0;
    for i in 1..m {
        while k > 0 && needle[i] != needle[k] {
            k = fail[k - 1];
        }
        if needle[i] == needle[k] {
            k += 1;
        }
        fail[i] = k;
    }
    let kmp_next = |mut j: usize, c: u8| -> usize {
        if j == m {
            return m; // absorbing once matched
        }
        while j > 0 && c != needle[j] {
            j = fail[j - 1];
        }
        if c == needle[j] {
            j += 1;
        }
        j
    };

    let n_states = m + 1;
    let mut accept = vec![false; n_states];
    accept[m] = true;
    let mut delta: Vec<Vec<(BytePred, StateId)>> = Vec::with_capacity(n_states);
    for st in 0..n_states {
        if st == m {
            delta.push(vec![(BytePred::any(), m)]); // stay accepted
            continue;
        }
        let mut row = Vec::with_capacity(alpha.len());
        for a in 0..alpha.len() {
            row.push((alpha.guard(a), kmp_next(st, alpha.byte_of(a))));
        }
        delta.push(row);
    }
    Sfa::new(0, accept, delta)
}

/// A regular over-approximation of an attack class: any word whose
/// concretization contains one of `needles` (CRS-class detection is
/// substring/regex anchored, so this is faithful). Empty `needles`
/// ⇒ the empty language (no attack ⇒ nothing to mine, never a false
/// bypass).
#[must_use]
pub fn attack_grammar(alpha: &Alphabet, needles: &[&[u8]]) -> Sfa {
    let mut it = needles.iter();
    let Some(first) = it.next() else {
        // Empty language: one non-accepting absorbing state.
        return Sfa::new(0, vec![false], vec![vec![(BytePred::any(), 0)]]);
    };
    let mut g = kmp_sfa(alpha, first);
    for n in it {
        g = g.union(&kmp_sfa(alpha, n));
    }
    g
}

/// Mine up to `max` bypasses for `attack` against `learned`, shortest
/// (provably minimal) first, none longer than `max_len`. Each result
/// is a concrete byte string the *modelled* WAF passes and that is an
/// attack — replay it against the real oracle to confirm zero
/// model↔reality gap (the truth-suite does exactly that).
#[must_use]
pub fn mine_bypasses(learned: &Sfa, attack: &Sfa, max: usize, max_len: usize) -> Vec<Vec<u8>> {
    learned.intersect(attack).enumerate_accepted(max, max_len)
}

/// The single provably-minimal bypass (length-then-lex minimum), or
/// `None` if the model has no hole for this attack class.
#[must_use]
pub fn minimal_bypass(learned: &Sfa, attack: &Sfa) -> Option<Vec<u8>> {
    learned.intersect(attack).shortest_accepted()
}

/// The transferable WAF-diff: inputs exactly one of the two learned
/// models passes (a Cloudflare-vs-CRS hole map), shortest first.
#[must_use]
pub fn waf_diff(a: &Sfa, b: &Sfa, max: usize, max_len: usize) -> Vec<Vec<u8>> {
    a.difference(b)
        .union(&b.difference(a))
        .enumerate_accepted(max, max_len)
}
