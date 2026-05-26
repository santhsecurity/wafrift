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

/// KMP "contains `needle`" recognizer, lifted to an [`Sfa`] whose
/// guards are fine-grained enough to be exact in the byte domain.
///
/// # Correctness: handling catch-all needle bytes (F-MINE-01)
///
/// The original code built one SFA transition per abstract alphabet class.
/// For a *distinguished* class that contains exactly one byte `b`, using
/// `b` as the KMP probe is correct. For the *catch-all* class, however,
/// using the representative byte (e.g. `Z`) as the probe is WRONG when
/// the needle contains bytes that belong to the catch-all class: the
/// representative `Z` ≠ the needle byte, so `kmp_next` never advances
/// past that needle position, and the SFA accepts zero words — zero
/// bypasses are mined.
///
/// The fix refines the catch-all class at each KMP state. For each
/// needle position `st`, if `needle[st]` belongs to the catch-all class
/// we emit **two** transitions instead of one:
///
/// 1. Guard = `{needle[st]}` → `kmp_next(st, needle[st])` = `st + 1`.
/// 2. Guard = catch-all-guard **minus** `{needle[st]}` →
///    `kmp_next(st, non_needle_byte)` (failure-function path).
///
/// The resulting SFA is no longer strictly aligned with the caller's
/// abstract alphabet, but it is still deterministic and total (the two
/// guards for the split catch-all are disjoint and their union covers
/// the original catch-all class exactly). The product construction in
/// [`Sfa::product`] works at the minterm level, so the intersection with
/// a learned model — which IS built on the original abstract alphabet —
/// is still exact.
///
/// Distinguished classes are not split: each contains exactly one byte,
/// so the probe is always correct.
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
    let catch_all_idx = alpha.catch_all();
    let mut delta: Vec<Vec<(BytePred, StateId)>> = Vec::with_capacity(n_states);
    for st in 0..n_states {
        if st == m {
            delta.push(vec![(BytePred::any(), m)]); // stay accepted
            continue;
        }
        // At each KMP state we need to know the set of needle bytes that are
        // reachable via the catch-all guard. Collect them up front so we can
        // split the catch-all without emitting duplicate singleton guards.
        //
        // We compute, for each possible KMP successor state `t`, the set of
        // catch-all bytes that lead to `t`. Then we emit one guarded
        // transition per distinct successor, with the guard being the union
        // of those bytes restricted to the catch-all class.
        //
        // For distinguished classes: one guard = one byte, no split needed.

        let mut row: Vec<(BytePred, StateId)> = Vec::with_capacity(alpha.len() + 1);

        // Distinguished classes: each contains exactly one byte.
        for a in 0..alpha.len() {
            if a == catch_all_idx {
                continue; // handled below
            }
            let b = alpha.byte_of(a);
            row.push((alpha.guard(a), kmp_next(st, b)));
        }

        // Catch-all class: split into one sub-guard per distinct KMP target.
        // We enumerate all 256 bytes in the catch-all predicate, group them
        // by their KMP successor, and emit one sub-guard per group.
        // This is exact — the sub-guards are pairwise disjoint and their
        // union is the original catch-all guard.
        let catch_guard = alpha.guard(catch_all_idx);
        // Map: kmp_next_state → accumulated BytePred.
        let mut groups: std::collections::HashMap<usize, BytePred> =
            std::collections::HashMap::new();
        for b in 0u8..=255u8 {
            if catch_guard.contains(b) {
                let t = kmp_next(st, b);
                groups.entry(t).or_insert_with(BytePred::none).insert(b);
            }
        }
        for (t, g) in groups {
            row.push((g, t));
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
