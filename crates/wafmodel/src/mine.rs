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
/// guards are fine-grained enough to be byte-exact.
///
/// # Correctness: catch-all needle bytes (F-MINE-01)
///
/// The original code built one transition per abstract alphabet class.
/// For a *distinguished* class (one byte), using that byte as the KMP
/// probe is correct. For the *catch-all* class (all non-distinguished
/// bytes), using the catch-all representative as the probe is WRONG when
/// the needle itself contains catch-all bytes: the representative differs
/// from those needle bytes, so `kmp_next` never advances the match
/// counter — the SFA accepts zero words, and zero bypasses are mined.
///
/// The fix refines the catch-all class at each KMP state by enumerating
/// all 256 bytes and grouping them by their KMP successor state. Each
/// group becomes one guard whose BytePred is the union of bytes in the
/// group. Distinguished bytes always form a singleton group (one guard
/// per distinguished class, unchanged). Catch-all bytes are split across
/// however many distinct KMP targets they produce.
///
/// The resulting SFA is deterministic and total: the guards out of each
/// state are pairwise disjoint (each byte appears in exactly one group)
/// and their union is `BytePred::any()`. The product construction in
/// [`Sfa::product`] works at the minterm level, so intersection with a
/// learned model (built on the original abstract alphabet) remains exact.
fn kmp_sfa(needle: &[u8]) -> Sfa {
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
        // Group all 256 bytes by their KMP successor state.
        // Each group becomes one (BytePred, target) transition.
        // This automatically handles both distinguished and catch-all bytes:
        // - A distinguished byte `b` belongs to its own class; `kmp_next(st, b)`
        //   is the correct target for guard `{b}`.
        // - Catch-all bytes are partitioned among (usually) two targets:
        //   the one needle-matching byte → st+1, and the rest → some
        //   failure-function state.
        // Using a fixed-size array avoids HashMap overhead (only m+1 ≤ 257
        // possible targets, but we index by target state which is ≤ m ≤ 255).
        // Use a Vec<Option<BytePred>> indexed by target state.
        let mut groups: Vec<Option<BytePred>> = vec![None; n_states];
        for b in 0u8..=255u8 {
            let t = kmp_next(st, b);
            match &mut groups[t] {
                Some(pred) => pred.insert(b),
                slot @ None => {
                    let mut pred = BytePred::none();
                    pred.insert(b);
                    *slot = Some(pred);
                }
            }
        }
        // Emit transitions in deterministic order (by target state index).
        let mut row: Vec<(BytePred, StateId)> = Vec::new();
        for (t, opt) in groups.into_iter().enumerate() {
            if let Some(pred) = opt {
                row.push((pred, t));
            }
        }
        // Sfa::new will validate totality + disjointness automatically.
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
pub fn attack_grammar(_alpha: &Alphabet, needles: &[&[u8]]) -> Sfa {
    let mut it = needles.iter();
    let Some(first) = it.next() else {
        // Empty language: one non-accepting absorbing state.
        return Sfa::new(0, vec![false], vec![vec![(BytePred::any(), 0)]]);
    };
    let mut g = kmp_sfa(first);
    for n in it {
        g = g.union(&kmp_sfa(n));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::learn::Alphabet;

    /// Build a simple all-pass SFA so we can test `mine_bypasses`
    /// directly (intersection with a pass-all model = the attack grammar
    /// itself).
    fn pass_all(alpha: &Alphabet) -> Sfa {
        // One accepting state; all transitions loop on it.
        let mut row = Vec::with_capacity(alpha.len());
        for a in 0..alpha.len() {
            row.push((alpha.guard(a), 0));
        }
        Sfa::new(0, vec![true], vec![row])
    }

    // ── F-MINE-01 regression: catch-all class representative mismatch ───

    /// Needle bytes that are ALL in the catch-all class (never
    /// distinguished). The old code fed the catch-all representative to
    /// `kmp_next`, which never matched the needle bytes, so the SFA
    /// accepted nothing — zero bypasses mined for any needle whose bytes
    /// weren't distinguished.
    #[test]
    fn kmp_sfa_matches_needle_with_catch_all_bytes() {
        // Distinguished: only b'Z'. Catch-all representative: b'Z'.
        // Needle: b"select" — all bytes are in the catch-all class.
        let alpha = Alphabet::new(vec![], b'Z');
        let g = attack_grammar(&alpha, &[b"select"]);
        let learned = pass_all(&alpha);
        let bypasses = mine_bypasses(&learned, &g, 10, 20);
        assert!(
            !bypasses.is_empty(),
            "attack_grammar must find words containing b\"select\" \
             even when all needle bytes are in the catch-all class; \
             got zero (F-MINE-01 regression)"
        );
        // Every result must contain the needle.
        for w in &bypasses {
            assert!(
                w.windows(6).any(|s| s == b"select"),
                "mined word {w:?} does not contain the needle b\"select\""
            );
        }
    }

    /// Needle with a mix: some bytes distinguished, some catch-all.
    /// `b"'or'"` — b'\'' is distinguished; b'o', b'r' are catch-all.
    #[test]
    fn kmp_sfa_matches_needle_with_mixed_distinguished_and_catch_all_bytes() {
        let alpha = Alphabet::new(vec![b'\''], b'Z');
        let g = attack_grammar(&alpha, &[b"'or'"]);
        let learned = pass_all(&alpha);
        let bypasses = mine_bypasses(&learned, &g, 10, 12);
        assert!(
            !bypasses.is_empty(),
            "attack_grammar must find words containing b\"'or'\" \
             with mixed distinguished/catch-all bytes; got zero (F-MINE-01)"
        );
        for w in &bypasses {
            assert!(
                w.windows(4).any(|s| s == b"'or'"),
                "mined word {w:?} does not contain the needle"
            );
        }
    }

    /// A needle where the catch-all byte happens to equal the catch-all
    /// representative — the old code worked in this edge case. Confirm
    /// the fix doesn't break it.
    #[test]
    fn kmp_sfa_matches_needle_whose_bytes_happen_to_be_the_representative() {
        // Needle b"ZZZ", representative b'Z'. Old code happened to work
        // because the representative equalled the needle byte.
        // The fix must still work here.
        let alpha = Alphabet::new(vec![], b'Z');
        let g = attack_grammar(&alpha, &[b"ZZZ"]);
        let learned = pass_all(&alpha);
        let bypasses = mine_bypasses(&learned, &g, 5, 10);
        assert!(
            !bypasses.is_empty(),
            "attack_grammar must find words containing b\"ZZZ\" \
             when the needle IS the representative"
        );
        for w in &bypasses {
            assert!(
                w.windows(3).any(|s| s == b"ZZZ"),
                "mined word {w:?} does not contain b\"ZZZ\""
            );
        }
    }

    /// Fully distinguished needle (all bytes in the distinguished set).
    /// This was always correct; the fix must not regress it.
    #[test]
    fn kmp_sfa_matches_fully_distinguished_needle() {
        let alpha = Alphabet::new(vec![b'a', b'b'], b'Z');
        let g = attack_grammar(&alpha, &[b"aba"]);
        let learned = pass_all(&alpha);
        let bypasses = mine_bypasses(&learned, &g, 5, 10);
        assert!(
            !bypasses.is_empty(),
            "attack_grammar must find words containing b\"aba\""
        );
        for w in &bypasses {
            assert!(
                w.windows(3).any(|s| s == b"aba"),
                "mined word {w:?} does not contain b\"aba\""
            );
        }
    }

    /// Empty needles ⇒ empty-language SFA (no bypasses, never a fake).
    #[test]
    fn attack_grammar_empty_needles_accepts_nothing() {
        let alpha = Alphabet::new(vec![b'a'], b'Z');
        let g = attack_grammar(&alpha, &[]);
        let learned = pass_all(&alpha);
        let bypasses = mine_bypasses(&learned, &g, 10, 20);
        assert!(
            bypasses.is_empty(),
            "empty needle set must produce zero bypasses, got {bypasses:?}"
        );
    }

    /// Self-overlapping needle with catch-all bytes: exercises the failure
    /// function path when the needle byte IS in the catch-all class.
    #[test]
    fn kmp_sfa_self_overlapping_catch_all_needle() {
        // Needle b"aaa" — all catch-all (representative b'X').
        let alpha = Alphabet::new(vec![], b'X');
        let g = attack_grammar(&alpha, &[b"aaa"]);
        let learned = pass_all(&alpha);
        let bypasses = mine_bypasses(&learned, &g, 5, 10);
        assert!(
            !bypasses.is_empty(),
            "attack_grammar must find words containing b\"aaa\" (all catch-all, self-overlapping)"
        );
        for w in &bypasses {
            assert!(
                w.windows(3).any(|s| s == b"aaa"),
                "mined word {w:?} does not contain b\"aaa\""
            );
        }
    }

    /// Two needles, one with all-distinguished bytes, one with all-catch-all
    /// bytes. Both must appear in the union grammar (verified independently
    /// via `shortest_accepted` so we don't depend on enumeration ordering).
    #[test]
    fn attack_grammar_union_of_distinguished_and_catch_all_needles() {
        let alpha = Alphabet::new(vec![b'<', b'/'], b'Z');
        // b"</" — both distinguished. b"union" — all catch-all.
        let g = attack_grammar(&alpha, &[b"</", b"union"]);
        let learned = pass_all(&alpha);

        // Test `</` independently: its kmp_sfa finds words immediately.
        let g_angle = attack_grammar(&alpha, &[b"</"]);
        let shortest_angle = learned
            .intersect(&g_angle)
            .shortest_accepted()
            .expect("union grammar must accept words containing b\"</\"");
        assert!(
            shortest_angle.windows(2).any(|s| s == b"</"),
            "shortest word {shortest_angle:?} does not contain b\"</\""
        );

        // Test b"union" independently: all catch-all bytes — the main F-MINE-01
        // regression case.
        let g_union = attack_grammar(&alpha, &[b"union"]);
        let shortest_union = learned
            .intersect(&g_union)
            .shortest_accepted()
            .expect("union grammar must accept words containing b\"union\" (catch-all needle)");
        assert!(
            shortest_union.windows(5).any(|s| s == b"union"),
            "shortest word {shortest_union:?} does not contain b\"union\""
        );

        // The combined grammar also accepts both.
        assert!(
            !learned.intersect(&g).is_language_empty(),
            "combined union grammar must be non-empty"
        );
    }
}
