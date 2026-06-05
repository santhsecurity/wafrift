//! Pure, deterministic, dependency-free hashing primitives shared
//! across the workspace.
//!
//! ## FNV-1a 64-bit
//!
//! Pre-pass-21 each consumer maintained its own copy of the FNV-1a-64
//! constants and inner loop (`evolution::h1_dedup`,
//! `cli::cache_diff_cmd`, `cli::corpus_recorder`). All three were
//! byte-for-byte identical. A future tweak — switching seed, swapping
//! to a SIMD variant, adding a salt — would have had to land in three
//! places synchronously or silently diverge. R57 pass-21 §7 DEDUP
//! collapses them to this single canonical home.
//!
//! ### Why FNV-1a-64 and not (say) AHash / xxhash3 / SipHash
//!
//! - **Deterministic across builds and across processes.** AHash is
//!   seeded from process entropy by default; xxhash3 has a streaming
//!   state. Both can produce different outputs on the same input
//!   between runs, which breaks the dedup contracts these call sites
//!   need (a "saved corpus" must hash-match on the next start).
//! - **Dependency-free.** wafrift-types is leaf-level and must not pull
//!   in a hash crate.
//! - **Adequately fast.** All consumers fingerprint bodies / canonical
//!   forms a few hundred times per scan, not in a hot path.
//!
//! The hash is NOT cryptographic. Do not use for signatures, tokens,
//! or anything an attacker is incentivised to forge.

/// FNV-1a 64-bit offset basis (RFC reference value).
pub const FNV_OFFSET_64: u64 = 0xcbf2_9ce4_8422_2325;

/// FNV-1a 64-bit prime (RFC reference value).
pub const FNV_PRIME_64: u64 = 0x100_0000_01b3;

/// Hash a byte slice with FNV-1a-64 in a single call.
///
/// `hash(b"") == FNV_OFFSET_64` per the algorithm contract — the empty
/// input is the zero element of the hash, not a sentinel.
#[must_use]
pub fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h = FNV_OFFSET_64;
    for &b in bytes {
        h = fnv1a_64_step(h, b);
    }
    h
}

/// Single-byte step of FNV-1a-64. Exposed for streaming callers (e.g.
/// `evolution::h1_dedup`'s incremental fingerprint over a tokenised
/// request, where each segment is fed independently).
///
/// `pub const fn` so it can sit in a const context if needed.
#[inline]
#[must_use]
pub const fn fnv1a_64_step(h: u64, b: u8) -> u64 {
    (h ^ (b as u64)).wrapping_mul(FNV_PRIME_64)
}

/// Streaming variant — fold `bytes` into the running `h` in place.
/// Equivalent to `*h = bytes.iter().fold(*h, fnv1a_64_step)` but
/// preserves the existing call site shape from `evolution::h1_dedup`.
pub fn fnv1a_64_extend(h: &mut u64, bytes: &[u8]) {
    for &b in bytes {
        *h = fnv1a_64_step(*h, b);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_hashes_to_offset_basis() {
        // Algorithm contract: empty bytes produce the offset basis
        // unchanged. Pinning this guards against an accidental
        // "always-start-fresh" rewrite that would invalidate every
        // serialised corpus the moment it shipped.
        assert_eq!(fnv1a_64(b""), FNV_OFFSET_64);
    }

    #[test]
    fn single_byte_matches_canonical_table() {
        // Reference values from the FNV homepage test vector table
        // (http://www.isthe.com/chongo/tech/comp/fnv/) — the canonical
        // 64-bit FNV-1a outputs for "a" and "foobar". Pre-fix the
        // foobar value was 0x85848004_8634e0f5, which is not the
        // FNV-1a-64 of any common input — a transcription error that
        // sat dormant because the algorithm was correct and the only
        // observer was this assertion. If any future "optimisation"
        // diverges, this test fires.
        assert_eq!(fnv1a_64(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a_64(b"foobar"), 0x8594_4171_f739_67e8);
    }

    #[test]
    fn step_and_extend_agree_with_oneshot() {
        // Streaming the same bytes byte-by-byte must produce the same
        // hash as a single-shot call. Pre-fix the three copies of this
        // function each implemented one or the other shape; this test
        // pins the equivalence so a future tweak to one doesn't drift
        // from the other.
        let input = b"the quick brown fox jumps over the lazy dog";
        let oneshot = fnv1a_64(input);
        let mut streaming = FNV_OFFSET_64;
        fnv1a_64_extend(&mut streaming, input);
        assert_eq!(oneshot, streaming);

        let mut by_step = FNV_OFFSET_64;
        for &b in input {
            by_step = fnv1a_64_step(by_step, b);
        }
        assert_eq!(oneshot, by_step);
    }

    #[test]
    fn fnv1a_64_is_deterministic_across_calls() {
        // Anti-rig: confirm no hidden state / entropy leak — same input
        // always hashes the same. If we ever swap to AHash and forget
        // this test, the corpus-dedup contract silently breaks.
        let input = b"wafrift-canonical-form";
        assert_eq!(fnv1a_64(input), fnv1a_64(input));
    }

    #[test]
    fn extend_from_offset_matches_oneshot_no_prefix_drift() {
        // Anti-rig: extending an empty accumulator must produce the
        // same hash as a one-shot call. Catches a future bug where
        // `_extend` starts with a different seed than `fnv1a_64`.
        let input = b"some-arbitrary-canonical-bytes";
        let mut acc = FNV_OFFSET_64;
        fnv1a_64_extend(&mut acc, input);
        assert_eq!(acc, fnv1a_64(input));
    }
}
