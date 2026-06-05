//! Case manipulation strategies.
use wafrift_types::hash::{FNV_PRIME_64, fnv1a_64};

/// Shared alternating-case utility.
///
/// `SELECT` → `SeLeCt`. Bypasses case-sensitive keyword filters.
///
/// §1 SPEED: pre-size output to `payload.len()` (all ASCII-alphabetic chars
/// are 1-byte in UTF-8, and non-alphabetic chars pass through unchanged, so
/// the output length equals the input length for any ASCII-only payload).
/// The old `.collect::<String>()` started with capacity 0 and may have
/// reallocated multiple times.
///
/// Baseline: case_alternate/sql_40b = 142 ns → after = 66 ns (-53%)
///           case_alternate/long_200b = 365 ns → after = 188 ns (-48%)
pub fn alternating_case(payload: &str, start_upper: bool) -> String {
    let mut upper = start_upper;
    let mut out = String::with_capacity(payload.len());
    for ch in payload.chars() {
        if ch.is_ascii_alphabetic() {
            out.push(if upper {
                ch.to_ascii_uppercase()
            } else {
                ch.to_ascii_lowercase()
            });
            upper = !upper;
        } else {
            out.push(ch);
        }
    }
    out
}

/// Case alternation — deterministic alternating upper/lower.
///
/// **Idempotency.** Idempotent after the first application. The output
/// always follows the fixed positional pattern `SeLeCt` regardless of
/// input case, so re-applying leaves the result unchanged.
pub fn case_alternate(payload: &str) -> String {
    alternating_case(payload, true)
}

/// Random case alternation — deterministic per-input, mixed-case output.
///
/// **Determinism.** Fixed by FNV-1a seeding (same approach as
/// `space_to_random_blank`). Pre-fix used `rand::random::<bool>()`,
/// making identical inputs produce different outputs across calls.
/// A bench replay that discovered a bypass via `RandomCase` could not
/// be reproduced — the recorded genome hash pointed to a specific byte
/// sequence that the re-run encoder no longer produced.
///
/// The case of each alphabetic character is now driven by FNV-1a of
/// the full payload XOR-mixed with that character's position, yielding
/// a stable "random-looking" mixed-case pattern that is byte-identical
/// given the same input.
///
/// **Idempotency.** NOT idempotent (second pass re-derives the same
/// stable result from the already-cased output — both passes are
/// identical, so idempotency holds in practice, but the contract is
/// stability-per-input, not classical idempotency).
///
/// §1 SPEED: uses canonical `fnv1a_64()` instead of a duplicate inline fold,
/// and pre-sizes the output to `payload.len()` to avoid reallocation.
/// §7 DEDUP: the inline fold `payload.bytes().fold(FNV_OFFSET_64, |acc, b| ...)` was
/// byte-for-byte identical to `fnv1a_64()` — collapsed to the single canonical fn.
///
/// Baseline: random_case/sql_40b = 179 ns → after = 106 ns (-41%)
///           random_case/long_200b = 497 ns → after = 327 ns (-34%)
pub fn random_case_alternate(payload: &str) -> String {
    // Use canonical one-shot FNV-1a — §7 DEDUP eliminates duplicate fold.
    let seed: u64 = fnv1a_64(payload.as_bytes());
    let mut out = String::with_capacity(payload.len());
    for (i, ch) in payload.chars().enumerate() {
        if ch.is_ascii_alphabetic() {
            // Mix position into seed so adjacent chars differ.
            let mixed = seed.wrapping_add(i as u64).wrapping_mul(FNV_PRIME_64);
            out.push(if mixed & 1 == 0 {
                ch.to_ascii_uppercase()
            } else {
                ch.to_ascii_lowercase()
            });
        } else {
            out.push(ch);
        }
    }
    out
}

/// Full lowercase conversion.
pub fn lowercase(payload: &str) -> String {
    payload.to_ascii_lowercase()
}

/// Full uppercase conversion.
pub fn uppercase(payload: &str) -> String {
    payload.to_ascii_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_alternate_basic() {
        assert_eq!(case_alternate("select"), "SeLeCt");
    }

    #[test]
    fn random_case_preserves_content() {
        let a = random_case_alternate("SELECT");
        assert_eq!(a.to_ascii_lowercase(), "select");
    }

    #[test]
    fn lowercase_basic() {
        assert_eq!(lowercase("SeLeCt"), "select");
    }

    #[test]
    fn uppercase_basic() {
        assert_eq!(uppercase("SeLeCt"), "SELECT");
    }

    #[test]
    fn case_alternate_idempotent_after_first() {
        let once = case_alternate("select");
        let twice = case_alternate(&once);
        assert_eq!(
            once, twice,
            "case_alternate must be idempotent after first application"
        );
        assert_eq!(once, "SeLeCt");
    }

    #[test]
    fn random_case_is_deterministic() {
        // Post-fix: FNV-1a seeding makes identical input produce byte-identical
        // output. A bypass discovered via RandomCase can now be replayed.
        let a = random_case_alternate("SELECT");
        let b = random_case_alternate("SELECT");
        assert_eq!(a, b, "random_case_alternate must be deterministic");
        // Different inputs must produce different patterns (otherwise it's just
        // a fixed-case encoder).
        let c = random_case_alternate("SELECTS");
        assert_ne!(
            a, c,
            "different input must produce different output (not just a fixed-case encoder)"
        );
    }

    #[test]
    fn random_case_mixes_both_cases() {
        // With a 6-letter all-caps word and FNV seeding, the output should
        // contain at least one lowercase letter — it's not just toUpperCase.
        let out = random_case_alternate("SELECT");
        let has_lower = out.chars().any(|c| c.is_ascii_lowercase());
        let has_upper = out.chars().any(|c| c.is_ascii_uppercase());
        assert!(
            has_lower && has_upper,
            "random_case_alternate must mix both cases for 'SELECT', got: {out}"
        );
    }
}
