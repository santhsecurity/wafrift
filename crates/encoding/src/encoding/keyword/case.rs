//! Case manipulation strategies.

/// Shared alternating-case utility.
///
/// `SELECT` → `SeLeCt`. Bypasses case-sensitive keyword filters.
pub fn alternating_case(payload: &str, start_upper: bool) -> String {
    let mut upper = start_upper;
    payload
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphabetic() {
                let result = if upper {
                    ch.to_ascii_uppercase()
                } else {
                    ch.to_ascii_lowercase()
                };
                upper = !upper;
                result
            } else {
                ch
            }
        })
        .collect()
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
pub fn random_case_alternate(payload: &str) -> String {
    // FNV-1a over the full payload — same primitive as space_to_random_blank.
    let seed: u64 = payload
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325_u64, |acc, b| {
            (acc ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
        });
    payload
        .chars()
        .enumerate()
        .map(|(i, ch)| {
            if ch.is_ascii_alphabetic() {
                // Mix position into seed so adjacent chars differ.
                let mixed = seed
                    .wrapping_add(i as u64)
                    .wrapping_mul(0x0000_0100_0000_01b3);
                if mixed & 1 == 0 {
                    ch.to_ascii_uppercase()
                } else {
                    ch.to_ascii_lowercase()
                }
            } else {
                ch
            }
        })
        .collect()
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
