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

/// Random case alternation — unpredictable mixed-case output.
///
/// **Idempotency.** NOT idempotent. Each application re-randomises the
/// case of every alphabetic character independently.
pub fn random_case_alternate(payload: &str) -> String {
    payload
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphabetic() {
                if rand::random::<bool>() {
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
    fn random_case_non_deterministic() {
        let a = random_case_alternate("SELECT");
        let b = random_case_alternate("SELECT");
        // Very unlikely to match by chance, but allow for it
        assert_eq!(a.to_ascii_lowercase(), "select");
        assert_eq!(b.to_ascii_lowercase(), "select");
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
    fn random_case_not_idempotent() {
        // A single `a != b` pair is FLAKY: for an n-letter word the two
        // independent random casings collide with probability 1/2^n
        // (~1.6% for "SELECT") — a ~1-in-64 spurious CI failure. The
        // real contract is that `random_case_alternate` re-randomises,
        // i.e. its output is not constant. Assert ≥2 distinct outputs
        // across many trials: P(all identical) = (1/2^6)^(N-1) → nil
        // for N=64, so this is deterministic in practice.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            seen.insert(random_case_alternate("SELECT"));
            if seen.len() >= 2 {
                return;
            }
        }
        panic!(
            "random_case_alternate produced only one distinct casing of \
             \"SELECT\" across 64 trials — it is not re-randomising"
        );
    }
}
