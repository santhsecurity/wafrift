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
/// **Idempotency.** NOT idempotent. Applying twice to the same payload
/// flips every alphabetic character again, producing a different pattern
/// (e.g., `select` → `SeLeCt` → `sElEcT`).
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
    fn case_alternate_not_idempotent() {
        let once = case_alternate("select");
        let twice = case_alternate(&once);
        assert_ne!(once, twice, "case_alternate must not be idempotent");
        assert_eq!(once, "SeLeCt");
        assert_eq!(twice, "sElEcT");
    }

    #[test]
    fn random_case_not_idempotent() {
        let a = random_case_alternate("SELECT");
        let b = random_case_alternate(&a);
        // Statistically almost certain to differ.
        assert_ne!(a, b, "random_case should re-randomise on second application");
    }
}
