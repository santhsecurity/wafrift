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
pub fn case_alternate(payload: &str) -> String {
    alternating_case(payload, true)
}

/// Random case alternation — unpredictable mixed-case output.
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
}
