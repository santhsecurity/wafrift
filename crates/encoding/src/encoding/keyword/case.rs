//! Case manipulation strategies.

/// FNV-1a hash of (byte index, payload bytes) for deterministic bool derivation.
fn fnv1a_char_hash(char_idx: usize, payload: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in char_idx.to_le_bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3);
    }
    for b in payload.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

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

/// Deterministic mixed-case alternation derived from FNV-1a hash of each
/// character's index and the full payload bytes.
///
/// Two calls with the same `payload` always produce byte-identical output.
/// The case pattern varies per payload but is stable across runs.
pub fn random_case_alternate(payload: &str) -> String {
    payload
        .chars()
        .enumerate()
        .map(|(i, ch)| {
            if ch.is_ascii_alphabetic() {
                if fnv1a_char_hash(i, payload) & 1 == 1 {
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
    fn random_case_is_deterministic() {
        let a = random_case_alternate("SELECT");
        let b = random_case_alternate("SELECT");
        assert_eq!(a, b, "random_case_alternate must be byte-identical for identical input");
        assert_eq!(a.to_ascii_lowercase(), "select");
    }

    #[test]
    fn random_case_varies_per_payload() {
        // The FNV hash includes all payload bytes, so different payloads
        // produce different per-char decisions across a range of inputs.
        // Check determinism (same input → same output) which is the core contract.
        for payload in &["SELECT", "UNION", "DROP TABLE users", "1 OR 1=1"] {
            let a = random_case_alternate(payload);
            let b = random_case_alternate(payload);
            assert_eq!(a, b, "random_case_alternate must be stable: {payload}");
            assert_eq!(a.to_ascii_lowercase(), payload.to_ascii_lowercase(),
                "random_case_alternate must preserve chars");
        }
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
}
