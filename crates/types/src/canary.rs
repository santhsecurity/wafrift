//! Per-probe correlation token shared by every wafrift evasion
//! module that emits wire-format payloads.
//!
//! Originally lived in `wafrift-smuggling::safety::Canary`, lifted
//! here 2026-05-27 so the new content-type / http3-evasion smuggle
//! modules can carry the same correlation surface without a
//! cross-crate dependency on `wafrift-smuggling` (which would be a
//! LAW 8 layering violation — smuggling is a leaf crate, not a
//! workspace primitive).
//!
//! ## What a Canary is for
//!
//! When wafrift fires N variants of the same logical probe at a
//! target, the only way to correlate a server-side response to the
//! specific variant that triggered it is a per-variant token. The
//! token MUST be:
//!
//! - **High-entropy** (128 bits is more than enough)
//! - **URL-safe + header-safe** (alphanumeric only, no escape worries)
//! - **Caller-opaque** (no brand, no semantic structure — anything
//!   structured would be a fingerprint surface)
//!
//! The 16-character base62 token below satisfies all three.

use crate::pick::pick_from_rng;

/// 16-character alphanumeric correlation token. Used by every
/// wafrift probe builder so logs and oracles can attribute a
/// server-side response back to the specific probe variant that
/// produced it.
///
/// The token is opaque to WAFs (no brand) and high-entropy (≈ 95
/// bits drawn from the 62-symbol alphabet) — high enough that no
/// two probes in any plausible scan campaign collide.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Canary {
    /// The 16-char base62 token.
    pub token: String,
}

impl Canary {
    /// Generate a random 16-character alphanumeric canary.
    #[must_use]
    pub fn generate() -> Self {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut rng = rand::thread_rng();
        let token: String = (0..16)
            .map(|_| pick_from_rng(CHARSET, b'A', &mut rng) as char)
            .collect();
        Self { token }
    }
}

impl Default for Canary {
    fn default() -> Self {
        Self::generate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn generate_produces_16_chars() {
        let c = Canary::generate();
        assert_eq!(c.token.len(), 16, "canary must be exactly 16 chars");
    }

    #[test]
    fn generate_alphanumeric_only() {
        // Anti-rig: the token MUST stay alphanumeric so it can ride
        // safely through HTTP headers, URL query, JSON, and shell
        // contexts without escaping. A regression that introduces
        // any other byte class would silently break callers that
        // splice the token into a URL or header.
        let c = Canary::generate();
        for ch in c.token.chars() {
            assert!(
                ch.is_ascii_alphanumeric(),
                "canary contained non-alphanumeric char: {ch:?} (token: {:?})",
                c.token
            );
        }
    }

    #[test]
    fn generate_distinct_across_many_calls() {
        // 1000 canaries must be unique with overwhelming probability
        // (entropy is ~95 bits over a 16-char base62 token). A
        // regression that seeds the RNG to a constant would collapse
        // all canaries to one value and this test catches it.
        let mut seen: HashSet<String> = HashSet::new();
        for _ in 0..1000 {
            seen.insert(Canary::generate().token);
        }
        assert!(
            seen.len() >= 999,
            "1000 canaries collapsed to {} unique — RNG seeded constant?",
            seen.len()
        );
    }

    #[test]
    fn default_equivalent_to_generate() {
        let a = Canary::default();
        let b = Canary::generate();
        // Both must be 16 chars and alphanumeric. The values differ
        // (each call randomises) but the shape is identical.
        assert_eq!(a.token.len(), b.token.len());
        for ch in a.token.chars().chain(b.token.chars()) {
            assert!(ch.is_ascii_alphanumeric());
        }
    }
}
