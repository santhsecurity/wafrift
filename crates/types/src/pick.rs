//! Random selection from a static pool — workspace-wide primitive.
//!
//! Several wafrift smuggle modules carry a small pool of "neutral"
//! values (boundary prefixes, capsule type values, control bytes,
//! field names) that they sample from per-call to defeat signature
//! WAFs that pin a specific literal. Before this module existed the
//! sampling idiom was duplicated five times across five files using
//! two distinct styles (`SliceRandom::choose` and `Rng::gen_range`).
//! Extracted here so the contract is in one place:
//!
//! - Empty pool returns the caller-supplied fallback (never panics).
//! - Non-empty pool returns one uniformly-sampled entry.
//! - Callers can use `rand::thread_rng()` or pass their own seeded RNG.
//!
//! ## Usage
//!
//! ```
//! use wafrift_types::pick::pick_from;
//!
//! const BOUNDARY_PREFIXES: &[&str] = &[
//!     "----WebKitFormBoundary",
//!     "----formdata-undici-",
//! ];
//! let prefix = pick_from(BOUNDARY_PREFIXES, "----default");
//! assert!(BOUNDARY_PREFIXES.contains(&prefix) || prefix == "----default");
//! ```

use rand::Rng;

/// Sample one entry from `pool` uniformly at random. Returns
/// `fallback` if the pool is empty. `T: Copy` lets the call site
/// drop the `&` indirection callers had to write before this
/// primitive existed.
#[must_use]
pub fn pick_from<T: Copy>(pool: &[T], fallback: T) -> T {
    let mut rng = rand::thread_rng();
    pick_from_rng(pool, fallback, &mut rng)
}

/// Sample one entry from `pool` uniformly at random using `rng`.
///
/// Returns `fallback` if the pool is empty.
#[must_use]
pub fn pick_from_rng<T: Copy, R: Rng + ?Sized>(pool: &[T], fallback: T, rng: &mut R) -> T {
    match pick_ref_from_rng(pool, rng) {
        Some(value) => *value,
        None => fallback,
    }
}

/// Sample one borrowed entry from `pool` uniformly at random using `rng`.
///
/// Returns `None` if the pool is empty.
#[must_use]
pub fn pick_ref_from_rng<'a, T, R: Rng + ?Sized>(pool: &'a [T], rng: &mut R) -> Option<&'a T> {
    if pool.is_empty() {
        return None;
    }
    Some(&pool[rng.gen_range(0..pool.len())])
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};
    use std::collections::HashSet;

    #[test]
    fn empty_pool_returns_fallback() {
        let empty: &[&str] = &[];
        assert_eq!(pick_from(empty, "default"), "default");
        let empty_u8: &[u8] = &[];
        assert_eq!(pick_from(empty_u8, 0x42), 0x42);
    }

    #[test]
    fn single_entry_pool_always_returns_that_entry() {
        let single = &["only"];
        for _ in 0..50 {
            assert_eq!(pick_from(single, "fallback"), "only");
        }
    }

    #[test]
    fn many_calls_eventually_hit_every_pool_entry() {
        // 1000 picks from a 5-entry pool must (with overwhelming
        // probability) hit every entry. Anti-rig: a regression that
        // accidentally biased to one entry would fail here.
        let pool = &["a", "b", "c", "d", "e"];
        let mut seen: HashSet<&str> = HashSet::new();
        for _ in 0..1000 {
            seen.insert(pick_from(pool, "fallback"));
        }
        assert_eq!(seen.len(), pool.len(), "must hit every pool entry");
    }

    #[test]
    fn pick_returns_pool_entry_not_fallback_when_non_empty() {
        let pool = &[42_u64, 100, 1000];
        for _ in 0..50 {
            let v = pick_from(pool, 0xDEAD_BEEF);
            assert!(
                pool.contains(&v),
                "pick returned non-pool value {v} on non-empty pool"
            );
        }
    }

    #[test]
    fn works_with_byte_pool() {
        let bytes: &[u8] = b"ABC";
        for _ in 0..30 {
            let v = pick_from(bytes, 0);
            assert!(bytes.contains(&v));
        }
    }

    #[test]
    fn pick_from_rng_uses_caller_rng_and_fallback_contract() {
        let mut rng = StdRng::seed_from_u64(11);
        let pool = &["alpha", "beta", "gamma"];
        for _ in 0..30 {
            let value = pick_from_rng(pool, "fallback", &mut rng);
            assert!(pool.contains(&value));
        }

        let empty: &[&str] = &[];
        assert_eq!(pick_from_rng(empty, "fallback", &mut rng), "fallback");
    }

    #[test]
    fn pick_ref_from_rng_returns_borrowed_entries_or_none() {
        let mut rng = StdRng::seed_from_u64(17);
        let pool = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        for _ in 0..30 {
            let value = pick_ref_from_rng(&pool, &mut rng).expect("non-empty pool should sample");
            assert!(pool.contains(value));
        }

        let empty: Vec<String> = Vec::new();
        assert!(pick_ref_from_rng(&empty, &mut rng).is_none());
    }
}
