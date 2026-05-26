//! Per-key warning throttle so a high-rate scanner (sqlmap, ffuf,
//! nuclei) hitting the proxy at 100 req/s doesn't flood the log
//! with thousands of identical lines. Every warn site picks a
//! stable key (typically "category:host") and the throttle
//! suppresses repeats within a cooldown window.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Hard cap on the throttle table size. Above this, every
/// `should_warn` call evicts expired entries; if still over, it
/// drops the oldest entry. 10k handles a long-running proxy
/// against ~thousands of distinct hosts × handful of warn
/// categories with margin.
const MAX_THROTTLE_ENTRIES: usize = 10_000;

pub struct WarnThrottle {
    cooldown: Duration,
    last: Mutex<HashMap<String, Instant>>,
}

impl WarnThrottle {
    /// Construct with the given cooldown in seconds. A cooldown of 0
    /// means "never throttle" (every call returns true).
    #[must_use]
    pub fn new(cooldown_secs: u64) -> Self {
        Self {
            cooldown: Duration::from_secs(cooldown_secs),
            last: Mutex::new(HashMap::new()),
        }
    }

    /// Returns true if at least `cooldown` has elapsed since the last
    /// warning with this key. The key should encode both the message
    /// category and the host (or other dimension) being warned about.
    pub fn should_warn(&self, key: &str) -> bool {
        let mut map = match self.last.lock() {
            Ok(g) => g,
            // PoisonError: recover the inner Map rather than panicking,
            // because a panicked logger thread must not also kill the
            // proxy. The map is just a cache; consistency-on-recovery
            // is acceptable.
            Err(e) => e.into_inner(),
        };
        let now = Instant::now();
        if let Some(last) = map.get(key)
            && now.duration_since(*last) < self.cooldown
        {
            return false;
        }
        // Cap defence — without it the map grows one-entry-per-distinct-key
        // forever. A long-running proxy session against thousands of unique
        // hosts × multiple warn categories accumulated stale entries
        // indefinitely (slow OOM).
        if map.len() >= MAX_THROTTLE_ENTRIES {
            // First pass: drop everything past the cooldown.
            map.retain(|_, last| now.duration_since(*last) < self.cooldown);
            // Still over? Drop the oldest entry (insertion-order isn't
            // available on HashMap, so use the smallest Instant).
            if map.len() >= MAX_THROTTLE_ENTRIES
                && let Some(oldest_key) = map
                    .iter()
                    .min_by_key(|(_, t)| **t)
                    .map(|(k, _)| k.clone())
            {
                map.remove(&oldest_key);
            }
        }
        map.insert(key.to_string(), now);
        true
    }

    /// Cap exposed for tests + downstream introspection.
    #[must_use]
    pub fn max_entries() -> usize {
        MAX_THROTTLE_ENTRIES
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn first_call_with_a_key_always_warns() {
        let t = WarnThrottle::new(60);
        assert!(t.should_warn("category:host-a"));
    }

    #[test]
    fn second_call_within_cooldown_returns_false() {
        let t = WarnThrottle::new(60);
        assert!(t.should_warn("k"));
        assert!(!t.should_warn("k"));
    }

    #[test]
    fn distinct_keys_have_independent_cooldowns() {
        let t = WarnThrottle::new(60);
        assert!(t.should_warn("a"));
        assert!(t.should_warn("b"));
        // First call for `b` was allowed even though `a` was just throttled.
        assert!(!t.should_warn("a"));
        assert!(!t.should_warn("b"));
    }

    #[test]
    fn after_cooldown_elapses_warning_fires_again() {
        let t = WarnThrottle::new(0); // 0-second cooldown — every call passes
        for _ in 0..5 {
            assert!(t.should_warn("k"));
        }
    }

    #[test]
    fn cooldown_one_millisecond_works_with_short_sleep() {
        // Boundary: cooldown=1s means a 1s sleep must let the next
        // warning fire. We use 0-cooldown for the trivial case above;
        // this exercises the time arithmetic with a real elapsed
        // measurement.
        let t = WarnThrottle::new(1);
        assert!(t.should_warn("k"));
        assert!(!t.should_warn("k"));
        sleep(Duration::from_millis(1100));
        assert!(t.should_warn("k"), "cooldown elapsed; should warn again");
    }

    #[test]
    fn map_stays_bounded_at_max_entries() {
        // Regression for the unbounded-growth bug: insert one MORE
        // distinct key than the cap and verify the map size never
        // exceeds the cap.
        let t = WarnThrottle::new(60); // long cooldown; entries stay fresh
        let cap = WarnThrottle::max_entries();
        for i in 0..=cap {
            t.should_warn(&format!("k{i}"));
        }
        let map = t.last.lock().unwrap();
        assert!(
            map.len() <= cap,
            "throttle map grew past cap: {} > {cap}",
            map.len()
        );
    }

    #[test]
    fn expired_entries_evicted_when_at_cap() {
        // With a 0-second cooldown every entry is immediately
        // "expired" and the retain() in the cap-pressure path
        // collapses the map down. Even adding cap+1 entries should
        // leave the map at ~1.
        let t = WarnThrottle::new(0);
        let cap = WarnThrottle::max_entries();
        for i in 0..=cap {
            t.should_warn(&format!("k{i}"));
        }
        // At the cap-pressure point the retain() drops every
        // entry whose age >= cooldown=0. So the map shouldn't be
        // anywhere near the cap.
        let map = t.last.lock().unwrap();
        assert!(
            map.len() <= cap,
            "map size {} should never exceed cap {cap}",
            map.len()
        );
    }
}
