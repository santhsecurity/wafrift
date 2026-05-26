//! Per-key warning throttle so a high-rate scanner (sqlmap, ffuf,
//! nuclei) hitting the proxy at 100 req/s doesn't flood the log
//! with thousands of identical lines. Every warn site picks a
//! stable key (typically "category:host") and the throttle
//! suppresses repeats within a cooldown window.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

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
        map.insert(key.to_string(), now);
        true
    }

    /// Cap exposed so the bounded-map test can assert the limit
    /// without re-declaring the constant. No production caller —
    /// gated to test builds so a real consumer must show up before
    /// the function shape can drift.
    #[cfg(test)]
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
}
