//! Per-host token-bucket rate limiter.
//!
//! Operators running wafrift-proxy in front of a real target need a way
//! to keep the natural request volume from accidentally hammering it
//! into a rate-limit ban or a noisy-neighbour incident. The global
//! `--max-concurrent-connections` knob protects the proxy itself but
//! does nothing to bound *per-host* request rate; this limiter does.
//!
//! Tokens accumulate at `rps` per second, capped at `burst`. Each call
//! to [`RateLimiter::acquire`] consumes one token, sleeping if the
//! bucket is empty until enough tokens have refilled. A `rps == 0`
//! limiter is treated as "no limit" — `acquire` returns immediately.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

#[derive(Debug, Clone, Copy)]
struct HostBucket {
    tokens: f64,
    last: Instant,
}

#[derive(Debug)]
pub struct RateLimiter {
    rps: f64,
    burst: f64,
    buckets: Mutex<HashMap<String, HostBucket>>,
}

impl RateLimiter {
    /// Build a limiter capped at `rps` requests/sec per host with a
    /// burst capacity equal to `burst` (defaults to `rps` if zero).
    /// Passing `rps == 0` returns a no-op limiter.
    #[must_use]
    pub fn new(rps: f64, burst: f64) -> Arc<Self> {
        let burst = if burst > 0.0 { burst } else { rps.max(1.0) };
        Arc::new(Self {
            rps: rps.max(0.0),
            burst,
            buckets: Mutex::new(HashMap::new()),
        })
    }

    /// Returns true when this limiter is configured to never block.
    #[must_use]
    pub fn is_unlimited(&self) -> bool {
        self.rps == 0.0
    }

    /// Block until one token is available for `host`.
    ///
    /// The implementation deliberately sleeps in a loop rather than
    /// computing a single exact wait, because if multiple callers hit
    /// the same empty bucket simultaneously they would all compute the
    /// same wait and then thunder. Re-checking under the lock after
    /// sleep serializes them naturally.
    pub async fn acquire(&self, host: &str) {
        if self.is_unlimited() {
            return;
        }
        loop {
            let wait = {
                let mut buckets = self.buckets.lock().await;
                let now = Instant::now();
                let bucket = buckets.entry(host.to_string()).or_insert(HostBucket {
                    tokens: self.burst,
                    last: now,
                });
                let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
                bucket.tokens = (bucket.tokens + elapsed * self.rps).min(self.burst);
                bucket.last = now;
                if bucket.tokens >= 1.0 {
                    bucket.tokens -= 1.0;
                    return;
                }
                let need = 1.0 - bucket.tokens;
                Duration::from_secs_f64(need / self.rps)
            };
            // Cap individual sleep at 1s so a slow/clock-jumping host
            // doesn't park the task for an absurd duration.
            let bounded = wait.min(Duration::from_secs(1));
            tokio::time::sleep(bounded).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Instant as TokioInstant;

    #[tokio::test]
    async fn unlimited_does_not_block() {
        let l = RateLimiter::new(0.0, 0.0);
        assert!(l.is_unlimited());
        let start = TokioInstant::now();
        for _ in 0..100 {
            l.acquire("h").await;
        }
        assert!(start.elapsed() < Duration::from_millis(50));
    }

    #[tokio::test]
    async fn burst_lets_first_n_through_immediately() {
        // 1 rps, burst 5 — first 5 should pass with no real wait.
        let l = RateLimiter::new(1.0, 5.0);
        let start = TokioInstant::now();
        for _ in 0..5 {
            l.acquire("h").await;
        }
        assert!(start.elapsed() < Duration::from_millis(50));
    }

    #[tokio::test]
    async fn refill_paces_subsequent_requests() {
        // 10 rps, burst 1. After draining the burst, the next acquire
        // should park ~100ms (one token at 10/s) in real wall-clock.
        let l = RateLimiter::new(10.0, 1.0);
        l.acquire("h").await; // drain initial burst
        let start = TokioInstant::now();
        l.acquire("h").await;
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(80),
            "expected ~100ms wait, got {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn buckets_are_per_host_independent() {
        // Drain host A; host B should still be unblocked.
        let l = RateLimiter::new(1.0, 1.0);
        l.acquire("a").await; // drains A
        let start = TokioInstant::now();
        l.acquire("b").await;
        assert!(start.elapsed() < Duration::from_millis(50));
    }

    #[tokio::test]
    async fn concurrent_stress_same_host_no_deadlock() {
        // Simulate sqlmap firing hundreds of requests/sec to one host.
        let l = RateLimiter::new(10_000.0, 100.0);
        let mut handles = vec![];
        for _ in 0..100 {
            let lim = l.clone();
            handles.push(tokio::spawn(async move {
                lim.acquire("target").await;
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
    }
}
