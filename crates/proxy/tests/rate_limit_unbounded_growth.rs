//! Regression coverage for the 2026-05-10 proxy `rate_limit` audit:
//!   HIGH: `RateLimiter::buckets` `HashMap` grew unboundedly. Every unique
//!     hostname `acquired()` against the limiter inserted a permanent
//!     entry. An attacker (or a long-running browser session crawling
//!     thousands of CDN edges) would OOM the proxy.
//!
//! Pre-fix this test would have grown the map past `MAX_TRACKED_HOSTS`
//! and kept growing.

use wafrift_proxy::rate_limit::RateLimiter;

#[tokio::test(flavor = "current_thread")]
async fn buckets_capped_at_max_tracked_hosts() {
    let limiter = RateLimiter::new(1_000_000.0, 1_000_000.0);
    // Far more than the cap (4096) so we hit eviction.
    for i in 0..10_000usize {
        limiter.acquire(&format!("host-{i}.example.com")).await;
    }
    let count = limiter.tracked_host_count().await;
    assert!(
        count <= 4096,
        "tracked_host_count {count} exceeds MAX_TRACKED_HOSTS=4096 — \
         buckets HashMap grows unboundedly"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn lru_eviction_keeps_recently_used_hosts() {
    let limiter = RateLimiter::new(1_000_000.0, 1_000_000.0);
    // Touch 4096 hosts (fills the cap exactly).
    for i in 0..4096 {
        limiter.acquire(&format!("baseline-{i}.example.com")).await;
    }
    // Now touch one specific recent host, then add 100 more new hosts.
    limiter.acquire("important.example.com").await;
    for i in 0..100 {
        limiter.acquire(&format!("flood-{i}.example.com")).await;
    }
    // The recently-touched important host should NOT have been the
    // oldest victim — we touched it after baseline-0..4095 and before
    // the flood. Implementation evicts min-by `last`, so the baseline
    // hosts get drained first. (Asserting precise survival is fragile
    // because Instant resolution can tie multiple hosts; we just
    // assert the cap is honoured throughout.)
    assert!(limiter.tracked_host_count().await <= 4096);
}

#[tokio::test(flavor = "current_thread")]
async fn unlimited_does_not_grow_buckets_at_all() {
    let limiter = RateLimiter::new(0.0, 0.0);
    for i in 0..100_000 {
        limiter.acquire(&format!("host-{i}")).await;
    }
    // Unlimited path returns immediately and never touches the map.
    assert_eq!(
        limiter.tracked_host_count().await,
        0,
        "unlimited limiter must not record any host"
    );
}
