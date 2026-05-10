//! Integration test: `install_global_solver` OnceCell semantics.
//!
//! Spawns 10 concurrent tasks that each call `install_global_solver`.
//! Asserts:
//!  1. Exactly one task receives `InstallOutcome::Installed`.
//!  2. Every other task receives `InstallOutcome::AlreadyInstalled`.
//!  3. `current_config()` returns a consistent, non-panicking value
//!     across all concurrent readers.
//!
//! Note: `SOLVER_INSTALLED` is a process-global static (OnceLock).
//! This test is designed so that the 10 concurrent callers all race
//! against each other; the first to win OnceLock::set receives
//! `Installed`. If a prior test in the same process already set the
//! cell the winner count will be 0, which is also explicitly checked.

use wafrift_captchaforge_bridge::{InstallOutcome, current_config, install_global_solver};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_install_exactly_one_installed() {
    const CONCURRENCY: usize = 10;

    let handles: Vec<_> = (0..CONCURRENCY)
        .map(|_| tokio::spawn(install_global_solver()))
        .collect();

    let mut installed_count = 0usize;
    let mut already_count = 0usize;

    for handle in handles {
        let outcome = handle
            .await
            .expect("task panicked")
            .expect("install_global_solver returned Err");

        match outcome {
            InstallOutcome::Installed => installed_count += 1,
            InstallOutcome::AlreadyInstalled => already_count += 1,
        }
    }

    // Because SOLVER_INSTALLED is process-global, a prior test run in
    // the same binary may have already set it. Acceptable outcomes:
    //   (a) this batch was first  → installed=1, already=9
    //   (b) some prior test was first → installed=0, already=10
    assert!(
        installed_count <= 1,
        "more than one task reported Installed (got {installed_count}); \
         OnceLock::set must be atomic"
    );
    assert_eq!(
        installed_count + already_count,
        CONCURRENCY,
        "outcome counts don't sum to {CONCURRENCY}"
    );
}

/// `current_config()` must return a consistent value under concurrent
/// readers — no panics, no poisoned locks.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_current_config_is_deterministic() {
    const CONCURRENCY: usize = 10;

    let handles: Vec<_> = (0..CONCURRENCY)
        .map(|_| tokio::spawn(current_config()))
        .collect();

    let mut configs = Vec::with_capacity(CONCURRENCY);
    for h in handles {
        let cfg = h.await.expect("task panicked");
        configs.push(cfg);
    }

    // All snapshots must agree on `headless` and have a positive timeout.
    let first = &configs[0];
    for (i, cfg) in configs.iter().enumerate() {
        assert_eq!(
            cfg.headless, first.headless,
            "config[{i}].headless differs from config[0].headless"
        );
        assert_eq!(
            cfg.solve_timeout_ms, first.solve_timeout_ms,
            "config[{i}].solve_timeout_ms differs from config[0].solve_timeout_ms"
        );
        assert!(
            cfg.solve_timeout_ms > 0,
            "config[{i}].solve_timeout_ms must be > 0"
        );
    }
}
