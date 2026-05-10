//! Concurrent callers must observe identical verdicts (no data races on oracle state).

use std::thread;

use wafrift_oracle::cmdi::CmdiOracle;
use wafrift_oracle::path::PathOracle;
use wafrift_oracle::ssrf::SsrfOracle;
use wafrift_oracle::traits::PayloadOracle;

const THREADS: usize = 50;

fn spawn_uniform<V>(
    threads: usize,
    f: impl Fn() -> V + Send + Sync + 'static,
) -> Vec<V>
where
    V: Send + 'static + Eq + std::fmt::Debug,
{
    let f = std::sync::Arc::new(f);
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let f = f.clone();
            thread::spawn(move || f())
        })
        .collect();
    handles.into_iter().map(|h| h.join().expect("thread panicked")).collect()
}

#[test]
fn cmdi_concurrent_identical_verdicts() {
    let oracle = CmdiOracle;
    let original = "; cat /etc/passwd";
    let transformed = "; id -u";
    let expected = oracle.is_semantically_valid(original, transformed);
    let verdicts = spawn_uniform(THREADS, move || {
        let oracle = CmdiOracle;
        oracle.is_semantically_valid(original, transformed)
    });
    assert!(verdicts.iter().all(|&v| v == expected));
}

#[test]
fn path_concurrent_identical_verdicts() {
    let oracle = PathOracle;
    let original = "../../../etc/passwd";
    let transformed = "..%2f..%2f..%2fetc%2fpasswd";
    let expected = oracle.is_semantically_valid(original, transformed);
    let verdicts = spawn_uniform(THREADS, move || {
        let oracle = PathOracle;
        oracle.is_semantically_valid(original, transformed)
    });
    assert!(verdicts.iter().all(|&v| v == expected));
}

#[test]
fn ssrf_concurrent_identical_verdicts() {
    let oracle = SsrfOracle;
    let original = "http://127.0.0.1/admin";
    let transformed = "http://127.0.0.1/api/v1/users";
    let expected = oracle.is_semantically_valid(original, transformed);
    let verdicts = spawn_uniform(THREADS, move || {
        let oracle = SsrfOracle;
        oracle.is_semantically_valid(original, transformed)
    });
    assert!(verdicts.iter().all(|&v| v == expected));
}
