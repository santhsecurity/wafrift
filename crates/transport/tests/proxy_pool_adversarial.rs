//! Adversarial / integration coverage for [`wafrift_transport::pool::ProxyPool`]:
//! concurrent round-robin, property-tested URL parsing, invalid schemes,
//! and clone sharing the rotation index.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use proptest::prelude::*;
use wafrift_transport::pool::{PoolError, ProxyPool};

#[cfg(test)]
mod helpers {
    use super::*;

    pub fn two_proxy_pool() -> ProxyPool {
        ProxyPool::new(&[
            String::from("http://127.0.0.1:8080"),
            String::from("socks5://127.0.0.1:9050"),
        ])
        .expect("pool construction")
        .expect("non-empty pool")
    }

    pub fn next_url_string(pool: &ProxyPool) -> String {
        pool.next_url().as_str().to_string()
    }
}

use helpers::{next_url_string, two_proxy_pool};

#[test]
fn concurrent_round_robin_distributes_without_panic() {
    let pool = Arc::new(two_proxy_pool());
    let http = "http://127.0.0.1:8080/";
    let socks = "socks5://127.0.0.1:9050";
    let http_hits = Arc::new(AtomicUsize::new(0));
    let socks_hits = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..8)
        .map(|_| {
            let pool = Arc::clone(&pool);
            let http_hits = Arc::clone(&http_hits);
            let socks_hits = Arc::clone(&socks_hits);
            thread::spawn(move || {
                for _ in 0..50 {
                    let u = pool.next_url().as_str().to_string();
                    if u == http {
                        http_hits.fetch_add(1, Ordering::Relaxed);
                    } else if u == socks {
                        socks_hits.fetch_add(1, Ordering::Relaxed);
                    }
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread must not panic");
    }

    let total = http_hits.load(Ordering::Relaxed) + socks_hits.load(Ordering::Relaxed);
    assert_eq!(total, 400, "every next_url call must hit a known proxy");
    assert!(http_hits.load(Ordering::Relaxed) > 0);
    assert!(socks_hits.load(Ordering::Relaxed) > 0);
}

#[test]
fn clone_shares_round_robin_index() {
    let pool = two_proxy_pool();
    let _ = next_url_string(&pool); // consume first slot
    let clone = pool.clone();
    // Shared index: clone continues from slot 1, not slot 0.
    assert_eq!(clone.next_url().as_str(), "socks5://127.0.0.1:9050");
    assert_eq!(pool.next_url().as_str(), "http://127.0.0.1:8080/");
}

#[test]
fn malformed_urls_fail_fast() {
    for bad in [
        "not-a-url",
        "://missing-scheme",
        "http://[::1", // bad bracket host
        "",
    ] {
        let err = ProxyPool::new(&[bad.to_string()]).expect_err("must reject bad URL");
        assert!(
            matches!(err, PoolError::InvalidUrl { .. }),
            "expected InvalidUrl for {bad:?}, got {err:?}"
        );
    }
}

#[test]
fn non_http_schemes_are_rejected() {
    // The pool must reject any scheme that is not http|https|socks4|socks5.
    // Previously `javascript:alert(1)` and `ftp:` were silently accepted —
    // the reqwest proxy engine would forward them verbatim, creating an SSRF
    // / security-context confusion vector.
    for bad_scheme in [
        "javascript:alert(1)",
        "ftp://127.0.0.1:21",
        "file:///etc/passwd",
        "data:text/html,<script>alert(1)</script>",
    ] {
        let err = ProxyPool::new(&[bad_scheme.to_string()])
            .expect_err(&format!("must reject {bad_scheme:?}"));
        assert!(
            matches!(err, PoolError::UnsupportedScheme { .. }),
            "expected UnsupportedScheme for {bad_scheme:?}, got {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("unsupported proxy scheme"),
            "error message must name the problem: {msg}"
        );
    }
}

#[test]
fn valid_proxy_schemes_accepted() {
    for scheme_url in [
        "http://127.0.0.1:8080",
        "https://127.0.0.1:8443",
        "socks4://127.0.0.1:1080",
        "socks5://127.0.0.1:9050",
    ] {
        let pool = ProxyPool::new(&[scheme_url.to_string()])
            .expect("construction must succeed")
            .expect("non-empty pool");
        assert_eq!(pool.len(), 1);
    }
}

#[test]
fn unsupported_scheme_error_names_scheme_and_url() {
    let err = ProxyPool::new(&["ftp://proxy.example.com:21".to_string()])
        .expect_err("ftp must be rejected");
    match err {
        PoolError::UnsupportedScheme { ref scheme, ref url } => {
            assert_eq!(scheme, "ftp");
            assert!(url.contains("proxy.example.com"), "url must echo the input: {url}");
        }
        other => panic!("expected UnsupportedScheme, got {other:?}"),
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    #[test]
    fn parsed_proxy_urls_round_trip(port in 1u16..65000u16) {
        let http = format!("http://127.0.0.1:{port}");
        let socks = format!("socks5://127.0.0.1:{port}");
        let pool = ProxyPool::new(&[http.clone(), socks.clone()])
            .expect("construction")
            .expect("non-empty");
        prop_assert_eq!(pool.len(), 2);
        let u0 = pool.next_url().as_str().to_string();
        let u1 = pool.next_url().as_str().to_string();
        prop_assert!(u0.starts_with("http://") || u0.starts_with("socks5://"));
        prop_assert!(u1.starts_with("http://") || u1.starts_with("socks5://"));
        prop_assert_ne!(u0, u1);
    }
}
