# wafrift-pool

Round-robin proxy rotation for [WafRift](https://github.com/santhsecurity/wafrift). Holds a parsed list of HTTP and SOCKS5 proxy URLs and hands one out per call in a thread-safe rotation. No connection logic — just URL selection — so any HTTP client (`reqwest`, `rquest`, `hyper`) can plug it in.

Used by `wafrift-proxy` and `wafrift-cli` to spread outbound traffic across an egress pool when a single source IP would get rate-limited or fingerprinted by the WAF.

## Use as a library

```rust
use wafrift_pool::ProxyPool;

let pool = ProxyPool::new(&[
    "http://127.0.0.1:8080".to_string(),
    "socks5://127.0.0.1:9050".to_string(),
])?
.expect("non-empty pool");

for _ in 0..6 {
    let url = pool.next_url();
    // Build a per-request reqwest::Client with .proxy(reqwest::Proxy::all(url)?)
    println!("next: {url}");
}
```

`ProxyPool::new` takes `&[String]`, returns:

- `Ok(None)` when the input slice is empty (callers can branch directly into the no-proxy path),
- `Ok(Some(pool))` when every URL parsed,
- `Err(PoolError::InvalidUrl { url, source })` on the first malformed entry, naming which URL failed.

## Concurrency

`ProxyPool` is `Clone + Send + Sync`. The internal index is an `AtomicUsize` advanced with `Ordering::Relaxed` — fine for round-robin selection where the only invariant is "different threads usually get different proxies."

## Out of scope

- Per-proxy health-checking and eviction — callers track failures and
  rebuild the pool with healthy URLs.
- HTTPS-CONNECT / SOCKS5 authentication — encode credentials in the
  URL (`http://user:pass@host:port`).
- Weighted rotation — every URL gets equal share. Build a pool where
  faster proxies appear multiple times if you need weighting.

## License

Dual-licensed under Apache-2.0 OR MIT. See the
[workspace root](https://github.com/santhsecurity/wafrift) for details.
