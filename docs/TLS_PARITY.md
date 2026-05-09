# TLS fingerprint parity (JA3 / JA4)

## What WafRift does today

WafRift ships **two** HTTP transports the practitioner can pick between:

| Transport | TLS stack | JA3/JA4 match | Default? | Pulls in |
|-----------|-----------|---------------|----------|----------|
| `EvasionClient` (default) | `rustls` via `reqwest` | **No** — rustls fingerprint, classifiable as "non-browser" | ✅ | none extra |
| `StealthClient` (opt-in) | BoringSSL via `rquest` | **Yes** — wire-identical Chrome / Firefox / Safari / Edge ClientHello | ❌ | `boring-sys` (C build) |

Both transports expose the same `send_and_check`-shaped API, so the
proxy + scan paths swap between them by reading the
`--tls-impersonate` flag.

## How to use the impersonating path

Build with the `tls-impersonate` feature on `wafrift-transport`:

```bash
cargo install wafrift-cli --features tls-impersonate
# or
cargo build -p wafrift-cli --features wafrift-transport/tls-impersonate
```

Then drive it:

```bash
# Scan with Chrome 131's TLS stack
wafrift scan --target https://target.com/x --payload "' OR 1=1--" \
    --tls-impersonate chrome131

# Proxy mode — every upstream request leaves the box wearing
# Firefox 133's ClientHello
wafrift-proxy --listen 127.0.0.1:8080 --tls-impersonate firefox133
```

Supported profile names: `chrome131`, `chrome120`, `edge131`,
`firefox133`, `safari18`, `safari17_5`, `okhttp5` plus the alias
`chrome` / `firefox` / `safari` / `edge` for "latest of that family."
The full set lives at `wafrift_transport::stealth::supported_profiles()`.

## What this changes vs not using `--tls-impersonate`

- **Cloudflare / Akamai / Fastly Sigsci / Imperva Bot Protection**
  classify the inbound TLS connection as a real browser before they
  ever look at HTTP. The default rustls path gets shunted to a JS
  challenge or an outright block; the impersonating path gets through
  to inspection — at which point WafRift's HTTP-level evasion engine
  takes over.
- **HTTP/2 SETTINGS** are also matched (rquest sends Chrome's exact
  `HEADER_TABLE_SIZE` / `INITIAL_WINDOW_SIZE` / `MAX_CONCURRENT_STREAMS`
  values, in Chrome's exact order — so h2-fingerprinting WAFs can't
  distinguish on that either).

## Build cost trade-off

Enabling `tls-impersonate` pulls in `boring-sys`, which compiles a
forked BoringSSL from C. Cold first build adds ~30-60 s on a typical
machine; subsequent rebuilds cache. Default `cargo install wafrift-cli`
consumers pay zero extra cost.

## Implementation

`crates/transport/src/stealth.rs` — `ImpersonateProfile` enum + parser
(case-insensitive aliases) + `StealthClient::{new, with_timeout, send}`.
The compile-time stub when the feature is off returns an actionable
`StealthError::Build` pointing the operator at the cargo flag, so
downstream code can call `StealthClient::new` unconditionally and get
a clear error rather than a "method not found" build failure.

Originally tracked as a "documented limitation" in
[`GAP_CLOSURE_ROADMAP.md`](./GAP_CLOSURE_ROADMAP.md) — closed.
