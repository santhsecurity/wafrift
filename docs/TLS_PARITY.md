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
# Proxy mode — every upstream request leaves the box wearing
# Firefox 133's ClientHello. This is the path that actually wires
# BoringSSL impersonation today.
wafrift-proxy --listen 127.0.0.1:8080 --tls-impersonate firefox133

# Then route `wafrift scan` (and any other client) through the
# proxy so its outbound traffic inherits the impersonated TLS:
wafrift scan --target https://target.com/x --payload "' OR 1=1--" \
    --proxy http://127.0.0.1:8080

# NOTE: `wafrift scan --stealth-browser chrome` selects canonical
# browser HTTP headers for the reqwest/rustls scan path. Route through the
# proxy when the scan must inherit wire-identical browser TLS.
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

## Per-request fingerprint rotation

`--tls-impersonate <profile>` keeps the same browser ClientHello on
every upstream forward. When the WAF rate-limits or reputation-scores
on JA3 hash, this is exactly as classifiable as any single browser.
For per-request rotation use:

```bash
wafrift-proxy --listen 127.0.0.1:8080 \
    --tls-impersonate-rotate chrome131,firefox133,safari18,edge131
```

Each upstream request advances a round-robin cursor and lands on the
next profile. Combine with `--no-conn-reuse` to also rotate the TCP
source port (kernel-chosen ephemeral, fresh per request). 4 profiles
× new src port = no two consecutive requests look alike at the
connection layer.

## Open work

The static-profile path is solid; the **per-request fingerprint coherence** work — JA3 rotation that matches a real session lifecycle, H2 frame-layout fingerprint (`SETTINGS` order, priority tree, `WINDOW_UPDATE` cadence), browser-realistic header insertion order — is tracked as Tier 1, item 1 in the [roadmap](./GAP_CLOSURE_ROADMAP.md). This is what unlocks the cloud-WAF bot-management tier where rotating profiles round-robin still gets you classified as a bot.

TCP raw-options rotation (MSS, window scale, SACK) needs `CAP_NET_RAW` + a bespoke connector replacing the kernel's TCP stack; coverage cost is high relative to the JA3/H2 gains, so it's parked in Tier 3.

## Body-size inspection bypass

Cloud WAFs only inspect the leading bytes of a request body
(Cloudflare Pro 8 KB, AWS WAF 16 KB, Akamai 8 KB). WafRift now ships
content-type-aware padding via `wafrift_evolution::body_padding` —
prepends `_wafrift_pad` as the leading JSON object key, form
parameter, or multipart part so the malicious payload sits past the
inspection window:

```bash
wafrift-proxy --body-padding-bytes 16384   # AWS WAF default tier
wafrift-proxy --body-padding-bytes 8192    # Cloudflare Pro / Akamai
wafrift-proxy --body-padding-bytes 131072  # Cloudflare Enterprise
```

Self-hosted modsec (PL1-4) and Naxsi inspect the full body up to
Apache `LimitRequestBody` — this evasion does not bypass them. Real
value lives at the cloud-WAF tier where the inspection cap is
architectural, not a config knob.
