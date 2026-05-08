# TLS fingerprint parity (JA3 / JA4)

## What WafRift does today

- **`wafrift-fingerprint`** defines **TLS ClientHello-shaped profiles** (cipher suites, extensions, GREASE, etc.) for documentation and future wiring.
- **Runtime HTTP(S)** uses **reqwest + rustls**. rustls chooses its own handshake ordering and extensions; it will **not** in general produce a **byte-identical** ClientHello to Chrome, Firefox, or Safari.

## Implication

Edge systems that block purely on **JA3/JA4** may still classify WafRift traffic as “non-browser” even when HTTP headers are rotated. That is a **known gap** vs tools that ship a BoringSSL/OpenSSL fork tuned for parity.

## Closing the gap (options)

1. **Document + accept** — optimize HTTP/oracle/evasion; accept rustls fingerprint for many lab targets.  
2. **Sidecar** — run a separate TLS-forwarding process that matches a browser JA3; point WafRift at its SOCKS/listener.  
3. **In-process (P2/P3)** — integrate a custom crypto provider or FFI to BoringSSL; high maintenance.

Track milestones in [`GAP_CLOSURE_ROADMAP.md`](./GAP_CLOSURE_ROADMAP.md).
