# wafrift-http3-evasion

HTTP/3 + QUIC protocol-level WAF-evasion descriptors for [wafrift](https://crates.io/crates/wafrift).

Emits descriptors for transport-layer evasion techniques that exploit the gap
between an HTTP/3 edge and an HTTP/1.1 or HTTP/2 origin. The crate describes
the technique the operator selects; it does not execute attacks or judge a
target.

## Technique Coverage

| Technique | Purpose |
|-----------|---------|
| QPACK desync | Dynamic-table state divergence between edge and origin header decoders |
| 0-RTT replay | Early-data idempotency assumptions on the request path |
| Connection-ID rotation | Migrate the QUIC connection to evade per-connection rate/inspection state |
| Stream-priority games | Reorder dependent streams to confuse reassembly-based inspection |

## License

MIT OR Apache-2.0
