# wafrift-smuggling

Generate HTTP request smuggling payloads and HTTP/2 downgrade / frame-level evasion descriptors.

## Safety

Every probe carries a **per-request poison canary**. Exploit-grade payloads are gated behind the `unsafe-probes` cargo feature to prevent accidental collateral damage on production targets. Safe `detect_*` probes use timing differentials without socket poisoning.

## Technique Coverage

| Technique | Research Source | Status |
|-----------|-----------------|--------|
| CL.TE | Kettle 2019 | ✅ |
| TE.CL | Kettle 2019 | ✅ |
| TE.TE (obfuscation matrix) | Kettle 2019 / Smuggler | ✅ |
| Line-wrapped `Transfer-Encoding` | Kettle 2019 | ✅ |
| Dual `Content-Length` | Watchfire / Kettle 2019 | ✅ |
| Multi-value `Content-Length` | RFC 7230 / Kettle 2019 | ✅ |
| CL formatting mutations (+5, 05, trailing space, tab) | Kettle 2019 | ✅ |
| Chunk extensions | RFC 7230 §4.1.1 / Kettle 2019 | ✅ |
| Chunk-size formatting mutations | Kettle 2019 | ✅ |
| Timeout-based detection probes | Kettle 2019 | ✅ |
| GET/PUT/DELETE body smuggling | Kettle 2019 | ✅ |
| HTTP/1.0 persistence disagreement | Kettle 2019 | ✅ |
| HTTP/0.9 simple-request downgrade | Kettle 2019 | ✅ |
| HTTP pipelining sequences | Kettle 2019 | ✅ |
| Unicode whitespace in TE | Smuggler / http2smugl | ✅ |
| Null-byte TE mutations | Smuggler | ✅ |
| Quoted TE values | RFC 7230 | ✅ |
| TE case mutations | Kettle 2019 | ✅ |
| H2C upgrade smuggling | Kettle 2019 / h2cSmuggler | ✅ |
| H2C `--upgrade-only` | h2cSmuggler | ✅ |
| Malformed `HTTP2-Settings` | h2cSmuggler | ✅ |
| H2.CL downgrade | Kettle 2021 | ✅ |
| H2.TE downgrade | Kettle 2021 | ✅ |
| CRLF in pseudo-headers | http2smugl | ✅ |
| CRLF in regular header values | http2smugl | ✅ |
| CRLF in header names | http2smugl | ✅ |
| `:method` anomalies (CONNECT, PRI) | http2smugl | ✅ |
| Empty / missing `:authority` | http2smugl | ✅ |
| Pseudo-header reordering | http2smugl / Frameshifter | ✅ |
| Regular header before pseudo-header | http2smugl | ✅ |
| CONTINUATION with pseudo after regular | Frameshifter | ✅ |
| Duplicate `:method` / `:scheme` / `:authority` | http2smugl | ✅ |
| Invalid `:path` characters | http2smugl | ✅ |
| Exotic `:scheme` (ftp, javascript, file, gopher) | http2smugl | ✅ |
| `:status` in request HEADERS | http2smugl | ✅ |
| ALPN h2c | h2cSmuggler | ✅ |
| END_STREAM / END_HEADERS flag manipulation | Frameshifter | ✅ |
| SETTINGS frame bombardment | Frameshifter | ✅ |
| WINDOW_UPDATE desync | Frameshifter | ✅ |
| RST_STREAM injection | Frameshifter | ✅ |
| GOAWAY injection | Frameshifter | ✅ |
| Invalid stream IDs | Frameshifter | ✅ |
| Malformed padding frames | Frameshifter / RFC | ✅ |
| HPACK table size extremes | Frameshifter | ✅ |

## TOML Probe Templates

Community-contributed probe templates live in `rules/smuggling/*.toml`. Each template follows this schema:

```toml
[[probe]]
id = "cl-te-zero"
variant = "ClTe"
description = "Classic CL.TE with Content-Length: 0"
method = "POST"
path = "/"
headers = [
    { name = "Host", value = "{{host}}" },
    { name = "Content-Length", value = "0" },
    { name = "Transfer-Encoding", value = "chunked" },
]
body = "0\r\n\r\n{{prefix}}"
requires_feature = "unsafe-probes"   # optional
```

Load templates at runtime with `wafrift_smuggling::rules::load_templates`.

## Usage

```rust
use wafrift_smuggling::smuggling;

// Safe detection probe (always available)
let probe = smuggling::detect_cl_te("target.com");

// Exploit payload (requires `unsafe-probes` feature)
#[cfg(feature = "unsafe-probes")]
let exploit = smuggling::cl_te("target.com", "GET /admin HTTP/1.1\r\n");
```

## License

MIT. Copyright 2026 CORUM COLLECTIVE LLC.
