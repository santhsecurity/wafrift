# wafrift-encoding

Encode payloads to evade Web Application Firewalls. URL encoding, hex, base64, null bytes, overlong UTF-8, SQL comment injection, case alternation, chunked transfer, parameter pollution, and layered combinations.

```rust
use wafrift_encoding::{encode, Strategy};

let payload = "' OR 1=1--";
let encoded = encode(payload, Strategy::DoubleUrlEncode).unwrap();
println!("{encoded}");
```

## Encoding strategies

| Strategy | What it does | Bypasses |
|----------|-------------|----------|
| `UrlEncode` | Standard percent-encoding (preserves unreserved) | Basic WAF rules |
| `DoubleUrlEncode` | Double URL encoding | WAFs that decode once |
| `TripleUrlEncode` | Triple URL encoding | WAFs that decode twice |
| `HexEncode` | Hex character encoding | Pattern-matching WAFs |
| `NullByte` | Insert null bytes | C-based WAF parsers |
| `OverlongUtf8` | Overlong UTF-8 sequences | UTF-8 validation bypass |
| `SqlCommentInsertion` | Replace spaces with SQL comments | SQL-aware WAFs |
| `CaseAlternation` | Mixed case (`SeLeCt`) | Case-sensitive rules |
| `RandomCase` | Random mixed case | Fingerprint-resistant evasion |
| `ChunkedSplit` | Transfer-Encoding: chunked | Content-length inspection |
| `ParameterPollution` | Duplicate parameters | First/last param confusion |
| `Base64Encode` | Standard Base64 encoding | Keyword-based filters |
| `Base64UrlEncode` | URL-safe Base64 encoding | URL contexts |
| `UnicodeEncode` | Unicode `\uXXXX` escapes | JSON context bypass |
| `HtmlEntityEncode` | HTML entity `&#xXX;` encoding | HTML context bypass |
| `JsonEncode` | JSON string with escapes | JSON context bypass |
| `GzipEncode` | Gzip compression | Body inspection bypass |
| `DeflateEncode` | Deflate compression | Body inspection bypass |

Many strategies include **context hints** via `Strategy::contexts()` indicating where they are semantically safe (e.g., `UnicodeEncode` is only valid in JSON/JavaScript contexts).

## Layered encoding

Chain strategies for deeper evasion:

```rust
use wafrift_encoding::{encode_layered, Strategy};

let encoded = encode_layered(
    "UNION SELECT",
    &[Strategy::CaseAlternation, Strategy::DoubleUrlEncode],
).unwrap();
```

Layered encoding enforces a hard output size cap to prevent OOM on adversarial input.

## Contributing

If a WAF blocks all current encodings, open a PR with the WAF and the bypass.

## License

MIT. Copyright 2026 CORUM COLLECTIVE LLC.
