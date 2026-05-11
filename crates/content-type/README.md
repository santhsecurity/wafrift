# wafrift-content-type

Content-Type switching for [WafRift](https://github.com/santhsecurity/wafrift) — exploits parser discrepancies between WAFs and origin applications by re-encoding the same logical request body across mutually-incompatible MIME formats.

The technique was popularized as **WAFFLED** (the "Web Application Firewall Forwarding/Lexing/Encoding Discrepancy" family of bypasses): a WAF that strict-parses `application/json` won't see attack tokens that live inside an `application/xml` body the upstream still happily ingests. WafRift extends the idea with a multipart-boundary fuzzer, comment-injected JSON, and unicode-escape variants.

## What it does

Given a single logical request `(field_name → value)` set, `generate_variants_from_body` produces a vector of equivalent bodies in different on-the-wire shapes:

| Variant                         | Body shape                                                                      |
|---------------------------------|---------------------------------------------------------------------------------|
| `MultipartFormData`             | `multipart/form-data; boundary=…` with one part per field                       |
| `MultipartMixed`                | `multipart/mixed` (some WAFs only inspect `form-data`)                          |
| `MultipartCharsetCollision`     | conflicting `charset=` parameters between the outer header and inner parts      |
| `MultipartBoundaryEvasion`      | adversarial boundary strings (LWS, fold, very-long, unicode)                    |
| `Json`                          | strict `application/json`                                                       |
| `JsonWithComments`              | `//`-comment-injected JSON (some upstream parsers tolerate this)                |
| `JsonUnicodeEscape`             | every non-ASCII byte as `\uXXXX`                                                |
| `Xml`                           | `application/xml` with one element per field                                    |
| `FormUrlencoded`                | `application/x-www-form-urlencoded` baseline                                    |

Every variant is marked with the matching `Content-Type` header so callers can dispatch the request directly.

## Boundary uniqueness

`unique_boundary()` is wired into every multipart variant — boundaries are RNG-generated per call so retries don't collide and a network sniffer can't cluster requests by boundary fingerprint.

## Use as a library

```rust
use wafrift_content_type::generate_variants_from_body;

let fields = vec![
    ("user".to_string(), "admin".to_string()),
    ("pass".to_string(), "' OR 1=1 --".to_string()),
];
for variant in generate_variants_from_body(&fields) {
    println!("Content-Type: {}", variant.content_type);
    println!("body bytes:    {}", variant.body.len());
}
```

## Stability

Public API tracks the rest of the WafRift workspace at the same minor
version. New variants get appended at the end of the enum behind
`#[non_exhaustive]` so consumers can pin a minor version and pick up
new shapes by recompiling.

## License

Dual-licensed under Apache-2.0 OR MIT. See the
[workspace root](https://github.com/santhsecurity/wafrift) for details.
