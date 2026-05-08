# wafrift-detect

Identify which WAF protects a website from HTTP response headers and body content.

```rust
use wafrift_detect::{detect, DetectedWaf};

let headers = vec![("server".into(), "cloudflare".into())];
let detected = detect(403, &headers, b"Attention Required!");

if let Some(waf) = detected.first() {
    println!("Detected: {} (confidence: {:.0}%)", waf.name, waf.confidence * 100.0);
}
```

`detect` returns a `Vec<DetectedWaf>` sorted by confidence descending.
If multiple WAFs score within the ambiguity delta (0.15), all are returned
so callers can union evasion techniques or escalate to the user.

## Supported WAFs

WAF signatures are loaded at runtime from `rules/detect/*.toml`.
The embedded rule set covers 160+ WAFs including:
Cloudflare, Akamai, AWS WAF, Imperva/Incapsula, ModSecurity, Sucuri,
F5 BIG-IP, Barracuda, Fortinet FortiWeb, Citrix NetScaler, and more.

Detection uses header regex signatures, body regex patterns, cookie patterns,
status code predicates, and active probe drift analysis. Each WAF has multiple
detection indicators weighted by reliability.

## Contributing

If a WAF is missing or misidentified, open a PR with the response headers
and body that triggered the issue, or add a new `rules/detect/<name>.toml` file.

## License

MIT. Copyright 2026 CORUM COLLECTIVE LLC.
