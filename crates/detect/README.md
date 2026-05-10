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

## Attribution

The signature catalog under `rules/detect/*.toml` is derived from the
[wafw00f](https://github.com/EnableSecurity/wafw00f) project
(BSD-3-Clause) — every TOML rule sourced from wafw00f carries a
`source = "WAFW00F:<plugin>"` field pointing back at the upstream
plugin name. We re-express each signature in wafrift's structured
TOML format so it can be loaded at runtime, weighted, scanned via a
single global `RegexSet`, and extended by the community without a
recompile.

Additional sources cited similarly: `IDENTYWAF:<probe>` for entries
derived from [identYwaf](https://github.com/stamparm/identYwaf)
(MIT). Local research signatures are tagged
`source = "wafrift:<context>"`.

## Contributing

If a WAF is missing or misidentified, open a PR with the response headers
and body that triggered the issue, or add a new `rules/detect/<name>.toml` file.
Each new file should include a `source` field (`WAFW00F:`, `IDENTYWAF:`,
or `wafrift:` if locally researched) and ship a positive fixture +
sanitised negative under `crates/detect/tests/` so future signature
edits don't break the claim.

## License

MIT. Copyright 2026 CORUM COLLECTIVE LLC.
