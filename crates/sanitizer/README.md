# wafrift-sanitizer

The **client-side sanitizer decompiler** — the DOM-XSS dual of the
[`wafrift-wafmodel`](../wafmodel) WAF decompiler.

Modern reflected XSS dies at the WAF; the XSS that pays is client-side, gated by
an HTML sanitizer (a DOMPurify config, a `sanitize-html` allowlist, a hand-rolled
`replace()` chain). This crate turns that sanitizer from a black box into a
solved model:

1. **Recover** (`sourcemap`) — parse the shipped `*.map` and pull the original
   sanitizer source out of `sourcesContent`. Full Source Map v3 + Base64-VLQ
   decoder.
2. **Extract** (`extract`) — identify the sanitizer (Tier-B signatures) and read
   off its allow/deny model: forbidden/allowed tags, blocked URL schemes,
   event-handler stripping, custom strip patterns.
3. **Model & mine** (`model`, `mine`) — wrap the model as a
   [`WafOracle`](../wafmodel) and drive the **same L\*/SFA machinery** that
   decompiles a server WAF, intersecting the learned "survives-executable"
   language with an XSS attack grammar to mine concrete bypass candidates.

Sound by construction: the model is derived from the sanitizer's own source,
mining only proposes survivors of that model (re-verified by a CEGIS-style gate),
and execution is confirmed in a real browser by scald — never fabricated here.

Tier-B data (`rules/sanitizers.toml`, `rules/xss_vectors.toml`) is operator-
extensible; no sanitizer names or vectors are hardcoded in code.

Driven by `wafrift sanitizer-decompile --source-map app.js.map` (or `--js`).
