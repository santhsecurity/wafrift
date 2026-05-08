# Deep Audit: `crates/detect/`

**Date:** 2026-04-16  
**Auditor:** Kimi  
**Scope:** `crates/detect/src/` (read-only audit)  

## Executive Summary

- **Supported WAFs:** 20 hardcoded detectors.
- **WAFW00F gap:** 143 missing WAFs out of 172 plugins.
- **identYwaf gap:** 81 missing WAFs out of 95 signatures.
- **Critical design flaw:** `detect()` returns a single arbitrary `Option<DetectedWaf>` instead of a ranked list with ambiguity handling. At internet scale this guarantees misidentification.
- **No active probing:** The crate is purely passive (header/body substring matching). No malicious payloads are sent to observe WAF reactions.
- **No community extensibility:** All signatures and evasion mappings are hardcoded in Rust source. No TOML rule files exist for WAF detection.
- **Test coverage:** Minimal. No property tests, no adversarial inputs, no concurrency tests, no collision tests.

---

## Architecture & Design Findings

### FIND-001: Single-Arbitration Winner — Misidentification Guaranteed
- **Severity:** Critical

`classifier.rs::detect()` iterates the `DETECTORS` array and keeps exactly one winner: the detector with the highest confidence score. If two WAFs score equally, the first one in the static array wins arbitrarily. The function signature returns `Option<DetectedWaf>` (a single WAF), not a list of candidates with confidence scores.

**Impact:** When a target sits behind Akamai -> Cloudflare (common multi-CDN setup) or when two signatures collide, the scanner picks one evasion set and applies it. If it picks the wrong WAF, every payload is blocked → false negatives across the entire target (product-killer).

**Fix:** Change `detect()` to return `Vec<DetectedWaf>` sorted by confidence. Downstream strategy selection must accept an ambiguity set and union evasion techniques, or escalate to the user. Add an explicit ambiguity threshold (e.g., if top-2 confidence delta < 0.15, report both).

### FIND-002: No Active Probing — Purely Passive Banner Matching
- **Severity:** Critical

The crate only exposes `detect(status, headers, body)` and `fingerprint(status, headers, body)`. There is no module, function, or state machine that sends known-bad payloads (XSS, SQLi, path traversal) and compares the reaction (status delta, body delta, response time) against a benign baseline.

Gold-standard tools (WAFW00F, identYwaf) rely on active probing. identYwaf specifically uses response-difference fingerprinting rather than banners because banners are stripped, randomised, or missing in production.

**Impact:** Targets that strip vendor headers, use custom block pages, or run WAFs in silent mode are reported as `None` (no WAF). This creates a massive blind spot.

**Fix:** Implement an `active_probe()` routine that: (1) sends a benign request, (2) sends a blocked-string payload, (3) computes `FingerprintDrift`, (4) maps drift patterns to WAF families. Wire this into the CLI/strategy engine.

### FIND-003: Hardcoded Signatures — No TOML Rule Extensibility
- **Severity:** Critical

Every WAF signature lives in Rust source (`cloud.rs`, `edge.rs`, `vendor.rs`) compiled into the binary. There is no `rules/detect/` directory, no TOML schema, and no runtime rule loader. `rules/` only contains SSTI attack templates.

**Impact:** Community cannot contribute a new WAF signature without forking the repo, writing Rust, and recompiling. This violates LAW 6 ("Community extensibility via TOML rules where applicable") and LAW 7 ("NEVER POSTPONE — do the deep refactor NOW").

**Fix:** Design a `rules/detect.toml` schema with header patterns, cookie regexes, body regexes, status-code predicates, and confidence weights. Load rules at startup. Delete the hardcoded detector functions and replace them with a generic rule engine.

### FIND-004: Hardcoded Evasion Mapping — Strategy Engine Tightly Coupled
- **Severity:** High

`evasion.rs::suggest_evasion()` is a giant `match waf_name` hardcoded in Rust. Adding a new WAF requires touching `evasion.rs`, `signatures.rs`, `classifier.rs`, and the detector module.

**Impact:** Same extensibility violation as FIND-003. Strategy selection is not data-driven.

**Fix:** Move evasion mappings into the same TOML rule file (e.g., `[[waf]] name = "..." evasions = ["..."]`). `suggest_evasion()` should do a table lookup, not a Rust match arm.

### FIND-005: No Regex Engine — Substring-Only Matching Is Fragile
- **Severity:** High

All body and header matching uses `String::contains()` or `str::starts_with()`. There are zero regular expressions in the crate. This means signatures cannot capture variable tokens (e.g., `Ray ID: [a-f0-9]{16}`), cannot assert word boundaries, and cannot match multiple alternatives concisely.

**Impact:** False positives (`x-ms-*` matching any Azure API) and false negatives (slightly reformatted block pages) are inevitable.

**Fix:** Integrate a bounded-regex engine (e.g., `regex` crate with a global timeout / DFA fallback, or `fancy-regex` with limits) and define patterns in TOML rules.

### FIND-006: Generic Header Prefixes Cause False Positives
- **Severity:** High

- `detect_aws_waf` adds `0.4` confidence for any header starting with `x-amzn`. AWS API Gateway, ALB, Lambda, and S3 all emit `x-amzn-*` headers on non-WAF responses.
- `detect_azure` adds `0.3` confidence for any header starting with `x-ms`. Azure Blob Storage, Cosmos DB, and Entra ID all emit `x-ms-*` headers.
- `detect_fastly` adds `0.4` for `x-served-by: cache-*`, which is present on every Fastly CDN cache hit, not just WAF interceptions.

**Impact:** Benign APIs hosted on AWS/Azure/Fastly will be fingerprinted as protected by those WAFs, leading to wasted or incorrect evasion attempts.

**Fix:** Replace weak prefix rules with specific header/value combinations (e.g., `x-amzn-waf-action: BLOCK` is strong; `x-amzn-requestid` is weak and should be removed or heavily down-weighted).

### FIND-007: Overly Generic Body Patterns Cause False Positives
- **Severity:** Medium

- `detect_modsecurity` matches `body.contains("owasp") && body.contains("crs")`. Any blog post, documentation page, or training site mentioning OWASP CRS will trigger this.
- `detect_wordfence` matches `body.contains("wordfence")`. A WordPress plugin page or changelog mentioning the plugin name will trigger it.

**Impact:** False-positive WAF detection on benign content.

**Fix:** Require at least one high-confidence indicator (header or cookie) before adding body-score points, or use regex word boundaries and context anchors (e.g., `generated by wordfence`).

### FIND-008: Duplicate Helper Functions — `has_header` vs `header_has`
- **Severity:** Low

`helpers.rs` defines both `has_header(headers, name)` and `header_has(headers, name)` with identical implementations. `cloud.rs` imports `has_header`; `edge.rs` imports `header_has`.

**Impact:** Dead code / confusion. Violates LAW 5 ("no dead code").

**Fix:** Delete one of them. Standardise on `has_header`.

### FIND-009: Manual DETECTORS Array Maintenance Is Error-Prone
- **Severity:** Medium

`signatures.rs` re-exports every detector function, then manually lists them in `DETECTORS: &[(&str, DetectorFn)]`. It is trivial to add a new `pub(crate) fn detect_xxx` in a submodule and forget to register it in the array, rendering it dead code.

**Impact:** Missing WAFs even after code is written.

**Fix:** If signatures remain in code, generate the `DETECTORS` array with a `inventory` or `linkme` crate, or a proc-macro. Better: move to TOML (FIND-003) and eliminate the array entirely.

### FIND-010: Confidence Scoring Is Unprincipled and Unbounded
- **Severity:** Medium

Individual detector functions sum arbitrary floating-point weights (e.g., Cloudflare can sum to `0.5+0.4+0.3+0.3+0.4+0.2+0.5 = 2.6`). The only clamp is `confidence.min(1.0)` in `classifier.rs`. There is no probability model, no training data, and no calibration. The `0.3` global threshold is a magic number.

**Impact:** Confidence values are not comparable across WAFs. A Cloudflare score of `0.9` is not the same statistical certainty as an AWS WAF score of `0.9`.

**Fix:** Cap each detector at `1.0` internally, document how weights were derived (empirical hit rates), and expose the threshold as a configuration parameter. Long-term, replace heuristics with a calibrated scoring model.

### FIND-011: `blocking.rs` Status-Code Heuristic Is Incomplete
- **Severity:** Medium

`is_blocked_response()` treats `403 | 406 | 429 | 503` as blocked. It ignores `401 Unauthorized`, `405 Method Not Allowed`, `407 Proxy Authentication Required`, `502 Bad Gateway`, `504 Gateway Timeout`, and many custom WAF status codes (e.g., `499`, `520`–`526` used by Cloudflare).

**Impact:** WAF blocks returned with non-listed status codes are missed by the lightweight heuristic.

**Fix:** Expand the list to include common WAF and CDN error codes, or derive the list from the TOML rule database.

### FIND-012: `response_fingerprint.rs` Drift Scoring Uses Undocumented Magic Weights
- **Severity:** Medium

The drift score adds fixed constants (`0.3` for status, `0.15` for content-type, `0.2` for length bucket, etc.) with no calibration or citation. The `likely_blocked` boolean logic is a nested conditional that is hard to reason about.

**Impact:** Silent blocks may be missed or false-alarmed depending on arbitrary thresholds.

**Fix:** Document why each weight was chosen. Make thresholds configurable. Add unit tests that pin exact scores for known baseline->block transitions.

### FIND-013: `extract_title` Fails on Real-World HTML Variations
- **Severity:** Low

`extract_title` looks for the exact byte sequence `<title>` and `</title>`. It does not handle:
- `<TITLE>` (already lowercased, so actually it does because body is lowercased in `fingerprint`)
- `<title lang="en">` or any attributes
- Whitespace inside the tag (`< title >`)
- Self-closing or missing closing tags

**Impact:** Title-tag drift component is unreliable for real HTML.

**Fix:** Use a lightweight HTML tokenizer or a regex that allows attributes inside `<title ...>`.

### FIND-014: No Determinism Property Test
- **Severity:** High

There is no property-based or randomized test asserting that `detect()` and `fingerprint()` return the same output for the same input across repeated calls. Given the reliance on `DefaultHasher` (which is stable within a process) this happens to pass, but it is not enforced.

**Fix:** Add a proptest or fuzz target that feeds random (but valid) headers and bodies into `detect`/`fingerprint` and asserts deterministic results.

### FIND-015: No Adversarial Input Tests
- **Severity:** High

The test suite does not exercise:
- Empty or all-whitespace body
- Gzip-encoded body bytes passed raw (will be treated as binary garbage)
- Chunked transfer-encoding trailers in headers
- HTTP/2 pseudo-headers (`:authority`, `:status`) mixed with regular headers
- Headers with non-ASCII or case-mixed names
- Body lengths exactly on bucket boundaries (`100`, `1000`, `5000`, ...)

**Impact:** Edge-case crashes or incorrect classification in production traffic are undiscovered.

**Fix:** Add adversarial unit tests for each of the above categories.

### FIND-016: No Collision / Ambiguity Test Coverage
- **Severity:** High

There is no test that supplies headers matching *both* Cloudflare and Akamai (or AWS WAF and CloudFront) and asserts correct ambiguity handling. The `highest_confidence_wins` test only checks that Cloudflare beats AWS when Cloudflare indicators are stronger; it does not verify the desired behavior when scores are near-equal.

**Fix:** Add collision tests. After fixing FIND-001, assert that the function returns multiple candidates with expected confidence ordering.

### FIND-017: No Concurrent Access Tests
- **Severity:** Medium

`detect()` and `fingerprint()` take immutable references and are technically `Send + Sync`, but there are no tests exercising concurrent calls (e.g., from a thread pool). `DefaultHasher` is thread-safe, but the confidence-scoring logic involves no shared state, so this should pass. Still, it is untested.

**Fix:** Add a `#[test]` spawning multiple threads that call `detect()` on shared sample data and assert no panics or data races.

### FIND-018: `README.md` Documents Non-Existent API
- **Severity:** Low

The README shows `use wafrift_detect::{detect_waf, WafResponse};` and `detect_waf(&response)`. These symbols do not exist in `lib.rs`. The actual API is `detect(status, headers, body)` and `DetectedWaf`.

**Fix:** Update README to match the real public API.

### FIND-019: No Regex Backtracking — Because No Regex Is Used
- **Severity:** Info

The crate contains zero regular expressions, therefore there is no regex backtracking attack surface. This is noted for completeness, but it is also a limitation (see FIND-005).

### FIND-020: No Panic or Unsafe Code Observed
- **Severity:** Info

A manual audit of `crates/detect/src/` found no `panic!`, `unwrap`, `expect` (outside tests), `unsafe`, or integer casts. The `String::from_utf8_lossy` fallback is safe. OOM risk is bounded by the 4 KiB body truncation in `detect()` and `fingerprint()`.

---

## Missing WAFs — WAFW00F Gap (143 individual findings)

WAFW00F is the de-facto gold standard with 172 detection plugins. wafrift-detect covers roughly 29 of them (Cloudflare, AWS WAF, Akamai/Kona, Imperva/Incapsula/SecureSphere, ModSecurity, Sucuri, F5 BIG-IP family, CloudFront, Fastly, Azure Application Gateway/Front Door, Barracuda/NetContinuum, Fortinet family, Wordfence, Radware, NetScaler/Teros, Reblaze, StackPath, Wallarm, DenyALL).

Every missing WAF below is a **Critical** finding because each represents a blind spot where the scanner will report `UNKNOWN` and apply a generic, ineffective evasion strategy.

### FIND-021: Missing WAF — aesecure
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `aesecure` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-022: Missing WAF — airee
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `airee` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-023: Missing WAF — airlock
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `airlock` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-024: Missing WAF — alertlogic
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `alertlogic` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-025: Missing WAF — aliyundun
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `aliyundun` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-026: Missing WAF — anquanbao
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `anquanbao` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-027: Missing WAF — anubis
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `anubis` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-028: Missing WAF — anyu
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `anyu` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-029: Missing WAF — approach
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `approach` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-030: Missing WAF — armor
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `armor` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-031: Missing WAF — arvancloud
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `arvancloud` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-032: Missing WAF — aspa
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `aspa` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-033: Missing WAF — aspnetgen
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `aspnetgen` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-034: Missing WAF — astra
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `astra` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-035: Missing WAF — azion
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `azion` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-036: Missing WAF — baffinbay
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `baffinbay` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-037: Missing WAF — baidu
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `baidu` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-038: Missing WAF — barikode
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `barikode` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-039: Missing WAF — bekchy
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `bekchy` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-040: Missing WAF — beluga
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `beluga` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-041: Missing WAF — binarysec
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `binarysec` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-042: Missing WAF — bitninja
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `bitninja` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-043: Missing WAF — blockdos
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `blockdos` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-044: Missing WAF — bluedon
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `bluedon` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-045: Missing WAF — bulletproof
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `bulletproof` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-046: Missing WAF — cachefly
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `cachefly` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-047: Missing WAF — cachewall
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `cachewall` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-048: Missing WAF — cdnns
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `cdnns` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-049: Missing WAF — cerber
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `cerber` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-050: Missing WAF — chinacache
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `chinacache` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-051: Missing WAF — chuangyu
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `chuangyu` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-052: Missing WAF — ciscoacexml
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `ciscoacexml` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-053: Missing WAF — cloudbric
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `cloudbric` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-054: Missing WAF — cloudfloordns
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `cloudfloordns` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-055: Missing WAF — cloudprotector
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `cloudprotector` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-056: Missing WAF — comodo
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `comodo` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-057: Missing WAF — crawlprotect
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `crawlprotect` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-058: Missing WAF — ddosguard
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `ddosguard` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-059: Missing WAF — distil
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `distil` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-060: Missing WAF — dosarrest
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `dosarrest` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-061: Missing WAF — dotdefender
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `dotdefender` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-062: Missing WAF — dynamicweb
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `dynamicweb` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-063: Missing WAF — edgecast
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `edgecast` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-064: Missing WAF — eisoo
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `eisoo` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-065: Missing WAF — envoy
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `envoy` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-066: Missing WAF — expressionengine
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `expressionengine` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-067: Missing WAF — gcparmor
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `gcparmor` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-068: Missing WAF — godaddy
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `godaddy` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-069: Missing WAF — greywizard
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `greywizard` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-070: Missing WAF — huaweicloud
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `huaweicloud` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-071: Missing WAF — hyperguard
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `hyperguard` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-072: Missing WAF — ibmdatapower
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `ibmdatapower` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-073: Missing WAF — imunify360
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `imunify360` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-074: Missing WAF — indusguard
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `indusguard` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-075: Missing WAF — instartdx
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `instartdx` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-076: Missing WAF — isaserver
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `isaserver` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-077: Missing WAF — janusec
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `janusec` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-078: Missing WAF — jiasule
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `jiasule` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-079: Missing WAF — kemp
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `kemp` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-080: Missing WAF — keycdn
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `keycdn` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-081: Missing WAF — knownsec
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `knownsec` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-082: Missing WAF — limelight
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `limelight` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-083: Missing WAF — link11
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `link11` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-084: Missing WAF — litespeed
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `litespeed` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-085: Missing WAF — malcare
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `malcare` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-086: Missing WAF — maxcdn
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `maxcdn` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-087: Missing WAF — missioncontrol
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `missioncontrol` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-088: Missing WAF — naxsi
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `naxsi` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-089: Missing WAF — nemesida
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `nemesida` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-090: Missing WAF — nevisproxy
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `nevisproxy` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-091: Missing WAF — newdefend
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `newdefend` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-092: Missing WAF — nexusguard
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `nexusguard` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-093: Missing WAF — ninja
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `ninja` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-094: Missing WAF — nsfocus
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `nsfocus` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-095: Missing WAF — nullddos
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `nullddos` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-096: Missing WAF — onmessage
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `onmessage` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-097: Missing WAF — openresty
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `openresty` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-098: Missing WAF — oraclecloud
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `oraclecloud` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-099: Missing WAF — paloalto
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `paloalto` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-100: Missing WAF — panyun360
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `panyun360` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-101: Missing WAF — pentawaf
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `pentawaf` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-102: Missing WAF — perimeterx
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `perimeterx` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-103: Missing WAF — pksec
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `pksec` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-104: Missing WAF — powercdn
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `powercdn` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-105: Missing WAF — profense
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `profense` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-106: Missing WAF — ptaf
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `ptaf` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-107: Missing WAF — puhui
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `puhui` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-108: Missing WAF — qcloud
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `qcloud` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-109: Missing WAF — qiniu
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `qiniu` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-110: Missing WAF — qrator
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `qrator` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-111: Missing WAF — reflected
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `reflected` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-112: Missing WAF — rsfirewall
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `rsfirewall` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-113: Missing WAF — rvmode
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `rvmode` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-114: Missing WAF — sabre
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `sabre` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-115: Missing WAF — safe3
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `safe3` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-116: Missing WAF — safedog
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `safedog` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-117: Missing WAF — safeline
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `safeline` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-118: Missing WAF — scutum
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `scutum` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-119: Missing WAF — secking
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `secking` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-120: Missing WAF — secupress
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `secupress` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-121: Missing WAF — secureentry
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `secureentry` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-122: Missing WAF — secureiis
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `secureiis` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-123: Missing WAF — senginx
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `senginx` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-124: Missing WAF — serverdefender
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `serverdefender` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-125: Missing WAF — shadowd
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `shadowd` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-126: Missing WAF — shieldon
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `shieldon` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-127: Missing WAF — shieldsecurity
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `shieldsecurity` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-128: Missing WAF — siteground
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `siteground` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-129: Missing WAF — siteguard
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `siteguard` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-130: Missing WAF — sitelock
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `sitelock` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-131: Missing WAF — sonicwall
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `sonicwall` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-132: Missing WAF — sophos
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `sophos` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-133: Missing WAF — squarespace
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `squarespace` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-134: Missing WAF — squidproxy
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `squidproxy` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-135: Missing WAF — tencent
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `tencent` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-136: Missing WAF — threatx
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `threatx` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-137: Missing WAF — transip
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `transip` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-138: Missing WAF — uewaf
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `uewaf` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-139: Missing WAF — urlmaster
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `urlmaster` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-140: Missing WAF — urlscan
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `urlscan` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-141: Missing WAF — variti
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `variti` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-142: Missing WAF — varnish
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `varnish` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-143: Missing WAF — vercel
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `vercel` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-144: Missing WAF — viettel
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `viettel` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-145: Missing WAF — virusdie
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `virusdie` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-146: Missing WAF — watchguard
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `watchguard` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-147: Missing WAF — webarx
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `webarx` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-148: Missing WAF — webknight
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `webknight` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-149: Missing WAF — webland
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `webland` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-150: Missing WAF — webray
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `webray` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-151: Missing WAF — webseal
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `webseal` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-152: Missing WAF — webtotem
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `webtotem` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-153: Missing WAF — west263cdn
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `west263cdn` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-154: Missing WAF — wpmudev
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `wpmudev` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-155: Missing WAF — wts
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `wts` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-156: Missing WAF — wzb360
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `wzb360` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-157: Missing WAF — xlabssecuritywaf
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `xlabssecuritywaf` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-158: Missing WAF — xuanwudun
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `xuanwudun` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-159: Missing WAF — yundun
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `yundun` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-160: Missing WAF — yunsuo
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `yunsuo` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-161: Missing WAF — yxlink
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `yxlink` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-162: Missing WAF — zenedge
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `zenedge` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

### FIND-163: Missing WAF — zscaler
- **Source:** WAFW00F plugin list
- **Severity:** Critical
- **Fix:** Add a signature detector for `zscaler` and register it in `DETECTORS`. Migrate to `rules/detect.toml` per LAW 6.

---

## Missing WAFs — identYwaf Gap (81 additional individual findings)

identYwaf detects 95 WAF families using response-difference fingerprinting rather than banner matching. wafrift-detect covers only 14 of them. The following are missing from identYwaf coverage (many overlap with WAFW00F but are listed separately per audit requirement).

### FIND-164: Missing WAF — 360
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `360` and register it. Migrate to TOML rules per LAW 6.

### FIND-165: Missing WAF — aesecure
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `aesecure` and register it. Migrate to TOML rules per LAW 6.

### FIND-166: Missing WAF — airlock
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `airlock` and register it. Migrate to TOML rules per LAW 6.

### FIND-167: Missing WAF — alertlogic
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `alertlogic` and register it. Migrate to TOML rules per LAW 6.

### FIND-168: Missing WAF — aliyundun
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `aliyundun` and register it. Migrate to TOML rules per LAW 6.

### FIND-169: Missing WAF — anquanbao
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `anquanbao` and register it. Migrate to TOML rules per LAW 6.

### FIND-170: Missing WAF — approach
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `approach` and register it. Migrate to TOML rules per LAW 6.

### FIND-171: Missing WAF — armor
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `armor` and register it. Migrate to TOML rules per LAW 6.

### FIND-172: Missing WAF — asm
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `asm` and register it. Migrate to TOML rules per LAW 6.

### FIND-173: Missing WAF — astra
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `astra` and register it. Migrate to TOML rules per LAW 6.

### FIND-174: Missing WAF — bekchy
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `bekchy` and register it. Migrate to TOML rules per LAW 6.

### FIND-175: Missing WAF — bitninja
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `bitninja` and register it. Migrate to TOML rules per LAW 6.

### FIND-176: Missing WAF — bluedon
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `bluedon` and register it. Migrate to TOML rules per LAW 6.

### FIND-177: Missing WAF — bulletproof
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `bulletproof` and register it. Migrate to TOML rules per LAW 6.

### FIND-178: Missing WAF — cdnns
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `cdnns` and register it. Migrate to TOML rules per LAW 6.

### FIND-179: Missing WAF — cerber
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `cerber` and register it. Migrate to TOML rules per LAW 6.

### FIND-180: Missing WAF — checkpoint
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `checkpoint` and register it. Migrate to TOML rules per LAW 6.

### FIND-181: Missing WAF — chuangyu
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `chuangyu` and register it. Migrate to TOML rules per LAW 6.

### FIND-182: Missing WAF — cloudbric
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `cloudbric` and register it. Migrate to TOML rules per LAW 6.

### FIND-183: Missing WAF — comodo
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `comodo` and register it. Migrate to TOML rules per LAW 6.

### FIND-184: Missing WAF — crawlprotect
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `crawlprotect` and register it. Migrate to TOML rules per LAW 6.

### FIND-185: Missing WAF — distil
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `distil` and register it. Migrate to TOML rules per LAW 6.

### FIND-186: Missing WAF — dotdefender
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `dotdefender` and register it. Migrate to TOML rules per LAW 6.

### FIND-187: Missing WAF — duedge
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `duedge` and register it. Migrate to TOML rules per LAW 6.

### FIND-188: Missing WAF — expressionengine
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `expressionengine` and register it. Migrate to TOML rules per LAW 6.

### FIND-189: Missing WAF — godaddy
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `godaddy` and register it. Migrate to TOML rules per LAW 6.

### FIND-190: Missing WAF — greywizard
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `greywizard` and register it. Migrate to TOML rules per LAW 6.

### FIND-191: Missing WAF — gtmc
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `gtmc` and register it. Migrate to TOML rules per LAW 6.

### FIND-192: Missing WAF — imunify360
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `imunify360` and register it. Migrate to TOML rules per LAW 6.

### FIND-193: Missing WAF — isaserver
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `isaserver` and register it. Migrate to TOML rules per LAW 6.

### FIND-194: Missing WAF — ithemes
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `ithemes` and register it. Migrate to TOML rules per LAW 6.

### FIND-195: Missing WAF — janusec
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `janusec` and register it. Migrate to TOML rules per LAW 6.

### FIND-196: Missing WAF — jiasule
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `jiasule` and register it. Migrate to TOML rules per LAW 6.

### FIND-197: Missing WAF — knownsec
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `knownsec` and register it. Migrate to TOML rules per LAW 6.

### FIND-198: Missing WAF — kuipernet
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `kuipernet` and register it. Migrate to TOML rules per LAW 6.

### FIND-199: Missing WAF — malcare
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `malcare` and register it. Migrate to TOML rules per LAW 6.

### FIND-200: Missing WAF — naxsi
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `naxsi` and register it. Migrate to TOML rules per LAW 6.

### FIND-201: Missing WAF — newdefend
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `newdefend` and register it. Migrate to TOML rules per LAW 6.

### FIND-202: Missing WAF — nexusguard
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `nexusguard` and register it. Migrate to TOML rules per LAW 6.

### FIND-203: Missing WAF — ninjafirewall
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `ninjafirewall` and register it. Migrate to TOML rules per LAW 6.

### FIND-204: Missing WAF — onmessageshield
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `onmessageshield` and register it. Migrate to TOML rules per LAW 6.

### FIND-205: Missing WAF — openrasp
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `openrasp` and register it. Migrate to TOML rules per LAW 6.

### FIND-206: Missing WAF — paloalto
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `paloalto` and register it. Migrate to TOML rules per LAW 6.

### FIND-207: Missing WAF — perimeterx
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `perimeterx` and register it. Migrate to TOML rules per LAW 6.

### FIND-208: Missing WAF — profense
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `profense` and register it. Migrate to TOML rules per LAW 6.

### FIND-209: Missing WAF — requestvalidationmode
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `requestvalidationmode` and register it. Migrate to TOML rules per LAW 6.

### FIND-210: Missing WAF — rsfirewall
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `rsfirewall` and register it. Migrate to TOML rules per LAW 6.

### FIND-211: Missing WAF — safe3
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `safe3` and register it. Migrate to TOML rules per LAW 6.

### FIND-212: Missing WAF — safedog
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `safedog` and register it. Migrate to TOML rules per LAW 6.

### FIND-213: Missing WAF — safeline
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `safeline` and register it. Migrate to TOML rules per LAW 6.

### FIND-214: Missing WAF — secupress
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `secupress` and register it. Migrate to TOML rules per LAW 6.

### FIND-215: Missing WAF — secureentry
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `secureentry` and register it. Migrate to TOML rules per LAW 6.

### FIND-216: Missing WAF — secureiis
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `secureiis` and register it. Migrate to TOML rules per LAW 6.

### FIND-217: Missing WAF — securesphere
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `securesphere` and register it. Migrate to TOML rules per LAW 6.

### FIND-218: Missing WAF — shieldsecurity
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `shieldsecurity` and register it. Migrate to TOML rules per LAW 6.

### FIND-219: Missing WAF — siteground
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `siteground` and register it. Migrate to TOML rules per LAW 6.

### FIND-220: Missing WAF — siteguard
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `siteguard` and register it. Migrate to TOML rules per LAW 6.

### FIND-221: Missing WAF — sitelock
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `sitelock` and register it. Migrate to TOML rules per LAW 6.

### FIND-222: Missing WAF — sniper
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `sniper` and register it. Migrate to TOML rules per LAW 6.

### FIND-223: Missing WAF — sonicwall
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `sonicwall` and register it. Migrate to TOML rules per LAW 6.

### FIND-224: Missing WAF — sophos
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `sophos` and register it. Migrate to TOML rules per LAW 6.

### FIND-225: Missing WAF — squarespace
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `squarespace` and register it. Migrate to TOML rules per LAW 6.

### FIND-226: Missing WAF — tencent
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `tencent` and register it. Migrate to TOML rules per LAW 6.

### FIND-227: Missing WAF — tmg
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `tmg` and register it. Migrate to TOML rules per LAW 6.

### FIND-228: Missing WAF — urlmaster
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `urlmaster` and register it. Migrate to TOML rules per LAW 6.

### FIND-229: Missing WAF — urlscan
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `urlscan` and register it. Migrate to TOML rules per LAW 6.

### FIND-230: Missing WAF — vercel
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `vercel` and register it. Migrate to TOML rules per LAW 6.

### FIND-231: Missing WAF — vfw
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `vfw` and register it. Migrate to TOML rules per LAW 6.

### FIND-232: Missing WAF — virusdie
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `virusdie` and register it. Migrate to TOML rules per LAW 6.

### FIND-233: Missing WAF — vsf
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `vsf` and register it. Migrate to TOML rules per LAW 6.

### FIND-234: Missing WAF — wapples
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `wapples` and register it. Migrate to TOML rules per LAW 6.

### FIND-235: Missing WAF — watchguard
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `watchguard` and register it. Migrate to TOML rules per LAW 6.

### FIND-236: Missing WAF — webarx
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `webarx` and register it. Migrate to TOML rules per LAW 6.

### FIND-237: Missing WAF — webknight
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `webknight` and register it. Migrate to TOML rules per LAW 6.

### FIND-238: Missing WAF — webland
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `webland` and register it. Migrate to TOML rules per LAW 6.

### FIND-239: Missing WAF — webseal
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `webseal` and register it. Migrate to TOML rules per LAW 6.

### FIND-240: Missing WAF — webtotem
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `webtotem` and register it. Migrate to TOML rules per LAW 6.

### FIND-241: Missing WAF — wts
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `wts` and register it. Migrate to TOML rules per LAW 6.

### FIND-242: Missing WAF — yundun
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `yundun` and register it. Migrate to TOML rules per LAW 6.

### FIND-243: Missing WAF — yunsuo
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `yunsuo` and register it. Migrate to TOML rules per LAW 6.

### FIND-244: Missing WAF — zenedge
- **Source:** identYwaf data.json
- **Severity:** Critical
- **Fix:** Add response-diff signature for `zenedge` and register it. Migrate to TOML rules per LAW 6.

---

## Recommendations (Priority Order)

1. **Return ambiguity sets:** Change `detect()` -> `Vec<DetectedWaf>` immediately. Do not postpone. (FIND-001)
2. **Implement active probing:** Build a benign + attack request pair and use `FingerprintDrift` to identify WAFs by reaction, not just banner. (FIND-002)
3. **Migrate to TOML:** Create `rules/detect.toml` with header, cookie, body, and status signatures. Delete hardcoded Rust detectors. (FIND-003)
4. **Add a regex engine:** Use bounded regex for robust pattern matching. (FIND-005)
5. **Expand adversarial tests:** Empty bodies, gzip bytes, HTTP/2 pseudo-headers, boundary lengths, collision cases. (FIND-015, FIND-016)
6. **Backfill missing WAFs:** Use WAFW00F and identYwaf signature databases as the source of truth. Do not add them one-by-one in Rust; add them in bulk via TOML.

**Total findings:** 244
