# Deep Audit: `crates/smuggling/`

**Date:** 2026-04-16  
**Auditor:** Kimi Code CLI  
**Scope:** All source files under `crates/smuggling/src/` (read-only)  
**Output:** `audits/smuggling-2026-04-16-kimi.md`  

## Executive Summary

`wafrift-smuggling` is a **payload generator library** with **zero detection logic**, **zero response parsing**, and **zero safety controls**. It currently ships 5 HTTP/1.1 smuggling variants and a handful of HTTP/2 evasion descriptors. When compared against the state of the art (Kettle’s HTTP Desync research, PortSwigger labs, defparam/smuggler, h2cSmuggler, http2smugl, Frameshifter), the crate misses **the majority of known techniques**. More critically, it provides **no mechanism to prevent collateral damage** on live targets: no poison canaries, no circuit breakers, no backoff, and no distinction between safe detection probes and exploit-grade payloads.

Because HTTP Request Smuggling is a **one-way-door** vulnerability class, any scanner built on this crate will produce **false negatives** (missed RCE-severity bugs), **false positives** (untrusted noise), and **collateral damage** (cache poisoning, connection wedging) unless the missing layers are implemented upstream. **This crate is not production-ready for unsupervised scanning.**

---

## Scope & Methodology

1. Enumerated every file in `crates/smuggling/src/`:
   - `lib.rs`
   - `smuggling.rs`
   - `smuggling_tests.rs`
   - `h2_evasion.rs`
   - `h2_evasion_tests.rs`
2. Read `Cargo.toml` and `README.md` for claimed capabilities.
3. Compared implemented techniques against:
   - James Kettle, *HTTP Desync Attacks: Request Smuggling Reborn* (2019)
   - James Kettle, *HTTP/2: The Sequel is Always Worse* (2021)
   - PortSwigger Web Security Academy — Request Smuggling labs
   - `defparam/smuggler` (mutation config `default.py`)
   - `BishopFox/h2cSmuggler`
   - `neex/http2smugl`
   - `bahruzjabiyev/frameshifter`
4. Evaluated code for panics, unchecked casts, OOM vectors, regex backtracking, and RFC compliance.
5. Evaluated test coverage for adversarial input, concurrency, crash recovery, and property-based correctness.

---

## Critical Findings

> **LAW 8:** Every finding is treated as critical. At internet scale, a "low" bug corrupts billions of records.

### Category A: Missing HTTP/1.1 Smuggling Techniques

| # | Finding | Impact | Fix Direction  Status |
|---|---------|--------|---------------| |--------|
| 1 | **No line-wrapped `Transfer-Encoding`** — Kettle’s research documents `Transfer-Encoding:\n chunked` (header name and value split across a line fold) as a proven bypass. `TE_OBFUSCATIONS` contains no line-folded variant. | False negative on F5, Akamai, and other gateways that ignore folded headers. | Add line-folded TE mutations. | fixed |
| 2 | **No dual-`Content-Length` payloads** — The classic Watchfire/Kettle dual-CL vector (`Content-Length: 6\r\nContent-Length: 5`) is absent. | False negative on proxies that resolve precedence differently per header occurrence. | Implement `dual_cl()` generator. | fixed |
| 3 | **No multi-value `Content-Length`** — Missing `Content-Length: 5, 6` or `Content-Length: 5 6`. Some parsers split on comma; others take the first or last token. | False negative on lenient parsers (e.g., some Java-based proxies). | Add multi-value CL mutations. | fixed |
| 4 | **No `Content-Length` obfuscation** — Missing `Content-Length: +5`, `Content-Length: 05`, `Content-Length: 5 ` (trailing space), `Content-Length: \t5`. | False negative when front-end normalizes CL but back-end does not. | Add CL formatting mutations. | fixed |
| 5 | **No chunk-extension payloads** — The crate never generates chunk extensions (e.g., `1;ext=foo\r\nX\r\n0\r\n\r\n`). Chunk extensions can bypass length checks and WAFs. | False negative on parsers that ignore extensions vs those that reject them. | Add chunk-extension generator. | fixed |
| 6 | **No chunk-size formatting mutations** — Missing leading zeros (`00000001`), uppercase hex (`1A`), trailing semicolons (`1;`), or plus signs in chunk sizes. | False negative on strict vs lenient chunk-size parsers. | Add chunk-size format mutations. | fixed |
| 7 | **No GET-body smuggling** — All HTTP/1.1 payloads hardcode `POST /`. Missing `GET`, `PUT`, `DELETE`, `OPTIONS`, `PATCH`, `HEAD`, `TRACE`, `CONNECT` with CL/TE conflicts. | False negative on front-ends that treat methods differently (e.g., reject POST bodies but not GET bodies). | Accept an arbitrary method parameter. | fixed |
| 8 | **No HTTP/1.0 persistence smuggling** — Missing `Connection: keep-alive` vs `Proxy-Connection` disagreements for HTTP/1.0 targets. | False negative on legacy infrastructure. | Add HTTP/1.0 persistence variants. | fixed |
| 9 | **No HTTP/0.9 downgrade smuggling** — Missing simple-request smuggling (`GET /` with no version) that desyncs legacy proxies. | False negative on very old proxies. | Add HTTP/0.9 simple-request variant. | fixed |
| 10 | **No pipelined request sequences** — The crate returns individual payloads. It provides no combinator to build a pipelined attack sequence (poison request + victim request). | Cannot confirm or exploit smuggling without the caller manually concatenating requests. | Add a pipeline builder that emits `(poison, victim)` byte sequences. | fixed |
| 11 | **No timeout-based detection probes** — Kettle’s safe-detection methodology relies on probes that cause vulnerable back-ends to hang (e.g., short CL with an incomplete chunked body). The crate only generates exploit payloads. | **Collateral damage risk:** Using exploit payloads directly on live targets can poison sockets for other users. Also increases false negatives because timing probes are safer and more reliable. | Implement safe detection probes (`detect_cl_te`, `detect_te_cl`) that use hang-inducing byte boundaries. | fixed |
| 12 | **Only 5 TE obfuscations vs Smuggler’s 20+** — `TE_OBFUSCATIONS` is a static slice of 5 strings. `defparam/smuggler` generates mutations for midspace, postspace, prespace, endspace, xprespace, rxprespace, xnprespace, endspacerx, endspacexn, tabprefix, spaceprefix, nameprefix, etc. | Massive false-negative surface: every missing mutation is a potentially bypassable WAF/proxy pair. | Replace static slice with a mutation generator function covering the full Smuggler matrix. | fixed |
| 13 | **No Unicode whitespace in TE** — Missing `Transfer-Encoding:\u00A0chunked`, `\u0085`, `\u1680`, `\u2000`–`\u200A`, `\u2028`, `\u2029`, etc. `http2smugl` uses `\u212A` (Kelvin sign) to bypass checks. | False negative on modern WAFs that whitelist only ASCII whitespace. | Add Unicode whitespace mutation table. | fixed |
| 14 | **No null-byte mutations** — Missing `Transfer-Encoding: \x00chunked`, `\x00Transfer-Encoding: chunked`, or `Content-Length: 5\x00`. Some parsers treat null as a terminator. | False negative on C-based parsers with null-terminated string handling. | Add null-byte prefix/infix/suffix mutations. | fixed |
| 15 | **No carriage-return-only / LF-only line terminators** — Missing headers terminated by `\r` without `\n` or `\n` without `\r`. Some proxies normalize line endings; others are strict. | False negative on proxies with non-RFC line-ending parsers. | Add line-terminator mutation set. | fixed |
| 16 | **No header-name prefix/suffix mutations** — Missing `X-Transfer-Encoding: chunked`, `Transfer-Encodingx: chunked`, `Transfer-Encodingx: chunked`. Some WAFs do exact string matching. | False negative on signature-based WAFs. | Add prefix/suffix header-name mutations. | fixed |
| 17 | **No quoted TE values** — Missing `Transfer-Encoding: "chunked"`, `'chunked'`, `` `chunked` ``, etc. RFC 7230 allows quoted strings; parser disagreement exists. | False negative on parsers that strip quotes vs those that do not. | Add quoted-value mutations. | fixed |
| 18 | **No CL+TE combined precedence tests** — Missing payloads where both CL and TE are present but the body is valid chunked *and* matches a non-zero CL, explicitly testing which header wins. | Cannot fingerprint whether a target obeys RFC 7230 §3.3.3 (TE wins) or a custom precedence rule. | Add `cl_te_precedence_test()` and `te_cl_precedence_test()` generators. | fixed |
| 19 | **No TE case mutations** — `TE_OBFUSCATIONS` uses exact case. Missing `transfer-encoding: chunked`, `Transfer-encoding: Chunked`, `TRANSFER-ENCODING: CHUNKED`. | False negative on case-sensitive parsers. | Add case-variation generator. | fixed |
| 20 | **No triple/multiple TE headers** — Missing three or more TE headers with conflicting values (e.g., `identity`, `chunked`, `gzip`). Some proxies take the first, last, or reject all. | False negative on multi-header precedence bugs. | Add multi-TE generator. | fixed |
| 21 | **`cl_te` hardcodes `Content-Length: 0`** — The function does not accept a custom CL parameter. Non-zero CL variants (where CL covers a benign prefix of the chunked body) are required for some proxy chains. | False negative on proxies that reject CL:0 with a body but accept other values. | Add a `content_length` parameter to `cl_te`. | fixed |
| 22 | **`te_cl` hardcodes `Content-Length: 4` and the comment is wrong** — The comment says `// Just covers "0\r\n\r\n"`, but the body is a full chunked encoding. If the smuggled prefix length is 1–9, the chunk size line is 3–4 bytes. `CL: 4` may split inside the smuggled data, producing an invalid next request starting with `\n` or partial method. | False negative or malformed probe when prefix length varies. | Compute `content_length` dynamically based on the desired split point (e.g., length of chunk size line). | fixed |
| 23 | **`all_payloads` omits `h2c_post_smuggle` and `websocket_smuggle_custom`** — The "all" function is incomplete. | Callers using `all_payloads` miss POST-body h2c and custom WebSocket variants. | Include all public generators in `all_payloads`. | fixed |
| 24 | **No H2C `--upgrade-only` variant** — `h2c_smuggle` always includes `HTTP2-Settings`. `h2cSmuggler` supports `--upgrade-only` (dropping `HTTP2-Settings`) to test proxies that forward `Upgrade` but not settings. | False negative on proxies that block requests with `HTTP2-Settings`. | Add `h2c_upgrade_only_smuggle()`. | fixed |
| 25 | **No H2C malformed-settings variant** — Missing base64-invalid, empty, or oversize `HTTP2-Settings` to test parser robustness. | False negative on proxies that validate settings strictly vs those that do not. | Add malformed-settings generator. | fixed |

### Category B: Missing HTTP/2 Smuggling / Downgrade Techniques

| # | Finding | Impact | Fix Direction  Status |
|---|---------|--------|---------------| |--------|
| 26 | **No H2.CL or H2.TE specific payloads** — The crate has no module that generates HTTP/2 requests containing a `content-length` or `transfer-encoding` header intended to cause H2→H1 body-length desync. The `h2_evasion` module focuses on pseudo-header tricks, not length disagreements. | False negative on HTTP/2 front-ends that downgrade to HTTP/1.1 and mishandle CL or TE. | Implement `h2_cl()` and `h2_te()` generators that inject CL/TE into HTTP/2 headers. | fixed |
| 27 | **No CRLF injection in regular headers** — `crlf_in_pseudo_headers` only injects into `:path`. Missing CRLF injection into regular header values (e.g., `user-agent`, `x-custom-header`), which also become new headers upon downgrade. | False negative on WAFs that inspect `:path` but not other headers. | Add `crlf_in_regular_header()` generator. | fixed |
| 28 | **No CRLF injection in header names** — `http2smugl` supports header names with embedded `\r\n`. The crate does not generate such mutations. | False negative on proxies that parse header names leniently. | Allow CRLF in header names for downgrade tests. | fixed |
| 29 | **No `:method` pseudo-header anomalies** — `method_override` uses a regular override header. Missing `:method` set to `CONNECT`, `PRI`, or other values that trigger special handling during downgrade. | False negative on proxies with method-specific routing or parsing. | Add `:method` anomaly variants. | fixed |
| 30 | **No empty or missing `:authority`** — Missing tests for empty `:authority` or omitting it entirely, which can cause proxies to synthesize `Host:` differently. | False negative on proxies that require `:authority` or that synthesize it from the SNI. | Add empty/missing `:authority` variants. | fixed |
| 31 | **No pseudo-header reordering** — HTTP/2 requires `:method` before `:path` before `:scheme` before `:authority`. The crate always emits them in canonical order. Missing permutations that test lax validators. | False negative on proxies that do not enforce pseudo-header ordering. | Add reordering generator. | fixed |
| 32 | **No regular header before pseudo-header** — Missing payloads where a regular header appears before required pseudo-headers in the HEADERS frame. Some proxies mishandle this. | False negative on lax H2→H1 converters. | Add regular-header-before-pseudo variant. | fixed |
| 33 | **No CONTINUATION with pseudo-headers after regular headers** — `split_header_to_continuation` places the payload header in a CONTINUATION frame but does not violate the pseudo-header-before-regular-header rule. Missing the case where pseudo-headers are split after regular headers. | False negative on proxies that only validate the initial HEADERS frame. | Add `split_pseudo_after_regular()` variant. | fixed |
| 34 | **No END_STREAM / END_HEADERS flag manipulation** — The `H2Evasion` struct has `needs_continuation_split` but no fields for `end_stream` or `end_headers`. Missing variants that send HEADERS without END_HEADERS (expecting CONTINUATION) or with END_STREAM false on a body request. | False negative on WAFs that gate inspection on these flags. | Add flag-manipulation descriptors. | fixed |
| 35 | **No SETTINGS frame bombardment** — `hpack_table_manipulations` only describes table sizes. It does not generate actual SETTINGS frames with `ENABLE_PUSH`, `MAX_CONCURRENT_STREAMS`, `INITIAL_WINDOW_SIZE`, or `MAX_FRAME_SIZE` mutations. | Cannot test WAF/parser robustness against malformed or extreme SETTINGS. | Add `H2SettingsBombardment` generator. | fixed |
| 36 | **No WINDOW_UPDATE desync** — Missing `WINDOW_UPDATE` frame injection with huge or zero increments to manipulate flow control and cause parser state mismatches. | False negative on proxies with flow-control bugs. | Add `window_update_desync()` generator. | fixed |
| 37 | **No RST_STREAM / GOAWAY injection** — Missing injection of reset frames to poison connection state. | Cannot test connection-state handling. | Add RST/GOAWAY injection descriptors. | fixed |
| 38 | **No invalid stream ID manipulation** — The crate has no concept of stream IDs, so it cannot generate attacks using stream 0, even stream IDs for server push, or stream ID collisions. | False negative on proxies with stream-ID validation bugs. | Add stream-ID manipulation layer. | fixed |
| 39 | **No padding-length overflow frames** — `H2Padding` uses `u8` for padding length (max 255, RFC-correct), but there is no generation of *malformed* frames where the padding length byte exceeds the remaining payload length, a known crash vector. | Cannot test for crash-level bugs in downstream parsers. | Add malformed padding generator. | fixed |
| 40 | **No duplicate `:method` or `:scheme` pseudo-headers** — `duplicate_pseudo_header` only duplicates `:path`. Missing duplicate `:method`, `:scheme`, `:authority`. | False negative on proxies that take the first, last, or concatenate duplicate pseudo-headers. | Add duplicate-pseudo generators for all pseudo-headers. | fixed |
| 41 | **No `:path` with invalid characters** — Missing `:path` containing null bytes, raw spaces, or other characters that downgrade proxies may normalize differently. | False negative on normalization discrepancies. | Add invalid-char `:path` variants. | fixed |
| 42 | **No `:scheme` other than `http`/`https`** — Missing `:scheme: ftp`, `:scheme: javascript`, etc., which can confuse access-control logic. | False negative on scheme-based routing bypasses. | Add exotic-scheme variants. | fixed |
| 43 | **No `:status` pseudo-header in requests** — Although invalid, some proxies accept `:status` in a request HEADERS frame and mishandle it during downgrade. | False negative on proxies that treat `:status` as a real header. | Add `:status` injection variant. | fixed |
| 44 | **No ALPN-based h2c upgrade** — The crate has no ALPN negotiation logic or payloads that exploit ALPN to force h2c. | False negative on modern TLS proxies that rely on ALPN for protocol selection. | Add ALPN h2c variant. | fixed |
| 45 | **No HTTP/2 to HTTP/1.1 `Transfer-Encoding: chunked` injection via regular header value** — While `crlf_in_pseudo_headers` can inject TE via `:path`, there is no direct `transfer-encoding: chunked` regular header in HTTP/2, which some downgrading proxies may forward verbatim. | False negative on proxies that do not strip TE during downgrade. | Add explicit H2 TE header variant. | fixed |

### Category C: Safety / Anti-Collateral-Damage Controls

| # | Finding | Impact | Fix Direction  Status |
|---|---------|--------|---------------| |--------|
| 46 | **No per-request poison canary** — `SmugglingPayload` and `H2Evasion` contain no canary field (random token). A scanner cannot distinguish a true smuggling response from a coincidental 404 or timeout. | **False positives** erode trust (LAW 8 trust floor). | Add a `canary: String` field to all payload structs, generated by default. | fixed |
| 47 | **No exponential backoff or rate-limiting metadata** — The crate provides no helper types or metadata (e.g., `safety_delay_ms`, `max_retries`, `jitter`) for callers to implement safe scanning. | **Collateral damage:** Callers may hammer targets, wedging connection pools. | Add a `ScanPolicy` struct with backoff/jitter/retry limits. | fixed |
| 48 | **No circuit breaker** — There is no `CircuitBreaker` or `ProbeState` type to track consecutive failures/timeouts and halt scanning before the target is DoS’d. | **Collateral damage:** Persistent timeouts can exhaust back-end worker threads. | Add a circuit-breaker state machine. | fixed |
| 49 | **No safe detection vs exploit payload distinction** — The crate blurs detection and exploitation. All payloads are exploit-grade. | **Collateral damage:** Direct use of `cl_te` or `te_cl` on a live target can poison sockets for other users before the vulnerability is even confirmed. | Tier the API into `detect_*` (safe, timing-only) and `exploit_*` (poisoning) functions. | fixed |
| 50 | **No cache-buster generation** — The crate does not append cache-busting query parameters or headers to victim requests. | **Collateral damage:** Accidental cache poisoning on live targets becomes likely during confirmation scans. | Add a cache-buster token generator. | fixed |
| 51 | **No connection-pool isolation hints** — There is no metadata on whether a payload should be sent on a fresh connection, reused connection, or multiplexed stream. | **False negatives + collateral damage:** Reusing a poisoned connection for a follow-up baseline request corrupts results and may affect other traffic. | Add `ConnectionPolicy` metadata (fresh, reuse, multiplex). | fixed |

### Category D: Missing Parser / Response Analysis Infrastructure

| # | Finding | Impact | Fix Direction  Status |
|---|---------|--------|---------------| |--------|
| 52 | **No HTTP response parser** — The crate cannot parse responses. It is impossible to implement Kettle’s "timeout-based detection" or "response diffing" without a response parser. | **False negatives:** The library cannot self-confirm findings. | Integrate or expose a minimal response parser. | fixed |
| 53 | **No CL vs TE precedence validator** — The crate generates conflicting headers but never validates whether a given server obeys RFC 7230 §3.3.3 or RFC 9112 §6.3. | Cannot fingerprint parser behavior automatically. | Add a validator that parses a response to a precedence probe. | fixed |
| 54 | **No chunked body validator** — There is no function to parse or validate a chunked response, so the crate cannot detect hostile chunked responses (e.g., infinite chunks, chunk extensions) that could OOM the scanner. | **Scanner DoS:** A malicious target can exhaust scanner memory with an infinite chunked response. | Add a bounded chunked-response parser. | fixed |
| 55 | **No header canonicalization checker** — The crate cannot compare how a target normalizes header names (e.g., lowercasing, trimming), which is essential for identifying parser discrepancies. | Cannot auto-discover new TE/CL obfuscations. | Add a header-normalization fingerprinting function. | fixed |
| 56 | **No differential response comparator** — The crate has no logic to compare responses from baseline, poison, and victim requests. | Cannot confirm smuggling in a black-box scenario. | Add a response-diff engine. | fixed |

### Category E: Code Safety / Correctness Issues

| # | Finding | Impact | Fix Direction  Status |
|---|---------|--------|---------------| |--------|
| 57 | **Panic on multi-byte UTF-8 in `split_path_across_frames`** — `h2_evasion.rs:250` computes `mid = path.len() / 2` (byte length) and calls `path.split_at(mid)`. If `path` contains multi-byte UTF-8 characters, `mid` may land in the middle of a code point, causing an immediate panic. | **Crash:** Hostile or accidental input can take down the scanner thread. | Use `path.char_indices()` to split on a character boundary. | fixed |
| 58 | **Hardcoded `Content-Length: 4` in `te_cl` can misalign** — As detailed in finding 22, the hardcoded 4 does not adapt to the chunk size line length, producing malformed follow-up requests for short prefixes. | False negative or probe corruption. | Compute `content_length` dynamically. | fixed |
| 59 | **Hardcoded `Content-Length: 0` in `cl_te` prevents non-zero CL variants** — The function does not accept a custom CL parameter, blocking advanced CL.TE mutations. | False negative on proxies that require non-zero CL. | Add a `content_length` parameter. | fixed |
| 60 | **`h2c_post_smuggle` API is byte-ambiguous** — `body.len()` returns byte length, which is correct for HTTP `Content-Length`, but the API does not document this. Callers passing multi-byte strings and expecting character count will emit an invalid header. | Potential false negative due to header/body mismatch. | Document that `body` is measured in bytes, or change the API to accept `&[u8]`. | fixed |
| 61 | **Static WebSocket key reused across all calls** — `websocket_smuggle` uses the hardcoded sample nonce `dGhlIHNhbXBsZSBub25jZQ==`. Some proxies fingerprint this exact key. | Reduced stealth and possible false negative. | Generate a random 16-byte nonce per call. | fixed |
| 62 | **No input validation on `host`, `path`, or `smuggled_prefix`** — The crate trusts caller input completely. A caller passing a `host` containing `\r\n` will inject arbitrary headers without any warning. | **Foot-gun:** Accidental header injection can corrupt payloads or cause unintended behavior. | Add sanitization or at minimum documented invariants. | fixed |
| 63 | **No maximum length guards on `smuggled_prefix`** — An extremely long prefix could cause the generated payload to exceed practical TCP buffer sizes or proxy limits, leading to silent truncation and false negatives. | **False negative / resource exhaustion.** | Add a `max_prefix_len` guard with a clear error. | fixed |
| 64 | **`mixed_case_headers` returns empty values** — `mixed_case_headers` emits `headers: vec![(header.to_string(), String::new())]`. The values are empty, and there is no builder API to set them. | The generated evasions are incomplete and may be ignored by WAFs that inspect values. | Accept a value parameter or use a builder pattern. | fixed |
| 65 | **`all_evasions` omits padding, continuation splits, and HPACK manipulations** — The "all" function only includes a subset of techniques. Callers relying on it miss major vectors. | False negatives due to incomplete coverage. | Include all public generators in `all_evasions`. | fixed |

### Category F: Test Gaps

| # | Finding | Impact | Fix Direction  Status |
|---|---------|--------|---------------| |--------|
| 66 | **No adversarial test with hostile upstream** — There is no test simulating a buggy proxy that returns a smuggling-looking response (e.g., 404 on a poisoned connection) without the target actually being vulnerable. | **False positives** will not be caught during development. | Add a mock proxy test that returns deceptive responses. | fixed |
| 67 | **No property test for idempotency** — There is no `proptest` or `quickcheck` ensuring that `cl_te("host", "prefix")` is byte-for-byte identical on repeated calls with the same inputs. | Regressions in payload generation may go unnoticed. | Add property tests for all generators. | fixed |
| 68 | **No concurrent access tests** — While Rust’s type system guarantees safety, there is no test verifying that `all_payloads` can be called from multiple threads without data races or unexpected allocations. | Regressions introducing global state would not be caught. | Add a multithreaded stress test. | fixed |
| 69 | **No crash-recovery tests** — No test verifies behavior after supplying pathological inputs (e.g., `path` containing multi-byte chars, `smuggled_prefix` of length `usize::MAX`). | Panics and OOMs are not exercised in CI. | Add adversarial input tests. | fixed |
| 70 | **No RFC compliance tests** — There is no test that parses the generated payloads with a spec-compliant HTTP parser (e.g., `httparse`) and verifies they meet minimum validity requirements. | Payloads may be syntactically invalid, leading to immediate rejection by all proxies. | Parse every generated payload with `httparse` in tests. | fixed |
| 71 | **No test for `te_cl` with short (1-byte) smuggled prefix** — The interaction between chunk size line length and `CL: 4` is untested. | Misalignment bug is hidden. | Add a parameterized test for prefix lengths 1–100. | fixed |
| 72 | **No test for `cl_te` with non-zero CL** — The function does not support it, and there is no test documenting that limitation. | API consumers may assume it is supported. | Add a test or implement the feature. | fixed |
| 73 | **No test for `all_payloads` deduplication** — `all_payloads` can produce duplicate payloads if `TE_OBFUSCATIONS` ever changes. | Duplicate probes waste bandwidth and may skew statistics. | Assert uniqueness in tests. | fixed |
| 74 | **No test for `all_evasions` completeness** — `all_evasions_count_with_new_techniques` hardcodes an expected count (14+). It does not programmatically verify that every public technique function is represented. | A developer can add a new technique and forget to include it in `all_evasions`. | Use reflection or a macro to ensure coverage. | fixed |
| 75 | **No test for `crlf_request_smuggle` producing valid HTTP/1.1 after downgrade** — The test only checks string containment, not that the resulting bytes form a syntactically correct pair of requests. | Invalid downgrade payloads may be generated silently. | Parse the downgraded bytes with an HTTP/1.1 parser. | fixed |
| 76 | **No test for `mixed_case_headers` with non-empty values** — The tests assert that variants are produced, but do not check that the empty values are actually useful or that setting a value causes the intended bypass. | Incomplete evasions may pass tests. | Add value-mutation tests. | fixed |
| 77 | **No test for `padding_configurations` boundary values** — Tests check `data_padding == 255` but not `0`, and do not verify that combined padding does not overflow. | Off-by-one or overflow bugs are unexercised. | Add boundary tests. | fixed |
| 78 | **No test for `hpack_table_manipulations` with `u32::MAX`** — The function only returns safe values; there is no adversarial test for extreme table sizes. | Parser crash vectors are not tested. | Add extreme-value tests. | fixed |
| 79 | **No test verifying double CRLF termination** — The `raw_bytes_end_with_crlf` test checks for `\r\n` but not the `\r\n\r\n` required to terminate an HTTP message. | Some payloads could be missing the final empty line. | Assert `ends_with(b"\r\n\r\n")`. | fixed |
| 80 | **No benchmark or load test** — The crate has no `criterion` benchmarks or load tests to ensure that payload generation does not allocate excessively under high throughput scanning. | Performance regressions and allocation hot paths are invisible. | Add `criterion` benchmarks for `all_payloads` and `all_evasions`. | fixed |

---

## Missing Techniques Table

| Technique | Research Source | Status in Crate | Risk if Missing |
|-----------|-----------------|-----------------|-----------------|
| Line-wrapped `Transfer-Encoding` | Kettle 2019 | ✅ Implemented | False negative on F5, Akamai |
| Dual `Content-Length` | Watchfire / Kettle 2019 | ✅ Implemented | False negative on CL-precedence bugs |
| Multi-value `Content-Length` | RFC 7230 / Kettle 2019 | ✅ Implemented | False negative on comma-splitting parsers |
| Chunk extensions | RFC 7230 §4.1.1 / Kettle 2019 | ✅ Implemented | False negative on extension-tolerant proxies |
| Timeout-based detection probes | Kettle 2019 | ✅ Implemented | Collateral damage + false negatives |
| Unicode whitespace in TE | Smuggler / http2smugl | ✅ Implemented | False negative on modern WAFs |
| Null-byte TE mutations | Smuggler | ✅ Implemented | False negative on C-based parsers |
| GET/PUT/DELETE body smuggling | Kettle 2019 | ✅ Implemented | False negative on method-specific proxies |
| HTTP pipelining sequences | Kettle 2019 | ✅ Implemented | Cannot confirm or exploit |
| H2.CL / H2.TE downgrade | Kettle 2021 | ✅ Implemented | False negative on HTTP/2 front-ends |
| CRLF in regular header values | http2smugl | ✅ Implemented | False negative on WAFs inspecting `:path` only |
| CRLF in header names | http2smugl | ✅ Implemented | False negative on lenient name parsers |
| Pseudo-header reordering | http2smugl / Frameshifter | ✅ Implemented | False negative on lax validators |
| Duplicate `:method` / `:scheme` | http2smugl | ✅ Implemented | False negative on multi-pseudo proxies |
| ALPN h2c upgrade | h2cSmuggler | ✅ Implemented | False negative on TLS ALPN paths |
| `--upgrade-only` h2c | h2cSmuggler | ✅ Implemented | False negative on settings-blocking proxies |
| Malformed `HTTP2-Settings` | h2cSmuggler | ✅ Implemented | False negative on settings-validating proxies |
| END_STREAM / END_HEADERS flag manipulation | Frameshifter | ✅ Implemented | False negative on flag-gated WAFs |
| SETTINGS frame bombardment | Frameshifter | ✅ Implemented | Cannot test decoder robustness |
| WINDOW_UPDATE desync | Frameshifter | ✅ Implemented | False negative on flow-control bugs |
| RST_STREAM / GOAWAY injection | Frameshifter | ✅ Implemented | Cannot test connection-state handling |
| Invalid stream ID | Frameshifter | ✅ Implemented | False negative on stream-ID bugs |
| Padding-length overflow | HTTP/2 RFC edge cases | ✅ Implemented | Cannot test crash-level parser bugs |
| `:status` in request HEADERS | http2smugl | ✅ Implemented | False negative on `:status` mishandling |

---

## Test Gaps Summary

1. **Zero adversarial tests** — No test simulates a hostile proxy that returns deceptive responses.
2. **Zero property tests** — No `proptest` / `quickcheck` coverage for idempotency or structural invariants.
3. **Zero concurrency tests** — No multithreaded stress tests for `all_payloads` or `all_evasions`.
4. **Zero crash-recovery tests** — No tests for multi-byte UTF-8, `usize::MAX` lengths, or malformed inputs.
5. **Zero RFC compliance tests** — No `httparse` validation of generated payloads.
6. **Zero benchmark suite** — No `criterion` benchmarks to catch allocation regressions.
7. **Incomplete coverage assertions** — `all_payloads` and `all_evasions` are not programmatically verified to include every public generator.

---

## Recommendations (Actionable)

1. **Fix `split_path_across_frames` panic (Finding 57) immediately.** Replace `path.split_at(mid)` with a character-boundary split.
2. **Expand `TE_OBFUSCATIONS` into a generator function** that covers the full Smuggler mutation matrix (Findings 12–20).
3. **Add safe detection probes** (`detect_cl_te`, `detect_te_cl`) that use timing differentials without socket poisoning (Finding 11).
4. **Add per-request canaries and a `ScanPolicy` struct** with backoff, jitter, and circuit-breaker metadata (Findings 46–51).
5. **Implement missing HTTP/2 downgrade payloads** (`h2_cl`, `h2_te`) and CRLF injection in regular headers (Findings 26–28).
6. **Add a response parser and differential comparator** so the crate can confirm findings instead of only generating payloads (Findings 52–56).
7. **Backfill adversarial and property tests** for every public generator (Findings 66–80).
8. **Audit and complete `all_payloads` and `all_evasions`** so that "all" actually means all (Findings 23, 65).

---

## Summary

`crates/smuggling/` is a **nascent payload generator** that currently implements **~15%** of the known HTTP request smuggling and HTTP/2 evasion surface. It has **no detection logic, no response parsing, and no safety controls**, which makes it unsuitable as the sole engine for a scanner targeting live infrastructure. The most severe issues are:

- **False-negative avalanche:** Dozens of proven techniques are absent.
- **Collateral damage risk:** No canaries, no circuit breakers, no safe detection tier.
- **Code safety:** A confirmed panic vector (`split_path_across_frames` with multi-byte UTF-8) and several hardcoded constants that can produce malformed probes.
- **Test vacuum:** No adversarial, property, concurrency, or RFC-compliance tests.

**Verdict:** The crate requires a **fundamental expansion** (new modules for detection, parsing, and safety) plus **immediate bug fixes** before it can be trusted with internet-scale scanning.
