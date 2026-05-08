# wafrift-encoding audit — 2026-04-16 (Kimi)

## Crate purpose and correctness guarantees

wafrift-encoding is a payload and header transformation library whose sole correctness guarantee is that every encoding variant it produces must be interpreted by the target server as semantically equivalent to the original payload, while evading WAF inspection. Any semantic drift—where the server decodes the payload differently than intended—results in false negatives (missed vulnerabilities) at internet scale. The crate must therefore preserve byte-level semantics for byte-oriented encodings, respect parser contexts for text-oriented encodings, and never panic, truncate, or OOM on adversarial input.

## Findings

### F-001 [CRITICAL] `String::from_utf8_lossy` silently corrupts invalid UTF-8 payloads
**Location**: `crates/encoding/src/encoding/strategy.rs:74` (and callers in `structural.rs`, `tamper.rs`)
**Class**: semantic-drift
**Evidence**: `let text = String::from_utf8_lossy(payload);` in the `encode()` dispatcher. If the input contains invalid UTF-8 sequences (e.g., `\x80\x81`), they are replaced with the Unicode replacement character `U+FFFD` (`�`) before any text-oriented strategy (Unicode, HTML entity, case alternation, etc.) processes them. The server will later decode the encoded `�`, not the original bytes.
**Why it matters**: At internet scale, scanners probe binary endpoints, legacy protocols, and malformed inputs. Silently mutating the payload means the attack string that reaches the target is not the one the engine intended to send, causing real vulnerabilities to be missed.
**Recommended fix**: Remove the blanket `from_utf8_lossy` in the dispatcher. Pass `&[u8]` directly to byte-oriented strategies (URL, base64, hex, chunked). For text-oriented strategies, use `std::str::from_utf8` and return a typed error rather than lossily replacing invalid sequences.
**Status**: open

### F-002 [CRITICAL] `UrlEncode` over-encodes unreserved characters, causing semantic drift on naive parsers
**Location**: `crates/encoding/src/encoding/url.rs:6-14`
**Class**: semantic-drift
**Evidence**: `for b in payload { let _ = write!(&mut out, "%{b:02X}"); }` encodes `A` as `%41`, `.` as `%2E`, `-` as `%2D`, `_` as `%5F`, and `~` as `%7E`. RFC 3986 defines these as unreserved characters that should NOT be percent-encoded. While most servers full-decode, simple middleware, caches, or regex-based parsers may treat `%41` as the literal string `%41`, changing the payload semantics.
**Why it matters**: A scanner sending `%41%44%4D%49%4E` instead of `ADMIN` may be processed as literal percent-sequences by a lightweight frontend (e.g., HAProxy ACLs, custom Lua routing), causing the backend to never see the intended keyword.
**Recommended fix**: Only encode reserved characters and anything outside the unreserved set per RFC 3986. Leave `A-Za-z0-9-_.~` untouched.
**Status**: open

### F-003 [CRITICAL] `UnicodeEncode` (`\uXXXX`) and `HtmlEntityEncode` (`&#xXX;`) produce semantic drift outside JSON/HTML contexts
**Location**: `crates/encoding/src/encoding/unicode.rs:9-15`, `17-28`
**Class**: semantic-drift
**Evidence**: `unicode_encode("A")` produces `\u0041`. Unless the target application explicitly JSON-parses the parameter, nginx, Apache, Tomcat, Flask, and Node.js will treat it as the literal 6-character string `\u0041`, not as `A`. The same applies to `&#x41;` outside an HTML entity parser.
**Why it matters**: These strategies are applied blindly to HTTP query strings and form data in the examples. The server receives a completely different byte sequence, so the attack never reaches the application logic.
**Recommended fix**: Add prominent doc comments (and runtime context hints) stating that `UnicodeEncode` is ONLY safe when the target parser performs JSON/JavaScript decoding, and `HtmlEntityEncode` is ONLY safe in HTML contexts. Do not apply them to raw HTTP parameters.
**Status**: open

### F-004 [CRITICAL] `OverlongUtf8` produces sequences rejected by modern servers as invalid UTF-8
**Location**: `crates/encoding/src/encoding/structural.rs:27-41`
**Class**: semantic-drift
**Evidence**: `/` is encoded as `%C0%AF`. nginx (since 0.7.17), Apache httpd with mod_security, Node.js, Python Flask (via Werkzeug), and Tomcat all return HTTP 400 for overlong UTF-8 because it is malformed per RFC 3629. The server rejects the request outright; the payload never reaches the application.
**Why it matters**: This strategy is marketed as a bypass, but for the majority of modern stacks it causes the request to be dropped entirely. The scanner will see a 400 and may classify the endpoint as non-vulnerable.
**Recommended fix**: Document that this technique only works against specific legacy WAFs/frontends that normalize overlong sequences rather than rejecting them. Gate it behind a context flag (e.g., `context: "iis-6"`) so it is not fired blindly at modern targets.
**Status**: open

### F-005 [CRITICAL] `NullByte` strategy appends `%00` which truncates in C parsers but is literal elsewhere
**Location**: `crates/encoding/src/encoding/structural.rs:11-19`
**Class**: semantic-drift
**Evidence**: `format!("{payload_str}%00")`. For C-based backends (PHP, some CGI), `%00` decodes to `\x00` and truncates strings. For Java, Python, Node.js, and modern Go services, `%00` is decoded to a literal null byte inside the string without truncation, changing the parsed value (e.g., `id=1%00` is not equivalent to `id=1`).
**Why it matters**: Applying null-byte injection universally assumes C-string semantics. On non-C backends it mutates the payload without achieving truncation, producing false negatives or syntax errors.
**Recommended fix**: Add a context hint (e.g., `context: "php"`) and document that this strategy is only semantically correct for backends using C-style null-terminated string handling.
**Status**: open

### F-006 [CRITICAL] `ChunkedSplit` generates a full chunked body without guaranteeing matching HTTP framing
**Location**: `crates/encoding/src/encoding/structural.rs:48-62`
**Class**: semantic-drift
**Evidence**: Output is `3\r\nabc\r\n0\r\n\r\n`. If this string is placed in a query parameter or a standard POST body without the corresponding `Transfer-Encoding: chunked` header, the server sees literal chunk framing, not the original payload.
**Why it matters**: The crate examples show layered encoding where `ChunkedSplit` is treated like any other string encoder. Unless the caller explicitly sends the result as a chunked request body, the payload is garbled.
**Recommended fix**: Add a doc comment stating this strategy is ONLY semantically correct when the resulting string is sent as the body of an HTTP request with `Transfer-Encoding: chunked`. Consider returning a structured type `(body: String, required_headers: Vec<(String,String)>)` instead of a raw string.
**Status**: open

### F-007 [CRITICAL] `Utf7Encode` is a naive mock that does not implement RFC 2152 correctly
**Location**: `crates/encoding/src/encoding/structural.rs:94-107`
**Class**: semantic-drift
**Evidence**: The code base64-encodes each non-ASCII character individually with `+b64-`. It does not escape the `+` character (`+-`), does not use the modified base64 alphabet required by UTF-7, does not handle shift sequences, and does not implement optional direct characters. A real UTF-7 decoder (e.g., old IIS/.NET) will fail to decode the output.
**Why it matters**: The module docs claim it is "simple mock or real UTF-7". If a caller relies on it against a target that actually decodes UTF-7, the payload will be mis-decoded or rejected.
**Recommended fix**: Either implement a standards-compliant RFC 2152 UTF-7 encoder with proper shifting and `+-` escaping, or delete the strategy (per LAW 1: no stubs).
**Status**: open

### F-008 [CRITICAL] `encode_layered` allows exponential memory growth without input size limits
**Location**: `crates/encoding/src/encoding/layered.rs:12-18`
**Class**: oom
**Evidence**: `let mut result = String::from_utf8_lossy(payload.as_ref()).into_owned();` then loops, reassigning `result = encode(&result, *strategy)`. Each layer can multiply size (e.g., `UrlEncode` ×3, `UnicodeEncode` ×6). A 16 MB payload with 3 layers can allocate hundreds of MB or GB.
**Why it matters**: An attacker can feed a multi-megabyte payload to the scanner and OOM-kill the process, turning the encoding crate into a denial-of-service vector against the scanner itself.
**Recommended fix**: Add a hard input size limit (e.g., 1 MB) before layered encoding, and abort with an error if the accumulated output exceeds a cap (e.g., 8 MB).
**Status**: open

### F-009 [CRITICAL] `line_fold` panics on multi-byte UTF-8 header values
**Location**: `crates/encoding/src/header.rs:107-113`
**Class**: panic
**Evidence**: `let mid = value.len() / 2;` uses byte length, then `&value[..mid]` slices by byte index. If `value` contains a multi-byte UTF-8 character (e.g., emoji, CJK) and `mid` falls inside the byte sequence, the `&str` slice panics at runtime with "byte index is not a char boundary".
**Why it matters**: Header values can legitimately contain UTF-8 in modern applications (e.g., `X-Custom-Name: 日本語`). A single such header will crash the scanner thread.
**Recommended fix**: Use `value.floor_char_boundary(mid)` (Rust 1.73+) or `value.char_indices()` to find a valid char boundary near the midpoint.
**Status**: open

### F-010 [CRITICAL] `multi_line_fold` panics on multi-byte UTF-8 header values
**Location**: `crates/encoding/src/header.rs:120-132`
**Class**: panic
**Evidence**: `let third = value.len() / 3;` followed by three byte-index slices `&value[..third]`, `&value[third..third*2]`, `&value[third*2..]`. Same char-boundary panic risk as F-009 when the value contains multi-byte UTF-8.
**Why it matters**: Same as F-009 — a header value with non-ASCII characters will crash the scanner.
**Recommended fix**: Compute split points on char boundaries using `char_indices()`.
**Status**: open


### F-011 [CRITICAL] `null_byte_inject` in header module panics on multi-byte UTF-8 header names
**Location**: `crates/encoding/src/header.rs:165-171`
**Class**: panic
**Evidence**: `let mid = header_name.len() / 2;` then `&header_name[..mid]`. If the header name contains multi-byte UTF-8 and `mid` is not on a char boundary, the slice panics.
**Why it matters**: Although header names are usually ASCII, the public API accepts any `&str`. An adversary or misconfigured upstream can trigger a panic.
**Recommended fix**: Use char-boundary logic or slice the UTF-8 bytes and reconstitute the string safely.
**Status**: open

### F-012 [CRITICAL] No maximum input size validation leads to OOM on adversarially large payloads
**Location**: `crates/encoding/src/encoding/url.rs:8`, `unicode.rs:10`, `structural.rs:51`, `tamper.rs:156`, etc.
**Class**: oom
**Evidence**: `String::with_capacity(payload.len() * 7)` in `triple_url_encode`, `payload.len() * 6` in `unicode_encode`, etc. No upper bound on `payload.len()`. A multi-gigabyte input causes unbounded allocation.
**Why it matters**: An attacker can upload a huge file or send a massive query parameter to OOM the scanner process, causing a self-inflicted DoS.
**Recommended fix**: Introduce a `MAX_PAYLOAD_SIZE` constant (e.g., 8 MB) and reject oversized inputs with a clear `Result::Err`.
**Status**: open

### F-013 [CRITICAL] `WhitespaceInsertion` splits SQL/XSS keywords in half with a tab, producing invalid tokens
**Location**: `crates/encoding/src/encoding/keyword.rs:34-83`
**Class**: semantic-drift
**Evidence**: `SELECT` becomes `SEL\tECT`. The code finds the keyword, calculates `mid = kw_len / 2`, inserts `\t`, and appends the remainder. In SQL, tabs are whitespace and separate tokens; `SEL` and `ECT` are not keywords, causing a syntax error on every major backend (MySQL, PostgreSQL, MSSQL, Oracle).
**Why it matters**: The module docs claim "The server decodes the payload back to its original form." This is false for this strategy. The scanner will send a payload that the database rejects, producing a false negative.
**Recommended fix**: Insert tabs *between* distinct tokens (e.g., `SELECT\t*\tFROM`), not inside individual keywords. Alternatively, rename the strategy to `token_separator` and document it as inserting whitespace between tokens.
**Status**: open

### F-014 [CRITICAL] `SqlCommentInsertion` splits SQL keywords in half with `/**/`, producing invalid SQL
**Location**: `crates/encoding/src/encoding/keyword.rs:89-137`
**Class**: semantic-drift
**Evidence**: `SELECT` becomes `SEL/**/ECT`. SQL comments are treated as whitespace; `SEL` and `ECT` are separate invalid tokens. No standard SQL backend will execute this as `SELECT`.
**Why it matters**: Same as F-013 — the strategy violates the crate's core correctness guarantee. The payload is mutated into a syntactically invalid form.
**Recommended fix**: Insert comments *between* tokens (e.g., `SELECT/**/ */**FROM`), or switch to MySQL versioned comments (`/*!50000SELECT*/`) which are conditionally executed by MySQL and ignored by other parsers.
**Status**: open

### F-015 [HIGH] Missing `space2comment` and related space-replacement tampers
**Location**: missing-technique (competitor gap)
**Class**: missing-technique
**Evidence**: SQLMap's `space2comment`, `space2dash`, `space2hash`, `space2plus`, and `space2randomblank` are among the most effective and widely used tamper scripts. wafrift has no equivalent. The existing `WhitespaceInsertion` is broken (F-013).
**Why it matters**: Many WAFs block the space character (`0x20`) in SQL injection payloads. Without these tampers, the scanner cannot bypass space-based filters on a huge class of deployments.
**Recommended fix**: Add `SpaceToComment`, `SpaceToDash`, `SpaceToHash`, `SpaceToPlus`, and `SpaceToRandomBlank` strategies that replace spaces between tokens.
**Status**: open

### F-016 [HIGH] Missing `modsecurityversioned` / `modsecurityzeroversioned` MySQL versioned comments
**Location**: missing-technique (competitor gap)
**Class**: missing-technique
**Evidence**: SQLMap wraps keywords in MySQL versioned comments such as `/*!50000SELECT*/`. These are executed by MySQL but treated as plain comments by ModSecurity and many WAFs. wafrift has no such strategy.
**Why it matters**: This is one of the most reliable MySQL-specific WAF bypasses. Missing it means the scanner is blind to a large population of ModSecurity-protected MySQL backends.
**Recommended fix**: Add a `MysqlVersionedComment` strategy (with configurable version number) that wraps keywords in `/*!50000...*/`.
**Status**: open

### F-017 [HIGH] Missing `unmagicquotes` multi-byte quote escape
**Location**: missing-technique (competitor gap)
**Class**: missing-technique
**Evidence**: SQLMap's `unmagicquotes.py` uses `%bf%27` (or similar) to exploit `addslashes()` in PHP when the connection charset is GBK, Big5, or Shift-JIS. wafrift has no equivalent.
**Why it matters**: This is a classic bypass for magic-quotes-like protections still found in legacy PHP applications. Missing it means the scanner cannot escape from slash-escaped quote contexts on those stacks.
**Recommended fix**: Add an `UnmagicQuotes` strategy that emits multi-byte sequences designed to consume the backslash and leave the quote intact in multi-byte charsets.
**Status**: open

### F-018 [HIGH] Missing `between` operator obfuscation
**Location**: missing-technique (competitor gap)
**Class**: missing-technique
**Evidence**: SQLMap's `between.py` replaces `>` with `NOT BETWEEN 0 AND #` and `=` with `BETWEEN # AND #`. wafrift has no SQL operator obfuscation.
**Why it matters**: WAFs often blacklist comparison operators. The `between` technique is a pure semantic-preserving rewrite that evades those rules.
**Recommended fix**: Add a `BetweenObfuscation` strategy that rewrites `=` and `>` using `BETWEEN` syntax.
**Status**: open

### F-019 [HIGH] Missing `charunicodeencode` (`%uXXXX`) for IIS/ASP
**Location**: missing-technique (competitor gap)
**Class**: missing-technique
**Evidence**: The crate has `unicode_encode` producing `\u0041`, but IIS/ASP classic parsers decode `%u0041` in URL parameters. These are completely different representations. `%uXXXX` is also used by some JavaScript `escape()` implementations.
**Why it matters**: Missing `%uXXXX` means missing a major bypass vector for Windows stacks (IIS, ASP, ASP.NET with legacy URL parsing).
**Recommended fix**: Add a `PercentUnicodeEncode` (or `IisUnicodeEncode`) strategy that emits `%uXXXX` per character.
**Status**: open

### F-020 [HIGH] Missing `randomcase` — deterministic alternation is trivially pattern-matchable
**Location**: `crates/encoding/src/encoding/keyword.rs:7-25`
**Class**: missing-technique
**Evidence**: `CaseAlternation` always produces `SeLeCt` for `select`. A WAF can pre-compute or regex-match this exact alternating pattern. SQLMap's `randomcase.py` uses a random number generator to choose case per character, making the output space exponential.
**Why it matters**: Deterministic encoding is easy for defenders to fingerprint. An adversarial WAF rule can block `sElEcT` while allowing `SElEcT`.
**Recommended fix**: Replace deterministic alternation with a `RandomCase` strategy that takes a random seed and produces unpredictable mixed-case output.
**Status**: open

### F-021 [HIGH] Missing `percentage` tamper
**Location**: missing-technique (competitor gap)
**Class**: missing-technique
**Evidence**: SQLMap's `percentage.py` adds `%` before each character (e.g., `%S%E%L%E%C%T`). This is a simple but effective bypass against WAFs that tokenize on alphanumeric boundaries but do not strip leading `%` signs.
**Why it matters**: It is a lightweight, database-agnostic bypass that requires no contextual knowledge. Its absence is a straightforward coverage gap.
**Recommended fix**: Add a `PercentagePrefix` strategy that prefixes `%` to every byte or character.
**Status**: open

### F-022 [MEDIUM] Public API `encode` and `Strategy` variants lack doc comments on limitations and server-specific drift
**Location**: `crates/encoding/src/encoding/strategy.rs:72-93`, `12-44`
**Class**: docs
**Evidence**: `pub fn encode(...)` has no doc comment at all. `Strategy` enum variants have one-line doc comments but no warnings about which server stacks will reject or mis-decode them, and no links to CVEs or writeups.
**Why it matters**: Downstream users cannot make informed decisions about which strategies are safe for their target. This leads to the blind application of F-003, F-004, F-005, and F-006.
**Recommended fix**: Add detailed doc comments to `encode` and every variant, including "Safe for: ...", "Unsafe for: ...", and links to the CVE / WAF bypass writeup that motivated the strategy.
**Status**: open

### F-023 [MEDIUM] `README.md` contains stale API names that do not exist in the source
**Location**: `crates/encoding/README.md:9`, `35`
**Class**: docs
**Evidence**: `Strategy::DoubleUrl` and `Strategy::CaseAlternate` are used in README examples, but the actual enum variants are `DoubleUrlEncode` and `CaseAlternation`.
**Why it matters**: New users copy-pasting from the README will get compile errors, eroding trust and slowing adoption.
**Recommended fix**: Update README.md to match the actual public API.
**Status**: open

### F-024 [MEDIUM] `encode` accepts raw bytes but immediately lossily converts to UTF-8, defeating the raw-byte API
**Location**: `crates/encoding/src/encoding/strategy.rs:73-74`
**Class**: semantic-drift
**Evidence**: `let payload = payload.as_ref(); let text = String::from_utf8_lossy(payload);`. Even though `UrlEncode` receives the original `&[u8]`, the dispatcher still performs the lossy conversion for every call, and text-based strategies operate on the corrupted `text`.
**Why it matters**: The signature `impl AsRef<[u8]>` promises byte fidelity, but the implementation breaks that promise for any strategy that touches `text`.
**Recommended fix**: Restructure the dispatcher so only text-oriented strategies perform UTF-8 decoding, and do so with `from_utf8` returning `Result`, not `from_utf8_lossy`.
**Status**: open

### F-025 [MEDIUM] `chunked_split` uses `from_utf8_lossy` on chunk bodies, corrupting invalid UTF-8 and making chunk lengths wrong
**Location**: `crates/encoding/src/encoding/structural.rs:55-59`
**Class**: semantic-drift
**Evidence**: `let piece = String::from_utf8_lossy(chunk);` then `write!(...,"{:x}\r\n{}\r\n", piece.len(), piece)`. If the chunk contains invalid UTF-8, `piece.len()` is the length of the *corrupted* string (with `U+FFFD` replacements), not the original bytes. The chunk length header becomes a lie.
**Why it matters**: The server will read `piece.len()` bytes, but those bytes are the replacement characters (3 bytes each in UTF-8), not the original payload. The chunked framing desynchronizes and the payload is garbled.
**Recommended fix**: Do not convert chunk bytes to `String`. Write the raw bytes directly (e.g., using `std::io::Write` on a `Vec<u8>`) or hex-encode them if a string representation is absolutely required.
**Status**: open

### F-026 [MEDIUM] `layered_combinations` is hardcoded and misses high-value combinations
**Location**: `crates/encoding/src/encoding/layered.rs:25-44`
**Class**: missing-technique
**Evidence**: Only 8 combinations are hardcoded. Missing critical combos such as `Base64Encode → UrlEncode`, `OverlongUtf8 → DoubleUrlEncode`, `NullByte → UrlEncode`, `Utf7Encode → UrlEncode`, `ParameterPollution → UrlEncode`.
**Why it matters**: Hardened WAFs often require 3+ layers or specific pairings. A static list of 8 combinations leaves huge bypass gaps.
**Recommended fix**: Generate combinations programmatically up to a depth limit, filtering out redundant or ineffective pairings.
**Status**: open

### F-027 [MEDIUM] `all_strategies` order does not match `aggressiveness` scores
**Location**: `crates/encoding/src/encoding/strategy.rs:97-114`
**Class**: semantic-drift / docs
**Evidence**: The doc comment says "ordered from least to most aggressive". `Base64Encode` (score 0.75) appears after `ChunkedSplit` (score 0.9). Also `Utf7Encode` (0.95) is last, which is correct, but `Base64Encode` is misplaced.
**Why it matters**: Callers relying on the vector for escalation ladders will apply a more aggressive strategy before a milder one, potentially wasting mild bypasses or hitting rate limits too early.
**Recommended fix**: Sort `all_strategies()` strictly by the `aggressiveness()` function.
**Status**: open

### F-028 [MEDIUM] `HeaderTechnique::DuplicateHeader` is defined but omitted from `all_obfuscations`
**Location**: `crates/encoding/src/header.rs:33`, `199-232`
**Class**: semantic-drift / missing-technique
**Evidence**: `all_obfuscations` returns 9 techniques and explicitly skips `DuplicateHeader`. The variant and `duplicate_header` function exist and are tested, but consumers of the "all" API never see it.
**Why it matters**: Duplicate-header evasion is a powerful and widely used technique. Hiding it from the bulk API means scanners miss a whole class of bypasses.
**Recommended fix**: Include `DuplicateHeader` in `all_obfuscations`, returning a tuple or a composite string representation.
**Status**: open

### F-029 [MEDIUM] `TamperConfig.params` is dead API surface
**Location**: `crates/encoding/src/tamper.rs:555`, `966-986`
**Class**: dead-code
**Evidence**: `StrategyConfig.params: Option<HashMap<String, toml::Value>>` is deserialized but never read by any built-in tamper strategy. The `TamperStrategy` trait has no method to accept params.
**Why it matters**: It creates the illusion of configurability while being impossible to use. Dead code violates LAW 5.
**Recommended fix**: Add `fn tamper_with_params(...)` to the trait, or remove `params` from `StrategyConfig` until it is actually wired up.
**Status**: open

### F-030 [MEDIUM] `case_mix` duplicates `case_alternate` logic, violating DRY
**Location**: `crates/encoding/src/header.rs:69-87` vs `crates/encoding/src/encoding/keyword.rs:7-25`
**Class**: docs / architecture
**Evidence**: The exact same alternating-case logic is duplicated verbatim in two modules. Any bug or improvement to one is likely to be missed in the other.
**Why it matters**: Violates LAW 2 (modular, single responsibility, swappable). Duplication increases maintenance cost and inconsistency risk.
**Recommended fix**: Extract a shared `alternating_case` utility in a common internal module and have both call sites use it.
**Status**: open

### F-031 [MEDIUM] `DoubleUrlEncodeTamper` duplicates `double_url_encode` logic
**Location**: `crates/encoding/src/tamper.rs:180-201` vs `crates/encoding/src/encoding/url.rs:22-43`
**Class**: architecture
**Evidence**: The two implementations are nearly identical. Any logic divergence (e.g., a future fix to one) creates inconsistency between the encoding module and the tamper module.
**Recommended fix**: Have `DoubleUrlEncodeTamper::tamper` delegate to `encoding::url::double_url_encode`.
**Status**: open

### F-032 [MEDIUM] `triple_url_encode` lacks detection for existing `%25XX` sequences, causing quadruple-encoding
**Location**: `crates/encoding/src/encoding/url.rs:49-57`
**Class**: semantic-drift
**Evidence**: `for b in payload { let _ = write!(&mut out, "%2525{b:02X}"); }`. If the input is already double-encoded (`%2541`), `triple_url_encode` treats each byte literally, producing a huge over-encoded string that does not decode correctly after two passes.
**Why it matters**: Callers layering `TripleUrlEncode` over a payload that already contains `%25` will generate artifacts that the server cannot decode back to the original.
**Recommended fix**: Add detection for existing `%25XX` and `%2525XX` sequences, similar to the logic in `double_url_encode`.
**Status**: open


### F-033 [MEDIUM] `url_encode` uses uppercase hex only, missing lowercase variant
**Location**: `crates/encoding/src/encoding/url.rs:11`
**Class**: missing-technique
**Evidence**: `%{b:02X}` produces `%2F`. While URL decoders are case-insensitive, WAF regexes are often case-sensitive. A rule may block `%2f` but miss `%2F`, or vice versa.
**Why it matters**: Missing a lowercase variant means missing a simple bypass against case-sensitive WAF signatures.
**Recommended fix**: Add a `UrlEncodeLower` strategy or a configuration flag on `UrlEncode` to choose hex case.
**Status**: open

### F-034 [MEDIUM] `base64_encode` uses standard alphabet only, missing URL-safe variant
**Location**: `crates/encoding/src/encoding/structural.rs:82-84`
**Class**: missing-technique
**Evidence**: `general_purpose::STANDARD.encode(payload)` produces `+` and `/`. Many modern APIs expect URL-safe Base64 (`-`, `_`, no padding). WAFs may not decode standard Base64 in a URL context.
**Why it matters**: A scanner sending standard Base64 in a query parameter may have `+` decoded as a space or rejected, causing semantic drift.
**Recommended fix**: Add a `Base64UrlEncode` strategy using `general_purpose::URL_SAFE_NO_PAD`.
**Status**: open

### F-035 [MEDIUM] `html_entity_encode` uses hexadecimal entities only, missing decimal entities
**Location**: `crates/encoding/src/encoding/unicode.rs:22-28`
**Class**: missing-technique
**Evidence**: Output is `&#x3C;`. WAFs may block `&#x` but allow `&#60;`. Missing the decimal variant reduces bypass surface.
**Why it matters**: HTML entity parsers accept both forms, but WAF regexes often target one. Covering only hex is incomplete.
**Recommended fix**: Add an `HtmlEntityDecimalEncode` strategy that emits `&#60;` style entities.
**Status**: open

### F-036 [MEDIUM] `OverlongUtf8` only covers 2-byte sequences and non-alphanumeric ASCII
**Location**: `crates/encoding/src/encoding/structural.rs:27-41`
**Class**: missing-technique
**Evidence**: Only `ch.is_ascii() && !ch.is_ascii_alphanumeric()` gets encoded as `%C0%80`–`%C0%BF`. SQLMap's `overlongutf8more` encodes a broader range, including 3-byte overlong sequences (`%E0%80%80`) which bypass stricter UTF-8 validators.
**Why it matters**: Some WAFs reject 2-byte overlongs but accept 3-byte overlongs (or vice versa). A limited implementation misses bypasses.
**Recommended fix**: Add an `OverlongUtf8More` strategy with broader coverage and 3-byte sequences.
**Status**: open

### F-037 [MEDIUM] `parameter_pollute` uses predictable `_wafrift_decoy=1` key
**Location**: `crates/encoding/src/encoding/structural.rs:76`
**Class**: semantic-drift
**Evidence**: When no `=` is found, the function prepends `_wafrift_decoy=1&`. A WAF can trivially add a rule for this literal string.
**Why it matters**: Predictable artifacts are easy for defenders to fingerprint, rendering the technique useless after the first detection.
**Recommended fix**: Generate a random decoy key or accept a configurable decoy key via context/params.
**Status**: open

### F-038 [MEDIUM] `chunked_split` hardcodes chunk size of 3 bytes
**Location**: `crates/encoding/src/encoding/structural.rs:53`
**Class**: semantic-drift / performance
**Evidence**: `let chunk_size = 3_usize;`. For a 1 MB payload this produces ~333,333 chunks plus CRLF overhead. Many WAFs and proxies have chunk-count limits or reassembly timeouts.
**Why it matters**: Excessive chunk counts can cause proxies to drop the request or time out, producing false negatives or scanner errors.
**Recommended fix**: Make chunk size configurable (e.g., 1024 bytes default) and document trade-offs.
**Status**: open

### F-039 [MEDIUM] `whitespace_pad` uses fixed two-space padding
**Location**: `crates/encoding/src/header.rs:97-99`
**Class**: missing-technique
**Evidence**: `format!("{header_name}:  {value}  ")`. A WAF can pattern-match on exactly two spaces.
**Why it matters**: Fixed padding is easy to fingerprint. Random-length padding increases entropy and evasion.
**Recommended fix**: Make padding length random or configurable.
**Status**: open

### F-040 [MEDIUM] `line_fold` and `multi_line_fold` use CRLF only, missing LF-only variant
**Location**: `crates/encoding/src/header.rs:107-132`
**Class**: missing-technique
**Evidence**: Some Unix-based servers and proxies accept LF-only continuation lines (`\n `) but not CRLF. Using only CRLF misses a bypass vector.
**Why it matters**: Header parsing behavior varies across stacks. Supporting only one line-ending type reduces coverage.
**Recommended fix**: Add `LfOnlyLineFold` and `LfOnlyMultiLineFold` variants, or make the line ending configurable.
**Status**: open

### F-041 [MEDIUM] `comma_join` and `duplicate_header` use hardcoded `safe_value`
**Location**: `crates/encoding/src/header.rs:141-146`, `191-193`
**Class**: semantic-drift
**Evidence**: Both functions embed the literal string `safe_value`. Predictable decoy values are trivial to block.
**Why it matters**: Defenders can write a single WAF rule for `safe_value` and neutralize both techniques.
**Recommended fix**: Accept a configurable benign value parameter or generate a random one.
**Status**: open

### F-042 [MEDIUM] `Strategy` and `HeaderTechnique` enums lack `#[non_exhaustive]`
**Location**: `crates/encoding/src/encoding/strategy.rs:12`, `header.rs:23`
**Class**: architecture
**Evidence**: Adding a new variant to a public enum is a semver-breaking change in Rust. A WAF evasion library should grow new techniques frequently.
**Why it matters**: Without `#[non_exhaustive]`, every new technique forces a major version bump, slowing iteration and causing downstream churn.
**Recommended fix**: Add `#[non_exhaustive]` to both enums.
**Status**: open

### F-043 [MEDIUM] `all_tamper_names` and `TamperRegistry::with_defaults` can drift out of sync
**Location**: `crates/encoding/src/tamper.rs:50-64`, `627-640`
**Class**: architecture
**Evidence**: `with_defaults` manually registers 11 strategies. `all_tamper_names` returns a static vec of 11 names. There is no compile-time guarantee they match.
**Why it matters**: A developer can add a strategy to the registry but forget to update the static name list, causing runtime mismatches.
**Recommended fix**: Derive `all_tamper_names` from the registry at initialization, or generate both from a single macro/static list.
**Status**: open

### F-044 [MEDIUM] Missing `JsonEncode` strategy
**Location**: missing-technique (competitor gap)
**Class**: missing-technique
**Evidence**: Modern APIs accept JSON bodies. WAFs inspect raw JSON. Encoding a payload as a JSON-escaped string (e.g., `\u0027` inside a JSON string with quotes) is a common bypass. The crate has raw `\u0027` but not a proper JSON string wrapper.
**Why it matters**: Many WAFs parse JSON but have weak escape handling. A dedicated JSON encoder would exploit gaps in JSON-specific rule sets.
**Recommended fix**: Add a `JsonEncode` strategy that wraps the payload in a JSON string with proper escaping.
**Status**: open

### F-045 [MEDIUM] Missing `GzipEncode` / `DeflateEncode` strategies
**Location**: missing-technique (competitor gap)
**Class**: missing-technique
**Evidence**: Many WAFs do not decompress request bodies. Sending a gzip-compressed payload with `Content-Encoding: gzip` is a standard bypass. The crate has no compression strategies.
**Why it matters**: Missing compression means missing one of the most reliable body-bypass techniques available.
**Recommended fix**: Add `GzipEncode` and `DeflateEncode` strategies that compress the payload.
**Status**: open

### F-046 [MEDIUM] Missing `UnicodeNormalize` (NFKC/NFC) strategy
**Location**: missing-technique (competitor gap)
**Class**: missing-technique
**Evidence**: PayloadsAllTheThings documents that characters like `‥` (U+2025) normalize to `..`, `／` (U+FF0F) to `/`, and `＇` (U+FF07) to `'`. When the backend normalizes Unicode but the WAF does not, this bypasses filters.
**Why it matters**: Unicode normalization bypasses are increasingly effective against cloud WAFs that pass through Unicode but backends normalize it (e.g., Python `unicodedata.normalize`).
**Recommended fix**: Add a `UnicodeNormalize` strategy that maps compatibility characters to ASCII equivalents using NFKC.
**Status**: open

### F-047 [MEDIUM] Missing `PathMangle` / `ReverseProxyUrl` strategies
**Location**: missing-technique (competitor gap)
**Class**: missing-technique
**Evidence**: PayloadsAllTheThings documents `....//`, `..;/`, `%2e%2e/`, and reverse-proxy-specific traversals (e.g., Spring `..;/`). The crate has no path-specific mangling.
**Why it matters**: Path traversal is a major vulnerability class. Without path-specific encodings, the scanner cannot bypass path-normalization WAFs.
**Recommended fix**: Add a `PathMangle` strategy that emits variants like `....//`, `..;/`, `%2e%2e%2f`, etc.
**Status**: open

### F-048 [MEDIUM] Missing `Ipv4AlternateEncode` strategy
**Location**: missing-technique (competitor gap)
**Class**: missing-technique
**Evidence**: PortSwigger's URL validation bypass cheat sheet shows IPv4 can be encoded as octal (`0177.0.0.1`), hex (`0x7F.0.0.1`), DWORD (`2130706433`), and partial decimal (`127.0.1`). The crate has no such encoding.
**Why it matters**: SSRF and URL-validation bypasses rely heavily on alternate IP representations. Missing them means missing a whole vulnerability class.
**Recommended fix**: Add an `Ipv4AlternateEncode` strategy that emits octal, hex, DWORD, and partial decimal forms.
**Status**: open

### F-049 [MEDIUM] `Strategy` and `HeaderTechnique` do not derive `Serialize`/`Deserialize`
**Location**: `crates/encoding/src/encoding/strategy.rs:12`, `header.rs:23`
**Class**: architecture
**Evidence**: The crate depends on `serde` (used by `TamperConfig`), but the core enums are not serializable. This limits integration with configuration-driven scanners that want to persist strategy choices.
**Why it matters**: Downstream users cannot load strategy configurations from JSON/TOML without writing custom wrappers.
**Recommended fix**: Derive `serde::Serialize` and `serde::Deserialize` for `Strategy` and `HeaderTechnique`.
**Status**: open

### F-050 [MEDIUM] `TamperRegistry::register` has no `unregister` or `clear` method
**Location**: `crates/encoding/src/tamper.rs:67-69`
**Class**: architecture
**Evidence**: There is no way to remove a strategy from a registry. This makes it impossible to build a temporary, request-scoped registry without dropping the whole struct.
**Why it matters**: In long-lived scanner processes, the inability to mutate the registry cleanly can lead to strategy leakage between scans.
**Recommended fix**: Add `unregister(&mut self, name: &str) -> Option<Box<dyn TamperStrategy>>` and `clear(&mut self)` methods.
**Status**: open

### F-051 [LOW] `TamperRegistry::by_aggressiveness` can have unstable ordering for NaN values
**Location**: `crates/encoding/src/tamper.rs:91-95`
**Class**: cast / logic
**Evidence**: `a.aggressiveness().partial_cmp(&b.aggressiveness()).unwrap_or(std::cmp::Ordering::Equal)`. If a custom strategy returns `NaN`, `partial_cmp` returns `None` and the pair is treated as equal. The sort is therefore unstable for NaN pairs.
**Why it matters**: A misbehaving custom strategy can cause non-deterministic ordering, making scan results irreproducible.
**Recommended fix**: Treat NaN as `1.0` (or reject it) before sorting, or use a total-order wrapper like `OrderedFloat`.
**Status**: open

### F-052 [LOW] `all_tamper_names()` returns `Vec` instead of static slice, causing allocation
**Location**: `crates/encoding/src/tamper.rs:626-640`
**Class**: performance
**Evidence**: `vec!["url_encode", "double_url_encode", ...]`. This allocates on the heap every time the function is called.
**Why it matters**: At internet scale, millions of calls waste CPU and allocator pressure for a constant list.
**Recommended fix**: Return `&'static [&'static str]` instead.
**Status**: open

### F-053 [LOW] Tests contain `unwrap()`/`expect()` on non-critical paths
**Location**: `crates/encoding/src/tamper.rs:812`, `817`, `874`, `891`, `904`; `encoding/tests.rs:69`
**Class**: panic
**Evidence**: Test code uses `expect(...)` and `unwrap()` for operations that could return `Err` (e.g., TOML parsing, file I/O). While test panics are less severe than production panics, they still violate LAW 5 (actionable errors, no dead code) and make test failures harder to diagnose.
**Why it matters**: Tests should use `assert!(result.is_ok())` or `match` to provide meaningful failure messages.
**Recommended fix**: Replace `unwrap()`/`expect()` in tests with assertions that inspect the `Err` variant.
**Status**: open

### F-054 [LOW] `encoding/tests.rs` has 50 copy-pasted adversarial tests instead of a property test
**Location**: `crates/encoding/src/encoding/tests.rs:170-1418`
**Class**: test
**Evidence**: 50 nearly identical `adversarial_encode_test_auto_N` functions. They differ only in `repeat_str` length. This bloats compile time and binary size.
**Why it matters**: Wasted CI time and larger test binaries. More importantly, they only assert `!result.is_empty()`, which is a trivial smoke test, not an adversarial one.
**Recommended fix**: Replace with a single loop or a property-based test (e.g., `proptest`) that exercises arbitrary lengths and payloads.
**Status**: open

### F-055 [LOW] No doc-tests for public functions
**Location**: All `pub fn` in `crates/encoding/src/`
**Class**: docs
**Evidence**: There are no `/// # Examples` blocks with runnable doc-tests in any public API.
**Why it matters**: Doc-tests serve as both documentation and regression tests. Their absence means examples can rot (as already seen in the README, F-023).
**Recommended fix**: Add doc-test examples to every public function, especially `encode`, `encode_layered`, and the header obfuscation functions.
**Status**: open

### F-056 [LOW] Crate lacks `#[forbid(unsafe_code)]` declaration
**Location**: `crates/encoding/src/lib.rs`
**Class**: architecture
**Evidence**: The crate contains no `unsafe` blocks, but it does not explicitly forbid them at the module level.
**Why it matters**: A future contributor could introduce `unsafe` without scrutiny. Explicitly forbidding it signals a safety boundary.
**Recommended fix**: Add `#![forbid(unsafe_code)]` to `lib.rs`.
**Status**: open


## Missing techniques (from competitor analysis)

| technique name | source | severity | existing similar impl? |
|---|---|---|---|
| `0eunion` | SQLMap | HIGH | none |
| `apostrophemask` | SQLMap | HIGH | none |
| `apostrophenullencode` | SQLMap | HIGH | none |
| `between` | SQLMap | HIGH | none |
| `binary` | SQLMap | MEDIUM | none |
| `bluecoat` | SQLMap | MEDIUM | none |
| `commalesslimit` | SQLMap | MEDIUM | none |
| `commalessmid` | SQLMap | MEDIUM | none |
| `commentbeforeparentheses` | SQLMap | HIGH | none (differs from keyword-split comments) |
| `concat2concatws` | SQLMap | MEDIUM | none |
| `decentities` | SQLMap | MEDIUM | `html_entity` only covers hex `&#xXX;` |
| `dunion` | SQLMap | MEDIUM | none |
| `equaltolike` | SQLMap | HIGH | none |
| `equaltorlike` | SQLMap | HIGH | none |
| `escapequotes` | SQLMap | MEDIUM | none |
| `greatest` | SQLMap | HIGH | none |
| `halfversionedmorekeywords` | SQLMap | HIGH | none |
| `hex2char` | SQLMap | MEDIUM | `hex_encode` is raw hex, not SQL `CHAR(0x41)` |
| `hexentities` | SQLMap | MEDIUM | `html_entity` only covers hex `&#xXX;` |
| `if2case` | SQLMap | MEDIUM | none |
| `ifnull2casewhenisnull` | SQLMap | MEDIUM | none |
| `ifnull2ifisnull` | SQLMap | MEDIUM | none |
| `informationschemacomment` | SQLMap | HIGH | none |
| `least` | SQLMap | HIGH | none |
| `lowercase` | SQLMap | LOW | none (`case_alternation` is mixed, not full lower) |
| `luanginx` | SQLMap | HIGH | none |
| `luanginxmore` | SQLMap | HIGH | none |
| `misunion` | SQLMap | MEDIUM | none |
| `modsecurityversioned` | SQLMap | CRITICAL | none |
| `modsecurityzeroversioned` | SQLMap | CRITICAL | none |
| `multiplespaces` | SQLMap | MEDIUM | none |
| `ord2ascii` | SQLMap | LOW | none |
| `overlongutf8more` | SQLMap | HIGH | `overlong_utf8` is weaker (2-byte only) |
| `percentage` | SQLMap | HIGH | none |
| `plus2concat` | SQLMap | MEDIUM | none |
| `plus2fnconcat` | SQLMap | MEDIUM | none |
| `randomcomments` | SQLMap | MEDIUM | none |
| `schemasplit` | SQLMap | MEDIUM | none |
| `scientific` | SQLMap | MEDIUM | none |
| `sleep2getlock` | SQLMap | MEDIUM | none |
| `space2comment` | SQLMap | CRITICAL | none (`sql_comment` splits keywords, not spaces) |
| `space2dash` | SQLMap | HIGH | none |
| `space2hash` | SQLMap | HIGH | none |
| `space2morecomment` | SQLMap | HIGH | none |
| `space2morehash` | SQLMap | HIGH | none |
| `space2mssqlblank` | SQLMap | MEDIUM | none |
| `space2mssqlhash` | SQLMap | MEDIUM | none |
| `space2mysqlblank` | SQLMap | MEDIUM | none |
| `space2mysqldash` | SQLMap | MEDIUM | none |
| `space2plus` | SQLMap | MEDIUM | none |
| `space2randomblank` | SQLMap | HIGH | none |
| `sp_password` | SQLMap | MEDIUM | none |
| `substring2leftright` | SQLMap | LOW | none |
| `symboliclogical` | SQLMap | MEDIUM | none |
| `unionalltounion` | SQLMap | MEDIUM | none |
| `unmagicquotes` | SQLMap | CRITICAL | none |
| `uppercase` | SQLMap | LOW | none |
| `varnish` | SQLMap | MEDIUM | none |
| `versionedkeywords` | SQLMap | HIGH | none |
| `versionedmorekeywords` | SQLMap | HIGH | none |
| `xforwardedfor` | SQLMap | MEDIUM | none |
| `charunicodeencode` (`%uXXXX`) | SQLMap / IIS | HIGH | `unicode_escape` does `\uXXXX`, not `%uXXXX` |
| `GzipEncode` | PayloadsAllTheThings / OWASP | CRITICAL | none |
| `DeflateEncode` | PayloadsAllTheThings / OWASP | HIGH | none |
| `JsonEncode` | PayloadsAllTheThings / OWASP | HIGH | none |
| `UnicodeNormalize` (NFKC/NFC) | PayloadsAllTheThings | HIGH | none |
| `PunycodeEncode` | PayloadsAllTheThings | MEDIUM | none |
| `PathMangle` (`....//`, `..;/`) | PayloadsAllTheThings | HIGH | none |
| `ReverseProxyUrl` (`..;/`) | PayloadsAllTheThings | HIGH | none |
| `Ipv4AlternateEncode` (octal/hex/DWORD) | PortSwigger / OWASP | HIGH | none |
| `UrlSafeBase64Encode` | PayloadsAllTheThings | MEDIUM | `base64` uses standard alphabet |
| `HtmlEntityDecimalEncode` | PayloadsAllTheThings | MEDIUM | `html_entity` is hex only |
| `Utf8BomInjection` | PayloadsAllTheThings / OWASP | MEDIUM | none |
| `ZeroWidthSpaceInsertion` | PayloadsAllTheThings / OWASP | MEDIUM | none |
| `Http2PseudoHeaderSmuggling` | OWASP | MEDIUM | none |
| `MultipartBoundaryConfusion` | OWASP | MEDIUM | none |
| `MixedCaseUrlEncode` | OWASP | MEDIUM | `url_encode` uses uppercase only |
| `XmlCdataEncode` | OWASP | MEDIUM | none |
| `ScientificNotation` | SQLMap / OWASP | MEDIUM | none |

## Test gaps

- **No property tests for round-trip semantics**: The crate implements only encoders, no decoders. There is no mechanical proof that `encode(decode(x)) ≡ x` for any strategy, because no `decode` functions exist.
- **No adversarial tests for >16 MB payloads**: All tests use small strings. There is no test verifying that the crate rejects or safely handles oversized inputs without OOM.
- **No adversarial tests for invalid UTF-8 byte slices**: The test `encode_accepts_raw_byte_slices` covers `UrlEncode` with raw bytes, but text-based strategies (`UnicodeEncode`, `HtmlEntityEncode`, `CaseAlternation`, etc.) are never tested with invalid UTF-8 inputs.
- **No panic tests for multi-byte UTF-8 in header functions**: `line_fold`, `multi_line_fold`, and `null_byte_inject` are never exercised with emoji or CJK characters, despite having char-boundary panic risks.
- **No concurrent access tests for `TamperRegistry`**: The registry is `Send + Sync` in practice, but there is no test spawning threads that register, look up, and apply strategies simultaneously.
- **No crash-recovery / fuzz tests**: There is no `cargo-fuzz` or `proptest` harness feeding random `&[u8]` into `encode` to verify panic-freedom.
- **No output-size bound tests**: No test asserts that `len(output) <= k * len(input)` for any strategy, which would have caught the unbounded growth in `encode_layered`.
- **No adversarial tests for `DoubleUrlEncode` with trailing `%` or `%X` sequences**: The edge case where a `%` is not followed by two hex digits is untested and mishandled.
- **No tests verifying `ChunkedSplit` chunk lengths match original bytes**: The existing test only checks for the presence of `\r\n` and the terminating chunk.
- **No doc-tests**: Public API examples in doc comments are completely absent, increasing the risk of documentation rot.

## Summary

- **Critical**: 14
- **High**: 7
- **Medium**: 29
- **Low**: 6
- **Missing techniques**: ~72

This audit reveals that wafrift-encoding has severe semantic-drift bugs in its core strategies (`WhitespaceInsertion`, `SqlCommentInsertion`, `OverlongUtf8`, `UnicodeEncode`, `HtmlEntityEncode`, `ChunkedSplit`, `NullByte`, `Utf7Encode`), multiple panic and OOM risks on adversarial input, and a massive coverage gap versus SQLMap (~57 missing tamper scripts) and PayloadsAllTheThings/OWASP (~15 additional techniques). The test suite is largely smoke tests and copy-pasted boilerplate, with no property tests, no fuzzing, no decoder round-trips, and no adversarial size or concurrency coverage. Before this crate can be trusted at internet scale, the semantic-drift findings must be fixed, input size limits must be enforced, char-boundary panics must be eliminated, and the missing technique catalog must be implemented.
