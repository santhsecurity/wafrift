# Changelog

All notable changes to wafrift are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added — three EvilWAF / nowafplsV2 gaps closed (body padding, TLS rotation, TUI)

- **`wafrift_evolution::body_padding`** — content-type-aware request
  body padder (`Technique::BodyPadding(usize)`). Cloud WAFs only
  inspect the leading N bytes (Cloudflare Pro 8 KB, AWS WAF 16 KB,
  Akamai 8 KB). Padding past that window makes the rule engine miss
  the malicious payload while the origin parses the body correctly.
  JSON / form-urlencoded / multipart all supported with structurally-
  valid splicing; opaque content-types skipped honestly. 14 unit
  tests cover roundtrips, edge cases, and case-sensitive boundary
  parameter handling. Wired into `wafrift-proxy
  --body-padding-bytes <N>`.

- **`wafrift-proxy --tls-impersonate-rotate p1,p2,p3`** — round-robin
  pool of `StealthClient`s. `UpstreamClient::StealthPool { clients,
  cursor }` advances an `AtomicUsize` cursor on every send so each
  upstream request lands on a different browser ClientHello
  fingerprint. Defeats per-fingerprint rate limits and reputation
  systems (Cloudflare bot-management, Akamai BMP, PerimeterX). 3
  unit tests prove cursor distribution + feature-disabled path +
  empty-slice rejection. Mutually exclusive with `--tls-impersonate`
  (clap-enforced).

- **`wafrift-proxy --no-conn-reuse`** — flips
  `pool_max_idle_per_host(0)` so every upstream forward opens a fresh
  TCP connection. Kernel picks a new ephemeral source port each time;
  defeats per-source-port rate limits and 5-tuple reputation. Trade-
  off (one TCP+TLS handshake per request) is explicit, never default.

- **`wafrift-proxy --tui`** — real-time terminal dashboard
  (ratatui + crossterm). Header (bind/mode/stealth/padding/conn-
  reuse), per-pane counters (Total / Bypassed % / Blocked / Errors /
  Padded bodies / Avg latency), TLS rotation distribution with
  per-profile bars, top-5 hosts table (sent/blocked/bypassed/top
  technique), 200-line scrollback of recent requests with
  BYPASS / BLOCK colour coding and `+pad` / TLS-profile tags.
  `q` / Esc / Ctrl-C trigger graceful shutdown (gene bank flushes
  on the same code path SIGINT uses); `r` resets counters; `c`
  clears the recent stream. Tracing logs route to a file when --tui
  is on so the dashboard owns the terminal alternate-screen.
  Verified live: 180-request stress through proxy → modsec-pl1 +
  modsec-pl3 + naxsi shows 119 bypassed (66.1%), 60 padded bodies,
  every POST tagged `+pad` in the recent stream.

### Honest limitations on local stress test

- Self-hosted modsec PL1-PL4 + Naxsi all inspect the FULL request
  body up to Apache `LimitRequestBody`. Body-padding evades cloud
  WAFs (paid SaaS with hard inspection caps) but not local instances
  configured to inspect everything. Manual verification: modsec-pl1
  returns 200 on `_wafrift_pad=A*16384&id=42` and httpbin echoes the
  full padded body back unchanged → padding is structurally valid
  and the proxy attaches it correctly; the local WAFs simply read
  past 16 KB.
- TCP raw-options rotation (EvilWAF's third TCP-layer evasion) is NOT
  implemented — would require `CAP_NET_RAW` and the proxy currently
  uses pure userspace networking. Filed as honest gap, not silently
  shipped.

### Added — EvilWAF JA3/JA4 parity (closed previously-documented gap)

- **`wafrift_transport::stealth::StealthClient`** wraps `rquest`
  (forked BoringSSL) behind the `tls-impersonate` cargo feature.
  Wire-identical Chrome / Firefox / Safari / Edge ClientHello bytes
  on every upstream forward — closes the JA3/JA4 + h2 SETTINGS gap
  vs Cloudflare / Akamai / Sigsci / Imperva-Bot. 7 profiles plus
  `chrome` / `firefox` / `safari` / `edge` "latest of family"
  aliases. Default builds are unaffected (no boring-sys); opt-in
  via `cargo install wafrift-proxy --features tls-impersonate`.

- **`wafrift-proxy --tls-impersonate <profile>`** — practitioner-
  facing CLI flag. Process-wide `OnceLock<StealthClient>` set at
  startup; `forward_wafrift_request` and `forward_passthrough` each
  branch on it, so the existing reqwest path runs unchanged when the
  flag is absent. Without the cargo feature, the flag is parsed but
  exits cleanly at startup with an actionable rebuild-instructions
  error (no silent half-works).

- **`crates/proxy/src/upstream.rs` — `UpstreamClient` enum**: typed
  wrapper exposed for library consumers building their own
  forwarders. `from_reqwest()` / `stealth(profile)` constructors,
  unified `send()` API, `tls_stack_name()` for log lines and
  `/_wafrift/status` output.

- **CI**: dedicated `tls-impersonate` job (`continue-on-error: true`
  — boring-sys C build is brittle across runner images, so the
  default lane stays green even if this one churns). Installs
  `ninja-build` + uses ubuntu-latest's bundled cmake/clang/golang.
  Default `ci` job no longer passes `--all-features` (would have
  required boring-sys deps for non-stealth users).

- **`docs/TLS_PARITY.md`** rewritten side-by-side comparing the two
  transports; **`docs/GAP_CLOSURE_ROADMAP.md`** definition-of-done
  updated to reflect that EvilWAF parity is implemented, not
  aspirational.

### Added — intelligence loops + audit-grade explanations

- **Rich response classification (H1).** New `wafrift_transport::signal`
  module replaces the binary `is_waf_block` with a structured
  `BlockClass` (`HardBlock | SoftBlock | RateLimit | Challenge | Pass`)
  + matched-WAF + prioritize/avoid lists + inspection model. The proxy
  now reads per-WAF profile recommendations from
  `rules/responses/*.toml` (or compiled-in fallback) and biases
  technique selection accordingly via `HostState::record_signal`.
  Crucially: rate-limits and JS challenges no longer penalize the
  active technique — they trigger backoff instead.

- **`wafrift discover` subcommand.** Endpoint discovery from one of
  three sources, output as JSON pipeable into `wafrift scan
  --from-discovery`:
    - `--spec api.json` — OpenAPI 2.0 (Swagger) + 3.x JSON parser
      with media-type-aware injection-context inference
      (`application/json` → `JsonString`, `application/xml` → `XmlText`,
      etc.) and path-templating extraction (`/users/{id}` → `Path`).
    - `--target ... --introspect` — POST a GraphQL `__schema` query,
      emit one endpoint per top-level field on Query / Mutation /
      Subscription with args as `Body` injection points.
    - `--target ... --mine-params --wordlist params.txt` — differential
      parameter mining: collect baseline (status / body length /
      latency envelope), probe each candidate, flag hits whose response
      diverges beyond configured thresholds.

- **Per-finding rule attribution + audit explanations (Phase 2C).**
  - `wafrift_detect::explain::explain_block(payload, waf)` returns the
    list of `RuleAttribution`s a payload would have triggered. 16
    OWASP-CRS-shaped rule families (SQLI/XSS/CMDI/LFI/RFI/SSTI/SSRF/
    PROTO), per-WAF confidence bias from the matched profile's
    inspection model.
  - `wafrift_strategy::explain::explain_bypass(original, bypass,
    techniques, waf, mode)` runs both payloads through `explain_block`,
    set-diffs the rule lists to identify which techniques actually
    removed the match, then narrates. Three modes: `Minimal` (one
    line), `Standard` (rule IDs + technique chain), `Educational`
    (per-technique 'why this works' paragraph for training material).
  - Real Myers-LCS character-level diff for payloads ≤ 1024 chars.

- **OOB confirmation oracle (Phase 2A).**
  `OobOracle::{confirm, confirm_background}` register a canary against
  the configured provider trait, poll until interaction or timeout,
  return `Confirmed | Timeout | Error`. `embed::embed_canary` injects
  per payload-type (SQL `LOAD_FILE`, CMDi `nslookup`, SSRF/XSS via URL).

- **JWT manipulation primitives (Phase 1B).**
  `wafrift_transport::jwt::manipulate(token, &JwtManipulation, key)`
  supports `StripAlg` (alg:none confusion), `Hs256WithKey` (RS256→HS256
  symmetric-key downgrade), `JwkEmbed` (header JWK injection).

- **Cookie-jar persistence + CSRF helpers (Phase 1B).**
  `session::{load_jar, save_jar, extract_csrf, inject_csrf}` —
  newline-delimited "Set-Cookie | https://origin/" disk format,
  regex-based CSRF extraction, header/query/body injection per
  `CsrfInjectionLocation`.

- **Modern body formats (Phase 2B).** `content_type::formats::{protobuf,
  messagepack, grpc_web}` — minimal but correct serializers for moving
  payloads out of WAF-inspected positions. Protobuf uses real varint
  length-prefix (previously truncated payloads >255 bytes silently).

- **Context-aware encoding (Phase 1A).**
  `wafrift_encoding::contextual::encode_in_context(payload, strategy,
  context)` applies strategy then escapes structurally per
  `InjectionContext` (JSON `\"` and control-char escapes, XML `&amp;
  &lt; &gt; &quot;`, URL percent, header CR/LF guard, multipart
  filename guard, etc.). Per-context max-size guards.

- **Response-profiles compiled into the binary.**
  `ResponseProfileDb::compiled_in()` `include_str!`s
  `crates/transport/rules/responses/profiles.toml` so `cargo install
  wafrift-proxy` users get all 7 reference WAF profiles
  (Cloudflare / ModSec / AWS / Imperva / F5 / Akamai / Sucuri) at
  startup — no manual file management.

### Robustness

- **`recon::discover_subdomains_ct` 30 s timeout.** crt.sh routinely
  takes 10-20 s and occasionally hangs entirely; the previous
  `reqwest::Client::new()` had no timeout, making `wafrift discover`
  a self-DoS for any blocked-up upstream.

- **`detect::response_fingerprint::extract_title` regex hoisted to
  `once_cell::Lazy`.** Was being compiled per response (~50 µs per call
  in a hot path).

- **15 `saturating_add(1)` sites.** Proxy/strategy/learning-cache u32
  counters previously wrapped silently after ~5 days at 10 k req/s
  — now plateau at `u32::MAX` for honest dashboards.

- **`detect::suggest_evasion` no longer `Box::leak`s every call.** Was
  leaking ~360 MB/hour at 1 k req/s. Switched to `Vec<String>`
  (zero external callers; API change invisible).

- **Tier B unblocked: 5 hardcoded marker tables → community TOML.**
  Oracle block / challenge / rate-limit / success markers, rule-id
  prefixes / categories / vendors, polyglot payloads, differential
  probes — all now live in `rules/*.toml` with per-crate `build.rs`
  generating Rust constants. Adding a new WAF block-marker is a
  one-line PR with no Rust knowledge.

### Fixed (in source — release pending)

- **`wafrift-grammar` / `wafrift-oracle` / `wafrift-strategy` rule files
  vendored into each crate.** Previously, `include_str!` reached up to
  `<workspace>/rules/...`, which `cargo publish` strips. The grammar
  crate could not be packaged at all; oracle and strategy depended on
  grammar so they cascaded. Files now live in `crates/<x>/rules/...`
  and the include paths point in-crate.

- **`wafrift-detect` build.rs prefers vendored rule copy.**
  v0.2.0 of `wafrift-detect` on crates.io was packaged with the legacy
  `../../rules/detect` path that resolved outside the published crate
  directory; the build script's fallback wrote a one-line empty
  rule-set so the build succeeded but the published artifact ships an
  empty WAF detection database. Source is now fixed (build.rs prefers
  the in-crate `crates/detect/rules/detect/` copy), but the registry
  artifact at `wafrift-detect@0.2.0` is still empty and needs a
  coordinated 0.2.1 bump across detect + every consumer that pins
  `detect = 0.2.0`. Open and unfinished — see internal task #52.

### Added

- **Release-readiness pass for cybersec practitioners (latest round).**
  - **`wafrift seed`** — pre-load gene-bank with known-working techniques
    (`--waf <name>` writes the per-WAF GeneBank, `--host <hostname>`
    writes the proxy gene-bank). Day-one practitioner workflow:
    skip discovery if you already know what beats the target.
  - **`wafrift import-curl`** — feed a curl invocation (e.g. from Burp's
    "Copy as cURL") + a payload/param into the scan engine. Tokeniser
    handles single/double quotes, multi-line `\\\n` continuations, and
    the no-op flags Chromium/Burp emit (`-i`, `--compressed`, etc.).
    Reads from `--curl-file` or `--from-stdin`.
  - **`wafrift bank list / export / import`** — manage gene-banks as
    first-class objects. `export` packs the proxy gene-bank + every
    per-WAF GeneBank into a self-describing JSON envelope (with
    `schema_version` + `wafrift_version`); `import` merges by
    default (union of techniques, dedupe) or `--replace` overwrites.
    Lets teams share findings: scp the envelope, `wafrift bank import`.
  - **`wafrift man`** — emits a troff(1) man page via clap_mangen.
    `wafrift man --output /usr/local/share/man/man1/wafrift.1` and
    `man wafrift` works. `--sub <subcommand>` for per-command pages.
  - **CTF / pentest quickstart** added to README — five concrete recipes
    (SQLi login bypass, SSTI, SSRF-to-internal, LFI/path-traversal,
    XXE) with single-command shapes.
  - **Lawful-use clause** added to `SECURITY.md`, new `CODE_OF_CONDUCT.md`,
    and `README.md` bottom. Codifies authorisation requirement,
    operator-bears-liability transfer, and the project's policy of
    refusing support for unauthorised testing.
  - **`Dockerfile` + `.dockerignore`** for one-step `docker run
    santhsecurity/wafrift`. Multi-stage build, non-root runtime user,
    tini PID 1, OCI image-spec labels.
  - **`.github/workflows/release.yml`** — on tag push, builds Linux
    x86_64 + aarch64, macOS x86_64 + arm64, Windows x86_64 binaries;
    SHA-256 checksum per artefact; attaches to GitHub Release.
    Practitioners on Kali / CTF VMs without a Rust toolchain can
    download a binary directly.
  - **scan text output** now prints the full evaded payload (was
    truncated to 120 chars) plus a copy-paste curl reproduce line, so
    the practitioner doesn't have to re-run anything to get the wire
    bytes for Burp/sqlmap.

- **Practitioner-shaped proxy + CLI surface (this round).**
  - `wafrift-proxy --only-host / --skip-host / --only-path / --skip-path
    / --only-method` — request-level scope filter with a tiny ASCII glob
    grammar (`*`, `?`). Out-of-scope requests are forwarded verbatim
    with no evasion, no gene-bank update, no detection — so dropping
    the proxy in front of Burp doesn't break login flows, oauth
    callbacks, or static assets. SSRF policy still applies.
  - `wafrift-proxy --max-rps-per-host / --max-rps-per-host-burst` —
    per-host token-bucket rate limiter so accidental hammering during
    exploration can't DoS a target. Default unlimited.
  - **`wafrift replay`** — re-fire a saved bypass against a target to
    prove reproducibility. Pulls the technique pool from explicit
    `--technique`, the proxy's gene bank (`--from-host`), or the per-WAF
    GeneBank (`--from-waf`). Exits `2` when the replay is blocked,
    `0` when it bypasses — directly usable as a CI regression gate.
  - **`wafrift report`** — render a pentest-ready markdown writeup from
    the proxy gene bank: per-host WAF, working/blocked techniques, and
    a copy-paste `wafrift replay` command for each finding. Supports
    `--only-host` host-glob filtering and `--output <file>`.
  - **`wafrift init`** — scaffold a commented `.wafrift.toml` so first-
    run isn't `--help` archaeology. Refuses to overwrite without
    `--force`. Every key shipped commented-out so the unmodified file
    is a pure no-op.
  - **`/_wafrift/findings.md`** — new live findings endpoint on the
    proxy (loopback-bind + peer-loopback gated, same as
    `/_wafrift/status`). `curl http://127.0.0.1:8080/_wafrift/findings.md`
    during a session for a markdown writeup of everything discovered
    so far.

- **`wafrift bench-waf --validate-only`** — corpus integrity check
  without standing up a WAF. Verifies every case has a unique id +
  non-empty payload + a known class (one of sql/xss/cmdi/ssti/path/
  ldap/ssrf/nosql/xxe/log4shell/cve_pocs); reports counts and exits
  4 on errors. Caught a real `tab_separated` id collision between
  `corpus/sql/comments_evasion.toml` and `corpus/cmdi/shell_unix.toml`
  on first run; renamed to `tab_separated_cmdi`.

- **`wafrift bench-diff`** — new subcommand. Compares two
  `bench-waf --output` JSON blobs; exits `3` if overall bypass rate
  drops more than `--bypass-drop-pp` (default 2pp), warns if
  `raw_block_rate` falls below `--raw-block-floor` (default 0.95,
  flags WAF-stack-changed not wafrift-bug). CI gate matching the
  methodology.md regression rules.

- **`wafrift-bench/targets/naxsi/`** — vendored naxsi-from-source
  bench target. Builds nginx 1.27.4 + naxsi 1.6 from source (no
  public naxsi docker image exists), bench-grade `naxsi.conf`
  (LearningMode off, denial → 403), exposed on `:18087`.
  `wafrift-bench/scripts/{up,down}.sh` updated to handle it. Cold
  build ~5 min, warm sub-second. Closes the naxsi-from-source open
  item in `wafrift-bench/WIRING.md`.

- **`bench-waf --lineage-output PATH`** — persists every
  evolution-strategy bypass (hill-climb / sim-anneal / tabu / novelty /
  map-elites) as a `wafrift_evolution::lineage::BypassEntry` and saves
  the deduplicated `BypassCorpus` JSONL on bench completion. Gene
  tuple is enough to reconstruct the wire payload exactly; the lineage
  trace records every mutation step. Closes the lineage-persistence
  open item in `wafrift-bench/WIRING.md`.

- **`bench-waf --strategies all`** — keyword that expands to every
  selectable strategy. Avoids having to type the 11-element comma list
  by hand and stays in sync with `ALL_STRATEGIES` (guarded by a unit
  test so that adding a new strategy without registering it would fail
  the build).

- **`bench-waf --strategies differential`** — wires
  `wafrift-evolution::differential::generate_probes` into the bench as
  an 11th selectable strategy. Sends class-filtered rule-fingerprint
  probes (sql/nosql → SQL probes, xss → XSS, cmdi/ssti → CMD,
  path → CMD path, others → baseline-only) and reports which probes the
  WAF lets through. The inverse of bypass-rate measurement: lets you
  see where your WAF has rule-coverage gaps. Closes the last open item
  in `wafrift-bench/WIRING.md`.

## [0.2.0] — 2026-05-08

Major bench + wiring rewrite. Introduces a real, reproducible
multi-strategy WAF benchmark and closes every dormant-crate gap from
the v0.1 audit.

### Added

- **`wafrift-bench/`** — production bypass-rate benchmark.
  - 557-case TOML corpus organized by attack class (sql / xss / cmdi /
    ssti / path / ssrf / ldap / nosql / xxe / log4shell), each split into
    sub-categories per attack family.
  - 6 docker-compose stacks: ModSec CRS PL=1/2/3/4, Coraza, BunkerWeb.
  - `wafrift bench-waf` with **10 selectable strategies**:
    `light` / `medium` / `heavy` (build_variants), `mcts` (mctrust 0.4),
    `smuggling` (CL.TE/TE.CL/TE.TE/dual-CL), `content-type`
    (multipart/json/xml), `redos` (catastrophic backtracking),
    `hill-climb` / `sim-anneal` / `tabu` / `novelty` / `map-elites`
    (feedback-driven evolution loops).
  - `--oracle-gate` per-class semantic-validity check on bypassed
    variants (sql / xss / cmdi / ssti / path / ldap / ssrf / nosql / xxe /
    log4shell) to filter "WAF allowed but parser would reject" garbage.
- **`crates/grammar/src/grammar/sql/ast_metamorph.rs`** — lift SQLi
  fragment via sqlparser, apply 7 semantic-preserving transforms
  (commute_or, commute_eq, identity_add_zero, identity_mul_one,
  eq_to_like, double_negation, paren_wrap), lower back. Wired through
  `sql::mutate` so AST variants flow into `build_variants` automatically.
- **`wafrift_strategy::evade_smart()`** — active-loop default that
  switches to MCTS once the host has block telemetry, falls back to
  classic `evade()` pipeline. Used by `wafrift-proxy` in discovery mode.
- **`wafrift-proxy --max-evade-retries N`** — multi-variant retry on
  WAF block. Each retry's recorded block bumps escalation so the next
  evade attempt picks heavier shapes.
- **`wafrift recon` CLI subcommand** — origin discovery via crt.sh + DNS
  (was dormant — `recon_cmd.rs` existed but never declared as a module
  and the CLI subcommand wasn't registered).

### Changed

- **`wafrift-cli`** now depends on `wafrift-fingerprint` + `wafrift-recon`
  directly. The `proxy-pool` feature is on by default — wafrift-pool
  HTTP/SOCKS rotation is live without flag jumping.
- **`wafrift-core`** re-exports the previously-missing crates: oracle,
  transport, pool, recon. Library consumers get the full surface from
  one dependency.
- **`wafrift-grammar`** promotes `sqlparser` from dev-dep to dep.
- **`mctrust`** dependency bumped to 0.4.0 (replaces 0.2.x API:
  `GameState`→`Outcome`, `GameSearch`→`TreeSearch`, `best_sequence`→
  `principal_variation`).

### Headline numbers

(modsec-pl1, all 10 strategies, 20 variants per case, --oracle-gate)

- 46k variants sent, 36% bypass rate, 95% of bypasses are oracle-valid.
- **557 of 557 corpus cases get at least one bypass at every paranoia
  level (PL=1 → PL=4).** At PL=4 (most aggressive CRS preset) the
  variant-level rate is ~27% — lower than PL=1's 36% but case-coverage
  stays 100%, meaning every attack type still has at least one working
  evasion for the gene bank to replay.

## [0.1.0] — 2026-05-08

First public release.

### Architecture

- **Evasion technique crates**: encoding, grammar, content-type, smuggling, fingerprint.
- **Intelligence crates**: detect (WAF fingerprinting), evolution (bypass discovery).
- **Pipeline**: strategy (planner, gene bank, learning cache) + oracle (typed multi-signal verdict classifier).
- **Transport**: evasion-aware HTTP client, connection pool, forward proxy with optional HTTPS MITM.
- **Tier B TOML rule system**: community-contributable WAF signatures, evasion pipelines, smuggling probes.
- **CLI**: interactive TUI + `scan` / `evade` / `detect` / `egress-example` / `recon` / `origin-hints` headless commands; `wafrift-proxy` forward proxy binary.

### Detection & evasion

- TOML-driven WAF detection: 160+ WAFs covered via community-extensible `rules/detect/*.toml` (parity with WAFW00F + identYwaf).
- Active WAF probing: benign + known-blocked baseline probes, response-drift classifier.
- Ambiguity handling in `detect()`: returns ranked `Vec<DetectedWaf>` with confidence scores and tie-breaking rules.
- Grammar dialects: MySQL/Postgres/MSSQL/Oracle/SQLite SQL, NoSQL (Mongo/Elastic/Redis), bash/sh/cmd.exe/PowerShell, SSTI for 7 engines.
- Grammar parser-validated equivalence: `sqlparser-rs` AST comparison proves SQL variant equivalence.
- Smuggling safety invariants: per-request poison canaries, exponential backoff on 5xx, circuit breaker. Probe templates under `rules/smuggling/`.

### Evolution & learning

- Search algorithms: hill-climb, simulated annealing, tabu search, novelty search, MAP-Elites.
- Lineage tracking: every discovered bypass serialized with its full transformation tree; replayable and shareable.
- Budget / termination / circuit-breaker: hard request budgets, plateau detection, target-health monitoring.
- Strategy learning cache: successful bypass pipelines persisted per WAF across scanner runs (gene bank in `~/.wafrift/genomes/`).

### Oracle

- Typed verdict enum: `Blocked | Allowed | RateLimited | ChallengeRequired | ServerError | Partial | Ambiguous`.
- Multi-signal fusion: calibration drift, connection, gzip body markers, headers, status, response time, H2 GOAWAY.
- Per-class oracles: SQL, XSS, CMDI, SSRF, SSTI, LDAP, path traversal.
- Final verdict includes the full collected signal list.
- H2 GOAWAY reason matching is case-insensitive; CMDI/SSRF tolerate trailing null / UTF-8 replacement noise; SSTI avoids Smarty false positives on `{{}}`.

### Proxy & transport

- Forward proxy (`wafrift-proxy`) for sqlmap / ffuf / browser integration.
- HTTPS MITM v1 with CA generation (`--write-mitm-ca-dir`, `--mitm --mitm-ca-dir`); CA-signed leaves; hop-by-hop header stripping on both directions.
- Egress: rotating proxies, Tor / SOCKS presets, source-port / local-bind rotation.
- TLS fingerprint profiles documented in `wafrift-fingerprint`; rustls-vs-browser JA3 caveat tracked in `docs/TLS_PARITY.md`.

### CLI fine-grained controls

- `--only` / `--exclude` flags on `evade` and `scan`, taking comma-separated hierarchical technique paths (`encoding/url`, `encoding/url/double`, `grammar`, ...).
- `wafrift techniques list` enumerates the selectable tree.
- Unknown selectors fail fast with a pointer to `techniques list` rather than silently dropping.
- The `--exclude grammar` selector is the structured replacement for the legacy `--encoding-only` shorthand (still supported).

### Tooling & release engineering

- CI workflow: fmt + clippy + build + test + doc with `-D warnings`.
- MSRV job (`cargo check` on Rust **1.88**, aligned with current `reqwest` / `idna` stack).
- `testbed/modsecurity-crs/` — optional Docker Compose for local ModSecurity/CRS benchmarking.
- `crates/cli/tests/modsec_local.rs` — ignored smoke test gated on `WAFRIFT_MODSEC_URL`.
- Full Cargo.toml metadata for every crate (description, license, repository, keywords, categories).
- Workspace `Cargo.toml`: internal crates use `workspace = true` dependencies with `version` fields for crates.io-compatible publishing; `mctrust` is a workspace member.

### Licensing

- Dual licensed: **MIT OR Apache-2.0**, aligning with the Rust ecosystem norm and providing an explicit patent grant.

### Notable fixes during stabilization

- Encoding semantic drift: URL over-encoding of unreserved chars, UTF-7 naive mock replaced with RFC 2152 implementation, unicode/HTML-entity context gating, layered encoding size cap.
- Encoding panics on multi-byte UTF-8 header values (`line_fold`, `multi_line_fold`, `null_byte_inject`).
- Encoding OOM on adversarially large payloads (input + output size caps).
- Workspace `proptest` dependency (subcrates referenced it without a workspace root entry, blocking `cargo metadata`).
- `LearningCache` JSON keys: string keys (fixes `HashMap<CacheKey, _>` JSON round-trip).
- `is_text_payload`: binary bodies without `Content-Type` are no longer treated as UTF-8 text.
- `wafrift-smuggling` tests: missing `HashSet` import under `unsafe-probes`.
- Encoding / grammar / oracle / strategy tests aligned with stochastic strategies and serde JSON map keys.
