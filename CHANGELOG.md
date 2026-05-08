# Changelog

All notable changes to wafrift are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

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
