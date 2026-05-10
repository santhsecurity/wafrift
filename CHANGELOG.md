# Changelog

All notable changes to wafrift are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

## [0.2.3] — 2026-05-10

### Added — community genome registry + ed25519 signing (#111)

- New `wafrift-genome-registry` crate (zero network dependencies):
  bundle wire format, ed25519 sign + verify, trust-list at
  `~/.wafrift/trusted-keys.toml`. Deterministic canonical encoding
  (genomes sorted by name) so two senders building the same pack
  produce byte-equal signatures. 22 unit tests covering signing,
  bundle round-trip, and trust-list lifecycle.

### Added — TUI evade-mutation diff (#109) and replay (#110)

- The detail pane now shows a third side: the diff between the
  request as the client sent it and the request that wafrift's evade
  pipeline put on the wire. Added headers tagged `+ name:` (green),
  removed `- name:` (red), changed `~ name:` (yellow) with arrow
  separator. Body delta line classifies as `mutated` or
  `byte-identical` with a directional arrow.
- New `R` keybinding writes a `/tmp/wafrift-replay-N.curl`
  reproducer; when `WAFRIFT_REPLAY_AUTOEXEC=1` is set, also re-fires
  via bash and reports the upstream exit code in the toast.

### Added — managed-challenge solver (#115)

- New `wafrift-transport::challenge` module: per-host clearance
  cookie capture/replay (cf_clearance / _abck / aws-waf-token),
  classifier for CloudflareManaged / Turnstile / Hcaptcha /
  Recaptcha / AwsWaf / AkamaiBmp / Unknown, and a dispatcher
  returning ReplayWithCookie / Wait / EscalateToOperator. Operator
  prompts are throttled per-host (5min cooldown).
- Wired into proxy: every response is scanned for clearance cookies
  and recorded; subsequent requests to the same host get the cookie
  folded into their `Cookie` header (appended, never replacing).

### Added — URL/query-param body-evasion (#114)

- `wafrift-proxy --mutate-url` (off by default). When set, every
  query parameter VALUE is aggressively percent-encoded; names,
  scheme, host, port, and path are left intact. Operators must opt
  in because mutating URLs changes upstream routing semantics.
- New `wafrift-encoding::url_mutate` module with four strategies
  (PercentEncodeAggressive / DoublePercentEncode / NonCanonicalSpaces
  / Hpp). 17 unit tests; 8 plumbing tests.

### Added — wafw00f attribution + regression test (#117)

- The 160-WAF detection catalog under `crates/detect/rules/detect/`
  is now properly attributed to [wafw00f](https://github.com/EnableSecurity/wafw00f)
  (BSD-3-Clause) plus selective contributions from
  [identYwaf](https://github.com/stamparm/identYwaf) (MIT). Top-level
  README + `wafrift-detect/README` + module-level rustdoc. Regression
  test refuses to ship a rule file without a `source =` field.

### Fixed — evolution engine internals (#112, #113)

- `EvolutionEngine::diversity_score()` previously returned a
  hardcoded 0.5; the engine could not adapt mutation pressure.
  Replaced with a real metric: pairwise gene-mismatch over
  `algorithm.population_snapshot()` ∪ in-flight chromosomes; falls
  back to gene-pool exploration entropy when the live population
  has fewer than two members. SearchAlgorithm trait gains
  `population_snapshot()` (default impl returns `best().into_iter()`)
  with overrides on NoveltySearch and MapElites. 17 integration
  tests.
- `EvolutionEngine::clone()` previously round-tripped the algorithm
  state through serde_json (`checkpoint` → `restore`), spiking
  allocations on populated MapElites grids and novelty archives.
  SearchAlgorithm trait gains `clone_box()` overridden by every
  in-tree algorithm with `Box::new(self.clone())`. New
  `pub type SharedEngine = Arc<tokio::sync::RwLock<EvolutionEngine>>`
  for the canonical shared-state pattern. Perf gates: populated
  MapElites engine clones in <50ms, NoveltySearch <100ms. 12
  integration tests covering correctness, perf, SharedEngine
  semantics, and backward compat.

### Added — Tsai-class differential probing (May 9-10, 2026)

- **`wafrift bypass-probe URL`** — new top-level subcommand. Ports the
  gossan `bypass403::probe` algorithm and wires it to wafrift's much
  larger probe surface. For every URL, fires:
    - 136 auth-bypass header probes (`X-Original-URL`, `X-Rewrite-URL`,
      `X-Forwarded-For` with 7 trusted IPs, method-override family,
      scheme-trust family, host-trust family)
    - All `path_traversal::mutate` variants — ~48 per target —
      including ProxyShell `?@`, semicolon path-param, double-encoded
      slash, IIS null-truncation, fullwidth-dot Unicode
    - HTTP method overrides on the wire (GET → POST/PUT/DELETE/PATCH/
      HEAD/OPTIONS/PROPFIND)
  Each probe is classified vs the baseline GET; status-flips from
  401/403 → 200/302 surface as HIGH-severity findings with reproduce-
  it `curl` one-liners. `--paths-file` walks a list (one path per
  line). `--concurrency N` (default 8) bounds in-flight probes via a
  `Semaphore`. `--min-severity low|medium|high` filters output.
  `--format json` produces a pipeable `{"results": [...]}` envelope.

- **`wafrift_grammar::ssrf::parser_confusion_authority`** — Orange Tsai
  2017 family. Generates 14 parser-disagreement variants per
  `(cover, target)` pair using the user's input host as cover and
  rotating 6 SSRF targets through the userinfo position. Covers
  basic userinfo, the GitLab CVE-2018-19571 fragment-userinfo
  pattern (`cover#@target`), Tsai canonical (`cover &@target`),
  port-then-userinfo, backslash family, `%40` / `%2540` encoded `@`,
  query-userinfo, path-relative jump, newline / null in authority.
  Live: every variant fires bypasses 40-80% on bench-waf naxsi.

- **`wafrift_encoding::auth_bypass`** — new module. `auth_bypass_probes
  (target_path)` returns 136 `(header, value)` probes covering five
  families: URL-rewrite (X-Original-URL etc., 6 headers), IP-trust
  spoofing (12 headers × 7 trusted IPs), host-trust override,
  method-override (GET-past-WAF → PUT/DELETE), scheme-trust. Pure
  library; `bypass-probe` is the consumer.

- **`wafrift_grammar::path_traversal`: routing-disagreement family**
  — 16 new variants targeting frontend/backend canonicalisation
  disagreement: Tomcat semicolon-strip (`/public/..;/etc/passwd`),
  double-encoded slash, overlong UTF-8 slash, ProxyShell `?@`,
  IIS null-truncation, trailing-dot/space, fullwidth-dot Unicode.

- **Bench corpus expansion: 579 → 607 cases.**
    - `wafrift-bench/corpus/ssrf/parser_confusion_authority.toml`
      (12 canonical Tsai cases)
    - `wafrift-bench/corpus/path/routing_disagreement.toml`
      (16 routing-disagreement cases)

### Added — TUI rewrite as MITM live viewer

- **Three tabs**: Flow (default), Overview, Hosts. Switch via `Tab`,
  `1`/`2`/`3`, or `f`/`o`/`h`.
- **Flow tab** — bounded ring of 500 requests with per-row coloring
  by outcome (BYPASS bright-green, BLOCK bright-red, PASS white).
  `j`/`k` (or `↑`/`↓`) navigate; `g`/`G` jump to first/last; `Enter`
  toggles a side detail pane that shows the full inspection: outgoing
  request line + every post-evasion header + body excerpt; incoming
  status (color-graded by 2xx/3xx/4xx/5xx) + every response header +
  body excerpt; summary block with WAF, attempts, latency, body
  padding, TLS profile, technique chain, total response size.
- **Two sparklines** under the request list — req/s and bypasses/s
  over the last 60 seconds, with live max-value annotation.
- **Overview tab** — counters, TLS rotation gauge, WAFs identified
  with per-product host counts.
- **Hosts tab** — per-host bypass table sortable by sent count, with
  bypass-rate color grading (≥75% green, ≥25% yellow, else gray) and
  identified WAF column.
- **Footer key-help bar** — context-sensitive bindings per tab.
- **Memory cap**: 500 records × ~2 KB = ~1 MB worst-case. Body
  excerpts capped at 1 KB per direction (`MAX_BODY_EXCERPT`).
- **No emojis.** Pure Unicode box-drawing.
- **11 new unit tests** covering the new state model, navigation
  clamp, severity → colour mapping, tab cycle, WAFs-seen counter,
  reset preserving uptime + tab.

### Fixed — proxy lifecycle, hot path, MITM panic

- **Critical: global `state.lock()` held across `evade()` /
  `evade_smart()`.** A single 100 KB POST burned 8+ seconds under
  the lock and serialised every other concurrent request behind it;
  the proxy then OOM-killed under load. Snapshotted host state into
  an `EvadePlan`, drop the lock, then run evasion outside.
  Concurrent burst 50/50 → all HTTP 200 after the fix.

- **MCTS body-size blowup.** `evade_mcts` ran 500 iterations and
  cloned the full request body each iteration. On a 1 MB body that
  was a gigabyte of allocations. Added `MCTS_BODY_BUDGET = 16 KiB`
  and `GRAMMAR_MUTATION_BODY_BUDGET = 64 KiB`. Bodies above the
  threshold skip the expensive mutation and only get header / URL
  evasion.

- **`--mitm` HTTPS aborted the worker thread.** rustls 0.23 panics
  with "no default CryptoProvider installed" on the first TLS
  handshake. Installing `aws_lc_rs::default_provider().install_default()`
  at process start fixes the MITM path end-to-end (verified against
  example.com).

- **`--insecure` now warns at startup.** `--insecure-open-upstream`
  already emitted a startup WARN; `--insecure` (TLS-cert-disable)
  was silent. Both flags are dangerous; both should warn.

- **Concurrent gene-bank race fix.** Atomic-write tmp filename now
  PID + nanosecond suffixed so multiple proxies pointed at the same
  gene-bank don't race on the same `<path>.tmp` (one rename
  succeeded; the other got ENOENT). Verified: 4 proxies, 100
  concurrent reqs, periodic flush → zero "flush failed" warnings.

- **Three more UTF-8 split panics in mutators.** `cmd.rs`
  `obfuscate_path` (`&file[..2]` on a `★shadow` filename),
  `cmd.rs` indirection-description truncate, and
  `binary_search.rs` `&trigger[..50]`. All fixed via
  `char_indices()`.

- **`origin_hints.rs` `ips[0]` panic** when DNS returned zero IPs.
  Now returns a clean error.

- **Eleven misplaced test blocks** across the workspace (cassandra,
  cmd_windows, elastic, mongo, redis, encoding/layered, strategy/
  pipeline + planner + waf_presets, oracle/signal_status_code,
  cli/origin_hints) — `#[test]` fns appended after the closing `}`
  of `mod tests`. They compiled but lived outside `#[cfg(test)]`
  and polluted the production binary. Wrapped back inside.

- **TUI channel was unbounded.** Switched to bounded `mpsc::channel
  (10_000)` with `try_send` and a `TUI_DROPPED` atomic counter so
  the request hot path never blocks on a stalled terminal.

### Diagnostics

- **`cargo clippy --workspace --all-targets -- -D warnings`** is
  CLEAN (was 5 warnings).
- **Hot-path unwrap audit**: 20 production hits, all on test code or
  hardcoded constants where unwrap is provably safe.
- **Credential leak**: `Authorization` and `Cookie` headers sent
  through the proxy do NOT appear in any log line (verified live).
- **`cargo audit`**: 1 transitive advisory — `lru 0.13.0` via
  `rquest 5.x` (RUSTSEC-2026-0002, unsound `IterMut`). Not a
  security vuln; wafrift doesn't use the lint-tripped pattern.

### Added — naxsi-class WAF closures (D5+E2)

- **`wafrift_grammar::sql::quote_free`** — quote / comment / paren-free
  SQL injection rewrites (`1' OR '1'='1` → `1 OR 1=1`,
  `1 OR 1 IS NOT NULL`, etc). URL-decodes the input first so encoded
  forms (`1%27%20OR%20%271%27%3D%271`) trigger the rewrite. Promoted
  to priority 1 in `sql::mutate` so the first 5 variants always
  include 5 quote-free candidates. naxsi sql: **0.6% → 99.4%** case
  bypass, **0.2% → 30.0%** oracle-valid.

- **`wafrift_grammar::ssrf` scheme-mangling** — emits scheme-mangled
  variants (`http:/X` single-slash, `//X` protocol-relative, bare
  `X`, `http:////X` quad-slash, plus protocol-relative + integer/
  octal IPs) that bypass naxsi's `http://<IP>` rule while still
  resolving via Python urllib3 / Java URL / Go net/url / libcurl
  normalisation. naxsi ssrf: **2.1% → 78.7%** case bypass.

- **`wafrift_grammar::path_traversal` absolute-target promotion** —
  16 high-value LFI targets that don't contain `..` or `passwd`
  (`/proc/self/environ`, `/.ssh/id_rsa`, `/.git/config`,
  `/var/log/auth.log`, etc) emitted FIRST in the variant list
  (refactored from BTreeSet to insertion-ordered Vec + HashSet
  dedup so `take(--variants 5)` actually reaches them). naxsi path:
  **5.6% → 70.4%** case bypass.

### Added — defensive hardening

- **`MAX_USEFUL_PAD = 8 MiB` ceiling on `body_padding::pad`** —
  silently clamps `requested_bytes >= 8 MiB` so a caller passing
  `usize::MAX` (deliberate or arithmetic underflow) doesn't OOM the
  process. 8 MiB is well above any documented cloud-WAF inspection
  window (Cloudflare Enterprise: 128 KiB).

- **5 new adversarial tests** across `body_padding` + `quote_free`:
  pathological-size clamping, malformed Content-Type strings, empty
  inputs with huge pads, URL-encoded shape detection, NUL-byte in
  payload. None panic; output may be empty. 19 + 12 tests pass.

### Fixed

- **rquest 5.x migration.** All rquest 4.x versions were yanked from
  crates.io between v0.2.2 release prep and CI run, breaking every
  build. Migrated `crates/transport/src/stealth.rs` to
  `rquest::ClientBuilder::emulation()` + `rquest_util::Emulation`
  (the new home for browser profiles after 5.0 split them out).
  Public `ImpersonateProfile` enum names are stable for CLI compat.

- **CI YAML parser fix.** Workflow file had an unquoted `stealth::`
  in a `- run:` value; YAML parser saw it as a nested mapping and
  rejected the file (CI ran zero jobs since c1699b4). Quoted the
  value.

- **MSRV 1.85 lock fix.** `gene_bank/mod.rs` used
  `std::fs::File::lock` which is gated behind unstable `file_lock`
  (Rust 1.89+). Switched to `fs4::FileExt::lock` (workspace dep
  already present, stable since fs4 1.0).

- **Per-class baseline `wafrift-bench/results/v022-by-class/`** —
  20 JSON files (10 classes × 2 WAFs) + SUMMARY.md documenting where
  naxsi has structural gaps that need new mutators (xss/ldap/xxe
  block on class-defining tokens; honest documentation rather than
  silent failure).

## [0.2.2] — 2026-05-09

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

### Added — body-padding wired into the evolution chain (D1+D2)

- `wafrift_evolution::body_padding::fill` switched from
  `b'A'.repeat(n)` to a deterministic xorshift64* over `[a-z0-9]`.
  Defeats Naxsi's BIG_REQUEST + RX heuristics that flag long
  single-character runs. Live verification across 7 stacks: 16 KB
  pure padding now passes through modsec-pl1, modsec-pl2, coraza,
  and bunkerweb cleanly (where run-of-A previously triggered them).

- `EvasionConfig.body_padding_bytes: usize` field; `maximum()` builder
  defaults to 16 * 1024 (AWS-WAF-default tier). `strategy::evade()`
  now applies body padding as Step 3, AFTER every other body-mutating
  layer, recording `Technique::BodyPadding(actual_added)` so the
  gene-bank credits padding-as-winner like any other technique.
  `EvasionLayer::BodyPadding` variant added with prerequisites
  `[Encoding, ContentType, Grammar]`.

- bench-waf v0.2.2 baseline pinned for all 7 local stacks
  (modsec PL1-4 + coraza + bunkerweb + naxsi) at
  `wafrift-bench/results/v022-*.json`. Highlights with the mcts
  strategy + body-padding-via-maximum:

  ```
  modsec-pl1   raw 94.2%   bypassed 100.0%   oracle-valid 86.1%
  modsec-pl2   raw 99.4%   bypassed 100.0%   oracle-valid 85.2%
  modsec-pl3   raw 99.4%   bypassed 100.0%   oracle-valid 82.7%
  modsec-pl4   raw 100.0%  bypassed 100.0%   oracle-valid 83.8%
  coraza       raw 94.8%   bypassed  35.8%   oracle-valid 16.2%
  bunkerweb    raw 94.2%   bypassed 100.0%   oracle-valid 86.7%
  naxsi        raw 99.4%   bypassed   0.6%   oracle-valid  0.2%
  ```

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
