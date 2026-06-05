# Wafrift crate wiring audit

What every crate is for, where it's actually called from, what's still
not wired to anything. Generated 2026-05-08.

## Crate surface

| Crate | Role | Used by |
|---|---|---|
| `wafrift-types` | Foundation — `Request`, `EvasionConfig`, `Method`, etc. | Everything (22 files) |
| `wafrift-encoding` | URL/case/whitespace/etc encoding strategies | helpers, strategy, content-type, smuggling, transport (11) |
| `wafrift-grammar` | Per-class grammar mutators (SQL/XSS/CMDi/SSTI/Path/LDAP/SSRF/NoSQL) | helpers, strategy, oracle, evolution (11) |
| `wafrift-content-type` | Content-Type confusion variants | strategy, **bench-waf** (4) |
| `wafrift-smuggling` | HTTP request smuggling shapes | strategy, **bench-waf** (3, with `unsafe-probes` feature) |
| `wafrift-fingerprint` | UA / TLS fingerprint rotation | strategy (2) |
| `wafrift-detect` | WAF identification from response signatures | strategy, cli (5) |
| `wafrift-evolution` | hill_climb, sim_anneal, tabu, novelty, MAP-Elites + advisor | strategy, intelligence, evolution-cli, helpers (6) |
| `wafrift-strategy` | Top-level pipeline (`evade`, `evade_mcts`, `evade_intelligent`) | cli, **bench-waf**, scan (8) |
| `wafrift-oracle` | SQL/XSS/CMDi/SSTI/Path semantic-validity check | strategy, evolution, mcts_bridge (3) |
| `wafrift-pool` | Round-robin HTTP/SOCKS proxy rotation | transport (under `proxy-pool` feature) |
| `wafrift-transport` | reqwest middleware that auto-applies evasion | cli, proxy (3) |
| `wafrift-proxy` | Standalone HTTP/HTTPS forward proxy with MITM | (own binary `wafrift-proxy`) |
| `wafrift-recon` | crt.sh / DNS origin discovery | cli (`wafrift recon`) (1) |
| `wafrift-core` | Façade re-exporting other crates | integration tests (3) |
| `wafrift-cli` | The `wafrift` binary | (own binary) |

## What's wired into bench-waf

The bench harness exercises:

| Strategy | Crate(s) called | Method |
|---|---|---|
| `light` / `medium` / `heavy` | grammar + encoding (via cli::helpers::build_variants) | payload-string mutation |
| `mcts` | strategy (evade_mcts) → mctrust 0.4 → grammar/encoding/content-type/fingerprint internally | tree search over per-step actions |
| `smuggling` | smuggling::all_payloads (CL.TE/TE.CL/TE.TE/dual-CL/cl_zero/multi-value-CL/method-body/h2c) | HTTP smuggling shapes |
| `content-type` | content_type::generate_variants_from_body (multipart, JSON, XML, ...) | parser-discrepancy attack |
| `redos` | inline catastrophic-backtracking shape generator | regex DoS / fail-open trigger |
| `differential` | evolution::differential::generate_probes filtered by class | rule-fingerprint coverage probe |
| `ml-evasion` | strategy::apply_ml_evasion_if_applicable → wafmodel::propose_mutation + is_attack_payload (manifold-projected structural mutation), fired live + oracle-verified | ML-WAF structural evasion; routes ONLY when `--waf-name` is ML-backed (AWS/CF/Akamai bot-mgmt, Datadome) — a clean no-op on rule WAFs. Adaptive boundary descent (wafmodel::evade_ml driven by live feedback) is a tracked frontier item |

## What's wired into the proxy binary

`wafrift-proxy` (`crates/proxy/src/main.rs::forward_wafrift_request`):

- Receives intercepted HTTP request
- Per-host `HostState` tracks blocks → escalation level
- If host has known winners → rotate winners
- Otherwise → call `strategy::evade` to discover new technique
- MITM mode: `crates/proxy/src/mitm.rs` issues a CA-signed leaf cert per
  upstream, terminates client TLS, runs the same evade pipeline on the
  decrypted request, re-encrypts upstream
- Hop-by-hop header stripping in `crates/proxy/src/hop_by_hop.rs`
- Optional proxy pool via `wafrift-pool` (`proxy-pool` feature on transport)

The proxy is a one-flag away from invisible-evasion-for-everything:
```
wafrift-proxy --bind 127.0.0.1:8080 --mitm --mitm-ca-dir ~/.wafrift-ca
sqlmap -u "http://target/x?q=1" --proxy=http://127.0.0.1:8080 ...
```
sqlmap's payloads get evade-wrapped on the fly.

## What's wired into the standalone `wafrift` CLI

| Subcommand | Crates exercised |
|---|---|
| `wafrift evade` | grammar + encoding (build_variants) |
| `wafrift detect` | detect (signature matching against response) |
| `wafrift probe` | evolution::differential (probe target generation) |
| `wafrift scan` | strategy::evade* + transport::is_waf_block + intelligence loop |
| `wafrift bench-waf` | (this whole document) |
| `wafrift origin-hints` | DNS resolution (origin-bypass discovery) |
| `wafrift egress-example` | print proxy/Tor preset JSON snippets |
| `wafrift techniques` | enumerate technique selectors |
| `wafrift recon` | recon::* (crt.sh + DNS for origin discovery) |

## Gaps — what's NOT wired (yet)

**[CLOSED 2026-05-08]**

1. ✅ **MAP-Elites + sim-anneal + hill-climb + tabu + novelty in bench** —
   `--strategies hill-climb,sim-anneal,tabu,novelty,map-elites` wired.
   `run_evolution_strategy` runs an `EvolutionEngine` per case, gets
   chromosomes, renders via grammar+encoding genes, sends, feeds
   verdict back. Algorithms learn what beats the WAF as they go.
2. ✅ **AST metamorphism** — `crates/grammar/src/grammar/sql/ast_metamorph.rs`
   lifts via sqlparser, applies 7 transforms, lowers back. Wired
   through `sql::mutate` so AST variants flow through `build_variants`
   automatically.
3. ✅ **Oracle semantic-validity** — `--oracle-gate` wires per-class
   oracle dispatch (sql / xss / cmdi / ssti / path / ldap / ssrf /
   nosql / xxe / log4shell). All 10 attack classes covered. NoSQL,
   XXE, log4shell use new structural-validity checks (Mongo operator
   markers; XML/DOCTYPE/ENTITY markers; JNDI lookup shapes incl.
   percent-encoded). Aggregate `total_variants_oracle_valid` +
   `oracle_valid_share_of_bypasses` in JSON output.
4. ✅ **Proxy multi-variant retry** — `wafrift-proxy
   --max-evade-retries N` wraps each request in a retry loop. Each
   retry's recorded block bumps escalation so successive attempts
   pick heavier evade shapes.
5. ✅ **Wafrift-fingerprint in CLI / wafrift-recon module / proxy-pool
   default-on / wafrift-core re-exports / MCTS as default in
   strategy active loop (evade_smart)** — all 5 user-flagged
   wiring gaps closed.
6. ✅ **Bench-waf production hardening** — `--skip-healthcheck` (off
   by default; pings target before queueing N variants),
   `--adaptive-pause-after-errors N` (auto-throttle on
   connection-storm), `--summary-only` (CI-friendly JSON),
   per-strategy text output, default UA from
   `wafrift_fingerprint::random_profile()`.
7. ✅ **cve_pocs/ corpus** — held-out test set per methodology;
   22 real CVE PoC payloads (log4shell, struts2, weblogic, gitlab,
   confluence, spring4shell, follina, apache traversal, etc.).
8. ✅ **BunkerWeb compose** — added `bunkerity/scheduler` +
   `redis:7-alpine` companion services so modsec actually engages.
11. ✅ **Naxsi-from-source bench target** — vendored Dockerfile builds
    nginx 1.27.4 + naxsi 1.6 from source (no public naxsi image
    exists). Bench-grade `naxsi.conf` runs LearningMode OFF and routes
    block to a 403. `wafrift-bench/scripts/up.sh naxsi` brings it up
    on `:18087`. Build is ~5 min cold, sub-second warm. Closes the
    naxsi-from-source open item.
10. ✅ **Lineage persistence** — `--lineage-output PATH` collects every
    successful evolution-strategy bypass as a
    `wafrift_evolution::lineage::BypassEntry` (genes + lineage trace +
    fitness + payload-hash) and dumps the deduplicated `BypassCorpus`
    JSONL on bench completion. Each entry is replayable: gene tuple
    reconstructs the wire payload, lineage trace records every mutation
    step. Only the search-loop strategies populate it (static strategies
    have no chromosome).
9. ✅ **Differential probing as bench strategy** —
   `--strategies differential` runs class-filtered probe payloads from
   `evolution::differential::generate_probes` against the target. A probe
   that comes back unblocked tells you which signature your WAF doesn't
   have — the inverse of bypass-rate measurement, useful for rule-coverage
   gap analysis. Class → probe-family map: sql/nosql → SQL probes, xss →
   XSS probes, cmdi/ssti → CMD probes, path → CMD path probes, others
   (xxe/log4shell) → baseline-only.

**Open / next-step**

- **Custom rules in bench** — `evolution::custom_rules` lets users
  drop their own technique TOMLs into the gene bank. No bench mode
  for "test cases against this user-supplied rule pack".
- *(closed — see #10 below)*
- **Persistent gene bank in proxy** — `wafrift-proxy` HostState lives
  only in-memory; restart loses winner pool. Add JSON checkpoint to
  `~/.wafrift/gene-bank.json`, load on start, save on signal-or-tick.
- **Wafrift-proxy graceful shutdown** — SIGTERM/SIGINT today drops
  pool + state. Add signal handler that flushes gene bank, drains
  in-flight requests, exits cleanly.
- *(closed — see #11 below)*
- **Transport feature gates** — `origin-bypass`, `gossan-integration`
  off by default in `wafrift-cli`. (proxy-pool now on by default —
  see closed item #5.) Decision on enabling the others depends on
  whether shipped binaries should pull in the gossan workspace dep.

## What's intentionally not in the bench

- `wafrift detect` (the signature engine) — bench targets a *known*
  WAF. Detect is for when you don't know what's in front of you.
- `wafrift recon` — origin discovery, not relevant to bench-against-localhost.
- `wafrift origin-hints` — same.

## Verification snippets

```bash
# Confirm every wired strategy fires on PL1
wafrift-bench/scripts/up.sh modsec-pl1
wafrift bench-waf --base-url http://127.0.0.1:18081 \
    --corpus wafrift-bench/corpus --evade \
    --strategies all \
    --variants 5 --format json | jq '.evaded_summary'

# Confirm proxy actually evades when fronted
wafrift-proxy --bind 127.0.0.1:8080 &
curl --proxy http://127.0.0.1:8080 \
    "http://127.0.0.1:18081/post" \
    -d "q=' OR 1=1--"
# proxy logs should show evade pipeline ran
```
