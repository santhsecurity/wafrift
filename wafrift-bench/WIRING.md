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

**[CLOSED 2026-05-08 evening]**

1. ✅ **MAP-Elites + sim-anneal + hill-climb + tabu + novelty in bench** —
   `--strategies hill-climb,sim-anneal,tabu,novelty,map-elites` wired.
   `run_evolution_strategy` runs an `EvolutionEngine` per case, gets
   chromosomes, renders via grammar+encoding genes, sends, feeds
   verdict back. Algorithms learn what beats the WAF as they go.
2. ✅ **AST metamorphism (#5)** — `crates/grammar/src/grammar/sql/ast_metamorph.rs`
   lifts via sqlparser, applies 7 transforms, lowers back. Wired
   through `sql::mutate` so AST variants flow through `build_variants`
   automatically.
3. ✅ **Oracle semantic-validity** — `--oracle-gate` flag wires
   per-class oracle dispatch (sql / xss / cmdi / ssti / path).
   Per-strategy `oracle_valid` counter; aggregate
   `total_variants_oracle_valid` + `oracle_valid_share_of_bypasses`
   in JSON output.

**Open / next-step**

- **Differential probing as bench strategy** — `evolution::differential`
  builds probe payloads to fingerprint exact WAF rule boundaries.
  Not exposed as a `--strategies differential` mode yet.
- **Custom rules in bench** — `evolution::custom_rules` lets users
  drop their own technique TOMLs into the gene bank. No bench mode
  for "test cases against this user-supplied rule pack".
- **Lineage persistence** — `evolution::lineage` records mutation
  chains. Bench logs `bypass_techniques` summary but doesn't persist
  the full lineage tree (would let users replay any single bypass
  exactly from the JSON).
- **Proxy multi-variant retry** — `wafrift-proxy` applies one
  `strategy::evade` per intercepted request. Bench achieves much
  higher bypass by trying 20 variants per case. Open: add a proxy
  retry mode that cycles strategies/variants until a non-403, then
  caches the winner per host.
- **More attack-class oracles** — `oracle_valid()` falls through to
  `true` for `ldap / ssrf / xxe / nosql / log4shell / cve_pocs`
  (no per-class oracle yet). Adding LDAP/NoSQL/XXE oracles would
  tighten the gating across the corpus.
- **Naxsi from source** — replaced with BunkerWeb (modsec-based)
  because no public naxsi docker image exists. BunkerWeb v1.6.0
  also requires the `bunkerity/scheduler` companion to actually
  engage modsec — env-var-only setup is pass-through. Open: build
  naxsi-from-source Dockerfile for true positive-security model
  coverage.
- **Transport feature gates** — `proxy-pool`, `origin-bypass`,
  `gossan-integration` off by default in `wafrift-cli`. Decision
  on enabling them in shipped binaries.

## What's intentionally not in the bench

- `wafrift detect` (the signature engine) — bench targets a *known*
  WAF. Detect is for when you don't know what's in front of you.
- `wafrift recon` — origin discovery, not relevant to bench-against-localhost.
- `wafrift origin-hints` — same.

## Verification snippets

```bash
# Confirm all 5 wired strategies fire on PL1
wafrift-bench/scripts/up.sh modsec-pl1
wafrift bench-waf --base-url http://127.0.0.1:18081 \
    --corpus wafrift-bench/corpus --evade \
    --strategies heavy,mcts,smuggling,content-type,redos \
    --variants 5 --format json | jq '.evaded_summary'

# Confirm proxy actually evades when fronted
wafrift-proxy --bind 127.0.0.1:8080 &
curl --proxy http://127.0.0.1:8080 \
    "http://127.0.0.1:18081/post" \
    -d "q=' OR 1=1--"
# proxy logs should show evade pipeline ran
```
