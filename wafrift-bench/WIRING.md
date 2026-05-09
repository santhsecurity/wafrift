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

1. **MAP-Elites loop in bench** — `evolution::search::map_elites` is
   coded but only invoked from `wafrift scan`'s feedback loop. Bench
   could expose `--strategies map-elites` to drive a feedback-search
   on each case.
2. **Novelty / sim-anneal / tabu / hill-climb** — same as MAP-Elites:
   coded in `evolution::search`, only callable through `scan`'s
   intelligence loop, not surfaced as a bench strategy.
3. **Differential probing** — `evolution::differential` builds probe
   payloads to fingerprint exact WAF rule boundaries. Not exposed as
   a bench strategy yet.
4. **Custom rules** — `evolution::custom_rules` lets users drop their
   own technique TOMLs into the gene bank. No bench mode exists for
   "test cases against this user-supplied rule pack".
5. **Lineage tracking** — `evolution::lineage` records which mutation
   chain produced each finding. The bench reports techniques that
   correlated with bypasses but doesn't persist the full lineage tree.
6. **Oracle semantic-validity** — `oracle::sql/xss/cmdi/ssti/path`
   could verify that bypassed payloads are actually valid attacks
   (not garbage that slipped through). Bench currently counts every
   non-blocked response as a bypass.
7. **AST metamorphism (#5)** — `wafrift-grammar` has dialect-aware
   string-level mutators but no full SQL-AST lift / transform / lower
   pipeline. sqlparser is already a dep (oracle uses it) so the
   foundation is there.
8. **Transport feature gates** — `proxy-pool`, `origin-bypass`,
   `gossan-integration` are off by default in `wafrift-cli`. The proxy
   binary uses transport directly. Need an explicit decision on
   enabling these in shipped binaries.

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
