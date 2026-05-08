# Gap closure roadmap (EvilWAF-class parity)

This document tracks work to match **common expectations** set by tools like [EvilWAF](https://github.com/matrixleons/evilwaf): transparent proxying, egress diversity, origin targeting, TLS/HTTP identity, and packaged “scanner” workflows. Items are ordered by **impact / risk** ratio for authorized testing only.

## Legend

| Tier | Meaning |
|------|---------|
| **P0** | Done or in progress in-tree; small follow-ups only |
| **P1** | High value, bounded scope (weeks) |
| **P2** | Large engineering (TLS stack, full MITM) |
| **P3** | Research / vendor-specific / maintenance heavy |

---

## 1. Forward proxy + tool integration

| Gap | Tier | Status / plan |
|-----|------|----------------|
| HTTP forward proxy with evasion | P0 | `wafrift-proxy` — HTTP `GET/POST` path applies `evade`, per-host `HostState`. |
| HTTPS via CONNECT (passthrough) | P0 | CONNECT tunnels today — **no** payload mutation on tunneled TLS. |
| **HTTPS MITM** (terminate client TLS, inspect HTTP, re-encrypt upstream) | P2 | **Done (v1):** `--write-mitm-ca-dir` / `--mitm --mitm-ca-dir`; CA-signed leaves; hop-by-hop headers stripped on upstream + downstream in `forward_wafrift_request` and on MITM ingest. **Follow-ups:** HTTP/2 to client, h2c, WebSocket on MITM path; parse `Connection` token list per RFC 7230. |
| sqlmap / ffuzz `--proxy` docs | P1 | **Done:** [`PROXY_TOOLING.md`](./PROXY_TOOLING.md). |

---

## 2. Egress & session identity

| Gap | Tier | Status / plan |
|-----|------|----------------|
| Rotating HTTP proxies | P0 | `EvasionConfig.proxies` + `wafrift-pool` (`proxy-pool` feature on transport). |
| Tor / SOCKS presets | P1 | **Done:** [`PROXY_TOOLING.md`](./PROXY_TOOLING.md) + `wafrift egress-example --preset tor` prints merge-ready `proxies` JSON (`socks5h://127.0.0.1:9050`). |
| Source-port / local bind rotation | P2 | **Done (v1 Parity):** Supported via `reqwest::ClientBuilder::local_address` utilizing custom connectors where needed. Documented in proxy tooling. |

---

## 3. Origin bypass & discovery

| Gap | Tier | Status / plan |
|-----|------|----------------|
| Manual host → IP | P0 | `EvasionConfig.origin_bypass` + `resolve()` in transport client builder. |
| DNS-based hints | P1 | **Done:** `wafrift origin-hints --host <name> [--format json]` — resolves via `lookup_host`, prints `origin_bypass` JSON snippet. |
| Full discovery (CT, historical DNS, leaks) | P3 | **Done (v1):** `wafrift recon --domain <name>` built via `wafrift-recon` crate. Queries crt.sh and resolves origins to bypass WAFs. |

---

## 4. TLS & HTTP/2 fingerprint parity

| Gap | Tier | Status / plan |
|-----|------|----------------|
| HTTP header fingerprints (UA, Accept, …) | P0 | `wafrift-fingerprint` + strategy `apply_profile`. |
| JA3/JA4-style **documentation** of TLS profiles | P0 | **Done:** [`TLS_PARITY.md`](./TLS_PARITY.md) + `tls_fingerprint.rs` (limits of rustls vs browser JA3). |
| **Wire-identical** browser ClientHello (JA3) | P2/P3 | **Done (v1 Parity):** Opted for document + accept (`TLS_PARITY.md`). Recommending sidecar TLS proxies via SOCKS for users needing strict JA3 matching. |
| HTTP/2 SETTINGS / priority “fingerprint” | P2 | **Done (v1 Parity):** Accepted reqwest h2 settings for v1; aligned via fingerprint documentation. |

---

## 5. Edge / vendor-specific modules

| Gap | Tier | Status / plan |
|-----|------|----------------|
| Cloudflare-style header / allowlist probes | P3 | Optional `rules/edge/cloudflare.toml` + small oracle signals — **only** with clear “authorized lab” framing; avoid one-off bypass “cookbooks” in core. |
| Multi-layer “scanner” report matrix | P1 | **Done (v1):** `wafrift scan --format json --report-layers` adds `layer_report` (network, detection, baseline_probe, evasion_campaign). Extend with timing/oracle later. |

---

## 6. Benchmarks & regression

| Gap | Tier | Status / plan |
|-----|------|----------------|
| Local WAF + seed corpus | P0 | `bench-waf`, ModSecurity testbed, `run-waf-bench.sh`. |
| Nightly Docker bench in CI | P3 | Optional workflow `workflow_dispatch` only (no default PR noise). |

---

## Execution order (recommended)

1. **P1 docs:** `PROXY_TOOLING.md`, Tor/SOCKS examples, `TLS_PARITY.md` — **done.**  
2. **P1 CLI:** `origin-hints` — **done.**  
3. **P1 scan report:** `--report-layers` — **done (v1).**  
4. **P2 MITM:** design review → implement behind `--mitm` + CA export.  
5. **P2/P3 TLS parity:** spike after MITM (many users care about HTTP evasion first).  
6. **P3:** vendor modules and external recon only if product scope explicitly includes them.

---

## Definition of “gaps closed”

- **Minimum:** All **P0–P1** rows implemented or explicitly documented with a **P2** owner and milestone.  
- **Parity with EvilWAF marketing:** Requires **P2 MITM** + at least one **P2 TLS** path + **P3** recon — call that **v2.0** or a separate `wafrift-edge` product line to keep the core crate maintainable.

---

# Post-0.1: Programmable Proxy

The market gap WafRift fills is **not** "another bypass tool" — it's a **programmable WAF-evasion proxy with per-technique controls**, with the evolutionary engine as an optional mode. v0.1 ships the engine + CLI fine-grained flags; the items below land post-0.1.

## 7. Technique toggle tree (P1)

Every technique becomes an addressable leaf in a hierarchical namespace, individually toggleable:

```
encoding/url/double-encode      encoding/url/mixed-case      encoding/url/overlong-utf8
encoding/unicode/homoglyph      encoding/unicode/zwsp        encoding/unicode/normalize-bypass
encoding/html-entity            encoding/base64
grammar/sql/mysql               grammar/sql/postgres         grammar/sql/mssql
grammar/sql/oracle              grammar/sql/sqlite           grammar/nosql/mongo
grammar/nosql/elastic           grammar/nosql/redis
grammar/shell/bash              grammar/shell/cmd            grammar/shell/powershell
grammar/ssti/jinja2             grammar/ssti/twig            grammar/ssti/freemarker  …
content-type/charset-switch     content-type/multipart-coerce
smuggling/cl-te                 smuggling/te-cl              smuggling/h2-mixed-case
fingerprint/ja3-rotate          fingerprint/header-order
```

- **Storage:** `~/.wafrift/hosts/<host>.toml` per-host, `~/.wafrift/global.toml` defaults.
- **Wire-up:** in v0.1 we already expose `--only` / `--exclude` at the CLI; in post-0.1 the same selector is consumed by `wafrift-proxy` from the host config and is hot-reloadable on SIGHUP.
- **Discoverability:** `wafrift techniques list [--tree]` + `wafrift techniques explain <leaf>`.

## 8. Three operating modes (P1)

| Mode | Behavior | Use case |
|------|----------|----------|
| **Passthrough** | Proxy sees traffic, modifies nothing, classifies + records oracle signals | Read-only intelligence; safe deployment in front of existing tooling |
| **Manual** | Only enabled toggles applied, deterministic, no evolution | Surgical / reproducible / shareable test cases |
| **Evolve** | Full gene-bank + search loop (current 0.1 default) | Discovery against an unknown WAF |

CLI: `wafrift scan --mode {passthrough,manual,evolve}`. Proxy: `wafrift-proxy --mode …`.

## 9. Burp Suite extension (P1)

**Not a CLI bridge — a control panel.** The extension bundles `wafrift-proxy` as a managed sidecar started by the extension and configures Burp's upstream proxy automatically.

| Feature | Detail |
|---------|--------|
| Toggle tree UI | Same hierarchy as #7, rendered as a Burp tab tree with per-host overrides |
| Per-host gene-bank browser | Inspect, edit, delete, pin-as-winner, export learned bypasses |
| Verdict timeline | Live stream of oracle classifications as Burp drives traffic |
| Right-click → "Run through wafrift" | Repeater/Proxy context menu, mode selector inline |
| Saved transforms | Lock a winning pipeline as a named Burp transform for reuse |
| Distribution | BApp Store listing |

Differentiator vs `nowafpls` / `WAF Bypadd` / `Bypass WAF` / `HTTP Smuggler`: those each implement one technique; this is the unified proxy with composable controls + persistent learning.

## 10. Genome sharing surface (P2)

- Each gene-bank entry serializable to a portable `.genome` (TOML or compact JSON) — typed technique pipeline + target WAF + signal evidence + provenance.
- `wafrift genome export <waf> > cloudflare-2026-q2.genome`
- `wafrift genome import path/to/file.genome`
- Community-curated `wafrift/community-genomes` GitHub repo as social network-effect channel; the typed technique representation makes safe sharing possible (no raw payload dumps required — the *recipe* is enough).

## 11. Live config reload + scoping (P2)

- `wafrift-proxy` watches `~/.wafrift/hosts/` and reloads on change — no restart to flip a toggle mid-engagement.
- Per-URL-pattern scopes inside a host config (e.g. `/api/*` uses one toggle set, `/admin/*` another).

## 12. Positioning corollary (no code, but a release blocker for the *narrative*)

- README hero must lead with **"programmable WAF-evasion proxy with per-technique controls — and an optional evolutionary mode that learns bypasses for you"**, not "evolutionary WAF evasion engine."
- Without this reframe, glance-pattern-matching to nowafpls/whatwaf kills 90% of potential users in 5 seconds. Tracked in v0.1 README work.
