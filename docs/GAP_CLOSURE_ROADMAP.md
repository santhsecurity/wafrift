# Roadmap

Forward-looking — what's open, in priority order. Closed items live in [CHANGELOG.md](../CHANGELOG.md); this doc tracks **what's next**.

Operating principle: every entry below ships **measurable** value. We don't add a feature; we add a `+N%` on the scoreboard, a closed CWE class, a `wafrift X` command that didn't exist. If you can't measure it, it doesn't get prioritised.

---

## Tier 1 — legendary lift

These three are what take wafrift from "best-in-class evader" to "the research instrument cited every time someone writes a WAF paper."

### 1. Break the fingerprint ceiling — JA3/JA4 + H2 + header order

| Problem | Modern Cloudflare / Akamai / AWS Shield / Imperva Bot Management classify at TLS+H2 *before* the payload is parsed. Default wafrift looks like reqwest-the-library; no amount of payload cleverness gets through. |
|---|---|
| **Today** | `--features tls-impersonate` ships rquest + BoringSSL with Chrome/Firefox/Safari ClientHellos. Solid for static fingerprint. |
| **What's missing** | (a) per-request JA3/JA4 rotation that's *coherent* — i.e. matches a real session lifecycle, not just round-robin profiles; (b) H2 frame-layout fingerprint (`SETTINGS` order, priority tree, `WINDOW_UPDATE` cadence); (c) browser-realistic header insertion order with the right entropy (Chrome doesn't emit `Accept-Encoding` in the same position as Firefox); (d) HPACK dynamic-table state that survives a real browsing session. |
| **Plan** | (1) Move `StealthClient` to `rquest`'s lower-level builder so we control frame timing. (2) Add `wafrift_fingerprint::h2_profile::{chrome, firefox, safari}` with frame-by-frame ground truth captured from real browsers (mitmproxy + wireshark). (3) Header-order strategy in `wafrift-fingerprint` keyed off `--tls-impersonate`. (4) JA3-coherence: when rotating, group consecutive requests under one profile for a "session" window before flipping. |
| **Measurable win** | Bypass rate on the cloud-WAF tier of the scoreboard (Tier 2). Today rustls-default is ~0% past Cloudflare Bot Management on a fresh IP; goal 70%+. |

### 2. Public scoreboard

| Problem | "Best-in-class" is a vibe today. Without a public benchmark there's no way to defend the claim — and no way to make every new mutator earn its keep. |
|---|---|
| **Plan** | (1) Docker-compose harness under `wafrift-bench/scoreboard/` with ModSec CRS PL1-4, Coraza, naxsi, libinjection-only. (2) Optional cloud-WAF rigs via terraform (`cf-staging.tf`, `aws-waf-staging.tf`) — opt-in, paid-tier required, gated behind `WAFRIFT_CLOUD_BENCH=1`. (3) GitHub Action that runs the full grid on every push, publishes per-(WAF × payload-class) pass/fail JSON to `wafrift-bench/results/`, and renders a dashboard page on the project site. (4) Per-mutator attribution: every bypass tagged with the technique chain, so we can answer "which mutator carried the bypass" not just "we bypassed." |
| **Measurable win** | Every PR that adds a mutator must show `+N` on the scoreboard. Makes the project legible to outside reviewers and turns wafrift from "tool people try" into "tool people cite." |

### 3. Persistent genome warm-start

| Problem | Every scan today starts cold. The bandit + wafmodel rediscover the same Cloudflare quirks they discovered last week. |
|---|---|
| **Today** | Per-WAF gene-bank at `~/.wafrift/genomes/<waf>.json` stores winning technique chains but doesn't seed the bandit state. |
| **Plan** | Persist Phase-C bandit posteriors + wafmodel SFA state to `~/.wafrift/genomes.db` keyed by `(waf_fingerprint, payload_class, delivery_shape)`. Warm-start from the persisted posterior on every scan; cross-target transfer when the fingerprint matches. |
| **Measurable win** | 5× faster time-to-first-bypass on a repeat target (measured against the scoreboard). Compounds: every scan you run improves the next. |

---

## Tier 2 — cheap, ship now

### 4. `wafrift legendary --target X` — one-shot demo

Runs `detect → fingerprint → discover → scan → bypass-probe → report` in a single command, emits a polished HTML + markdown writeup. Today every step is a separate invocation; the demo magnet is one command that produces the artifact you'd actually show a stakeholder.

### 5. Oracle echo-back — close the DVWA 20% gap

Blind / stored vulns need an oracle that observes the application side-channel, not the immediate response. `wafrift listener` brings up a loopback HTTP/DNS callback so blind SSRF / time-based SQLi / stored XSS produce a verifiable signal back into the scan. Lifts DVWA recall 80% → ~95%.

### 6. CRS PL4 full coverage in bench

Confirm the bench harness exercises PL4 across all 10 payload classes (not just smoke). Add any missing classes; report pass/fail per class on the scoreboard so PL4 gets its own column.

### 7. Bypass-probe JSON telemetry surfacing

The `retry_after_responses` / `max_retry_after_obeyed_ms` aggregates added in 0.2.18 are already in JSON — add them to the text report's "rate-limited" panel and to `--report-layers` output, so operators see "the WAF asked for 30 s and we obeyed" without parsing JSON.

---

## Tier 3 — open, not blocking legendary

| Item | Why open | Why not blocking |
|---|---|---|
| TCP raw-options rotation (MSS, window scale, SACK) | Needs `CAP_NET_RAW` + custom TCP stack | Coverage cost > value; the JA3/H2 work in #1 picks up most of the same signal |
| Burp BApp Store extension | Distribution channel for non-CLI users | The proxy + chain workflow already works; BApp is polish |
| `.genome` portable bundle export | Genome sharing surface | Today's `wafrift bank export` round-trips the same data; portable format is nice-to-have |
| SARIF output for CI integration | Pentest pipeline polish | `--format json` covers the same machine consumer today |
| Auto-generated SBOM (CycloneDX) | Supply-chain compliance | `cargo-cyclonedx` works out-of-tree if needed |
| Code-signed release artefacts (sigstore / cosign) | Trust chain for binary distribution | Crates.io distribution path is already authenticated |

These show up here so they're not forgotten — but none of them moves the scoreboard, so none of them blocks legendary.

---

## How this roadmap stays honest

- Every Tier-1 + Tier-2 item lands behind a scoreboard delta. No "infrastructure" items that don't have an end-user measurable win.
- "Done" rows are deleted, not buffered. The CHANGELOG is the audit trail; this doc is what's left.
- If a Tier-3 item starts getting requested, it gets promoted with a measurable win statement. If a Tier-1 item stalls past a deadline, it gets demoted and re-scoped.

Supporting docs: [TLS_PARITY.md](./TLS_PARITY.md) · [PROXY_TOOLING.md](./PROXY_TOOLING.md) · [PRACTITIONER_WALKTHROUGH.md](./PRACTITIONER_WALKTHROUGH.md).
