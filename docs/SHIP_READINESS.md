# Ship-readiness audit — wafrift v0.2.1

Anticipated reviewer/critic surface and what we shipped to defuse it.
Updated 2026-05-09.

## Things people will hit you on — addressed

| Critique | Status |
|---|---|
| `wafrift-detect 0.2.0` on crates.io ships **empty** WAF rules | README warning + 0.2.1 release ready (awaits maintainer publish) |
| Marketing claim "100% bypass" reads as one-shot vs reality | Headline rewritten with explicit "given enough variants" qualifier + link to `PRACTITIONER_WALKTHROUGH.md` |
| `--from-waf Cloudflare` README example doesn't work on first install | Rewritten to explain genomes are populated by first scan |
| Proxy silent 403 when targeting localhost | Error message names the fix (`--allow-private-upstream`) |
| HTTPS-without-MITM is a pure tunnel — practitioner thinks evasion is happening | Throttled per-host info log on first CONNECT pass-through |
| MITM CA defaulted to rcgen's 10-year validity | Bounded to 397 days (CA/B-forum max for leafs) |
| No comparison vs sqlmap tampers / Burp nowafpls / smuggler | Calibrated comparison table in README's "Why WafRift?" |
| No reproducibility hash for bench corpus | `wafrift-bench/CORPUS.SHA256` + CI gate |
| No fuzz/property coverage on input parsers | `import_curl_proptest.rs` — 2048 cases per property, 3 invariants |
| Dockerfile shipped but CI never builds it | New `docker:` job in `.github/workflows/ci.yml` — builds image, smokes wafrift/wafrift-proxy/man on every PR |
| Doc-link rot risk | All four referenced docs (`docs/{GAP_CLOSURE_ROADMAP,PROXY_TOOLING,TLS_PARITY,REFINEMENT_AUDIT}.md`) confirmed present |
| `v0.1` references in README | Stripped (now version-agnostic / auto from cargo) |
| Default proxy has no auth — anyone on loopback can use it | Loopback-only bind by default + peer-loopback gate on status/findings endpoints; `--listen 0.0.0.0` already warned + `--mitm` on non-loopback hard-aborts |
| Block-only host telemetry was being dropped on flush | Fixed in this round (commit `142357c`) |
| TUI ships as default but README admits "early-stage" | Documented in README; non-TTY exits cleanly with usage hint, no crash |

## Genuine open items (stated, not hidden)

- **Proxy evasion ≠ scan evasion.** The proxy currently does
  HTTP-layer-only escalation (UA / headers / body encoding) and does
  NOT mutate URL-injected payload bytes. That mutation lives in
  `wafrift scan` and `wafrift bench-waf`. A practitioner using only
  the proxy against a strict WAF (e.g. ModSec PL=4) will under-deliver
  vs the scan-path numbers. Documented in
  `docs/PRACTITIONER_WALKTHROUGH.md` step 5.
- **No pre-shipped vendor genomes** for Cloudflare / AWS WAF /
  Akamai — first scan against any new WAF goes through full
  discovery. Practitioners share gene-banks via
  `wafrift bank export` / `wafrift bank import`.
- **wafrift-detect 0.2.1 still pending crates.io publish.** Code,
  vendored rules, and dry-run all green; awaits explicit `cargo
  publish` go-ahead from the maintainer per the project's
  "personally read every file" policy.

## Verification

- 1774 unit/integration tests across 62 binaries, 0 failed,
  1 ignored.
- Live walkthrough against ModSec + OWASP CRS at PL=4 captured in
  `docs/PRACTITIONER_WALKTHROUGH.md`.
- `wafrift seed`, `bank list/export/import`, `report`, `replay`,
  `man`, and `import-curl` all exercised end-to-end against fixtures.
- `wafrift-bench/CORPUS.SHA256` pinned at
  `aaba7e256ceeca0ab5a8d4b5b95ae34a704e53db716ba4b9d12c5c7fe11367bc`;
  CI fails any drift.

## Out-of-scope for v0.2.1 (acknowledged, not shipped)

- SARIF output for security-tooling pipeline integration.
- Per-tool tamper-script export (sqlmap-compatible).
- Burp extension (`.bambda` / Java). Tracked separately.
- Auto-generated SBOM (CycloneDX). The release workflow can grow it
  in a follow-up.
- Code-signing of release artefacts (sigstore / cosign).
