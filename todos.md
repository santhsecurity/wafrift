# Wafrift Improvement Todos — Discovered During Discourse Web Bounty

## WAF Detection

- [ ] **`detect` subcommand lacks `--url` flag for direct probing**
  Current workflow requires manual `curl` to capture headers, then feeding `--status` and `--headers` arguments. This breaks recon automation. `wafrift detect --url https://target.com` should perform the request internally.
  Repro: `wafrift detect --url https://discourse.org` fails with "unexpected argument '--url'".

- [ ] **Failed to detect CloudFront on discourse.org**
  discourse.org sits behind CloudFront (`via: 1.1 ...cloudfront.net`, `x-cache: Hit from cloudfront`, `x-amz-cf-pop`, `x-amz-cf-id`). wafrift detect reported "No WAF confidently detected." CloudFront is a CDN/WAF — it should be fingerprinted.
  Repro: `wafrift detect --status 200 --headers "via: 1.1 b7f67574068333a51eb10f999105d790.cloudfront.net (CloudFront)" --headers "x-cache: Hit from cloudfront"`

- [ ] **Failed to detect any protection on meta.discourse.org**
  meta.discourse.org likely has CloudFlare or similar CDN. Response headers include `server: nginx`, `x-discourse-route`, CSP, HSTS. wafrift detect returned "No WAF confidently detected." Either there is no WAF (possible) or wafrift's signatures are missing common Discourse hosting configurations.
  Repro: `wafrift detect --status 200 --headers "server: nginx" --headers "x-frame-options: SAMEORIGIN"`

## General

- [ ] **No integration with gossan recon pipeline**
  The ideal workflow would be: gossan finds endpoints → pipes directly to wafrift scan/detect. Currently these are completely separate manual steps.

## Rate Limit Evasion

- [ ] **No rate-limit evasion techniques for 429 responses**
  meta.discourse.org uses `discourse-rate-limit-error-code: ip_10_secs_limit`. Wafrift has no specific technique to bypass or evade Discourse's per-IP rate limiting. For authorized testing, distributed egress or slow-roll strategies would be needed — wafrift should document or support this.

## Bypass-Probe False Positives

- [ ] **Rate-limit responses incorrectly flagged as bypass divergences**
  Against try.discourse.org/admin (baseline 404), 135 of 191 probes returned 429 due to Discourse's `ip_10_secs_limit` rate limiting. wafrift flagged every 429 as a "divergence" with body delta ~-99%. A 429 response is not a bypass — it's the target telling us to slow down. The tool should recognize 429/503/403-WAF-block responses and exclude them from bypass claims, or at minimum flag them as "RATE_LIMITED, inconclusive" rather than "LOW severity bypass."
  Repro: `wafrift bypass-probe https://try.discourse.org/admin --delay-ms 100`

## Build / Distribution

- [ ] **Release binary disappeared from expected path**
  The wafrift release binary at `/media/mukund-thiru/SanthData/Santh/software/wafrift/target/release/wafrift` vanished during the session. The symlink `~/.local/bin/wafrift` points to a non-existent file. Whether this was `cargo clean`, a tmpfs cleanup, or something else — the install is not durable. Need a stable install path or post-build hook that validates the symlink target.
  Repro: `ls -la ~/.local/bin/wafrift` → broken symlink.

## CLI Inconsistency

- [ ] **Inconsistent argument passing across subcommands**
  `wafrift bypass-probe` takes a positional `<URL>` argument, but `wafrift scan` requires `--target <TARGET>`, `wafrift discover` takes no positional args, and `wafrift evade` takes no positional args. The CLI is unpredictable — users have to check `--help` for every single command. Standardize on either positional args for the primary target or flags everywhere.
  Repro: `wafrift scan https://try.discourse.org/...` fails; `wafrift bypass-probe https://...` works.

- [ ] **`evade` help claims `--format` is supported but CLI rejects it**
  `wafrift evade --help` lists `--format` as an option, but running `wafrift evade --payload '<script>alert(1)</script>' --format json` fails with `unexpected argument '--format' found`. The help text and actual argument parser are out of sync.
  Repro: `wafrift evade --payload 'test' --format json`

- [ ] **`init` mentions `wafrift-proxy` binary that may not exist**
  `wafrift init` outputs: "Run `wafrift-proxy --listen 127.0.0.1:8080 --mitm`..." but `wafrift-proxy` is a separate crate/binary that may not be installed or in PATH. The init scaffold should check for the proxy binary's presence or at minimum document how to install it.
  Repro: `wafrift init` then `which wafrift-proxy` → not found.

- [ ] **`.wafrift.toml` config is not auto-loaded by `wafrift scan`**
  The scaffolded config file contains an explicit note: "`wafrift scan` does not yet auto-load this file. The `[scan]` section below documents the keys that match `ScanArgs` flags; they must be passed as CLI flags until the config-integration pass wires `WafRiftConfig::load()` into the scan command." A config file that isn't read by the tool it's meant to configure is a broken user experience.
  Repro: `wafrift init` → edit `.wafrift.toml` → `wafrift scan` ignores it.

- [ ] **`report` only reads from proxy gene bank, not from `scan` output**
  `wafrift report` generates a markdown report from `wafrift-proxy` gene bank data. It does not read `wafrift scan` JSON output. Users running `scan` followed by `report` get "No bypasses recorded yet." The two commands don't compose in the expected way.
  Repro: `wafrift scan --target ... --format json > findings.json` → `wafrift report` → empty report.

- [ ] **`origin-hints` requires `--host` flag, not positional arg**
  `wafrift origin-hints discourse.org` fails with `unexpected argument 'discourse.org' found`. The command requires `--host discourse.org`. More CLI inconsistency — `bypass-probe` takes positional URL, `origin-hints` requires `--host`.
  Repro: `wafrift origin-hints discourse.org`

- [ ] **`scan` hangs for 3+ minutes with zero output against live target**
  `wafrift scan --target https://try.discourse.org/t/welcome-to-our-demo/57 --payload '<script>alert(1)</script>' --delay-ms 200 --format json` ran for 180 seconds and produced nothing before timing out. The target has rate limiting, but even with `--delay-ms 200` the scan made no progress and emitted no status. It should at minimum print a startup banner ("Firing N variants against target...") and handle 429 responses gracefully.
  Repro: `wafrift scan --target https://try.discourse.org/... --payload '<script>alert(1)</script>' --delay-ms 200`

- [ ] **`bench-waf` default corpus path fails when not run from repo root**
  `wafrift bench-waf --base-url https://try.discourse.org --evade` fails with `read_dir wafrift-bench/corpus: No such file or directory`. The default `--corpus` path is relative to CWD, not the binary location or a system data dir. When installed via `cargo install`, the corpus won't exist unless manually cloned.
  Repro: Run `wafrift bench-waf` from any directory other than the wafrift repo root.

- [ ] **`import-curl` requires `--param` and `--payload` flags instead of parsing the curl command**
  `wafrift import-curl 'curl -s https://try.discourse.org/'` fails because `--param` and `--payload` are required. The command name suggests it should parse a curl invocation and extract the target automatically. Instead it seems to use the curl string only as a base and still requires explicit param/payload.
  Repro: `wafrift import-curl 'curl -s https://try.discourse.org/'`

- [ ] **`seed` help says `--technique` is optional but it's actually required**
  `wafrift seed --help` shows `--technique` without `[REQUIRED]` marker, but running `wafrift seed --waf cloudflare --dry-run` fails with `error: --technique is required`. The help text and argument validation are out of sync.
  Repro: `wafrift seed --waf cloudflare --dry-run`

- [ ] **`evade` rejects `--stealth-browser` even though it's in global help**
  `wafrift evade --payload 'A' --level heavy --stealth-browser chrome` fails with `unexpected argument '--stealth-browser' found`. The flag is listed in the top-level `wafrift --help` as a global option, but `evade` doesn't accept it. Either remove it from global help or wire it through to all subcommands.
  Repro: `wafrift evade --payload 'A' --stealth-browser chrome`

- [ ] **`detect` accepts invalid HTTP status code 999 without error**
  `wafrift detect --status 999 --headers 'server: nginx'` runs without validation error. HTTP status codes must be in range 100-599. Invalid status codes should be rejected at parse time.
  Repro: `wafrift detect --status 999 --headers 'server: nginx'`

- [ ] **Binary/null-byte payload rejected as "empty"**
  `wafrift evade --payload $'\x00\x01\x02' --level light` fails with `Input error: --payload is empty`. The payload contains binary data but is not empty. The argument parser likely uses a C-string comparison that terminates at the first null byte.
  Repro: `wafrift evade --payload $'\x00\x01\x02' --level light`

- [ ] **`--only` technique names don't match `techniques list` display names**
  `wafrift evade --payload '<script>alert(1)</script>' --only encoding::UrlEncode` fails with `unknown technique selector(s): encoding::UrlEncode`. The `techniques list` shows paths like `encoding/url/single`, `encoding/url/double`, etc. The error message suggests running `techniques list` but the naming convention is unclear — users can't directly map "UrlEncode" to `encoding/url/single`. Need better documentation or fuzzy matching.
  Repro: `wafrift evade --payload 'test' --only encoding::UrlEncode`

- [ ] **`scan` rejects `--verify-batch` even though it's in help**
  `wafrift scan --target ... --payload ... --verify-batch` fails with `unexpected argument '--verify-batch' found`. The flag is documented in `wafrift scan --help` but not accepted by the parser.
  Repro: `wafrift scan --target https://try.discourse.org/... --payload 'test' --verify-batch`

- [ ] **`bypass-probe` accepts invalid `--body-diff-threshold-pct` > 100**
  `wafrift bypass-probe ... --body-diff-threshold-pct 200` runs without error. A percentage threshold above 100 is meaningless (body can't be 200% different from itself). The tool should validate the range is 0-100.
  Repro: `wafrift bypass-probe https://try.discourse.org/admin --body-diff-threshold-pct 200`

- [ ] **`scan` without `--encoding-only` is impractically slow against live rate-limited targets**
  `wafrift scan --target https://try.discourse.org/... --payload '<script>alert(1)</script>' --delay-ms 200` timed out after 3 minutes with zero output. The same command with `--encoding-only` completed in ~115 seconds and found 159 bypasses against ThreatX. The full evasion engine (grammar mutations, etc.) is so slow that it appears hung. The tool needs progress indicators and a default mode that completes in reasonable time.
  Repro: Compare `wafrift scan ...` (hangs) vs `wafrift scan ... --encoding-only` (works in ~2min).
