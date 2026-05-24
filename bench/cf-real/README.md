# `bench/cf-real` — wafrift Cloudflare-real WAF target

A small intentionally-vulnerable Cloudflare Worker that lives in
this repo so wafrift can fire bypass payloads through a REAL
Cloudflare WAF — not a local mock. The Worker echoes what reached
origin so a "passed" payload can be confirmed verbatim.

## Why this exists

The mock harness at `crates/cli/tests/mock_waf_e2e.rs` proves
wafrift *can* bypass synthetic regex-based blocks, but real
Cloudflare WAF behaviour (Managed Rulesets, custom rule scope,
edge-only inspections, rate-limit interactions) only shows up
against the actual edge. This bench lets the operator pin a
ground-truth bypass rate against a known-fixed ruleset.

## Isolation guarantees

The Worker is stateless and side-effect-free:

- No database / KV / R2 / D1 binding.
- No outbound `fetch()` — even a successful injection can't
  pivot to SSRF.
- Every response bounded at 8 KiB (no amplification surface).
- The `/redirect` endpoint refuses cross-origin destinations.
- Set-Cookie reflect (`/reflect-cookie`) lives on `Path=/`
  with `HttpOnly`; the cookie is never read back by the
  Worker.

If an attacker fully compromises the Worker the blast radius is
"they can make requests against the bench surface" — same as a
public proof-of-concept page.

## Files

```
bench/cf-real/
├── README.md              this file
├── wrangler.toml          Wrangler deploy config
├── scripts/
│   └── apply-waf.sh       install zone-level WAF rules
└── worker/
    ├── package.json
    ├── tsconfig.json
    └── src/
        └── index.ts        the Worker
```

## Operator runbook

1. **Install wrangler** (one-time, on a host with Node):

   ```
   cd bench/cf-real/worker
   npm install
   ```

2. **Authenticate** (one-time):

   ```
   npx wrangler login
   ```

3. **Deploy the Worker:**

   ```
   npx wrangler deploy --config ../wrangler.toml
   ```

   Wrangler will print a URL like
   `https://wafrift-bench.<your-account>.workers.dev`.

4. **Install the WAF rules** on the zone (paid plan required for
   workers.dev custom rules; free-tier workers.dev does NOT honor
   zone Custom Rules):

   ```
   export CF_API_TOKEN=...   # token with Zone:WAF:Edit + Zone:Read
   export CF_ZONE_ID=...     # the zone hosting wafrift-bench
   bash bench/cf-real/scripts/apply-waf.sh
   ```

5. **Run wafrift against it:**

   ```
   cargo run --release --bin wafrift -- bench-waf \
     --base-url https://wafrift-bench.<your-account>.workers.dev \
     --evade \
     --variants 200 \
     --format json > cf-real-bench.json
   ```

   The bench harness POSTs `q=<payload>` to `/post` by default,
   which this Worker handles via its `/post` and `/form` aliases.

6. **Inspect the results:**

   ```
   jq '.scoreboard | sort_by(.strategy)' cf-real-bench.json
   ```

   The Worker's response body for every successful (non-blocked)
   payload contains the bytes the WAF let through to origin —
   verify the payload semantics survived the bypass via
   `jq '.findings[] | {payload, echoed: .response_body.q}'`.

## Disclaimers

- **The Worker is intentionally vulnerable**. Do NOT deploy it
  on a domain that hosts production data or shares cookies with
  a real app. Use the workers.dev subdomain or a dedicated
  domain isolated from production.

- **Cloudflare bills metered features**. The Free plan covers
  100k Worker requests / day; large bench runs may overshoot.
  Check the dashboard before kicking off long sweeps.

- **The WAF rules in `apply-waf.sh` are intentionally minimal**
  so wafrift's bypass-rate trend is meaningful. The free
  Managed Ruleset offers far more coverage — toggle it in the
  zone dashboard if you want a stricter target. Higher coverage
  = lower bypass rates, which is fine for trending.
