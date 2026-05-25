# santh.dev hardening — pre-flight before exposing testing.santh.dev

Audit performed 2026-05-25. Items below are ordered by priority; ship 1–4 BEFORE adding `testing.santh.dev` so the vulnerable subdomain can't be used as a foothold.

---

## Already strong (do NOT touch)

| Control | Value | Notes |
|---|---|---|
| SPF | `v=spf1 include:_spf.google.com -all` | Hard-fail `-all` is correct |
| DMARC | `v=DMARC1; p=reject; rua=mailto:dmarc@santh.dev; adkim=s; aspf=s; pct=100` | Strictest possible — full reject + strict alignment |
| HSTS | `max-age=31536000; includeSubDomains; preload` | Preload + subdomain coverage |
| CSP | `default-src 'none'; ...` (locked down) | One of the strictest possible |
| Headers | XFO=DENY, nosniff, Permissions-Policy locked, Referrer-Policy strict | Production-grade |

---

## CRITICAL — fix before testing.santh.dev goes live

### 1. DKIM (Google Workspace) — broken delivery risk

Currently `google._domainkey.santh.dev` returns **empty**. DMARC `p=reject` is being enforced by SPF alone; SPF breaks on forwarded mail, so any santh.dev → Gmail-then-forward → recipient chain currently **bounces**. Symptom: sporadic complaints from people who didn't get a reply you actually sent.

**Action:**
1. Google Workspace Admin → Apps → Google Workspace → Gmail → Authenticate email
2. Generate DKIM key for `santh.dev` (Google emits a 2048-bit key by default — accept)
3. Copy the TXT record value Google shows
4. Add at Cloudflare DNS:
   - **Type**: TXT
   - **Name**: `google._domainkey`
   - **Content**: `v=DKIM1; k=rsa; p=<long key from Google>`
   - **TTL**: Auto
   - **Proxy**: DNS only (gray cloud)
5. Wait 24h, then click "Start authentication" in Google Workspace
6. Verify: `dig +short google._domainkey.santh.dev TXT` should return the key

### 2. CAA — anyone can issue a cert for santh.dev right now

No CAA record means ANY public CA can issue a valid cert for `santh.dev`. crt.sh shows current issuers are Google Trust Services + Let's Encrypt (Cloudflare's edge certs). Lock to just those.

Add at Cloudflare DNS:

| Type | Name | Content |
|---|---|---|
| CAA | `@` | `0 issue "pki.goog"` |
| CAA | `@` | `0 issue "letsencrypt.org"` |
| CAA | `@` | `0 issuewild "pki.goog"` |
| CAA | `@` | `0 issuewild "letsencrypt.org"` |
| CAA | `@` | `0 iodef "mailto:security@santh.dev"` |

(The CF dashboard's CAA form takes flags + tag + value separately — flags=0, tag=issue/issuewild/iodef, value=the string.)

Verify: `dig +short santh.dev CAA` should return all 5.

---

## MEDIUM

### 3. MTA-STS — prevent STARTTLS stripping on inbound mail

Without MTA-STS, an active network attacker can downgrade inbound mail TLS to plaintext.

**Two parts:**

**a. Policy file** at `https://mta-sts.santh.dev/.well-known/mta-sts.txt`:

```
version: STSv1
mode: enforce
mx: aspmx.l.google.com
mx: alt1.aspmx.l.google.com
mx: alt2.aspmx.l.google.com
mx: alt3.aspmx.l.google.com
mx: alt4.aspmx.l.google.com
max_age: 604800
```

Easiest hosting: another Cloudflare Worker (or a Pages project) on `mta-sts.santh.dev`. There's a 5-line worker that just returns the file with `Content-Type: text/plain`.

**b. DNS records:**

| Type | Name | Content |
|---|---|---|
| CNAME | `mta-sts` | `<your-mta-sts-worker>.workers.dev` |
| TXT | `_mta-sts` | `v=STSv1; id=20260525000000` |

The `id` is an opaque version string — bump it (e.g. `id=20260601000000`) whenever you change the policy file. Mail senders cache the policy until the id changes.

### 4. TLS-RPT — get reports when TLS delivery fails

Pairs with MTA-STS. Senders that support TLS-RPT will mail you a JSON report when their connection to your MX hit a TLS problem.

| Type | Name | Content |
|---|---|---|
| TXT | `_smtp._tls` | `v=TLSRPTv1; rua=mailto:tls-reports@santh.dev` |

(If you don't want yet-another-mailbox, route `tls-reports@santh.dev` to whoever handles DMARC reports.)

---

## After 1–4 are in: provision testing.santh.dev

The subdomain is safe for santh.dev as long as you do NOT do the following:
- Set cookies with `Domain=.santh.dev` from any santh.dev surface (cookies will leak to the vulnerable subdomain)
- Share auth/session state across subdomains
- Rely on `document.domain` (modern browsers reject this anyway)

The worker code already satisfies these constraints — it sets cookies with no `Domain` attribute (host-only), has no session/auth state, and never reaches out beyond its own response.

### CF dashboard

1. Cloudflare DNS → Add record:
   - **Type**: CNAME
   - **Name**: `testing`
   - **Target**: `wafrift-bench.contactmukundthiru.workers.dev`
   - **Proxy**: **Proxied (orange cloud)** — required for Custom Rules + Managed Ruleset to fire
2. Upgrade santh.dev to **Pro** (Cloudflare → santh.dev → Plans). Free tier doesn't get the full Managed Ruleset.

### wrangler.toml — add the route

```toml
[[routes]]
pattern = "testing.santh.dev/*"
zone_name = "santh.dev"
```

Then re-deploy: `npx wrangler deploy` from `bench/cf-real/`.

### Apply WAF rules

After CNAME + Pro are live, set:

```bash
export CF_API_TOKEN=<token with Zone:WAF:Edit + Zone:Zone:Read on santh.dev>
export CF_ZONE_ID=<santh.dev zone id from CF dashboard>
bash bench/cf-real/scripts/apply-waf.sh
```

That installs the SQLi + XSS Custom Rules and toggles the Managed Ruleset on.

### Verify isolation

```bash
# testing.santh.dev should respond
curl -sI https://testing.santh.dev/ | head -3

# Cookies set on testing should NOT be visible to santh.dev
curl -s -c /tmp/jar https://testing.santh.dev/reflect-cookie?name=test=1
grep '^[^#].*test' /tmp/jar
# Should show domain="testing.santh.dev" (host-only), NOT ".santh.dev"

# CSP / HSTS still active on the parent
curl -sI https://santh.dev/ | grep -iE 'strict-transport|content-security'
```

### Bench

```bash
./target/release/wafrift bench-waf \
  --base-url https://testing.santh.dev \
  --corpus wafrift-bench/corpus \
  --evade \
  --strategies heavy,equiv-cegis \
  --variants 5 \
  --delay-ms 100 \
  --format json \
  --output bench/cf-real/results-pro-$(date +%Y%m%d).json \
  --summary-only
```

The `--delay-ms 100` is conservative for the Cloudflare rate-limit; bump down if you have a paid plan that lifts the per-IP cap.

---

## Optional polish (after the bench works)

- **BIMI** (`default._bimi.santh.dev`) — shows your logo next to Gmail/Yahoo senders. Requires a VMC cert (~$1.5k/yr from Entrust/DigiCert) so usually only worth it post-revenue.
- **DNSSEC** — Cloudflare can enable this in two clicks. Verifies your DNS hasn't been tampered with. Low effort, high payoff.
- **Security.txt** at `https://santh.dev/.well-known/security.txt` — RFC 9116 contact channel for vulnerability reports. Five lines.
