# Wafrift Feedback — Paddle Hash-Fragment + Sanitizer Bypass

**Date:** 2026-06-03
**Target:** sandbox-buy.paddle.com (Cloudflare WAF)
**Finding:** Critical XSS → Session Token Theft
**Wafrift Result:** 1,660 variants fired, 0 real bypasses found
**Actual Bypass Found:** Manual source-code analysis

---

## What Wafrift Did

```bash
wafrift scan \
  "https://sandbox-buy.paddle.com/checkout/che_01kt51kfcm7sr4y71kb0yj1yq3" \
  --param success \
  --payload "javascript:alert(1)" \
  --payload-class xss \
  --level heavy
```

- Fired 1,660 variants against the **query parameter** `?success=`
- Reported 17 "bypasses" early in the run — these were likely HTTP 200 responses on non-dangerous mutations, not actual `javascript:` execution
- Zero real bypasses of Cloudflare's `javascript:` blocking on query params

## What Wafrift Missed

### 1. Hash Fragment Injection Point

The buy page reads `success` from **both query string and hash fragment** via `getQueryOrHashParam()`:

```javascript
static getQueryOrHashParam(t) {
    return ut.queryParams[t] || ut.hashParams[t]
}
```

Cloudflare WAF inspects query parameters but **does not inspect URL hash fragments**:

```bash
?success=javascript:alert(1)   → 403 Blocked
#success=javascript:alert(1)   → 200 OK ← bypass
```

**Wafrift never tested `#success=` as an injection point.** It only fires `?param=...` variants.

### 2. Sanitizer Logic Flaws (Not WAF Flaws)

The actual gate was not the WAF — it was the client-side `sanitizeUrl()` function:

```javascript
if (url.substring(0, 11).toLowerCase() === 'javascript:') {
    return preventUrl
}
```

This only blocks **exact match at position 0**. A leading space bypasses it:

```bash
#success=%20javascript:alert(1)
```

Stored as: `" javascript:alert(1)"` → sanitizer passes → browser normalizes space → executes.

**Wafrift tests WAF bypass, not sanitizer bypass.** Even if wafrift had tested hash fragments, it would not have caught the sanitizer flaw because:
- Wafrift's "detonate" engine (`jsdet` / `chrome`) tests whether a payload executes in a sandbox
- It does not model the target application's specific sanitizer logic
- It cannot know that `substring(0, 11)` is the exact check being used

### 3. Architectural Two-Code-Path Bugs

The root cause was an **invariant violation**: the API explicitly blocks `settings.success_url` modifications (`400 validation.no_validation_set`), but the buy page's URL parameter parser accepts arbitrary URLs for the same field.

This is not a WAF bypass — it's a **design flaw**. Wafrift cannot detect when an application has two conflicting code paths for the same security-sensitive field.

### 4. Post-Payment Context

The XSS only fires after checkout status transitions to `"completed"` or `"paid"`. Wafrift scans fire payloads against the initial page load, not against the post-payment redirect flow. The vulnerability is state-machine-driven, not present on every request.

## What Manual Testing Found That Wafrift Could Not

| Finding | Manual Method | Why Wafrift Missed It |
|---|---|---|
| Hash fragment injection | `grep getQueryOrHashParam` in bundle | Only tests `?param=` |
| Sanitizer exact-position check | Source map analysis of `src/utils/urls.ts` | No sanitizer modeling |
| Two-code-path invariant violation | API PATCH returns 400, URL param returns 200 | No API-state comparison |
| Browser whitespace normalization | `page.goto(" javascript:alert(1)")` testing | No browser scheme parsing tests |
| Session token theft | Playwright cookie exfiltration in target origin | Detonation sandbox is isolated, not target origin |

## Recommendations for Wafrift

### A. Hash Fragment Testing

Add `--param-location query|hash|both` to `wafrift scan`. Default `both`. Hash fragments bypass many WAFs because they are never sent to the server.

### B. Sanitizer Modeling (Long-term)

If wafrift could ingest a target's source map or bundle and extract sanitizer functions, it could model the exact logic and find bypasses like `substring(0, 11)` exact-match failures. This is a significant feature — essentially "decompile the sanitizer and find its holes."

Short-term: Add a `--prefix-bypass` mode that prepends whitespace/null/CJK/confusable characters to payloads and verifies execution.

### C. State-Aware Scanning

For checkout/payment flows, add a `--state-aware` mode that:
1. Loads the checkout page
2. Completes the flow (or simulates completion)
3. Captures the redirect/response
4. Tests XSS execution in the ORIGIN of the redirect target, not an isolated sandbox

### D. API Invariant Detection

Add a `--probe-api` flag that compares URL parameter acceptance against API-level restrictions for the same field. If `PATCH /settings/{field}` returns 400 but `?field=` returns 200, flag it.

---

## Bottom Line

**Wafrift is a WAF bypass tool, not an application logic auditor.** This finding was 100% application logic:
- Hash fragment parsing (architectural)
- Exact-position sanitizer check (code bug)
- API vs. URL parameter inconsistency (design flaw)
- Post-payment redirect flow (state machine)

None of these are WAF evasion techniques. Wafrift correctly reported "zero WAF bypasses" because Cloudflare's WAF is actually working correctly on query parameters. The vulnerability lives in the gap between what the WAF sees and what the application does with the data after it passes the WAF.
