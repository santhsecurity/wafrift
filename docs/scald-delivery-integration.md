# scald ← wafrift delivery-shape XSS integration (apply post-0.2.16)

Prereq: `wafrift-{types,grammar} = "=0.2.16"` published; scald
`crates/scald-core/Cargo.toml` repinned to `=0.2.16`;
`cargo update -p wafrift-grammar -p wafrift-types`.

## 0.2.17 update — two more channels, ZERO scald code change

0.2.17 adds `DeliveryShape::HeaderValue` (e.g. `X-Forwarded-Host`) and
`DeliveryShape::Cookie` — the reflected-XSS surface a CRS-class WAF
covers more weakly in `REQUEST_HEADERS` / `REQUEST_COOKIES` than in
ARGS at PL1. **`waf_delivery.rs` needs no change**: it already
iterates `xss_delivered()` and renders each member via
`m.delivery.to_request()`, both of which now include the two new
channels (smuggle-guarded: CR/LF/NUL/`;` can never reach the wire, and
the generator never pairs a transport-illegal payload with a raw
channel). To pick them up: bump the scald pin to `=0.2.17`, then
`cargo update -p wafrift-grammar -p wafrift-types`. Nothing else.

Honest basis: payload-string XSS = 0 % vs CRS (it normalises every
encoding); the only lever that beats CRS = delivery shape
(multipart-file / path-segment / JSON-no-CT) = 18.5 %. scald's
escalation ladder ends at the double-URL tier and never tries it.

## 1. New module — `crates/scald-core/src/waf_delivery.rs` (verbatim)

```rust
//! Terminal WAF-evasion tier: re-deliver the SAME instrumented payload
//! via wafrift's sound `(payload × delivery)` equivalence shapes
//! (multipart-file / path-segment / JSON-without-Content-Type). A
//! CRS-class WAF normalises every payload-string trick but inspects
//! these transport shapes differently; the backend still sinks the
//! value, so the marker still reflects. Each member still executes the
//! original script (wafrift verifies that by construction).

use wafrift_grammar::grammar::equiv::xss_delivered;

/// One non-blocked, marker-bearing delivery attempt.
pub struct DeliveryHit {
    pub url: String,
    pub method: String,
    pub status: u16,
    pub body: String,
    pub label: &'static str, // delivery shape: multipart_file / …
}

/// Try every delivered equivalence member of `instrumented` against
/// `target`. Returns the first that the WAF did not block AND whose
/// response still carries `marker` (caller then runs the normal
/// `verify::verify_payload` + finding construction). `None` ⇒ the
/// delivery tier did not beat the WAF for this payload.
pub async fn try_delivery_shapes(
    client: &reqwest::Client,
    target: &str,
    instrumented: &str,
    marker: &str,
    max_members: usize,
    max_response_bytes: usize,
    rate_limiter: &crate::rate::RateLimiter,
) -> Option<DeliveryHit> {
    for m in xss_delivered(instrumented, max_members) {
        let req = m.delivery.to_request(target, &m.payload);
        let method = reqwest::Method::from_bytes(req.method.as_str().as_bytes())
            .unwrap_or(reqwest::Method::GET);
        let mut rb = client.request(method.clone(), &req.url);
        for (k, v) in &req.headers {
            rb = rb.header(k, v);
        }
        if let Some(b) = &req.body {
            rb = rb.body(b.clone());
        }
        let res = match rb.send().await {
            Ok(r) => r,
            Err(_) => continue,
        };
        if let Some(len) = res.content_length() {
            if len as usize > max_response_bytes {
                continue;
            }
        }
        let status = res.status().as_u16();
        rate_limiter.record_status(status);
        let body = res.text().await.unwrap_or_default();
        if body.len() > max_response_bytes {
            continue;
        }
        // Same block oracle the query path uses.
        if crate::waf::classify_response(status, &body, 200).is_blocked() {
            continue;
        }
        if body.contains(marker) {
            return Some(DeliveryHit {
                url: req.url,
                method: method.as_str().to_string(),
                status,
                body,
                label: m.delivery.label(),
            });
        }
    }
    None
}
```

Register it: add `mod waf_delivery;` to `crates/scald-core/src/lib.rs`
(next to the other `mod` lines).

## 2. Escalation-tier wiring in `reflected.rs`

a. Near `let mut double_url_pass = false;` (~L381) add
   `let mut delivery_pass = false;`.

b. Ladder: replace the final `} else { … break 'escalation }`
   (~L734) so the delivery tier runs AFTER double-URL is exhausted
   (it must NOT be gated on `!is_json && !is_path` — exploring other
   shapes is the entire point):
   ```rust
   } else if config.waf_evasion && !delivery_pass {
       delivery_pass = true;
       escalation = wafrift_types::EscalationLevel::None;
       current_payloads = base_payloads.clone();
   } else {
       break 'escalation;
   }
   ```

c. At the TOP of `for base_payload in &current_payloads {` (right
   after `let xss_payload = instrument_payload(base_payload,&marker);`,
   ~L386) short-circuit when in the delivery tier:
   ```rust
   if delivery_pass {
       let Some(hit) = crate::waf_delivery::try_delivery_shapes(
           &client, target.as_str(), &xss_payload, &marker,
           24, max_response_bytes, &rate_limiter,
       ).await else { continue };
       let verify_result = match crate::verify::verify_payload(&hit.body, &marker) {
           Ok(r) if r.triggered => r,
           _ => continue,
       };
       let mut observations = verify_result.observations;
       observations.push(format!("waf_escalation_chain: delivery::{}", hit.label));
       let authed = config.auth.is_some() || config.login.is_some();
       let sev = crate::severity::score(&crate::severity::SeverityInput::reflected(
           context, true, crate::severity::source_from_param(param_source),
           authed, false, /*waf_was_bypassed=*/true,
       ));
       for r in &sev.rationale { observations.push(format!("severity_rationale: {r}")); }
       local_findings.push(XssFinding {
           rule_id: "scald/reflected-xss".into(),
           xss_type: XssType::Reflected,
           severity: sev.band, confidence: sev.confidence,
           param: param_name.clone(), context,
           payload: xss_payload.clone(),
           evidence: Evidence {
               request_url: hit.url.clone(),
               request_method: hit.method.clone(),
               response_status: hit.status,
               response_snippet: snippet_around_marker(&hit.body, &marker, 80),
               sandbox_observations: observations,
           },
           taint_path: None, cwe: "CWE-79".into(),
           poc_url: hit.url,
           waf_bypassed: true,
           fix_hint: format!(
               "Input reflected unsafely; the WAF was bypassed by \
                delivering the payload via the `{}` transport shape — \
                inspect non-query request bodies/paths too.", hit.label),
           unverified: false,
       });
       break 'escalation;
   }
   ```

## 3. Tests (add with the change)
- unit: `xss_delivered("<svg onload=alert(1)>",8)` non-empty, shapes
  varied, every member `equiv::xss::still_executes_xss`.
- e2e vs `wafrift-bench` modsec-pl1: a reflected XSS that 403s in the
  query MUST verify via a delivery member (`multipart_file` /
  `path_segment`); WAF-less target unchanged (delivery tier only
  reached after lower tiers exhaust).
