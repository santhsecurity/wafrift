# scald ← wafrift delivery-shape XSS integration (post-0.2.16)

Apply AFTER `wafrift-types`/`wafrift-grammar` 0.2.16 are on crates.io
and scald is repinned (`crates/scald-core/Cargo.toml`:
`wafrift-grammar = "=0.2.16"`, `wafrift-types = "=0.2.16"`;
`cargo update -p wafrift-grammar -p wafrift-types`).

## Why
Measured honest fact: payload-string XSS = 0% vs CRS (it normalises
every encoding). The only lever that beats CRS = delivery shape
(multipart-file / path-segment / JSON-no-Content-Type) = 18.5%.
scald's escalation ladder (`reflected.rs` `'escalation: loop`,
~L383) ends at the double-URL tier — it never tries delivery shapes.

## wafrift API to consume (shipped 0.2.16)
- `wafrift_grammar::grammar::equiv::xss_delivered(payload: &str, max: usize)
   -> Vec<EquivPayload>` — sound `(payload × delivery)` XSS class,
  deterministic; every member still executes the original.
- `EquivPayload { payload: String, delivery: DeliveryShape, .. }`.
- `DeliveryShape::to_request(&self, target: &str, payload: &str)
   -> wafrift_types::Request { method, url, headers:Vec<(String,String)>,
   body:Option<Vec<u8>> }` — the single-source renderer.

## Adapter (scald has none — add once, mirrors L532-543 json path)
```rust
async fn send_wafrift_request(
    client: &reqwest::Client,
    r: &wafrift_types::Request,
) -> reqwest::Result<reqwest::Response> {
    let m = reqwest::Method::from_bytes(r.method.as_str().as_bytes())
        .unwrap_or(reqwest::Method::GET);
    let mut rb = client.request(m, &r.url);
    for (k, v) in &r.headers { rb = rb.header(k, v); }
    if let Some(b) = &r.body { rb = rb.body(b.clone()); }
    rb.send().await
}
```
(`wafrift_types::Method` — confirm the `as_str()`/uppercase accessor
name at integration time; request.rs:72 has "method as uppercase
string slice".)

## Escalation-tier wiring (reflected.rs)
1. Add `let mut delivery_pass = false;` next to `double_url_pass`
   (~L381).
2. New ladder arm BEFORE the final `else { break 'escalation }`
   (~L734), after the double-URL arm:
   ```rust
   } else if config.waf_evasion && !delivery_pass {
       delivery_pass = true;
       escalation = wafrift_types::EscalationLevel::None;
       current_payloads = base_payloads.clone();
   }
   ```
   Note: delivery tier runs for ALL param sources (incl. is_json /
   is_path) — exploring OTHER shapes is the whole point, so do NOT
   gate it on `!is_json && !is_path` the way HPP/double-URL are.
3. In the per-payload build section (~L390), add a FIRST branch:
   ```rust
   if delivery_pass {
       let members = wafrift_grammar::grammar::equiv::xss_delivered(
           &xss_payload, 24);
       for m in &members {
           let req = m.delivery.to_request(target.as_str(), &m.payload);
           let res = send_wafrift_request(&client, &req).await;
           // → existing marker/reflection + verify path, then
           //   record XssFinding with technique =
           //   format!("delivery::{}", m.delivery.label()).
       }
       continue; // skip the normal query/json/path build for this payload
   }
   ```
   `DeliveryShape::label()` is `pub` (query/form_body/json_body/
   multipart_field/multipart_file/path_segment/hpp_split).
4. Verification: the instrumented marker is unchanged by delivery, so
   the existing reflection/exec check applies as-is to `res`.
   A verified hit ⇒ `XssFinding { unverified:false, .. }` exactly like
   the other tiers (mirror the L600-677 record block).

## Test
- Unit: `xss_delivered("<svg onload=alert(1)>",8)` non-empty, shapes
  varied, every member `still_executes_xss`.
- e2e: scald vs the wafrift-bench modsec-pl1 container — a reflected
  XSS that 403s in query must verify via a delivery member
  (multipart_file / path_segment), proving the tier fires end to end.
- Regression: WAF-less target unchanged (delivery tier only reached
  after lower tiers exhaust).
