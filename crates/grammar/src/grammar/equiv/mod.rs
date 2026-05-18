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
pub mod path;
pub mod sql;
pub mod ssti;
pub mod wafmodel;
pub mod xss;

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
    matches!(class, "sql" | "xss" | "cmdi" | "path" | "ssti" | "ldap")
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
        _ => Vec::new(),
    }
}
