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
use wafrift_transport::is_waf_block;

mod builders;
mod encoders;

use builders::build_request_for_vector;

/// A single (vector_name, default_content_type) row in the
/// catalogue. The `name` is the dispatch key for
/// [`build_request_for_vector`]; the `content_type` is what the
/// builder usually sets (compression variants override it).
#[derive(Debug, Clone, Copy)]
pub struct Vector {
    pub name: &'static str,
    pub content_type: &'static str,
}

/// Catalogue, organised by attack axis. Adding a new vector is one
/// row in the right section + one match arm in
/// [`build_request_for_vector`]. Each section's lead-comment names
/// the WAF gap exploited and points at the backend behaviour that
/// makes the vector land.
///
/// Display ordering is functionally meaningful only at the head —
/// the operator's text-mode scan-output table starts with the
/// natural body shapes (POST-form / POST-json) so the most-common
/// surface is visible first. Beyond the baselines, ordering reflects
/// the attack-axis grouping, not any per-row significance.
pub const VECTORS: &[Vector] = &[
    // ──────── BASELINE BODY SHAPES ────────────────────────────
    // The four natural request shapes a backend speaks: form,
    // JSON, XML, multipart. WAFs gate body inspection per
    // Content-Type; everything below stretches one or more of
    // those routing decisions until the gate breaks.
    Vector { name: "POST-form", content_type: "application/x-www-form-urlencoded" },
    Vector { name: "POST-json", content_type: "application/json" },
    Vector { name: "POST-xml", content_type: "application/xml" },
    Vector { name: "POST-multipart", content_type: "multipart/form-data" },

    // ──────── COMPRESSION-CONFUSION (Content-Encoding gap) ────
    // brotli is the headline class — almost no inspection
    // pipeline ships a brotli decoder. gzip is the control (most
    // WAFs do decode it); a gzip-only bypass is a separate bug.
    // deflate is the third option — the encoding crate's own
    // doc-comment flags it as "irregular WAF support".
    // Chain `gzip,br` per RFC 9110 §8.4 stacks both layers so
    // a WAF with ONE decoder still sees an opaque blob.
    Vector { name: "POST-form-br", content_type: "application/x-www-form-urlencoded" },
    Vector { name: "POST-json-br", content_type: "application/json" },
    Vector { name: "POST-form-gz", content_type: "application/x-www-form-urlencoded" },
    Vector { name: "POST-json-gz", content_type: "application/json" },
    Vector { name: "POST-form-deflate", content_type: "application/x-www-form-urlencoded" },
    Vector { name: "POST-json-deflate", content_type: "application/json" },
    Vector { name: "POST-json-gz-br", content_type: "application/json" },
    Vector { name: "POST-form-gz-br", content_type: "application/x-www-form-urlencoded" },

    // ──────── JSON PARSER-DISAGREEMENT ────────────────────────
    // Bytes that parse one way for the WAF and a different way
    // for the backend. UTF-8 BOM, duplicate keys, array root,
    // deep nesting past the WAF's recursion cap, payload-as-key.
    Vector { name: "POST-json-bom", content_type: "application/json" },
    Vector { name: "POST-json-dupkey", content_type: "application/json" },
    Vector { name: "POST-json-array", content_type: "application/json" },
    Vector { name: "POST-json-deeply-nested", content_type: "application/json" },
    Vector { name: "POST-json-key-as-payload", content_type: "application/json" },
    // JSON5 / hjson — `{ /* comment */ "key": "value" }`. Strict
    // JSON parsers refuse the comment and skip body inspection;
    // permissive backends (Node `json5`, RethinkDB, several Go/
    // Python parsers configured for trailing-comma/comment) strip
    // the comment and read the real key/value.
    Vector { name: "POST-json5-comment", content_type: "application/json" },

    // ──────── CONTENT-TYPE LYING / CHARSET ROUTING ────────────
    // The body is one shape; the declared Content-Type is
    // another. Lenient backends accept anyway; WAFs skip the
    // body-processor on the declared (wrong) shape.
    Vector { name: "POST-json-as-plain", content_type: "text/plain" },
    Vector { name: "POST-form-as-octet", content_type: "application/octet-stream" },
    Vector { name: "POST-json-utf7", content_type: "application/json; charset=utf-7" },
    Vector { name: "POST-form-utf7", content_type: "application/x-www-form-urlencoded; charset=utf-7" },
    Vector { name: "POST-text-xml", content_type: "text/xml" },
    Vector { name: "POST-yaml", content_type: "application/yaml" },
    Vector { name: "POST-cbor", content_type: "application/cbor" },
    // NDJSON / JSON-Lines — `application/x-ndjson` body, one JSON
    // doc per line. WAF processors that fan out ARGS from one
    // top-level JSON doc miss the multi-doc stream; backends that
    // accept NDJSON (logging endpoints, streaming APIs, ELK ingest)
    // parse each line independently.
    Vector { name: "POST-ndjson", content_type: "application/x-ndjson" },
    // JSON body declared as form — reverse of `POST-form-as-octet`.
    // The body is real JSON; the declared Content-Type is
    // `application/x-www-form-urlencoded`. WAFs route to the form
    // processor and find no `=`-separated pairs; lenient backends
    // sniff the body or are configured to accept JSON regardless.
    Vector { name: "POST-json-as-form", content_type: "application/x-www-form-urlencoded" },

    // ──────── METHOD-AXIS ────────────────────────────────────
    // WAF rule paths gated on REQUEST_METHOD for POST miss the
    // request entirely. PUT/PATCH/PUT-form ride the actual wire
    // method; method-override-* keeps POST on the request line
    // but signals the intended method via a header (Spring,
    // Rails, Express, Symfony all honour the header).
    Vector { name: "PUT-json", content_type: "application/json" },
    Vector { name: "PATCH-json", content_type: "application/json" },
    Vector { name: "PUT-form", content_type: "application/x-www-form-urlencoded" },
    Vector { name: "POST-method-override-GET", content_type: "application/x-www-form-urlencoded" },
    Vector { name: "POST-method-override-PUT", content_type: "application/x-www-form-urlencoded" },

    // ──────── MULTIPART VARIANTS ──────────────────────────────
    // The MIME parser is its own attack axis. Base64 CTE hides
    // the payload behind RFC 2045 §6.8 encoding; dup-boundary
    // splits the body across two boundary strings; filename=
    // routes the attack through the part metadata.
    Vector { name: "POST-multipart-b64", content_type: "multipart/form-data" },
    Vector { name: "POST-multipart-dupbound", content_type: "multipart/form-data" },
    Vector { name: "POST-multipart-filename", content_type: "multipart/form-data" },
    // Quoted-printable CTE per RFC 2045 §6.7 — sibling of the
    // base64 multipart vector. WAFs that decode neither QP nor
    // base64 see the encoded blob; backend MIME parsers decode
    // both. QP is rarer than base64 in WAF inspection pipelines
    // exactly because the encoding is so close to plain ASCII.
    Vector { name: "POST-multipart-qp", content_type: "multipart/form-data" },

    // ──────── HTTP PARAMETER POLLUTION (HPP) ──────────────────
    // Two values for one param, encoded so the WAF takes one
    // and the backend takes the other. `&` is the standard
    // separator; `;` is Tomcat/Jetty's parallel separator that
    // ModSec doesn't split on.
    Vector { name: "hpp", content_type: "" },
    Vector { name: "hpp-semicolon", content_type: "" },

    // ──────── COMPOUND (STACKED-AXIS) ────────────────────────
    // Combining two axes defeats WAFs that handle either
    // alone but not the AND of both. Pair a parse-confusion
    // with a compression layer (BOM+br), a charset routing
    // with a compression layer (utf-7+gz), or stack two
    // parse-confusions (dupkey+BOM).
    Vector { name: "POST-json-bom-br", content_type: "application/json" },
    Vector { name: "POST-json-utf7-gz", content_type: "application/json; charset=utf-7" },
    Vector { name: "POST-json-dupkey-bom", content_type: "application/json" },

    // ──────── URL POSITION ────────────────────────────────────
    // Payload lives in the URL itself — path segment or
    // header-driven proxy reverse-routing. WAFs scoped to
    // ARGS / REQUEST_URI miss either.
    Vector { name: "path-segment", content_type: "" },
    Vector { name: "x-original-url", content_type: "" },
    Vector { name: "x-rewrite-url", content_type: "" },

    // ──────── HEADER CARRIERS ────────────────────────────────
    // Less-inspected headers that backends still log, render,
    // or use for routing decisions. Cookie + variants, the
    // four well-known proxy-trust headers (XFF, Forwarded,
    // Referer, Origin), Range/From/Accept-Language for apps
    // that log them, Authorization-Basic for apps that log
    // decoded usernames.
    Vector { name: "cookie", content_type: "" },
    Vector { name: "cookie-hpp", content_type: "" },
    Vector { name: "x-forwarded-for", content_type: "" },
    Vector { name: "forwarded", content_type: "" },
    Vector { name: "referer", content_type: "" },
    Vector { name: "origin", content_type: "" },
    Vector { name: "range", content_type: "" },
    Vector { name: "from", content_type: "" },
    Vector { name: "accept-language", content_type: "" },
    Vector { name: "authorization-basic", content_type: "" },
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
mod tests;
