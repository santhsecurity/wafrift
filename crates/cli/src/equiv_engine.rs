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
use wafrift_oracle::cmdi::CmdiOracle;
use wafrift_oracle::ldap::LdapOracle;
use wafrift_oracle::path::PathOracle;
use wafrift_oracle::sql::{self as sql_oracle, DatabaseDialect};
use wafrift_oracle::ssrf::SsrfOracle;
use wafrift_oracle::ssti::SstiOracle;
use wafrift_oracle::traits::PayloadOracle;
use wafrift_oracle::xss::XssOracle;
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
pub fn request_reached_app(status: u16) -> bool {
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
pub fn verified_bypass(
    class: &str,
    original: &str,
    effective: &str,
    blocked: bool,
    status: u16,
) -> bool {
    !blocked && request_reached_app(status) && oracle_valid(class, original, effective)
}

/// True iff the variant retains the exploit semantics of the original
/// payload for `class` (per-class structural validity via the
/// corresponding `wafrift-oracle`). Falls back to `true` only for
/// classes with genuinely no oracle (`cve_pocs` is held-out data).
#[must_use]
pub fn oracle_valid(class: &str, original: &str, transformed: &str) -> bool {
    match class {
        "sql" => sql_oracle::is_valid_expression_injection(transformed, DatabaseDialect::Generic),
        "xss" => XssOracle.is_semantically_valid(original, transformed),
        "cmdi" => CmdiOracle.is_semantically_valid(original, transformed),
        "ssti" => SstiOracle.is_semantically_valid(original, transformed),
        "path" => PathOracle.is_semantically_valid(original, transformed),
        "ldap" => LdapOracle.is_semantically_valid(original, transformed),
        "ssrf" => SsrfOracle.is_semantically_valid(original, transformed),
        "nosql" => is_valid_nosql(original, transformed),
        "xxe" => is_valid_xxe(original, transformed),
        "log4shell" => is_valid_log4shell(original, transformed),
        _ => true,
    }
}

/// `NoSQL` validity: the variant must express the SAME MongoDB
/// operator-injection (operator + operand) as the original. Delegates
/// to the RFC-8259-grounded equivalence predicate (anti-rig: a marker
/// match alone — the old behaviour — let a mangled/broken payload
/// score as a bypass; `still_injects` rejects an operator/operand
/// swap).
#[must_use]
pub fn is_valid_nosql(original: &str, transformed: &str) -> bool {
    grammar::equiv::nosql::still_injects(original, transformed)
}

/// XXE validity: the variant must still make the parser fetch the SAME
/// external resource(s) as the original (external-id equivalence).
/// `still_exfils` rejects a target-URI swap — the marker-only check it
/// replaces did not.
#[must_use]
pub fn is_valid_xxe(original: &str, transformed: &str) -> bool {
    grammar::equiv::xxe::still_exfils(original, transformed)
}

/// `Log4Shell` validity: the variant must drive the SAME JNDI fetch
/// (protocol + authority + path) after Log4j lookup-collapse.
/// `still_executes` rejects a protocol/host swap — the substring check
/// it replaces did not.
#[must_use]
pub fn is_valid_log4shell(original: &str, transformed: &str) -> bool {
    grammar::equiv::log4shell::still_executes(original, transformed)
}

/// Attack class string for a grammar [`PayloadType`], or `None` when
/// the moat has no sound model for it (anti-rig: never guess).
#[must_use]
pub fn class_for_payload_type(pt: PayloadType) -> Option<&'static str> {
    let c = match pt {
        PayloadType::Sql => "sql",
        PayloadType::Xss => "xss",
        PayloadType::CommandInjection => "cmdi",
        PayloadType::PathTraversal => "path",
        PayloadType::TemplateInjection => "ssti",
        PayloadType::Ldap => "ldap",
        _ => return None,
    };
    grammar::equiv::supports_class(c).then_some(c)
}

// ───────────────────────── request builders ─────────────────────────

/// JSON-string-escape (control chars + `"` + `\`).
#[must_use]
pub fn json_escape(s: &str) -> String {
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

const MP_BOUNDARY: &str = "----wafriftEQUIVb0undary";

/// Translate an equivalence `DeliveryShape` into a concrete request
/// against the **httpbin-backed WAF testbed** (`/get`, `/post`,
/// `/anything/…`). Used by the corpus bench. Behaviour is pinned by
/// `bench_waf::tests::delivery_shapes_build_correct_requests` — do not
/// alter the shapes.
#[must_use]
pub fn build_request_for_delivery(
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
        D::MultipartField { name } => {
            let body = format!(
                "--{MP_BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{payload}\r\n--{MP_BOUNDARY}--\r\n"
            );
            let mut r = Request::post(format!("{b}/post"), body.into_bytes());
            r.add_header(
                "content-type",
                format!("multipart/form-data; boundary={MP_BOUNDARY}"),
            );
            r
        }
        D::MultipartFile {
            name,
            filename,
            part_ct,
        } => {
            let body = format!(
                "--{MP_BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\nContent-Type: {part_ct}\r\n\r\n{payload}\r\n--{MP_BOUNDARY}--\r\n"
            );
            let mut r = Request::post(format!("{b}/post"), body.into_bytes());
            r.add_header(
                "content-type",
                format!("multipart/form-data; boundary={MP_BOUNDARY}"),
            );
            r
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
pub fn build_live_request_for_delivery(
    target: &str,
    d: &grammar::equiv::DeliveryShape,
    payload: &str,
) -> Request {
    // Single source of truth: the joint (payload × delivery) algebra
    // lives on `DeliveryShape` in `wafrift-grammar` so scald, the
    // proxy and the CLI render delivery identically.
    d.to_request(target, payload)
}

/// Fire one `wafrift_types::Request` through the shared reqwest client.
/// Returns `(status, blocked, latency_ms)`. `blocked` is the SAME
/// `is_waf_block` signal the scan baseline uses.
pub async fn send(
    client: &reqwest::Client,
    req: &Request,
    timeout_secs: u64,
) -> Result<(u16, bool, f64), String> {
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
        builder = builder.header(k, v);
    }
    if let Some(body) = &req.body {
        builder = builder.body(body.clone());
    }
    builder = builder.timeout(std::time::Duration::from_secs(timeout_secs));
    let resp = builder.send().await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let body = resp.bytes().await.map_err(|e| e.to_string())?;
    let blocked = is_waf_block(status, &body);
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    Ok((status, blocked, elapsed_ms))
}

// ───────────────────────── B→C→A CEGIS loop ─────────────────────────

/// One verified bypass produced by the moat.
#[derive(Debug, Clone)]
pub struct EquivBypass {
    pub payload: String,
    pub delivery_label: &'static str,
    pub rules: Vec<&'static str>,
    pub status: u16,
    /// `"learn"` (Phase-C diverse probe) or `"cegis"` (Phase-A
    /// synthesized counterexample-guided probe).
    pub phase: &'static str,
}

/// Aggregate outcome of one moat run for one (class, payload).
#[derive(Debug, Clone, Default)]
pub struct EquivOutcome {
    /// Equivalence members actually sent.
    pub variants: usize,
    /// Requests fired (== variants; kept distinct for clarity).
    pub sends: usize,
    /// Slipped the WAF but failed an independent gate (NOT counted as
    /// a bypass — surfaced for honesty/triage).
    pub unverified_not_blocked: usize,
    /// Members that passed all three `verified_bypass` gates.
    pub bypasses: Vec<EquivBypass>,
    /// The per-WAF boundary model was refined and persisted.
    pub model_saved: bool,
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
pub async fn run_equiv_cegis<F>(
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
    let mut out = EquivOutcome::default();
    if !grammar::equiv::supports_class(class) {
        return out;
    }

    // FNV-1a of the stable id → deterministic per (target, payload).
    let mut case_seed: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in seed_src.bytes() {
        case_seed ^= u64::from(byte);
        case_seed = case_seed.wrapping_mul(0x0000_0100_0000_01b3);
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
        let (m, arm) = pool[i].clone();
        if out.variants > 0 && delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        }
        let req = build(&m.delivery, &m.payload);
        out.variants += 1;
        sends += 1;
        match send(client, &req, timeout_secs).await {
            Ok((status, blocked, _l)) => {
                samples.push((featurize(&m.payload, arm), blocked));
                if verified_bypass(class, payload, &m.payload, blocked, status) {
                    out.bypasses.push(EquivBypass {
                        payload: m.payload.clone(),
                        delivery_label: m.delivery.label(),
                        rules: m.rules.clone(),
                        status,
                        phase: "learn",
                    });
                } else if !blocked {
                    out.unverified_not_blocked += 1;
                }
                tried.insert((m.payload.clone(), arm));
            }
            Err(e) => eprintln!("warn: equiv learn send ({class}): {e}"),
        }
    }

    // Phase 2: CEGIS — synthesize, confirm, refit on counterexample.
    let mut model = prior
        .clone()
        .unwrap_or_else(|| WafModel::learn(&samples, 30));
    while sends < budget {
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
        match send(client, &req, timeout_secs).await {
            Ok((status, blocked, _l)) => {
                samples.push((featurize(&m.payload, arm), blocked));
                if verified_bypass(class, payload, &m.payload, blocked, status) {
                    out.bypasses.push(EquivBypass {
                        payload: m.payload.clone(),
                        delivery_label: m.delivery.label(),
                        rules: m.rules.clone(),
                        status,
                        phase: "cegis",
                    });
                } else if !blocked {
                    out.unverified_not_blocked += 1;
                }
                tried.insert((pp.clone(), aa));
                if blocked {
                    model = WafModel::learn(&samples, 30);
                }
            }
            Err(e) => eprintln!("warn: equiv cegis send ({class}): {e}"),
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
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use grammar::equiv::DeliveryShape as D;

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
}
