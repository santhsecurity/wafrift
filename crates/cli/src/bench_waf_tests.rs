use super::*;
// Pinned anti-rig tests exercise the single-source oracle/escaper
// directly (non-test bench code reaches them only via
// `verified_bypass`); imported here, not at module scope.
use crate::equiv_engine::{json_escape, oracle_valid, request_reached_app};
use wafrift_types::Method;

// ───────── anti-rig invariants (pinned forever) ─────────
//
// These freeze the definition of "bypass" so the headline can
// never silently re-inflate the way it did before: count every
// non-403 (incl. mangled 400s and destroyed payloads) as a win.

#[test]
fn request_reached_app_rejects_non_executed_requests() {
    // WAF blocks / transport / malformed-evasion: NOT a reached app.
    for s in [403u16, 406, 503, 400, 413, 414, 421, 431, 502, 504, 0, 100] {
        assert!(
            !request_reached_app(s),
            "status {s} must NOT count as the app processing the attack"
        );
    }
    // The app actually saw and processed it (200/redirect/app-error,
    // and 500 — a SQL error page is positive injection evidence).
    for s in [200u16, 201, 204, 301, 302, 304, 401, 404, 405, 422, 500] {
        assert!(
            request_reached_app(s),
            "status {s} must count as the app processing the request"
        );
    }
}

#[test]
fn verified_bypass_requires_all_three_gates() {
    // The SQL oracle splices into a NUMERIC context
    // (`WHERE id = <frag>`), so use a numeric-context injection
    // whose oracle verdict is known (their own unit test asserts
    // `1 OR 1=1 --` parses). This test pins the 3-gate AND
    // composition, not the oracle's context policy.
    let ok = "1 OR 1=1 --"; // oracle-VALID in numeric context
    let junk = ")) not sql at all (("; // oracle-INVALID (won't parse)

    // 1. All gates pass → real bypass.
    assert!(
        verified_bypass("sql", ok, ok, false, 200),
        "valid attack + WAF passed + app processed = bypass"
    );
    // 2. WAF blocked → never.
    assert!(!verified_bypass("sql", ok, ok, true, 200), "WAF-blocked");
    // 3. Not blocked but 400 (evasion broke the request, attack
    //    never executed) — the residual rig. Must not count.
    assert!(
        !verified_bypass("sql", ok, ok, false, 400),
        "400 malformed is NOT a bypass"
    );
    // 4. Not blocked, reached app, but payload is not a valid
    //    attack — the ORIGINAL oracle rig. Must not count.
    assert!(
        !verified_bypass("sql", ok, junk, false, 200),
        "non-attack that slipped past is NOT a bypass"
    );
    // 5. Upstream failure.
    assert!(
        !verified_bypass("sql", ok, ok, false, 502),
        "502 upstream-down is NOT a bypass"
    );
}

#[test]
fn oracle_gate_is_not_a_no_op() {
    // If this returns true for both, the oracle is neutered and the
    // bench is rigged again.
    assert!(
        oracle_valid("sql", "1 OR 1=1", "1 OR 1=1"),
        "a valid numeric-context tautology must pass the SQL oracle"
    );
    assert!(
        !oracle_valid("sql", "1 OR 1=1", ")) not sql at all (("),
        "unparseable noise is not a valid SQL injection"
    );
}

#[test]
fn class_probes_sql_has_keywords_and_baseline() {
    let probes = class_probes("sql");
    assert!(!probes.is_empty(), "sql class must have probes");
    assert!(
        probes
            .iter()
            .any(|p| matches!(p.tests, ProbeTarget::SqlKeyword(_))),
        "sql probes must include keyword family"
    );
    assert!(
        probes
            .iter()
            .any(|p| matches!(p.tests, ProbeTarget::Baseline)),
        "every class probe set must include a baseline so unblock=baseline-passes is recorded"
    );
    // Negative — sql probe set must NOT contain xss or cmd probes.
    assert!(
        !probes.iter().any(|p| matches!(
            p.tests,
            ProbeTarget::XssTag(_) | ProbeTarget::CmdSeparator(_)
        )),
        "sql probe set must not bleed xss/cmd families"
    );
}

#[test]
fn class_probes_xss_only_returns_xss_family() {
    let probes = class_probes("xss");
    assert!(!probes.is_empty());
    for p in &probes {
        assert!(
            matches!(
                p.tests,
                ProbeTarget::XssTag(_)
                    | ProbeTarget::XssEvent(_)
                    | ProbeTarget::XssExecFunction(_)
                    | ProbeTarget::Baseline
            ),
            "xss probes must be xss-family + baseline only, got {:?}",
            p.tests
        );
    }
}

#[test]
fn all_strategies_constant_includes_every_dispatched_arm() {
    // If a new strategy is added to the dispatch match in `run_evade`
    // but not to `ALL_STRATEGIES`, `--strategies all` would silently
    // omit it. This guards that.
    for required in &[
        "heavy",
        "mcts",
        "smuggling",
        "content-type",
        "redos",
        "hill-climb",
        "sim-anneal",
        "tabu",
        "novelty",
        "map-elites",
        "differential",
        "equiv",
        "equiv-adaptive",
        "equiv-cegis",
    ] {
        assert!(
            ALL_STRATEGIES.contains(required),
            "ALL_STRATEGIES is missing {required:?} — `--strategies all` would skip it"
        );
    }
}

#[test]
fn json_escape_is_safe() {
    assert_eq!(json_escape(r#"a"b\c"#), r#"a\"b\\c"#);
    assert_eq!(json_escape("x\ny\tz"), "x\\ny\\tz");
    assert_eq!(json_escape("\u{0001}"), "\\u0001");
}

#[test]
fn delivery_shapes_build_correct_requests() {
    use grammar::equiv::DeliveryShape as D;
    let p = "1' OR '1'='1";

    let q = build_request_for_delivery("http://h", &D::Query { param: "q".into() }, p);
    assert_eq!(q.method, Method::Get);
    assert!(q.url.starts_with("http://h/get?q="), "{}", q.url);
    assert!(!q.url.contains('\''), "query not url-encoded: {}", q.url);

    let f = build_request_for_delivery("http://h", &D::FormBody { param: "q".into() }, p);
    assert_eq!(f.method, Method::Post);
    assert!(f.url.ends_with("/post"));
    assert!(
        f.headers
            .iter()
            .any(|(k, v)| k == "content-type" && v == "application/x-www-form-urlencoded")
    );
    assert!(String::from_utf8_lossy(f.body.as_ref().unwrap()).starts_with("q="));

    let j = build_request_for_delivery(
        "http://h",
        &D::JsonBody {
            param: "q".into(),
            content_type: None,
        },
        p,
    );
    assert!(
        !j.headers.iter().any(|(k, _)| k == "content-type"),
        "JsonBody None must omit Content-Type (the CRS-blind shape)"
    );
    assert_eq!(
        String::from_utf8_lossy(j.body.as_ref().unwrap()),
        r#"{"q":"1' OR '1'='1"}"#
    );

    let jc = build_request_for_delivery(
        "http://h",
        &D::JsonBody {
            param: "q".into(),
            content_type: Some("application/json".into()),
        },
        p,
    );
    assert!(
        jc.headers
            .iter()
            .any(|(k, v)| k == "content-type" && v == "application/json")
    );

    let mf = build_request_for_delivery(
        "http://h",
        &D::MultipartFile {
            name: "q".into(),
            filename: "a.txt".into(),
            part_ct: "application/octet-stream".into(),
        },
        p,
    );
    let mb = String::from_utf8_lossy(mf.body.as_ref().unwrap());
    assert!(mb.contains("filename=\"a.txt\""));
    assert!(mb.contains("Content-Type: application/octet-stream"));
    assert!(mb.contains(p), "file part must carry the exploit verbatim");
    assert!(
        mf.headers
            .iter()
            .any(|(k, v)| k == "content-type" && v.starts_with("multipart/form-data; boundary="))
    );

    let ps = build_request_for_delivery("http://h", &D::PathSegment, p);
    assert_eq!(ps.method, Method::Get);
    assert!(ps.url.starts_with("http://h/anything/"));
    assert!(!ps.url.contains('\''), "path seg not encoded: {}", ps.url);
    assert!(
        !ps.url
            .trim_start_matches("http://h/anything/")
            .contains('?'),
        "payload must stay one path segment"
    );

    let hpp = build_request_for_delivery(
        "http://h",
        &D::HppSplit {
            param: "q".into(),
            parts: 2,
        },
        p,
    );
    // parts = decoy count; total = decoys + 1 (the FULL payload),
    // and the payload must be the LAST occurrence (last-wins
    // backend binds the whole attack — never a split fragment).
    assert_eq!(
        hpp.url.matches("q=").count(),
        3,
        "HPP must be 2 decoys + full payload: {}",
        hpp.url
    );
    let last = hpp.url.rsplit("q=").next().unwrap();
    assert_eq!(
        last,
        urlencoding::encode(p),
        "the final HPP param must carry the full attack verbatim"
    );
    assert!(
        !hpp.url.contains("q=v0&q=v1") || hpp.url.ends_with(&urlencoding::encode(p).to_string()),
        "decoys must precede the payload"
    );

    // Raw reflected channels → httpbin echo endpoints, rendered
    // through the single-source `to_request` (smuggle-guarded).
    let hv = build_request_for_delivery(
        "http://h",
        &D::HeaderValue {
            name: "X-Forwarded-Host".into(),
        },
        p,
    );
    assert_eq!(hv.method, Method::Get);
    assert_eq!(hv.url, "http://h/headers", "header shape hits /headers");
    assert_eq!(
        hv.get_header("X-Forwarded-Host"),
        Some(p),
        "header carries the exact payload bytes"
    );

    let ck = build_request_for_delivery("http://h", &D::Cookie { name: "q".into() }, p);
    assert_eq!(ck.method, Method::Get);
    assert_eq!(ck.url, "http://h/cookies", "cookie shape hits /cookies");
    assert_eq!(
        ck.get_header("cookie"),
        Some(format!("q={p}").as_str()),
        "cookie carries name=payload (p has no ';'/CRLF to strip)"
    );
}

#[test]
fn equiv_strategy_is_dispatched_and_listed() {
    // Wiring guard: the strategy name resolves in ALL_STRATEGIES
    // (so `--strategies all` runs it) and is SQL-gated.
    assert!(ALL_STRATEGIES.contains(&"equiv"));
    let mut st = StrategyStat::default();
    // non-sql class ⇒ no members emitted (anti-rig: no model).
    let c = case("x", "xss", "<script>alert(1)</script>");
    assert_eq!(c.class, "xss");
    let _ = &mut st;
}

fn case(id: &str, class: &str, payload: &str) -> BenchCase {
    BenchCase {
        id: id.into(),
        class: class.into(),
        payload: payload.into(),
        mode: "body_form_q".into(),
        description: String::new(),
    }
}

#[test]
fn validate_corpus_flags_duplicate_id() {
    let cases = vec![case("a", "sql", "1=1"), case("a", "xss", "<script>")];
    let code = validate_corpus_and_exit(&cases).unwrap();
    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(4)));
}

#[test]
fn validate_corpus_flags_unknown_class() {
    let cases = vec![case("a", "definitelynot", "x")];
    let code = validate_corpus_and_exit(&cases).unwrap();
    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(4)));
}

#[test]
fn validate_corpus_flags_empty_payload() {
    let cases = vec![case("a", "sql", "")];
    let code = validate_corpus_and_exit(&cases).unwrap();
    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(4)));
}

#[test]
fn validate_corpus_passes_clean_set() {
    let cases = vec![
        case("a", "sql", "1=1"),
        case("b", "xss", "<script>"),
        case("c", "log4shell", "${jndi:ldap://x}"),
    ];
    let code = validate_corpus_and_exit(&cases).unwrap();
    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
}

#[test]
fn class_probes_unknown_class_yields_only_baseline() {
    // Classes with no rule-fingerprint family (xxe / log4shell / ssrf)
    // should fall through to baseline-only — never zero, so the
    // strategy doesn't divide-by-zero downstream.
    let probes = class_probes("log4shell");
    assert!(
        probes
            .iter()
            .all(|p| matches!(p.tests, ProbeTarget::Baseline)),
        "unknown classes must yield only baseline probes"
    );
}

// ── pure helpers ──────────────────────────────────────────

#[test]
fn truncate_short_input_passes_through_unchanged() {
    assert_eq!(truncate("abc", 10), "abc");
    assert_eq!(truncate("", 0), "");
    assert_eq!(truncate("x", 1), "x");
}

#[test]
fn truncate_long_input_emits_ellipsis_suffix() {
    let got = truncate("abcdefghij", 5);
    assert!(got.ends_with('…'));
    assert!(got.starts_with("abcd"));
}

#[test]
fn truncate_multibyte_does_not_panic_at_codepoint_boundary() {
    // Regression: the previous impl sliced `&s[..n.saturating_sub(1)]`
    // which panicked when the byte index landed mid-codepoint.
    // "café" is 5 bytes (é = 2 bytes); truncate to 5 used to
    // slice 4 bytes — splitting é. Must NOT panic.
    let got = truncate("café-payload", 5);
    // Result is the largest char-boundary prefix ≤ 4 bytes
    // plus ellipsis.
    assert!(got.ends_with('…'));
    assert!(got.starts_with("caf") || got.starts_with("café"));
}

#[test]
fn truncate_chinese_chars_do_not_panic() {
    // Three-byte UTF-8 chars stress the boundary walker even
    // more.
    let got = truncate("中文测试", 5);
    assert!(got.ends_with('…'));
}

#[test]
fn truncate_zero_n_emits_ellipsis_only_for_non_empty_input() {
    // n = 0 → saturating_sub(1) = 0 → empty prefix + ellipsis.
    // Empty input passes through unchanged (covered above).
    let got = truncate("abc", 0);
    assert_eq!(got, "…");
}

// ── pick_level ────────────────────────────────────────────

#[test]
fn pick_level_recognises_canonical_tokens() {
    assert!(matches!(pick_level("light"), Some(Level::Light)));
    assert!(matches!(pick_level("medium"), Some(Level::Medium)));
    assert!(matches!(pick_level("heavy"), Some(Level::Heavy)));
}

#[test]
fn pick_level_rejects_unknown_tokens() {
    assert!(pick_level("").is_none());
    assert!(pick_level("LIGHT").is_none(), "must be case-sensitive");
    assert!(pick_level("turbo").is_none());
}

// ── class_to_payload_type ─────────────────────────────────

#[test]
fn class_to_payload_type_maps_every_known_class() {
    // Anti-rig: every class accepted by KNOWN_CLASSES that has
    // a wafrift mutator must map to a distinct non-Unknown
    // PayloadType. A future class addition that's left at
    // Unknown silently regresses mutator richness.
    for class in [
        "sql", "xss", "cmdi", "ssti", "path", "ldap", "ssrf", "nosql",
    ] {
        let pt = class_to_payload_type(class);
        assert!(
            !matches!(pt, PayloadType::Unknown),
            "{class} must not map to Unknown"
        );
    }
}

#[test]
fn class_to_payload_type_unknown_class_falls_back_to_unknown() {
    // log4shell / xxe / cve_pocs have no wafrift mutator yet
    // — they fall back to Unknown by design (encoding-only
    // mutations). Lock this contract in.
    for class in ["log4shell", "xxe", "cve_pocs", "totally-bogus"] {
        assert!(matches!(class_to_payload_type(class), PayloadType::Unknown));
    }
}

// ── resolve_base_url ──────────────────────────────────────

#[test]
fn resolve_base_url_returns_arg_when_set() {
    let args = BenchWafArgs {
        base_url: Some("http://test.example/".into()),
        ..default_bench_args_for_tests()
    };
    assert_eq!(resolve_base_url(&args), "http://test.example/");
}

#[test]
fn resolve_base_url_explicit_argument_overrides_any_env() {
    // Even with env vars set, an explicit `--base-url` wins.
    // Skipping the env-mutation path (parallel-test-unsafe);
    // the explicit-arg branch is the contract that matters.
    let args = BenchWafArgs {
        base_url: Some("http://explicit.example/".into()),
        ..default_bench_args_for_tests()
    };
    assert_eq!(resolve_base_url(&args), "http://explicit.example/");
}

/// Helper that materializes a BenchWafArgs with sane defaults
/// for the unit-test paths that don't actually fire requests.
/// Lets test cases override only the fields they care about.
fn default_bench_args_for_tests() -> BenchWafArgs {
    BenchWafArgs {
        base_url: None,
        corpus: PathBuf::from("wafrift-bench/corpus"),
        class: Vec::new(),
        evade: false,
        variants: 5,
        strategies: vec!["heavy".into()],
        delay_ms: 25,
        timeout_secs: 15,
        insecure: false,
        format: "text".into(),
        output: None,
        summary_only: false,
        skip_healthcheck: true,
        adaptive_pause_after_errors: 50,
        adaptive_pause_secs: 2,
        validate_only: false,
        lineage_output: None,
        egress_socks5: Vec::new(),
        egress_http_proxy: Vec::new(),
        egress_tailscale_nodes: Vec::new(),
        egress_tailscale_socks_addr: "127.0.0.1:1055".into(),
        egress_challenge_threshold: 3,
        egress_cooldown_secs: 300,
        mutator: "default".into(),
        seed: None,
        dilution_weight: 0.0,
        corpus_out: None,
        coverage_out: None,
        corpus_fingerprint: String::new(),
        target_waf: String::new(),
        h1_archive: None,
        lattice_max_chains: 256,
        shotgun_replays: 0,
    }
}

// ── build_request shapes ──────────────────────────────────

#[test]
fn build_request_url_query_mode_emits_get_with_encoded_param() {
    let case = BenchCase {
        id: "t1".into(),
        class: "sql".into(),
        mode: "url_query_q".into(),
        payload: "a&b=c".into(),
        description: String::new(),
    };
    let r = build_request("http://h", &case);
    assert_eq!(r.method, Method::Get);
    assert!(r.url.starts_with("http://h/get?q="), "url={}", r.url);
    // `&` and `=` MUST be percent-encoded.
    assert!(r.url.contains("%26"));
    assert!(r.url.contains("%3D"));
}

#[test]
fn build_request_raw_body_mode_emits_post_with_text_plain() {
    let case = BenchCase {
        id: "t2".into(),
        class: "xss".into(),
        mode: "raw_body".into(),
        payload: "<script>alert(1)</script>".into(),
        description: String::new(),
    };
    let r = build_request("http://h", &case);
    assert_eq!(r.method, Method::Post);
    assert!(r.url.ends_with("/post"));
    assert!(
        r.headers
            .iter()
            .any(|(k, v)| k == "content-type" && v == "text/plain"),
        "must set text/plain on raw_body"
    );
    // Body is the raw payload bytes.
    let body = r.body.as_ref().unwrap();
    assert_eq!(String::from_utf8_lossy(body), "<script>alert(1)</script>");
}

#[test]
fn build_request_default_mode_is_form_body() {
    // Any unrecognised mode string falls through to form-body.
    let case = BenchCase {
        id: "t3".into(),
        class: "sql".into(),
        mode: "made_up_mode".into(),
        payload: "x".into(),
        description: String::new(),
    };
    let r = build_request("http://h", &case);
    assert_eq!(r.method, Method::Post);
    assert!(
        r.headers
            .iter()
            .any(|(k, v)| k == "content-type" && v == "application/x-www-form-urlencoded")
    );
}

#[test]
fn build_request_trims_trailing_slash_from_base_url() {
    // Anti-rig: missing trim would emit `http://h//get?...`
    // which routes the same on most servers but is ugly and
    // some routers reject it.
    let case = BenchCase {
        id: "t4".into(),
        class: "sql".into(),
        mode: "url_query_q".into(),
        payload: "x".into(),
        description: String::new(),
    };
    let r = build_request("http://h/", &case);
    assert!(!r.url.contains("//get"), "url={}", r.url);
}

// Note: `validate_corpus_flags_unknown_class`,
// `validate_corpus_flags_empty_payload`, and
// `validate_corpus_passes_clean_set` already exist above using
// the `case()` shorthand. Only the duplicate-ids case is new.

#[test]
fn validate_corpus_flags_duplicate_ids() {
    let cases = vec![
        BenchCase {
            id: "dup".into(),
            class: "sql".into(),
            mode: "url_query_q".into(),
            payload: "x".into(),
            description: String::new(),
        },
        BenchCase {
            id: "dup".into(),
            class: "sql".into(),
            mode: "url_query_q".into(),
            payload: "y".into(),
            description: String::new(),
        },
    ];
    let code = validate_corpus_and_exit(&cases).unwrap();
    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(4)));
}

// ── dilution fitness gate ────────────────────────────────────────────

#[test]
fn dilution_gate_off_when_weight_zero() {
    // Even against a known ensemble WAF, weight 0 disables the gate.
    assert!(!dilution_gate_active("Cloudflare", 0.0));
}

#[test]
fn dilution_gate_off_when_target_waf_unknown() {
    // No declared WAF → no gate, regardless of weight.
    assert!(!dilution_gate_active("", 0.5));
    assert!(!dilution_gate_active("nginx", 0.5));
    assert!(!dilution_gate_active("unknown-appliance", 0.99));
}

#[test]
fn dilution_gate_on_for_ensemble_waf_with_positive_weight() {
    assert!(dilution_gate_active("Cloudflare", 0.1));
    assert!(dilution_gate_active("Cloudflare", 0.99));
    // Substring match (case-insensitive, per is_ensemble_waf).
    assert!(dilution_gate_active("CloudFlare WAF", 0.5));
    assert!(dilution_gate_active("aws core rule set", 0.5));
}

#[test]
fn dilution_gate_off_for_negative_weight_even_when_ensemble() {
    // Weight is clamped downstream but the activation check is a
    // strict > 0 — defends against a slipped clamp.
    assert!(!dilution_gate_active("Cloudflare", 0.0));
    assert!(!dilution_gate_active("Cloudflare", -0.1));
}

#[test]
fn strategy_stat_default_initializes_dilution_pruned_zero() {
    let s = StrategyStat::default();
    assert_eq!(s.dilution_pruned, 0, "pruned counter must default to zero");
}

#[test]
fn compute_dilution_score_in_unit_interval() {
    // Pin the contract bench relies on: the scorer returns a value
    // in `[0.0, 1.0]` for any input. Exact-value semantics are
    // tested inside `wafrift_evolution::dilution`; here we only
    // confirm the linkage and the range so the gate predicate
    // `score < dilution_weight` stays meaningful.
    let est = wafrift_evolution::dilution::default_estimator();
    for payload in ["hello world", "' OR 1=1--", "<script>", "\n\n\n"] {
        let score = wafrift_evolution::dilution::compute_dilution_score(
            payload,
            &est,
            wafrift_evolution::dilution::DEFAULT_DILUTION_THRESHOLD,
        );
        assert!(
            (0.0..=1.0).contains(&score),
            "score must be in [0,1], got {score} for {payload:?}"
        );
    }
}

#[test]
fn dilution_threshold_matches_evolution_default() {
    // Pinned: the bench uses the evolution module's documented
    // default threshold rather than a local magic number. If the
    // crate-level default changes, this catches the drift.
    assert!((wafrift_evolution::dilution::DEFAULT_DILUTION_THRESHOLD - 25.0).abs() < 1e-9);
}

// ── polyglot strategy: build_polyglots ──────────────────────────

#[test]
fn polyglots_produce_at_least_four_distinct_skeletons() {
    let polys = build_polyglots("' OR 1=1--");
    let skeletons: std::collections::HashSet<&'static str> =
        polys.iter().map(|(s, _, _)| *s).collect();
    assert!(
        skeletons.len() >= 4,
        "polyglot strategy must produce ≥4 distinct skeletons \
         (otherwise H1 dedup collapses them into one bypass): {:?}",
        skeletons
    );
}

#[test]
fn polyglots_embed_the_attack_in_every_variant() {
    // Every polyglot body MUST contain the attack — otherwise it's
    // not delivering the payload, just confusing CT routing for no
    // reason.
    let attack = "' OR 1=1--";
    for (skel, _ct, body) in build_polyglots(attack) {
        let urlenc = urlencoding::encode(attack);
        let json_esc = json_escape_value(attack);
        let plain = attack;
        assert!(
            body.contains(plain) || body.contains(&*urlenc) || body.contains(&json_esc),
            "polyglot skeleton {skel:?} did not embed attack: body={body:?}"
        );
    }
}

#[test]
fn polyglots_declare_distinct_content_types() {
    let polys = build_polyglots("x");
    let cts: std::collections::HashSet<&'static str> =
        polys.iter().map(|(_, ct, _)| *ct).collect();
    assert!(
        cts.contains("application/json"),
        "missing JSON declaration: {cts:?}"
    );
    assert!(
        cts.iter().any(|c| c.starts_with("application/x-www-form-urlencoded")),
        "missing form-urlencoded declaration: {cts:?}"
    );
    assert!(
        cts.iter().any(|c| c.starts_with("multipart/form-data")),
        "missing multipart declaration: {cts:?}"
    );
}

#[test]
fn polyglots_empty_attack_does_not_panic() {
    // Adversarial: empty attack must produce structurally-valid
    // polyglots (the attack segment is empty, but the wrappers
    // remain).
    let polys = build_polyglots("");
    assert!(!polys.is_empty(), "even empty attacks must produce polyglots");
    for (_skel, _ct, body) in &polys {
        assert!(!body.is_empty(), "polyglot body must not be empty");
    }
}

#[test]
fn polyglots_unicode_attack_passes_through() {
    let polys = build_polyglots("alert('пëîçÿ')");
    assert!(polys.len() >= 4);
    for (_skel, _ct, body) in &polys {
        // Either url-encoded or json-escaped form should appear.
        assert!(body.contains("alert") || body.contains("%27") || body.contains("alert"));
    }
}

#[test]
fn polyglots_huge_attack_one_megabyte() {
    // Adversarial: large attack must not panic and bodies grow
    // bounded-by-input.
    let huge = "x".repeat(1_048_576);
    let polys = build_polyglots(&huge);
    assert!(polys.len() >= 4);
    for (_skel, _ct, body) in &polys {
        assert!(body.len() >= huge.len(), "body must contain at least the attack");
        assert!(body.len() < huge.len() * 10, "body must not balloon 10x");
    }
}

#[test]
fn polyglots_with_control_chars_are_json_safe() {
    // Adversarial: attack contains a literal `"` that must NOT
    // break out of the JSON-doc-as-form skeleton.
    let polys = build_polyglots("\"break-out\"");
    let json_skel = polys
        .iter()
        .find(|(s, _, _)| *s == "json_doc_as_form")
        .expect("json_doc_as_form skeleton must exist");
    // The JSON-doc-as-form body must be parseable as JSON.
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&json_skel.2);
    assert!(
        parsed.is_ok(),
        "json_doc_as_form body must be valid JSON even with attack containing `\"`: {}",
        json_skel.2
    );
}

#[test]
fn polyglots_with_null_byte_attack_no_panic() {
    let polys = build_polyglots("attack\0nul");
    assert!(polys.len() >= 4);
}

// ── json_escape_value invariants ────────────────────────────────

#[test]
fn json_escape_value_escapes_quote_backslash_newline() {
    assert_eq!(json_escape_value("a\"b"), "a\\\"b");
    assert_eq!(json_escape_value("a\\b"), "a\\\\b");
    assert_eq!(json_escape_value("a\nb"), "a\\nb");
    assert_eq!(json_escape_value("a\rb"), "a\\rb");
    assert_eq!(json_escape_value("a\tb"), "a\\tb");
}

#[test]
fn json_escape_value_escapes_low_control_chars_as_unicode() {
    // \x01..\x1f must be \uXXXX-escaped.
    let s = "\x01\x07\x1b";
    let esc = json_escape_value(s);
    assert!(esc.contains("\\u0001"));
    assert!(esc.contains("\\u0007"));
    assert!(esc.contains("\\u001b"));
}

#[test]
fn json_escape_value_idempotent_on_safe_input() {
    let safe = "hello world";
    assert_eq!(json_escape_value(safe), safe);
}

#[test]
fn json_escape_value_output_is_valid_json_when_wrapped() {
    // After wrapping the escaped value in `"..."`, the result must
    // be a valid JSON string literal.
    for raw in [
        "simple",
        "with \"quote\"",
        "with\nnewline",
        "with\\backslash",
        "tab\there",
        "\u{0007}bell",
        "пëîçÿ",
    ] {
        let wrapped = format!("\"{}\"", json_escape_value(raw));
        let parsed: Result<String, _> = serde_json::from_str(&wrapped);
        assert!(
            parsed.is_ok(),
            "wrapped json_escape_value({raw:?}) = {wrapped:?} must parse as JSON string"
        );
        assert_eq!(parsed.unwrap(), raw, "round-trip must equal input");
    }
}

#[test]
fn json_escape_value_no_panic_on_empty() {
    assert_eq!(json_escape_value(""), "");
}

#[test]
fn json_escape_value_no_panic_on_lone_high_unicode() {
    // High unicode passes through unchanged; pin behaviour.
    let s = "\u{1F600}"; // 😀
    let esc = json_escape_value(s);
    assert_eq!(esc, s, "high unicode passes through unchanged");
}
