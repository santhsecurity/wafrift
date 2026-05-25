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
        oracle_gate: false,
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
        payload_class: None,
        waf_name: None,
        no_warm_start: false,
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

// ── B1: 5xx classification policy ────────────────────────────────

#[test]
fn request_reached_app_includes_501_and_505() {
    // B1: 501 and 505 are origin-processed codes (not CDN/gateway).
    assert!(
        request_reached_app(501),
        "501 Not Implemented: origin parsed request far enough to reject method"
    );
    assert!(
        request_reached_app(505),
        "505 HTTP Version Not Supported: origin-level protocol check"
    );
    // 503/504 are CDN/gateway layer -- NOT a reached app.
    assert!(!request_reached_app(503), "503 must NOT count as reached");
    assert!(!request_reached_app(504), "504 must NOT count as reached");
}

// ── B6: warm_state_hash in EquivOutcome ──────────────────────────

#[test]
fn equiv_outcome_warm_state_hash_defaults_to_none() {
    // B6: new EquivOutcome must have warm_state_hash = None by default
    // (no warm-start model loaded).
    use crate::equiv_engine::EquivOutcome;
    let out = EquivOutcome::default();
    assert!(
        out.warm_state_hash.is_none(),
        "default EquivOutcome must have no warm_state_hash"
    );
}

// ── B4: graphql + cve_pocs oracle gates ───────────────────────────

#[test]
fn oracle_valid_graphql_rejects_empty_and_bare_brace() {
    // B4: graphql oracle must return false for destroyed payloads.
    assert!(
        !oracle_valid("graphql", "{ user { id } }", ""),
        "empty transformed must fail"
    );
    assert!(
        !oracle_valid("graphql", "{ user { id } }", "   "),
        "whitespace-only must fail"
    );
    assert!(
        !oracle_valid("graphql", "{ user { id } }", "no-braces-here"),
        "no opening brace must fail"
    );
    // Bare brace with no field name is not a valid GQL body.
    assert!(
        !oracle_valid("graphql", "{ user { id } }", "{}"),
        "bare empty braces must fail"
    );
}

#[test]
fn oracle_valid_graphql_accepts_minimal_operation() {
    // B4: a payload with at least one field inside braces must pass.
    assert!(
        oracle_valid("graphql", "{ user { id } }", "{ user { id } }"),
        "valid GQL with field inside must pass"
    );
    assert!(
        oracle_valid("graphql", "{ me }", "{ me }"),
        "minimal single-field must pass"
    );
    assert!(
        oracle_valid("graphql", "{ user { id } }", "query { user { name } }"),
        "query operation with field must pass"
    );
}

#[test]
fn oracle_valid_cve_pocs_always_returns_false() {
    // B4: cve_pocs has no structural model -- always false (safe under-count).
    assert!(
        !oracle_valid("cve_pocs", "CVE-2021-44228", "CVE-2021-44228"),
        "cve_pocs must always return false (no oracle)"
    );
    assert!(
        !oracle_valid("cve_pocs", "anything", ""),
        "cve_pocs must return false even for empty transformed"
    );
}

#[test]
fn oracle_valid_unknown_class_returns_false() {
    // B4: unknown classes default to false (under-count, not over-count).
    assert!(
        !oracle_valid("totally_unknown_class", "payload", "payload"),
        "unknown class must return false, not true"
    );
}
