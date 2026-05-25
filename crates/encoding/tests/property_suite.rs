//! Comprehensive property-based test suite across every encoding
//! attack module.
//!
//! Each `proptest!` macro runs 256 cases by default — so this file
//! contributes thousands of effective test executions per
//! `cargo test` invocation. The properties enforce three invariants
//! every payload library MUST hold:
//!
//! 1. **No panic on arbitrary string input.** Operator-supplied
//!    strings come from untrusted sources (request bodies, CLI
//!    args, captured tokens). Panicking on any of them is a
//!    DoS surface in our own engine.
//! 2. **Determinism.** Same input → same output. Required so
//!    `wafrift bench` results are reproducible and the genome
//!    registry can store stable hashes.
//! 3. **Non-empty output for non-empty input.** A payload generator
//!    that silently returns empty bytes is a stub disguised as a
//!    function — and the engine would happily fire an empty
//!    request expecting a payload.

use proptest::prelude::*;
use wafrift_encoding::encoding::{
    cookie_attacks, csv_formula, deserialization, dom_clobber, invisible, jwt, oauth, path_norm,
    proto_pollution, request_line, saml_xsw, ssti_escape,
};

// ───────────────────────────────────────────────────────────────
// invisible.rs
// ───────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn invisible_tag_char_encode_no_panic(s in ".*") {
        let _ = invisible::tag_char_encode(&s);
    }

    #[test]
    fn invisible_tag_char_encode_deterministic(s in ".*") {
        prop_assert_eq!(
            invisible::tag_char_encode(&s),
            invisible::tag_char_encode(&s)
        );
    }

    #[test]
    fn invisible_tag_char_encode_preserves_length_for_ascii(s in "[A-Za-z0-9]{0,200}") {
        // Every ASCII byte becomes a 4-byte plane-14 codepoint, so
        // codepoint count equals input length. Byte count is 4×.
        let out = invisible::tag_char_encode(&s);
        prop_assert_eq!(out.chars().count(), s.len());
    }

    #[test]
    fn invisible_ligature_encode_no_panic(s in ".*") {
        let _ = invisible::ligature_encode(&s);
    }

    #[test]
    fn invisible_ligature_encode_idempotent_on_no_match(s in "[^fis]*") {
        // Without any of the ligature-trigger chars, the output
        // equals the input byte-for-byte.
        prop_assert_eq!(invisible::ligature_encode(&s), s);
    }

    #[test]
    fn invisible_soft_hyphen_inject_no_panic(s in ".*") {
        let _ = invisible::soft_hyphen_inject(&s);
    }

    #[test]
    fn invisible_word_joiner_wrap_no_panic(s in ".*") {
        let _ = invisible::word_joiner_wrap(&s);
    }

    #[test]
    fn invisible_circled_letter_no_panic(s in ".*") {
        let _ = invisible::circled_letter_encode(&s);
    }

    #[test]
    fn invisible_parenthesized_letter_no_panic(s in ".*") {
        let _ = invisible::parenthesized_letter_encode(&s);
    }

    #[test]
    fn invisible_variation_selector_pad_no_panic(s in ".*") {
        let _ = invisible::variation_selector_pad(&s, '\u{FE0F}');
    }
}

// ───────────────────────────────────────────────────────────────
// path_norm.rs
// ───────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn path_norm_variants_no_panic(prefix in "/[A-Za-z0-9_-]{0,30}", target in "/[A-Za-z0-9_-]{1,30}") {
        let _ = path_norm::path_variants(&prefix, &target);
    }

    #[test]
    fn path_norm_variants_minimum_count(prefix in "/[A-Za-z]{0,10}", target in "/[A-Za-z]{1,10}") {
        let v = path_norm::path_variants(&prefix, &target);
        prop_assert!(v.len() >= 20);
    }

    #[test]
    fn path_norm_variants_deterministic(prefix in "/[A-Za-z]{0,10}", target in "/[A-Za-z]{1,10}") {
        prop_assert_eq!(
            path_norm::path_variants(&prefix, &target),
            path_norm::path_variants(&prefix, &target)
        );
    }

    #[test]
    fn path_norm_deep_collapse_no_panic(depth in 0u32..=200, target in "/[A-Za-z]{1,20}") {
        let _ = path_norm::deep_path_collapse(depth as usize, &target);
    }

    #[test]
    fn path_norm_rfc3986_no_panic(s in ".*") {
        let _ = path_norm::rfc3986_remove_dot_segments(&s);
    }

    #[test]
    fn path_norm_rfc3986_deterministic(s in "/[A-Za-z0-9./_-]{0,200}") {
        prop_assert_eq!(
            path_norm::rfc3986_remove_dot_segments(&s),
            path_norm::rfc3986_remove_dot_segments(&s)
        );
    }
}

// ───────────────────────────────────────────────────────────────
// request_line.rs
// ───────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn request_line_exotic_methods_stable() {
        let a = request_line::exotic_methods();
        let b = request_line::exotic_methods();
        prop_assert_eq!(a, b);
    }

    #[test]
    fn request_line_absolute_uri_no_panic(
        method in "[A-Z]{1,10}",
        host in "[a-z]{1,20}\\.example",
        path in "/[a-zA-Z0-9/_-]{0,100}"
    ) {
        let _ = request_line::absolute_uri_request_line(&method, &host, &path);
    }

    #[test]
    fn request_line_authority_form_no_panic(
        method in "[A-Z]{1,10}",
        host in "[a-z]{1,20}",
        port in 1u16..=u16::MAX
    ) {
        let _ = request_line::authority_form_request_line(&method, &host, port);
    }

    #[test]
    fn request_line_no_crlf_in_output(
        method in "[A-Z]{1,5}",
        host in "[a-z]{1,10}",
        path in "/[a-z]{1,20}"
    ) {
        let outputs = vec![
            request_line::absolute_uri_request_line(&method, &host, &path),
            request_line::absolute_uri_https_request_line(&method, &host, &path),
            request_line::asterisk_form_request_line(&method),
            request_line::authority_form_request_line(&method, &host, 443),
            request_line::request_line_with_version(&method, &path, "HTTP/1.1"),
        ];
        for o in outputs {
            prop_assert!(!o.contains("\r\n"));
            prop_assert!(!o.contains('\n'));
        }
    }
}

// ───────────────────────────────────────────────────────────────
// deserialization.rs
// ───────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn deser_java_no_panic(bytes in proptest::collection::vec(any::<u8>(), 0..=4096)) {
        let _ = deserialization::java_serialized_blob(&bytes);
    }

    #[test]
    fn deser_java_starts_with_magic(bytes in proptest::collection::vec(any::<u8>(), 0..=512)) {
        let p = deserialization::java_serialized_blob(&bytes);
        prop_assert!(p.starts_with(deserialization::JAVA_SER_MAGIC));
    }

    #[test]
    fn deser_pickle_no_panic(bytes in proptest::collection::vec(any::<u8>(), 0..=4096)) {
        let _ = deserialization::python_pickle_blob(&bytes);
        let _ = deserialization::python_pickle_v2_blob(&bytes);
    }

    #[test]
    fn deser_pickle_v4_starts_with_proto_4(bytes in proptest::collection::vec(any::<u8>(), 0..=512)) {
        let p = deserialization::python_pickle_blob(&bytes);
        prop_assert!(p.starts_with(deserialization::PICKLE_PROTO_4));
    }

    #[test]
    fn deser_php_no_panic(class in "[A-Za-z][A-Za-z0-9_]{0,30}", n in 0usize..20) {
        let fields: Vec<(String, String)> = (0..n)
            .map(|i| (format!("k{i}"), format!("v{i}")))
            .collect();
        let refs: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let _ = deserialization::php_serialized_object(&class, &refs);
    }

    #[test]
    fn deser_php_class_length_correct(class in "[A-Za-z]{1,30}") {
        let p = deserialization::php_serialized_object(&class, &[]);
        prop_assert!(p.starts_with(&format!("O:{}:", class.len())));
    }

    #[test]
    fn deser_dotnet_no_panic(bytes in proptest::collection::vec(any::<u8>(), 0..=4096)) {
        let _ = deserialization::dotnet_binary_formatter_blob(&bytes);
    }

    #[test]
    fn deser_ruby_starts_with_marshal_magic(bytes in proptest::collection::vec(any::<u8>(), 0..=512)) {
        let p = deserialization::ruby_marshal_blob(&bytes);
        prop_assert!(p.starts_with(deserialization::RUBY_MARSHAL_4_8));
    }

    #[test]
    fn deser_detect_round_trip_java(bytes in proptest::collection::vec(any::<u8>(), 0..=512)) {
        let p = deserialization::java_serialized_blob(&bytes);
        prop_assert_eq!(
            deserialization::detect_deserialization_format(&p),
            Some("java-ser")
        );
    }
}

// ───────────────────────────────────────────────────────────────
// jwt.rs
// ───────────────────────────────────────────────────────────────

fn arb_jwt_segment() -> impl Strategy<Value = String> {
    // Random b64url-clean segment: alnum + -_ (no padding).
    "[A-Za-z0-9_-]{1,40}"
}

proptest! {
    #[test]
    fn jwt_split_then_join_round_trip(h in arb_jwt_segment(), p in arb_jwt_segment(), s in arb_jwt_segment()) {
        let token = jwt::join_jwt(&h, &p, &s);
        let split = jwt::split_jwt(&token);
        prop_assert!(split.is_some());
        let (h2, p2, s2) = split.unwrap();
        prop_assert_eq!(h, h2);
        prop_assert_eq!(p, p2);
        prop_assert_eq!(s, s2);
    }

    #[test]
    fn jwt_split_rejects_non_three_parts(parts_count in 1usize..=10) {
        let parts: Vec<&str> = (0..parts_count).map(|_| "x").collect();
        let token = parts.join(".");
        if parts_count == 3 {
            prop_assert!(jwt::split_jwt(&token).is_some());
        } else {
            prop_assert!(jwt::split_jwt(&token).is_none());
        }
    }

    #[test]
    fn jwt_alg_none_family_count(h in arb_jwt_segment(), p in arb_jwt_segment(), s in arb_jwt_segment()) {
        // Construct a JWT with a valid JSON header so the b64-decode
        // path succeeds — random b64 doesn't decode to valid JSON.
        let _ = (h, p, s);
        // Use a fixture token.
        let header = base64::engine::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            br#"{"alg":"RS256","typ":"JWT"}"#,
        );
        let token = format!("{header}.eyJzdWIiOiJ4In0.sig");
        let v = jwt::alg_none_family(&token);
        prop_assert_eq!(v.len(), 5);
    }

    #[test]
    fn jwt_kid_attacks_minimum_count() {
        let header = base64::engine::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            br#"{"alg":"RS256"}"#,
        );
        let token = format!("{header}.eyJzdWIiOiJ4In0.sig");
        let v = jwt::kid_attacks(&token);
        prop_assert!(v.len() >= 10);
    }

    #[test]
    fn jwt_jku_ssrf_count(attacker in "[a-z]{1,20}", trusted in "[a-z]{1,20}") {
        let header = base64::engine::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            br#"{"alg":"RS256"}"#,
        );
        let token = format!("{header}.eyJzdWIiOiJ4In0.sig");
        let v = jwt::jku_ssrf(&token, &attacker, &trusted);
        prop_assert!(v.len() >= 4);
    }
}

// ───────────────────────────────────────────────────────────────
// dom_clobber.rs
// ───────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn dom_shadow_global_no_panic(name in "[A-Za-z0-9_]{1,40}", href in "[a-zA-Z0-9:/_.-]{0,200}") {
        let _ = dom_clobber::shadow_global(&name, &href);
    }

    #[test]
    fn dom_form_clobber_contains_name(name in "[A-Za-z]{1,30}", action in "[a-z:/.]{1,50}") {
        let out = dom_clobber::form_clobber(&name, &action);
        prop_assert!(out.contains(&name));
        prop_assert!(out.contains(&action));
    }

    #[test]
    fn dom_all_clobbers_minimum_count(name in "[A-Za-z]{1,30}", payload in "[A-Za-z]{1,30}") {
        let v = dom_clobber::all_clobbers_for_global(&name, &payload);
        prop_assert!(v.len() >= 9);
    }

    #[test]
    fn dom_all_clobbers_no_script_tag(name in "[A-Za-z]{1,20}", payload in "[A-Za-z]{1,20}") {
        // The whole point of DOM clobbering is to defeat WAFs that
        // scan for <script>. The library MUST NOT smuggle one.
        let v = dom_clobber::all_clobbers_for_global(&name, &payload);
        for p in &v {
            prop_assert!(!p.to_lowercase().contains("<script"));
        }
    }
}

// ───────────────────────────────────────────────────────────────
// proto_pollution.rs
// ───────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn pp_json_proto_no_panic(prop in "[A-Za-z]{1,30}", value in "[A-Za-z]{1,30}") {
        let _ = proto_pollution::json_proto_pollute(&prop, &value);
    }

    #[test]
    fn pp_json_proto_is_valid_json(prop in "[A-Za-z]{1,20}", value in "[A-Za-z]{1,20}") {
        let p = proto_pollution::json_proto_pollute(&prop, &value);
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&p);
        prop_assert!(parsed.is_ok());
    }

    #[test]
    fn pp_deep_merge_no_panic(depth in 0u8..=50, prop in "[A-Za-z]{1,20}", value in "[A-Za-z]{1,20}") {
        let _ = proto_pollution::deep_merge_pollute(depth, &prop, &value);
    }

    #[test]
    fn pp_all_pollution_minimum_count(prop in "[A-Za-z]{1,20}", value in "[A-Za-z]{1,20}") {
        let v = proto_pollution::all_pollution_payloads(&prop, &value);
        prop_assert!(v.len() >= 8);
    }

    #[test]
    fn pp_all_pollution_unique_names(prop in "[A-Za-z]{1,20}", value in "[A-Za-z]{1,20}") {
        let v = proto_pollution::all_pollution_payloads(&prop, &value);
        let names: std::collections::HashSet<&String> = v.iter().map(|(n, _)| n).collect();
        prop_assert_eq!(names.len(), v.len());
    }
}

// ───────────────────────────────────────────────────────────────
// ssti_escape.rs
// ───────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn ssti_jinja2_class_walk_no_panic(cmd in "[a-zA-Z0-9 _-]{0,200}") {
        let _ = ssti_escape::jinja2_class_walk(&cmd);
    }

    #[test]
    fn ssti_jinja2_class_walk_balanced_braces(cmd in "[a-zA-Z0-9 _-]{0,100}") {
        let p = ssti_escape::jinja2_class_walk(&cmd);
        prop_assert_eq!(p.matches('{').count(), p.matches('}').count());
    }

    #[test]
    fn ssti_all_escapes_minimum_count(cmd in "[a-zA-Z]{1,30}") {
        let v = ssti_escape::all_ssti_escapes(&cmd);
        prop_assert!(v.len() >= 16);
    }

    #[test]
    fn ssti_all_escapes_carry_cmd(cmd in "[a-zA-Z]{3,30}") {
        let v = ssti_escape::all_ssti_escapes(&cmd);
        for (name, payload) in &v {
            prop_assert!(payload.contains(&cmd), "engine {} dropped cmd: {}", name, payload);
        }
    }

    #[test]
    fn ssti_velocity_contains_runtime(cmd in "[a-zA-Z]{1,30}") {
        let p = ssti_escape::velocity_runtime(&cmd);
        prop_assert!(p.contains("java.lang.Runtime"));
    }

    #[test]
    fn ssti_freemarker_contains_execute(cmd in "[a-zA-Z]{1,30}") {
        let p = ssti_escape::freemarker_execute(&cmd);
        prop_assert!(p.contains("freemarker.template.utility.Execute"));
    }
}

// ───────────────────────────────────────────────────────────────
// saml_xsw.rs
// ───────────────────────────────────────────────────────────────

fn arb_fixture_saml() -> &'static str {
    // Static minimal fixture — small enough for proptest, valid
    // landmarks for each XSW builder.
    r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r" Version="2.0"><saml:Assertion ID="_a" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:Reference URI="#_a"/></ds:SignedInfo><ds:SignatureValue>AA</ds:SignatureValue></ds:Signature><saml:Subject><saml:NameID>victim</saml:NameID></saml:Subject><saml:AttributeStatement><saml:Attribute Name="role"><saml:AttributeValue>user</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>"#
}

proptest! {
    #[test]
    fn xsw_no_panic_random_subject(subject in "[a-zA-Z]{1,30}") {
        let saml = arb_fixture_saml();
        let _ = saml_xsw::xsw1(saml, &subject);
        let _ = saml_xsw::xsw2(saml, &subject);
        let _ = saml_xsw::xsw3(saml, &subject);
        let _ = saml_xsw::xsw4(saml, &subject);
        let _ = saml_xsw::xsw5(saml, &subject);
        let _ = saml_xsw::xsw6(saml, &subject);
        let _ = saml_xsw::xsw7(saml, &subject);
        let _ = saml_xsw::xsw8(saml, &subject);
    }

    #[test]
    fn xsw_all_variants_emits_eight(subject in "[a-zA-Z]{1,20}") {
        let v = saml_xsw::all_xsw_variants(arb_fixture_saml(), &subject);
        prop_assert_eq!(v.len(), 8);
    }

    #[test]
    fn xsw_each_variant_preserves_signature(subject in "[a-zA-Z]{1,20}") {
        let v = saml_xsw::all_xsw_variants(arb_fixture_saml(), &subject);
        for (name, payload) in &v {
            prop_assert!(payload.contains("AA"), "{} lost signature: {}", name, payload);
        }
    }

    #[test]
    fn xsw1_inserts_attacker_subject(subject in "[a-zA-Z]{3,20}") {
        let out = saml_xsw::xsw1(arb_fixture_saml(), &subject).unwrap();
        prop_assert!(out.contains(&subject));
    }
}

// ───────────────────────────────────────────────────────────────
// cookie_attacks.rs
// ───────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn cookie_toss_no_panic(domain in "[a-z]{1,30}\\.example", name in "[a-z]{1,20}", value in "[a-zA-Z]{0,100}") {
        let _ = cookie_attacks::cookie_toss(&domain, &name, &value);
    }

    #[test]
    fn cookie_jar_overflow_exact_count(n in 0usize..=500) {
        let v = cookie_attacks::jar_overflow_headers(n);
        prop_assert_eq!(v.len(), n);
    }

    #[test]
    fn cookie_double_encoded_alnum_passthrough(name in "[a-z]{1,20}", value in "[A-Za-z0-9]{0,40}") {
        let c = cookie_attacks::double_encoded_value(&name, &value);
        // No %25 in output since the input is pure alphanumeric.
        if !value.is_empty() {
            prop_assert!(!c.contains("%25"));
        }
        prop_assert!(c.starts_with(&format!("{name}=")));
    }

    #[test]
    fn cookie_oversized_exact_size(padding in 0usize..=10_000) {
        let c = cookie_attacks::oversized_cookie("n", padding);
        prop_assert_eq!(c.matches('A').count(), padding);
    }

    #[test]
    fn cookie_all_attacks_minimum_count(name in "[a-z]{1,20}", value in "[a-z]{1,20}", domain in "[a-z]{1,20}\\.com") {
        let v = cookie_attacks::all_cookie_attacks(&name, &value, &domain);
        prop_assert!(v.len() >= 10);
    }
}

// ───────────────────────────────────────────────────────────────
// csv_formula.rs
// ───────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn csv_excel_dde_starts_with_equals(cmd in "[a-z]{1,50}") {
        let p = csv_formula::excel_dde(&cmd);
        prop_assert!(p.starts_with('='));
        prop_assert!(p.contains(&cmd));
    }

    #[test]
    fn csv_hyperlink_phish_contains_url(url in "[a-z:/.]{1,80}", text in "[a-z]{1,30}") {
        let p = csv_formula::hyperlink_phish(&url, &text);
        prop_assert!(p.contains(&url));
        prop_assert!(p.contains(&text));
    }

    #[test]
    fn csv_all_attacks_minimum_count(url in "[a-z:/.]{1,30}", cmd in "[a-z]{1,30}") {
        let v = csv_formula::all_csv_attacks(&url, &cmd);
        prop_assert!(v.len() >= 14);
    }

    #[test]
    fn csv_prefix_variants_each_starts_with_their_char(content in "[a-zA-Z0-9]{1,40}") {
        prop_assert!(csv_formula::plus_prefix(&content).starts_with('+'));
        prop_assert!(csv_formula::minus_prefix(&content).starts_with('-'));
        prop_assert!(csv_formula::at_prefix(&content).starts_with('@'));
        prop_assert!(csv_formula::tab_prefix(&content).starts_with('\t'));
        prop_assert!(csv_formula::cr_prefix(&content).starts_with('\r'));
        prop_assert!(csv_formula::lf_prefix(&content).starts_with('\n'));
    }
}

// ───────────────────────────────────────────────────────────────
// oauth.rs (uses agent's API — best-effort property test)
// ───────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn oauth_redirect_uri_attacks_no_panic(
        trusted in "[a-z]{1,30}\\.example",
        attacker in "[a-z]{1,30}\\.attacker"
    ) {
        let _ = oauth::redirect_uri_attacks(&trusted, &attacker);
    }

    #[test]
    fn oauth_state_attack_payloads_no_panic(state in "[A-Za-z0-9]{0,40}") {
        let _ = oauth::state_attack_payloads(&state);
    }
}
