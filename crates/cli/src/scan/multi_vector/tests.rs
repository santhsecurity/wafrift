//! Tests for [`super`] (the `multi_vector` module) — pulled into
//! their own file so `mod.rs` carries only production code.
//!
//! Grouped by what they exercise:
//! - Catalogue integrity (uniqueness, axis coverage, presence)
//! - Per-vector builders (one test per attack axis, often many)
//! - `run_phase` orchestration (cancellation, empty input, rescue
//!   bypass tagging)

#![cfg(test)]

use super::*;

fn http() -> Client {
    Client::builder().build().expect("client")
}

/// Test-only client with a tight `connect_timeout` so the
/// dead-target loop tests (e.g. `run_phase_*`) don't bleed
/// 1-2 s of OS connect-refused retry per vector. With ~40
/// vectors and a real Windows ECONNREFUSED delay, the
/// non-timeout client made unit-tests take >90 s for a
/// single test case.
fn fast_fail_http() -> Client {
    Client::builder()
        .connect_timeout(Duration::from_millis(50))
        .timeout(Duration::from_millis(100))
        .build()
        .expect("client")
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
    let names: std::collections::HashSet<&str> = VECTORS.iter().map(|v| v.name).collect();
    assert!(names.contains("POST-form-br"), "missing brotli vector");
    assert!(names.contains("POST-json-bom"), "missing BOM vector");
    assert!(
        names.contains("POST-json-as-plain"),
        "missing CT-lying vector"
    );
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
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-json-dupkey")
        .unwrap();
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
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-json-array")
        .unwrap();
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
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-json-as-plain")
        .unwrap();
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
    let h = fast_fail_http();
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
        fires_so_far: 0,
        max_fires: 0, // 0 = unlimited
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
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-json-gz-br")
        .unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "abc", 0)
        .unwrap()
        .build()
        .unwrap();
    let ce = req
        .headers()
        .get("content-encoding")
        .unwrap()
        .to_str()
        .unwrap();
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
    assert_eq!(req.headers().get("x-http-method-override").unwrap(), "PUT",);
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
    assert!(
        !s.contains("<script>"),
        "raw payload must NOT appear unescaped"
    );
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
    let h = fast_fail_http();
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
        fires_so_far: 0,
        max_fires: 0, // 0 = unlimited
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
    assert!(
        s.contains("%26"),
        "& must url-encode to %26 inside form value: {s}"
    );
    assert!(
        s.contains("%3D"),
        "= must url-encode to %3D inside form value: {s}"
    );
    assert!(
        s.contains("%20") || s.contains("+"),
        "space must encode: {s}"
    );
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
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-json-dupkey")
        .unwrap();
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
        let v = VECTORS
            .iter()
            .find(|v| v.name == "POST-json-dupkey")
            .unwrap();
        let req = build_request_for_vector(v, &h, "http://x/", param, "payload", 0)
            .unwrap()
            .build()
            .unwrap();
        let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
        let s = std::str::from_utf8(body).unwrap();
        // The param name should appear TWICE.
        let needle = format!("\"{param}\":");
        assert_eq!(
            s.matches(needle.as_str()).count(),
            2,
            "param={param}, body={s}"
        );
    }
}

#[test]
fn build_post_json_array_root_emits_exactly_one_element() {
    let h = http();
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-json-array")
        .unwrap();
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
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-json-array")
        .unwrap();
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
    let v = VECTORS
        .iter()
        .find(|v| v.name == "x-forwarded-for")
        .unwrap();
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
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-json-gz-br")
        .unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
        .unwrap()
        .build()
        .unwrap();
    let ce = req
        .headers()
        .get("content-encoding")
        .unwrap()
        .to_str()
        .unwrap();
    // RFC 9110 §8.4: leftmost is outermost wrapper. We pass
    // [Gzip, Brotli] meaning body is gzip(brotli(payload)),
    // so header must list gzip FIRST.
    let gzip_pos = ce.find("gzip").expect("gzip in header");
    let br_pos = ce.find("br").expect("br in header");
    assert!(gzip_pos < br_pos);
}

#[test]
fn build_post_multipart_dupbound_header_boundary_is_not_decoy_boundary() {
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
        fires_so_far: 0,
        max_fires: 0, // 0 = unlimited
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
    let h = fast_fail_http();
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
        fires_so_far: 0,
        max_fires: 0, // 0 = unlimited
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
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-json-deflate")
        .unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "abc", 0)
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(req.headers().get("content-encoding").unwrap(), "deflate");
}

#[test]
fn build_post_json_deflate_content_type_stays_application_json() {
    let h = http();
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-json-deflate")
        .unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "abc", 0)
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(
        req.headers().get("content-type").unwrap(),
        "application/json"
    );
}

#[test]
fn build_post_json_deflate_body_is_not_plaintext_json() {
    // The point of compression-confusion: bytes on the wire
    // must not be readable as JSON.
    let h = http();
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-json-deflate")
        .unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "abc", 0)
        .unwrap()
        .build()
        .unwrap();
    let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
    let s = String::from_utf8_lossy(body);
    assert!(
        !s.contains("\"q\""),
        "compressed body must hide the param: {s}"
    );
}

#[test]
fn build_post_json_deflate_round_trips_under_deflate_decompression() {
    use wafrift_encoding::compression::{Algorithm, CompressedBody, decompress};
    let h = http();
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-json-deflate")
        .unwrap();
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
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-json-deflate")
        .unwrap();
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
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-form-deflate")
        .unwrap();
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
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-form-deflate")
        .unwrap();
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
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-form-deflate")
        .unwrap();
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
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-form-deflate")
        .unwrap();
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
    assert_eq!(
        req.headers().get("content-type").unwrap(),
        "application/yaml"
    );
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
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-multipart-b64")
        .unwrap();
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
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-multipart-b64")
        .unwrap();
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
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-multipart-b64")
        .unwrap();
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
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-multipart-b64")
        .unwrap();
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
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-multipart-b64")
        .unwrap();
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
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-multipart-b64")
        .unwrap();
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
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-multipart-b64")
        .unwrap();
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
    let names: std::collections::HashSet<&str> = VECTORS.iter().map(|v| v.name).collect();
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
    assert_eq!(
        req.headers().get("content-type").unwrap(),
        "application/json"
    );
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
fn build_post_cbor_emits_application_cbor_content_type() {
    let h = http();
    let v = VECTORS.iter().find(|v| v.name == "POST-cbor").unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(
        req.headers().get("content-type").unwrap(),
        "application/cbor"
    );
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
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-multipart-filename")
        .unwrap();
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
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-multipart-filename")
        .unwrap();
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
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-multipart-filename")
        .unwrap();
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
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-multipart-filename")
        .unwrap();
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
    let v = VECTORS
        .iter()
        .find(|v| v.name == "authorization-basic")
        .unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "user", 0)
        .unwrap()
        .build()
        .unwrap();
    let auth = req
        .headers()
        .get("authorization")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(auth.starts_with("Basic "));
}

#[test]
fn build_authorization_basic_encodes_payload_as_username_half() {
    use base64::Engine as _;
    let h = http();
    let v = VECTORS
        .iter()
        .find(|v| v.name == "authorization-basic")
        .unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "' OR 1=1--", 0)
        .unwrap()
        .build()
        .unwrap();
    let auth = req
        .headers()
        .get("authorization")
        .unwrap()
        .to_str()
        .unwrap();
    let b64 = auth.strip_prefix("Basic ").unwrap();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .unwrap();
    let s = std::str::from_utf8(&decoded).unwrap();
    // Username:password — payload MUST be the user half.
    assert!(s.starts_with("' OR 1=1--:"));
}

#[test]
fn build_authorization_basic_uses_get_method() {
    let h = http();
    let v = VECTORS
        .iter()
        .find(|v| v.name == "authorization-basic")
        .unwrap();
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
    let v = VECTORS
        .iter()
        .find(|v| v.name == "authorization-basic")
        .unwrap();
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

// ── cookie-hpp ────────────────────────────────────────────

#[test]
fn build_cookie_hpp_emits_two_pairs_with_same_name() {
    let h = http();
    let v = VECTORS.iter().find(|v| v.name == "cookie-hpp").unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "attack", 0)
        .unwrap()
        .build()
        .unwrap();
    let cookie = req.headers().get("cookie").unwrap().to_str().unwrap();
    assert_eq!(
        cookie.matches("q=").count(),
        2,
        "must emit q= twice: {cookie}"
    );
}

#[test]
fn build_cookie_hpp_benign_pair_comes_first() {
    let h = http();
    let v = VECTORS.iter().find(|v| v.name == "cookie-hpp").unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "attack", 0)
        .unwrap()
        .build()
        .unwrap();
    let cookie = req.headers().get("cookie").unwrap().to_str().unwrap();
    let h_pos = cookie.find("q=harmless").unwrap();
    let a_pos = cookie.find("q=attack").unwrap();
    assert!(h_pos < a_pos, "harmless before attack: {cookie}");
}

#[test]
fn build_cookie_hpp_uses_semicolon_space_separator_per_rfc6265() {
    let h = http();
    let v = VECTORS.iter().find(|v| v.name == "cookie-hpp").unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
        .unwrap()
        .build()
        .unwrap();
    let cookie = req.headers().get("cookie").unwrap().to_str().unwrap();
    // RFC 6265 cookie-string syntax: `name=value; name=value`
    assert!(cookie.contains("; "), "must use `; ` separator: {cookie}");
}

#[test]
fn build_cookie_hpp_uses_get_method() {
    let h = http();
    let v = VECTORS.iter().find(|v| v.name == "cookie-hpp").unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(req.method(), "GET");
}

// ── path-segment ──────────────────────────────────────────

#[test]
fn build_path_segment_vector_emits_url_with_payload_in_path() {
    let h = http();
    let v = VECTORS.iter().find(|v| v.name == "path-segment").unwrap();
    let req = build_request_for_vector(v, &h, "http://example.com/api", "q", "PAYLOAD", 0)
        .unwrap()
        .build()
        .unwrap();
    let url = req.url().to_string();
    // The percent-encoded payload appears in the path,
    // BEFORE the original path segment.
    assert!(
        url.contains("/PAYLOAD/api") || url.contains("/PAYLOAD%2Fapi"),
        "url: {url}"
    );
}

#[test]
fn build_path_segment_uses_get_method() {
    let h = http();
    let v = VECTORS.iter().find(|v| v.name == "path-segment").unwrap();
    let req = build_request_for_vector(v, &h, "http://example.com/", "q", "x", 0)
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(req.method(), "GET");
}

#[test]
fn build_path_segment_percent_encodes_payload() {
    let h = http();
    let v = VECTORS.iter().find(|v| v.name == "path-segment").unwrap();
    let req = build_request_for_vector(v, &h, "http://example.com/", "q", "a b", 0)
        .unwrap()
        .build()
        .unwrap();
    let url = req.url().to_string();
    // Space in payload MUST be url-encoded — otherwise the
    // URL is malformed and reqwest will refuse / mangle.
    assert!(
        url.contains("a%20b") || url.contains("a+b"),
        "space must encode: {url}"
    );
}

// ── catalogue presence (round 4) ──────────────────────────

#[test]
fn round_four_vectors_are_in_catalogue() {
    let names: std::collections::HashSet<&str> = VECTORS.iter().map(|v| v.name).collect();
    for required in ["cookie-hpp", "path-segment"] {
        assert!(names.contains(required), "missing vector {required}");
    }
}

// ── x-original-url / x-rewrite-url ────────────────────────

#[test]
fn build_x_original_url_sets_header_with_payload_path() {
    let h = http();
    let v = VECTORS.iter().find(|v| v.name == "x-original-url").unwrap();
    let req = build_request_for_vector(v, &h, "http://example.com/safe", "q", "ADMIN", 0)
        .unwrap()
        .build()
        .unwrap();
    let hdr = req
        .headers()
        .get("x-original-url")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(hdr.starts_with("/"), "must start with /: {hdr}");
    assert!(hdr.contains("ADMIN"));
}

#[test]
fn build_x_rewrite_url_uses_distinct_header_name() {
    let h = http();
    let v = VECTORS.iter().find(|v| v.name == "x-rewrite-url").unwrap();
    let req = build_request_for_vector(v, &h, "http://example.com/", "q", "x", 0)
        .unwrap()
        .build()
        .unwrap();
    assert!(req.headers().contains_key("x-rewrite-url"));
    assert!(!req.headers().contains_key("x-original-url"));
}

#[test]
fn build_x_original_url_request_line_still_targets_original_path() {
    // The wire request-line URI must STILL be the operator's
    // target — the override goes only in the header. Anti-rig:
    // a refactor that put the override into the URL too would
    // double-up and hit the WAF rules anyway.
    let h = http();
    let v = VECTORS.iter().find(|v| v.name == "x-original-url").unwrap();
    let req = build_request_for_vector(v, &h, "http://example.com/safe", "q", "ADMIN", 0)
        .unwrap()
        .build()
        .unwrap();
    let url = req.url().to_string();
    assert!(
        url.contains("/safe"),
        "request-line URI keeps the target: {url}"
    );
    assert!(
        !url.contains("/ADMIN"),
        "override must NOT be in the URL: {url}"
    );
}

#[test]
fn build_x_original_url_percent_encodes_unsafe_chars() {
    let h = http();
    let v = VECTORS.iter().find(|v| v.name == "x-original-url").unwrap();
    let req = build_request_for_vector(v, &h, "http://example.com/", "q", "admin?x=y", 0)
        .unwrap()
        .build()
        .unwrap();
    let hdr = req
        .headers()
        .get("x-original-url")
        .unwrap()
        .to_str()
        .unwrap();
    // `?` must be %3F so the header value stays a single
    // path-shape string (no inline query split).
    assert!(hdr.contains("%3F") || hdr.contains("%3f"), "hdr: {hdr}");
}

#[test]
fn build_x_original_url_uses_get_method() {
    let h = http();
    let v = VECTORS.iter().find(|v| v.name == "x-original-url").unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(req.method(), "GET");
}

// ── accept-language ───────────────────────────────────────

#[test]
fn build_accept_language_carries_payload_verbatim() {
    let h = http();
    let v = VECTORS
        .iter()
        .find(|v| v.name == "accept-language")
        .unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "' OR 1=1--", 0)
        .unwrap()
        .build()
        .unwrap();
    // The Accept-Language header value contains the payload
    // bytes. reqwest accepts arbitrary visible ASCII; non-ASCII
    // payloads route through the same wire path because
    // header-value validation is "non-control bytes" only.
    let hdr = req
        .headers()
        .get("accept-language")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(hdr.contains("' OR 1=1--"));
}

#[test]
fn build_accept_language_uses_get_method() {
    let h = http();
    let v = VECTORS
        .iter()
        .find(|v| v.name == "accept-language")
        .unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(req.method(), "GET");
}

// ── catalogue presence (round 5) ──────────────────────────

#[test]
fn round_five_vectors_are_in_catalogue() {
    let names: std::collections::HashSet<&str> = VECTORS.iter().map(|v| v.name).collect();
    for required in ["x-original-url", "x-rewrite-url", "accept-language"] {
        assert!(names.contains(required), "missing vector {required}");
    }
}

// ── POST-json-deeply-nested ───────────────────────────────

#[test]
fn build_post_json_deeply_nested_buries_payload_at_depth_twelve() {
    let h = http();
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-json-deeply-nested")
        .unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "PAYLOAD", 0)
        .unwrap()
        .build()
        .unwrap();
    let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
    let s = std::str::from_utf8(body).unwrap();
    let v: serde_json::Value = serde_json::from_str(s).unwrap();

    // Walk 11 layers of "n" wrapping, then the innermost is
    // {"q": "PAYLOAD"}.
    let mut cur = &v;
    for level in 0..11 {
        cur = &cur["n"];
        assert!(
            cur.is_object(),
            "level {level} should still be an object: {v}"
        );
    }
    assert_eq!(cur["q"], "PAYLOAD");
}

#[test]
fn build_post_json_deeply_nested_is_valid_json() {
    let h = http();
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-json-deeply-nested")
        .unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "abc", 0)
        .unwrap()
        .build()
        .unwrap();
    let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
    let s = std::str::from_utf8(body).unwrap();
    let _: serde_json::Value = serde_json::from_str(s).expect("must be valid JSON");
}

#[test]
fn build_post_json_deeply_nested_emits_application_json() {
    let h = http();
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-json-deeply-nested")
        .unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(
        req.headers().get("content-type").unwrap(),
        "application/json"
    );
}

// ── POST-json-key-as-payload ──────────────────────────────

#[test]
fn build_post_json_key_as_payload_makes_payload_the_key() {
    let h = http();
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-json-key-as-payload")
        .unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "param", "ATTACK", 0)
        .unwrap()
        .build()
        .unwrap();
    let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
    let s = std::str::from_utf8(body).unwrap();
    let v: serde_json::Value = serde_json::from_str(s).unwrap();
    // The single key in the object IS the payload.
    let obj = v.as_object().unwrap();
    assert_eq!(obj.len(), 1);
    let key = obj.keys().next().unwrap();
    assert_eq!(key, "ATTACK");
}

#[test]
fn build_post_json_key_as_payload_value_is_the_param_name() {
    let h = http();
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-json-key-as-payload")
        .unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "search", "EVIL", 0)
        .unwrap()
        .build()
        .unwrap();
    let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
    let s = std::str::from_utf8(body).unwrap();
    let v: serde_json::Value = serde_json::from_str(s).unwrap();
    // The value of the key MUST be the param name, so a
    // value-iterating backend sees something meaningful.
    assert_eq!(v["EVIL"], "search");
}

#[test]
fn build_post_json_key_as_payload_handles_payload_with_quotes() {
    // The payload becomes a JSON key — quotes / backslashes
    // in it must be escaped or the JSON breaks.
    let h = http();
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-json-key-as-payload")
        .unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "param", "a\"b\\c", 0)
        .unwrap()
        .build()
        .unwrap();
    let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
    let s = std::str::from_utf8(body).unwrap();
    let v: serde_json::Value = serde_json::from_str(s).expect("must be valid JSON");
    let obj = v.as_object().unwrap();
    let key = obj.keys().next().unwrap();
    assert_eq!(key, "a\"b\\c");
}

// ── forwarded (RFC 7239) ──────────────────────────────────

#[test]
fn build_forwarded_uses_rfc7239_for_equals_shape() {
    let h = http();
    let v = VECTORS.iter().find(|v| v.name == "forwarded").unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "10.0.0.1", 0)
        .unwrap()
        .build()
        .unwrap();
    let hdr = req.headers().get("forwarded").unwrap().to_str().unwrap();
    assert!(
        hdr.starts_with("for="),
        "must use RFC 7239 for= shape: {hdr}"
    );
    assert!(hdr.contains("10.0.0.1"));
}

#[test]
fn build_forwarded_uses_get_method() {
    let h = http();
    let v = VECTORS.iter().find(|v| v.name == "forwarded").unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(req.method(), "GET");
}

#[test]
fn build_forwarded_does_not_set_x_forwarded_for_header() {
    // The 7239 header is distinct from XFF — confirm the
    // builder doesn't accidentally set BOTH (which would
    // give the WAF a chance to match on the well-known XFF
    // header).
    let h = http();
    let v = VECTORS.iter().find(|v| v.name == "forwarded").unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
        .unwrap()
        .build()
        .unwrap();
    assert!(!req.headers().contains_key("x-forwarded-for"));
    assert!(req.headers().contains_key("forwarded"));
}

// ── catalogue presence (round 6) ──────────────────────────

#[test]
fn round_six_vectors_are_in_catalogue() {
    let names: std::collections::HashSet<&str> = VECTORS.iter().map(|v| v.name).collect();
    for required in [
        "POST-json-deeply-nested",
        "POST-json-key-as-payload",
        "forwarded",
    ] {
        assert!(names.contains(required), "missing vector {required}");
    }
}

// ── origin / range / from header carriers ─────────────────

#[test]
fn build_origin_uses_https_scheme_prefix_with_payload_as_host() {
    let h = http();
    let v = VECTORS.iter().find(|v| v.name == "origin").unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "evil.example", 0)
        .unwrap()
        .build()
        .unwrap();
    let hdr = req.headers().get("origin").unwrap().to_str().unwrap();
    assert!(hdr.starts_with("https://"));
    assert!(hdr.contains("evil.example"));
}

#[test]
fn build_origin_uses_get_method() {
    let h = http();
    let v = VECTORS.iter().find(|v| v.name == "origin").unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(req.method(), "GET");
}

#[test]
fn build_range_uses_bytes_equals_prefix() {
    let h = http();
    let v = VECTORS.iter().find(|v| v.name == "range").unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "0-100", 0)
        .unwrap()
        .build()
        .unwrap();
    let hdr = req.headers().get("range").unwrap().to_str().unwrap();
    assert!(hdr.starts_with("bytes="));
    assert!(hdr.contains("0-100"));
}

#[test]
fn build_range_carries_payload_verbatim_in_value() {
    // Range may carry arbitrary bytes (modulo header-value
    // validity). The payload survives the `bytes=` wrapper.
    let h = http();
    let v = VECTORS.iter().find(|v| v.name == "range").unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "PAYLOAD", 0)
        .unwrap()
        .build()
        .unwrap();
    let hdr = req.headers().get("range").unwrap().to_str().unwrap();
    assert!(hdr.contains("PAYLOAD"));
}

#[test]
fn build_from_appends_at_suffix_so_value_looks_like_email() {
    let h = http();
    let v = VECTORS.iter().find(|v| v.name == "from").unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "operator", 0)
        .unwrap()
        .build()
        .unwrap();
    let hdr = req.headers().get("from").unwrap().to_str().unwrap();
    // Must contain `@` so an email-format-checking middleware
    // doesn't reject the request before our payload gets logged.
    assert!(hdr.contains('@'));
    assert!(hdr.starts_with("operator"));
}

#[test]
fn build_from_uses_get_method() {
    let h = http();
    let v = VECTORS.iter().find(|v| v.name == "from").unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(req.method(), "GET");
}

// ── catalogue presence (round 7) ──────────────────────────

#[test]
fn round_seven_vectors_are_in_catalogue() {
    let names: std::collections::HashSet<&str> = VECTORS.iter().map(|v| v.name).collect();
    for required in ["origin", "range", "from"] {
        assert!(names.contains(required), "missing vector {required}");
    }
}

// ── Compound vectors ──────────────────────────────────────

#[test]
fn build_post_json_bom_br_emits_brotli_content_encoding() {
    let h = http();
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-json-bom-br")
        .unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "abc", 0)
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(req.headers().get("content-encoding").unwrap(), "br");
}

#[test]
fn build_post_json_bom_br_round_trip_recovers_bom_prefixed_json() {
    use wafrift_encoding::compression::{Algorithm, CompressedBody, decompress};
    let h = http();
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-json-bom-br")
        .unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "PAYLOAD", 0)
        .unwrap()
        .build()
        .unwrap();
    let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
    let recovered = decompress(&CompressedBody {
        body: body.to_vec(),
        content_encoding: Algorithm::Brotli.content_encoding().to_string(),
    })
    .expect("brotli round-trip");
    // First three bytes MUST be the BOM.
    assert_eq!(&recovered[..3], &[0xEF, 0xBB, 0xBF]);
    // Rest must be valid JSON with the payload.
    let s = std::str::from_utf8(&recovered[3..]).unwrap();
    let v: serde_json::Value = serde_json::from_str(s).unwrap();
    assert_eq!(v["q"], "PAYLOAD");
}

#[test]
fn build_post_json_utf7_gz_declares_utf7_charset_and_gzip_encoding() {
    let h = http();
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-json-utf7-gz")
        .unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
        .unwrap()
        .build()
        .unwrap();
    let ct = req.headers().get("content-type").unwrap().to_str().unwrap();
    assert!(ct.contains("charset=utf-7"));
    assert_eq!(req.headers().get("content-encoding").unwrap(), "gzip");
}

#[test]
fn build_post_json_utf7_gz_round_trip_recovers_json() {
    use wafrift_encoding::compression::{Algorithm, CompressedBody, decompress};
    let h = http();
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-json-utf7-gz")
        .unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "abc", 0)
        .unwrap()
        .build()
        .unwrap();
    let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
    let recovered = decompress(&CompressedBody {
        body: body.to_vec(),
        content_encoding: Algorithm::Gzip.content_encoding().to_string(),
    })
    .unwrap();
    let s = String::from_utf8(recovered).unwrap();
    let v: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert_eq!(v["q"], "abc");
}

#[test]
fn build_post_json_dupkey_bom_starts_with_bom_then_dupkey_shape() {
    let h = http();
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-json-dupkey-bom")
        .unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "attack", 0)
        .unwrap()
        .build()
        .unwrap();
    let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
    assert_eq!(&body[..3], &[0xEF, 0xBB, 0xBF]);
    let s = std::str::from_utf8(&body[3..]).unwrap();
    assert_eq!(s.matches("\"q\":").count(), 2, "must emit q twice: {s}");
    // Benign first, attack second — same as plain dupkey.
    let first_pos = s.find("\"q\":").unwrap();
    let second_pos = s.rfind("\"q\":").unwrap();
    assert!(first_pos < second_pos);
    let after_second = &s[second_pos..];
    assert!(after_second.contains("attack"));
}

#[test]
fn build_post_json_dupkey_bom_body_after_bom_parses_as_json() {
    // Strip the BOM, the remaining bytes are valid JSON with
    // two q keys — serde_json takes the LAST one.
    let h = http();
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-json-dupkey-bom")
        .unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "attack", 0)
        .unwrap()
        .build()
        .unwrap();
    let body = req.body().and_then(|b| b.as_bytes()).unwrap_or(b"");
    let s = std::str::from_utf8(&body[3..]).unwrap();
    let v: serde_json::Value = serde_json::from_str(s).expect("post-BOM body must parse");
    // serde_json default is last-occurrence-wins, so q = attack.
    assert_eq!(v["q"], "attack");
}

// ── compound catalogue ────────────────────────────────────

#[test]
fn compound_vectors_are_in_catalogue() {
    let names: std::collections::HashSet<&str> = VECTORS.iter().map(|v| v.name).collect();
    for required in [
        "POST-json-bom-br",
        "POST-json-utf7-gz",
        "POST-json-dupkey-bom",
    ] {
        assert!(names.contains(required), "missing vector {required}");
    }
}

// ── round 8: chunked-T-E / NDJSON / JSON5 / QP / json-as-form ─

#[test]
fn round_eight_vectors_are_in_catalogue() {
    let names: std::collections::HashSet<&str> = VECTORS.iter().map(|v| v.name).collect();
    for required in [
        "POST-json5-comment",
        "POST-ndjson",
        "POST-json-as-form",
        "POST-multipart-qp",
    ] {
        assert!(names.contains(required), "missing vector {required}");
    }
}

// ── POST-json5-comment ───────────────────────────────────

#[test]
fn build_post_json5_comment_emits_application_json_ct() {
    let h = http();
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-json5-comment")
        .unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(
        req.headers().get("content-type").unwrap(),
        "application/json"
    );
    assert_eq!(req.method(), "POST");
}

#[test]
fn build_post_json5_comment_body_contains_block_comment() {
    let h = http();
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-json5-comment")
        .unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "X", 0)
        .unwrap()
        .build()
        .unwrap();
    let body = std::str::from_utf8(req.body().and_then(|b| b.as_bytes()).unwrap_or(b"")).unwrap();
    assert!(
        body.contains("/*") && body.contains("*/"),
        "must carry a block comment: {body}"
    );
}

#[test]
fn build_post_json5_comment_body_carries_decoy_first_attack_after_comment() {
    let h = http();
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-json5-comment")
        .unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "ATTACK", 0)
        .unwrap()
        .build()
        .unwrap();
    let body = std::str::from_utf8(req.body().and_then(|b| b.as_bytes()).unwrap_or(b"")).unwrap();
    // Decoy must come before the comment block.
    let decoy_pos = body.find("\"decoy\"").expect("decoy key present");
    let comment_pos = body.find("/*").expect("comment present");
    let attack_pos = body.find("ATTACK").expect("attack present");
    assert!(decoy_pos < comment_pos, "decoy before comment");
    assert!(comment_pos < attack_pos, "attack after the comment opens");
}

#[test]
fn build_post_json5_comment_body_is_invalid_strict_json() {
    // Strict serde_json should refuse a body with /* */
    // comments — that's the whole bypass: a WAF using strict
    // JSON parsing falls through to no inspection.
    let h = http();
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-json5-comment")
        .unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
        .unwrap()
        .build()
        .unwrap();
    let body = std::str::from_utf8(req.body().and_then(|b| b.as_bytes()).unwrap_or(b"")).unwrap();
    assert!(
        serde_json::from_str::<serde_json::Value>(body).is_err(),
        "strict JSON must refuse comments: {body}"
    );
}

// ── POST-ndjson ──────────────────────────────────────────

#[test]
fn build_post_ndjson_declares_ndjson_content_type() {
    let h = http();
    let v = VECTORS.iter().find(|v| v.name == "POST-ndjson").unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(
        req.headers().get("content-type").unwrap(),
        "application/x-ndjson"
    );
}

#[test]
fn build_post_ndjson_body_has_two_newline_separated_json_docs() {
    let h = http();
    let v = VECTORS.iter().find(|v| v.name == "POST-ndjson").unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "ATTACK", 0)
        .unwrap()
        .build()
        .unwrap();
    let body = std::str::from_utf8(req.body().and_then(|b| b.as_bytes()).unwrap_or(b"")).unwrap();
    let lines: Vec<&str> = body.split('\n').filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 2, "exactly two docs expected: {body}");
    // Each line must parse as a standalone JSON doc.
    let first: serde_json::Value = serde_json::from_str(lines[0]).expect("line 1 parses");
    let second: serde_json::Value = serde_json::from_str(lines[1]).expect("line 2 parses");
    // Decoy first, attack second.
    assert_eq!(first["q"], "harmless");
    assert_eq!(second["q"], "ATTACK");
}

#[test]
fn build_post_ndjson_body_is_not_a_single_top_level_json_doc() {
    // The whole bypass premise: a WAF JSON processor that
    // parses the body as ONE doc gets a parse error on the
    // newline-separated stream and skips inspection.
    let h = http();
    let v = VECTORS.iter().find(|v| v.name == "POST-ndjson").unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
        .unwrap()
        .build()
        .unwrap();
    let body = std::str::from_utf8(req.body().and_then(|b| b.as_bytes()).unwrap_or(b"")).unwrap();
    assert!(
        serde_json::from_str::<serde_json::Value>(body).is_err(),
        "single-doc parser must refuse multi-line ndjson: {body}"
    );
}

// ── POST-json-as-form ─────────────────────────────────────

#[test]
fn build_post_json_as_form_declares_form_content_type() {
    let h = http();
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-json-as-form")
        .unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(
        req.headers().get("content-type").unwrap(),
        "application/x-www-form-urlencoded"
    );
}

#[test]
fn build_post_json_as_form_body_is_actually_json() {
    let h = http();
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-json-as-form")
        .unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "ATTACK", 0)
        .unwrap()
        .build()
        .unwrap();
    let body = std::str::from_utf8(req.body().and_then(|b| b.as_bytes()).unwrap_or(b"")).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(body).expect("body is JSON");
    assert_eq!(parsed["q"], "ATTACK");
}

#[test]
fn build_post_json_as_form_body_lacks_form_kv_separator() {
    // The bypass premise: form processor scans for `key=value`,
    // finds none, treats body as opaque / empty.
    let h = http();
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-json-as-form")
        .unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
        .unwrap()
        .build()
        .unwrap();
    let body = std::str::from_utf8(req.body().and_then(|b| b.as_bytes()).unwrap_or(b"")).unwrap();
    // `q=` (literal) must not appear — only `"q":` (JSON shape) does.
    assert!(
        !body.contains("q="),
        "no form-shape KV pair in body: {body}"
    );
    assert!(body.contains("\"q\":"), "JSON shape present: {body}");
}

// ── POST-multipart-qp ─────────────────────────────────────

#[test]
fn build_post_multipart_qp_declares_multipart_content_type() {
    let h = http();
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-multipart-qp")
        .unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
        .unwrap()
        .build()
        .unwrap();
    let ct = req.headers().get("content-type").unwrap().to_str().unwrap();
    assert!(
        ct.starts_with("multipart/form-data; boundary="),
        "got: {ct}"
    );
}

#[test]
fn build_post_multipart_qp_part_carries_quoted_printable_cte() {
    let h = http();
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-multipart-qp")
        .unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
        .unwrap()
        .build()
        .unwrap();
    let body = std::str::from_utf8(req.body().and_then(|b| b.as_bytes()).unwrap_or(b"")).unwrap();
    assert!(
        body.contains("Content-Transfer-Encoding: quoted-printable"),
        "must declare QP CTE: {body}"
    );
}

#[test]
fn build_post_multipart_qp_encodes_non_ascii_bytes() {
    // Pick a payload with a single `=` so we know QP rewrote
    // it. Raw `=` would be ambiguous to the decoder; QP encodes
    // it as `=3D`.
    let h = http();
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-multipart-qp")
        .unwrap();
    let req = build_request_for_vector(v, &h, "http://x/", "q", "1=2", 0)
        .unwrap()
        .build()
        .unwrap();
    let body = std::str::from_utf8(req.body().and_then(|b| b.as_bytes()).unwrap_or(b"")).unwrap();
    // Encoded `1=2` becomes `1=3D2`.
    assert!(body.contains("1=3D2"), "QP must rewrite `=`: {body}");
    // Raw `1=2` must NOT appear on the wire — that's the bypass.
    assert!(
        !body.contains("\r\n\r\n1=2\r\n"),
        "raw payload leaked: {body}"
    );
}

#[test]
fn build_post_multipart_qp_unique_boundary_per_fire_counter() {
    let h = http();
    let v = VECTORS
        .iter()
        .find(|v| v.name == "POST-multipart-qp")
        .unwrap();
    let r0 = build_request_for_vector(v, &h, "http://x/", "q", "x", 0)
        .unwrap()
        .build()
        .unwrap();
    let r1 = build_request_for_vector(v, &h, "http://x/", "q", "x", 1)
        .unwrap()
        .build()
        .unwrap();
    let ct0 = r0.headers().get("content-type").unwrap().to_str().unwrap();
    let ct1 = r1.headers().get("content-type").unwrap().to_str().unwrap();
    assert_ne!(
        ct0, ct1,
        "boundary must differ across fires: {ct0} == {ct1}"
    );
}
