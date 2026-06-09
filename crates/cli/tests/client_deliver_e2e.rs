//! End-to-end dogfood of the shipped `wafrift client-deliver` binary.
//!
//! `client-deliver` emits the WAF-blind client-side delivery plan for an XSS
//! payload — the fragment / window.name / postMessage / storage / client-route
//! channels whose taint source never reaches the server. It sends nothing, so
//! these tests need no mock server: they drive the compiled binary's arg
//! parsing, plan construction, and both output formats, and assert the operator
//! contract (every lane is WAF-blind, the scald taint sources are correct, the
//! JSON carries the versioned schema).

mod common;
use common::wafrift;

#[test]
fn text_plan_lists_every_waf_blind_channel_with_its_taint_source() {
    let (code, stdout, _stderr) = wafrift(&[
        "client-deliver",
        "--target",
        "https://shop.test/checkout",
        "--payload",
        "javascript:alert(1)",
    ]);
    assert_eq!(code, 0, "client-deliver text mode must exit 0");
    // The five distinct scald taint sources must all be represented.
    for taint in [
        "location.hash",
        "window.name",
        "postMessage",
        "localStorage",
        "sessionStorage",
    ] {
        assert!(
            stdout.contains(taint),
            "text plan missing taint source {taint}:\n{stdout}"
        );
    }
    // The WAF-blindness must be stated to the operator.
    assert!(
        stdout.to_lowercase().contains("waf-blind") || stdout.to_lowercase().contains("never"),
        "plan must explain the channels are not WAF-inspected:\n{stdout}"
    );
    // The fragment lane builds a navigation URL against the target.
    assert!(
        stdout.contains("https://shop.test/checkout#javascript:alert(1)"),
        "fragment navigation URL missing:\n{stdout}"
    );
}

#[test]
fn json_plan_carries_the_versioned_schema_and_marks_every_lane_waf_blind() {
    let (code, stdout, _stderr) = wafrift(&[
        "client-deliver",
        "--target",
        "https://t.test/app",
        "--payload",
        "javascript:alert(1)",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0);
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout must be valid JSON in --format json");
    assert_eq!(v["schema"], "wafrift.client_deliver.v1");
    assert_eq!(v["target"], "https://t.test/app");
    let deliveries = v["deliveries"].as_array().expect("deliveries array");
    assert!(!deliveries.is_empty(), "plan must have deliveries");
    for d in deliveries {
        assert_eq!(
            d["reaches_server"], false,
            "every delivery must be flagged WAF-blind: {d}"
        );
        assert!(d["taint_source"].is_string());
        assert!(
            d["action"]["kind"].is_string(),
            "action must be kind-tagged: {d}"
        );
    }
    // The scheme payload must produce at least one prefix-bypass delivery.
    assert!(
        deliveries.iter().any(|d| d["rules"]
            .as_array()
            .is_some_and(|r| r.iter().any(|x| x == "prefix_bypass"))),
        "a javascript: payload must yield prefix-bypass deliveries:\n{stdout}"
    );
}

#[test]
fn json_window_name_action_sets_state_then_navigates() {
    let (code, stdout, _stderr) = wafrift(&[
        "client-deliver",
        "--target",
        "https://t.test/",
        "--payload",
        "PAYLOAD_MARKER_42",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let wn = v["deliveries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["channel"] == "window_name")
        .expect("window_name delivery present");
    assert_eq!(wn["action"]["kind"], "set_window_name");
    assert_eq!(wn["action"]["value"], "PAYLOAD_MARKER_42");
    assert_eq!(wn["action"]["then_navigate"], "https://t.test/");
}

#[test]
fn max_flag_caps_the_number_of_deliveries() {
    let (code, stdout, _stderr) = wafrift(&[
        "client-deliver",
        "--target",
        "https://t.test/",
        "--max",
        "3",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let n = v["deliveries"].as_array().unwrap().len();
    assert!(n <= 3, "expected at most 3 deliveries, got {n}");
    assert_eq!(v["count"].as_u64().unwrap() as usize, n);
}

#[test]
fn zero_max_is_rejected_with_a_clear_error() {
    let (code, _stdout, stderr) = wafrift(&[
        "client-deliver",
        "--target",
        "https://t.test/",
        "--max",
        "0",
    ]);
    assert_eq!(code, 2, "--max 0 must be a usage error");
    assert!(
        stderr.to_lowercase().contains("max"),
        "error must mention --max: {stderr}"
    );
}

#[test]
fn markup_payload_covers_channels_without_prefix_bypass_noise() {
    let (code, stdout, _stderr) = wafrift(&[
        "client-deliver",
        "--target",
        "https://t.test/",
        "--payload",
        "<img src=x onerror=alert(1)>",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let deliveries = v["deliveries"].as_array().unwrap();
    // No scheme ⇒ the channel itself is the bypass; no prefix variants.
    assert!(
        !deliveries.iter().any(|d| d["rules"]
            .as_array()
            .is_some_and(|r| r.iter().any(|x| x == "prefix_bypass"))),
        "markup payload must not emit prefix-bypass deliveries:\n{stdout}"
    );
    // …but the fragment lane still carries the raw markup.
    assert!(
        deliveries.iter().any(|d| d["channel"] == "fragment"
            && d["action"]["url"] == "https://t.test/#<img src=x onerror=alert(1)>"),
        "fragment lane must carry the raw markup payload:\n{stdout}"
    );
}

#[test]
fn help_explains_the_waf_blind_client_side_purpose() {
    let (code, stdout, _stderr) = wafrift(&["client-deliver", "--help"]);
    assert_eq!(code, 0);
    let lc = stdout.to_lowercase();
    assert!(lc.contains("--target"), "help must document --target");
    assert!(lc.contains("--payload"), "help must document --payload");
    assert!(
        lc.contains("client")
            && (lc.contains("waf-blind") || lc.contains("dom") || lc.contains("fragment")),
        "help must convey the client-side / WAF-blind purpose:\n{stdout}"
    );
}
