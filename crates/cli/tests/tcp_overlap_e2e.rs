//! End-to-end dogfood of the shipped `wafrift tcp-overlap` binary.
//!
//! Drives the compiled binary's planning + both output formats. Sends nothing
//! (the planner is pure), so no mock server is needed — but every emitted plan is
//! self-verified by the crate, so a green result is a genuine reassembly split.

mod common;
use common::wafrift;

#[test]
fn enumerates_verified_policy_differentials_as_json() {
    let (code, stdout, stderr) = wafrift(&[
        "tcp-overlap",
        "--benign",
        "GET /safe",
        "--attack",
        "GET /evil",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "a differential must exist; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["schema"], "wafrift.tcp_overlap.v1");
    let diffs = v["differentials"].as_array().expect("differentials array");
    assert!(
        !diffs.is_empty(),
        "some policy pair must disagree: {stdout}"
    );
    for d in diffs {
        // The contract: WAF view is benign, origin view is attack, policies differ.
        assert_eq!(d["waf_view"], "GET /safe");
        assert_eq!(d["origin_view"], "GET /evil");
        assert_ne!(d["waf_policy"], d["origin_policy"]);
        // Two overlapping segments at the same sequence number.
        let segs = d["segments"].as_array().unwrap();
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0]["seq"], segs[1]["seq"]);
    }
}

#[test]
fn the_canonical_first_to_last_pair_is_present() {
    let (code, stdout, _e) = wafrift(&[
        "tcp-overlap",
        "--benign",
        "AAAA",
        "--attack",
        "BBBB",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let diffs = v["differentials"].as_array().unwrap();
    assert!(
        diffs
            .iter()
            .any(|d| d["waf_policy"] == "first" && d["origin_policy"] == "last"),
        "the canonical first→last evasion must appear: {stdout}"
    );
}

#[test]
fn a_specific_policy_pair_can_be_targeted() {
    let (code, stdout, _e) = wafrift(&[
        "tcp-overlap",
        "--benign",
        "safe",
        "--attack",
        "evil",
        "--waf-policy",
        "first",
        "--origin-policy",
        "last",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let diffs = v["differentials"].as_array().unwrap();
    assert_eq!(diffs.len(), 1, "exactly the requested pair");
    assert_eq!(diffs[0]["waf_policy"], "first");
    assert_eq!(diffs[0]["origin_policy"], "last");
}

#[test]
fn unequal_length_inputs_exit_4_with_explanation() {
    let (code, stdout, _e) =
        wafrift(&["tcp-overlap", "--benign", "short", "--attack", "muchlonger"]);
    assert_eq!(
        code, 4,
        "no clean full-overlap differential for unequal lengths"
    );
    assert!(
        stdout.to_lowercase().contains("equal length")
            || stdout.to_lowercase().contains("no differential"),
        "must explain why: {stdout}"
    );
}

#[test]
fn identical_policy_request_finds_no_differential() {
    let (code, _stdout, _e) = wafrift(&[
        "tcp-overlap",
        "--benign",
        "aaaa",
        "--attack",
        "bbbb",
        "--waf-policy",
        "first",
        "--origin-policy",
        "first",
    ]);
    assert_eq!(code, 4, "a stack cannot disagree with itself");
}

#[test]
fn help_explains_the_overlap_desync() {
    let (code, stdout, _e) = wafrift(&["tcp-overlap", "--help"]);
    assert_eq!(code, 0);
    let lc = stdout.to_lowercase();
    assert!(lc.contains("--benign") && lc.contains("--attack"));
    assert!(
        lc.contains("overlap") || lc.contains("reassembl"),
        "help must convey the overlap-reassembly purpose:\n{stdout}"
    );
}
