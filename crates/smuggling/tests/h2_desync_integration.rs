//! Integration coverage for `h2_evasion` frame/header builders (no network).
//! Exercises the public builders the smuggling crate exports for H2 downgrade
//! and desync probes.

use std::collections::HashSet;

use wafrift_smuggling::h2_evasion::{
    H2TargetFlaw, all_evasions, authority_host_mismatch, crlf_in_pseudo_headers,
    crlf_in_regular_header, crlf_request_smuggle, method_override, padding_configurations,
    split_header_to_continuation, split_path_across_frames,
};

#[test]
fn crlf_pseudo_header_builder_injects_crlf() {
    let evasion = crlf_in_pseudo_headers("/search", "X-Injected", "true").unwrap();
    let path = evasion
        .pseudo_headers
        .iter()
        .find(|(n, _)| n == ":path")
        .map(|(_, v)| v.as_str())
        .unwrap();
    assert!(path.contains("\r\n"));
    assert!(path.contains("X-Injected: true"));
    assert_eq!(evasion.target_flaw, H2TargetFlaw::ProtocolDowngrade);
}

#[test]
fn crlf_request_smuggle_builder_embeds_second_request() {
    let evasion = crlf_request_smuggle("/api/search", "/admin").unwrap();
    let path = evasion
        .pseudo_headers
        .iter()
        .find(|(n, _)| n == ":path")
        .map(|(_, v)| v.as_str())
        .unwrap();
    assert!(path.contains("GET /admin"));
    assert!(path.contains("Host:"));
}

#[test]
fn regular_header_crlf_builder_present() {
    let evasion = crlf_in_regular_header("user-agent", "Mozilla/5.0");
    let val = evasion
        .headers
        .iter()
        .find(|(n, _)| n == "user-agent")
        .map(|(_, v)| v.as_str())
        .unwrap();
    assert!(val.contains("\r\n"));
}

#[test]
fn authority_host_mismatch_builder_sets_both_hosts() {
    let evasion = authority_host_mismatch("safe.example.com", "malicious.internal");
    assert!(
        evasion
            .pseudo_headers
            .iter()
            .any(|(n, v)| n == ":authority" && v == "safe.example.com")
    );
    assert!(
        evasion
            .headers
            .iter()
            .any(|(n, v)| n == "host" && v == "malicious.internal")
    );
}

#[test]
fn continuation_split_builder_separates_payload_header() {
    let split = split_header_to_continuation("X-Payload", "malicious_value");
    assert!(!split.headers_frame.is_empty());
    assert!(!split.continuation_frames.is_empty());
    assert!(!split.headers_frame.iter().any(|(n, _)| n == "X-Payload"));
    assert!(
        split.continuation_frames[0]
            .iter()
            .any(|(n, _)| n == "X-Payload")
    );
}

#[test]
fn split_path_across_frames_reconstructs_path() {
    let path = "/admin/日本語/dashboard?action=delete";
    let split = split_path_across_frames(path);
    let first = split
        .headers_frame
        .iter()
        .find(|(n, _)| n == ":path")
        .map(|(_, v)| v.clone())
        .unwrap();
    let second = split.continuation_frames[0]
        .iter()
        .find(|(n, _)| n == ":path")
        .map(|(_, v)| v.clone())
        .unwrap();
    assert_eq!(format!("{first}{second}"), path);
}

#[test]
fn padding_configurations_has_expected_variants() {
    let configs = padding_configurations();
    assert!(configs.len() >= 4);
    assert!(configs.iter().any(|c| c.data_padding == 255));
    assert!(configs.iter().any(|c| c.inject_priority_frames));
}

#[test]
fn method_override_builder_sets_override_headers() {
    let evasion = method_override("/api", "example.com", "POST");
    assert_eq!(evasion.target_flaw, H2TargetFlaw::MethodOverride);
    assert!(
        evasion
            .headers
            .iter()
            .any(|(n, v)| n == "x-http-method-override" && v == "POST")
    );
    assert!(
        evasion
            .pseudo_headers
            .iter()
            .any(|(n, v)| n == ":method" && v == "GET")
    );
}

#[test]
fn all_evasions_catalog_covers_core_flaws() {
    let evasions = all_evasions("/api/v1/search", "example.com").unwrap();
    assert!(
        evasions.len() >= 20,
        "expected a large evasion catalog, got {}",
        evasions.len()
    );
    let flaws: HashSet<_> = evasions.iter().map(|e| e.target_flaw).collect();
    assert!(flaws.contains(&H2TargetFlaw::ProtocolDowngrade));
    assert!(flaws.contains(&H2TargetFlaw::PseudoHeaderMismatch));
    assert!(flaws.contains(&H2TargetFlaw::LaxHeaderValidation));
}
