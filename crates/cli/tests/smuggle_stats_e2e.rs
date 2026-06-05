//! End-to-end tests for `wafrift smuggle-stats`.

mod common;
use common::wafrift;

#[test]
fn smuggle_stats_emits_top_level_summary_fields() {
    let (code, stdout, stderr) = wafrift(&["smuggle-stats"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON");
    // Every documented field must be present.
    assert!(v["total_probes"].is_u64(), "total_probes missing");
    assert!(v["per_family"].is_object(), "per_family missing");
    assert!(v["per_kind"].is_object(), "per_kind missing");
    assert!(v["total_wire_bytes"].is_u64(), "total_wire_bytes missing");
    assert!(v["avg_wire_bytes"].is_u64(), "avg_wire_bytes missing");
    assert!(v["max_wire_bytes"].is_u64(), "max_wire_bytes missing");
    assert!(v["max_technique"].is_string(), "max_technique missing");
}

#[test]
fn smuggle_stats_total_probes_matches_per_family_sum() {
    let (code, stdout, _stderr) = wafrift(&["smuggle-stats"]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON");
    let total = v["total_probes"].as_u64().unwrap();
    let per_family_sum: u64 = v["per_family"]
        .as_object()
        .unwrap()
        .values()
        .map(|x| x.as_u64().unwrap())
        .sum();
    assert_eq!(total, per_family_sum, "total != sum(per_family)");
}

#[test]
fn smuggle_stats_per_kind_sums_to_total_probes() {
    let (code, stdout, _stderr) = wafrift(&["smuggle-stats"]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON");
    let total = v["total_probes"].as_u64().unwrap();
    let per_kind_sum: u64 = v["per_kind"]
        .as_object()
        .unwrap()
        .values()
        .map(|x| x.as_u64().unwrap())
        .sum();
    assert_eq!(total, per_kind_sum, "total != sum(per_kind)");
}

#[test]
fn smuggle_stats_includes_all_eleven_families() {
    let (code, stdout, _stderr) = wafrift(&["smuggle-stats"]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON");
    let families = v["per_family"].as_object().unwrap();
    for required in [
        "cookie",
        "auth",
        "range",
        "path",
        "host",
        "jwt",
        "content-type",
        "json",
        "capsule",
        "quic-datagram",
        "compression",
    ] {
        assert!(
            families.contains_key(required),
            "missing family {required} in stats: {families:?}"
        );
        assert!(
            families[required].as_u64().unwrap() > 0,
            "family {required} has zero probes"
        );
    }
}

#[test]
fn smuggle_stats_per_kind_covers_headers_body_frames() {
    let (code, stdout, _stderr) = wafrift(&["smuggle-stats"]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON");
    let kinds = v["per_kind"].as_object().unwrap();
    for required in ["headers", "body", "frames"] {
        assert!(kinds.contains_key(required), "missing kind {required}");
        assert!(kinds[required].as_u64().unwrap() > 0);
    }
}

#[test]
fn smuggle_stats_avg_bytes_equals_total_over_count() {
    let (code, stdout, _stderr) = wafrift(&["smuggle-stats"]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON");
    let total = v["total_probes"].as_u64().unwrap();
    let total_bytes = v["total_wire_bytes"].as_u64().unwrap();
    let avg = v["avg_wire_bytes"].as_u64().unwrap();
    assert_eq!(avg, total_bytes / total, "avg miscomputed");
}

#[test]
fn smuggle_stats_max_technique_is_non_empty_and_dot_qualified() {
    let (code, stdout, _stderr) = wafrift(&["smuggle-stats"]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON");
    let tech = v["max_technique"].as_str().unwrap();
    assert!(!tech.is_empty());
    assert!(
        tech.contains('.'),
        "max_technique must be family.variant: {tech}"
    );
}

#[test]
fn smuggle_stats_pretty_flag_produces_indented_json() {
    let (code, stdout, _stderr) = wafrift(&["smuggle-stats", "--pretty"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains('\n'),
        "pretty output must span multiple lines"
    );
    assert!(stdout.contains("  "), "pretty output must be indented");
}

#[test]
fn smuggle_stats_help_lists_seed_flags() {
    let (code, stdout, _stderr) = wafrift(&["smuggle-stats", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("--cookie-name"));
    assert!(stdout.contains("--credential"));
    assert!(stdout.contains("--payload"));
    assert!(stdout.contains("--protected-path"));
    assert!(stdout.contains("--pretty"));
}

#[test]
fn smuggle_stats_family_filter_restricts_output_to_single_family() {
    let (code, stdout, _stderr) = wafrift(&["smuggle-stats", "--family", "cookie"]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON");
    let families = v["per_family"].as_object().unwrap();
    // With --family cookie, only the cookie family remains in
    // per_family.
    assert_eq!(families.len(), 1, "expected one family entry: {families:?}");
    assert!(families.contains_key("cookie"));
    // total_probes equals the per-family count.
    let total = v["total_probes"].as_u64().unwrap();
    assert_eq!(total, families["cookie"].as_u64().unwrap());
    // max_technique starts with cookie.*
    assert!(
        v["max_technique"].as_str().unwrap().starts_with("cookie."),
        "max_technique must be in cookie family: {}",
        v["max_technique"]
    );
}

#[test]
fn smuggle_stats_unknown_family_filter_exits_2() {
    let (code, _stdout, stderr) = wafrift(&["smuggle-stats", "--family", "nonexistent-family-xyz"]);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("matched zero probes"),
        "stderr must explain: {stderr}"
    );
}

#[test]
fn smuggle_stats_total_probes_meets_minimum_floor() {
    // Anti-rig: pin a lower bound on total probes so a regression
    // that silently drops a family surfaces here.
    let (code, stdout, _stderr) = wafrift(&["smuggle-stats"]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON");
    let total = v["total_probes"].as_u64().unwrap();
    assert!(total >= 78, "expected >=78 total probes, got {total}");
}
