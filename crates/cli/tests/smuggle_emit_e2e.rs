//! End-to-end tests for `wafrift smuggle-emit`.

mod common;
use common::wafrift;

#[test]
fn smuggle_emit_help_lists_family_flag() {
    let (code, stdout, _stderr) = wafrift(&["smuggle-emit", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("--family"), "stdout: {stdout}");
    assert!(stdout.contains("--payload"), "stdout: {stdout}");
    assert!(stdout.contains("--credential"), "stdout: {stdout}");
    assert!(stdout.contains("--cookie-name"), "stdout: {stdout}");
}

#[test]
fn smuggle_emit_default_emits_one_json_per_line_across_eleven_families() {
    let (code, stdout, stderr) = wafrift(&["smuggle-emit"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert!(
        lines.len() >= 78,
        "expected >=78 probes across 11 families, got {} lines",
        lines.len()
    );

    // Every line must parse as JSON with the documented shape.
    let mut families = std::collections::HashSet::new();
    for line in &lines {
        let v: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("non-JSON line {line:?}: {e}"));
        let tech = v["technique"]
            .as_str()
            .unwrap_or_else(|| panic!("technique missing: {line}"));
        let family = tech.split('.').next().unwrap_or("").to_string();
        families.insert(family);

        // Each line must carry a 16-char canary and a non-empty
        // description (the operator-visible surface).
        assert_eq!(
            v["canary"].as_str().unwrap_or("").len(),
            16,
            "canary must be 16 chars: {line}"
        );
        assert!(
            !v["description"].as_str().unwrap_or("").is_empty(),
            "description must be non-empty: {line}"
        );
        // Artifact must have a `kind` tag.
        assert!(
            v["artifact"]["kind"].is_string(),
            "artifact.kind must be a string: {line}"
        );
    }

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
            families.contains(required),
            "missing family {required:?} in output; got {families:?}"
        );
    }
}

#[test]
fn smuggle_emit_family_filter_restricts_output() {
    let (code, stdout, _stderr) = wafrift(&["smuggle-emit", "--family", "cookie"]);
    assert_eq!(code, 0);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert!(!lines.is_empty(), "cookie filter must produce >=1 probe");
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).expect("JSON parse");
        let tech = v["technique"].as_str().expect("technique str");
        assert!(
            tech.starts_with("cookie."),
            "technique {tech:?} does not match cookie family filter"
        );
    }
}

#[test]
fn smuggle_emit_unknown_family_filter_exits_2() {
    let (code, _stdout, stderr) = wafrift(&["smuggle-emit", "--family", "nonexistent-family-xyz"]);
    assert_eq!(code, 2, "exit 2 signals zero-match family filter");
    assert!(
        stderr.contains("matched zero probes"),
        "stderr must explain why: {stderr}"
    );
}

#[test]
fn smuggle_emit_canaries_unique_across_full_sweep() {
    let (code, stdout, _stderr) = wafrift(&["smuggle-emit"]);
    assert_eq!(code, 0);
    let canaries: std::collections::HashSet<String> = stdout
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            v["canary"].as_str().unwrap().to_string()
        })
        .collect();
    let total = stdout.lines().filter(|l| !l.is_empty()).count();
    assert_eq!(
        canaries.len(),
        total,
        "every probe must carry a distinct canary across the full sweep"
    );
}

#[test]
fn smuggle_emit_pretty_flag_produces_multi_line_json_objects() {
    let (code, stdout, _stderr) = wafrift(&["smuggle-emit", "--family", "cookie", "--pretty"]);
    assert_eq!(code, 0);
    // Pretty JSON has nested-object indentation; at least one
    // line must START with whitespace (field indent).
    assert!(
        stdout
            .lines()
            .any(|l| l.starts_with("  \"") || l.starts_with("    \"")),
        "pretty flag must produce indented JSON; got: {stdout}"
    );
}

#[test]
fn smuggle_emit_kind_filter_headers_keeps_only_header_artifacts() {
    let (code, stdout, _stderr) = wafrift(&["smuggle-emit", "--kind", "headers"]);
    assert_eq!(code, 0);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert!(!lines.is_empty(), "headers kind filter must keep >=1 probe");
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).expect("JSON");
        assert_eq!(
            v["artifact"]["kind"].as_str().unwrap(),
            "headers",
            "non-headers artifact slipped past --kind filter: {line}"
        );
    }
}

#[test]
fn smuggle_emit_kind_filter_body_keeps_only_body_artifacts() {
    let (code, stdout, _stderr) = wafrift(&["smuggle-emit", "--kind", "body"]);
    assert_eq!(code, 0);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert!(!lines.is_empty(), "body kind filter must keep >=1 probe");
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).expect("JSON");
        assert_eq!(
            v["artifact"]["kind"].as_str().unwrap(),
            "body_with_content_type",
            "non-body artifact slipped past --kind filter: {line}"
        );
    }
}

#[test]
fn smuggle_emit_kind_filter_frames_keeps_only_frame_artifacts() {
    let (code, stdout, _stderr) = wafrift(&["smuggle-emit", "--kind", "frames"]);
    assert_eq!(code, 0);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert!(!lines.is_empty(), "frames kind filter must keep >=1 probe");
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).expect("JSON");
        assert_eq!(
            v["artifact"]["kind"].as_str().unwrap(),
            "frames",
            "non-frames artifact slipped past --kind filter: {line}"
        );
    }
}

#[test]
fn smuggle_emit_curl_target_mode_emits_curl_commands() {
    let (code, stdout, _stderr) = wafrift(&[
        "smuggle-emit",
        "--family",
        "cookie",
        "--curl-target",
        "https://example.com/admin",
    ]);
    assert_eq!(code, 0);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert!(!lines.is_empty());
    for line in &lines {
        assert!(
            line.starts_with("curl -X "),
            "expected curl command: {line}"
        );
        assert!(line.contains("https://example.com/admin"));
        // Cookie probes always carry a Cookie header.
        assert!(
            line.contains("-H 'Cookie:"),
            "missing Cookie header: {line}"
        );
    }
}

#[test]
fn smuggle_emit_curl_target_mode_renders_body_probes_as_post() {
    let (code, stdout, _stderr) = wafrift(&[
        "smuggle-emit",
        "--family",
        "content-type",
        "--curl-target",
        "https://example.com/admin",
    ]);
    assert_eq!(code, 0);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert!(!lines.is_empty());
    for line in &lines {
        assert!(
            line.starts_with("curl -X POST "),
            "body probes -> POST: {line}"
        );
        assert!(line.contains("--data-binary"));
        assert!(line.contains("Content-Type:"));
    }
}

#[test]
fn smuggle_emit_curl_target_skips_frame_artifacts_with_stderr_warning() {
    let (code, stdout, stderr) = wafrift(&[
        "smuggle-emit",
        "--family",
        "capsule",
        "--curl-target",
        "https://example.com/admin",
    ]);
    // capsule produces Frames only, so stdout is empty after curl
    // mode skips every probe — exit code is 2 (zero match).
    assert_eq!(code, 2);
    assert!(
        stdout.lines().filter(|l| !l.is_empty()).count() == 0,
        "stdout must be empty"
    );
    assert!(
        stderr.contains("frame artifacts can't ride curl"),
        "stderr must explain why: {stderr}"
    );
}

#[test]
fn smuggle_emit_curl_target_body_probes_render_as_single_line_per_probe() {
    // Anti-rig: body probes contain multipart bodies with embedded
    // newlines. Without ANSI-C-style escaping (`$'...'`), each
    // body's newline would split the curl command across multiple
    // stdout lines and operators piping to `bash` would only see
    // fragments. Pin: stdout.lines() count must equal probe count.
    let (code, stdout, _stderr) = wafrift(&[
        "smuggle-emit",
        "--family",
        "content-type",
        "--curl-target",
        "https://example.com/admin",
    ]);
    assert_eq!(code, 0);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert!(!lines.is_empty());
    for line in &lines {
        assert!(
            line.starts_with("curl -X "),
            "every output line must be a complete curl command: {line:?}"
        );
        assert!(
            line.contains("$'"),
            "body must use ANSI-C `$'...'` quoting: {line:?}"
        );
    }
}

#[test]
fn smuggle_emit_curl_target_propagates_canary_header() {
    let (code, stdout, _stderr) = wafrift(&[
        "smuggle-emit",
        "--family",
        "cookie",
        "--curl-target",
        "https://example.com/admin",
        "--canary-header",
        "X-Wafrift-Canary",
    ]);
    assert_eq!(code, 0);
    for line in stdout.lines().filter(|l| !l.is_empty()) {
        assert!(
            line.contains("-H 'X-Wafrift-Canary:"),
            "canary header missing from curl: {line}"
        );
    }
}

#[test]
fn smuggle_emit_sort_by_bytes_asc_orders_smallest_first() {
    let (code, stdout, _stderr) = wafrift(&[
        "smuggle-emit",
        "--family",
        "cookie",
        "--sort-by-bytes",
        "asc",
    ]);
    assert_eq!(code, 0);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert!(lines.len() >= 2);
    // Compute wire-byte size per emitted artifact (header pairs:
    // "name: value\r\n" per pair) and assert non-decreasing.
    let sizes: Vec<usize> = lines
        .iter()
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            let headers = v["artifact"]["value"].as_array().unwrap();
            headers
                .iter()
                .map(|h| {
                    let pair = h.as_array().unwrap();
                    pair[0].as_str().unwrap().len() + pair[1].as_str().unwrap().len() + 4 // ": " + CRLF
                })
                .sum()
        })
        .collect();
    let mut prev = 0;
    for s in &sizes {
        assert!(*s >= prev, "asc must be non-decreasing: {sizes:?}");
        prev = *s;
    }
}

#[test]
fn smuggle_emit_sort_by_bytes_desc_orders_largest_first() {
    let (code, stdout, _stderr) = wafrift(&[
        "smuggle-emit",
        "--family",
        "cookie",
        "--sort-by-bytes",
        "desc",
    ]);
    assert_eq!(code, 0);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    let sizes: Vec<usize> = lines
        .iter()
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            let headers = v["artifact"]["value"].as_array().unwrap();
            headers
                .iter()
                .map(|h| {
                    let pair = h.as_array().unwrap();
                    pair[0].as_str().unwrap().len() + pair[1].as_str().unwrap().len() + 4
                })
                .sum()
        })
        .collect();
    let mut prev = usize::MAX;
    for s in &sizes {
        assert!(*s <= prev, "desc must be non-increasing: {sizes:?}");
        prev = *s;
    }
}

#[test]
fn smuggle_emit_limit_flag_caps_output_count() {
    let (code, stdout, _stderr) = wafrift(&["smuggle-emit", "--limit", "5"]);
    assert_eq!(code, 0);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert!(
        lines.len() <= 5,
        "--limit 5 must cap output; got {}",
        lines.len()
    );
    assert!(!lines.is_empty(), "--limit 5 must emit at least 1");
}

#[test]
fn smuggle_emit_limit_zero_means_unlimited() {
    let (code, stdout, _stderr) = wafrift(&["smuggle-emit", "--limit", "0"]);
    assert_eq!(code, 0);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    // 0 = no cap = full corpus.
    assert!(
        lines.len() >= 60,
        "limit=0 must emit full corpus, got {}",
        lines.len()
    );
}

#[test]
fn smuggle_emit_canary_header_flag_populates_extra_headers() {
    let (code, stdout, _stderr) = wafrift(&[
        "smuggle-emit",
        "--family",
        "cookie",
        "--canary-header",
        "X-Wafrift-Canary",
    ]);
    assert_eq!(code, 0);
    let line = stdout.lines().find(|l| !l.is_empty()).expect("at least 1");
    let v: serde_json::Value = serde_json::from_str(line).expect("JSON");
    let extras = v["extra_headers"].as_array().expect("extra_headers array");
    assert_eq!(extras.len(), 1, "exactly one extra header pair");
    let pair = extras[0].as_array().expect("pair array");
    assert_eq!(pair[0].as_str(), Some("X-Wafrift-Canary"));
    // The value must be the same as the top-level canary.
    let token = v["canary"].as_str().expect("canary str");
    assert_eq!(pair[1].as_str(), Some(token));
}

#[test]
fn smuggle_emit_without_canary_header_flag_omits_extra_headers() {
    // Anti-rig: skip_serializing_if = Vec::is_empty must hold —
    // operators that don't ask for extra_headers must not see the
    // field in the JSON.
    let (code, stdout, _stderr) = wafrift(&["smuggle-emit", "--family", "cookie"]);
    assert_eq!(code, 0);
    for line in stdout.lines().filter(|l| !l.is_empty()) {
        assert!(
            !line.contains("\"extra_headers\""),
            "extra_headers must not appear when --canary-header is unset: {line}"
        );
    }
}

#[test]
fn smuggle_emit_custom_credential_appears_in_some_probe_value() {
    // The custom credential bytes must end up in at least one
    // header value somewhere in the output (cookie / auth families
    // splice it into their probes).
    let token = "uniqcred-zxc-9384719";
    let (code, stdout, _stderr) =
        wafrift(&["smuggle-emit", "--family", "cookie", "--credential", token]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains(token),
        "custom credential {token:?} must appear in output; got: {stdout}"
    );
}
