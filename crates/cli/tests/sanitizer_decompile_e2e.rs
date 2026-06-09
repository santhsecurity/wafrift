//! End-to-end dogfood of the shipped `wafrift sanitizer-decompile` binary.
//!
//! Drives the full operator path through the compiled binary: source-map
//! recovery, sanitizer extraction, L*/SFA mining, and both output formats —
//! against fixtures that exercise a bypassable config, a strict config, and a
//! file with no sanitizer. Sends nothing (the sanitizer oracle is in-process),
//! so no mock server is needed.

mod common;
use common::wafrift;

/// Write `content` to a uniquely-named temp file and return its path.
fn temp_file(tag: &str, content: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "wafrift_sanitizer_{}_{}.tmp",
        tag,
        std::process::id()
    ));
    std::fs::write(&path, content).expect("write temp fixture");
    path
}

/// A source map whose `sourcesContent` carries a DOMPurify config that forbids
/// `<script>` but does NOT strip event handlers — so `<svg onload=>` survives.
fn bypassable_source_map() -> String {
    let sanitizer_src = r#"
        import DOMPurify from 'dompurify';
        export function clean(dirty) {
            return DOMPurify.sanitize(dirty, { FORBID_TAGS: ['script', 'style'] });
        }
    "#;
    serde_json::json!({
        "version": 3,
        "sources": ["src/sanitize.js"],
        "sourcesContent": [sanitizer_src],
        "names": [],
        "mappings": ""
    })
    .to_string()
}

#[test]
fn decompiles_bypassable_dompurify_and_mines_a_surviving_vector() {
    let map = temp_file("bypassable_map", &bypassable_source_map());
    let (code, stdout, stderr) = wafrift(&[
        "sanitizer-decompile",
        "--source-map",
        map.to_str().unwrap(),
        "--format",
        "json",
    ]);
    let _ = std::fs::remove_file(&map);
    assert_eq!(
        code, 0,
        "a bypassable sanitizer must exit 0; stderr={stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["schema"], "wafrift.sanitizer_decompile.v1");
    assert_eq!(v["sanitizer_detected"], true);
    assert_eq!(v["model"]["kind"], "dompurify");
    assert!(
        v["model"]["forbidden_tags"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t == "script"),
        "FORBID_TAGS must be recovered: {stdout}"
    );
    let bypasses = v["bypasses"].as_array().expect("bypasses array");
    assert!(
        !bypasses.is_empty(),
        "a handler-leaking config must yield a bypass: {stdout}"
    );
    // Every reported bypass must be self-described as surviving + carry a vector.
    for b in bypasses {
        assert_eq!(b["survives_executable"], true);
        assert!(b["vector"].is_string());
    }
    // The learner must actually have run (membership queries spent).
    assert!(v["membership_queries"].as_u64().unwrap() > 0);
}

#[test]
fn bypassable_config_also_flags_reachable_mxss_candidates() {
    // The bypassable fixture forbids only `script` and `style`, leaving foreign
    // roots (`svg`, `math`) and their re-parse children reachable — so the
    // decompiler must surface mXSS candidates (which the in-model executability
    // check cannot prove) AND must never flag a pair touching the forbidden
    // `style` tag.
    let map = temp_file("mxss_map", &bypassable_source_map());
    let (code, stdout, stderr) = wafrift(&[
        "sanitizer-decompile",
        "--source-map",
        map.to_str().unwrap(),
        "--format",
        "json",
    ]);
    let _ = std::fs::remove_file(&map);
    assert_eq!(code, 0, "stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let mxss = v["mxss_candidates"]
        .as_array()
        .expect("mxss_candidates array");
    assert!(
        !mxss.is_empty(),
        "a config forbidding only script/style is mXSS-exposed: {stdout}"
    );
    for c in mxss {
        assert!(c["root"].is_string() && c["child"].is_string() && c["class"].is_string());
        assert_ne!(
            c["root"], "style",
            "a forbidden tag must not be a reachable mXSS root"
        );
        assert_ne!(
            c["child"], "style",
            "a forbidden tag must not be a reachable mXSS child"
        );
    }
}

#[test]
fn strict_config_has_no_mxss_candidates() {
    // A DOMPurify ALLOWED_TAGS allowlist of only inert tags makes every
    // foreign-content root unreachable, so the mXSS advisory must be empty —
    // precise, not noise. (Uses DOMPurify's own key so the allowlist is parsed.)
    let js = temp_file(
        "mxss_strict_js",
        r#"DOMPurify.sanitize(x, { ALLOWED_TAGS: ['b','i','em','p'] });"#,
    );
    let (code, stdout, _e) = wafrift(&[
        "sanitizer-decompile",
        "--js",
        js.to_str().unwrap(),
        "--format",
        "json",
    ]);
    let _ = std::fs::remove_file(&js);
    // Exit may be 0 or 4 depending on handler-strip; we only assert the mXSS set.
    assert!(code == 0 || code == 4, "unexpected exit {code}: {stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert!(
        v["mxss_candidates"].as_array().expect("array").is_empty(),
        "a tight allowlist must yield no mXSS candidates: {stdout}"
    );
}

#[test]
fn raw_js_input_path_works_too() {
    let js = temp_file(
        "raw_js",
        "const s = DOMPurify.sanitize(x, { FORBID_TAGS: ['script'] });",
    );
    let (code, stdout, _stderr) = wafrift(&[
        "sanitizer-decompile",
        "--js",
        js.to_str().unwrap(),
        "--format",
        "json",
    ]);
    let _ = std::fs::remove_file(&js);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["model"]["kind"], "dompurify");
}

#[test]
fn strict_sanitizer_reports_no_bypass_with_exit_4() {
    // Allowlist only inert tags AND forbid the dangerous ones — model-proven safe.
    let js = temp_file(
        "strict_js",
        r#"sanitizeHtml(x, { allowedTags: ['b','i','em','p'] });
           DOMPurify.sanitize(x, { FORBID_TAGS: ['script','svg','img','iframe','math','a'] });
           html = html.replace(/\son\w+=("[^"]*"|'[^']*'|[^\s>]*)/gi, '');"#,
    );
    let (code, stdout, _stderr) = wafrift(&[
        "sanitizer-decompile",
        "--js",
        js.to_str().unwrap(),
        "--format",
        "json",
    ]);
    let _ = std::fs::remove_file(&js);
    assert_eq!(
        code, 4,
        "a strict sanitizer with no bypass must exit 4: {stdout}"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert!(v["bypasses"].as_array().unwrap().is_empty());
}

#[test]
fn no_sanitizer_in_source_exits_6() {
    let js = temp_file("nosan_js", "function add(a, b) { return a + b; }");
    let (code, stdout, _stderr) = wafrift(&[
        "sanitizer-decompile",
        "--js",
        js.to_str().unwrap(),
        "--format",
        "json",
    ]);
    let _ = std::fs::remove_file(&js);
    assert_eq!(code, 6, "no sanitizer must exit 6 (nothing to decompile)");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["sanitizer_detected"], false);
}

#[test]
fn source_map_without_embedded_content_is_a_clear_error() {
    // version 3 but no sourcesContent → nothing to decompile → exit 2 with a
    // helpful message (not a silent empty success).
    let map = temp_file(
        "no_content_map",
        r#"{"version":3,"sources":["a.js"],"names":[],"mappings":"AAAA"}"#,
    );
    let (code, _stdout, stderr) =
        wafrift(&["sanitizer-decompile", "--source-map", map.to_str().unwrap()]);
    let _ = std::fs::remove_file(&map);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("sourcesContent") || stderr.to_lowercase().contains("no embedded"),
        "error must explain the missing embedded content: {stderr}"
    );
}

#[test]
fn requires_exactly_one_input_source() {
    let (code, _stdout, stderr) = wafrift(&["sanitizer-decompile"]);
    assert_eq!(code, 2, "missing input must be a usage error");
    assert!(
        stderr.to_lowercase().contains("source-map") || stderr.to_lowercase().contains("js"),
        "error must name the required flags: {stderr}"
    );

    let (code2, _o, _e) = wafrift(&[
        "sanitizer-decompile",
        "--source-map",
        "/nonexistent.map",
        "--js",
        "/nonexistent.js",
    ]);
    assert_ne!(code2, 0, "supplying both inputs must fail (clap conflict)");
}

#[test]
fn help_explains_the_client_sanitizer_decompiler() {
    let (code, stdout, _stderr) = wafrift(&["sanitizer-decompile", "--help"]);
    assert_eq!(code, 0);
    let lc = stdout.to_lowercase();
    assert!(lc.contains("--source-map"));
    assert!(lc.contains("--js"));
    assert!(
        lc.contains("sanitizer") && (lc.contains("client") || lc.contains("dom")),
        "help must convey the client sanitizer decompiler purpose:\n{stdout}"
    );
}
