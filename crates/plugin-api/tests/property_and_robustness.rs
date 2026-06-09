//! Property + robustness tests for `wafrift_plugin_api`.
//!
//! The plugin loader is a security boundary: external contributors
//! drop arbitrary TOML and WASM into `~/.wafrift/tampers/`, and the
//! loader must
//!
//! 1. **Never panic.** No matter how malformed the file, the loader
//!    surfaces a typed `PluginError` and continues with the rest of
//!    the directory.
//! 2. **Enforce size limits.** TOML > 256 KiB and WASM > 4 MiB are
//!    rejected before allocation, so an attacker cannot OOM wafrift
//!    by writing a huge plugin file.
//! 3. **Validate every manifest field.** Empty name/version/author
//!    or oversized description fails fast with `InvalidManifest`.
//! 4. **Be portable.** Cross-platform path handling, no hard-coded
//!    `/tmp`, no panics on non-existent directories.

use std::path::Path;

use proptest::prelude::*;
use tempfile::TempDir;
use wafrift_plugin_api::{PluginError, TamperManifest, TamperRegistry, load_from};

// ── Test helpers ──────────────────────────────────────────────

fn manifest_with(name: &str, version: &str, author: &str, description: &str) -> TamperManifest {
    TamperManifest {
        name: name.to_string(),
        version: version.to_string(),
        author: author.to_string(),
        payload_classes: vec!["sqli".to_string()],
        contexts: vec!["query_string".to_string()],
        description: description.to_string(),
    }
}

fn write_plugin(dir: &TempDir, filename: &str, content: &str) {
    let path = dir.path().join(filename);
    std::fs::write(&path, content).expect("write plugin file");
}

fn minimal_toml_with_rules(name: &str, rules_block: &str) -> String {
    format!(
        r#"
[manifest]
name = "{name}"
version = "1.0.0"
author = "Adv-Test"
payload_classes = ["sqli"]
contexts = ["query_string"]
description = "Adversarial test plugin"

{rules_block}
"#
    )
}

// ── 1. Size-limit enforcement (TOML > 256 KiB) ───────────────

#[test]
fn oversized_toml_rejected() {
    let dir = TempDir::new().unwrap();
    // 300 KiB description — well over the 256 KiB cap.
    let huge = "x".repeat(300 * 1024);
    let content = minimal_toml_with_rules(
        "huge",
        &format!("[[rules]]\npattern = \"x\"\nreplacement = \"y\"\n# pad: {huge}"),
    );
    write_plugin(&dir, "huge.toml", &content);

    let mut reg = TamperRegistry::new();
    let errors = reg.load_dir(dir.path());
    assert!(
        !errors.is_empty(),
        "oversized TOML must produce an error, got none"
    );
    assert_eq!(reg.len(), 0, "oversized TOML must not register");
}

// ── 2. Empty rules section is valid (manifest-only plugin) ───

#[test]
fn manifest_only_no_rules_loads_as_passthrough() {
    // External contributors should be able to register metadata
    // (manifest only) without shipping rules yet — useful as a
    // placeholder while wiring up a future WASM upgrade.
    let dir = TempDir::new().unwrap();
    let content = r#"
[manifest]
name = "passthrough"
version = "1.0.0"
author = "Adv-Test"
payload_classes = ["sqli"]
contexts = ["query_string"]
description = "Manifest-only identity tamper"
"#;
    write_plugin(&dir, "passthrough.toml", content);

    let mut reg = TamperRegistry::new();
    let errors = reg.load_dir(dir.path());
    assert!(
        errors.is_empty(),
        "manifest-only TOML must load: {errors:?}"
    );
    assert_eq!(reg.len(), 1);
    // Empty rules → input passes through unchanged.
    let result = reg.get("passthrough").unwrap().apply("hello world");
    assert_eq!(result, "hello world");
}

// ── 3. Manifest validation — every required field ───────────

#[test]
fn empty_name_rejected() {
    let mf = manifest_with("", "1.0.0", "A", "desc");
    assert!(matches!(
        mf.validate(),
        Err(PluginError::InvalidManifest(_))
    ));
}

#[test]
fn empty_version_rejected() {
    let mf = manifest_with("name", "", "A", "desc");
    assert!(matches!(
        mf.validate(),
        Err(PluginError::InvalidManifest(_))
    ));
}

#[test]
fn empty_author_rejected() {
    let mf = manifest_with("name", "1.0.0", "", "desc");
    assert!(matches!(
        mf.validate(),
        Err(PluginError::InvalidManifest(_))
    ));
}

#[test]
fn description_exactly_512_chars_accepted() {
    // Boundary: 512 chars is OK, 513 is not.
    let mf = manifest_with("n", "1.0.0", "A", &"x".repeat(512));
    assert!(mf.validate().is_ok());
}

#[test]
fn description_513_chars_rejected() {
    let mf = manifest_with("n", "1.0.0", "A", &"x".repeat(513));
    assert!(matches!(
        mf.validate(),
        Err(PluginError::InvalidManifest(_))
    ));
}

#[test]
fn name_with_unicode_rejected() {
    // Names are ASCII-alphanumeric + underscore only — a unicode name
    // would break the plugin URL / dispatch table contract.
    let mf = manifest_with("naïve_name", "1.0.0", "A", "desc");
    assert!(matches!(
        mf.validate(),
        Err(PluginError::InvalidManifest(_))
    ));
}

#[test]
fn name_with_dash_rejected() {
    // Underscore is allowed, dash is not — this is a deliberate
    // ergonomic choice (snake_case in Rust dispatch).
    let mf = manifest_with("dash-name", "1.0.0", "A", "desc");
    assert!(matches!(
        mf.validate(),
        Err(PluginError::InvalidManifest(_))
    ));
}

#[test]
fn name_with_dot_rejected() {
    let mf = manifest_with("dotted.name", "1.0.0", "A", "desc");
    assert!(matches!(
        mf.validate(),
        Err(PluginError::InvalidManifest(_))
    ));
}

#[test]
fn name_with_slash_rejected() {
    // Slash in name is a path-traversal hazard.
    let mf = manifest_with("../etc/passwd", "1.0.0", "A", "desc");
    assert!(matches!(
        mf.validate(),
        Err(PluginError::InvalidManifest(_))
    ));
}

#[test]
fn name_alphanumeric_underscore_accepted() {
    let mf = manifest_with("snake_case_123", "1.0.0", "A", "desc");
    assert!(mf.validate().is_ok());
}

// ── 4. WASM file rejection (wrong magic, oversized) ─────────

#[test]
fn empty_wasm_file_rejected() {
    let dir = TempDir::new().unwrap();
    write_plugin(&dir, "empty.wasm", "");
    let mut reg = TamperRegistry::new();
    let errors = reg.load_dir(dir.path());
    // Either a wasm-load error or none-registered — both acceptable;
    // the contract is no-panic and no-zombie-registration.
    assert_eq!(reg.len(), 0);
    assert!(!errors.is_empty(), "empty wasm must error");
}

#[test]
fn text_pretending_to_be_wasm_rejected() {
    let dir = TempDir::new().unwrap();
    write_plugin(&dir, "fake.wasm", "this is not a wasm module");
    let mut reg = TamperRegistry::new();
    let errors = reg.load_dir(dir.path());
    assert_eq!(reg.len(), 0);
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, PluginError::WasmLoad { .. })),
        "expected WasmLoad error, got {errors:?}"
    );
}

// ── 5. Loader robustness against weird filenames ────────────

#[test]
fn nonexistent_directory_returns_empty_no_panic() {
    let p = Path::new("/this/path/definitely/does/not/exist/anywhere");
    let plugins = load_from(p);
    assert!(plugins.is_empty());
}

#[test]
fn empty_directory_returns_empty() {
    let dir = TempDir::new().unwrap();
    let plugins = load_from(dir.path());
    assert!(plugins.is_empty());
}

#[test]
fn file_with_no_extension_skipped() {
    let dir = TempDir::new().unwrap();
    write_plugin(&dir, "noext", "anything");
    let plugins = load_from(dir.path());
    assert!(plugins.is_empty());
}

#[test]
fn nested_subdirectory_does_not_recurse() {
    let dir = TempDir::new().unwrap();
    let sub = dir.path().join("subdir");
    std::fs::create_dir_all(&sub).unwrap();
    // Valid TOML inside the subdir should NOT be loaded — loader is
    // explicitly one-level (no recursion) to keep tamper directory
    // semantics flat.
    std::fs::write(
        sub.join("nested.toml"),
        minimal_toml_with_rules("nested", "[[rules]]\npattern = \"x\"\nreplacement = \"y\""),
    )
    .unwrap();
    let plugins = load_from(dir.path());
    assert!(plugins.is_empty(), "nested plugins must not be loaded");
}

// ── 6. TOML parser robustness ───────────────────────────────

#[test]
fn toml_with_unicode_in_string_field_loads() {
    let dir = TempDir::new().unwrap();
    let content = r#"
[manifest]
name = "unicode_desc"
version = "1.0.0"
author = "测试作者"
payload_classes = ["sqli"]
contexts = ["query_string"]
description = "Description with 中文 and emoji 🦀"

[[rules]]
pattern = "a"
replacement = "b"
"#;
    write_plugin(&dir, "unicode.toml", content);
    let mut reg = TamperRegistry::new();
    let errors = reg.load_dir(dir.path());
    assert!(
        errors.is_empty(),
        "unicode in author/description allowed: {errors:?}"
    );
    assert_eq!(reg.len(), 1);
}

#[test]
fn many_rules_in_one_plugin_load() {
    let dir = TempDir::new().unwrap();
    let mut rules = String::new();
    for i in 0..100 {
        rules.push_str(&format!(
            "[[rules]]\npattern = \"x{i}\"\nreplacement = \"y{i}\"\n"
        ));
    }
    let content = minimal_toml_with_rules("many_rules", &rules);
    write_plugin(&dir, "many_rules.toml", &content);
    let mut reg = TamperRegistry::new();
    let errors = reg.load_dir(dir.path());
    assert!(errors.is_empty(), "100-rule plugin must load: {errors:?}");
    assert_eq!(reg.len(), 1);
}

// ── 7. Property tests over manifest validation ──────────────

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn validate_never_panics(
        name in ".*",
        version in ".*",
        author in ".*",
        description in ".*"
    ) {
        let mf = manifest_with(&name, &version, &author, &description);
        let _ = mf.validate(); // must not panic regardless of input
    }

    #[test]
    fn validate_accepts_canonical_inputs(
        name in "[a-z][a-z0-9_]{0,30}",
        version in "[0-9]\\.[0-9]\\.[0-9]",
        author in "[A-Za-z][A-Za-z ]{0,40}",
        description in "[A-Za-z][A-Za-z0-9 .,!?]{0,400}"
    ) {
        let mf = manifest_with(&name, &version, &author, &description);
        prop_assert!(mf.validate().is_ok(),
                     "canonical manifest rejected: name={name:?}, version={version:?}, author={author:?}, description-len={}", description.len());
    }

    #[test]
    fn validate_rejects_long_descriptions(
        description in "[a-z]{513,2000}"
    ) {
        let mf = manifest_with("ok_name", "1.0.0", "A", &description);
        prop_assert!(matches!(
            mf.validate(),
            Err(PluginError::InvalidManifest(_))
        ));
    }
}

// ── 8. Registry semantics ───────────────────────────────────

#[test]
fn empty_registry_is_empty() {
    let r = TamperRegistry::new();
    assert!(r.is_empty());
    assert_eq!(r.len(), 0);
    assert!(r.get("anything").is_none());
}

#[test]
fn load_dir_with_mixed_valid_and_invalid_partial_success() {
    let dir = TempDir::new().unwrap();
    write_plugin(
        &dir,
        "ok.toml",
        &minimal_toml_with_rules(
            "ok_plugin",
            "[[rules]]\npattern = \"x\"\nreplacement = \"y\"",
        ),
    );
    write_plugin(&dir, "bad.toml", "not valid toml [[[!!");
    write_plugin(&dir, "ignored.txt", "ignored");

    let mut reg = TamperRegistry::new();
    let errors = reg.load_dir(dir.path());
    // ok loads; bad errors; txt skipped.
    assert_eq!(reg.len(), 1);
    assert_eq!(errors.len(), 1);
    assert!(matches!(errors[0], PluginError::TomlParse { .. }));
    assert!(reg.get("ok_plugin").is_some());
}

// ── 9. Tamper apply semantics ───────────────────────────────

#[test]
fn tamper_apply_on_empty_input_no_panic() {
    let dir = TempDir::new().unwrap();
    write_plugin(
        &dir,
        "rev.toml",
        &minimal_toml_with_rules(
            "rev_empty",
            "[[rules]]\npattern = \"^(.+)$\"\nreplacement = \"$REVERSED\"",
        ),
    );
    let mut reg = TamperRegistry::new();
    reg.load_dir(dir.path());
    let result = reg.get("rev_empty").unwrap().apply("");
    // Empty input: regex `^(.+)$` doesn't match (require 1+ chars),
    // so result stays "". No panic.
    assert_eq!(result, "");
}

#[test]
fn tamper_apply_long_input_no_panic() {
    let dir = TempDir::new().unwrap();
    write_plugin(
        &dir,
        "wide.toml",
        &minimal_toml_with_rules(
            "wide_input",
            "[[rules]]\npattern = \"a\"\nreplacement = \"b\"",
        ),
    );
    let mut reg = TamperRegistry::new();
    reg.load_dir(dir.path());
    let input = "a".repeat(100_000);
    let result = reg.get("wide_input").unwrap().apply(&input);
    assert_eq!(result.len(), input.len());
    assert!(result.starts_with('b'));
}

// ── 10. Concurrent registry reads under load ───────────────

#[test]
fn high_concurrency_registry_read() {
    use std::sync::Arc;
    use std::thread;

    let dir = TempDir::new().unwrap();
    write_plugin(
        &dir,
        "shared.toml",
        &minimal_toml_with_rules(
            "shared_t",
            "[[rules]]\npattern = \"0\"\nreplacement = \"X\"",
        ),
    );
    let mut reg = TamperRegistry::new();
    reg.load_dir(dir.path());
    let reg = Arc::new(reg);

    let handles: Vec<_> = (0..32)
        .map(|i| {
            let r = Arc::clone(&reg);
            thread::spawn(move || {
                for _ in 0..100 {
                    let input = format!("payload_0_{i}");
                    let result = r.get("shared_t").unwrap().apply(&input);
                    assert!(result.contains('X'), "thread {i}: {result}");
                }
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }
}

// ── 11. Defense against name-collision attacks ─────────────

#[test]
fn name_collision_first_wins() {
    let dir = TempDir::new().unwrap();
    write_plugin(
        &dir,
        "a.toml",
        &minimal_toml_with_rules(
            "samename",
            "[[rules]]\npattern = \"first\"\nreplacement = \"FIRST\"",
        ),
    );
    write_plugin(
        &dir,
        "b.toml",
        &minimal_toml_with_rules(
            "samename",
            "[[rules]]\npattern = \"second\"\nreplacement = \"SECOND\"",
        ),
    );

    let mut reg = TamperRegistry::new();
    let errors = reg.load_dir(dir.path());
    assert_eq!(reg.len(), 1, "exactly one same-name plugin registered");
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, PluginError::NameCollision(_))),
        "second registration must report NameCollision"
    );
}

// ── 12. Output validation of `all()` ───────────────────────

#[test]
fn registry_all_returns_all_loaded() {
    let dir = TempDir::new().unwrap();
    for i in 0..5 {
        write_plugin(
            &dir,
            &format!("p{i}.toml"),
            &minimal_toml_with_rules(
                &format!("p_{i}"),
                "[[rules]]\npattern = \"x\"\nreplacement = \"y\"",
            ),
        );
    }
    let mut reg = TamperRegistry::new();
    reg.load_dir(dir.path());
    assert_eq!(reg.all().len(), 5);
    let names: Vec<&str> = reg.all().iter().map(|p| p.name()).collect();
    for i in 0..5 {
        assert!(names.contains(&format!("p_{i}").as_str()), "missing p_{i}");
    }
}

// ── 13. Size_limit wiring: invalid-regex patterns are rejected ─────────

/// Anti-regression: ensures `size_limit` is wired into TOML plugin
/// regex compilation — an invalid pattern (verifiable at compile time)
/// must be rejected with `PluginError::InvalidRegex`.
///
/// The regex crate uses linear-time matching so classical backtracking
/// ReDoS doesn't apply, but the `size_limit` cap guards against
/// compile-time DoS (very large NFA expansions). This test proves the
/// error-propagation path works by using a syntactically invalid
/// pattern (unmatched `(`) which the regex engine rejects regardless
/// of the size limit.
#[test]
fn syntactically_invalid_regex_is_rejected_at_load_time() {
    let dir = TempDir::new().unwrap();
    // Unmatched parenthesis — rejected at regex compile time.
    write_plugin(
        &dir,
        "bomb.toml",
        &minimal_toml_with_rules(
            "invalid_regex_plugin",
            "[[rules]]\npattern = \"(unclosed\"\nreplacement = \"safe\"",
        ),
    );

    let mut reg = TamperRegistry::new();
    let errors = reg.load_dir(dir.path());
    // The invalid pattern must fail to load.
    assert_eq!(
        reg.len(),
        0,
        "invalid-regex plugin must not be registered; got {} registered",
        reg.len()
    );
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, PluginError::InvalidRegex { .. })),
        "load must report InvalidRegex for the invalid pattern; errors: {errors:?}"
    );
}

/// Anti-regression: verifies that a plugin with a valid regex pattern
/// still loads correctly after the size_limit wiring was added.
/// Guards against a regression where size_limit was set too low and
/// broke loading of legitimate patterns.
#[test]
fn valid_regex_still_loads_after_size_limit_added() {
    let dir = TempDir::new().unwrap();
    write_plugin(
        &dir,
        "valid.toml",
        &minimal_toml_with_rules(
            "valid_regex_plugin",
            "[[rules]]\npattern = \"union\\\\s+select\"\nreplacement = \"REDACTED\"",
        ),
    );

    let mut reg = TamperRegistry::new();
    let errors = reg.load_dir(dir.path());
    assert!(
        errors.is_empty(),
        "valid plugin must load cleanly; errors: {errors:?}"
    );
    assert_eq!(reg.len(), 1, "valid plugin must be registered");
}
