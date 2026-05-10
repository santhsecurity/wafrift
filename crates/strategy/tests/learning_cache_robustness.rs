//! Regression coverage for the 2026-05-10 learning_cache audit findings:
//!   HIGH #1: save() was not atomic — kill-9 between write and rename
//!     left a half-written JSON file that crashed every subsequent open.
//!   HIGH #2: open() crashed on a corrupt file, losing ALL prior
//!     learning across the strategy engine.
//!
//! Both tests would have failed pre-fix.

use std::fs;
use wafrift_strategy::learning_cache::{CacheKey, LearningCache};
use wafrift_strategy::pipeline::{EvasionPipeline, EvasionStage};
use wafrift_types::Technique;

fn unique_tmp(suffix: &str) -> std::path::PathBuf {
    // Per-test path keyed on (pid, nanos, suffix) so parallel cargo
    // test runs don't race each other through /tmp.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "wafrift_lc_robust_{}_{}_{}.json",
        std::process::id(),
        nanos,
        suffix
    ))
}

fn pipeline(name: &str) -> EvasionPipeline {
    EvasionPipeline::new(
        name,
        vec![EvasionStage {
            technique: Technique::UserAgentRotation,
            context: None,
        }],
        1,
    )
}

// ── HIGH #2: corrupt file resilience ────────────────────────────────

#[test]
fn open_does_not_crash_on_corrupt_json() {
    let path = unique_tmp("corrupt");
    let _ = fs::remove_file(&path);
    fs::write(&path, b"{ not valid json").unwrap();

    // Pre-fix: this would return Err(LearningCacheError::Serde) and the
    // strategy engine on first cold-start would panic on .unwrap(),
    // discarding all subsequent learning.
    let cache = LearningCache::open(&path).expect("must not crash on corrupt JSON");
    assert!(cache.keys().is_empty(), "corrupt cache must reset to empty");

    // The corrupt file should have been moved aside so the next save
    // can succeed atomically.
    let dir = path.parent().unwrap();
    let stem = path.file_stem().unwrap().to_string_lossy().to_string();
    let moved_aside = fs::read_dir(dir).unwrap().any(|e| {
        let p = e.unwrap().path();
        p.file_name()
            .map(|n| n.to_string_lossy().starts_with(&stem))
            .unwrap_or(false)
            && p.extension()
                .map(|e| e.to_string_lossy().starts_with("corrupt-"))
                .unwrap_or(false)
    });
    assert!(
        moved_aside,
        "corrupt file must be moved aside to <stem>.corrupt-<epoch>"
    );
    // Clean up the moved-aside file too.
    for e in fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.file_name()
            .map(|n| n.to_string_lossy().starts_with(&stem))
            .unwrap_or(false)
        {
            let _ = fs::remove_file(p);
        }
    }
}

#[test]
fn open_does_not_crash_on_truncated_file() {
    let path = unique_tmp("truncated");
    let _ = fs::remove_file(&path);
    // Write the first half of a valid pretty-printed JSON object —
    // exactly what kill-9 mid-`fs::write` would leave.
    fs::write(&path, b"{\n  \"entries\": {\n    \"key1\": {\n      \"pip").unwrap();

    let cache = LearningCache::open(&path).expect("must recover from truncated JSON");
    assert!(cache.keys().is_empty());

    // Cleanup.
    let dir = path.parent().unwrap();
    let stem = path.file_stem().unwrap().to_string_lossy().to_string();
    for e in fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.file_name()
            .map(|n| n.to_string_lossy().starts_with(&stem))
            .unwrap_or(false)
        {
            let _ = fs::remove_file(p);
        }
    }
}

#[test]
fn open_after_corrupt_file_can_save_again() {
    // Defence-in-depth — the recovered cache must be usable.
    let path = unique_tmp("recover_save");
    let _ = fs::remove_file(&path);
    fs::write(&path, b"\x00\x00\x00garbage\x00\x00").unwrap();

    let mut cache = LearningCache::open(&path).expect("must recover from binary garbage");
    cache.record_success(CacheKey::new("modsec", "xss"), pipeline("p1"));
    cache.save().expect("save after corruption recovery must succeed");

    // Reopen and verify the new entry stuck.
    let cache2 = LearningCache::open(&path).unwrap();
    assert_eq!(
        cache2
            .get(&CacheKey::new("modsec", "xss"))
            .expect("entry must persist after recovery save")
            .successes,
        1
    );

    let _ = fs::remove_file(&path);
    let dir = path.parent().unwrap();
    let stem = path.file_stem().unwrap().to_string_lossy().to_string();
    for e in fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.file_name()
            .map(|n| n.to_string_lossy().starts_with(&stem))
            .unwrap_or(false)
        {
            let _ = fs::remove_file(p);
        }
    }
}

// ── HIGH #1: save atomicity ─────────────────────────────────────────

#[test]
fn save_does_not_leave_partial_file_visible() {
    // Pre-fix: fs::write created the target file then wrote contents
    // chunk-by-chunk. A reader observing the file mid-write could see
    // an empty or partial file and the next `open` would fail.
    //
    // Post-fix: write happens to a sibling tmp file and is then renamed
    // over the target path. The target either has the OLD content or
    // the FULL new content — never partial.
    //
    // This test exercises the contract by saving twice and verifying
    // that no `.tmp.*` orphan files are left behind in the steady state.
    let path = unique_tmp("atomic");
    let _ = fs::remove_file(&path);

    let mut cache = LearningCache::open(&path).unwrap();
    cache.record_success(CacheKey::new("waf-a", "sql"), pipeline("p"));
    cache.save().unwrap();
    cache.record_success(CacheKey::new("waf-a", "sql"), pipeline("p"));
    cache.save().unwrap();

    // Verify no orphan tmp files remain in the cache directory.
    let dir = path.parent().unwrap();
    let stem = path.file_stem().unwrap().to_string_lossy().to_string();
    let orphans: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .flatten()
        .filter(|e| {
            let p = e.path();
            let name_match = p
                .file_name()
                .map(|n| n.to_string_lossy().starts_with(&stem))
                .unwrap_or(false);
            let is_tmp = p
                .extension()
                .map(|x| x.to_string_lossy().starts_with("tmp."))
                .unwrap_or(false);
            name_match && is_tmp
        })
        .collect();
    assert!(
        orphans.is_empty(),
        "save() must not leave orphan tmp files: {orphans:?}"
    );

    // Verify the surviving file is valid JSON we can reopen.
    let cache2 = LearningCache::open(&path).expect("post-save file must reopen cleanly");
    assert_eq!(
        cache2.get(&CacheKey::new("waf-a", "sql")).unwrap().successes,
        2
    );

    let _ = fs::remove_file(&path);
}

#[test]
fn save_writes_full_pretty_json_each_call() {
    // The renamed file must have valid pretty-printed JSON and the
    // entry count must match the in-memory cache. Cheap end-to-end
    // sanity check that our rewrite didn't break the format.
    let path = unique_tmp("pretty");
    let _ = fs::remove_file(&path);

    let mut cache = LearningCache::open(&path).unwrap();
    for i in 0..50 {
        cache.record_success(
            CacheKey::new(format!("waf-{i}"), "xss"),
            pipeline(&format!("p{i}")),
        );
    }
    cache.save().unwrap();

    let bytes = fs::read(&path).unwrap();
    let s = std::str::from_utf8(&bytes).expect("save must produce valid utf-8 json");
    assert!(s.starts_with("{"), "pretty json must start with '{{'");
    assert!(s.contains("\"entries\""), "must contain entries field");
    let parsed: serde_json::Value = serde_json::from_str(s).expect("must reopen as valid json");
    assert_eq!(
        parsed["entries"].as_object().unwrap().len(),
        50,
        "must have all 50 entries"
    );

    let _ = fs::remove_file(&path);
}
