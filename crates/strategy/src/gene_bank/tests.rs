use super::*;
use std::fs;

#[test]
fn technique_record_success_rate() {
    let rec = TechniqueRecord {
        name: "DoubleUrlEncode".into(),
        total_successes: 8,
        total_attempts: 10,
        target_count: 3,
        last_success_epoch: 0,
        ..Default::default()
    };
    assert!((rec.success_rate() - 0.8).abs() < f64::EPSILON);
}

#[test]
fn technique_record_zero_attempts() {
    let rec = TechniqueRecord {
        name: "Test".into(),
        total_successes: 0,
        total_attempts: 0,
        target_count: 0,
        last_success_epoch: 0,
        ..Default::default()
    };
    assert!((rec.success_rate()).abs() < f64::EPSILON);
}

#[test]
fn genome_merge_session_new_techniques() {
    let mut genome = WafGenome::new("TestWAF");
    let stats = vec![
        ("DoubleUrlEncode".into(), 8, 10),
        ("OverlongUtf8".into(), 5, 10),
    ];
    genome.merge_session(&stats);
    assert_eq!(genome.techniques.len(), 2);
    assert_eq!(genome.targets_scanned, 1);
    assert_eq!(genome.techniques[0].total_successes, 8);
}

#[test]
fn genome_merge_session_accumulates() {
    let mut genome = WafGenome::new("TestWAF");
    let stats1 = vec![("DoubleUrlEncode".into(), 5, 10)];
    let stats2 = vec![("DoubleUrlEncode".into(), 3, 5)];
    genome.merge_session(&stats1);
    genome.merge_session(&stats2);
    assert_eq!(genome.targets_scanned, 2);
    assert_eq!(genome.techniques[0].total_successes, 8);
    assert_eq!(genome.techniques[0].total_attempts, 15);
    assert_eq!(genome.techniques[0].target_count, 2);
}

#[test]
fn genome_seed_winners_filters_low_rate() {
    let mut genome = WafGenome::new("TestWAF");
    genome.techniques.push(TechniqueRecord {
        name: "Good".into(),
        total_successes: 9,
        total_attempts: 10,
        target_count: 5,
        last_success_epoch: 100,
        ..Default::default()
    });
    genome.techniques.push(TechniqueRecord {
        name: "Bad".into(),
        total_successes: 1,
        total_attempts: 10,
        target_count: 1,
        last_success_epoch: 50,
        ..Default::default()
    });
    let winners = genome.seed_winners();
    assert_eq!(winners, vec!["Good".to_string()]);
}

#[test]
fn gene_bank_roundtrip() {
    let tmp = std::env::temp_dir().join("wafrift_test_genebank");
    let _ = fs::remove_dir_all(&tmp);
    let mut bank = GeneBank::open(tmp.clone()).unwrap();

    let mut genome = WafGenome::new("Cloudflare");
    genome.merge_session(&[("OverlongUtf8".into(), 9, 10)]);
    bank.save(&genome).unwrap();

    // Re-open and load
    let mut bank2 = GeneBank::open(tmp.clone()).unwrap();
    let loaded = bank2.load("Cloudflare").unwrap();
    assert_eq!(loaded.techniques[0].name, "OverlongUtf8");
    assert_eq!(loaded.techniques[0].total_successes, 9);

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn gene_bank_list_wafs() {
    // PID + nanos suffix so concurrent test runs (`cargo test` with the
    // default thread pool) don't trample each other's tmp dir. The
    // earlier `wafrift_test_list` static-name version flaked under
    // load — two threads racing on the same directory would unwrap()
    // a `NotFound` between one's remove_dir_all and another's save.
    let tmp = std::env::temp_dir().join(format!(
        "wafrift_test_list_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let _ = fs::remove_dir_all(&tmp);
    let mut bank = GeneBank::open(tmp.clone()).unwrap();

    bank.save(&WafGenome::new("Cloudflare")).unwrap();
    bank.save(&WafGenome::new("AWS WAF")).unwrap();

    let wafs = bank.list_wafs();
    assert!(wafs.contains(&"cloudflare".to_string()));
    assert!(wafs.contains(&"aws_waf".to_string()));

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn normalize_name_handles_special_chars() {
    assert_eq!(normalize_name("AWS WAF"), "aws_waf");
    assert_eq!(normalize_name("Cloudflare (Pro)"), "cloudflare__pro_");
    assert_eq!(normalize_name("ModSecurity/CRS"), "modsecurity_crs");
}

// ── Corruption resilience tests ──

#[test]
fn corrupt_genome_is_quarantined_on_load() {
    let tmp = std::env::temp_dir().join("wafrift_test_corrupt_load");
    let _ = fs::remove_dir_all(&tmp);
    let _ = fs::create_dir_all(&tmp);

    // Write corrupt JSON to the genome file.
    let corrupt_path = tmp.join("cloudflare.json");
    fs::write(&corrupt_path, "{ this is not valid json!!!").unwrap();

    let mut bank = GeneBank::open(tmp.clone()).unwrap();
    let result = bank.load("Cloudflare");

    // Should return None (corrupt file).
    assert!(result.is_none());

    // Original file should be quarantined (renamed).
    assert!(
        !corrupt_path.exists(),
        "corrupt file should have been renamed"
    );

    // A .corrupt. file should exist.
    let quarantined: Vec<_> = fs::read_dir(&tmp)
        .unwrap()
        .filter_map(std::result::Result::ok)
        .filter(|e| e.file_name().to_string_lossy().contains(".corrupt."))
        .collect();
    assert_eq!(
        quarantined.len(),
        1,
        "expected exactly one quarantined file"
    );

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn corrupt_genome_is_quarantined_on_merge() {
    let tmp = std::env::temp_dir().join("wafrift_test_corrupt_merge");
    let _ = fs::remove_dir_all(&tmp);
    let _ = fs::create_dir_all(&tmp);

    // Write corrupt JSON.
    let corrupt_path = tmp.join("cloudflare.json");
    fs::write(&corrupt_path, "GARBAGE").unwrap();

    let mut bank = GeneBank::open(tmp.clone()).unwrap();

    // merge_and_save should quarantine the corrupt file and create
    // a fresh genome from the session data.
    bank.merge_and_save("Cloudflare", &[("DoubleUrlEncode".into(), 5, 10)])
        .unwrap();

    // The genome should now be loadable with the new data.
    let mut bank2 = GeneBank::open(tmp.clone()).unwrap();
    let loaded = bank2.load("Cloudflare").unwrap();
    assert_eq!(loaded.techniques.len(), 1);
    assert_eq!(loaded.techniques[0].name, "DoubleUrlEncode");
    assert_eq!(loaded.techniques[0].total_successes, 5);

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn atomic_write_no_temp_file_left() {
    let tmp = std::env::temp_dir().join("wafrift_test_atomic");
    let _ = fs::remove_dir_all(&tmp);
    let mut bank = GeneBank::open(tmp.clone()).unwrap();

    bank.save(&WafGenome::new("TestWAF")).unwrap();

    // No .tmp files should remain.
    let tmp_files: Vec<_> = fs::read_dir(&tmp)
        .unwrap()
        .filter_map(std::result::Result::ok)
        .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
        .collect();
    assert!(
        tmp_files.is_empty(),
        "no .tmp files should remain after save"
    );

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn list_wafs_excludes_corrupt_and_tmp_files() {
    let tmp = std::env::temp_dir().join("wafrift_test_list_filter");
    let _ = fs::remove_dir_all(&tmp);
    let _ = fs::create_dir_all(&tmp);

    // Create valid, corrupt, and tmp files.
    fs::write(tmp.join("cloudflare.json"), "{}").unwrap();
    fs::write(tmp.join("aws.json.corrupt.12345"), "GARBAGE").unwrap();
    fs::write(tmp.join("modsec.json.tmp"), "{}").unwrap();

    let bank = GeneBank::open(tmp.clone()).unwrap();
    let wafs = bank.list_wafs();

    assert_eq!(wafs, vec!["cloudflare"]);

    let _ = fs::remove_dir_all(&tmp);
}

// ── Schema forward/backward compatibility tests ──

#[test]
fn forward_compatible_unknown_fields_ignored() {
    let tmp = std::env::temp_dir().join("wafrift_test_forward_compat");
    let _ = fs::remove_dir_all(&tmp);
    let _ = fs::create_dir_all(&tmp);

    // JSON with a field that doesn't exist in the current struct.
    // File must be at <normalize_name(waf_name)>.json — i.e. lowercased.
    let json = r#"{
        "waf_name": "FutureWAF",
        "techniques": [],
        "targets_scanned": 5,
        "updated_at": 12345,
        "future_field_we_do_not_know_yet": true
    }"#;
    fs::write(tmp.join("futurewaf.json"), json).unwrap();

    let mut bank = GeneBank::open(tmp.clone()).unwrap();
    let loaded = bank
        .load("FutureWAF")
        .expect("should parse despite unknown field");
    assert_eq!(loaded.waf_name, "FutureWAF");
    assert_eq!(loaded.targets_scanned, 5);

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn backward_compatible_missing_fields_defaulted() {
    let tmp = std::env::temp_dir().join("wafrift_test_backward_compat");
    let _ = fs::remove_dir_all(&tmp);
    let _ = fs::create_dir_all(&tmp);

    // JSON missing some fields — they should default to zero/empty.
    // File must be at <normalize_name(waf_name)>.json — i.e. lowercased.
    let json = r#"{"waf_name": "OldWAF"}"#;
    fs::write(tmp.join("oldwaf.json"), json).unwrap();

    let mut bank = GeneBank::open(tmp.clone()).unwrap();
    let loaded = bank
        .load("OldWAF")
        .expect("should parse despite missing fields");
    assert_eq!(loaded.waf_name, "OldWAF");
    assert!(loaded.techniques.is_empty());
    assert_eq!(loaded.targets_scanned, 0);

    let _ = fs::remove_dir_all(&tmp);
}

// ── Concurrency tests ──

#[test]
fn advisory_lock_blocks_concurrent_writers() {
    let tmp = std::env::temp_dir().join("wafrift_test_lock");
    let _ = fs::remove_dir_all(&tmp);
    let _ = fs::create_dir_all(&tmp);

    let path = tmp.join("test.json");
    let lock_path = path.with_extension("lock");

    let f1 = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&lock_path)
        .unwrap();
    fs4::FileExt::lock(&f1).unwrap();

    let f2 = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&lock_path)
        .unwrap();
    assert!(
        fs4::FileExt::try_lock(&f2).is_err(),
        "second lock should be blocked"
    );

    fs4::FileExt::unlock(&f1).unwrap();
    assert!(
        fs4::FileExt::try_lock(&f2).is_ok(),
        "lock should be available after release"
    );

    let _ = fs::remove_dir_all(&tmp);
}

// ── Per-class warm-start surface ───────────────────────────────────
//
// Over-the-top coverage: every public method on the per-class
// extension gets at least one test that exercises the success path,
// one that exercises the empty/fallback path, one that exercises
// the threshold gate, and an integration test that round-trips via
// disk to prove the serde schema actually persists. The goal is that
// a future change which silently drops the per-class breakdown trips
// at least one of these gates before it lands.

#[test]
fn class_stat_success_rate_basic_and_zero_attempts() {
    let a = ClassStat { successes: 7, attempts: 10 };
    assert!((a.success_rate() - 0.7).abs() < f64::EPSILON);
    let zero = ClassStat { successes: 0, attempts: 0 };
    assert!(zero.success_rate().abs() < f64::EPSILON);
    // Anti-rig: high successes with zero attempts is malformed input;
    // we return 0.0 rather than infinity or NaN.
    let nonsensical = ClassStat { successes: 99, attempts: 0 };
    assert!(nonsensical.success_rate().abs() < f64::EPSILON);
}

#[test]
fn technique_record_class_success_rate_returns_none_when_class_unseen() {
    // A technique with global history but no per-class data should
    // return None for `success_rate_for_class` — that's the signal
    // for the caller to fall back to the global rate.
    let rec = TechniqueRecord {
        name: "DoubleUrlEncode".into(),
        total_successes: 8,
        total_attempts: 10,
        ..Default::default()
    };
    assert_eq!(rec.success_rate_for_class("sql"), None);
    assert_eq!(rec.attempts_for_class("sql"), 0);
}

#[test]
fn technique_record_class_lookup_is_case_insensitive() {
    let mut rec = TechniqueRecord {
        name: "T".into(),
        total_successes: 5,
        total_attempts: 10,
        ..Default::default()
    };
    rec.per_class
        .insert("sql".into(), ClassStat { successes: 5, attempts: 10 });
    // Various caller-casings must all resolve to the lowercase key.
    assert!((rec.success_rate_for_class("sql").unwrap() - 0.5).abs() < f64::EPSILON);
    assert!((rec.success_rate_for_class("SQL").unwrap() - 0.5).abs() < f64::EPSILON);
    assert!((rec.success_rate_for_class("Sql").unwrap() - 0.5).abs() < f64::EPSILON);
}

#[test]
fn merge_session_for_class_creates_per_class_record_for_new_technique() {
    let mut genome = WafGenome::new("TestWAF");
    genome.merge_session_for_class("sql", &[("XYZ".into(), 7, 10)]);
    assert_eq!(genome.techniques.len(), 1);
    let t = &genome.techniques[0];
    assert_eq!(t.total_successes, 7);
    assert_eq!(t.total_attempts, 10);
    let cs = t.per_class.get("sql").expect("sql class stat present");
    assert_eq!(cs.successes, 7);
    assert_eq!(cs.attempts, 10);
}

#[test]
fn merge_session_for_class_accumulates_across_sessions() {
    // Two SQL sessions + one XSS session for the same technique:
    // global totals add to 12/30, per-class sql = 8/20, xss = 4/10.
    let mut genome = WafGenome::new("TestWAF");
    genome.merge_session_for_class("sql", &[("T".into(), 5, 10)]);
    genome.merge_session_for_class("sql", &[("T".into(), 3, 10)]);
    genome.merge_session_for_class("xss", &[("T".into(), 4, 10)]);
    let t = genome.techniques.iter().find(|t| t.name == "T").unwrap();
    assert_eq!(t.total_successes, 12);
    assert_eq!(t.total_attempts, 30);
    let sql = t.per_class.get("sql").unwrap();
    assert_eq!(sql.successes, 8);
    assert_eq!(sql.attempts, 20);
    let xss = t.per_class.get("xss").unwrap();
    assert_eq!(xss.successes, 4);
    assert_eq!(xss.attempts, 10);
}

#[test]
fn merge_session_for_class_empty_class_falls_through_to_global() {
    // Passing "" (or whitespace) for class must NOT create an empty-
    // string per-class bucket — it must fall through to merge_session
    // so the global totals get updated and per_class stays clean.
    let mut genome = WafGenome::new("TestWAF");
    genome.merge_session_for_class("", &[("T".into(), 5, 10)]);
    genome.merge_session_for_class("   ", &[("T".into(), 3, 10)]);
    let t = genome.techniques.iter().find(|t| t.name == "T").unwrap();
    assert_eq!(t.total_successes, 8);
    assert_eq!(t.total_attempts, 20);
    assert!(
        t.per_class.is_empty(),
        "empty class must NOT create a per_class entry, got {:?}",
        t.per_class
    );
}

#[test]
fn seed_winners_for_class_returns_class_specific_winners() {
    let mut genome = WafGenome::new("TestWAF");
    // Tech A: great at SQL (10/10), bad at XSS (1/10).
    genome.merge_session_for_class("sql", &[("A".into(), 10, 10)]);
    genome.merge_session_for_class("xss", &[("A".into(), 1, 10)]);
    // Tech B: opposite — bad at SQL (1/10), great at XSS (10/10).
    genome.merge_session_for_class("sql", &[("B".into(), 1, 10)]);
    genome.merge_session_for_class("xss", &[("B".into(), 10, 10)]);
    // SQL warm-start picks A only; XSS picks B only — the global
    // seed_winners would have lumped them both in.
    assert_eq!(genome.seed_winners_for_class("sql"), vec!["A".to_string()]);
    assert_eq!(genome.seed_winners_for_class("xss"), vec!["B".to_string()]);
}

#[test]
fn seed_winners_for_class_fallback_when_no_class_history() {
    // If the class has been seen by ZERO techniques (or all
    // techniques are below the threshold), fall back to the global
    // seed_winners so warm-start still provides *something* useful
    // — the fresh-class case must not silently produce an empty
    // priority list and lose all benefit of historical data.
    let mut genome = WafGenome::new("TestWAF");
    genome.merge_session_for_class("sql", &[("Good".into(), 9, 10)]);
    // Asking for a class never observed -> fall back to global.
    let fallback = genome.seed_winners_for_class("never_seen_class");
    assert_eq!(fallback, vec!["Good".to_string()]);
}

#[test]
fn seed_winners_for_class_threshold_excludes_under_attempted_techniques() {
    // The 60% / 5-attempt threshold applies per-class too: a 5-for-5
    // looks better than a 3-for-3 but only the former should clear
    // the gate even though both have a 100% rate.
    let mut genome = WafGenome::new("TestWAF");
    genome.merge_session_for_class("sql", &[("Sparse".into(), 3, 3)]);
    genome.merge_session_for_class("sql", &[("Solid".into(), 5, 5)]);
    let winners = genome.seed_winners_for_class("sql");
    assert!(winners.contains(&"Solid".to_string()));
    assert!(
        !winners.contains(&"Sparse".to_string()),
        "3-of-3 must NOT clear the 5-attempt floor: {winners:?}"
    );
}

#[test]
fn old_genome_without_per_class_field_loads_cleanly() {
    // Backwards-compat gate: a genome saved BEFORE the per_class
    // field landed must still deserialise. The `#[serde(default)]`
    // on `TechniqueRecord::per_class` is the only thing that makes
    // this work; if someone removes that attribute, this test
    // catches it.
    let json_old = r#"{
        "waf_name": "Legacy",
        "techniques": [
            {
                "name": "OldTech",
                "total_successes": 5,
                "total_attempts": 10,
                "target_count": 2,
                "last_success_epoch": 100
            }
        ],
        "targets_scanned": 2,
        "updated_at": 100
    }"#;
    let genome: WafGenome = serde_json::from_str(json_old).expect("must load old genome");
    assert_eq!(genome.techniques.len(), 1);
    assert!(
        genome.techniques[0].per_class.is_empty(),
        "old genome must load with empty per_class map"
    );
    // And seed_winners_for_class must still produce SOMETHING via the
    // fallback path (the technique's global rate is 50%, below the
    // 60% global threshold, so global winners is empty -> class-
    // specific is also empty; both honest).
    let winners = genome.seed_winners_for_class("sql");
    assert!(
        winners.is_empty(),
        "global rate 50% < 60% threshold means no winners by either path: {winners:?}"
    );
}

#[test]
fn merge_and_save_for_class_round_trips_per_class_via_disk() {
    use std::env::temp_dir;
    let tmp = temp_dir().join(format!(
        "wafrift-genebank-warmstart-test-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&tmp);

    // Round 1: save a sql session.
    {
        let mut bank = GeneBank::open(&tmp).expect("open temp gene bank");
        bank.merge_and_save_for_class("Cloudflare", "sql", &[("UrlEncode".into(), 8, 10)])
            .expect("merge sql");
    }
    // Round 2: separate process-equivalent re-open + ANOTHER sql
    // session + an xss session. Per-class breakdown must persist
    // and accumulate.
    {
        let mut bank = GeneBank::open(&tmp).expect("re-open temp gene bank");
        bank.merge_and_save_for_class("Cloudflare", "sql", &[("UrlEncode".into(), 2, 10)])
            .expect("merge sql 2");
        bank.merge_and_save_for_class("Cloudflare", "xss", &[("UrlEncode".into(), 6, 10)])
            .expect("merge xss");
    }
    // Round 3: read-only verify.
    {
        let mut bank = GeneBank::open(&tmp).expect("re-open for read");
        let genome = bank.load("Cloudflare").expect("Cloudflare genome present");
        let tech = genome
            .techniques
            .iter()
            .find(|t| t.name == "UrlEncode")
            .expect("UrlEncode present");
        // Global totals: 8+2+6 / 10+10+10 = 16/30.
        assert_eq!(tech.total_successes, 16);
        assert_eq!(tech.total_attempts, 30);
        let sql = tech.per_class.get("sql").expect("sql persisted");
        assert_eq!(sql.successes, 10, "8+2 sql successes persisted");
        assert_eq!(sql.attempts, 20, "10+10 sql attempts persisted");
        let xss = tech.per_class.get("xss").expect("xss persisted");
        assert_eq!(xss.successes, 6);
        assert_eq!(xss.attempts, 10);
    }
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn merge_and_save_for_class_empty_class_falls_through() {
    use std::env::temp_dir;
    let tmp = temp_dir().join(format!(
        "wafrift-genebank-warmstart-empty-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&tmp);
    {
        let mut bank = GeneBank::open(&tmp).expect("open");
        bank.merge_and_save_for_class("WAF", "", &[("T".into(), 5, 10)])
            .expect("empty class falls through");
    }
    {
        let mut bank = GeneBank::open(&tmp).expect("re-open");
        let genome = bank.load("WAF").expect("genome present");
        let t = genome
            .techniques
            .iter()
            .find(|t| t.name == "T")
            .expect("T present");
        assert_eq!(t.total_successes, 5);
        assert_eq!(t.total_attempts, 10);
        assert!(
            t.per_class.is_empty(),
            "empty-class merge must not create a per_class entry"
        );
    }
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn merge_and_save_for_class_concurrent_safe_via_lock() {
    // Both merge_and_save and merge_and_save_for_class take the same
    // advisory lock, so a class-aware merge interleaved with a
    // class-less merge must not lose either's writes. Run two
    // back-to-back operations on the same waf — final state must
    // reflect both.
    use std::env::temp_dir;
    let tmp = temp_dir().join(format!(
        "wafrift-genebank-interleave-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&tmp);
    {
        let mut bank = GeneBank::open(&tmp).expect("open");
        bank.merge_and_save("WAF", &[("A".into(), 1, 2)]).expect("class-less");
        bank.merge_and_save_for_class("WAF", "sql", &[("A".into(), 3, 4)])
            .expect("class-aware");
        bank.merge_and_save("WAF", &[("B".into(), 5, 5)]).expect("class-less B");
    }
    {
        let mut bank = GeneBank::open(&tmp).expect("re-open");
        let genome = bank.load("WAF").expect("present");
        let a = genome.techniques.iter().find(|t| t.name == "A").unwrap();
        assert_eq!(a.total_successes, 4, "1+3 from both merges");
        assert_eq!(a.total_attempts, 6, "2+4 from both merges");
        assert!(a.per_class.get("sql").is_some(), "sql per-class persisted");
        let b = genome.techniques.iter().find(|t| t.name == "B").unwrap();
        assert_eq!(b.total_successes, 5);
        // B had no per-class merge, so its per_class is empty.
        assert!(b.per_class.is_empty());
    }
    let _ = fs::remove_dir_all(&tmp);
}
