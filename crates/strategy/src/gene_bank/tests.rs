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
    });
    genome.techniques.push(TechniqueRecord {
        name: "Bad".into(),
        total_successes: 1,
        total_attempts: 10,
        target_count: 1,
        last_success_epoch: 50,
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
    let tmp = std::env::temp_dir().join("wafrift_test_list");
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
        .filter_map(|e| e.ok())
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
        .filter_map(|e| e.ok())
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
    let json = r#"{
        "waf_name": "FutureWAF",
        "techniques": [],
        "targets_scanned": 5,
        "updated_at": 12345,
        "future_field_we_do_not_know_yet": true
    }"#;
    fs::write(tmp.join("future.json"), json).unwrap();

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
    let json = r#"{"waf_name": "OldWAF"}"#;
    fs::write(tmp.join("old.json"), json).unwrap();

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
        .write(true)
        .open(&lock_path)
        .unwrap();
    fs4::FileExt::lock(&f1).unwrap();

    let f2 = fs::OpenOptions::new()
        .create(true)
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
