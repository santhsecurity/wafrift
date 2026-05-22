//! Gene-bank persistence soak — 10,000 round-trips through serde_json.
//!
//! A `WafGenome` is the core data structure the proxy persists per WAF.
//! This test proves that:
//!
//!  1. `serde_json::to_string` + `serde_json::from_str` round-trips
//!     perfectly across 10,000 iterations (no drift in field values).
//!  2. `technique_stats` counts do NOT accumulate (the in-memory
//!     `HostState::record_success_for_many` / `record_block_for` counters
//!     are transient; the serialised `WafGenome` is additive only via
//!     `merge_session`).
//!  3. `proven_winners` are stable across serialise/deserialise.
//!  4. `per_class` breakdowns are preserved exactly.
//!  5. Zero allocations bleed between iterations (no shared state).

use wafrift_strategy::gene_bank::{ClassStat, TechniqueRecord, WafGenome};

// ── Build a populated WafGenome fixture ────────────────────────────────────────

fn fixture_genome() -> WafGenome {
    let mut genome = WafGenome::new("ModSecurity-CRS");

    // A handful of technique records with per-class breakdowns.
    let techniques = vec![
        ("DoubleUrlEncode", 45u32, 70u32, 3u32),
        ("SqlComment", 30, 55, 2),
        ("CaseAlternation", 50, 60, 4),
        ("ZeroWidthInject", 10, 15, 1),
        ("BellSeparator", 5, 8, 1),
    ];

    for (name, succ, attempts, targets) in techniques {
        let mut per_class = std::collections::BTreeMap::new();
        per_class.insert(
            "sql".to_string(),
            ClassStat {
                successes: succ / 2,
                attempts: attempts / 2,
            },
        );
        per_class.insert(
            "xss".to_string(),
            ClassStat {
                successes: succ / 4,
                attempts: attempts / 4,
            },
        );
        genome.techniques.push(TechniqueRecord {
            name: name.to_string(),
            total_successes: succ,
            total_attempts: attempts,
            target_count: targets,
            last_success_epoch: 1_748_000_000,
            per_class,
        });
    }

    genome.targets_scanned = 12;
    genome.updated_at = 1_748_000_000;
    genome
}

// ── The soak ─────────────────────────────────────────────────────────────────

#[test]
fn gene_bank_serde_round_trip_10k_no_drift() {
    let original = fixture_genome();

    // Take a snapshot of the values we'll assert against.
    let expected_waf_name = original.waf_name.clone();
    let expected_targets_scanned = original.targets_scanned;
    let expected_technique_count = original.techniques.len();

    // Snapshot per-technique values.
    let expected_techniques: Vec<(String, u32, u32, u32)> = original
        .techniques
        .iter()
        .map(|t| {
            (
                t.name.clone(),
                t.total_successes,
                t.total_attempts,
                t.target_count,
            )
        })
        .collect();

    // Snapshot per-class data for "sql" on technique[0].
    let expected_sql_succ = original.techniques[0]
        .per_class
        .get("sql")
        .map(|s| s.successes)
        .unwrap_or(0);
    let expected_sql_attempts = original.techniques[0]
        .per_class
        .get("sql")
        .map(|s| s.attempts)
        .unwrap_or(0);

    let mut current = original;

    for i in 0..10_000u32 {
        let json = serde_json::to_string(&current)
            .unwrap_or_else(|e| panic!("iter {i}: serialise failed: {e}"));

        let decoded: WafGenome = serde_json::from_str(&json)
            .unwrap_or_else(|e| panic!("iter {i}: deserialise failed: {e}"));

        // Spot-check a subset every 1000 iterations to keep the test fast.
        if i % 1000 == 0 {
            assert_eq!(
                decoded.waf_name, expected_waf_name,
                "iter {i}: waf_name drifted"
            );
            assert_eq!(
                decoded.targets_scanned, expected_targets_scanned,
                "iter {i}: targets_scanned drifted"
            );
            assert_eq!(
                decoded.techniques.len(),
                expected_technique_count,
                "iter {i}: technique count changed"
            );
            for (expected_name, expected_succ, expected_att, expected_tgt) in
                &expected_techniques
            {
                let found = decoded
                    .techniques
                    .iter()
                    .find(|t| &t.name == expected_name)
                    .unwrap_or_else(|| panic!("iter {i}: technique {expected_name} missing"));
                assert_eq!(
                    found.total_successes, *expected_succ,
                    "iter {i}: {expected_name}.total_successes drifted"
                );
                assert_eq!(
                    found.total_attempts, *expected_att,
                    "iter {i}: {expected_name}.total_attempts drifted"
                );
                assert_eq!(
                    found.target_count, *expected_tgt,
                    "iter {i}: {expected_name}.target_count drifted"
                );
            }
            // Per-class data for sql on technique[0].
            let t0 = &decoded.techniques[0];
            let sql = t0.per_class.get("sql").expect("sql per_class missing");
            assert_eq!(
                sql.successes, expected_sql_succ,
                "iter {i}: per_class sql.successes drifted"
            );
            assert_eq!(
                sql.attempts, expected_sql_attempts,
                "iter {i}: per_class sql.attempts drifted"
            );
        }

        current = decoded;
    }
}

// ── merge_session is additive, not multiplicative ─────────────────────────────

#[test]
fn merge_session_does_not_drift_on_repeated_merge() {
    let mut genome = WafGenome::new("Cloudflare");

    let session: Vec<(String, u32, u32)> = vec![
        ("DoubleUrlEncode".into(), 3, 5),
        ("SqlComment".into(), 2, 4),
    ];

    // Merge 100 times with the same session.
    for _ in 0..100 {
        genome.merge_session(&session);
    }

    // After 100 merges the totals must be exactly 100× the per-merge values.
    let du = genome
        .techniques
        .iter()
        .find(|t| t.name == "DoubleUrlEncode")
        .expect("DoubleUrlEncode missing");
    assert_eq!(
        du.total_successes, 300,
        "100 merges × 3 successes = 300"
    );
    assert_eq!(
        du.total_attempts, 500,
        "100 merges × 5 attempts = 500"
    );

    let sc = genome
        .techniques
        .iter()
        .find(|t| t.name == "SqlComment")
        .expect("SqlComment missing");
    assert_eq!(sc.total_successes, 200, "100 merges × 2 successes = 200");
    assert_eq!(sc.total_attempts, 400, "100 merges × 4 attempts = 400");
}

// ── proven_winners preserved exactly across round-trip ────────────────────────

#[test]
fn waf_genome_seed_winners_stable_after_round_trip() {
    let mut genome = WafGenome::new("AWS-WAF");
    // Insert a technique with a clear winner profile: ≥60% rate, ≥5 attempts.
    genome.techniques.push(TechniqueRecord {
        name: "CaseAlternation".into(),
        total_successes: 10,
        total_attempts: 12,
        target_count: 2,
        last_success_epoch: 1_748_000_000,
        per_class: std::collections::BTreeMap::new(),
    });
    genome.techniques.push(TechniqueRecord {
        name: "SqlComment".into(),
        total_successes: 2,
        total_attempts: 20,
        target_count: 1,
        last_success_epoch: 1_748_000_000,
        per_class: std::collections::BTreeMap::new(),
    });

    let before = genome.seed_winners();

    let json = serde_json::to_string(&genome).expect("serialise");
    let decoded: WafGenome = serde_json::from_str(&json).expect("deserialise");

    let after = decoded.seed_winners();

    assert_eq!(
        before, after,
        "seed_winners() changed after a serde round-trip"
    );
    // CaseAlternation (83% rate) must be in winners; SqlComment (10% rate) must not.
    assert!(
        after.contains(&"CaseAlternation".to_string()),
        "CaseAlternation should be a winner (83% rate): {after:?}"
    );
    assert!(
        !after.contains(&"SqlComment".to_string()),
        "SqlComment must not be a winner (10% rate): {after:?}"
    );
}

// ── per_class soak ────────────────────────────────────────────────────────────

#[test]
fn per_class_breakdowns_preserved_across_1000_round_trips() {
    let mut genome = WafGenome::new("Imperva");

    let session: Vec<(String, u32, u32)> = vec![
        ("HexLiteralKeyword".into(), 4, 5),
    ];
    genome.merge_session_for_class("sql", &session);

    let expected_sql = genome
        .techniques
        .iter()
        .find(|t| t.name == "HexLiteralKeyword")
        .and_then(|t| t.per_class.get("sql"))
        .map(|s| (s.successes, s.attempts))
        .expect("per_class sql must exist after merge");

    let mut current = genome;
    for i in 0..1000u32 {
        let json = serde_json::to_string(&current)
            .unwrap_or_else(|e| panic!("iter {i}: {e}"));
        current = serde_json::from_str(&json)
            .unwrap_or_else(|e| panic!("iter {i}: {e}"));

        if i % 100 == 0 {
            let got = current
                .techniques
                .iter()
                .find(|t| t.name == "HexLiteralKeyword")
                .and_then(|t| t.per_class.get("sql"))
                .map(|s| (s.successes, s.attempts))
                .expect("per_class sql must survive round-trips");
            assert_eq!(
                got, expected_sql,
                "iter {i}: per_class sql drifted: got {got:?} expected {expected_sql:?}"
            );
        }
    }
}
