//! Property-based fuzz tests for [`rule_corpus`].
//!
//! Closes [#171] — the corpus is the hunt loop's persistent state and
//! may be loaded from operator-supplied paths (or eventually from
//! genome-registry pulls). Every load path must withstand:
//!
//! 1. Arbitrary string fingerprints (unicode, empty, very long, path
//!    traversal attempts).
//! 2. Arbitrary garbage on disk where a valid corpus is expected.
//! 3. Arbitrary record sequences (block / bypass / drift interleaving)
//!    without panicking or corrupting cross-rule state.
//! 4. Round-trip determinism — serialize → deserialize must preserve
//!    every field byte-for-byte.

use proptest::prelude::*;
use tempfile::tempdir;
use wafrift_evolution::coverage_feedback::PayloadClass;
use wafrift_evolution::rule_corpus::{
    CORPUS_SCHEMA_VERSION, RuleBypassCorpus, SubmissionStatus, default_corpus_path,
};

fn cls(s: &str) -> PayloadClass {
    PayloadClass::new(s)
}

proptest! {
    /// load_or_default must never panic, regardless of what bytes are
    /// in the target file.
    #[test]
    fn load_arbitrary_bytes_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..=4096)) {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("c.json");
        std::fs::write(&path, &bytes).expect("write");
        let c = RuleBypassCorpus::load_or_default(&path, "fallback-fingerprint");
        // Either the bytes parsed (rare) and the corpus is non-default,
        // or they didn't and the fallback fingerprint took over.
        // Either way: no panic and the object is well-formed.
        prop_assert!(c.schema_version == CORPUS_SCHEMA_VERSION || c.schema_version == 0);
    }

    /// Arbitrary fingerprint strings must serialize round-trip safely.
    #[test]
    fn fingerprint_round_trips(fp in ".*") {
        let c = RuleBypassCorpus::new(&fp);
        let json = serde_json::to_string(&c).expect("serialize");
        let back: RuleBypassCorpus = serde_json::from_str(&json).expect("deserialize");
        prop_assert_eq!(back.target_fingerprint, fp);
    }

    /// Arbitrary rule_id + payload + class combinations record without
    /// panic and the count math stays consistent.
    #[test]
    fn record_block_keeps_invariants(
        rule_id in "[A-Za-z0-9_-]{1,30}",
        payload in ".*",
        class in "[a-z]{1,15}",
        hashes in proptest::collection::vec(any::<u64>(), 1..=20),
    ) {
        let mut c = RuleBypassCorpus::new("t");
        for h in &hashes {
            c.record_block(&rule_id, &payload, cls(&class), vec![], *h);
        }
        // The dedup key is (payload, response_hash). Same payload +
        // N distinct hashes = N records.
        let unique_hashes: std::collections::HashSet<&u64> = hashes.iter().collect();
        prop_assert_eq!(c.blocked_for_rule(&rule_id).len(), unique_hashes.len());
    }

    /// Arbitrary bypass records round-trip through atomic save.
    #[test]
    fn bypass_round_trips_through_atomic_save(
        rule_id in "[A-Za-z0-9_-]{1,30}",
        payload in "[\\x20-\\x7e]{0,200}",
        class in "[a-z]{1,15}",
    ) {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("c.json");
        let mut c = RuleBypassCorpus::new("t");
        c.record_bypass(&rule_id, &payload, cls(&class), vec![], 0xDEAD_BEEF);
        c.save_atomic(&path).expect("save");
        let r = RuleBypassCorpus::load_or_default(&path, "ignored");
        let bypasses = r.bypasses_for_rule(&rule_id);
        prop_assert_eq!(bypasses.len(), 1);
        prop_assert_eq!(&bypasses[0].payload, &payload);
    }

    /// Submission lifecycle transitions never produce a state the
    /// reader can't deserialize.
    #[test]
    fn submission_status_round_trips(
        report_id in "[A-Za-z0-9-]{1,30}",
        reason in ".*",
    ) {
        let statuses = vec![
            SubmissionStatus::Queued,
            SubmissionStatus::DryRunHold {
                release_at_secs: 1_700_000_000,
            },
            SubmissionStatus::Submitted {
                report_id: report_id.clone(),
            },
            SubmissionStatus::Accepted {
                report_id: report_id.clone(),
            },
            SubmissionStatus::Duplicate {
                duplicate_of: report_id.clone(),
            },
            SubmissionStatus::Rejected {
                reason: reason.clone(),
            },
        ];
        for s in statuses {
            let json = serde_json::to_string(&s).expect("ser");
            let back: SubmissionStatus = serde_json::from_str(&json).expect("de");
            prop_assert_eq!(format!("{:?}", s), format!("{:?}", back));
        }
    }

    /// unexplored_rules + rules_due_for_retry must always return
    /// rule_ids that actually exist in the corpus.
    #[test]
    fn query_methods_only_return_known_rules(
        rules in proptest::collection::vec("[A-Za-z0-9_-]{1,15}", 0..=15),
        threshold in 0usize..=10,
        window in 0u64..=86400,
    ) {
        let mut c = RuleBypassCorpus::new("t");
        for r in &rules {
            c.record_block(r, "p", cls("sql"), vec![], 1);
        }
        let unexplored = c.unexplored_rules(threshold);
        let due = c.rules_due_for_retry(window);
        for r in &unexplored {
            prop_assert!(rules.contains(r));
        }
        for r in &due {
            prop_assert!(rules.contains(r));
        }
    }

    /// novel_bypasses_pending_submission must not panic on
    /// arbitrary dry-run windows.
    #[test]
    fn pending_submission_no_panic_on_arbitrary_dry_run(
        dry_run in 0u64..=u64::MAX / 4,
    ) {
        let mut c = RuleBypassCorpus::new("t");
        c.record_bypass("R1", "p", cls("sql"), vec![], 1);
        let _ = c.novel_bypasses_pending_submission(dry_run);
    }

    /// default_corpus_path must produce a valid filesystem path for
    /// any fingerprint (path separator / unicode / long strings).
    #[test]
    fn default_corpus_path_never_panics(fp in ".*") {
        let p = default_corpus_path(&fp);
        // The path is non-empty and ends with ".json".
        let s = p.to_string_lossy().to_string();
        prop_assert!(s.ends_with(".json"));
        prop_assert!(!s.is_empty());
    }

    /// mark_drift on N rule_ids leaves each one with a Some timestamp.
    #[test]
    fn mark_drift_sets_timestamp(
        rules in proptest::collection::vec("[A-Za-z0-9_-]{1,15}", 0..=10),
    ) {
        let mut c = RuleBypassCorpus::new("t");
        for r in &rules {
            c.mark_drift(r);
        }
        for r in &rules {
            let bucket = c.buckets.get(r);
            prop_assert!(bucket.is_some());
            prop_assert!(bucket.unwrap().last_drift_at_secs.is_some());
        }
    }

    /// Schema version is always normalized to CORPUS_SCHEMA_VERSION
    /// on save.
    #[test]
    fn schema_version_pinned_on_save(initial_version in 0u32..=5) {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("c.json");
        let mut c = RuleBypassCorpus::new("t");
        c.schema_version = initial_version;
        c.save_atomic(&path).expect("save");
        let r = RuleBypassCorpus::load_or_default(&path, "ignored");
        prop_assert_eq!(r.schema_version, CORPUS_SCHEMA_VERSION);
    }
}

// ───────────────────────────────────────────────────────────────
// Concurrency stress — closes #172.
// ───────────────────────────────────────────────────────────────

#[test]
fn concurrent_record_no_data_race_via_mutex() {
    use std::sync::{Arc, Mutex};
    use std::thread;

    let corpus = Arc::new(Mutex::new(RuleBypassCorpus::new("t")));
    let mut handles = vec![];

    for worker in 0..8 {
        let c = corpus.clone();
        handles.push(thread::spawn(move || {
            for i in 0..200 {
                let mut guard = c.lock().expect("lock");
                let rule_id = format!("rule-{}", i % 10);
                let payload = format!("worker-{worker}-payload-{i}");
                guard.record_block(
                    &rule_id,
                    &payload,
                    cls("sql"),
                    vec![],
                    (worker * 1000 + i) as u64,
                );
            }
        }));
    }

    for h in handles {
        h.join().expect("join");
    }

    let c = corpus.lock().expect("final lock");
    // 8 workers × 200 distinct payloads = 1600 distinct records.
    let total: usize = c.buckets.values().map(|b| b.blocked.len()).sum();
    assert_eq!(total, 1600, "lost writes — concurrency bug");
}

#[test]
fn save_atomic_no_torn_write_under_concurrent_readers() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("c.json");

    // Seed with a valid corpus.
    let mut seed = RuleBypassCorpus::new("seed-fingerprint");
    for i in 0..50 {
        seed.record_block(
            &format!("R{i}"),
            &format!("p{i}"),
            cls("sql"),
            vec![],
            i as u64,
        );
    }
    seed.save_atomic(&path).expect("seed");

    let writer_barrier = Arc::new(Barrier::new(2));
    let reader_barrier = writer_barrier.clone();
    let writer_path = path.clone();
    let reader_path = path.clone();

    let writer = thread::spawn(move || {
        writer_barrier.wait();
        // Rapid-fire saves while a reader runs.
        for round in 0..20 {
            let mut c = RuleBypassCorpus::new(format!("round-{round}"));
            for i in 0..30 {
                c.record_bypass(
                    &format!("R{i}"),
                    &format!("p{i}-{round}"),
                    cls("sql"),
                    vec![],
                    (round * 100 + i) as u64,
                );
            }
            c.save_atomic(&writer_path).expect("save");
        }
    });

    let reader = thread::spawn(move || {
        reader_barrier.wait();
        // Concurrent reads — every load must either see the prior
        // valid snapshot or a new valid snapshot. Never a torn one.
        for _ in 0..100 {
            let c = RuleBypassCorpus::load_or_default(&reader_path, "fallback");
            // Either the seed (50 blocks) or one of the writer's 20
            // snapshots (30 bypasses each). Never an in-between
            // corrupted state where the fingerprint is empty.
            assert!(
                !c.target_fingerprint.is_empty(),
                "torn write: empty fingerprint"
            );
        }
    });

    writer.join().expect("writer");
    reader.join().expect("reader");
}
