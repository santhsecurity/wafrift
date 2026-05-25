//! Live wire-up between the bench/hunt probe loops and the
//! `wafrift_evolution` corpus / coverage / dedup infrastructure.
//!
//! Closes the integration gap: every module under
//! `wafrift_evolution::{rule_corpus, edge_pop_coverage, h1_dedup,
//! hunt_corpus_bridge}` was shipped with tests but ZERO production
//! callers. This module is the one production caller: bench_waf,
//! scan, and hunt all route their per-probe results through
//! [`CorpusRecorder::record`].
//!
//! ## What gets recorded
//!
//! Per probe, given a [`ProbeEnvelope`] + payload metadata:
//! 1. [`wafrift_oracle::cloudflare::parse_cf_block`] derives the CF
//!    rule attribution + edge POP from headers + body.
//! 2. [`wafrift_evolution::hunt_corpus_bridge::record_probe`] writes
//!    to BOTH the rule_corpus AND edge_pop_coverage, and returns a
//!    bypass fingerprint.
//! 3. The fingerprint is checked against the operator-supplied
//!    `H1Archive` so duplicate-of-published bypasses don't enter the
//!    submission queue.
//!
//! ## Persistence
//!
//! [`CorpusRecorder::flush`] saves the corpus + coverage atomically
//! via the `save_atomic` helpers each module ships. Callers can
//! flush periodically (every N probes) or once at the end of a run.

use std::path::PathBuf;

use wafrift_evolution::coverage_feedback::PayloadClass;
use wafrift_evolution::edge_pop_coverage::EdgePopCoverage;
use wafrift_evolution::h1_dedup::{BypassFingerprint, H1Archive};
use wafrift_evolution::hunt_corpus_bridge::{ProbeOutcome, ProbeRecord, record_probe};
use wafrift_evolution::rule_corpus::RuleBypassCorpus;
use wafrift_oracle::cloudflare::parse_cf_block;

use crate::equiv_engine::ProbeEnvelope;

/// One probe record waiting to be flushed.
///
/// We accumulate these and write to disk in `flush()` rather than
/// after every probe so the bench loop stays fast.
pub struct CorpusRecorder {
    /// Per-rule bypass / block corpus.
    corpus: RuleBypassCorpus,
    /// Cross-region CF edge POP coverage.
    coverage: EdgePopCoverage,
    /// HackerOne dedup archive — pre-populated by the operator with
    /// already-submitted bypass fingerprints.
    h1_archive: H1Archive,
    /// Where the corpus is persisted.
    corpus_path: PathBuf,
    /// Where the edge-POP coverage is persisted.
    coverage_path: PathBuf,
    /// Number of probes seen since startup.
    probe_count: u64,
    /// Number of confirmed-novel bypasses (not in h1_archive).
    novel_bypass_count: u64,
}

impl CorpusRecorder {
    /// Create a recorder bound to the given target fingerprint and
    /// output paths. Loads any existing corpus / coverage / archive
    /// from disk so successive runs accumulate state.
    #[must_use]
    pub fn new(
        target_fingerprint: impl Into<String>,
        corpus_path: PathBuf,
        coverage_path: PathBuf,
        h1_archive_path: Option<PathBuf>,
    ) -> Self {
        let corpus = RuleBypassCorpus::load_or_default(&corpus_path, target_fingerprint);
        let coverage = EdgePopCoverage::load_or_default(&coverage_path);
        let h1_archive = match h1_archive_path {
            Some(p) => H1Archive::load_or_default(&p),
            None => H1Archive::new(),
        };
        Self {
            corpus,
            coverage,
            h1_archive,
            corpus_path,
            coverage_path,
            probe_count: 0,
            novel_bypass_count: 0,
        }
    }

    /// Record one probe result. The envelope's headers + body are
    /// fed through `parse_cf_block` to derive the rule attribution
    /// and edge POP automatically. Returns the bypass fingerprint
    /// and `is_novel` (true ⇔ fingerprint not in h1_archive).
    pub fn record(
        &mut self,
        envelope: &ProbeEnvelope,
        payload: &str,
        payload_class: PayloadClass,
        encoding_chain: Vec<String>,
        egress_label: &str,
        target_host: &str,
        outcome: ProbeOutcome,
    ) -> (BypassFingerprint, bool) {
        self.probe_count = self.probe_count.saturating_add(1);
        let signal = parse_cf_block(&envelope.headers, &envelope.body);
        let rule_attribution = if signal.rule_attribution.is_empty() {
            None
        } else {
            Some(signal.rule_attribution.as_str())
        };
        let pop_raw = signal.edge_pop.as_deref();
        // Stable response hash for corpus dedup. FNV-1a of body bytes
        // is plenty discriminating without dragging in a heavier hash.
        let response_hash = fnv1a_64(&envelope.body);
        let fp = record_probe(ProbeRecord {
            corpus: &mut self.corpus,
            coverage: &mut self.coverage,
            outcome,
            rule_id: rule_attribution,
            payload,
            payload_class,
            encoding_chain,
            response_hash,
            egress_label,
            target_host,
            pop_raw,
        });
        let is_novel = !self.h1_archive.contains(&fp);
        if outcome == ProbeOutcome::Bypass && is_novel {
            self.novel_bypass_count = self.novel_bypass_count.saturating_add(1);
        }
        (fp, is_novel)
    }

    /// Persist corpus + coverage to disk. Operators call this
    /// periodically (every N probes) or once at end-of-run.
    pub fn flush(&self) -> std::io::Result<()> {
        self.corpus.save_atomic(&self.corpus_path)?;
        self.coverage.save_atomic(&self.coverage_path)?;
        Ok(())
    }

    /// Borrow the corpus for read-only inspection (CLI status output).
    #[must_use]
    pub fn corpus(&self) -> &RuleBypassCorpus {
        &self.corpus
    }

    /// Borrow the coverage map for read-only inspection.
    #[must_use]
    pub fn coverage(&self) -> &EdgePopCoverage {
        &self.coverage
    }

    /// Total probes recorded since startup.
    #[must_use]
    pub fn probe_count(&self) -> u64 {
        self.probe_count
    }

    /// Confirmed-novel bypasses (not already in the H1 archive).
    #[must_use]
    pub fn novel_bypass_count(&self) -> u64 {
        self.novel_bypass_count
    }
}

/// FNV-1a 64-bit hash of a byte slice.
fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(prefix: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "wafrift_recorder_test_{}_{}_{}",
            prefix,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ))
    }

    fn cls() -> PayloadClass {
        PayloadClass::new("sql")
    }

    fn envelope_with_cf_block() -> ProbeEnvelope {
        ProbeEnvelope {
            status: 403,
            headers: vec![
                ("cf-ray".to_string(), "8a1b2c3d4e5f6a7b-SJC".to_string()),
                ("cf-mitigated".to_string(), "block".to_string()),
                ("server".to_string(), "cloudflare".to_string()),
            ],
            body: b"<html><body>Sorry, you have been blocked</body></html>".to_vec(),
            blocked: true,
            latency_ms: 12.3,
        }
    }

    fn envelope_no_cf() -> ProbeEnvelope {
        ProbeEnvelope {
            status: 200,
            headers: vec![("server".to_string(), "nginx".to_string())],
            body: b"OK".to_vec(),
            blocked: false,
            latency_ms: 4.2,
        }
    }

    #[test]
    fn record_cf_block_populates_corpus_and_coverage() {
        let corpus_p = tmp("corpus_cf");
        let coverage_p = tmp("coverage_cf");
        let mut r = CorpusRecorder::new(
            "cf:cumulus:example.com",
            corpus_p.clone(),
            coverage_p.clone(),
            None,
        );
        let env = envelope_with_cf_block();
        let (_, _) = r.record(
            &env,
            "' OR 1=1--",
            cls(),
            vec!["url".into()],
            "egress-a",
            "example.com",
            ProbeOutcome::Block,
        );
        assert!(r.corpus().total_blocks() >= 1);
        // SJC was the cf-ray POP suffix.
        let pops = r.coverage().pops_for("egress-a", "example.com");
        assert!(pops.contains("SJC"), "coverage must record SJC POP, got {pops:?}");
        assert_eq!(r.probe_count(), 1);
        let _ = std::fs::remove_file(&corpus_p);
        let _ = std::fs::remove_file(&coverage_p);
    }

    #[test]
    fn record_non_cf_response_uses_unattributed_bucket() {
        let corpus_p = tmp("corpus_no_cf");
        let coverage_p = tmp("coverage_no_cf");
        let mut r = CorpusRecorder::new(
            "non-cf-target",
            corpus_p.clone(),
            coverage_p.clone(),
            None,
        );
        let env = envelope_no_cf();
        let (_, _) = r.record(
            &env,
            "benign",
            cls(),
            vec![],
            "egress-a",
            "no-cf.example",
            ProbeOutcome::Block,
        );
        // No CF POP observed → coverage probe_count incremented but no POP.
        assert!(r.coverage().pops_for("egress-a", "no-cf.example").is_empty());
        assert_eq!(r.coverage().probes_for("egress-a", "no-cf.example"), 1);
        let _ = std::fs::remove_file(&corpus_p);
        let _ = std::fs::remove_file(&coverage_p);
    }

    #[test]
    fn flush_persists_corpus_and_coverage() {
        let corpus_p = tmp("corpus_flush");
        let coverage_p = tmp("coverage_flush");
        let mut r = CorpusRecorder::new(
            "tf",
            corpus_p.clone(),
            coverage_p.clone(),
            None,
        );
        let env = envelope_with_cf_block();
        let _ = r.record(
            &env,
            "p",
            cls(),
            vec![],
            "e",
            "h",
            ProbeOutcome::Bypass,
        );
        r.flush().unwrap();
        assert!(corpus_p.exists());
        assert!(coverage_p.exists());
        // Load back and verify content.
        let r2 = CorpusRecorder::new(
            "tf",
            corpus_p.clone(),
            coverage_p.clone(),
            None,
        );
        assert!(r2.corpus().total_bypasses() >= 1);
        let _ = std::fs::remove_file(&corpus_p);
        let _ = std::fs::remove_file(&coverage_p);
    }

    #[test]
    fn novel_bypass_count_excludes_h1_archive_hits() {
        let corpus_p = tmp("corpus_h1");
        let coverage_p = tmp("coverage_h1");
        let archive_p = tmp("h1_archive");
        // Pre-seed archive with the fingerprint of "p" under rule cf:SJC:?
        let mut archive = H1Archive::new();
        let fp = wafrift_evolution::h1_dedup::fingerprint(
            "cf:SJC:?",
            &[],
            "p",
        );
        archive.add_report(&fp);
        archive.save_atomic(&archive_p).unwrap();

        let mut r = CorpusRecorder::new(
            "t",
            corpus_p.clone(),
            coverage_p.clone(),
            Some(archive_p.clone()),
        );
        let env = envelope_with_cf_block();
        let (_, is_novel) = r.record(
            &env,
            "p",
            cls(),
            vec![],
            "e",
            "h",
            ProbeOutcome::Bypass,
        );
        // The cf-ray sets POP=SJC and ruleset_hint absent (`?`) — the
        // pre-seeded fingerprint with key "cf:SJC:?" matches.
        assert!(!is_novel, "fingerprint must be flagged as known");
        assert_eq!(r.novel_bypass_count(), 0);
        let _ = std::fs::remove_file(&corpus_p);
        let _ = std::fs::remove_file(&coverage_p);
        let _ = std::fs::remove_file(&archive_p);
    }

    #[test]
    fn fnv1a_64_deterministic_for_same_input() {
        assert_eq!(fnv1a_64(b"hello"), fnv1a_64(b"hello"));
        assert_ne!(fnv1a_64(b"hello"), fnv1a_64(b"world"));
        // Empty input has the FNV-1a offset basis.
        assert_eq!(fnv1a_64(b""), 0xcbf29ce484222325);
    }
}
