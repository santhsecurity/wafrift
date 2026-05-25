//! Per-rule WAF-bypass corpus — persistent {rule_id → bucket} store.
//!
//! [`super::coverage_feedback`] tracks rule_id observations in process
//! memory for the current bench run. This module persists the
//! richer corpus across runs:
//!
//! - The **payload bytes** that triggered each rule (not just the
//!   descriptor — actual reproducible bytes).
//! - The **encoding/grammar/smuggling chain** that produced the payload
//!   so the operator can rebuild any variant by name.
//! - The **bypass set** per rule — payloads that the WAF passed
//!   (the only payloads with bounty value).
//! - **Submission status** so the dry-run-submit grace period gates
//!   HackerOne filing.
//! - **Drift timestamps** so [`super::dilution`] / [`super::coverage_feedback`]
//!   can re-fire bypasses around CF Auto-Tune retrain windows.
//!
//! ## Why a separate module
//!
//! `coverage_feedback` is in the MAP-Elites hot path — every probe
//! response updates it. We do NOT want disk I/O in that loop. The
//! corpus is the **persistence layer** — written at round boundaries
//! (every N probes, or on shutdown). The in-memory `RuleCoverage`
//! observes; the on-disk `RuleBypassCorpus` accumulates.
//!
//! ## Target fingerprint
//!
//! One corpus per TARGET. Cloudflare's Managed Ruleset against
//! `bench/cf-real/` is a different rule surface from AWS WAF's
//! `AWSManagedRulesCommonRuleSet`. The corpus carries a
//! `target_fingerprint` (typically `<vendor>:<ruleset-version>:<host>`)
//! so cross-pollution between targets is impossible.
//!
//! ## File format
//!
//! JSON, schema-versioned. Field additions are backwards-compatible
//! via serde defaults. Schema bumps require an explicit migration in
//! [`RuleBypassCorpus::load_or_default`].
//!
//! ## Concurrency
//!
//! Mid-hunt, multiple async workers may want to write the corpus.
//! [`RuleBypassCorpus::save_atomic`] writes to a tempfile in the
//! same directory then renames — POSIX rename is atomic on the same
//! filesystem. Callers serialize their writes with a `Mutex` at the
//! orchestrator level; the file itself is not a synchronization
//! primitive.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::coverage_feedback::{PayloadClass, RuleId};

/// Current on-disk corpus schema version. Bump when a non-additive
/// field change lands; older files load via the upgrade path.
pub const CORPUS_SCHEMA_VERSION: u32 = 1;

/// One attack-payload recorded against a WAF rule.
///
/// Distinguished from [`RecordedBypass`] in two ways:
///
/// 1. **Verdict** — a `RecordedAttempt` was blocked. A `RecordedBypass`
///    was passed.
/// 2. **Submission lifecycle** — only bypasses have submission status
///    fields; blocks are tracked for "we've seen this fail before,
///    don't retry until drift."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedAttempt {
    /// The payload bytes as sent on the wire (after every encoder /
    /// grammar mutation / smuggling wrap).
    pub payload: String,
    /// Attack class (`sql`, `xss`, `cmd`, …) so the corpus can
    /// answer "what classes have we explored against rule X."
    pub payload_class: PayloadClass,
    /// Ordered list of technique identifiers applied to produce this
    /// payload. Operator can rebuild the variant by replaying the chain.
    pub encoding_chain: Vec<String>,
    /// Hash of the response body — collapses near-identical "Sorry,
    /// you have been blocked" pages so the corpus stays compact.
    pub response_hash: u64,
    /// Epoch seconds at observation.
    pub observed_at_secs: u64,
}

/// A confirmed WAF bypass — the WAF passed this payload through to
/// origin (verified by the oracle).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedBypass {
    /// The payload that bypassed.
    pub payload: String,
    pub payload_class: PayloadClass,
    pub encoding_chain: Vec<String>,
    pub response_hash: u64,
    pub observed_at_secs: u64,
    /// Lifecycle status of the bounty submission.
    #[serde(default)]
    pub submission: SubmissionStatus,
}

/// HackerOne submission lifecycle for a single bypass.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "stage", content = "data")]
pub enum SubmissionStatus {
    /// Just discovered; awaiting the dry-run grace window.
    #[default]
    Queued,
    /// Held until `release_at_secs` epoch — first 24h of any new
    /// bypass goes here so we don't fire submissions at 3am.
    DryRunHold { release_at_secs: u64 },
    /// Sent to HackerOne, awaiting triage. `report_id` is the H1
    /// report number.
    Submitted { report_id: String },
    /// H1 accepted the report. `report_id` retained for tracking.
    Accepted { report_id: String },
    /// H1 marked duplicate of a prior report.
    Duplicate { duplicate_of: String },
    /// H1 rejected (informative / NA / out-of-scope).
    Rejected { reason: String },
}

/// All recorded attempts and bypasses for ONE WAF rule.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleBucket {
    /// Rule identifier the corpus is keyed on. Stored redundantly so
    /// a bucket extracted from the map stays self-describing.
    pub rule_id: RuleId,
    /// Optional human-readable rule name when the WAF exposes one
    /// (e.g. CRS rule "942100 — SQL Injection Attack: Detected").
    #[serde(default)]
    pub description: Option<String>,
    /// Payloads that triggered this rule.
    #[serde(default)]
    pub blocked: Vec<RecordedAttempt>,
    /// Payloads that bypassed this rule (passed through to origin).
    #[serde(default)]
    pub bypassed: Vec<RecordedBypass>,
    /// Epoch seconds of last detected ruleset drift — when CF
    /// Auto-Tune retrains, this updates and previously-blocked
    /// payloads become retry-eligible.
    #[serde(default)]
    pub last_drift_at_secs: Option<u64>,
}

/// The full persistent corpus, indexed by rule_id.
///
/// Cheap to clone (BTreeMap of buckets); meant to be held by the
/// hunt orchestrator + read by the bench reporter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleBypassCorpus {
    /// Schema version — load_or_default uses this to migrate older
    /// formats. Always [`CORPUS_SCHEMA_VERSION`] on save.
    #[serde(default)]
    pub schema_version: u32,
    /// Target fingerprint — `<vendor>:<ruleset>:<host>`. Two
    /// fingerprints share no buckets; protect against cross-target
    /// pollution.
    pub target_fingerprint: String,
    /// rule_id → bucket. BTreeMap so iteration is deterministic
    /// (the bench-result determinism contract per Sonnet B's work
    /// extends to this corpus's serialization).
    #[serde(default)]
    pub buckets: BTreeMap<String, RuleBucket>,
    /// Epoch seconds at last save.
    #[serde(default)]
    pub last_saved_at_secs: u64,
}

impl RuleBypassCorpus {
    /// Create a new empty corpus for the given target fingerprint.
    #[must_use]
    pub fn new(target_fingerprint: impl Into<String>) -> Self {
        Self {
            schema_version: CORPUS_SCHEMA_VERSION,
            target_fingerprint: target_fingerprint.into(),
            buckets: BTreeMap::new(),
            last_saved_at_secs: 0,
        }
    }

    /// Load from disk OR return a fresh corpus when:
    /// - The file doesn't exist (first run for this target).
    /// - The file is corrupted (the corpus is operator-private; we
    ///   prefer fresh-start to crashing the bench).
    /// - The schema version is unrecognized and no migration applies.
    ///
    /// `target_fingerprint` is used only when the file doesn't exist
    /// or has to be rebuilt — when the file IS valid its embedded
    /// fingerprint wins (callers should verify the fingerprint matches
    /// what they expect via [`Self::target_fingerprint`]).
    pub fn load_or_default(
        path: &Path,
        target_fingerprint: impl Into<String>,
    ) -> Self {
        let raw = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => return Self::new(target_fingerprint),
        };
        match serde_json::from_str::<Self>(&raw) {
            Ok(mut corpus) => {
                if corpus.schema_version == 0 {
                    corpus.schema_version = CORPUS_SCHEMA_VERSION;
                }
                corpus
            }
            Err(_) => Self::new(target_fingerprint),
        }
    }

    /// Save atomically via tempfile + rename. Returns an error only on
    /// I/O failure; the rename itself is atomic on the same filesystem
    /// so a concurrent reader either sees the prior snapshot or this
    /// one — never a torn write.
    pub fn save_atomic(&self, path: &Path) -> std::io::Result<()> {
        let mut snap = self.clone();
        snap.schema_version = CORPUS_SCHEMA_VERSION;
        snap.last_saved_at_secs = current_epoch_secs();
        let body = serde_json::to_vec_pretty(&snap)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = tempfile_path(path);
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&body)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Get or insert the bucket for `rule_id`. Cheap because we hand
    /// out a `&mut RuleBucket` instead of cloning.
    pub fn bucket_mut(&mut self, rule_id: &str) -> &mut RuleBucket {
        self.buckets
            .entry(rule_id.to_string())
            .or_insert_with(|| RuleBucket {
                rule_id: RuleId::new(rule_id),
                ..RuleBucket::default()
            })
    }

    /// Record a payload that the WAF BLOCKED, tagged with the rule_id
    /// it triggered (if the oracle could attribute it).
    pub fn record_block(
        &mut self,
        rule_id: &str,
        payload: &str,
        payload_class: PayloadClass,
        encoding_chain: Vec<String>,
        response_hash: u64,
    ) {
        let entry = RecordedAttempt {
            payload: payload.to_string(),
            payload_class,
            encoding_chain,
            response_hash,
            observed_at_secs: current_epoch_secs(),
        };
        let bucket = self.bucket_mut(rule_id);
        // Dedup by (response_hash, payload) so re-running the same
        // bench doesn't bloat the file.
        if !bucket.blocked.iter().any(|a| {
            a.response_hash == entry.response_hash && a.payload == entry.payload
        }) {
            bucket.blocked.push(entry);
        }
    }

    /// Record a payload that BYPASSED the WAF. The default submission
    /// status is `Queued`; callers can transition via
    /// [`Self::set_submission`].
    pub fn record_bypass(
        &mut self,
        rule_id: &str,
        payload: &str,
        payload_class: PayloadClass,
        encoding_chain: Vec<String>,
        response_hash: u64,
    ) {
        let entry = RecordedBypass {
            payload: payload.to_string(),
            payload_class,
            encoding_chain,
            response_hash,
            observed_at_secs: current_epoch_secs(),
            submission: SubmissionStatus::Queued,
        };
        let bucket = self.bucket_mut(rule_id);
        if !bucket.bypassed.iter().any(|b| {
            b.response_hash == entry.response_hash && b.payload == entry.payload
        }) {
            bucket.bypassed.push(entry);
        }
    }

    /// Mark a ruleset drift event on a specific rule (e.g. CF
    /// Auto-Tune retrain detected via [`crate::dilution`]'s drift
    /// detector). Triggers "retry the blocked corpus" downstream.
    pub fn mark_drift(&mut self, rule_id: &str) {
        let bucket = self.bucket_mut(rule_id);
        bucket.last_drift_at_secs = Some(current_epoch_secs());
    }

    /// Update the submission status of a previously-recorded bypass.
    /// Returns `true` if the bypass was found and updated.
    pub fn set_submission(
        &mut self,
        rule_id: &str,
        payload: &str,
        new_status: SubmissionStatus,
    ) -> bool {
        if let Some(bucket) = self.buckets.get_mut(rule_id) {
            if let Some(b) = bucket.bypassed.iter_mut().find(|b| b.payload == payload) {
                b.submission = new_status;
                return true;
            }
        }
        false
    }

    /// Rules with fewer than `min_attempts` recorded blocks AND zero
    /// bypasses. The hunt orchestrator targets these first — they're
    /// the unexplored cells of the (rule_id × class) grid.
    #[must_use]
    pub fn unexplored_rules(&self, min_attempts: usize) -> Vec<String> {
        self.buckets
            .iter()
            .filter(|(_, b)| b.blocked.len() < min_attempts && b.bypassed.is_empty())
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Rules where drift was detected within the last `window_secs`
    /// AND there are blocked payloads worth re-firing.
    #[must_use]
    pub fn rules_due_for_retry(&self, window_secs: u64) -> Vec<String> {
        let now = current_epoch_secs();
        self.buckets
            .iter()
            .filter(|(_, b)| {
                b.last_drift_at_secs
                    .is_some_and(|d| now.saturating_sub(d) <= window_secs)
                    && !b.blocked.is_empty()
            })
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// All bypasses recorded against a specific rule (newest last
    /// per insertion order).
    #[must_use]
    pub fn bypasses_for_rule(&self, rule_id: &str) -> &[RecordedBypass] {
        self.buckets
            .get(rule_id)
            .map(|b| b.bypassed.as_slice())
            .unwrap_or(&[])
    }

    /// All blocked attempts recorded against a specific rule.
    #[must_use]
    pub fn blocked_for_rule(&self, rule_id: &str) -> &[RecordedAttempt] {
        self.buckets
            .get(rule_id)
            .map(|b| b.blocked.as_slice())
            .unwrap_or(&[])
    }

    /// Bypasses still in `Queued` status whose dry-run hold has
    /// expired — these are ready for submission to HackerOne.
    ///
    /// `default_dry_run_secs` is applied to bypasses still in
    /// `Queued` state whose `observed_at_secs + default_dry_run_secs`
    /// has passed (most operators leave bypasses queued without
    /// setting an explicit `DryRunHold` and rely on this default).
    #[must_use]
    pub fn novel_bypasses_pending_submission(
        &self,
        default_dry_run_secs: u64,
    ) -> Vec<(&str, &RecordedBypass)> {
        let now = current_epoch_secs();
        let mut out = vec![];
        for (rule_id, bucket) in &self.buckets {
            for b in &bucket.bypassed {
                let ready = match &b.submission {
                    SubmissionStatus::Queued => {
                        now.saturating_sub(b.observed_at_secs) >= default_dry_run_secs
                    }
                    SubmissionStatus::DryRunHold { release_at_secs } => now >= *release_at_secs,
                    _ => false,
                };
                if ready {
                    out.push((rule_id.as_str(), b));
                }
            }
        }
        out
    }

    /// Total bypass count across all rules.
    #[must_use]
    pub fn total_bypasses(&self) -> usize {
        self.buckets.values().map(|b| b.bypassed.len()).sum()
    }

    /// Total block count across all rules.
    #[must_use]
    pub fn total_blocks(&self) -> usize {
        self.buckets.values().map(|b| b.blocked.len()).sum()
    }

    /// Number of distinct rule_ids with at least one observation.
    #[must_use]
    pub fn rules_seen(&self) -> usize {
        self.buckets.len()
    }

    /// Summary suitable for the bench reporter — totals + per-class
    /// breakdown for quick "what did we learn" gut-check.
    #[must_use]
    pub fn summary(&self) -> CoverageSummary {
        let mut per_class: BTreeMap<String, ClassStats> = BTreeMap::new();
        for bucket in self.buckets.values() {
            for b in &bucket.blocked {
                let entry = per_class.entry(b.payload_class.as_str().to_string()).or_default();
                entry.blocks += 1;
            }
            for b in &bucket.bypassed {
                let entry = per_class.entry(b.payload_class.as_str().to_string()).or_default();
                entry.bypasses += 1;
            }
        }
        CoverageSummary {
            target_fingerprint: self.target_fingerprint.clone(),
            rules_seen: self.rules_seen(),
            total_blocks: self.total_blocks(),
            total_bypasses: self.total_bypasses(),
            per_class,
        }
    }
}

/// Per-class block/bypass counts for the corpus summary.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClassStats {
    pub blocks: usize,
    pub bypasses: usize,
}

/// What the bench reporter pulls when it wants a one-line gut-check
/// on the corpus state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageSummary {
    pub target_fingerprint: String,
    pub rules_seen: usize,
    pub total_blocks: usize,
    pub total_bypasses: usize,
    pub per_class: BTreeMap<String, ClassStats>,
}

/// Default disk location for the corpus — `~/.wafrift/corpus/<fingerprint>.json`.
/// Falls back to a `wafrift-bench/results/corpus/` directory under CWD when
/// the home directory can't be resolved.
#[must_use]
pub fn default_corpus_path(target_fingerprint: &str) -> PathBuf {
    let safe = sanitize_fingerprint_for_filename(target_fingerprint);
    if let Some(home) = dirs_home() {
        return home.join(".wafrift").join("corpus").join(format!("{safe}.json"));
    }
    PathBuf::from("wafrift-bench/results/corpus").join(format!("{safe}.json"))
}

/// Sanitize a fingerprint string for use as a filename — strips
/// path separators and other shell-hostile bytes.
fn sanitize_fingerprint_for_filename(fp: &str) -> String {
    fp.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn current_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn tempfile_path(target: &Path) -> PathBuf {
    let mut name = target
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "corpus".to_string());
    name.push_str(".tmp");
    target.with_file_name(name)
}

fn dirs_home() -> Option<PathBuf> {
    // We don't take a hard dep on `dirs` here — read $HOME or
    // %USERPROFILE% directly. Keeps the crate's dep surface tight.
    if let Ok(h) = std::env::var("HOME") {
        if !h.is_empty() {
            return Some(PathBuf::from(h));
        }
    }
    if let Ok(h) = std::env::var("USERPROFILE") {
        if !h.is_empty() {
            return Some(PathBuf::from(h));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn cls(s: &str) -> PayloadClass {
        PayloadClass::new(s)
    }

    #[test]
    fn new_corpus_is_empty() {
        let c = RuleBypassCorpus::new("cf:managed-ruleset:cumulusfire.cloudflare.com");
        assert_eq!(c.rules_seen(), 0);
        assert_eq!(c.total_blocks(), 0);
        assert_eq!(c.total_bypasses(), 0);
        assert_eq!(c.target_fingerprint, "cf:managed-ruleset:cumulusfire.cloudflare.com");
        assert_eq!(c.schema_version, CORPUS_SCHEMA_VERSION);
    }

    #[test]
    fn record_block_dedups_by_payload_and_hash() {
        let mut c = RuleBypassCorpus::new("t");
        c.record_block("942100", "' OR 1=1--", cls("sql"), vec!["url".into()], 0xCAFE);
        c.record_block("942100", "' OR 1=1--", cls("sql"), vec!["url".into()], 0xCAFE);
        c.record_block("942100", "' OR 1=1--", cls("sql"), vec!["url".into()], 0xCAFE);
        assert_eq!(c.blocked_for_rule("942100").len(), 1);
    }

    #[test]
    fn record_block_keeps_distinct_payloads_per_rule() {
        let mut c = RuleBypassCorpus::new("t");
        c.record_block("942100", "' OR 1=1--", cls("sql"), vec![], 1);
        c.record_block("942100", "UNION SELECT 1", cls("sql"), vec![], 2);
        c.record_block("942100", "1' AND 1=1--", cls("sql"), vec![], 3);
        assert_eq!(c.blocked_for_rule("942100").len(), 3);
    }

    #[test]
    fn record_bypass_dedups() {
        let mut c = RuleBypassCorpus::new("t");
        c.record_bypass("942100", "Ω union select", cls("sql"), vec![], 1);
        c.record_bypass("942100", "Ω union select", cls("sql"), vec![], 1);
        assert_eq!(c.bypasses_for_rule("942100").len(), 1);
    }

    #[test]
    fn record_bypass_default_status_is_queued() {
        let mut c = RuleBypassCorpus::new("t");
        c.record_bypass("942100", "payload", cls("sql"), vec![], 1);
        let b = &c.bypasses_for_rule("942100")[0];
        assert!(matches!(b.submission, SubmissionStatus::Queued));
    }

    #[test]
    fn set_submission_updates_lifecycle() {
        let mut c = RuleBypassCorpus::new("t");
        c.record_bypass("942100", "payload", cls("sql"), vec![], 1);
        let ok = c.set_submission(
            "942100",
            "payload",
            SubmissionStatus::Submitted {
                report_id: "H1-12345".into(),
            },
        );
        assert!(ok);
        let b = &c.bypasses_for_rule("942100")[0];
        assert!(matches!(
            &b.submission,
            SubmissionStatus::Submitted { report_id } if report_id == "H1-12345"
        ));
    }

    #[test]
    fn set_submission_missing_returns_false() {
        let mut c = RuleBypassCorpus::new("t");
        let ok = c.set_submission(
            "doesnt-exist",
            "payload",
            SubmissionStatus::Accepted {
                report_id: "X".into(),
            },
        );
        assert!(!ok);
    }

    #[test]
    fn unexplored_rules_skips_ones_with_bypass() {
        let mut c = RuleBypassCorpus::new("t");
        c.record_block("R1", "p1", cls("sql"), vec![], 1);
        c.record_bypass("R2", "p2", cls("sql"), vec![], 2);
        // R1: 1 block, 0 bypasses → unexplored when threshold > 1.
        // R2: 0 blocks, 1 bypass → NOT unexplored.
        let unexplored = c.unexplored_rules(3);
        assert!(unexplored.contains(&"R1".to_string()));
        assert!(!unexplored.contains(&"R2".to_string()));
    }

    #[test]
    fn rules_due_for_retry_respects_window() {
        let mut c = RuleBypassCorpus::new("t");
        c.record_block("R1", "p", cls("sql"), vec![], 1);
        // Drift now, ask for 60s window → should be present.
        c.mark_drift("R1");
        let due = c.rules_due_for_retry(60);
        assert_eq!(due, vec!["R1".to_string()]);
    }

    #[test]
    fn rules_due_for_retry_skips_rules_with_no_blocks() {
        let mut c = RuleBypassCorpus::new("t");
        c.mark_drift("R1");
        // No blocks recorded — nothing to re-try.
        assert!(c.rules_due_for_retry(60).is_empty());
    }

    #[test]
    fn total_counts_aggregate_across_rules() {
        let mut c = RuleBypassCorpus::new("t");
        c.record_block("R1", "p1", cls("sql"), vec![], 1);
        c.record_block("R2", "p2", cls("xss"), vec![], 2);
        c.record_bypass("R1", "p3", cls("sql"), vec![], 3);
        assert_eq!(c.total_blocks(), 2);
        assert_eq!(c.total_bypasses(), 1);
        assert_eq!(c.rules_seen(), 2);
    }

    #[test]
    fn summary_breaks_down_by_class() {
        let mut c = RuleBypassCorpus::new("cf:mr:foo");
        c.record_block("R1", "p1", cls("sql"), vec![], 1);
        c.record_block("R1", "p2", cls("sql"), vec![], 2);
        c.record_block("R2", "p3", cls("xss"), vec![], 3);
        c.record_bypass("R1", "p4", cls("sql"), vec![], 4);
        let s = c.summary();
        assert_eq!(s.target_fingerprint, "cf:mr:foo");
        assert_eq!(s.rules_seen, 2);
        assert_eq!(s.total_blocks, 3);
        assert_eq!(s.total_bypasses, 1);
        let sql_stats = s.per_class.get("sql").unwrap();
        assert_eq!(sql_stats.blocks, 2);
        assert_eq!(sql_stats.bypasses, 1);
        let xss_stats = s.per_class.get("xss").unwrap();
        assert_eq!(xss_stats.blocks, 1);
        assert_eq!(xss_stats.bypasses, 0);
    }

    #[test]
    fn save_load_round_trip() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("corpus.json");
        let mut c = RuleBypassCorpus::new("cf:mr:cumulus");
        c.record_block("942100", "payload-1", cls("sql"), vec!["url".into()], 1);
        c.record_bypass(
            "942100",
            "payload-2",
            cls("sql"),
            vec!["unicode".into(), "case".into()],
            2,
        );
        c.save_atomic(&path).expect("save");

        let reloaded = RuleBypassCorpus::load_or_default(&path, "ignored");
        assert_eq!(reloaded.target_fingerprint, "cf:mr:cumulus");
        assert_eq!(reloaded.rules_seen(), 1);
        assert_eq!(reloaded.total_blocks(), 1);
        assert_eq!(reloaded.total_bypasses(), 1);
        let bp = &reloaded.bypasses_for_rule("942100")[0];
        assert_eq!(bp.payload, "payload-2");
        assert_eq!(bp.encoding_chain, vec!["unicode".to_string(), "case".to_string()]);
    }

    #[test]
    fn load_missing_file_returns_default() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("nope.json");
        let c = RuleBypassCorpus::load_or_default(&path, "cf:mr:x");
        assert_eq!(c.target_fingerprint, "cf:mr:x");
        assert_eq!(c.rules_seen(), 0);
    }

    #[test]
    fn load_corrupted_file_returns_default_not_panic() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("trash.json");
        std::fs::write(&path, b"{not valid json !!!").expect("write");
        let c = RuleBypassCorpus::load_or_default(&path, "fallback");
        // Corrupted → falls back to the supplied target fingerprint.
        assert_eq!(c.target_fingerprint, "fallback");
        assert_eq!(c.rules_seen(), 0);
    }

    #[test]
    fn load_empty_file_returns_default() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("empty.json");
        std::fs::write(&path, b"").expect("write");
        let c = RuleBypassCorpus::load_or_default(&path, "fallback");
        assert_eq!(c.target_fingerprint, "fallback");
    }

    #[test]
    fn save_creates_parent_directory() {
        let dir = tempdir().expect("tempdir");
        let nested = dir.path().join("deep/nested/path/corpus.json");
        let c = RuleBypassCorpus::new("t");
        c.save_atomic(&nested).expect("save creates parents");
        assert!(nested.exists());
    }

    #[test]
    fn save_atomic_no_torn_write_on_existing_file() {
        // Pre-populate the target with garbage. save_atomic should
        // replace it with valid JSON, never leaving a partial state.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("corpus.json");
        std::fs::write(&path, b"prior-garbage-bytes").expect("seed");
        let c = RuleBypassCorpus::new("cf:mr:t");
        c.save_atomic(&path).expect("save");
        let bytes = std::fs::read(&path).expect("read");
        // Should NOT contain the prior garbage.
        assert!(!std::str::from_utf8(&bytes).unwrap().contains("prior-garbage"));
    }

    #[test]
    fn novel_bypasses_pending_submission_honors_dry_run() {
        let mut c = RuleBypassCorpus::new("t");
        c.record_bypass("R1", "fresh", cls("sql"), vec![], 1);
        // Just-recorded with default dry-run 24h → NOT ready.
        let pending = c.novel_bypasses_pending_submission(86400);
        assert!(pending.is_empty(), "fresh bypass should not be pending");

        // With a 0-second dry-run, the same bypass IS ready.
        let pending = c.novel_bypasses_pending_submission(0);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].0, "R1");
    }

    #[test]
    fn novel_bypasses_pending_submission_skips_already_submitted() {
        let mut c = RuleBypassCorpus::new("t");
        c.record_bypass("R1", "p", cls("sql"), vec![], 1);
        c.set_submission(
            "R1",
            "p",
            SubmissionStatus::Submitted {
                report_id: "H1-X".into(),
            },
        );
        let pending = c.novel_bypasses_pending_submission(0);
        assert!(
            pending.is_empty(),
            "Submitted bypass should not appear pending"
        );
    }

    #[test]
    fn novel_bypasses_pending_submission_honors_explicit_hold() {
        let mut c = RuleBypassCorpus::new("t");
        c.record_bypass("R1", "p", cls("sql"), vec![], 1);
        // Explicit hold one hour in the future.
        let future = current_epoch_secs() + 3600;
        c.set_submission(
            "R1",
            "p",
            SubmissionStatus::DryRunHold {
                release_at_secs: future,
            },
        );
        let pending = c.novel_bypasses_pending_submission(0);
        assert!(pending.is_empty(), "explicit DryRunHold must be honored");
    }

    #[test]
    fn schema_version_normalized_on_load() {
        // Simulate an older file without a schema_version.
        let raw = r#"{"target_fingerprint":"t","buckets":{}}"#;
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("c.json");
        std::fs::write(&path, raw).expect("write");
        let c = RuleBypassCorpus::load_or_default(&path, "ignored");
        assert_eq!(c.schema_version, CORPUS_SCHEMA_VERSION);
    }

    #[test]
    fn sanitize_fingerprint_strips_path_separators() {
        assert_eq!(
            sanitize_fingerprint_for_filename("cf:managed-ruleset:host/foo"),
            "cf_managed-ruleset_host_foo"
        );
        // Backslashes become `_`; dots are allowed (used in fingerprint versions).
        // The function strips path SEPARATORS, not all punctuation — `..` in a
        // fingerprint label is semantically distinct from `..` in a file path.
        assert_eq!(
            sanitize_fingerprint_for_filename("..\\..\\evil"),
            ".._.._evil"
        );
    }

    #[test]
    fn sanitize_fingerprint_preserves_safe_chars() {
        let safe = "cf-managed.ruleset_v1";
        assert_eq!(sanitize_fingerprint_for_filename(safe), safe);
    }

    #[test]
    fn default_corpus_path_uses_fingerprint() {
        let p = default_corpus_path("cf:mr:x.com");
        let s = p.to_string_lossy();
        assert!(s.contains("cf_mr_x.com"));
        assert!(s.ends_with(".json"));
    }

    #[test]
    fn determinism_serialization_btree_order() {
        // BTreeMap iteration is deterministic — serializing the same
        // corpus twice must produce identical bytes.
        let mut c = RuleBypassCorpus::new("t");
        for i in (0..50).rev() {
            c.record_block(&format!("R{i}"), &format!("p{i}"), cls("sql"), vec![], i as u64);
        }
        let a = serde_json::to_string(&c).unwrap();
        let b = serde_json::to_string(&c).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn description_field_persists() {
        let mut c = RuleBypassCorpus::new("t");
        c.record_block("942100", "p", cls("sql"), vec![], 1);
        c.bucket_mut("942100").description = Some("SQL injection — OWASP CRS 942100".into());
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("c.json");
        c.save_atomic(&path).expect("save");
        let r = RuleBypassCorpus::load_or_default(&path, "ignored");
        let desc = r.buckets.get("942100").and_then(|b| b.description.as_deref());
        assert_eq!(desc, Some("SQL injection — OWASP CRS 942100"));
    }

    #[test]
    fn mark_drift_updates_timestamp() {
        let mut c = RuleBypassCorpus::new("t");
        c.record_block("R1", "p", cls("sql"), vec![], 1);
        c.mark_drift("R1");
        let t1 = c.buckets["R1"].last_drift_at_secs.unwrap();
        // Subsequent mark_drift updates (within 1s test, monotone).
        std::thread::sleep(std::time::Duration::from_millis(1100));
        c.mark_drift("R1");
        let t2 = c.buckets["R1"].last_drift_at_secs.unwrap();
        assert!(t2 >= t1);
    }

    #[test]
    fn adversarial_large_chain_no_panic() {
        let big_chain: Vec<String> = (0..1000).map(|i| format!("technique-{i}")).collect();
        let mut c = RuleBypassCorpus::new("t");
        c.record_bypass("R1", "p", cls("sql"), big_chain.clone(), 1);
        assert_eq!(c.bypasses_for_rule("R1")[0].encoding_chain.len(), 1000);
    }

    #[test]
    fn adversarial_huge_payload_no_panic() {
        let big = "A".repeat(1_000_000);
        let mut c = RuleBypassCorpus::new("t");
        c.record_block("R1", &big, cls("sql"), vec![], 1);
        // Verify round-trip through serde doesn't OOM on a 1MB payload.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("c.json");
        c.save_atomic(&path).expect("save");
        let r = RuleBypassCorpus::load_or_default(&path, "ignored");
        assert_eq!(r.blocked_for_rule("R1").len(), 1);
        assert_eq!(r.blocked_for_rule("R1")[0].payload.len(), 1_000_000);
    }

    #[test]
    fn unicode_in_payload_round_trips() {
        let mut c = RuleBypassCorpus::new("t");
        c.record_bypass("R1", "ＳＥＬＥＣＴ Ω 中文 \u{200B} \u{E0041}", cls("sql"), vec![], 1);
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("c.json");
        c.save_atomic(&path).expect("save");
        let r = RuleBypassCorpus::load_or_default(&path, "ignored");
        let b = &r.bypasses_for_rule("R1")[0];
        assert!(b.payload.contains("ＳＥＬＥＣＴ"));
        assert!(b.payload.contains("中文"));
        assert!(b.payload.contains('\u{200B}'));
        assert!(b.payload.contains('\u{E0041}'));
    }

    #[test]
    fn dedup_distinguishes_different_response_hashes() {
        let mut c = RuleBypassCorpus::new("t");
        c.record_block("R1", "p", cls("sql"), vec![], 1);
        c.record_block("R1", "p", cls("sql"), vec![], 2); // different hash
        // Same payload + different response = two separate observations
        // (the WAF may have returned different block pages).
        assert_eq!(c.blocked_for_rule("R1").len(), 2);
    }
}
