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
//! - **Submission status** tracking the bounty lifecycle (Queued →
//!   Submitted → Accepted / Duplicate / Rejected) so `wafrift harvest`
//!   skips already-handled bypasses. wafrift never auto-files — filing is
//!   a deliberate, one-at-a-time `wafrift submit` step.
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
    /// Serialized delivery shape that produced this bypass — the EXACT
    /// `(method, path, headers, body)` envelope the winning probe used,
    /// JSON-encoded (`wafrift_grammar::grammar::equiv::DeliveryShape`).
    /// `wafrift harvest` deserializes it to re-fire the *same* request
    /// instead of guessing across standard shapes — the difference
    /// between a recorded number and a reproducible, submittable bypass.
    ///
    /// Stored as an opaque `String` (not the typed shape) so this crate
    /// stays decoupled from the grammar crate — the same deliberate
    /// decoupling as [`Self::encoding_chain`]. Empty for bypasses
    /// recorded before delivery capture, or by strategies with no
    /// equivalence shape; harvest falls back to standard shapes then.
    #[serde(default)]
    pub delivery: String,
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

    /// Maximum corpus size we will read into memory. The corpus is
    /// operator-private, self-authored state (NOT an untrusted download),
    /// so the decompression-bomb threat model behind `safe_io` does not
    /// apply — this ceiling only bounds memory on a pathologically huge
    /// file and sits far above any real corpus. A file larger than this
    /// is *preserved* (moved aside), never silently dropped. (§15 / §1)
    const CORPUS_READ_CEILING_BYTES: usize = 1024 * 1024 * 1024; // 1 GiB

    /// Load from disk, **never destroying recoverable data**.
    ///
    /// Return a fresh corpus ONLY when the file genuinely does not exist
    /// or is empty (first run for this target). Every OTHER outcome on an
    /// *existing, non-empty* file is treated as recoverable bounty data
    /// that must survive:
    ///
    /// - **Too large to read / I-O error** → the file is moved aside to
    ///   `<path>.corrupt-<epoch>` (so a later save can't overwrite it)
    ///   and a loud warning is printed before a fresh corpus is returned.
    /// - **Won't parse** (schema drift, truncation, corruption) → same
    ///   preserve-aside-then-fresh path.
    /// - **Parses, but bloated** → recompacted in memory (per-bucket caps
    ///   re-applied) and returned intact; the next save reclaims the bloat.
    ///   No bypass is ever lost — bypasses are capped generously, far
    ///   above any real hunt.
    ///
    /// This is the fix for the recurring "corpus disappeared" data loss:
    /// the old code returned an empty `Self::new(...)` on ANY read/parse
    /// failure, and the next `save_atomic` atomically overwrote the real
    /// corpus with nothing. A load failure must never silently become an
    /// empty corpus the next save destroys.
    ///
    /// `target_fingerprint` is used only when the file is absent/empty or
    /// had to be preserved-and-rebuilt — when the file IS valid its
    /// embedded fingerprint wins (callers should verify the fingerprint
    /// matches what they expect via [`Self::target_fingerprint`]).
    pub fn load_or_default(
        path: &Path,
        target_fingerprint: impl Into<String>,
    ) -> Self {
        // A genuinely missing file is a legitimate fresh start.
        if !path.exists() {
            return Self::new(target_fingerprint);
        }
        let raw = match crate::safe_io::read_capped_text(path, Self::CORPUS_READ_CEILING_BYTES) {
            Ok(s) => s,
            Err(e) => {
                // Oversize or I-O error on an existing file. We can't
                // read it, but we must NOT let the next save clobber it.
                preserve_unreadable_corpus(path, &format!("read failed: {e}"));
                return Self::new(target_fingerprint);
            }
        };
        // An empty / whitespace-only file is equivalent to absent — a
        // fresh start, with no noisy preserve-aside.
        if raw.trim().is_empty() {
            return Self::new(target_fingerprint);
        }
        match serde_json::from_str::<Self>(&raw) {
            Ok(mut corpus) => {
                if corpus.schema_version == 0 {
                    corpus.schema_version = CORPUS_SCHEMA_VERSION;
                }
                // Recompact a pre-cap / bloated corpus: truncate each
                // bucket to the respective cap on load so the next save
                // reclaims the bloat. Keeps the earliest coverage and
                // harvest samples; bypasses are capped generously so no
                // real harvest material is lost. (§15/§1)
                for bucket in corpus.buckets.values_mut() {
                    bucket.blocked.truncate(Self::MAX_BLOCKED_PER_BUCKET);
                    bucket.bypassed.truncate(Self::MAX_BYPASSED_PER_BUCKET);
                }
                corpus
            }
            Err(e) => {
                // The file exists and is non-empty but won't parse. DO
                // NOT return an empty corpus the next save would write
                // over the original — preserve the bytes aside first.
                preserve_unreadable_corpus(path, &format!("parse failed: {e}"));
                Self::new(target_fingerprint)
            }
        }
    }

    /// Save atomically via tempfile + rename. Returns an error only on
    /// I/O failure; the rename itself is atomic on the same filesystem
    /// so a concurrent reader either sees the prior snapshot or this
    /// one — never a torn write.
    pub fn save_atomic(&self, path: &Path) -> std::io::Result<()> {
        // Rolling backup: before replacing an existing non-empty corpus,
        // snapshot it to `<path>.bak`. One bad save — a logic regression,
        // a parse-fail-induced empty reload that slipped past the loader's
        // preserve guard, a schema drift — is then always one step
        // recoverable. The corpus is irreplaceable bounty data. (§15/§1)
        backup_before_overwrite(path);
        let mut snap = self.clone();
        snap.schema_version = CORPUS_SCHEMA_VERSION;
        snap.last_saved_at_secs = current_epoch_secs();
        let body = serde_json::to_vec_pretty(&snap)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        // R55 pass-19 I4 (CLAUDE.md §7 DEDUP): route through the
        // workspace's canonical atomic writer so the mkdir-parent,
        // unique-tmp-name, fsync, rename(2) sequence lives in ONE
        // place. Pre-fix this module + edge_pop_coverage + h1_dedup
        // each had their own subtly different copy.
        wafrift_types::loaders::write_atomic(path, &body)
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

    /// Max BLOCKED samples retained per rule bucket. Blocked payloads are a
    /// rule-coverage sample, not harvest material (bypasses are uncapped), so a
    /// few hundred per rule fully characterise what a rule blocks. The cap
    /// bounds three real costs a 62 MB CumulusFire corpus surfaced via dogfood
    /// (§15 / §1): corpus growth toward `RULE_CORPUS_MAX_BYTES` (past which the
    /// whole corpus is lost on the next `load_or_default`), `save_atomic` write
    /// size, and the O(n) dedup scan below — which would otherwise make the hot
    /// record path O(n²) over a long hunt.
    const MAX_BLOCKED_PER_BUCKET: usize = 512;

    /// Max BYPASSED samples retained per rule bucket. Bypasses are the primary
    /// harvest material so the cap is generous (8× the blocked cap), but it is
    /// still finite: an adversarial response-varying WAF can grow `bypassed`
    /// without bound, eventually pushing the corpus past `RULE_CORPUS_MAX_BYTES`
    /// — at which point `load_or_default` silently discards the WHOLE corpus
    /// (total data-loss). This cap bounds growth far below that cliff while
    /// preserving virtually all real harvest material encountered in practice.
    /// `load_or_default` truncates over-cap buckets on load to heal corpora
    /// written before this cap was introduced.
    const MAX_BYPASSED_PER_BUCKET: usize = 4096;

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
        // Coverage cap: once a rule has MAX_BLOCKED_PER_BUCKET samples we have
        // characterised what it blocks; stop recording blocked payloads to bound
        // corpus growth and keep the dedup scan below O(cap), not O(n). Bypasses
        // have their own generous cap (MAX_BYPASSED_PER_BUCKET). (§15/§1)
        if bucket.blocked.len() >= Self::MAX_BLOCKED_PER_BUCKET {
            return;
        }
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
            delivery: String::new(),
        };
        let bucket = self.bucket_mut(rule_id);
        // Generous cap: 4 096 bypasses per rule is far more than any real hunt
        // accumulates, but bounds corpus growth away from the 128 MiB load cliff
        // that would silently discard the whole corpus (§15 / §1).
        if bucket.bypassed.len() >= Self::MAX_BYPASSED_PER_BUCKET {
            return;
        }
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
        if let Some(bucket) = self.buckets.get_mut(rule_id)
            && let Some(b) = bucket.bypassed.iter_mut().find(|b| b.payload == payload)
        {
            b.submission = new_status;
            return true;
        }
        false
    }

    /// Attach the serialized delivery shape (see [`RecordedBypass::delivery`])
    /// to a previously-recorded bypass. Returns `true` if the bypass was
    /// found and updated.
    ///
    /// Recorded as a separate step after [`Self::record_bypass`] so the
    /// hot record path (which dedups by `(response_hash, payload)`) stays
    /// unchanged: the recorder calls this once, immediately after the
    /// write, with the shape the winning probe used. A blank `delivery`
    /// is never written — only a non-empty shape overwrites.
    pub fn set_delivery(&mut self, rule_id: &str, payload: &str, delivery: String) -> bool {
        if delivery.is_empty() {
            return false;
        }
        if let Some(bucket) = self.buckets.get_mut(rule_id)
            && let Some(b) = bucket.bypassed.iter_mut().find(|b| b.payload == payload)
        {
            b.delivery = delivery;
            return true;
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
///
/// Allows only `[A-Za-z0-9_-]`; every other character (including `.`)
/// becomes `_`. Excluding `.` prevents a crafted fingerprint such as
/// `..` from producing a `..`-bearing filename component, eliminating
/// even the theoretical path-traversal surface.
fn sanitize_fingerprint_for_filename(fp: &str) -> String {
    fp.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
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

/// Move an existing-but-unreadable corpus file aside to a timestamped
/// sidecar (`<path>.corrupt-<epoch>`) so a subsequent `save_atomic` can
/// never overwrite it, and emit a loud warning naming the preserved file.
///
/// This is the load-side half of the corpus-durability guarantee: an
/// oversize / corrupt / unparseable corpus is *preserved*, never silently
/// discarded. Best-effort — if the file can't be moved aside we still
/// warn (and the save-side [`backup_before_overwrite`] guard provides a
/// second line of defence by copying the file to `<path>.bak` before any
/// overwrite). Never panics; the caller still receives a fresh corpus.
fn preserve_unreadable_corpus(path: &Path, reason: &str) {
    // Unique sidecar name (epoch + pid + nanos) so two corruption events within
    // the same wall-clock second can't collide — a second-granularity name
    // would let the second `rename` replace the first sidecar and lose the
    // earlier corrupt bytes. Mirrors the unique-tmp-name policy `write_atomic`
    // uses. (§15 / §1 — never lose recoverable data.)
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut aside = path.as_os_str().to_owned();
    aside.push(format!(
        ".corrupt-{}-{}-{}",
        current_epoch_secs(),
        std::process::id(),
        nanos
    ));
    let aside = PathBuf::from(aside);
    match std::fs::rename(path, &aside) {
        Ok(()) => eprintln!(
            "wafrift: WARNING — corpus at {} could not be loaded ({reason}). \
             Your data was PRESERVED at {} and a fresh corpus was started. \
             Rename it back once the cause is addressed.",
            path.display(),
            aside.display(),
        ),
        Err(e) => eprintln!(
            "wafrift: ERROR — corpus at {} could not be loaded ({reason}) AND \
             could not be moved aside ({e}). Back this file up MANUALLY before \
             the next run — a save may otherwise overwrite it.",
            path.display(),
        ),
    }
}

/// Snapshot an existing non-empty corpus to `<path>.bak` before it is
/// overwritten by [`RuleBypassCorpus::save_atomic`]. Best-effort; never
/// blocks or fails the save. Empty/absent prior files are skipped (nothing
/// to protect). This is the save-side half of the durability guarantee.
fn backup_before_overwrite(path: &Path) {
    match std::fs::metadata(path) {
        Ok(meta) if meta.len() > 0 => {
            let mut bak = path.as_os_str().to_owned();
            bak.push(".bak");
            let _ = std::fs::copy(path, PathBuf::from(bak));
        }
        _ => {}
    }
}

fn dirs_home() -> Option<PathBuf> {
    // We don't take a hard dep on `dirs` here — read $HOME or
    // %USERPROFILE% directly. Keeps the crate's dep surface tight.
    if let Ok(h) = std::env::var("HOME")
        && !h.is_empty()
    {
        return Some(PathBuf::from(h));
    }
    if let Ok(h) = std::env::var("USERPROFILE")
        && !h.is_empty()
    {
        return Some(PathBuf::from(h));
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
    fn record_block_caps_blocked_per_bucket() {
        // Dogfood-found (§15/§1): a 62 MB CumulusFire corpus came from an
        // UNCAPPED `blocked` array (unique + dedup'd, but unbounded → creeps to
        // the 128 MiB load cliff + an O(n²) dedup scan). Pin the per-bucket cap
        // on blocked; bypasses have their own generous cap (MAX_BYPASSED_PER_BUCKET).
        let mut c = RuleBypassCorpus::new("t");
        let over = RuleBypassCorpus::MAX_BLOCKED_PER_BUCKET + 200;
        for i in 0..over {
            // Distinct payload + hash so dedup never collapses them — only the
            // cap should bound the count.
            c.record_block("r", &format!("p{i}"), cls("sql"), vec![], i as u64);
        }
        assert_eq!(
            c.blocked_for_rule("r").len(),
            RuleBypassCorpus::MAX_BLOCKED_PER_BUCKET,
            "blocked must be capped per bucket"
        );
        // Bypasses have a generous cap (4096). Push well under it — all persist.
        let n_bypass = RuleBypassCorpus::MAX_BLOCKED_PER_BUCKET + 50;
        for i in 0..n_bypass {
            c.record_bypass("r", &format!("b{i}"), cls("sql"), vec![], 1_000_000 + i as u64);
        }
        assert_eq!(
            c.total_bypasses(),
            n_bypass,
            "bypasses under MAX_BYPASSED_PER_BUCKET must all persist"
        );
    }

    #[test]
    fn record_bypass_caps_bypassed_per_bucket() {
        // A response-varying WAF can drive unbounded `bypassed` growth → total
        // corpus loss when it hits the 128 MiB RULE_CORPUS_MAX_BYTES cliff.
        // Pin that the cap is enforced at MAX_BYPASSED_PER_BUCKET. (§15/§1)
        let mut c = RuleBypassCorpus::new("t");
        let over = RuleBypassCorpus::MAX_BYPASSED_PER_BUCKET + 500;
        for i in 0..over {
            // Distinct payload + hash so dedup never collapses — only the cap limits.
            c.record_bypass("r", &format!("b{i}"), cls("sql"), vec![], i as u64);
        }
        assert_eq!(
            c.bypasses_for_rule("r").len(),
            RuleBypassCorpus::MAX_BYPASSED_PER_BUCKET,
            "bypassed must be capped at MAX_BYPASSED_PER_BUCKET"
        );
    }

    #[test]
    fn load_or_default_heals_pre_cap_oversized_blocked() {
        use std::env::temp_dir;
        // A corpus written BEFORE the cap (or hand-edited) may hold >cap
        // blocked entries — e.g. the 62 MB CumulusFire corpus. Loading must
        // truncate each bucket to the cap so the next save reclaims the bloat,
        // while bypasses (harvest material) survive untouched. (§15/§1)
        let mut c = RuleBypassCorpus::new("heal-test");
        let over = RuleBypassCorpus::MAX_BLOCKED_PER_BUCKET + 300;
        let blocked: Vec<RecordedAttempt> = (0..over)
            .map(|i| RecordedAttempt {
                payload: format!("p{i}"),
                payload_class: cls("sql"),
                encoding_chain: vec![],
                response_hash: i as u64,
                observed_at_secs: 0,
            })
            .collect();
        c.buckets.insert(
            "r".to_string(),
            RuleBucket {
                blocked,
                ..RuleBucket::default()
            },
        );
        c.record_bypass("r", "winner", cls("sql"), vec![], 42);

        let path = temp_dir().join(format!("wafrift-corpus-heal-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        c.save_atomic(&path).expect("save oversized corpus");
        let healed = RuleBypassCorpus::load_or_default(&path, "heal-test");
        assert_eq!(
            healed.blocked_for_rule("r").len(),
            RuleBypassCorpus::MAX_BLOCKED_PER_BUCKET,
            "load must truncate over-cap blocked to reclaim the bloat"
        );
        assert_eq!(healed.total_bypasses(), 1, "bypasses survive the heal");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_or_default_heals_pre_cap_oversized_bypassed() {
        use std::env::temp_dir;
        // A corpus written before MAX_BYPASSED_PER_BUCKET was introduced may
        // hold more bypasses than the cap. load_or_default must truncate each
        // bucket's `bypassed` vec to MAX_BYPASSED_PER_BUCKET on load so the
        // next save reclaims the bloat and stays below the 128 MiB cliff.
        // (§15/§1 — mirrors the blocked-heal test above)
        let mut c = RuleBypassCorpus::new("bypass-heal-test");
        let over = RuleBypassCorpus::MAX_BYPASSED_PER_BUCKET + 200;
        // Construct an over-cap bypassed vec directly (bypassing record_bypass's
        // write-time cap) to simulate a legacy on-disk corpus.
        let bypassed: Vec<RecordedBypass> = (0..over)
            .map(|i| RecordedBypass {
                payload: format!("b{i}"),
                payload_class: cls("sql"),
                encoding_chain: vec![],
                response_hash: i as u64,
                observed_at_secs: 0,
                submission: SubmissionStatus::Queued,
                delivery: String::new(),
            })
            .collect();
        c.buckets.insert(
            "r".to_string(),
            RuleBucket {
                bypassed,
                ..RuleBucket::default()
            },
        );
        // Also confirm a blocked entry survives the heal.
        c.record_block("r", "blocker", cls("sql"), vec![], 1);

        let path =
            temp_dir().join(format!("wafrift-corpus-bypass-heal-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        c.save_atomic(&path).expect("save oversized bypass corpus");
        let healed = RuleBypassCorpus::load_or_default(&path, "bypass-heal-test");
        assert_eq!(
            healed.bypasses_for_rule("r").len(),
            RuleBypassCorpus::MAX_BYPASSED_PER_BUCKET,
            "load must truncate over-cap bypassed to MAX_BYPASSED_PER_BUCKET"
        );
        assert_eq!(healed.total_blocks(), 1, "blocked entries survive the heal");
        let _ = std::fs::remove_file(&path);
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
    fn record_bypass_default_delivery_is_empty() {
        let mut c = RuleBypassCorpus::new("t");
        c.record_bypass("R1", "p", cls("sql"), vec![], 1);
        assert_eq!(c.bypasses_for_rule("R1")[0].delivery, "");
    }

    #[test]
    fn set_delivery_attaches_shape_to_recorded_bypass() {
        let mut c = RuleBypassCorpus::new("t");
        c.record_bypass("R1", "p", cls("sql"), vec![], 1);
        let ok = c.set_delivery("R1", "p", "{\"Query\":{\"param\":\"q\"}}".into());
        assert!(ok);
        assert_eq!(c.bypasses_for_rule("R1")[0].delivery, "{\"Query\":{\"param\":\"q\"}}");
    }

    #[test]
    fn set_delivery_missing_bypass_returns_false() {
        let mut c = RuleBypassCorpus::new("t");
        assert!(!c.set_delivery("nope", "p", "{\"PathSegment\":null}".into()));
    }

    #[test]
    fn set_delivery_ignores_empty_string() {
        // A blank delivery must never clobber an already-recorded shape.
        let mut c = RuleBypassCorpus::new("t");
        c.record_bypass("R1", "p", cls("sql"), vec![], 1);
        assert!(c.set_delivery("R1", "p", "\"PathSegment\"".into()));
        assert!(!c.set_delivery("R1", "p", String::new()));
        assert_eq!(c.bypasses_for_rule("R1")[0].delivery, "\"PathSegment\"");
    }

    #[test]
    fn delivery_round_trips_through_save_load() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("c.json");
        let mut c = RuleBypassCorpus::new("cf:mr:cumulus");
        c.record_bypass("942100", "1 OR 1=1 --", cls("sql"), vec![], 9);
        c.set_delivery("942100", "1 OR 1=1 --", "{\"HppSplit\":{\"param\":\"q\",\"parts\":3}}".into());
        c.save_atomic(&path).expect("save");
        let r = RuleBypassCorpus::load_or_default(&path, "ignored");
        assert_eq!(
            r.bypasses_for_rule("942100")[0].delivery,
            "{\"HppSplit\":{\"param\":\"q\",\"parts\":3}}"
        );
    }

    #[test]
    fn delivery_defaults_empty_for_corpus_without_the_field() {
        // Pre-delivery-capture corpus files have no `delivery` key. Prove
        // serde default keeps them loadable (LAW 2 backwards-compat) by
        // STRIPPING the key from a real serialization — robust against the
        // exact RuleId / PayloadClass JSON shape.
        let mut c = RuleBypassCorpus::new("t");
        c.record_bypass("R1", "old", cls("sql"), vec![], 1);
        let mut v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
        for bucket in v["buckets"].as_object_mut().unwrap().values_mut() {
            for bp in bucket["bypassed"].as_array_mut().unwrap() {
                assert!(
                    bp.as_object_mut().unwrap().remove("delivery").is_some(),
                    "serialization must include the delivery key to strip"
                );
            }
        }
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("old.json");
        std::fs::write(&path, serde_json::to_string(&v).unwrap()).expect("write");
        let r = RuleBypassCorpus::load_or_default(&path, "ignored");
        let b = &r.bypasses_for_rule("R1")[0];
        assert_eq!(b.payload, "old");
        assert_eq!(b.delivery, "", "missing delivery must default to empty");
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
    fn load_corrupted_file_preserves_original_then_defaults() {
        // A non-empty, unparseable corpus must NOT be silently dropped.
        // The original bytes are moved aside to a `.corrupt-*` sidecar
        // (so a later save can't clobber them) and a fresh corpus is
        // returned. (Regression: the old behaviour returned an empty
        // corpus that the next save destroyed the original with.)
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("trash.json");
        let original = b"{not valid json !!! but represents 500 lost bypasses";
        std::fs::write(&path, original).expect("write");

        let c = RuleBypassCorpus::load_or_default(&path, "fallback");
        assert_eq!(c.target_fingerprint, "fallback");
        assert_eq!(c.rules_seen(), 0);

        // The original file was moved aside, not left where a save would
        // overwrite it, and the preserved bytes are intact.
        assert!(!path.exists(), "the unparseable file must be moved aside");
        let aside: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .contains("trash.json.corrupt-")
            })
            .collect();
        assert_eq!(aside.len(), 1, "exactly one preserved sidecar must exist");
        let preserved = std::fs::read(aside[0].path()).expect("read sidecar");
        assert_eq!(preserved, original, "preserved bytes must be byte-identical");
    }

    #[test]
    fn load_empty_file_returns_default_without_preserving() {
        // An empty file is equivalent to "no corpus yet" — a clean fresh
        // start, and crucially NO noisy `.corrupt-*` sidecar.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("empty.json");
        std::fs::write(&path, b"").expect("write");
        let c = RuleBypassCorpus::load_or_default(&path, "fallback");
        assert_eq!(c.target_fingerprint, "fallback");
        let has_sidecar = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .any(|e| e.file_name().to_string_lossy().contains(".corrupt-"));
        assert!(!has_sidecar, "empty file must not spawn a preserve sidecar");
    }

    #[test]
    fn save_atomic_backs_up_prior_corpus_before_overwrite() {
        // The save-side durability guard: overwriting an existing
        // non-empty corpus first snapshots it to `<path>.bak`, so one bad
        // save is always one step recoverable.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("corpus.json");

        let mut a = RuleBypassCorpus::new("cf:mr:cumulus");
        a.record_bypass("942100", "winner-A", cls("xss"), vec![], 1);
        a.save_atomic(&path).expect("save A");

        // A second save (e.g. a regression that produced an EMPTY corpus)
        // must leave the prior good corpus recoverable in `.bak`.
        let empty = RuleBypassCorpus::new("cf:mr:cumulus");
        empty.save_atomic(&path).expect("save empty over A");

        let bak = dir.path().join("corpus.json.bak");
        assert!(bak.exists(), "a .bak snapshot of the prior corpus must exist");
        let recovered = RuleBypassCorpus::load_or_default(&bak, "ignored");
        assert_eq!(
            recovered.total_bypasses(),
            1,
            "the prior bypass must be recoverable from the .bak snapshot"
        );
        assert_eq!(recovered.bypasses_for_rule("942100")[0].payload, "winner-A");
    }

    #[test]
    fn corrupt_then_save_does_not_destroy_preserved_bypasses() {
        // End-to-end: a corpus file goes corrupt, the recorder reloads
        // (gets a fresh corpus) and saves an empty one — the real bypasses
        // must still be on disk in the preserved sidecar. This is the
        // exact "corpus disappeared" sequence, now non-destructive.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("corpus.json");

        // A real corpus existed and was later corrupted (truncated mid
        // write by a crash, NFS hiccup, schema drift, ...).
        let mut real = RuleBypassCorpus::new("cf:mr:cumulus");
        for i in 0..50 {
            real.record_bypass("942100", &format!("bypass-{i}"), cls("xss"), vec![], i);
        }
        let real_bytes = serde_json::to_vec_pretty(&real).unwrap();
        // Simulate corruption: keep the (parseable-looking) bytes but break them.
        let mut corrupt = real_bytes.clone();
        corrupt.truncate(corrupt.len() / 2);
        std::fs::write(&path, &corrupt).expect("write corrupt");

        // Recorder reloads → fresh corpus → saves empty.
        let fresh = RuleBypassCorpus::load_or_default(&path, "cf:mr:cumulus");
        assert_eq!(fresh.total_bypasses(), 0);
        fresh.save_atomic(&path).expect("save fresh");

        // The corrupt bytes were preserved in a sidecar — not destroyed.
        let aside: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".corrupt-"))
            .collect();
        assert_eq!(aside.len(), 1, "corrupt bytes must be preserved aside");
        assert_eq!(
            std::fs::read(aside[0].path()).unwrap(),
            corrupt,
            "preserved sidecar must hold the exact corrupt bytes for manual recovery"
        );
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
        // Backslashes AND dots become `_`; a `..` fingerprint can never produce
        // a `..`-bearing filename component (path-traversal hygiene).
        assert_eq!(
            sanitize_fingerprint_for_filename("..\\..\\evil"),
            "______evil"
        );
    }

    #[test]
    fn sanitize_fingerprint_preserves_safe_chars() {
        // Only [A-Za-z0-9_-] pass through unchanged; dots map to `_`.
        assert_eq!(
            sanitize_fingerprint_for_filename("cf-managed_ruleset_v1"),
            "cf-managed_ruleset_v1"
        );
        // A dot-containing fingerprint segment gets its dots replaced.
        assert_eq!(
            sanitize_fingerprint_for_filename("cf-managed.ruleset_v1"),
            "cf-managed_ruleset_v1"
        );
    }

    #[test]
    fn default_corpus_path_uses_fingerprint() {
        let p = default_corpus_path("cf:mr:x.com");
        let s = p.to_string_lossy();
        // dots in fingerprint are replaced by `_` in the filename
        assert!(s.contains("cf_mr_x_com"));
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

    // ====================================================================
    // Durability / preservation adversarial + boundary + property tests.
    //
    // Contract under test (corpus-durability fix):
    //   missing/empty/whitespace  -> fresh corpus, NO sidecar
    //   oversize-but-valid         -> recompact + keep (1 GiB ceiling)
    //   unparseable / IO / non-UTF8 -> move file aside to
    //       `<path>.corrupt-<epoch>` with BYTE-IDENTICAL content, then fresh
    //   save_atomic over non-empty prior -> snapshot prior to `<path>.bak`
    //
    // Every assertion checks real bytes / contents — never just !is_empty().
    // ====================================================================

    /// Collect every `<base>.corrupt-*` sidecar in `dir`.
    fn corrupt_sidecars(dir: &Path, base: &str) -> Vec<PathBuf> {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                name.starts_with(base) && name.contains(".corrupt-")
            })
            .map(|e| e.path())
            .collect()
    }

    /// Assert the load preserved `original` byte-for-byte in exactly one
    /// sidecar, returned a fresh corpus, and moved the original path aside.
    fn assert_preserved_fresh(
        dir: &Path,
        path: &Path,
        base: &str,
        original: &[u8],
        fingerprint: &str,
    ) {
        let c = RuleBypassCorpus::load_or_default(path, fingerprint);
        assert_eq!(c.target_fingerprint, fingerprint, "fresh corpus uses fallback fp");
        assert_eq!(c.rules_seen(), 0, "returned corpus must be fresh/empty");
        assert_eq!(c.total_bypasses(), 0);
        assert_eq!(c.total_blocks(), 0);
        assert!(!path.exists(), "the unreadable original must be moved aside");
        let aside = corrupt_sidecars(dir, base);
        assert_eq!(aside.len(), 1, "exactly one preserved sidecar must exist");
        let preserved = std::fs::read(&aside[0]).expect("read sidecar");
        assert_eq!(
            preserved, original,
            "preserved sidecar bytes must be byte-identical to the original"
        );
    }

    // ---- Preservation: unparseable / non-UTF8 / truncated / partial -----

    #[test]
    fn preserve_non_utf8_file_byte_identical() {
        // Invalid UTF-8 fails inside read_capped_text -> read-failed branch ->
        // preserved aside. Bytes must survive exactly (a binary-corrupted
        // corpus is still recoverable material).
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("nonutf8.json");
        // Lone continuation + invalid lead bytes — definitively not UTF-8.
        let original: &[u8] = &[0x7B, 0xFF, 0xFE, 0x80, 0xC0, 0x22, 0x6B, 0x65, 0x79];
        std::fs::write(&path, original).expect("write");
        assert_preserved_fresh(dir.path(), &path, "nonutf8.json", original, "fb");
    }

    #[test]
    fn preserve_truncated_mid_json_byte_identical() {
        // A write/crash truncated the file mid-token. Non-empty + unparseable
        // -> preserve aside, fresh corpus.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("trunc.json");
        let original = br#"{"schema_version":1,"target_fingerprint":"cf:mr:x","buckets":{"942100":{"rule_id":{"#;
        std::fs::write(&path, original).expect("write");
        assert_preserved_fresh(dir.path(), &path, "trunc.json", original, "fb");
    }

    #[test]
    fn preserve_lone_open_brace_byte_identical() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("brace.json");
        let original = b"{";
        std::fs::write(&path, original).expect("write");
        assert_preserved_fresh(dir.path(), &path, "brace.json", original, "fb");
    }

    #[test]
    fn preserve_valid_json_wrong_schema_byte_identical() {
        // Syntactically valid JSON but NOT a corpus (missing the required
        // non-default `target_fingerprint` field) -> serde fails -> preserved.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("wrongschema.json");
        let original = br#"{"completely":"different","shape":[1,2,3],"nested":{"a":true}}"#;
        std::fs::write(&path, original).expect("write");
        assert_preserved_fresh(dir.path(), &path, "wrongschema.json", original, "fb");
    }

    #[test]
    fn preserve_json_array_instead_of_object_byte_identical() {
        // A top-level array is valid JSON but the wrong type for the corpus.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("arr.json");
        let original = br#"["this","is","not","a","corpus"]"#;
        std::fs::write(&path, original).expect("write");
        assert_preserved_fresh(dir.path(), &path, "arr.json", original, "fb");
    }

    #[test]
    fn preserve_garbage_text_byte_identical() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("garbage.json");
        let original = b"this is not json at all -- 500 lost bypasses live here\n\x01\x02";
        std::fs::write(&path, original).expect("write");
        assert_preserved_fresh(dir.path(), &path, "garbage.json", original, "fb");
    }

    #[test]
    fn preserve_moves_aside_on_every_corruption_event() {
        // Each corrupt load moves the original path aside into a
        // `.corrupt-<epoch>` sidecar with its EXACT bytes, and always returns
        // a fresh corpus (the original is never left where a save could
        // overwrite it). NOTE: the sidecar name carries only epoch-SECOND
        // granularity, so two corruptions within the same wall-clock second
        // map to the same sidecar name and the second rename replaces the
        // first — i.e. at second resolution at least the most-recent corrupt
        // bytes are always recoverable. We assert that guaranteed property
        // (the latest corruption's exact bytes survive) plus the move-aside
        // and fresh-corpus invariants that hold on every event.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("multi.json");

        let first = b"FIRST corrupt corpus bytes !!!";
        std::fs::write(&path, first).expect("write 1");
        let c1 = RuleBypassCorpus::load_or_default(&path, "fb");
        assert_eq!(c1.rules_seen(), 0, "fresh corpus after first corruption");
        assert!(!path.exists(), "original moved aside after first corruption");

        let second = b"SECOND corrupt corpus bytes ???";
        std::fs::write(&path, second).expect("write 2");
        let c2 = RuleBypassCorpus::load_or_default(&path, "fb");
        assert_eq!(c2.rules_seen(), 0, "fresh corpus after second corruption");
        assert!(!path.exists(), "original moved aside after second corruption");

        // The latest corruption's exact bytes are always recoverable.
        let bytes: Vec<Vec<u8>> = corrupt_sidecars(dir.path(), "multi.json")
            .iter()
            .map(|p| std::fs::read(p).unwrap())
            .collect();
        assert!(
            bytes.iter().any(|b| b.as_slice() == second.as_slice()),
            "latest corruption's exact bytes must be preserved aside"
        );
    }

    // ---- Empty / whitespace -> fresh, NO sidecar ------------------------

    #[test]
    fn whitespace_only_file_is_fresh_no_sidecar() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("ws.json");
        std::fs::write(&path, b"   \n\t  \r\n   ").expect("write");
        let c = RuleBypassCorpus::load_or_default(&path, "fb");
        assert_eq!(c.target_fingerprint, "fb");
        assert_eq!(c.rules_seen(), 0);
        assert!(
            corrupt_sidecars(dir.path(), "ws.json").is_empty(),
            "whitespace-only file must NOT spawn a preserve sidecar"
        );
        // The whitespace file itself is treated as absent — left in place, not
        // moved aside (only unreadable/unparseable files are preserved-aside).
        assert!(path.exists(), "whitespace file is not moved aside");
    }

    #[test]
    fn empty_file_leaves_no_sidecar_and_returns_fresh() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("zero.json");
        std::fs::write(&path, b"").expect("write");
        let c = RuleBypassCorpus::load_or_default(&path, "fb");
        assert_eq!(c.rules_seen(), 0);
        assert!(corrupt_sidecars(dir.path(), "zero.json").is_empty());
    }

    // ---- save_atomic .bak behaviour ------------------------------------

    #[test]
    fn bak_recovers_first_corpus_after_empty_second_save() {
        // First save writes real bypasses; a second (empty) save must leave
        // the FIRST corpus fully recoverable from `<path>.bak`.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("c.json");

        let mut first = RuleBypassCorpus::new("cf:mr:cumulus");
        first.record_bypass("942100", "winner-A", cls("xss"), vec!["b64".into()], 7);
        first.record_bypass("942100", "winner-B", cls("sql"), vec![], 8);
        first.record_block("942100", "blk", cls("sql"), vec![], 9);
        first.save_atomic(&path).expect("save first");

        let empty = RuleBypassCorpus::new("cf:mr:cumulus");
        empty.save_atomic(&path).expect("save empty");

        let bak = dir.path().join("c.json.bak");
        assert!(bak.exists(), ".bak must exist after overwriting a non-empty corpus");
        let recovered = RuleBypassCorpus::load_or_default(&bak, "ignored");
        assert_eq!(recovered.total_bypasses(), 2, "both prior bypasses recoverable");
        assert_eq!(recovered.total_blocks(), 1, "prior block recoverable");
        let payloads: Vec<_> = recovered
            .bypasses_for_rule("942100")
            .iter()
            .map(|b| b.payload.clone())
            .collect();
        assert_eq!(payloads, vec!["winner-A".to_string(), "winner-B".to_string()]);
        assert_eq!(recovered.bypasses_for_rule("942100")[0].encoding_chain, vec!["b64".to_string()]);
    }

    #[test]
    fn bak_skipped_when_no_prior_file() {
        // First-ever save (no prior file) must NOT create a .bak — there is
        // nothing to protect.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("c.json");
        let mut c = RuleBypassCorpus::new("t");
        c.record_bypass("R1", "p", cls("sql"), vec![], 1);
        c.save_atomic(&path).expect("save");
        assert!(
            !dir.path().join("c.json.bak").exists(),
            "no .bak on the first save (no prior file)"
        );
    }

    #[test]
    fn bak_skipped_when_prior_file_empty() {
        // An empty prior file has nothing worth protecting — backup is skipped.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("c.json");
        std::fs::write(&path, b"").expect("seed empty");
        let mut c = RuleBypassCorpus::new("t");
        c.record_bypass("R1", "p", cls("sql"), vec![], 1);
        c.save_atomic(&path).expect("save over empty");
        assert!(
            !dir.path().join("c.json.bak").exists(),
            "empty prior file must not be backed up"
        );
    }

    #[test]
    fn bak_holds_exact_prior_bytes() {
        // The .bak must be a byte-exact copy of the prior on-disk file, not a
        // re-serialization. Prove by comparing bytes captured before overwrite.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("c.json");
        let mut first = RuleBypassCorpus::new("cf:mr:x");
        first.record_bypass("R1", "p", cls("sql"), vec![], 1);
        first.save_atomic(&path).expect("save first");
        let prior_bytes = std::fs::read(&path).expect("read prior");

        let mut second = RuleBypassCorpus::new("cf:mr:x");
        second.record_bypass("R2", "q", cls("xss"), vec![], 2);
        second.save_atomic(&path).expect("save second");

        let bak_bytes = std::fs::read(dir.path().join("c.json.bak")).expect("read bak");
        assert_eq!(bak_bytes, prior_bytes, ".bak must be a byte-exact snapshot of the prior file");
    }

    #[test]
    fn bak_round_trips_then_main_continues() {
        // After a bad empty save, recover from .bak, re-save it, and confirm
        // the corpus is whole again on the main path.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("c.json");
        let mut good = RuleBypassCorpus::new("cf:mr:x");
        good.record_bypass("R1", "keep-me", cls("sql"), vec![], 1);
        good.save_atomic(&path).expect("save good");
        RuleBypassCorpus::new("cf:mr:x").save_atomic(&path).expect("save empty");

        let bak = dir.path().join("c.json.bak");
        let recovered = RuleBypassCorpus::load_or_default(&bak, "x");
        recovered.save_atomic(&path).expect("restore");
        let reloaded = RuleBypassCorpus::load_or_default(&path, "x");
        assert_eq!(reloaded.bypasses_for_rule("R1").len(), 1);
        assert_eq!(reloaded.bypasses_for_rule("R1")[0].payload, "keep-me");
    }

    // ---- End-to-end "corpus disappeared" with NON-UTF8 corruption ------

    #[test]
    fn end_to_end_corpus_disappeared_non_utf8() {
        // Real corpus on disk -> binary corruption (non-UTF8) -> reload (fresh)
        // -> save empty over it. The corrupt bytes must be preserved in a
        // sidecar; the empty save must NOT have destroyed recoverable bytes.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("corpus.json");

        let mut real = RuleBypassCorpus::new("cf:mr:cumulus");
        for i in 0..30 {
            real.record_bypass("942100", &format!("bypass-{i}"), cls("xss"), vec![], i);
        }
        real.save_atomic(&path).expect("save real");

        // Corrupt with raw non-UTF8 bytes (e.g. partial NFS write of binary).
        let corrupt: &[u8] = &[0x00, 0xFF, 0x80, 0x7B, 0xC3, 0x28, 0x42];
        std::fs::write(&path, corrupt).expect("corrupt");

        let fresh = RuleBypassCorpus::load_or_default(&path, "cf:mr:cumulus");
        assert_eq!(fresh.total_bypasses(), 0);
        fresh.save_atomic(&path).expect("save fresh empty");

        let aside = corrupt_sidecars(dir.path(), "corpus.json");
        assert_eq!(aside.len(), 1, "corrupt non-UTF8 bytes preserved aside");
        assert_eq!(
            std::fs::read(&aside[0]).unwrap(),
            corrupt,
            "sidecar holds the exact corrupt bytes"
        );
    }

    // ---- Per-bucket heal on load (mixed) -------------------------------

    #[test]
    fn heal_truncates_blocked_but_keeps_all_bypasses() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("c.json");
        let mut c = RuleBypassCorpus::new("heal");
        let over = RuleBypassCorpus::MAX_BLOCKED_PER_BUCKET + 100;
        let blocked: Vec<RecordedAttempt> = (0..over)
            .map(|i| RecordedAttempt {
                payload: format!("blk{i}"),
                payload_class: cls("sql"),
                encoding_chain: vec![],
                response_hash: i as u64,
                observed_at_secs: 0,
            })
            .collect();
        // Under-cap bypasses must all survive the heal untouched.
        let bypassed: Vec<RecordedBypass> = (0..10)
            .map(|i| RecordedBypass {
                payload: format!("by{i}"),
                payload_class: cls("xss"),
                encoding_chain: vec![],
                response_hash: 1_000 + i as u64,
                observed_at_secs: 0,
                submission: SubmissionStatus::Queued,
                delivery: String::new(),
            })
            .collect();
        c.buckets.insert("r".into(), RuleBucket { blocked, bypassed, ..RuleBucket::default() });
        c.save_atomic(&path).expect("save");

        let healed = RuleBypassCorpus::load_or_default(&path, "heal");
        assert_eq!(
            healed.blocked_for_rule("r").len(),
            RuleBypassCorpus::MAX_BLOCKED_PER_BUCKET
        );
        // The earliest blocked sample is kept (truncate keeps the prefix).
        assert_eq!(healed.blocked_for_rule("r")[0].payload, "blk0");
        assert_eq!(healed.bypasses_for_rule("r").len(), 10, "under-cap bypasses untouched");
        assert_eq!(healed.bypasses_for_rule("r")[9].payload, "by9");
    }

    #[test]
    fn heal_leaves_under_cap_bucket_untouched() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("c.json");
        let mut c = RuleBypassCorpus::new("t");
        for i in 0..5 {
            c.record_block("r", &format!("b{i}"), cls("sql"), vec![], i);
            c.record_bypass("r", &format!("p{i}"), cls("sql"), vec![], 100 + i);
        }
        c.save_atomic(&path).expect("save");
        let healed = RuleBypassCorpus::load_or_default(&path, "t");
        assert_eq!(healed.blocked_for_rule("r").len(), 5);
        assert_eq!(healed.bypasses_for_rule("r").len(), 5);
        // Order + exact payloads preserved.
        assert_eq!(healed.blocked_for_rule("r")[4].payload, "b4");
        assert_eq!(healed.bypasses_for_rule("r")[0].payload, "p0");
    }

    #[test]
    fn heal_truncated_bypassed_keeps_blocked_and_prefix() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("c.json");
        let mut c = RuleBypassCorpus::new("t");
        let over = RuleBypassCorpus::MAX_BYPASSED_PER_BUCKET + 17;
        let bypassed: Vec<RecordedBypass> = (0..over)
            .map(|i| RecordedBypass {
                payload: format!("by{i}"),
                payload_class: cls("sql"),
                encoding_chain: vec![],
                response_hash: i as u64,
                observed_at_secs: 0,
                submission: SubmissionStatus::Queued,
                delivery: String::new(),
            })
            .collect();
        c.buckets.insert("r".into(), RuleBucket { bypassed, ..RuleBucket::default() });
        c.bucket_mut("r").blocked.push(RecordedAttempt {
            payload: "survivor".into(),
            payload_class: cls("sql"),
            encoding_chain: vec![],
            response_hash: 9,
            observed_at_secs: 0,
        });
        c.save_atomic(&path).expect("save");
        let healed = RuleBypassCorpus::load_or_default(&path, "t");
        assert_eq!(
            healed.bypasses_for_rule("r").len(),
            RuleBypassCorpus::MAX_BYPASSED_PER_BUCKET
        );
        assert_eq!(healed.bypasses_for_rule("r")[0].payload, "by0", "kept prefix");
        assert_eq!(healed.blocked_for_rule("r").len(), 1);
        assert_eq!(healed.blocked_for_rule("r")[0].payload, "survivor");
    }

    // ---- schema_version normalization ----------------------------------

    #[test]
    fn schema_version_zero_normalized_to_current() {
        // An explicit `schema_version: 0` must be upgraded to the current
        // version on load (0 is the serde-default sentinel for "old file").
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("c.json");
        let raw = r#"{"schema_version":0,"target_fingerprint":"t","buckets":{}}"#;
        std::fs::write(&path, raw).expect("write");
        let c = RuleBypassCorpus::load_or_default(&path, "ignored");
        assert_eq!(c.schema_version, CORPUS_SCHEMA_VERSION);
        assert_eq!(c.target_fingerprint, "t", "embedded fingerprint wins for valid file");
    }

    #[test]
    fn schema_version_missing_normalized_to_current() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("c.json");
        // No schema_version key at all -> serde default 0 -> normalized.
        let raw = r#"{"target_fingerprint":"emb","buckets":{}}"#;
        std::fs::write(&path, raw).expect("write");
        let c = RuleBypassCorpus::load_or_default(&path, "ignored");
        assert_eq!(c.schema_version, CORPUS_SCHEMA_VERSION);
        assert_eq!(c.target_fingerprint, "emb");
    }

    #[test]
    fn valid_file_fingerprint_overrides_fallback() {
        // When the file is valid, its embedded fingerprint wins; the passed
        // fallback fingerprint is ignored.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("c.json");
        let mut c = RuleBypassCorpus::new("embedded-fp");
        c.record_bypass("R1", "p", cls("sql"), vec![], 1);
        c.save_atomic(&path).expect("save");
        let r = RuleBypassCorpus::load_or_default(&path, "fallback-should-be-ignored");
        assert_eq!(r.target_fingerprint, "embedded-fp");
    }

    // ---- delivery defaults / set_delivery edge cases -------------------

    #[test]
    fn old_corpus_loads_with_default_delivery_for_every_bypass() {
        // Multiple bypasses, none with a `delivery` key — all must default
        // to "" and remain fully intact otherwise.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("old.json");
        let mut c = RuleBypassCorpus::new("t");
        c.record_bypass("R1", "a", cls("sql"), vec!["x".into()], 1);
        c.record_bypass("R1", "b", cls("xss"), vec![], 2);
        let mut v: serde_json::Value = serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
        for bucket in v["buckets"].as_object_mut().unwrap().values_mut() {
            for bp in bucket["bypassed"].as_array_mut().unwrap() {
                bp.as_object_mut().unwrap().remove("delivery");
            }
        }
        std::fs::write(&path, serde_json::to_string(&v).unwrap()).expect("write");
        let r = RuleBypassCorpus::load_or_default(&path, "ignored");
        let bps = r.bypasses_for_rule("R1");
        assert_eq!(bps.len(), 2);
        assert_eq!(bps[0].delivery, "");
        assert_eq!(bps[1].delivery, "");
        assert_eq!(bps[0].encoding_chain, vec!["x".to_string()]);
    }

    #[test]
    fn set_delivery_overwrites_existing_shape_with_non_empty() {
        let mut c = RuleBypassCorpus::new("t");
        c.record_bypass("R1", "p", cls("sql"), vec![], 1);
        assert!(c.set_delivery("R1", "p", "\"first\"".into()));
        assert!(c.set_delivery("R1", "p", "\"second\"".into()));
        assert_eq!(c.bypasses_for_rule("R1")[0].delivery, "\"second\"");
    }

    #[test]
    fn set_delivery_empty_on_missing_bucket_returns_false() {
        // Empty delivery short-circuits to false even before bucket lookup.
        let mut c = RuleBypassCorpus::new("t");
        assert!(!c.set_delivery("nope", "p", String::new()));
    }

    #[test]
    fn set_submission_empty_corpus_returns_false() {
        let mut c = RuleBypassCorpus::new("t");
        assert!(!c.set_submission("R1", "p", SubmissionStatus::Queued));
    }

    #[test]
    fn set_submission_bucket_exists_but_payload_absent_returns_false() {
        let mut c = RuleBypassCorpus::new("t");
        c.record_bypass("R1", "present", cls("sql"), vec![], 1);
        assert!(
            !c.set_submission("R1", "absent", SubmissionStatus::Accepted { report_id: "X".into() }),
            "wrong payload in an existing bucket must not match"
        );
        // The real bypass is untouched.
        assert!(matches!(c.bypasses_for_rule("R1")[0].submission, SubmissionStatus::Queued));
    }

    #[test]
    fn submission_status_round_trips_all_variants() {
        // Each lifecycle variant must serialize + deserialize losslessly so a
        // mid-flight bounty status survives a save/load cycle.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("c.json");
        let mut c = RuleBypassCorpus::new("t");
        let variants = [
            ("p0", SubmissionStatus::Queued),
            ("p1", SubmissionStatus::DryRunHold { release_at_secs: 1234 }),
            ("p2", SubmissionStatus::Submitted { report_id: "H1-1".into() }),
            ("p3", SubmissionStatus::Accepted { report_id: "H1-2".into() }),
            ("p4", SubmissionStatus::Duplicate { duplicate_of: "H1-3".into() }),
            ("p5", SubmissionStatus::Rejected { reason: "informative".into() }),
        ];
        for (p, _) in &variants {
            c.record_bypass("R1", p, cls("sql"), vec![], 0);
        }
        for (p, st) in &variants {
            assert!(c.set_submission("R1", p, st.clone()));
        }
        c.save_atomic(&path).expect("save");
        let r = RuleBypassCorpus::load_or_default(&path, "ignored");
        let by_payload: BTreeMap<_, _> = r
            .bypasses_for_rule("R1")
            .iter()
            .map(|b| (b.payload.clone(), b.submission.clone()))
            .collect();
        assert_eq!(by_payload["p1"], SubmissionStatus::DryRunHold { release_at_secs: 1234 });
        assert_eq!(by_payload["p2"], SubmissionStatus::Submitted { report_id: "H1-1".into() });
        assert_eq!(by_payload["p4"], SubmissionStatus::Duplicate { duplicate_of: "H1-3".into() });
        assert_eq!(by_payload["p5"], SubmissionStatus::Rejected { reason: "informative".into() });
    }

    // ---- Determinism / property tests ----------------------------------

    #[test]
    fn determinism_identical_serialization_after_save_load() {
        // Serializing the SAME corpus twice is byte-identical, and a
        // save/load round-trip re-serializes identically (BTreeMap order).
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("c.json");
        let mut c = RuleBypassCorpus::new("t");
        for i in (0..40).rev() {
            c.record_bypass(&format!("R{i:03}"), &format!("p{i}"), cls("sql"), vec![], i);
        }
        let s1 = serde_json::to_string(&c).unwrap();
        let s2 = serde_json::to_string(&c).unwrap();
        assert_eq!(s1, s2);
        c.save_atomic(&path).expect("save");
        let r = RuleBypassCorpus::load_or_default(&path, "ignored");
        // Bucket iteration order is sorted regardless of insertion order.
        let keys: Vec<_> = r.buckets.keys().cloned().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "BTreeMap keys must iterate in sorted order");
    }

    #[test]
    fn btreemap_order_independent_of_insertion_order() {
        // Two corpora with the same rules inserted in opposite orders must
        // serialize identically.
        let mut a = RuleBypassCorpus::new("t");
        let mut b = RuleBypassCorpus::new("t");
        let ids = ["R5", "R1", "R9", "R3", "R7"];
        for id in ids {
            a.record_block(id, "p", cls("sql"), vec![], 1);
        }
        for id in ids.iter().rev() {
            b.record_block(id, "p", cls("sql"), vec![], 1);
        }
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap(),
            "BTreeMap makes serialization insertion-order-independent"
        );
    }

    #[test]
    fn unicode_payload_round_trips_with_exact_bytes() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("c.json");
        let payload = "𝕊𝔼𝕃𝔼ℂ𝕋 ' OR 𝟙=𝟙 -- 中文 \u{200B}\u{FEFF}\u{1F4A9} emoji";
        let mut c = RuleBypassCorpus::new("t");
        c.record_bypass("R1", payload, cls("sql"), vec![], 1);
        c.save_atomic(&path).expect("save");
        let r = RuleBypassCorpus::load_or_default(&path, "ignored");
        assert_eq!(r.bypasses_for_rule("R1")[0].payload, payload, "unicode payload exact");
    }

    #[test]
    fn one_mb_bypass_payload_round_trips_no_oom() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("c.json");
        let big = "A".repeat(1_200_000);
        let mut c = RuleBypassCorpus::new("t");
        c.record_bypass("R1", &big, cls("sql"), vec![], 1);
        c.save_atomic(&path).expect("save");
        let r = RuleBypassCorpus::load_or_default(&path, "ignored");
        assert_eq!(r.bypasses_for_rule("R1")[0].payload.len(), 1_200_000);
        assert!(r.bypasses_for_rule("R1")[0].payload.bytes().all(|b| b == b'A'));
    }

    #[test]
    fn huge_encoding_chain_round_trips() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("c.json");
        let chain: Vec<String> = (0..5000).map(|i| format!("t{i}")).collect();
        let mut c = RuleBypassCorpus::new("t");
        c.record_bypass("R1", "p", cls("sql"), chain.clone(), 1);
        c.save_atomic(&path).expect("save");
        let r = RuleBypassCorpus::load_or_default(&path, "ignored");
        let got = &r.bypasses_for_rule("R1")[0].encoding_chain;
        assert_eq!(got.len(), 5000);
        assert_eq!(got[0], "t0");
        assert_eq!(got[4999], "t4999");
    }

    #[test]
    fn dedup_bypass_by_response_hash_and_payload_property() {
        // Property: across N records, the stored count equals the number of
        // distinct (response_hash, payload) pairs, never more.
        let mut c = RuleBypassCorpus::new("t");
        // 3 distinct pairs, each recorded several times in interleaved order.
        let inputs = [
            ("p", 1u64), ("q", 1), ("p", 2), ("p", 1), ("q", 1), ("p", 2), ("p", 2),
        ];
        for (p, h) in inputs {
            c.record_bypass("R1", p, cls("sql"), vec![], h);
        }
        assert_eq!(c.bypasses_for_rule("R1").len(), 3, "only distinct (hash,payload) survive");
        // Same payload different hash are distinct entries.
        let pairs: std::collections::BTreeSet<(String, u64)> = c
            .bypasses_for_rule("R1")
            .iter()
            .map(|b| (b.payload.clone(), b.response_hash))
            .collect();
        assert!(pairs.contains(&("p".to_string(), 1)));
        assert!(pairs.contains(&("p".to_string(), 2)));
        assert!(pairs.contains(&("q".to_string(), 1)));
    }

    #[test]
    fn drift_timestamp_monotonic_across_remarks() {
        let mut c = RuleBypassCorpus::new("t");
        c.record_block("R1", "p", cls("sql"), vec![], 1);
        c.mark_drift("R1");
        let t1 = c.buckets["R1"].last_drift_at_secs.unwrap();
        // Re-marking never moves the timestamp backwards (epoch is monotone).
        c.mark_drift("R1");
        let t2 = c.buckets["R1"].last_drift_at_secs.unwrap();
        assert!(t2 >= t1, "drift timestamp must be monotonic non-decreasing");
    }

    #[test]
    fn first_save_writes_current_schema_version_to_disk() {
        // save_atomic must stamp CORPUS_SCHEMA_VERSION regardless of the
        // in-memory value, so a corpus constructed with version 0 is healed
        // on its first write.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("c.json");
        let mut c = RuleBypassCorpus::new("t");
        c.schema_version = 0; // force a stale value
        c.record_bypass("R1", "p", cls("sql"), vec![], 1);
        c.save_atomic(&path).expect("save");
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["schema_version"].as_u64().unwrap(), u64::from(CORPUS_SCHEMA_VERSION));
    }

    #[test]
    fn save_stamps_last_saved_at_secs() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("c.json");
        let c = RuleBypassCorpus::new("t");
        assert_eq!(c.last_saved_at_secs, 0);
        c.save_atomic(&path).expect("save");
        let r = RuleBypassCorpus::load_or_default(&path, "t");
        assert!(r.last_saved_at_secs > 0, "save must stamp a real epoch second");
    }

    #[test]
    fn valid_oversize_under_ceiling_is_preserved_not_dropped() {
        // A large-but-valid corpus (well under the 1 GiB ceiling) must load
        // intact — never preserved-aside. Build a multi-MB valid file.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("c.json");
        let mut c = RuleBypassCorpus::new("t");
        // ~3 MB of valid bypasses across buckets (under per-bucket caps).
        for r in 0..30 {
            for i in 0..50 {
                c.record_bypass(
                    &format!("R{r}"),
                    &format!("{}-{r}-{i}", "X".repeat(2000)),
                    cls("sql"),
                    vec![],
                    (r * 1000 + i) as u64,
                );
            }
        }
        c.save_atomic(&path).expect("save");
        let on_disk = std::fs::metadata(&path).unwrap().len();
        assert!(on_disk > 1_000_000, "test corpus should be multi-MB");
        let r = RuleBypassCorpus::load_or_default(&path, "ignored");
        assert_eq!(r.total_bypasses(), 30 * 50, "all valid bypasses load intact");
        assert!(corrupt_sidecars(dir.path(), "c.json").is_empty(), "valid file never preserved-aside");
    }

    #[test]
    fn save_atomic_leaves_no_tempfiles_behind() {
        // The atomic writer's temp file must be renamed into place, leaving
        // only the corpus (and possibly a .bak) in the directory.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("c.json");
        let mut c = RuleBypassCorpus::new("t");
        c.record_bypass("R1", "p", cls("sql"), vec![], 1);
        c.save_atomic(&path).expect("save");
        let entries: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(entries.contains(&"c.json".to_string()));
        assert!(
            entries.iter().all(|n| n == "c.json" || n == "c.json.bak"),
            "no stray temp files left behind, got: {entries:?}"
        );
    }

    #[test]
    fn empty_buckets_and_blocks_persist_exact_counts() {
        // A corpus with rules that have ONLY blocks, ONLY bypasses, or a mix
        // round-trips with exact per-rule counts.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("c.json");
        let mut c = RuleBypassCorpus::new("t");
        c.record_block("only-block", "b", cls("sql"), vec![], 1);
        c.record_bypass("only-bypass", "p", cls("xss"), vec![], 2);
        c.record_block("mixed", "b", cls("cmd"), vec![], 3);
        c.record_bypass("mixed", "p", cls("cmd"), vec![], 4);
        c.save_atomic(&path).expect("save");
        let r = RuleBypassCorpus::load_or_default(&path, "t");
        assert_eq!(r.blocked_for_rule("only-block").len(), 1);
        assert_eq!(r.bypasses_for_rule("only-block").len(), 0);
        assert_eq!(r.bypasses_for_rule("only-bypass").len(), 1);
        assert_eq!(r.blocked_for_rule("only-bypass").len(), 0);
        assert_eq!(r.blocked_for_rule("mixed").len(), 1);
        assert_eq!(r.bypasses_for_rule("mixed").len(), 1);
        assert_eq!(r.rules_seen(), 3);
    }
}
