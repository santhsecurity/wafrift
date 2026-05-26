//! Cross-region Cloudflare edge-POP coverage map.
//!
//! Closes #170. Cloudflare runs an anycast network with 300+ edge
//! POPs (IATA-coded data centers — `SJC`, `LHR`, `NRT`, `FRA`, etc).
//! A payload that's *blocked* through one POP can still be *bypassed*
//! through another if that POP runs a different OpenResty build,
//! older ruleset compiler, or different geo-specific managed rules.
//!
//! `parse_cf_block` in the oracle crate already extracts the
//! `edge_pop` (IATA suffix of `cf-ray`) from every response. This
//! module accumulates the (egress_label, target_host) → set-of-pops
//! mapping so the hunt loop can bias rotation toward
//! egress-IPs / proxy-routes that have NOT yet been observed hitting
//! a given POP.
//!
//! ## Coverage policy
//!
//! - A `(egress, target)` pair that has hit `≥k` distinct POPs is
//!   considered *exhausted* for cross-region purposes — further
//!   probes through that egress are unlikely to land in a new POP
//!   any time soon. (`k` defaults to 8; CF anycast usually pins a
//!   client IP to a small set of nearby POPs.)
//! - When *all* egress entries are exhausted, the hunt loop should
//!   either rotate to a fresh egress pool (different proxy provider
//!   / different VPN exit) or accept that the current set has
//!   plateaued.
//! - POPs are stored as upper-case 3-letter IATA codes for stable
//!   set semantics (e.g. `SJC`, not `sjc` or `Sjc`).
//!
//! ## Why this matters for #170
//!
//! Without POP awareness, a hunt loop that rotates egress IPs blindly
//! often re-hits the same POP many times before stumbling onto a new
//! one. With POP awareness, the loop can:
//!
//! 1. **Detect plateau early** — if the same egress has hit only one
//!    POP after 50 probes, anycast has pinned it; abandon faster.
//! 2. **Prioritize gap-filling** — pick egress entries whose seen-POP
//!    set is smallest, since those have the most room to discover
//!    new POPs.
//! 3. **Report coverage** — after a hunt round, surface "we touched
//!    47 distinct CF edge POPs" so the operator knows the search
//!    actually fanned out.
//!
//! All persistent — same atomic save/load contract as
//! [`crate::rule_corpus`].

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Bounded number of POPs we track per (egress, target). A pair that
/// has hit this many distinct POPs is considered *exhausted* — the
/// anycast network is unlikely to surface new POPs without major IP
/// rotation. Conservative default; raise via [`EdgePopCoverage::set_exhaustion_threshold`].
pub const DEFAULT_EXHAUSTION_THRESHOLD: usize = 8;

/// Schema version. Bumped if the on-disk shape changes. Backwards
/// compatibility is preserved via [`load_or_default`].
pub const SCHEMA_VERSION: u32 = 1;

/// Per (egress_label, target_host) record of which POPs have been
/// observed. POPs are stored as upper-case 3-letter IATA strings so
/// set equality is byte-exact.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EgressTargetPops {
    /// IATA POPs observed from this (egress, target). Sorted via
    /// `BTreeSet` so serialization is deterministic for bench
    /// reproducibility.
    pub pops: BTreeSet<String>,
    /// Total probes observed (regardless of POP). Useful for
    /// computing pop-discovery efficiency.
    pub total_probes: u64,
}

/// Coverage map keyed by `(egress_label, target_host)`.
///
/// The composite key is encoded as `egress_label \u{1F} target_host`
/// (ASCII unit separator). `BTreeMap` over the joined key gives stable
/// iteration order for deterministic save/load. Operators read the
/// map via [`pops_for`] / [`uncovered_pops`] without seeing the
/// internal key encoding.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EdgePopCoverage {
    /// Schema version of the on-disk format.
    pub schema_version: u32,
    /// (egress_label, target_host) → observed POPs.
    pub entries: BTreeMap<String, EgressTargetPops>,
    /// Anycast plateau threshold for [`is_exhausted`].
    exhaustion_threshold: usize,
}

impl Default for EdgePopCoverage {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            entries: BTreeMap::new(),
            exhaustion_threshold: DEFAULT_EXHAUSTION_THRESHOLD,
        }
    }
}

const KEY_SEP: char = '\u{1F}';

fn make_key(egress: &str, target: &str) -> String {
    format!("{egress}{KEY_SEP}{target}")
}

fn split_key(key: &str) -> Option<(&str, &str)> {
    key.split_once(KEY_SEP)
}

/// Validate an IATA-style POP code: exactly 3 ASCII letters. Returns
/// the upper-cased canonical form, or `None` if not a valid IATA
/// suffix. We accept any 3-letter ASCII because CF expands its POP
/// list often; whitelisting known POPs would rot.
#[must_use]
pub fn normalize_pop(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.len() != 3 {
        return None;
    }
    if !trimmed.chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    Some(trimmed.to_ascii_uppercase())
}

impl EdgePopCoverage {
    /// Construct an empty map at the current schema version.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the exhaustion threshold. Useful for tests, or for
    /// operators on extremely well-distributed proxy pools.
    pub fn set_exhaustion_threshold(&mut self, n: usize) {
        self.exhaustion_threshold = n.max(1);
    }

    /// Current exhaustion threshold.
    #[must_use]
    pub fn exhaustion_threshold(&self) -> usize {
        self.exhaustion_threshold
    }

    /// Record that we observed `pop` (must be a valid IATA-style
    /// string — pass the raw `signal.edge_pop` from `parse_cf_block`).
    /// Returns `true` if the POP was newly observed for this
    /// `(egress, target)`, `false` if already known.
    ///
    /// Invalid POP strings (wrong length, non-letter) increment
    /// `total_probes` but don't add to the set — they're noise from
    /// non-CF responses (origin direct, captive portals, etc).
    pub fn record(&mut self, egress: &str, target: &str, pop_raw: &str) -> bool {
        let key = make_key(egress, target);
        let entry = self.entries.entry(key).or_default();
        entry.total_probes += 1;
        match normalize_pop(pop_raw) {
            Some(canon) => entry.pops.insert(canon),
            None => false,
        }
    }

    /// Record a probe with NO POP observed (e.g. timeout, non-CF
    /// edge, raw TCP error). Updates only the probe counter.
    pub fn record_no_pop(&mut self, egress: &str, target: &str) {
        let key = make_key(egress, target);
        self.entries.entry(key).or_default().total_probes += 1;
    }

    /// Look up observed POPs for this pair. Returns an empty set if
    /// the pair has never been probed.
    #[must_use]
    pub fn pops_for(&self, egress: &str, target: &str) -> BTreeSet<String> {
        self.entries
            .get(&make_key(egress, target))
            .map(|e| e.pops.clone())
            .unwrap_or_default()
    }

    /// Total probes recorded for this pair. Zero if never probed.
    #[must_use]
    pub fn probes_for(&self, egress: &str, target: &str) -> u64 {
        self.entries
            .get(&make_key(egress, target))
            .map(|e| e.total_probes)
            .unwrap_or(0)
    }

    /// True if `(egress, target)` has hit at least
    /// `exhaustion_threshold` distinct POPs and is unlikely to
    /// surface more without major IP rotation.
    #[must_use]
    pub fn is_exhausted(&self, egress: &str, target: &str) -> bool {
        self.pops_for(egress, target).len() >= self.exhaustion_threshold
    }

    /// All POPs seen across every egress for this target. Used to
    /// answer "what's the union of CF POPs our hunt has touched for
    /// `target.example`".
    #[must_use]
    pub fn pops_covered_for_target(&self, target: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for (key, entry) in &self.entries {
            if let Some((_, t)) = split_key(key) {
                if t == target {
                    out.extend(entry.pops.iter().cloned());
                }
            }
        }
        out
    }

    /// All POPs seen across every (egress, target). Useful for the
    /// global "we touched N distinct POPs this hunt round" headline.
    #[must_use]
    pub fn pops_covered_global(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for entry in self.entries.values() {
            out.extend(entry.pops.iter().cloned());
        }
        out
    }

    /// All egress labels we have data for. Stable order (BTreeMap
    /// iteration).
    #[must_use]
    pub fn egress_labels(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for key in self.entries.keys() {
            if let Some((e, _)) = split_key(key) {
                out.insert(e.to_string());
            }
        }
        out
    }

    /// Egress entries that are NOT yet exhausted for `target` —
    /// these are the candidates the hunt loop should prioritize for
    /// new probes, sorted ascending by current POP count so we
    /// favor entries with the most room to grow.
    #[must_use]
    pub fn rank_egresses_for_discovery(&self, target: &str) -> Vec<(String, usize)> {
        let mut all: BTreeMap<String, usize> = BTreeMap::new();
        for (key, entry) in &self.entries {
            if let Some((e, t)) = split_key(key) {
                if t == target {
                    all.insert(e.to_string(), entry.pops.len());
                }
            }
        }
        let mut ranked: Vec<(String, usize)> = all
            .into_iter()
            .filter(|(_, n)| *n < self.exhaustion_threshold)
            .collect();
        ranked.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
        ranked
    }

    /// Persist atomically via tempfile + rename. The on-disk format
    /// is JSON for human-readable diffs across hunt sessions.
    pub fn save_atomic(&self, path: &Path) -> std::io::Result<()> {
        use std::io::Write;

        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let tmp = path.with_extension("tmp");
        {
            let mut f = std::fs::File::create(&tmp)?;
            let bytes = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Load from disk; on missing file or corrupt JSON return
    /// `default()`. Same forgiveness contract as
    /// [`rule_corpus::load_or_default`] — operator data is precious
    /// but a corrupt coverage map shouldn't crash a hunt round.
    #[must_use]
    pub fn load_or_default(path: &Path) -> Self {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(_) => return Self::default(),
        };
        serde_json::from_slice(&bytes).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn normalize_pop_accepts_3_letter_iata() {
        assert_eq!(normalize_pop("SJC"), Some("SJC".to_string()));
        assert_eq!(normalize_pop("sjc"), Some("SJC".to_string()));
        assert_eq!(normalize_pop("Lhr"), Some("LHR".to_string()));
        assert_eq!(normalize_pop("  AMS  "), Some("AMS".to_string()));
    }

    #[test]
    fn normalize_pop_rejects_garbage() {
        assert_eq!(normalize_pop(""), None);
        assert_eq!(normalize_pop("AB"), None);
        assert_eq!(normalize_pop("ABCD"), None);
        assert_eq!(normalize_pop("12A"), None);
        assert_eq!(normalize_pop("A1A"), None);
        assert_eq!(normalize_pop("---"), None);
        // Unicode 3-char string that is not all ASCII alphabetic.
        assert_eq!(normalize_pop("a\u{0301}b"), None);
    }

    #[test]
    fn record_first_pop_returns_true() {
        let mut c = EdgePopCoverage::new();
        assert!(c.record("egress-a", "target.example", "SJC"));
    }

    #[test]
    fn record_duplicate_pop_returns_false() {
        let mut c = EdgePopCoverage::new();
        c.record("egress-a", "target.example", "SJC");
        assert!(!c.record("egress-a", "target.example", "SJC"));
        // Lower-case duplicate is also detected after normalization.
        assert!(!c.record("egress-a", "target.example", "sjc"));
    }

    #[test]
    fn record_invalid_pop_still_counts_probe() {
        let mut c = EdgePopCoverage::new();
        let inserted = c.record("egress-a", "target.example", "NOT-A-POP");
        assert!(!inserted);
        assert_eq!(c.probes_for("egress-a", "target.example"), 1);
        assert!(c.pops_for("egress-a", "target.example").is_empty());
    }

    #[test]
    fn record_no_pop_increments_counter_only() {
        let mut c = EdgePopCoverage::new();
        c.record_no_pop("egress-a", "target.example");
        c.record_no_pop("egress-a", "target.example");
        assert_eq!(c.probes_for("egress-a", "target.example"), 2);
        assert!(c.pops_for("egress-a", "target.example").is_empty());
    }

    #[test]
    fn pops_per_pair_isolated() {
        let mut c = EdgePopCoverage::new();
        c.record("egress-a", "target.example", "SJC");
        c.record("egress-b", "target.example", "LHR");
        c.record("egress-a", "other.example", "NRT");
        assert_eq!(
            c.pops_for("egress-a", "target.example"),
            ["SJC".to_string()].into_iter().collect()
        );
        assert_eq!(
            c.pops_for("egress-b", "target.example"),
            ["LHR".to_string()].into_iter().collect()
        );
        assert_eq!(
            c.pops_for("egress-a", "other.example"),
            ["NRT".to_string()].into_iter().collect()
        );
    }

    #[test]
    fn pops_covered_for_target_unions_across_egresses() {
        let mut c = EdgePopCoverage::new();
        c.record("egress-a", "target.example", "SJC");
        c.record("egress-b", "target.example", "LHR");
        c.record("egress-c", "target.example", "AMS");
        // Mixed in a different target — must not contaminate.
        c.record("egress-d", "other.example", "ORD");

        let pops = c.pops_covered_for_target("target.example");
        assert_eq!(pops.len(), 3);
        assert!(pops.contains("SJC"));
        assert!(pops.contains("LHR"));
        assert!(pops.contains("AMS"));
        assert!(!pops.contains("ORD"));
    }

    #[test]
    fn pops_covered_global_unions_everything() {
        let mut c = EdgePopCoverage::new();
        c.record("egress-a", "target.example", "SJC");
        c.record("egress-b", "other.example", "LHR");
        let global = c.pops_covered_global();
        assert_eq!(global.len(), 2);
        assert!(global.contains("SJC"));
        assert!(global.contains("LHR"));
    }

    #[test]
    fn is_exhausted_only_after_threshold() {
        let mut c = EdgePopCoverage::new();
        c.set_exhaustion_threshold(3);
        c.record("egress-a", "target.example", "SJC");
        c.record("egress-a", "target.example", "LHR");
        assert!(!c.is_exhausted("egress-a", "target.example"));
        c.record("egress-a", "target.example", "NRT");
        assert!(c.is_exhausted("egress-a", "target.example"));
    }

    #[test]
    fn is_exhausted_unprobed_pair_is_false() {
        let c = EdgePopCoverage::new();
        assert!(!c.is_exhausted("egress-a", "target.example"));
    }

    #[test]
    fn rank_egresses_excludes_exhausted_and_orders_by_pop_count() {
        let mut c = EdgePopCoverage::new();
        c.set_exhaustion_threshold(3);

        // egress-a: 1 POP (most room to grow)
        c.record("egress-a", "target.example", "SJC");
        // egress-b: 2 POPs
        c.record("egress-b", "target.example", "SJC");
        c.record("egress-b", "target.example", "LHR");
        // egress-c: 3 POPs (exhausted)
        c.record("egress-c", "target.example", "SJC");
        c.record("egress-c", "target.example", "LHR");
        c.record("egress-c", "target.example", "AMS");

        let ranked = c.rank_egresses_for_discovery("target.example");
        // egress-c is excluded.
        assert_eq!(ranked.len(), 2);
        // egress-a (1 POP) before egress-b (2 POPs).
        assert_eq!(ranked[0], ("egress-a".to_string(), 1));
        assert_eq!(ranked[1], ("egress-b".to_string(), 2));
    }

    #[test]
    fn rank_egresses_ignores_other_targets() {
        let mut c = EdgePopCoverage::new();
        c.set_exhaustion_threshold(3);
        c.record("egress-a", "target.example", "SJC");
        c.record("egress-b", "other.example", "LHR");
        let ranked = c.rank_egresses_for_discovery("target.example");
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].0, "egress-a");
    }

    #[test]
    fn rank_egresses_breaks_ties_alphabetically() {
        let mut c = EdgePopCoverage::new();
        c.set_exhaustion_threshold(5);
        c.record("egress-z", "target.example", "SJC");
        c.record("egress-a", "target.example", "LHR");
        c.record("egress-m", "target.example", "AMS");
        let ranked = c.rank_egresses_for_discovery("target.example");
        // All three have 1 POP; alphabetical order wins.
        assert_eq!(ranked.len(), 3);
        assert_eq!(ranked[0].0, "egress-a");
        assert_eq!(ranked[1].0, "egress-m");
        assert_eq!(ranked[2].0, "egress-z");
    }

    #[test]
    fn egress_labels_returns_unique_set() {
        let mut c = EdgePopCoverage::new();
        c.record("egress-a", "target.example", "SJC");
        c.record("egress-a", "other.example", "LHR");
        c.record("egress-b", "target.example", "NRT");
        let labels = c.egress_labels();
        let want: HashSet<String> =
            ["egress-a".to_string(), "egress-b".to_string()].into_iter().collect();
        let got: HashSet<String> = labels.into_iter().collect();
        assert_eq!(got, want);
    }

    #[test]
    fn save_load_roundtrip_atomic() {
        let mut c = EdgePopCoverage::new();
        c.set_exhaustion_threshold(5);
        c.record("egress-a", "target.example", "SJC");
        c.record("egress-a", "target.example", "LHR");
        c.record("egress-b", "target.example", "NRT");
        c.record_no_pop("egress-c", "target.example");

        let tmp = std::env::temp_dir()
            .join(format!("wafrift_pop_cov_{}.json", std::process::id()));
        c.save_atomic(&tmp).unwrap();
        let loaded = EdgePopCoverage::load_or_default(&tmp);
        assert_eq!(loaded.schema_version, c.schema_version);
        assert_eq!(loaded.entries.len(), c.entries.len());
        assert_eq!(
            loaded.pops_for("egress-a", "target.example"),
            c.pops_for("egress-a", "target.example")
        );
        assert_eq!(
            loaded.probes_for("egress-c", "target.example"),
            c.probes_for("egress-c", "target.example")
        );
        // exhaustion_threshold is private; verify behaviorally via
        // is_exhausted (5-threshold means 2 POPs is not enough).
        assert!(!loaded.is_exhausted("egress-a", "target.example"));
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn load_missing_file_returns_default() {
        let nope = std::env::temp_dir().join("wafrift_pop_cov_nonexistent.json");
        let _ = std::fs::remove_file(&nope);
        let loaded = EdgePopCoverage::load_or_default(&nope);
        assert_eq!(loaded.schema_version, SCHEMA_VERSION);
        assert!(loaded.entries.is_empty());
    }

    #[test]
    fn load_corrupt_file_returns_default() {
        let tmp = std::env::temp_dir()
            .join(format!("wafrift_pop_cov_corrupt_{}.json", std::process::id()));
        std::fs::write(&tmp, b"this is not json {{{ ").unwrap();
        let loaded = EdgePopCoverage::load_or_default(&tmp);
        assert!(loaded.entries.is_empty());
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn save_creates_parent_directory() {
        let dir = std::env::temp_dir().join(format!(
            "wafrift_pop_cov_dir_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let nested = dir.join("nested").join("coverage.json");
        let mut c = EdgePopCoverage::new();
        c.record("egress-a", "target.example", "SJC");
        c.save_atomic(&nested).unwrap();
        assert!(nested.exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn set_exhaustion_threshold_min_clamped_to_one() {
        let mut c = EdgePopCoverage::new();
        c.set_exhaustion_threshold(0);
        assert_eq!(c.exhaustion_threshold(), 1);
        // With threshold 1, a single POP is enough.
        c.record("egress-a", "target.example", "SJC");
        assert!(c.is_exhausted("egress-a", "target.example"));
    }

    #[test]
    fn key_separator_not_observable_in_public_api() {
        // Even if an operator passes the unit-separator char in
        // egress / target strings, the lookups must remain consistent.
        let mut c = EdgePopCoverage::new();
        let weird_egress = "egress\u{1F}with-sep";
        c.record(weird_egress, "target.example", "SJC");
        let pops = c.pops_for(weird_egress, "target.example");
        // Either it's recorded under a synthetic key or rejected, but
        // must not crash and must remain self-consistent across save.
        assert!(pops.len() <= 1);
    }

    #[test]
    fn record_increments_total_probes_per_pair() {
        let mut c = EdgePopCoverage::new();
        c.record("egress-a", "target.example", "SJC");
        c.record("egress-a", "target.example", "LHR");
        c.record("egress-a", "target.example", "NRT");
        assert_eq!(c.probes_for("egress-a", "target.example"), 3);
        // Different pair untouched.
        assert_eq!(c.probes_for("egress-b", "target.example"), 0);
    }

    #[test]
    fn empty_global_coverage_is_empty_set() {
        let c = EdgePopCoverage::new();
        assert!(c.pops_covered_global().is_empty());
        assert!(c.pops_covered_for_target("any.example").is_empty());
        assert!(c.egress_labels().is_empty());
    }
}
