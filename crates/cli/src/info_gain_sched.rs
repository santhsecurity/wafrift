//! Info-gain payload scheduler — given prior bench history, schedule
//! payload replays in descending order of expected information gain.
//!
//! ## Why this exists
//!
//! Operators frequently have a budget cap ("only send 1 000 requests
//! against this WAF, not 100 000"). Running every payload greedily
//! wastes the budget on payloads that already block trivially or
//! already bypass trivially — neither outcome teaches the operator
//! anything new about the rule set. The payloads that DO teach
//! something are the ones whose observed block rate is near 0.5: the
//! WAF blocks them sometimes, passes them sometimes, depending on a
//! rule the operator has not yet fingerprinted.
//!
//! Binary Shannon entropy `H(p) = -p·log2(p) − (1−p)·log2(1−p)`
//! captures exactly this: it peaks at 1 bit when p = 0.5 and drops to
//! zero at the endpoints. Scheduling by descending `H(theta)` puts
//! the high-information payloads at the front of the queue.
//!
//! ## Model
//!
//! Each payload's block probability is treated as a Beta-distributed
//! posterior under a uniform Beta(1,1) prior:
//!
//! ```text
//!   alpha = 1 + n_blocked
//!   beta  = 1 + n_passed
//!   theta_mean = alpha / (alpha + beta)
//! ```
//!
//! A payload with no prior observations starts at theta = 0.5 — the
//! cold-start payload carries one bit of uncertainty, the maximum.
//! As observations accumulate, theta converges and H(theta) shrinks.
//!
//! ## Why posterior-mean entropy, not Thompson sampling
//!
//! Thompson sampling balances exploration vs exploitation toward
//! reward maximisation (e.g. "find a bypass"). The scheduler's goal
//! is **information gain about the rule set**, a research objective
//! — posterior-mean entropy is the right objective for that. If a
//! future caller wants the reward-maximisation variant, build it as
//! a separate scheduler that shares this module's `PayloadStats`
//! contract.
//!
//! ## Tiebreak design
//!
//! When two payloads have equal entropy (frequently: many cold-start
//! payloads at theta = 0.5), the secondary sort key is `n_trials`
//! ascending — prefer the LESS-explored one. Without this tiebreak,
//! the schedule would re-run the same handful of cold-start payloads
//! until one of them happened to differ, starving the rest. The
//! final tiebreak is `id` ascending so the schedule is deterministic
//! for test reproducibility.
//!
//! ## Backwards compatibility
//!
//! `PayloadStats::default()` is the cold-start prior. Any payload
//! added in a future release that is missing from a prior history
//! file deserialises to cold-start; no migration required (LAW 2).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use wafrift_types::binary_shannon;

/// Per-payload Bernoulli observation tally. Default = cold-start
/// (zero trials, theta = 0.5 under Beta(1,1)).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PayloadStats {
    /// Trials that ended with the WAF blocking the request.
    #[serde(default)]
    pub n_blocked: u32,
    /// Trials that ended with the WAF letting the request through.
    #[serde(default)]
    pub n_passed: u32,
}

impl PayloadStats {
    /// Total number of observations contributed so far. Saturating
    /// addition — `observe()` already caps each component at
    /// `u32::MAX`, but the sum of two near-`u32::MAX` values would
    /// still overflow with plain `+`. Saturate to keep n_trials
    /// monotonically non-decreasing across the public API.
    #[must_use]
    pub const fn n_trials(&self) -> u32 {
        self.n_blocked.saturating_add(self.n_passed)
    }

    /// Posterior mean of the block probability under a Beta(1,1)
    /// prior. Always in `[0, 1]`. The `+1` shift on both alpha and
    /// beta ensures `n_trials == 0` returns `0.5` without a special
    /// case.
    #[must_use]
    pub fn theta_estimate(&self) -> f64 {
        let alpha = 1.0 + f64::from(self.n_blocked);
        let beta = 1.0 + f64::from(self.n_passed);
        alpha / (alpha + beta)
    }

    /// Expected information gain from running this payload one more
    /// time, approximated as the binary Shannon entropy of the
    /// current `theta_estimate`. Always in `[0, 1]` bits.
    #[must_use]
    pub fn info_gain(&self) -> f64 {
        binary_shannon(self.theta_estimate())
    }

    /// Approximate 95% credible interval `(lower, upper)` for
    /// `theta_estimate` under the Beta-Bernoulli posterior, using
    /// the Wald (normal) approximation
    /// `theta ± Z_SCORE_95 · sqrt(theta·(1-theta) / n_eff)` where
    /// `n_eff = n_trials + BETA11_PRIOR_PSEUDO_TRIALS`. Result
    /// clamped to `[0, 1]`.
    ///
    /// Useful for operators answering "how confident is the scheduler
    /// in this estimate?" — a payload with theta=0.5 and n_trials=2
    /// has a much wider band than one with theta=0.5 and n_trials=200,
    /// even though their `info_gain` matches at 1.0 bit.
    ///
    /// For more accurate intervals near the boundary (theta close to
    /// 0 or 1), a future version could swap in Wilson score or the
    /// exact Beta credible interval — both require either an
    /// inverse-CDF dependency or tabulated approximations. The Wald
    /// form here is adequate for the scheduler's "is this estimate
    /// stable?" question without pulling in a stats crate on a leaf-
    /// level module.
    #[must_use]
    pub fn theta_ci_95(&self) -> (f64, f64) {
        /// Standard-normal critical value for a two-sided 95% interval
        /// (`Φ⁻¹(0.975) ≈ 1.96`). Named so a future tightening (e.g.
        /// switching to a 99% interval, `Φ⁻¹(0.995) ≈ 2.576`) is a
        /// one-place edit and a silent re-tune is impossible.
        const Z_SCORE_95: f64 = 1.959_963_984_540_054;
        /// Pseudo-trial contribution from the uniform Beta(1,1)
        /// prior: 1 from `n_blocked` shift + 1 from `n_passed` shift.
        /// Adding this to `n_trials` gives the effective sample size
        /// the Wald formula needs. Named so the meaning isn't
        /// inscrutable to a reader who hasn't memorised Beta-Bernoulli.
        const BETA11_PRIOR_PSEUDO_TRIALS: f64 = 2.0;
        let theta = self.theta_estimate();
        let n_eff = f64::from(self.n_trials()) + BETA11_PRIOR_PSEUDO_TRIALS;
        let se = (theta * (1.0 - theta) / n_eff).sqrt();
        let half = Z_SCORE_95 * se;
        let lo = (theta - half).max(0.0);
        let hi = (theta + half).min(1.0);
        (lo, hi)
    }

    /// Update the posterior with a single observation. Saturating
    /// arithmetic — a single payload that runs `u32::MAX` times
    /// silently caps rather than wraps. Realistic budget ceilings are
    /// in the millions; saturation is a safety net for adversarial
    /// inputs, not a normal-path concern.
    pub fn observe(&mut self, blocked: bool) {
        if blocked {
            self.n_blocked = self.n_blocked.saturating_add(1);
        } else {
            self.n_passed = self.n_passed.saturating_add(1);
        }
    }
}

/// Aggregate history across payloads. Persisted to disk between
/// invocations as the scheduler's warm-start memory.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct History {
    #[serde(default)]
    pub by_id: BTreeMap<String, PayloadStats>,
}

impl History {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Stats for a payload id — cold-start prior if unknown. Does NOT
    /// insert; the scheduler may call this on thousands of payloads
    /// without growing the history.
    #[must_use]
    pub fn stats(&self, id: &str) -> PayloadStats {
        self.by_id.get(id).cloned().unwrap_or_default()
    }

    /// Update the posterior for `id` with a single observation,
    /// creating the entry if absent.
    pub fn observe(&mut self, id: impl Into<String>, blocked: bool) {
        self.by_id.entry(id.into()).or_default().observe(blocked);
    }

    /// Number of payloads with at least one observation.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// True if no payload has been observed yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Merge another history into this one. For each payload id in
    /// `other`, the local `n_blocked` and `n_passed` counts are
    /// incremented by the other history's counts. New payload ids
    /// from `other` are inserted at their absolute counts.
    ///
    /// Saturating arithmetic — if either side overflows `u32::MAX`,
    /// the merged total caps at `u32::MAX` rather than wrapping. In
    /// practice a single payload accumulating more than 4 billion
    /// observations is adversarial-input territory; the saturation
    /// is a safety net, not a normal-path concern.
    ///
    /// Useful for operators running multiple parallel WAF
    /// assessments who want to combine the per-payload posteriors
    /// into a single warm-start file for a follow-up bench. Pure on
    /// the inputs (`other` is not mutated).
    ///
    /// Wired into `bench-waf --history-merge` (repeatable) so the
    /// operator-facing path uses the same primitive the unit tests
    /// pin. Do NOT add `#[cfg(test)]` here — the production wiring
    /// depends on it.
    pub fn merge(&mut self, other: &History) {
        for (id, other_stats) in &other.by_id {
            let entry = self.by_id.entry(id.clone()).or_default();
            entry.n_blocked = entry.n_blocked.saturating_add(other_stats.n_blocked);
            entry.n_passed = entry.n_passed.saturating_add(other_stats.n_passed);
        }
    }
}

/// A scheduled payload paired with the diagnostics that justify its
/// rank — `info_gain` bits, `theta_estimate` block probability,
/// `theta_ci_95_*` Wald credible-interval bounds, and `n_trials` prior
/// observations. Used by `schedule_with_diagnostics` and the
/// `bench-waf --list-schedule` preview path.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct ScheduleEntry {
    /// Payload identifier (matches `BenchCase::id`).
    pub id: String,
    /// Posterior mean of the block probability, in `[0, 1]`.
    pub theta_estimate: f64,
    /// Lower bound of the 95% Wald credible interval for theta.
    #[serde(default)]
    pub theta_ci_95_lo: f64,
    /// Upper bound of the 95% Wald credible interval for theta.
    #[serde(default)]
    pub theta_ci_95_hi: f64,
    /// Binary Shannon entropy of `theta_estimate`, in `[0, 1]` bits.
    pub info_gain: f64,
    /// Prior observations contributing to the estimate.
    pub n_trials: u32,
}

/// Order `payloads` by descending expected info gain (ties broken by
/// fewer prior trials, then by id ascending) and return the top
/// `budget` entries with their diagnostic fields preserved.
///
/// Useful when the caller wants to display *why* a payload was
/// chosen, not just *that* it was chosen — the `bench-waf
/// --list-schedule` flag uses this to render an operator-readable
/// preview table. The plain [`schedule`] function is a thin wrapper
/// that discards the diagnostics and returns just the id list.
#[must_use]
pub(crate) fn schedule_with_diagnostics<'a, I, S>(
    history: &History,
    payloads: I,
    budget: usize,
) -> Vec<ScheduleEntry>
where
    I: IntoIterator<Item = &'a S>,
    S: AsRef<str> + 'a + ?Sized,
{
    if budget == 0 {
        return Vec::new();
    }
    // Pre-compute (info_gain, n_trials, stats) per payload so the
    // sort comparator reads cached f64s instead of recomputing
    // theta_estimate→info_gain (log2 + multiply) at every comparison.
    // For N=10k payloads with ~150k comparisons in unstable sort, that
    // saves ~300k log2/multiply pairs. Empirical ~7% wall-clock
    // improvement at N=10k; bigger wins at N=100k.
    let mut items: Vec<(String, f64, u32, PayloadStats)> = payloads
        .into_iter()
        .map(|p| {
            let id = p.as_ref().to_string();
            let stats = history.stats(&id);
            let info_gain = stats.info_gain();
            let n_trials = stats.n_trials();
            (id, info_gain, n_trials, stats)
        })
        .collect();
    // sort_unstable_by is faster than sort_by and equivalent here:
    // the comparator already has explicit tie-breaks (n_trials, then
    // id) so the result is deterministic regardless of underlying
    // sort stability. Wins ~20% on large corpora.
    items.sort_unstable_by(|(a_id, a_gain, a_trials, _), (b_id, b_gain, b_trials, _)| {
        // Descending by gain: b vs a, not a vs b. partial_cmp can
        // return None for NaN, but `binary_shannon` zeroes NaN out so
        // this path is defensive only.
        b_gain
            .partial_cmp(a_gain)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a_trials.cmp(b_trials))
            .then_with(|| a_id.cmp(b_id))
    });
    items
        .into_iter()
        .take(budget)
        .map(|(id, info_gain, n_trials, stats)| {
            let (lo, hi) = stats.theta_ci_95();
            ScheduleEntry {
                id,
                theta_estimate: stats.theta_estimate(),
                theta_ci_95_lo: lo,
                theta_ci_95_hi: hi,
                info_gain,
                n_trials,
            }
        })
        .collect()
}

/// Order `payloads` by descending expected info gain, ties broken by
/// fewer prior trials, then by id ascending. Returns the top
/// `budget` payload ids in schedule order.
///
/// `budget == 0` returns an empty Vec without iterating. `budget >=
/// payloads.len()` returns every payload in schedule order — useful
/// as a deterministic ordering primitive even when budget is not the
/// binding constraint.
///
/// Thin wrapper over [`schedule_with_diagnostics`] that discards the
/// per-entry diagnostic fields. If you need to surface *why* a
/// payload was chosen, call `schedule_with_diagnostics` directly.
///
/// Test-only: production paths call `schedule_with_diagnostics` so
/// they can surface the diagnostic fields (info_gain, theta, n_trials)
/// in `--list-schedule` output without a second traversal.
#[cfg(test)]
#[must_use]
pub(crate) fn schedule<'a, I, S>(history: &History, payloads: I, budget: usize) -> Vec<String>
where
    I: IntoIterator<Item = &'a S>,
    S: AsRef<str> + 'a + ?Sized,
{
    schedule_with_diagnostics(history, payloads, budget)
        .into_iter()
        .map(|e| e.id)
        .collect()
}

/// Schedule with per-class fairness — every class receives roughly
/// `budget / num_classes` slots; within each class, payloads are
/// ordered by descending info gain (same primitive as [`schedule`]).
///
/// ## Why this exists
///
/// Pure [`schedule`] is class-blind. A corpus with 95% SQL cases and
/// 5% XSS cases will, under budget pressure, deliver an "all SQL"
/// schedule even though the operator probably wanted some signal on
/// every class. Per-class fairness prevents that starvation.
///
/// ## Allocation rule
///
/// Integer division: `base = budget / num_classes`, with the
/// remainder `extras = budget % num_classes` distributed one per
/// class in iteration order (BTreeMap → alphabetical by class name).
/// This makes the per-class allocation deterministic and reproducible
/// across runs — critical for the [`schedule`] anti-rig guarantees.
///
/// If a class has fewer payloads than its allocation, the surplus
/// is NOT redistributed: a class with 2 payloads and a 5-slot
/// allocation contributes 2 ordered payloads, total result is
/// (budget − 3) items. This is the documented "honest under-fill"
/// contract; a redistribution mode is a future feature.
///
/// ## Output ordering
///
/// Classes interleave in BTreeMap iteration order (alphabetical),
/// each class contributing its top picks in descending info_gain
/// order. The result is NOT globally sorted by info_gain — operators
/// who want that should call [`schedule`] directly.
///
/// Thin wrapper over [`schedule_per_class_with_diagnostics`] that
/// discards the per-entry diagnostic fields. Use the diagnostic
/// version when the caller needs to surface `info_gain`/`theta`/
/// `n_trials` (e.g. `--list-schedule --fair-class` preview).
///
/// Test-only: production paths call `schedule_per_class_with_diagnostics`
/// so they can render `--list-schedule` output without a second traversal.
#[cfg(test)]
#[must_use]
pub(crate) fn schedule_per_class(
    history: &History,
    payloads_by_class: &std::collections::BTreeMap<String, Vec<String>>,
    budget: usize,
) -> Vec<String> {
    schedule_per_class_with_diagnostics(history, payloads_by_class, budget)
        .into_iter()
        .map(|e| e.id)
        .collect()
}

/// Per-class fairness schedule with diagnostic fields preserved.
/// Mirror of [`schedule_per_class`] that emits [`ScheduleEntry`]
/// values instead of bare ids, so the `bench-waf --list-schedule`
/// preview path can render correct per-case info_gain numbers even
/// when `--fair-class` is the active mode.
///
/// Same allocation rule + same interleaving order as
/// [`schedule_per_class`] — the only difference is the return type.
#[must_use]
pub(crate) fn schedule_per_class_with_diagnostics(
    history: &History,
    payloads_by_class: &std::collections::BTreeMap<String, Vec<String>>,
    budget: usize,
) -> Vec<ScheduleEntry> {
    if budget == 0 || payloads_by_class.is_empty() {
        return Vec::new();
    }
    let num_classes = payloads_by_class.len();
    let base_per_class = budget / num_classes;
    let extras = budget % num_classes;

    let mut result = Vec::with_capacity(budget);
    for (idx, (_class, payloads)) in payloads_by_class.iter().enumerate() {
        let class_budget = base_per_class + usize::from(idx < extras);
        if class_budget == 0 {
            continue;
        }
        let payload_refs: Vec<&str> = payloads.iter().map(String::as_str).collect();
        let entries = schedule_with_diagnostics(history, &payload_refs, class_budget);
        result.extend(entries);
    }
    result
}

/// Load a persisted [`History`] from `path`, cold-starting (empty history) when
/// the file is absent — the documented first-run path, which must not error — or
/// when it fails to parse (a warning is emitted and a cold history returned, so a
/// corrupt history never aborts a live run). A genuine IO error on an existing
/// file IS propagated. Bounded read (no OOM / TOCTOU): single fd, hard cap.
///
/// The same loader `bench-waf --history-file` uses, so the scheduler's warm-start
/// semantics are identical across every command that schedules by info gain.
pub(crate) fn load_history(path: &std::path::Path) -> Result<History, String> {
    if !path.exists() {
        return Ok(History::new());
    }
    let text = crate::safe_body::read_bounded_text_file(
        path,
        crate::safe_body::GENE_BANK_FILE_MAX_BYTES,
    )
    .map_err(|e| format!("history file {} unreadable: {e}", path.display()))?;
    Ok(serde_json::from_str::<History>(&text).unwrap_or_else(|e| {
        eprintln!(
            "warn: history file {} parse error ({e}); starting cold",
            path.display()
        );
        History::new()
    }))
}

/// Persist `history` to `path` as pretty JSON via an **atomic** write (temp +
/// rename), so a crash mid-write can never truncate the operator's warm-start
/// file. Single-writer file owned by wafrift itself (never a symlink target it
/// doesn't control). The canonical persist used by both `bench-waf
/// --history-file` and `fingerprint --filter-history`.
pub(crate) fn save_history(path: &std::path::Path, history: &History) -> Result<(), String> {
    let json =
        serde_json::to_string_pretty(history).map_err(|e| format!("serialise history: {e}"))?;
    wafrift_types::loaders::write_atomic(path, json.as_bytes())
        .map_err(|e| format!("writing history file {}: {e}", path.display()))
}

/// Reorder `items` into descending info-gain schedule order under `history`,
/// returning at most `budget` of them (`budget == 0` ⇒ all, just reordered).
/// `id_of` maps an item to its scheduler id (e.g. a probe's token). When
/// `budget` is binding, the dropped items are the LOWEST-info-gain ones — under
/// a warm history that is exactly the live-query budget spent where it teaches
/// the most. Cold-start (empty history) is deterministic: every id ties at
/// θ=0.5, so the order falls back to ascending id (the scheduler's final
/// tiebreak), never RNG.
///
/// Items with ids absent from the computed schedule (only possible when `budget`
/// truncates) are dropped; duplicate ids keep the last item (battery integrity
/// forbids dup tokens, so this is defensive).
pub(crate) fn order_items_by_info_gain<T>(
    history: &History,
    items: Vec<T>,
    budget: usize,
    id_of: impl Fn(&T) -> String,
) -> Vec<T> {
    let effective = if budget == 0 {
        items.len()
    } else {
        budget.min(items.len())
    };
    let ids: Vec<String> = items.iter().map(&id_of).collect();
    let scheduled = schedule_with_diagnostics(history, &ids, effective);
    let mut by_id: std::collections::HashMap<String, T> =
        items.into_iter().map(|it| (id_of(&it), it)).collect();
    scheduled
        .into_iter()
        .filter_map(|e| by_id.remove(&e.id))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── PayloadStats invariants ─────────────────────────────

    #[test]
    fn cold_start_has_uniform_prior_theta_and_max_info_gain() {
        let s = PayloadStats::default();
        assert_eq!(s.n_trials(), 0);
        assert_eq!(s.theta_estimate(), 0.5);
        assert_eq!(s.info_gain(), 1.0);
    }

    // ── theta_ci_95 ────────────────────────────────────────

    #[test]
    fn ci_95_at_cold_start_is_wide_band_around_half() {
        // n_eff = 2, theta = 0.5 → se = sqrt(0.25/2) ≈ 0.354
        // CI half-width ≈ 0.693, clamped to [0,1] → [0.0, 1.0]
        // approximately (the formal Wald is wider than [0,1] here).
        let s = PayloadStats::default();
        let (lo, hi) = s.theta_ci_95();
        assert!(lo == 0.0, "cold-start lo must clamp to 0 (Wald wide): {lo}");
        assert!(hi == 1.0, "cold-start hi must clamp to 1 (Wald wide): {hi}");
    }

    #[test]
    fn ci_95_narrows_as_evidence_accumulates() {
        // 100 evenly-balanced trials at theta=0.5 should produce a
        // tight band — pinned at ≤ 0.2 to catch a regression that
        // accidentally widens the SE.
        let mut s = PayloadStats::default();
        for _ in 0..50 {
            s.observe(true);
            s.observe(false);
        }
        let (lo, hi) = s.theta_ci_95();
        let width = hi - lo;
        assert!(
            width <= 0.2,
            "expected narrow band at n=100: width={width} ({lo}, {hi})"
        );
        // Symmetry about 0.5 — pin so a future numerical change doesn't
        // shift the centre.
        assert!(
            (lo + hi - 1.0).abs() < 1e-9,
            "expected symmetric band: lo={lo} hi={hi}"
        );
    }

    #[test]
    fn ci_95_clamped_at_endpoints_with_many_blocks() {
        // 1000 blocks → theta ≈ 1.0 → SE ≈ 0 → CI ≈ [theta, theta]
        // clamped to ≤ 1.
        let mut s = PayloadStats::default();
        for _ in 0..1000 {
            s.observe(true);
        }
        let (lo, hi) = s.theta_ci_95();
        assert!(lo >= 0.99, "expected high lo near certainty: {lo}");
        assert!(hi <= 1.0, "expected hi clamped at 1: {hi}");
    }

    #[test]
    fn ci_95_pinned_value_at_balanced_n_20() {
        // Pin EXACT numerical output to lock in the Z_SCORE_95 and
        // BETA11_PRIOR_PSEUDO_TRIALS named constants. Independently
        // computed via Python:
        //   n_eff = 22
        //   theta = 0.5
        //   se = sqrt(0.25 / 22) = 0.10660035817780521
        //   half = 1.959963984540054 * se = 0.20893286282...
        //   lo, hi = (0.29106713717..., 0.70893286282...)
        // Tolerance loose enough for cross-platform f64 jitter but
        // tight enough to catch a 1.96 → 1.95 silent drift.
        let s = PayloadStats {
            n_blocked: 10,
            n_passed: 10,
        };
        let (lo, hi) = s.theta_ci_95();
        assert!((lo - 0.291_067_137_2).abs() < 1e-9, "lo drift: {lo}");
        assert!((hi - 0.708_932_862_8).abs() < 1e-9, "hi drift: {hi}");
    }

    #[test]
    fn ci_95_lo_le_theta_le_hi() {
        // Anti-rig: the CI must always bracket the point estimate.
        // Pin across a sweep of evidence shapes.
        for blocked in [0u32, 1, 5, 25, 100] {
            for passed in [0u32, 1, 5, 25, 100] {
                let s = PayloadStats {
                    n_blocked: blocked,
                    n_passed: passed,
                };
                let theta = s.theta_estimate();
                let (lo, hi) = s.theta_ci_95();
                assert!(
                    lo <= theta && theta <= hi,
                    "{blocked}/{passed}: CI {lo}..{hi} doesn't bracket theta={theta}"
                );
            }
        }
    }

    #[test]
    fn ci_95_bounded_in_unit_interval() {
        // Property: even at extreme counts the CI never escapes [0, 1].
        // Catches a future bug that subtracts negative se or
        // overflows.
        for blocked in [0u32, 1, 1_000, u32::MAX / 2] {
            for passed in [0u32, 1, 1_000, u32::MAX / 2] {
                let s = PayloadStats {
                    n_blocked: blocked,
                    n_passed: passed,
                };
                let (lo, hi) = s.theta_ci_95();
                assert!((0.0..=1.0).contains(&lo), "lo escaped: {lo}");
                assert!((0.0..=1.0).contains(&hi), "hi escaped: {hi}");
                assert!(lo <= hi, "inverted CI: {lo} > {hi}");
            }
        }
    }

    #[test]
    fn one_block_pulls_theta_above_half() {
        let mut s = PayloadStats::default();
        s.observe(true);
        // alpha = 2, beta = 1, theta = 2/3
        assert!((s.theta_estimate() - 2.0 / 3.0).abs() < 1e-12);
        assert_eq!(s.n_trials(), 1);
        assert!(s.info_gain() < 1.0);
    }

    #[test]
    fn one_pass_pulls_theta_below_half() {
        let mut s = PayloadStats::default();
        s.observe(false);
        // alpha = 1, beta = 2, theta = 1/3
        assert!((s.theta_estimate() - 1.0 / 3.0).abs() < 1e-12);
        assert_eq!(s.n_trials(), 1);
        assert!(s.info_gain() < 1.0);
    }

    #[test]
    fn many_blocks_converges_to_one() {
        let mut s = PayloadStats::default();
        for _ in 0..1000 {
            s.observe(true);
        }
        assert!(s.theta_estimate() > 0.99);
        assert!(
            s.info_gain() < 0.1,
            "info gain should shrink near certainty"
        );
    }

    #[test]
    fn many_passes_converges_to_zero() {
        let mut s = PayloadStats::default();
        for _ in 0..1000 {
            s.observe(false);
        }
        assert!(s.theta_estimate() < 0.01);
        assert!(s.info_gain() < 0.1);
    }

    #[test]
    fn balanced_observations_keep_theta_near_half() {
        let mut s = PayloadStats::default();
        for _ in 0..50 {
            s.observe(true);
            s.observe(false);
        }
        // alpha = 51, beta = 51, theta exactly 0.5
        assert!((s.theta_estimate() - 0.5).abs() < 1e-12);
        assert_eq!(s.info_gain(), 1.0);
    }

    #[test]
    fn observe_saturates_at_u32_max() {
        // Anti-rig: u32::MAX trials must not wrap and silently reset
        // theta toward 0.5. Saturation is the documented contract.
        let mut s = PayloadStats {
            n_blocked: u32::MAX,
            n_passed: 0,
        };
        s.observe(true);
        assert_eq!(s.n_blocked, u32::MAX);
    }

    #[test]
    fn n_trials_saturates_at_u32_max_when_both_components_max() {
        // Anti-rig: n_trials() must NEVER overflow even with
        // adversarial counts. Pinned at u32::MAX for both fields.
        // Pre-fix this would have wrapped to (u32::MAX + u32::MAX)
        // mod 2^32 = u32::MAX - 1, breaking the
        // n_trials-monotonically-non-decreasing invariant.
        let s = PayloadStats {
            n_blocked: u32::MAX,
            n_passed: u32::MAX,
        };
        assert_eq!(s.n_trials(), u32::MAX);
    }

    #[test]
    fn n_trials_sums_components() {
        let s = PayloadStats {
            n_blocked: 7,
            n_passed: 13,
        };
        assert_eq!(s.n_trials(), 20);
    }

    #[test]
    fn theta_estimate_bounded_in_unit_interval_for_any_counts() {
        // Property: no matter what u32 counts you stuff in, theta
        // never escapes [0, 1]. Catches a future "optimisation" that
        // changes the alpha/beta shift and breaks the invariant.
        for blocked in [0u32, 1, 7, 1_000, u32::MAX / 2] {
            for passed in [0u32, 1, 7, 1_000, u32::MAX / 2] {
                let s = PayloadStats {
                    n_blocked: blocked,
                    n_passed: passed,
                };
                let t = s.theta_estimate();
                assert!((0.0..=1.0).contains(&t), "theta={t} out of range");
            }
        }
    }

    // ── History API ─────────────────────────────────────────

    #[test]
    fn history_unknown_id_returns_cold_start() {
        let h = History::new();
        let s = h.stats("never-seen");
        assert_eq!(s, PayloadStats::default());
        // And reading must not insert — anti-rig: a future "let me
        // populate the cache lazily" change would silently inflate
        // history files.
        assert!(h.is_empty());
    }

    #[test]
    fn history_observe_creates_entry() {
        let mut h = History::new();
        h.observe("p1", true);
        assert_eq!(h.len(), 1);
        assert_eq!(h.stats("p1").n_blocked, 1);
    }

    #[test]
    fn history_merge_sums_overlapping_counts() {
        let mut a = History::new();
        a.observe("p1", true);
        a.observe("p1", true);
        a.observe("p2", false);
        let mut b = History::new();
        b.observe("p1", false);
        b.observe("p3", true);
        a.merge(&b);
        let s1 = a.stats("p1");
        assert_eq!(s1.n_blocked, 2);
        assert_eq!(s1.n_passed, 1);
        let s2 = a.stats("p2");
        assert_eq!(s2.n_passed, 1);
        let s3 = a.stats("p3");
        assert_eq!(s3.n_blocked, 1);
    }

    #[test]
    fn history_merge_with_empty_is_a_noop() {
        let mut a = History::new();
        a.observe("p1", true);
        let snapshot = a.clone();
        a.merge(&History::new());
        // Compare the by_id maps directly (PayloadStats: PartialEq).
        assert_eq!(a.by_id, snapshot.by_id);
    }

    #[test]
    fn history_merge_into_empty_copies() {
        let mut a = History::new();
        let mut b = History::new();
        b.observe("p", true);
        b.observe("p", false);
        a.merge(&b);
        assert_eq!(a.stats("p").n_blocked, 1);
        assert_eq!(a.stats("p").n_passed, 1);
    }

    #[test]
    fn history_merge_saturates_on_overflow() {
        // Anti-rig: if some adversarial input pushes a count near
        // u32::MAX on one side and the other side is non-zero, the
        // sum must saturate, not wrap. Wrapping would silently zero
        // out the posterior and re-rank a payload as cold-start.
        let mut a = History::new();
        a.by_id.insert(
            "p".to_string(),
            PayloadStats {
                n_blocked: u32::MAX - 1,
                n_passed: 0,
            },
        );
        let mut b = History::new();
        b.by_id.insert(
            "p".to_string(),
            PayloadStats {
                n_blocked: 5,
                n_passed: 0,
            },
        );
        a.merge(&b);
        assert_eq!(a.stats("p").n_blocked, u32::MAX);
    }

    #[test]
    fn history_merge_is_commutative_in_counts() {
        // Property: merge(a, b) and merge(b, a) produce the same
        // total counts per id. Pin so a future order-dependent
        // bug doesn't sneak in (e.g. if merge starts depending on
        // serialisation iteration order).
        let mut a = History::new();
        a.observe("p", true);
        a.observe("p", true);
        let mut b = History::new();
        b.observe("p", false);
        b.observe("q", true);
        let mut a1 = a.clone();
        a1.merge(&b);
        let mut b1 = b.clone();
        b1.merge(&a);
        assert_eq!(a1.stats("p"), b1.stats("p"));
        assert_eq!(a1.stats("q"), b1.stats("q"));
    }

    #[test]
    fn history_observe_accumulates() {
        let mut h = History::new();
        h.observe("p1", true);
        h.observe("p1", true);
        h.observe("p1", false);
        let s = h.stats("p1");
        assert_eq!(s.n_blocked, 2);
        assert_eq!(s.n_passed, 1);
        assert_eq!(s.n_trials(), 3);
    }

    // ── Scheduler ───────────────────────────────────────────

    #[test]
    fn schedule_zero_budget_returns_empty() {
        let h = History::new();
        let payloads = ["a", "b", "c"];
        let out = schedule(&h, &payloads, 0);
        assert!(out.is_empty());
    }

    #[test]
    fn schedule_budget_capped_to_payloads_len() {
        let h = History::new();
        let payloads = ["a", "b", "c"];
        let out = schedule(&h, &payloads, 100);
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn schedule_returns_at_most_budget() {
        let h = History::new();
        let payloads = ["a", "b", "c", "d", "e"];
        let out = schedule(&h, &payloads, 2);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn schedule_orders_by_descending_info_gain() {
        // p1: 10 blocks, 0 passes → theta near 1, low info gain
        // p2: 5 blocks, 5 passes → theta = 0.5, max info gain
        // p3: 0 blocks, 10 passes → theta near 0, low info gain
        let mut h = History::new();
        for _ in 0..10 {
            h.observe("p1", true);
        }
        for _ in 0..5 {
            h.observe("p2", true);
            h.observe("p2", false);
        }
        for _ in 0..10 {
            h.observe("p3", false);
        }
        let payloads = ["p1", "p2", "p3"];
        let out = schedule(&h, &payloads, 3);
        assert_eq!(out[0], "p2", "p2 has max entropy; got order {out:?}");
        // p1 and p3 are symmetric; tie-broken by n_trials (both 10)
        // then by id ascending — p1 before p3.
        assert_eq!(out[1], "p1");
        assert_eq!(out[2], "p3");
    }

    #[test]
    fn schedule_tiebreak_prefers_less_explored_at_equal_entropy() {
        // p_explored: 50 blocks, 50 passes → theta = 0.5, n_trials = 100
        // p_fresh:    0 blocks,  0 passes → theta = 0.5, n_trials = 0
        // Both have entropy 1.0; tiebreak by ascending n_trials picks
        // p_fresh first.
        let mut h = History::new();
        for _ in 0..50 {
            h.observe("p_explored", true);
            h.observe("p_explored", false);
        }
        let payloads = ["p_explored", "p_fresh"];
        let out = schedule(&h, &payloads, 2);
        assert_eq!(out[0], "p_fresh", "less-explored at equal entropy");
        assert_eq!(out[1], "p_explored");
    }

    #[test]
    fn schedule_deterministic_at_full_tie() {
        // All three payloads are cold-start; entropy and n_trials
        // both tie. Final tiebreak: id ascending.
        let h = History::new();
        let payloads = ["c", "a", "b"];
        let out = schedule(&h, &payloads, 3);
        assert_eq!(out, vec!["a", "b", "c"]);
    }

    #[test]
    fn schedule_handles_empty_payload_list() {
        let h = History::new();
        let payloads: [&str; 0] = [];
        let out = schedule(&h, &payloads, 10);
        assert!(out.is_empty());
    }

    #[test]
    fn schedule_with_single_payload_returns_it() {
        let h = History::new();
        let payloads = ["only"];
        let out = schedule(&h, &payloads, 5);
        assert_eq!(out, vec!["only"]);
    }

    #[test]
    fn schedule_demotes_certain_payloads_to_tail() {
        // Anti-rig: if the schedule ever stops demoting trivial
        // bypasses, operators would burn budget rediscovering known
        // bypasses. Pin the demotion.
        let mut h = History::new();
        for _ in 0..20 {
            h.observe("always_blocks", true);
        }
        // Cold-start payloads should all precede always_blocks.
        let payloads = ["always_blocks", "cold_a", "cold_b", "cold_c"];
        let out = schedule(&h, &payloads, 4);
        assert_eq!(out[3], "always_blocks", "got {out:?}");
    }

    // ── Serde round-trip ────────────────────────────────────

    #[test]
    fn history_serde_round_trip() {
        let mut h = History::new();
        h.observe("a", true);
        h.observe("b", false);
        h.observe("a", false);
        let json = serde_json::to_string(&h).expect("serialise");
        let parsed: History = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed.stats("a").n_blocked, 1);
        assert_eq!(parsed.stats("a").n_passed, 1);
        assert_eq!(parsed.stats("b").n_passed, 1);
    }

    #[test]
    fn history_deserialises_with_missing_fields_as_cold_start() {
        // Backwards compatibility (LAW 2): a future field added to
        // PayloadStats must not break loading old history files.
        // Currently the only fields are n_blocked / n_passed; both
        // default to zero on missing, so a payload entry of `{}`
        // deserialises to cold-start.
        let json = r#"{"by_id": {"p1": {}}}"#;
        let h: History = serde_json::from_str(json).expect("loose-shape parse");
        assert_eq!(h.stats("p1"), PayloadStats::default());
    }

    #[test]
    fn history_deserialises_with_empty_object() {
        // An empty `{}` (no by_id key) must yield an empty history,
        // not an error. Pin this so a future serde tweak doesn't
        // break the "first-run" path.
        let h: History = serde_json::from_str("{}").expect("empty parse");
        assert!(h.is_empty());
    }

    // ── Info-gain semantic pinning (anti-rig) ───────────────

    #[test]
    fn pinned_info_gain_at_half_is_exactly_one_bit() {
        // The headline guarantee: scheduling by H(theta) means a
        // theta-of-0.5 payload contributes exactly one bit of
        // information per trial. If this ever becomes 0.9999 due to
        // a numerical-stability tweak, scheduling silently biases.
        let s = PayloadStats::default();
        assert_eq!(s.info_gain(), 1.0);
    }

    // ── schedule_with_diagnostics ───────────────────────────

    #[test]
    fn diagnostics_preserves_theta_info_gain_n_trials() {
        // Diagnostic entries must carry the exact same numbers a
        // caller would have computed by reading PayloadStats. Pinned
        // so a future refactor that recomputes via an indirect path
        // (e.g. caching) doesn't silently drift.
        let mut h = History::new();
        h.observe("p", true);
        h.observe("p", true);
        h.observe("p", false);
        let out = schedule_with_diagnostics(&h, &["p"], 1);
        assert_eq!(out.len(), 1);
        let entry = &out[0];
        assert_eq!(entry.id, "p");
        // alpha = 1 + 2 = 3, beta = 1 + 1 = 2, theta = 3/5 = 0.6
        assert!((entry.theta_estimate - 0.6).abs() < 1e-12);
        let h_expected = -(0.6_f64 * 0.6_f64.log2() + 0.4_f64 * 0.4_f64.log2());
        assert!((entry.info_gain - h_expected).abs() < 1e-12);
        assert_eq!(entry.n_trials, 3);
    }

    // ── Property tests ──────────────────────────────────────

    #[test]
    fn property_schedule_returns_unique_ids() {
        // Schedule must NEVER return duplicate ids — even when the
        // input contains duplicates, the output should de-dup or
        // preserve only one. This catches a regression where a
        // future refactor stops de-duping at the corpus loader.
        let h = History::new();
        // Note: we never feed dup ids in practice (corpus_integrity
        // forbids it), but a property invariant is cheap to pin.
        let payloads = ["a", "b", "c", "d", "e", "f", "g"];
        for budget in 0..=10 {
            let out = schedule(&h, &payloads, budget);
            let mut sorted = out.clone();
            sorted.sort();
            sorted.dedup();
            assert_eq!(
                out.len(),
                sorted.len(),
                "schedule returned dups at budget={budget}: {out:?}"
            );
        }
    }

    #[test]
    fn property_schedule_is_subset_of_input() {
        // Anti-rig: the schedule must NEVER return an id that wasn't
        // in the input. Pinned across a sweep of budgets + histories.
        let mut h = History::new();
        for _ in 0..7 {
            h.observe("warm", true);
        }
        let payloads = ["alpha", "beta", "gamma", "delta", "epsilon"];
        let input_set: std::collections::HashSet<&str> = payloads.iter().copied().collect();
        for budget in 0..=10 {
            let out = schedule(&h, &payloads, budget);
            for id in &out {
                assert!(
                    input_set.contains(id.as_str()),
                    "schedule emitted unknown id {id:?} at budget={budget}: {out:?}"
                );
            }
        }
    }

    #[test]
    fn property_schedule_length_respects_budget() {
        // Property: |schedule(_, payloads, budget)| = min(budget, payloads.len())
        let h = History::new();
        let payloads = ["a", "b", "c", "d", "e"];
        for budget in 0..=10 {
            let out = schedule(&h, &payloads, budget);
            let expected = budget.min(payloads.len());
            assert_eq!(out.len(), expected, "budget={budget}");
        }
    }

    #[test]
    fn property_schedule_idempotent_for_repeated_calls() {
        // Anti-rig: schedule(h, p, b) must be a pure function — two
        // calls with the same args return the same Vec. Already
        // covered by the per-class test but pin for the bare schedule
        // too (a future RNG sneak-in would slip past the per-class
        // test if the bare path used a different RNG path).
        let mut h = History::new();
        for _ in 0..3 {
            h.observe("p1", true);
        }
        for _ in 0..1 {
            h.observe("p2", false);
        }
        let payloads = ["p1", "p2", "p3", "p4"];
        let a = schedule(&h, &payloads, 3);
        let b = schedule(&h, &payloads, 3);
        let c = schedule(&h, &payloads, 3);
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn property_history_observe_preserves_invariants() {
        // Property sweep: after any sequence of observe() calls, the
        // PayloadStats invariants must hold — theta ∈ [0,1],
        // info_gain ∈ [0,1], ci ⊆ [0,1], lo ≤ theta ≤ hi.
        let mut h = History::new();
        let outcomes = [
            true, true, false, true, false, false, true, true, false, true, false, false, false,
            true, true, false,
        ];
        for (i, &blocked) in outcomes.iter().enumerate() {
            h.observe("p", blocked);
            let s = h.stats("p");
            let theta = s.theta_estimate();
            let ig = s.info_gain();
            let (lo, hi) = s.theta_ci_95();
            assert!((0.0..=1.0).contains(&theta), "step {i} theta {theta}");
            assert!((0.0..=1.0).contains(&ig), "step {i} info_gain {ig}");
            assert!((0.0..=1.0).contains(&lo), "step {i} ci_lo {lo}");
            assert!((0.0..=1.0).contains(&hi), "step {i} ci_hi {hi}");
            assert!(
                lo <= theta && theta <= hi,
                "step {i} bracket: {lo} {theta} {hi}"
            );
        }
    }

    #[test]
    fn diagnostics_carries_theta_ci_95_bounds() {
        // Anti-rig: the CI fields populated by schedule_with_diagnostics
        // must match what PayloadStats::theta_ci_95 returns directly.
        // Drift between the two would mean --list-schedule lies about
        // estimate confidence.
        let mut h = History::new();
        for _ in 0..20 {
            h.observe("p", true);
            h.observe("p", false);
        }
        let out = schedule_with_diagnostics(&h, &["p"], 1);
        let entry = &out[0];
        let stats = h.stats("p");
        let (expected_lo, expected_hi) = stats.theta_ci_95();
        assert!(
            (entry.theta_ci_95_lo - expected_lo).abs() < 1e-12,
            "lo drift: entry={} stats={}",
            entry.theta_ci_95_lo,
            expected_lo
        );
        assert!(
            (entry.theta_ci_95_hi - expected_hi).abs() < 1e-12,
            "hi drift: entry={} stats={}",
            entry.theta_ci_95_hi,
            expected_hi
        );
        // Sanity: with 40 balanced trials the CI must be substantially
        // narrower than the cold-start [0,1] band.
        let width = entry.theta_ci_95_hi - entry.theta_ci_95_lo;
        assert!(width < 0.5, "expected narrow CI at n=40: {width}");
    }

    #[test]
    fn diagnostics_zero_budget_returns_empty() {
        let h = History::new();
        let out = schedule_with_diagnostics(&h, &["a", "b"], 0);
        assert!(out.is_empty());
    }

    #[test]
    fn diagnostics_ordering_matches_plain_schedule() {
        // Anti-rig: the diagnostic-bearing schedule and the bare
        // schedule must produce the same id sequence. Drift between
        // the two would mean the operator's preview lies about the
        // actual run order.
        let mut h = History::new();
        for _ in 0..7 {
            h.observe("warm", true);
        }
        for _ in 0..3 {
            h.observe("medium", true);
            h.observe("medium", false);
        }
        let payloads = ["cold_z", "warm", "medium", "cold_a"];
        let plain = schedule(&h, &payloads, 4);
        let diag: Vec<String> = schedule_with_diagnostics(&h, &payloads, 4)
            .into_iter()
            .map(|e| e.id)
            .collect();
        assert_eq!(plain, diag);
    }

    #[test]
    fn diagnostics_cold_start_entries_carry_uniform_prior() {
        let h = History::new();
        let out = schedule_with_diagnostics(&h, &["a"], 1);
        assert_eq!(out[0].theta_estimate, 0.5);
        assert_eq!(out[0].info_gain, 1.0);
        assert_eq!(out[0].n_trials, 0);
    }

    #[test]
    fn diagnostics_serde_round_trip() {
        // The diagnostic table is exposed in --list-schedule JSON
        // output. Pin that the round-trip is stable so a downstream
        // parser written today still works tomorrow (LAW 2).
        let entry = ScheduleEntry {
            id: "p1".to_string(),
            theta_estimate: 0.75,
            theta_ci_95_lo: 0.4,
            theta_ci_95_hi: 1.0,
            info_gain: 0.8112781244591328,
            n_trials: 4,
        };
        let json = serde_json::to_string(&entry).expect("serialise");
        let back: ScheduleEntry = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(entry, back);
    }

    // ── schedule_per_class ──────────────────────────────────

    fn per_class_inputs() -> std::collections::BTreeMap<String, Vec<String>> {
        let mut m = std::collections::BTreeMap::new();
        m.insert(
            "sql".to_string(),
            vec!["s1".into(), "s2".into(), "s3".into(), "s4".into()],
        );
        m.insert("xss".to_string(), vec!["x1".into(), "x2".into()]);
        m.insert("cmdi".to_string(), vec!["c1".into()]);
        m
    }

    #[test]
    fn per_class_zero_budget_returns_empty() {
        let h = History::new();
        let out = schedule_per_class(&h, &per_class_inputs(), 0);
        assert!(out.is_empty());
    }

    #[test]
    fn per_class_empty_input_returns_empty() {
        let h = History::new();
        let empty = std::collections::BTreeMap::new();
        let out = schedule_per_class(&h, &empty, 100);
        assert!(out.is_empty());
    }

    #[test]
    fn per_class_distributes_evenly_with_exact_divisibility() {
        // 3 classes, budget=3 → 1 slot each.
        let h = History::new();
        let out = schedule_per_class(&h, &per_class_inputs(), 3);
        assert_eq!(out.len(), 3);
        // BTreeMap iterates alphabetically: cmdi, sql, xss
        // First pick from each class, lexicographic tiebreak within
        // class at cold start.
        assert_eq!(out[0], "c1");
        assert_eq!(out[1], "s1");
        assert_eq!(out[2], "x1");
    }

    #[test]
    fn per_class_distributes_extras_in_iteration_order() {
        // 3 classes, budget=5 → base=1, extras=2 → cmdi+1, sql+1,
        // xss+0 = (2, 2, 1).
        let h = History::new();
        let out = schedule_per_class(&h, &per_class_inputs(), 5);
        // cmdi has only 1 payload, so contributes 1 even though
        // allocated 2 — honest under-fill.
        // Expected: c1, s1, s2, x1 = 4 items (not 5).
        assert_eq!(out.len(), 4, "under-fill expected for cmdi: got {out:?}");
        assert!(out.contains(&"c1".to_string()));
        assert!(out.contains(&"s1".to_string()));
        assert!(out.contains(&"s2".to_string()));
        assert!(out.contains(&"x1".to_string()));
    }

    #[test]
    fn per_class_honours_within_class_info_gain_ordering() {
        // Mark sql/s2 as fully-bypassing (theta ~ 1, low info gain).
        // Cold-start sql/s1, s3, s4 should rank ahead.
        let mut h = History::new();
        for _ in 0..20 {
            h.observe("s2", true);
        }
        // budget=12 → 4 per class, so all 4 sql payloads are kept
        // (the fairness path doesn't drop the low-rank payload here;
        // it does rank it last within its class).
        let out = schedule_per_class(&h, &per_class_inputs(), 12);
        let s2_pos = out
            .iter()
            .position(|s| s == "s2")
            .expect("s2 must appear at budget=12");
        let s1_pos = out.iter().position(|s| s == "s1").expect("s1 must appear");
        let s3_pos = out.iter().position(|s| s == "s3").expect("s3 must appear");
        let s4_pos = out.iter().position(|s| s == "s4").expect("s4 must appear");
        // All cold-start sql payloads should precede the certain s2.
        assert!(
            s1_pos < s2_pos,
            "s1 should rank ahead of certain s2: {out:?}"
        );
        assert!(
            s3_pos < s2_pos,
            "s3 should rank ahead of certain s2: {out:?}"
        );
        assert!(
            s4_pos < s2_pos,
            "s4 should rank ahead of certain s2: {out:?}"
        );
    }

    #[test]
    fn per_class_drops_low_gain_payload_when_class_budget_too_tight() {
        // Anti-rig: with budget=3 per class but only 3 of 4 sql
        // payloads fit, the lowest-info-gain payload (certain s2)
        // must be the one dropped, not a cold-start one. Catches a
        // future bug that picks by id alphabetical only.
        let mut h = History::new();
        for _ in 0..20 {
            h.observe("s2", true);
        }
        let out = schedule_per_class(&h, &per_class_inputs(), 9);
        // s2 is the certain one — should NOT appear (cold-start s1,
        // s3, s4 absorb the 3 sql slots).
        assert!(
            !out.contains(&"s2".to_string()),
            "low-gain s2 should be dropped when sql budget=3: {out:?}"
        );
        // The three cold-start sql payloads must all be present.
        assert!(out.contains(&"s1".to_string()));
        assert!(out.contains(&"s3".to_string()));
        assert!(out.contains(&"s4".to_string()));
    }

    #[test]
    fn per_class_budget_larger_than_total_payloads_returns_all_no_panic() {
        // 7 total payloads, budget 1000 → returns all 7.
        let h = History::new();
        let out = schedule_per_class(&h, &per_class_inputs(), 1000);
        assert_eq!(out.len(), 7);
    }

    #[test]
    fn per_class_one_class_acts_like_plain_schedule() {
        let mut m = std::collections::BTreeMap::new();
        m.insert("sql".to_string(), vec!["a".into(), "b".into(), "c".into()]);
        let h = History::new();
        let out = schedule_per_class(&h, &m, 2);
        // Cold start, alphabetic tiebreak.
        assert_eq!(out, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn per_class_deterministic_across_repeated_calls() {
        // Anti-rig: schedule_per_class must be a pure function of
        // (history, inputs, budget). Pin via two calls returning the
        // same output. Catches a future change that uses RNG.
        let h = History::new();
        let out1 = schedule_per_class(&h, &per_class_inputs(), 5);
        let out2 = schedule_per_class(&h, &per_class_inputs(), 5);
        assert_eq!(out1, out2);
    }

    // ── schedule_per_class_with_diagnostics ──────────────────

    #[test]
    fn per_class_with_diagnostics_matches_per_class_id_order() {
        // Anti-rig: the diagnostic-bearing fair-class scheduler must
        // produce the same id sequence as the bare fair-class
        // scheduler. Drift between the two would mean the
        // `--list-schedule --fair-class` preview lies about the
        // actual run order.
        let mut h = History::new();
        for _ in 0..15 {
            h.observe("s2", true);
        }
        h.observe("x1", false);
        let plain = schedule_per_class(&h, &per_class_inputs(), 9);
        let diag: Vec<String> = schedule_per_class_with_diagnostics(&h, &per_class_inputs(), 9)
            .into_iter()
            .map(|e| e.id)
            .collect();
        assert_eq!(plain, diag);
    }

    #[test]
    fn per_class_with_diagnostics_zero_budget_returns_empty() {
        let h = History::new();
        let out = schedule_per_class_with_diagnostics(&h, &per_class_inputs(), 0);
        assert!(out.is_empty());
    }

    #[test]
    fn per_class_with_diagnostics_empty_input_returns_empty() {
        let h = History::new();
        let empty = std::collections::BTreeMap::new();
        let out = schedule_per_class_with_diagnostics(&h, &empty, 100);
        assert!(out.is_empty());
    }

    #[test]
    fn per_class_with_diagnostics_carries_correct_stats() {
        // Each diagnostic entry must reflect the same
        // theta/info_gain/n_trials the plain per-class would have
        // observed via History::stats. Pinned so a future change
        // doesn't cache stale stats. Budget=12 (4 per class) so
        // all sql payloads survive — s1's diagnostics are still
        // reachable even though s1's info_gain is below cold-start.
        let mut h = History::new();
        for _ in 0..5 {
            h.observe("s1", true);
        }
        let out = schedule_per_class_with_diagnostics(&h, &per_class_inputs(), 12);
        let s1_entry = out
            .iter()
            .find(|e| e.id == "s1")
            .expect("s1 must appear at budget=12");
        assert_eq!(s1_entry.n_trials, 5);
        // alpha = 6, beta = 1, theta = 6/7
        assert!((s1_entry.theta_estimate - 6.0 / 7.0).abs() < 1e-12);
    }

    #[test]
    fn pinned_info_gain_approaches_zero_with_more_evidence() {
        // Anti-rig: as evidence accumulates, info_gain MUST shrink
        // toward zero. The exact decay is `H(theta_n) ~ log2(n) / n`
        // — at n = 10^6 trials it's about 22 microbits; at n = u32::MAX
        // (~4·10^9) it falls below 1 nanobit. We pin BOTH the
        // monotone-decreasing property and an upper bound for n=10^6
        // that catches a future bug that adds an epsilon floor and
        // turns the schedule head into noise.
        let s_small = PayloadStats {
            n_blocked: 1_000,
            n_passed: 0,
        };
        let s_medium = PayloadStats {
            n_blocked: 1_000_000,
            n_passed: 0,
        };
        let s_huge = PayloadStats {
            n_blocked: u32::MAX,
            n_passed: 0,
        };
        let g_small = s_small.info_gain();
        let g_medium = s_medium.info_gain();
        let g_huge = s_huge.info_gain();
        assert!(g_small > g_medium, "{g_small} should exceed {g_medium}");
        assert!(g_medium > g_huge, "{g_medium} should exceed {g_huge}");
        // Concrete upper bound at 10^6 trials: a few hundred microbits
        // is the loosest interesting cap. If a future estimator
        // change pushes this above 1 millibit, scheduling will
        // re-explore already-certain payloads.
        assert!(g_medium < 1e-3, "info_gain at 10^6 trials = {g_medium}");
        // And the symmetric case (all passes) decays the same way.
        let s_pass_huge = PayloadStats {
            n_blocked: 0,
            n_passed: u32::MAX,
        };
        assert!(
            s_pass_huge.info_gain() < 1e-6,
            "{}",
            s_pass_huge.info_gain()
        );
    }

    // ── order_items_by_info_gain ────────────────────────────

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Item {
        tok: String,
        tag: u32,
    }
    fn item(tok: &str, tag: u32) -> Item {
        Item { tok: tok.into(), tag }
    }

    #[test]
    fn order_items_cold_start_is_deterministic_id_order() {
        let h = History::new();
        let items = vec![item("z", 1), item("a", 2), item("m", 3)];
        let out = order_items_by_info_gain(&h, items, 0, |i| i.tok.clone());
        // Cold start ⇒ θ=0.5 for all ⇒ ascending id tiebreak: a, m, z.
        assert_eq!(
            out.iter().map(|i| i.tok.as_str()).collect::<Vec<_>>(),
            vec!["a", "m", "z"]
        );
        // The item payload (tag) must travel with its id, not get reassigned.
        assert_eq!(out[0].tag, 2);
    }

    #[test]
    fn order_items_budget_drops_lowest_info_gain_under_warm_history() {
        // `blocked` is fully policed (θ→1, low info gain); `uncertain` sits near
        // 0.5 (high info gain). Budget 1 must keep the uncertain probe and drop
        // the already-known one.
        let mut h = History::new();
        for _ in 0..30 {
            h.observe("blocked", true);
        }
        h.observe("uncertain", true);
        h.observe("uncertain", false);
        let items = vec![item("blocked", 1), item("uncertain", 2)];
        let out = order_items_by_info_gain(&h, items, 1, |i| i.tok.clone());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].tok, "uncertain", "budget must spend on the uncertain token");
    }

    #[test]
    fn order_items_budget_zero_keeps_all_just_reordered() {
        let mut h = History::new();
        for _ in 0..30 {
            h.observe("known", true);
        }
        let items = vec![item("known", 1), item("fresh", 2)];
        let out = order_items_by_info_gain(&h, items, 0, |i| i.tok.clone());
        assert_eq!(out.len(), 2, "budget 0 drops nothing");
        // Fresh (θ=0.5, max info gain) ranks ahead of the certain `known`.
        assert_eq!(out[0].tok, "fresh");
    }

    #[test]
    fn order_items_budget_above_len_is_a_noop_cap() {
        let h = History::new();
        let items = vec![item("a", 1), item("b", 2)];
        let out = order_items_by_info_gain(&h, items, 99, |i| i.tok.clone());
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn order_items_empty_input_yields_empty() {
        let h = History::new();
        let items: Vec<Item> = Vec::new();
        let out = order_items_by_info_gain(&h, items, 5, |i| i.tok.clone());
        assert!(out.is_empty());
    }

    // ── load_history / save_history round-trip ──────────────

    #[test]
    fn load_history_absent_file_is_cold_start_not_error() {
        let dir = std::env::temp_dir();
        let path = dir.join("wafrift_test_no_such_history_xyz.json");
        // Ensure it does not exist.
        let _ = std::fs::remove_file(&path);
        let h = load_history(&path).expect("absent file must cold-start, not error");
        assert!(h.is_empty());
    }

    #[test]
    fn save_then_load_history_round_trips_counts() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "wafrift_test_history_rt_{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let mut h = History::new();
        h.observe("tokA", true);
        h.observe("tokA", false);
        h.observe("tokB", true);
        save_history(&path, &h).expect("save");
        let back = load_history(&path).expect("load");
        assert_eq!(back.stats("tokA").n_blocked, 1);
        assert_eq!(back.stats("tokA").n_passed, 1);
        assert_eq!(back.stats("tokB").n_blocked, 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_history_corrupt_file_cold_starts_with_warning_not_panic() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "wafrift_test_history_corrupt_{}.json",
            std::process::id()
        ));
        std::fs::write(&path, "{ this is not valid json ]").expect("write corrupt");
        let h = load_history(&path).expect("corrupt file must not be a hard error");
        assert!(h.is_empty(), "corrupt history must cold-start");
        let _ = std::fs::remove_file(&path);
    }
}
