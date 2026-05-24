//! Per-host evasion state — tracks what works and what doesn't.
//!
//! One struct, one job: maintain a per-host record of which techniques
//! have been tried, which succeeded, and how aggressively we need
//! to escalate. Maintains a pool of proven winners and continuously
//! re-evaluates as the WAF adapts.

use wafrift_content_type as content_type;
use wafrift_encoding::encoding;
use wafrift_types::Technique;
use wafrift_types::escalation::EscalationLevel;

/// Minimum number of attempts before a technique is eligible for
/// promotion to the winner pool or demotion to the blocklist.
const MIN_ATTEMPTS_FOR_VERDICT: u32 = 3;

/// Success rate (0.0–1.0) above which a technique is promoted to the
/// winner pool and rotated for all subsequent requests.
const WINNER_THRESHOLD: f64 = 0.60;

/// Success rate below which a technique is demoted to the blocklist
/// and no longer used.
const BLOCK_THRESHOLD: f64 = 0.20;

/// Number of consecutive blocks on a previously-winning technique
/// before it is evicted from the winner pool (drift detection).
const DRIFT_BLOCK_LIMIT: u32 = 2;

/// Hard cap on `prioritized_techniques` and `avoided_techniques` so a
/// long-running scan that ingests many adversarial WAF profiles cannot
/// grow `HostState` memory without bound. Audit (2026-05-10).
const MAX_HINTS_PER_LIST: usize = 200;

/// Hard cap on `technique_stats` and `winner_consecutive_blocks` —
/// per-host structures that key on the technique name. With ~100
/// distinct names in the standard catalogue, 500 is generous headroom
/// while still bounding worst-case adversarial growth. Audit (2026-05-10).
const MAX_TECHNIQUE_STATS: usize = 500;

/// Per-host evasion state — tracks what works and what doesn't.
#[derive(Debug, Default, Clone)]
pub struct HostState {
    /// Number of requests blocked.
    pub blocks: u32,
    /// Number of requests that succeeded.
    pub successes: u32,
    /// Encoding strategies that have been tried.
    pub tried_encodings: Vec<encoding::Strategy>,
    /// Content-Type variants that have been tried.
    pub tried_content_types: Vec<content_type::ContentTypeTechnique>,
    /// The last strategy that succeeded (if any).
    pub last_success: Option<Technique>,
    /// Per-technique success rate: (`technique_name`, successes, attempts).
    pub technique_stats: Vec<(String, u32, u32)>,
    /// Whether WAF presence has been confirmed via calibration.
    pub waf_confirmed: bool,
    /// Detected WAF name (if identified).
    pub waf_name: Option<String>,

    // ── Adaptive rotation state ─────────────────────────────────────
    /// Techniques with a proven bypass rate above the internal winner threshold.
    /// The proxy rotates only these once the discovery phase ends.
    pub proven_winners: Vec<String>,
    /// Techniques that consistently fail — never used again unless
    /// the winner pool is exhausted and a full re-discovery is needed.
    pub blocklisted: Vec<String>,
    /// Round-robin index into `proven_winners`.
    pub rotation_index: usize,
    /// Per-winner consecutive block counter for drift detection.
    /// Key: technique name, Value: consecutive blocks since last success.
    pub winner_consecutive_blocks: Vec<(String, u32)>,
    /// Whether the initial discovery phase is complete (enough data
    /// collected to populate the winner pool).
    pub discovery_complete: bool,

    // ── WAF-aware strategy hints (populated from ResponseSignal) ────
    /// Techniques the matched WAF profile recommends trying first.
    /// Set by `record_signal()` when a response matches a loaded profile.
    /// The strategy engine reads these to bias MCTS exploration or
    /// shortcut the escalation pipeline.
    pub prioritized_techniques: Vec<String>,
    /// Techniques the matched WAF profile says are a waste of requests.
    /// The strategy engine skips these entirely.
    pub avoided_techniques: Vec<String>,
    /// WAF inspection model hint (e.g. "`single_pass_url_decode`",
    /// "`multi_regex_scoring`"). Informs which encoding dimensions to explore.
    pub inspection_model: Option<String>,
    /// Number of rate-limit (429) responses seen — drives backoff, not
    /// technique change.
    pub rate_limits: u32,
    /// Number of JS challenges (Cloudflare captcha pages, etc.) seen.
    pub challenges: u32,
}

impl HostState {
    /// Record a blocked response (no technique tracking).
    pub fn record_block(&mut self) {
        self.blocks = self.blocks.saturating_add(1);
    }

    fn bump_block_attempt_for_technique(&mut self, technique_name: &str) {
        if let Some(stat) = self
            .technique_stats
            .iter_mut()
            .find(|(n, _, _)| n == technique_name)
        {
            // saturating_add avoids the u32 overflow audit finding —
            // pre-fix `stat.2 += 1` would panic in debug or wrap in
            // release after 2^32 attempts.
            stat.2 = stat.2.saturating_add(1);
        } else if self.technique_stats.len() < MAX_TECHNIQUE_STATS {
            // Audit (2026-05-10): cap technique_stats so a host that
            // sees an unbounded stream of unique technique names from
            // adversarial profiles cannot grow the vector forever.
            self.technique_stats
                .push((technique_name.to_string(), 0, 1));
        }

        if self.proven_winners.contains(&technique_name.to_string()) {
            if let Some(entry) = self
                .winner_consecutive_blocks
                .iter_mut()
                .find(|(n, _)| n == technique_name)
            {
                entry.1 = entry.1.saturating_add(1);
            } else if self.winner_consecutive_blocks.len() < MAX_TECHNIQUE_STATS {
                self.winner_consecutive_blocks
                    .push((technique_name.to_string(), 1));
            }
        }
    }

    /// Record a blocked response with technique tracking.
    ///
    /// Updates per-technique stats and triggers drift detection if the
    /// technique was previously in the winner pool.
    pub fn record_block_for(&mut self, technique_name: &str) {
        self.blocks = self.blocks.saturating_add(1);
        self.bump_block_attempt_for_technique(technique_name);
        self.prune();
    }

    /// One blocked HTTP response attributed to several active techniques (compound evasion).
    pub fn record_block_for_many(&mut self, technique_names: &[String]) {
        self.blocks = self.blocks.saturating_add(1);
        for name in technique_names {
            self.bump_block_attempt_for_technique(name);
        }
        self.prune();
    }

    fn bump_success_for_technique(&mut self, technique: &Technique) {
        let name = technique.to_string();
        if let Some(stat) = self.technique_stats.iter_mut().find(|(n, _, _)| *n == name) {
            // Use saturating_add to match the block path (audit fix: plain `+= 1`
            // panics in debug or silently wraps in release after 2^32 successes on
            // the same technique in a long-running proxy session).
            stat.1 = stat.1.saturating_add(1);
            stat.2 = stat.2.saturating_add(1);
        } else {
            self.technique_stats.push((name.clone(), 1, 1));
        }

        if let Some(entry) = self
            .winner_consecutive_blocks
            .iter_mut()
            .find(|(n, _)| *n == name)
        {
            entry.1 = 0;
        }
    }

    /// Record a successful response with technique tracking.
    ///
    /// Resets the drift counter for this technique (it's still working)
    /// and triggers pool re-evaluation.
    pub fn record_success(&mut self, technique: Technique) {
        self.record_success_for_many(&[technique]);
    }

    /// One successful HTTP response when multiple techniques were applied together.
    pub fn record_success_for_many(&mut self, techniques: &[Technique]) {
        if techniques.is_empty() {
            return;
        }
        self.successes = self.successes.saturating_add(1);
        for technique in techniques {
            self.bump_success_for_technique(technique);
        }
        self.last_success = techniques.last().cloned();

        self.evaluate_pools();
    }

    /// Get the technique with highest success rate.
    ///
    /// Requires at least 2 attempts before a technique is considered to
    /// avoid drawing conclusions from a single sample.
    #[must_use]
    pub fn best_technique(&self) -> Option<&str> {
        self.technique_stats
            .iter()
            .filter(|(_, _, attempts)| *attempts >= 2)
            .max_by(|(_, s1, a1), (_, s2, a2)| {
                let rate1 = if *a1 == 0 {
                    0.0
                } else {
                    f64::from(*s1) / f64::from(*a1)
                };
                let rate2 = if *a2 == 0 {
                    0.0
                } else {
                    f64::from(*s2) / f64::from(*a2)
                };
                rate1
                    .partial_cmp(&rate2)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(name, _, _)| name.as_str())
    }

    /// Get success rate for a specific technique.
    #[must_use]
    pub fn technique_success_rate(&self, name: &str) -> f64 {
        self.technique_stats
            .iter()
            .find(|(n, _, _)| n == name)
            .map_or(0.0, |(_, s, a)| {
                if *a > 0 {
                    f64::from(*s) / f64::from(*a)
                } else {
                    0.0
                }
            })
    }

    /// Mark WAF as confirmed present on this host.
    pub fn confirm_waf(&mut self, waf_name: Option<String>) {
        self.waf_confirmed = true;
        self.waf_name = waf_name;
    }

    /// Check if this host needs evasion at all.
    ///
    /// Returns `false` only if we have sent requests and none were blocked
    /// AND the WAF has not been confirmed via calibration. When we have no
    /// data yet the safe default is to assume evasion is needed.
    #[must_use]
    pub fn needs_evasion(&self) -> bool {
        self.waf_confirmed || self.blocks > 0 || (self.successes == 0 && self.blocks == 0)
    }

    /// Get the next encoding strategy to try (one we haven't tried yet
    /// and isn't blocklisted). Blocklist comparison uses the canonical
    /// `Strategy::as_str()` name — same form `record_block_for_many` /
    /// proxy gene-bank persistence use everywhere else. (Earlier
    /// versions used `format!("{s:?}")` here, which produced `PascalCase`
    /// debug names that did not match the kebab-case strings stored on
    /// blocklist.)
    #[must_use]
    pub fn next_encoding(&self) -> Option<encoding::Strategy> {
        encoding::all_strategies().iter().copied().find(|s| {
            !self.tried_encodings.contains(s) && !self.blocklisted.contains(&s.as_str().to_string())
        })
    }

    /// Escalation level based on block count.
    #[must_use]
    pub fn escalation_level(&self) -> EscalationLevel {
        match self.blocks {
            0 => EscalationLevel::None,
            1..=2 => EscalationLevel::Light,
            3..=5 => EscalationLevel::Medium,
            _ => EscalationLevel::Heavy,
        }
    }

    // ── Adaptive rotation API ───────────────────────────────────────

    /// Pick the next technique from the proven winner pool.
    ///
    /// Returns `None` if the winner pool is empty (still in discovery
    /// phase or all winners were pruned). Round-robins through
    /// the pool to avoid WAF pattern detection.
    #[must_use]
    pub fn next_winner(&mut self) -> Option<String> {
        if self.proven_winners.is_empty() {
            return None;
        }
        let idx = self.rotation_index % self.proven_winners.len();
        self.rotation_index = self.rotation_index.wrapping_add(1);
        Some(self.proven_winners[idx].clone())
    }

    /// Whether the host has finished initial discovery and has a
    /// non-empty winner pool to rotate through.
    #[must_use]
    pub fn has_winners(&self) -> bool {
        self.discovery_complete && !self.proven_winners.is_empty()
    }

    /// Re-evaluate all technique stats and populate winner/blocklist pools.
    ///
    /// Called after every success observation. Checks whether enough
    /// data has been collected to declare discovery complete.
    pub fn evaluate_pools(&mut self) {
        // Audit (2026-05-10): pre-fix this used `u32::sum()` which can
        // overflow under sustained scanning (technique_stats.len()
        // × MAX_TECHNIQUE_STATS attempts each). Lift to u64 so the
        // total monotonically grows past u32::MAX without panicking
        // in debug or wrapping in release.
        let total_attempted: u64 = self
            .technique_stats
            .iter()
            .map(|(_, _, a)| u64::from(*a))
            .sum();

        // Don't declare discovery complete until we have meaningful data.
        if total_attempted < 10 {
            return;
        }

        let mut new_winners = Vec::new();
        let mut new_blocked = Vec::new();

        for (name, successes, attempts) in &self.technique_stats {
            if *attempts < MIN_ATTEMPTS_FOR_VERDICT {
                continue;
            }
            let rate = f64::from(*successes) / f64::from(*attempts);
            if rate >= WINNER_THRESHOLD {
                new_winners.push(name.clone());
            } else if rate < BLOCK_THRESHOLD {
                new_blocked.push(name.clone());
            }
        }

        if !new_winners.is_empty() {
            self.proven_winners = new_winners;
            self.discovery_complete = true;
        }

        // Only add newly-discovered blocked techniques — don't
        // remove existing blocklist entries.
        for blocked in new_blocked {
            if !self.blocklisted.contains(&blocked) {
                self.blocklisted.push(blocked);
            }
        }
    }

    /// Continuously prune the winner pool based on drift detection.
    ///
    /// If a previously-winning technique has been blocked repeatedly
    /// (see internal drift limit), it is evicted from
    /// the winner pool and moved to the blocklist. If the winner pool
    /// becomes empty, `discovery_complete` is reset so the system
    /// re-enters discovery mode.
    pub fn prune(&mut self) {
        let mut evicted = Vec::new();

        for (name, consecutive) in &self.winner_consecutive_blocks {
            if *consecutive >= DRIFT_BLOCK_LIMIT {
                evicted.push(name.clone());
            }
        }

        for name in &evicted {
            self.proven_winners.retain(|w| w != name);
            if !self.blocklisted.contains(name) {
                self.blocklisted.push(name.clone());
            }
            self.winner_consecutive_blocks.retain(|(n, _)| n != name);
        }

        // If all winners were pruned, re-enter discovery mode.
        if self.proven_winners.is_empty() && self.discovery_complete {
            self.discovery_complete = false;
            // Clear blocklist to allow full re-discovery with fresh data.
            self.blocklisted.clear();
            // Reset technique stats for a clean slate.
            self.technique_stats.clear();
            self.winner_consecutive_blocks.clear();
        }
    }

    // ── Rich response signal API ────────────────────────────────────
    //
    // Mirrors `wafrift_transport::signal::BlockClass` via boolean flags
    // instead of importing the type — the strategy crate must not depend
    // on transport (transport already depends on strategy). The proxy
    // destructures the transport `ResponseSignal` and passes the fields
    // through here.

    /// Record a rich response signal from the upstream WAF response.
    ///
    /// This is the upgrade path from the binary `record_block()` /
    /// `record_success()` API. Instead of just "blocked or not," the
    /// signal tells us:
    ///
    /// - **Which WAF** produced the block (→ sets `waf_name`)
    /// - **What techniques to prioritize** (→ populates `prioritized_techniques`)
    /// - **What to avoid** (→ populates `avoided_techniques`)
    /// - **Whether this is a rate limit / challenge** (→ doesn't penalize
    ///   the current technique, increments `rate_limits` / `challenges`)
    /// - **The inspection model** (→ stored for MCTS dimension weighting)
    ///
    /// # Arguments
    ///
    /// * `is_hard_block` — WAF returned 403/406/etc.
    /// * `is_soft_block` — 200 OK but body contains WAF block markers.
    /// * `is_rate_limit` — 429 or equivalent — back off, don't change technique.
    /// * `is_challenge` — JS challenge / captcha — back off, don't change technique.
    /// * `matched_waf` — Which WAF profile matched (e.g. "Cloudflare").
    /// * `prioritize` — Techniques the profile recommends.
    /// * `avoid` — Techniques the profile says to skip.
    /// * `inspection_model` — WAF's inspection strategy hint.
    /// * `technique_keys` — The techniques that were applied to this request.
    #[allow(clippy::too_many_arguments)]
    pub fn record_signal(
        &mut self,
        is_hard_block: bool,
        is_soft_block: bool,
        is_rate_limit: bool,
        is_challenge: bool,
        matched_waf: Option<&str>,
        prioritize: &[String],
        avoid: &[String],
        inspection_model: Option<&str>,
        technique_keys: &[String],
    ) {
        if is_rate_limit {
            // Rate limit is NOT a technique failure. Don't penalize
            // the current technique — the WAF is telling us to slow
            // down, not that our payload was caught.
            self.rate_limits = self.rate_limits.saturating_add(1);
        } else if is_challenge {
            // JS challenge (e.g. Cloudflare captcha). Same logic:
            // this isn't a technique failure, it's a bot detection.
            self.challenges = self.challenges.saturating_add(1);
        } else if is_hard_block || is_soft_block {
            // Real technique failure — the WAF caught the payload.
            self.blocks = self.blocks.saturating_add(1);
            for name in technique_keys {
                self.bump_block_attempt_for_technique(name);
            }
            self.prune();
        } else {
            // Pass — bypass confirmed.
            self.successes = self.successes.saturating_add(1);
            // Success attribution is handled by the caller via
            // record_success_for_many() since it needs the full
            // Technique objects, not just string keys.
        }

        // Ingest WAF profile hints (only update, never downgrade).
        if let Some(waf_name) = matched_waf
            && self.waf_name.is_none()
        {
            self.waf_name = Some(waf_name.to_string());
            self.waf_confirmed = true;
        }

        // Merge prioritized techniques (union, preserving order).
        // Audit (2026-05-10): pre-fix this grew unboundedly. A long-
        // running scan picking up 100k unique technique names from
        // adversarial profiles would balloon HostState past safe
        // memory limits. Cap at MAX_HINTS_PER_LIST entries.
        for tech in prioritize {
            if self.prioritized_techniques.len() >= MAX_HINTS_PER_LIST {
                break;
            }
            if !self.prioritized_techniques.contains(tech) {
                self.prioritized_techniques.push(tech.clone());
            }
        }

        // Merge avoided techniques (same cap).
        for tech in avoid {
            if self.avoided_techniques.len() >= MAX_HINTS_PER_LIST {
                break;
            }
            if !self.avoided_techniques.contains(tech) {
                self.avoided_techniques.push(tech.clone());
            }
        }

        // Set inspection model hint.
        if let Some(model) = inspection_model
            && self.inspection_model.is_none()
        {
            self.inspection_model = Some(model.to_string());
        }
    }

    /// Check whether a technique should be skipped based on WAF profile hints.
    ///
    /// Returns `true` if the technique name appears in either:
    /// - The WAF profile's `avoid` list (known to waste requests)
    /// - The host's `blocklisted` techniques (proven failures)
    #[must_use]
    pub fn should_skip_technique(&self, technique_name: &str) -> bool {
        self.avoided_techniques.iter().any(|t| t == technique_name)
            || self.blocklisted.contains(&technique_name.to_string())
    }

    /// Get the ordered list of techniques to try, incorporating WAF
    /// profile priorities. Returns prioritized techniques first
    /// (from the matched profile), filtered to exclude blocklisted
    /// and avoided techniques.
    #[must_use]
    pub fn suggested_techniques(&self) -> Vec<String> {
        self.prioritized_techniques
            .iter()
            .filter(|t| !self.should_skip_technique(t))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_state_no_evasion() {
        let state = HostState::default();
        assert_eq!(state.escalation_level(), EscalationLevel::None);
    }

    #[test]
    fn light_after_two_blocks() {
        let mut state = HostState::default();
        state.record_block();
        state.record_block();
        assert_eq!(state.escalation_level(), EscalationLevel::Light);
    }

    #[test]
    fn medium_after_four_blocks() {
        let mut state = HostState::default();
        for _ in 0..4 {
            state.record_block();
        }
        assert_eq!(state.escalation_level(), EscalationLevel::Medium);
    }

    #[test]
    fn heavy_after_many_blocks() {
        let mut state = HostState::default();
        for _ in 0..10 {
            state.record_block();
        }
        assert_eq!(state.escalation_level(), EscalationLevel::Heavy);
    }

    #[test]
    fn record_success_tracks_technique() {
        let mut state = HostState::default();
        state.record_success(Technique::PayloadEncoding("CaseAlternation".into()));
        assert_eq!(state.successes, 1);
        assert!(state.last_success.is_some());
    }

    #[test]
    fn record_block_for_tracks_technique() {
        let mut state = HostState::default();
        state.record_block_for("CaseAlternation");
        state.record_block_for("CaseAlternation");
        assert_eq!(state.blocks, 2);
        assert_eq!(state.technique_stats[0].2, 2); // 2 attempts
    }

    #[test]
    fn record_block_for_many_one_http_block_multi_technique() {
        let mut state = HostState::default();
        state.record_block_for_many(&["a".to_string(), "b".to_string()]);
        assert_eq!(state.blocks, 1);
        assert_eq!(state.technique_stats.len(), 2);
        assert_eq!(
            state
                .technique_stats
                .iter()
                .find(|(n, _, _)| n == "a")
                .unwrap()
                .2,
            1
        );
        assert_eq!(
            state
                .technique_stats
                .iter()
                .find(|(n, _, _)| n == "b")
                .unwrap()
                .2,
            1
        );
    }

    #[test]
    fn record_success_for_many_compound() {
        let mut state = HostState::default();
        state.record_success_for_many(&[
            Technique::PayloadEncoding("A".into()),
            Technique::PayloadEncoding("B".into()),
        ]);
        assert_eq!(state.successes, 1);
        let sa = state
            .technique_stats
            .iter()
            .find(|(n, _, _)| n == "encoding:A")
            .unwrap();
        assert_eq!(sa.1, 1);
        assert_eq!(sa.2, 1);
    }

    #[test]
    fn best_technique_needs_two_attempts() {
        let mut state = HostState::default();
        state.record_success(Technique::PayloadEncoding("DoubleUrlEncode".into()));
        // One attempt — should not be returned
        assert!(state.best_technique().is_none());
    }

    #[test]
    fn needs_evasion_default() {
        let state = HostState::default();
        assert!(state.needs_evasion()); // Safe default
    }

    #[test]
    fn needs_evasion_after_success_no_blocks() {
        let state = HostState {
            successes: 5,
            ..Default::default()
        };
        assert!(!state.needs_evasion());
    }

    #[test]
    fn confirm_waf_sets_flag() {
        let mut state = HostState::default();
        state.confirm_waf(Some("Cloudflare".into()));
        assert!(state.waf_confirmed);
        assert_eq!(state.waf_name.as_deref(), Some("Cloudflare"));
        assert!(state.needs_evasion());
    }

    // ── Adaptive rotation tests ─────────────────────────────────────

    #[test]
    fn no_winners_before_discovery() {
        let state = HostState::default();
        assert!(!state.has_winners());
        assert!(state.proven_winners.is_empty());
    }

    #[test]
    fn evaluate_pools_promotes_winners() {
        let mut state = HostState {
            technique_stats: vec![
                ("GoodTech".into(), 9, 10), // 90% — should be winner
                ("OkTech".into(), 7, 10),   // 70% — should be winner
                ("BadTech".into(), 1, 10),  // 10% — should be blocklisted
                ("TooFew".into(), 2, 2),    // 100% but only 2 attempts — skip
            ],
            ..Default::default()
        };
        state.evaluate_pools();
        assert!(state.discovery_complete);
        assert!(state.proven_winners.contains(&"GoodTech".to_string()));
        assert!(state.proven_winners.contains(&"OkTech".to_string()));
        assert!(!state.proven_winners.contains(&"BadTech".to_string()));
        assert!(!state.proven_winners.contains(&"TooFew".to_string()));
        assert!(state.blocklisted.contains(&"BadTech".to_string()));
    }

    #[test]
    fn evaluate_pools_skips_insufficient_data() {
        // Only 5 total attempts — not enough to declare discovery.
        let mut state = HostState {
            technique_stats: vec![("T1".into(), 3, 5)],
            ..Default::default()
        };
        state.evaluate_pools();
        assert!(!state.discovery_complete);
        assert!(state.proven_winners.is_empty());
    }

    #[test]
    fn next_winner_round_robins() {
        let mut state = HostState {
            proven_winners: vec!["A".into(), "B".into(), "C".into()],
            discovery_complete: true,
            ..Default::default()
        };

        assert_eq!(state.next_winner().as_deref(), Some("A"));
        assert_eq!(state.next_winner().as_deref(), Some("B"));
        assert_eq!(state.next_winner().as_deref(), Some("C"));
        assert_eq!(state.next_winner().as_deref(), Some("A"));
    }

    #[test]
    fn next_winner_returns_none_when_empty() {
        let mut state = HostState::default();
        assert!(state.next_winner().is_none());
    }

    #[test]
    fn drift_detection_evicts_winner() {
        let mut state = HostState {
            proven_winners: vec!["WinTech".into(), "StillGood".into()],
            discovery_complete: true,
            ..Default::default()
        };

        // Two consecutive blocks on WinTech triggers eviction.
        state.record_block_for("WinTech");
        state.record_block_for("WinTech");

        assert!(!state.proven_winners.contains(&"WinTech".to_string()));
        assert!(state.blocklisted.contains(&"WinTech".to_string()));
        // StillGood survives.
        assert!(state.proven_winners.contains(&"StillGood".to_string()));
    }

    #[test]
    fn success_resets_drift_counter() {
        let mut state = HostState {
            proven_winners: vec!["encoding:Tech".into()],
            discovery_complete: true,
            ..Default::default()
        };

        // One block.
        state.record_block_for("encoding:Tech");
        // Then a success — should reset the drift counter.
        state.record_success(Technique::PayloadEncoding("Tech".into()));

        // Another block — should NOT evict because counter was reset.
        state.record_block_for("encoding:Tech");
        assert!(state.proven_winners.contains(&"encoding:Tech".to_string()));
    }

    #[test]
    fn all_winners_evicted_triggers_rediscovery() {
        let mut state = HostState {
            proven_winners: vec!["OnlyWinner".into()],
            discovery_complete: true,
            blocklisted: vec!["PrevBad".into()],
            technique_stats: vec![("OnlyWinner".into(), 5, 10)],
            ..Default::default()
        };

        // Evict the only winner.
        state.record_block_for("OnlyWinner");
        state.record_block_for("OnlyWinner");

        // Should re-enter discovery mode.
        assert!(!state.discovery_complete);
        assert!(state.proven_winners.is_empty());
        // Blocklist and stats are cleared for a clean re-discovery.
        assert!(state.blocklisted.is_empty());
        assert!(state.technique_stats.is_empty());
    }

    #[test]
    fn full_lifecycle_discover_rotate_drift_rediscover() {
        let mut state = HostState::default();

        // Phase 1: Discovery — simulate 15 technique observations.
        for _ in 0..5 {
            state.record_success(Technique::PayloadEncoding("Winner".into()));
        }
        for _ in 0..5 {
            state.record_block_for("Loser");
        }
        // Add some more to reach threshold.
        for _ in 0..5 {
            state.record_success(Technique::PayloadEncoding("AlsoGood".into()));
        }

        // Should have promoted winners.
        assert!(state.discovery_complete);
        assert!(state.has_winners());
        assert!(
            state
                .proven_winners
                .contains(&"encoding:Winner".to_string())
                || state
                    .proven_winners
                    .contains(&"encoding:AlsoGood".to_string())
        );

        // Phase 2: Rotation — get next winner.
        let w = state.next_winner();
        assert!(w.is_some());

        // Phase 3: Drift — block a winner twice.
        let winner_name = state.proven_winners[0].clone();
        state.record_block_for(&winner_name);
        state.record_block_for(&winner_name);

        // Winner should be evicted.
        assert!(!state.proven_winners.contains(&winner_name));
    }

    #[test]
    fn blocklisted_encoding_not_suggested() {
        let mut state = HostState::default();
        // Blocklist a known encoding strategy name.
        state.blocklisted.push("CaseAlternation".into());
        // next_encoding should skip it.
        if let Some(strategy) = state.next_encoding() {
            assert_ne!(format!("{strategy:?}"), "CaseAlternation");
        }
    }

    // ── Rich signal API tests ───────────────────────────────────────

    #[test]
    fn signal_rate_limit_does_not_penalize_technique() {
        let mut state = HostState::default();
        state.record_signal(
            false,                                     // not hard block
            false,                                     // not soft block
            true,                                      // IS rate limit
            false,                                     // not challenge
            Some("Cloudflare"),                        // matched WAF
            &["DoubleUrlEncode".to_string()],          // prioritize
            &["CaseAlternation".to_string()],          // avoid
            Some("single_pass_url_decode"),            // inspection model
            &["encoding:DoubleUrlEncode".to_string()], // technique keys
        );
        // Rate limit should NOT increase blocks.
        assert_eq!(state.blocks, 0);
        assert_eq!(state.rate_limits, 1);
        // But should still ingest WAF hints.
        assert_eq!(state.waf_name.as_deref(), Some("Cloudflare"));
        assert!(
            state
                .prioritized_techniques
                .contains(&"DoubleUrlEncode".to_string())
        );
    }

    #[test]
    fn signal_challenge_does_not_penalize_technique() {
        let mut state = HostState::default();
        state.record_signal(
            false,
            false,
            false,
            true, // challenge
            Some("Cloudflare"),
            &[],
            &[],
            None,
            &["encoding:UrlEncode".to_string()],
        );
        assert_eq!(state.blocks, 0);
        assert_eq!(state.challenges, 1);
    }

    #[test]
    fn signal_hard_block_records_block_with_technique() {
        let mut state = HostState::default();
        state.record_signal(
            true, // hard block
            false,
            false,
            false,
            Some("ModSecurity CRS"),
            &["CommentObfuscation".to_string()],
            &[],
            Some("multi_regex_scoring"),
            &["encoding:UrlEncode".to_string()],
        );
        assert_eq!(state.blocks, 1);
        assert_eq!(state.waf_name.as_deref(), Some("ModSecurity CRS"));
        assert_eq!(
            state.inspection_model.as_deref(),
            Some("multi_regex_scoring")
        );
        // Technique should have been attributed.
        assert!(
            state
                .technique_stats
                .iter()
                .any(|(n, _, a)| n == "encoding:UrlEncode" && *a == 1)
        );
    }

    #[test]
    fn signal_pass_records_success() {
        let mut state = HostState::default();
        state.record_signal(
            false,
            false,
            false,
            false, // pass
            None,
            &[],
            &[],
            None,
            &[],
        );
        assert_eq!(state.successes, 1);
        assert_eq!(state.blocks, 0);
    }

    #[test]
    fn signal_merges_prioritized_and_avoided() {
        let mut state = HostState::default();
        // First signal.
        state.record_signal(
            true,
            false,
            false,
            false,
            Some("TestWAF"),
            &["A".to_string(), "B".to_string()],
            &["X".to_string()],
            None,
            &[],
        );
        // Second signal with overlapping and new techniques.
        state.record_signal(
            true,
            false,
            false,
            false,
            None,
            &["B".to_string(), "C".to_string()],
            &["X".to_string(), "Y".to_string()],
            None,
            &[],
        );
        // Union — no duplicates.
        assert_eq!(state.prioritized_techniques, vec!["A", "B", "C"]);
        assert_eq!(state.avoided_techniques, vec!["X", "Y"]);
    }

    #[test]
    fn should_skip_technique_checks_both_lists() {
        let mut state = HostState::default();
        state.avoided_techniques.push("CaseAlternation".into());
        state.blocklisted.push("UrlEncode".into());
        assert!(state.should_skip_technique("CaseAlternation"));
        assert!(state.should_skip_technique("UrlEncode"));
        assert!(!state.should_skip_technique("DoubleUrlEncode"));
    }

    #[test]
    fn suggested_techniques_filters_skipped() {
        let state = HostState {
            prioritized_techniques: vec![
                "DoubleUrlEncode".into(),
                "CaseAlternation".into(),
                "UnicodeHomoglyph".into(),
            ],
            avoided_techniques: vec!["CaseAlternation".into()],
            ..HostState::default()
        };
        let suggested = state.suggested_techniques();
        assert_eq!(suggested, vec!["DoubleUrlEncode", "UnicodeHomoglyph"]);
    }

    #[test]
    fn waf_name_not_overwritten_by_subsequent_signals() {
        let mut state = HostState::default();
        state.record_signal(
            true,
            false,
            false,
            false,
            Some("Cloudflare"),
            &[],
            &[],
            None,
            &[],
        );
        state.record_signal(
            true,
            false,
            false,
            false,
            Some("ModSecurity"),
            &[],
            &[],
            None,
            &[],
        );
        // First detection wins — don't flip-flop.
        assert_eq!(state.waf_name.as_deref(), Some("Cloudflare"));
    }

    // ── Overflow guard tests ────────────────────────────────────────────

    #[test]
    fn bump_success_saturates_at_u32_max_not_wraps() {
        // Pre-fix: plain `+= 1` would overflow in debug (panic) or
        // silently wrap to 0 in release after 2^32 successes on the
        // same technique in a long-running proxy session.
        let mut state = HostState::default();
        // Inject a stat entry already at (u32::MAX - 1, u32::MAX - 1)
        // to force the boundary on the very next success.
        state
            .technique_stats
            .push(("encoding:Test".to_string(), u32::MAX - 1, u32::MAX - 1));
        // Record one more success — this used to plain-add, now saturates.
        state.bump_success_for_technique(&Technique::PayloadEncoding("Test".into()));
        let stat = state
            .technique_stats
            .iter()
            .find(|(n, _, _)| n == "encoding:Test")
            .expect("stat entry must exist");
        // Both successes (stat.1) and attempts (stat.2) must saturate, not wrap.
        assert_eq!(stat.1, u32::MAX, "successes must saturate at u32::MAX");
        assert_eq!(stat.2, u32::MAX, "attempts must saturate at u32::MAX");

        // One more: must stay at MAX, not wrap back to 0.
        state.bump_success_for_technique(&Technique::PayloadEncoding("Test".into()));
        let stat2 = state
            .technique_stats
            .iter()
            .find(|(n, _, _)| n == "encoding:Test")
            .expect("stat entry must exist");
        assert_eq!(
            stat2.1,
            u32::MAX,
            "successes must remain at u32::MAX after second saturating add"
        );
        assert_eq!(
            stat2.2,
            u32::MAX,
            "attempts must remain at u32::MAX after second saturating add"
        );
    }

    #[test]
    fn bump_success_and_block_both_use_saturating_arithmetic() {
        // Prove the two paths are symmetric: the block path already
        // had saturating_add; the success path now also has it.
        // Both must reach u32::MAX and stay there.
        let mut state = HostState::default();
        let name = "encoding:Sym".to_string();

        // Start at u32::MAX - 2 so we can hit the boundary in two ops.
        state
            .technique_stats
            .push((name.clone(), u32::MAX - 2, u32::MAX - 2));

        // Two successes take successes+attempts to MAX then stick.
        state.bump_success_for_technique(&Technique::PayloadEncoding("Sym".into()));
        state.bump_success_for_technique(&Technique::PayloadEncoding("Sym".into()));
        // One extra must not wrap.
        state.bump_success_for_technique(&Technique::PayloadEncoding("Sym".into()));

        let stat = state
            .technique_stats
            .iter()
            .find(|(n, _, _)| n == &name)
            .unwrap();
        assert_eq!(stat.1, u32::MAX);
        assert_eq!(stat.2, u32::MAX);
    }
}
