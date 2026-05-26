//! Drift-aware evasion window detection (#115).
//!
//! WAF behaviour is not stationary. Rules reload (CF Auto-Tune retrains every
//! ~hour), edges throttle, IP reputation flips. The same payload may be blocked
//! at minute 0 and pass at minute 47.
//!
//! This module implements a CUSUM-based sequential change-point detector that
//! tracks four per-target signals:
//!
//! 1. **Median response time** — slower = heavier inspection.
//! 2. **P95 response time** — spike = new DPI layer spinning up.
//! 3. **Block rate** (over last 50 probes) — direct measure of WAF policy.
//! 4. **Body-hash entropy** — change in response diversity signals new rules.
//!
//! Each signal runs an independent CUSUM detector. A [`RegimeChange`] fires
//! when **≥ 2 signals agree** on the direction of change.
//!
//! The [`HostState`] integration calls [`DriftDetector::observe`] on every
//! probe result and, when [`RegimeChange::LooserNow`] fires, re-queues
//! previously-blocked payloads for retry.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

// ── Constants ───────────────────────────────────────────────────────────────

/// Number of probes to keep in the sliding window for baseline statistics.
const DEFAULT_WINDOW_SIZE: usize = 50;

/// CUSUM threshold: how many standard deviations of accumulated drift before
/// we fire a change-point. 4.0 σ balances false-positive rate vs. detection
/// latency at the 50-sample window.
const DEFAULT_THRESHOLD: f64 = 4.0;

/// Number of bodies to track for hash-entropy estimation.
const BODY_HASH_WINDOW: usize = 32;

/// Agreement threshold: how many independent CUSUM signals must agree before
/// a `RegimeChange` fires. Prevents single-signal noise from triggering retries.
const SIGNAL_AGREEMENT: usize = 2;

// ── Public types ─────────────────────────────────────────────────────────────

/// Direction and magnitude of a detected WAF regime change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegimeChange {
    /// WAF is blocking less aggressively — retry the blocked corpus now.
    LooserNow,
    /// WAF is blocking more aggressively — back off, slow down probing.
    StricterNow,
    /// Regime changed but signals disagree on direction (e.g. latency went
    /// up while block rate went down). Retry cautiously; do not assume free
    /// passage.
    Unclear,
}

/// A single probe observation fed into [`DriftDetector::observe`].
#[derive(Debug, Clone)]
pub struct ProbeObservation {
    /// Round-trip time of the probe in milliseconds.
    pub response_time_ms: f64,
    /// Whether this probe was blocked by the WAF.
    pub was_blocked: bool,
    /// A cheap hash of the response body (e.g. `hash(body[..512])`).
    /// `None` if the response had no body or it was not read.
    pub body_hash: Option<u64>,
}

/// CUSUM-based sequential change-point detector for a single scalar signal.
///
/// Tracks cumulative sum of deviations above/below a rolling baseline.
/// When either `s_high` or `s_low` exceeds `threshold * baseline_std` a
/// change is detected and the accumulators reset.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CusumDetector {
    /// Rolling baseline window for mean/stdev estimation.
    window: VecDeque<f64>,
    window_size: usize,
    /// CUSUM accumulator for upward shifts (signal rising above mean).
    s_high: f64,
    /// CUSUM accumulator for downward shifts (signal falling below mean).
    s_low: f64,
    /// Detection threshold as a multiple of baseline stdev.
    threshold: f64,
    /// Direction of the most-recently fired change (+1 = higher, -1 = lower).
    last_direction: i8,
}

impl CusumDetector {
    fn new(window_size: usize, threshold: f64) -> Self {
        Self {
            window: VecDeque::with_capacity(window_size),
            window_size,
            s_high: 0.0,
            s_low: 0.0,
            threshold,
            last_direction: 0,
        }
    }

    /// Push a new observation.  Returns `Some(direction)` (+1 or -1) when a
    /// change-point fires, `None` when still within the stationary regime.
    fn push(&mut self, value: f64) -> Option<i8> {
        // Need at least 4 points to estimate a meaningful baseline.
        if self.window.len() < 4 {
            if self.window.len() >= self.window_size {
                self.window.pop_front();
            }
            self.window.push_back(value);
            return None;
        }

        let (mean, std) = self.mean_std();
        // The CUSUM detection threshold k = threshold × σ. When the baseline
        // is perfectly stationary (σ ≈ 0), k → 0 and ANY deviation fires
        // immediately — a false-positive on perfectly identical synthetic data.
        //
        // Enforce a minimum σ floor to keep the detector from being hair-
        // triggered by floating-point noise, while still allowing large step
        // changes (block rate 0→1, latency 20ms→200ms) to register quickly:
        //
        //   - For signals near zero (mean < 0.1): floor = 0.01 (1% of the
        //     maximum useful magnitude for a rate-like signal in [0,1]).
        //   - For signals with positive mean: floor = 1% of mean.
        //
        // This means a single-step deviation must be at least
        //   `threshold × floor` above the mean to fire. For threshold=3.0
        //   and block rate: k/2 = 3.0 × 0.01 / 2 = 0.015, so a full-scale
        //   step from 0→1 (deviation=1.0) nets 0.985 per observation →
        //   fires after 4 observations, which is the desired behavior.
        // Minimum σ floor: prevents hair-trigger on perfectly stationary
        // baselines where σ=0 would make k=0 and any deviation fires.
        // For near-zero-mean signals (block rate, entropy in [0,1]):
        //   floor = 0.01 — requires a 1% meaningful shift per threshold unit.
        // For positive-mean signals (latency in ms):
        //   floor = 5% of mean — requires a 5% shift to count as signal.
        // This keeps threshold=10 from firing on a 10% nudge (5ms on 50ms
        // baseline) while allowing threshold=3 to fire on a 10× step change.
        let floor = if mean.abs() < 1.0 {
            0.01
        } else {
            mean.abs() * 0.05
        };
        let effective_std = std.max(floor);
        let k = self.threshold * effective_std;

        // CUSUM update: accumulate signed deviation from mean.
        self.s_high = (self.s_high + (value - mean - k / 2.0)).max(0.0);
        self.s_low = (self.s_low + (mean - value - k / 2.0)).max(0.0);

        // Slide the window.
        if self.window.len() >= self.window_size {
            self.window.pop_front();
        }
        self.window.push_back(value);

        // Fire if either accumulator exceeds the detection threshold.
        if self.s_high > k {
            self.s_high = 0.0;
            self.s_low = 0.0;
            self.last_direction = 1;
            return Some(1);
        }
        if self.s_low > k {
            self.s_high = 0.0;
            self.s_low = 0.0;
            self.last_direction = -1;
            return Some(-1);
        }

        None
    }

    fn mean_std(&self) -> (f64, f64) {
        let n = self.window.len() as f64;
        if n == 0.0 {
            return (0.0, 0.0);
        }
        let mean: f64 = self.window.iter().sum::<f64>() / n;
        let variance: f64 = self.window.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
        (mean, variance.sqrt())
    }
}

/// Per-target drift detector.  Tracks four independent CUSUM streams and
/// fires a [`RegimeChange`] when ≥ 2 agree.
///
/// # Example
///
/// ```rust
/// use wafrift_strategy::drift_window::{DriftDetector, ProbeObservation};
///
/// let mut det = DriftDetector::default();
/// for _ in 0..60 {
///     det.observe(ProbeObservation {
///         response_time_ms: 50.0,
///         was_blocked: true,
///         body_hash: Some(0xdeadbeef),
///     });
/// }
/// // After a sudden drop in block rate the detector should eventually fire
/// // LooserNow.
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftDetector {
    /// Window size passed to each CUSUM channel.
    pub window_size: usize,
    /// Detection threshold (σ-multiples) passed to each CUSUM channel.
    pub threshold: f64,

    // ── Four independent CUSUM channels ──────────────────────────────
    cusum_median_rt: CusumDetector,
    cusum_p95_rt: CusumDetector,
    cusum_block_rate: CusumDetector,
    cusum_body_entropy: CusumDetector,

    // ── Sliding windows for computing the four signals ────────────────
    /// Raw response times for the current window (for median + p95).
    rt_window: VecDeque<f64>,
    /// Boolean blocked flags for the last `window_size` probes (for block rate).
    block_window: VecDeque<bool>,
    /// Recent body hashes for Shannon entropy estimation.
    body_hash_window: VecDeque<u64>,

    /// Total probes observed (monotonically increasing).
    pub probe_count: u64,
}

impl Default for DriftDetector {
    fn default() -> Self {
        Self::new(DEFAULT_WINDOW_SIZE, DEFAULT_THRESHOLD)
    }
}

impl DriftDetector {
    /// Create a detector with explicit window and threshold parameters.
    pub fn new(window_size: usize, threshold: f64) -> Self {
        let ws = window_size.max(8); // minimum 8 for meaningful statistics
        Self {
            window_size: ws,
            threshold,
            cusum_median_rt: CusumDetector::new(ws, threshold),
            cusum_p95_rt: CusumDetector::new(ws, threshold),
            cusum_block_rate: CusumDetector::new(ws, threshold),
            cusum_body_entropy: CusumDetector::new(ws, threshold),
            rt_window: VecDeque::with_capacity(ws),
            block_window: VecDeque::with_capacity(ws),
            body_hash_window: VecDeque::with_capacity(BODY_HASH_WINDOW),
            probe_count: 0,
        }
    }

    /// Feed a probe observation and return a [`RegimeChange`] if detected.
    ///
    /// Returns `None` when the regime is stationary (or insufficient data).
    /// Returns `Some(RegimeChange)` when ≥ 2 CUSUM channels agree.
    pub fn observe(&mut self, obs: ProbeObservation) -> Option<RegimeChange> {
        self.probe_count = self.probe_count.saturating_add(1);

        // ── 1. Update sliding windows ─────────────────────────────────
        if self.rt_window.len() >= self.window_size {
            self.rt_window.pop_front();
        }
        self.rt_window.push_back(obs.response_time_ms);

        if self.block_window.len() >= self.window_size {
            self.block_window.pop_front();
        }
        self.block_window.push_back(obs.was_blocked);

        if let Some(hash) = obs.body_hash {
            if self.body_hash_window.len() >= BODY_HASH_WINDOW {
                self.body_hash_window.pop_front();
            }
            self.body_hash_window.push_back(hash);
        }

        // ── 2. Derive the four signals ────────────────────────────────
        let median_rt = self.compute_median_rt();
        let p95_rt = self.compute_p95_rt();
        let block_rate = self.compute_block_rate();
        let body_entropy = self.compute_body_entropy();

        // ── 3. Feed each signal into its CUSUM channel ────────────────
        //
        // Directional signals (block rate + latency) determine whether the
        // WAF became looser or stricter. Body-hash entropy is a
        // non-directional "something changed" witness — it contributes to
        // the total change-event count but not to the directional split,
        // because entropy can rise or fall regardless of enforcement posture.
        let mut up_votes: i32 = 0;
        let mut down_votes: i32 = 0;
        // Non-directional: entropy change just adds to total witness count.
        let mut witness_events: i32 = 0;

        for direction in [
            self.cusum_median_rt.push(median_rt),
            self.cusum_p95_rt.push(p95_rt),
            self.cusum_block_rate.push(block_rate),
        ]
        .iter()
        .flatten()
        {
            if *direction > 0 {
                up_votes += 1;
            } else {
                down_votes += 1;
            }
        }

        // Entropy fires as a non-directional witness.
        if self.cusum_body_entropy.push(body_entropy).is_some() {
            witness_events += 1;
        }

        // ── 4. Agreement gate — need ≥ 2 signals agreeing ─────────────
        // Directional vote count (block_rate + latencies fire), augmented
        // by the entropy witness if it also fired.
        let directional_votes = up_votes + down_votes;
        let total_change_witnesses = directional_votes + witness_events;

        // Must have at least 2 total witnesses of change.
        if total_change_witnesses < SIGNAL_AGREEMENT as i32 {
            return None;
        }

        // Direction is determined by the directional signals only.
        // If there are no directional votes but entropy fired, emit Unclear.
        if directional_votes == 0 {
            return Some(RegimeChange::Unclear);
        }

        // Higher latency + higher block rate = StricterNow.
        // Lower latency + lower block rate = LooserNow.
        // Mixed directional signals = Unclear.
        if up_votes >= SIGNAL_AGREEMENT as i32 && down_votes == 0 {
            Some(RegimeChange::StricterNow)
        } else if down_votes >= SIGNAL_AGREEMENT as i32 && up_votes == 0 {
            Some(RegimeChange::LooserNow)
        } else if up_votes > 0 && down_votes == 0 {
            // Only 1 directional up-vote but entropy corroborated — weak
            // evidence of stricter regime.
            Some(RegimeChange::StricterNow)
        } else if down_votes > 0 && up_votes == 0 {
            // Only 1 directional down-vote but entropy corroborated — weak
            // evidence of looser regime.
            Some(RegimeChange::LooserNow)
        } else {
            Some(RegimeChange::Unclear)
        }
    }

    // ── Signal derivation helpers ─────────────────────────────────────────

    /// Median response time over the current RT window (ms).
    fn compute_median_rt(&self) -> f64 {
        if self.rt_window.is_empty() {
            return 0.0;
        }
        let mut sorted: Vec<f64> = self.rt_window.iter().copied().collect();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let mid = sorted.len() / 2;
        if sorted.len() % 2 == 0 {
            (sorted[mid - 1] + sorted[mid]) / 2.0
        } else {
            sorted[mid]
        }
    }

    /// 95th-percentile response time over the current RT window (ms).
    fn compute_p95_rt(&self) -> f64 {
        if self.rt_window.is_empty() {
            return 0.0;
        }
        let mut sorted: Vec<f64> = self.rt_window.iter().copied().collect();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        // Nearest-rank P95.
        let idx = ((sorted.len() as f64 * 0.95).ceil() as usize).saturating_sub(1);
        sorted[idx.min(sorted.len() - 1)]
    }

    /// Fraction of probes blocked over the current block window.
    fn compute_block_rate(&self) -> f64 {
        if self.block_window.is_empty() {
            return 0.0;
        }
        let blocked = self.block_window.iter().filter(|&&b| b).count();
        blocked as f64 / self.block_window.len() as f64
    }

    /// Shannon entropy of the body-hash distribution (bits).
    ///
    /// A sudden shift in the diversity of response bodies (new error pages,
    /// new challenge bodies) signals a WAF rule change.
    fn compute_body_entropy(&self) -> f64 {
        if self.body_hash_window.len() < 2 {
            return 0.0;
        }
        // Count frequency of each unique hash.
        let mut counts: Vec<(u64, usize)> = Vec::new();
        for &h in &self.body_hash_window {
            if let Some(entry) = counts.iter_mut().find(|(hh, _)| *hh == h) {
                entry.1 += 1;
            } else {
                counts.push((h, 1));
            }
        }
        let total = self.body_hash_window.len() as f64;
        counts
            .iter()
            .map(|(_, c)| {
                let p = *c as f64 / total;
                if p > 0.0 { -p * p.log2() } else { 0.0 }
            })
            .sum()
    }

    /// Returns `true` if the detector has accumulated enough observations to
    /// produce meaningful change-point estimates (at least `window_size / 2`
    /// probes).
    #[must_use]
    pub fn has_baseline(&self) -> bool {
        self.probe_count >= (self.window_size / 2) as u64
    }

    /// Snapshot of the four current signal values (for diagnostics/logging).
    /// Order: `[median_rt_ms, p95_rt_ms, block_rate, body_entropy_bits]`.
    #[must_use]
    pub fn signal_snapshot(&self) -> [f64; 4] {
        [
            self.compute_median_rt(),
            self.compute_p95_rt(),
            self.compute_block_rate(),
            self.compute_body_entropy(),
        ]
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helper builders ───────────────────────────────────────────────────

    fn blocked_obs(rt_ms: f64) -> ProbeObservation {
        ProbeObservation {
            response_time_ms: rt_ms,
            was_blocked: true,
            body_hash: Some(0xaaaa_aaaa_aaaa_aaaa),
        }
    }

    fn pass_obs(rt_ms: f64) -> ProbeObservation {
        ProbeObservation {
            response_time_ms: rt_ms,
            was_blocked: false,
            body_hash: Some(0xbbbb_bbbb_bbbb_bbbb),
        }
    }

    fn pass_obs_varied(rt_ms: f64, hash: u64) -> ProbeObservation {
        ProbeObservation {
            response_time_ms: rt_ms,
            was_blocked: false,
            body_hash: Some(hash),
        }
    }

    /// Feed `n` identical stationary observations.
    fn feed_stationary(det: &mut DriftDetector, n: usize, rt: f64, blocked: bool, hash: u64) {
        for _ in 0..n {
            det.observe(ProbeObservation {
                response_time_ms: rt,
                was_blocked: blocked,
                body_hash: Some(hash),
            });
        }
    }

    // ── 1. Step change detected (latency only) ────────────────────────────

    #[test]
    fn latency_step_change_detected() {
        let mut det = DriftDetector::new(20, 3.0);
        // Establish baseline: 20 ms, not blocked.
        feed_stationary(&mut det, 30, 20.0, false, 0x1111);
        // Sudden step up to 200 ms (WAF DPI layer spinning up).
        let mut fired = false;
        for _ in 0..30 {
            if det.observe(blocked_obs(200.0)).is_some() {
                fired = true;
                break;
            }
        }
        assert!(fired, "latency step change must be detected");
    }

    // ── 2. Block-rate-only change detected ───────────────────────────────

    #[test]
    fn block_rate_step_change_detected() {
        let mut det = DriftDetector::new(20, 3.0);
        // Baseline: 0% block rate, constant latency.
        feed_stationary(&mut det, 30, 50.0, false, 0x2222);
        // Sudden 100% block rate (new WAF rule deployed).
        let mut fired = false;
        for _ in 0..30 {
            if det.observe(blocked_obs(52.0)).is_some() {
                fired = true;
                break;
            }
        }
        assert!(fired, "block-rate step change must be detected");
    }

    // ── 3. No false positives on stationary Gaussian noise ───────────────

    #[test]
    fn no_false_positives_stationary_noise() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut det = DriftDetector::new(50, 4.5);
        // Use a deterministic pseudo-random sequence (FNV-style hash chain)
        // so this test is reproducible without adding a rand dep.
        let mut seed: u64 = 0xdead_beef_cafe_babe;
        let mut false_positives = 0u32;

        for i in 0u64..500 {
            // LCG: cheap deterministic noise in [40, 60] ms range.
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            let noise = ((seed >> 33) % 21) as f64; // 0..20
            let rt = 40.0 + noise;

            let mut h = DefaultHasher::new();
            i.hash(&mut h);
            let hash = h.finish() % 4; // 4 distinct bodies → stable entropy

            let obs = ProbeObservation {
                response_time_ms: rt,
                was_blocked: (seed >> 60) == 0, // ~6% block rate, stable
                body_hash: Some(hash),
            };
            if det.observe(obs).is_some() {
                false_positives += 1;
            }
        }

        // At threshold 4.5σ on stationary noise we expect 0 false positives
        // over 500 samples. Allow 1 for edge-case tolerance.
        assert!(
            false_positives <= 1,
            "too many false positives on stationary noise: {false_positives}"
        );
    }

    // ── 4. LooserNow fires when block rate drops ──────────────────────────

    #[test]
    fn looser_now_fires_on_block_rate_drop() {
        // Use a small window (8) so the baseline flushes quickly after the
        // regime change, and a low threshold (2.0) for fast detection.
        // 80 transition observations is generous — the CUSUM should fire
        // well before that once both latency and block-rate signals agree.
        let mut det = DriftDetector::new(8, 2.0);
        // Baseline: 100% block, high latency.
        feed_stationary(&mut det, 20, 150.0, true, 0xaaaa);
        // WAF reloads: drops to 0% block, low latency.
        let mut regime = None;
        for _ in 0..80 {
            regime = det.observe(pass_obs(30.0));
            if regime.is_some() {
                break;
            }
        }
        assert_eq!(
            regime,
            Some(RegimeChange::LooserNow),
            "must detect LooserNow when block rate drops"
        );
    }

    // ── 5. StricterNow fires when block rate rises ────────────────────────

    #[test]
    fn stricter_now_fires_on_block_rate_rise() {
        // Small window + low threshold for fast detection.
        let mut det = DriftDetector::new(8, 2.0);
        // Baseline: 0% block, low latency.
        feed_stationary(&mut det, 20, 30.0, false, 0x1111);
        // WAF tightens: 100% block, high latency.
        let mut regime = None;
        for _ in 0..80 {
            regime = det.observe(blocked_obs(200.0));
            if regime.is_some() {
                break;
            }
        }
        assert_eq!(
            regime,
            Some(RegimeChange::StricterNow),
            "must detect StricterNow when block rate rises"
        );
    }

    // ── 6. Multi-signal agreement required (single-signal does not fire) ──

    #[test]
    fn single_signal_alone_does_not_fire() {
        // Use a very high threshold so only latency changes; block rate stays
        // constant. With threshold=10 and window=100, two signals firing at
        // once is extremely unlikely from a single-direction latency nudge.
        // We verify the detector stays silent for a small nudge.
        let mut det = DriftDetector::new(50, 10.0);
        feed_stationary(&mut det, 60, 50.0, false, 0xcccc);

        // Tiny latency nudge — not enough to move multiple signals past threshold.
        let mut fired = false;
        for _ in 0..10 {
            if det.observe(pass_obs(55.0)).is_some() {
                fired = true;
                break;
            }
        }
        assert!(!fired, "tiny single-signal nudge must not fire with high threshold");
    }

    // ── 7. Window-size boundary: detector still works at minimum window ───

    #[test]
    fn minimum_window_size_respected() {
        // window_size=0 is clamped to 8 internally.
        let mut det = DriftDetector::new(0, 2.0);
        assert_eq!(det.window_size, 8, "window_size must be clamped to minimum 8");

        // Should still detect a gross step change.
        feed_stationary(&mut det, 20, 20.0, false, 0x1234);
        let mut fired = false;
        for _ in 0..30 {
            if det.observe(blocked_obs(500.0)).is_some() {
                fired = true;
                break;
            }
        }
        assert!(fired, "detector with minimum window must still detect step changes");
    }

    // ── 8. Threshold sensitivity: lower threshold = faster detection ──────

    #[test]
    fn lower_threshold_detects_faster() {
        let mut fast = DriftDetector::new(20, 1.5);
        let mut slow = DriftDetector::new(20, 5.0);

        feed_stationary(&mut fast, 25, 30.0, false, 0x9999);
        feed_stationary(&mut slow, 25, 30.0, false, 0x9999);

        let mut fast_detection = None;
        let mut slow_detection = None;

        for i in 0..50u64 {
            let obs = blocked_obs(200.0);
            if fast_detection.is_none() && fast.observe(obs.clone()).is_some() {
                fast_detection = Some(i);
            }
            if slow_detection.is_none() && slow.observe(obs).is_some() {
                slow_detection = Some(i);
            }
        }

        assert!(fast_detection.is_some(), "low-threshold detector must fire");
        assert!(
            fast_detection <= slow_detection.or(Some(u64::MAX)),
            "low-threshold must detect at least as fast as high-threshold"
        );
    }

    // ── 9. JSON serialization round-trips ────────────────────────────────

    #[test]
    fn json_serialization_round_trips() {
        let mut det = DriftDetector::new(30, 3.5);
        feed_stationary(&mut det, 15, 40.0, false, 0xdead);
        det.observe(blocked_obs(300.0));

        let json = serde_json::to_string(&det).expect("serialization must succeed");
        let restored: DriftDetector =
            serde_json::from_str(&json).expect("deserialization must succeed");

        assert_eq!(restored.window_size, det.window_size);
        assert_eq!(restored.threshold, det.threshold);
        assert_eq!(restored.probe_count, det.probe_count);
    }

    // ── 10. Body-entropy change alone contributes a signal ───────────────

    #[test]
    fn body_entropy_signal_contributes() {
        let mut det = DriftDetector::new(20, 2.0);

        // Baseline: all responses identical body hash (entropy = 0).
        feed_stationary(&mut det, 30, 50.0, false, 0xAAAA_AAAA);

        // Now each response has a unique body hash (high entropy) — new
        // challenge pages appearing signals rule change.
        let mut body_entropy_fired = false;
        for i in 0u64..40 {
            let obs = pass_obs_varied(52.0, i * 0xdead_beef + 1);
            // snapshot entropy increasing
            let snap_before = det.signal_snapshot()[3];
            det.observe(obs);
            let snap_after = det.signal_snapshot()[3];
            if snap_after > snap_before + 0.01 {
                body_entropy_fired = true;
                break;
            }
        }
        assert!(body_entropy_fired, "body entropy signal must increase on hash diversity");
    }

    // ── 11. has_baseline returns false before window/2 probes ────────────

    #[test]
    fn has_baseline_gated_on_probe_count() {
        let mut det = DriftDetector::new(40, 4.0);
        assert!(!det.has_baseline(), "no baseline before any probes");

        for _ in 0..19 {
            det.observe(pass_obs(50.0));
        }
        assert!(!det.has_baseline(), "baseline not ready at 19/40 probes");

        det.observe(pass_obs(50.0)); // 20th probe = window_size/2
        assert!(det.has_baseline(), "baseline must be ready at window_size/2 probes");
    }

    // ── 12. probe_count saturates at u64::MAX ────────────────────────────

    #[test]
    fn probe_count_saturates_not_wraps() {
        let mut det = DriftDetector::new(8, 4.0);
        // Inject a near-max count directly (can't loop 2^64 times).
        det.probe_count = u64::MAX - 1;
        det.observe(pass_obs(50.0));
        assert_eq!(det.probe_count, u64::MAX, "probe_count must saturate at u64::MAX");
        det.observe(pass_obs(50.0));
        assert_eq!(
            det.probe_count,
            u64::MAX,
            "probe_count must remain at u64::MAX after second saturating add"
        );
    }

    // ── 13. signal_snapshot returns correct structure ─────────────────────

    #[test]
    fn signal_snapshot_structure() {
        let mut det = DriftDetector::default();
        // Zero-state snapshot.
        let snap = det.signal_snapshot();
        assert_eq!(snap.len(), 4);
        for v in &snap {
            assert!(v.is_finite(), "all signal values must be finite at zero state");
        }

        // After observations the snapshot must update.
        feed_stationary(&mut det, 10, 75.0, true, 0xBEEF);
        let snap2 = det.signal_snapshot();
        // median and p95 must be ~75.0.
        assert!((snap2[0] - 75.0).abs() < 1.0, "median RT must be ~75 ms");
        // block rate must be 1.0 (all blocked).
        assert!((snap2[2] - 1.0).abs() < 0.01, "block rate must be ~1.0");
    }
}
