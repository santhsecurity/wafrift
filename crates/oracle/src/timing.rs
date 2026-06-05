//! Timing oracle — confirms blind attacks via response-latency anomaly.
//!
//! When a WAF blocks the DNS callback channel (no exfil) AND squashes
//! the error oracle (every error → generic 403), the last remaining
//! confirmation channel is response latency. A payload that forces the
//! backend to wait on `pg_sleep(5)` / `WAITFOR DELAY '0:0:5'` /
//! `DBMS_PIPE.RECEIVE_MESSAGE` / `; ping -c 10 127.0.0.1` produces a
//! deterministic ~5–9 second response delay that the WAF cannot mask
//! because the bytes never reach the rule engine — the delay happens at
//! origin, after the WAF passed the request through.
//!
//! Unlike `signal_response_time.rs` (a 3x-ratio heuristic for live
//! traffic), `TimingOracle` is statistically grounded: take N
//! calibration probes (typically 5–10 benign requests), compute mean +
//! stdev, then confirm only when an observed latency exceeds
//! `mean + k * stdev` for `k = 3` by default (≈99.7% confidence).
//!
//! ```rust,ignore
//! // `timing` is pub(crate) — use TimingOracle from within the oracle crate.
//! use wafrift_oracle::timing::TimingOracle;
//!
//! // 5 benign-request latencies (ms).
//! let oracle = TimingOracle::from_calibration(&[120.0, 135.0, 128.0, 140.0, 130.0]);
//! // Normal jitter — not confirmed.
//! assert!(!oracle.is_anomalous(180.0));
//! // 9-second delay from `; ping -c 10 127.0.0.1` — confirmed.
//! assert!(oracle.is_anomalous(9_200.0));
//! ```
//!
//! # Why a statistical threshold, not a fixed ratio
//!
//! A 3x ratio threshold mis-fires on low-baseline targets: a 30 ms
//! baseline + 100 ms variance turns every cached-vs-uncached page into
//! a "timing anomaly". With `mean + 3·σ` the threshold scales with the
//! target's actual variance, so the false-positive rate stays at the
//! statistical bound regardless of baseline magnitude.

/// Default confidence multiplier for `is_anomalous`. `mean + 3·σ`
/// corresponds to a ~99.7% one-sided confidence interval under the
/// Gaussian assumption; for non-Gaussian latency distributions the
/// real false-positive rate is bounded by Chebyshev (≤ 11%), still
/// strict enough for bench use.
pub(crate) const DEFAULT_K_SIGMA: f64 = 3.0;

/// Hard floor on stdev so a degenerate calibration (all 5 probes hit
/// the same cached value) doesn't reduce the threshold to mean + 0,
/// which would mark any single jitter pulse as anomalous.
const MIN_STDEV_MS: f64 = 25.0;

/// Hard floor on baseline so a sub-millisecond baseline (loopback
/// localhost target) doesn't make any 100ms variant look anomalous.
/// R55 pass-18 I5 (CLAUDE.md §7 DEDUP): renamed from the bare
/// `MIN_BASELINE_MS` to disambiguate from
/// `signal_response_time::MIN_SIGNAL_BASELINE_MS` (which is a u64
/// 10-ms guard for the response-time signal extractor, a different
/// oracle semantic with a 5x different floor).
const MIN_TIMING_ORACLE_BASELINE_MS: f64 = 50.0;

/// A timing oracle calibrated against a known-benign baseline.
///
/// Constructed once per (target, endpoint) and queried per observed
/// response. Cheap (no I/O, two f64 comparisons per `is_anomalous`).
#[derive(Debug, Clone, Copy)]
pub struct TimingOracle {
    /// Mean response time across the calibration set, ms.
    pub baseline_ms: f64,
    /// Sample standard deviation across the calibration set, ms.
    pub stdev_ms: f64,
    /// Sigma multiplier used as the anomaly threshold.
    pub k_sigma: f64,
}

impl TimingOracle {
    /// Build an oracle from a calibration set of latencies (ms).
    ///
    /// Caller is responsible for ensuring the calibration set is
    /// representative (benign requests to the same endpoint, same
    /// session, same time of day). An empty slice yields a permissive
    /// oracle (`baseline = MIN_TIMING_ORACLE_BASELINE_MS`, `stdev = MIN_STDEV_MS`)
    /// rather than panicking — caller can still query it but should
    /// log the missing calibration.
    #[must_use]
    pub fn from_calibration(latencies_ms: &[f64]) -> Self {
        Self::from_calibration_with_k(latencies_ms, DEFAULT_K_SIGMA)
    }

    /// Same as [`from_calibration`] but with an explicit sigma
    /// multiplier — use `k=2` for a permissive oracle (~95% one-sided)
    /// or `k=4` for very strict (~99.99%).
    #[must_use]
    pub fn from_calibration_with_k(latencies_ms: &[f64], k_sigma: f64) -> Self {
        if latencies_ms.is_empty() {
            return Self {
                baseline_ms: MIN_TIMING_ORACLE_BASELINE_MS,
                stdev_ms: MIN_STDEV_MS,
                k_sigma,
            };
        }
        let n = latencies_ms.len() as f64;
        let mean = latencies_ms.iter().sum::<f64>() / n;
        // Sample stdev (Bessel-corrected n-1) when n >= 2; for n=1 we
        // can't measure variance so fall back to MIN_STDEV_MS.
        let stdev = if latencies_ms.len() >= 2 {
            let var = latencies_ms
                .iter()
                .map(|x| (*x - mean).powi(2))
                .sum::<f64>()
                / (n - 1.0);
            var.sqrt().max(MIN_STDEV_MS)
        } else {
            MIN_STDEV_MS
        };
        Self {
            baseline_ms: mean.max(MIN_TIMING_ORACLE_BASELINE_MS),
            stdev_ms: stdev,
            k_sigma,
        }
    }

    /// Threshold above which an observation is considered anomalous.
    #[must_use]
    pub fn threshold_ms(&self) -> f64 {
        self.baseline_ms + self.k_sigma * self.stdev_ms
    }

    /// True if `observed_ms` exceeds the anomaly threshold.
    ///
    /// One-sided check by design: a faster-than-baseline response
    /// (cache hit) is NOT confirmation of an attack — only a slower
    /// response can confirm a `WAITFOR` / `pg_sleep` / `; ping -c 10`
    /// fired at the backend.
    #[must_use]
    pub fn is_anomalous(&self, observed_ms: f64) -> bool {
        observed_ms > self.threshold_ms()
    }

    /// Update the oracle in-place with a new calibration sample.
    ///
    /// Uses Welford's algorithm so accumulating thousands of probes
    /// over a long campaign stays numerically stable. Mutates only
    /// the running mean and variance; caller decides when to seal the
    /// oracle and start using it for confirmation.
    pub fn observe_calibration(&mut self, sample_ms: f64, prior_count: usize) {
        // Welford incremental update. `prior_count` is the number of
        // samples already absorbed (so the caller tracks it — keeps
        // TimingOracle a value type, no interior mutability).
        let n = (prior_count as f64) + 1.0;
        let delta = sample_ms - self.baseline_ms;
        let new_mean = self.baseline_ms + delta / n;
        let delta2 = sample_ms - new_mean;
        // Recover sum-of-squared-deviations from current stdev, add
        // the new term, re-derive stdev. `n - 1` Bessel correction is
        // applied on the way out, so on the way in we have to undo it.
        let prior_m2 = self.stdev_ms.powi(2) * (prior_count as f64).max(1.0);
        let new_m2 = prior_m2 + delta * delta2;
        self.baseline_ms = new_mean.max(MIN_TIMING_ORACLE_BASELINE_MS);
        self.stdev_ms = if n >= 2.0 {
            (new_m2 / (n - 1.0)).sqrt().max(MIN_STDEV_MS)
        } else {
            MIN_STDEV_MS
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_calibration_yields_permissive_floor_oracle() {
        let o = TimingOracle::from_calibration(&[]);
        // Floors apply, oracle is queryable without panic.
        assert!((o.baseline_ms - MIN_TIMING_ORACLE_BASELINE_MS).abs() < 1e-9);
        assert!((o.stdev_ms - MIN_STDEV_MS).abs() < 1e-9);
        // A 5-second delay still triggers anomaly even on a permissive
        // oracle — caller can use the oracle even pre-calibration.
        assert!(o.is_anomalous(5_000.0));
    }

    #[test]
    fn calibration_mean_and_stdev_compute_correctly() {
        let o = TimingOracle::from_calibration(&[100.0, 120.0, 140.0, 110.0, 130.0]);
        // Mean: (100+120+140+110+130)/5 = 120.
        assert!((o.baseline_ms - 120.0).abs() < 1e-9);
        // Sample stdev: sqrt(sum((x-mean)^2)/(n-1))
        // = sqrt((400+0+400+100+100)/4) = sqrt(250) ≈ 15.81
        // MIN_STDEV_MS = 25 enforces a floor — actual stdev (15.81)
        // is below floor, so we expect stdev = 25.
        assert!((o.stdev_ms - MIN_STDEV_MS).abs() < 1e-9);
    }

    #[test]
    fn benign_jitter_below_threshold_not_anomalous() {
        let o = TimingOracle::from_calibration(&[100.0, 120.0, 140.0, 110.0, 130.0]);
        // mean=120, k=3, stdev=25 → threshold = 195.
        assert!(!o.is_anomalous(180.0));
        assert!(!o.is_anomalous(195.0));
    }

    #[test]
    fn long_ping_delay_confirmed_anomalous() {
        let o = TimingOracle::from_calibration(&[100.0, 120.0, 140.0, 110.0, 130.0]);
        // 9-second `ping -c 10` blows past threshold (195 ms).
        assert!(o.is_anomalous(9_200.0));
    }

    #[test]
    fn pg_sleep_5_confirmed_anomalous() {
        let o = TimingOracle::from_calibration(&[200.0, 210.0, 220.0, 215.0]);
        // 5s pg_sleep — easily exceeds mean + 3σ.
        assert!(o.is_anomalous(5_200.0));
    }

    #[test]
    fn one_sided_no_anomaly_on_fast_response() {
        let o = TimingOracle::from_calibration(&[500.0, 550.0, 520.0, 540.0]);
        // Cache hit at 50 ms is faster than baseline — NOT a positive
        // confirmation of `pg_sleep` (the oracle is one-sided).
        assert!(!o.is_anomalous(50.0));
    }

    #[test]
    fn incremental_observe_matches_batch() {
        let mut incremental = TimingOracle::from_calibration(&[100.0]);
        let samples = [120.0, 140.0, 110.0, 130.0];
        for (i, s) in samples.iter().enumerate() {
            // i+1 because we started with 1 sample.
            incremental.observe_calibration(*s, i + 1);
        }
        let batch = TimingOracle::from_calibration(&[100.0, 120.0, 140.0, 110.0, 130.0]);
        // Mean should match within floating-point tolerance.
        assert!((incremental.baseline_ms - batch.baseline_ms).abs() < 0.001);
    }

    #[test]
    fn degenerate_zero_variance_calibration_uses_stdev_floor() {
        let o = TimingOracle::from_calibration(&[100.0, 100.0, 100.0, 100.0]);
        // Real stdev is 0 — floor must apply, otherwise any > 100 ms
        // would be "anomalous" and false-positive every probe.
        assert!(o.stdev_ms >= MIN_STDEV_MS);
        assert!(!o.is_anomalous(120.0));
    }

    #[test]
    fn k_sigma_4_is_stricter_than_default() {
        let lenient = TimingOracle::from_calibration_with_k(&[100.0, 120.0, 140.0, 110.0, 130.0], 2.0);
        let strict = TimingOracle::from_calibration_with_k(&[100.0, 120.0, 140.0, 110.0, 130.0], 4.0);
        // k=2 threshold < k=4 threshold for the same calibration.
        assert!(lenient.threshold_ms() < strict.threshold_ms());
        // A 200 ms response: anomalous under k=2 (threshold 170 ms),
        // not anomalous under k=4 (threshold 220 ms).
        assert!(lenient.is_anomalous(200.0));
        assert!(!strict.is_anomalous(200.0));
    }

    // -- §12 boundary tests -------------------------------------------------

    #[test]
    fn exact_threshold_is_not_anomalous() {
        // The oracle uses `actual > threshold` (strict), not `>=`.
        // A response at exactly the threshold must NOT fire — that is the
        // boundary invariant. One millisecond above it must fire.
        let o = TimingOracle::from_calibration(&[100.0, 120.0, 140.0, 110.0, 130.0]);
        let thresh = o.threshold_ms();
        assert!(
            !o.is_anomalous(thresh),
            "exactly at threshold ({thresh} ms) must not be anomalous (strict >, not >=)"
        );
        assert!(
            o.is_anomalous(thresh + 0.001),
            "one tick past threshold ({:.3} ms) must be anomalous",
            thresh + 0.001
        );
    }

    #[test]
    fn single_sample_calibration_does_not_panic() {
        // With n=1 the sample stdev is undefined (division by 0); the floor
        // MIN_STDEV_MS = 25ms applies and the oracle must remain queryable.
        // baseline=500, stdev=25 (floor), threshold = 500 + 3*25 = 575ms.
        let o = TimingOracle::from_calibration(&[500.0]);
        assert_eq!(o.stdev_ms, MIN_STDEV_MS, "single-sample stdev must be the floor");
        // 500ms (baseline itself) must not be anomalous.
        assert!(!o.is_anomalous(500.0), "baseline response must not be anomalous");
        // A big delay still fires.
        assert!(o.is_anomalous(10_000.0), "10s delay must trigger even on single-sample cal");
    }

    #[test]
    fn min_timing_oracle_baseline_ms_floor_applies() {
        // If calibration samples are very small (sub-1ms), the baseline
        // must be clamped to at least MIN_TIMING_ORACLE_BASELINE_MS so
        // the threshold is reasonable, not 0.
        let o = TimingOracle::from_calibration(&[0.1, 0.2, 0.3, 0.15, 0.25]);
        assert!(
            o.baseline_ms >= MIN_TIMING_ORACLE_BASELINE_MS,
            "baseline must never fall below the floor: got {}",
            o.baseline_ms
        );
    }

    #[test]
    fn threshold_monotonically_increases_with_k() {
        let samples = &[200.0, 210.0, 220.0, 190.0, 205.0];
        let t2 = TimingOracle::from_calibration_with_k(samples, 2.0).threshold_ms();
        let t3 = TimingOracle::from_calibration_with_k(samples, 3.0).threshold_ms();
        let t4 = TimingOracle::from_calibration_with_k(samples, 4.0).threshold_ms();
        assert!(t2 < t3, "k=2 threshold must be less than k=3");
        assert!(t3 < t4, "k=3 threshold must be less than k=4");
    }
}
