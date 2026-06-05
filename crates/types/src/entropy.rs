//! Information-theoretic primitives shared across the workspace.
//!
//! Pre-extract, `bench_waf::classify_case_quality` computed its own
//! binary Shannon entropy inline. The info-gain payload scheduler
//! (`cli::info_gain_sched`) needs the same primitive. Two definitions
//! would drift the moment one tunes the endpoint convention (`0 * log 0
//! == 0`, `log2(0) == -inf` in IEEE 754) without the other matching.
//! R69 §7 DEDUP lifts entropy here as the single canonical source.
//!
//! ## Why not pull in `statrs` or `info-theory`
//!
//! `wafrift-types` is leaf-level. Adding a stats crate to satisfy one
//! ten-line function (which has a well-defined closed form) would pay
//! a perpetual compile-time cost for nothing. The function is pure,
//! const-friendly, and trivially tested.

/// General Shannon entropy over a discrete distribution `probs`, in
/// bits. `H(p_1, …, p_n) = -Σ p_i · log2(p_i)`, with the convention
/// `0 · log 0 = 0` (the mathematical limit).
///
/// `probs` need NOT sum to 1 — the function is defensive against
/// caller drift. Outcomes with `p ≤ 0` or non-finite values are
/// skipped. The maximum over a normalised distribution is `log2(n)`
/// for the uniform.
///
/// ```
/// use wafrift_types::entropy::shannon;
/// assert_eq!(shannon(&[1.0, 0.0, 0.0]), 0.0);
/// assert!((shannon(&[0.25, 0.25, 0.25, 0.25]) - 2.0).abs() < 1e-9);
/// ```
///
/// Use [`binary_shannon`] for the binary case — it is mathematically
/// equivalent to `shannon(&[p, 1.0 - p])` but a few percent faster
/// in the hot path (no allocation, no iterator overhead).
#[must_use]
pub fn shannon(probs: &[f64]) -> f64 {
    if probs.len() < 2 {
        return 0.0;
    }
    let mut h = 0.0;
    for &p in probs {
        // Only count probabilities in the proper unit interval. For
        // a normalised distribution every p satisfies this; non-
        // normalised inputs (caller drift) silently skip out-of-range
        // components rather than emit incoherent negative entropy.
        // Without the upper bound, p > 1.0 produces `-p · log2(p) < 0`
        // (log2 of >1 is positive), which would surface as negative
        // bits — a NaN-in-disguise that poisons any sort key it
        // touches.
        if p > 0.0 && p <= 1.0 && p.is_finite() {
            h -= p * p.log2();
        }
    }
    // Final clamp: a perfectly-normalised input can still hit
    // `-0.0` here (e.g. shannon(&[1.0, 0.0]) loop body never runs
    // for the second component, h stays 0.0 then negated → -0.0).
    // Map both to +0.0 so downstream sort keys see a stable
    // canonical zero. `h.max(0.0)` also handles f64 drift toward
    // tiny negative values from accumulated rounding error.
    if h.is_finite() { h.max(0.0) } else { 0.0 }
}

/// Binary Shannon entropy of a Bernoulli with parameter `p`, in bits.
///
/// `H(p) = -p · log2(p) - (1-p) · log2(1-p)` for `p ∈ (0, 1)`.
///
/// Boundary convention: `H(0) = H(1) = 0`. The mathematical limit
/// `lim_{p→0} p·log p = 0` justifies this; IEEE 754 would otherwise
/// produce `0 * -inf = NaN`. Callers passing `p` outside `[0, 1]`
/// (e.g. from a faulty estimator) also get `0.0` — a silent NaN
/// propagating into a sort key would be far worse than a flat zero
/// that pins the offending sample to the bottom of the schedule.
///
/// Maximum value is exactly `1.0` at `p = 0.5` (a fair coin = 1 bit).
///
/// ```
/// use wafrift_types::entropy::binary_shannon;
/// assert_eq!(binary_shannon(0.5), 1.0);
/// assert_eq!(binary_shannon(0.0), 0.0);
/// assert_eq!(binary_shannon(1.0), 0.0);
/// ```
#[must_use]
pub fn binary_shannon(p: f64) -> f64 {
    if !(0.0..=1.0).contains(&p) || !p.is_finite() {
        return 0.0;
    }
    if p == 0.0 || p == 1.0 {
        return 0.0;
    }
    let q = 1.0 - p;
    -(p * p.log2() + q * q.log2())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peaks_at_one_bit_when_p_is_half() {
        // Anti-rig: this is the load-bearing semantic for the info-gain
        // scheduler. H(0.5) MUST equal exactly 1.0 — any future
        // "smoothing" or numerical-stability tweak that nudges this off
        // would silently bias the schedule. Pin it hard.
        assert_eq!(binary_shannon(0.5), 1.0);
    }

    #[test]
    fn zero_at_endpoints() {
        // Boundary convention: certain outcomes carry no information.
        // The mathematical limit `lim_{p→0} p·log p = 0` is what we
        // want, not IEEE 754's NaN. Pin to catch a future rewrite
        // that "fixes" the endpoint by returning NaN.
        assert_eq!(binary_shannon(0.0), 0.0);
        assert_eq!(binary_shannon(1.0), 0.0);
    }

    #[test]
    fn symmetric_around_half() {
        // H(p) = H(1-p) for every legal p. If a future "optimisation"
        // breaks symmetry the scheduler becomes biased.
        for &p in &[0.1, 0.2, 0.3, 0.4, 0.45, 0.49] {
            let lhs = binary_shannon(p);
            let rhs = binary_shannon(1.0 - p);
            assert!(
                (lhs - rhs).abs() < 1e-12,
                "asymmetric at p={p}: H(p)={lhs} H(1-p)={rhs}"
            );
        }
    }

    #[test]
    fn monotonically_decreases_from_half_to_endpoints() {
        // Anti-rig: the schedule depends on H being unimodal at 0.5.
        // If a future bug introduces local maxima, the scheduler would
        // prioritise irrelevant payloads. Pin the unimodal shape.
        let mut prev = binary_shannon(0.5);
        for step in 1..=10 {
            let p = 0.5 + step as f64 * 0.05;
            let h = binary_shannon(p);
            assert!(h <= prev, "non-monotone descent at p={p}: {h} > {prev}");
            prev = h;
        }
    }

    #[test]
    fn out_of_range_returns_zero() {
        // Defensive: a faulty estimator could pass p < 0 or p > 1.
        // Returning 0 keeps the schedule total-ordered (NaN would
        // poison the sort).
        assert_eq!(binary_shannon(-0.1), 0.0);
        assert_eq!(binary_shannon(1.1), 0.0);
        assert_eq!(binary_shannon(-1.0), 0.0);
        assert_eq!(binary_shannon(2.0), 0.0);
    }

    #[test]
    fn nan_and_infinity_return_zero() {
        // IEEE 754 corner cases: a NaN sample would otherwise propagate
        // into every consumer. Zero out rather than panic — this is a
        // measurement primitive, not a contract-enforcement gate.
        assert_eq!(binary_shannon(f64::NAN), 0.0);
        assert_eq!(binary_shannon(f64::INFINITY), 0.0);
        assert_eq!(binary_shannon(f64::NEG_INFINITY), 0.0);
    }

    #[test]
    fn never_returns_negative_or_above_one() {
        // Anti-rig: H is non-negative and capped at 1 bit. Bound the
        // schedule's sort key to a known interval — a stray value
        // outside [0, 1] indicates upstream corruption.
        for step in 0..=1000 {
            let p = step as f64 / 1000.0;
            let h = binary_shannon(p);
            assert!(
                (0.0..=1.0).contains(&h),
                "H({p})={h} escaped [0,1]"
            );
        }
    }

    #[test]
    fn matches_known_table_within_tolerance() {
        // Pinned against a table computed independently — guards
        // against a future rewrite that drifts the floating-point
        // implementation. Tolerance is loose (1e-9) because the
        // log2 implementation is platform-stable but not bit-exact
        // across compilers.
        let table = [
            (0.10, 0.4689955935892812),
            (0.25, 0.8112781244591328),
            (0.40, 0.9709505944546686),
            (0.50, 1.0000000000000000),
            (0.60, 0.9709505944546686),
            (0.75, 0.8112781244591328),
            (0.90, 0.4689955935892812),
        ];
        for (p, expected) in table {
            let got = binary_shannon(p);
            assert!(
                (got - expected).abs() < 1e-9,
                "H({p})={got} expected={expected}"
            );
        }
    }

    #[test]
    fn near_endpoints_does_not_underflow_or_explode() {
        // Floating-point edge: p extremely close to 0 or 1 — the
        // formula has `p * log2(p)` where log2(p) → -inf but p → 0.
        // f64 has 53 bits of mantissa, so for p as small as 1e-300
        // the product is still finite and tiny. Pin that no platform
        // produces NaN here.
        let near_zero = binary_shannon(1e-12);
        assert!(near_zero.is_finite() && (0.0..=1.0).contains(&near_zero));
        let near_one = binary_shannon(1.0 - 1e-12);
        assert!(near_one.is_finite() && (0.0..=1.0).contains(&near_one));
    }

    // ── shannon (n-ary) ─────────────────────────────────────

    #[test]
    fn shannon_binary_case_matches_binary_shannon() {
        // The general `shannon` over [p, 1-p] must produce the same
        // bits as `binary_shannon(p)`. Pinning the equivalence so a
        // future tweak to one stays in lock-step with the other.
        for p in [0.0, 0.1, 0.25, 0.5, 0.75, 0.9, 1.0] {
            let bin = binary_shannon(p);
            let nary = shannon(&[p, 1.0 - p]);
            assert!(
                (bin - nary).abs() < 1e-12,
                "binary_shannon({p}) = {bin}, shannon([p,1-p]) = {nary}"
            );
        }
    }

    #[test]
    fn shannon_uniform_three_state_is_log2_3() {
        // H(1/3, 1/3, 1/3) = log2(3) ≈ 1.585. Pin so a future change
        // to normalisation doesn't silently bias the n-ary code path.
        let got = shannon(&[1.0 / 3.0, 1.0 / 3.0, 1.0 / 3.0]);
        let expected = (3f64).log2();
        assert!((got - expected).abs() < 1e-9, "got {got}, want {expected}");
    }

    #[test]
    fn shannon_uniform_n_state_is_log2_n() {
        // Generalisation: H(uniform over n outcomes) = log2(n).
        for n in 2usize..=8 {
            let probs: Vec<f64> = vec![1.0 / n as f64; n];
            let got = shannon(&probs);
            let expected = (n as f64).log2();
            assert!(
                (got - expected).abs() < 1e-9,
                "n={n}: got {got}, want {expected}"
            );
        }
    }

    #[test]
    fn shannon_certain_outcome_is_zero() {
        // One outcome with p=1, rest p=0: no uncertainty.
        assert_eq!(shannon(&[1.0, 0.0, 0.0, 0.0]), 0.0);
        assert_eq!(shannon(&[0.0, 1.0]), 0.0);
    }

    #[test]
    fn shannon_empty_slice_is_zero() {
        // Defensive: empty input is a degenerate case, return 0
        // rather than NaN to keep the value safe in a sort key.
        assert_eq!(shannon(&[]), 0.0);
    }

    #[test]
    fn shannon_single_outcome_is_zero() {
        // Single outcome at any probability collapses to 0
        // (you can't have uncertainty over a one-element space).
        assert_eq!(shannon(&[1.0]), 0.0);
        assert_eq!(shannon(&[0.7]), 0.0);
    }

    #[test]
    fn shannon_handles_zero_probability_components() {
        // Anti-rig: zero-probability outcomes contribute 0 (the
        // 0 · log 0 limit). A naive implementation would emit NaN.
        let got = shannon(&[0.5, 0.5, 0.0, 0.0, 0.0]);
        assert_eq!(got, 1.0);
    }

    #[test]
    fn shannon_non_normalised_input_does_not_panic() {
        // Defensive: a caller passing probs that don't sum to 1 must
        // not crash the scheduler. The result will be mathematically
        // incoherent but bounded.
        let got = shannon(&[0.3, 0.3, 0.3]);
        assert!(got.is_finite());
        // And bounded at zero — never negative.
        assert!(got >= 0.0);
    }

    #[test]
    fn shannon_rejects_out_of_range_components_no_negative_entropy() {
        // Anti-rig: a faulty caller passing p > 1 (e.g. raw counts
        // mistakenly mistreated as probabilities) must not produce
        // negative entropy. Pre-fix `shannon(&[2.0, 0.0])` returned
        // -2.0 (log2(2)=1, -p·log2(p) = -2·1 = -2); post-fix it
        // skips p > 1 and returns 0.0.
        let got = shannon(&[2.0, 0.0]);
        assert!(got >= 0.0, "negative entropy from p > 1: {got}");
        let got2 = shannon(&[1.5, 0.5]);
        assert!(got2 >= 0.0, "negative entropy from p > 1: {got2}");
        // Counter-test: legitimate sub-1 sum still produces +entropy.
        let got3 = shannon(&[0.3, 0.3]);
        assert!(got3 > 0.0 && got3.is_finite());
    }

    #[test]
    fn shannon_skips_non_finite_components_without_panicking() {
        // Defensive: NaN / Inf in a single component must not
        // poison the whole sum.
        let got = shannon(&[0.5, 0.5, f64::NAN, f64::INFINITY]);
        assert_eq!(got, 1.0);
    }
}
