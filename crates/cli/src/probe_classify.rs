//! Shared probe-response classification primitives — the dedup
//! target for `bypass_probe` and `parser_diff` (and any future
//! "fire-N-variants-against-a-baseline-and-rate-the-divergence"
//! command).
//!
//! Before this module existed, the same `severity_rank`,
//! `is_throttle_or_unavailable`, and "status-changed + body-delta"
//! logic lived inline in each consumer. That guaranteed silent
//! drift: a rule update to handle (say) `HTTP 525` as a throttle
//! status would have to be applied twice and might miss one. Now
//! it lives here, tested once, consumed by both.

/// Numeric rank for severity strings — used for sorting and for
/// `--min-severity` filtering. Unknown strings rank as 0 (always
/// included when sorting; never matched when filtering). Case-
/// insensitive so callers can pass `"HIGH"`, `"high"`, or `"High"`.
#[must_use]
pub fn severity_rank(s: &str) -> u8 {
    match s.to_ascii_uppercase().as_str() {
        "HIGH" => 4,
        "MEDIUM" => 3,
        "LOW" => 2,
        "EQUAL" => 1,
        _ => 0,
    }
}

/// HTTP statuses that mean "the target is throttling or temporarily
/// unavailable", NOT "you bypassed the control". A 429 (or a 503 /
/// 502 / 504 / 408, or Cloudflare's 520-527 origin-error band) is
/// the target telling us to slow down — turning it into a "LOW
/// severity bypass divergence" (the dogfood bug: 135/191 probes
/// were 429 against try.discourse.org and every one was flagged)
/// is a false positive that buries any real finding in rate-limit
/// noise.
#[must_use]
pub fn is_throttle_or_unavailable(status: u16) -> bool {
    matches!(status, 408 | 429 | 502 | 503 | 504 | 520..=527)
}

/// Body-length delta as a percentage, with the consistent "zero
/// baseline" convention shared across `bypass_probe` and
/// `parser_diff`: an empty baseline plus non-empty probe = 100%
/// (content appeared); both empty = 0% (no change).
#[must_use]
pub fn body_delta_pct(baseline_len: usize, probe_len: usize) -> f64 {
    if baseline_len == 0 {
        if probe_len == 0 { 0.0 } else { 100.0 }
    } else {
        ((probe_len as f64 - baseline_len as f64) / baseline_len as f64) * 100.0
    }
}

/// The "is this response meaningfully different from the baseline?"
/// gate used by both probe families.
///
/// Returns `(status_changed, body_changed, delta_pct)`. The caller
/// folds those into its own severity heuristic — this function
/// doesn't pick a name for the divergence because the consumers
/// disagree on the vocabulary (`Divergence` vs `DiffResult`).
#[must_use]
pub fn delta_signal(
    baseline_status: u16,
    baseline_len: usize,
    probe_status: u16,
    probe_len: usize,
    body_threshold_pct: f64,
) -> (bool, bool, f64) {
    let status_changed = probe_status != baseline_status;
    let delta = body_delta_pct(baseline_len, probe_len);
    let body_changed = delta.abs() >= body_threshold_pct;
    (status_changed, body_changed, delta)
}

/// Canonical severity heuristic: HIGH for an auth bypass
/// (401/403 -> 2xx/3xx), MEDIUM for a status flip into the 2xx-3xx
/// band OR a meaningful body growth, LOW for anything else that
/// still counts as a divergence, EQUAL for "baseline matched".
#[must_use]
pub fn severity_label(
    baseline_status: u16,
    probe_status: u16,
    body_delta: f64,
    body_threshold_pct: f64,
) -> &'static str {
    let status_changed = baseline_status != probe_status;
    let body_changed = body_delta.abs() >= body_threshold_pct;
    if matches!(baseline_status, 401 | 403)
        && matches!(probe_status, 200 | 201 | 202 | 204 | 301 | 302)
    {
        "HIGH"
    } else if (status_changed && (200..400).contains(&probe_status))
        || (body_changed && body_delta > 0.0)
    {
        "MEDIUM"
    } else if status_changed || body_changed {
        "LOW"
    } else {
        "EQUAL"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── severity_rank ──────────────────────────────────────────

    #[test]
    fn severity_rank_canonical_orderings() {
        assert!(severity_rank("HIGH") > severity_rank("MEDIUM"));
        assert!(severity_rank("MEDIUM") > severity_rank("LOW"));
        assert!(severity_rank("LOW") > severity_rank("EQUAL"));
        assert!(severity_rank("EQUAL") > severity_rank("garbage"));
    }

    #[test]
    fn severity_rank_is_case_insensitive() {
        for variant in ["high", "HIGH", "High", "hIgH"] {
            assert_eq!(severity_rank(variant), severity_rank("HIGH"));
        }
    }

    #[test]
    fn severity_rank_unknown_string_is_zero() {
        assert_eq!(severity_rank(""), 0);
        assert_eq!(severity_rank("CRITICAL"), 0);
        assert_eq!(severity_rank("INFO"), 0);
    }

    // ── is_throttle_or_unavailable ─────────────────────────────

    #[test]
    fn throttle_covers_canonical_codes() {
        for c in [408_u16, 429, 502, 503, 504] {
            assert!(is_throttle_or_unavailable(c), "{c} should be a throttle");
        }
    }

    #[test]
    fn throttle_covers_cloudflare_origin_band() {
        for c in 520_u16..=527_u16 {
            assert!(
                is_throttle_or_unavailable(c),
                "{c} should be in the CF origin-error band"
            );
        }
    }

    #[test]
    fn throttle_excludes_success_and_client_error() {
        for c in [200_u16, 201, 301, 302, 400, 401, 403, 404, 405, 500] {
            assert!(
                !is_throttle_or_unavailable(c),
                "{c} should NOT count as throttle"
            );
        }
    }

    // ── body_delta_pct ─────────────────────────────────────────

    #[test]
    fn body_delta_both_zero_is_zero() {
        assert!(body_delta_pct(0, 0).abs() < f64::EPSILON);
    }

    #[test]
    fn body_delta_empty_baseline_with_content_is_one_hundred() {
        assert!((body_delta_pct(0, 500) - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn body_delta_doubled_is_one_hundred_pct() {
        assert!((body_delta_pct(100, 200) - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn body_delta_halved_is_minus_fifty() {
        assert!((body_delta_pct(100, 50) - (-50.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn body_delta_no_change_is_zero() {
        assert!(body_delta_pct(1234, 1234).abs() < f64::EPSILON);
    }

    // ── delta_signal ───────────────────────────────────────────

    #[test]
    fn delta_signal_status_unchanged_body_below_threshold_is_inert() {
        let (sc, bc, d) = delta_signal(200, 1000, 200, 1050, 10.0);
        assert!(!sc);
        assert!(!bc);
        assert!((d - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn delta_signal_status_changed_no_body_change_is_meaningful() {
        let (sc, bc, _) = delta_signal(403, 500, 200, 500, 10.0);
        assert!(sc);
        assert!(!bc);
    }

    #[test]
    fn delta_signal_body_grew_past_threshold_is_meaningful() {
        let (sc, bc, d) = delta_signal(200, 100, 200, 150, 10.0);
        assert!(!sc);
        assert!(bc, "50% growth must clear a 10% threshold");
        assert!((d - 50.0).abs() < f64::EPSILON);
    }

    // ── severity_label ─────────────────────────────────────────

    #[test]
    fn severity_label_403_to_200_is_high() {
        assert_eq!(severity_label(403, 200, 0.0, 10.0), "HIGH");
    }

    #[test]
    fn severity_label_401_to_302_is_high() {
        assert_eq!(severity_label(401, 302, 0.0, 10.0), "HIGH");
    }

    #[test]
    fn severity_label_403_to_500_is_low_not_high() {
        // Anti-rig: a status flip 403→500 is NOT an auth bypass
        // (the request never reached the protected resource). It
        // might still be a divergence worth reporting, but it must
        // not be HIGH.
        let s = severity_label(403, 500, 0.0, 10.0);
        assert!(
            s == "LOW" || s == "MEDIUM",
            "403→500 should be LOW or MEDIUM, got {s}"
        );
        assert_ne!(s, "HIGH");
    }

    #[test]
    fn severity_label_unchanged_is_equal() {
        assert_eq!(severity_label(200, 200, 0.0, 10.0), "EQUAL");
        assert_eq!(severity_label(403, 403, 0.0, 10.0), "EQUAL");
    }

    #[test]
    fn severity_label_body_shrank_is_low() {
        // Body shrinkage (probe smaller than baseline) is typically
        // an error page — not a bypass. Must surface as LOW, never
        // MEDIUM/HIGH.
        assert_eq!(severity_label(200, 200, -50.0, 10.0), "LOW");
    }

    #[test]
    fn severity_label_body_growth_is_medium() {
        assert_eq!(severity_label(200, 200, 50.0, 10.0), "MEDIUM");
    }

    #[test]
    fn severity_label_status_flip_into_2xx_is_medium() {
        // 404→200 is interesting (we found a hidden resource) but
        // not an auth bypass.
        assert_eq!(severity_label(404, 200, 0.0, 10.0), "MEDIUM");
    }

    #[test]
    fn severity_label_status_flip_into_3xx_redirect_is_high_when_from_block() {
        // 401→302 is the canonical "now we're being redirected
        // somewhere authenticated" auth bypass.
        assert_eq!(severity_label(401, 302, 0.0, 10.0), "HIGH");
    }

    #[test]
    fn severity_label_status_flip_into_5xx_is_low() {
        // 200→500 is not a bypass — it's the WAF (or origin)
        // failing on our variant. LOW signals "this happened but
        // do not get excited."
        assert_eq!(severity_label(200, 500, 0.0, 10.0), "LOW");
    }

    #[test]
    fn severity_label_high_threshold_suppresses_small_body_changes() {
        // With a strict 50% threshold, a 30% growth must NOT count
        // as a divergence — caller asked for the noise floor.
        assert_eq!(severity_label(200, 200, 30.0, 50.0), "EQUAL");
    }
}
