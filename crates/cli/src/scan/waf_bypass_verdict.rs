//! Blunt WAF-bypass verdict for scan output — one answer: did we beat the WAF?
//!
//! Legacy `bypass_rate_pct` counted pass-through on uninspected parameters.
//! Consumers should read `waf_bypass` first; treat `bypass_rate_pct` as deprecated
//! when `waf_in_play` is false.

use serde::Serialize;

use super::waf_engagement::WafEngagementLevel;

/// Operator-facing verdict string (stable for scripts).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WafBypassVerdictKind {
    /// WAF inspected this surface and at least one evasion was not blocked.
    BypassConfirmed,
    /// WAF blocked (active/selective) but no variant beat it on this run.
    WafActiveNoBypass,
    /// No WAF engagement on this injection point — bypass counts are invalid.
    WafNotInPlay,
    /// Could not reach target to assess engagement.
    Inconclusive,
}

// NOTE (§7 DEDUP): a hand-rolled `as_str()` returning "bypass_confirmed" /
// "waf_active_no_bypass" / … was removed — `#[serde(rename_all =
// "snake_case")]` on the enum above already emits those exact strings as the
// single source of truth, and `as_str` had zero callers. One mapping, one home.

/// Primary scan outcome for WAF bypass missions.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct WafBypassVerdict {
    /// True when engagement is `active` or `selective` — a WAF is fighting on this param.
    pub waf_in_play: bool,
    /// Variants that beat a block signal while `waf_in_play` (same as `meaningful_bypassed`).
    pub bypass_confirmed: u32,
    /// Blocked by WAF during contested probes (while `waf_in_play`).
    pub waf_blocked: u32,
    /// Percent of contested WAF decisions that bypassed: confirmed / (confirmed + blocked).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub waf_bypass_rate_pct: Option<f64>,
    pub verdict: WafBypassVerdictKind,
    /// One-line human summary for logs and text mode.
    pub headline: String,
    pub engagement_level: String,
}

#[must_use]
pub(crate) fn compute(
    level: WafEngagementLevel,
    meaningful_bypassed: u32,
    blocked_while_guarded: u32,
) -> WafBypassVerdict {
    let waf_in_play = level.counts_meaningful_bypass();
    let bypass_confirmed = if waf_in_play { meaningful_bypassed } else { 0 };
    let waf_blocked = if waf_in_play {
        blocked_while_guarded
    } else {
        0
    };

    let contested = bypass_confirmed.saturating_add(waf_blocked);
    let waf_bypass_rate_pct = if waf_in_play && contested > 0 {
        Some(f64::from(bypass_confirmed) / f64::from(contested) * 100.0)
    } else {
        None
    };

    let verdict = if !matches!(level, WafEngagementLevel::Unknown) && !waf_in_play {
        WafBypassVerdictKind::WafNotInPlay
    } else if matches!(level, WafEngagementLevel::Unknown) {
        WafBypassVerdictKind::Inconclusive
    } else if bypass_confirmed > 0 {
        WafBypassVerdictKind::BypassConfirmed
    } else {
        WafBypassVerdictKind::WafActiveNoBypass
    };

    let headline = match verdict {
        WafBypassVerdictKind::BypassConfirmed => format!(
            "WAF BYPASS CONFIRMED — {bypass_confirmed} evasion(s) beat {} on this surface",
            waf_name_engagement(level)
        ),
        WafBypassVerdictKind::WafActiveNoBypass => format!(
            "WAF IN PLAY — no bypass found ({waf_blocked} blocked); retest other params or --auto-escalate surfaces"
        ),
        WafBypassVerdictKind::WafNotInPlay => format!(
            "NO WAF ON THIS PARAM ({}) — not a bypass measurement; use --auto-escalate or scan forms/API paths",
            level.as_str()
        ),
        WafBypassVerdictKind::Inconclusive => {
            "INCONCLUSIVE — baseline transport failed; fix reachability and retry".to_string()
        }
    };

    WafBypassVerdict {
        waf_in_play,
        bypass_confirmed,
        waf_blocked,
        waf_bypass_rate_pct,
        verdict,
        headline,
        engagement_level: level.as_str().to_string(),
    }
}

fn waf_name_engagement(level: WafEngagementLevel) -> &'static str {
    match level {
        WafEngagementLevel::Active => "active WAF rules",
        WafEngagementLevel::Selective => "selective WAF rules",
        _ => "WAF",
    }
}

#[must_use]
pub(crate) fn exit_code_for_verdict(
    verdict: WafBypassVerdictKind,
    scan_timeout: bool,
    aborted_rate_limited: bool,
) -> u8 {
    if scan_timeout {
        return 7;
    }
    if aborted_rate_limited {
        return 5;
    }
    match verdict {
        WafBypassVerdictKind::BypassConfirmed => 0,
        WafBypassVerdictKind::WafActiveNoBypass => 4,
        WafBypassVerdictKind::WafNotInPlay | WafBypassVerdictKind::Inconclusive => 6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waf_not_in_play_zeroes_bypass_confirmed() {
        let v = compute(WafEngagementLevel::Unguarded, 99, 0);
        assert!(!v.waf_in_play);
        assert_eq!(v.bypass_confirmed, 0);
        assert_eq!(v.verdict, WafBypassVerdictKind::WafNotInPlay);
        assert!(v.waf_bypass_rate_pct.is_none());
    }

    #[test]
    fn active_with_bypass_is_confirmed() {
        let v = compute(WafEngagementLevel::Active, 3, 10);
        assert!(v.waf_in_play);
        assert_eq!(v.bypass_confirmed, 3);
        assert_eq!(v.verdict, WafBypassVerdictKind::BypassConfirmed);
        assert!((v.waf_bypass_rate_pct.unwrap() - 23.076923).abs() < 0.01);
    }

    #[test]
    fn active_zero_bypass_is_waf_active_no_bypass() {
        let v = compute(WafEngagementLevel::Selective, 0, 5);
        assert_eq!(v.verdict, WafBypassVerdictKind::WafActiveNoBypass);
        assert_eq!(exit_code_for_verdict(v.verdict, false, false), 4);
    }

    #[test]
    fn exit_codes_for_timeout_and_rl() {
        assert_eq!(
            exit_code_for_verdict(WafBypassVerdictKind::BypassConfirmed, true, false),
            7
        );
        assert_eq!(
            exit_code_for_verdict(WafBypassVerdictKind::BypassConfirmed, false, true),
            5
        );
    }

    #[test]
    fn exit_code_contract_matches_documented_readme_table() {
        // §10 COHERENCE / claims-integrity: this is the single source of
        // truth for the README "Exit codes (CI-friendly)" table. If the
        // mapping changes, the README row must change with it — and vice
        // versa. Pins every documented scan exit code so a silent drift
        // (e.g. collapsing 6 back into 0, the bug that motivated documenting
        // 6) turns this test red. Precedence: timeout (7) > rate-limit (5) >
        // verdict.
        // 0 = bypass confirmed (clean run, something bypassed).
        assert_eq!(
            exit_code_for_verdict(WafBypassVerdictKind::BypassConfirmed, false, false),
            0
        );
        // 4 = WAF active but nothing bypassed.
        assert_eq!(
            exit_code_for_verdict(WafBypassVerdictKind::WafActiveNoBypass, false, false),
            4
        );
        // 6 = inconclusive / no WAF on the param — NOT 0. Both verdict kinds
        // map here (the README documents 6 as "could not measure").
        assert_eq!(
            exit_code_for_verdict(WafBypassVerdictKind::WafNotInPlay, false, false),
            6
        );
        assert_eq!(
            exit_code_for_verdict(WafBypassVerdictKind::Inconclusive, false, false),
            6
        );
        // Precedence: a wall-clock timeout (7) and a rate-limit abort (5)
        // outrank the verdict, even a "bypass confirmed" one — the run did
        // not complete cleanly, so CI must see the partial-run code.
        assert_eq!(
            exit_code_for_verdict(WafBypassVerdictKind::WafNotInPlay, true, false),
            7,
            "timeout outranks the verdict"
        );
        assert_eq!(
            exit_code_for_verdict(WafBypassVerdictKind::WafActiveNoBypass, false, true),
            5,
            "rate-limit abort outranks the verdict"
        );
        // Timeout outranks rate-limit when both are set.
        assert_eq!(
            exit_code_for_verdict(WafBypassVerdictKind::BypassConfirmed, true, true),
            7,
            "timeout outranks rate-limit"
        );
    }
}
