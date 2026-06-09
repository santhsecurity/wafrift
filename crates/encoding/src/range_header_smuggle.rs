//! `Range` request-header parser-differential smuggling (RFC 7233).
//!
//! The `Range` request header (RFC 7233 §3.1) is one of the most
//! casually-parsed header surfaces in HTTP. Most WAFs treat it as
//! opaque metadata; most origin servers parse loosely because real-
//! world clients have always done weird things with it. That gap is
//! the bypass surface.
//!
//! ## Wire format (RFC 7233 §3.1)
//!
//! ```text
//! Range = byte-ranges-specifier / other-ranges-specifier
//! byte-ranges-specifier = bytes-unit "=" byte-range-set
//! bytes-unit = "bytes"
//! byte-range-set = 1#( byte-range-spec / suffix-byte-range-spec )
//! byte-range-spec = first-byte-pos "-" [ last-byte-pos ]
//! suffix-byte-range-spec = "-" suffix-length
//! ```
//!
//! Per the RFC each spec is a comma-separated list. Real parser
//! divergence emerges around:
//!
//! - **Multiple `Range:` headers** — RFC 7230 §3.2.2 prohibits, but
//!   clients send them; nginx keeps first, Apache last.
//! - **Empty range** — `Range: bytes=` is accepted as "the whole
//!   resource" by some, rejected with 416 by others.
//! - **Reversed range** — `Range: bytes=100-0` (first > last); MUST
//!   be 416 per RFC but some servers swap the boundaries silently.
//! - **Overlapping ranges** — `Range: bytes=0-99,50-149`; some
//!   servers coalesce, some emit separate multipart parts.
//! - **Gigabyte ranges** — `Range: bytes=0-999999999`; servers that
//!   pre-allocate based on declared length OOM.
//! - **Whitespace inside range** — `Range: bytes= 0-99` or `bytes=0
//!   -99` (space around `-`); RFC says no whitespace, parsers vary.
//! - **Suffix length** — `Range: bytes=-1000` (last 1000 bytes);
//!   some interpret as "byte at -1000" (negative-position interpretation
//!   error → off-by-one or wraparound).
//! - **Non-bytes units** — `Range: pages=0-9`; RFC allows but only
//!   `bytes` is universally implemented; lax origins accept, strict
//!   reject.

use rand::Rng;
use wafrift_types::canary::Canary;
use wafrift_types::pick::pick_from;
use wafrift_types::probe::{SmuggleArtifact, SmuggleProbe};

/// Max length for a single Range header value (bounded so adversarial
/// callers can't synthesize multi-megabyte header lines through this
/// builder).
pub const MAX_RANGE_HEADER_BYTES: usize = 2 * 1024;

/// Range-header smuggle variants — each surfaces a distinct RFC 7233
/// parser-divergence seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RangeSmuggleVariant {
    /// `Range: bytes=` — empty range-set. RFC says 400/416; lax
    /// servers serve the whole resource as if no Range was set.
    EmptyRangeSet,
    /// `Range: bytes=last-first` (e.g. `bytes=100-0`). Strictly
    /// 416; lax servers swap.
    ReversedFirstLast,
    /// `Range: bytes=0-99,50-149` — overlapping spans. Coalesce vs
    /// multipart vs reject differential.
    OverlappingRanges,
    /// `Range: bytes=0-<gigabyte>` — over-large last-byte position.
    /// Servers that pre-allocate OOM; capped at a sane ceiling
    /// (`SAFE_LARGE_LAST_POS`) so wafrift itself doesn't enable
    /// denial-of-service attacks on authorized targets.
    OverLargeLastPosition,
    /// `Range: bytes= 0-99` (leading whitespace after `=`) or
    /// `bytes=0 -99` (whitespace around `-`). RFC says no WS;
    /// lenient parsers strip.
    WhitespaceInsideRange,
    /// `Range: bytes=-1000` — suffix range; some implementations
    /// misread as "byte position -1000" leading to underflow.
    SuffixLengthAsNegativePosition,
    /// `Range: pages=0-9` — non-bytes unit. RFC allows; only
    /// `bytes` is universal. Probes which side rejects.
    NonBytesUnit,
    /// Two `Range:` headers — first benign, second smuggle. nginx
    /// keeps first, Apache last → differential.
    DuplicateHeaderFirstWinsBenign,
}

impl SmuggleProbe for RangeSmuggleProbe {
    fn canary(&self) -> &Canary {
        &self.canary
    }

    fn technique(&self) -> String {
        let suffix = match self.variant {
            RangeSmuggleVariant::EmptyRangeSet => "empty-range-set",
            RangeSmuggleVariant::ReversedFirstLast => "reversed-first-last",
            RangeSmuggleVariant::OverlappingRanges => "overlapping-ranges",
            RangeSmuggleVariant::OverLargeLastPosition => "over-large-last-position",
            RangeSmuggleVariant::WhitespaceInsideRange => "whitespace-inside-range",
            RangeSmuggleVariant::SuffixLengthAsNegativePosition => {
                "suffix-length-as-negative-position"
            }
            RangeSmuggleVariant::NonBytesUnit => "non-bytes-unit",
            RangeSmuggleVariant::DuplicateHeaderFirstWinsBenign => {
                "duplicate-header-first-wins-benign"
            }
        };
        format!("range.{suffix}")
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn artifact(&self) -> SmuggleArtifact {
        SmuggleArtifact::Headers(self.header_lines.clone())
    }
}

/// Realistic last-byte positions for the
/// [`OverLargeLastPosition`](RangeSmuggleVariant::OverLargeLastPosition)
/// probe. Each is "large enough to OOM a sloppy server" but bounded
/// well below the QUIC-varint / signed-i64 ceiling so wafrift itself
/// never emits a value that could be misread as a sentinel.
pub(crate) const SAFE_LARGE_LAST_POS: &[u64] = &[
    1_000_000,         // 1 MB
    100_000_000,       // 100 MB
    10_000_000_000,    // 10 GB
    1_000_000_000_000, // 1 TB
];

/// Non-`bytes` range units for the
/// [`NonBytesUnit`](RangeSmuggleVariant::NonBytesUnit) probe.
pub(crate) const NON_BYTES_UNITS: &[&str] = &[
    "pages",   // PDF page ranges, accepted by some PDF servers
    "items",   // generic
    "rows",    // SQL-style range, accepted by some REST APIs
    "objects", // S3-style
    "lines",   // log-streaming
];

/// A Range-header smuggle probe.
#[derive(Debug, Clone)]
pub struct RangeSmuggleProbe {
    pub variant: RangeSmuggleVariant,
    /// Header lines to attach. Most variants emit one `(name,
    /// value)` pair; the duplicate-header variant emits two.
    pub header_lines: Vec<(String, String)>,
    pub description: String,
    pub canary: Canary,
}

impl RangeSmuggleProbe {
    fn finalise(
        variant: RangeSmuggleVariant,
        mut header_lines: Vec<(String, String)>,
        description: String,
    ) -> Self {
        for (_, v) in header_lines.iter_mut() {
            if v.len() > MAX_RANGE_HEADER_BYTES {
                // §15 panic fix: cap at a UTF-8 char boundary (shared helper) so
                // a multibyte value can't panic String::truncate mid-codepoint.
                let cut = crate::floor_char_boundary(v, MAX_RANGE_HEADER_BYTES);
                v.truncate(cut);
            }
        }
        Self {
            variant,
            header_lines,
            description,
            canary: Canary::generate(),
        }
    }

    /// `Range: bytes=` — empty range set.
    #[must_use]
    pub fn empty_range_set() -> Self {
        Self::finalise(
            RangeSmuggleVariant::EmptyRangeSet,
            vec![("Range".into(), "bytes=".into())],
            "Empty Range value — `bytes=` with no spec; RFC 7233 vs lax differential".into(),
        )
    }

    /// `Range: bytes={first}-{last}` with `first > last`. Strict =
    /// 416. Lax = swapped.
    #[must_use]
    pub fn reversed_first_last(first: u64, last: u64) -> Self {
        // Caller may pass them either way; ensure first > last so
        // the probe semantic holds. If they were already in correct
        // order, swap them.
        let (hi, lo) = if first > last {
            (first, last)
        } else if first == last {
            (first.saturating_add(1), last)
        } else {
            (last, first)
        };
        let value = format!("bytes={hi}-{lo}");
        Self::finalise(
            RangeSmuggleVariant::ReversedFirstLast,
            vec![("Range".into(), value)],
            format!("Reversed Range `bytes={hi}-{lo}` — first > last violation, swap-vs-416 diff"),
        )
    }

    /// `Range: bytes=0-99,50-149` — overlapping spans.
    #[must_use]
    pub fn overlapping_ranges() -> Self {
        let value = "bytes=0-99,50-149".to_string();
        Self::finalise(
            RangeSmuggleVariant::OverlappingRanges,
            vec![("Range".into(), value)],
            "Overlapping Range spans — coalesce vs multipart vs reject differential".into(),
        )
    }

    /// `Range: bytes=0-{LARGE}` — over-large last position. The
    /// position is drawn from `SAFE_LARGE_LAST_POS` per-call.
    #[must_use]
    pub fn over_large_last_position() -> Self {
        let last = pick_from(SAFE_LARGE_LAST_POS, 1_000_000_000_u64);
        let value = format!("bytes=0-{last}");
        Self::finalise(
            RangeSmuggleVariant::OverLargeLastPosition,
            vec![("Range".into(), value)],
            format!(
                "Over-large last-byte position {last} — naive pre-allocators OOM, capped vs error"
            ),
        )
    }

    /// `Range: bytes= 0 - 99` — whitespace sprinkled in the spec.
    /// Specific whitespace insertion locations are randomised per
    /// call so signature WAFs that pin "exactly one space after `=`"
    /// don't catch every probe.
    #[must_use]
    pub fn whitespace_inside_range() -> Self {
        let mut rng = rand::thread_rng();
        let after_eq = if rng.gen_bool(0.5) { " " } else { "" };
        let around_dash_left = if rng.gen_bool(0.5) { " " } else { "" };
        let around_dash_right = if rng.gen_bool(0.5) { " " } else { "" };
        let value = format!("bytes={after_eq}0{around_dash_left}-{around_dash_right}99");
        Self::finalise(
            RangeSmuggleVariant::WhitespaceInsideRange,
            vec![("Range".into(), value)],
            "Whitespace inside Range spec — strict-reject vs trim differential".into(),
        )
    }

    /// `Range: bytes=-1000` — suffix range. Some implementations
    /// misread the leading `-` as a sign.
    #[must_use]
    pub fn suffix_length_as_negative_position(suffix_len: u64) -> Self {
        let value = format!("bytes=-{suffix_len}");
        Self::finalise(
            RangeSmuggleVariant::SuffixLengthAsNegativePosition,
            vec![("Range".into(), value)],
            format!("Suffix range `bytes=-{suffix_len}` — last-N vs negative-position misparse"),
        )
    }

    /// `Range: <unit>=0-9` — non-`bytes` unit. Unit drawn from
    /// `NON_BYTES_UNITS` per-call.
    #[must_use]
    pub fn non_bytes_unit() -> Self {
        let unit = pick_from(NON_BYTES_UNITS, "pages");
        let value = format!("{unit}=0-9");
        Self::finalise(
            RangeSmuggleVariant::NonBytesUnit,
            vec![("Range".into(), value)],
            format!("Non-bytes range unit `{unit}` — RFC allows; only `bytes` universal"),
        )
    }

    /// Two `Range:` header lines — first benign full-resource,
    /// second the smuggled range.
    #[must_use]
    pub fn duplicate_header_first_wins_benign(smuggle_range: &str) -> Self {
        let benign = "bytes=0-".to_string(); // whole resource
        let smuggle = if smuggle_range.starts_with("bytes=") {
            smuggle_range.to_string()
        } else {
            format!("bytes={smuggle_range}")
        };
        Self::finalise(
            RangeSmuggleVariant::DuplicateHeaderFirstWinsBenign,
            vec![("Range".into(), benign), ("Range".into(), smuggle)],
            "Duplicate Range headers — nginx-vs-Apache first/last-wins differential".into(),
        )
    }
}

/// Enumerate one probe per variant. Useful for sweep-style probes.
#[must_use]
pub fn all_variants() -> Vec<RangeSmuggleProbe> {
    vec![
        RangeSmuggleProbe::empty_range_set(),
        RangeSmuggleProbe::reversed_first_last(100, 0),
        RangeSmuggleProbe::overlapping_ranges(),
        RangeSmuggleProbe::over_large_last_position(),
        RangeSmuggleProbe::whitespace_inside_range(),
        RangeSmuggleProbe::suffix_length_as_negative_position(1000),
        RangeSmuggleProbe::non_bytes_unit(),
        RangeSmuggleProbe::duplicate_header_first_wins_benign("bytes=100-199"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn sweep_emits_eight_distinct_variants() {
        let v = all_variants();
        assert_eq!(v.len(), 8);
        let kinds: HashSet<_> = v.iter().map(|p| p.variant).collect();
        assert_eq!(kinds.len(), 8);
    }

    #[test]
    fn empty_range_value_is_just_bytes_equals() {
        let p = RangeSmuggleProbe::empty_range_set();
        assert_eq!(p.header_lines[0].1, "bytes=");
    }

    #[test]
    fn reversed_first_last_orders_high_then_low_on_wire() {
        let p = RangeSmuggleProbe::reversed_first_last(0, 100);
        // Caller passed (0, 100); probe should swap to (100, 0).
        assert_eq!(p.header_lines[0].1, "bytes=100-0");
    }

    #[test]
    fn reversed_first_last_handles_equal_inputs_by_offset() {
        // first == last would defeat the "first > last" invariant.
        // Builder must adjust.
        let p = RangeSmuggleProbe::reversed_first_last(50, 50);
        let v = &p.header_lines[0].1;
        assert!(
            v.contains("51-50") || v.contains("50-49"),
            "expected offset to break equality, got {v:?}"
        );
    }

    #[test]
    fn overlapping_ranges_contains_two_comma_separated_spans() {
        let p = RangeSmuggleProbe::overlapping_ranges();
        let v = &p.header_lines[0].1;
        assert!(v.starts_with("bytes="));
        // Two spans = one comma.
        assert_eq!(v.matches(',').count(), 1);
    }

    #[test]
    fn over_large_last_position_picks_from_safe_pool() {
        let p = RangeSmuggleProbe::over_large_last_position();
        let v = &p.header_lines[0].1;
        // The last value must equal one of the SAFE_LARGE_LAST_POS
        // entries (anti-rig: a regression that hardcoded one value
        // would defeat the per-call signature randomisation).
        let last_str = v.trim_start_matches("bytes=0-");
        let last: u64 = last_str.parse().expect("parseable u64");
        assert!(
            SAFE_LARGE_LAST_POS.contains(&last),
            "last position {last} not in SAFE_LARGE_LAST_POS"
        );
    }

    #[test]
    fn whitespace_probe_contains_at_least_one_space_or_tab() {
        // The whitespace insertion is randomised; over a few
        // independent calls, at least one MUST produce a space in
        // the value (anti-rig for the per-call randomness).
        let mut saw_ws = false;
        for _ in 0..20 {
            let p = RangeSmuggleProbe::whitespace_inside_range();
            if p.header_lines[0].1.contains(' ') {
                saw_ws = true;
                break;
            }
        }
        assert!(
            saw_ws,
            "20 calls to whitespace_inside_range produced ZERO spaces — RNG broken or coin biased"
        );
    }

    #[test]
    fn suffix_length_uses_dash_prefix() {
        let p = RangeSmuggleProbe::suffix_length_as_negative_position(2048);
        assert_eq!(p.header_lines[0].1, "bytes=-2048");
    }

    #[test]
    fn non_bytes_unit_picks_from_pool() {
        let p = RangeSmuggleProbe::non_bytes_unit();
        let v = &p.header_lines[0].1;
        let unit_end = v.find('=').expect("=");
        let unit = &v[..unit_end];
        assert!(
            NON_BYTES_UNITS.contains(&unit),
            "unit {unit:?} not in NON_BYTES_UNITS pool"
        );
    }

    #[test]
    fn duplicate_header_probe_emits_two_range_lines() {
        let p = RangeSmuggleProbe::duplicate_header_first_wins_benign("bytes=500-999");
        assert_eq!(p.header_lines.len(), 2);
        assert_eq!(p.header_lines[0].0, "Range");
        assert_eq!(p.header_lines[1].0, "Range");
        assert_eq!(p.header_lines[0].1, "bytes=0-"); // benign whole-resource
        assert_eq!(p.header_lines[1].1, "bytes=500-999");
    }

    #[test]
    fn duplicate_header_probe_accepts_unprefixed_smuggle_input() {
        // Caller convenience: "100-199" without the bytes= prefix.
        let p = RangeSmuggleProbe::duplicate_header_first_wins_benign("100-199");
        assert_eq!(p.header_lines[1].1, "bytes=100-199");
    }

    #[test]
    fn every_probe_carries_a_distinct_canary() {
        let a = RangeSmuggleProbe::empty_range_set();
        let b = RangeSmuggleProbe::empty_range_set();
        assert_ne!(a.canary.token, b.canary.token);
        assert_eq!(a.canary.token.len(), 16);
    }

    #[test]
    fn safe_large_last_pos_pool_within_signed_i64_band() {
        // Anti-rig: every pool entry must fit in i64 so any
        // downstream code that parses Range with signed arithmetic
        // doesn't wrap. i64::MAX is ~9.2e18.
        for &p in SAFE_LARGE_LAST_POS {
            assert!(p < i64::MAX as u64);
        }
    }

    #[test]
    fn non_bytes_units_pool_is_non_empty_and_unique() {
        assert!(!NON_BYTES_UNITS.is_empty());
        let unique: HashSet<&&str> = NON_BYTES_UNITS.iter().collect();
        assert_eq!(unique.len(), NON_BYTES_UNITS.len());
    }
}
