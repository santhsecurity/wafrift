//! TCP reassembly policies — how a stack resolves **overlapping** segments.
//!
//! When two TCP segments cover the same sequence range with different bytes, the
//! receiver must pick which wins. RFC 793 left this under-specified, so stacks
//! diverge — and *target-based reassembly* (Ptacek & Newsham 1998; Snort
//! `stream5`) is built on exactly that divergence: if a WAF/IDS resolves overlaps
//! one way and the origin another, the same packets become two different byte
//! streams. The WAF inspects the benign reassembly; the origin executes the
//! attack reassembly.
//!
//! This enum models the four behaviours that span the real disagreement space.
//! Each rule is expressed as a single predicate, [`ReassemblyPolicy::overwrites`]:
//! given an incoming byte (its segment's left-edge sequence and arrival order)
//! and the existing occupant of a position, should the incoming byte win?

use serde::{Deserialize, Serialize};

/// A target-based TCP overlap-reassembly policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReassemblyPolicy {
    /// **Favor old** — the first segment to cover a position wins; later
    /// overlapping data is dropped for already-filled bytes. Classic Windows /
    /// "favor old" behaviour.
    First,
    /// **Favor new** — a later-arriving segment overwrites earlier data on
    /// overlap. "Favor new" behaviour.
    Last,
    /// **BSD** — the segment with the *lower* starting sequence number wins the
    /// overlap; on an equal left edge the existing (older) segment is kept.
    Bsd,
    /// **Linux** — like BSD but an incoming segment whose left edge is ≤ the
    /// existing one's wins (ties go to the *newer* segment). More "favor new" on
    /// left-aligned overlaps than BSD.
    Linux,
}

impl ReassemblyPolicy {
    /// Every modelled policy, for differential sweeps.
    #[must_use]
    pub fn all() -> &'static [ReassemblyPolicy] {
        &[Self::First, Self::Last, Self::Bsd, Self::Linux]
    }

    /// Stable label for reports / JSON.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::First => "first",
            Self::Last => "last",
            Self::Bsd => "bsd",
            Self::Linux => "linux",
        }
    }

    /// Should an incoming byte overwrite the existing occupant of a position?
    ///
    /// * `in_seq` / `ex_seq` — the left-edge sequence number of the incoming /
    ///   existing byte's *segment* (the standard target-based criterion).
    /// * Arrival order is implicit: bytes are processed in arrival order, so the
    ///   incoming byte is always the newer one — `Last` therefore always
    ///   overwrites.
    #[must_use]
    pub fn overwrites(self, in_seq: u32, ex_seq: u32) -> bool {
        match self {
            Self::First => false,            // never overwrite filled bytes
            Self::Last => true,              // newer (incoming) always wins
            Self::Bsd => in_seq < ex_seq,    // strictly-lower left edge wins
            Self::Linux => in_seq <= ex_seq, // ≤ left edge wins (tie → newer)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_never_overwrites() {
        for (a, b) in [(0, 0), (0, 5), (5, 0)] {
            assert!(!ReassemblyPolicy::First.overwrites(a, b));
        }
    }

    #[test]
    fn last_always_overwrites() {
        for (a, b) in [(0, 0), (0, 5), (5, 0)] {
            assert!(ReassemblyPolicy::Last.overwrites(a, b));
        }
    }

    #[test]
    fn bsd_favors_strictly_lower_left_edge_keeps_on_tie() {
        assert!(ReassemblyPolicy::Bsd.overwrites(3, 7), "lower seq wins");
        assert!(!ReassemblyPolicy::Bsd.overwrites(7, 3), "higher seq loses");
        assert!(
            !ReassemblyPolicy::Bsd.overwrites(5, 5),
            "tie keeps existing (older)"
        );
    }

    #[test]
    fn linux_favors_le_left_edge_tie_goes_to_newer() {
        assert!(ReassemblyPolicy::Linux.overwrites(3, 7));
        assert!(!ReassemblyPolicy::Linux.overwrites(7, 3));
        assert!(
            ReassemblyPolicy::Linux.overwrites(5, 5),
            "tie goes to newer"
        );
    }

    #[test]
    fn bsd_and_linux_differ_only_on_the_tie() {
        // The single distinguishing case: equal left edges (full overlap).
        assert_ne!(
            ReassemblyPolicy::Bsd.overwrites(4, 4),
            ReassemblyPolicy::Linux.overwrites(4, 4)
        );
    }

    #[test]
    fn label_round_trips_through_serde() {
        for p in ReassemblyPolicy::all() {
            let json = serde_json::to_string(p).unwrap();
            let back: ReassemblyPolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(*p, back);
            assert!(json.contains(p.label()));
        }
    }
}
