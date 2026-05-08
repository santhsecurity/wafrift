//! Escalation levels — how aggressively we need to evade.
//!
//! One enum, one job: represent the intensity of evasion required.

use serde::{Deserialize, Serialize};

/// How aggressively we need to evade.
///
/// Typically derived from per-host telemetry: the ratio of blocked to successful
/// requests (see `wafrift_strategy::host_state::HostState` where that logic lives).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum EscalationLevel {
    /// No evasion needed — requests go through.
    None,
    /// Light evasion — case alternation, basic encoding, header obfuscation.
    Light,
    /// Medium evasion — encoding + Content-Type switching + grammar mutations.
    Medium,
    /// Heavy evasion — all techniques layered together.
    Heavy,
}

impl EscalationLevel {
    /// Check if any evasion is needed at this level.
    #[must_use]
    pub fn needs_evasion(self) -> bool {
        !matches!(self, Self::None)
    }

    /// Check if grammar mutations should be applied at this level.
    #[must_use]
    pub fn use_grammar(self) -> bool {
        matches!(self, Self::Medium | Self::Heavy)
    }

    /// Check if content-type switching should be applied at this level.
    #[must_use]
    pub fn use_content_type(self) -> bool {
        matches!(self, Self::Medium | Self::Heavy)
    }

    /// Check if smuggling and H2 evasion should be applied at this level.
    #[must_use]
    pub fn use_advanced(self) -> bool {
        matches!(self, Self::Heavy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_needs_no_evasion() {
        assert!(!EscalationLevel::None.needs_evasion());
    }

    #[test]
    fn light_needs_evasion() {
        assert!(EscalationLevel::Light.needs_evasion());
    }

    #[test]
    fn grammar_at_medium_and_heavy() {
        assert!(!EscalationLevel::None.use_grammar());
        assert!(!EscalationLevel::Light.use_grammar());
        assert!(EscalationLevel::Medium.use_grammar());
        assert!(EscalationLevel::Heavy.use_grammar());
    }

    #[test]
    fn advanced_at_heavy_only() {
        assert!(!EscalationLevel::Medium.use_advanced());
        assert!(EscalationLevel::Heavy.use_advanced());
    }
}
