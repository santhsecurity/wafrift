//! WAF classification by architectural backing — governs which evasion
//! sub-engines are activated for a given target.
//!
//! The distinction that matters for evasion is *how the WAF makes its
//! decision*:
//!
//! - **Rule-based WAFs** (ModSecurity/Coraza, Cloudflare Managed Rules,
//!   AWS Core Rule Set) maintain a finite set of regex/signature rules and
//!   score them with a threshold. Dilution attacks exploit the multi-group
//!   scoring; the `ensemble_dilution` module handles these.
//!
//! - **ML-backed WAFs** (AWS Bot Control, Cloudflare Bot Management,
//!   Akamai Bot Manager, Datadome) run a learned classifier — there is no
//!   rule to learn, only a decision boundary. The `mlwaf::evade_ml`
//!   decision-based boundary attack handles these.
//!
//! Variants marked `#[non_exhaustive]` so adding a new WAF family is a
//! backwards-compatible source change (callers must handle `_` arms).

use serde::{Deserialize, Serialize};

/// High-level WAF architectural class.
///
/// Used by the strategy engine to select the appropriate evasion sub-engine.
/// Adding a new variant here requires only:
/// 1. A match arm in `strategy::evade_ml_backed` (one file).
/// 2. A detection rule in `detect/rules/detect/` (one TOML block).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum WafClass {
    // ── Rule-based (anomaly-scoring) ──────────────────────────────────
    /// ModSecurity CRS or Coraza with anomaly scoring.
    PlainModSec,
    /// Cloudflare Managed Rules (CF WAF) — multi-group anomaly scoring.
    /// Ensemble dilution is applicable.
    CloudflareManagedRules,
    /// AWS Core Rule Set — multi-group anomaly scoring.
    /// Ensemble dilution is applicable.
    AwsCoreRuleSet,
    /// Generic OWASP CRS-based WAF (unknown vendor but CRS-shaped).
    GenericCrs,

    // ── ML-backed (classifier) ────────────────────────────────────────
    /// AWS Bot Control — ML-classifier WAF from AWS.
    /// `mlwaf::evade_ml` is the primary attack engine.
    AwsBotControl,
    /// Cloudflare Bot Management — ML-classifier WAF from Cloudflare.
    /// `mlwaf::evade_ml` is the primary attack engine.
    CloudflareBotMgmt,
    /// Akamai Bot Manager — ML-classifier WAF from Akamai.
    /// `mlwaf::evade_ml` is the primary attack engine.
    AkamaiBotManager,
    /// Datadome — ML-classifier bot-protection service.
    Datadome,

    // ── Unknown / unclassified ────────────────────────────────────────
    /// WAF detected but architectural class unknown.
    Unknown,
}

impl WafClass {
    /// Returns `true` if this WAF uses a learned classifier rather than
    /// rule-based anomaly scoring. When `true`, `mlwaf::evade_ml` should
    /// be invoked instead of (or in addition to) the heuristic pipeline.
    #[must_use]
    pub fn is_ml_backed(self) -> bool {
        matches!(
            self,
            Self::AwsBotControl | Self::CloudflareBotMgmt | Self::AkamaiBotManager | Self::Datadome
        )
    }

    /// Returns `true` if this WAF uses multi-rule-group ensemble scoring.
    /// When `true`, `ensemble_dilution` scoring should be blended into
    /// the evolutionary fitness function.
    #[must_use]
    pub fn is_ensemble(self) -> bool {
        matches!(
            self,
            Self::CloudflareManagedRules | Self::AwsCoreRuleSet | Self::GenericCrs
        )
    }

    /// Infer a `WafClass` from a detected WAF name string (case-insensitive).
    ///
    /// Uses substring matching rather than an exact-name registry so that
    /// variant vendor names ("Cloudflare WAF", "cf-managed", ...) resolve
    /// correctly without a maintenance table.
    #[must_use]
    pub fn from_waf_name(name: &str) -> Self {
        let lower = name.to_ascii_lowercase();
        // ML-backed checks first — more specific.
        if lower.contains("bot control") || lower.contains("botcontrol") {
            return Self::AwsBotControl;
        }
        if lower.contains("bot management") || lower.contains("botmanagement") {
            return Self::CloudflareBotMgmt;
        }
        if lower.contains("bot manager") || lower.contains("botmanager") {
            return Self::AkamaiBotManager;
        }
        if lower.contains("datadome") {
            return Self::Datadome;
        }
        // Rule-based ensemble.
        if lower.contains("cloudflare") {
            return Self::CloudflareManagedRules;
        }
        if lower.contains("aws") || lower.contains("amazon") {
            return Self::AwsCoreRuleSet;
        }
        if lower.contains("modsec") || lower.contains("coraza") {
            return Self::PlainModSec;
        }
        if lower.contains("owasp") || lower.contains("crs") {
            return Self::GenericCrs;
        }
        Self::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ml_backed_variants_identified() {
        assert!(WafClass::AwsBotControl.is_ml_backed());
        assert!(WafClass::CloudflareBotMgmt.is_ml_backed());
        assert!(WafClass::AkamaiBotManager.is_ml_backed());
        assert!(WafClass::Datadome.is_ml_backed());
    }

    #[test]
    fn rule_based_not_ml() {
        assert!(!WafClass::PlainModSec.is_ml_backed());
        assert!(!WafClass::CloudflareManagedRules.is_ml_backed());
        assert!(!WafClass::AwsCoreRuleSet.is_ml_backed());
        assert!(!WafClass::Unknown.is_ml_backed());
    }

    #[test]
    fn ensemble_variants_identified() {
        assert!(WafClass::CloudflareManagedRules.is_ensemble());
        assert!(WafClass::AwsCoreRuleSet.is_ensemble());
        assert!(WafClass::GenericCrs.is_ensemble());
    }

    #[test]
    fn ml_backed_not_ensemble() {
        assert!(!WafClass::AwsBotControl.is_ensemble());
        assert!(!WafClass::CloudflareBotMgmt.is_ensemble());
    }

    #[test]
    fn from_waf_name_cloudflare() {
        assert_eq!(
            WafClass::from_waf_name("Cloudflare WAF"),
            WafClass::CloudflareManagedRules
        );
    }

    #[test]
    fn from_waf_name_aws_bot_control() {
        assert_eq!(
            WafClass::from_waf_name("AWS Bot Control"),
            WafClass::AwsBotControl
        );
    }

    #[test]
    fn from_waf_name_akamai_bot_manager() {
        assert_eq!(
            WafClass::from_waf_name("Akamai Bot Manager"),
            WafClass::AkamaiBotManager
        );
    }

    #[test]
    fn from_waf_name_unknown() {
        assert_eq!(
            WafClass::from_waf_name("SomeUnknownThing"),
            WafClass::Unknown
        );
    }

    #[test]
    fn serde_roundtrip() {
        let classes = [
            WafClass::AwsBotControl,
            WafClass::CloudflareBotMgmt,
            WafClass::PlainModSec,
            WafClass::Unknown,
        ];
        for cls in classes {
            let s = serde_json::to_string(&cls).expect("serialize");
            let back: WafClass = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(cls, back);
        }
    }
}
