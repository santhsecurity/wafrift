//! WAF-specific evasion presets loaded from TOML rules.
//!
//! When a WAF is fingerprinted, this module provides the known-effective
//! bypass techniques and payloads to try first, dramatically reducing
//! the search space and time-to-bypass.

use serde::Deserialize;
use std::sync::OnceLock;

/// Compile-time embedded TOML for WAF presets.
const WAF_PRESETS_TOML: &str = include_str!("../../../rules/waf_presets.toml");

/// A single WAF evasion preset.
#[derive(Debug, Clone, Deserialize)]
pub struct WafPreset {
    /// WAF name (matches detect crate output).
    pub name: String,
    /// Ordered encoding strategy names to prioritize.
    pub techniques: Vec<String>,
    /// SQL-specific bypass payloads.
    #[serde(default)]
    pub sql_tricks: Vec<String>,
    /// XSS-specific bypass payloads.
    #[serde(default)]
    pub xss_tricks: Vec<String>,
    /// Operator notes for manual review.
    #[serde(default)]
    pub notes: String,
}

/// Root structure for the presets TOML.
#[derive(Debug, Clone, Deserialize)]
struct WafPresetsFile {
    #[serde(default)]
    waf_preset: Vec<WafPreset>,
}

/// Load all presets once at first access.
fn all_presets() -> &'static [WafPreset] {
    static PRESETS: OnceLock<Vec<WafPreset>> = OnceLock::new();
    PRESETS.get_or_init(|| {
        let file: WafPresetsFile = toml::from_str(WAF_PRESETS_TOML).unwrap_or_else(|e| {
            eprintln!("warn: invalid TOML in rules/waf_presets.toml: {e}");
            WafPresetsFile {
                waf_preset: Vec::new(),
            }
        });
        file.waf_preset
    })
}

/// Look up a preset by WAF name (case-insensitive).
///
/// Returns `None` if no preset exists for the given WAF.
#[must_use]
pub fn preset_for(waf_name: &str) -> Option<&'static WafPreset> {
    let name_lower = waf_name.to_ascii_lowercase();
    all_presets()
        .iter()
        .find(|p| p.name.to_ascii_lowercase() == name_lower)
}

/// List all known WAF preset names.
#[must_use]
pub fn known_wafs() -> Vec<&'static str> {
    all_presets().iter().map(|p| p.name.as_str()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_load_successfully() {
        let presets = all_presets();
        assert!(!presets.is_empty(), "should load at least one preset");
    }

    #[test]
    fn cloudflare_preset_exists() {
        let preset = preset_for("Cloudflare");
        assert!(preset.is_some());
        let p = preset.unwrap();
        assert!(!p.techniques.is_empty());
        assert!(!p.sql_tricks.is_empty());
    }

    #[test]
    fn modsecurity_preset_exists() {
        let preset = preset_for("ModSecurity");
        assert!(preset.is_some());
    }

    #[test]
    fn case_insensitive_lookup() {
        assert!(preset_for("cloudflare").is_some());
        assert!(preset_for("CLOUDFLARE").is_some());
    }

    #[test]
    fn unknown_waf_returns_none() {
        assert!(preset_for("NonExistentWAF").is_none());
    }

    #[test]
    fn known_wafs_list() {
        let wafs = known_wafs();
        assert!(wafs.contains(&"Cloudflare"));
        assert!(wafs.contains(&"ModSecurity"));
        assert!(wafs.contains(&"AWS WAF"));
    }

    #[test]
    fn all_presets_have_techniques() {
        for preset in all_presets() {
            assert!(
                !preset.techniques.is_empty(),
                "{} should have techniques",
                preset.name
            );
        }
    }
}
