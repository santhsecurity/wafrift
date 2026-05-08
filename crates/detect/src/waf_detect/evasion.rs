//! WAF-specific evasion recommendations.

use crate::waf_detect::rules;

/// Returns recommended evasion strategy names for a detected WAF.
///
/// Looks up the evasion list from the loaded TOML rule database.
/// If the WAF is not known, returns a balanced generic set.
#[must_use]
pub fn suggest_evasion(waf_name: &str) -> Vec<&'static str> {
    rules::suggest_evasion(waf_name)
}
