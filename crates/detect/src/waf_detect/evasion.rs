//! WAF-specific evasion recommendations.

use crate::waf_detect::rules;

/// Returns recommended evasion strategy names for a detected WAF.
///
/// Looks up the evasion list from the loaded TOML rule database.
/// If the WAF is not known, returns a balanced generic set.
///
/// Returns owned `String`s — the previous `&'static str` shape leaked
/// memory (one Box::leak per evasion string per call) and was wrong for
/// the per-response hot path.
#[must_use]
pub fn suggest_evasion(waf_name: &str) -> Vec<String> {
    rules::suggest_evasion(waf_name)
}
