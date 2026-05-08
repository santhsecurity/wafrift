//! TOML probe template loader for community-contributed smuggling variants.

use serde::Deserialize;
use std::path::Path;

/// Root container for smuggling probe templates.
#[derive(Debug, Clone, Deserialize)]
pub struct ProbeRuleFile {
    pub probe: Vec<ProbeTemplate>,
}

/// A single probe template describing a smuggling variant.
#[derive(Debug, Clone, Deserialize)]
pub struct ProbeTemplate {
    pub id: String,
    pub variant: String,
    pub description: String,
    pub method: String,
    pub path: String,
    pub headers: Vec<HeaderTemplate>,
    pub body: String,
    pub requires_feature: Option<String>,
}

/// Header template within a probe.
#[derive(Debug, Clone, Deserialize)]
pub struct HeaderTemplate {
    pub name: String,
    pub value: String,
}

/// Load probe templates from a TOML file.
///
/// # Errors
/// Returns an error if the file cannot be read or parsed.
pub fn load_templates<P: AsRef<Path>>(path: P) -> Result<ProbeRuleFile, RulesError> {
    let contents = std::fs::read_to_string(path)?;
    let file: ProbeRuleFile = toml::from_str(&contents)?;
    Ok(file)
}

/// Errors that can occur when loading rules.
#[derive(Debug, thiserror::Error)]
pub enum RulesError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("toml parse error: {0}")]
    Toml(#[from] toml::de::Error),
}

/// Validate that a loaded template has non-empty required fields.
pub fn validate_template(t: &ProbeTemplate) -> Result<(), RulesError> {
    if t.id.is_empty() || t.variant.is_empty() || t.method.is_empty() {
        return Err(RulesError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "probe template missing required fields",
        )));
    }
    Ok(())
}
