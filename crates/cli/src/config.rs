//! TOML configuration file support for WafRift.
//!
//! Config files are loaded in priority order (CLI flags > env vars > file):
//!   1. `.wafrift.toml` in the current directory
//!   2. `~/.config/wafrift/config.toml`
//!
//! Any field left unset in the config file uses compiled defaults.

use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Operational configuration (Tier A) — runtime behavior tuning.
#[allow(dead_code)] // Infrastructure: will be wired to CLI in next pass
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct WafRiftConfig {
    /// Default scan settings.
    pub scan: ScanConfig,
    /// HTTP transport settings.
    pub http: HttpConfig,
    /// Output settings.
    pub output: OutputConfig,
}

/// Scan-related configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    /// Default evasion intensity: "light", "medium", or "heavy".
    pub level: String,
    /// Default query parameter name for injection.
    pub param: String,
    /// Delay between requests in milliseconds.
    pub delay_ms: u64,
    /// Apply encoding only (no grammar mutations).
    pub encoding_only: bool,
    /// Concurrency level for parallel variant firing.
    pub concurrency: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            level: String::from("heavy"),
            param: String::from("q"),
            delay_ms: 50,
            encoding_only: false,
            concurrency: 8,
        }
    }
}

/// HTTP transport configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct HttpConfig {
    /// Browser fingerprint to impersonate.
    pub stealth_browser: Option<String>,
    /// Disable TLS certificate verification.
    pub insecure: bool,
    /// Custom User-Agent header.
    pub user_agent: Option<String>,
    /// Request timeout in seconds.
    pub timeout_secs: u64,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            stealth_browser: None,
            insecure: false,
            user_agent: None,
            timeout_secs: 30,
        }
    }
}

/// Output configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct OutputConfig {
    /// Default output format: "text" or "json".
    pub format: String,
    /// Include layer report in JSON output.
    pub report_layers: bool,
    /// Suppress human-readable output.
    pub quiet: bool,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: String::from("text"),
            report_layers: false,
            quiet: false,
        }
    }
}

impl WafRiftConfig {
    /// Load configuration from the standard search paths.
    ///
    /// Search order:
    /// 1. `.wafrift.toml` in the current working directory
    /// 2. `~/.config/wafrift/config.toml`
    ///
    /// Returns `Default` if no config file is found.
    #[allow(dead_code)] // Infrastructure: will be wired to CLI in next pass
    pub fn load() -> Self {
        // Try current directory first.
        let cwd_config = PathBuf::from(".wafrift.toml");
        if let Ok(config) = Self::load_from(&cwd_config) {
            return config;
        }

        // Try XDG / home config.
        if let Some(config_dir) = dirs::config_dir() {
            let home_config = config_dir.join("wafrift").join("config.toml");
            if let Ok(config) = Self::load_from(&home_config) {
                return config;
            }
        }

        Self::default()
    }

    /// Load configuration from a specific file path.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or parsed.
    pub fn load_from(path: &Path) -> Result<Self, String> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read config at {}: {e}", path.display()))?;
        toml::from_str(&contents)
            .map_err(|e| format!("failed to parse config at {}: {e}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = WafRiftConfig::default();
        assert_eq!(config.scan.level, "heavy");
        assert_eq!(config.scan.param, "q");
        assert_eq!(config.scan.delay_ms, 50);
        assert!(!config.scan.encoding_only);
        assert_eq!(config.scan.concurrency, 8);
        assert!(!config.http.insecure);
        assert_eq!(config.output.format, "text");
    }

    #[test]
    fn parse_toml_config() {
        let toml_str = r#"
[scan]
level = "light"
param = "id"
delay_ms = 100
encoding_only = true
concurrency = 4

[http]
insecure = true
stealth_browser = "chrome"
user_agent = "WafRift/1.0"
timeout_secs = 60

[output]
format = "json"
report_layers = true
quiet = true
"#;
        let config: WafRiftConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.scan.level, "light");
        assert_eq!(config.scan.param, "id");
        assert_eq!(config.scan.delay_ms, 100);
        assert!(config.scan.encoding_only);
        assert_eq!(config.scan.concurrency, 4);
        assert!(config.http.insecure);
        assert_eq!(config.http.stealth_browser.as_deref(), Some("chrome"));
        assert_eq!(config.http.user_agent.as_deref(), Some("WafRift/1.0"));
        assert_eq!(config.http.timeout_secs, 60);
        assert_eq!(config.output.format, "json");
        assert!(config.output.report_layers);
        assert!(config.output.quiet);
    }

    #[test]
    fn partial_toml_uses_defaults() {
        let toml_str = r#"
[scan]
delay_ms = 200
"#;
        let config: WafRiftConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.scan.delay_ms, 200);
        // Everything else should use defaults.
        assert_eq!(config.scan.level, "heavy");
        assert_eq!(config.scan.param, "q");
        assert!(!config.http.insecure);
        assert_eq!(config.output.format, "text");
    }

    #[test]
    fn empty_toml_uses_all_defaults() {
        let config: WafRiftConfig = toml::from_str("").unwrap();
        assert_eq!(config.scan.level, "heavy");
        assert_eq!(config.scan.param, "q");
        assert_eq!(config.scan.delay_ms, 50);
    }

    #[test]
    fn load_nonexistent_file_errors() {
        let result = WafRiftConfig::load_from(std::path::Path::new("/nonexistent/config.toml"));
        assert!(result.is_err());
    }
}
