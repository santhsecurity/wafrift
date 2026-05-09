//! Evasion configuration — knobs for the strategy engine.
//!
//! One struct, one job: controls which evasion layers are enabled
//! and how aggressively the engine escalates.

use serde::{Deserialize, Serialize};

/// Evasion configuration.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionConfig {
    /// Enable payload encoding transformations.
    pub encoding_enabled: bool,
    /// Enable Content-Type switching (form → JSON, XML, multipart).
    pub content_type_switching: bool,
    /// Enable browser fingerprint rotation (User-Agent, Accept, etc.).
    pub fingerprint_rotation: bool,
    /// Enable header obfuscation (case mixing, tab separators, folding).
    pub header_obfuscation: bool,
    /// Enable grammar-aware payload mutation (SQL/XSS/CMD transforms).
    pub grammar_mutations: bool,
    /// Enable request smuggling metadata generation.
    pub smuggling_enabled: bool,
    /// Enable HTTP/2 evasion metadata generation.
    pub h2_evasion_enabled: bool,
    /// Maximum evasion retry attempts before giving up.
    pub max_attempts: u32,
    /// Disable TLS verification (danger_accept_invalid_certs).
    pub insecure_tls: bool,
    /// Proxies for round-robin IP rotation.
    #[serde(default)]
    pub proxies: Vec<String>,
    /// Manual origin bypass mapping from Host to IP.
    #[serde(default)]
    pub origin_bypass: std::collections::HashMap<String, std::net::IpAddr>,
}

impl Default for EvasionConfig {
    fn default() -> Self {
        Self {
            encoding_enabled: true,
            content_type_switching: true,
            fingerprint_rotation: true,
            header_obfuscation: true,
            grammar_mutations: true,
            smuggling_enabled: true,
            h2_evasion_enabled: true,
            max_attempts: 5,
            insecure_tls: false,
            proxies: Vec::new(),
            origin_bypass: std::collections::HashMap::new(),
        }
    }
}

impl EvasionConfig {
    /// Create a minimal config with only encoding enabled.
    #[must_use]
    pub fn encoding_only() -> Self {
        Self {
            encoding_enabled: true,
            content_type_switching: false,
            fingerprint_rotation: false,
            header_obfuscation: false,
            grammar_mutations: false,
            smuggling_enabled: false,
            h2_evasion_enabled: false,
            max_attempts: 3,
            insecure_tls: false,
            proxies: Vec::new(),
            origin_bypass: std::collections::HashMap::new(),
        }
    }

    /// Create a maximum-aggression config with everything enabled.
    #[must_use]
    pub fn maximum() -> Self {
        Self {
            encoding_enabled: true,
            content_type_switching: true,
            fingerprint_rotation: true,
            header_obfuscation: true,
            grammar_mutations: true,
            smuggling_enabled: true,
            h2_evasion_enabled: true,
            max_attempts: 10,
            insecure_tls: false,
            proxies: Vec::new(),
            origin_bypass: std::collections::HashMap::new(),
        }
    }

    /// Validate the configuration for conflicts or missing dependencies.
    pub fn validate(&self) -> Result<(), String> {
        if self.insecure_tls {
            tracing::warn!(
                "TLS certificate validation is disabled (--insecure-tls). Do not use in production."
            );
        }

        if self.grammar_mutations && !self.encoding_enabled {
            tracing::warn!(
                "Grammar mutations are enabled but encoding is disabled. Mutations may require encoding to bypass effectively."
            );
        }

        if self.max_attempts == 0 {
            return Err("max_attempts must be greater than 0".to_string());
        }

        self.validate_proxies()?;

        Ok(())
    }

    /// Validate the format of proxies.
    fn validate_proxies(&self) -> Result<(), String> {
        for proxy in &self.proxies {
            if !proxy.starts_with("http://")
                && !proxy.starts_with("https://")
                && !proxy.starts_with("socks5://")
                && !proxy.starts_with("socks5h://")
            {
                return Err(format!(
                    "Invalid proxy URL '{}': must start with http://, https://, socks5://, or socks5h://",
                    proxy
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_all_enabled() {
        let config = EvasionConfig::default();
        assert!(config.encoding_enabled);
        assert!(config.content_type_switching);
        assert!(config.fingerprint_rotation);
        assert!(config.header_obfuscation);
        assert!(config.grammar_mutations);
        assert!(config.smuggling_enabled);
        assert!(config.h2_evasion_enabled);
        assert_eq!(config.max_attempts, 5);
        assert!(!config.insecure_tls);
    }

    #[test]
    fn encoding_only_config() {
        let config = EvasionConfig::encoding_only();
        assert!(config.encoding_enabled);
        assert!(!config.content_type_switching);
        assert!(!config.grammar_mutations);
    }

    #[test]
    fn maximum_config() {
        let config = EvasionConfig::maximum();
        assert!(config.grammar_mutations);
        assert_eq!(config.max_attempts, 10);
    }

    #[test]
    fn config_serde_roundtrip() {
        let config = EvasionConfig::default();
        let json = serde_json::to_string(&config).expect("serialize");
        let deserialized: EvasionConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.max_attempts, config.max_attempts);
    }
}
