//! TOML loading support for tamper strategies.

use std::collections::HashMap;

use super::{TamperError, TamperRegistry};

/// Configuration for tamper strategies loaded from TOML.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct StrategyConfig {
    /// Strategy name
    pub name: String,
    /// Whether this strategy is enabled
    pub enabled: bool,
    /// Optional context hints (e.g., ["sql", "xss"])
    pub contexts: Option<Vec<String>>,
    /// Custom parameters for the strategy
    pub params: Option<HashMap<String, toml::Value>>,
}

/// Full configuration for all tamper strategies.
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct TamperConfig {
    /// List of strategy configurations
    pub strategies: Vec<StrategyConfig>,
}

/// Hard cap on a single strategy-config TOML file. Real configs are
/// hundreds of bytes to a few KB; a pathological multi-MB file (or
/// an adversarial deeply-nested-table file aimed at the parser's
/// quadratic edge cases) would otherwise be loaded whole into RAM
/// and shoved at `toml::from_str` with no guardrail.
const STRATEGY_FILE_MAX_BYTES: u64 = 256 * 1024; // 256 KiB

/// UTF-8 text reader with the cap enforced DURING the read (so a
/// `/dev/zero` symlink cannot evade the size gate the way it would
/// with a `metadata()`-then-`read()` pattern). The advisory
/// `metadata()` gate in `load_toml` filters obvious giant files
/// without opening them; this function backstops it for the cases
/// metadata lies about (symlinks, races, posthumous file-replace).
fn read_capped_tamper_text(path: &std::path::Path, max_bytes: u64) -> std::io::Result<String> {
    use std::io::Read;
    let f = std::fs::File::open(path)?;
    let mut limited = f.take(max_bytes + 1);
    let mut buf = Vec::with_capacity(8 * 1024);
    limited.read_to_end(&mut buf)?;
    if (buf.len() as u64) > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{}: tamper config exceeds {}-byte cap",
                path.display(),
                max_bytes,
            ),
        ));
    }
    String::from_utf8(buf).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{}: tamper config is not valid UTF-8: {e}", path.display()),
        )
    })
}

impl TamperRegistry {
    /// Loads strategy configurations from a TOML file.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read, exceeds
    /// `STRATEGY_FILE_MAX_BYTES`, or fails TOML parsing.
    pub fn load_toml<P: AsRef<std::path::Path>>(
        &mut self,
        path: P,
    ) -> Result<TamperConfig, TamperError> {
        let path_ref = path.as_ref();

        // Cheap pre-check via file metadata avoids ever opening a
        // multi-GB tar pretending to be a TOML file. But metadata is
        // advisory only: a symlink to /dev/zero reports len=0 and
        // would pass this gate. The bounded read below is
        // authoritative — it enforces the cap DURING the read.
        let meta = std::fs::metadata(path_ref).map_err(|e| {
            TamperError::LoadError(format!("Failed to stat {}: {e}", path_ref.display()))
        })?;
        if meta.len() > STRATEGY_FILE_MAX_BYTES {
            return Err(TamperError::InvalidConfig(format!(
                "strategy file {} is {} bytes, exceeds {}-byte cap",
                path_ref.display(),
                meta.len(),
                STRATEGY_FILE_MAX_BYTES,
            )));
        }

        let content = read_capped_tamper_text(path_ref, STRATEGY_FILE_MAX_BYTES)
            .map_err(|e| TamperError::LoadError(format!("Failed to read file: {e}")))?;

        let config: TamperConfig = toml::from_str(&content)
            .map_err(|e| TamperError::InvalidConfig(format!("Failed to parse TOML: {e}")))?;

        Ok(config)
    }

    /// Applies all enabled strategies from a configuration.
    ///
    /// Strategies are applied in order of aggressiveness (least to most).
    pub fn apply_config(&self, payload: &str, config: &TamperConfig) -> Vec<(String, String)> {
        let mut results = Vec::new();

        for strategy_config in &config.strategies {
            if !strategy_config.enabled {
                continue;
            }

            if let Some(strategy) = self.get(&strategy_config.name) {
                let context = strategy_config
                    .contexts
                    .as_ref()
                    .and_then(|v| v.first().map(std::string::String::as_str));
                let result = if let Some(ref params) = strategy_config.params {
                    strategy.tamper_with_params(payload, context, params)
                } else {
                    strategy.tamper(payload, context)
                };
                results.push((strategy_config.name.clone(), result));
            }
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tamper_config_serialization() {
        let config = TamperConfig {
            strategies: vec![
                StrategyConfig {
                    name: "url_encode".to_string(),
                    enabled: true,
                    contexts: Some(vec!["sql".to_string(), "xss".to_string()]),
                    params: None,
                },
                StrategyConfig {
                    name: "base64".to_string(),
                    enabled: false,
                    contexts: None,
                    params: None,
                },
            ],
        };

        let toml_str = toml::to_string(&config).expect("Failed to serialize config");
        assert!(toml_str.contains("url_encode"));
        assert!(toml_str.contains("enabled = true"));
        assert!(toml_str.contains("enabled = false"));

        let deserialized: TamperConfig =
            toml::from_str(&toml_str).expect("Failed to deserialize config");
        assert_eq!(deserialized.strategies.len(), 2);
        assert!(deserialized.strategies[0].enabled);
        assert!(!deserialized.strategies[1].enabled);
    }

    #[test]
    fn apply_config_filters_disabled() {
        let registry = TamperRegistry::with_defaults();
        let config = TamperConfig {
            strategies: vec![
                StrategyConfig {
                    name: "url_encode".to_string(),
                    enabled: true,
                    contexts: None,
                    params: None,
                },
                StrategyConfig {
                    name: "base64".to_string(),
                    enabled: false,
                    contexts: None,
                    params: None,
                },
            ],
        };

        let results = registry.apply_config("test", &config);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "url_encode");
    }

    #[test]
    fn apply_config_with_context() {
        let registry = TamperRegistry::with_defaults();
        let config = TamperConfig {
            strategies: vec![StrategyConfig {
                name: "sql_comment".to_string(),
                enabled: true,
                contexts: Some(vec!["sql".to_string()]),
                params: None,
            }],
        };

        let results = registry.apply_config("SELECT * FROM", &config);
        assert_eq!(results.len(), 1);
        assert!(results[0].1.contains("/**/"));
    }

    #[test]
    fn strategy_config_roundtrip() {
        let config_str = r#"
[[strategies]]
name = "url_encode"
enabled = true
contexts = ["sql", "xss"]
"#;

        let config: TamperConfig = toml::from_str(config_str).expect("Failed to parse TOML");
        assert_eq!(config.strategies.len(), 1);
        assert_eq!(config.strategies[0].name, "url_encode");
        assert!(config.strategies[0].enabled);
        assert_eq!(
            config.strategies[0].contexts,
            Some(vec!["sql".to_string(), "xss".to_string()])
        );
    }

    #[test]
    fn load_toml_from_strategies_d() {
        let mut registry = TamperRegistry::with_defaults();
        let path = std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../strategies.d/core.toml"
        ));

        if path.exists() {
            let config = registry.load_toml(path).expect("Failed to load core.toml");
            let has_url_encode = config
                .strategies
                .iter()
                .any(|s| s.name == "url_encode" && s.enabled);
            assert!(has_url_encode, "core.toml should have url_encode enabled");
        }
    }

    #[test]
    fn tamper_error_invalid_toml() {
        let mut registry = TamperRegistry::with_defaults();
        let invalid_toml = "not valid toml [[";

        // Use a unique suffix to avoid races when `cargo test` runs this
        // test in parallel with other process instances.
        let temp_file = std::env::temp_dir().join(format!(
            "wafrift-invalid-toml-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        std::fs::write(&temp_file, invalid_toml).unwrap();

        let result = registry.load_toml(&temp_file);
        assert!(matches!(result, Err(TamperError::InvalidConfig(_))));

        std::fs::remove_file(&temp_file).ok();
    }

    #[test]
    fn tamper_error_missing_file() {
        let mut registry = TamperRegistry::with_defaults();
        let result = registry.load_toml("/nonexistent/path/file.toml");
        assert!(matches!(result, Err(TamperError::LoadError(_))));
    }

    #[test]
    fn layered_tamper_chain() {
        let registry = TamperRegistry::with_defaults();
        let config = TamperConfig {
            strategies: vec![
                StrategyConfig {
                    name: "case_alternation".to_string(),
                    enabled: true,
                    contexts: None,
                    params: None,
                },
                StrategyConfig {
                    name: "url_encode".to_string(),
                    enabled: true,
                    contexts: None,
                    params: None,
                },
            ],
        };

        let results = registry.apply_config("select <", &config);
        assert_eq!(results.len(), 2);

        assert!(results.iter().any(|(n, _)| n == "case_alternation"));
        assert!(results.iter().any(|(n, _)| n == "url_encode"));

        let url_result = results.iter().find(|(n, _)| n == "url_encode").unwrap();
        assert!(url_result.1.contains('%'));
    }

    #[test]
    fn tamper_strategy_trait_object_safety() {
        let strategies: Vec<Box<dyn super::super::TamperStrategy>> = vec![
            Box::new(super::super::UrlEncodeTamper),
            Box::new(super::super::Base64Tamper),
            Box::new(super::super::CaseAlternationTamper),
        ];

        for strategy in &strategies {
            let result = strategy.tamper("test", None);
            assert!(!result.is_empty());
            assert!(strategy.aggressiveness() >= 0.0 && strategy.aggressiveness() <= 1.0);
        }
    }

    #[test]
    fn custom_strategy_params() {
        let config = StrategyConfig {
            name: "custom".to_string(),
            enabled: true,
            contexts: None,
            params: {
                let mut map = std::collections::HashMap::new();
                map.insert("level".to_string(), toml::Value::Integer(5));
                map.insert(
                    "prefix".to_string(),
                    toml::Value::String("test_".to_string()),
                );
                Some(map)
            },
        };

        assert!(config.params.is_some());
        let params = config.params.as_ref().unwrap();
        assert_eq!(params.get("level").unwrap().as_integer(), Some(5));
        assert_eq!(params.get("prefix").unwrap().as_str(), Some("test_"));
    }
}
