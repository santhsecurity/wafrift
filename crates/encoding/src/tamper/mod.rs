//! Payload tampering strategies — advanced payload transformations beyond basic encoding.
//!
//! Tamper strategies combine multiple transformations in sophisticated ways
//! to bypass WAF rules that simple encoding cannot evade.

use std::collections::HashMap;

mod builtins;
mod config;

pub use builtins::*;
pub use config::{StrategyConfig, TamperConfig};

/// A tamper strategy transforms a payload for WAF evasion.
///
/// Unlike basic encoding, tamper strategies may use contextual knowledge
/// about the target (SQL, XSS, etc.) to apply targeted transformations.
pub trait TamperStrategy: Send + Sync {
    /// Returns the unique name of this tamper strategy.
    fn name(&self) -> &'static str;

    /// Returns a description of what this strategy does.
    fn description(&self) -> &'static str;

    /// Transforms the input payload.
    ///
    /// # Arguments
    /// * `payload` - The input payload to transform
    /// * `context` - Optional context about the payload (e.g., "sql", "xss")
    fn tamper(&self, payload: &str, context: Option<&str>) -> String;

    /// Transforms the input payload with custom parameters.
    ///
    /// Default implementation delegates to [`Self::tamper`].
    fn tamper_with_params(
        &self,
        payload: &str,
        context: Option<&str>,
        _params: &HashMap<String, toml::Value>,
    ) -> String {
        self.tamper(payload, context)
    }

    /// Returns the aggressiveness score (0.0 = mild, 1.0 = extreme).
    fn aggressiveness(&self) -> f64;
}

/// Registry of all available tamper strategies.
#[derive(Default)]
pub struct TamperRegistry {
    strategies: HashMap<String, Box<dyn TamperStrategy>>,
}

/// Built-in tamper strategy names.
const DEFAULT_NAMES: &[&str] = &[
    "url_encode",
    "double_url_encode",
    "unicode_escape",
    "html_entity",
    "case_alternation",
    "random_case",
    "whitespace_insertion",
    "sql_comment",
    "null_byte",
    "overlong_utf8",
    "base64",
    "hex_encode",
];

impl TamperRegistry {
    /// Creates a new empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            strategies: HashMap::new(),
        }
    }

    /// Creates a new registry with all built-in strategies registered.
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut registry = Self::new();
        for name in DEFAULT_NAMES {
            match *name {
                "url_encode" => registry.register(Box::new(UrlEncodeTamper)),
                "double_url_encode" => registry.register(Box::new(DoubleUrlEncodeTamper)),
                "unicode_escape" => registry.register(Box::new(UnicodeEscapeTamper)),
                "html_entity" => registry.register(Box::new(HtmlEntityTamper)),
                "case_alternation" => registry.register(Box::new(CaseAlternationTamper)),
                "random_case" => registry.register(Box::new(RandomCaseTamper)),
                "whitespace_insertion" => registry.register(Box::new(WhitespaceInsertionTamper)),
                "sql_comment" => registry.register(Box::new(SqlCommentTamper)),
                "null_byte" => registry.register(Box::new(NullByteTamper)),
                "overlong_utf8" => registry.register(Box::new(OverlongUtf8Tamper)),
                "base64" => registry.register(Box::new(Base64Tamper)),
                "hex_encode" => registry.register(Box::new(HexEncodeTamper)),
                _ => {}
            }
        }
        registry
    }

    /// Registers a tamper strategy.
    pub fn register(&mut self, strategy: Box<dyn TamperStrategy>) {
        self.strategies
            .insert(strategy.name().to_string(), strategy);
    }

    /// Unregisters a tamper strategy by name.
    pub fn unregister(&mut self, name: &str) -> Option<Box<dyn TamperStrategy>> {
        self.strategies.remove(name)
    }

    /// Clears all registered strategies.
    pub fn clear(&mut self) {
        self.strategies.clear();
    }

    /// Gets a strategy by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&dyn TamperStrategy> {
        self.strategies.get(name).map(std::convert::AsRef::as_ref)
    }

    /// Returns all registered strategy names.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.strategies.keys().map(std::string::String::as_str).collect()
    }

    /// Returns all strategies sorted by aggressiveness (least to most).
    #[must_use]
    pub fn by_aggressiveness(&self) -> Vec<&dyn TamperStrategy> {
        let mut strategies: Vec<&dyn TamperStrategy> =
            self.strategies.values().map(std::convert::AsRef::as_ref).collect();
        strategies.sort_by(|a, b| {
            let a_score = if a.aggressiveness().is_nan() {
                1.0
            } else {
                a.aggressiveness()
            };
            let b_score = if b.aggressiveness().is_nan() {
                1.0
            } else {
                b.aggressiveness()
            };
            a_score
                .partial_cmp(&b_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        strategies
    }

    /// Applies a named strategy to a payload.
    ///
    /// # Errors
    /// Returns an error if the strategy is not found.
    pub fn tamper_with(
        &self,
        name: &str,
        payload: &str,
        context: Option<&str>,
    ) -> Result<String, TamperError> {
        self.get(name)
            .map(|s| s.tamper(payload, context))
            .ok_or_else(|| TamperError::StrategyNotFound(name.to_string()))
    }

    /// Applies a named strategy with parameters.
    ///
    /// # Errors
    /// Returns an error if the strategy is not found.
    pub fn tamper_with_params(
        &self,
        name: &str,
        payload: &str,
        context: Option<&str>,
        params: &HashMap<String, toml::Value>,
    ) -> Result<String, TamperError> {
        self.get(name)
            .map(|s| s.tamper_with_params(payload, context, params))
            .ok_or_else(|| TamperError::StrategyNotFound(name.to_string()))
    }
}

/// Errors that can occur during tampering.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TamperError {
    /// The requested strategy was not found in the registry.
    #[error("Strategy not found: {0}")]
    StrategyNotFound(String),
    /// The TOML configuration is invalid.
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    /// Failed to load strategies from file.
    #[error("Failed to load strategies: {0}")]
    LoadError(String),
}

/// Creates a registry with all default strategies.
#[must_use]
pub fn default_registry() -> TamperRegistry {
    TamperRegistry::with_defaults()
}

/// Apply a single tamper strategy by name.
///
/// # Errors
/// Returns an error if the strategy name is not recognized.
pub fn tamper(strategy: &str, payload: &str, context: Option<&str>) -> Result<String, TamperError> {
    let registry = default_registry();
    registry.tamper_with(strategy, payload, context)
}

/// Get all available tamper strategy names.
#[must_use]
pub fn all_tamper_names() -> &'static [&'static str] {
    DEFAULT_NAMES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_with_defaults_has_strategies() {
        let registry = TamperRegistry::with_defaults();
        assert!(!registry.names().is_empty());
        assert!(registry.get("url_encode").is_some());
        assert!(registry.get("base64").is_some());
    }

    #[test]
    fn registry_lookup_fails_for_unknown() {
        let registry = TamperRegistry::with_defaults();
        assert!(registry.get("unknown_strategy").is_none());
    }

    #[test]
    fn tamper_with_error_for_unknown() {
        let registry = TamperRegistry::with_defaults();
        let result = registry.tamper_with("unknown", "payload", None);
        assert!(matches!(result, Err(TamperError::StrategyNotFound(_))));
    }

    #[test]
    fn aggressiveness_sorting() {
        let registry = TamperRegistry::with_defaults();
        let strategies = registry.by_aggressiveness();
        for i in 1..strategies.len() {
            assert!(
                strategies[i - 1].aggressiveness() <= strategies[i].aggressiveness(),
                "Strategies should be sorted by aggressiveness"
            );
        }
    }

    #[test]
    fn unregister_removes_strategy() {
        let mut registry = TamperRegistry::with_defaults();
        assert!(registry.get("url_encode").is_some());
        let removed = registry.unregister("url_encode");
        assert!(removed.is_some());
        assert!(registry.get("url_encode").is_none());
    }

    #[test]
    fn clear_removes_all() {
        let mut registry = TamperRegistry::with_defaults();
        registry.clear();
        assert!(registry.names().is_empty());
    }

    #[test]
    fn nan_aggressiveness_treated_as_one() {
        struct NaNStrategy;
        impl TamperStrategy for NaNStrategy {
            fn name(&self) -> &'static str {
                "nan_test"
            }
            fn description(&self) -> &'static str {
                "test"
            }
            fn tamper(&self, _p: &str, _c: Option<&str>) -> String {
                "test".to_string()
            }
            fn aggressiveness(&self) -> f64 {
                f64::NAN
            }
        }
        let mut registry = TamperRegistry::new();
        registry.register(Box::new(NaNStrategy));
        let sorted = registry.by_aggressiveness();
        assert_eq!(sorted.len(), 1);
    }

    #[test]
    fn all_tamper_names_static() {
        let names = all_tamper_names();
        assert!(!names.is_empty());
        assert!(names.contains(&"url_encode"));
    }

    #[test]
    fn tamper_error_display() {
        let err = TamperError::StrategyNotFound("test".to_string());
        assert_eq!(format!("{err}"), "Strategy not found: test");
    }

    #[test]
    fn default_registry_function() {
        let registry = default_registry();
        assert!(!registry.names().is_empty());
    }

    #[test]
    fn convenience_tamper_function() {
        let result = tamper("url_encode", "test!", None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test%21");
    }

    #[test]
    fn convenience_tamper_function_error() {
        let result = tamper("unknown", "test", None);
        assert!(result.is_err());
    }
}
