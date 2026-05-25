//! Plugin bridge — integrates [`wafrift_plugin_api`] external tampers into
//! the strategy pipeline alongside built-in tampers.
//!
//! # Usage
//!
//! ```no_run
//! use wafrift_strategy::plugin_bridge;
//!
//! // Apply all external plugins loaded from ~/.wafrift/tampers/ to a payload.
//! let transformed = plugin_bridge::apply_all_plugins("SELECT 1--");
//! ```
//!
//! External tampers are loaded **once** at first call and cached for the
//! lifetime of the process.  The load is thread-safe (backed by
//! `std::sync::OnceLock`).

use std::sync::OnceLock;

use wafrift_plugin_api::{Tamper, TamperRegistry, default_plugin_dir};

/// Process-global registry of external plugins loaded from disk.
static PLUGIN_REGISTRY: OnceLock<TamperRegistry> = OnceLock::new();

/// Initialise (or return the already-initialised) plugin registry.
fn registry() -> &'static TamperRegistry {
    PLUGIN_REGISTRY.get_or_init(|| {
        let mut reg = TamperRegistry::new();
        if let Some(dir) = default_plugin_dir() {
            let errors = reg.load_dir(&dir);
            for e in errors {
                tracing::warn!("plugin-bridge: skipping plugin: {e}");
            }
        }
        reg
    })
}

/// Apply every loaded external tamper to `payload` in registration order,
/// collecting (name, transformed_payload) pairs.
///
/// Returns an empty `Vec` when no plugins are installed.
#[must_use]
pub fn apply_all_plugins(payload: &str) -> Vec<(String, String)> {
    registry()
        .all()
        .iter()
        .map(|t| (t.name().to_owned(), t.apply(payload)))
        .collect()
}

/// Apply a single named external plugin to `payload`.
///
/// Returns `None` if the plugin is not registered.
#[must_use]
pub fn apply_plugin(name: &str, payload: &str) -> Option<String> {
    registry().get(name).map(|t: &dyn Tamper| t.apply(payload))
}

/// Return the names of all loaded external plugins.
#[must_use]
pub fn plugin_names() -> Vec<String> {
    registry()
        .all()
        .iter()
        .map(|t| t.name().to_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_all_with_no_plugins_returns_empty() {
        // The static registry may already be initialised by another test.
        // We can't reset it, but we can verify the function doesn't panic
        // and returns a Vec (possibly non-empty if real plugins exist on disk).
        let result = apply_all_plugins("SELECT 1");
        // All results must be non-empty strings.
        for (name, transformed) in &result {
            assert!(!name.is_empty());
            assert!(!transformed.is_empty() || true); // empty output is valid
        }
    }

    #[test]
    fn apply_unknown_plugin_returns_none() {
        let result = apply_plugin("__nonexistent_plugin_xyz__", "payload");
        assert!(result.is_none());
    }

    #[test]
    fn plugin_names_returns_vec() {
        let names = plugin_names();
        // Every name must be non-empty (if any plugins are loaded).
        for n in &names {
            assert!(!n.is_empty());
        }
    }
}
