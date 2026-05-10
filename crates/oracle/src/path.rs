//! Path traversal payload oracle.
//!
//! Path traversal payloads navigate the filesystem by using `../` sequences
//! and target sensitive files. The oracle validates that:
//! 1. **Traversal sequences survive** — `../` or encoded equivalents
//! 2. **Target paths remain readable** — `/etc/passwd`, `/etc/shadow`, etc.
//!
//! If encoding destroys the `../` sequences or the target path, the
//! server won't resolve the file and the traversal fails.

use crate::ascii_scan::contains_ascii_insensitive;
use crate::traits::PayloadOracle;
use serde::Deserialize;
use std::sync::OnceLock;

/// Path traversal oracle that validates directory escape sequences.
pub struct PathOracle;

// ──────────────────────────────────────────────
//  TOML-loaded path traversal rules
// ──────────────────────────────────────────────

/// Compile-time embedded TOML rules for path traversal.
const PATH_TRAVERSAL_TOML: &str = include_str!("../rules/path_traversal/sequences.toml");

/// Traversal sequence definition from TOML.
#[derive(Debug, Clone, Deserialize)]
struct TraversalSequence {
    sequence: String,
    #[allow(dead_code)]
    description: String,
    #[allow(dead_code)]
    encoding: String,
}

/// Target file definition from TOML.
#[derive(Debug, Clone, Deserialize)]
struct TargetFile {
    path: String,
    #[allow(dead_code)]
    description: String,
    #[allow(dead_code)]
    os: String,
}

/// Root structure for sequences.toml.
#[derive(Debug, Clone, Deserialize)]
struct PathTraversalRules {
    #[serde(default)]
    traversal_sequence: Vec<TraversalSequence>,
    #[serde(default)]
    target_file: Vec<TargetFile>,
}

/// Parse the embedded TOML rules once at first access.
fn get_rules() -> &'static PathTraversalRules {
    static RULES: OnceLock<PathTraversalRules> = OnceLock::new();
    RULES.get_or_init(|| {
        toml::from_str(PATH_TRAVERSAL_TOML).unwrap_or_else(|_| {
            PathTraversalRules { traversal_sequence: Vec::new(), target_file: Vec::new() }
        })
    })
}

/// Get traversal sequences (various encodings that servers may decode).
fn traversal_sequences() -> &'static [String] {
    static CACHE: OnceLock<Vec<String>> = OnceLock::new();
    CACHE.get_or_init(|| {
        get_rules()
            .traversal_sequence
            .iter()
            .map(|s| s.sequence.clone())
            .collect()
    })
}

/// Get common target files for path traversal.
fn target_files() -> &'static [String] {
    static CACHE: OnceLock<Vec<String>> = OnceLock::new();
    CACHE.get_or_init(|| {
        get_rules()
            .target_file
            .iter()
            .map(|f| f.path.clone())
            .collect()
    })
}

/// Quick reject: traversal probes always involve `.`, `%`, `\`, or `/`.
fn may_contain_traversal_bytes(payload: &str) -> bool {
    payload
        .as_bytes()
        .iter()
        .any(|&x| matches!(x, b'.' | b'%' | b'\\' | b'/'))
}

/// Checks whether a payload contains path traversal structure.
fn has_traversal_structure(payload: &str) -> bool {
    if !may_contain_traversal_bytes(payload) {
        return false;
    }

    // Must have at least one traversal sequence
    let has_traversal = traversal_sequences()
        .iter()
        .any(|seq| contains_ascii_insensitive(payload, seq));

    // Must reference at least one target file/path
    let has_target = target_files()
        .iter()
        .any(|target| contains_ascii_insensitive(payload, target));

    // A bare traversal sequence is also valid (attacker may be probing)
    has_traversal || (has_target && payload.contains(".."))
}

impl PayloadOracle for PathOracle {
    fn is_semantically_valid(&self, _original: &str, transformed: &str) -> bool {
        has_traversal_structure(transformed)
    }

    fn name(&self) -> &'static str {
        "PathTraversal"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classic_traversal_valid() {
        let oracle = PathOracle;
        assert!(oracle.is_semantically_valid("../../../etc/passwd", "../../../etc/passwd",));
    }

    #[test]
    fn encoded_traversal_valid() {
        let oracle = PathOracle;
        assert!(oracle.is_semantically_valid("../../../etc/passwd", "..%2f..%2f..%2fetc/passwd",));
    }

    #[test]
    fn double_dot_semicolon_valid() {
        let oracle = PathOracle;
        assert!(oracle.is_semantically_valid("../../../etc/passwd", "..;/..;/..;/etc/passwd",));
    }

    #[test]
    fn windows_traversal_valid() {
        let oracle = PathOracle;
        assert!(
            oracle.is_semantically_valid("..\\..\\windows\\win.ini", "..\\..\\windows\\win.ini",)
        );
    }

    #[test]
    fn destroyed_dots_invalid() {
        let oracle = PathOracle;
        // All traversal markers and target paths are fully encoded
        assert!(!oracle.is_semantically_valid("../../../etc/passwd", "XXXX/XXXX/XXXX/XXXX/XXXX",));
    }

    #[test]
    fn plain_text_invalid() {
        let oracle = PathOracle;
        assert!(!oracle.is_semantically_valid("../../../etc/passwd", "hello world",));
    }

    #[test]
    fn proc_self_environ_valid() {
        let oracle = PathOracle;
        assert!(
            oracle
                .is_semantically_valid("../../../proc/self/environ", "../../../proc/self/environ",)
        );
    }

    #[test]
    fn dot_env_valid() {
        let oracle = PathOracle;
        assert!(oracle.is_semantically_valid("../../.env", "../../.env",));
    }

    #[test]
    fn null_byte_bypass_valid() {
        let oracle = PathOracle;
        // Null byte appended but traversal preserved
        assert!(
            oracle.is_semantically_valid("../../../etc/passwd", "../../../etc/passwd\x00.jpg",)
        );
    }
}
