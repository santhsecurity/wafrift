//! Path traversal payload oracle.
//!
//! Path traversal payloads escape the filesystem with `../` sequences (or
//! encoded equivalents) toward a sensitive target. The oracle confirms the
//! EFFECTIVE (post-transform) payload is still a structurally-valid traversal
//! attack. Per the `verified_bypass` contract the bar is "still a valid attack"
//! (not "textually identical to the original"), so it inspects the transformed
//! bytes only and accepts EITHER:
//!
//! - a traversal SEQUENCE survives — `../` or a known encoded form
//!   (`..%2f`, `..%5c`, `%2e%2e/`, …) from `sequences.toml`; OR
//! - a literal target path (`/etc/passwd`, …) is present together with `..`.
//!
//! A bare traversal sequence with NO literal target is deliberately accepted:
//! the target is frequently percent-/double-encoded (the whole point of the
//! evasion), so it can't be matched textually — requiring a literal target
//! here would false-negative exactly the encoded bypasses this oracle exists to
//! validate. If a transform destroyed the traversal sequence entirely, the
//! server can't climb directories and the check correctly fails.
//!
//! (Looser than the nosql/xxe/log4shell equivalence oracles, which CAN compare
//! the decoded original↔candidate. A decode-then-verify path oracle that pins
//! the original's target through the same decodings is a tracked enhancement.)

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

// Per consolidation F13/F30: `description`/`encoding`/`os` TOML fields
// are human-readable docs not consumed at runtime. Serde silently
// ignores unknown TOML fields by default — drop them from the struct
// rather than allocating a heap String per rule on every parse.

/// Traversal sequence definition from TOML.
#[derive(Debug, Clone, Deserialize)]
struct TraversalSequence {
    sequence: String,
}

/// Target file definition from TOML.
#[derive(Debug, Clone, Deserialize)]
struct TargetFile {
    path: String,
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
        toml::from_str(PATH_TRAVERSAL_TOML).unwrap_or_else(|_| PathTraversalRules {
            traversal_sequence: Vec::new(),
            target_file: Vec::new(),
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
