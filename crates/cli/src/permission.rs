//! Target permission gate.
//!
//! Wafrift is a real attack tool. By default it should refuse to fire
//! probes at any target that the operator hasn't explicitly authorized.
//! This module provides a single gate: `assert_permitted(target_url,
//! explicit_permission)` that:
//!
//! 1. Allows any target on the built-in **bounty allowlist** (programs
//!    that publicly permit automated security testing — primarily
//!    Cloudflare's CumulusFire surface and the wafrift-bench-local
//!    Docker stacks).
//! 2. Allows any target if `--i-have-permission <reason>` was passed
//!    on the command line.
//! 3. Otherwise prints a clear refusal message naming the target and
//!    exits with code 3 (distinct from arg-parse errors).
//!
//! ## Why this exists
//!
//! - A YC pentest customer evaluating wafrift will ask "how do you
//!   stop a script kiddie from blasting some random e-commerce site?"
//!   This gate is the answer. The refuse-by-default posture is the
//!   answer to the legal-defensibility-of-distribution question too.
//!
//! - The allowlist is data-driven (TOML at
//!   `~/.wafrift/permission.toml`) so operators can extend it for
//!   engagements without touching wafrift source.
//!
//! ## What is NOT in this gate
//!
//! - This is not a license check, not a phone-home, not a kill switch.
//!   It's a single boolean: did the operator opt in for this target?
//!
//! - It does not gate `wafrift scan` against `localhost` /
//!   `127.0.0.1` / RFC1918 ranges — local Docker bench targets are
//!   always permitted (`is_local_target`).

use std::collections::BTreeSet;
use std::sync::OnceLock;

/// Built-in bounty / lab allowlist — hosts that publicly permit
/// automated security testing. Kept small + auditable; extensions go
/// in the operator's `~/.wafrift/permission.toml`.
///
/// Each entry is a hostname suffix: `waf.cumulusfire.net` matches
/// itself AND any subdomain (`foo.waf.cumulusfire.net`).
const BUILTIN_ALLOWLIST: &[&str] = &[
    // Cloudflare's official WAF bypass bounty surface ($50/bypass
    // per their HackerOne policy as of 2026).
    "waf.cumulusfire.net",
    // Operator-owned bench surface set up for the wafrift YC pitch.
    // Public DNS but private bypass purpose; operator authorizes via
    // ownership.
    "testing.santh.dev",
    // PortSwigger's deliberately-vulnerable training labs — public,
    // documented as fair-game for security tooling.
    "ginandjuice.shop",
    // Local-loopback aliases used by Docker bench stacks.
    "localhost",
    "127.0.0.1",
    "::1",
];

/// Outcome of a permission check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionVerdict {
    /// The target is on the built-in or operator-extended allowlist.
    AllowedByList,
    /// The operator passed `--i-have-permission <reason>` explicitly.
    AllowedByOperator { reason: String },
    /// The target is a private-network / loopback address — local
    /// Docker bench is always permitted (it's the operator's own box).
    AllowedLocal,
    /// No path to authorization — refuse to send a single probe.
    Refused,
}

/// True if `host` is a literal local address (loopback or RFC1918).
/// These are always permitted on the theory that the operator controls
/// the box on the other end of `127.0.0.1` / `192.168.x.x` /
/// `10.x.x.x` / `172.16-31.x.x` / `fc00::/7`.
#[must_use]
pub fn is_local_target(host: &str) -> bool {
    use std::net::IpAddr;
    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_unspecified()
            }
            IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    // Unique-local (fc00::/7) per RFC 4193.
                    || (v6.segments()[0] & 0xfe00) == 0xfc00
                    // Link-local (fe80::/10).
                    || (v6.segments()[0] & 0xffc0) == 0xfe80
            }
        }
    } else {
        matches!(host.to_ascii_lowercase().as_str(), "localhost")
    }
}

/// Load the operator-extended allowlist from
/// `~/.wafrift/permission.toml`. Cached for the lifetime of the
/// process so a 24/7 hunt doesn't re-parse on every probe.
///
/// File schema (all fields optional):
///
/// ```toml
/// # Hostname suffixes the operator has authorization for.
/// allowed_hosts = ["bug-bounty.example", "scope.h1.com"]
/// ```
fn operator_allowlist() -> &'static BTreeSet<String> {
    static CACHED: OnceLock<BTreeSet<String>> = OnceLock::new();
    CACHED.get_or_init(|| {
        let path = match dirs::home_dir() {
            Some(h) => h.join(".wafrift").join("permission.toml"),
            None => return BTreeSet::new(),
        };
        let Ok(raw) = std::fs::read_to_string(&path) else {
            return BTreeSet::new();
        };
        // Minimal hand-roll instead of pulling serde::Deserialize on a
        // single-field struct — keeps this module zero-dep beyond
        // `dirs` which the workspace already uses.
        let mut out = BTreeSet::new();
        let mut in_array = false;
        for line in raw.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if line.starts_with("allowed_hosts") {
                in_array = true;
                continue;
            }
            if in_array {
                if line.starts_with(']') {
                    in_array = false;
                    continue;
                }
                // Crude quote strip — accept `"foo",` or `'foo'`.
                let cleaned: String = line
                    .trim_end_matches(',')
                    .trim_matches(|c: char| c == '"' || c == '\'' || c.is_whitespace())
                    .to_string();
                if !cleaned.is_empty() {
                    out.insert(cleaned);
                }
            }
        }
        out
    })
}

/// Check if `target_url`'s host is on any allowlist or if the operator
/// explicitly authorized via the `--i-have-permission` CLI flag.
///
/// `explicit_permission` is the value the operator passed for that
/// flag (`Some("HackerOne #12345")` if used; `None` if not).
#[must_use]
pub fn check_permission(target_url: &str, explicit_permission: Option<&str>) -> PermissionVerdict {
    if let Some(reason) = explicit_permission {
        let trimmed = reason.trim();
        if !trimmed.is_empty() {
            return PermissionVerdict::AllowedByOperator {
                reason: trimmed.to_string(),
            };
        }
    }
    let Some(host) = extract_host(target_url) else {
        return PermissionVerdict::Refused;
    };
    let host_lc = host.to_ascii_lowercase();
    if is_local_target(&host_lc) {
        return PermissionVerdict::AllowedLocal;
    }
    for entry in BUILTIN_ALLOWLIST {
        if host_matches(&host_lc, entry) {
            return PermissionVerdict::AllowedByList;
        }
    }
    for entry in operator_allowlist() {
        if host_matches(&host_lc, entry) {
            return PermissionVerdict::AllowedByList;
        }
    }
    PermissionVerdict::Refused
}

/// Enforce the permission check — print refusal + exit 3 on Refused.
/// Returns silently on Allowed.
pub fn assert_permitted(target_url: &str, explicit_permission: Option<&str>) {
    let verdict = check_permission(target_url, explicit_permission);
    if matches!(verdict, PermissionVerdict::Refused) {
        eprintln!(
            "wafrift refuses: {target_url} is not on any allowlist and \
             --i-have-permission was not passed.\n\
             \n\
             Add the host to ~/.wafrift/permission.toml under \
             `allowed_hosts = [..]`, OR pass\n\
             `--i-have-permission \"HackerOne #...\"` (or any \
             non-empty justification) to override.\n\
             \n\
             Built-in allowlist: {builtin:?}",
            builtin = BUILTIN_ALLOWLIST
        );
        std::process::exit(3);
    }
}

fn extract_host(url: &str) -> Option<String> {
    // Avoid pulling `url` crate for a one-shot parse — handle the
    // forms we actually accept: full URL, `host:port`, bare host.
    let stripped = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let host_port = stripped.split('/').next()?;
    let host = host_port.rsplit_once(':').map_or(host_port, |(h, _)| h);
    // Strip IPv6 brackets if present.
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() { None } else { Some(host.to_string()) }
}

fn host_matches(actual: &str, allowed_suffix: &str) -> bool {
    // Exact match OR `actual` ends with `.allowed_suffix` (true
    // subdomain — boundary at `.` so `evilexample.com` does NOT match
    // `example.com`).
    let allowed = allowed_suffix.to_ascii_lowercase();
    actual == allowed
        || (actual.ends_with(&allowed)
            && actual.len() > allowed.len()
            && actual.as_bytes()[actual.len() - allowed.len() - 1] == b'.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_loopback_always_permitted() {
        for host in &["127.0.0.1", "::1", "localhost", "10.0.0.1", "192.168.1.5", "172.16.0.1"] {
            assert!(is_local_target(host), "{host} should be local");
        }
    }

    #[test]
    fn public_ips_are_not_local() {
        for host in &["8.8.8.8", "1.1.1.1", "203.0.113.5", "2001:4860:4860::8888"] {
            assert!(!is_local_target(host), "{host} should not be local");
        }
    }

    #[test]
    fn cumulusfire_allowed_by_builtin() {
        assert_eq!(
            check_permission("https://waf.cumulusfire.net/xss?q=test", None),
            PermissionVerdict::AllowedByList
        );
    }

    #[test]
    fn cumulusfire_subdomain_allowed() {
        assert_eq!(
            check_permission("https://foo.waf.cumulusfire.net/xss", None),
            PermissionVerdict::AllowedByList
        );
    }

    #[test]
    fn lookalike_is_refused() {
        // `evilcumulusfire.net` ends with `cumulusfire.net` as a
        // string but is NOT a subdomain. Must be refused.
        assert_eq!(
            check_permission("https://evilwaf.cumulusfire.net.attacker.com/xss", None),
            PermissionVerdict::Refused
        );
        // Suffix-only — no dot boundary — also refused.
        assert_eq!(
            check_permission("https://evilcumulusfire.net/xss", None),
            PermissionVerdict::Refused
        );
    }

    #[test]
    fn unknown_target_refused_without_permission() {
        assert_eq!(
            check_permission("https://random-target.example.com/", None),
            PermissionVerdict::Refused
        );
    }

    #[test]
    fn explicit_permission_overrides_refusal() {
        let v = check_permission(
            "https://random-target.example.com/",
            Some("HackerOne #12345 pentest scope"),
        );
        assert!(matches!(v, PermissionVerdict::AllowedByOperator { .. }));
    }

    #[test]
    fn empty_explicit_permission_does_not_authorize() {
        assert_eq!(
            check_permission("https://random-target.example.com/", Some("")),
            PermissionVerdict::Refused
        );
        assert_eq!(
            check_permission("https://random-target.example.com/", Some("   ")),
            PermissionVerdict::Refused
        );
    }

    #[test]
    fn local_target_does_not_need_permission() {
        assert_eq!(
            check_permission("http://localhost:18084/get?q=test", None),
            PermissionVerdict::AllowedLocal
        );
        assert_eq!(
            check_permission("http://127.0.0.1:8080/", None),
            PermissionVerdict::AllowedLocal
        );
    }

    #[test]
    fn ipv6_loopback_permitted() {
        assert_eq!(
            check_permission("http://[::1]:8080/", None),
            PermissionVerdict::AllowedLocal
        );
    }

    #[test]
    fn extract_host_strips_scheme_port_path() {
        assert_eq!(extract_host("https://example.com:443/path"), Some("example.com".into()));
        assert_eq!(extract_host("http://example.com/"), Some("example.com".into()));
        assert_eq!(extract_host("example.com"), Some("example.com".into()));
        assert_eq!(extract_host("http://[::1]:8080/"), Some("::1".into()));
        assert_eq!(extract_host(""), None);
    }
}
