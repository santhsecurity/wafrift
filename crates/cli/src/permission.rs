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
//!    exits with code 2 — the argument-class error bucket. An
//!    unauthorized target is an invalid-input condition, so it shares
//!    the exit code of "unknown flag" / "missing required field".
//!    (Exit 3 is reserved for `bench-diff` regression gating.)
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
pub(crate) enum PermissionVerdict {
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
pub(crate) fn is_local_target(host: &str) -> bool {
    use std::net::IpAddr;
    if let Ok(ip) = host.parse::<IpAddr>() {
        // SSRF hardening: cloud metadata endpoints (AWS/GCP/Azure IMDS) live in
        // the link-local / unique-local ranges that would otherwise auto-allow,
        // but they are NEVER a benign "local bench" — they are the canonical SSRF
        // objective. Require explicit --i-have-permission for them. (A target may
        // redirect here; the permission gate is the backstop.)
        if is_cloud_metadata_ip(&ip) {
            return false;
        }
        match ip {
            IpAddr::V4(v4) => {
                v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
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

/// The well-known cloud-metadata service addresses (AWS/GCP/Azure IMDS). These
/// fall inside the auto-allowed link-local/unique-local ranges but are the
/// canonical SSRF objective, so the permission gate denies them by default.
#[must_use]
fn is_cloud_metadata_ip(ip: &std::net::IpAddr) -> bool {
    use std::net::{IpAddr, Ipv6Addr};
    match ip {
        IpAddr::V4(v4) => v4.octets() == [169, 254, 169, 254],
        IpAddr::V6(v6) => {
            // AWS IMDSv6 (fd00:ec2::254) and an IPv4-mapped 169.254.169.254.
            *v6 == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254)
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|m| m.octets() == [169, 254, 169, 254])
        }
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
        if !path.exists() {
            // First run: scaffold a self-documenting template so the operator
            // has a discoverable file to extend — the refusal message points
            // here, so it must actually exist. Best-effort; a read-only HOME
            // just means "built-in allowlist only".
            scaffold_permission_file(&path);
            return BTreeSet::new();
        }
        // §15 OOM guard: permission.toml is tiny TOML; 1 MiB cap catches
        // /dev/zero symlinks without breaking any real config file.
        let Ok(raw) = crate::safe_body::read_bounded_text_file(
            &path,
            crate::safe_body::MAX_OPERATOR_INPUT_BYTES,
        ) else {
            return BTreeSet::new();
        };
        parse_allowed_hosts(&raw)
    })
}

/// Parse the `allowed_hosts = [ ... ]` array from a `permission.toml` body.
/// Minimal hand-roll instead of pulling serde::Deserialize on a single-field
/// struct — keeps this module zero-dep beyond `dirs`. Handles the multi-line
/// array form (one quoted host per line); comments and blanks are ignored.
fn parse_allowed_hosts(raw: &str) -> BTreeSet<String> {
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
}

/// First-run scaffold: write a commented `permission.toml` template at `path`
/// if it does not yet exist. Uses `create_new` so a file written concurrently
/// (or already edited by the operator) is never clobbered. Silent on any error
/// — the gate degrades to "built-in allowlist only" and never blocks on a
/// read-only HOME.
fn scaffold_permission_file(path: &std::path::Path) {
    use std::io::Write;
    if let Some(dir) = path.parent()
        && std::fs::create_dir_all(dir).is_err()
    {
        return;
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        let _ = f.write_all(PERMISSION_TEMPLATE.as_bytes());
    }
}

/// Self-documenting template written to `~/.wafrift/permission.toml` on first
/// run. Mirrors the schema parsed by [`operator_allowlist`] and the guidance in
/// the refusal message, so the file an operator opens matches what they were
/// told to edit.
const PERMISSION_TEMPLATE: &str = "\
# wafrift operator allowlist — hosts you are AUTHORISED to test.
#
# wafrift refuses to fire offensive traffic at a target unless its host is on an
# allowlist (this file or the built-in bounty list) OR you pass
#   --i-have-permission \"<justification>\"
# on the command line.
#
# Add the hostnames you have written authorisation for under `allowed_hosts`.
# A bare host matches that host and its subdomains. Example:
#
#   allowed_hosts = [\n\
#     \"scope.example.com\",\n\
#     \"bug-bounty.example\",\n\
#   ]
#
# This file was auto-created on first run. localhost / 127.0.0.1 / RFC1918 are
# always permitted for local bench targets and need no entry here.
allowed_hosts = []
";

/// Check if `target_url`'s host is on any allowlist or if the operator
/// explicitly authorized via the `--i-have-permission` CLI flag.
///
/// `explicit_permission` is the value the operator passed for that
/// flag (`Some("HackerOne #12345")` if used; `None` if not).
#[must_use]
pub(crate) fn check_permission(
    target_url: &str,
    explicit_permission: Option<&str>,
) -> PermissionVerdict {
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

/// Enforce the permission check — print refusal + exit 2 on Refused.
/// Returns silently on Allowed.
pub(crate) fn assert_permitted(target_url: &str, explicit_permission: Option<&str>) {
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
        // Exit 2 = argument / input error (same bucket as "unknown flag",
        // "contradictory selectors", "missing required field"). Permission
        // refusal is fundamentally an argument-class error: the operator
        // supplied a target URL that is not authorized. It is NOT exit 3
        // (bench-diff regression) — using 3 here was a code-overload bug.
        std::process::exit(2);
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
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
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
        for host in &[
            "127.0.0.1",
            "::1",
            "localhost",
            "10.0.0.1",
            "192.168.1.5",
            "172.16.0.1",
        ] {
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
    fn cloud_metadata_ips_are_not_auto_permitted() {
        // SSRF hardening: the IMDS endpoints sit in the link-local / unique-local
        // ranges that otherwise auto-allow, but they are the canonical SSRF
        // objective — they MUST require explicit --i-have-permission.
        for host in &["169.254.169.254", "fd00:ec2::254", "::ffff:169.254.169.254"] {
            assert!(
                !is_local_target(host),
                "{host} (cloud metadata) must NOT be auto-permitted"
            );
        }
        // General link-local / RFC1918 stays auto-allowed (real local bench): the
        // hardening is surgical, not a blanket link-local ban.
        for host in &["169.254.1.1", "192.168.1.5", "10.0.0.1", "127.0.0.1"] {
            assert!(is_local_target(host), "{host} should still be local");
        }
    }

    #[test]
    fn scaffold_creates_self_documenting_template() {
        let dir = tempfile::tempdir().unwrap();
        // Nested path: scaffold must mkdir -p the `.wafrift` parent.
        let path = dir.path().join(".wafrift").join("permission.toml");
        assert!(!path.exists());
        scaffold_permission_file(&path);
        assert!(path.exists(), "first-run scaffold must create the file");
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(
            body.contains("allowed_hosts = []"),
            "must seed the schema: {body}"
        );
        assert!(
            body.contains("--i-have-permission"),
            "must document the override"
        );
    }

    #[test]
    fn scaffold_never_clobbers_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("permission.toml");
        std::fs::write(&path, "allowed_hosts = [\n  \"my.scope.example\",\n]\n").unwrap();
        scaffold_permission_file(&path);
        // The operator's edits must survive — create_new means no overwrite.
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(
            body.contains("my.scope.example"),
            "operator content clobbered: {body}"
        );
    }

    #[test]
    fn scaffolded_template_parses_to_an_empty_allowlist() {
        // The file an operator opens must agree with the parser: the default
        // template grants nothing until they add a host.
        assert!(parse_allowed_hosts(PERMISSION_TEMPLATE).is_empty());
    }

    #[test]
    fn parse_allowed_hosts_reads_multiline_quoted_entries() {
        let toml = "# comment\nallowed_hosts = [\n  \"a.example\",\n  'b.example',\n]\n";
        let got = parse_allowed_hosts(toml);
        assert!(
            got.contains("a.example") && got.contains("b.example"),
            "{got:?}"
        );
        assert_eq!(got.len(), 2);
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
        assert_eq!(
            extract_host("https://example.com:443/path"),
            Some("example.com".into())
        );
        assert_eq!(
            extract_host("http://example.com/"),
            Some("example.com".into())
        );
        assert_eq!(extract_host("example.com"), Some("example.com".into()));
        assert_eq!(extract_host("http://[::1]:8080/"), Some("::1".into()));
        assert_eq!(extract_host(""), None);
    }

    // Permission refusal verdict is Refused (not any allowed variant).
    // The assert_permitted path calls process::exit(2) on Refused; we test
    // the verdict shape here since the exit-code assertion requires a
    // subprocess test — that exit-2 contract is pinned by
    // tests/smuggle_fire_e2e.rs::smuggle_fire_refuses_non_allowlist_target_without_permission.
    #[test]
    fn refused_verdict_for_unlisted_target_without_permission() {
        let v = check_permission("https://arbitrary-target.example.com/", None);
        assert!(
            matches!(v, PermissionVerdict::Refused),
            "expected Refused, got {v:?}"
        );
    }

    #[test]
    fn refused_verdict_for_whitespace_permission_string() {
        // Whitespace-only justifications must NOT grant authorization —
        // they're a common operator typo (e.g. `--i-have-permission "  "`).
        let v = check_permission("https://arbitrary-target.example.com/", Some("  \t "));
        assert!(
            matches!(v, PermissionVerdict::Refused),
            "expected Refused for whitespace-only permission, got {v:?}"
        );
    }
}
