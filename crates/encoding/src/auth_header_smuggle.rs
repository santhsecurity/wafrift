//! `Authorization` / `Proxy-Authorization` header parser-differential
//! smuggling.
//!
//! RFC 7235 §2.1 defines the Authorization header value as
//! `auth-scheme 1*SP token68 / auth-params`. Real-world parsers are
//! inconsistent about:
//!
//! - **Case sensitivity** of the scheme — RFC says case-insensitive
//!   (`Bearer` ≡ `bearer` ≡ `BEARER`) but some WAFs match `Bearer`
//!   literally and miss lowercase.
//! - **Linear whitespace** between scheme and token — RFC says
//!   `1*SP` (one or more spaces) but some parsers accept tabs,
//!   multiple spaces, or no space at all (`Bearereyj…`).
//! - **Multiple Authorization headers** — RFC 7230 §3.2.2 forbids
//!   most header duplication; Authorization is single-valued. Real
//!   stacks: nginx keeps first, Apache keeps last, some join with
//!   commas. Privilege-escalation surface when WAF and origin
//!   disagree on which header wins.
//! - **Quoted scheme** (`"Bearer" eyj…`) — strict RFC rejects; lax
//!   parsers strip quotes.
//! - **Trailing junk** after the token — many origin parsers stop
//!   at the first whitespace and ignore the rest; WAFs that scan
//!   the entire header value see the trailing payload.
//! - **Control bytes in the token** — strict RFC 5234 token68
//!   alphabet forbids CTLs; lax parsers silently strip them.
//!
//! The same matrix applies to `Proxy-Authorization` (RFC 7235
//! §4.4). Caller passes the header name; the same variant generators
//! work for both.
//!
//! ## Wire shape
//!
//! Every probe produces a single string for the header value. The
//! caller attaches it to a `Request` under either `Authorization` or
//! `Proxy-Authorization`. Some variants emit a `Vec<(name, value)>`
//! when the probe requires more than one header — see
//! [`AuthSmuggleProbe::header_lines`].

use rand::Rng;
use wafrift_types::canary::Canary;
use wafrift_types::pick::pick_from;
use wafrift_types::probe::{SmuggleArtifact, SmuggleProbe};

/// Maximum total length wafrift will emit for a single Authorization
/// header value. Most stacks have a 4-8 KiB header-line cap; we sit
/// well under so probes don't get dropped at the framing layer
/// before reaching the parser-differential surface we care about.
pub const MAX_AUTH_HEADER_BYTES: usize = 4 * 1024;

/// Authorization-header smuggle variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthHeaderVariant {
    /// `bearer <token>` — lowercase scheme. RFC 7235 §2.1 says
    /// case-insensitive; some WAFs match literally and miss it.
    LowercaseScheme,
    /// `Bearer<token>` — no whitespace between scheme and token.
    /// RFC says `1*SP`; some lenient parsers join them.
    NoWhitespaceAfterScheme,
    /// `Bearer\t<token>` — TAB instead of SP between scheme and
    /// token. RFC 5234 allows SP only in `1*SP`; lax parsers accept
    /// any LWS.
    TabBetweenSchemeAndToken,
    /// `Bearer   <token>` — multiple spaces (3-7 chosen randomly)
    /// instead of `1*SP`. Some strict parsers reject; most accept.
    MultipleSpacesAfterScheme,
    /// Two `Authorization:` header lines with different tokens.
    /// `header_lines` returns both. WAF takes first; origin may
    /// take last → privilege escalation differential.
    DuplicateHeaderFirstWinsBenign,
    /// `"Bearer" <token>` — scheme wrapped in double quotes. Strict
    /// RFC rejects; some lax parsers strip.
    QuotedScheme,
    /// `Bearer <token> trailing junk` — extra bytes after the
    /// token. Most parsers stop at whitespace; WAFs scanning the
    /// whole value see the trailing payload.
    TrailingJunkAfterToken,
    /// `Bearer <token-with-ctl-byte>` — control byte inserted into
    /// the token. Strict parsers reject; lax parsers strip.
    ControlByteInToken,
}

/// An Authorization-header smuggle probe.
#[derive(Debug, Clone)]
pub struct AuthSmuggleProbe {
    /// Which smuggle shape this probe implements.
    pub variant: AuthHeaderVariant,
    /// Header lines to attach to the request. Most variants emit
    /// exactly one `(name, value)` pair; the duplicate-header
    /// variant emits two.
    pub header_lines: Vec<(String, String)>,
    /// Telemetry description.
    pub description: String,
    /// Per-probe correlation token.
    pub canary: Canary,
}

impl AuthSmuggleProbe {
    fn finalise(
        variant: AuthHeaderVariant,
        mut header_lines: Vec<(String, String)>,
        description: String,
    ) -> Self {
        for (_, v) in header_lines.iter_mut() {
            if v.len() > MAX_AUTH_HEADER_BYTES {
                // §15 panic fix: `String::truncate` panics off a char boundary.
                // Auth values can be multibyte (operator `--credential`), so cap
                // at a UTF-8 boundary via the shared helper (matches cookie/range).
                let cut = crate::floor_char_boundary(v, MAX_AUTH_HEADER_BYTES);
                v.truncate(cut);
            }
        }
        Self {
            variant,
            header_lines,
            description,
            canary: Canary::generate(),
        }
    }

    /// `bearer <token>` — lowercase scheme.
    #[must_use]
    pub fn lowercase_scheme(header_name: &str, scheme: &str, token: &str) -> Self {
        let value = format!("{} {}", scheme.to_lowercase(), sanitise_token(token));
        Self::finalise(
            AuthHeaderVariant::LowercaseScheme,
            vec![(header_name.to_string(), value)],
            format!(
                "Lowercase auth scheme {:?} — RFC 7235 §2.1 case-insensitive but some WAFs match literal",
                scheme.to_lowercase()
            ),
        )
    }

    /// `Bearer<token>` — no whitespace between scheme and token.
    #[must_use]
    pub fn no_whitespace_after_scheme(
        header_name: &str,
        scheme: &str,
        token: &str,
    ) -> Self {
        let value = format!("{}{}", scheme, sanitise_token(token));
        Self::finalise(
            AuthHeaderVariant::NoWhitespaceAfterScheme,
            vec![(header_name.to_string(), value)],
            "No SP between scheme and token — RFC 7235 §2.1 violation, lenient parsers join"
                .into(),
        )
    }

    /// `Bearer\t<token>` — TAB instead of SP between scheme and
    /// token.
    #[must_use]
    pub fn tab_between_scheme_and_token(
        header_name: &str,
        scheme: &str,
        token: &str,
    ) -> Self {
        let value = format!("{}\t{}", scheme, sanitise_token(token));
        Self::finalise(
            AuthHeaderVariant::TabBetweenSchemeAndToken,
            vec![(header_name.to_string(), value)],
            "TAB between scheme and token — RFC requires SP, some accept any LWS".into(),
        )
    }

    /// `Bearer   <token>` — 3-7 spaces between scheme and token.
    #[must_use]
    pub fn multiple_spaces_after_scheme(
        header_name: &str,
        scheme: &str,
        token: &str,
    ) -> Self {
        let mut rng = rand::thread_rng();
        let n = rng.gen_range(3..=7);
        let value = format!("{}{}{}", scheme, " ".repeat(n), sanitise_token(token));
        Self::finalise(
            AuthHeaderVariant::MultipleSpacesAfterScheme,
            vec![(header_name.to_string(), value)],
            format!("{n} spaces between scheme and token — boundary stretch of `1*SP`"),
        )
    }

    /// Two header lines with the same name; first benign, second
    /// the real smuggled token. nginx-style "first wins" parsers
    /// see benign; Apache-style "last wins" parsers see smuggle.
    #[must_use]
    pub fn duplicate_header_first_wins_benign(
        header_name: &str,
        scheme: &str,
        benign_token: &str,
        smuggle_token: &str,
    ) -> Self {
        let v1 = format!("{} {}", scheme, sanitise_token(benign_token));
        let v2 = format!("{} {}", scheme, sanitise_token(smuggle_token));
        Self::finalise(
            AuthHeaderVariant::DuplicateHeaderFirstWinsBenign,
            vec![
                (header_name.to_string(), v1),
                (header_name.to_string(), v2),
            ],
            "Duplicate Authorization headers — nginx-vs-Apache first/last-wins differential"
                .into(),
        )
    }

    /// `"Bearer" <token>` — scheme wrapped in double quotes.
    #[must_use]
    pub fn quoted_scheme(header_name: &str, scheme: &str, token: &str) -> Self {
        // Strip any inner quotes so the wrapping pair isn't ambiguous.
        let clean_scheme = scheme.replace('"', "");
        let value = format!("\"{}\" {}", clean_scheme, sanitise_token(token));
        Self::finalise(
            AuthHeaderVariant::QuotedScheme,
            vec![(header_name.to_string(), value)],
            "Quoted scheme — strict RFC rejects, lax parsers strip quotes".into(),
        )
    }

    /// `Bearer <token> <junk>` — extra bytes after the token.
    #[must_use]
    pub fn trailing_junk_after_token(
        header_name: &str,
        scheme: &str,
        token: &str,
        junk: &str,
    ) -> Self {
        let value = format!(
            "{} {} {}",
            scheme,
            sanitise_token(token),
            sanitise_token(junk)
        );
        Self::finalise(
            AuthHeaderVariant::TrailingJunkAfterToken,
            vec![(header_name.to_string(), value)],
            "Trailing bytes after token — parser stops at SP vs WAF scans whole value"
                .into(),
        )
    }

    /// `Bearer <token-with-ctl>` — control byte injected at the
    /// token midpoint. CTL pool randomised per call.
    #[must_use]
    pub fn control_byte_in_token(
        header_name: &str,
        scheme: &str,
        token: &str,
    ) -> Self {
        let clean = sanitise_token(token);
        let ctl = pick_from(CONTROL_BYTE_POOL, b'\t');
        // §15 panic fix (sibling of cookie_smuggle::control_byte_in_value):
        // sanitise_token keeps multibyte UTF-8, so a raw `len/2` split would
        // panic when a codepoint straddles the midpoint (token "éa" → mid=1 =
        // middle of `é`). Snap to a char boundary via the shared helper.
        let mid = crate::floor_char_boundary(&clean, clean.len() / 2);
        let value = format!(
            "{} {}{}{}",
            scheme,
            &clean[..mid],
            ctl as char,
            &clean[mid..]
        );
        Self::finalise(
            AuthHeaderVariant::ControlByteInToken,
            vec![(header_name.to_string(), value)],
            format!("Control byte 0x{ctl:02x} inside token — strict reject vs lax strip"),
        )
    }
}

impl SmuggleProbe for AuthSmuggleProbe {
    fn canary(&self) -> &Canary {
        &self.canary
    }

    fn technique(&self) -> String {
        let suffix = match self.variant {
            AuthHeaderVariant::LowercaseScheme => "lowercase-scheme",
            AuthHeaderVariant::NoWhitespaceAfterScheme => "no-whitespace-after-scheme",
            AuthHeaderVariant::TabBetweenSchemeAndToken => "tab-between-scheme-and-token",
            AuthHeaderVariant::MultipleSpacesAfterScheme => "multiple-spaces-after-scheme",
            AuthHeaderVariant::DuplicateHeaderFirstWinsBenign => "duplicate-header-first-wins-benign",
            AuthHeaderVariant::QuotedScheme => "quoted-scheme",
            AuthHeaderVariant::TrailingJunkAfterToken => "trailing-junk-after-token",
            AuthHeaderVariant::ControlByteInToken => "control-byte-in-token",
        };
        format!("auth.{suffix}")
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn artifact(&self) -> SmuggleArtifact {
        SmuggleArtifact::Headers(self.header_lines.clone())
    }
}

/// Control bytes the
/// [`ControlByteInToken`](AuthHeaderVariant::ControlByteInToken) probe
/// may inject. Each is forbidden by strict RFC 5234 in `token68` but
/// silently stripped by various lax parsers.
pub(crate) const CONTROL_BYTE_POOL: &[u8] = &[
    0x09, // HTAB
    0x0B, // VT
    0x0C, // FF
    0x1F, // US
    0x7F, // DEL
];

/// Strip CR / LF / NUL from a token. These three bytes break the
/// HTTP header-line on every stack so probes that "explore lax
/// parsing" still must not break framing.
fn sanitise_token(s: &str) -> String {
    s.chars()
        .filter(|&c| c != '\r' && c != '\n' && c != '\0')
        .collect()
}

/// Enumerate one probe per variant, seeded with `scheme` and
/// `token`. Defaults to the `Authorization` header. Pass
/// `"Proxy-Authorization"` as `header_name` to target the proxy
/// auth surface (RFC 7235 §4.4).
#[must_use]
pub fn all_variants(header_name: &str, scheme: &str, token: &str) -> Vec<AuthSmuggleProbe> {
    vec![
        AuthSmuggleProbe::lowercase_scheme(header_name, scheme, token),
        AuthSmuggleProbe::no_whitespace_after_scheme(header_name, scheme, token),
        AuthSmuggleProbe::tab_between_scheme_and_token(header_name, scheme, token),
        AuthSmuggleProbe::multiple_spaces_after_scheme(header_name, scheme, token),
        AuthSmuggleProbe::duplicate_header_first_wins_benign(
            header_name,
            scheme,
            "benign-token-aaaa",
            token,
        ),
        AuthSmuggleProbe::quoted_scheme(header_name, scheme, token),
        AuthSmuggleProbe::trailing_junk_after_token(header_name, scheme, token, "junk-tail"),
        AuthSmuggleProbe::control_byte_in_token(header_name, scheme, token),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn sweep_emits_eight_distinct_variants() {
        let v = all_variants("Authorization", "Bearer", "eyJhbGciOiJ");
        assert_eq!(v.len(), 8);
        let kinds: HashSet<_> = v.iter().map(|p| p.variant).collect();
        assert_eq!(kinds.len(), 8);
    }

    #[test]
    fn lowercase_scheme_probe_actually_lowercases_the_scheme() {
        let p = AuthSmuggleProbe::lowercase_scheme("Authorization", "Bearer", "X");
        let (_, v) = &p.header_lines[0];
        assert!(v.starts_with("bearer "), "expected lowercase scheme: {v:?}");
        assert!(
            !v.starts_with("Bearer "),
            "must NOT preserve original case: {v:?}"
        );
    }

    #[test]
    fn no_whitespace_probe_has_no_sp_between_scheme_and_token() {
        let p = AuthSmuggleProbe::no_whitespace_after_scheme(
            "Authorization",
            "Bearer",
            "Token",
        );
        let (_, v) = &p.header_lines[0];
        // First SP would split into scheme + token; the probe MUST
        // not have one in the wire form.
        assert!(
            !v.contains(' '),
            "no-whitespace probe must contain zero SPs, got: {v:?}"
        );
        assert!(v.starts_with("BearerToken"));
    }

    #[test]
    fn tab_probe_uses_tab_not_space() {
        let p =
            AuthSmuggleProbe::tab_between_scheme_and_token("Authorization", "Bearer", "T");
        let (_, v) = &p.header_lines[0];
        assert!(v.contains('\t'), "expected TAB in header value: {v:?}");
        assert!(
            !v.contains(' '),
            "TAB probe must not also carry a space (would defeat the test)"
        );
    }

    #[test]
    fn multiple_spaces_probe_has_three_to_seven_spaces() {
        let p = AuthSmuggleProbe::multiple_spaces_after_scheme(
            "Authorization",
            "Bearer",
            "T",
        );
        let (_, v) = &p.header_lines[0];
        // Count consecutive spaces between "Bearer" and "T".
        let after_bearer = v.trim_start_matches("Bearer");
        let space_count = after_bearer.chars().take_while(|&c| c == ' ').count();
        assert!(
            (3..=7).contains(&space_count),
            "expected 3..=7 spaces, got {space_count}"
        );
    }

    #[test]
    fn duplicate_header_probe_emits_two_header_lines_same_name() {
        let p = AuthSmuggleProbe::duplicate_header_first_wins_benign(
            "Authorization",
            "Bearer",
            "benign",
            "smuggle",
        );
        assert_eq!(p.header_lines.len(), 2);
        assert_eq!(p.header_lines[0].0, "Authorization");
        assert_eq!(p.header_lines[1].0, "Authorization");
        // First is benign, second is smuggle.
        assert!(p.header_lines[0].1.contains("benign"));
        assert!(p.header_lines[1].1.contains("smuggle"));
    }

    #[test]
    fn quoted_scheme_probe_wraps_scheme_in_double_quotes() {
        let p = AuthSmuggleProbe::quoted_scheme("Authorization", "Bearer", "T");
        let (_, v) = &p.header_lines[0];
        assert!(v.starts_with("\"Bearer\""), "got: {v:?}");
    }

    #[test]
    fn quoted_scheme_strips_inner_quotes_from_scheme() {
        // Anti-rig: nested quotes would render the probe ambiguous.
        let p = AuthSmuggleProbe::quoted_scheme("Authorization", "Be\"a\"rer", "T");
        let (_, v) = &p.header_lines[0];
        // Exactly two quotes (the wrappers).
        assert_eq!(
            v.matches('"').count(),
            2,
            "expected exactly 2 quotes (the wrappers), got: {v:?}"
        );
    }

    #[test]
    fn trailing_junk_probe_appends_extra_bytes_after_token() {
        let p = AuthSmuggleProbe::trailing_junk_after_token(
            "Authorization",
            "Bearer",
            "TOK",
            "EXTRA",
        );
        let (_, v) = &p.header_lines[0];
        // Format is "Bearer <token> <junk>" so two SPs split into 3
        // segments.
        let parts: Vec<&str> = v.splitn(3, ' ').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "Bearer");
        assert_eq!(parts[1], "TOK");
        assert_eq!(parts[2], "EXTRA");
    }

    #[test]
    fn ctl_probe_injects_a_byte_from_the_pool() {
        let p =
            AuthSmuggleProbe::control_byte_in_token("Authorization", "Bearer", "ABCDEF");
        let (_, v) = &p.header_lines[0];
        let bytes = v.as_bytes();
        assert!(
            bytes.iter().any(|b| CONTROL_BYTE_POOL.contains(b)),
            "no CTL byte found in header: {v:?}"
        );
    }

    #[test]
    fn sanitise_strips_cr_lf_nul_from_token() {
        // Anti-rig: CR/LF/NUL must NEVER reach the wire even when the
        // probe explores lax parsers — they break framing universally.
        let p =
            AuthSmuggleProbe::lowercase_scheme("Authorization", "Bearer", "to\rke\nn\0X");
        let (_, v) = &p.header_lines[0];
        assert!(!v.contains('\r'));
        assert!(!v.contains('\n'));
        assert!(!v.contains('\0'));
    }

    #[test]
    fn every_probe_carries_a_distinct_canary() {
        let a = AuthSmuggleProbe::lowercase_scheme("Authorization", "Bearer", "x");
        let b = AuthSmuggleProbe::lowercase_scheme("Authorization", "Bearer", "x");
        assert_ne!(a.canary.token, b.canary.token);
        assert_eq!(a.canary.token.len(), 16);
    }

    #[test]
    fn header_value_capped_at_max() {
        let huge = "x".repeat(MAX_AUTH_HEADER_BYTES * 4);
        let p = AuthSmuggleProbe::lowercase_scheme("Authorization", "Bearer", &huge);
        let (_, v) = &p.header_lines[0];
        assert!(
            v.len() <= MAX_AUTH_HEADER_BYTES,
            "header value exceeded cap: {}",
            v.len()
        );
    }

    #[test]
    fn proxy_authorization_header_name_also_supported() {
        let p = AuthSmuggleProbe::lowercase_scheme("Proxy-Authorization", "Bearer", "T");
        assert_eq!(p.header_lines[0].0, "Proxy-Authorization");
    }

    #[test]
    fn empty_inputs_do_not_panic_in_any_builder() {
        let _ = AuthSmuggleProbe::lowercase_scheme("Authorization", "", "");
        let _ = AuthSmuggleProbe::no_whitespace_after_scheme("Authorization", "", "");
        let _ = AuthSmuggleProbe::tab_between_scheme_and_token("Authorization", "", "");
        let _ = AuthSmuggleProbe::multiple_spaces_after_scheme("Authorization", "", "");
        let _ = AuthSmuggleProbe::duplicate_header_first_wins_benign(
            "Authorization",
            "",
            "",
            "",
        );
        let _ = AuthSmuggleProbe::quoted_scheme("Authorization", "", "");
        let _ = AuthSmuggleProbe::trailing_junk_after_token("Authorization", "", "", "");
        // control_byte_in_token's `mid = clean.len() / 2 = 0`; slice
        // [..0] is empty, [0..] is empty. Verify no panic.
        let _ = AuthSmuggleProbe::control_byte_in_token("Authorization", "", "");
    }

    #[test]
    fn control_byte_in_token_multibyte_does_not_panic() {
        // §15 regression (sibling of cookie_smuggle): sanitise_token keeps
        // multibyte UTF-8, so the pre-fix `&clean[..clean.len()/2]` split
        // panicked when a codepoint straddled the midpoint. "éa" is 3 bytes;
        // len/2 = 1 is the middle of `é`. Now floor_char_boundary snaps it.
        for tok in ["éa", "aé", "日本語", "🦀x", "Bearer-café-日"] {
            let p = AuthSmuggleProbe::control_byte_in_token("Authorization", "Bearer", tok);
            // The single header pair's value must be valid UTF-8 + non-empty;
            // reaching here without a panic is the assertion.
            assert!(
                p.header_lines.iter().any(|(_, v)| !v.is_empty()),
                "control-byte-in-token must not panic on multibyte token {tok:?}"
            );
        }
    }
}
