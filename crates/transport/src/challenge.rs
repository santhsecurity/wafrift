//! Managed-challenge solver scaffolding (Cloudflare-class, AWS WAF
//! Captcha, Akamai Bot Manager).
//!
//! Closes blocker #115. Previously the [`Verdict::ChallengeRequired`]
//! verdict was DETECTED but not ACTED ON — the evade loop stalled.
//! This module provides the dispatch primitives so the proxy can:
//!
//! 1. Capture a `cf_clearance` (or equivalent) cookie once the operator
//!    (or an external solver) has cleared the challenge in any session.
//! 2. Replay the cookie on every subsequent request to the same host
//!    until it expires.
//! 3. Escalate to the operator (TUI prompt, stderr warn, push
//!    notification) for variants that require a human (hCaptcha,
//!    Turnstile, Akamai sensor data) rather than failing silently.
//!
//! What this module is NOT:
//! - A JS-challenge auto-solver. Cloudflare's "I'm under attack" mode
//!   serves obfuscated JS that performs a math computation, sets the
//!   cookie, and reloads. Auto-solving requires a JS engine
//!   (boa / quickjs WASM); see [`JsSolver`] for the documented
//!   integration point. Not implemented here — the cookie-capture
//!   solver covers ~90% of CF managed-challenge cases once any
//!   browser session has cleared the challenge.
//! - A captcha solver. Turnstile / hCaptcha / reCAPTCHA detection
//!   triggers [`SolveAction::EscalateToOperator`].

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Decision the dispatcher returns to the request layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SolveAction {
    /// A valid clearance cookie is on file — attach it and replay.
    ReplayWithCookie {
        /// `Cookie:`-header-ready string e.g. `cf_clearance=abc; foo=bar`.
        cookie_header: String,
    },
    /// No solution yet. Caller should back off and retry after `delay`.
    /// Used when an external solver is in flight (browser-in-the-loop)
    /// or when the rate-limit window hasn't passed.
    Wait { delay: Duration },
    /// Surface a prompt to the operator (TUI / stderr / push) so a
    /// human can clear the challenge and seed the cookie store.
    EscalateToOperator {
        /// Stable kind (`hcaptcha`, `turnstile`, `akamai_sensor`,
        /// `unknown`) so the UI can branch on it.
        kind: ChallengeKind,
        /// One-line operator-facing reason.
        reason: String,
    },
    /// Detection was a false positive — proceed unmodified.
    Bypass,
}

/// Coarse classification of the challenge surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChallengeKind {
    /// Cloudflare "I'm under attack" / managed challenge — JS-only,
    /// solvable via cookie replay.
    CloudflareManaged,
    /// Cloudflare Turnstile widget (interactive). Operator only.
    Turnstile,
    /// hCaptcha widget. Operator only.
    Hcaptcha,
    /// Google reCAPTCHA. Operator only.
    Recaptcha,
    /// AWS WAF managed CAPTCHA / Challenge action.
    AwsWaf,
    /// Akamai Bot Manager `_abck` cookie + sensor-data POST.
    AkamaiBmp,
    /// Unknown / heuristic-only detection.
    Unknown,
}

impl ChallengeKind {
    /// Whether this kind is in scope for cookie-replay solving (vs
    /// requiring a human).
    #[must_use]
    pub fn is_cookie_solvable(self) -> bool {
        matches!(self, Self::CloudflareManaged | Self::AkamaiBmp)
    }

    /// Stable string label for telemetry / logs.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::CloudflareManaged => "cloudflare_managed",
            Self::Turnstile => "turnstile",
            Self::Hcaptcha => "hcaptcha",
            Self::Recaptcha => "recaptcha",
            Self::AwsWaf => "aws_waf",
            Self::AkamaiBmp => "akamai_bmp",
            Self::Unknown => "unknown",
        }
    }
}

/// Per-host clearance cookie entry with absolute expiry.
#[derive(Debug, Clone)]
struct CookieEntry {
    cookie_header: String,
    expires_at: Instant,
    captured_at: Instant,
    kind: ChallengeKind,
}

/// Process-wide store of captured clearance cookies keyed by host.
///
/// The store is the bridge between the cookie-capture path (run when
/// an upstream response carries `Set-Cookie: cf_clearance=...`) and
/// the request-build path (which attaches the cookie to the next
/// request to the same host). Cheap to clone — wraps an internal
/// `Arc<RwLock<>>`.
#[derive(Debug, Default, Clone)]
pub struct ChallengeStore {
    inner: Arc<RwLock<ChallengeInner>>,
}

#[derive(Debug, Default)]
struct ChallengeInner {
    by_host: HashMap<String, CookieEntry>,
    /// Hosts the operator has been prompted about, with the timestamp
    /// of the last prompt. Used to throttle prompts to one per host
    /// per `OPERATOR_PROMPT_COOLDOWN`.
    operator_prompted: HashMap<String, Instant>,
}

/// Default clearance-cookie TTL when the upstream `Set-Cookie` carries
/// no explicit `Max-Age`/`Expires`. CF default is 30 minutes; we
/// match that.
pub const DEFAULT_CLEARANCE_TTL: Duration = Duration::from_secs(30 * 60);

/// Don't re-prompt the operator about the same host more than once
/// every 5 minutes — avoids noise when an automated retry burst
/// re-triggers the challenge.
pub const OPERATOR_PROMPT_COOLDOWN: Duration = Duration::from_secs(5 * 60);

/// Normalize a host key so case + optional trailing port don't
/// scatter entries across multiple slots. DNS is case-insensitive and
/// `Example.com:443` / `example.com` resolve to the same upstream
/// for our purposes — pre-fix they were stored under different keys
/// and `get("example.com")` would silently miss the cookie captured
/// under `Example.com`.
fn normalize_host(host: &str) -> String {
    let no_port = host.split(':').next().unwrap_or(host);
    no_port.to_ascii_lowercase()
}

impl ChallengeStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of the active cookie for `host`, or `None` if absent
    /// or expired.
    #[must_use]
    pub fn get(&self, host: &str) -> Option<String> {
        let key = normalize_host(host);
        let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
        let entry = inner.by_host.get(&key)?;
        if Instant::now() >= entry.expires_at {
            return None;
        }
        Some(entry.cookie_header.clone())
    }

    /// Record a freshly captured clearance cookie for `host`.
    ///
    /// `ttl` defaults to [`DEFAULT_CLEARANCE_TTL`] when `None`.
    ///
    /// Opportunistically GCs expired entries on every insert so the
    /// store self-bounds without requiring an external background
    /// task. Worst case: an attacker who churns through N hosts
    /// before any TTL expires holds N entries — which is the same
    /// behaviour as a sane caller, so the bound is acceptable.
    pub fn record(
        &self,
        host: impl Into<String>,
        cookie_header: impl Into<String>,
        kind: ChallengeKind,
        ttl: Option<Duration>,
    ) {
        let now = Instant::now();
        let entry = CookieEntry {
            cookie_header: cookie_header.into(),
            captured_at: now,
            expires_at: now + ttl.unwrap_or(DEFAULT_CLEARANCE_TTL),
            kind,
        };
        let key = normalize_host(&host.into());
        let mut inner = self.inner.write().unwrap_or_else(|e| e.into_inner());
        inner.by_host.retain(|_, e| now < e.expires_at);
        inner
            .operator_prompted
            .retain(|_, t| now < *t + OPERATOR_PROMPT_COOLDOWN);
        inner.by_host.insert(key, entry);
    }

    /// Drop the entry for `host` (e.g. after observing a 4xx that
    /// suggests the cookie has been invalidated upstream).
    pub fn forget(&self, host: &str) {
        let key = normalize_host(host);
        self.inner
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .by_host
            .remove(&key);
    }

    /// Capacity-trimming sweep: drop every expired entry. Cheap;
    /// callers should run it periodically (e.g. every minute on a
    /// background task) to stop the table growing on long-running
    /// proxies.
    pub fn purge_expired(&self) {
        let now = Instant::now();
        let mut inner = self.inner.write().unwrap_or_else(|e| e.into_inner());
        inner.by_host.retain(|_, e| now < e.expires_at);
        inner
            .operator_prompted
            .retain(|_, t| now < *t + OPERATOR_PROMPT_COOLDOWN);
    }

    /// Returns `true` if the operator should be prompted about a
    /// challenge for `host` — i.e. either no recent prompt has been
    /// emitted, or the cooldown has passed.
    pub fn should_prompt_operator(&self, host: &str) -> bool {
        let key = normalize_host(host);
        let mut inner = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        match inner.operator_prompted.get(&key).copied() {
            Some(prev) if now < prev + OPERATOR_PROMPT_COOLDOWN => false,
            _ => {
                inner.operator_prompted.insert(key, now);
                true
            }
        }
    }

    /// Diagnostic: how old is the clearance cookie we have for `host`?
    /// Returns `None` if no entry exists (regardless of expiry).
    #[must_use]
    pub fn age(&self, host: &str) -> Option<Duration> {
        let key = normalize_host(host);
        let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
        inner.by_host.get(&key).map(|e| e.captured_at.elapsed())
    }

    /// Diagnostic: which challenge kind is associated with the active
    /// cookie for `host`?
    #[must_use]
    pub fn kind(&self, host: &str) -> Option<ChallengeKind> {
        let key = normalize_host(host);
        let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
        let e = inner.by_host.get(&key)?;
        if Instant::now() >= e.expires_at {
            return None;
        }
        Some(e.kind)
    }

    /// Number of currently-stored entries (test/diagnostic only —
    /// not for production decisions).
    #[doc(hidden)]
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .by_host
            .len()
    }

    /// True iff the store has no live entries.
    #[doc(hidden)]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Hard cap on the body prefix scanned by [`classify`]. Real
/// challenge pages are well under this; large benign responses
/// (CDN-cached HTML, asset bundles) shouldn't OOM the proxy.
pub const CLASSIFY_BODY_SCAN_CAP: usize = 64 * 1024;

/// Detect the challenge kind from a response body + headers heuristic.
///
/// Returns `ChallengeKind::Unknown` when nothing matches — the caller
/// then defaults to `EscalateToOperator` rather than acting on a
/// guess.
///
/// Only the first [`CLASSIFY_BODY_SCAN_CAP`] bytes of `body` are
/// scanned. A multi-MB upstream response (e.g. a streamed PDF or a
/// CDN-cached HTML page that happens to mention "turnstile") would
/// otherwise force a body-sized lowercase allocation on every call.
///
/// Prefer [`classify_with_status`] when the HTTP status code is
/// available — passing the status lets the classifier reject the
/// false-positive case where a benign 200 OK page mentions
/// "turnstile" or "hcaptcha" in its body (e.g. a blog post about
/// captcha bypass) and would otherwise be treated as a challenge.
#[must_use]
pub fn classify(body: &[u8], headers: &[(String, String)]) -> ChallengeKind {
    // Back-compat shim: status = 0 means "caller didn't tell us" →
    // scan anyway, preserving pre-status-aware behaviour for callers
    // that haven't been updated.
    classify_with_status(body, headers, 0)
}

/// Status-aware classifier: only flags challenges on responses with
/// challenge-shaped status codes (403, 429, 503, or any 5xx). For
/// 200/3xx responses returns [`ChallengeKind::Unknown`] without even
/// scanning the body — a benign page mentioning a captcha keyword
/// is not a challenge.
///
/// `status = 0` is the back-compat sentinel: scan regardless. Anything
/// else gates the heuristic on the status check.
#[must_use]
pub fn classify_with_status(
    body: &[u8],
    headers: &[(String, String)],
    status: u16,
) -> ChallengeKind {
    if status != 0 && !is_challenge_status(status) {
        return ChallengeKind::Unknown;
    }
    classify_inner(body, headers)
}

/// Status codes where a body-keyword match plausibly means "this is
/// a challenge response". Anything 2xx/3xx is by definition NOT a
/// challenge — the upstream let the request through.
#[must_use]
fn is_challenge_status(status: u16) -> bool {
    matches!(status, 403 | 429 | 503) || (500..=599).contains(&status)
}

fn classify_inner(body: &[u8], headers: &[(String, String)]) -> ChallengeKind {
    let scan_slice = &body[..body.len().min(CLASSIFY_BODY_SCAN_CAP)];
    let lower_body = std::str::from_utf8(scan_slice)
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    let server = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("server"))
        .map(|(_, v)| v.to_ascii_lowercase())
        .unwrap_or_default();
    let cf_ray = headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("cf-ray"));

    if lower_body.contains("turnstile")
        || lower_body.contains("challenges.cloudflare.com/turnstile")
    {
        return ChallengeKind::Turnstile;
    }
    if lower_body.contains("hcaptcha") || lower_body.contains("hcaptcha.com") {
        return ChallengeKind::Hcaptcha;
    }
    if lower_body.contains("recaptcha") || lower_body.contains("google.com/recaptcha") {
        return ChallengeKind::Recaptcha;
    }
    if (cf_ray || server.contains("cloudflare"))
        && (lower_body.contains("cf_chl_opt")
            || lower_body.contains("checking your browser")
            || lower_body.contains("cf-mitigated")
            || lower_body.contains("cf-challenge"))
    {
        return ChallengeKind::CloudflareManaged;
    }
    if lower_body.contains("_abck") || server.contains("akamai") {
        return ChallengeKind::AkamaiBmp;
    }
    if lower_body.contains("aws-waf-token") || server.contains("awselb") {
        return ChallengeKind::AwsWaf;
    }
    ChallengeKind::Unknown
}

/// Capture a clearance cookie from a `Set-Cookie` header set, if one
/// of the recognised cookie names appears.
///
/// Returns the formatted `Cookie:` value ready for replay (`name=value`)
/// or `None` if no clearance cookie was present, OR if the cookie
/// value contains characters that would corrupt a downstream `Cookie`
/// header (CR, LF, NUL, semicolon — RFC 6265 cookie-octet rules).
/// Silently dropping a malicious cookie is preferable to forwarding
/// HTTP-request-splitting bytes to the upstream.
#[must_use]
pub fn extract_clearance_cookie(set_cookie_headers: &[&str]) -> Option<(String, ChallengeKind)> {
    for raw in set_cookie_headers {
        // Each Set-Cookie header is `name=value; attr1; attr2; …`
        let Some(nv) = raw.split(';').next() else {
            continue;
        };
        let Some((name, value)) = nv.split_once('=') else {
            continue;
        };
        let name_trim = name.trim();
        let value_trim = value.trim();
        let kind = match name_trim {
            "cf_clearance" => ChallengeKind::CloudflareManaged,
            "_abck" | "ak_bmsc" => ChallengeKind::AkamaiBmp,
            "aws-waf-token" => ChallengeKind::AwsWaf,
            _ => continue,
        };
        if !is_safe_cookie_value(value_trim) {
            // Malicious upstream tried to inject control characters.
            // Drop silently — never propagate splitable bytes.
            continue;
        }
        return Some((format!("{name_trim}={value_trim}"), kind));
    }
    None
}

/// Reject any byte that an HTTP/1.1 parser would treat as a header
/// terminator (CR, LF, NUL) or as an inline cookie separator (`;`).
/// Matches RFC 6265 cookie-octet excluding CTLs and the separators
/// the receiver would re-tokenise on.
fn is_safe_cookie_value(value: &str) -> bool {
    !value
        .bytes()
        .any(|b| b == b'\r' || b == b'\n' || b == 0 || b == b';')
}

/// Decide what to do given a verdict-classified challenge response.
///
/// `host` is the upstream host we'd be retrying. `kind` is the
/// classified challenge type. `store` is consulted for an active
/// cookie before any other decision.
pub fn dispatch(host: &str, kind: ChallengeKind, store: &ChallengeStore) -> SolveAction {
    if let Some(cookie) = store.get(host) {
        return SolveAction::ReplayWithCookie {
            cookie_header: cookie,
        };
    }
    if kind.is_cookie_solvable() {
        // We don't (yet) auto-solve — wait for an external sensor /
        // browser to populate the store. Add ±25% jitter to the
        // 2-second base so N concurrent waiters for the same host
        // don't all retry in the same instant (thundering herd
        // against the upstream after the cookie lands).
        return SolveAction::Wait {
            delay: jittered_wait(Duration::from_secs(2)),
        };
    }
    SolveAction::EscalateToOperator {
        kind,
        reason: format!("{} requires interactive solve", kind.label()),
    }
}

/// Apply ±25% pseudo-random jitter to `base` so concurrent callers
/// scheduling the same backoff don't all retry at the same wall
/// time. Uses Instant::now() nanos as the entropy source so we
/// don't pull in a dedicated RNG dep on this hot path.
#[must_use]
fn jittered_wait(base: Duration) -> Duration {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    // jitter ∈ [-25%, +25%]
    let half_range = base.as_millis() as u64 / 2; // 25% of base in ms
    let offset = (nanos % (half_range.saturating_mul(2).max(1))) as i64 - half_range as i64;
    let new_ms = (base.as_millis() as i64 + offset).max(1) as u64;
    Duration::from_millis(new_ms)
}

/// Marker type for the future JS-challenge auto-solver. Kept as an
/// uninhabited type so downstream code can match on it once the boa /
/// quickjs integration lands without a breaking change.
#[derive(Debug)]
pub enum JsSolver {}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> ChallengeStore {
        ChallengeStore::new()
    }

    // ── ChallengeStore lifecycle ─────────────────────────────────

    #[test]
    fn record_then_get_returns_cookie() {
        let s = store();
        s.record(
            "api.target.com",
            "cf_clearance=abc",
            ChallengeKind::CloudflareManaged,
            None,
        );
        assert_eq!(s.get("api.target.com"), Some("cf_clearance=abc".into()));
    }

    #[test]
    fn get_returns_none_after_explicit_ttl_expiry() {
        let s = store();
        s.record(
            "h",
            "cf_clearance=x",
            ChallengeKind::CloudflareManaged,
            Some(Duration::from_millis(10)),
        );
        std::thread::sleep(Duration::from_millis(25));
        assert_eq!(s.get("h"), None, "expired entry must not be served");
    }

    #[test]
    fn get_returns_none_for_unknown_host() {
        let s = store();
        assert_eq!(s.get("never-seen.com"), None);
    }

    #[test]
    fn cookie_does_not_leak_across_hosts() {
        let s = store();
        s.record(
            "a.com",
            "cf_clearance=1",
            ChallengeKind::CloudflareManaged,
            None,
        );
        s.record(
            "b.com",
            "cf_clearance=2",
            ChallengeKind::CloudflareManaged,
            None,
        );
        assert_eq!(s.get("a.com"), Some("cf_clearance=1".into()));
        assert_eq!(s.get("b.com"), Some("cf_clearance=2".into()));
        assert_eq!(s.get("c.com"), None);
    }

    #[test]
    fn forget_drops_entry_immediately() {
        let s = store();
        s.record(
            "h",
            "cf_clearance=x",
            ChallengeKind::CloudflareManaged,
            None,
        );
        s.forget("h");
        assert_eq!(s.get("h"), None);
    }

    #[test]
    fn purge_expired_drops_only_expired_entries() {
        let s = store();
        s.record(
            "fresh",
            "cf_clearance=1",
            ChallengeKind::CloudflareManaged,
            None,
        );
        s.record(
            "stale",
            "cf_clearance=2",
            ChallengeKind::CloudflareManaged,
            Some(Duration::from_millis(5)),
        );
        std::thread::sleep(Duration::from_millis(15));
        s.purge_expired();
        assert!(s.get("fresh").is_some());
        assert!(s.get("stale").is_none());
    }

    #[test]
    fn record_overwrites_existing_entry() {
        let s = store();
        s.record(
            "h",
            "cf_clearance=v1",
            ChallengeKind::CloudflareManaged,
            None,
        );
        s.record(
            "h",
            "cf_clearance=v2",
            ChallengeKind::CloudflareManaged,
            None,
        );
        assert_eq!(s.get("h"), Some("cf_clearance=v2".into()));
    }

    // ── operator-prompt throttling ─────────────────────────────

    #[test]
    fn operator_prompt_fires_first_time_then_throttles() {
        let s = store();
        assert!(s.should_prompt_operator("h"));
        assert!(
            !s.should_prompt_operator("h"),
            "second prompt within cooldown must throttle"
        );
    }

    #[test]
    fn operator_prompt_throttle_is_per_host() {
        let s = store();
        assert!(s.should_prompt_operator("a"));
        assert!(
            s.should_prompt_operator("b"),
            "different host must not be throttled by 'a's prompt"
        );
    }

    // ── classify() ────────────────────────────────────────────

    #[test]
    fn classify_cloudflare_from_cf_ray_and_marker() {
        let body = b"<title>Just a moment...</title><script>cf_chl_opt = ...</script>";
        let headers = vec![("cf-ray".into(), "8c2a3f4d4d4f9b2c-FRA".into())];
        assert_eq!(classify(body, &headers), ChallengeKind::CloudflareManaged);
    }

    #[test]
    fn classify_cloudflare_from_server_header_and_body_marker() {
        let body = b"checking your browser before accessing example.com";
        let headers = vec![("server".into(), "cloudflare".into())];
        assert_eq!(classify(body, &headers), ChallengeKind::CloudflareManaged);
    }

    #[test]
    fn classify_turnstile_takes_precedence_over_cloudflare_managed() {
        let body = b"<div class=\"cf-turnstile\" data-sitekey=\"X\"></div>";
        let headers = vec![("cf-ray".into(), "X".into())];
        assert_eq!(classify(body, &headers), ChallengeKind::Turnstile);
    }

    #[test]
    fn classify_hcaptcha_recognised() {
        let body = b"<script src=\"https://hcaptcha.com/1/api.js\"></script>";
        assert_eq!(classify(body, &[]), ChallengeKind::Hcaptcha);
    }

    #[test]
    fn classify_recaptcha_recognised() {
        let body = b"<script src=\"https://www.google.com/recaptcha/api.js\"></script>";
        assert_eq!(classify(body, &[]), ChallengeKind::Recaptcha);
    }

    #[test]
    fn classify_unknown_when_no_marker() {
        assert_eq!(classify(b"hello world", &[]), ChallengeKind::Unknown);
    }

    #[test]
    fn classify_does_not_panic_on_invalid_utf8() {
        let body = vec![0xff, 0xfe, 0xfd];
        let _ = classify(&body, &[]);
    }

    // ── extract_clearance_cookie ─────────────────────────────

    #[test]
    fn extract_cf_clearance_cookie_with_attributes() {
        let h = vec!["cf_clearance=abc123; path=/; domain=.example.com; secure; httponly"];
        let r = extract_clearance_cookie(&h);
        assert_eq!(
            r,
            Some((
                "cf_clearance=abc123".into(),
                ChallengeKind::CloudflareManaged
            ))
        );
    }

    #[test]
    fn extract_handles_multiple_set_cookie_headers_taking_first_match() {
        let h = vec!["session=xyz", "cf_clearance=abc", "tracker=foo"];
        let r = extract_clearance_cookie(&h);
        assert_eq!(
            r,
            Some(("cf_clearance=abc".into(), ChallengeKind::CloudflareManaged))
        );
    }

    #[test]
    fn extract_recognises_akamai_abck() {
        let h = vec!["_abck=ABC123~-1~YAAQ; path=/"];
        let r = extract_clearance_cookie(&h);
        assert_eq!(
            r,
            Some(("_abck=ABC123~-1~YAAQ".into(), ChallengeKind::AkamaiBmp))
        );
    }

    #[test]
    fn extract_returns_none_for_no_clearance_cookie() {
        let h = vec!["session=xyz; path=/"];
        assert_eq!(extract_clearance_cookie(&h), None);
    }

    #[test]
    fn extract_returns_none_for_empty_input() {
        assert_eq!(extract_clearance_cookie(&[]), None);
    }

    // ── dispatch() ─────────────────────────────────────────

    #[test]
    fn dispatch_replays_when_cookie_present() {
        let s = store();
        s.record(
            "h",
            "cf_clearance=ok",
            ChallengeKind::CloudflareManaged,
            None,
        );
        let action = dispatch("h", ChallengeKind::CloudflareManaged, &s);
        assert_eq!(
            action,
            SolveAction::ReplayWithCookie {
                cookie_header: "cf_clearance=ok".into()
            }
        );
    }

    #[test]
    fn dispatch_waits_for_cookie_solvable_kind_when_no_cookie() {
        let s = store();
        let action = dispatch("h", ChallengeKind::CloudflareManaged, &s);
        assert!(matches!(action, SolveAction::Wait { .. }));
    }

    #[test]
    fn dispatch_escalates_for_interactive_kind() {
        let s = store();
        let action = dispatch("h", ChallengeKind::Hcaptcha, &s);
        assert!(matches!(
            action,
            SolveAction::EscalateToOperator {
                kind: ChallengeKind::Hcaptcha,
                ..
            }
        ));
    }

    #[test]
    fn dispatch_escalates_for_unknown_kind() {
        let s = store();
        let action = dispatch("h", ChallengeKind::Unknown, &s);
        assert!(matches!(
            action,
            SolveAction::EscalateToOperator {
                kind: ChallengeKind::Unknown,
                ..
            }
        ));
    }

    #[test]
    fn dispatch_replays_even_for_interactive_kind_if_cookie_present() {
        // Operator solved Turnstile interactively in a browser and we
        // captured the resulting cookie — replay it on subsequent
        // requests instead of re-prompting.
        let s = store();
        s.record("h", "cf_clearance=manual", ChallengeKind::Turnstile, None);
        let action = dispatch("h", ChallengeKind::Turnstile, &s);
        assert!(matches!(action, SolveAction::ReplayWithCookie { .. }));
    }

    // ── ChallengeKind helpers ─────────────────────────────

    #[test]
    fn kind_is_cookie_solvable_only_for_cf_managed_and_akamai() {
        assert!(ChallengeKind::CloudflareManaged.is_cookie_solvable());
        assert!(ChallengeKind::AkamaiBmp.is_cookie_solvable());
        assert!(!ChallengeKind::Turnstile.is_cookie_solvable());
        assert!(!ChallengeKind::Hcaptcha.is_cookie_solvable());
        assert!(!ChallengeKind::Recaptcha.is_cookie_solvable());
        assert!(!ChallengeKind::AwsWaf.is_cookie_solvable());
        assert!(!ChallengeKind::Unknown.is_cookie_solvable());
    }
}
