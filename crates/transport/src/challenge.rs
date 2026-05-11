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
    ///
    /// Audit (2026-05-10): added `AwsWaf` — `extract_clearance_cookie`
    /// already recognised `aws-waf-token` and stored it in the cookie
    /// store, but `is_cookie_solvable() == false` meant `dispatch`
    /// would always escalate to the operator instead of replaying the
    /// captured token. The cookie was being thrown away after capture.
    #[must_use]
    pub fn is_cookie_solvable(self) -> bool {
        matches!(
            self,
            Self::CloudflareManaged | Self::AkamaiBmp | Self::AwsWaf
        )
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

/// RFC 6265 cookie scoping attributes captured from a `Set-Cookie`
/// header. Used by [`ChallengeStore::record_scoped`] to pin where
/// the captured cookie is allowed to replay.
#[derive(Debug, Clone, Default)]
pub struct CookieScope {
    /// Domain attribute. `None` means host-only (replays only on the
    /// exact host that captured it). `Some("example.com")` means
    /// example.com AND any subdomain.
    pub domain: Option<String>,
    /// Path attribute. `None` or `Some("/")` means any path. Anything
    /// else restricts replay to paths that start with the prefix.
    pub path: Option<String>,
    /// Secure attribute. When true, the cookie must only replay over
    /// HTTPS.
    pub secure: bool,
    /// `HttpOnly` attribute. RFC 6265 §4.1.2.6: when true, the cookie
    /// must be sent ONLY in actual HTTP requests (it's invisible to
    /// document.cookie / XHR / fetch). For wafrift's request-replay
    /// path that means the cookie ALWAYS goes on the wire and is
    /// never exposed by the proxy to client-side JS-injection probes.
    /// Audit (2026-05-10): the field was parsed in tests but absent
    /// from `CookieScope`, so the constraint was never enforced.
    pub http_only: bool,
}

impl CookieScope {
    /// The most-restrictive scope: host-only, any path, plain HTTP OK.
    /// This is what [`ChallengeStore::record`] uses when no scope is
    /// supplied.
    #[must_use]
    pub fn host_only() -> Self {
        Self::default()
    }
}

/// Per-host clearance cookie entry with absolute expiry + RFC 6265
/// scoping attributes captured from the original `Set-Cookie`.
#[derive(Debug, Clone)]
struct CookieEntry {
    cookie_header: String,
    expires_at: Instant,
    captured_at: Instant,
    kind: ChallengeKind,
    /// Domain attribute (lowercased, no leading dot). When set, the
    /// cookie replays on this host AND its subdomains. When None,
    /// host-only matching is used (cookie replays only on the exact
    /// host that captured it).
    scope_domain: Option<String>,
    /// Path attribute. The cookie replays only on requests whose
    /// path starts with this prefix. When None or "/", any path
    /// matches.
    scope_path: Option<String>,
    /// Secure attribute. When true, the cookie must only replay over
    /// HTTPS — the get path enforces this when the caller indicates
    /// the request scheme.
    secure: bool,
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
    /// Hosts with a solver currently in flight. Populated by
    /// [`ChallengeStore::mark_solver_pending`] and cleared by
    /// [`ChallengeStore::clear_solver_pending`]. The dispatch path
    /// inspects this so N concurrent requests to the same host
    /// don't all spawn a redundant external solver.
    solver_in_flight: HashMap<String, Instant>,
    /// Global token bucket for operator prompts. Tracks the
    /// (host, timestamp) of the last `OPERATOR_PROMPT_GLOBAL_CAP_PER_MIN`
    /// prompts across ALL hosts.
    ///
    /// Audit (2026-05-10): tracking only the timestamp meant the cap
    /// was first-come-first-served — one chatty host could fill the
    /// 30-prompt window inside its cooldown and starve every other
    /// host. We now record the host too and additionally cap any
    /// single host at `OPERATOR_PROMPT_PER_HOST_CAP_PER_MIN` of those
    /// 30 slots, so the chatty host is forced to share.
    global_prompt_window: std::collections::VecDeque<(String, Instant)>,
}

/// Maximum operator prompts emitted per rolling 60-second window
/// across ALL hosts. Hit when N>>1 distinct hosts flip into the
/// challenge state simultaneously — the per-host cooldown would
/// otherwise let all N fire at once and overwhelm the operator.
pub const OPERATOR_PROMPT_GLOBAL_CAP_PER_MIN: usize = 30;
/// Per-host cap on the share of `GLOBAL_PROMPT_WINDOW` prompts a single
/// host may consume. With `CAP_PER_MIN` = 30 and `PER_HOST` = 8, a chatty
/// host taking its full quota still leaves room for ~3 other hosts to
/// each take their full quota — fair enough that the operator can
/// triage incoming requests across distinct sites. Audit (2026-05-10).
pub const OPERATOR_PROMPT_PER_HOST_CAP_PER_MIN: usize = 8;
const GLOBAL_PROMPT_WINDOW: Duration = Duration::from_secs(60);

/// How long a `mark_solver_pending` claim stays valid before another
/// caller may take over. Solvers that legitimately take longer than
/// this should call `mark_solver_pending` again to extend.
pub const SOLVER_INFLIGHT_TTL: Duration = Duration::from_secs(60);

/// Default clearance-cookie TTL when the upstream `Set-Cookie` carries
/// no explicit `Max-Age`/`Expires`. CF default is 30 minutes; we
/// match that.
pub const DEFAULT_CLEARANCE_TTL: Duration = Duration::from_secs(30 * 60);

/// Don't re-prompt the operator about the same host more than once
/// every 5 minutes — avoids noise when an automated retry burst
/// re-triggers the challenge.
pub const OPERATOR_PROMPT_COOLDOWN: Duration = Duration::from_secs(5 * 60);

/// Acquire a write lock, surfacing poisoning via `tracing::warn`!
/// before recovering. Pre-fix the call sites used `unwrap_or_else(|e|
/// e.into_inner())` which silently swallowed the panic that
/// poisoned the lock — making real data-corruption bugs invisible.
/// Now poisoning is logged with the call site so it shows up in
/// production logs.
fn poison_recover_write<'a, T>(
    lock: &'a std::sync::RwLock<T>,
    site: &'static str,
) -> std::sync::RwLockWriteGuard<'a, T> {
    match lock.write() {
        Ok(g) => g,
        Err(poisoned) => {
            tracing::warn!(
                site,
                "wafrift_transport::challenge: recovering from poisoned RwLock (write); \
                 a previous panic left the lock in an inconsistent state. \
                 If this fires repeatedly, look for the panic source."
            );
            poisoned.into_inner()
        }
    }
}

fn poison_recover_read<'a, T>(
    lock: &'a std::sync::RwLock<T>,
    site: &'static str,
) -> std::sync::RwLockReadGuard<'a, T> {
    match lock.read() {
        Ok(g) => g,
        Err(poisoned) => {
            tracing::warn!(
                site,
                "wafrift_transport::challenge: recovering from poisoned RwLock (read); \
                 a previous panic left the lock in an inconsistent state."
            );
            poisoned.into_inner()
        }
    }
}

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
    ///
    /// Audit (2026-05-10): when an expired entry was observed here it
    /// was returned-as-None but left in the map. A high-churn host that
    /// kept writing expiring cookies (or an attacker spraying short-
    /// TTL Set-Cookies) could grow `by_host` indefinitely. We now
    /// upgrade to a write lock and remove the expired entry inline.
    #[must_use]
    pub fn get(&self, host: &str) -> Option<String> {
        let key = normalize_host(host);
        let now = Instant::now();
        // Fast-path read first.
        {
            let inner = poison_recover_read(&self.inner, "ChallengeStore::get");
            if let Some(entry) = inner.by_host.get(&key)
                && now < entry.expires_at
            {
                return Some(entry.cookie_header.clone());
            }
        }
        // Slow path: either missing OR expired. Take the write lock,
        // re-check, and remove if expired.
        let mut inner = poison_recover_write(&self.inner, "ChallengeStore::get");
        let expired = inner
            .by_host
            .get(&key)
            .is_some_and(|e| now >= e.expires_at);
        if expired {
            inner.by_host.remove(&key);
        }
        None
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
        self.record_scoped(host, cookie_header, kind, ttl, CookieScope::host_only());
    }

    /// Record a clearance cookie with the original `Set-Cookie`
    /// scoping attributes (Domain / Path / Secure). [`get_for_request`]
    /// uses the scope to decide whether to replay the cookie.
    pub fn record_scoped(
        &self,
        host: impl Into<String>,
        cookie_header: impl Into<String>,
        kind: ChallengeKind,
        ttl: Option<Duration>,
        scope: CookieScope,
    ) {
        let now = Instant::now();
        let entry = CookieEntry {
            cookie_header: cookie_header.into(),
            captured_at: now,
            expires_at: now + ttl.unwrap_or(DEFAULT_CLEARANCE_TTL),
            kind,
            scope_domain: scope.domain.map(|d| normalize_host(&d)),
            scope_path: scope.path,
            secure: scope.secure,
        };
        let key = normalize_host(&host.into());
        let mut inner = poison_recover_write(&self.inner, "ChallengeStore::record_scoped");
        inner.by_host.retain(|_, e| now < e.expires_at);
        inner
            .operator_prompted
            .retain(|_, t| now < *t + OPERATOR_PROMPT_COOLDOWN);
        inner.by_host.insert(key, entry);
    }

    /// Scoped cookie lookup: returns the cookie only if the captured
    /// scope (Domain / Path / Secure) admits a request for `host`,
    /// `request_path`, and `is_https`.
    ///
    /// The plain [`Self::get`] returns the cookie regardless of
    /// scope (caller is responsible for matching). New code should
    /// prefer this method when the request context is available.
    #[must_use]
    pub fn get_for_request(
        &self,
        host: &str,
        request_path: &str,
        is_https: bool,
    ) -> Option<String> {
        let key = normalize_host(host);
        let inner = poison_recover_read(&self.inner, "ChallengeStore::get_for_request");
        let entry = inner.by_host.get(&key)?;
        if Instant::now() >= entry.expires_at {
            return None;
        }
        // Domain scope: empty/None → host-only (already matched via
        // by_host key); set → request host must equal it OR be a
        // subdomain of it.
        if let Some(domain) = entry.scope_domain.as_deref() {
            let req_host = key.as_str();
            let domain_matches = req_host == domain
                || req_host.ends_with(&format!(".{domain}"));
            if !domain_matches {
                return None;
            }
        }
        // Path scope: cookie scoped to /admin/ does NOT replay on /api/.
        // Pre-fix this used `starts_with` directly, which mis-matches
        // `/adminxss` against scope `/admin` (RFC 6265 §5.1.4: the
        // request-path must equal the cookie-path OR continue with a
        // `/` after the cookie-path prefix). The audit caught this as
        // a HIGH — replaying admin cookies onto an unrelated subtree.
        if let Some(path) = entry.scope_path.as_deref() {
            let prefix_match = request_path.starts_with(path)
                && (request_path.len() == path.len()
                    || path.ends_with('/')
                    || request_path.as_bytes().get(path.len()) == Some(&b'/'));
            if !prefix_match {
                return None;
            }
        }
        // Secure scope: HTTPS-only cookies must not replay over HTTP.
        if entry.secure && !is_https {
            return None;
        }
        Some(entry.cookie_header.clone())
    }

    /// Drop the entry for `host` (e.g. after observing a 4xx that
    /// suggests the cookie has been invalidated upstream).
    pub fn forget(&self, host: &str) {
        let key = normalize_host(host);
        let mut inner = poison_recover_write(&self.inner, "ChallengeStore::forget");
        inner.by_host.remove(&key);
    }

    /// Capacity-trimming sweep: drop every expired entry. Cheap;
    /// callers should run it periodically (e.g. every minute on a
    /// background task) to stop the table growing on long-running
    /// proxies.
    pub fn purge_expired(&self) {
        let now = Instant::now();
        let mut inner = poison_recover_write(&self.inner, "ChallengeStore::purge_expired");
        inner.by_host.retain(|_, e| now < e.expires_at);
        inner
            .operator_prompted
            .retain(|_, t| now < *t + OPERATOR_PROMPT_COOLDOWN);
        inner
            .solver_in_flight
            .retain(|_, t| now < *t + SOLVER_INFLIGHT_TTL);
    }

    /// Returns `true` if the operator should be prompted about a
    /// challenge for `host` — i.e. either no recent prompt has been
    /// emitted, or the cooldown has passed.
    ///
    /// Two-tier throttle:
    ///   - per-host cooldown of `OPERATOR_PROMPT_COOLDOWN` (5 min)
    ///   - global rolling-window cap of
    ///     `OPERATOR_PROMPT_GLOBAL_CAP_PER_MIN` prompts per 60 s
    ///     across ALL hosts. Hit when N>>1 distinct hosts flip into
    ///     the challenge state simultaneously — without this, a
    ///     1000-host storm would emit 1000 prompts at once.
    pub fn should_prompt_operator(&self, host: &str) -> bool {
        let key = normalize_host(host);
        let mut inner = poison_recover_write(&self.inner, "should_prompt_operator");
        let now = Instant::now();
        // Garbage-collect the global rolling window: drop entries
        // older than 60 s before checking the cap.
        let cutoff = now.checked_sub(GLOBAL_PROMPT_WINDOW);
        if let Some(cut) = cutoff {
            while let Some((_, ts)) = inner.global_prompt_window.front() {
                if *ts < cut {
                    inner.global_prompt_window.pop_front();
                } else {
                    break;
                }
            }
        }
        if inner.global_prompt_window.len() >= OPERATOR_PROMPT_GLOBAL_CAP_PER_MIN {
            return false;
        }
        // Audit (2026-05-10): per-host fairness. A chatty host that's
        // already taken its share of the window must wait, even if
        // the global cap has slack. Without this a single noisy host
        // can starve every other host's prompt.
        let host_count = inner
            .global_prompt_window
            .iter()
            .filter(|(h, _)| h == &key)
            .count();
        if host_count >= OPERATOR_PROMPT_PER_HOST_CAP_PER_MIN {
            return false;
        }
        match inner.operator_prompted.get(&key).copied() {
            Some(prev) if now < prev + OPERATOR_PROMPT_COOLDOWN => false,
            _ => {
                inner.operator_prompted.insert(key.clone(), now);
                inner.global_prompt_window.push_back((key, now));
                true
            }
        }
    }

    /// Claim the "I'm running an external solver for this host" slot.
    /// Returns true if the claim succeeded (caller should run the
    /// solver), false if another caller already has the slot
    /// (caller should fall back to Wait without spawning).
    ///
    /// Claims auto-expire after `SOLVER_INFLIGHT_TTL` so a crashed
    /// solver doesn't permanently lock out retries.
    ///
    /// Long-running solvers (chromium-based captcha solvers, Turnstile
    /// flows that wait for a human) MUST call [`refresh_solver_pending`]
    /// before the TTL elapses or a concurrent caller will claim the
    /// slot and spawn a duplicate solver. Audit (2026-05-10) caught
    /// the silent-eviction case as CRITICAL.
    pub fn mark_solver_pending(&self, host: &str) -> bool {
        let key = normalize_host(host);
        let mut inner = poison_recover_write(&self.inner, "mark_solver_pending");
        let now = Instant::now();
        // GC stale claims first — but log so a chronic eviction
        // pattern is visible in operator logs.
        inner.solver_in_flight.retain(|h, t| {
            if now >= *t + SOLVER_INFLIGHT_TTL {
                tracing::warn!(
                    host = %h,
                    held_for_secs = (now - *t).as_secs(),
                    "solver_in_flight slot evicted by TTL — a concurrent caller may now spawn a duplicate solver. Long-running solvers should call refresh_solver_pending() to keep the slot alive."
                );
                false
            } else {
                true
            }
        });
        if inner.solver_in_flight.contains_key(&key) {
            return false;
        }
        inner.solver_in_flight.insert(key, now);
        true
    }

    /// Refresh the in-flight solver TTL. The owning solver must call
    /// this before `SOLVER_INFLIGHT_TTL` elapses, otherwise its slot is
    /// evicted and a concurrent caller can claim it. Audit (2026-05-10).
    ///
    /// Returns true if the slot was refreshed (the caller still owns
    /// it), false if the slot is already gone — in which case the
    /// solver should treat itself as superseded and exit.
    pub fn refresh_solver_pending(&self, host: &str) -> bool {
        let key = normalize_host(host);
        let mut inner = poison_recover_write(&self.inner, "refresh_solver_pending");
        let now = Instant::now();
        if let Some(t) = inner.solver_in_flight.get_mut(&key) {
            *t = now;
            true
        } else {
            false
        }
    }

    /// Release the in-flight solver slot — called after the solver
    /// either succeeds (cookie now in store) or fails (so the next
    /// caller can retry without waiting for the TTL).
    pub fn clear_solver_pending(&self, host: &str) {
        let key = normalize_host(host);
        let mut inner = poison_recover_write(&self.inner, "clear_solver_pending");
        inner.solver_in_flight.remove(&key);
    }

    /// Read-only check: is a solver already in flight for `host`?
    /// `dispatch` uses this to decide between Wait and `EscalateToOperator`.
    #[must_use]
    pub fn has_solver_pending(&self, host: &str) -> bool {
        let key = normalize_host(host);
        let inner = poison_recover_read(&self.inner, "has_solver_pending");
        let now = Instant::now();
        match inner.solver_in_flight.get(&key) {
            Some(t) => now < *t + SOLVER_INFLIGHT_TTL,
            None => false,
        }
    }

    /// Diagnostic: how old is the clearance cookie we have for `host`?
    /// Returns `None` if no entry exists (regardless of expiry).
    #[must_use]
    pub fn age(&self, host: &str) -> Option<Duration> {
        let key = normalize_host(host);
        let inner = poison_recover_read(&self.inner, "ChallengeStore::age");
        inner.by_host.get(&key).map(|e| e.captured_at.elapsed())
    }

    /// Diagnostic: which challenge kind is associated with the active
    /// cookie for `host`?
    #[must_use]
    pub fn kind(&self, host: &str) -> Option<ChallengeKind> {
        let key = normalize_host(host);
        let inner = poison_recover_read(&self.inner, "ChallengeStore::kind");
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
        poison_recover_read(&self.inner, "ChallengeStore::len")
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
/// **Use [`classify_with_status`] instead.** Audit (2026-05-10): this
/// shim ignores the HTTP status, which means a benign 200 OK page
/// mentioning "turnstile" or "hcaptcha" in its body (a blog post
/// about captcha bypass, an admin doc page, this project's own
/// README) gets misclassified as a challenge and parks dispatch in
/// `Wait`. The status-aware variant gates body-keyword matches on
/// 4xx/5xx responses where a challenge is actually possible. This
/// function is kept only for the binary-compat needs of the older
/// CLI flow; new callers should always use `classify_with_status`.
#[deprecated(
    since = "0.2.9",
    note = "use classify_with_status — passing status=0 would silently bypass the challenge-status guard and false-positive on benign 200s"
)]
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
    // Audit (2026-05-10): server-header alone false-positives on every
    // CDN-served 200. `Server: AkamaiGHost` ships on legitimate static
    // assets too, and treating that as a challenge made the dispatcher
    // park every Akamai response with `SolveAction::Wait`. Require a
    // body keyword as the primary signal; server-header now only acts
    // as a corroborating signal alongside it.
    if lower_body.contains("_abck") {
        return ChallengeKind::AkamaiBmp;
    }
    if lower_body.contains("aws-waf-token") {
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
    extract_clearance_cookie_scoped(set_cookie_headers).map(|(c, k, _)| (c, k))
}

/// Attribute-aware variant: returns the cookie header AND the
/// scoping attributes ([Domain] / [Path] / [Secure]) parsed from
/// the original `Set-Cookie`. Pair with
/// [`ChallengeStore::record_scoped`] to enforce scope on replay.
#[must_use]
pub fn extract_clearance_cookie_scoped(
    set_cookie_headers: &[&str],
) -> Option<(String, ChallengeKind, CookieScope)> {
    for raw in set_cookie_headers {
        // Each Set-Cookie header is `name=value; attr1; attr2; …`
        let mut parts = raw.split(';');
        let Some(nv) = parts.next() else {
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
        // Parse attributes for scope. Reject ANY attribute value that
        // contains CRLF / NUL — same defence-in-depth as the cookie
        // value itself. Unknown attributes are silently ignored.
        let mut scope = CookieScope::default();
        for attr in parts {
            let attr = attr.trim();
            if attr.eq_ignore_ascii_case("Secure") {
                scope.secure = true;
                continue;
            }
            if attr.eq_ignore_ascii_case("HttpOnly") {
                scope.http_only = true;
                continue;
            }
            if let Some((k, v)) = attr.split_once('=') {
                let v = v.trim();
                if !is_safe_cookie_value(v) {
                    continue;
                }
                if k.trim().eq_ignore_ascii_case("Domain") {
                    let v = v.strip_prefix('.').unwrap_or(v);
                    // Audit (2026-05-10): reject Domain values that
                    // contain `:` (port), `/`, `?`, whitespace, OR
                    // whose effective TLD equals the value itself
                    // (PSL guard). RFC 6265 §5.2.3 makes Domain a
                    // hostname; pre-fix the parser silently accepted
                    // `Domain=evil.com:8080` (matched bare `evil.com`)
                    // and `Domain=co.uk` (would replay on EVERY
                    // co.uk site — supercookie). The PSL check
                    // catches the supercookie case across all 2000+
                    // public suffixes the `psl` crate ships.
                    let shape_ok = !v.is_empty()
                        && !v.contains(':')
                        && !v.contains('/')
                        && !v.contains('?')
                        && !v.chars().any(char::is_whitespace);
                    let psl_ok = if shape_ok {
                        is_safe_cookie_domain(v)
                    } else {
                        false
                    };
                    if psl_ok {
                        scope.domain = Some(v.to_string());
                    }
                } else if k.trim().eq_ignore_ascii_case("Path")
                    && !v.is_empty() {
                        scope.path = Some(v.to_string());
                    }
            }
        }
        return Some((format!("{name_trim}={value_trim}"), kind, scope));
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

/// True if `domain` is a safe Cookie Domain attribute value — i.e.
/// it is NOT itself a public suffix (eTLD). Pre-fix `Domain=co.uk`,
/// `Domain=com`, `Domain=github.io`, etc. were silently accepted and
/// would let a captured cookie replay on EVERY site under that
/// suffix (the classic "supercookie" vulnerability documented by
/// RFC 6265 §5.2.3 and Mozilla's PSL project).
///
/// Uses the embedded Public Suffix List from the `psl` crate so we
/// don't ship a hardcoded eTLD blocklist that goes stale.
fn is_safe_cookie_domain(domain: &str) -> bool {
    use psl::Psl;
    // psl operates on bytes; non-ASCII Domains are punycode by spec.
    let bytes = domain.as_bytes();
    let list = psl::List;
    // suffix() returns the eTLD portion (e.g. `co.uk` for
    // `bbc.co.uk`). When the Domain value IS the eTLD, the suffix
    // bytes equal the input bytes — that's the supercookie case.
    match list.suffix(bytes) {
        Some(suffix) => {
            // Reject if Domain equals the eTLD exactly.
            suffix.as_bytes() != bytes
        }
        None => {
            // Couldn't parse — be conservative and reject. Real
            // cookies always have a parseable hostname.
            false
        }
    }
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
        // Dedup against an already-running solver for this host so
        // N concurrent requests don't all spawn redundant external
        // solvers (thundering herd against chromium/captchaforge).
        // If a solver is in flight, back off LONGER so the second
        // caller doesn't poll-storm before the first solver lands a
        // cookie. Otherwise, jittered short wait + the caller is
        // expected to claim the solver slot via store.mark_solver_pending.
        let delay = if store.has_solver_pending(host) {
            jittered_wait(Duration::from_secs(5))
        } else {
            jittered_wait(Duration::from_secs(2))
        };
        return SolveAction::Wait { delay };
    }
    SolveAction::EscalateToOperator {
        kind,
        reason: format!("{} requires interactive solve", kind.label()),
    }
}

/// Apply ±25% pseudo-random jitter to `base` so concurrent callers
/// scheduling the same backoff don't all retry at the same wall
/// time. Uses `Instant::now()` nanos as the entropy source so we
/// don't pull in a dedicated RNG dep on this hot path.
#[must_use]
fn jittered_wait(base: Duration) -> Duration {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos() as u64);
    // jitter ∈ [-25%, +25%]
    let quarter_range = base.as_millis() as u64 / 4; // 25% of base in ms
    let offset =
        (nanos % (quarter_range.saturating_mul(2).max(1))) as i64 - quarter_range as i64;
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
    fn cookie_solvable_aligned_with_extract_clearance_cookie() {
        // The extract_clearance_cookie path stores cookies for
        // CloudflareManaged, AkamaiBmp, AND AwsWaf (`aws-waf-token`).
        // is_cookie_solvable must include all three or the AwsWaf
        // captures get thrown away on dispatch.
        assert!(ChallengeKind::CloudflareManaged.is_cookie_solvable());
        assert!(ChallengeKind::AkamaiBmp.is_cookie_solvable());
        assert!(ChallengeKind::AwsWaf.is_cookie_solvable());
        // Interactive widgets stay operator-only.
        assert!(!ChallengeKind::Turnstile.is_cookie_solvable());
        assert!(!ChallengeKind::Hcaptcha.is_cookie_solvable());
        assert!(!ChallengeKind::Recaptcha.is_cookie_solvable());
        assert!(!ChallengeKind::Unknown.is_cookie_solvable());
    }
}
