//! Wire-time header-order coherence for stealth transports.
//!
//! `wafrift-fingerprint::session` ships the canonical browser
//! header orders + H2 SETTINGS profiles, plus the `SessionPool`
//! primitive that gives the same host the same browser profile
//! across a session window. This module is the THIN bridge from
//! that library to the live transport path:
//!
//! - [`reorder_headers_for_profile`] takes the `--tls-impersonate`
//!   profile name + the caller's header bag, and returns a reordered
//!   bag in the browser's canonical insertion order. Headers not in
//!   the canonical slot list (custom evasion headers, etc.) follow
//!   the browser block at the tail — preserving the browser shape
//!   without dropping anything.
//!
//! - [`SharedSessionPool`] wraps a [`wafrift_fingerprint::session::SessionPool`]
//!   in an `Arc` so the proxy can clone it across many tokio tasks
//!   without re-allocating per-task profile state.
//!
//! Why this lives in `wafrift-transport` and not in fingerprint
//! itself: the fingerprint crate is dep-light (no HTTP, no TLS).
//! Pulling reqwest/rquest types in there would invert the dep
//! graph. Keeping the bridge here means the wire-time concerns
//! (header maps, request mutation) stay in the transport crate.

use std::sync::Arc;

use wafrift_fingerprint::fingerprint::BrowserProfile;
use wafrift_fingerprint::session::{HeaderOrder, SessionPool, pair_for_name};

/// Reorder `headers` to match the canonical insertion order of the
/// named browser family. Returns the input unchanged if `profile_name`
/// is not recognised — never panics, never errors. Coherence is
/// best-effort: an unknown profile is a config issue, not a transport
/// failure.
#[must_use]
pub fn reorder_headers_for_profile(
    profile_name: &str,
    headers: Vec<(String, String)>,
) -> Vec<(String, String)> {
    match pair_for_name(profile_name) {
        Some((order, _h2)) => order.apply_in_order(headers),
        None => headers,
    }
}

/// Direct (HeaderOrder, _) lookup — exposed so callers that want
/// the order without paying for the H2Profile clone get a small
/// fast path. Returns `None` for unknown profiles.
#[must_use]
pub fn header_order_for_profile(profile_name: &str) -> Option<HeaderOrder> {
    pair_for_name(profile_name).map(|(order, _)| order)
}

/// Thread-safe wrapper around `SessionPool` for the proxy path
/// (which spawns tokio tasks freely and needs cheap clones).
///
/// The pool itself uses interior `RwLock`s so the `Arc` does not
/// add lock contention beyond what `SessionPool` already manages —
/// it only saves the per-clone heap allocation of cloning the
/// underlying `Vec<&'static BrowserProfile>` profile list.
#[derive(Clone)]
pub struct SharedSessionPool(Arc<SessionPool>);

impl SharedSessionPool {
    /// New shared pool. `rotate_after_requests` follows `SessionPool`
    /// semantics: 0 is coerced to 1; same-host calls return the same
    /// profile until the counter trips, then re-shuffle.
    #[must_use]
    pub fn new(
        profiles: Vec<&'static BrowserProfile>,
        rotate_after_requests: u32,
    ) -> Self {
        Self(Arc::new(SessionPool::new(profiles, rotate_after_requests)))
    }

    /// Profile assigned to `host` for the current session. See
    /// `SessionPool::profile_for` for the rotation semantics.
    pub fn profile_for(&self, host: &str) -> &'static BrowserProfile {
        self.0.profile_for(host)
    }

    /// Forget every binding (e.g. at the start of a new scan run).
    pub fn clear(&self) {
        self.0.clear();
    }

    /// Snapshot of `(host, profile_name, request_count)` for the
    /// `wafrift-proxy --tui` host table.
    pub fn snapshot(&self) -> Vec<(String, &'static str, u32)> {
        self.0.snapshot()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wafrift_fingerprint::fingerprint::PROFILES;

    // ── reorder_headers_for_profile ────────────────────────────────

    #[test]
    fn reorder_for_chrome_promotes_host_to_first_position() {
        let input = vec![
            ("X-Custom".into(), "v".into()),
            ("Cookie".into(), "a=1".into()),
            ("Host".into(), "x.com".into()),
            ("User-Agent".into(), "chrome".into()),
        ];
        let out = reorder_headers_for_profile("chrome131", input);
        assert!(
            out[0].0.eq_ignore_ascii_case("host"),
            "Chrome's canonical order puts Host first; got `{}`",
            out[0].0
        );
    }

    #[test]
    fn reorder_for_unknown_profile_returns_input_unchanged() {
        let input = vec![
            ("X-A".into(), "1".into()),
            ("X-B".into(), "2".into()),
            ("X-C".into(), "3".into()),
        ];
        let cloned = input.clone();
        let out = reorder_headers_for_profile("never-a-browser", input);
        assert_eq!(
            out, cloned,
            "unknown profile must NOT panic or drop headers; pass-through expected"
        );
    }

    #[test]
    fn reorder_for_safari_drops_no_headers() {
        // Safari's slot list is much shorter than Chrome's; any
        // headers not in the Safari list must still come out (at the
        // tail) — never dropped.
        let input = vec![
            ("Host".into(), "x".into()),
            ("Accept".into(), "*/*".into()),
            ("Sec-Ch-Ua".into(), "leftover-from-prior-chrome-session".into()),
            ("User-Agent".into(), "safari".into()),
        ];
        let n_in = input.len();
        let out = reorder_headers_for_profile("safari18", input);
        assert_eq!(
            out.len(),
            n_in,
            "Safari reorder must preserve every header (count: in {n_in}, out {})",
            out.len()
        );
        // The leftover sec-ch-ua header isn't in Safari's slot list,
        // so it should appear AFTER user-agent (which IS in the list).
        let ua_pos = out
            .iter()
            .position(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
            .unwrap();
        let leftover_pos = out
            .iter()
            .position(|(k, _)| k.eq_ignore_ascii_case("sec-ch-ua"))
            .unwrap();
        assert!(
            leftover_pos > ua_pos,
            "non-slot header must follow the browser block: ua at {ua_pos}, leftover at {leftover_pos}"
        );
    }

    #[test]
    fn reorder_for_firefox_matches_firefox_canonical_order() {
        // Firefox's order puts user-agent IMMEDIATELY after host.
        // (Chrome puts sec-ch-ua between them.) This test pins the
        // family-specific shape.
        let input = vec![
            ("Cookie".into(), "x=1".into()),
            ("User-Agent".into(), "ff".into()),
            ("Host".into(), "x.com".into()),
        ];
        let out = reorder_headers_for_profile("firefox133", input);
        let host_pos = out.iter().position(|(k, _)| k.eq_ignore_ascii_case("host")).unwrap();
        let ua_pos = out.iter().position(|(k, _)| k.eq_ignore_ascii_case("user-agent")).unwrap();
        let cookie_pos = out.iter().position(|(k, _)| k.eq_ignore_ascii_case("cookie")).unwrap();
        assert!(host_pos < ua_pos);
        assert!(ua_pos < cookie_pos, "Firefox: user-agent must come before cookie");
    }

    // ── header_order_for_profile ───────────────────────────────────

    #[test]
    fn header_order_known_aliases_resolve() {
        for alias in ["chrome", "chrome131", "edge", "firefox", "safari"] {
            assert!(
                header_order_for_profile(alias).is_some(),
                "alias `{alias}` should resolve to a HeaderOrder"
            );
        }
    }

    #[test]
    fn header_order_unknown_profile_is_none() {
        assert!(header_order_for_profile("unknown").is_none());
        assert!(header_order_for_profile("").is_none());
    }

    // ── SharedSessionPool ──────────────────────────────────────────

    #[test]
    fn shared_session_pool_round_trips_through_arc_clones() {
        // Multiple Arc clones of the SAME pool must share the same
        // host-binding state — assigning a profile through clone A
        // must show up in clone B's snapshot.
        let pool = SharedSessionPool::new(PROFILES.iter().collect(), 50);
        let clone = pool.clone();
        let _ = clone.profile_for("shared.example.com");
        let snap = pool.snapshot();
        assert!(
            snap.iter().any(|(h, _, _)| h == "shared.example.com"),
            "binding made via clone must be visible via the original"
        );
    }

    #[test]
    fn shared_session_pool_clear_drops_bindings_across_clones() {
        let pool = SharedSessionPool::new(PROFILES.iter().collect(), 50);
        let clone = pool.clone();
        let _ = pool.profile_for("a.com");
        let _ = clone.profile_for("b.com");
        assert_eq!(pool.snapshot().len(), 2);
        clone.clear();
        assert!(
            pool.snapshot().is_empty(),
            "clear via clone must drop bindings visible from the original"
        );
    }
}
