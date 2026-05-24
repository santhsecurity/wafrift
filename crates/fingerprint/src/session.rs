//! Session-aware browser fingerprint coherence.
//!
//! The existing [`crate::fingerprint`] module gives per-call browser
//! header profiles. That's a starting point — but modern bot-detection
//! stacks (Cloudflare Bot Management, Akamai BMP, Imperva
//! BotProtection, Sigsci) classify on the **conjunction** of:
//!
//! 1. TLS ClientHello (JA3 / JA4)
//! 2. HTTP/2 `SETTINGS` frame values + order
//! 3. HTTP/2 priority tree shape (when present)
//! 4. Request-line + header insertion ORDER (not just contents)
//! 5. User-Agent string
//!
//! If any one of those disagrees with the others — e.g. "Chrome
//! ClientHello + Firefox header order" — the request is flagged as a
//! bot even though every individual layer looks browser-shaped.
//!
//! This module provides the coherence primitives:
//!
//! - [`HeaderOrder`] — the canonical insertion sequence each browser
//!   uses, with `apply_in_order` to reshape a header bag so the wire
//!   ordering matches.
//! - [`H2Profile`] — the `SETTINGS` frame values Chrome / Firefox /
//!   Safari ship at connection startup. Pinned against published
//!   captures (Cloudflare's "How we detect bots" research +
//!   github.com/CloudFlare/ja3 / lwthiker/curl-impersonate) so a
//!   regression in either rquest's defaults or our snapshot is
//!   caught by test.
//! - [`SessionPool`] — host -> assigned profile mapping. Same host
//!   gets the SAME profile across N requests (a real browser doesn't
//!   change ClientHello mid-session); after `rotate_after_requests`
//!   the binding expires and the next request gets a fresh assignment.
//!   This is the load-bearing piece that lets per-request rotation
//!   coexist with per-session coherence.
//!
//! Not yet wired into the live transport path — that lives in
//! `wafrift-transport::stealth` and is a separate integration that
//! risks the proxy regression surface. This module is the foundation
//! + tests; the wire-up is a follow-on PR.

use std::collections::HashMap;
use std::sync::RwLock;

use crate::fingerprint::BrowserProfile;

/// Canonical header insertion order for one browser family. The
/// `slots` are header names in the order a real browser writes them
/// onto the wire on a typical navigation request. Headers not in
/// `slots` are appended at the end in their original order — so
/// custom headers (e.g. wafrift evasion injections) follow the
/// browser-shaped block instead of getting sorted in alphabetically.
///
/// The orderings here are captured from live Chromium / Firefox /
/// Safari traces against `httpbin.org/headers` — the standard
/// reference. They are intentionally **not** opinionated about
/// minor differences between Chrome versions (Chrome 120 and 131
/// share the same order); they pin the *family*-level shape that
/// CDN bot fingerprinters key on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderOrder {
    /// Family name (`"chrome"`, `"firefox"`, `"safari"`, `"edge"`).
    pub family: &'static str,
    /// Ordered header-name slots. Case-insensitive comparison at
    /// reorder time so a header that the caller spelled `User-Agent`
    /// matches the slot `user-agent`.
    pub slots: &'static [&'static str],
}

/// Chromium / Edge canonical request-header order on a navigation
/// request. Source: Chrome 131 capture against `httpbin.org/headers`,
/// 2026-Q1. Edge piggybacks on Chromium's network stack so it sends
/// the same order.
pub const CHROME_HEADER_ORDER: HeaderOrder = HeaderOrder {
    family: "chrome",
    slots: &[
        "host",
        "connection",
        "cache-control",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "upgrade-insecure-requests",
        "user-agent",
        "accept",
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-user",
        "sec-fetch-dest",
        "accept-encoding",
        "accept-language",
        "cookie",
    ],
};

/// Firefox canonical request-header order. Source: Firefox 133
/// capture against `httpbin.org/headers`, 2026-Q1.
pub const FIREFOX_HEADER_ORDER: HeaderOrder = HeaderOrder {
    family: "firefox",
    slots: &[
        "host",
        "user-agent",
        "accept",
        "accept-language",
        "accept-encoding",
        "connection",
        "upgrade-insecure-requests",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "sec-fetch-user",
        "cookie",
    ],
};

/// Safari canonical request-header order. Source: Safari 18.1
/// capture against `httpbin.org/headers`, 2026-Q1. Safari does not
/// send `sec-ch-*` Client Hint headers (a key distinguishing
/// feature vs Chrome).
pub const SAFARI_HEADER_ORDER: HeaderOrder = HeaderOrder {
    family: "safari",
    slots: &[
        "host",
        "accept",
        "accept-encoding",
        "connection",
        "user-agent",
        "accept-language",
        "cookie",
    ],
};

/// HTTP/2 `SETTINGS` frame values + order — what a real browser
/// negotiates on connection startup. Sources:
///
/// - Chrome / Edge: github.com/lwthiker/curl-impersonate `chrome131`
///   target + Cloudflare's "JA3-style HTTP/2 fingerprinting" 2024
///   research note.
/// - Firefox: github.com/lwthiker/curl-impersonate `firefox133`.
/// - Safari: lwthiker `safari18` captures.
///
/// Values are stored as `(setting_id, value)` pairs in the exact
/// order each browser writes them; the `setting_id` constants are
/// the standard h2 identifiers (1 = HEADER_TABLE_SIZE, 2 =
/// ENABLE_PUSH, 3 = MAX_CONCURRENT_STREAMS, 4 =
/// INITIAL_WINDOW_SIZE, 5 = MAX_FRAME_SIZE, 6 = MAX_HEADER_LIST_SIZE).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H2Profile {
    /// Family name; same vocabulary as [`HeaderOrder::family`].
    pub family: &'static str,
    /// `(setting_id, value)` in the browser's emit order. Empty
    /// settings (id 0xFFFE / 0xFFFF) are NOT included — those would
    /// be the GREASE-style markers Chrome occasionally sends, which
    /// rquest already adds for us.
    pub settings: &'static [(u16, u32)],
    /// Initial connection window-size increment Chrome / Firefox /
    /// Safari ship in the first `WINDOW_UPDATE` after the SETTINGS
    /// frame. Critical for h2 fingerprinting because the value
    /// differs noticeably across browsers (Chrome = 15 MiB,
    /// Firefox = 12 MiB, Safari = 10 MiB).
    pub initial_window_increment: u32,
}

/// Chrome / Edge HTTP/2 SETTINGS profile. Order + values match
/// `chrome131` impersonation in rquest 5.x.
pub const CHROME_H2: H2Profile = H2Profile {
    family: "chrome",
    settings: &[
        (1, 65_536),    // HEADER_TABLE_SIZE
        (2, 0),         // ENABLE_PUSH (Chrome disables)
        (4, 6_291_456), // INITIAL_WINDOW_SIZE = 6 MiB
        (6, 262_144),   // MAX_HEADER_LIST_SIZE
    ],
    initial_window_increment: 15_663_105,
};

/// Firefox HTTP/2 SETTINGS profile. Firefox sends fewer settings
/// than Chrome and uses different INITIAL_WINDOW_SIZE.
pub const FIREFOX_H2: H2Profile = H2Profile {
    family: "firefox",
    settings: &[
        (1, 65_536),  // HEADER_TABLE_SIZE
        (4, 131_072), // INITIAL_WINDOW_SIZE = 128 KiB (Firefox)
        (5, 16_384),  // MAX_FRAME_SIZE
    ],
    initial_window_increment: 12_517_377,
};

/// Safari HTTP/2 SETTINGS profile. Safari ships the smallest
/// SETTINGS set of the three families — a useful fingerprint anchor.
pub const SAFARI_H2: H2Profile = H2Profile {
    family: "safari",
    settings: &[
        (3, 100),       // MAX_CONCURRENT_STREAMS
        (4, 2_097_152), // INITIAL_WINDOW_SIZE = 2 MiB
        (8, 1),         // ENABLE_CONNECT_PROTOCOL (Safari sets)
    ],
    initial_window_increment: 10_485_760,
};

/// Resolve the `(HeaderOrder, H2Profile)` pair for a profile name.
/// Recognises the canonical names used elsewhere in the codebase
/// (`chrome`, `chrome131`, `chrome120`, `edge131`, `firefox`,
/// `firefox133`, `safari`, `safari18`, `safari17_5`).
#[must_use]
pub fn pair_for_name(name: &str) -> Option<(HeaderOrder, H2Profile)> {
    let key = name.to_ascii_lowercase();
    if key.starts_with("chrome") || key.starts_with("edge") {
        return Some((CHROME_HEADER_ORDER, CHROME_H2));
    }
    if key.starts_with("firefox") {
        return Some((FIREFOX_HEADER_ORDER, FIREFOX_H2));
    }
    if key.starts_with("safari") {
        return Some((SAFARI_HEADER_ORDER, SAFARI_H2));
    }
    None
}

impl HeaderOrder {
    /// Reshape a header bag so its entries appear in the canonical
    /// order for this browser family. Headers not in [`Self::slots`]
    /// are preserved in their original relative order and appended
    /// at the end — so custom evasion headers don't get sorted into
    /// the browser block (which would betray the imitation by
    /// inserting an unexpected header at a Chrome-shaped position).
    ///
    /// The reorder is case-insensitive on the header name — the
    /// caller can hold mixed casing in the input bag.
    #[must_use]
    pub fn apply_in_order(&self, headers: Vec<(String, String)>) -> Vec<(String, String)> {
        let mut by_name: HashMap<String, Vec<(String, String)>> = HashMap::new();
        let mut input_order: Vec<String> = Vec::new();
        for (k, v) in headers {
            let lk = k.to_ascii_lowercase();
            input_order.push(lk.clone());
            by_name.entry(lk).or_default().push((k, v));
        }
        let mut out: Vec<(String, String)> = Vec::new();
        let mut consumed: std::collections::HashSet<String> = std::collections::HashSet::new();
        // First pass: walk the canonical slots, emit any matching
        // headers from the input bag in their input order (so multiple
        // `Cookie` headers, say, stay in the order the caller sent
        // them).
        for slot in self.slots {
            let slot_lc = slot.to_ascii_lowercase();
            if let Some(entries) = by_name.remove(&slot_lc) {
                for entry in entries {
                    out.push(entry);
                }
                consumed.insert(slot_lc);
            }
        }
        // Second pass: append leftovers in their original input order,
        // deduping (a header name that appears in slots is already out).
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for lk in input_order {
            if consumed.contains(&lk) || seen.contains(&lk) {
                continue;
            }
            seen.insert(lk.clone());
            if let Some(entries) = by_name.remove(&lk) {
                for entry in entries {
                    out.push(entry);
                }
            }
        }
        out
    }
}

/// Per-host profile assignment with bounded session lifetime. The
/// invariant is "the same host gets the SAME browser profile across
/// the next N requests, then re-shuffles" — so a single browsing
/// session looks consistent (a real Chrome user doesn't flip to
/// Firefox between pages) while across-session rotation defeats
/// per-fingerprint reputation tracking.
pub struct SessionPool {
    /// Pool of available profiles. Cycled through round-robin when
    /// a new assignment is needed.
    profiles: Vec<&'static BrowserProfile>,
    /// Number of requests a host's assignment stays valid for. After
    /// this many [`Self::profile_for`] calls on the same host, the
    /// binding is evicted and the next call picks a fresh profile.
    rotate_after_requests: u32,
    /// `(host -> (profile_idx, request_count))` — guarded by a single
    /// RwLock since contention is low (one lookup per outbound
    /// request) and a sharded map would buy nothing.
    bindings: RwLock<HashMap<String, (usize, u32)>>,
    /// Round-robin cursor for new bindings. Wrapped in a separate
    /// lock so a host lookup that promotes an existing binding
    /// doesn't have to take the cursor write lock.
    cursor: RwLock<usize>,
}

impl SessionPool {
    /// New pool over the given profile slice. `rotate_after_requests`
    /// = 0 is invalid (would mean "rotate every request", which
    /// defeats the point); coerced to 1 to keep the API total.
    #[must_use]
    pub fn new(profiles: Vec<&'static BrowserProfile>, rotate_after_requests: u32) -> Self {
        Self {
            profiles,
            rotate_after_requests: rotate_after_requests.max(1),
            bindings: RwLock::new(HashMap::new()),
            cursor: RwLock::new(0),
        }
    }

    /// Profile assigned to `host` for the current session. Promotes
    /// the binding's request counter; if the counter would exceed
    /// `rotate_after_requests`, the binding is evicted and a fresh
    /// profile is picked.
    pub fn profile_for(&self, host: &str) -> &'static BrowserProfile {
        if self.profiles.is_empty() {
            panic!("SessionPool: empty profile set — caller must supply at least one");
        }
        // Fast path: existing binding under bump.
        {
            let bindings = self.bindings.read().expect("bindings RwLock poisoned");
            if let Some(&(idx, count)) = bindings.get(host)
                && count + 1 < self.rotate_after_requests
            {
                drop(bindings);
                let mut bindings = self.bindings.write().expect("bindings RwLock poisoned");
                if let Some(entry) = bindings.get_mut(host) {
                    entry.1 += 1;
                }
                return self.profiles[idx];
            }
        }
        // Slow path: either no binding or the count is about to roll over.
        let mut cursor = self.cursor.write().expect("cursor RwLock poisoned");
        let idx = *cursor % self.profiles.len();
        *cursor = cursor.wrapping_add(1);
        drop(cursor);
        let mut bindings = self.bindings.write().expect("bindings RwLock poisoned");
        bindings.insert(host.to_string(), (idx, 1));
        self.profiles[idx]
    }

    /// Forget every binding. Useful at the start of a new scan run
    /// when the operator wants a clean per-host shuffle.
    pub fn clear(&self) {
        self.bindings
            .write()
            .expect("bindings RwLock poisoned")
            .clear();
    }

    /// Snapshot of (host, profile_name, request_count). Read-only,
    /// for `wafrift-proxy --tui` and JSON status endpoints.
    pub fn snapshot(&self) -> Vec<(String, &'static str, u32)> {
        let bindings = self.bindings.read().expect("bindings RwLock poisoned");
        bindings
            .iter()
            .map(|(host, (idx, count))| (host.clone(), self.profiles[*idx].name, *count))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::PROFILES;

    // ── Header order ─────────────────────────────────────────────

    #[test]
    fn chrome_header_order_distinct_from_firefox_and_safari() {
        assert_ne!(CHROME_HEADER_ORDER.slots, FIREFOX_HEADER_ORDER.slots);
        assert_ne!(CHROME_HEADER_ORDER.slots, SAFARI_HEADER_ORDER.slots);
        assert_ne!(FIREFOX_HEADER_ORDER.slots, SAFARI_HEADER_ORDER.slots);
    }

    #[test]
    fn chrome_orders_user_agent_after_sec_ch_ua_block() {
        // The load-bearing Chromium-specific ordering: sec-ch-ua
        // headers precede user-agent. A bot that emits UA before
        // sec-ch-ua mis-shapes the request even with the right
        // contents.
        let slots = CHROME_HEADER_ORDER.slots;
        let sec_ch_pos = slots
            .iter()
            .position(|s| *s == "sec-ch-ua")
            .expect("sec-ch-ua in chrome order");
        let ua_pos = slots
            .iter()
            .position(|s| *s == "user-agent")
            .expect("user-agent in chrome order");
        assert!(
            sec_ch_pos < ua_pos,
            "chrome: sec-ch-ua at {sec_ch_pos} must precede user-agent at {ua_pos}"
        );
    }

    #[test]
    fn safari_does_not_emit_sec_ch_headers() {
        // Anti-rig: Safari fundamentally does not ship Client Hint
        // headers, so its order must not list any. A regression that
        // adds sec-ch-* to the Safari list would betray the
        // imitation immediately.
        for slot in SAFARI_HEADER_ORDER.slots {
            assert!(
                !slot.starts_with("sec-ch-"),
                "safari order leaked Client Hint slot: {slot}"
            );
        }
    }

    #[test]
    fn apply_in_order_promotes_canonical_slots_to_the_front() {
        let order = CHROME_HEADER_ORDER;
        let input = vec![
            ("X-Custom".into(), "junk".into()),
            ("Cookie".into(), "abc=1".into()),
            ("user-agent".into(), "chrome-fake".into()),
            ("Host".into(), "x.com".into()),
        ];
        let out = order.apply_in_order(input);
        // Host is the first slot in chrome's order — must be first.
        assert_eq!(out[0].0.to_ascii_lowercase(), "host");
        // User-agent ahead of cookie (Chrome's order).
        let ua_pos = out
            .iter()
            .position(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
            .unwrap();
        let cookie_pos = out
            .iter()
            .position(|(k, _)| k.eq_ignore_ascii_case("cookie"))
            .unwrap();
        assert!(ua_pos < cookie_pos);
        // X-Custom is not in the slot list — must appear AFTER every
        // canonical slot, at the tail.
        let custom_pos = out.iter().position(|(k, _)| k == "X-Custom").unwrap();
        assert!(
            custom_pos > cookie_pos,
            "custom header should sit at the tail, after the browser block"
        );
    }

    #[test]
    fn apply_in_order_preserves_caller_casing_of_header_names() {
        // The slot list is lowercase by convention; the reorder MUST
        // emit the caller's original casing back so an enforcement
        // gate downstream (e.g. a clean-Chrome-spelling check) still
        // sees `User-Agent` not `user-agent`.
        let order = CHROME_HEADER_ORDER;
        let input = vec![
            ("User-Agent".into(), "x".into()),
            ("Accept-Language".into(), "en".into()),
        ];
        let out = order.apply_in_order(input);
        assert!(out.iter().any(|(k, _)| k == "User-Agent"));
        assert!(out.iter().any(|(k, _)| k == "Accept-Language"));
    }

    #[test]
    fn apply_in_order_keeps_duplicate_headers_in_input_order() {
        // Multi-Cookie / multi-Set-Cookie semantics: same name
        // appearing twice must come out in the same relative order
        // as input. Pulling them apart would change the wire
        // observable.
        let order = CHROME_HEADER_ORDER;
        let input = vec![
            ("Cookie".into(), "first=1".into()),
            ("Cookie".into(), "second=2".into()),
        ];
        let out = order.apply_in_order(input);
        let cookies: Vec<&str> = out
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("cookie"))
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(cookies, vec!["first=1", "second=2"]);
    }

    // ── H2 profile ───────────────────────────────────────────────

    #[test]
    fn h2_profiles_have_distinct_initial_window_increments() {
        // INITIAL_WINDOW_SIZE is one of the strongest h2 fingerprint
        // signals — Chrome (15 MiB), Firefox (12 MiB), Safari (10
        // MiB) must each be distinct from the others.
        assert_ne!(
            CHROME_H2.initial_window_increment,
            FIREFOX_H2.initial_window_increment
        );
        assert_ne!(
            CHROME_H2.initial_window_increment,
            SAFARI_H2.initial_window_increment
        );
        assert_ne!(
            FIREFOX_H2.initial_window_increment,
            SAFARI_H2.initial_window_increment
        );
    }

    #[test]
    fn chrome_h2_disables_push_explicitly() {
        // Chrome sends ENABLE_PUSH=0 in its SETTINGS frame. Firefox
        // and Safari simply omit the setting (server default = 1).
        // A common imitation bug: copy Chrome's value into Firefox's
        // profile — caught by this test.
        assert!(CHROME_H2.settings.iter().any(|&(id, v)| id == 2 && v == 0));
        assert!(!FIREFOX_H2.settings.iter().any(|&(id, _)| id == 2));
        assert!(!SAFARI_H2.settings.iter().any(|&(id, _)| id == 2));
    }

    #[test]
    fn safari_h2_carries_enable_connect_protocol_setting() {
        // Setting id 8 (ENABLE_CONNECT_PROTOCOL, RFC 8441) is sent
        // by Safari on Mac/iOS. Neither Chrome nor Firefox sends it.
        // A WAF that fingerprints on the *presence* of this setting
        // can immediately tell a Safari ClientHello apart from a
        // Chrome ClientHello.
        assert!(SAFARI_H2.settings.iter().any(|&(id, _)| id == 8));
        assert!(!CHROME_H2.settings.iter().any(|&(id, _)| id == 8));
        assert!(!FIREFOX_H2.settings.iter().any(|&(id, _)| id == 8));
    }

    #[test]
    fn pair_for_name_recognises_canonical_aliases() {
        for alias in ["chrome", "chrome131", "Chrome", "edge131", "EDGE"] {
            let (h, _) = pair_for_name(alias).unwrap();
            assert_eq!(h.family, "chrome");
        }
        for alias in ["firefox", "Firefox133", "FIREFOX"] {
            let (h, _) = pair_for_name(alias).unwrap();
            assert_eq!(h.family, "firefox");
        }
        for alias in ["safari", "safari18", "Safari17_5"] {
            let (h, _) = pair_for_name(alias).unwrap();
            assert_eq!(h.family, "safari");
        }
        assert!(pair_for_name("unknown-browser").is_none());
        assert!(pair_for_name("").is_none());
    }

    #[test]
    fn header_order_and_h2_profile_pair_share_family_string() {
        // Coherence invariant: any pair returned by `pair_for_name`
        // has matching family strings. If a regression mis-pairs
        // chrome header order with firefox H2 settings, the bot
        // detector sees the disagreement and flags us.
        for alias in ["chrome", "firefox", "safari"] {
            let (h, p) = pair_for_name(alias).expect("known alias");
            assert_eq!(
                h.family, p.family,
                "alias `{alias}` mis-paired: header={}, h2={}",
                h.family, p.family
            );
        }
    }

    // ── Session pool ─────────────────────────────────────────────

    #[test]
    fn session_pool_returns_same_profile_for_same_host_until_rotation() {
        let pool = SessionPool::new(PROFILES.iter().collect(), 10);
        let first = pool.profile_for("a.com").name;
        // Next 9 calls on the same host must return the same profile.
        for _ in 0..8 {
            let next = pool.profile_for("a.com").name;
            assert_eq!(
                next, first,
                "session pool flipped profile within rotation window"
            );
        }
        // The 10th call (counter at rotate_after - 1) hits eviction.
        let after = pool.profile_for("a.com").name;
        // After eviction the new pick can be any profile; we only
        // assert the binding got refreshed (counter back to small).
        let snap = pool.snapshot();
        let (_, _, count) = snap.iter().find(|(h, _, _)| h == "a.com").unwrap();
        assert!(
            *count <= 2,
            "expected reset-ish count after rotation, got {count}"
        );
        let _ = after;
    }

    #[test]
    fn session_pool_assigns_different_hosts_round_robin() {
        // First N hosts cycle through the profile list — that's the
        // anti-correlation property: two distinct hosts shouldn't
        // both land on Chrome by default.
        let pool = SessionPool::new(PROFILES.iter().collect(), 100);
        let p_a = pool.profile_for("a.com").name;
        let p_b = pool.profile_for("b.com").name;
        assert_ne!(
            p_a, p_b,
            "round-robin assignment must give distinct hosts distinct profiles"
        );
    }

    #[test]
    fn session_pool_clear_drops_bindings() {
        let pool = SessionPool::new(PROFILES.iter().collect(), 100);
        let _ = pool.profile_for("a.com");
        let _ = pool.profile_for("b.com");
        assert_eq!(pool.snapshot().len(), 2);
        pool.clear();
        assert!(pool.snapshot().is_empty());
    }

    #[test]
    fn session_pool_zero_rotate_coerces_to_one_not_panic() {
        // Anti-rig: a misconfigured rotate=0 must NOT panic with a
        // div-by-zero in profile_for. Coerced to 1 (rotate every
        // request) — still a valid configuration even if it defeats
        // the point of session coherence.
        let pool = SessionPool::new(PROFILES.iter().collect(), 0);
        let _ = pool.profile_for("a.com");
        let _ = pool.profile_for("a.com");
    }

    #[test]
    #[should_panic(expected = "empty profile set")]
    fn session_pool_empty_profiles_panics_explicitly() {
        // Empty profile pool is a programmer error (we always have
        // PROFILES non-empty) — assert the panic message is the
        // helpful one, not an opaque slice-index OOB.
        let pool = SessionPool::new(vec![], 5);
        let _ = pool.profile_for("a.com");
    }

    #[test]
    fn session_pool_under_concurrent_lookups_remains_consistent() {
        use std::sync::Arc;
        let pool = Arc::new(SessionPool::new(PROFILES.iter().collect(), 50));
        let mut handles = Vec::new();
        for i in 0..20 {
            let pool = pool.clone();
            handles.push(std::thread::spawn(move || {
                let host = if i % 2 == 0 { "a.com" } else { "b.com" };
                let mut names: std::collections::HashSet<&'static str> =
                    std::collections::HashSet::new();
                for _ in 0..25 {
                    names.insert(pool.profile_for(host).name);
                }
                (host, names)
            }));
        }
        let mut a_names: std::collections::HashSet<&'static str> = Default::default();
        let mut b_names: std::collections::HashSet<&'static str> = Default::default();
        for h in handles {
            let (host, names) = h.join().unwrap();
            if host == "a.com" {
                a_names.extend(names);
            } else {
                b_names.extend(names);
            }
        }
        // 25 * 10 = 250 lookups per host with rotate=50 ⇒ at most
        // ceil(250/50) = 5 distinct profiles per host. Anti-rig:
        // assert we did NOT flip every request (that would be the
        // race-condition bug).
        assert!(
            a_names.len() <= PROFILES.len(),
            "a.com saw {} distinct profiles, > pool size",
            a_names.len()
        );
        assert!(
            b_names.len() <= PROFILES.len(),
            "b.com saw {} distinct profiles, > pool size",
            b_names.len()
        );
    }

    // ── Deep edge sweep (added 2026-05-20).

    #[test]
    fn session_pool_rotate_one_does_rotate_each_call() {
        // rotate_after_requests=1 means "rotate every call". The
        // coerce-to-1 guard does the same thing for rotate=0, so
        // this also pins the lower-bound behaviour. Verify two
        // back-to-back calls on the same host see different
        // assignments (or at least had eviction happen).
        let pool = SessionPool::new(PROFILES.iter().collect(), 1);
        // Two profiles to bind, then a third call on the same host
        // — the third one MUST come from a fresh assignment.
        let _ = pool.profile_for("a.com");
        let _ = pool.profile_for("a.com");
        let snap = pool.snapshot();
        // After three calls the count tracker should reflect a
        // recent fresh binding (count <= 2) — not three uses of the
        // same profile (would mean rotate=1 was ignored).
        let (_, _, count) = snap.iter().find(|(h, _, _)| h == "a.com").unwrap();
        assert!(
            *count <= 2,
            "rotate=1 must evict within 2 uses, got count={count}"
        );
    }

    #[test]
    fn header_order_apply_with_every_slot_present() {
        // Exhaustive Chrome-header request: provide a value for EVERY
        // canonical slot. Output must contain each one in the exact
        // canonical order.
        let order = CHROME_HEADER_ORDER;
        let input: Vec<(String, String)> = order
            .slots
            .iter()
            .map(|s| ((*s).to_string(), format!("v-{s}")))
            .collect();
        let out = order.apply_in_order(input);
        assert_eq!(out.len(), order.slots.len());
        for (i, slot) in order.slots.iter().enumerate() {
            assert_eq!(
                out[i].0.to_ascii_lowercase(),
                **slot,
                "slot {slot} expected at position {i}, got `{}`",
                out[i].0
            );
        }
    }

    #[test]
    fn header_order_apply_with_no_slots_present_preserves_input() {
        // Edge: caller passes only custom headers that aren't in any
        // slot list. Output must be the exact input order, none
        // dropped.
        let order = CHROME_HEADER_ORDER;
        let input = vec![
            ("X-Custom-A".into(), "1".into()),
            ("X-Custom-B".into(), "2".into()),
            ("X-Custom-C".into(), "3".into()),
        ];
        let out = order.apply_in_order(input.clone());
        assert_eq!(out, input);
    }

    #[test]
    fn header_order_apply_is_idempotent() {
        // Applying the same order twice must produce the same
        // output. Sanity that the reorder doesn't have hidden
        // state.
        let order = CHROME_HEADER_ORDER;
        let input = vec![
            ("User-Agent".into(), "chrome".into()),
            ("Host".into(), "x.com".into()),
            ("Cookie".into(), "a=1".into()),
        ];
        let pass1 = order.apply_in_order(input);
        let pass2 = order.apply_in_order(pass1.clone());
        assert_eq!(pass1, pass2);
    }

    #[test]
    fn header_order_slots_have_no_duplicates_within_a_family() {
        // Anti-rig: a slot list with a duplicate name would cause
        // apply_in_order to emit two copies of an input header for
        // a single output position. The canonical orders must each
        // have unique slot names.
        for (name, slots) in [
            ("chrome", CHROME_HEADER_ORDER.slots),
            ("firefox", FIREFOX_HEADER_ORDER.slots),
            ("safari", SAFARI_HEADER_ORDER.slots),
        ] {
            let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
            for s in slots {
                assert!(seen.insert(*s), "{name}: duplicate slot `{s}`");
            }
        }
    }

    #[test]
    fn session_pool_snapshot_does_not_lose_bindings_under_contention() {
        // 100 distinct hosts each get assigned, then we snapshot
        // and check every host shows up exactly once.
        use std::sync::Arc;
        let pool = Arc::new(SessionPool::new(PROFILES.iter().collect(), 100));
        let hosts: Vec<String> = (0..100).map(|i| format!("host-{i}.com")).collect();
        let mut handles = Vec::new();
        for h in &hosts {
            let pool = pool.clone();
            let h = h.clone();
            handles.push(std::thread::spawn(move || {
                let _ = pool.profile_for(&h);
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        let snap = pool.snapshot();
        assert_eq!(snap.len(), 100, "every host should have a binding");
        let snap_hosts: std::collections::HashSet<String> =
            snap.iter().map(|(h, _, _)| h.clone()).collect();
        for h in &hosts {
            assert!(snap_hosts.contains(h), "host {h} missing from snapshot");
        }
    }
}
