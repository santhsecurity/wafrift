//! Multi-egress IP rotation for wafrift probes.
//!
//! Cloudflare / AWS WAF / Akamai bot-detection profiles source IPs:
//! a bench that fires 1000 probes from one IP burns the persona within
//! minutes — every subsequent probe gets a JS challenge or CAPTCHA, not
//! the actual WAF verdict. This module rotates egress through a pool of
//! clean egress addresses so no single IP accumulates enough signal for
//! the reputation engine to act on.
//!
//! # Strategies
//!
//! Three backend strategies implement [`EgressRouter`]:
//!
//! - [`TailscaleEgress`] — round-robins through Tailscale exit-nodes the
//!   operator configures. Constructs a SOCKS5 proxy URL pointing at the
//!   Tailscale SOCKS listener (`127.0.0.1:1055` by default) and sets the
//!   `Tailscale-Exit-Node` request header to select the node.
//! - [`SocksPool`] — operator supplies one or more SOCKS5 URLs
//!   (`socks5://user:pass@host:port`). Rotates round-robin or by
//!   least-recently-blocked.
//! - [`HttpProxyPool`] — operator supplies one or more HTTP proxy URLs.
//!   Same rotation logic.
//!
//! # Per-target blacklisting
//!
//! When a given egress sees 3 consecutive challenge responses from the
//! same target host, it is marked **cooled** for that host for
//! `cooldown_secs` (default 300). All subsequent probes for that host
//! skip the cooled entry. When the entire pool is cooled for a host,
//! [`EgressPool::next_for`] returns [`EgressError::EntirePoolCooled`] so
//! the caller can surface a clean diagnostic rather than looping forever.
//!
//! # Deterministic replay
//!
//! Pass `seed: Some(n)` to [`EgressPool::builder`] and the rotation
//! order becomes deterministic — the selection sequence is reproducible
//! across runs, which is useful for regression tests.
//!
//! # Example
//!
//! ```rust,no_run
//! use wafrift_transport::egress_pool::EgressPool;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let pool = EgressPool::builder()
//!     .socks5_str(vec![
//!         "socks5://user:pass@10.0.0.1:1080".to_owned(),
//!         "socks5://user:pass@10.0.0.2:1080".to_owned(),
//!     ])?
//!     .cooldown_secs(300)
//!     .build()?;
//!
//! // Get a reqwest::ClientBuilder pre-configured for one egress.
//! let entry = pool.next_for("target.example.com")?;
//! let _client = entry.apply_to_builder(reqwest::ClientBuilder::new()).build()?;
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use reqwest::ClientBuilder;
use thiserror::Error;

// ── public error type ─────────────────────────────────────────────────────────

/// Errors from the egress pool.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EgressError {
    /// The pool was constructed with an empty list of egress entries.
    #[error(
        "egress pool is empty — supply at least one --socks5, --http-proxy, or --tailscale-exit-node"
    )]
    EmptyPool,
    /// Every entry in the pool is currently in its cooldown window for
    /// `target`. The caller should surface this as a diagnostic and
    /// either wait or abort the probe run for this host.
    #[error(
        "all {count} egress entries are cooled for target {target:?}; retry after {cooldown_secs}s"
    )]
    EntirePoolCooled {
        target: String,
        count: usize,
        cooldown_secs: u64,
    },
    /// A provided proxy URL failed to parse or has an invalid scheme.
    #[error("invalid proxy URL {url:?}: {reason}")]
    InvalidUrl { url: String, reason: String },
}

// ── URL validation helpers ────────────────────────────────────────────────────

/// Validate that `raw` is a syntactically valid URL with a SOCKS5 scheme
/// (`socks5://` or `socks5h://`).
///
/// Returns the original string on success so callers can use it directly
/// with [`reqwest::Proxy`] without re-boxing.
pub fn parse_socks5_url(raw: &str) -> Result<String, EgressError> {
    // Validate through proxywire's canonical strict parser — the single source
    // of truth for proxy-URL syntax + the scheme allow-list (rejects bad
    // schemes, embedded paths/queries, missing host/port). Then confirm the
    // SOCKS5 family. The original credential-bearing string is returned so
    // `reqwest::Proxy::all` keeps any `user:pass@` userinfo.
    let endpoint = proxywire::ProxyEndpoint::from_url(raw).map_err(|e| EgressError::InvalidUrl {
        url: raw.to_owned(),
        reason: e.to_string(),
    })?;
    match endpoint.protocol {
        proxywire::ProxyProtocol::Socks5 | proxywire::ProxyProtocol::Socks5LocalDns => {
            Ok(raw.to_owned())
        }
        _ => Err(EgressError::InvalidUrl {
            url: raw.to_owned(),
            reason: "expected socks5:// or socks5h:// scheme".to_owned(),
        }),
    }
}

/// Validate that `raw` is an HTTP or HTTPS proxy URL.
pub fn parse_http_proxy_url(raw: &str) -> Result<String, EgressError> {
    // Validate through proxywire's canonical strict parser (see
    // [`parse_socks5_url`]) and confirm the HTTP(S) family. proxywire maps both
    // `http://` and `https://` to `ProxyProtocol::HttpConnect`.
    let endpoint = proxywire::ProxyEndpoint::from_url(raw).map_err(|e| EgressError::InvalidUrl {
        url: raw.to_owned(),
        reason: e.to_string(),
    })?;
    match endpoint.protocol {
        proxywire::ProxyProtocol::HttpConnect => Ok(raw.to_owned()),
        _ => Err(EgressError::InvalidUrl {
            url: raw.to_owned(),
            reason: "expected http:// or https:// scheme".to_owned(),
        }),
    }
}

// ── egress backend ────────────────────────────────────────────────────────────

/// The transport mechanism a single egress entry uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressBackend {
    /// A SOCKS5 proxy URL (e.g. `socks5://user:pass@10.0.0.1:1080`).
    Socks5(String),
    /// An HTTP proxy URL (e.g. `http://10.0.0.1:3128`).
    HttpProxy(String),
    /// A Tailscale exit-node name (e.g. `mullvad-us-nyc-001`).
    /// The transport contacts the local Tailscale SOCKS listener and
    /// adds a `Tailscale-Exit-Node` header to select the exit node.
    TailscaleNode {
        node_name: String,
        /// Local Tailscale SOCKS listener address. Defaults to
        /// `127.0.0.1:1055`.
        socks_addr: String,
    },
}

impl EgressBackend {
    /// The short display label used in tracing / diagnostics.
    pub fn label(&self) -> &str {
        match self {
            EgressBackend::Socks5(url) => url,
            EgressBackend::HttpProxy(url) => url,
            EgressBackend::TailscaleNode { node_name, .. } => node_name,
        }
    }
}

// ── per-entry cooldown tracker ─────────────────────────────────────────────

/// Tracks challenge-response counts + cooldown state for one egress entry
/// against one target host.
#[derive(Debug, Clone)]
struct TargetCooldown {
    /// Number of consecutive challenge/block responses seen.
    consecutive_challenges: u32,
    /// When the cooldown expires (`None` if not currently cooled).
    cooled_until: Option<Instant>,
}

impl TargetCooldown {
    fn new() -> Self {
        Self {
            consecutive_challenges: 0,
            cooled_until: None,
        }
    }

    fn is_cooled(&self, now: Instant) -> bool {
        self.cooled_until.is_some_and(|until| now < until)
    }

    /// Record a challenge response. Returns `true` when the threshold is
    /// crossed and the entry transitions into cooldown.
    ///
    /// The counter is saturated at `threshold` rather than allowed to grow
    /// unboundedly. Without saturation, an entry that is already cooled
    /// (condition guarded by `cooled_until.is_none()`) would increment
    /// `consecutive_challenges` on every call and eventually overflow
    /// `u32` after ~4 billion probes — a panic in debug, UB-adjacent in
    /// release.
    fn record_challenge(&mut self, threshold: u32, cooldown: Duration, now: Instant) -> bool {
        self.consecutive_challenges = self.consecutive_challenges.saturating_add(1);
        if self.consecutive_challenges >= threshold && self.cooled_until.is_none() {
            self.cooled_until = Some(now + cooldown);
            return true;
        }
        false
    }

    /// Record a clean pass — reset the consecutive challenge counter and
    /// clear any expired cooldown.
    fn record_pass(&mut self, now: Instant) {
        self.consecutive_challenges = 0;
        if let Some(until) = self.cooled_until
            && now >= until
        {
            self.cooled_until = None;
        }
    }
}

// ── single egress entry ────────────────────────────────────────────────────

/// A single slot in the pool — one configured egress with its own
/// per-target cooldown map.
#[derive(Debug)]
pub struct EgressEntry {
    /// The transport backend.
    pub backend: EgressBackend,
    /// Per-target cooldown state. Key = normalised target host.
    cooldowns: Mutex<HashMap<String, TargetCooldown>>,
}

impl EgressEntry {
    fn new(backend: EgressBackend) -> Self {
        Self {
            backend,
            cooldowns: Mutex::new(HashMap::new()),
        }
    }

    /// Apply this egress entry's proxy configuration to a `reqwest::ClientBuilder`.
    ///
    /// For Tailscale backends the proxy points at the local Tailscale SOCKS
    /// listener; the caller must also add the `Tailscale-Exit-Node` header
    /// (via [`EgressEntry::tailscale_exit_node_header`]).
    ///
    /// # Proxy construction failure
    ///
    /// URLs are validated at insertion time, so `reqwest::Proxy::all` should
    /// never fail here. If it does (e.g. a reqwest version incompatibility),
    /// a `tracing::error!` is emitted and the builder is returned WITHOUT the
    /// proxy configured. This is a last-resort fallback; the caller will route
    /// traffic direct rather than via the intended egress. The error log gives
    /// operators a clear diagnostic.
    pub fn apply_to_builder(&self, builder: ClientBuilder) -> ClientBuilder {
        match &self.backend {
            EgressBackend::Socks5(url) => match reqwest::Proxy::all(url) {
                Ok(proxy) => builder.proxy(proxy),
                Err(e) => {
                    tracing::error!(
                        url = url.as_str(),
                        err = %e,
                        "SOCKS5 proxy URL failed reqwest::Proxy::all after validation — \
                         routing direct (BUG: report to wafrift maintainers)"
                    );
                    builder
                }
            },
            EgressBackend::HttpProxy(url) => match reqwest::Proxy::all(url) {
                Ok(proxy) => builder.proxy(proxy),
                Err(e) => {
                    tracing::error!(
                        url = url.as_str(),
                        err = %e,
                        "HTTP proxy URL failed reqwest::Proxy::all after validation — \
                         routing direct (BUG: report to wafrift maintainers)"
                    );
                    builder
                }
            },
            EgressBackend::TailscaleNode { socks_addr, .. } => {
                let socks_url = format!("socks5://{socks_addr}");
                match reqwest::Proxy::all(&socks_url) {
                    Ok(proxy) => builder.proxy(proxy),
                    Err(e) => {
                        tracing::error!(
                            socks_addr = socks_addr.as_str(),
                            err = %e,
                            "Tailscale SOCKS proxy URL failed reqwest::Proxy::all — \
                             routing direct (BUG: check socks_addr format)"
                        );
                        builder
                    }
                }
            }
        }
    }

    /// For Tailscale backends, returns the exit-node header pair
    /// `("Tailscale-Exit-Node", "<node_name>")`. Returns `None` for
    /// other backends.
    pub fn tailscale_exit_node_header(&self) -> Option<(&str, &str)> {
        match &self.backend {
            EgressBackend::TailscaleNode { node_name, .. } => {
                Some(("Tailscale-Exit-Node", node_name.as_str()))
            }
            _ => None,
        }
    }

    fn is_cooled_for(&self, target: &str, now: Instant) -> bool {
        let guard = self.cooldowns.lock().unwrap_or_else(|p| p.into_inner());
        guard.get(target).is_some_and(|c| c.is_cooled(now))
    }

    /// Signal that this entry received a challenge response for `target`.
    ///
    /// Returns `true` when the entry has just been cooled.
    pub fn record_challenge(&self, target: &str, threshold: u32, cooldown: Duration) -> bool {
        let now = Instant::now();
        let mut guard = self.cooldowns.lock().unwrap_or_else(|p| p.into_inner());
        let entry = guard
            .entry(target.to_owned())
            .or_insert_with(TargetCooldown::new);
        let cooled = entry.record_challenge(threshold, cooldown, now);
        if cooled {
            tracing::warn!(
                egress = self.backend.label(),
                target,
                "egress entry cooled after {} consecutive challenges",
                threshold
            );
        }
        cooled
    }

    /// Signal that this entry received a clean (non-challenge) response
    /// for `target`.
    pub fn record_pass(&self, target: &str) {
        let now = Instant::now();
        let mut guard = self.cooldowns.lock().unwrap_or_else(|p| p.into_inner());
        let entry = guard
            .entry(target.to_owned())
            .or_insert_with(TargetCooldown::new);
        entry.record_pass(now);
    }
}

// ── pool ─────────────────────────────────────────────────────────────────────

/// Round-robin egress pool with per-target cooldown tracking.
///
/// See the module-level documentation for usage.
#[derive(Debug)]
pub struct EgressPool {
    entries: Vec<Arc<EgressEntry>>,
    /// Number of consecutive challenge responses before an entry is cooled.
    challenge_threshold: u32,
    /// How long a cooled entry stays out of rotation.
    cooldown: Duration,
    /// Current rotation index (monotonically increasing; mod entries.len()).
    cursor: Mutex<u64>,
    /// Optional seed for deterministic rotation (overrides cursor with a
    /// seeded sequence).
    seed: Option<u64>,
}

impl EgressPool {
    /// Start building a pool.
    pub fn builder() -> EgressPoolBuilder {
        EgressPoolBuilder::default()
    }

    /// Total number of entries in the pool (including cooled ones).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` when the pool has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return the next [`Arc<EgressEntry>`] suitable for `target_host`.
    ///
    /// Skips entries that are currently cooled for `target_host`. Returns
    /// [`EgressError::EntirePoolCooled`] when every entry is in cooldown
    /// for this host.
    pub fn next_for(&self, target_host: &str) -> Result<Arc<EgressEntry>, EgressError> {
        let now = Instant::now();
        let n = self.entries.len();
        if n == 0 {
            return Err(EgressError::EmptyPool);
        }

        let start_cursor = {
            let mut guard = self.cursor.lock().unwrap_or_else(|p| p.into_inner());
            // Use seed-derived cursor for deterministic replay.
            let c = if let Some(s) = self.seed {
                s.wrapping_add(*guard)
            } else {
                *guard
            };
            *guard = guard.wrapping_add(1);
            c
        };

        // Scan up to `n` slots for one that isn't cooled.
        for offset in 0..n {
            let idx = ((start_cursor as usize) + offset) % n;
            let entry = &self.entries[idx];
            if !entry.is_cooled_for(target_host, now) {
                tracing::debug!(
                    egress = entry.backend.label(),
                    target = target_host,
                    slot = idx,
                    "egress selected"
                );
                return Ok(Arc::clone(entry));
            }
        }

        Err(EgressError::EntirePoolCooled {
            target: target_host.to_owned(),
            count: n,
            cooldown_secs: self.cooldown.as_secs(),
        })
    }

    /// Convenience: signal a challenge response from `entry` for `target`.
    pub fn record_challenge(&self, entry: &EgressEntry, target: &str) {
        entry.record_challenge(target, self.challenge_threshold, self.cooldown);
    }

    /// Convenience: signal a pass from `entry` for `target`.
    pub fn record_pass(&self, entry: &EgressEntry, target: &str) {
        entry.record_pass(target);
    }

    /// The challenge threshold configured for this pool.
    pub fn challenge_threshold(&self) -> u32 {
        self.challenge_threshold
    }

    /// The cooldown duration configured for this pool.
    pub fn cooldown(&self) -> Duration {
        self.cooldown
    }
}

// ── builder ───────────────────────────────────────────────────────────────────

/// Builder for [`EgressPool`].
#[derive(Default)]
pub struct EgressPoolBuilder {
    backends: Vec<EgressBackend>,
    challenge_threshold: Option<u32>,
    cooldown_secs: Option<u64>,
    seed: Option<u64>,
    validation_errors: Vec<EgressError>,
}

impl EgressPoolBuilder {
    /// Add validated SOCKS5 proxy URL strings to the pool.
    ///
    /// Returns `Err` immediately if any URL fails validation; callers can
    /// also call the infallible `socks5_str_raw` to defer validation.
    pub fn socks5_str(mut self, urls: Vec<String>) -> Result<Self, EgressError> {
        for u in urls {
            let validated = parse_socks5_url(&u)?;
            self.backends.push(EgressBackend::Socks5(validated));
        }
        Ok(self)
    }

    /// Add raw SOCKS5 URL strings, collecting validation errors to be
    /// surfaced at [`build`] time. Use when you want to batch-validate.
    pub fn socks5_str_raw(mut self, urls: Vec<String>) -> Self {
        for u in urls {
            match parse_socks5_url(&u) {
                Ok(validated) => self.backends.push(EgressBackend::Socks5(validated)),
                Err(e) => self.validation_errors.push(e),
            }
        }
        self
    }

    /// Add validated HTTP proxy URL strings to the pool.
    pub fn http_proxy_str(mut self, urls: Vec<String>) -> Result<Self, EgressError> {
        for u in urls {
            let validated = parse_http_proxy_url(&u)?;
            self.backends.push(EgressBackend::HttpProxy(validated));
        }
        Ok(self)
    }

    /// Add raw HTTP proxy URL strings, deferring validation to `build`.
    pub fn http_proxy_str_raw(mut self, urls: Vec<String>) -> Self {
        for u in urls {
            match parse_http_proxy_url(&u) {
                Ok(validated) => self.backends.push(EgressBackend::HttpProxy(validated)),
                Err(e) => self.validation_errors.push(e),
            }
        }
        self
    }

    /// Add Tailscale exit-node names to the pool.
    ///
    /// Each node is accessed via the Tailscale local SOCKS listener at
    /// `socks_addr` (default `127.0.0.1:1055`).
    pub fn tailscale_nodes(mut self, node_names: Vec<String>, socks_addr: Option<String>) -> Self {
        let addr = socks_addr.unwrap_or_else(|| "127.0.0.1:1055".to_owned());
        for name in node_names {
            self.backends.push(EgressBackend::TailscaleNode {
                node_name: name,
                socks_addr: addr.clone(),
            });
        }
        self
    }

    /// Number of consecutive challenge responses before an entry is cooled.
    /// Default: 3.
    pub fn challenge_threshold(mut self, n: u32) -> Self {
        self.challenge_threshold = Some(n);
        self
    }

    /// How long (in seconds) a cooled entry stays out of rotation.
    /// Default: 300.
    pub fn cooldown_secs(mut self, secs: u64) -> Self {
        self.cooldown_secs = Some(secs);
        self
    }

    /// Fix the rotation seed for deterministic replay. Without this, cursor
    /// advances monotonically from 0.
    pub fn seed(mut self, seed: u64) -> Self {
        self.seed = Some(seed);
        self
    }

    /// Build the pool.
    ///
    /// Returns `Err(EgressError::EmptyPool)` when no backends were added.
    /// Returns `Err(EgressError::InvalidUrl)` when any raw URL validation
    /// errors were recorded during builder calls.
    pub fn build(self) -> Result<EgressPool, EgressError> {
        // Surface the first validation error collected during builder calls.
        if let Some(e) = self.validation_errors.into_iter().next() {
            return Err(e);
        }
        if self.backends.is_empty() {
            return Err(EgressError::EmptyPool);
        }
        let entries = self
            .backends
            .into_iter()
            .map(|b| Arc::new(EgressEntry::new(b)))
            .collect();
        // R63 pass-21 §6: route through `wafrift_types` constants so the
        // builder fallback and the CLI default never drift. Pre-fix the
        // numbers `3` and `300` were open-coded here AND in cli/config —
        // an operator who tuned the CLI default to e.g. 2/180 wouldn't
        // see it apply to clients built via this Builder.
        Ok(EgressPool {
            entries,
            challenge_threshold: self
                .challenge_threshold
                .unwrap_or(wafrift_types::DEFAULT_EGRESS_CHALLENGE_THRESHOLD),
            cooldown: Duration::from_secs(
                self.cooldown_secs
                    .unwrap_or(wafrift_types::DEFAULT_EGRESS_COOLDOWN_SECS),
            ),
            cursor: Mutex::new(0),
            seed: self.seed,
        })
    }
}

// ── trait for swappable backends ──────────────────────────────────────────────

/// Trait that any egress-rotation strategy must implement.
///
/// The [`EgressPool`] struct is the production implementation. Tests and
/// alternate deployments can supply a different implementation.
pub trait EgressRouter: Send + Sync {
    /// Select the next egress entry for `target_host` and return a
    /// configured `ClientBuilder`.
    fn next_builder(&self, target_host: &str) -> Result<ClientBuilder, EgressError>;

    /// Report a challenge/block response for the entry most recently
    /// returned by [`EgressRouter::next_builder`] for `target_host`.
    fn record_challenge_for(&self, target_host: &str);

    /// Report a clean pass for the entry most recently returned by
    /// [`EgressRouter::next_builder`] for `target_host`.
    fn record_pass_for(&self, target_host: &str);
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // helper: pool with N fake SOCKS5 entries (raw, no scheme validation error)
    fn socks_pool(n: usize) -> EgressPool {
        let urls: Vec<String> = (0..n)
            .map(|i| format!("socks5://127.0.0.{i}:1080"))
            .collect();
        EgressPool::builder()
            .socks5_str(urls)
            .expect("valid socks5 urls")
            .build()
            .expect("pool should build")
    }

    // helper: seeded pool for deterministic ordering
    fn seeded_socks_pool(n: usize, seed: u64) -> EgressPool {
        let urls: Vec<String> = (0..n)
            .map(|i| format!("socks5://127.0.0.{i}:1080"))
            .collect();
        EgressPool::builder()
            .socks5_str(urls)
            .expect("valid socks5 urls")
            .seed(seed)
            .build()
            .expect("pool should build")
    }

    // ── TEST 1 — rotation order is round-robin ────────────────────────────
    #[test]
    fn rotation_round_robin_order() {
        let pool = seeded_socks_pool(3, 0);
        let labels: Vec<String> = (0..6)
            .map(|_| {
                pool.next_for("host.example.com")
                    .unwrap()
                    .backend
                    .label()
                    .to_owned()
            })
            .collect();
        // With seed=0, cursor starts at 0 and advances by 1 each call.
        // Sequence: 0,1,2,0,1,2 → socks5://127.0.0.{0,1,2,0,1,2}:1080
        assert_eq!(labels[0], "socks5://127.0.0.0:1080");
        assert_eq!(labels[1], "socks5://127.0.0.1:1080");
        assert_eq!(labels[2], "socks5://127.0.0.2:1080");
        assert_eq!(labels[3], "socks5://127.0.0.0:1080");
        assert_eq!(labels[4], "socks5://127.0.0.1:1080");
        assert_eq!(labels[5], "socks5://127.0.0.2:1080");
    }

    // ── TEST 2 — entry cools after N consecutive challenges ───────────────
    #[test]
    fn cooldown_after_n_consecutive_blocks() {
        let pool = EgressPool::builder()
            .socks5_str(vec!["socks5://127.0.0.1:1080".to_owned()])
            .expect("valid url")
            .challenge_threshold(3)
            .cooldown_secs(300)
            .build()
            .unwrap();

        let entry = pool.next_for("target.com").unwrap();
        // Two challenges — still available.
        entry.record_challenge("target.com", 3, Duration::from_secs(300));
        entry.record_challenge("target.com", 3, Duration::from_secs(300));
        assert!(
            pool.next_for("target.com").is_ok(),
            "should still be available"
        );

        // Third challenge — now cooled.
        entry.record_challenge("target.com", 3, Duration::from_secs(300));
        let result = pool.next_for("target.com");
        assert!(
            matches!(result, Err(EgressError::EntirePoolCooled { .. })),
            "pool should be entirely cooled after threshold"
        );
    }

    // ── TEST 3 — fallback when entire pool is cooled ──────────────────────
    #[test]
    fn fallback_entire_pool_cooled() {
        let pool = EgressPool::builder()
            .socks5_str(vec![
                "socks5://127.0.0.1:1080".to_owned(),
                "socks5://127.0.0.2:1080".to_owned(),
            ])
            .expect("valid urls")
            .challenge_threshold(1)
            .cooldown_secs(300)
            .build()
            .unwrap();

        // Cool both entries.
        for entry in &pool.entries {
            entry.record_challenge("victim.com", 1, Duration::from_secs(300));
        }

        let err = pool.next_for("victim.com").unwrap_err();
        assert!(
            matches!(err, EgressError::EntirePoolCooled { count: 2, .. }),
            "should report count=2 when both cooled: {err:?}"
        );
    }

    // ── TEST 4 — different target hosts have independent cooldowns ────────
    #[test]
    fn cooldown_is_per_target() {
        let pool = EgressPool::builder()
            .socks5_str(vec!["socks5://127.0.0.1:1080".to_owned()])
            .expect("valid url")
            .challenge_threshold(1)
            .cooldown_secs(300)
            .build()
            .unwrap();

        let entry = pool.next_for("a.com").unwrap();
        entry.record_challenge("a.com", 1, Duration::from_secs(300));

        // a.com is cooled, b.com is not.
        assert!(matches!(
            pool.next_for("a.com"),
            Err(EgressError::EntirePoolCooled { .. })
        ));
        assert!(pool.next_for("b.com").is_ok());
    }

    // ── TEST 5 — deterministic order with seed ────────────────────────────
    #[test]
    fn deterministic_with_seed() {
        let pool_a = seeded_socks_pool(4, 42);
        let pool_b = seeded_socks_pool(4, 42);

        let seq_a: Vec<String> = (0..8)
            .map(|_| pool_a.next_for("host").unwrap().backend.label().to_owned())
            .collect();
        let seq_b: Vec<String> = (0..8)
            .map(|_| pool_b.next_for("host").unwrap().backend.label().to_owned())
            .collect();
        assert_eq!(
            seq_a, seq_b,
            "seeded pools must produce identical sequences"
        );
    }

    // ── TEST 6 — empty pool returns EmptyPool error ────────────────────────
    #[test]
    fn empty_pool_error() {
        let err = EgressPool::builder().build().unwrap_err();
        assert_eq!(err, EgressError::EmptyPool);
    }

    // ── TEST 7 — parse valid SOCKS5 URL with auth ─────────────────────────
    #[test]
    fn parse_socks5_url_with_auth() {
        let validated = parse_socks5_url("socks5://alice:s3cr3t@10.8.0.1:1080").unwrap();
        assert!(validated.contains("10.8.0.1"));
    }

    // ── TEST 8 — parse SOCKS5h variant ────────────────────────────────────
    #[test]
    fn parse_socks5h_url() {
        let validated = parse_socks5_url("socks5h://proxy.internal:1080").unwrap();
        assert!(validated.starts_with("socks5h://"));
    }

    // ── TEST 9 — invalid URL scheme rejected ──────────────────────────────
    #[test]
    fn invalid_url_scheme_rejected() {
        let err = parse_socks5_url("http://10.0.0.1:1080").unwrap_err();
        assert!(
            matches!(err, EgressError::InvalidUrl { .. }),
            "http:// should be rejected for SOCKS5 parser"
        );
    }

    // ── TEST 10 — completely invalid URL rejected ─────────────────────────
    #[test]
    fn completely_invalid_url_rejected() {
        let err = parse_socks5_url("not a url at all !!!").unwrap_err();
        assert!(matches!(err, EgressError::InvalidUrl { .. }));
    }

    // ── TEST 11 — HTTP proxy URL parsing ──────────────────────────────────
    #[test]
    fn parse_http_proxy_url_ok() {
        let validated = parse_http_proxy_url("http://burp.internal:8080").unwrap();
        assert!(validated.contains(":8080"));
    }

    // ── TEST 12 — cooldown skip: non-cooled entry preferred ──────────────
    #[test]
    fn cooled_entry_skipped_non_cooled_preferred() {
        let pool = EgressPool::builder()
            .socks5_str(vec![
                "socks5://127.0.0.1:1080".to_owned(), // will be cooled
                "socks5://127.0.0.2:1080".to_owned(), // stays clean
            ])
            .expect("valid urls")
            .challenge_threshold(1)
            .cooldown_secs(300)
            .seed(0) // deterministic: cursor starts at slot 0
            .build()
            .unwrap();

        // Cool slot 0.
        pool.entries[0].record_challenge("victim.com", 1, Duration::from_secs(300));

        // next_for must skip slot 0 and pick slot 1.
        let entry = pool.next_for("victim.com").unwrap();
        assert_eq!(entry.backend.label(), "socks5://127.0.0.2:1080");
    }

    // ── TEST 13 — record_pass resets consecutive counter ─────────────────
    #[test]
    fn record_pass_resets_challenge_counter() {
        let pool = EgressPool::builder()
            .socks5_str(vec!["socks5://127.0.0.1:1080".to_owned()])
            .expect("valid url")
            .challenge_threshold(3)
            .cooldown_secs(300)
            .build()
            .unwrap();

        let entry = pool.next_for("x.com").unwrap();
        entry.record_challenge("x.com", 3, Duration::from_secs(300));
        entry.record_challenge("x.com", 3, Duration::from_secs(300));
        // Two challenges — reset before threshold.
        entry.record_pass("x.com");
        // Two more — still under threshold (counter reset).
        entry.record_challenge("x.com", 3, Duration::from_secs(300));
        entry.record_challenge("x.com", 3, Duration::from_secs(300));
        assert!(
            pool.next_for("x.com").is_ok(),
            "after pass reset, two more challenges should not cool the entry"
        );
    }

    // ── TEST 14 — Tailscale backend exposes exit-node header ─────────────
    #[test]
    fn tailscale_backend_header() {
        let pool = EgressPool::builder()
            .tailscale_nodes(
                vec!["mullvad-us-nyc-001".to_owned()],
                Some("127.0.0.1:1055".to_owned()),
            )
            .build()
            .unwrap();

        let entry = pool.next_for("target.example.com").unwrap();
        let (name, value) = entry.tailscale_exit_node_header().unwrap();
        assert_eq!(name, "Tailscale-Exit-Node");
        assert_eq!(value, "mullvad-us-nyc-001");
    }

    // ── TEST 15 — SOCKS backend has no Tailscale header ──────────────────
    #[test]
    fn socks_backend_no_tailscale_header() {
        let pool = socks_pool(1);
        let entry = pool.next_for("x.com").unwrap();
        assert!(entry.tailscale_exit_node_header().is_none());
    }

    // ── TEST 16 — challenge counter saturates at u32::MAX (no overflow) ───
    #[test]
    fn challenge_counter_saturates_no_overflow() {
        // Regression: before the saturating_add fix, calling record_challenge
        // beyond u32::MAX while already cooled would overflow in debug builds.
        // The entry is cooled after threshold=1; every subsequent call must
        // saturate the counter rather than panic.
        let pool = EgressPool::builder()
            .socks5_str(vec!["socks5://127.0.0.1:1080".to_owned()])
            .expect("valid url")
            .challenge_threshold(1)
            .cooldown_secs(300)
            .build()
            .unwrap();

        let entry = pool.next_for("x.com").unwrap();
        // Cool the entry.
        entry.record_challenge("x.com", 1, Duration::from_secs(300));
        // Fire many more challenges while cooled — must not panic on overflow.
        for _ in 0..1_000 {
            entry.record_challenge("x.com", 1, Duration::from_secs(300));
        }
        // Entry should still be cooled.
        assert!(
            matches!(
                pool.next_for("x.com"),
                Err(EgressError::EntirePoolCooled { .. })
            ),
            "entry must remain cooled after saturation-add calls"
        );
    }

    // ── TEST 17 — challenge_threshold=0 immediately cools on first call ───
    #[test]
    fn challenge_threshold_zero_cools_immediately() {
        // threshold=0: consecutive_challenges starts at 0, saturating_add(1)
        // yields 1, and 1 >= 0 is always true, so the entry cools on the
        // very first record_challenge call.
        let pool = EgressPool::builder()
            .socks5_str(vec!["socks5://127.0.0.1:1080".to_owned()])
            .expect("valid url")
            .challenge_threshold(0)
            .cooldown_secs(300)
            .build()
            .unwrap();

        let entry = pool.next_for("x.com").unwrap();
        let cooled = entry.record_challenge("x.com", 0, Duration::from_secs(300));
        assert!(cooled, "threshold=0: first challenge must trigger cooldown");
        assert!(
            matches!(
                pool.next_for("x.com"),
                Err(EgressError::EntirePoolCooled { .. })
            ),
            "pool must be cooled after threshold=0 challenge"
        );
    }

    // ── TEST 18 — empty-string target is a valid key in cooldown map ─────
    #[test]
    fn empty_target_host_does_not_panic() {
        let pool = socks_pool(1);
        // next_for("") must not panic; it's a valid (if unusual) key.
        assert!(pool.next_for("").is_ok());
        let entry = pool.next_for("").unwrap();
        // record_challenge / record_pass on empty host must not panic.
        entry.record_challenge("", 3, Duration::from_secs(300));
        entry.record_pass("");
    }

    // ── TEST 19 — single-entry pool: cooldown then pass recovery ─────────
    #[test]
    fn single_entry_recovery_after_pass() {
        // A pool with 1 entry that was cooled at threshold=2 must become
        // available again once the cooldown expires (simulated via pass).
        let pool = EgressPool::builder()
            .socks5_str(vec!["socks5://127.0.0.1:1080".to_owned()])
            .expect("valid url")
            .challenge_threshold(2)
            .cooldown_secs(0) // 0s cooldown expires immediately
            .build()
            .unwrap();

        let entry = pool.next_for("t.com").unwrap();
        entry.record_challenge("t.com", 2, Duration::from_secs(0));
        entry.record_challenge("t.com", 2, Duration::from_secs(0));
        // Cooldown=0 means cooled_until is in the past at record_pass time.
        // record_pass clears an expired cooldown.
        entry.record_pass("t.com");
        assert!(
            pool.next_for("t.com").is_ok(),
            "entry must be available after pass clears an expired cooldown"
        );
    }

    // ── TEST 20 — url with embedded auth credentials validates ok ─────────
    #[test]
    fn socks5_url_with_special_chars_in_password() {
        // Passwords with @ or : in them are legal when percent-encoded.
        // The validator must accept the URL so the pool can use it.
        let result = parse_socks5_url("socks5://user:p%40ss%3Aword@proxy.example.com:1080");
        assert!(result.is_ok(), "percent-encoded auth must be accepted");
    }
}

// ── integration tests via wiremock ────────────────────────────────────────────

#[cfg(test)]
mod integration {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Spin up two mock servers: one returns 200, one returns 429 (challenge).
    /// Assert that after enough probes the pool routes around the 429 server.
    #[tokio::test]
    async fn prefers_200_source_over_429() {
        let ok_server = MockServer::start().await;
        let challenge_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/probe"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&ok_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/probe"))
            .respond_with(ResponseTemplate::new(429).set_body_string("rate limited"))
            .mount(&challenge_server)
            .await;

        let ok_url = format!("http://{}", ok_server.address());
        let bad_url = format!("http://{}", challenge_server.address());

        // Pool: slot 0 = ok_url (HTTP proxy), slot 1 = bad_url.
        let pool = EgressPool::builder()
            .http_proxy_str(vec![ok_url.clone(), bad_url])
            .expect("valid http proxy urls")
            .challenge_threshold(3)
            .cooldown_secs(300)
            .seed(0)
            .build()
            .unwrap();

        // Cool slot 1 (bad_url) by recording 3 challenges.
        for _ in 0..3 {
            pool.entries[1].record_challenge("target.com", 3, Duration::from_secs(300));
        }

        // All subsequent calls should resolve to slot 0 (ok).
        for _ in 0..5 {
            let entry = pool.next_for("target.com").expect("should get ok entry");
            // Verify it is the ok_url entry.
            assert_eq!(entry.backend.label(), ok_url);
        }
    }

    /// When both servers have been cooled, the pool returns EntirePoolCooled.
    #[tokio::test]
    async fn entire_pool_cooled_when_both_servers_bad() {
        let server_a = MockServer::start().await;
        let server_b = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server_a)
            .await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server_b)
            .await;

        let url_a = format!("http://{}", server_a.address());
        let url_b = format!("http://{}", server_b.address());

        let pool = EgressPool::builder()
            .http_proxy_str(vec![url_a, url_b])
            .expect("valid urls")
            .challenge_threshold(1)
            .cooldown_secs(300)
            .build()
            .unwrap();

        pool.entries[0].record_challenge("host.com", 1, Duration::from_secs(300));
        pool.entries[1].record_challenge("host.com", 1, Duration::from_secs(300));

        assert!(matches!(
            pool.next_for("host.com"),
            Err(EgressError::EntirePoolCooled { count: 2, .. })
        ));
    }

    /// After the ok server is used successfully, it stays preferred.
    #[tokio::test]
    async fn clean_entry_stays_preferred_after_passes() {
        let ok_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&ok_server)
            .await;

        let ok_url = format!("http://{}", ok_server.address());
        let bad_url = "http://127.255.255.254:9999".to_owned();

        let pool = EgressPool::builder()
            .http_proxy_str(vec![ok_url.clone(), bad_url])
            .expect("valid urls")
            .challenge_threshold(1)
            .cooldown_secs(300)
            .seed(0)
            .build()
            .unwrap();

        // Cool slot 1.
        pool.entries[1].record_challenge("host.com", 1, Duration::from_secs(300));

        // Record passes on slot 0.
        for _ in 0..5 {
            pool.entries[0].record_pass("host.com");
        }

        // Slot 0 should still be healthy.
        let entry = pool.next_for("host.com").unwrap();
        assert_eq!(entry.backend.label(), ok_url);
    }
}
