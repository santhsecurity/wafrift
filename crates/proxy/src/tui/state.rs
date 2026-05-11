//! Mutable state for the TUI: counters, request ring, filter mode,
//! latency samples, per-technique stats, toast queue.
//!
//! Pure state + mutation logic — no rendering, no I/O. Render layers
//! read from `&State`; the event loop drives [`State::record`].

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use super::format::{chrono_now, status_bucket_index};

/// Maximum bytes of a request OR response body the dashboard keeps
/// per record. Bigger bodies are truncated by the emitter; the
/// dashboard only displays what arrived.
pub const MAX_BODY_EXCERPT: usize = 1024;

/// Request ring capacity. Sized so a few hours of operator-driven
/// traffic fit without losing the head; bypass-hunting sessions
/// regularly hit thousands of requests.
pub const REQUEST_RING: usize = 5000;

/// Sliding window of per-second buckets feeding the sparklines.
pub const SPARK_WINDOW_SECS: usize = 60;

/// Latency-sample ring. Big enough that p99 over a busy minute is
/// stable (≈ one sample per request × ~17 rps × 60 s).
pub const LATENCY_RING: usize = 1024;

/// Cap on filter-query length. Prevents accidental terminal-paste of
/// a megabyte from melting the redraw loop.
pub const MAX_FILTER_LEN: usize = 80;

/// Toast TTL on the header banner.
pub const TOAST_TTL: Duration = Duration::from_millis(2400);

/// Outbound proxy → dashboard event.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum Event {
    /// One finished proxied request.
    Request {
        host: String,
        method: String,
        path: String,
        status: u16,
        bypassed: bool,
        blocked: bool,
        techniques: String,
        tls_profile: Option<String>,
        body_padded: bool,
        upstream_latency_ms: u64,
        waf_name: Option<String>,
        /// Outgoing request headers (post-evade — what hit the wire).
        req_headers: Vec<(String, String)>,
        /// Outgoing request body excerpt (post-evade).
        req_body_excerpt: Vec<u8>,
        /// PRE-evade request headers (what the client sent before
        /// wafrift mutated them). Empty when the proxy is in
        /// passthrough mode and no evade ran.
        req_headers_pre: Vec<(String, String)>,
        /// PRE-evade request body excerpt (capped at `MAX_BODY_EXCERPT`).
        req_body_pre_excerpt: Vec<u8>,
        resp_headers: Vec<(String, String)>,
        resp_body_excerpt: Vec<u8>,
        resp_body_total: u64,
        attempts: u32,
    },
    /// Soft reset of all counters (the `r` keybinding fires this so
    /// the proxy main loop and the TUI loop share one code path).
    ResetCounters,
}

/// Single inspectable record — one proxied request + its response.
#[derive(Debug, Clone)]
pub struct RequestRecord {
    pub timestamp: String,
    pub host: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub bypassed: bool,
    pub blocked: bool,
    pub techniques: String,
    pub tls_profile: Option<String>,
    pub body_padded: bool,
    pub upstream_latency_ms: u64,
    pub waf_name: Option<String>,
    pub req_headers: Vec<(String, String)>,
    pub req_body_excerpt: Vec<u8>,
    pub req_headers_pre: Vec<(String, String)>,
    pub req_body_pre_excerpt: Vec<u8>,
    pub resp_headers: Vec<(String, String)>,
    pub resp_body_excerpt: Vec<u8>,
    pub resp_body_total: u64,
    pub attempts: u32,
}

impl RequestRecord {
    pub fn outcome(&self) -> &'static str {
        if self.bypassed {
            "BYPASS"
        } else if self.blocked {
            "BLOCK"
        } else {
            "PASS"
        }
    }

    /// Tokenise the comma-separated techniques string into individual
    /// keys for the per-technique leaderboard. Empty input yields an
    /// empty iterator.
    pub fn technique_keys(&self) -> impl Iterator<Item = &str> {
        self.techniques
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
    }
}

#[derive(Default, Debug, Clone)]
pub struct HostStats {
    pub sent: u64,
    pub blocked: u64,
    pub bypassed: u64,
    pub top_technique: String,
    pub waf_name: Option<String>,
}

#[derive(Default, Debug, Clone)]
pub struct TlsStats {
    pub counts: HashMap<String, u64>,
}

impl TlsStats {
    pub fn record(&mut self, profile: &str) {
        *self.counts.entry(profile.to_string()).or_insert(0) += 1;
    }
    pub fn total(&self) -> u64 {
        self.counts.values().sum()
    }
}

/// Tally for a single evasion technique key (e.g. `encoding:UrlEncode`).
#[derive(Default, Debug, Clone)]
pub struct TechStats {
    pub tried: u64,
    pub bypassed: u64,
    pub last_bypass_unix_secs: u64,
}

impl TechStats {
    pub fn bypass_rate(&self) -> f64 {
        if self.tried == 0 {
            0.0
        } else {
            #[allow(clippy::cast_precision_loss)]
            let r = self.bypassed as f64 / self.tried as f64;
            r
        }
    }
}

/// Which top-level view is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tab {
    #[default]
    Flow,
    Overview,
    Hosts,
    Techniques,
    Intercept,
}

impl Tab {
    pub const ORDER: [Tab; 5] = [
        Self::Flow,
        Self::Overview,
        Self::Hosts,
        Self::Techniques,
        Self::Intercept,
    ];

    pub fn next(self) -> Self {
        match self {
            Self::Flow => Self::Overview,
            Self::Overview => Self::Hosts,
            Self::Hosts => Self::Techniques,
            Self::Techniques => Self::Intercept,
            Self::Intercept => Self::Flow,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Flow => "Flow",
            Self::Overview => "Overview",
            Self::Hosts => "Hosts",
            Self::Techniques => "Techniques",
            Self::Intercept => "Intercept",
        }
    }
}

/// Outcome filter cycled by the `o` key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutcomeFilter {
    #[default]
    All,
    BypassOnly,
    BlockOnly,
    PassOnly,
}

impl OutcomeFilter {
    pub fn next(self) -> Self {
        match self {
            Self::All => Self::BypassOnly,
            Self::BypassOnly => Self::BlockOnly,
            Self::BlockOnly => Self::PassOnly,
            Self::PassOnly => Self::All,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::All => "ALL",
            Self::BypassOnly => "BYPASS",
            Self::BlockOnly => "BLOCK",
            Self::PassOnly => "PASS",
        }
    }

    pub fn matches(self, rec: &RequestRecord) -> bool {
        match self {
            Self::All => true,
            Self::BypassOnly => rec.bypassed,
            Self::BlockOnly => rec.blocked,
            Self::PassOnly => !rec.bypassed && !rec.blocked,
        }
    }
}

/// Input mode — drives whether keystrokes are commands or filter text.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum InputMode {
    #[default]
    Normal,
    /// User is typing into the filter buffer.
    FilterEdit,
}

/// Toast banner severity for the right-aligned header chip.
#[derive(Debug, Clone, Copy)]
pub enum ToastKind {
    Info,
    Ok,
    Warn,
    Err,
}

#[derive(Debug, Clone)]
pub struct Toast {
    pub message: String,
    pub kind: ToastKind,
    pub expires: Instant,
}

impl Toast {
    pub fn new(message: impl Into<String>, kind: ToastKind) -> Self {
        Self {
            message: message.into(),
            kind,
            expires: Instant::now() + TOAST_TTL,
        }
    }
}

/// Per-second tally bucket that feeds the sparklines.
#[derive(Default, Clone, Copy)]
pub struct SecBucket {
    pub requests: u64,
    pub bypasses: u64,
}

#[derive(Default)]
pub struct State {
    pub started: Option<Instant>,
    pub total: u64,
    pub bypassed: u64,
    pub blocked: u64,
    pub errors: u64,
    pub padded: u64,
    pub latency_sum_ms: u64,
    pub latency_samples: VecDeque<u64>,
    pub status_buckets: [u64; 6],
    pub hosts: HashMap<String, HostStats>,
    pub tls: TlsStats,
    pub recent: VecDeque<RequestRecord>,
    /// Index INTO `recent` for the Flow tab. `None` means "no
    /// explicit selection — auto-follow newest at the bottom".
    pub selected: Option<usize>,
    /// Whether the inspect/detail pane is open in Flow tab.
    pub inspect: bool,
    /// Vertical scroll offset within the open detail pane.
    pub detail_scroll: u16,
    /// Currently focused tab.
    pub tab: Tab,
    pub spark: VecDeque<SecBucket>,
    pub spark_current_sec: u64,
    pub waf_seen: HashMap<String, u64>,
    pub attempts_sum: u64,
    /// Per-technique tried/bypassed counts; drives the Techniques tab.
    pub tech_stats: HashMap<String, TechStats>,
    /// Outcome filter chip state.
    pub outcome_filter: OutcomeFilter,
    /// `Normal` for command keys, `FilterEdit` while typing a query.
    pub input_mode: InputMode,
    /// Active substring filter query (case-insensitive, host+path).
    pub filter_query: String,
    /// Auto-stick to newest record on every event when true.
    pub follow: bool,
    /// Ephemeral header banner (e.g. "yanked → /tmp/...").
    pub toast: Option<Toast>,
    /// Monotonic counter for `/tmp/wafrift-yank-N.curl` filenames.
    pub yank_seq: u64,
    /// Index INTO the latest `intercept::global_store().snapshot()`
    /// for the Intercept tab. Recomputed each render — selection
    /// survives across snapshots when possible.
    pub intercept_selected: Option<u64>,
}

impl State {
    pub fn new() -> Self {
        Self {
            started: Some(Instant::now()),
            tab: Tab::Flow,
            follow: true,
            ..Self::default()
        }
    }

    pub fn record(&mut self, ev: &Event) {
        match ev {
            Event::Request {
                host,
                method,
                path,
                status,
                bypassed,
                blocked,
                techniques,
                tls_profile,
                body_padded,
                upstream_latency_ms,
                waf_name,
                req_headers,
                req_body_excerpt,
                req_headers_pre,
                req_body_pre_excerpt,
                resp_headers,
                resp_body_excerpt,
                resp_body_total,
                attempts,
            } => {
                self.total += 1;
                if *bypassed {
                    self.bypassed += 1;
                }
                if *blocked {
                    self.blocked += 1;
                }
                if *status >= 500 {
                    self.errors += 1;
                }
                if *body_padded {
                    self.padded += 1;
                }
                self.latency_sum_ms = self.latency_sum_ms.saturating_add(*upstream_latency_ms);
                self.attempts_sum = self.attempts_sum.saturating_add(u64::from(*attempts));
                self.push_latency_sample(*upstream_latency_ms);
                self.status_buckets[status_bucket_index(*status)] += 1;

                let hs = self.hosts.entry(host.clone()).or_default();
                hs.sent += 1;
                if *blocked {
                    hs.blocked += 1;
                }
                if *bypassed {
                    hs.bypassed += 1;
                }
                if !techniques.is_empty() {
                    hs.top_technique.clone_from(techniques);
                }
                if let Some(w) = waf_name {
                    if hs.waf_name.is_none() {
                        *self.waf_seen.entry(w.clone()).or_insert(0) += 1;
                    }
                    hs.waf_name = Some(w.clone());
                }

                if let Some(p) = tls_profile {
                    self.tls.record(p);
                }

                self.bump_spark(*bypassed);
                self.tally_techniques(techniques, *bypassed);

                let rec = RequestRecord {
                    timestamp: chrono_now(),
                    host: host.clone(),
                    method: method.clone(),
                    path: path.clone(),
                    status: *status,
                    bypassed: *bypassed,
                    blocked: *blocked,
                    techniques: techniques.clone(),
                    tls_profile: tls_profile.clone(),
                    body_padded: *body_padded,
                    upstream_latency_ms: *upstream_latency_ms,
                    waf_name: waf_name.clone(),
                    req_headers: req_headers.clone(),
                    req_body_excerpt: req_body_excerpt.clone(),
                    req_headers_pre: req_headers_pre.clone(),
                    req_body_pre_excerpt: req_body_pre_excerpt.clone(),
                    resp_headers: resp_headers.clone(),
                    resp_body_excerpt: resp_body_excerpt.clone(),
                    resp_body_total: *resp_body_total,
                    attempts: *attempts,
                };
                if self.recent.len() == REQUEST_RING {
                    self.recent.pop_front();
                    if let Some(i) = self.selected.as_mut() {
                        *i = i.saturating_sub(1);
                    }
                }
                self.recent.push_back(rec);

                // Auto-follow: when in follow mode AND nothing is
                // selected, the list naturally tails. When something
                // IS selected and follow is on, stick selection to
                // the newest entry so the operator sees live action.
                if self.follow && self.selected.is_some() {
                    self.selected = Some(self.recent.len() - 1);
                }
            }
            Event::ResetCounters => {
                let started = self.started;
                let tab = self.tab;
                let outcome_filter = self.outcome_filter;
                let filter_query = std::mem::take(&mut self.filter_query);
                let follow = self.follow;
                let yank_seq = self.yank_seq;
                *self = State::default();
                self.started = started;
                self.tab = tab;
                self.outcome_filter = outcome_filter;
                self.filter_query = filter_query;
                self.follow = follow;
                self.yank_seq = yank_seq;
            }
        }
    }

    fn push_latency_sample(&mut self, ms: u64) {
        if self.latency_samples.len() == LATENCY_RING {
            self.latency_samples.pop_front();
        }
        self.latency_samples.push_back(ms);
    }

    fn tally_techniques(&mut self, csv: &str, bypassed: bool) {
        for key in csv.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let entry = self.tech_stats.entry(key.to_string()).or_default();
            entry.tried += 1;
            if bypassed {
                entry.bypassed += 1;
                entry.last_bypass_unix_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
            }
        }
    }

    fn bump_spark(&mut self, bypassed: bool) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if self.spark_current_sec != now {
            self.spark_current_sec = now;
            self.spark.push_back(SecBucket::default());
            while self.spark.len() > SPARK_WINDOW_SECS {
                self.spark.pop_front();
            }
        }
        if let Some(b) = self.spark.back_mut() {
            b.requests += 1;
            if bypassed {
                b.bypasses += 1;
            }
        }
    }

    pub fn uptime(&self) -> Duration {
        self.started.map_or_else(|| Duration::from_secs(0), |s| s.elapsed())
    }

    pub fn avg_latency_ms(&self) -> u64 {
        self.latency_sum_ms.checked_div(self.total).unwrap_or(0)
    }

    /// Compute a percentile (e.g. `0.95`) from the latency-sample ring.
    /// Returns 0 when the ring is empty. Sorts a copy on every call —
    /// fine at dashboard refresh rate (≤7 Hz) for a 1024-entry ring.
    pub fn latency_percentile(&self, p: f64) -> u64 {
        if self.latency_samples.is_empty() {
            return 0;
        }
        let mut v: Vec<u64> = self.latency_samples.iter().copied().collect();
        v.sort_unstable();
        let p = p.clamp(0.0, 1.0);
        // "Nearest rank" with floor — matches NIST C=1 convention for
        // common percentiles: p50 of [10..100 by 10] = 50, not 60.
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let idx = ((v.len() as f64 - 1.0) * p).floor() as usize;
        v[idx]
    }

    pub fn bypass_rate_pct(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        #[allow(clippy::cast_precision_loss)]
        let r = (self.bypassed as f64 / self.total as f64) * 100.0;
        r
    }

    pub fn rps_recent(&self) -> f64 {
        let n = self.spark.len().min(5);
        if n == 0 {
            return 0.0;
        }
        #[allow(clippy::cast_precision_loss)]
        let sum: f64 = self
            .spark
            .iter()
            .rev()
            .take(n)
            .map(|b| b.requests as f64)
            .sum();
        sum / (n as f64)
    }

    pub fn top_hosts(&self, n: usize) -> Vec<(&String, &HostStats)> {
        let mut v: Vec<_> = self.hosts.iter().collect();
        v.sort_by_key(|b| std::cmp::Reverse(b.1.sent));
        v.truncate(n);
        v
    }

    /// Return the indices of `recent` that pass the active filter
    /// query and outcome filter, in chronological order.
    pub fn visible_indices(&self) -> Vec<usize> {
        let q = self.filter_query.to_ascii_lowercase();
        let q = q.trim();
        self.recent
            .iter()
            .enumerate()
            .filter(|(_, r)| self.outcome_filter.matches(r))
            .filter(|(_, r)| {
                if q.is_empty() {
                    true
                } else {
                    r.host.to_ascii_lowercase().contains(q)
                        || r.path.to_ascii_lowercase().contains(q)
                        || r.method.to_ascii_lowercase().contains(q)
                        || r.techniques.to_ascii_lowercase().contains(q)
                        || r.waf_name
                            .as_deref()
                            .is_some_and(|w| w.to_ascii_lowercase().contains(q))
                }
            })
            .map(|(i, _)| i)
            .collect()
    }

    /// Move the selection by `delta` rows within the *visible* list
    /// (filter-aware). Selection is stored as an index into `recent`
    /// so external code (detail pane, yank) can deref directly.
    pub fn select_offset(&mut self, delta: i64) {
        let visible = self.visible_indices();
        if visible.is_empty() {
            self.selected = None;
            return;
        }
        let cur_visible = self
            .selected
            .and_then(|i| visible.iter().position(|&v| v == i))
            .unwrap_or(visible.len().saturating_sub(1));
        #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
        let new_visible =
            (cur_visible as i64 + delta).clamp(0, (visible.len() - 1) as i64) as usize;
        self.selected = Some(visible[new_visible]);
        // any explicit navigation drops auto-follow — operator wants to
        // pin a row.
        if delta != 0 {
            self.follow = false;
        }
    }

    pub fn select_first(&mut self) {
        let visible = self.visible_indices();
        if let Some(&first) = visible.first() {
            self.selected = Some(first);
            self.follow = false;
        } else {
            self.selected = None;
        }
    }

    pub fn select_last(&mut self) {
        let visible = self.visible_indices();
        if let Some(&last) = visible.last() {
            self.selected = Some(last);
        } else {
            self.selected = None;
        }
    }

    pub fn toggle_follow(&mut self) {
        self.follow = !self.follow;
        if self.follow {
            // jump back to newest visible row when re-engaging follow
            let visible = self.visible_indices();
            if let Some(&last) = visible.last() {
                self.selected = Some(last);
            }
        }
    }

    pub fn cycle_outcome_filter(&mut self) {
        self.outcome_filter = self.outcome_filter.next();
        // Clamp selection so we don't dangle on a now-invisible row.
        let visible = self.visible_indices();
        if let Some(sel) = self.selected
            && !visible.contains(&sel)
        {
            self.selected = visible.last().copied();
        }
    }

    pub fn enter_filter_edit(&mut self) {
        self.input_mode = InputMode::FilterEdit;
    }

    pub fn cancel_filter_edit(&mut self) {
        self.input_mode = InputMode::Normal;
        self.filter_query.clear();
        let visible = self.visible_indices();
        if let Some(sel) = self.selected
            && !visible.contains(&sel)
        {
            self.selected = visible.last().copied();
        }
    }

    pub fn commit_filter_edit(&mut self) {
        self.input_mode = InputMode::Normal;
        let visible = self.visible_indices();
        if let Some(sel) = self.selected {
            if !visible.contains(&sel) {
                self.selected = visible.last().copied();
            }
        } else {
            self.selected = visible.last().copied();
        }
    }

    pub fn filter_push(&mut self, c: char) {
        if self.filter_query.chars().count() < MAX_FILTER_LEN {
            self.filter_query.push(c);
        }
    }

    pub fn filter_backspace(&mut self) {
        self.filter_query.pop();
    }

    pub fn set_toast(&mut self, msg: impl Into<String>, kind: ToastKind) {
        self.toast = Some(Toast::new(msg, kind));
    }

    /// Drop the toast if it's expired. Called every redraw tick.
    pub fn tick_toast(&mut self) {
        if let Some(t) = &self.toast
            && Instant::now() >= t.expires
        {
            self.toast = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(host: &str, status: u16, bypassed: bool, padded: bool, profile: Option<&str>) -> Event {
        Event::Request {
            host: host.to_string(),
            method: "GET".into(),
            path: "/".into(),
            status,
            bypassed,
            blocked: !bypassed && status == 403,
            techniques: "encoding:UrlEncode".into(),
            tls_profile: profile.map(std::string::ToString::to_string),
            body_padded: padded,
            upstream_latency_ms: 50,
            waf_name: None,
            req_headers: vec![],
            req_body_excerpt: vec![],
            req_headers_pre: vec![],
            req_body_pre_excerpt: vec![],
            resp_headers: vec![],
            resp_body_excerpt: vec![],
            resp_body_total: 0,
            attempts: 0,
        }
    }

    fn req_with(host: &str, path: &str, status: u16, bypassed: bool, techniques: &str) -> Event {
        let mut e = req(host, status, bypassed, false, None);
        if let Event::Request {
            path: p,
            techniques: t,
            ..
        } = &mut e
        {
            *p = path.into();
            *t = techniques.into();
        }
        e
    }

    fn req_with_waf(host: &str, waf: &str) -> Event {
        let mut e = req(host, 403, false, false, None);
        if let Event::Request { waf_name, .. } = &mut e {
            *waf_name = Some(waf.to_string());
        }
        e
    }

    #[test]
    fn state_counts_bypass_block_padding_and_status_buckets() {
        let mut s = State::new();
        s.record(&req("a.com", 200, true, true, Some("chrome131")));
        s.record(&req("a.com", 403, false, true, Some("firefox133")));
        s.record(&req("b.com", 500, false, false, None));
        assert_eq!(s.total, 3);
        assert_eq!(s.bypassed, 1);
        assert_eq!(s.blocked, 1);
        assert_eq!(s.errors, 1);
        assert_eq!(s.padded, 2);
        assert_eq!(s.status_buckets[1], 1); // 200
        assert_eq!(s.status_buckets[3], 1); // 403
        assert_eq!(s.status_buckets[4], 1); // 500
    }

    #[test]
    fn latency_percentiles_track_distribution() {
        let mut s = State::new();
        for ms in [10u64, 20, 30, 40, 50, 60, 70, 80, 90, 100] {
            let mut e = req("h", 200, true, false, None);
            if let Event::Request {
                upstream_latency_ms,
                ..
            } = &mut e
            {
                *upstream_latency_ms = ms;
            }
            s.record(&e);
        }
        assert_eq!(s.latency_percentile(0.5), 50);
        assert_eq!(s.latency_percentile(0.9), 90);
        assert_eq!(s.latency_percentile(1.0), 100);
        assert_eq!(s.latency_percentile(0.0), 10);
    }

    #[test]
    fn latency_ring_capped_at_1024() {
        let mut s = State::new();
        for i in 0..(LATENCY_RING + 100) {
            let mut e = req("h", 200, false, false, None);
            if let Event::Request {
                upstream_latency_ms,
                ..
            } = &mut e
            {
                *upstream_latency_ms = i as u64;
            }
            s.record(&e);
        }
        assert_eq!(s.latency_samples.len(), LATENCY_RING);
        // oldest 100 values must have been evicted
        assert_eq!(s.latency_samples.front().copied(), Some(100));
    }

    #[test]
    fn outcome_filter_cycles_and_filters() {
        let mut s = State::new();
        s.record(&req_with("a.com", "/x", 200, true, "encoding:UrlEncode"));
        s.record(&req_with("a.com", "/y", 403, false, "")); // block (403, not bypassed)
        s.record(&req_with("a.com", "/z", 200, false, "")); // pass
        assert_eq!(s.visible_indices().len(), 3);
        s.cycle_outcome_filter(); // BypassOnly
        assert_eq!(s.outcome_filter, OutcomeFilter::BypassOnly);
        assert_eq!(s.visible_indices().len(), 1);
        s.cycle_outcome_filter(); // BlockOnly
        assert_eq!(s.visible_indices().len(), 1);
        s.cycle_outcome_filter(); // PassOnly
        assert_eq!(s.visible_indices().len(), 1);
        s.cycle_outcome_filter(); // back to All
        assert_eq!(s.visible_indices().len(), 3);
    }

    #[test]
    fn filter_query_matches_host_path_method_techniques_waf_case_insensitive() {
        let mut s = State::new();
        s.record(&req_with(
            "api.target.com",
            "/admin",
            200,
            true,
            "encoding:UrlEncode",
        ));
        s.record(&req_with(
            "static.example.com",
            "/style.css",
            200,
            false,
            "",
        ));
        s.filter_query = "ADMIN".into();
        let v = s.visible_indices();
        assert_eq!(v.len(), 1, "filter must be case-insensitive on path");
        s.filter_query = "url".into();
        assert_eq!(s.visible_indices().len(), 1);
        s.filter_query = "static".into();
        assert_eq!(s.visible_indices().len(), 1);
        s.filter_query = "nope".into();
        assert_eq!(s.visible_indices().len(), 0);
    }

    #[test]
    fn select_navigation_uses_visible_only() {
        let mut s = State::new();
        s.record(&req_with("a.com", "/x", 200, true, "")); // bypass
        s.record(&req_with("a.com", "/y", 403, false, "")); // block
        s.record(&req_with("a.com", "/z", 200, true, "")); // bypass
        s.outcome_filter = OutcomeFilter::BypassOnly;
        s.select_last();
        // Last bypass is index 2 in `recent`
        assert_eq!(s.selected, Some(2));
        s.select_offset(-1);
        // Previous visible bypass is index 0
        assert_eq!(s.selected, Some(0));
        s.select_offset(-1);
        // clamps at start
        assert_eq!(s.selected, Some(0));
    }

    #[test]
    fn tech_stats_per_key_tally() {
        let mut s = State::new();
        s.record(&req_with(
            "h",
            "/",
            200,
            true,
            "encoding:UrlEncode, grammar:cmd",
        ));
        s.record(&req_with("h", "/", 200, true, "encoding:UrlEncode"));
        s.record(&req_with("h", "/", 403, false, "encoding:UrlEncode"));
        let url = s.tech_stats.get("encoding:UrlEncode").expect("present");
        assert_eq!(url.tried, 3);
        assert_eq!(url.bypassed, 2);
        let cmd = s.tech_stats.get("grammar:cmd").expect("present");
        assert_eq!(cmd.tried, 1);
        assert_eq!(cmd.bypassed, 1);
    }

    #[test]
    fn waf_seen_increments_once_per_host() {
        let mut s = State::new();
        s.record(&req_with_waf("a.com", "Cloudflare"));
        s.record(&req_with_waf("a.com", "Cloudflare"));
        s.record(&req_with_waf("b.com", "Cloudflare"));
        s.record(&req_with_waf("c.com", "ModSecurity"));
        assert_eq!(s.waf_seen.get("Cloudflare"), Some(&2));
        assert_eq!(s.waf_seen.get("ModSecurity"), Some(&1));
    }

    #[test]
    fn reset_preserves_uptime_tab_outcome_filter_query_follow() {
        let mut s = State::new();
        s.tab = Tab::Hosts;
        s.outcome_filter = OutcomeFilter::BypassOnly;
        s.filter_query = "admin".into();
        s.follow = false;
        let started = s.started;
        s.record(&req("a", 200, true, true, Some("chrome131")));
        s.record(&Event::ResetCounters);
        assert_eq!(s.total, 0);
        assert_eq!(s.started, started);
        assert_eq!(s.tab, Tab::Hosts);
        assert_eq!(s.outcome_filter, OutcomeFilter::BypassOnly);
        assert_eq!(s.filter_query, "admin");
        assert!(!s.follow);
    }

    #[test]
    fn toggle_follow_jumps_to_newest_visible_when_engaged() {
        let mut s = State::new();
        s.record(&req_with("a", "/x", 200, true, ""));
        s.record(&req_with("a", "/y", 403, false, ""));
        s.outcome_filter = OutcomeFilter::BypassOnly;
        s.selected = Some(0);
        s.follow = false;
        s.toggle_follow();
        assert!(s.follow);
        // Only one visible (the bypass at index 0)
        assert_eq!(s.selected, Some(0));
    }

    #[test]
    fn ring_capped_and_selection_decremented() {
        let mut s = State::new();
        for i in 0..(REQUEST_RING + 50) {
            s.record(&req(&format!("h{i}"), 200, true, false, None));
        }
        assert_eq!(s.recent.len(), REQUEST_RING);
    }

    #[test]
    fn tab_cycles_in_five() {
        assert_eq!(Tab::Flow.next(), Tab::Overview);
        assert_eq!(Tab::Overview.next(), Tab::Hosts);
        assert_eq!(Tab::Hosts.next(), Tab::Techniques);
        assert_eq!(Tab::Techniques.next(), Tab::Intercept);
        assert_eq!(Tab::Intercept.next(), Tab::Flow);
    }

    #[test]
    fn outcome_filter_cycles_in_four() {
        assert_eq!(OutcomeFilter::All.next(), OutcomeFilter::BypassOnly);
        assert_eq!(OutcomeFilter::BypassOnly.next(), OutcomeFilter::BlockOnly);
        assert_eq!(OutcomeFilter::BlockOnly.next(), OutcomeFilter::PassOnly);
        assert_eq!(OutcomeFilter::PassOnly.next(), OutcomeFilter::All);
    }

    #[test]
    fn filter_push_caps_length() {
        let mut s = State::new();
        for _ in 0..(MAX_FILTER_LEN + 50) {
            s.filter_push('a');
        }
        assert_eq!(s.filter_query.chars().count(), MAX_FILTER_LEN);
    }
}
