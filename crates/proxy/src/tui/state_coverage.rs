//! Extra unit tests for `tui::state` — functions that had zero coverage
//! despite being public API used by every TUI render pass.
//!
//! Each test names the property it pins.

#[cfg(test)]
mod state_coverage_tests {
    use crate::tui::state::{
        Event, InputMode, OutcomeFilter, RequestRecord, State, Tab, TechStats, TlsStats, Toast,
        ToastKind,
    };
    use std::time::Duration;

    // ─── helper ─────────────────────────────────────────────────────────

    fn req_with(host: &str, path: &str, status: u16, bypassed: bool, techniques: &str) -> Event {
        Event::Request {
            host: host.to_string(),
            method: "GET".into(),
            path: path.to_string(),
            status,
            bypassed,
            blocked: !bypassed && status == 403,
            techniques: techniques.to_string(),
            tls_profile: None,
            body_padded: false,
            upstream_latency_ms: 10,
            waf_name: None,
            req_headers: vec![],
            req_body_excerpt: vec![],
            req_headers_pre: vec![],
            req_body_pre_excerpt: vec![],
            resp_headers: vec![],
            resp_body_excerpt: vec![],
            resp_body_total: 0,
            attempts: 1,
        }
    }

    // ─── TechStats::bypass_rate ──────────────────────────────────────────

    #[test]
    fn tech_stats_bypass_rate_zero_when_no_tries() {
        // PROPERTY: `bypass_rate()` must return 0.0 when `tried == 0`
        // to avoid a division-by-zero panic (which was gated with an
        // explicit check in the implementation but must be tested).
        let ts = TechStats::default();
        assert_eq!(ts.bypass_rate(), 0.0);
    }

    #[test]
    fn tech_stats_bypass_rate_one_when_all_bypass() {
        // PROPERTY: if every attempt bypassed, bypass_rate must be 1.0.
        let ts = TechStats {
            tried: 4,
            bypassed: 4,
            last_bypass_unix_secs: 0,
        };
        assert!((ts.bypass_rate() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn tech_stats_bypass_rate_fraction() {
        // PROPERTY: bypass_rate = bypassed / tried exactly.
        let ts = TechStats {
            tried: 10,
            bypassed: 3,
            last_bypass_unix_secs: 0,
        };
        assert!((ts.bypass_rate() - 0.3).abs() < 1e-9);
    }

    // ─── TlsStats::record / total ─────────────────────────────────────────

    #[test]
    fn tls_stats_record_increments_total() {
        // PROPERTY: `total()` must equal the number of `record()` calls,
        // regardless of how many distinct profile strings are used.
        let mut ts = TlsStats::default();
        ts.record("chrome131");
        ts.record("chrome131");
        ts.record("firefox133");
        assert_eq!(ts.total(), 3);
    }

    #[test]
    fn tls_stats_record_counts_per_profile() {
        // PROPERTY: each distinct profile is counted independently; two
        // profiles with the same count must both appear in `counts`.
        let mut ts = TlsStats::default();
        for _ in 0..5 {
            ts.record("chrome131");
        }
        for _ in 0..3 {
            ts.record("safari17");
        }
        assert_eq!(ts.counts.get("chrome131"), Some(&5));
        assert_eq!(ts.counts.get("safari17"), Some(&3));
        assert_eq!(ts.total(), 8);
    }

    #[test]
    fn tls_stats_total_zero_when_empty() {
        // PROPERTY: `total()` on a fresh `TlsStats` must be 0 (no panic
        // on an empty HashMap sum).
        assert_eq!(TlsStats::default().total(), 0);
    }

    // ─── RequestRecord::outcome ───────────────────────────────────────────

    #[test]
    fn request_record_outcome_bypass() {
        // PROPERTY: when `bypassed = true`, outcome() must return "BYPASS".
        let rec = RequestRecord {
            timestamp: "t".into(),
            host: "h".into(),
            method: "GET".into(),
            path: "/".into(),
            status: 200,
            bypassed: true,
            blocked: false,
            techniques: "".into(),
            tls_profile: None,
            body_padded: false,
            upstream_latency_ms: 0,
            waf_name: None,
            req_headers: vec![],
            req_body_excerpt: vec![],
            req_headers_pre: vec![],
            req_body_pre_excerpt: vec![],
            resp_headers: vec![],
            resp_body_excerpt: vec![],
            resp_body_total: 0,
            attempts: 1,
        };
        assert_eq!(rec.outcome(), "BYPASS");
    }

    #[test]
    fn request_record_outcome_block_and_pass() {
        // PROPERTY: blocked=true, bypassed=false → "BLOCK"; both false → "PASS".
        let base = RequestRecord {
            timestamp: "t".into(),
            host: "h".into(),
            method: "GET".into(),
            path: "/".into(),
            status: 403,
            bypassed: false,
            blocked: true,
            techniques: "".into(),
            tls_profile: None,
            body_padded: false,
            upstream_latency_ms: 0,
            waf_name: None,
            req_headers: vec![],
            req_body_excerpt: vec![],
            req_headers_pre: vec![],
            req_body_pre_excerpt: vec![],
            resp_headers: vec![],
            resp_body_excerpt: vec![],
            resp_body_total: 0,
            attempts: 1,
        };
        assert_eq!(base.outcome(), "BLOCK");
        let pass = RequestRecord {
            blocked: false,
            status: 200,
            ..base
        };
        assert_eq!(pass.outcome(), "PASS");
    }

    // ─── RequestRecord::technique_keys ────────────────────────────────────

    #[test]
    fn technique_keys_parses_comma_separated() {
        // PROPERTY: technique_keys must split on commas and strip
        // whitespace — the TUI uses this for the per-technique stats.
        let rec = RequestRecord {
            timestamp: "t".into(),
            host: "h".into(),
            method: "GET".into(),
            path: "/".into(),
            status: 200,
            bypassed: true,
            blocked: false,
            techniques: "encoding:UrlEncode, grammar:cmd, header:obf".into(),
            tls_profile: None,
            body_padded: false,
            upstream_latency_ms: 0,
            waf_name: None,
            req_headers: vec![],
            req_body_excerpt: vec![],
            req_headers_pre: vec![],
            req_body_pre_excerpt: vec![],
            resp_headers: vec![],
            resp_body_excerpt: vec![],
            resp_body_total: 0,
            attempts: 1,
        };
        let keys: Vec<&str> = rec.technique_keys().collect();
        assert_eq!(
            keys,
            vec!["encoding:UrlEncode", "grammar:cmd", "header:obf"]
        );
    }

    #[test]
    fn technique_keys_empty_string_yields_no_keys() {
        // PROPERTY: an empty techniques string must yield zero keys — the
        // TUI must not count an empty key as a technique.
        let rec = RequestRecord {
            timestamp: "t".into(),
            host: "h".into(),
            method: "GET".into(),
            path: "/".into(),
            status: 200,
            bypassed: false,
            blocked: false,
            techniques: "".into(),
            tls_profile: None,
            body_padded: false,
            upstream_latency_ms: 0,
            waf_name: None,
            req_headers: vec![],
            req_body_excerpt: vec![],
            req_headers_pre: vec![],
            req_body_pre_excerpt: vec![],
            resp_headers: vec![],
            resp_body_excerpt: vec![],
            resp_body_total: 0,
            attempts: 1,
        };
        assert_eq!(rec.technique_keys().count(), 0);
    }

    // ─── State::avg_latency_ms ────────────────────────────────────────────

    #[test]
    fn avg_latency_ms_zero_when_no_requests() {
        // PROPERTY: avg_latency_ms must return 0 (not panic) when there
        // are no requests — the denominator is `total`, which starts at 0.
        let s = State::new();
        assert_eq!(s.avg_latency_ms(), 0);
    }

    #[test]
    fn avg_latency_ms_correct_average() {
        // PROPERTY: avg_latency = sum / count.
        let mut s = State::new();
        for lat in [10u64, 20, 30] {
            let mut e = req_with("h", "/", 200, false, "");
            if let Event::Request {
                upstream_latency_ms,
                ..
            } = &mut e
            {
                *upstream_latency_ms = lat;
            }
            s.record(&e);
        }
        assert_eq!(s.avg_latency_ms(), 20);
    }

    // ─── State::bypass_rate_pct ───────────────────────────────────────────

    #[test]
    fn bypass_rate_pct_zero_when_no_requests() {
        // PROPERTY: bypass_rate_pct must be 0.0 with no requests (no
        // division-by-zero).
        let s = State::new();
        assert_eq!(s.bypass_rate_pct(), 0.0);
    }

    #[test]
    fn bypass_rate_pct_correct_percentage() {
        // PROPERTY: bypass_rate_pct = (bypassed / total) * 100.
        let mut s = State::new();
        s.record(&req_with("h", "/", 200, true, ""));
        s.record(&req_with("h", "/", 200, true, ""));
        s.record(&req_with("h", "/", 403, false, ""));
        s.record(&req_with("h", "/", 403, false, ""));
        // 2 bypasses out of 4 total = 50%
        assert!((s.bypass_rate_pct() - 50.0).abs() < 1e-6);
    }

    // ─── State::rps_recent ────────────────────────────────────────────────

    #[test]
    fn rps_recent_zero_when_no_spark_data() {
        // PROPERTY: `rps_recent()` over an empty spark buffer must return
        // 0.0 (no panic on empty slice average).
        let s = State::new();
        assert_eq!(s.rps_recent(), 0.0);
    }

    // ─── State::top_hosts ────────────────────────────────────────────────

    #[test]
    fn top_hosts_returns_n_busiest_in_descending_order() {
        // PROPERTY: `top_hosts(n)` must return at most `n` hosts sorted
        // by `sent` descending — the most active first.
        let mut s = State::new();
        s.record(&req_with("busy.com", "/", 200, false, ""));
        s.record(&req_with("busy.com", "/", 200, false, ""));
        s.record(&req_with("busy.com", "/", 200, false, ""));
        s.record(&req_with("quiet.com", "/", 200, false, ""));
        let top = s.top_hosts(1);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].0, "busy.com");
    }

    #[test]
    fn top_hosts_with_n_larger_than_host_count_returns_all() {
        // PROPERTY: top_hosts(100) when only 3 hosts exist must return 3.
        let mut s = State::new();
        for h in ["a.com", "b.com", "c.com"] {
            s.record(&req_with(h, "/", 200, false, ""));
        }
        assert_eq!(s.top_hosts(100).len(), 3);
    }

    // ─── State::select_first ─────────────────────────────────────────────

    #[test]
    fn select_first_selects_first_visible_index() {
        // PROPERTY: select_first must set selected to the index of the
        // first record that passes the active filter — not index 0
        // unconditionally (filters may exclude the head of the ring).
        let mut s = State::new();
        s.record(&req_with("a.com", "/x", 403, false, "")); // block — index 0
        s.record(&req_with("a.com", "/y", 200, true, "")); // bypass — index 1
        s.outcome_filter = OutcomeFilter::BypassOnly;
        s.select_first();
        // Only index 1 is visible; select_first must land on it.
        assert_eq!(s.selected, Some(1));
        // follow is disabled on explicit navigation.
        assert!(!s.follow, "select_first must disengage follow");
    }

    #[test]
    fn select_first_sets_none_when_no_visible_records() {
        // PROPERTY: when the filter hides every record, select_first
        // must set `selected = None` (not leave a dangling index).
        let mut s = State::new();
        s.record(&req_with("a.com", "/", 200, false, ""));
        s.outcome_filter = OutcomeFilter::BypassOnly;
        s.select_first();
        assert_eq!(s.selected, None);
    }

    // ─── State::enter/cancel/commit filter edit ───────────────────────────

    #[test]
    fn enter_filter_edit_switches_input_mode() {
        // PROPERTY: `enter_filter_edit` must flip the input mode so
        // keystrokes are routed to the filter buffer instead of commands.
        let mut s = State::new();
        assert_eq!(s.input_mode, InputMode::Normal);
        s.enter_filter_edit();
        assert_eq!(s.input_mode, InputMode::FilterEdit);
    }

    #[test]
    fn cancel_filter_edit_clears_query_and_restores_normal_mode() {
        // PROPERTY: `cancel_filter_edit` must clear the filter query AND
        // restore Normal mode — the user is aborting the filter, not
        // committing it.
        let mut s = State::new();
        s.filter_query = "admin".into();
        s.input_mode = InputMode::FilterEdit;
        s.cancel_filter_edit();
        assert_eq!(s.input_mode, InputMode::Normal);
        assert_eq!(s.filter_query, "");
    }

    #[test]
    fn commit_filter_edit_keeps_query_and_restores_normal_mode() {
        // PROPERTY: `commit_filter_edit` must KEEP the filter query
        // (unlike cancel) and restore Normal mode.
        let mut s = State::new();
        s.filter_query = "admin".into();
        s.input_mode = InputMode::FilterEdit;
        s.commit_filter_edit();
        assert_eq!(s.input_mode, InputMode::Normal);
        assert_eq!(s.filter_query, "admin");
    }

    // ─── State::filter_backspace ──────────────────────────────────────────

    #[test]
    fn filter_backspace_removes_last_char() {
        // PROPERTY: `filter_backspace` must remove the last character
        // (pop), not the first — it's the user pressing ⌫.
        let mut s = State::new();
        s.filter_query = "adm".into();
        s.filter_backspace();
        assert_eq!(s.filter_query, "ad");
    }

    #[test]
    fn filter_backspace_on_empty_query_does_not_panic() {
        // PROPERTY: backspacing an empty query must be a no-op (not panic
        // with an underflow). String::pop returns None on empty.
        let mut s = State::new();
        assert!(s.filter_query.is_empty());
        s.filter_backspace(); // must not panic
        assert!(s.filter_query.is_empty());
    }

    // ─── State::set_toast / tick_toast ────────────────────────────────────

    #[test]
    fn set_toast_stores_toast_message() {
        // PROPERTY: `set_toast` must populate `self.toast` so the render
        // layer can display the banner.
        let mut s = State::new();
        assert!(s.toast.is_none());
        s.set_toast("yanked", ToastKind::Ok);
        assert!(s.toast.is_some());
        assert_eq!(s.toast.as_ref().unwrap().message, "yanked");
    }

    #[test]
    fn tick_toast_clears_expired_toast() {
        // PROPERTY: `tick_toast` must remove the toast once its TTL has
        // passed. A stale toast that persists forever would be a banner
        // that never dismisses.
        let mut s = State::new();
        // Create a toast with a very short TTL by backdating its `expires`.
        s.toast = Some(Toast {
            message: "stale".into(),
            kind: ToastKind::Info,
            // Already expired — set to 1 second ago.
            expires: std::time::Instant::now() - Duration::from_secs(1),
        });
        s.tick_toast();
        assert!(s.toast.is_none(), "expired toast must be cleared");
    }

    #[test]
    fn tick_toast_keeps_non_expired_toast() {
        // PROPERTY: `tick_toast` must NOT clear a toast whose TTL has
        // not yet elapsed. Clearing early would make banners flash
        // imperceptibly.
        let mut s = State::new();
        s.set_toast("live", ToastKind::Warn);
        s.tick_toast(); // TTL is ~2.4 s; this fires < 1 ms later
        assert!(
            s.toast.is_some(),
            "non-expired toast must survive tick_toast"
        );
    }

    // ─── OutcomeFilter::matches ───────────────────────────────────────────

    #[test]
    fn outcome_filter_all_matches_everything() {
        // PROPERTY: `OutcomeFilter::All.matches` must always return true —
        // no filtering when the operator has not selected a specific outcome.
        let rec = RequestRecord {
            timestamp: "t".into(),
            host: "h".into(),
            method: "GET".into(),
            path: "/".into(),
            status: 200,
            bypassed: true,
            blocked: false,
            techniques: "".into(),
            tls_profile: None,
            body_padded: false,
            upstream_latency_ms: 0,
            waf_name: None,
            req_headers: vec![],
            req_body_excerpt: vec![],
            req_headers_pre: vec![],
            req_body_pre_excerpt: vec![],
            resp_headers: vec![],
            resp_body_excerpt: vec![],
            resp_body_total: 0,
            attempts: 1,
        };
        assert!(OutcomeFilter::All.matches(&rec));
        let blocked = RequestRecord {
            bypassed: false,
            blocked: true,
            status: 403,
            ..rec.clone()
        };
        assert!(OutcomeFilter::All.matches(&blocked));
        let pass = RequestRecord {
            bypassed: false,
            blocked: false,
            status: 200,
            ..rec.clone()
        };
        assert!(OutcomeFilter::All.matches(&pass));
    }

    #[test]
    fn outcome_filter_labels_are_stable() {
        // PROPERTY: the label strings are rendered into the TUI; they must
        // not change between refactors.
        assert_eq!(OutcomeFilter::All.label(), "ALL");
        assert_eq!(OutcomeFilter::BypassOnly.label(), "BYPASS");
        assert_eq!(OutcomeFilter::BlockOnly.label(), "BLOCK");
        assert_eq!(OutcomeFilter::PassOnly.label(), "PASS");
    }

    // ─── Tab labels ───────────────────────────────────────────────────────

    #[test]
    fn tab_labels_are_stable() {
        // PROPERTY: tab labels are rendered in the header bar; they must
        // not silently change.
        assert_eq!(Tab::Flow.label(), "Flow");
        assert_eq!(Tab::Overview.label(), "Overview");
        assert_eq!(Tab::Hosts.label(), "Hosts");
        assert_eq!(Tab::Techniques.label(), "Techniques");
        assert_eq!(Tab::Intercept.label(), "Intercept");
    }

    #[test]
    fn tab_order_constant_has_five_variants() {
        // PROPERTY: Tab::ORDER must contain every variant exactly once.
        assert_eq!(Tab::ORDER.len(), 5);
        let mut seen = std::collections::HashSet::<&'static str>::new();
        for t in Tab::ORDER {
            assert!(
                seen.insert(t.label()),
                "duplicate tab in ORDER: {:?}",
                t.label()
            );
        }
    }
}
