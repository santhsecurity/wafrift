//! Keystroke dispatch for the TUI event loop.
//!
//! Two-mode model:
//! - **Normal**: keys are commands (tab switching, navigation, yank, …).
//! - **`FilterEdit`**: printable chars build the filter query; Esc cancels,
//!   Enter commits, Backspace deletes.

use crossterm::event::{KeyCode, KeyModifiers};
use tokio::sync::oneshot;

use super::state::{InputMode, State, Tab, ToastKind};
use super::yank::{replay_to_disk_and_optionally_exec, yank_to_disk_and_clipboard};

/// Result of one keystroke dispatch — `true` means the loop should
/// exit.
#[must_use]
pub fn handle_key(
    state: &mut State,
    code: KeyCode,
    mods: KeyModifiers,
    quit: &mut Option<oneshot::Sender<()>>,
) -> bool {
    // Filter-edit mode swallows most keys to build the query.
    if state.input_mode == InputMode::FilterEdit {
        return handle_filter_edit(state, code, mods);
    }
    handle_normal(state, code, mods, quit)
}

fn handle_filter_edit(state: &mut State, code: KeyCode, mods: KeyModifiers) -> bool {
    match code {
        KeyCode::Esc => state.cancel_filter_edit(),
        KeyCode::Enter => state.commit_filter_edit(),
        KeyCode::Backspace => state.filter_backspace(),
        KeyCode::Char(c) => {
            // Ctrl-c during edit cancels rather than quitting — operator
            // expects edit-mode to be modal.
            if mods.contains(KeyModifiers::CONTROL) && (c == 'c' || c == 'C') {
                state.cancel_filter_edit();
            } else if !mods.contains(KeyModifiers::CONTROL) {
                state.filter_push(c);
            }
        }
        _ => {}
    }
    false
}

fn handle_normal(
    state: &mut State,
    code: KeyCode,
    mods: KeyModifiers,
    quit: &mut Option<oneshot::Sender<()>>,
) -> bool {
    match code {
        KeyCode::Char('q') | KeyCode::Esc => {
            send_quit(quit);
            return true;
        }
        KeyCode::Char('c') if mods.contains(KeyModifiers::CONTROL) => {
            send_quit(quit);
            return true;
        }

        // Tab switching
        KeyCode::Tab => state.tab = state.tab.next(),
        KeyCode::Char('1' | 'f' | 'F') => state.tab = Tab::Flow,
        KeyCode::Char('2' | 'o' | 'O') if !is_flow_outcome_cycle(state, code) => {
            // 'o' / 'O' is bound to outcome filter on Flow; on other tabs
            // it switches to Overview (kept for backward compat).
            state.tab = Tab::Overview;
        }
        KeyCode::Char('2') => state.tab = Tab::Overview,
        KeyCode::Char('3' | 'H') => state.tab = Tab::Hosts,
        KeyCode::Char('4' | 't' | 'T') => {
            state.tab = Tab::Techniques;
        }
        KeyCode::Char('5') => state.tab = Tab::Intercept,

        // Outcome filter cycle (Flow only) — 'o' lowercase
        KeyCode::Char('o') if state.tab == Tab::Flow => {
            state.cycle_outcome_filter();
            let label = state.outcome_filter.label();
            state.set_toast(format!("outcome filter → {label}"), ToastKind::Info);
        }

        // Filter-edit entry
        KeyCode::Char('/') => {
            state.enter_filter_edit();
            state.set_toast(
                "filter: type to narrow, Enter to commit, Esc to cancel",
                ToastKind::Info,
            );
        }

        // Pause/follow toggle
        KeyCode::Char('p' | 'P') => {
            state.toggle_follow();
            let msg = if state.follow {
                "follow → ON"
            } else {
                "follow → PAUSED"
            };
            state.set_toast(msg, ToastKind::Info);
        }

        KeyCode::Char('r') if state.tab != Tab::Intercept => {
            state.record(&super::state::Event::ResetCounters);
            state.set_toast("counters reset", ToastKind::Ok);
        }
        KeyCode::Char('c') if state.tab != Tab::Intercept => {
            state.recent.clear();
            state.selected = None;
            state.set_toast("request list cleared", ToastKind::Ok);
        }

        // Navigation — when inspect pane is open, j/k scroll the detail
        // pane; otherwise they navigate the list.
        KeyCode::Char('j') | KeyCode::Down if state.tab == Tab::Flow => {
            if state.inspect {
                state.detail_scroll = state.detail_scroll.saturating_add(1);
            } else {
                state.select_offset(1);
            }
        }
        KeyCode::Char('k') | KeyCode::Up if state.tab == Tab::Flow => {
            if state.inspect {
                state.detail_scroll = state.detail_scroll.saturating_sub(1);
            } else {
                state.select_offset(-1);
            }
        }
        KeyCode::PageDown if state.tab == Tab::Flow => {
            if state.inspect {
                state.detail_scroll = state.detail_scroll.saturating_add(10);
            } else {
                state.select_offset(10);
            }
        }
        KeyCode::PageUp if state.tab == Tab::Flow => {
            if state.inspect {
                state.detail_scroll = state.detail_scroll.saturating_sub(10);
            } else {
                state.select_offset(-10);
            }
        }
        KeyCode::Home if state.tab == Tab::Flow => {
            if state.inspect {
                state.detail_scroll = 0;
            } else {
                state.select_first();
            }
        }
        KeyCode::End if state.tab == Tab::Flow => {
            if state.inspect {
                state.detail_scroll = u16::MAX;
            } else {
                state.select_last();
                state.follow = true;
            }
        }
        KeyCode::Char('g') if state.tab == Tab::Flow => state.select_first(),
        KeyCode::Char('G') if state.tab == Tab::Flow => state.select_last(),
        KeyCode::Enter if state.tab == Tab::Flow => {
            state.inspect = !state.inspect;
            state.detail_scroll = 0;
            if state.inspect && state.selected.is_none() {
                state.select_last();
            }
        }

        // Yank curl (Flow with selection only)
        KeyCode::Char('y' | 'Y') if state.tab == Tab::Flow => {
            do_yank(state);
        }

        // Replay — write a /tmp/wafrift-replay-N.curl reproducer and
        // (when WAFRIFT_REPLAY_AUTOEXEC=1) re-fire it via bash. This
        // does NOT route through the proxy's evade pipeline — the
        // captured request is already evaded.
        KeyCode::Char('R') if state.tab == Tab::Flow => {
            do_replay(state);
        }

        // Intercept-mode toggle — works from any tab so the operator
        // doesn't have to navigate to enable.
        KeyCode::Char('i' | 'I') => {
            let now_on = crate::intercept::toggle_intercept_mode();
            state.set_toast(
                format!("intercept mode → {}", if now_on { "ON" } else { "OFF" }),
                if now_on {
                    ToastKind::Warn
                } else {
                    ToastKind::Info
                },
            );
            if now_on {
                state.tab = Tab::Intercept;
            }
        }

        // Intercept tab actions: r releases the oldest pending,
        // k kills the oldest pending. Operator-friendly default
        // (act on the head of the queue) so no per-row selection
        // is needed for the v1 surface.
        KeyCode::Char('r') if state.tab == Tab::Intercept => {
            let store = crate::intercept::global_store();
            if let Some(pending) = store.snapshot().into_iter().next() {
                store.resolve(pending.id, crate::intercept::InterceptDecision::Release);
                state.set_toast(
                    format!("released #{} → upstream", pending.id),
                    ToastKind::Ok,
                );
            } else {
                state.set_toast("intercept: no pending request", ToastKind::Warn);
            }
        }
        KeyCode::Char('k') if state.tab == Tab::Intercept => {
            let store = crate::intercept::global_store();
            if let Some(pending) = store.snapshot().into_iter().next() {
                store.resolve(pending.id, crate::intercept::InterceptDecision::Kill);
                state.set_toast(format!("killed #{} → 403", pending.id), ToastKind::Err);
            } else {
                state.set_toast("intercept: no pending request", ToastKind::Warn);
            }
        }

        _ => {}
    }
    false
}

/// Bypass the `2`/`o` overlap: when we're already on Flow, lowercase
/// `o` is the outcome filter command, not "switch to Overview". This
/// helper detects that exact case so the broader keymap match doesn't
/// fire the wrong arm.
fn is_flow_outcome_cycle(state: &State, code: KeyCode) -> bool {
    matches!(code, KeyCode::Char('o')) && state.tab == Tab::Flow
}

fn send_quit(quit: &mut Option<oneshot::Sender<()>>) {
    if let Some(tx) = quit.take() {
        let _ = tx.send(());
    }
}

fn do_replay(state: &mut State) {
    let Some(idx) = state.selected else {
        state.set_toast("replay: no request selected", ToastKind::Warn);
        return;
    };
    let Some(rec) = state.recent.get(idx).cloned() else {
        state.set_toast("replay: stale selection", ToastKind::Warn);
        return;
    };
    state.yank_seq = state.yank_seq.wrapping_add(1);
    let seq = state.yank_seq;
    match replay_to_disk_and_optionally_exec(&rec, seq) {
        Ok(report) => {
            let exec_label = match report.upstream_status {
                Some(code) => format!("autoexec exit={code}"),
                None => "no autoexec (set WAFRIFT_REPLAY_AUTOEXEC=1 to fire on every R)".into(),
            };
            state.set_toast(
                format!(
                    "replay → {} ({} bytes, {})",
                    report.path.display(),
                    report.bytes,
                    exec_label
                ),
                if report.upstream_status.unwrap_or(0) == 0 {
                    ToastKind::Ok
                } else {
                    ToastKind::Info
                },
            );
        }
        Err(e) => {
            state.set_toast(format!("replay failed: {e}"), ToastKind::Err);
        }
    }
}

fn do_yank(state: &mut State) {
    let Some(idx) = state.selected else {
        state.set_toast("yank: no request selected", ToastKind::Warn);
        return;
    };
    let Some(rec) = state.recent.get(idx).cloned() else {
        state.set_toast("yank: stale selection", ToastKind::Warn);
        return;
    };
    state.yank_seq = state.yank_seq.wrapping_add(1);
    let seq = state.yank_seq;
    match yank_to_disk_and_clipboard(&rec, seq) {
        Ok(report) => {
            let clip_label = if report.clipboard_ok {
                "clipboard ✓"
            } else {
                "clipboard ✗"
            };
            state.set_toast(
                format!(
                    "yanked → {} ({} bytes, {})",
                    report.path.display(),
                    report.bytes,
                    clip_label
                ),
                if report.clipboard_ok {
                    ToastKind::Ok
                } else {
                    ToastKind::Warn
                },
            );
        }
        Err(e) => {
            state.set_toast(format!("yank failed: {e}"), ToastKind::Err);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::state::{Event, OutcomeFilter, State, Tab};

    fn req(host: &str, status: u16, bypassed: bool) -> Event {
        Event::Request {
            host: host.into(),
            method: "GET".into(),
            path: "/".into(),
            status,
            bypassed,
            blocked: !bypassed && status == 403,
            techniques: String::new(),
            tls_profile: None,
            body_padded: false,
            upstream_latency_ms: 1,
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

    fn key(c: char) -> (KeyCode, KeyModifiers) {
        (KeyCode::Char(c), KeyModifiers::NONE)
    }

    fn press(s: &mut State, code: KeyCode, mods: KeyModifiers) {
        let mut q: Option<oneshot::Sender<()>> = None;
        let _ = handle_key(s, code, mods, &mut q);
    }

    #[test]
    fn slash_enters_filter_edit_mode() {
        let mut s = State::new();
        let (c, m) = key('/');
        press(&mut s, c, m);
        assert_eq!(s.input_mode, InputMode::FilterEdit);
    }

    #[test]
    fn typing_in_filter_edit_builds_query() {
        let mut s = State::new();
        s.enter_filter_edit();
        press(&mut s, KeyCode::Char('a'), KeyModifiers::NONE);
        press(&mut s, KeyCode::Char('p'), KeyModifiers::NONE);
        press(&mut s, KeyCode::Char('i'), KeyModifiers::NONE);
        assert_eq!(s.filter_query, "api");
        // Esc cancels, clearing the query
        press(&mut s, KeyCode::Esc, KeyModifiers::NONE);
        assert_eq!(s.input_mode, InputMode::Normal);
        assert_eq!(s.filter_query, "");
    }

    #[test]
    fn enter_commits_filter_edit() {
        let mut s = State::new();
        s.enter_filter_edit();
        press(&mut s, KeyCode::Char('a'), KeyModifiers::NONE);
        press(&mut s, KeyCode::Enter, KeyModifiers::NONE);
        assert_eq!(s.input_mode, InputMode::Normal);
        assert_eq!(s.filter_query, "a");
    }

    #[test]
    fn p_toggles_follow() {
        let mut s = State::new();
        assert!(s.follow);
        press(&mut s, KeyCode::Char('p'), KeyModifiers::NONE);
        assert!(!s.follow);
        press(&mut s, KeyCode::Char('p'), KeyModifiers::NONE);
        assert!(s.follow);
    }

    #[test]
    fn o_on_flow_cycles_outcome_filter() {
        let mut s = State::new();
        assert_eq!(s.tab, Tab::Flow);
        press(&mut s, KeyCode::Char('o'), KeyModifiers::NONE);
        assert_eq!(s.outcome_filter, OutcomeFilter::BypassOnly);
        // tab unchanged — 'o' on Flow MUST NOT also jump to Overview
        assert_eq!(s.tab, Tab::Flow);
    }

    #[test]
    fn o_on_overview_does_not_cycle_outcome_filter() {
        let mut s = State::new();
        s.tab = Tab::Overview;
        let before = s.outcome_filter;
        press(&mut s, KeyCode::Char('o'), KeyModifiers::NONE);
        // we're on Overview already — pressing 'o' is a no-op (was a
        // jump-to-Overview command, but we're already there)
        assert_eq!(s.outcome_filter, before);
    }

    #[test]
    fn t_switches_to_techniques_tab() {
        let mut s = State::new();
        press(&mut s, KeyCode::Char('t'), KeyModifiers::NONE);
        assert_eq!(s.tab, Tab::Techniques);
    }

    #[test]
    fn h_capital_switches_to_hosts() {
        let mut s = State::new();
        press(&mut s, KeyCode::Char('H'), KeyModifiers::NONE);
        assert_eq!(s.tab, Tab::Hosts);
    }

    #[test]
    fn j_in_inspect_scrolls_detail_not_list() {
        let mut s = State::new();
        s.record(&req("a.com", 200, true));
        s.record(&req("b.com", 200, true));
        s.select_last();
        s.inspect = true;
        let before_sel = s.selected;
        press(&mut s, KeyCode::Char('j'), KeyModifiers::NONE);
        assert_eq!(s.detail_scroll, 1);
        assert_eq!(
            s.selected, before_sel,
            "selection must NOT move while inspecting"
        );
    }

    #[test]
    fn pgdn_scrolls_detail_when_inspecting() {
        let mut s = State::new();
        s.record(&req("a.com", 200, true));
        s.select_last();
        s.inspect = true;
        press(&mut s, KeyCode::PageDown, KeyModifiers::NONE);
        assert_eq!(s.detail_scroll, 10);
    }

    #[test]
    fn end_outside_inspect_engages_follow() {
        let mut s = State::new();
        s.record(&req("a.com", 200, true));
        s.follow = false;
        press(&mut s, KeyCode::End, KeyModifiers::NONE);
        assert!(s.follow);
    }

    #[test]
    fn five_switches_to_intercept_tab() {
        let mut s = State::new();
        press(&mut s, KeyCode::Char('5'), KeyModifiers::NONE);
        assert_eq!(s.tab, Tab::Intercept);
    }

    #[test]
    fn i_toggles_intercept_mode_and_jumps_to_tab_when_enabling() {
        // Reset known state so the toggle direction is deterministic.
        crate::intercept::set_intercept_mode(false);
        let mut s = State::new();
        assert_eq!(s.tab, Tab::Flow);
        press(&mut s, KeyCode::Char('i'), KeyModifiers::NONE);
        assert!(crate::intercept::intercept_mode_enabled());
        assert_eq!(s.tab, Tab::Intercept, "enabling intercept jumps to the tab");
        press(&mut s, KeyCode::Char('i'), KeyModifiers::NONE);
        assert!(!crate::intercept::intercept_mode_enabled());
        // Reset for any later test.
        crate::intercept::set_intercept_mode(false);
    }

    #[test]
    fn r_on_intercept_tab_does_not_reset_counters() {
        let mut s = State::new();
        // Force the unguarded reset arm NOT to fire from the
        // Intercept tab — total must stay 0 after r.
        s.tab = Tab::Intercept;
        s.total = 7;
        press(&mut s, KeyCode::Char('r'), KeyModifiers::NONE);
        assert_eq!(s.total, 7, "r on Intercept must not run reset_counters");
    }

    #[test]
    fn ctrl_c_in_filter_edit_cancels_not_quits() {
        let mut s = State::new();
        s.enter_filter_edit();
        s.filter_push('a');
        let mut q: Option<oneshot::Sender<()>> = None;
        let exit = handle_key(&mut s, KeyCode::Char('c'), KeyModifiers::CONTROL, &mut q);
        assert!(!exit);
        assert_eq!(s.input_mode, InputMode::Normal);
    }
}
