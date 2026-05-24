//! Operator-driven intercept queue: pause every forward, surface it
//! in the TUI, let the operator release / kill before upstream sees
//! anything.
//!
//! Closes blocker #119. The queue is process-scoped via an
//! [`InterceptStore`] held behind an `Arc<Mutex<>>` so the proxy
//! request handler and the TUI render+keymap layers see the same
//! state.
//!
//! Locking discipline:
//! - Both register and release/kill take the write lock briefly,
//!   never across an `await` that performs I/O.
//! - The waiting future does NOT hold the lock — it parks on a
//!   per-request `tokio::sync::oneshot` instead.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tokio::sync::oneshot;

/// Process-wide intercept-mode flag. Toggleable from the TUI keymap.
/// When `true`, every proxy forward parks on the global
/// [`InterceptStore`] until an operator action.
static INTERCEPT_MODE: AtomicBool = AtomicBool::new(false);

/// Process-wide pending-intercept queue. Lazily initialised so the
/// proxy and TUI see the same state.
static INTERCEPT_STORE: OnceLock<InterceptStore> = OnceLock::new();

/// Read intercept-mode atomically. Cheap.
#[must_use]
pub fn intercept_mode_enabled() -> bool {
    INTERCEPT_MODE.load(Ordering::Relaxed)
}

/// Serializes the (flip, drain) pair in toggle/set so two concurrent
/// toggles can't interleave such that the drain runs while another
/// thread has already flipped intercept back ON. Without this guard
/// the audit's `test_concurrent_toggle_race` reproduced the
/// spurious-release bug.
static MODE_TRANSITION: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Toggle intercept-mode and return the new value. When toggling
/// OFF, drains every pending intercept with `Release` so existing
/// requests don't wedge.
pub fn toggle_intercept_mode() -> bool {
    // Hold MODE_TRANSITION across the entire (read-modify-drain)
    // sequence — the atomic alone isn't enough because the drain is
    // a separate observation of the store. Closes the TOCTOU window
    // identified by the 2026-05-10 audit.
    let _guard = MODE_TRANSITION
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let prev = INTERCEPT_MODE.fetch_xor(true, Ordering::Relaxed);
    let now_on = !prev;
    if !now_on {
        let _ = global_store().drain_release();
    }
    now_on
}

/// Force intercept-mode to a specific value (test / programmatic
/// override). Drains pending on transition to OFF.
pub fn set_intercept_mode(on: bool) {
    let _guard = MODE_TRANSITION
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let prev = INTERCEPT_MODE.swap(on, Ordering::Relaxed);
    if prev && !on {
        let _ = global_store().drain_release();
    }
}

/// Get the process-wide intercept store, initialising it on first
/// access.
pub fn global_store() -> &'static InterceptStore {
    INTERCEPT_STORE.get_or_init(InterceptStore::new)
}

/// Decision the operator (or the timeout fallback) returns to the
/// blocked request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptDecision {
    /// Forward the request unmodified.
    Release,
    /// Return a synthetic 403 to the client; never hits upstream.
    Kill,
}

/// One pending intercept the TUI shows + the operator acts on.
#[derive(Debug, Clone)]
pub struct PendingIntercept {
    pub id: u64,
    pub host: String,
    pub method: String,
    pub path: String,
    /// When the request was registered.
    pub since: Instant,
}

/// Shared per-process intercept store.
#[derive(Debug, Default, Clone)]
pub struct InterceptStore {
    inner: Arc<Mutex<InterceptInner>>,
}

#[derive(Debug)]
struct InterceptInner {
    /// Per-request rendezvous sender. Removed when the operator
    /// resolves the intercept (release/kill) or when a timeout fires.
    senders: BTreeMap<u64, oneshot::Sender<InterceptDecision>>,
    /// Snapshot of the same set the TUI iterates for display.
    pending: BTreeMap<u64, PendingIntercept>,
    /// Monotonic ID generator. Starts at 0 so the first `register`
    /// call's `wrapping_add(1)` yields id=1 — id=0 is RESERVED as
    /// an "invalid intercept" sentinel. `resolve(0, ...)` and
    /// `cancel(0, ...)` silently return false, so callers must
    /// never pass 0 expecting it to map to a real intercept.
    next_id: u64,
}

impl Default for InterceptInner {
    fn default() -> Self {
        Self {
            senders: BTreeMap::new(),
            pending: BTreeMap::new(),
            next_id: 0,
        }
    }
}

/// Default intercept timeout — after which the request defaults
/// to `Release` so the proxy never wedges if the operator walks
/// away.
pub const INTERCEPT_TIMEOUT: Duration = Duration::from_secs(30);

impl InterceptStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a fresh intercept and return the receiver the request
    /// handler should await on, plus the assigned ID.
    ///
    /// Each call also opportunistically GCs any senders whose receiver
    /// has been dropped — this catches the client-disconnect path where
    /// neither `resolve` nor the timeout's `cancel` fires (the request
    /// future is cancelled before either arm of `tokio::select!` runs).
    /// Without the GC the entries leak forever in `senders` + `pending`.
    pub fn register(
        &self,
        host: impl Into<String>,
        method: impl Into<String>,
        path: impl Into<String>,
    ) -> (u64, oneshot::Receiver<InterceptDecision>) {
        let (tx, rx) = oneshot::channel();
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // GC closed senders (client-disconnect leak).
        let dead: Vec<u64> = inner
            .senders
            .iter()
            .filter(|(_, tx)| tx.is_closed())
            .map(|(id, _)| *id)
            .collect();
        for id in dead {
            inner.senders.remove(&id);
            inner.pending.remove(&id);
        }
        inner.next_id = inner.next_id.wrapping_add(1);
        let id = inner.next_id;
        inner.senders.insert(id, tx);
        inner.pending.insert(
            id,
            PendingIntercept {
                id,
                host: host.into(),
                method: method.into(),
                path: path.into(),
                since: Instant::now(),
            },
        );
        (id, rx)
    }

    /// Drop entries whose oneshot rx has been dropped. Exposed for
    /// tests + the TUI render loop, which can call this periodically
    /// even when no new intercepts are arriving.
    pub fn gc_dead_senders(&self) -> usize {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dead: Vec<u64> = inner
            .senders
            .iter()
            .filter(|(_, tx)| tx.is_closed())
            .map(|(id, _)| *id)
            .collect();
        let n = dead.len();
        for id in dead {
            inner.senders.remove(&id);
            inner.pending.remove(&id);
        }
        n
    }

    /// Resolve a pending intercept with a decision. Idempotent — a
    /// second resolve for the same id is a no-op.
    pub fn resolve(&self, id: u64, decision: InterceptDecision) -> bool {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.pending.remove(&id);
        if let Some(tx) = inner.senders.remove(&id) {
            let _ = tx.send(decision);
            true
        } else {
            false
        }
    }

    /// Cancel a pending intercept WITHOUT sending a decision. The
    /// proxy calls this when the receiver is dropped (client
    /// disconnected, request timed out before the operator decided)
    /// so the sender + pending entry don't leak forever in the maps.
    /// Idempotent.
    ///
    /// Returns true if an entry was removed, false if no such id.
    pub fn cancel(&self, id: u64) -> bool {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let removed_pending = inner.pending.remove(&id).is_some();
        let removed_sender = inner.senders.remove(&id).is_some();
        removed_pending || removed_sender
    }

    /// Release every pending intercept with `Release`. Used when the
    /// operator toggles intercept-mode OFF — don't strand existing
    /// requests.
    pub fn drain_release(&self) -> usize {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let ids: Vec<u64> = inner.senders.keys().copied().collect();
        let mut released = 0;
        for id in ids {
            if let Some(tx) = inner.senders.remove(&id) {
                inner.pending.remove(&id);
                let _ = tx.send(InterceptDecision::Release);
                released += 1;
            }
        }
        released
    }

    /// Snapshot of the pending list for the TUI.
    pub fn snapshot(&self) -> Vec<PendingIntercept> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.pending.values().cloned().collect()
    }

    /// How many requests are currently parked in the rendezvous.
    pub fn pending_count(&self) -> usize {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> InterceptStore {
        InterceptStore::new()
    }

    #[tokio::test]
    async fn register_then_release_unblocks_with_release() {
        let s = store();
        let (id, rx) = s.register("h", "GET", "/");
        let s2 = s.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            s2.resolve(id, InterceptDecision::Release);
        });
        let decision = rx.await.expect("rx");
        assert_eq!(decision, InterceptDecision::Release);
        assert_eq!(s.pending_count(), 0, "pending must drain after resolve");
    }

    #[tokio::test]
    async fn register_then_kill_unblocks_with_kill() {
        let s = store();
        let (id, rx) = s.register("h", "POST", "/admin");
        let s2 = s.clone();
        tokio::spawn(async move {
            s2.resolve(id, InterceptDecision::Kill);
        });
        assert_eq!(rx.await.unwrap(), InterceptDecision::Kill);
    }

    #[tokio::test]
    async fn snapshot_shows_pending_until_resolved() {
        let s = store();
        let (id1, _r1) = s.register("a.com", "GET", "/x");
        let (id2, _r2) = s.register("b.com", "POST", "/y");
        let snap = s.snapshot();
        assert_eq!(snap.len(), 2);
        assert!(snap.iter().any(|p| p.id == id1 && p.host == "a.com"));
        assert!(snap.iter().any(|p| p.id == id2 && p.host == "b.com"));
    }

    #[tokio::test]
    async fn drain_release_unblocks_every_pending() {
        let s = store();
        let (_, rx1) = s.register("a", "GET", "/");
        let (_, rx2) = s.register("b", "GET", "/");
        let n = s.drain_release();
        assert_eq!(n, 2);
        assert_eq!(rx1.await.unwrap(), InterceptDecision::Release);
        assert_eq!(rx2.await.unwrap(), InterceptDecision::Release);
        assert_eq!(s.pending_count(), 0);
    }

    #[tokio::test]
    async fn resolve_unknown_id_is_idempotent_no_op() {
        let s = store();
        let acted = s.resolve(999, InterceptDecision::Release);
        assert!(!acted, "resolve of unknown id must report it didn't fire");
    }

    #[tokio::test]
    async fn resolve_twice_only_fires_once() {
        let s = store();
        let (id, rx) = s.register("h", "GET", "/");
        assert!(s.resolve(id, InterceptDecision::Release));
        assert!(
            !s.resolve(id, InterceptDecision::Kill),
            "second resolve must no-op"
        );
        assert_eq!(rx.await.unwrap(), InterceptDecision::Release);
    }

    #[tokio::test]
    async fn timeout_default_release_via_select() {
        // The proxy uses tokio::select! { _ = rx => …, _ = sleep(TIMEOUT) => Release }.
        // Verifies the receiver actually waits forever when no resolve fires.
        let s = store();
        let (_id, rx) = s.register("h", "GET", "/");
        let result = tokio::time::timeout(Duration::from_millis(50), rx).await;
        assert!(result.is_err(), "rx must NOT complete on its own");
    }

    #[tokio::test]
    async fn ids_are_monotonic_per_register() {
        let s = store();
        let (id1, _) = s.register("a", "GET", "/");
        let (id2, _) = s.register("a", "GET", "/");
        let (id3, _) = s.register("a", "GET", "/");
        assert_eq!(id2, id1 + 1);
        assert_eq!(id3, id2 + 1);
    }

    #[test]
    fn id_zero_is_reserved_and_resolve_cancel_return_false() {
        // Contract regression: id=0 is a reserved sentinel — no
        // register() call can ever assign it (the first call hands
        // back id=1). Caller mistakes that pass 0 must not match
        // any real intercept; both resolve and cancel return false.
        let s = store();
        // No intercepts registered yet.
        assert!(!s.resolve(0, InterceptDecision::Release));
        assert!(!s.cancel(0));
        // Register one — id is 1, never 0.
        let (id, _rx) = s.register("h", "GET", "/");
        assert_eq!(id, 1, "first id must be 1 (0 is reserved)");
        // 0 still returns false even with real intercepts present.
        assert!(!s.resolve(0, InterceptDecision::Release));
        assert!(!s.cancel(0));
    }
}
