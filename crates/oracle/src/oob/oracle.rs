//! Out-of-band confirmation oracle.
//!
//! Wraps an `OobProviderTrait` (Interactsh / Burp Collaborator / custom)
//! with the polling loop that confirms whether an embedded canary fired.
//! This is the bridge between "we sent payload X and got 200" and "the
//! payload actually executed server-side."
//!
//! # Confirmation loop
//!
//! 1. `register()` against the provider → `OobCanary { expected_dns,
//!    expected_http_path }`.
//! 2. Caller embeds the canary into the payload via
//!    `oracle::oob::embed::embed_canary` and sends it.
//! 3. `confirm()` polls the provider every `poll_interval_secs` until
//!    one of:
//!       - any `OobInteraction` arrives → `Confirmed`
//!       - `timeout_secs` elapses → `Timeout`
//!       - the provider errors → `Error`
//!
//! `confirm_background()` returns immediately with a `Receiver` that
//! gets one message when the polling loop terminates — for the
//! pentester running scan in parallel.

use crate::oob::provider::{OobError, OobProviderTrait};
use std::sync::Arc;
use std::time::Duration;
use wafrift_types::oob::{OobCanary, OobConfig, OobConfirmation};

pub struct OobOracle {
    /// `Arc` rather than `Box` so `confirm_background` can clone a
    /// handle into the polling task — otherwise the spawned future
    /// couldn't outlive the `&self` borrow.
    provider: Arc<dyn OobProviderTrait>,
    config: OobConfig,
}

impl OobOracle {
    pub fn new(provider: Box<dyn OobProviderTrait>, config: OobConfig) -> Self {
        Self {
            provider: Arc::from(provider),
            config,
        }
    }

    /// Register a canary, then poll until the provider sees an
    /// interaction or the configured timeout elapses.
    ///
    /// `payload` and `payload_type` are accepted for API symmetry with
    /// `confirm_background` — the actual embedding lives in
    /// `crate::oob::embed::embed_canary`. This function only owns the
    /// polling lifecycle.
    pub async fn confirm(
        &self,
        _payload: &str,
        _payload_type: &str,
    ) -> Result<OobConfirmation, OobError> {
        let canary = self.provider.register().await?;
        let deadline = std::time::Instant::now() + Duration::from_secs(self.config.timeout_secs);
        let interval = Duration::from_secs(self.config.poll_interval_secs.max(1));
        loop {
            match self.provider.poll(&canary).await {
                Ok(interactions) if !interactions.is_empty() => {
                    return Ok(OobConfirmation::Confirmed);
                }
                Ok(_) => {} // empty → keep polling
                // F93: was `Err(_) => Ok(OobConfirmation::Error)`,
                // which silently converted a transport failure into
                // a scan result. Callers that only check the
                // `Confirmed` variant could never tell the oracle
                // was dead the entire run. Propagate the typed
                // error so the caller can distinguish
                // "oracle broken" from "no interaction observed".
                Err(e) => return Err(e),
            }
            if std::time::Instant::now() >= deadline {
                return Ok(OobConfirmation::Timeout);
            }
            tokio::time::sleep(interval).await;
        }
    }

    /// Register the canary, return it immediately along with a
    /// `Receiver` that will yield the eventual confirmation outcome.
    /// The polling loop runs as a background tokio task.
    ///
    /// Caller is expected to embed the returned `OobCanary` into their
    /// payload (via `embed::embed_canary`) BEFORE awaiting the receiver
    /// — otherwise the canary will time out.
    pub async fn confirm_background(
        &self,
    ) -> Result<(OobCanary, tokio::sync::mpsc::Receiver<OobConfirmation>), OobError> {
        let canary = self.provider.register().await?;
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        // Spawn the polling loop on tokio so this function returns
        // IMMEDIATELY with the canary. Pre-fix the loop ran inline
        // on the caller's task and blocked for the full timeout
        // before yielding — any caller that embedded the canary
        // AFTER receiving (canary, rx) was guaranteed to time out
        // because the polling window had already elapsed. The
        // Arc-stored provider is cheap to clone into the task.
        let provider = Arc::clone(&self.provider);
        let canary_for_task = canary.clone();
        let timeout = self.config.timeout_secs;
        let interval_secs = self.config.poll_interval_secs.max(1);
        tokio::spawn(async move {
            let outcome =
                poll_until(provider.as_ref(), &canary_for_task, timeout, interval_secs).await;
            // Receiver may have been dropped — that's the caller's
            // choice (e.g. scan completed early). Silently swallow
            // the send error; the poll loop has done its job.
            let _ = tx.send(outcome).await;
        });
        Ok((canary, rx))
    }
}

async fn poll_until(
    provider: &dyn OobProviderTrait,
    canary: &OobCanary,
    timeout_secs: u64,
    interval_secs: u64,
) -> OobConfirmation {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    let interval = Duration::from_secs(interval_secs.max(1));
    loop {
        match provider.poll(canary).await {
            Ok(ints) if !ints.is_empty() => return OobConfirmation::Confirmed,
            Ok(_) => {}
            // F93 sibling: the background-poll path still has to
            // return an `OobConfirmation` (it owns its channel), so
            // it can't propagate `OobError` like `confirm()` does.
            // Keep the `Error` variant here, but `confirm()` —
            // which CAN signal failure to the caller — should.
            Err(_) => return OobConfirmation::Error,
        }
        if std::time::Instant::now() >= deadline {
            return OobConfirmation::Timeout;
        }
        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use uuid::Uuid;
    use wafrift_types::oob::{OobInteraction, OobProvider};

    /// Test provider: returns a canary on register, then either always
    /// reports an interaction (if `confirm_after_n_polls == 0`), or
    /// reports nothing for the first N polls then reports one interaction.
    #[derive(Debug)]
    struct FakeProvider {
        polls: AtomicUsize,
        confirm_after: usize,
    }

    #[async_trait]
    impl OobProviderTrait for FakeProvider {
        async fn register(&self) -> Result<OobCanary, OobError> {
            Ok(OobCanary {
                id: Uuid::nil(),
                expected_dns: "abc.fake.oast".into(),
                expected_http_path: "/abc".into(),
                created_at: None,
            })
        }
        async fn poll(&self, _canary: &OobCanary) -> Result<Vec<OobInteraction>, OobError> {
            let n = self.polls.fetch_add(1, Ordering::Relaxed);
            if n >= self.confirm_after {
                Ok(vec![OobInteraction::DnsQuery {
                    query: "abc.fake.oast".into(),
                    source_ip: "203.0.113.10".into(),
                }])
            } else {
                Ok(Vec::new())
            }
        }
    }

    fn fast_config() -> OobConfig {
        OobConfig {
            provider: OobProvider::Interactsh {
                server: "test".into(),
            },
            poll_interval_secs: 1,
            timeout_secs: 5,
        }
    }

    #[tokio::test]
    async fn confirm_returns_confirmed_on_first_interaction() {
        let provider = Box::new(FakeProvider {
            polls: AtomicUsize::new(0),
            confirm_after: 0, // immediate
        });
        let oracle = OobOracle::new(provider, fast_config());
        let result = oracle.confirm("' OR 1=1--", "Sql").await.unwrap();
        assert_eq!(result, OobConfirmation::Confirmed);
    }

    #[tokio::test]
    async fn confirm_times_out_when_no_interaction() {
        let provider = Box::new(FakeProvider {
            polls: AtomicUsize::new(0),
            confirm_after: 100, // never within 5s timeout @ 1s interval
        });
        let oracle = OobOracle::new(
            provider,
            OobConfig {
                provider: OobProvider::Interactsh {
                    server: "test".into(),
                },
                poll_interval_secs: 1,
                timeout_secs: 2, // short for test speed
            },
        );
        let result = oracle.confirm("benign", "Sql").await.unwrap();
        assert_eq!(result, OobConfirmation::Timeout);
    }

    #[tokio::test]
    async fn confirm_background_returns_canary_and_outcome() {
        let provider = Box::new(FakeProvider {
            polls: AtomicUsize::new(0),
            confirm_after: 0,
        });
        let oracle = OobOracle::new(provider, fast_config());
        let (canary, mut rx) = oracle.confirm_background().await.unwrap();
        assert_eq!(canary.expected_dns, "abc.fake.oast");
        let outcome = rx.recv().await.unwrap();
        assert_eq!(outcome, OobConfirmation::Confirmed);
    }

    #[tokio::test]
    async fn confirm_background_returns_before_polling_completes() {
        // Regression for F43: pre-fix the function blocked the
        // caller for the full timeout window inline before yielding
        // the canary. Caller-supplied embedding could never run in
        // time → guaranteed Timeout. Post-fix the canary returns
        // immediately, polling runs on a spawned task. We measure
        // wall-clock to prove it.
        let provider = Box::new(FakeProvider {
            polls: AtomicUsize::new(0),
            confirm_after: 100, // won't fire within the test window
        });
        let oracle = OobOracle::new(
            provider,
            OobConfig {
                provider: OobProvider::Interactsh {
                    server: "test".into(),
                },
                poll_interval_secs: 1,
                timeout_secs: 30, // long, so a sync impl would block ~30s
            },
        );
        let start = std::time::Instant::now();
        let (_canary, _rx) = oracle.confirm_background().await.unwrap();
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(500),
            "confirm_background must return immediately (background poll) — \
             took {elapsed:?} which suggests inline blocking"
        );
        // Don't await the receiver — we proved the return-fast contract.
    }

    /// Atomic counters threaded through Arc keep the provider alive
    /// across multiple poll calls without losing state.
    #[tokio::test]
    async fn poll_counter_advances() {
        let provider_arc = Arc::new(FakeProvider {
            polls: AtomicUsize::new(0),
            confirm_after: 2,
        });
        // Wrap in another box that delegates to the Arc.
        struct ArcProvider(Arc<FakeProvider>);
        #[async_trait]
        impl OobProviderTrait for ArcProvider {
            async fn register(&self) -> Result<OobCanary, OobError> {
                self.0.register().await
            }
            async fn poll(&self, c: &OobCanary) -> Result<Vec<OobInteraction>, OobError> {
                self.0.poll(c).await
            }
        }
        impl std::fmt::Debug for ArcProvider {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }
        let oracle = OobOracle::new(Box::new(ArcProvider(provider_arc.clone())), fast_config());
        let result = oracle.confirm("x", "Sql").await.unwrap();
        assert_eq!(result, OobConfirmation::Confirmed);
        assert!(provider_arc.polls.load(Ordering::Relaxed) >= 3);
    }
}
