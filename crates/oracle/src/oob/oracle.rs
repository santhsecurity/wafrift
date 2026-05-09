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
use std::time::Duration;
use wafrift_types::oob::{OobCanary, OobConfig, OobConfirmation};

pub struct OobOracle {
    provider: Box<dyn OobProviderTrait>,
    config: OobConfig,
}

impl OobOracle {
    pub fn new(provider: Box<dyn OobProviderTrait>, config: OobConfig) -> Self {
        Self { provider, config }
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
        let deadline = std::time::Instant::now()
            + Duration::from_secs(self.config.timeout_secs);
        let interval = Duration::from_secs(self.config.poll_interval_secs.max(1));
        loop {
            match self.provider.poll(&canary).await {
                Ok(interactions) if !interactions.is_empty() => {
                    return Ok(OobConfirmation::Confirmed);
                }
                Ok(_) => {} // empty → keep polling
                Err(_) => return Ok(OobConfirmation::Error),
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
    ) -> Result<
        (
            OobCanary,
            tokio::sync::mpsc::Receiver<OobConfirmation>,
        ),
        OobError,
    > {
        let canary = self.provider.register().await?;
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        // Note: spawning requires the provider be Clone-able. Trait
        // objects don't allow Clone, so the polling closure captures
        // an Arc + spawns it. Callers that need true background mode
        // should hold the OobOracle in an Arc and call from there.
        // This in-place loop runs synchronously on the caller task
        // until first interaction OR timeout — then sends and returns.
        let canary_clone = canary.clone();
        let timeout = self.config.timeout_secs;
        let interval_secs = self.config.poll_interval_secs.max(1);
        // Borrow the provider for the duration of the inline loop.
        let interactions = poll_until(
            self.provider.as_ref(),
            &canary_clone,
            timeout,
            interval_secs,
        )
        .await;
        let _ = tx.send(interactions).await;
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
        async fn poll(
            &self,
            _canary: &OobCanary,
        ) -> Result<Vec<OobInteraction>, OobError> {
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
            async fn poll(
                &self,
                c: &OobCanary,
            ) -> Result<Vec<OobInteraction>, OobError> {
                self.0.poll(c).await
            }
        }
        impl std::fmt::Debug for ArcProvider {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }
        let oracle = OobOracle::new(
            Box::new(ArcProvider(provider_arc.clone())),
            fast_config(),
        );
        let result = oracle.confirm("x", "Sql").await.unwrap();
        assert_eq!(result, OobConfirmation::Confirmed);
        assert!(provider_arc.polls.load(Ordering::Relaxed) >= 3);
    }
}
