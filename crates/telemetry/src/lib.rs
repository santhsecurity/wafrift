//! wafrift-telemetry — central observability layer for the wafrift WAF-evasion engine.
//!
//! Architecture:
//!
//!   tracing::info!()  ->  TelemetryLayer (Subscriber)  ->  stderr
//!   Telemetry::record_event()  ->  SegQueue  ->  drain task  ->  stdout / JSONL
//!   Telemetry::counter/gauge/histogram  ->  Prometheus /metrics
//!
//! Usage:
//!
//!   let tel = Telemetry::init(TelemetryConfig::default()).await.unwrap();
//!   tel.record_event(Event::ProbeSent);
//!   tel.counter("probes_sent").inc();

pub mod backends;
pub mod config;
pub mod event;
pub mod metrics;
pub mod subscriber;

pub use config::TelemetryConfig;
pub use event::Event;
pub use metrics::{Counter, Gauge, Histogram};

use std::sync::Arc;

use backends::drain::DrainTask;
use crossbeam_queue::SegQueue;

/// Cheap-to-clone handle to the telemetry subsystem (Arc<Inner> inside).
#[derive(Clone)]
pub struct Telemetry {
    inner: Arc<Inner>,
}

struct Inner {
    config: TelemetryConfig,
    queue: Arc<SegQueue<Event>>,
    registry: Arc<metrics::Registry>,
}

#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    #[error("failed to create JSONL output directory: {0}")]
    Io(#[from] std::io::Error),

    #[cfg(feature = "backend-prometheus")]
    #[error("failed to bind Prometheus HTTP server: {0}")]
    PrometheusBind(String),
}

impl Telemetry {
    /// Initialise the telemetry subsystem. Call once from main().
    pub async fn init(config: TelemetryConfig) -> Result<Self, TelemetryError> {
        let queue = Arc::new(SegQueue::new());
        let registry = Arc::new(metrics::Registry::new());

        subscriber::install(config.clone(), Arc::clone(&queue));

        #[cfg(feature = "backend-jsonl")]
        if config.jsonl_enabled {
            if let Some(parent) = config.jsonl_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
        }

        #[cfg(feature = "backend-prometheus")]
        if config.prometheus_enabled {
            backends::prometheus::start_server(config.prometheus_addr, Arc::clone(&registry))
                .await
                .map_err(TelemetryError::PrometheusBind)?;
        }

        let tel = Self {
            inner: Arc::new(Inner { config, queue, registry }),
        };

        DrainTask::spawn(Arc::clone(&tel.inner.queue), tel.inner.config.clone());
        Ok(tel)
    }

    /// Record an Event. Non-blocking, infallible, <1 us on the hot path.
    #[inline]
    pub fn record_event(&self, event: Event) {
        self.inner.queue.push(event);
    }

    /// Return (or create) a named Counter.
    pub fn counter(&self, name: &str) -> Counter {
        self.inner.registry.counter(name)
    }

    /// Return (or create) a named Gauge.
    pub fn gauge(&self, name: &str) -> Gauge {
        self.inner.registry.gauge(name)
    }

    /// Return (or create) a named Histogram.
    pub fn histogram(&self, name: &str) -> Histogram {
        self.inner.registry.histogram(name)
    }

    /// Render all metrics in Prometheus text exposition format.
    pub fn export_prometheus(&self) -> String {
        self.inner.registry.export_prometheus()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> TelemetryConfig {
        TelemetryConfig {
            stdout_enabled: false,
            jsonl_enabled: false,
            prometheus_enabled: false,
            install_tracing_layer: false,
            ..TelemetryConfig::default()
        }
    }

    // 1. record_event does not block or panic
    #[tokio::test]
    async fn test_record_event_noop() {
        let tel = Telemetry::init(test_config()).await.unwrap();
        for _ in 0..1_000 {
            tel.record_event(Event::ProbeSent);
        }
    }

    // 2. Counter increment
    #[tokio::test]
    async fn test_counter_increment() {
        let tel = Telemetry::init(test_config()).await.unwrap();
        let c = tel.counter("test_counter");
        assert_eq!(c.get(), 0);
        c.inc();
        c.inc();
        c.add(8);
        assert_eq!(c.get(), 10);
    }

    // 3. Histogram observation
    #[tokio::test]
    async fn test_histogram_observation() {
        let tel = Telemetry::init(test_config()).await.unwrap();
        let h = tel.histogram("latency_us");
        h.observe(100.0);
        h.observe(200.0);
        h.observe(300.0);
        let snap = h.snapshot();
        assert_eq!(snap.count, 3);
        assert!((snap.sum - 600.0).abs() < 0.01, "sum={}", snap.sum);
        assert!((snap.min - 100.0).abs() < 0.01, "min={}", snap.min);
        assert!((snap.max - 300.0).abs() < 0.01, "max={}", snap.max);
    }

    // 4. JSONL serialisation round-trip
    #[test]
    fn test_event_jsonl_roundtrip() {
        let events = vec![
            Event::ProbeSent,
            Event::ProbeBlocked,
            Event::BypassFound { rule_id: "SQLI-42".to_string(), oracle_valid: true },
            Event::WafProfileChanged,
            Event::RateLimitHit { egress: "192.168.1.1".to_string() },
            Event::PayloadMutated { strategy: "hex-encode".to_string() },
            Event::CampaignTick,
        ];
        for event in &events {
            let json = serde_json::to_string(event).expect("serialize");
            let back: Event = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(
                serde_json::to_string(&back).unwrap(),
                serde_json::to_string(event).unwrap(),
                "round-trip mismatch: {json}",
            );
        }
    }

    // 5. Prometheus export format
    #[tokio::test]
    async fn test_prometheus_export() {
        let tel = Telemetry::init(test_config()).await.unwrap();
        tel.counter("http_requests_total").add(42);
        tel.gauge("active_connections").set(7.0);
        tel.histogram("response_time_ms").observe(55.0);

        let output = tel.export_prometheus();

        assert!(output.contains("http_requests_total 42"), "counter missing:
{output}");
        assert!(output.contains("active_connections 7"), "gauge missing:
{output}");
        assert!(output.contains("response_time_ms_count 1"), "hist count missing:
{output}");
        assert!(output.contains("response_time_ms_sum 55"), "hist sum missing:
{output}");
    }
}
