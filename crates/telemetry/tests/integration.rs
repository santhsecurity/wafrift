//! Integration tests for wafrift-telemetry.
//!
//! These tests exercise the full Telemetry stack end-to-end, complementing
//! the unit tests in lib.rs.

use wafrift_telemetry::{Event, Telemetry, TelemetryConfig};

fn no_io_config() -> TelemetryConfig {
    TelemetryConfig {
        stdout_enabled: false,
        jsonl_enabled: false,
        prometheus_enabled: false,
        install_tracing_layer: false,
        ..TelemetryConfig::default()
    }
}

// 1. Multiple independent Telemetry handles share no state
#[tokio::test]
async fn test_independent_handles_isolated() {
    let t1 = Telemetry::init(no_io_config()).await.unwrap();
    let t2 = Telemetry::init(no_io_config()).await.unwrap();
    t1.counter("shared_name").add(10);
    t2.counter("shared_name").add(3);
    assert_eq!(t1.counter("shared_name").get(), 10, "t1 counter polluted by t2");
    assert_eq!(t2.counter("shared_name").get(), 3, "t2 counter polluted by t1");
}

// 2. Cloned Telemetry handle shares the same registry
#[tokio::test]
async fn test_clone_shares_registry() {
    let t1 = Telemetry::init(no_io_config()).await.unwrap();
    let t2 = t1.clone();
    t1.counter("cloned").inc();
    assert_eq!(t2.counter("cloned").get(), 1, "clone does not share counter");
}

// 3. Gauge inc/dec symmetry
#[tokio::test]
async fn test_gauge_symmetry() {
    let tel = Telemetry::init(no_io_config()).await.unwrap();
    let g = tel.gauge("backpressure");
    g.set(100.0);
    g.dec(40.0);
    g.inc(5.0);
    let v = g.get();
    assert!((v - 65.0).abs() < 0.01, "gauge={v}");
}

// 4. All Event variants serialize / deserialize without loss
#[test]
fn test_all_event_variants_serde() {
    let variants: Vec<Event> = vec![
        Event::ProbeSent,
        Event::ProbeBlocked,
        Event::BypassFound { rule_id: "RCE-01".into(), oracle_valid: false },
        Event::WafProfileChanged,
        Event::RateLimitHit { egress: "10.0.0.1".into() },
        Event::PayloadMutated { strategy: "unicode-fullwidth".into() },
        Event::CampaignTick,
    ];
    for v in &variants {
        let s = serde_json::to_string(v).unwrap();
        // Must contain the discriminant tag
        assert!(s.contains("type"), "missing type tag in: {s}");
        // Round-trip
        let back: Event = serde_json::from_str(&s).unwrap();
        assert_eq!(
            serde_json::to_string(&back).unwrap(),
            s,
            "round-trip failed for: {s}",
        );
    }
}

// 5. Prometheus output is valid text exposition format (basic checks)
#[tokio::test]
async fn test_prometheus_exposition_structure() {
    let tel = Telemetry::init(no_io_config()).await.unwrap();
    tel.counter("total_probes").add(100);
    tel.gauge("egress_slots").set(4.0);
    tel.histogram("probe_latency_ms").observe(12.5);
    tel.histogram("probe_latency_ms").observe(87.3);

    let prom = tel.export_prometheus();

    // Every metric must have a # HELP line
    for name in &["total_probes", "egress_slots", "probe_latency_ms"] {
        assert!(
            prom.contains(&format!("# HELP {name}")),
            "# HELP missing for {name}
{prom}",
        );
        assert!(
            prom.contains(&format!("# TYPE {name}")),
            "# TYPE missing for {name}
{prom}",
        );
    }

    // Histogram count should reflect two observations
    assert!(
        prom.contains("probe_latency_ms_count 2"),
        "hist count wrong:
{prom}",
    );
}
