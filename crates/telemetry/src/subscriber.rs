//! tracing subscriber integration.
//!
//! Installs a layered subscriber that:
//! 1. Formats and writes to stderr (standard wafrift behaviour).
//! 2. Converts tracing events into CampaignTick entries on the telemetry
//!    queue so existing tracing::info!() call sites flow through without
//!    modification.
//!
//! If a subscriber is already installed (e.g. in tests) this function is a
//! no-op — it does not panic.

use std::sync::Arc;

use crossbeam_queue::SegQueue;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::{config::TelemetryConfig, event::Event};

/// Install the telemetry tracing subscriber.
///
/// Safe to call multiple times: subsequent calls after the global default is
/// set are silently ignored.
pub fn install(config: TelemetryConfig, queue: Arc<SegQueue<Event>>) {
    if !config.install_tracing_layer {
        return;
    }

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let fmt_layer = fmt::layer()
        .with_target(true)
        .with_writer(std::io::stderr);

    let telemetry_layer = TelemetryTracingLayer { queue };

    // try_init is a no-op if a subscriber is already installed.
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .with(telemetry_layer)
        .try_init();
}

struct TelemetryTracingLayer {
    queue: Arc<SegQueue<Event>>,
}

impl<S> tracing_subscriber::Layer<S> for TelemetryTracingLayer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        _event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        self.queue.push(Event::CampaignTick);
    }
}
