//! Background drain task.
//!
//! Drains the SegQueue of Events and forwards each one to every
//! enabled backend.  Runs as a tokio::spawn loop; exits when the owning
//! Telemetry handle is dropped.

use std::{sync::Arc, time::Duration};

use crossbeam_queue::SegQueue;
use tracing::warn;

use crate::{config::TelemetryConfig, event::Event};

#[cfg(feature = "backend-jsonl")]
use std::{fs::OpenOptions, io::Write};

pub struct DrainTask;

impl DrainTask {
    /// Spawn the background drain loop.
    ///
    /// Holds a weak reference to the queue and exits cleanly once the owning
    /// Telemetry is dropped.
    pub fn spawn(queue: Arc<SegQueue<Event>>, config: TelemetryConfig) {
        let weak = Arc::downgrade(&queue);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(50)).await;
                let q = match weak.upgrade() {
                    Some(q) => q,
                    None => break,
                };
                let mut batch: Vec<Event> = Vec::with_capacity(64);
                for _ in 0..1_000 {
                    match q.pop() {
                        Some(e) => batch.push(e),
                        None => break,
                    }
                }
                if batch.is_empty() { continue; }
                for event in &batch {
                    #[cfg(feature = "backend-stdout")]
                    if config.stdout_enabled {
                        stdout_emit(event);
                    }
                    #[cfg(feature = "backend-jsonl")]
                    if config.jsonl_enabled {
                        jsonl_emit(event, &config);
                    }
                }
            }
        });
    }
}

#[cfg(feature = "backend-stdout")]
fn stdout_emit(event: &Event) {
    tracing::info!(telemetry = true, event = ?event, "wafrift-telemetry");
}

#[cfg(feature = "backend-jsonl")]
fn jsonl_emit(event: &Event, config: &TelemetryConfig) {
    let line = match serde_json::to_string(event) {
        Ok(l) => l,
        Err(e) => { warn!("wafrift-telemetry: JSONL serialize failed: {e}"); return; }
    };
    let mut file = match OpenOptions::new().create(true).append(true).open(&config.jsonl_path) {
        Ok(f) => f,
        Err(e) => { warn!("wafrift-telemetry: JSONL open {:?} failed: {e}", config.jsonl_path); return; }
    };
    if let Err(e) = writeln!(file, "{line}") {
        warn!("wafrift-telemetry: JSONL write failed: {e}");
    }
}
