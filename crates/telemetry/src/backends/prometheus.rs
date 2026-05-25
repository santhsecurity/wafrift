//! Prometheus HTTP backend (feature = backend-prometheus).

use std::{net::SocketAddr, sync::Arc};
use crate::metrics::Registry;

pub async fn start_server(addr: SocketAddr, registry: Arc<Registry>) -> Result<(), String> {
    let server = tiny_http::Server::http(addr)
        .map_err(|e| format!("bind {addr}: {e}"))?;
    let server = Arc::new(server);
    tokio::task::spawn_blocking(move || {
        for request in server.incoming_requests() {
            let body = registry.export_prometheus();
            let response = tiny_http::Response::from_string(body)
                .with_header(
                    "Content-Type: text/plain; version=0.0.4; charset=utf-8"
                        .parse::<tiny_http::Header>()
                        .expect("static header"),
                );
            let _ = request.respond(response);
        }
    });
    Ok(())
}
