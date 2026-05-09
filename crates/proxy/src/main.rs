//! WAF Rift Proxy — HTTP forward proxy with automatic WAF evasion.
//!
//! Point your browser or scanner at this proxy and all outbound traffic
//! is automatically transformed to bypass WAF rules. Per-host evasion
//! state is tracked so the proxy learns what works and escalates when
//! blocks are detected.

use clap::Parser;
use futures_util::StreamExt;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};
use tracing::{error, info, warn};

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};

use wafrift_proxy::hop_by_hop::{
    collect_connection_header_names, collect_connection_header_names_hyper,
    should_strip_proxy_header,
};
use wafrift_proxy::mitm::{CertificateAuthority, tls_server_name_from_authority};
use wafrift_proxy::upstream_policy::{
    UpstreamPolicy, assert_connect_target_allowed, assert_forward_url_allowed,
};
use wafrift_strategy::strategy::{evade, evade_smart};
use wafrift_strategy::{EvasionConfig, HostState};
use wafrift_transport::is_waf_block;

/// Maximum request body buffered per message (plain HTTP + MITM plaintext).
const MAX_PROXY_BODY_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone)]
struct ProxyLimits {
    max_upstream_response_bytes: usize,
    /// On a WAF block (403/406/etc.), retry the request with escalated
    /// evasion up to this many extra times. Default 0 (no retry).
    /// Each retry bumps the host's "blocks" counter so successive
    /// attempts use heavier evasion. The first non-blocked response
    /// wins; otherwise the last block is returned.
    max_evade_retries: u32,
}

/// CLI arguments for the proxy binary.
#[derive(Parser, Debug)]
#[command(name = "wafrift-proxy", about = "WAF Evasion Proxy")]
struct Args {
    /// Address to listen on (host:port).
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: String,

    /// Force escalation level: light, medium, heavy.
    #[arg(long)]
    escalation: Option<String>,

    /// Enable Content-Type switching.
    #[arg(long)]
    content_type_switching: bool,

    /// Enable browser fingerprint rotation.
    #[arg(long)]
    fingerprint_rotation: bool,

    /// Disable TLS verification.
    #[arg(long, default_value_t = false)]
    insecure: bool,

    /// Write a fresh MITM CA to this directory (`wafrift-mitm-ca.pem` + key) and exit.
    #[arg(long = "write-mitm-ca-dir")]
    write_mitm_ca_dir: Option<PathBuf>,

    /// Terminate TLS on CONNECT using a CA from `--mitm-ca-dir` (install CA in the client first).
    #[arg(long, default_value_t = false)]
    mitm: bool,

    /// Directory containing `wafrift-mitm-ca.pem` and `wafrift-mitm-ca-key.pem` (see `--write-mitm-ca-dir`).
    #[arg(long = "mitm-ca-dir")]
    mitm_ca_dir: Option<PathBuf>,

    /// Allow CONNECT/forward to private, loopback, and link-local targets (literal or DNS).
    #[arg(long, default_value_t = false)]
    allow_private_upstream: bool,

    /// Disable upstream destination checks (any host/IP). **Dangerous** if clients are untrusted.
    #[arg(long = "insecure-open-upstream", default_value_t = false)]
    insecure_open_upstream: bool,

    /// Maximum concurrent TCP connections (backpressure).
    #[arg(long, default_value_t = 4096)]
    max_concurrent_connections: usize,

    /// Maximum bytes buffered per upstream HTTP response body.
    #[arg(long, default_value_t = 33554432)]
    max_upstream_response_bytes: usize,

    /// On a WAF block (HTTP 403/406 or matching block body), retry the
    /// same request with escalated evasion this many times before giving
    /// up. Default 0 = current behavior (one attempt, return whatever
    /// the WAF says). With N>0, the proxy mimics the bench behavior:
    /// keep trying different evade strategies until one lands or the
    /// budget is exhausted. The successful technique is recorded in
    /// the host's gene bank so subsequent requests rotate it directly.
    #[arg(long, default_value_t = 0)]
    max_evade_retries: u32,
}

type SharedState = Arc<Mutex<ProxyState>>;

/// Mutable proxy state shared across connections.
#[derive(Default)]
struct ProxyState {
    /// Per-host evasion state.
    hosts: HashMap<String, HostState>,
    /// Total requests proxied.
    total_scanned: u32,
    /// Total WAF blocks observed.
    total_blocks: u32,
    /// Technique usage counts.
    techniques_used: HashMap<String, u32>,
}

use wafrift_proxy::extract_host_from_header;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let mut args = Args::parse();

    if let Some(dir) = &args.write_mitm_ca_dir {
        let ca = CertificateAuthority::generate()?;
        ca.write_to_dir(dir)?;
        info!(
            "Wrote MITM CA to {} — install {} in your client, then run with --mitm --mitm-ca-dir ...",
            dir.display(),
            dir.join("wafrift-mitm-ca.pem").display()
        );
        println!(
            "MITM CA written to:\n  {}\n  {}\n\nTrust the CA in your OS or browser, then:\n  wafrift-proxy --mitm --mitm-ca-dir {}",
            dir.join("wafrift-mitm-ca.pem").display(),
            dir.join("wafrift-mitm-ca-key.pem").display(),
            dir.display()
        );
        return Ok(());
    }

    if args.mitm && args.mitm_ca_dir.is_none() {
        // Auto-generate CA to default directory.
        let default_dir = wafrift_proxy::mitm::default_mitm_ca_dir()
            .ok_or_else(|| {
                error!("cannot determine home directory for MITM CA storage");
                std::process::exit(1);
            })
            .unwrap();
        info!(
            "No --mitm-ca-dir specified; using default: {}",
            default_dir.display()
        );
        args.mitm_ca_dir = Some(default_dir);
    }

    let mitm_ca: Option<Arc<CertificateAuthority>> = if args.mitm {
        let dir = args.mitm_ca_dir.as_ref().unwrap();
        let ca = wafrift_proxy::mitm::ensure_ca(dir)?;

        // Attempt OS trust store installation.
        let cert_path = dir.join("wafrift-mitm-ca.pem");
        match wafrift_proxy::mitm::install_ca_trust(&cert_path) {
            wafrift_proxy::mitm::TrustResult::Installed { method } => {
                info!("MITM CA auto-trusted via {method}");
            }
            wafrift_proxy::mitm::TrustResult::ManualRequired { instructions } => {
                println!("\n{instructions}\n");
                info!("CA generated at: {}", cert_path.display());
            }
            wafrift_proxy::mitm::TrustResult::Failed {
                error,
                instructions,
            } => {
                warn!("Auto-trust failed: {error}");
                println!("\n{instructions}\n");
            }
        }

        Some(Arc::new(ca))
    } else {
        None
    };

    if args.max_concurrent_connections == 0 {
        error!("--max-concurrent-connections must be >= 1");
        std::process::exit(1);
    }
    if args.max_upstream_response_bytes < 4096 {
        error!("--max-upstream-response-bytes must be >= 4096");
        std::process::exit(1);
    }

    let addr: SocketAddr = args.listen.parse().unwrap_or_else(|e| {
        error!("Invalid listen address '{}': {}", args.listen, e);
        std::process::exit(1);
    });

    let listener = TcpListener::bind(addr).await.unwrap_or_else(|e| {
        error!("Failed to bind to {addr}: {e}");
        std::process::exit(1);
    });
    info!("Listening on http://{}", addr);
    let expose_wafrift_status = addr.ip().is_loopback();
    if !expose_wafrift_status {
        info!("/_wafrift/status disabled (bind address is not loopback-only)");
    }

    let mut config = EvasionConfig::default();
    if args.content_type_switching {
        config.content_type_switching = true;
    }
    if args.fingerprint_rotation {
        config.fingerprint_rotation = true;
    }
    if args.insecure {
        config.insecure_tls = true;
    }

    let shared_state = Arc::new(Mutex::new(ProxyState::default()));
    let config = Arc::new(config);
    let default_escalation = args.escalation.clone();
    let mitm_enabled = args.mitm;

    // S1, S2 fix: Create a single global client with timeout and TLS rules
    let global_client = reqwest::Client::builder()
        .danger_accept_invalid_certs(config.insecure_tls)
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_else(|e| {
            error!("reqwest client build failed: {e}");
            std::process::exit(1);
        });

    let policy = Arc::new(UpstreamPolicy {
        allow_private_upstream: args.allow_private_upstream,
        insecure_open_upstream: args.insecure_open_upstream,
    });
    let limits = Arc::new(ProxyLimits {
        max_upstream_response_bytes: args.max_upstream_response_bytes,
        max_evade_retries: args.max_evade_retries,
    });
    let conn_sem = Arc::new(Semaphore::new(args.max_concurrent_connections));

    if args.insecure_open_upstream {
        warn!("--insecure-open-upstream: upstream DNS/literal policy checks are disabled");
    }

    loop {
        let permit = match conn_sem.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => continue,
        };
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let shared_state = shared_state.clone();
        let config = config.clone();
        let default_escalation = default_escalation.clone();
        let client = global_client.clone();
        let mitm_ca = mitm_ca.clone();
        let policy = policy.clone();
        let limits = limits.clone();

        tokio::task::spawn(async move {
            let _permit = permit;
            if let Err(err) = http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        proxy(
                            req,
                            shared_state.clone(),
                            config.clone(),
                            default_escalation.clone(),
                            client.clone(),
                            mitm_enabled,
                            mitm_ca.clone(),
                            policy.clone(),
                            limits.clone(),
                            expose_wafrift_status,
                        )
                    }),
                )
                .with_upgrades()
                .await
            {
                error!("failed to serve connection: {:?}", err);
            }
        });
    }
}

/// Build an error response without panicking.
fn error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from(message.to_string())))
        .unwrap_or_else(|_| {
            // Infallible in practice — status and body are always valid.
            // But if it somehow fails, return a minimal 500.
            let mut resp = Response::new(Full::new(Bytes::from("internal error")));
            *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            resp
        })
}

/// Wrap [`forward_wafrift_request`] with a retry loop. The first attempt
/// runs the standard pipeline. If the WAF blocks (HTTP 403/406), each
/// retry re-enters `forward_wafrift_request` — which records the previous
/// block in the host's `HostState`, automatically bumping escalation so
/// the next pass picks heavier evasion. Returns the first non-blocked
/// response, or the last block if all attempts fail. Behavior is
/// identical to the old single-shot proxy when `max_evade_retries == 0`.
#[allow(clippy::too_many_arguments)]
async fn forward_with_evade_retry(
    wafrift_req: wafrift_types::Request,
    host: String,
    request_log_uri: String,
    state: SharedState,
    config: Arc<EvasionConfig>,
    default_escalation: Option<String>,
    client: &reqwest::Client,
    policy: Arc<UpstreamPolicy>,
    limits: Arc<ProxyLimits>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let max = limits.max_evade_retries;
    let mut last: Option<Response<Full<Bytes>>> = None;
    for attempt in 0..=max {
        let resp = forward_wafrift_request(
            wafrift_req.clone(),
            host.clone(),
            request_log_uri.clone(),
            Arc::clone(&state),
            Arc::clone(&config),
            default_escalation.clone(),
            client,
            Arc::clone(&policy),
            Arc::clone(&limits),
        )
        .await?;
        let status = resp.status().as_u16();
        if status != 403 && status != 406 {
            if attempt > 0 {
                info!(
                    host = %host,
                    attempt,
                    status,
                    "evade retry landed a bypass"
                );
            }
            return Ok(resp);
        }
        last = Some(resp);
    }
    Ok(last.unwrap_or_else(|| {
        let mut r = Response::new(Full::new(Bytes::from("no attempt completed")));
        *r.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        r
    }))
}

/// Run `evade` + upstream `reqwest` forward for one logical request.
#[allow(clippy::too_many_arguments)]
async fn forward_wafrift_request(
    wafrift_req: wafrift_types::Request,
    host: String,
    request_log_uri: String,
    state: SharedState,
    config: Arc<EvasionConfig>,
    default_escalation: Option<String>,
    client: &reqwest::Client,
    policy: Arc<UpstreamPolicy>,
    limits: Arc<ProxyLimits>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Determine evasion strategy: winner rotation vs. discovery.
    let (evasion_result, technique_keys) = {
        let mut st = state.lock().await;
        st.total_scanned += 1;

        // Prevent unbounded memory growth from arbitrary Host headers (DoS vector)
        if st.hosts.len() >= 10_000
            && !st.hosts.contains_key(&host)
            && let Some(key_to_remove) = st.hosts.keys().next().cloned()
        {
            st.hosts.remove(&key_to_remove);
        }

        let hs = st.hosts.entry(host.clone()).or_default();

        // Apply default escalation if requested.
        if let Some(esc) = &default_escalation {
            match esc.as_str() {
                "heavy" if hs.blocks < 6 => hs.blocks = 6,
                "medium" if hs.blocks < 3 => hs.blocks = 3,
                "light" if hs.blocks < 1 => hs.blocks = 1,
                _ => {}
            }
        }

        if hs.has_winners() {
            // ── Rotation mode: only use proven winners ─────────────
            let winner_name = hs.next_winner().unwrap_or_default();
            info!(
                host = %host,
                technique = %winner_name,
                pool_size = hs.proven_winners.len(),
                "rotating proven winner"
            );

            let replay_state = HostState {
                proven_winners: vec![winner_name.clone()],
                discovery_complete: true,
                ..HostState::default()
            };
            let result = evade(&wafrift_req, &replay_state, &config);
            let mut keys: Vec<String> = result
                .techniques
                .iter()
                .map(std::string::ToString::to_string)
                .collect();
            if keys.is_empty() {
                keys.push(winner_name);
            }
            (result, keys)
        } else {
            // ── Discovery mode: MCTS-first via evade_smart, falls back
            // to classic evade() pipeline. evade_smart switches to MCTS
            // once the host has accumulated block telemetry — so the
            // first request to a new host runs the cheap pipeline, and
            // every subsequent block triggers tree-search reasoning. ──
            if hs.discovery_complete {
                // Winners were pruned — re-entering discovery.
                info!(host = %host, "all winners pruned, re-entering discovery");
            }
            let host_state = hs.clone();
            let result = evade_smart(&wafrift_req, &host_state, &config);
            let keys: Vec<String> = result
                .techniques
                .iter()
                .map(std::string::ToString::to_string)
                .collect();
            if !result.techniques.is_empty() {
                info!(
                    uri = %request_log_uri,
                    techniques = %result.description,
                    "discovery: evading WAF"
                );
            }
            (result, keys)
        }
    };

    if let Err(msg) = assert_forward_url_allowed(&evasion_result.request.url, &policy).await {
        warn!(host = %host, url = %evasion_result.request.url, "{}", msg);
        return Ok(error_response(StatusCode::FORBIDDEN, &msg));
    }

    // Build forward request using reqwest.
    let method = match reqwest::Method::from_bytes(
        evasion_result.request.method.as_str().as_bytes(),
    ) {
        Ok(m) => m,
        Err(e) => {
            warn!(host = %host, error = %e, method = %evasion_result.request.method.as_str(), "invalid HTTP method");
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "invalid HTTP method",
            ));
        }
    };
    let mut builder = client.request(method, &evasion_result.request.url);

    let conn_fwd = collect_connection_header_names(&evasion_result.request.headers);
    for (k, v) in &evasion_result.request.headers {
        if k.eq_ignore_ascii_case("host") || should_strip_proxy_header(k, &conn_fwd) {
            continue;
        }
        builder = builder.header(k.as_str(), v.as_str());
    }

    if let Some(b) = evasion_result.request.body.clone() {
        builder = builder.body(b);
    }

    let resp = match builder.send().await {
        Ok(r) => r,
        Err(e) => {
            warn!(host = %host, error = %e, "forwarding failed");
            // S3 fix: Do not leak internal errors to external callers
            return Ok(error_response(StatusCode::BAD_GATEWAY, "forwarding error"));
        }
    };

    let status = resp.status();
    let conn_resp = collect_connection_header_names_hyper(resp.headers());
    let mut response_builder = Response::builder().status(status.as_u16());
    for (k, v) in resp.headers().iter() {
        if should_strip_proxy_header(k.as_str(), &conn_resp) {
            continue;
        }
        response_builder = response_builder.header(k, v);
    }

    let max = limits.max_upstream_response_bytes;
    let mut stream = resp.bytes_stream();
    let mut buf = Vec::new();
    while let Some(item) = stream.next().await {
        let chunk = match item {
            Ok(c) => c,
            Err(e) => {
                warn!(host = %host, error = %e, "upstream body read failed");
                return Ok(error_response(
                    StatusCode::BAD_GATEWAY,
                    "upstream read error",
                ));
            }
        };
        if buf.len().saturating_add(chunk.len()) > max {
            return Ok(error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "upstream response too large",
            ));
        }
        buf.extend_from_slice(&chunk);
    }

    let is_block = is_waf_block(status.as_u16(), &buf);

    // ── Feedback loop: attribute result to the active technique(s) ───
    {
        let mut st = state.lock().await;
        if is_block {
            st.total_blocks += 1;
            if let Some(hs) = st.hosts.get_mut(&host) {
                if technique_keys.is_empty() {
                    hs.record_block();
                } else {
                    hs.record_block_for_many(&technique_keys);
                }
            }
        } else {
            if let Some(hs) = st.hosts.get_mut(&host) {
                if !evasion_result.techniques.is_empty() {
                    hs.record_success_for_many(&evasion_result.techniques);
                } else {
                    let parsed: Vec<wafrift_types::Technique> = technique_keys
                        .iter()
                        .filter_map(|k| wafrift_types::Technique::from_pool_key(k))
                        .collect();
                    if !parsed.is_empty() {
                        hs.record_success_for_many(&parsed);
                    }
                }
            }
            for t in &evasion_result.techniques {
                let name = t.to_string();
                *st.techniques_used.entry(name).or_insert(0) += 1;
            }
        }
    }

    Ok(response_builder
        .body(Full::new(Bytes::from(buf)))
        .unwrap_or_else(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to build response",
            )
        }))
}

#[allow(clippy::too_many_arguments)]
async fn mitm_plaintext_request(
    mut req: Request<Incoming>,
    connect_authority: String,
    state: SharedState,
    config: Arc<EvasionConfig>,
    default_escalation: Option<String>,
    client: reqwest::Client,
    policy: Arc<UpstreamPolicy>,
    limits: Arc<ProxyLimits>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Pin upstream to the CONNECT target; do not follow a different inner `Host:`.
    let sni_host = tls_server_name_from_authority(&connect_authority);
    if let Some(h) = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|x| x.to_str().ok())
    {
        let inner = extract_host_from_header(h);
        if !inner.eq_ignore_ascii_case(&sni_host) {
            warn!(inner = %inner, expected = %sni_host, "mitm Host header does not match CONNECT");
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "Host header does not match CONNECT target",
            ));
        }
    }

    let authority = connect_authority.trim();
    let path_and_q = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let url = format!("https://{}{}", authority, path_and_q);
    let host = sni_host;

    let body_bytes = match req.body_mut().collect().await {
        Ok(b) => b.to_bytes().to_vec(),
        Err(e) => {
            warn!(host = %host, error = %e, "mitm: failed to read request body");
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "failed to read request body",
            ));
        }
    };
    if body_bytes.len() > MAX_PROXY_BODY_BYTES {
        return Ok(error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body too large",
        ));
    }

    let raw_headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                String::from_utf8_lossy(v.as_bytes()).to_string(),
            )
        })
        .collect();
    let conn = collect_connection_header_names(&raw_headers);
    let headers: Vec<(String, String)> = raw_headers
        .into_iter()
        .filter(|(k, _)| !should_strip_proxy_header(k, &conn))
        .collect();

    let wafrift_req = wafrift_types::Request {
        method: wafrift_types::Method::from(req.method().as_str()),
        url,
        headers,
        body: if body_bytes.is_empty() {
            None
        } else {
            Some(body_bytes)
        },
    };

    let log_uri = wafrift_req.url.clone();
    forward_with_evade_retry(
        wafrift_req,
        host,
        log_uri,
        state,
        config,
        default_escalation,
        &client,
        policy,
        limits,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn mitm_https_session(
    upgraded: Upgraded,
    connect_authority: String,
    ca: Arc<CertificateAuthority>,
    state: SharedState,
    config: Arc<EvasionConfig>,
    default_escalation: Option<String>,
    client: reqwest::Client,
    policy: Arc<UpstreamPolicy>,
    limits: Arc<ProxyLimits>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let tls_name = tls_server_name_from_authority(&connect_authority);
    let acceptor = ca.create_tls_acceptor(&tls_name)?;
    let upgraded = TokioIo::new(upgraded);
    let tls_stream = acceptor.accept(upgraded).await?;
    let io = TokioIo::new(tls_stream);

    let svc_state = state.clone();
    let svc_config = config.clone();
    let svc_default_esc = default_escalation.clone();
    let svc_client = client.clone();
    let svc_policy = policy.clone();
    let svc_limits = limits.clone();
    let cauth = connect_authority.clone();

    let service = service_fn(move |req: Request<Incoming>| {
        let state = svc_state.clone();
        let config = svc_config.clone();
        let default_escalation = svc_default_esc.clone();
        let client = svc_client.clone();
        let policy = svc_policy.clone();
        let limits = svc_limits.clone();
        let connect_authority = cauth.clone();
        async move {
            mitm_plaintext_request(
                req,
                connect_authority,
                state,
                config,
                default_escalation,
                client,
                policy,
                limits,
            )
            .await
        }
    });

    http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(io, service)
        .await?;
    Ok(())
}

/// Proxy a single HTTP request with WAF evasion.
///
/// The evasion lifecycle per-host is:
///
/// 1. **Discovery** — try all techniques, track what bypasses vs. blocks.
/// 2. **Rotation** — once enough data, only rotate proven winners.
/// 3. **Drift detection** — if a winner starts failing, prune it.
/// 4. **Re-discovery** — if all winners fail, reset and start over.
#[allow(clippy::too_many_arguments)]
async fn proxy(
    mut req: Request<Incoming>,
    state: SharedState,
    config: Arc<EvasionConfig>,
    default_escalation: Option<String>,
    client: reqwest::Client,
    mitm_enabled: bool,
    mitm_ca: Option<Arc<CertificateAuthority>>,
    policy: Arc<UpstreamPolicy>,
    limits: Arc<ProxyLimits>,
    expose_wafrift_status: bool,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // CONNECT: optional TLS MITM (terminate client TLS, evade, forward via HTTPS).
    if req.method() == Method::CONNECT {
        if let Some(addr) = host_addr(req.uri()) {
            if let Err(msg) = assert_connect_target_allowed(&addr, &policy).await {
                warn!("CONNECT rejected: {}", msg);
                return Ok(error_response(StatusCode::FORBIDDEN, &msg));
            }
            if let (true, Some(ca)) = (mitm_enabled, mitm_ca.as_ref()) {
                let ca = ca.clone();
                let state = state.clone();
                let config = config.clone();
                let default_escalation = default_escalation.clone();
                let client = client.clone();
                let policy = policy.clone();
                let limits = limits.clone();
                tokio::task::spawn(async move {
                    match hyper::upgrade::on(req).await {
                        Ok(upgraded) => {
                            if let Err(e) = mitm_https_session(
                                upgraded,
                                addr,
                                ca,
                                state,
                                config,
                                default_escalation,
                                client,
                                policy,
                                limits,
                            )
                            .await
                            {
                                error!("mitm session error: {e:?}");
                            }
                        }
                        Err(e) => error!("upgrade error: {}", e),
                    }
                });
            } else {
                tokio::task::spawn(async move {
                    match hyper::upgrade::on(req).await {
                        Ok(upgraded) => {
                            if let Err(e) = tunnel(upgraded, addr).await {
                                error!("server io error: {}", e);
                            };
                        }
                        Err(e) => error!("upgrade error: {}", e),
                    }
                });
            }
            return Ok(Response::new(Full::new(Bytes::new())));
        }
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "CONNECT must be to a socket address",
        ));
    }

    // Status endpoint — returns JSON stats about the proxy (loopback bind only).
    if req.uri().path() == "/_wafrift/status" {
        if !expose_wafrift_status {
            return Ok(error_response(StatusCode::NOT_FOUND, "not found"));
        }
        let st = state.lock().await;
        let response = serde_json::json!({
            "status_schema_version": 1,
            "hosts_scanned": st.hosts.len(),
            "total_scanned": st.total_scanned,
            "total_blocks": st.total_blocks,
            "techniques_used": st.techniques_used,
            "hosts": st.hosts.iter().map(|(host, hs)| {
                serde_json::json!({
                    "host": host,
                    "blocks": hs.blocks,
                    "successes": hs.successes,
                    "discovery_complete": hs.discovery_complete,
                    "proven_winners": hs.proven_winners,
                    "blocklisted": hs.blocklisted,
                })
            }).collect::<Vec<_>>(),
        });
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(response.to_string())))
            .unwrap_or_else(|_| {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to build status response",
                )
            }));
    }

    // Forward proxy
    let host = req
        .uri()
        .host()
        .map(|s| s.to_string())
        .or_else(|| {
            req.headers()
                .get(hyper::header::HOST)
                .and_then(|h| h.to_str().ok().map(extract_host_from_header))
        })
        .unwrap_or_else(|| "unknown".to_string());

    // Read body
    let body_bytes = match req.body_mut().collect().await {
        Ok(b) => b.to_bytes().to_vec(),
        Err(e) => {
            warn!(host = %host, error = %e, "failed to read request body");
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "failed to read request body",
            ));
        }
    };
    if body_bytes.len() > MAX_PROXY_BODY_BYTES {
        return Ok(error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body too large",
        ));
    }

    let raw_headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                String::from_utf8_lossy(v.as_bytes()).to_string(),
            )
        })
        .collect();
    let conn = collect_connection_header_names(&raw_headers);
    let headers: Vec<(String, String)> = raw_headers
        .into_iter()
        .filter(|(k, _)| !should_strip_proxy_header(k, &conn))
        .collect();

    let wafrift_req = wafrift_types::Request {
        method: wafrift_types::Method::from(req.method().as_str()),
        url: req.uri().to_string(),
        headers,
        body: if body_bytes.is_empty() {
            None
        } else {
            Some(body_bytes)
        },
    };

    let log_uri = req.uri().to_string();
    forward_with_evade_retry(
        wafrift_req,
        host,
        log_uri,
        state,
        config,
        default_escalation,
        &client,
        policy,
        limits,
    )
    .await
}

/// Extract the host:port from a URI authority.
fn host_addr(uri: &hyper::Uri) -> Option<String> {
    uri.authority().map(|auth| auth.to_string())
}

/// Bidirectional tunnel for CONNECT (HTTPS pass-through).
async fn tunnel(upgraded: Upgraded, addr: String) -> std::io::Result<()> {
    let mut server = TcpStream::connect(addr).await?;
    let mut upgraded = TokioIo::new(upgraded);
    tokio::io::copy_bidirectional(&mut upgraded, &mut server).await?;
    Ok(())
}

#[cfg(test)]
#[path = "proxy_tests.rs"]
mod tests;
