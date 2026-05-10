//! WAF Rift Proxy — HTTP forward proxy with automatic WAF evasion.
//!
//! Point your browser or scanner at this proxy and all outbound traffic
//! is automatically transformed to bypass WAF rules. Per-host evasion
//! state is tracked so the proxy learns what works and escalates when
//! blocks are detected.

use clap::Parser;
use futures_util::StreamExt;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore};
use tracing::{debug, error, info, trace, warn};

use http_body_util::{BodyExt, Full, Limited};
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
use wafrift_proxy::rate_limit::RateLimiter;
use wafrift_proxy::scope::ScopeFilter;
use wafrift_proxy::upstream_policy::{
    BogonFilteringResolver, UpstreamPolicy, assert_connect_target_allowed,
    assert_forward_url_allowed,
};
use wafrift_strategy::strategy::{evade, evade_smart};
use wafrift_strategy::{EvasionConfig, HostState};
use wafrift_transport::signal::{BlockClass, ResponseProfileDb};

/// Maximum request body buffered per message (plain HTTP + MITM plaintext).
const MAX_PROXY_BODY_BYTES: usize = 16 * 1024 * 1024;

use std::sync::OnceLock;

static WARN_THROTTLE: OnceLock<WarnThrottle> = OnceLock::new();

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

// ── Per-request evasion control via X-WafRift-Evade header ──────────
/// Header name the client can set to control evasion per-request.
/// Values: "off" (skip evasion entirely) or "light"/"medium"/"heavy"
/// (force escalation level for this request only).
const X_WAFRIFT_EVADE: &str = "x-wafrift-evade";

// ── Response tagging headers ────────────────────────────────────────
/// Injected into every evaded response so the practitioner can see at a
/// glance what happened. Visible in Burp, browser devtools, curl -v.
const X_WAFRIFT_TECHNIQUES: &str = "x-wafrift-techniques";
const X_WAFRIFT_BLOCKED: &str = "x-wafrift-blocked";

// ── NDJSON request/response logger ──────────────────────────────────
/// Shared logger handle; None when --log-dir is not set.
type SharedLogger = Option<Arc<RequestLogger>>;

struct RequestLogger {
    #[allow(dead_code)] // kept for future log rotation
    dir: PathBuf,
    /// Append-only file, protected by a tokio mutex for async writes.
    writer: tokio::sync::Mutex<std::io::BufWriter<std::fs::File>>,
}

impl RequestLogger {
    fn open(dir: &std::path::Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let now = time::OffsetDateTime::now_utc();
        let ts = format!(
            "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
            now.year(),
            now.month() as u8,
            now.day(),
            now.hour(),
            now.minute(),
            now.second(),
        );
        let path = dir.join(format!("wafrift-proxy-{ts}.ndjson"));
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        info!(path = %path.display(), "request/response log opened");
        Ok(Self {
            dir: dir.to_path_buf(),
            writer: tokio::sync::Mutex::new(std::io::BufWriter::new(file)),
        })
    }

    async fn log_entry(&self, entry: &serde_json::Value) {
        use std::io::Write;
        let mut w = self.writer.lock().await;
        if let Ok(line) = serde_json::to_string(entry) {
            let _ = writeln!(w, "{line}");
            let _ = w.flush();
        }
    }
}

/// CLI arguments for the proxy binary.
#[derive(Parser, Debug)]
#[command(name = "wafrift-proxy", about = "WAF Evasion Proxy")]
struct Args {
    /// Socket address to bind the proxy server. Examples: 127.0.0.1:8080, 0.0.0.0:8080, [::1]:8080.
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: String,

    /// Bypass discovery and force an escalation level. Valid values: light, medium, heavy.
    #[arg(long)]
    escalation: Option<String>,

    /// Enable Content-Type header mutation (e.g. application/json → text/plain) during evasion.
    #[arg(long)]
    content_type_switching: bool,

    /// Rotate User-Agent and other browser fingerprint headers on each request.
    #[arg(long)]
    fingerprint_rotation: bool,

    /// Accept invalid or self-signed upstream TLS certificates. Dangerous on untrusted networks.
    #[arg(long, default_value_t = false)]
    insecure: bool,

    /// Generate a fresh MITM CA, write `wafrift-mitm-ca.pem` and `wafrift-mitm-ca-key.pem` to this directory, then exit.
    #[arg(long = "write-mitm-ca-dir")]
    write_mitm_ca_dir: Option<PathBuf>,

    /// Intercept HTTPS traffic by terminating TLS on CONNECT. Requires the CA to be trusted by the client.
    #[arg(long, default_value_t = false)]
    mitm: bool,

    /// Directory containing the MITM CA files generated by `--write-mitm-ca-dir`. Defaults to ~/.wafrift/mitm-ca/ when --mitm is used without this flag.
    #[arg(long = "mitm-ca-dir")]
    mitm_ca_dir: Option<PathBuf>,

    /// Allow forwarding to RFC1918, loopback, and link-local addresses. Use only when targeting local lab infrastructure.
    #[arg(long, default_value_t = false)]
    allow_private_upstream: bool,

    /// Disable all upstream destination safety checks (bogon filtering, SSRF protection). NEVER use with untrusted clients.
    #[arg(long = "insecure-open-upstream", default_value_t = false)]
    insecure_open_upstream: bool,

    /// Maximum concurrent TCP connections. When the limit is reached, new connections wait until a slot opens.
    #[arg(long, default_value_t = 4096)]
    max_concurrent_connections: usize,

    /// Maximum upstream response body size in bytes. Responses exceeding this return HTTP 413. Default 33,554,432 (32 MiB).
    #[arg(long, default_value_t = 33554432)]
    max_upstream_response_bytes: usize,

    /// Number of evasion retries on WAF block (HTTP 403/406). 0 = one attempt (default). Each retry escalates technique weight automatically.
    #[arg(long, default_value_t = 0)]
    max_evade_retries: u32,

    /// Path to the persistent gene-bank JSON file. Proven winners and blocklisted techniques survive proxy restarts. Default: ~/.wafrift/gene-bank.json. Pass "off" or "" to disable persistence.
    #[arg(long, default_value = "")]
    gene_bank_path: String,

    /// Gene-bank flush interval in seconds. 0 disables periodic flushing (shutdown signal still triggers a flush).
    #[arg(long, default_value_t = 60)]
    gene_bank_flush_interval_secs: u64,

    /// Only evade requests whose Host header matches one of these glob patterns (e.g. *.example.com, *.*.target.com). Out-of-scope traffic is forwarded unchanged. Repeatable or comma-separated.
    #[arg(long, num_args = 1.., value_delimiter = ',')]
    only_host: Vec<String>,

    /// Skip evasion for Host headers matching these glob patterns. Evaluated after --only-host. Useful for login/oauth endpoints.
    #[arg(long, num_args = 1.., value_delimiter = ',')]
    skip_host: Vec<String>,

    /// Only evade requests whose path matches one of these glob patterns (e.g. /api/*, /v2/admin/*).
    #[arg(long, num_args = 1.., value_delimiter = ',')]
    only_path: Vec<String>,

    /// Skip evasion for paths matching these glob patterns (e.g. /static/*, /oauth/*, /favicon.ico).
    #[arg(long, num_args = 1.., value_delimiter = ',')]
    skip_path: Vec<String>,

    /// Only evade requests using these HTTP methods (e.g. POST,PUT,PATCH). GET and HEAD are unaffected unless listed.
    #[arg(long, num_args = 1.., value_delimiter = ',')]
    only_method: Vec<String>,

    /// Per-host requests-per-second throttle. Token-bucket algorithm; burst defaults to this value. 0 = unlimited.
    #[arg(long, default_value_t = 0.0)]
    max_rps_per_host: f64,

    /// Token-bucket burst capacity for --max-rps-per-host. Defaults to the rps value when 0. Ignored when rps is 0.
    #[arg(long, default_value_t = 0.0)]
    max_rps_per_host_burst: f64,

    /// Write NDJSON request/response logs to this directory. Each proxy session creates a timestamped
    /// file. Every proxied request is logged with method, URL, headers sent, techniques applied,
    /// upstream status, and whether the WAF blocked. Essential for pentest engagement reports.
    #[arg(long = "log-dir")]
    log_dir: Option<PathBuf>,

    /// Wear a real browser's TLS ClientHello on every upstream forward.
    /// Closes the JA3/JA4 fingerprint gap vs Cloudflare / Akamai /
    /// Fastly Sigsci / Imperva Bot Protection — which classify the
    /// inbound TLS connection as "non-browser" before they ever look
    /// at HTTP. Supported profiles: chrome131, chrome120, edge131,
    /// firefox133, safari18, safari17_5, okhttp5; aliases `chrome`,
    /// `firefox`, `safari`, `edge` resolve to the latest in each
    /// family. REQUIRES the binary to be built with the
    /// `tls-impersonate` cargo feature (pulls in boring-sys); without
    /// it, this flag errors at startup with an actionable message.
    /// See docs/TLS_PARITY.md.
    #[arg(long = "tls-impersonate", conflicts_with = "tls_impersonate_rotate")]
    tls_impersonate: Option<String>,

    /// Rotate the TLS ClientHello fingerprint per upstream request,
    /// drawn round-robin from this comma-separated profile list (e.g.
    /// `chrome131,firefox133,safari18`). Defeats per-fingerprint rate
    /// limits and reputation systems (Cloudflare bot-management,
    /// Akamai BMP, PerimeterX) that group requests by JA3 hash.
    /// Mutually exclusive with --tls-impersonate. REQUIRES
    /// `tls-impersonate` cargo feature.
    #[arg(long = "tls-impersonate-rotate", num_args = 1.., value_delimiter = ',')]
    tls_impersonate_rotate: Vec<String>,

    /// Pad request bodies with N bytes of inert ASCII filler before the
    /// real payload. Cloud WAFs only inspect the first 8 KB
    /// (Cloudflare Pro / Akamai default) or 16 KB (AWS WAF default) of
    /// a request body — pushing the malicious payload past that
    /// inspection window makes the WAF rule engine miss it entirely
    /// while the origin still parses the body correctly. Content-type
    /// aware: JSON gets a leading `_wafrift_pad` field, form-urlencoded
    /// gets `_wafrift_pad=<bytes>&...`, multipart gets a junk leading
    /// part. Default 0 (off). Recommended values: 8192 (Cloudflare
    /// Pro), 16384 (AWS WAF default), 65536 (Naxsi default), 131072
    /// (Cloudflare Enterprise / ModSecurity default).
    #[arg(long = "body-padding-bytes", default_value_t = 0)]
    body_padding_bytes: usize,

    /// Disable HTTP connection re-use. Every upstream request opens a
    /// fresh TCP connection — the kernel picks a new ephemeral source
    /// port, defeating per-source-port rate limits and any heuristic
    /// that groups requests by 5-tuple. Costs ~one TCP+TLS handshake
    /// per request. Combine with --tls-impersonate-rotate for full
    /// per-request fingerprint rotation.
    #[arg(long = "no-conn-reuse", default_value_t = false)]
    no_conn_reuse: bool,

    /// Run a real-time terminal dashboard alongside the proxy. Shows
    /// per-host bypass rate, TLS profile rotation distribution, body
    /// padding hits, and a live request stream. Press 'q' or Ctrl-C
    /// for graceful shutdown. Requires a TTY; if stdout is not a
    /// terminal the proxy starts without the TUI and logs a warning.
    #[arg(long = "tui", default_value_t = false)]
    tui: bool,
}

type SharedState = Arc<Mutex<ProxyState>>;

/// Process-wide stealth client. `OnceLock` because we want the upstream
/// forward sites to dispatch through it without every function in the
/// chain having to thread an extra parameter — initialised once at
/// startup if `--tls-impersonate <profile>` was passed, never touched
/// again. `None` (uninitialised) ⇒ all upstream forwards use the
/// default reqwest+rustls client.
static STEALTH_CLIENT: std::sync::OnceLock<wafrift_transport::stealth::StealthClient> =
    std::sync::OnceLock::new();

/// Process-wide rotating stealth pool. When set (via
/// `--tls-impersonate-rotate p1,p2,p3`), every upstream forward picks
/// the next client in round-robin. Mutually exclusive with
/// `STEALTH_CLIENT` — only one of the two is ever populated.
static STEALTH_POOL: std::sync::OnceLock<StealthPool> = std::sync::OnceLock::new();

/// Process-wide body-padding bytes. Read at every request to decide
/// whether to invoke `wafrift_evolution::body_padding::pad`. Set once
/// at startup from `--body-padding-bytes`.
static BODY_PADDING_BYTES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Process-wide TUI event channel. `Some` when `--tui` is set; the
/// dashboard task drains it. Bounded at 10 k events so a slow TTY can't
/// produce unbounded memory growth on a heavy-traffic proxy (was
/// unbounded — at 10 k req/s with a stalled TUI that's 200 MB/s of
/// dropped allocations). `try_send` drops on full so the request hot
/// path never blocks on TUI backpressure.
static TUI_TX: std::sync::OnceLock<tokio::sync::mpsc::Sender<wafrift_proxy::tui::Event>> =
    std::sync::OnceLock::new();

/// Counter of TUI events dropped because the channel was full. Visible
/// at /_wafrift/status so an operator can tell their TUI is too slow
/// for the request rate (vs. silent data loss).
static TUI_DROPPED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[inline]
fn emit_tui(ev: wafrift_proxy::tui::Event) {
    if let Some(tx) = TUI_TX.get()
        && tx.try_send(ev).is_err()
    {
        TUI_DROPPED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Round-robin pool of stealth clients with an atomic cursor.
struct StealthPool {
    clients: Vec<wafrift_transport::stealth::StealthClient>,
    cursor: std::sync::atomic::AtomicUsize,
}

impl StealthPool {
    fn pick(&self) -> &wafrift_transport::stealth::StealthClient {
        let i = self
            .cursor
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % self.clients.len();
        &self.clients[i]
    }
}

#[inline]
fn stealth() -> Option<&'static wafrift_transport::stealth::StealthClient> {
    if let Some(pool) = STEALTH_POOL.get() {
        return Some(pool.pick());
    }
    STEALTH_CLIENT.get()
}

/// Simple per-key warning throttle so high-rate scanners (sqlmap,
/// ffuf) don't flood the logs with identical messages.
struct WarnThrottle {
    cooldown: Duration,
    last: std::sync::Mutex<HashMap<String, Instant>>,
}

impl WarnThrottle {
    fn new(cooldown_secs: u64) -> Self {
        Self {
            cooldown: Duration::from_secs(cooldown_secs),
            last: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Returns true if at least `cooldown` has elapsed since the last
    /// warning with this key. The key should encode both the message
    /// category and the host (or other dimension) being warned about.
    fn should_warn(&self, key: &str) -> bool {
        let mut map = match self.last.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let now = Instant::now();
        if let Some(last) = map.get(key)
            && now.duration_since(*last) < self.cooldown
        {
            return false;
        }
        map.insert(key.to_string(), now);
        true
    }
}

/// Mutable proxy state shared across connections.
#[derive(Default)]
struct ProxyState {
    /// Per-host evasion state.
    hosts: HashMap<String, HostState>,
    /// FIFO queue tracking host insertion order. Used for deterministic
    /// eviction when the map exceeds its cap — prevents arbitrary
    /// HashMap-bucket-order removal from discarding active hosts.
    host_fifo: VecDeque<String>,
    /// Total requests proxied.
    total_scanned: u32,
    /// Total WAF blocks observed.
    total_blocks: u32,
    /// Technique usage counts.
    techniques_used: HashMap<String, u32>,
}

/// Subset of HostState worth persisting across proxy restarts. Block
/// counts and pending discovery state re-accumulate naturally; what we
/// don't want to lose is the painstakingly-discovered winners pool and
/// the per-host blocklist.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
struct PersistedHostState {
    proven_winners: Vec<String>,
    blocklisted: Vec<String>,
    waf_name: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
struct PersistedGeneBank {
    /// Format version so future schema changes can be detected.
    schema: u32,
    hosts: HashMap<String, PersistedHostState>,
}

fn default_gene_bank_path(supplied: &str) -> Option<std::path::PathBuf> {
    if supplied.is_empty() {
        // Default: ~/.wafrift/gene-bank.json. If $HOME is unset, disable.
        let home = std::env::var_os("HOME")?;
        let p = std::path::PathBuf::from(home)
            .join(".wafrift")
            .join("gene-bank.json");
        Some(p)
    } else if supplied == "off" || supplied == "-" {
        None
    } else {
        Some(std::path::PathBuf::from(supplied))
    }
}

fn load_gene_bank(path: &std::path::Path) -> PersistedGeneBank {
    match std::fs::read_to_string(path) {
        Ok(s) => {
            if s.trim().is_empty() {
                info!(path = %path.display(), "gene bank file is empty; starting fresh");
                return PersistedGeneBank::default();
            }
            match serde_json::from_str::<PersistedGeneBank>(&s) {
                Ok(bank) => {
                    if bank.schema > 1 {
                        warn!(
                            path = %path.display(),
                            schema = bank.schema,
                            "gene bank has newer schema than expected (1); data may be incomplete"
                        );
                    }
                    bank
                }
                Err(e) => {
                    warn!(
                        path = %path.display(),
                        error = %e,
                        "gene bank malformed (invalid JSON); starting fresh. Fix: inspect the file and fix the JSON syntax, or delete it to start over."
                    );
                    PersistedGeneBank::default()
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            info!(path = %path.display(), "gene bank not found; starting fresh");
            PersistedGeneBank::default()
        }
        Err(e) => {
            warn!(
                path = %path.display(),
                error = %e,
                "gene bank unreadable; starting fresh. Fix: check file permissions."
            );
            PersistedGeneBank::default()
        }
    }
}

fn save_gene_bank(state: &ProxyState, path: &std::path::Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut bank = PersistedGeneBank {
        schema: 1,
        hosts: HashMap::new(),
    };
    for (host, hs) in &state.hosts {
        // Persist any host where the proxy has accumulated discovery
        // signal — proven winners, blocklisted techniques, identified
        // WAF, OR observed blocks. The earlier "skip empty hosts to
        // keep the file small" rule dropped hosts with only
        // block-count telemetry, so a practitioner who left the proxy
        // running through 100 blocked attempts and then SIGTERM'd
        // would lose every bit of discovery progress on restart.
        // A host with non-zero blocks is a host worth remembering.
        if hs.proven_winners.is_empty()
            && hs.blocklisted.is_empty()
            && hs.waf_name.is_none()
            && hs.blocks == 0
        {
            continue; // truly empty — skip
        }
        bank.hosts.insert(
            host.clone(),
            PersistedHostState {
                proven_winners: hs.proven_winners.clone(),
                blocklisted: hs.blocklisted.clone(),
                waf_name: hs.waf_name.clone(),
            },
        );
    }
    let json = serde_json::to_string_pretty(&bank)?;
    // Atomic, durable write via tempfile + fsync + rename + parent fsync.
    // Without the fsyncs a system crash between write and rename can leave
    // the renamed file zero-length or partially flushed.
    let tmp = path.with_extension("json.tmp");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(json.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    // Fsync parent directory so the rename is durable.
    if let Some(parent) = path.parent()
        && let Ok(dir) = std::fs::OpenOptions::new().read(true).open(parent)
    {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Restore persisted host states from disk into the in-memory proxy state.
///
/// # Concurrency safety
///
/// This function must be called while holding the `ProxyState` mutex.
/// In `main()` the load+restore is performed before the accept loop
/// begins, and the mutex is held for the entire operation, so no
/// request can interleave and create host entries during restore.
/// The `HashMap::entry` call would merge with (and partially
/// overwrite) any existing entry, which is why the atomic load+restore
/// under the lock matters.
fn restore_gene_bank(state: &mut ProxyState, bank: PersistedGeneBank) -> usize {
    let mut restored = 0usize;
    for (host, persisted) in bank.hosts {
        let hs = state.hosts.entry(host.clone()).or_default();
        if !persisted.proven_winners.is_empty() {
            hs.proven_winners = persisted.proven_winners;
            hs.discovery_complete = true;
            restored += 1;
        }
        if !persisted.blocklisted.is_empty() {
            hs.blocklisted = persisted.blocklisted;
        }
        if persisted.waf_name.is_some() {
            hs.waf_name = persisted.waf_name;
            hs.waf_confirmed = true;
        }
        if !state.host_fifo.contains(&host) {
            state.host_fifo.push_back(host);
        }
    }
    restored
}

use wafrift_proxy::extract_host_from_header;

/// Validate CLI arguments before the proxy starts. Returns an
/// actionable error message for the operator.
fn validate_args(args: &Args) -> Result<(), String> {
    if args.max_concurrent_connections == 0 {
        return Err("--max-concurrent-connections must be >= 1, got 0".into());
    }
    if args.max_upstream_response_bytes < 4096 {
        return Err(format!(
            "--max-upstream-response-bytes must be >= 4096 (4 KiB), got {}",
            args.max_upstream_response_bytes
        ));
    }
    if args.max_rps_per_host < 0.0 {
        return Err(format!(
            "--max-rps-per-host must be a non-negative number, got {}",
            args.max_rps_per_host
        ));
    }
    if args.max_rps_per_host_burst < 0.0 {
        return Err(format!(
            "--max-rps-per-host-burst must be a non-negative number, got {}",
            args.max_rps_per_host_burst
        ));
    }
    if let Some(esc) = &args.escalation
        && !matches!(esc.as_str(), "light" | "medium" | "heavy")
    {
        return Err(format!(
            "--escalation must be one of: light, medium, heavy. Got: {}",
            esc
        ));
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse args FIRST so we can route logs to a file when --tui is on
    // (otherwise the tracing subscriber would write to stdout and tear
    // up the TUI's alternate-screen rendering).
    let mut args = Args::parse();

    use tracing_subscriber::EnvFilter;
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if args.tui {
        // Redirect logs to a file so the TUI owns the terminal. Default
        // to /tmp/wafrift-proxy.log; honour --log-dir if set.
        let log_path = match &args.log_dir {
            Some(dir) => {
                std::fs::create_dir_all(dir).ok();
                dir.join("wafrift-proxy-tui.log")
            }
            None => std::path::PathBuf::from("/tmp/wafrift-proxy-tui.log"),
        };
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
        {
            Ok(f) => {
                tracing_subscriber::fmt()
                    .with_env_filter(env_filter)
                    .with_writer(std::sync::Mutex::new(f))
                    .with_ansi(false)
                    .init();
                eprintln!("(--tui) logs writing to {}", log_path.display());
            }
            Err(e) => {
                eprintln!(
                    "(--tui) could not open log file {}: {} — disabling --tui to keep stdout logs",
                    log_path.display(),
                    e
                );
                args.tui = false;
                tracing_subscriber::fmt().with_env_filter(env_filter).init();
            }
        }
    } else {
        tracing_subscriber::fmt().with_env_filter(env_filter).init();
    }

    if let Err(msg) = validate_args(&args) {
        error!("{msg}");
        std::process::exit(1);
    }

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
        let Some(default_dir) = wafrift_proxy::mitm::default_mitm_ca_dir() else {
            error!(
                "cannot determine home directory for MITM CA storage \
                 (no $HOME / dirs::config_dir on this OS). Pass --mitm-ca-dir \
                 explicitly or unset --mitm."
            );
            std::process::exit(1);
        };
        info!(
            "No --mitm-ca-dir specified; using default: {}",
            default_dir.display()
        );
        args.mitm_ca_dir = Some(default_dir);
    }

    let mitm_ca: Option<Arc<CertificateAuthority>> = if args.mitm {
        // Safe: the block above guarantees mitm_ca_dir is Some when args.mitm is true.
        let dir = args
            .mitm_ca_dir
            .as_ref()
            .expect("mitm_ca_dir was set above when args.mitm is true");
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

    let addr: SocketAddr = args.listen.parse().unwrap_or_else(|e| {
        error!("--listen must be a valid socket address (e.g. 127.0.0.1:8080, [::1]:8080), got '{}': {}", args.listen, e);
        std::process::exit(1);
    });

    let listener = TcpListener::bind(addr).await.unwrap_or_else(|e| {
        error!("Failed to bind to {addr}: {e}");
        std::process::exit(1);
    });
    info!("Listening on http://{}", addr);
    let expose_wafrift_status = addr.ip().is_loopback();
    if !expose_wafrift_status {
        warn!(
            "--listen is bound to a non-loopback address ({}). /_wafrift/status and /_wafrift/findings.md are disabled to prevent information leakage.",
            addr
        );
        if args.mitm {
            // The proxy will accept CONNECT from any client reachable
            // on the LAN and re-sign upstream certs with the local CA
            // — turning the MITM CA into a network-wide trust root.
            // That's almost never what the operator wanted; if they
            // really meant it, they have to explicitly accept the risk
            // by running on loopback + binding through a tunnel.
            error!(
                "REFUSING TO START: --mitm + non-loopback --listen ({}) is a CA-private-key-exposure risk. \
                 Anyone on the network can route HTTPS through this proxy and have it re-signed with your MITM CA. \
                 If you really want this (lab-only), bind to a loopback address and front-end with your own ACL'd reverse proxy.",
                addr
            );
            std::process::exit(1);
        }
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

    // ── Load WAF response profiles for intelligent feedback ─────────
    // Resolution order:
    //   1. `--rules-dir` (CLI override, future)
    //   2. `<binary>/rules/responses/` (next to wafrift-proxy binary)
    //   3. `./rules/responses/` (cwd, dev convenience)
    //   4. `ResponseProfileDb::compiled_in()` — embedded copy that ships
    //      inside the binary, so `cargo install wafrift-proxy` is never
    //      stuck with empty profiles. (Fixes the same shape of bug
    //      wafrift-detect 0.2.0 had.)
    //
    // Profiles classify upstream responses into HardBlock/SoftBlock/
    // RateLimit/Challenge/Pass — each getting different treatment by
    // `HostState::record_signal`.
    let response_profiles = {
        let next_to_binary = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("rules/responses")))
            .filter(|d| d.is_dir());
        let cwd_dir = std::path::Path::new("rules/responses");
        if let Some(dir) = next_to_binary {
            ResponseProfileDb::load_dir(&dir)
        } else if cwd_dir.is_dir() {
            ResponseProfileDb::load_dir(cwd_dir)
        } else {
            info!(
                "no rules/responses/ directory found — using compiled-in profiles \
                 (override with a rules/responses/ dir next to the binary)"
            );
            ResponseProfileDb::compiled_in()
        }
    };
    let response_profiles = Arc::new(response_profiles);

    let policy = Arc::new(UpstreamPolicy {
        allow_private_upstream: args.allow_private_upstream,
        insecure_open_upstream: args.insecure_open_upstream,
    });

    let _ = WARN_THROTTLE.set(WarnThrottle::new(5));

    if args.insecure_open_upstream && args.allow_private_upstream {
        warn!(
            "--insecure-open-upstream makes --allow-private-upstream redundant; all upstream checks are disabled"
        );
    }

    // ── Optional stealth (browser-identical TLS ClientHello) ──────────
    // When `--tls-impersonate <profile>` is set, build a `StealthClient`
    // and stash it in `STEALTH_CLIENT` so the upstream-forward sites
    // (forward_wafrift_request + forward_passthrough) dispatch through
    // it instead of the default reqwest+rustls client. This closes the
    // JA3/JA4 fingerprint gap vs Cloudflare / Akamai / Sigsci /
    // Imperva-Bot at the cost of a `boring-sys` build dep — gated on
    // the `tls-impersonate` cargo feature. See docs/TLS_PARITY.md.
    if let Some(profile_str) = &args.tls_impersonate {
        use wafrift_transport::stealth::{ImpersonateProfile, StealthClient};
        let profile = match ImpersonateProfile::parse(profile_str) {
            Ok(p) => p,
            Err(e) => {
                error!("--tls-impersonate: {}", e);
                std::process::exit(2);
            }
        };
        let client = match StealthClient::with_timeout(
            profile,
            std::time::Duration::from_secs(wafrift_types::DEFAULT_REQUEST_TIMEOUT_SECS),
        ) {
            Ok(c) => c,
            Err(e) => {
                error!(
                    "--tls-impersonate {}: {}\nhint: rebuild with `cargo build --features wafrift-transport/tls-impersonate` (pulls in boring-sys)",
                    profile.name(),
                    e
                );
                std::process::exit(2);
            }
        };
        if STEALTH_CLIENT.set(client).is_err() {
            // Unreachable in practice — main runs once per process.
            warn!("STEALTH_CLIENT was already initialised; ignoring duplicate set");
        }
        info!(
            "TLS impersonation active: every upstream forward will wear {}'s ClientHello",
            profile.name()
        );
    }

    // Per-request rotation pool. Built only when --tls-impersonate-rotate
    // is set; mutually exclusive with --tls-impersonate (clap enforces).
    if !args.tls_impersonate_rotate.is_empty() {
        use wafrift_transport::stealth::{ImpersonateProfile, StealthClient};
        let mut clients = Vec::with_capacity(args.tls_impersonate_rotate.len());
        let mut names = Vec::with_capacity(args.tls_impersonate_rotate.len());
        for raw in &args.tls_impersonate_rotate {
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            let profile = match ImpersonateProfile::parse(raw) {
                Ok(p) => p,
                Err(e) => {
                    error!("--tls-impersonate-rotate: {}", e);
                    std::process::exit(2);
                }
            };
            let c = match StealthClient::with_timeout(
                profile,
                std::time::Duration::from_secs(wafrift_types::DEFAULT_REQUEST_TIMEOUT_SECS),
            ) {
                Ok(c) => c,
                Err(e) => {
                    error!(
                        "--tls-impersonate-rotate {}: {}\nhint: rebuild with `cargo build --features wafrift-transport/tls-impersonate`",
                        profile.name(),
                        e
                    );
                    std::process::exit(2);
                }
            };
            clients.push(c);
            names.push(profile.name());
        }
        if clients.is_empty() {
            error!("--tls-impersonate-rotate: empty profile list after trimming");
            std::process::exit(2);
        }
        let pool = StealthPool {
            clients,
            cursor: std::sync::atomic::AtomicUsize::new(0),
        };
        if STEALTH_POOL.set(pool).is_err() {
            warn!("STEALTH_POOL was already initialised; ignoring duplicate set");
        }
        info!(
            "TLS impersonation rotation active: every upstream forward picks round-robin from {:?}",
            names
        );
    }

    // Body padding — applied per request, controlled by an atomic so
    // there's no per-request lock contention on the hot path.
    if args.body_padding_bytes > 0 {
        BODY_PADDING_BYTES.store(
            args.body_padding_bytes,
            std::sync::atomic::Ordering::Relaxed,
        );
        if args.body_padding_bytes < wafrift_evolution::body_padding::MIN_USEFUL_PAD {
            warn!(
                "--body-padding-bytes {} is below the {}-byte useful minimum; padding will be skipped",
                args.body_padding_bytes,
                wafrift_evolution::body_padding::MIN_USEFUL_PAD
            );
        } else {
            info!(
                "Body padding active: every JSON / form / multipart request body gets {} bytes of inert leading filler",
                args.body_padding_bytes
            );
        }
    }

    // Single global client. Custom resolver re-runs the bogon filter on
    // every connection-time DNS lookup, closing the DNS-rebinding TOCTOU
    // between the policy check and reqwest's own resolution. Without
    // this, attacker-controlled DNS could return a public IP at the
    // policy check then 169.254.169.254 / 127.0.0.1 / RFC1918 at fetch
    // time.
    let mut client_builder = reqwest::Client::builder()
        .danger_accept_invalid_certs(config.insecure_tls)
        .timeout(std::time::Duration::from_secs(
            wafrift_types::DEFAULT_REQUEST_TIMEOUT_SECS,
        ))
        .dns_resolver(Arc::new(BogonFilteringResolver {
            policy: policy.clone(),
        }));
    if args.no_conn_reuse {
        // Force a fresh TCP connection per request. Kernel chooses a
        // new ephemeral source port each time, defeating per-source-
        // port rate limits and any 5-tuple-based reputation system.
        // Costs ~one handshake per request — set explicitly, not the
        // default.
        client_builder = client_builder.pool_max_idle_per_host(0);
        info!(
            "Connection re-use disabled: every upstream forward opens a fresh TCP connection (new source port per request)"
        );
    }
    let global_client = client_builder.build().unwrap_or_else(|e| {
        error!("reqwest client build failed: {e}");
        std::process::exit(1);
    });
    let limits = Arc::new(ProxyLimits {
        max_upstream_response_bytes: args.max_upstream_response_bytes,
        max_evade_retries: args.max_evade_retries,
    });
    let scope = Arc::new(ScopeFilter::new(
        args.only_host.clone(),
        args.skip_host.clone(),
        args.only_path.clone(),
        args.skip_path.clone(),
        args.only_method.clone(),
    ));
    if !scope.is_empty() {
        info!(
            only_host = ?args.only_host,
            skip_host = ?args.skip_host,
            only_path = ?args.only_path,
            skip_path = ?args.skip_path,
            only_method = ?args.only_method,
            "scope filter active — out-of-scope requests pass through unchanged"
        );
    }
    let rate_limiter = RateLimiter::new(args.max_rps_per_host, args.max_rps_per_host_burst);
    if !rate_limiter.is_unlimited() {
        info!(
            rps = args.max_rps_per_host,
            burst = if args.max_rps_per_host_burst > 0.0 {
                args.max_rps_per_host_burst
            } else {
                args.max_rps_per_host
            },
            "per-host rate limiter active"
        );
    }
    let conn_sem = Arc::new(Semaphore::new(args.max_concurrent_connections));

    // ── Request/response logger ─────────────────────────────────────
    let logger: SharedLogger = if let Some(dir) = &args.log_dir {
        match RequestLogger::open(dir) {
            Ok(l) => Some(Arc::new(l)),
            Err(e) => {
                error!(dir = %dir.display(), error = %e, "failed to open log directory");
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    if args.insecure_open_upstream {
        warn!("--insecure-open-upstream: upstream DNS/literal policy checks are disabled");
    }

    // ── Persistent gene bank ────────────────────────────────────────
    let gene_bank_path = default_gene_bank_path(&args.gene_bank_path);
    if let Some(path) = &gene_bank_path {
        let restored = {
            let mut st = shared_state.lock().await;
            let bank = load_gene_bank(path);
            restore_gene_bank(&mut st, bank)
        };
        if restored > 0 {
            info!(
                path = %path.display(),
                hosts_restored = restored,
                "loaded persistent gene bank"
            );
        } else {
            info!(path = %path.display(), "starting with empty gene bank");
        }

        // Periodic flush task.
        if args.gene_bank_flush_interval_secs > 0 {
            let flush_path = path.clone();
            let flush_state = shared_state.clone();
            let interval = args.gene_bank_flush_interval_secs;
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(interval));
                tick.tick().await; // skip the immediate first tick
                loop {
                    tick.tick().await;
                    let st = flush_state.lock().await;
                    if let Err(e) = save_gene_bank(&st, &flush_path) {
                        warn!(error = %e, "periodic gene bank flush failed");
                    }
                }
            });
        }
    }

    // ── Graceful shutdown: SIGINT/SIGTERM flush gene bank then exit ──
    let shutdown_state = shared_state.clone();
    let shutdown_path = gene_bank_path.clone();
    tokio::spawn(async move {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => return,
        };
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(_) => return,
        };
        tokio::select! {
            _ = sigterm.recv() => info!("received SIGTERM"),
            _ = sigint.recv() => info!("received SIGINT"),
        };
        if let Some(path) = &shutdown_path {
            let st = shutdown_state.lock().await;
            match save_gene_bank(&st, path) {
                Ok(()) => info!(path = %path.display(), "gene bank flushed on shutdown"),
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "gene bank flush on shutdown failed")
                }
            }
        }
        info!("shutting down");
        std::process::exit(0);
    });

    // ── Optional TUI dashboard ──────────────────────────────────────
    if args.tui {
        // Bounded at 10 k events. At ~200 B per event that caps memory
        // pressure at ~2 MB even with a fully-stalled TUI; emit_tui
        // drops on full and bumps TUI_DROPPED.
        let (tx, rx) = tokio::sync::mpsc::channel(10_000);
        if TUI_TX.set(tx).is_err() {
            warn!("TUI_TX was already initialised; skipping TUI startup");
        } else {
            let tls_label = if !args.tls_impersonate_rotate.is_empty() {
                format!("rotate({})", args.tls_impersonate_rotate.join(","))
            } else if let Some(p) = &args.tls_impersonate {
                format!("single({p})")
            } else {
                "off".to_string()
            };
            let cfg = wafrift_proxy::tui::DashboardConfig {
                bind_addr: addr.to_string(),
                mode: default_escalation
                    .clone()
                    .unwrap_or_else(|| "evade".to_string()),
                tls_stack_label: tls_label,
                body_padding_bytes: args.body_padding_bytes,
                conn_reuse: !args.no_conn_reuse,
            };
            let (quit_tx, quit_rx) = tokio::sync::oneshot::channel();
            // Dashboard lives in a blocking-friendly task so it can do
            // its terminal I/O without starving the runtime.
            tokio::spawn(async move {
                if let Err(e) = wafrift_proxy::tui::run(cfg, rx, quit_tx).await {
                    eprintln!("TUI exited with error: {e}");
                }
            });
            // 'q' inside the TUI fires this oneshot — translate to a
            // graceful shutdown on the same code path SIGINT uses.
            let quit_state = shared_state.clone();
            let quit_path = gene_bank_path.clone();
            tokio::spawn(async move {
                if quit_rx.await.is_ok() {
                    if let Some(path) = &quit_path {
                        let st = quit_state.lock().await;
                        if let Err(e) = save_gene_bank(&st, path) {
                            warn!(path = %path.display(), error = %e, "gene bank flush from TUI quit failed");
                        }
                    }
                    std::process::exit(0);
                }
            });
        }
    }

    loop {
        let permit = match conn_sem.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => continue,
        };
        let (stream, peer) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let shared_state = shared_state.clone();
        let config = config.clone();
        let default_escalation = default_escalation.clone();
        let client = global_client.clone();
        let mitm_ca = mitm_ca.clone();
        let policy = policy.clone();
        let limits = limits.clone();
        let scope = scope.clone();
        let rate_limiter = rate_limiter.clone();
        let response_profiles = response_profiles.clone();

        // Per-connection peer-loopback gate for /_wafrift/status. The
        // bind-address check (expose_wafrift_status) is necessary but
        // not sufficient: a reverse proxy or socat fronting wafrift on
        // loopback would otherwise leak host names and proven winners
        // to external callers. Require BOTH bind AND peer to be
        // loopback before exposing the status endpoint.
        let expose_status_per_conn = expose_wafrift_status && peer.ip().is_loopback();

        let logger = logger.clone();
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
                            scope.clone(),
                            rate_limiter.clone(),
                            expose_status_per_conn,
                            logger.clone(),
                            response_profiles.clone(),
                        )
                    }),
                )
                .with_upgrades()
                .await
            {
                warn!("failed to serve connection: {:?}", err);
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
    response_profiles: Arc<ResponseProfileDb>,
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
            Arc::clone(&response_profiles),
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
    response_profiles: Arc<ResponseProfileDb>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Determine evasion strategy: winner rotation vs. discovery.
    let (mut evasion_result, technique_keys) = {
        let mut st = state.lock().await;
        st.total_scanned = st.total_scanned.saturating_add(1);

        // Prevent unbounded memory growth from arbitrary Host headers (DoS vector).
        // Evict the oldest host (FIFO) rather than an arbitrary HashMap bucket.
        if st.hosts.len() >= 10_000 && !st.hosts.contains_key(&host) {
            while let Some(key_to_remove) = st.host_fifo.pop_front() {
                if st.hosts.remove(&key_to_remove).is_some() {
                    break;
                }
                // If the key was already gone (stale FIFO entry), keep popping.
            }
        }

        let is_new = !st.hosts.contains_key(&host);
        if is_new {
            st.host_fifo.push_back(host.clone());
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

    // ── Body padding (8KB/16KB cloud-WAF inspection bypass) ─────────
    // Applied AFTER URL validation but BEFORE the upstream fetch so
    // SSRF policy still gates the unmodified URL and the WAF sees the
    // padded body on the wire. Skipped when the configured size is
    // below the useful threshold (small pads can't push payload past
    // any real WAF window) or when the content-type is opaque.
    let pad_target = BODY_PADDING_BYTES.load(std::sync::atomic::Ordering::Relaxed);
    if pad_target >= wafrift_evolution::body_padding::MIN_USEFUL_PAD {
        let ct = evasion_result
            .request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| "application/octet-stream".to_string());
        let original = evasion_result.request.body.clone().unwrap_or_default();
        match wafrift_evolution::body_padding::pad(&original, &ct, pad_target) {
            wafrift_evolution::body_padding::PadOutcome::Padded { bytes, added } => {
                evasion_result.request.body = Some(bytes);
                debug!(
                    host = %host,
                    added,
                    target = pad_target,
                    "body padding applied"
                );
            }
            wafrift_evolution::body_padding::PadOutcome::SkippedOpaque => {
                trace!(host = %host, content_type = %ct, "body padding skipped: opaque content-type");
            }
            wafrift_evolution::body_padding::PadOutcome::SkippedTooSmall => {
                // Already warned at startup; nothing to do per-request.
            }
        }
    }

    // ── Upstream fetch ──────────────────────────────────────────────
    // Two paths: default rustls via reqwest, or stealth (browser-
    // identical TLS) via wafrift_transport::stealth::StealthClient
    // when `--tls-impersonate <profile>` was set at startup.
    // Both paths converge on (response_builder, buf) so the rest of
    // this function (signal classification, header tagging, body
    // re-emit) stays unified.
    let conn_fwd = collect_connection_header_names(&evasion_result.request.headers);
    let max = limits.max_upstream_response_bytes;

    let status_code: u16;
    let (mut response_builder, buf) = if let Some(sc) = stealth() {
        let mut filtered_headers = Vec::with_capacity(evasion_result.request.headers.len());
        for (k, v) in &evasion_result.request.headers {
            if k.eq_ignore_ascii_case("host")
                || k.eq_ignore_ascii_case("content-length")
                || should_strip_proxy_header(k, &conn_fwd)
            {
                continue;
            }
            filtered_headers.push((k.clone(), v.clone()));
        }
        let stealth_resp = match sc
            .send(
                evasion_result.request.method.as_str(),
                &evasion_result.request.url,
                &filtered_headers,
                evasion_result.request.body.as_deref(),
                max,
            )
            .await
        {
            Ok(r) => r,
            Err(e) => {
                if let Some(throttle) = WARN_THROTTLE.get()
                    && throttle.should_warn(&format!("forward:{host}"))
                {
                    warn!(host = %host, error = %e, stack = "stealth", "forwarding failed");
                }
                return Ok(error_response(StatusCode::BAD_GATEWAY, "forwarding error"));
            }
        };
        status_code = stealth_resp.status;
        let mut response_builder = Response::builder().status(stealth_resp.status);
        // Build a HashSet view of Connection header tokens for stripping.
        let conn_resp: std::collections::HashSet<String> = stealth_resp
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("connection"))
            .map(|(_, v)| {
                v.split(',')
                    .map(|t| t.trim().to_ascii_lowercase())
                    .filter(|t| !t.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        for (k, v) in &stealth_resp.headers {
            if should_strip_proxy_header(k, &conn_resp) {
                continue;
            }
            response_builder = response_builder.header(k.as_str(), v.as_str());
        }
        (response_builder, stealth_resp.body.to_vec())
    } else {
        // Existing reqwest path (default).
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
        for (k, v) in &evasion_result.request.headers {
            if k.eq_ignore_ascii_case("host")
                // Strip Content-Length: evasion may have mutated the body. Reqwest
                // recalculates the correct length from the body bytes; a stale
                // CL header would mismatch and either smuggle or truncate.
                || k.eq_ignore_ascii_case("content-length")
                || should_strip_proxy_header(k, &conn_fwd)
            {
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
                if let Some(throttle) = WARN_THROTTLE.get()
                    && throttle.should_warn(&format!("forward:{host}"))
                {
                    warn!(host = %host, error = %e, "forwarding failed");
                }
                // S3 fix: Do not leak internal errors to external callers
                return Ok(error_response(StatusCode::BAD_GATEWAY, "forwarding error"));
            }
        };
        let status = resp.status();
        status_code = status.as_u16();
        let conn_resp = collect_connection_header_names_hyper(resp.headers());
        let mut response_builder = Response::builder().status(status.as_u16());
        for (k, v) in resp.headers().iter() {
            if should_strip_proxy_header(k.as_str(), &conn_resp) {
                continue;
            }
            response_builder = response_builder.header(k, v);
        }
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
        (response_builder, buf)
    };

    // ── Rich response classification ────────────────────────────────
    // Classify the upstream response through loaded WAF profiles
    // (rules/responses/*.toml). The signal distinguishes hard blocks,
    // soft blocks (200+block-page), rate limits, and JS challenges —
    // each gets different treatment by record_signal below. This
    // replaces the binary is_waf_block check.
    let header_pairs: Vec<(String, String)> = response_builder
        .headers_ref()
        .map(|hm| {
            hm.iter()
                .map(|(k, v)| {
                    (
                        k.as_str().to_string(),
                        v.to_str().unwrap_or_default().to_string(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let signal = response_profiles.classify(status_code, &header_pairs, &buf);
    let is_block = signal.classification.is_blocked();

    // ── WAF identification: which product is in front of us? ────────
    // The response signal may have already identified the WAF from a
    // loaded profile. If not, fall back to wafrift-detect's
    // header/body fingerprint database (160+ vendor rules).
    let detected_waf = {
        let st = state.lock().await;
        st.hosts.get(&host).and_then(|h| h.waf_name.clone())
    };
    if detected_waf.is_none() {
        if let Some(ref waf_name) = signal.matched_waf {
            let mut st = state.lock().await;
            if let Some(hs) = st.hosts.get_mut(&host) {
                hs.confirm_waf(Some(waf_name.clone()));
                info!(
                    host = %host,
                    waf = %waf_name,
                    source = "response_profile",
                    "WAF identified"
                );
            }
        } else {
            let body_slice = &buf[..buf.len().min(8192)];
            let detections =
                wafrift_detect::waf_detect::detect(status_code, &header_pairs, body_slice);
            if let Some(top) = detections.first()
                && top.confidence >= wafrift_detect::waf_detect::ACTIONABLE_CONFIDENCE_THRESHOLD
            {
                let mut st = state.lock().await;
                if let Some(hs) = st.hosts.get_mut(&host) {
                    hs.confirm_waf(Some(top.name.clone()));
                    info!(
                        host = %host,
                        waf = %top.name,
                        confidence = top.confidence,
                        source = "wafrift_detect",
                        "WAF identified"
                    );
                }
            }
        }
    }

    // ── Feedback loop: rich signal replaces binary block/pass ────────
    // Key insight: a 429 (rate limit) is NOT a technique failure —
    // the WAF is saying "slow down," not "I caught your payload."
    // Same for JS challenges. Only HardBlock and SoftBlock penalize
    // the current evasion technique. record_signal also ingests the
    // matched profile's prioritize/avoid lists so future requests
    // bias toward techniques known to bypass this WAF.
    {
        let mut st = state.lock().await;
        if let Some(hs) = st.hosts.get_mut(&host) {
            hs.record_signal(
                signal.classification == BlockClass::HardBlock,
                signal.classification == BlockClass::SoftBlock,
                signal.classification == BlockClass::RateLimit,
                signal.classification == BlockClass::Challenge,
                signal.matched_waf.as_deref(),
                &signal.prioritize,
                &signal.avoid,
                signal.inspection_model.as_deref(),
                &technique_keys,
            );

            // Success attribution: on Pass, credit the active technique(s).
            if signal.classification == BlockClass::Pass {
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

            if signal.classification.should_backoff() {
                info!(
                    host = %host,
                    classification = ?signal.classification,
                    "WAF rate limit / challenge — backing off, not changing technique"
                );
            }
        }
        if is_block {
            st.total_blocks = st.total_blocks.saturating_add(1);
        } else {
            for t in &evasion_result.techniques {
                let name = t.to_string();
                *st.techniques_used.entry(name).or_insert(0) += 1;
            }
        }
    }

    // ── Inject response tagging headers ──────────────────────────────
    // These are visible in Burp, browser devtools, and curl -v so the
    // practitioner immediately knows what WafRift did to this request.
    if !technique_keys.is_empty() {
        response_builder = response_builder.header(X_WAFRIFT_TECHNIQUES, technique_keys.join(", "));
    }
    response_builder =
        response_builder.header(X_WAFRIFT_BLOCKED, if is_block { "true" } else { "false" });

    // Emit a TUI event so the dashboard can update — skipped silently
    // when --tui isn't on (TUI_TX is None). The send is non-blocking
    // and ignores backpressure: a full-channel failure must not slow
    // the proxy hot path.
    {
        let path_only = request_log_uri
            .split('?')
            .next()
            .unwrap_or(&request_log_uri)
            .to_string();
        let body_padded = wafrift_evolution::body_padding::looks_padded(
            evasion_result.request.body.as_deref().unwrap_or(&[]),
        );
        let tls_profile = stealth().map(|sc| sc.profile().name().to_string());
        let bypassed = !is_block && !evasion_result.techniques.is_empty();
        emit_tui(wafrift_proxy::tui::Event::Request {
            host: host.clone(),
            method: evasion_result.request.method.as_str().to_string(),
            path: path_only,
            status: status_code,
            bypassed,
            blocked: is_block,
            techniques: technique_keys.join(", "),
            tls_profile,
            body_padded,
            upstream_latency_ms: 0,
        });
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
    scope: Arc<ScopeFilter>,
    rate_limiter: Arc<RateLimiter>,
    response_profiles: Arc<ResponseProfileDb>,
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

    // Limit body collection up front — without this, an attacker
    // streaming an unbounded body would exhaust proxy memory before
    // any post-collection size check could fire.
    let limited = Limited::new(req.body_mut(), MAX_PROXY_BODY_BYTES);
    let body_bytes = match limited.collect().await {
        Ok(b) => b.to_bytes().to_vec(),
        Err(_) => {
            if let Some(throttle) = WARN_THROTTLE.get()
                && throttle.should_warn(&format!("body-limit:{host}"))
            {
                warn!(host = %host, limit = MAX_PROXY_BODY_BYTES, "request body exceeded size limit");
            }
            return Ok(error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body too large",
            ));
        }
    };

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

    let mut wafrift_req = wafrift_types::Request::with_method(
        wafrift_types::Method::from(req.method().as_str()),
        url,
    );
    wafrift_req.headers = headers;
    if !body_bytes.is_empty() {
        wafrift_req.body = Some(body_bytes);
    }

    let log_uri = wafrift_req.url.clone();

    // Per-host rate limit applies to BOTH evade and passthrough paths —
    // it bounds raw request volume hitting the upstream.
    rate_limiter.acquire(&host).await;

    let path_for_scope = req
        .uri()
        .path_and_query()
        .map(|p| p.path().to_string())
        .unwrap_or_else(|| "/".to_string());
    if !scope.allows(&host, &path_for_scope, &wafrift_req.method) {
        return forward_passthrough(wafrift_req, host, &client, policy, limits).await;
    }

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
        response_profiles,
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
    scope: Arc<ScopeFilter>,
    rate_limiter: Arc<RateLimiter>,
    response_profiles: Arc<ResponseProfileDb>,
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
    let svc_scope = scope.clone();
    let svc_rl = rate_limiter.clone();
    let svc_profiles = response_profiles.clone();
    let cauth = connect_authority.clone();

    let service = service_fn(move |req: Request<Incoming>| {
        let state = svc_state.clone();
        let config = svc_config.clone();
        let default_escalation = svc_default_esc.clone();
        let client = svc_client.clone();
        let policy = svc_policy.clone();
        let limits = svc_limits.clone();
        let scope = svc_scope.clone();
        let rate_limiter = svc_rl.clone();
        let response_profiles = svc_profiles.clone();
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
                scope,
                rate_limiter,
                response_profiles,
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
    scope: Arc<ScopeFilter>,
    rate_limiter: Arc<RateLimiter>,
    expose_wafrift_status: bool,
    logger: SharedLogger,
    response_profiles: Arc<ResponseProfileDb>,
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
                let scope = scope.clone();
                let rate_limiter = rate_limiter.clone();
                let response_profiles = response_profiles.clone();
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
                                scope,
                                rate_limiter,
                                response_profiles,
                            )
                            .await
                            {
                                warn!("mitm session error: {e:?}");
                            }
                        }
                        Err(e) => warn!("upgrade error: {}", e),
                    }
                });
            } else {
                // Plain HTTPS tunnel — wafrift only sees encrypted bytes
                // and CANNOT apply evasion. Throttled per-host info log
                // so the practitioner notices the gap without spamming
                // every CONNECT (each tunnel hits this branch once).
                if let Some(throttle) = WARN_THROTTLE.get()
                    && throttle.should_warn(&format!("connect-passthrough:{addr}"))
                {
                    info!(
                        target = %addr,
                        "CONNECT pass-through (no MITM): bytes are TLS-encrypted, evasion engine inactive. \
                         Pass `--mitm` to terminate TLS and apply evasion to HTTPS request bodies."
                    );
                }
                tokio::task::spawn(async move {
                    match hyper::upgrade::on(req).await {
                        Ok(upgraded) => {
                            if let Err(e) = tunnel(upgraded, addr).await {
                                warn!("server io error: {}", e);
                            };
                        }
                        Err(e) => warn!("upgrade error: {}", e),
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

    // Live findings endpoint — returns the current gene-bank as a
    // markdown report. Same loopback gating as /_wafrift/status. Lets
    // a practitioner `curl http://127.0.0.1:8080/_wafrift/findings.md`
    // mid-session without dropping out to a separate `wafrift report`
    // invocation.
    if req.uri().path() == "/_wafrift/findings.md" {
        if !expose_wafrift_status {
            return Ok(error_response(StatusCode::NOT_FOUND, "not found"));
        }
        let st = state.lock().await;
        let md = render_live_findings(&st);
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/markdown; charset=utf-8")
            .body(Full::new(Bytes::from(md)))
            .unwrap_or_else(|_| {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to build findings response",
                )
            }));
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

    // Read body — bounded by MAX_PROXY_BODY_BYTES at stream-read time
    // so an unbounded streaming body can't exhaust proxy memory before
    // a post-collection size check could fire.
    let limited = Limited::new(req.body_mut(), MAX_PROXY_BODY_BYTES);
    let body_bytes = match limited.collect().await {
        Ok(b) => b.to_bytes().to_vec(),
        Err(_) => {
            if let Some(throttle) = WARN_THROTTLE.get()
                && throttle.should_warn(&format!("body-limit:{host}"))
            {
                warn!(host = %host, limit = MAX_PROXY_BODY_BYTES, "request body exceeded size limit");
            }
            return Ok(error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body too large",
            ));
        }
    };

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

    let mut wafrift_req = wafrift_types::Request::with_method(
        wafrift_types::Method::from(req.method().as_str()),
        req.uri().to_string(),
    );
    wafrift_req.headers = headers;
    if !body_bytes.is_empty() {
        wafrift_req.body = Some(body_bytes);
    }

    let log_uri = req.uri().to_string();

    // ── Per-request evasion control via X-WafRift-Evade header ──────
    // Strip the header before forwarding — it's for the proxy, not upstream.
    let evade_override = wafrift_req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(X_WAFRIFT_EVADE))
        .map(|(_, v)| v.to_ascii_lowercase());
    wafrift_req
        .headers
        .retain(|(k, _)| !k.eq_ignore_ascii_case(X_WAFRIFT_EVADE));

    rate_limiter.acquire(&host).await;

    let path_for_scope = req
        .uri()
        .path_and_query()
        .map(|p| p.path().to_string())
        .unwrap_or_else(|| "/".to_string());

    // X-WafRift-Evade: off  → skip evasion entirely for this request
    let skip_evasion = evade_override.as_deref() == Some("off");
    if skip_evasion || !scope.allows(&host, &path_for_scope, &wafrift_req.method) {
        debug!(host = %host, uri = %log_uri, "evasion skipped (off/out-of-scope)");
        let resp = forward_passthrough(wafrift_req, host.clone(), &client, policy, limits).await;
        if let (Ok(r), Some(log)) = (&resp, &logger) {
            log.log_entry(&serde_json::json!({
                "ts": time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
                "host": host,
                "method": req.method().as_str(),
                "url": log_uri,
                "evaded": false,
                "status": r.status().as_u16(),
            }))
            .await;
        }
        return resp;
    }

    // X-WafRift-Evade: light/medium/heavy → override escalation for this request
    let effective_escalation = match evade_override.as_deref() {
        Some("light") | Some("medium") | Some("heavy") => evade_override,
        _ => default_escalation,
    };

    let resp = forward_with_evade_retry(
        wafrift_req,
        host.clone(),
        log_uri.clone(),
        state,
        config,
        effective_escalation,
        &client,
        policy,
        limits,
        response_profiles,
    )
    .await;

    // ── Log the request/response ────────────────────────────────────
    if let (Ok(r), Some(log)) = (&resp, &logger) {
        let techniques: Vec<&str> = r
            .headers()
            .get(X_WAFRIFT_TECHNIQUES)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(", ").collect())
            .unwrap_or_default();
        let blocked = r
            .headers()
            .get(X_WAFRIFT_BLOCKED)
            .and_then(|v| v.to_str().ok())
            == Some("true");
        log.log_entry(&serde_json::json!({
            "ts": time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
            "host": host,
            "method": req.method().as_str(),
            "url": log_uri,
            "evaded": true,
            "techniques": techniques,
            "status": r.status().as_u16(),
            "blocked": blocked,
        }))
        .await;
    }

    resp
}

/// Forward a request verbatim with no evasion, no gene-bank update,
/// no detection. Used when the request is out of the configured scope
/// (e.g. login flows, oauth callbacks, static assets) so the practitioner
/// can browse normally with the proxy in front of Burp.
///
/// SSRF policy still applies — out-of-scope is a *behavioural* opt-out,
/// not an authorisation bypass.
async fn forward_passthrough(
    req: wafrift_types::Request,
    host: String,
    client: &reqwest::Client,
    policy: Arc<UpstreamPolicy>,
    limits: Arc<ProxyLimits>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Err(msg) = assert_forward_url_allowed(&req.url, &policy).await {
        warn!(host = %host, url = %req.url, "{}", msg);
        return Ok(error_response(StatusCode::FORBIDDEN, &msg));
    }

    // Same dual-path fetch as forward_wafrift_request: stealth via
    // `STEALTH_CLIENT` if `--tls-impersonate <profile>` was set,
    // else default reqwest path.
    let conn_fwd = collect_connection_header_names(&req.headers);
    let max = limits.max_upstream_response_bytes;

    let (response_builder, buf) = if let Some(sc) = stealth() {
        let mut filtered_headers = Vec::with_capacity(req.headers.len());
        for (k, v) in &req.headers {
            if k.eq_ignore_ascii_case("host")
                || k.eq_ignore_ascii_case("content-length")
                || should_strip_proxy_header(k, &conn_fwd)
            {
                continue;
            }
            filtered_headers.push((k.clone(), v.clone()));
        }
        let stealth_resp = match sc
            .send(
                req.method.as_str(),
                &req.url,
                &filtered_headers,
                req.body.as_deref(),
                max,
            )
            .await
        {
            Ok(r) => r,
            Err(e) => {
                if let Some(throttle) = WARN_THROTTLE.get()
                    && throttle.should_warn(&format!("passthrough:{host}"))
                {
                    warn!(host = %host, error = %e, stack = "stealth", "passthrough forwarding failed");
                }
                return Ok(error_response(StatusCode::BAD_GATEWAY, "forwarding error"));
            }
        };
        let mut response_builder = Response::builder().status(stealth_resp.status);
        let conn_resp: std::collections::HashSet<String> = stealth_resp
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("connection"))
            .map(|(_, v)| {
                v.split(',')
                    .map(|t| t.trim().to_ascii_lowercase())
                    .filter(|t| !t.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        for (k, v) in &stealth_resp.headers {
            if should_strip_proxy_header(k, &conn_resp) {
                continue;
            }
            response_builder = response_builder.header(k.as_str(), v.as_str());
        }
        (response_builder, stealth_resp.body.to_vec())
    } else {
        let method = match reqwest::Method::from_bytes(req.method.as_str().as_bytes()) {
            Ok(m) => m,
            Err(_) => {
                return Ok(error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid HTTP method",
                ));
            }
        };
        let mut builder = client.request(method, &req.url);
        for (k, v) in &req.headers {
            if k.eq_ignore_ascii_case("host")
                || k.eq_ignore_ascii_case("content-length")
                || should_strip_proxy_header(k, &conn_fwd)
            {
                continue;
            }
            builder = builder.header(k.as_str(), v.as_str());
        }
        if let Some(b) = req.body {
            builder = builder.body(b);
        }
        let resp = match builder.send().await {
            Ok(r) => r,
            Err(e) => {
                if let Some(throttle) = WARN_THROTTLE.get()
                    && throttle.should_warn(&format!("passthrough:{host}"))
                {
                    warn!(host = %host, error = %e, "passthrough forwarding failed");
                }
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
        (response_builder, buf)
    };

    Ok(response_builder
        .body(Full::new(Bytes::from(buf)))
        .unwrap_or_else(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to build response",
            )
        }))
}

/// Render an ad-hoc markdown findings report from the current proxy
/// state. Used by the `/_wafrift/findings.md` endpoint so practitioners
/// can `curl` a writeup mid-session without exporting + re-importing
/// through the gene bank file.
fn render_live_findings(state: &ProxyState) -> String {
    let mut out = String::new();
    out.push_str("# wafrift live findings\n\n");
    out.push_str(&format!(
        "Total proxied: {} · Total WAF blocks observed: {} · Hosts seen: {}\n\n",
        state.total_scanned,
        state.total_blocks,
        state.hosts.len(),
    ));

    if state.total_scanned == 0 {
        out.push_str("No requests have been proxied yet. Send traffic through the proxy to begin evasion discovery.\n");
        return out;
    }

    let mut hosts_with_winners: Vec<(&String, &HostState)> = state
        .hosts
        .iter()
        .filter(|(_, hs)| !hs.proven_winners.is_empty())
        .collect();
    hosts_with_winners.sort_by(|a, b| a.0.cmp(b.0));

    if hosts_with_winners.is_empty() {
        out.push_str("_No bypasses discovered yet — keep traffic flowing through the proxy. Blocks are being recorded and will inform technique selection._\n");
        return out;
    }

    out.push_str("## Hosts with proven bypasses\n\n");
    for (host, hs) in hosts_with_winners {
        // Hostnames come from Host headers — attacker-controllable in
        // every relevant threat model. If a host contains backticks,
        // pipes, or asterisks, they'd be interpreted as markdown
        // formatting (or worse, raw HTML in renderers that allow it)
        // and the local /_wafrift/findings.md endpoint would become a
        // stored-markdown-injection sink. Sanitise to the printable-
        // ASCII subset of valid host characters before interpolating.
        let host_md = sanitize_for_markdown(host);
        let waf_md = hs.waf_name.as_deref().map(sanitize_for_markdown);
        out.push_str(&format!("### `{host_md}`\n\n"));
        if let Some(waf) = &waf_md {
            out.push_str(&format!("**Identified WAF:** {waf}\n\n"));
        }
        out.push_str("**Working techniques:**\n\n");
        for t in &hs.proven_winners {
            out.push_str(&format!("- `{}`\n", sanitize_for_markdown(t)));
        }
        out.push('\n');
        out.push_str(&format!(
            "**Reproduce:** `wafrift replay --target 'https://{host_md}/<PATH>' --param q --payload '<PAYLOAD>' --from-host '{host_md}'`\n\n",
        ));
    }
    out
}

/// Replace markdown- and shell-special characters with `_` so attacker-
/// controlled strings (host headers, technique pool keys round-tripped
/// through gene bank) cannot break out of the rendered markdown.
fn sanitize_for_markdown(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '/' | '+' | '@') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Extract the host:port from a URI authority.
fn host_addr(uri: &hyper::Uri) -> Option<String> {
    uri.authority().map(|auth| auth.to_string())
}

/// Cap on bytes transferred per direction per CONNECT tunnel. Prevents
/// a client from streaming gigabytes through the proxy under a single
/// CONNECT — without this, `copy_bidirectional` runs unbounded and
/// MAX_PROXY_BODY_BYTES / max_upstream_response_bytes (which guard the
/// HTTP-mode paths) do not apply. 2 GiB is generous for legitimate
/// long-lived TLS sessions while still blocking sustained exfil.
const MAX_TUNNEL_BYTES_PER_DIRECTION: u64 = 2 * 1024 * 1024 * 1024;

/// Bidirectional tunnel for CONNECT (HTTPS pass-through). Per-direction
/// byte counter aborts the copy when either side exceeds the cap.
async fn tunnel(upgraded: Upgraded, addr: String) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut server = TcpStream::connect(addr).await?;
    let mut upgraded = TokioIo::new(upgraded);
    let (mut up_r, mut up_w) = tokio::io::split(&mut upgraded);
    let (mut sv_r, mut sv_w) = server.split();

    // Each direction owns its own bounded copy loop. When either trips
    // the byte cap, drop both halves and return a clean error.
    let to_server = async {
        let mut buf = vec![0u8; 16 * 1024];
        let mut total: u64 = 0;
        loop {
            let n = up_r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            total = total.saturating_add(n as u64);
            if total > MAX_TUNNEL_BYTES_PER_DIRECTION {
                return Err(std::io::Error::other(
                    "tunnel exceeded byte cap (client→server)",
                ));
            }
            sv_w.write_all(&buf[..n]).await?;
        }
        Ok::<(), std::io::Error>(())
    };
    let to_client = async {
        let mut buf = vec![0u8; 16 * 1024];
        let mut total: u64 = 0;
        loop {
            let n = sv_r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            total = total.saturating_add(n as u64);
            if total > MAX_TUNNEL_BYTES_PER_DIRECTION {
                return Err(std::io::Error::other(
                    "tunnel exceeded byte cap (server→client)",
                ));
            }
            up_w.write_all(&buf[..n]).await?;
        }
        Ok::<(), std::io::Error>(())
    };
    tokio::try_join!(to_server, to_client)?;
    Ok(())
}

#[cfg(test)]
#[path = "proxy_tests.rs"]
mod tests;
