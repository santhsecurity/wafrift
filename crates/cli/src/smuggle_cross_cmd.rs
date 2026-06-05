//! `wafrift smuggle-cross-product` — emit the cartesian product of
//! two smuggle-probe families as composed JSON artifacts.
//!
//! For every probe in family X × every probe in family Y, emit one
//! [`ComposedArtifact`](wafrift_types::probe::ComposedArtifact)
//! carrying both probes' wire shapes merged into one. The output
//! exercises bypass-chain interactions that no single technique
//! produces (e.g. duplicate-Cookie × multipart preamble smuggle = a
//! request that smuggles two parser disagreements at once).
//!
//! Each emitted line has the shape:
//!
//! ```json
//! {
//!   "techniques": [
//!     "cookie.duplicate-name-last-wins",
//!     "auth.duplicate-header-first-wins-benign"
//!   ],
//!   "headers": [["Cookie","..."],["Authorization","..."]],
//!   "body": null,
//!   "frames": []
//! }
//! ```
//!
//! The output size is `|lhs| × |rhs|` — bound it with `--cap N`
//! (default 64) for sane scan budgets.

use clap::Parser;
use std::io::Write;
use std::process::ExitCode;

use wafrift_core::probe_aggregator::{ProbeSeeds, all_probes};
use wafrift_types::probe::{SmuggleProbe, compose_cross_product};

use crate::permission;
use crate::smuggle_transport;

#[derive(Debug, Parser)]
pub struct SmuggleCrossProductArgs {
    /// Family prefix for the left-hand side of the cross product
    /// (e.g. `cookie`). Empty (default) = every family.
    #[arg(long, default_value = "")]
    pub lhs: String,

    /// Family prefix for the right-hand side. Empty (default) =
    /// every family.
    #[arg(long, default_value = "")]
    pub rhs: String,

    /// Cap on the number of composed artifacts emitted. 0 = no cap.
    /// Default 64 — the full cross-product of two 10-probe families
    /// is 100 composed artifacts and grows quadratically.
    #[arg(long, default_value_t = wafrift_types::DEFAULT_SMUGGLE_COMPOSED_CAP)]
    pub cap: usize,

    /// Cookie / Authorization name seed.
    #[arg(long, default_value = "session")]
    pub cookie_name: String,

    /// Credential value seed.
    #[arg(long, default_value = "wafrift-test-token")]
    pub credential: String,

    /// Opaque payload seed.
    #[arg(long, default_value = "wafrift-smuggle-payload")]
    pub payload: String,

    /// Form params for multipart smuggle.
    #[arg(long, default_value = "user=admin&token=wafrift-test-token")]
    pub form: String,

    /// Protected path seed for path-normalize probes.
    #[arg(long, default_value = "/admin")]
    pub protected_path: String,

    /// Protected hostname seed for host-header probes.
    #[arg(long, default_value = "admin.example.com")]
    pub protected_host: String,

    /// Pretty-print each JSON object on multiple lines (default is
    /// one compact JSON per line — friendly to `jq -c` and streaming
    /// consumers).
    #[arg(long)]
    pub pretty: bool,

    /// When set, splice `(NAME, canary)` pairs into each composed
    /// artifact's `headers` — one per merged probe canary. Operators
    /// set this to e.g. `X-Wafrift-Canary` so OOB callbacks land
    /// already tagged with both component techniques' canaries
    /// (chain attribution is automatic). In `--fire-target` mode the
    /// response headers and body are also scanned for these tokens —
    /// a verbatim echo yields the `canary-reflected` signal and the
    /// matching tokens appear in each report's `reflected_canaries`.
    #[arg(long, default_value = "", value_name = "HEADER_NAME")]
    pub canary_header: String,

    /// Emit a ready-to-fire `curl` command per composed artifact
    /// targeting the supplied URL instead of JSON. Same as the
    /// `--curl-target` flag on `smuggle-emit` but operates on the
    /// composed wire shape. Composed artifacts containing only
    /// frames (no chain has those by default) are skipped with a
    /// stderr warning.
    #[arg(long, value_name = "URL", default_value = "")]
    pub curl_target: String,

    /// Fire each composed artifact as a real HTTP request against
    /// this URL. Replaces JSON emission with one
    /// `ComposedFireReport` per fired artifact (techniques/canaries
    /// arrays + status/body_len/latency + bypass_signal vs a
    /// baseline GET). Requires `--i-have-permission` for non-
    /// allowlisted hosts. Pair with `--canary-header X-Wafrift-Canary`
    /// for OOB attribution and `--include-reproducer` for paste-
    /// ready curl in each report.
    #[arg(long, value_name = "URL", default_value = "")]
    pub fire_target: String,

    /// Authorization gate for non-allowlist `--fire-target` hosts.
    /// Pass any non-empty justification (e.g. HackerOne ticket).
    #[arg(long, value_name = "REASON")]
    pub i_have_permission: Option<String>,

    /// Per-request HTTP timeout (seconds) in fire mode.
    #[arg(long, default_value_t = wafrift_types::DEFAULT_SMUGGLE_FIRE_TIMEOUT_SECS)]
    pub timeout_secs: u64,

    /// Inter-request delay (ms) in sequential fire mode.
    #[arg(long, default_value_t = wafrift_types::DEFAULT_SMUGGLE_FIRE_DELAY_MS)]
    pub delay_ms: u64,

    /// Concurrent fires in fire mode. 1 = sequential.
    #[arg(long, default_value_t = wafrift_types::DEFAULT_SMUGGLE_FIRE_PARALLEL)]
    pub parallel: usize,

    /// Body-length divergence threshold (fraction) for the fire
    /// `bypass_signal` classification. 0.05 = 5% delta.
    #[arg(long, default_value_t = wafrift_types::DEFAULT_SMUGGLE_BODY_DIVERGENCE_THRESHOLD)]
    pub body_divergence_threshold: f64,

    /// When set, include a `reproducer_curl` field in each fire
    /// report carrying the single-line bash-pasteable curl that
    /// reproduces the composed request.
    #[arg(long)]
    pub include_reproducer: bool,

    /// Suppress the end-of-fire summary on stderr.
    #[arg(long)]
    pub no_summary: bool,
}

/// Run the subcommand. Exit codes: 0 on clean emit; 2 when either
/// side of the product matches zero probes or zero composed
/// artifacts were emitted (filtered to nothing).
pub fn run_smuggle_cross_product(args: SmuggleCrossProductArgs) -> ExitCode {
    let form_params = crate::helpers::parse_form_pairs(&args.form);
    // Each side regenerates from a fresh seed copy so the
    // canaries are independent across lhs/rhs. The aggregator
    // returns boxed dyn SmuggleProbe — we can't clone trait
    // objects, so we generate twice and filter each.
    let seeds_lhs = ProbeSeeds {
        cookie_name: &args.cookie_name,
        credential_value: &args.credential,
        form_params: form_params.clone(),
        payload: args.payload.as_bytes().to_vec(),
        protected_path: &args.protected_path,
        protected_host: &args.protected_host,
    };
    let seeds_rhs = ProbeSeeds {
        cookie_name: &args.cookie_name,
        credential_value: &args.credential,
        form_params,
        payload: args.payload.as_bytes().to_vec(),
        protected_path: &args.protected_path,
        protected_host: &args.protected_host,
    };

    let lhs: Vec<Box<dyn SmuggleProbe>> = all_probes(&seeds_lhs)
        .into_iter()
        .filter(|p| args.lhs.is_empty() || p.technique().starts_with(&args.lhs))
        .collect();
    let rhs: Vec<Box<dyn SmuggleProbe>> = all_probes(&seeds_rhs)
        .into_iter()
        .filter(|p| args.rhs.is_empty() || p.technique().starts_with(&args.rhs))
        .collect();

    if lhs.is_empty() || rhs.is_empty() {
        let _ = writeln!(
            std::io::stderr(),
            "wafrift smuggle-cross-product: lhs={:?} rhs={:?} matched no probes (lhs={}, rhs={})",
            args.lhs,
            args.rhs,
            lhs.len(),
            rhs.len()
        );
        return ExitCode::from(2);
    }

    let composed = compose_cross_product(&lhs, &rhs);

    // Fire path: when --fire-target is set, fire each composed
    // artifact instead of emitting JSON. The composed-fire
    // pipeline in smuggle_transport handles permission, baseline,
    // classification, summary.
    if !args.fire_target.is_empty() {
        permission::assert_permitted(&args.fire_target, args.i_have_permission.as_deref());
        let cfg = smuggle_transport::ComposedFireConfig {
            target: &args.fire_target,
            timeout_secs: args.timeout_secs,
            baseline_method: "GET",
            baseline_body: &[],
            baseline_headers: &[],
            canary_header: &args.canary_header,
            cap: args.cap,
            delay_ms: args.delay_ms,
            parallel: args.parallel,
            body_divergence_threshold: args.body_divergence_threshold,
            include_reproducer: args.include_reproducer,
            no_summary: args.no_summary,
        };
        return crate::helpers::block_on_with_runtime(smuggle_transport::fire_composed_pipeline(
            &composed, &cfg,
        ));
    }

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut emitted = 0usize;
    for c in &composed {
        if args.cap > 0 && emitted >= args.cap {
            break;
        }
        // Optionally splice canary headers — one (NAME, canary) per
        // merged probe. Pre-pended so they sit at the top of the
        // composed header block and operators can find them by
        // searching for the chosen name.
        let mut emitted_artifact = c.clone();
        if !args.canary_header.is_empty() {
            let mut canary_pairs: Vec<(String, String)> = emitted_artifact
                .canaries
                .iter()
                .map(|t| (args.canary_header.clone(), t.clone()))
                .collect();
            canary_pairs.append(&mut emitted_artifact.headers);
            emitted_artifact.headers = canary_pairs;
        }
        if !args.curl_target.is_empty() {
            let line = render_composed_curl(&emitted_artifact, &args.curl_target);
            let _ = writeln!(out, "{line}");
            emitted += 1;
            continue;
        }
        let line = if args.pretty {
            serde_json::to_string_pretty(&emitted_artifact)
        } else {
            serde_json::to_string(&emitted_artifact)
        };
        match line {
            Ok(s) => {
                let _ = writeln!(out, "{s}");
                emitted += 1;
            }
            Err(e) => {
                let _ = writeln!(std::io::stderr(), "serialize error: {e}");
                return ExitCode::from(1);
            }
        }
    }

    if emitted == 0 {
        let _ = writeln!(
            std::io::stderr(),
            "wafrift smuggle-cross-product: zero composed artifacts emitted"
        );
        return ExitCode::from(2);
    }
    ExitCode::SUCCESS
}

/// Render a [`wafrift_types::probe::ComposedArtifact`] as a single-
/// line `curl` command targeting `url`, via the shared
/// [`crate::helpers::render_curl_parts`] core so this and the
/// artifact-shaped emitter cannot diverge. Composed headers go via
/// `-H`, a `:path` pseudo-header splices into the URL path (matching
/// the fire path), and the body (if any) rides `--data-binary` after
/// its `Content-Type` header. Frames are not representable as curl and
/// are omitted — composed fire artifacts carry none.
fn render_composed_curl(c: &wafrift_types::probe::ComposedArtifact, url: &str) -> String {
    let method = if c.body.is_some() { "POST" } else { "GET" };
    let mut headers = c.headers.clone();
    let body = if let Some((ct, b)) = &c.body {
        headers.push(("Content-Type".to_string(), ct.clone()));
        Some(b.as_slice())
    } else {
        None
    };
    crate::helpers::render_curl_parts(method, url, &headers, body)
}
