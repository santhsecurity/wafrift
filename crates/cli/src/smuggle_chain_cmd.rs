//! `wafrift smuggle-chain` — N-way smuggle-probe composition CLI.
//!
//! Takes 2+ `--family <NAME>` flags and emits the cartesian product
//! of probes across all N families as composed JSON artifacts. The
//! N-way generalisation of `smuggle-cross-product`.
//!
//! Example: `wafrift smuggle-chain --family cookie --family auth --family range`
//! emits 7 × 8 × 8 = 448 composed artifacts (capped at 64 by
//! default; raise via `--cap`).
//!
//! Each emitted line has the shape:
//!
//! ```json
//! {
//!   "techniques": ["cookie.x", "auth.y", "range.z"],
//!   "canaries": ["abc...", "def...", "ghi..."],
//!   "headers": [["Cookie","..."],["Authorization","..."],["Range","..."]],
//!   "body": null,
//!   "frames": []
//! }
//! ```

use clap::Parser;
use std::io::Write;
use std::process::ExitCode;

use wafrift_core::probe_aggregator::{ProbeSeeds, all_probes};
use wafrift_types::probe::{SmuggleProbe, compose_n_product};

use crate::permission;
use crate::smuggle_transport;

#[derive(Debug, Parser)]
pub struct SmuggleChainArgs {
    /// Family prefix to include in the chain (repeatable). Order
    /// determines the artifact composition order. At least 2
    /// families required — for 2-family chains, prefer
    /// `smuggle-cross-product` (which has the same shape but
    /// dedicated `--lhs/--rhs` flag names).
    #[arg(long = "family", num_args = 1.., value_name = "FAMILY", required = true)]
    pub families: Vec<String>,

    /// Cap on emitted composed artifacts. 0 = unlimited. Default
    /// 64 — a 3-way chain across families of 8 probes each is
    /// already 512 composed artifacts and grows polynomially.
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

    /// Form params for multipart / JSON smuggle.
    #[arg(long, default_value = "user=admin&token=wafrift-test-token")]
    pub form: String,

    /// Protected path seed for path-normalize probes.
    #[arg(long, default_value = "/admin")]
    pub protected_path: String,

    /// Protected hostname seed for host-header probes.
    #[arg(long, default_value = "admin.example.com")]
    pub protected_host: String,

    /// Pretty-print JSON output across multiple lines.
    #[arg(long)]
    pub pretty: bool,

    /// When set, splice `(NAME, canary)` pairs into each composed
    /// artifact's `headers` — one per merged probe canary. Operators
    /// set this to e.g. `X-Wafrift-Canary` so OOB callbacks land
    /// already tagged with all component techniques' canaries. In
    /// `--fire-target` mode the response headers and body are also
    /// scanned for these tokens — a verbatim echo yields the
    /// `canary-reflected` signal and matching tokens appear in
    /// `reflected_canaries`.
    #[arg(long, default_value = "", value_name = "HEADER_NAME")]
    pub canary_header: String,

    /// Fire each composed N-way chain as a real HTTP request
    /// against this URL. Replaces JSON emission with
    /// `ComposedFireReport`s. Requires `--i-have-permission` for
    /// non-allowlisted hosts.
    #[arg(long, value_name = "URL", default_value = "")]
    pub fire_target: String,

    /// Authorization gate for non-allowlist `--fire-target` hosts.
    #[arg(long, value_name = "REASON")]
    pub i_have_permission: Option<String>,

    /// Per-request HTTP timeout (seconds).
    #[arg(long, default_value_t = wafrift_types::DEFAULT_SMUGGLE_FIRE_TIMEOUT_SECS)]
    pub timeout_secs: u64,

    /// Inter-request delay (ms) in sequential fire mode.
    #[arg(long, default_value_t = wafrift_types::DEFAULT_SMUGGLE_FIRE_DELAY_MS)]
    pub delay_ms: u64,

    /// Concurrent fires. 1 = sequential.
    #[arg(long, default_value_t = wafrift_types::DEFAULT_SMUGGLE_FIRE_PARALLEL)]
    pub parallel: usize,

    /// Body-length divergence threshold (fraction).
    #[arg(long, default_value_t = wafrift_types::DEFAULT_SMUGGLE_BODY_DIVERGENCE_THRESHOLD)]
    pub body_divergence_threshold: f64,

    /// Include reproducer curl in each fire report.
    #[arg(long)]
    pub include_reproducer: bool,

    /// Suppress end-of-fire summary on stderr.
    #[arg(long)]
    pub no_summary: bool,
}

/// Run the subcommand. Exit codes: 0 on clean emit; 2 when any
/// family filter matches zero probes; 1 on JSON serialization
/// error.
pub fn run_smuggle_chain(args: SmuggleChainArgs) -> ExitCode {
    if args.families.len() < 2 {
        let _ = writeln!(
            std::io::stderr(),
            "wafrift smuggle-chain: need at least 2 --family flags (got {})",
            args.families.len()
        );
        return ExitCode::from(2);
    }

    let form_params = crate::helpers::parse_form_pairs(&args.form);

    // Build N independent probe lists (one per family). Each
    // call to `all_probes` regenerates fresh canaries; we filter
    // by family prefix per axis.
    let mut family_vecs: Vec<Vec<Box<dyn SmuggleProbe>>> = Vec::with_capacity(args.families.len());
    for family in &args.families {
        let seeds = ProbeSeeds {
            cookie_name: &args.cookie_name,
            credential_value: &args.credential,
            form_params: form_params.clone(),
            payload: args.payload.as_bytes().to_vec(),
            protected_path: &args.protected_path,
            protected_host: &args.protected_host,
        };
        let filtered: Vec<Box<dyn SmuggleProbe>> = all_probes(&seeds)
            .into_iter()
            .filter(|p| p.technique().starts_with(family))
            .collect();
        if filtered.is_empty() {
            let _ = writeln!(
                std::io::stderr(),
                "wafrift smuggle-chain: family {family:?} matched zero probes"
            );
            return ExitCode::from(2);
        }
        family_vecs.push(filtered);
    }

    // Convert owned Vecs to slice references for the primitive.
    let family_refs: Vec<&[Box<dyn SmuggleProbe>]> =
        family_vecs.iter().map(|v| v.as_slice()).collect();

    let composed = compose_n_product(&family_refs);
    if composed.is_empty() {
        let _ = writeln!(
            std::io::stderr(),
            "wafrift smuggle-chain: zero composed artifacts (one or more families empty)"
        );
        return ExitCode::from(2);
    }

    // Fire path: when --fire-target is set, fire each composed
    // N-way chain instead of emitting JSON.
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

    ExitCode::SUCCESS
}
