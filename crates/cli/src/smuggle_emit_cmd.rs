//! `wafrift smuggle-emit` — JSON probe artifact emitter.
//!
//! Lists every wafrift smuggle probe (across the 11 families covered by
//! the workspace-wide `SmuggleProbe` trait) as JSON, one per line.
//! Operators pipe to `jq` / Splunk / Burp / `xargs curl` to drive
//! probes through any HTTP client that can read JSON.
//!
//! Each emitted line has the shape:
//!
//! ```json
//! {
//!   "canary": "abc123XYZ...",
//!   "technique": "cookie.duplicate-name-last-wins",
//!   "description": "Duplicate-name cookie pair — first/last resolution differential",
//!   "artifact": {"kind":"headers","Headers":[["Cookie","name=safe; name=evil"]]}
//! }
//! ```
//!
//! The `--family` flag filters to probes whose technique starts with
//! a given prefix (`cookie`, `auth`, `range`, `path`, `host`, `jwt`,
//! `content-type`, `json`, `capsule`, `quic-datagram`,
//! `compression`).

use clap::Parser;
use std::io::Write;
use std::process::ExitCode;

use wafrift_core::probe_aggregator::{ProbeSeeds, all_probes};

#[derive(Debug, Parser)]
pub struct SmuggleEmitArgs {
    /// Optional family prefix to filter probes — e.g. `cookie`,
    /// `auth`, `range`, `path`, `host`, `jwt`, `content-type`,
    /// `json`, `capsule`, `quic-datagram`, `compression`. Empty
    /// (default) emits every probe across every family.
    #[arg(long, default_value = "")]
    pub family: String,

    /// Cookie/Authorization name to splice into the credential
    /// probes (default `session`).
    #[arg(long, default_value = "session")]
    pub cookie_name: String,

    /// Credential value to splice into cookie / auth probes
    /// (default `wafrift-test-token`).
    #[arg(long, default_value = "wafrift-test-token")]
    pub credential: String,

    /// Opaque payload bytes (UTF-8) for capsule / datagram /
    /// compression probes.
    #[arg(long, default_value = "wafrift-smuggle-payload")]
    pub payload: String,

    /// Form-encoded body for multipart smuggle probes. Example:
    /// `user=admin&token=secret`.
    #[arg(long, default_value = "user=admin&token=wafrift-test-token")]
    pub form: String,

    /// Protected path seed for the path-normalization smuggle family.
    /// Probes craft encoded variants that bypass literal-path WAF
    /// rules gating this resource (default `/admin`).
    #[arg(long, default_value = "/admin")]
    pub protected_path: String,

    /// Protected hostname seed for the host-header smuggle family.
    /// Probes craft byte-level variants that bypass literal-host
    /// vhost-matching WAF rules (default `admin.example.com`).
    #[arg(long, default_value = "admin.example.com")]
    pub protected_host: String,

    /// Pretty-print each JSON object on multiple lines (default
    /// is one compact JSON per line — friendly to `jq -c` and
    /// streaming consumers).
    #[arg(long)]
    pub pretty: bool,

    /// Filter probes by artifact KIND: `headers` (cookie / auth /
    /// range / path), `body` (multipart smuggle), or `frames`
    /// (HTTP/3 capsule / QUIC datagram / WS compression). Empty
    /// (default) emits every kind.
    #[arg(long, default_value = "")]
    pub kind: String,

    /// When set, emit a top-level `extra_headers` field on each
    /// probe carrying one `(NAME, canary_token)` pair. Operators
    /// splice this header into the outgoing HTTP request alongside
    /// the artifact's own headers so inbound OOB callbacks already
    /// carry the technique-distinguishing token (no manual splice
    /// step). Recommended: `X-Wafrift-Canary`.
    #[arg(long, default_value = "", value_name = "HEADER_NAME")]
    pub canary_header: String,

    /// Maximum probes to emit after filtering. 0 = unlimited.
    /// Useful when sampling against a rate-limited target —
    /// `--limit 10` gives an operator a small representative
    /// sweep without firing the full 78-probe corpus.
    #[arg(long, default_value_t = 0)]
    pub limit: usize,

    /// Sort emitted probes by wire-byte footprint. `asc` lists
    /// the smallest probes first (sample cheap before committing
    /// budget on heavyweight body probes). `desc` puts the largest
    /// first (operators that want to fire the loudest probes
    /// against well-protected targets). Empty (default) =
    /// aggregator order. Applied after `--family` and `--kind`
    /// filtering, before `--limit`.
    #[arg(long, default_value = "", value_parser = ["", "asc", "desc"])]
    pub sort_by_bytes: String,

    /// Emit a ready-to-fire `curl` command per probe (one per
    /// line) targeting the supplied URL instead of JSON. Splices
    /// headers via `-H`, body via `-d`. Frame artifacts (HTTP/3
    /// capsule, QUIC datagram, WS compression) can't ride curl —
    /// they're skipped with a stderr warning. Operators pipe to
    /// `bash`, paste into Repeater, or `xargs -I{}` for a quick
    /// dogfood sweep.
    #[arg(long, value_name = "URL", default_value = "")]
    pub curl_target: String,
}

#[derive(serde::Serialize)]
struct EmittedProbe {
    canary: String,
    technique: String,
    description: String,
    artifact: wafrift_types::probe::SmuggleArtifact,
    /// Operator-requested instrumentation headers (e.g. the
    /// `--canary-header` pair). Empty by default; omitted from JSON
    /// via `skip_serializing_if` so old consumers see the
    /// original shape unless the operator opted in.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    extra_headers: Vec<(String, String)>,
}

/// Run the subcommand. Returns exit code 0 on clean emit, 2 when
/// the family filter matches zero probes (signals "no probes
/// emitted" without being a hard error).
pub fn run_smuggle_emit(args: SmuggleEmitArgs) -> ExitCode {
    let form_params = crate::helpers::parse_form_pairs(&args.form);
    let seeds = ProbeSeeds {
        cookie_name: &args.cookie_name,
        credential_value: &args.credential,
        form_params,
        payload: args.payload.as_bytes().to_vec(),
        protected_path: &args.protected_path,
        protected_host: &args.protected_host,
    };

    let mut probes = all_probes(&seeds);

    // Apply --sort-by-bytes ordering AFTER family/kind filtering
    // happens in the loop below — but the sort must be globally
    // visible, so we filter pre-sort here and emit in the sorted
    // order. We pre-filter so the sort operates only on the
    // probes that will actually emit.
    if !args.sort_by_bytes.is_empty() {
        probes.retain(|p| {
            let tech = p.technique();
            if !args.family.is_empty() && !tech.starts_with(&args.family) {
                return false;
            }
            if !args.kind.is_empty() {
                let kind_name = match p.artifact() {
                    wafrift_types::probe::SmuggleArtifact::Headers(_) => "headers",
                    wafrift_types::probe::SmuggleArtifact::BodyWithContentType { .. } => "body",
                    wafrift_types::probe::SmuggleArtifact::Frames(_) => "frames",
                };
                let matches = args.kind == kind_name
                    || (args.kind == "body_with_content_type" && kind_name == "body");
                if !matches {
                    return false;
                }
            }
            true
        });
        let ascending = args.sort_by_bytes == "asc";
        probes.sort_by(|a, b| {
            let a_n = a.artifact().wire_byte_count();
            let b_n = b.artifact().wire_byte_count();
            if ascending {
                a_n.cmp(&b_n)
            } else {
                b_n.cmp(&a_n)
            }
        });
    }

    let mut emitted: usize = 0;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    for probe in probes {
        let tech = probe.technique();
        if !args.family.is_empty() && !tech.starts_with(&args.family) {
            continue;
        }
        let artifact = probe.artifact();
        if !args.kind.is_empty() {
            let kind_name = match &artifact {
                wafrift_types::probe::SmuggleArtifact::Headers(_) => "headers",
                wafrift_types::probe::SmuggleArtifact::BodyWithContentType { .. } => "body",
                wafrift_types::probe::SmuggleArtifact::Frames(_) => "frames",
            };
            // Accept the canonical name and also the `body_with_content_type`
            // serde tag so operators can paste-and-go from the JSON output.
            let matches = args.kind == kind_name
                || (args.kind == "body_with_content_type" && kind_name == "body");
            if !matches {
                continue;
            }
        }
        let extra_headers = if args.canary_header.is_empty() {
            Vec::new()
        } else {
            vec![(args.canary_header.clone(), probe.canary().token.clone())]
        };
        let e = EmittedProbe {
            canary: probe.canary().token.clone(),
            technique: tech,
            description: probe.description().to_string(),
            artifact,
            extra_headers,
        };
        if !args.curl_target.is_empty() {
            match render_curl(&e, &args.curl_target) {
                Ok(line) => {
                    let _ = writeln!(out, "{line}");
                    emitted += 1;
                }
                Err(CurlRenderError::FramesNotSupported) => {
                    let _ = writeln!(
                        std::io::stderr(),
                        "wafrift smuggle-emit: skipping {} (frame artifacts can't ride curl)",
                        e.technique
                    );
                }
            }
        } else {
            let line = if args.pretty {
                serde_json::to_string_pretty(&e)
            } else {
                serde_json::to_string(&e)
            };
            match line {
                Ok(s) => {
                    let _ = writeln!(out, "{s}");
                    emitted += 1;
                }
                Err(err) => {
                    let _ = writeln!(std::io::stderr(), "serialize error: {err}");
                    return ExitCode::from(1);
                }
            }
        }
        if args.limit > 0 && emitted >= args.limit {
            break;
        }
    }

    if emitted == 0 {
        let _ = writeln!(
            std::io::stderr(),
            "wafrift smuggle-emit: family filter {:?} matched zero probes",
            args.family
        );
        return ExitCode::from(2);
    }
    ExitCode::SUCCESS
}

/// Reasons why curl rendering can fail for a given probe.
enum CurlRenderError {
    /// Frame artifacts (HTTP/3 capsule, QUIC datagram, WS
    /// compression) can't be expressed as a curl command line —
    /// they live at a lower transport layer than HTTP/1.1 / 2.
    FramesNotSupported,
}

/// Render an [`EmittedProbe`] as a single-line `curl` command
/// targeting `url`. Delegates to the shared
/// [`crate::helpers::render_artifact_as_curl`] primitive, passing
/// the probe's `extra_headers` (canary instrumentation) as the
/// extra-headers argument.
fn render_curl(probe: &EmittedProbe, url: &str) -> Result<String, CurlRenderError> {
    crate::helpers::render_artifact_as_curl(&probe.artifact, url, &probe.extra_headers)
        .ok_or(CurlRenderError::FramesNotSupported)
}

#[cfg(test)]
mod tests {
    use crate::helpers::parse_form_pairs;

    #[test]
    fn parse_form_handles_simple_pairs() {
        let p = parse_form_pairs("a=1&b=2");
        assert_eq!(
            p,
            vec![("a".to_string(), "1".to_string()), ("b".into(), "2".into())]
        );
    }

    #[test]
    fn parse_form_skips_empty_keys_and_no_equals() {
        let p = parse_form_pairs("=value&keyonly&actual=ok");
        assert_eq!(p, vec![("actual".into(), "ok".into())]);
    }

    #[test]
    fn parse_form_empty_string_returns_empty_vec() {
        assert!(parse_form_pairs("").is_empty());
    }
}
