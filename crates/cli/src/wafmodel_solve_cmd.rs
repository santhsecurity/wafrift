//! `wafrift solve-bypass` — wrap `wafrift_wafmodel::solve_bypass` as
//! an operator-facing live-target subcommand.
//!
//! Closes the "first production caller" gap for the wafmodel CEGIS
//! solver: `solve_bypass` had nine integration tests but no shipped
//! binary ever called it. Operators wanting structural-preimage
//! bypasses had to drop into Rust and link wafmodel directly.
//!
//! ## Algorithm
//!
//! For a given (attack, sink, oracle) triple, the solver returns
//! `Some(Solution)` when it can find an input that:
//!   1. The oracle (live WAF) passes,
//!   2. `sink.apply(input)` reconstructs the literal attack bytes,
//!   3. The raw attack is itself blocked by the oracle (anti-rig
//!      control — a "bypass" of an unblocked attack is vacuous).
//!
//! The CEGIS escalation is internal: `Scope::Danger` (encode only
//! dangerous bytes) first, then `Scope::All`. Both are *verified*
//! against the live oracle before being reported — never fabricated.
//!
//! ## Sink presets
//!
//! Picking the right `Pipeline` is the operator's choice. We expose
//! four named presets that cover the bulk of real-world stacks:
//!
//! - `url`         — one URL-decode pass (reverse-proxy decode only).
//! - `double-url`  — two URL-decode passes (proxy + app re-decode).
//! - `html-entity` — URL-decode + HTML-entity-decode.
//! - `json`        — JSON unescape (body parsed as JSON literal).

use std::process::ExitCode;
use std::sync::Arc;

use clap::Args;
use serde::Serialize;
use wafrift_types::Request;
use wafrift_wafmodel::{
    FnOracle, Outcome, Pipeline, Solution, Stage, WafModelError, WafOracle, solve_bypass,
};

#[derive(Args, Debug)]
pub struct SolveBypassArgs {
    /// Target URL — the WAF-protected endpoint to bypass. The probe
    /// is a `GET <target>?<param>=<urlencoded-candidate>`.
    #[arg(long, value_name = "URL")]
    pub target: String,

    /// Query parameter to inject candidates into. Default `q`.
    #[arg(long, default_value = "q")]
    pub param: String,

    /// Attack bytes the operator wants to deliver through the WAF.
    /// Accepted as a UTF-8 string; for raw bytes use `\xNN` escape via
    /// your shell. Required because a "bypass" of nothing is vacuous.
    #[arg(long, value_name = "ATTACK")]
    pub attack: String,

    /// Sink pipeline preset describing how the target decodes the body
    /// before the application sees it. One of: `url`, `double-url`,
    /// `html-entity`, `json`. The solver inverts this pipeline to
    /// build candidate bytes that reconstruct `--attack` after decoding.
    #[arg(
        long,
        default_value = "url",
        value_parser = ["url", "double-url", "html-entity", "json"],
    )]
    pub sink: String,

    /// Disable TLS verification for the target probe. Required when
    /// the target uses a self-signed or otherwise untrusted cert.
    #[arg(long, default_value_t = false)]
    pub insecure: bool,

    /// Output format. `text` (default) prints a human report; `json`
    /// emits a machine-parseable envelope describing the solver
    /// outcome and any solution it found.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,
}

/// JSON envelope shape for the `--format json` path. Stable schema so
/// downstream tooling can grow against it without churn.
#[derive(Serialize)]
struct SolveOutput {
    schema_version: u32,
    target: String,
    sink: String,
    attack: String,
    raw_attack_blocked: bool,
    found_bypass: bool,
    solution: Option<SolutionRow>,
}

#[derive(Serialize)]
struct SolutionRow {
    input: String,
    encoding: String,
    sink_view: String,
}

const SCHEMA_VERSION: u32 = 1;

pub fn run_solve_bypass(args: SolveBypassArgs) -> ExitCode {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: failed to start tokio runtime: {e}");
            return ExitCode::from(1);
        }
    };
    let rt = Arc::new(rt);
    let oracle =
        match build_http_oracle(rt, args.target.clone(), args.param.clone(), args.insecure) {
            Ok(o) => o,
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::from(1);
            }
        };
    run_solve_bypass_inner(args, oracle)
}

fn run_solve_bypass_inner<O: WafOracle>(args: SolveBypassArgs, mut oracle: O) -> ExitCode {
    let sink = match sink_preset(&args.sink) {
        Some(p) => p,
        None => {
            // clap value_parser gates this — reached only via direct test calls.
            eprintln!("error: unknown sink preset {}", args.sink);
            return ExitCode::from(2);
        }
    };
    let attack_bytes = args.attack.as_bytes();
    let build = |b: &[u8]| Request::post(args.target.clone(), b.to_vec());
    // Probe raw_attack_blocked first so we know the control state
    // even when the solver returns None.  solve_bypass also records
    // this internally on the returned Solution, but when it returns
    // None we lose visibility; probing here unifies the signal.
    let raw_blocked = match oracle.classify(&build(attack_bytes)) {
        Ok(Outcome::Block) => true,
        Ok(_) => false,
        Err(e) => {
            eprintln!("error: raw attack probe failed: {e}");
            return ExitCode::from(1);
        }
    };
    let solution = match solve_bypass(attack_bytes, &sink, &mut oracle, &build) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: solver failed: {e}");
            return ExitCode::from(1);
        }
    };
    let json_mode = args.format == "json";
    if json_mode {
        let envelope = SolveOutput {
            schema_version: SCHEMA_VERSION,
            target: args.target.clone(),
            sink: args.sink.clone(),
            attack: args.attack.clone(),
            raw_attack_blocked: raw_blocked,
            found_bypass: solution.is_some(),
            solution: solution.as_ref().map(|s| SolutionRow {
                input: String::from_utf8_lossy(&s.input).into_owned(),
                encoding: s.encoding.clone(),
                sink_view: String::from_utf8_lossy(&s.sink_view).into_owned(),
            }),
        };
        match serde_json::to_string_pretty(&envelope) {
            Ok(s) => {
                println!("{s}");
            }
            Err(e) => {
                eprintln!("error: json render: {e}");
                return ExitCode::from(1);
            }
        }
    } else {
        print_text(&args, raw_blocked, solution.as_ref());
    }
    // Exit codes: 0 = real bypass found (raw blocked AND a bypass
    // exists), 3 = raw attack not blocked so "bypass" is vacuous,
    // 4 = raw blocked but no bypass found despite escalation.
    // Matches the "headline number" convention bench-waf uses.
    match (raw_blocked, solution.is_some()) {
        (true, true) => ExitCode::SUCCESS,
        (false, _) => ExitCode::from(3),
        (true, false) => ExitCode::from(4),
    }
}

fn print_text(args: &SolveBypassArgs, raw_blocked: bool, sol: Option<&Solution>) {
    println!("Target : {}", args.target);
    println!("Sink   : {}", args.sink);
    println!("Attack : {}", args.attack);
    println!(
        "Raw blocked: {}",
        if raw_blocked { "yes" } else { "no (vacuous bypass — pick a real attack)" }
    );
    match sol {
        Some(s) => {
            println!(
                "Bypass FOUND ({} bytes)\n  encoding: {}",
                s.input.len(),
                s.encoding
            );
            println!("  input    : {:?}", String::from_utf8_lossy(&s.input));
            println!("  sink_view: {:?}", String::from_utf8_lossy(&s.sink_view));
        }
        None => {
            println!("No bypass found via this sink preset.");
        }
    }
}

/// Map a CLI `--sink` flag value to the matching `Pipeline`. Pinned
/// in a test so adding a new preset to the value-parser surface
/// without wiring its `Pipeline` trips CI rather than shipping a
/// silent "unknown sink" runtime panic.
#[must_use]
fn sink_preset(name: &str) -> Option<Pipeline> {
    match name {
        "url" => Some(Pipeline(vec![Stage::UrlDecode { plus_is_space: false }])),
        "double-url" => Some(Pipeline(vec![Stage::DoubleUrlDecode])),
        "html-entity" => Some(Pipeline(vec![
            Stage::UrlDecode { plus_is_space: false },
            Stage::HtmlEntityDecode,
        ])),
        "json" => Some(Pipeline(vec![Stage::JsonUnescape])),
        _ => None,
    }
}

/// HTTP oracle: send `GET <target>?<param>=<urlencoded(body)>` for
/// every candidate. 2xx → Pass; anything else → Block. Mirrors the
/// pattern in `model_evade_cmd::build_http_oracle` so live targets
/// see consistent classification across CLI surfaces.
fn build_http_oracle(
    rt: Arc<tokio::runtime::Runtime>,
    target_url: String,
    param: String,
    insecure: bool,
) -> Result<impl WafOracle, String> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(insecure)
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("wafrift/solve-bypass (authorized security research)")
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;
    let client = Arc::new(client);
    let target_url = Arc::new(target_url);
    let param = Arc::new(param);
    Ok(FnOracle::new(move |req: &Request| {
        let payload_bytes = req.body_bytes().unwrap_or(&[]).to_vec();
        let payload = String::from_utf8_lossy(&payload_bytes).into_owned();
        let probe_url = format!(
            "{}?{}={}",
            target_url.as_str(),
            param.as_str(),
            urlencoding::encode(&payload)
        );
        let client2 = client.clone();
        let probe_url_clone = probe_url.clone();
        let resp = rt
            .block_on(async move { client2.get(&probe_url_clone).send().await })
            .map_err(|e| WafModelError::Oracle(format!("HTTP error probing {probe_url}: {e}")))?;
        Ok(if resp.status().is_success() {
            Outcome::Pass
        } else {
            Outcome::Block
        })
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(sink: &str, attack: &str) -> SolveBypassArgs {
        SolveBypassArgs {
            target: "http://127.0.0.1:1/".into(),
            param: "q".into(),
            attack: attack.into(),
            sink: sink.into(),
            insecure: false,
            format: "json".into(),
        }
    }

    #[test]
    fn sink_preset_returns_some_for_each_valid_name() {
        for name in ["url", "double-url", "html-entity", "json"] {
            assert!(
                sink_preset(name).is_some(),
                "preset {name} must map to a Pipeline"
            );
        }
    }

    #[test]
    fn sink_preset_unknown_returns_none() {
        assert!(sink_preset("does-not-exist").is_none());
    }

    #[test]
    fn url_preset_decodes_percent_xx() {
        let p = sink_preset("url").unwrap();
        // %3Cscript%3E → <script>
        let decoded = p.apply(b"%3Cscript%3E");
        assert_eq!(decoded, b"<script>");
    }

    #[test]
    fn double_url_preset_decodes_two_passes() {
        let p = sink_preset("double-url").unwrap();
        // %253Cscript%253E → %3Cscript%3E → <script>
        let decoded = p.apply(b"%253Cscript%253E");
        assert_eq!(decoded, b"<script>");
    }

    #[test]
    fn json_preset_decodes_escape_sequences() {
        let p = sink_preset("json").unwrap();
        // \"\\u003cscript\\u003e\" — JSON-unescaped to <script>
        let decoded = p.apply(b"\\u003cscript\\u003e");
        assert_eq!(decoded, b"<script>");
    }

    #[test]
    fn html_entity_preset_combines_url_and_entity_decode() {
        let p = sink_preset("html-entity").unwrap();
        // `%3Cscript%3E` → `<script>` via URL decode, then entity-decode
        // doesn't add anything for this case; pinned for clarity.
        let decoded = p.apply(b"%3Cscript%3E");
        assert_eq!(decoded, b"<script>");
    }

    #[test]
    fn inner_returns_exit_3_when_raw_attack_passes() {
        // Oracle that ALWAYS passes — raw attack is not blocked.
        let oracle = FnOracle::new(|_req: &Request| Ok(Outcome::Pass));
        let code = run_solve_bypass_inner(args("url", "<script>"), oracle);
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::from(3)),
            "vacuous-bypass case must exit 3"
        );
    }

    #[test]
    fn inner_returns_exit_0_when_solver_finds_bypass() {
        // Oracle that blocks the raw attack literal but passes anything else.
        // The structural-preimage candidate (URL-encoded) bypasses it.
        let oracle = FnOracle::new(|req: &Request| {
            let body = req.body_bytes().unwrap_or(&[]);
            if body.windows(8).any(|w| w == b"<script>") {
                Ok(Outcome::Block)
            } else {
                Ok(Outcome::Pass)
            }
        });
        let code = run_solve_bypass_inner(args("url", "<script>"), oracle);
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::SUCCESS),
            "must exit 0 when a bypass is found"
        );
    }

    #[test]
    fn inner_returns_exit_4_when_raw_blocked_no_bypass() {
        // Block everything. The solver can never find a bypass.
        let oracle = FnOracle::new(|_req: &Request| Ok(Outcome::Block));
        let code = run_solve_bypass_inner(args("url", "<script>"), oracle);
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::from(4)),
            "raw-blocked + no-bypass must exit 4"
        );
    }
}
