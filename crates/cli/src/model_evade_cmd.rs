//! `wafrift model-evade` — active-learning WAF bypass via L* decompilation.
//!
//! This command implements the P1 attack paradigm:
//!
//! 1. **Learn**: Call `l_star_budgeted` over an HTTP oracle that sends
//!    live membership queries to the target WAF (each query = one HTTP
//!    request). Spend at most `--budget` membership queries.
//! 2. **Mine**: Intersect the learned symbolic automaton (the WAF's
//!    pass-language) with an attack grammar offline at ~1M candidates/s
//!    — zero further live queries in this phase.
//! 3. **Verify**: For every mined candidate, send ONE live probe to
//!    confirm the learned model matches reality (model↔reality gap check).
//! 4. **Report**: Write verified bypasses as structured JSON.
//!
//! The key advantage over `wafrift scan` (mutation-first): the learner
//! reasons about the WAF's DECISION BOUNDARY, not just whether specific
//! mutations happen to pass. A bypass is deduced, not found by luck.
//!
//! # Example
//!
//! ```text
//! wafrift model-evade http://localhost:8080 --class sqli --budget 200
//! ```

use clap::Args;
use colored::Colorize;
use serde_json::json;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Instant;

use wafrift_types::Request;
use wafrift_wafmodel::{
    Alphabet, BoundedExhaustiveEq, FnOracle, LearnReport, Outcome, WafModelError, WafOracle,
    attack_grammar, l_star_budgeted, minimal_bypass, mine_bypasses,
};

/// Arguments for `wafrift model-evade`.
#[derive(Args, Debug)]
pub struct ModelEvadeArgs {
    /// Target URL — the WAF-protected endpoint to decompile and bypass.
    /// Membership queries are sent as GET requests with the candidate
    /// payload in the `--param` query parameter.
    /// Local / RFC1918 targets (localhost, 127.x.x.x, 10.x, 192.168.x)
    /// are always permitted. Public targets require `--i-have-permission`.
    #[arg(value_name = "TARGET_URL")]
    pub target_url: String,

    /// Attack class to decompile and mine bypasses for.
    /// `sqli`  — SQL injection markers (UNION SELECT, OR 1=1, sleep(), etc.)
    /// `xss`   — Cross-site scripting markers (<script, onerror=, onload=, etc.)
    /// `all`   — Both classes combined.
    #[arg(long, default_value = "sqli", value_parser = ["sqli", "xss", "all"])]
    pub class: String,

    /// Maximum number of live membership queries to spend on the L*
    /// learning phase. Each query = one HTTP request to the target.
    /// Larger budgets produce more precise models; smaller budgets
    /// produce coarser approximations (still useful — the miner works
    /// with whatever boundary is learned). Budget-exhaustion is not an
    /// error: the command reports whatever bypasses the partial model
    /// yields and exits 0.
    #[arg(long, default_value_t = 500)]
    pub budget: u64,

    /// Maximum number of bypass candidates to mine from the learned
    /// model. Mining is offline (no HTTP); cap this for short runs.
    #[arg(long, default_value_t = 64)]
    pub max_mine: usize,

    /// Maximum byte length of mined bypass candidates. Shorter = faster
    /// mining; longer = richer candidates. The learner uses a small
    /// abstract alphabet so 24 bytes of abstract word can expand to a
    /// much longer concrete payload.
    #[arg(long, default_value_t = 24)]
    pub max_len: usize,

    /// Query parameter name to inject candidates into.
    /// Membership queries go to `<TARGET_URL>?<param>=<candidate>`.
    #[arg(long, default_value = "q")]
    pub param: String,

    /// I certify that I have permission to test this target (required
    /// for non-local targets not on the built-in allowlist).
    /// The value is logged so auditors can trace authorization back to
    /// the person who ran the tool — keep it short and specific:
    /// `"Bug bounty HackerOne #12345"`, `"Authorized pen test SOW 2026-05"`.
    #[arg(long, value_name = "REASON")]
    pub i_have_permission: Option<String>,

    /// Disable TLS certificate verification (useful for self-signed
    /// certs on internal test environments — do not use against
    /// production targets).
    #[arg(long, default_value_t = false)]
    pub insecure: bool,

    /// Write the JSON result to a file. Without this flag, JSON is
    /// printed to stdout so it can be piped to `jq`.
    #[arg(long, short)]
    pub output: Option<PathBuf>,

    /// Output format: `text` (default, colored summary) or `json`
    /// (machine-parseable, also implied by `--output`).
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    // ─── Egress rotation ─────────────────────────────────────────────────────

    /// SOCKS5 proxy URL for egress rotation (repeatable).
    #[arg(long = "socks5", value_name = "URL", num_args = 0..)]
    pub egress_socks5: Vec<String>,

    /// HTTP proxy URL for egress rotation (repeatable).
    #[arg(long = "http-proxy", value_name = "URL", num_args = 0..)]
    pub egress_http_proxy: Vec<String>,

    /// Tailscale exit-node name for egress rotation (repeatable).
    #[arg(long = "tailscale-exit-node", value_name = "NODE", num_args = 0..)]
    pub egress_tailscale_nodes: Vec<String>,

    /// Tailscale SOCKS listener address. Default: `127.0.0.1:1055`.
    #[arg(long = "tailscale-socks-addr", value_name = "ADDR", default_value = "127.0.0.1:1055")]
    pub egress_tailscale_socks_addr: String,

    /// Consecutive challenges before cooling an egress entry. Default: 3.
    #[arg(long = "egress-challenge-threshold", default_value_t = 3u32)]
    pub egress_challenge_threshold: u32,

    /// Seconds a cooled egress entry stays out of rotation. Default: 300.
    #[arg(long = "egress-cooldown-secs", default_value_t = 300u64)]
    pub egress_cooldown_secs: u64,
}

// ── Attack-class configuration ─────────────────────────────────────────────

/// Return the abstract alphabet + attack-grammar needles for a class.
///
/// The alphabet covers every byte a WAF rule in this class branches on;
/// the catch-all (`b'A'`) stands for every byte not otherwise listed.
/// The needles are the minimal substrings any block-triggering pattern
/// must contain — the attack grammar is their union.
pub(crate) fn class_config(class: &str) -> (Alphabet, Vec<&'static [u8]>) {
    match class {
        "sqli" => (
            // Distinguished bytes that SQL-injection WAF rules branch on.
            // INVARIANT (same as XSS above): every byte that appears in ANY
            // needle below MUST be in this set. kmp_sfa() uses the catch-all
            // representative (b'A') for unlisted bytes, so a needle byte not
            // here maps to the catch-all class and the KMP state machine can
            // never advance past it — the needle becomes silently unmatchable.
            //
            // Pre-fix: only UPPERCASE u/n/i/o/s/e/l/t/r/c were listed (left
            // over from a draft that used uppercase needles), but ALL needles
            // are lowercase. Every character in "union select", "or 1=1",
            // "sleep(", "; select" mapped to catch-all — zero bypasses were
            // ever mined from the sqli class.
            Alphabet::new(
                vec![
                    // Punctuation / operators that WAF rules branch on.
                    b'\'', b'"', b' ', b'-', b'/', b'*', b'=', b'(', b')', b';',
                    // Digits used in payloads (`1=1`, `0`).
                    b'0', b'1',
                    // Lowercase letters used in sqli needles:
                    //   union select → u, n, i, o, s, e, l, c, t
                    //   or / or 1=1  → o, r
                    //   sleep(       → s, l, e, p
                    //   ; select     → s, e, l, c, t
                    b'u', b'n', b'i', b'o', b's', b'e', b'l', b't', b'r', b'c', b'p',
                ],
                b'A',
            ),
            vec![
                b"union select" as &[u8],
                b"' or '",
                b"1=1",
                b"or 1=1",
                b"sleep(",
                b"; select",
            ],
        ),
        "xss" => (
            // Distinguished bytes that XSS WAF rules branch on.
            // INVARIANT: every byte that appears in ANY needle below MUST
            // be in this set. kmp_sfa() uses alpha.byte_of(catch_all_idx)
            // (= b'A') as the representative for all non-distinguished
            // bytes — so a needle byte not in the distinguished set maps
            // to the catch-all class, and kmp_next(state, b'A') will
            // never advance the KMP state machine past that needle byte,
            // making the needle silently unmatchable over the abstract alphabet.
            // Missing before: v, g, m, d (needed by <svg, <img, onload=).
            Alphabet::new(
                vec![
                    b'<', b'>', b'/', b'"', b'\'', b' ', b'=', b'(', b')',
                    b's', b'c', b'r', b'i', b'p', b't', b'o', b'n', b'l',
                    b'a', b'e',
                    b'v', b'g', b'm', b'd',
                ],
                b'A',
            ),
            vec![
                b"<script" as &[u8],
                b"onerror=",
                b"onload=",
                b"<svg",
                b"<img",
                b"alert(",
            ],
        ),
        _ => {
            // "all" — union of both sqli and xss.
            let (sqli_alpha, mut sqli_needles) = class_config("sqli");
            let (xss_alpha, xss_needles) = class_config("xss");
            sqli_needles.extend(xss_needles);
            // Merge alphabets: combine distinguished bytes from both classes.
            let mut combined: Vec<u8> =
                sqli_alpha.raw_symbols()[..sqli_alpha.catch_all()].to_vec();
            for &b in &xss_alpha.raw_symbols()[..xss_alpha.catch_all()] {
                if !combined.contains(&b) {
                    combined.push(b);
                }
            }
            (Alphabet::new(combined, b'A'), sqli_needles)
        }
    }
}

// ── HTTP oracle ────────────────────────────────────────────────────────────

/// Build a WAF oracle backed by async reqwest, run via the provided tokio
/// runtime handle.
///
/// The oracle sends `GET <target>?<param>=<payload>` for each membership
/// query. `2xx` status → `Pass`; anything else → `Block`.
///
/// The oracle is `FnOracle<impl FnMut(...) -> Result<Outcome>>` — it
/// implements `WafOracle` exactly as the trait requires.
fn build_http_oracle(
    rt: Arc<tokio::runtime::Runtime>,
    target_url: String,
    param: String,
    insecure: bool,
) -> Result<impl WafOracle, String> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(insecure)
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("wafrift/model-evade (authorized security research)")
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;

    let client = Arc::new(client);
    let target_url = Arc::new(target_url);
    let param = Arc::new(param);

    Ok(FnOracle::new(move |req: &Request| {
        // Extract payload bytes from the wafrift Request body (the learner
        // passes abstract-alphabet bytes concretized into a byte vector).
        let payload_bytes = req.body_bytes().unwrap_or(&[]).to_vec();
        let payload = String::from_utf8_lossy(&payload_bytes).into_owned();

        // Build probe URL: target?param=url-encoded-payload
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

        // 2xx = WAF let it through (Pass). Everything else = Block.
        // 429 (rate-limit) is Block — the payload was rejected.
        let outcome = if resp.status().is_success() {
            Outcome::Pass
        } else {
            Outcome::Block
        };
        Ok(outcome)
    }))
}

// ── Permission gate ────────────────────────────────────────────────────────

/// Check that the operator has declared permission to test the target.
/// Localhost / RFC1918 targets are always permitted (local bench stacks).
pub(crate) fn check_permission(url: &str, explicit_reason: &Option<String>) -> Result<(), String> {
    use std::net::IpAddr;

    // Parse hostname from URL — strip scheme, then take the host:port part.
    let host = url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(url)
        // Strip port.
        .split(':')
        .next()
        .unwrap_or(url);

    // Always allow localhost / loopback aliases.
    let loopback_hosts = ["localhost", "127.0.0.1", "::1", "0.0.0.0"];
    if loopback_hosts.contains(&host) {
        return Ok(());
    }

    // Allow RFC1918 IP ranges.
    if let Ok(ip) = host.parse::<IpAddr>() {
        let is_private = match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                // 10.0.0.0/8
                o[0] == 10
                // 172.16.0.0/12
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                // 192.168.0.0/16
                || (o[0] == 192 && o[1] == 168)
                // Loopback 127.0.0.0/8
                || o[0] == 127
            }
            IpAddr::V6(v6) => v6.is_loopback(),
        };
        if is_private {
            return Ok(());
        }
    }

    // Built-in allowlist (public bounty programs and lab targets).
    let allowlist = [
        "waf.cumulusfire.net",
        "testing.santh.dev",
        "ginandjuice.shop",
    ];
    for suffix in allowlist {
        if host == suffix || host.ends_with(&format!(".{suffix}")) {
            return Ok(());
        }
    }

    // Require explicit permission for everything else.
    match explicit_reason {
        Some(reason) if !reason.trim().is_empty() => {
            eprintln!(
                "{} Permission declared: {reason}",
                "model-evade:".bold().cyan()
            );
            Ok(())
        }
        _ => Err(format!(
            "Target `{url}` is not on the built-in allowlist. \
             Declare authorization with `--i-have-permission \"<reason>\"` \
             (e.g. \"Bug bounty HackerOne #12345\" or \"Authorized pen test SOW 2026-05\"). \
             Local targets (localhost, 127.x, 10.x, 192.168.x) are always permitted."
        )),
    }
}

// ── JSON output schema ─────────────────────────────────────────────────────

/// One candidate entry in the output JSON (verified or not).
#[derive(serde::Serialize, Debug)]
pub(crate) struct BypassEntry {
    pub payload: String,
    pub payload_hex: String,
    pub verified: bool,
    pub class: String,
}

impl BypassEntry {
    pub(crate) fn new(bytes: Vec<u8>, class: &str, verified: bool) -> Self {
        let payload = String::from_utf8_lossy(&bytes).into_owned();
        let payload_hex = hex::encode(&bytes);
        BypassEntry {
            payload,
            payload_hex,
            verified,
            class: class.to_string(),
        }
    }
}

// ── Accept-all SFA (fallback for budget-exhausted learning) ───────────────

/// An SFA that accepts every input string — used as the fallback model
/// when the L* budget is exhausted before the hypothesis stabilised.
/// Mining against an accept-all model proposes all attack-grammar strings
/// as bypass candidates; online verification then filters them honestly.
fn accept_all_sfa() -> wafrift_wafmodel::Sfa {
    use wafrift_wafmodel::{BytePred, Sfa};
    Sfa::new(0, vec![true], vec![vec![(BytePred::any(), 0)]])
}

// ── Main entry point ───────────────────────────────────────────────────────

/// Run `wafrift model-evade`.
pub fn run_model_evade(mut args: ModelEvadeArgs) -> ExitCode {
    args.target_url = crate::helpers::normalize_target_url(&args.target_url);
    // ── Step 0: permission gate ──────────────────────────────────────
    if let Err(msg) = check_permission(&args.target_url, &args.i_have_permission) {
        eprintln!("{} {msg}", "Permission error:".red().bold());
        return ExitCode::from(2);
    }

    // ── Step 0b: tokio runtime ───────────────────────────────────────
    let rt = match tokio::runtime::Runtime::new() {
        Ok(r) => Arc::new(r),
        Err(e) => {
            eprintln!("error: failed to start tokio runtime: {e}");
            return ExitCode::from(1);
        }
    };

    let json_mode = args.format == "json" || args.output.is_some();

    if !json_mode {
        println!("{}", "wafrift model-evade".bold().cyan());
        println!("{} {}", "Target:".bold().cyan(), args.target_url);
        println!("{} {}", "Class: ".bold().cyan(), args.class);
        println!(
            "{} {} queries / {} candidates / max {} bytes",
            "Budget:".bold().cyan(),
            args.budget,
            args.max_mine,
            args.max_len
        );
        println!();
    }

    // ── Step 1: build alphabet + attack grammar ──────────────────────
    let (alpha, needles) = class_config(&args.class);

    // ── Step 2: learn the WAF's decision boundary ────────────────────
    if !json_mode {
        println!("{}", "Phase 1: Learning WAF decision boundary (L*)...".bold());
    }
    let t_learn_start = Instant::now();

    // Build the oracle FIRST (validates HTTP client construction).
    let mut oracle = match build_http_oracle(
        rt.clone(),
        args.target_url.clone(),
        args.param.clone(),
        args.insecure,
    ) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{} {e}", "Oracle error:".red().bold());
            return ExitCode::from(1);
        }
    };

    // Request builder: POST body is the injection channel.
    // The body channel is what most WAFs inspect as REQUEST_BODY.
    let target_url_for_build = args.target_url.clone();
    let build_req = move |bytes: &[u8]| -> Request {
        Request::post(
            format!(
                "{}/model-evade-probe",
                target_url_for_build.trim_end_matches('/')
            ),
            bytes.to_vec(),
        )
        .header("Content-Type", "application/x-www-form-urlencoded")
    };

    let mut eq = BoundedExhaustiveEq { max_len: 6 };
    let learn_result: LearnReport =
        match l_star_budgeted(&mut oracle, &build_req, &alpha, &mut eq, args.budget) {
            Ok(r) => {
                if !json_mode {
                    println!(
                        "  {} {} membership queries, {} equivalence rounds, {:.1}s",
                        "Learned:".bold().green(),
                        r.membership_queries,
                        r.equivalence_rounds,
                        t_learn_start.elapsed().as_secs_f64()
                    );
                }
                r
            }
            Err(WafModelError::BudgetExhausted { queries }) => {
                if !json_mode {
                    println!(
                        "  {} budget of {} queries exhausted after {} queries — \
                         using optimistic accept-all model for mining.",
                        "Note:".bold().yellow(),
                        args.budget,
                        queries
                    );
                }
                // Fallback: accept-all SFA. Mining proposes all attack-grammar
                // strings; online verification gates every result honestly.
                LearnReport {
                    sfa: accept_all_sfa(),
                    membership_queries: queries,
                    equivalence_rounds: 0,
                }
            }
            Err(e) => {
                eprintln!("{} {e}", "Learning error:".red().bold());
                return ExitCode::from(1);
            }
        };

    let t_learn_elapsed = t_learn_start.elapsed();
    let learned_sfa = &learn_result.sfa;

    // ── Step 3: mine bypasses offline ────────────────────────────────
    if !json_mode {
        println!("{}", "\nPhase 2: Mining bypass candidates (offline)...".bold());
    }
    let t_mine_start = Instant::now();
    let grammar = attack_grammar(&alpha, &needles);
    let candidates = mine_bypasses(learned_sfa, &grammar, args.max_mine, args.max_len);
    let t_mine_elapsed = t_mine_start.elapsed();

    if !json_mode {
        println!(
            "  {} {} candidate(s) in {:.3}s",
            "Mined:".bold().green(),
            candidates.len(),
            t_mine_elapsed.as_secs_f64()
        );
    }

    if candidates.is_empty() {
        let note = "No bypass candidates found. The learned model has no intersection \
                    with the attack grammar — either the WAF blocks everything in \
                    this class, or the budget was too small to learn the boundary \
                    precisely. Try a larger --budget.";
        if json_mode {
            let report = json!({
                "schema_version": 1u32,
                "target": args.target_url,
                "class": args.class,
                "budget_used": learn_result.membership_queries,
                "equivalence_rounds": learn_result.equivalence_rounds,
                "learn_time_secs": t_learn_elapsed.as_secs_f64(),
                "mine_time_secs": t_mine_elapsed.as_secs_f64(),
                "verify_time_secs": 0.0,
                "total_queries": oracle.queries(),
                "candidates_mined": 0u32,
                "bypass_count": 0u32,
                "verified_rate_pct": 0.0,
                "bypasses": serde_json::Value::Array(Vec::new()),
                "all_candidates": serde_json::Value::Array(Vec::new()),
                "note": note,
            });
            emit_output(args.output.as_deref(), &report.to_string());
        } else {
            println!("\n{} {note}", "Note:".bold().yellow());
        }
        return ExitCode::SUCCESS;
    }

    // ── Step 4: verify candidates online ─────────────────────────────
    if !json_mode {
        println!(
            "{}",
            "\nPhase 3: Verifying candidates against the live target...".bold()
        );
    }
    let t_verify_start = Instant::now();
    let mut verified: Vec<BypassEntry> = Vec::new();

    for candidate in &candidates {
        let payload_str = String::from_utf8_lossy(candidate).into_owned();
        // Verify via GET to the target URL with the payload as query param.
        let probe_url = format!(
            "{}?{}={}",
            args.target_url.trim_end_matches('/'),
            args.param,
            urlencoding::encode(&payload_str)
        );
        let probe_req = Request::get(&probe_url);
        let outcome = oracle.classify(&probe_req);
        let is_bypass = matches!(outcome, Ok(Outcome::Pass));

        if is_bypass && !json_mode {
            println!(
                "  {} {}",
                "BYPASS:".bold().green(),
                payload_str.bright_white()
            );
        }
        verified.push(BypassEntry::new(candidate.clone(), &args.class, is_bypass));
    }

    let t_verify_elapsed = t_verify_start.elapsed();
    let bypass_count = verified.iter().filter(|e| e.verified).count();
    let total_queries = oracle.queries();
    let verified_rate_pct = if !candidates.is_empty() {
        (bypass_count as f64 / candidates.len() as f64) * 100.0
    } else {
        0.0
    };

    // ── Step 5: output ────────────────────────────────────────────────
    if json_mode {
        let bypass_objs: Vec<serde_json::Value> = verified
            .iter()
            .filter(|e| e.verified)
            .map(|e| {
                json!({
                    "payload": e.payload,
                    "payload_hex": e.payload_hex,
                    "class": e.class,
                    "verified": true,
                })
            })
            .collect();

        let all_objs: Vec<serde_json::Value> = verified
            .iter()
            .map(|e| {
                json!({
                    "payload": e.payload,
                    "payload_hex": e.payload_hex,
                    "class": e.class,
                    "verified": e.verified,
                })
            })
            .collect();

        let report = json!({
            "schema_version": 1u32,
            "target": args.target_url,
            "class": args.class,
            "budget_used": learn_result.membership_queries,
            "equivalence_rounds": learn_result.equivalence_rounds,
            "total_queries": total_queries,
            "candidates_mined": candidates.len(),
            "bypass_count": bypass_count,
            "verified_rate_pct": verified_rate_pct,
            "learn_time_secs": t_learn_elapsed.as_secs_f64(),
            "mine_time_secs": t_mine_elapsed.as_secs_f64(),
            "verify_time_secs": t_verify_elapsed.as_secs_f64(),
            "bypasses": bypass_objs,
            "all_candidates": all_objs,
        });

        emit_output(args.output.as_deref(), &report.to_string());
    } else {
        println!();
        println!("{}", "─── Summary ───".bold().bright_black());
        println!(
            "  {:<32} {}",
            "Total queries (learn + verify):".bold().cyan(),
            total_queries
        );
        println!(
            "  {:<32} {:.1}s",
            "Learn time:".bold().cyan(),
            t_learn_elapsed.as_secs_f64()
        );
        println!(
            "  {:<32} {:.4}s",
            "Mine time (offline):".bold().cyan(),
            t_mine_elapsed.as_secs_f64()
        );
        println!(
            "  {:<32} {:.1}s",
            "Verify time:".bold().cyan(),
            t_verify_elapsed.as_secs_f64()
        );
        println!(
            "  {:<32} {} / {} ({:.1}%)",
            "Bypasses (verified / mined):".bold().cyan(),
            bypass_count,
            candidates.len(),
            verified_rate_pct
        );

        if bypass_count == 0 {
            println!(
                "\n{} No verified bypasses found. The model predicted candidates \
                 but the live target blocked them — the model may need more budget. \
                 Try a larger --budget.",
                "Note:".bold().yellow()
            );
        }
    }

    ExitCode::SUCCESS
}

/// Emit the JSON output to a file or stdout.
fn emit_output(path: Option<&std::path::Path>, content: &str) {
    match path {
        Some(p) => {
            let to_write = format!("{content}\n");
            if let Err(e) = std::fs::write(p, &to_write) {
                eprintln!("error writing output to {}: {e}", p.display());
            } else {
                eprintln!("model-evade results written to {}", p.display());
            }
        }
        None => println!("{content}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wafrift_wafmodel::{BytePred, Sfa};

    // ── check_permission unit tests ─────────────────────────────────

    #[test]
    fn permission_localhost_always_allowed() {
        assert!(check_permission("http://localhost:8080", &None).is_ok());
        assert!(check_permission("http://127.0.0.1:9000/probe", &None).is_ok());
        assert!(check_permission("http://127.0.0.1", &None).is_ok());
    }

    #[test]
    fn permission_rfc1918_always_allowed() {
        assert!(check_permission("http://10.0.0.1/target", &None).is_ok());
        assert!(check_permission("http://192.168.1.100:8080", &None).is_ok());
        assert!(check_permission("http://172.16.0.1", &None).is_ok());
        assert!(check_permission("http://172.31.255.255", &None).is_ok());
    }

    #[test]
    fn permission_rfc1918_boundary_172_15_denied_without_auth() {
        // 172.15.x.x is NOT RFC1918 (range is 172.16.0.0/12).
        let r = check_permission("http://172.15.0.1/target", &None);
        assert!(
            r.is_err(),
            "172.15.x.x is not RFC1918 — must require permission"
        );
    }

    #[test]
    fn permission_public_target_denied_without_reason() {
        let r = check_permission("https://example.com/target", &None);
        assert!(r.is_err());
        let msg = r.unwrap_err();
        assert!(
            msg.contains("--i-have-permission"),
            "error must mention the flag: {msg}"
        );
    }

    #[test]
    fn permission_public_target_allowed_with_reason() {
        let r = check_permission(
            "https://example.com/target",
            &Some("Bug bounty program".to_string()),
        );
        assert!(r.is_ok());
    }

    #[test]
    fn permission_empty_reason_denied() {
        let r = check_permission("https://example.com", &Some("   ".to_string()));
        assert!(r.is_err());
    }

    #[test]
    fn permission_builtin_allowlist_waf_cumulusfire() {
        assert!(check_permission("https://waf.cumulusfire.net/test", &None).is_ok());
        assert!(check_permission("https://api.waf.cumulusfire.net/test", &None).is_ok());
    }

    #[test]
    fn permission_builtin_allowlist_testing_santh_dev() {
        assert!(check_permission("https://testing.santh.dev/probe", &None).is_ok());
    }

    // ── class_config unit tests ─────────────────────────────────────

    #[test]
    fn class_config_sqli_has_needles() {
        let (_alpha, needles) = class_config("sqli");
        assert!(!needles.is_empty(), "sqli must have attack needles");
        assert!(
            needles.iter().any(|n| *n == b"union select"),
            "sqli must include 'union select'"
        );
    }

    #[test]
    fn class_config_xss_has_needles() {
        let (_alpha, needles) = class_config("xss");
        assert!(!needles.is_empty(), "xss must have attack needles");
        assert!(
            needles.iter().any(|n| *n == b"<script"),
            "xss must include '<script'"
        );
    }

    #[test]
    fn class_config_all_includes_both() {
        let (_sqli_alpha, sqli_needles) = class_config("sqli");
        let (_xss_alpha, xss_needles) = class_config("xss");
        let (_all_alpha, all_needles) = class_config("all");
        for n in &sqli_needles {
            assert!(
                all_needles.contains(n),
                "'all' must include sqli needle {:?}",
                String::from_utf8_lossy(n)
            );
        }
        for n in &xss_needles {
            assert!(
                all_needles.contains(n),
                "'all' must include xss needle {:?}",
                String::from_utf8_lossy(n)
            );
        }
    }

    #[test]
    fn class_config_alphabet_catch_all_not_in_distinguished() {
        for class in ["sqli", "xss", "all"] {
            let (alpha, _) = class_config(class);
            let syms = alpha.raw_symbols();
            let catch_all = syms[syms.len() - 1];
            let distinguished = &syms[..syms.len() - 1];
            assert!(
                !distinguished.contains(&catch_all),
                "class {class}: catch-all byte {catch_all} must not be in distinguished"
            );
        }
    }

    #[test]
    fn class_config_alphabet_non_empty() {
        for class in ["sqli", "xss", "all"] {
            let (alpha, _) = class_config(class);
            assert!(
                alpha.len() >= 2,
                "class {class}: alphabet must have ≥1 distinguished + 1 catch-all"
            );
        }
    }

    // ── emit_output unit test ───────────────────────────────────────

    #[test]
    fn emit_output_to_file_creates_file() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "wafrift_model_evade_test_{}.json",
            std::process::id()
        ));
        let content = r#"{"test":true}"#;
        emit_output(Some(&path), content);
        assert!(path.exists(), "emit_output must create the file");
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.contains(content));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn emit_output_none_does_not_panic() {
        // Should print to stdout without panicking.
        emit_output(None, r#"{"ok":true}"#);
    }

    // ── bypass_entry schema ─────────────────────────────────────────

    #[test]
    fn bypass_entry_serializes_payload_hex() {
        let entry = BypassEntry::new(b"1 OR 1=1".to_vec(), "sqli", true);
        let v = serde_json::to_value(&entry).unwrap();
        assert_eq!(v["verified"], true);
        assert_eq!(v["class"], "sqli");
        assert_eq!(v["payload"], "1 OR 1=1");
        let expected_hex = hex::encode(b"1 OR 1=1");
        assert_eq!(v["payload_hex"], expected_hex);
    }

    #[test]
    fn bypass_entry_unverified() {
        let entry = BypassEntry::new(b"<script>".to_vec(), "xss", false);
        let v = serde_json::to_value(&entry).unwrap();
        assert_eq!(v["verified"], false);
    }

    #[test]
    fn bypass_entry_hex_for_non_utf8_bytes() {
        let raw = vec![0xFF, 0xFE, 0x00, 0x01];
        let entry = BypassEntry::new(raw.clone(), "sqli", false);
        assert_eq!(entry.payload_hex, hex::encode(&raw));
    }

    // ── accept_all_sfa ──────────────────────────────────────────────

    #[test]
    fn accept_all_sfa_accepts_everything() {
        let sfa = accept_all_sfa();
        assert!(sfa.accepts(b""), "accept-all must accept empty");
        assert!(sfa.accepts(b"union select"), "accept-all must accept sql");
        assert!(sfa.accepts(b"<script>"), "accept-all must accept xss");
        assert!(sfa.accepts(b"\x00\xff\x7f"), "accept-all must accept binary");
    }

    // ── oracle integration: FnOracle wrapping ──────────────────────

    #[test]
    fn fn_oracle_counts_queries() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let counter = Arc::new(AtomicU64::new(0));
        let c2 = counter.clone();
        let mut oracle = FnOracle::new(move |_req: &Request| {
            c2.fetch_add(1, Ordering::SeqCst);
            Ok(Outcome::Pass)
        });
        let req = Request::get("http://localhost/");
        oracle.classify(&req).unwrap();
        oracle.classify(&req).unwrap();
        assert_eq!(oracle.queries(), 2);
    }

    #[test]
    fn fn_oracle_pass_outcome() {
        let mut oracle = FnOracle::new(|_req: &Request| Ok(Outcome::Pass));
        let req = Request::get("http://localhost/");
        assert_eq!(oracle.classify(&req).unwrap(), Outcome::Pass);
    }

    #[test]
    fn fn_oracle_block_outcome() {
        let mut oracle = FnOracle::new(|_req: &Request| Ok(Outcome::Block));
        let req = Request::get("http://localhost/");
        assert_eq!(oracle.classify(&req).unwrap(), Outcome::Block);
    }

    // ── l_star_budgeted integration: offline SimRegexWaf oracle ────

    #[test]
    fn lstar_budgeted_learns_simple_boundary() {
        use wafrift_wafmodel::canon::Channel;
        use wafrift_wafmodel::{ChannelSet, Rule, SimRegexWaf};
        let mut waf = SimRegexWaf::new(
            vec![Rule {
                id: "test-sqli".into(),
                channels: ChannelSet::none().with(Channel::Body),
                transforms: vec![],
                pattern: regex::bytes::Regex::new("union select").unwrap(),
                score: 5,
            }],
            5,
        );
        let (alpha, _needles) = class_config("sqli");
        let build = |bytes: &[u8]| -> Request {
            Request::post("https://h/p", bytes.to_vec())
                .header("Content-Type", "application/x-www-form-urlencoded")
        };
        let mut eq = BoundedExhaustiveEq { max_len: 5 };
        let report = l_star_budgeted(&mut waf, &build, &alpha, &mut eq, 2000).unwrap();
        // Learned model must pass the empty body (benign).
        assert!(report.sfa.accepts(b""), "empty body must pass");
        assert!(report.membership_queries > 0);
    }

    #[test]
    fn lstar_budgeted_budget_exhaustion_returns_error() {
        use wafrift_wafmodel::canon::Channel;
        use wafrift_wafmodel::{ChannelSet, Rule, SimRegexWaf};
        let mut waf = SimRegexWaf::new(
            vec![Rule {
                id: "test-sqli".into(),
                channels: ChannelSet::none().with(Channel::Body),
                transforms: vec![],
                pattern: regex::bytes::Regex::new("union select").unwrap(),
                score: 5,
            }],
            5,
        );
        let (alpha, _) = class_config("sqli");
        let build = |bytes: &[u8]| -> Request {
            Request::post("https://h/p", bytes.to_vec())
                .header("Content-Type", "application/x-www-form-urlencoded")
        };
        let mut eq = BoundedExhaustiveEq { max_len: 5 };
        // Budget of 1 is too small — must return BudgetExhausted.
        let result = l_star_budgeted(&mut waf, &build, &alpha, &mut eq, 1);
        assert!(
            matches!(result, Err(WafModelError::BudgetExhausted { .. })),
            "tiny budget must exhaust: {result:?}"
        );
    }

    #[test]
    fn mine_bypasses_empty_when_no_intersection() {
        // An accept-all SFA ∩ empty attack grammar = empty.
        let (alpha, _) = class_config("sqli");
        let accept_all = Sfa::new(0, vec![true], vec![vec![(BytePred::any(), 0)]]);
        let empty_grammar = attack_grammar(&alpha, &[]); // no needles = empty language
        let candidates = mine_bypasses(&accept_all, &empty_grammar, 64, 24);
        assert!(
            candidates.is_empty(),
            "empty grammar ∩ accept-all = empty: {candidates:?}"
        );
    }

    #[test]
    fn mine_bypasses_finds_candidates_with_accept_all_model() {
        let (alpha, needles) = class_config("sqli");
        let accept_all = Sfa::new(0, vec![true], vec![vec![(BytePred::any(), 0)]]);
        let grammar = attack_grammar(&alpha, &needles);
        let candidates = mine_bypasses(&accept_all, &grammar, 10, 20);
        assert!(
            !candidates.is_empty(),
            "accept-all WAF must yield bypass candidates for sqli grammar"
        );
    }

    #[test]
    fn mine_bypasses_respects_max_limit() {
        let (alpha, needles) = class_config("sqli");
        let accept_all = Sfa::new(0, vec![true], vec![vec![(BytePred::any(), 0)]]);
        let grammar = attack_grammar(&alpha, &needles);
        let candidates = mine_bypasses(&accept_all, &grammar, 3, 20);
        assert!(
            candidates.len() <= 3,
            "mine_bypasses must respect max: {}",
            candidates.len()
        );
    }

    #[test]
    fn mine_bypasses_candidates_contain_attack_needle() {
        // Every mined sqli candidate must contain at least one attack needle.
        let (alpha, needles) = class_config("sqli");
        let accept_all = Sfa::new(0, vec![true], vec![vec![(BytePred::any(), 0)]]);
        let grammar = attack_grammar(&alpha, &needles);
        let candidates = mine_bypasses(&accept_all, &grammar, 10, 30);
        for cand in &candidates {
            let payload = String::from_utf8_lossy(cand).to_ascii_lowercase();
            let has_needle = needles
                .iter()
                .any(|n| payload.contains(std::str::from_utf8(n).unwrap_or("")));
            assert!(
                has_needle,
                "mined candidate {:?} must contain an attack needle",
                payload
            );
        }
    }

    #[test]
    fn attack_grammar_xss_contains_script_needle() {
        let (alpha, needles) = class_config("xss");
        let grammar = attack_grammar(&alpha, &needles);
        let found = grammar.shortest_accepted();
        assert!(found.is_some(), "xss grammar must accept something");
        let bytes = found.unwrap();
        let s = String::from_utf8_lossy(&bytes).to_ascii_lowercase();
        let has_needle = needles
            .iter()
            .any(|n| s.contains(std::str::from_utf8(n).unwrap_or("")));
        assert!(has_needle, "shortest xss accept must have a needle: {s:?}");
    }

    #[test]
    fn mine_bypasses_max_len_respected() {
        let (alpha, needles) = class_config("sqli");
        let accept_all = Sfa::new(0, vec![true], vec![vec![(BytePred::any(), 0)]]);
        let grammar = attack_grammar(&alpha, &needles);
        // max_len = 14 (shorter than longest needle "union select" = 12 bytes)
        let candidates = mine_bypasses(&accept_all, &grammar, 20, 14);
        for cand in &candidates {
            assert!(
                cand.len() <= 14,
                "candidate longer than max_len: {:?}",
                String::from_utf8_lossy(cand)
            );
        }
    }

    /// INVARIANT test: every byte in every needle for each class MUST
    /// appear in the class's distinguished-symbol alphabet. Violation
    /// means the KMP SFA maps that byte to the catch-all representative
    /// (b'A') and can never advance the needle match — the needle becomes
    /// silently unmatchable over the abstract alphabet. This is the exact
    /// bug that existed in the sqli alphabet before the fix (uppercase
    /// letters listed, lowercase needles).
    #[test]
    fn class_config_alphabet_covers_all_needle_bytes() {
        for class in &["sqli", "xss", "all"] {
            let (alpha, needles) = class_config(class);
            let sym_count = alpha.catch_all();
            let symbols = &alpha.raw_symbols()[..sym_count];
            for needle in &needles {
                for &byte in *needle {
                    assert!(
                        symbols.contains(&byte),
                        "class={class}: needle byte {byte:?} ({:?}) not in distinguished \
                         alphabet — it maps to catch-all and kmp_sfa cannot match it.\n\
                         Needle: {:?}\nAlphabet: {:?}",
                        byte as char,
                        String::from_utf8_lossy(needle),
                        symbols.iter().map(|b| *b as char).collect::<Vec<_>>(),
                    );
                }
            }
        }
    }

    #[test]
    fn mine_bypasses_all_class_finds_both_sqli_and_xss() {
        // Use `minimal_bypass` (shortest_accepted with a seen-set, O(states)) to
        // verify each class grammar accepts its attack language.  `mine_bypasses`
        // (enumerate_accepted, no seen-set) hits ENUMERATE_QUEUE_CAP on large
        // cyclic grammars when max_len is generous; it is NOT the correctness
        // oracle — `minimal_bypass` is.
        let accept_all = Sfa::new(0, vec![true], vec![vec![(BytePred::any(), 0)]]);

        // SQLi: the shortest bypass must contain an SQLi needle.
        let (sqli_alpha, sqli_needles) = class_config("sqli");
        let sqli_grammar = attack_grammar(&sqli_alpha, &sqli_needles);
        let sqli_word = minimal_bypass(&accept_all, &sqli_grammar)
            .expect("sqli grammar must accept at least one bypass");
        let sqli_s = String::from_utf8_lossy(&sqli_word).to_ascii_lowercase();
        assert!(
            sqli_needles
                .iter()
                .any(|n| sqli_s.contains(std::str::from_utf8(n).unwrap_or(""))),
            "sqli minimal bypass {:?} must contain a sqli needle",
            sqli_s
        );

        // XSS: the shortest bypass must contain an XSS needle.
        let (xss_alpha, xss_needles) = class_config("xss");
        let xss_grammar = attack_grammar(&xss_alpha, &xss_needles);
        let xss_word = minimal_bypass(&accept_all, &xss_grammar)
            .expect("xss grammar must accept at least one bypass");
        let xss_s = String::from_utf8_lossy(&xss_word).to_ascii_lowercase();
        assert!(
            xss_needles
                .iter()
                .any(|n| xss_s.contains(std::str::from_utf8(n).unwrap_or(""))),
            "xss minimal bypass {:?} must contain an xss needle",
            xss_s
        );
    }
}
