//! Live WAF evasion scan pipeline.
//!
//! This module contains the core scan loop — the 7-step autonomous pipeline
//! that detects the WAF, generates variants, probes differentially, explores,
//! exploits, evolves, and saves results.
//!
//! # Module structure
//!
//! - `state` — `ScanState` (mutable counters) and `ScanConfig` (immutable args)
//! - this module (`mod.rs`) — the `run_scan` orchestrator and step functions

pub(crate) mod baseline;
pub(crate) mod callback_poll;
pub(crate) mod detect_phase;
pub(crate) mod differential_phase;
pub(crate) mod graphql_phase;
pub(crate) mod header_obf_phase;
pub(crate) mod multi_vector;
pub(crate) mod pentest_client;
pub(crate) mod raw_runner;
pub(crate) mod session_init_plug;

use colored::Colorize;
use serde_json::json;
use std::collections::HashSet;
use std::io::{self, Write};
use std::process::ExitCode;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

// waf_detect now consumed via `crate::scan::detect_phase`.
// compression is now consumed via `crate::scan::multi_vector`.
// header obfuscation is now consumed via `crate::scan::header_obf_phase`.
use wafrift_encoding::encoding::{self, Strategy};
use wafrift_encoding::tamper::TamperRegistry;
// advisor now consumed via `crate::scan::detect_phase`.
// IntelligenceLoop now consumed via `crate::scan::differential_phase`.
use wafrift_grammar::grammar::{self, PayloadType};
use wafrift_oracle::response_oracle::{ResponseContext, ResponseOracle};
use wafrift_strategy::composition;
use wafrift_strategy::cost;
use wafrift_strategy::gene_bank::GeneBank;
use wafrift_strategy::learning_cache::{CacheKey, LearningCache};
use wafrift_strategy::pipeline::EvasionPipeline;
use wafrift_transport::is_waf_block;

pub(crate) use crate::ScanArgs;
use crate::helpers::{
    build_variants, confidence_badge, max_mutations_for_level, payload_type_label,
    strategies_for_level, variant_confidence,
};

/// Build the `bypass_variants` JSON array embedded in `scan
/// --format json` output. Pure formatter; extracted so it's testable
/// in isolation and the `run_scan` orchestrator stays focused on
/// control flow rather than serialisation.
///
/// `variants` mirrors the orchestrator's `bypass_variants` Vec of
/// `(variant_idx, payload, techniques, confidence)` rows;
/// `minimal_payloads` aligns 1:1 by index and is `Some(min)` only
/// when `--auto-distill` produced a smaller bypass for that row.
pub(crate) fn build_bypass_variants_json(
    target: &str,
    param: &str,
    variants: &[(usize, String, Vec<String>, f64)],
    minimal_payloads: &[Option<String>],
) -> Vec<serde_json::Value> {
    variants
        .iter()
        .enumerate()
        .map(|(i, (idx, payload, techniques, conf))| {
            let minimal = minimal_payloads.get(i).and_then(Option::as_ref);
            let full_url = scan_url_with_param(target, param, &urlencoding::encode(payload));
            // Use poc_emit for annotated repro_curl (metadata comment block
            // names the technique chain and confidence); fall back to the
            // plain url_query helper on render errors so bypasses are never
            // silently dropped.
            let repro_curl = crate::poc_emit::render_raw_curl(
                &full_url,
                "GET",
                &[],
                None,
                techniques,
                *conf,
                &format!("scan bypass (variant {idx})"),
                None,
                Some(&format!("variant.{idx}")),
            )
            .unwrap_or_else(|_| crate::helpers::url_query_repro_curl(target, param, payload));
            serde_json::json!({
                "variant": idx,
                "payload": payload,
                "techniques": techniques,
                "confidence": conf,
                "minimal_payload": minimal,
                "repro_curl": repro_curl,
                "minimal_repro_curl": minimal
                    .map(|m| crate::helpers::url_query_repro_curl(target, param, m)),
            })
        })
        .collect()
}

/// Build the `layer_report` envelope that wraps the scan JSON when
/// `--report-layers` is set. Pure formatter; extracted for the same
/// reason as `build_bypass_variants_json`. The `scan_body` argument
/// is the already-built scan JSON; this fn only adds the wrapper.
pub(crate) fn build_layered_json(
    scan_body: serde_json::Value,
    target: &str,
    baseline_status: u16,
    waf_name: &str,
    detected: &[wafrift_detect::waf_detect::DetectedWaf],
    raw_status: u16,
    raw_blocked: bool,
    transport_ok: bool,
    total_fired: usize,
    requests_completed: u32,
    bypassed: u32,
    blocked: u32,
    errors: u32,
    bypass_rate: f64,
) -> serde_json::Value {
    serde_json::json!({
        "layer_report": {
            "network": {
                "target": target,
                "baseline_get_status": baseline_status,
            },
            "detection": {
                "chosen_waf": waf_name,
                "candidates": detected.iter().map(|d| {
                    serde_json::json!({
                        "name": d.name,
                        "confidence": d.confidence,
                        "indicators": d.indicators,
                    })
                }).collect::<Vec<_>>(),
            },
            "baseline_probe": {
                "raw_get_status": raw_status,
                "treated_as_blocked": raw_blocked,
                "transport_ok": transport_ok,
            },
            "evasion_campaign": {
                "variants_generated": total_fired,
                "requests_completed": requests_completed,
                "bypassed": bypassed,
                "blocked": blocked,
                "errors": errors,
                "bypass_rate_pct": bypass_rate,
            },
        },
        "scan": scan_body,
    })
}

/// Render the top summary banner of the text-output. Pure — the
/// caller writes the result via `print!`. Extracted from the
/// orchestrator so the colored top-of-scan summary is testable
/// without standing up a tokio runtime + mock server.
pub(crate) fn render_summary_text_block(
    waf_name: &str,
    total_fired: usize,
    requests_completed: u32,
    blocked: u32,
    bypassed: u32,
    errors: u32,
    bypass_rate: f64,
    elapsed_secs: f64,
) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{}",
        "══════════════════════════════════════════════════".bright_cyan()
    );
    let _ = writeln!(
        out,
        "  {} {}",
        "WAF:".bold().cyan(),
        waf_name.bold().yellow()
    );
    let _ = writeln!(
        out,
        "  {} {}",
        "Variants (scheduled):".bold().cyan(),
        format!("{total_fired}").bold()
    );
    let _ = writeln!(
        out,
        "  {} {}",
        "Requests completed:".bold().cyan(),
        format!("{requests_completed}").bold()
    );
    let _ = writeln!(
        out,
        "  {} {}",
        "Blocked:".bold().cyan(),
        format!("{blocked}").red().bold()
    );
    let _ = writeln!(
        out,
        "  {} {}",
        "Bypassed:".bold().cyan(),
        format!("{bypassed}").green().bold()
    );
    if errors > 0 {
        let _ = writeln!(
            out,
            "  {} {}",
            "Errors:".bold().cyan(),
            format!("{errors}").yellow()
        );
    }
    let _ = writeln!(
        out,
        "  {} {}",
        "Bypass Rate:".bold().cyan(),
        format!("{bypass_rate:.1}%")
            .bold()
            .color(if bypass_rate > 50.0 {
                colored::Color::BrightGreen
            } else if bypass_rate > 20.0 {
                colored::Color::Yellow
            } else {
                colored::Color::Red
            })
    );
    let _ = writeln!(out, "  {} {:.1}s", "Elapsed:".bold().cyan(), elapsed_secs);
    let _ = writeln!(
        out,
        "{}",
        "══════════════════════════════════════════════════".bright_cyan()
    );
    out
}

/// Render the per-bypass "Successful Bypasses" block for the text
/// output of `wafrift scan`. Pure — operates on a borrowed slice
/// and returns a single colored string the caller writes to stdout
/// via `print!`. Extracted so the orchestrator stays focused on
/// control flow and so the renderer is testable in isolation.
///
/// `variants` matches the orchestrator's `bypass_variants` Vec of
/// `(variant_idx, payload, techniques, confidence)` rows.
pub(crate) fn render_bypass_variants_text_block(
    variants: &[(usize, String, Vec<String>, f64)],
    param: &str,
    target: &str,
) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "\n{}",
        "Successful Bypasses:".bold().bright_green().underline()
    );
    for (idx, payload, techniques, confidence) in variants {
        let _ = writeln!(
            out,
            "\n  {} #{} {}",
            "Variant".bold().green(),
            idx,
            confidence_badge(*confidence)
        );
        let _ = writeln!(
            out,
            "  {} {}",
            "Techniques:".bold().cyan(),
            techniques.join(" → ").yellow()
        );
        // Print the full payload — practitioner needs the complete
        // wire bytes to paste into Burp/curl/sqlmap. Note the byte
        // length so they can spot truncation in their next step.
        let _ = writeln!(
            out,
            "  {} {} {}",
            "Payload:".bold().cyan(),
            payload.bright_white(),
            format!("({} bytes)", payload.len()).bright_black()
        );
        let _ = writeln!(
            out,
            "  {} curl -G --data-urlencode {}=$'{}' '{}'",
            "Reproduce:".bold().cyan(),
            param,
            payload.replace('\'', "'\\''"),
            target,
        );
    }
    out
}

/// Heuristic time-to-finish for a scan campaign. Used only for the
/// pre-fire estimate banner — the actual wall-clock varies with
/// target latency, retry-after backoff, and the exploit-chain phase
/// adding fires after the initial loop. This is a "first 90% of work
/// is the variant loop" approximation:
///
///   per_request ≈ delay + 300ms typical RTT
///   total       ≈ variants × per_request / parallelism(8)
///
/// Bounded to 1s minimum so a tight loop doesn't render "~0s" which
/// reads as "broken" to a fresh operator. Public to the module so the
/// banner code can call it twice (heavy estimate + light estimate)
/// without copy/paste.
#[must_use]
pub(crate) fn estimate_scan_seconds(variants: usize, delay_ms: u64) -> u64 {
    let typical_rtt_ms: u64 = 300;
    let parallelism: u64 = 8;
    let per_req_ms = delay_ms.saturating_add(typical_rtt_ms);
    let total_ms = (variants as u64).saturating_mul(per_req_ms) / parallelism.max(1);
    (total_ms / 1000).max(1)
}

/// Build a URL with `param=value_encoded` appended to the query string.
///
/// `value_encoded` MUST already be percent-encoded by the caller (e.g.
/// via `urlencoding::encode`). This function does NOT re-encode — it
/// concatenates the value verbatim so the wire payload is singly-encoded.
///
/// # Why not `append_pair`?
/// `reqwest::Url::query_pairs_mut().append_pair(k, v)` interprets `v` as
/// a raw (non-encoded) value and percent-encodes it again, producing
/// double-encoded output (`%20` → `%2520`). All callers of this function
/// pre-encode the payload, so using `append_pair` would corrupt every
/// evasion payload on the wire — turning `<script>` into `%253Cscript%253E`
/// instead of `%3Cscript%3E`, making the WAF see an obviously mangled token
/// rather than the actual evasion candidate.
pub(crate) fn scan_url_with_param(target: &str, param: &str, value_encoded: &str) -> String {
    let base = target.trim_end_matches('/');
    // Determine whether the base already has a query string so we use
    // `&` vs `?` as the separator.  Parse is attempted first to handle
    // complex URLs correctly; if the URL is not parseable we fall back
    // to a simple string-match on `?`.
    if let Ok(parsed) = reqwest::Url::parse(base) {
        let sep = if parsed.query().is_some() { "&" } else { "?" };
        format!("{base}{sep}{param}={value_encoded}")
    } else {
        // Unparseable target (e.g. typo'd scheme) — fall back to
        // a simple string check so the param is never lost.
        if base.contains('?') {
            format!("{base}&{param}={value_encoded}")
        } else {
            format!("{base}?{param}={value_encoded}")
        }
    }
}

/// Fire evasion variants against a live target and report bypass/block results.
pub(crate) async fn run_scan(
    mut args: ScanArgs,
    cancel: tokio_util::sync::CancellationToken,
) -> ExitCode {
    // `-r/--raw-request` mode: short-circuit to the raw-template
    // runner. The default scan loop assumes URL-query shape
    // (target + ?param=payload); the raw runner accepts an
    // operator-supplied Burp-saved request as the template and
    // mutates the payload at every `§§` marker. See
    // [`raw_runner::run_scan_raw`] for the runner's scope.
    if let Some(path) = args.raw_request.clone() {
        let text = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "{} could not read --raw-request file {}: {e}",
                    "Input error:".red().bold(),
                    path.display()
                );
                return ExitCode::from(2);
            }
        };
        let template = match crate::raw_request::parse_raw_http_request_with_scheme(
            &text,
            &args.raw_request_scheme,
        ) {
            Ok(t) => t,
            Err(e) => {
                eprintln!(
                    "{} could not parse --raw-request {}: {e}",
                    "Input error:".red().bold(),
                    path.display()
                );
                return ExitCode::from(2);
            }
        };
        return raw_runner::run_scan_raw(template, args, cancel).await;
    }

    // `--from-discovery` expansion (handled in main.rs) always sets a
    // concrete target; the direct path is clap-guaranteed to have one
    // via the `target_positional` OR `--target` arms of `ScanArgs`.
    let target_owned = crate::helpers::normalize_target_url(
        args.resolved_target().unwrap_or(""),
    );
    let target_owned = target_owned.trim_end_matches('/').to_string();
    let target = target_owned.as_str();

    // Permission gate: refuse to fire against any target the operator
    // hasn't authorized. Local/RFC1918 targets and the built-in bounty
    // allowlist are always permitted. All others require either
    // `--i-have-permission <reason>` or `~/.wafrift/permission.toml`.
    crate::permission::assert_permitted(target, args.i_have_permission.as_deref());
    if target.is_empty() {
        eprintln!(
            "{} target URL must be valid (e.g. https://example.com/search) — \
             pass it as the first positional arg or via --target, \
             or use --from-discovery <report.json|->",
            "Input error:".red().bold()
        );
        return ExitCode::from(1);
    }
    if args.payload.is_empty() {
        eprintln!(
            "{} --payload must not be empty (e.g. \"' OR 1=1--\")",
            "Input error:".red().bold()
        );
        return ExitCode::from(1);
    }

    // OOB callback substitution: when --callback-url is set + the
    // payload contains `{{CALLBACK}}`, mint a fresh token, substitute
    // the placeholder, and surface the assigned callback URL so the
    // operator can correlate any inbound hit at their listener back
    // to this scan. Skipped silently when either side is absent —
    // unchanged behaviour for scans that don't use OOB verification.
    //
    // The (token, callback_url, base_url) tuple is captured into
    // `callback_pending` so `callback_poll::verify` can ask the
    // listener "did you receive this token?" after the fire loop
    // — closes the oracle loop for blind/stored vuln classes that
    // never echo a verdict on the same response.
    let mut callback_pending: Option<callback_poll::CallbackPending> = None;
    if let Some(ref base_url) = args.callback_url {
        if let Some(sub) = crate::callback_token::substitute(&args.payload, base_url) {
            if args.format == "text" {
                eprintln!(
                    "{} oob callback URL substituted into payload — token = {}",
                    "[wafrift scan]".bright_cyan(),
                    sub.token.bold().yellow()
                );
                eprintln!(
                    "  watch your listener log for a hit at {}",
                    sub.callback_url.bright_white()
                );
            }
            callback_pending = Some(callback_poll::CallbackPending {
                token: sub.token,
                callback_url: sub.callback_url,
                base_url: base_url.clone(),
            });
            args.payload = sub.payload;
        } else if args.format == "text" {
            eprintln!(
                "{} --callback-url set but payload has no `{{{{CALLBACK}}}}` placeholder; \
                 no substitution performed.",
                "[wafrift scan]".bright_black()
            );
        }
    }
    let filter = match crate::technique_filter::TechniqueFilter::parse(&args.only, &args.exclude) {
        Ok(f) => f,
        Err(msg) => {
            eprintln!("{} {msg}", "Filter error:".red().bold());
            return ExitCode::from(2);
        }
    };
    let encoding_only = args.encoding_only || !filter.grammar_enabled();
    let payload_type = grammar::classify(&args.payload);
    let mut strategies = filter.filter_strategies(strategies_for_level(args.level));
    if strategies.is_empty() && !filter.is_default() {
        eprintln!(
            "{} no encoding strategies remain after --only/--exclude",
            "Filter error:".red().bold()
        );
        return ExitCode::from(2);
    }
    let max_mutations = max_mutations_for_level(args.level);

    // Gene bank: re-order strategies so historically proven ones go first.
    // When `--payload-class` is set, prefer the per-class winners (a SQLi
    // scan against Cloudflare warm-starts from the chains that beat CF
    // on SQLi yesterday — not the global average); the class-aware lookup
    // falls back to the global winners when this WAF has no per-class
    // history yet, so unset `--payload-class` keeps the existing
    // behaviour.
    let payload_class_pre = args.payload_class.as_deref().unwrap_or("");
    let gene_seed_names: Vec<String> = match GeneBank::open_default() {
        Ok(mut bank) => {
            let all_names: Vec<String> = bank
                .list_wafs()
                .into_iter()
                .flat_map(|waf| {
                    bank.load(&waf)
                        .map(|g| {
                            if payload_class_pre.is_empty() {
                                g.seed_winners()
                            } else {
                                g.seed_winners_for_class(payload_class_pre)
                            }
                        })
                        .unwrap_or_default()
                })
                .collect();
            if all_names.is_empty() {
                vec![]
            } else {
                all_names
            }
        }
        Err(e) => {
            eprintln!(
                "{} failed to open: {e}",
                "Gene bank warning:".yellow().bold(),
            );
            vec![]
        }
    };

    if !gene_seed_names.is_empty() {
        // Move strategies that match gene bank winners to the front.
        strategies.sort_by(|a, b| {
            let a_known = gene_seed_names
                .iter()
                .any(|s| s.contains(&format!("{a:?}")));
            let b_known = gene_seed_names
                .iter()
                .any(|s| s.contains(&format!("{b:?}")));
            b_known.cmp(&a_known) // true > false, so winners go first
        });
    }

    let mut variants = build_variants(
        &args.payload,
        payload_type,
        encoding_only,
        &strategies,
        max_mutations,
    );

    // Hard cap honours `--variants-cap N`. Truncation runs AFTER the
    // build (which already orders by confidence inside each
    // technique chain), so the lower-quality tail is what gets
    // dropped. A pre-cap eprintln tells the operator the truncation
    // happened — silent truncation would be confusing when they
    // notice the bypass set is smaller than expected.
    if args.variants_cap > 0 && variants.len() > args.variants_cap {
        let dropped = variants.len() - args.variants_cap;
        let original = variants.len();
        variants.truncate(args.variants_cap);
        eprintln!(
            "[wafrift scan] --variants-cap {} → keeping {} of {original} variants ({dropped} dropped from tail)",
            args.variants_cap,
            variants.len(),
        );
    }

    if variants.is_empty() {
        eprintln!(
            "{}",
            "No variants generated for the supplied payload."
                .red()
                .bold()
        );
        return ExitCode::from(1);
    }

    // TRACING: variant build outcome — visible at RUST_LOG=wafrift=debug.
    debug!(
        target: "wafrift::scan",
        variant_count = variants.len(),
        strategies = strategies.len(),
        payload_type = ?payload_type,
        encoding_only,
        level = ?args.level,
        "variant set built"
    );

    // `--quiet` AND `--format json` both suppress the human-readable
    // banner/progress lines. `--quiet` is the explicit "shut up" flag
    // a CI script reaches for when piping the output blob to disk;
    // `--format json` is the implicit one. Either is sufficient.
    let scan_text = !args.quiet && args.format != "json";
    if scan_text {
        println!(
            "{}\n",
            "╔══════════════════════════════════════════════════╗".bright_cyan()
        );
        println!(
            "{}  {}",
            "║".bright_cyan(),
            "WafRift Live WAF Evasion Scanner".bold().bright_white()
        );
        println!(
            "{}\n",
            "╚══════════════════════════════════════════════════╝".bright_cyan()
        );
        println!("  {} {}", "Target:".bold().cyan(), target.yellow());
        println!(
            "  {} {}",
            "Payload Type:".bold().cyan(),
            payload_type_label(payload_type).bold()
        );
        println!(
            "  {} {}",
            "Variants:".bold().cyan(),
            format!("{}", variants.len()).yellow()
        );
        println!(
            "  {} {}ms",
            "Delay:".bold().cyan(),
            format!("{}", args.delay_ms).yellow()
        );
        // Time-to-finish hint: a fresh operator launching `wafrift
        // scan ... --level heavy` against a target with --delay-ms
        // 500 sees nothing happen for 5 minutes and assumes the tool
        // is broken. Surface a rough wall-clock estimate AND the
        // exact tighter-loop flag so they can ^C and re-run in
        // light mode for a quick answer. Emitted on STDERR so a
        // `wafrift scan --format text | tee` pipeline doesn't end
        // up with the hint glued into the text body — the hint is
        // operator UX, not part of the result stream.
        let estimate_secs = estimate_scan_seconds(variants.len(), args.delay_ms);
        if estimate_secs >= 60 {
            let mins = estimate_secs / 60;
            let secs = estimate_secs % 60;
            eprintln!(
                "  {} ~{mins}m{secs:02}s (fast mode: `--level light` ~{}s)",
                "Estimated:".bold().cyan(),
                estimate_scan_seconds(variants.len() / 4, args.delay_ms.min(50)),
            );
        } else {
            eprintln!("  {} ~{estimate_secs}s", "Estimated:".bold().cyan(),);
        }
        println!();
    }

    // Unconditional startup line on STDERR — even in `--format json`
    // mode, where every `println!` above is suppressed and the only
    // stdout is the final JSON blob. Without this a JSON-mode scan
    // against a rate-limiting/slow target (the dogfood: 180 s of total
    // silence on try.discourse.org) is indistinguishable from a hung
    // process. stderr keeps stdout pure for `| jq`.
    let scan_started = std::time::Instant::now();
    eprintln!(
        "[wafrift scan] {} variants → {target} (param={}, level={:?}, delay={}ms) — progress on stderr, results on stdout",
        variants.len(),
        args.param,
        args.level,
        args.delay_ms
    );

    // Honest-contract guard: `--stealth-browser <profile>` is a flag
    // that scan currently does not wire. TLS-level browser
    // impersonation requires `rquest`/BoringSSL and lives in
    // `wafrift-proxy --tls-impersonate <profile>` (built with the
    // `tls-impersonate` feature). The flag is retained on `wafrift
    // scan` for backwards compatibility — pre-flag scripts that set
    // it keep working — but rather than silently doing nothing, we
    // surface a warning so operators relying on it know they're
    // getting reqwest/rustls TLS, not Chrome/Firefox bytes.
    if let Some(ref profile) = args.stealth_browser {
        eprintln!(
            "[wafrift scan] {} --stealth-browser={profile:?} is currently a no-op in `scan` \
             (CLI uses reqwest/rustls TLS). For wire-identical browser TLS, run \
             `wafrift-proxy --tls-impersonate {profile}` and route this scan through it.",
            "warn:".yellow().bold()
        );
    }

    // Per-request timeout: operator can override via `--timeout-secs`
    // (or `.wafrift.toml`'s `http.timeout_secs`); 0 keeps the workspace
    // default. Single source of truth for both the session-init client
    // and the main scan client.
    let request_timeout = Duration::from_secs(if args.timeout_secs > 0 {
        args.timeout_secs
    } else {
        wafrift_types::DEFAULT_REQUEST_TIMEOUT_SECS
    });

    // Step 0: Stateful chain — see `session_init_plug` module.
    let session_state = match session_init_plug::run(
        args.session_init.as_deref(),
        args.insecure,
        scan_text,
        request_timeout,
    )
    .await
    {
        Ok(s) => s,
        Err(code) => return code,
    };

    // Step 1: WAF detection — fetch target and identify WAF.
    // UA is operator-configurable via `.wafrift.toml`'s `http.user_agent`.
    // Default is a browser-shaped UA: CRS PL2+ rule 913100/913110
    // blocks `reqwest/*`, `curl/*`, `python-requests/*` before any
    // payload inspection ever runs.
    let scan_ua = crate::config::shared_user_agent();

    // Build the optional egress rotation pool from --egress-* flags
    // before the http client.  When ANY of --egress-socks5,
    // --egress-http-proxy, --egress-tailscale-nodes is non-empty the
    // pool routes every request through a rotating backend (with
    // challenge-based cooldown).  Empty inputs short-circuit to
    // None so the legacy single-client hot path is unchanged.
    let egress_inputs = crate::egress_args::EgressArgs {
        socks5: &args.egress_socks5,
        http_proxy: &args.egress_http_proxy,
        tailscale_nodes: &args.egress_tailscale_nodes,
        tailscale_socks_addr: &args.egress_tailscale_socks_addr,
        challenge_threshold: args.egress_challenge_threshold,
        cooldown_secs: args.egress_cooldown_secs,
    };
    let egress_pool = match crate::egress_args::build_egress_pool(&egress_inputs) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{} {e}", "✗ Egress pool config:".red().bold());
            return ExitCode::from(1);
        }
    };
    // Extract bare host for egress validation. EgressPool::next_for
    // gates on host-keyed cooldown state, so we feed it the target's
    // host. Empty string is the "no-pool" sentinel inside transport.
    let egress_host = egress_pool
        .as_ref()
        .and(crate::egress_args::target_host(target))
        .unwrap_or_default();
    let mut http_builder = match wafrift_transport::base_client_builder_with_egress(
        request_timeout.as_secs(),
        args.insecure,
        Some(&scan_ua),
        egress_pool.as_ref(),
        &egress_host,
    ) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "{} {e}\n    {}",
                "✗ Failed to build egress-aware HTTP client:".red().bold(),
                "hint: every entry in --egress-* may be in cooldown; lower --egress-challenge-threshold or wait for --egress-cooldown-secs".bright_black()
            );
            return ExitCode::from(1);
        }
    };
    http_builder = http_builder.redirect(reqwest::redirect::Policy::limited(5));
    if let Some(ref state) = session_state {
        // Default headers travel on every request issued by this
        // client — so cookies/auth captured at init replay through
        // detect, baseline, and every variant fire without each
        // call site needing to remember.
        http_builder = http_builder.default_headers(state.headers.clone());
    }
    // Pentest pivot: --proxy + -H/--header. See `pentest_client`
    // for the validation grammar and unit tests.
    http_builder = match pentest_client::apply_pentest_flags_or_print(
        http_builder,
        args.proxy.as_deref(),
        &args.header,
        session_state.as_ref().map(|s| &s.headers),
    ) {
        Ok(b) => b,
        Err(code) => return code,
    };
    let http = match http_builder.build() {
        Ok(client) => client,
        Err(e) => {
            eprintln!(
                "  {} reqwest builder error ({})\n    {}",
                "✗ Failed to create HTTP client:".red().bold(),
                e,
                "hint: this usually means a TLS backend (rustls / native-tls) failed to initialise — check OS root certs are present".bright_black()
            );
            return ExitCode::from(1);
        }
    };
    let scan_start = Instant::now();

    // ── GraphQL detection + payload injection ─────────────────────────
    // When --graphql is set OR the target auto-detects as a GraphQL
    // endpoint, inject the full wafrift-graphql battery into a
    // dedicated side-pool. These payloads are POST bodies (JSON), NOT
    // URL-query values, so they live in their own vec and are fired
    // separately (below) via POST to the detected GraphQL endpoint.
    let graphql_probe_result =
        graphql_phase::build_graphql_payloads(&http, target, args.graphql, scan_text).await;
    let (graphql_payloads, graphql_endpoint) =
        if let Some((payloads, endpoint)) = graphql_probe_result {
            (payloads, Some(endpoint))
        } else {
            (Vec::new(), None)
        };

    // Optional: load operator-supplied custom WAF detection signatures
    // (`--custom-rules <PATH>`). Layered on top of the built-in 160+
    // rule corpus inside `detect_phase::run`. A load error aborts the
    // scan early with a clear message rather than silently falling
    // back to built-ins, since the operator EXPLICITLY asked for the
    // custom set.
    let custom_rules = match args.custom_rules.as_ref() {
        Some(path) => {
            match wafrift_evolution::custom_rules::load_rules_from_file(path) {
                Ok(r) => Some(r),
                Err(e) => {
                    eprintln!(
                        "{} failed to load --custom-rules {}: {e}",
                        "error:".red().bold(),
                        path.display()
                    );
                    return ExitCode::from(1);
                }
            }
        }
        None => None,
    };

    // Step 1: WAF detection + advisor planning — see `detect_phase`.
    let detect_outcome = match detect_phase::run(
        &http,
        target,
        scan_text,
        custom_rules.as_ref(),
    )
    .await
    {
        Ok(o) => o,
        Err(code) => return code,
    };
    let baseline_status = detect_outcome.baseline_status;
    let _headers_vec = detect_outcome.headers_vec;
    let _body_bytes = detect_outcome.body_bytes;
    let detected = detect_outcome.detected;
    let waf_name = detect_outcome.waf_name;
    let _detected_waf_obj = detect_outcome.detected_waf_obj;
    let evasion_plan = detect_outcome.evasion_plan;

    // TRACING: WAF detection outcome — lets the operator confirm RUST_LOG=info
    // shows what the advisor decided and why strategies were weighted.
    info!(
        target: "wafrift::scan",
        waf = %waf_name,
        baseline_status,
        candidates = detected.len(),
        header_obf = evasion_plan.use_header_obfuscation,
        content_type_switch = evasion_plan.use_content_type_switch,
        h2 = evasion_plan.use_h2,
        "WAF detection complete"
    );
    let advisor_strategies = evasion_plan.encoding_strategies.clone();

    // Learning cache: load historical winning pipelines.
    let mut learning_cache = match LearningCache::open_default() {
        Ok(cache) => Some(cache),
        Err(e) => {
            eprintln!(
                "{} failed to open: {e}",
                "Learning cache warning:".yellow().bold(),
            );
            None
        }
    };
    let payload_type_str = format!("{payload_type:?}");
    if let Some(ref cache) = learning_cache {
        let key = CacheKey::new(&waf_name, &payload_type_str);
        if let Some(entry) = cache.get(&key)
            && scan_text
        {
            println!(
                "  {} cached pipeline '{}' — {:.0}% success rate",
                "📦 Learning cache:".bold().cyan(),
                entry.pipeline.name.yellow(),
                entry.success_rate() * 100.0
            );
        }
    }

    // Gene bank: load known bypasses for this WAF.
    if let Ok(mut bank) = GeneBank::open_default()
        && let Some(genome) = bank.load(&waf_name)
    {
        let seeds = genome.seed_winners();
        if !seeds.is_empty() && scan_text {
            println!(
                "\n  {} {} {}",
                "🧬".bold(),
                "Gene bank loaded:".bold().cyan(),
                format!(
                    "{} proven techniques from {} previous scan(s)",
                    seeds.len(),
                    genome.targets_scanned
                )
                .yellow()
            );
            for seed in seeds.iter().take(5) {
                let rate = genome
                    .top_techniques(20, 1)
                    .iter()
                    .find(|t| t.name == *seed)
                    .map_or(0.0, |t| t.success_rate() * 100.0);
                println!("    {} {:.0}% {}", "→".bright_cyan(), rate, seed.yellow());
            }
        }
    }

    // Step 2: Baseline — see `baseline` module.
    let baseline_outcome =
        baseline::run(&http, target, &args.param, &args.payload, scan_text).await;
    let raw_status = baseline_outcome.status;
    let raw_blocked = baseline_outcome.blocked;
    // Note: baseline_outcome.transport_ok was used downstream; preserved as
    // baseline_outcome.transport_ok for any later phase that needs
    // it (today none read it, but the baseline state is observable
    // via baseline_outcome.transport_ok if needed).

    // Step 2b: Differential probing — see `differential_phase` module.
    let mut intel_loop =
        differential_phase::run(&http, target, &args.param, args.delay_ms, scan_text).await;

    // Scan counters (declared early so cache replay can use them).
    let mut bypassed = 0_u32;
    let mut blocked = 0_u32;
    let mut errors = 0_u32;
    let mut _rate_limited = 0_u32;
    let mut _challenges = 0_u32;
    let mut bypass_variants: Vec<(usize, String, Vec<String>, f64)> = Vec::new();
    let mut variant_outcomes: Vec<(Vec<String>, bool)> = Vec::new();
    let delay = Duration::from_millis(args.delay_ms);
    let mut winning_strategies: HashSet<String> = HashSet::new();
    let mut total_fired = 0_usize;

    // Step 2c: Learning cache replay — try cached winning pipeline first.
    let mut cache_hit_bypass = false;
    if let Some(ref cache) = learning_cache {
        let key = CacheKey::new(&waf_name, &payload_type_str);
        if let Some(entry) = cache.get(&key)
            && entry.success_rate() > 0.5
        {
            // Replay the winning pipeline's encoding on raw payload.
            for tech in &entry.pipeline.stages {
                let encoded = match &tech.technique {
                    wafrift_types::Technique::PayloadEncoding(enc_name) => {
                        encoding::all_strategies()
                            .iter()
                            .find(|s| s.as_str() == enc_name.as_str())
                            .and_then(|s| match encoding::encode(&args.payload, *s) {
                                Ok(enc) => Some(enc),
                                Err(e) => {
                                    eprintln!(
                                        "{} {enc_name} failed: {e}",
                                        "Encoding warning:".yellow().bold(),
                                    );
                                    None
                                }
                            })
                    }
                    _ => None,
                };
                if let Some(ref enc_payload) = encoded {
                    let url =
                        scan_url_with_param(target, &args.param, &urlencoding::encode(enc_payload));
                    if let Ok(resp) = http.get(&url).send().await {
                        let status = resp.status().as_u16();
                        let body = crate::safe_body::read_bounded(
                            resp,
                            crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES,
                        )
                        .await
                        .unwrap_or_default();
                        if !is_waf_block(status, &body) {
                            cache_hit_bypass = true;
                            bypassed += 1;
                            total_fired += 1;
                            bypass_variants.push((
                                0,
                                enc_payload.clone(),
                                vec![format!("cache_replay::{}", tech.technique)],
                                0.95,
                            ));
                            if scan_text {
                                println!(
                                    "  {} cached pipeline '{}' bypassed immediately!",
                                    "⚡ Cache replay:".bold().green(),
                                    entry.pipeline.name.yellow()
                                );
                            }
                            break;
                        }
                    }
                }
            }
        }
    }

    // Step 2d: Differential-guided strategy reorder.
    // Promote encoding strategies that match differential insights.
    let diff_suggestions = intel_loop.suggested_evasions();
    if !diff_suggestions.is_empty() && scan_text {
        println!(
            "  {} promoting: {}",
            "🎯 Diff-guided:".bold().cyan(),
            diff_suggestions
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
                .yellow()
        );
    }

    // Step 2e: Equivalence moat (B→C→A) — the flagship engine.
    //
    // The sound-by-construction `(payload × delivery)` generator + the
    // per-WAF learned decision boundary (averaged-perceptron + CEGIS).
    // This is the EXACT loop the corpus bench measures
    // (`equiv_engine::run_equiv_cegis`) — here it runs against the live
    // target, keyed on the DETECTED WAF so the boundary compounds
    // across engagements (run #2 vs the same WAF warm-starts from
    // learned knowledge). Every member is independently
    // `verified_bypass`-gated: WAF passed + request reached the app +
    // the per-class oracle confirms it is still a structurally-valid
    // attack. No member is counted on shape alone.
    if !cancel.is_cancelled() {
        if let Some(class) = crate::equiv_engine::class_for_payload_type(payload_type) {
            if scan_text {
                println!(
                    "\n{}",
                    format!(
                        "[2e/7] Equivalence moat — B→C→A ({class}, learned-WAF CEGIS vs {waf_name})..."
                    )
                    .bold()
                    .cyan()
                );
            }
            let equiv_budget = match args.level {
                crate::Level::Light => 16usize,
                crate::Level::Medium => 40,
                crate::Level::Heavy => 96,
            };
            let moat = crate::equiv_engine::run_equiv_cegis(
                &http,
                |d, p| crate::equiv_engine::build_live_request_for_delivery(target, d, p),
                class,
                &args.payload,
                target,
                &args.param,
                equiv_budget,
                args.delay_ms,
                // Pre-fix this was hardcoded `DEFAULT_REQUEST_TIMEOUT_SECS`,
                // ignoring the operator's `--timeout-secs` setting. Every
                // OTHER scan phase respected request_timeout (the
                // computed Duration on line ~677), but the equiv moat
                // hardcoded the default — so an operator who raised
                // --timeout-secs to handle a slow target would still see
                // the moat phase time out at the workspace default.
                request_timeout.as_secs(),
                &waf_name,
            )
            .await;

            for b in &moat.bypasses {
                bypassed += 1;
                total_fired += 1;
                let techs = vec![
                    format!("equiv-moat::{}::{}", b.phase, b.delivery_label),
                    format!("equiv-rules::{}", b.rules.join("+")),
                ];
                variant_outcomes.push((techs.clone(), false));
                // Oracle-gated verified bypass → top confidence band.
                bypass_variants.push((total_fired, b.payload.clone(), techs, 0.97));
            }
            // Sends that did NOT yield a verified bypass are non-wins
            // (WAF-blocked, or slipped but oracle-rejected) — counted
            // truthfully as blocked, never as bypass.
            let non_bypass = moat.variants.saturating_sub(moat.bypasses.len());
            total_fired += non_bypass;
            // saturating_add: if `non_bypass` overflows u32 the conversion
            // yields u32::MAX, then the plain `+=` would wrap. Two saturations
            // keep the counter honest rather than wrapping to a wrong value.
            blocked = blocked.saturating_add(
                u32::try_from(non_bypass).unwrap_or(u32::MAX)
            );

            if scan_text {
                println!(
                    "  {} {} verified bypass / {} sent · {} slipped-but-oracle-rejected{}",
                    if moat.bypasses.is_empty() {
                        "✗".red().bold()
                    } else {
                        "⚡".bright_green().bold()
                    },
                    format!("{}", moat.bypasses.len()).bold(),
                    moat.variants,
                    moat.unverified_not_blocked,
                    if moat.model_saved {
                        " · per-WAF boundary refined+persisted".to_string()
                    } else {
                        String::new()
                    }
                );
                for b in moat.bypasses.iter().take(6) {
                    let shown: String = b.payload.chars().take(88).collect();
                    println!(
                        "    {} [{}|{}] {} (HTTP {})",
                        "→".bright_green(),
                        b.phase,
                        b.delivery_label.cyan(),
                        shown.yellow(),
                        b.status
                    );
                }
            }
        } else if scan_text {
            println!(
                "\n  {}",
                format!(
                    "[2e/7] Equivalence moat — skipped: no sound model for {} yet",
                    payload_type_label(payload_type)
                )
                .bright_black()
            );
        }
    }

    // Step 3: Explore — fire all pre-generated variants.
    if scan_text {
        if cache_hit_bypass {
            println!(
                "\n{}",
                "[3/7] Exploring evasion variants (cache hit — already have a bypass)..."
                    .bold()
                    .cyan()
            );
        } else {
            println!("\n{}", "[3/7] Exploring evasion variants...".bold().cyan());
        }
        println!();
    }

    // Create the response oracle for multi-signal classification.
    let oracle = std::sync::Arc::new(ResponseOracle::new());

    // Create the tamper registry for advanced payload transforms.
    let tamper_registry = TamperRegistry::with_defaults();
    // Tamper-only names that are NOVEL (not duplicating basic
    // encoding::encode).  Frontier 2025-2026 additions live below
    // the original four so the scan phase fires them too — leaving
    // them only in the registry means they're available via the
    // standalone `wafrift evade` command but inert during scans.
    let novel_tamper_names: Vec<&str> = vec![
        "sql_comment",
        "whitespace_insertion",
        "null_byte",
        "overlong_utf8",
        // Frontier additions (2026-05).  Each is a distinct
        // WAF-evasion class verified against ModSec PL4 + Coraza
        // mocks:
        "zero_width_inject",
        "postgres_dollar_quote",
        "mysql_versioned_comment_wrap",
        "bracket_confusable",
        "hex_literal_keyword",
        "bell_separator",
    ];

    // Concurrency level for parallel variant firing. Operator override
    // via `--concurrency N` (or `.wafrift.toml`'s `scan.concurrency`);
    // 0 = dynamic default (8 with no delay, 4 with one) — preserves
    // pre-flag behaviour for every existing invocation.
    let concurrency = if args.concurrency > 0 {
        args.concurrency
    } else if delay.is_zero() {
        8_usize
    } else {
        4
    };

    // Fire variants in concurrent batches.
    //
    // `aborted_rate_limited` is set when the target is so uniformly
    // rate-limiting that continuing is pointless and dishonest: every
    // 429 the oracle returns is *not* a bypass and *not* a block, it's
    // the target saying "slow down". The old code fired the entire
    // variant + tamper + header + vector set anyway — minutes of
    // requests producing a meaningless "0 bypasses" verdict. Now we
    // detect the condition early, cancel the run (every later phase
    // already polls `cancel.is_cancelled()`), and report it truthfully
    // with an exit code distinct from "scan completed, no bypass".
    let mut aborted_rate_limited = false;
    // Scan-wide rate-limit telemetry, surfaced in `--format json` so a
    // dashboard / CI consumer can tell "obeyed server cooldown" apart
    // from "fell back to computed exponential backoff".
    let mut retry_after_responses: u32 = 0;
    let mut max_retry_after_obeyed: Option<Duration> = None;
    let mut batches_done = 0_u32;
    let mut last_heartbeat = std::time::Instant::now();
    let mut variant_idx = 0_usize;
    while variant_idx < variants.len() {
        if cancel.is_cancelled() {
            if scan_text {
                println!(
                    "\n  {}",
                    "⚠ Cancelled — skipping remaining variants".yellow().bold()
                );
            }
            break;
        }

        // Build the next batch.
        let batch_end = (variant_idx + concurrency).min(variants.len());
        let batch: Vec<(usize, &crate::helpers::Variant)> = variants[variant_idx..batch_end]
            .iter()
            .enumerate()
            .map(|(i, v)| (variant_idx + i, v))
            .collect();

        // Fire all requests in this batch concurrently.
        let mut tasks = tokio::task::JoinSet::new();
        for (index, variant) in batch {
            let url =
                scan_url_with_param(target, &args.param, &urlencoding::encode(&variant.payload));
            let client = http.clone();
            let payload = variant.payload.clone();
            let techniques = variant.techniques.clone();
            let confidence = variant.confidence;
            let oracle = oracle.clone();
            tasks.spawn(async move {
                let (verdict, retry_after) = match client.get(&url).send().await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        // Capture Retry-After BEFORE the body — a polite
                        // 429/503 names how long to wait in this header
                        // and obeying it precisely (capped) is the
                        // single highest-yield rate-limit evasion.
                        let ra = if status == 429 || status == 503 {
                            let now = std::time::SystemTime::now();
                            resp.headers()
                                .get_all("retry-after")
                                .iter()
                                .filter_map(|v| v.to_str().ok())
                                .filter_map(|s| crate::retry_after::parse(s, now))
                                .max()
                        } else {
                            None
                        };
                        let body = crate::safe_body::read_bounded(
                            resp,
                            crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES,
                        )
                        .await
                        .unwrap_or_default();
                        let ctx = ResponseContext {
                            status,
                            body: body.to_vec(),
                            ..Default::default()
                        };
                        (Some(oracle.classify(&ctx)), ra)
                    }
                    Err(_) => (None, None),
                };
                (index, payload, techniques, confidence, verdict, retry_after)
            });
        }

        // Collect results (order doesn't matter for counting).
        let mut batch_rate_limited = false;
        // The strongest Retry-After (largest, capped at MAX_OBEYED) any
        // RL response in this batch named. None ⇒ no polite hint; fall
        // back to the existing exponential-backoff curve.
        let mut batch_retry_after: Option<Duration> = None;
        while let Some(result) = tasks.join_next().await {
            let Ok((index, payload, techniques, confidence, verdict_opt, retry_after_opt)) = result
            else {
                errors += 1;
                continue;
            };
            let Some(verdict) = verdict_opt else {
                errors += 1;
                continue;
            };

            let is_blocked = verdict.is_blocked();
            variant_outcomes.push((techniques.clone(), is_blocked));
            total_fired += 1;

            if matches!(verdict, wafrift_types::Verdict::RateLimited { .. }) {
                _rate_limited += 1;
                batch_rate_limited = true;
                if let Some(d) = retry_after_opt {
                    batch_retry_after = Some(batch_retry_after.map_or(d, |b| b.max(d)));
                    retry_after_responses += 1;
                    max_retry_after_obeyed = Some(max_retry_after_obeyed.map_or(d, |b| b.max(d)));
                }
                if args.format == "text" {
                    print!("{}", "R".yellow());
                }
            } else if verdict.is_challenge() {
                _challenges += 1;
                blocked += 1;
                if args.format == "text" {
                    print!("{}", "C".bright_yellow());
                }
            } else if is_blocked {
                blocked += 1;
                if args.format == "text" {
                    print!("{}", ".".bright_black());
                }
            } else {
                bypassed += 1;
                bypass_variants.push((
                    total_fired,
                    payload.clone(),
                    techniques.clone(),
                    confidence,
                ));
                // Record winning encoding strategies for exploitation.
                for tech in &techniques {
                    if tech.starts_with("encoding::") {
                        winning_strategies.insert(tech.clone());
                    }
                }
                // TRACING: bypass found — visible at RUST_LOG=wafrift=info so CI
                // consumers see each bypass without needing the full JSON blob.
                // Payload is shown truncated to 120 chars; never log session tokens
                // (techniques list identifies what changed, payload is the mutated
                // public string, not any credential).
                let payload_preview: String = payload.chars().take(120).collect();
                info!(
                    target: "wafrift::scan",
                    techniques = %techniques.join("+"),
                    confidence,
                    probe = total_fired,
                    payload = %payload_preview,
                    "bypass found"
                );
                if args.format == "text" {
                    print!("{}", "!".bright_green().bold());
                }
            }

            // Live progress: show rate every 20 variants.
            let done = index + 1;
            if args.format == "text" && done % 20 == 0 {
                let current_total = bypassed + blocked + errors;
                let rate = if current_total > 0 {
                    f64::from(bypassed) / f64::from(current_total) * 100.0
                } else {
                    0.0
                };
                let total_variants = variants.len();
                print!(
                    " {}",
                    format!("[{done}/{total_variants} {rate:.0}%]").bright_black()
                );
                let _ = io::stdout().flush();
            }
        }

        variant_idx = batch_end;
        batches_done += 1;

        // Heartbeat on stderr at most every 3 s (cache-window-friendly,
        // not spammy) so JSON-mode users — and anyone watching a
        // rate-limited target crawl — can see the scan is alive and
        // making progress instead of staring at a frozen terminal.
        if last_heartbeat.elapsed() >= Duration::from_secs(3) {
            eprintln!(
                "[wafrift scan] fired {total_fired}/{} · bypass {bypassed} · blocked {blocked} · rate-limited {_rate_limited} · err {errors} · {}s",
                variants.len(),
                scan_started.elapsed().as_secs()
            );
            last_heartbeat = std::time::Instant::now();
        }

        // Early rate-limit abort. Once we have a real sample
        // (≥12 fired) and the target has rate-limited ≥80% of them,
        // every additional request just deepens the ban and tells us
        // nothing. Stop, explain, and hand the operator the actual
        // remedies instead of silently grinding for minutes.
        // Magic-number rationale: `12` is the smallest sample where
        // "rate of 429s exceeds 80%" is statistically meaningful
        // (≥10 throttles out of ≥12); `0.80` is the fraction above
        // which continued firing is dishonest — every later 429
        // is target-controlled, not a bypass / not a block. Both
        // values pinned here rather than exposed as flags because
        // operators tuning them have always-wrong intuition about
        // the math; the tuning knob that DOES matter is
        // `--delay-ms`, which delays the cohort firing.
        if total_fired >= 12 && f64::from(_rate_limited) / total_fired.max(1) as f64 >= 0.80 {
            aborted_rate_limited = true;
            // TRACING: rate-limit abort — critical signal that the scan was
            // inconclusive (not "clean, no bypass"). Surfaced at warn level so
            // operators with RUST_LOG=wafrift=warn still see it.
            warn!(
                target: "wafrift::scan",
                rate_limited = _rate_limited,
                total_fired,
                target = %target,
                "scan aborted: ≥80% probes rate-limited — results would be noise"
            );
            eprintln!(
                "\n[wafrift scan] {} {}/{} probes were rate-limited (HTTP 429/slow-down). \
                 Aborting — the target is throttling us, so any \"bypass/blocked\" \
                 verdict would be noise, not signal.\n  Remedies:\n    \
                 • raise --delay-ms (e.g. --delay-ms 2000) to stay under the limit\n    \
                 • spread requests across egress IPs (--egress-socks5 / --egress-http-proxy / --egress-tailscale-nodes)\n    \
                 • test an endpoint that is not behind the per-IP limiter",
                "RATE-LIMITED:".yellow().bold(),
                _rate_limited,
                total_fired
            );
            // Cancel so every subsequent phase (tamper/header/vector),
            // which already checks `cancel.is_cancelled()`, stops too.
            cancel.cancel();
            break;
        }

        // Inter-batch delay: prefer the server's own Retry-After hint
        // when any 429/503 named one; else escalating backoff (×2 per
        // consecutive throttled batch, capped) so we ease off the
        // target instead of hammering a fixed 2× delay. Add ±20%
        // jitter so we do not all-clients-at-once re-fire at the same
        // instant the limiter window opens (some WAFs penalise that).
        if batch_rate_limited {
            let computed = {
                let factor = 2_u32.saturating_pow(batches_done.min(4));
                (delay.max(Duration::from_millis(50)))
                    .saturating_mul(factor)
                    .min(Duration::from_secs(30))
            };
            // Honest hint > our guess. Both are already capped (the
            // header parser at MAX_OBEYED, the computed at 30 s).
            let base = batch_retry_after.map_or(computed, |ra| ra.max(computed));
            let backoff =
                crate::retry_after::jittered(base, u32::try_from(total_fired).unwrap_or(u32::MAX));
            if let Some(ra) = batch_retry_after {
                eprintln!(
                    "[wafrift scan] obeying Retry-After: {} ms (server-named cooldown)",
                    ra.as_millis()
                );
            }
            tokio::time::sleep(backoff).await;
        } else if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }

    // Step 3b: Tamper — apply novel tamper strategies to grammar mutations.
    // These are fundamentally different from encoding: SQL comment insertion (/**/),
    // overlong UTF-8, null byte injection exploit WAF implementation bugs.
    if !encoding_only {
        let tamper_context = match payload_type {
            PayloadType::Sql => Some("sql"),
            PayloadType::Xss => Some("xss"),
            PayloadType::CommandInjection => Some("cmd"),
            _ => None,
        };

        let grammar_mutations = grammar::mutate_as(&args.payload, payload_type, max_mutations);
        let mut tamper_seen: HashSet<String> = HashSet::new();
        // Seed seen set with explore payloads.
        for v in &variants {
            tamper_seen.insert(v.payload.clone());
        }

        if scan_text {
            println!(
                "\n\n{}",
                format!(
                    "[3b/7] Tamper probing — {} mutations × {} tamper strategies...",
                    grammar_mutations.len(),
                    novel_tamper_names.len()
                )
                .bold()
                .cyan()
            );
        }

        let mut tamper_bypassed = 0_u32;
        let mut tamper_fired = 0_u32;

        // Operator-supplied plugin tampers loaded from
        // `~/.wafrift/tampers/`. Loaded once-per-process via OnceLock
        // inside plugin_bridge; we just consume them per mutation
        // alongside the built-in novel_tamper_names. Plugin names are
        // dynamic (driven by the operator's filesystem), so we cache
        // them once outside the loop to avoid hammering the registry.
        let plugin_names: Vec<String> = wafrift_strategy::plugin_bridge::plugin_names();
        if scan_text && !plugin_names.is_empty() {
            println!(
                "  {} {} external plugin(s) loaded from ~/.wafrift/tampers/: {}",
                "Plugins:".bold().cyan(),
                plugin_names.len(),
                plugin_names.join(", ").bright_black()
            );
        }

        for mutation in &grammar_mutations {
            if cancel.is_cancelled() {
                break;
            }
            // Apply every operator-loaded plugin to this mutation.
            // Each plugin produces (name, transformed_payload); we
            // fire each transformed payload as its own variant,
            // tagged `plugin::<name>` so winning strategies are
            // attributable.  Skips de-dupes against the seen-set so
            // a plugin that no-ops doesn't burn a request.
            for (plugin_name, transformed) in
                wafrift_strategy::plugin_bridge::apply_all_plugins(&mutation.payload)
            {
                if cancel.is_cancelled() {
                    break;
                }
                if !tamper_seen.insert(transformed.clone()) {
                    continue;
                }
                let url =
                    scan_url_with_param(target, &args.param, &urlencoding::encode(&transformed));
                let verdict = match http.get(&url).send().await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let body = crate::safe_body::read_bounded(
                            resp,
                            crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES,
                        )
                        .await
                        .unwrap_or_default();
                        oracle.classify(&ResponseContext {
                            status,
                            body: body.to_vec(),
                            ..Default::default()
                        })
                    }
                    Err(_) => {
                        errors += 1;
                        continue;
                    }
                };
                total_fired += 1;
                tamper_fired += 1;
                let mut techniques: Vec<String> = mutation
                    .rules_applied
                    .iter()
                    .map(|r| (*r).to_string())
                    .collect();
                techniques.push(format!("plugin::{plugin_name}"));
                let is_blocked = verdict.is_blocked() || verdict.is_challenge();
                variant_outcomes.push((techniques.clone(), is_blocked));
                if is_blocked {
                    blocked += 1;
                } else if matches!(verdict, wafrift_types::Verdict::RateLimited { .. }) {
                    _rate_limited += 1;
                    tokio::select! {
                        () = tokio::time::sleep(delay * 2) => {}
                        () = cancel.cancelled() => { break; }
                    }
                } else {
                    bypassed += 1;
                    tamper_bypassed += 1;
                    bypass_variants.push((
                        total_fired,
                        transformed,
                        techniques.clone(),
                        0.75,
                    ));
                    winning_strategies.insert(format!("plugin::{plugin_name}"));
                }
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
            }
            for tamper_name in &novel_tamper_names {
                let tampered = match tamper_registry.tamper_with(
                    tamper_name,
                    &mutation.payload,
                    tamper_context,
                ) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                if !tamper_seen.insert(tampered.clone()) {
                    continue;
                }

                let url = scan_url_with_param(target, &args.param, &urlencoding::encode(&tampered));

                let verdict = match http.get(&url).send().await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let body = crate::safe_body::read_bounded(
                            resp,
                            crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES,
                        )
                        .await
                        .unwrap_or_default();
                        oracle.classify(&ResponseContext {
                            status,
                            body: body.to_vec(),
                            ..Default::default()
                        })
                    }
                    Err(_) => {
                        errors += 1;
                        continue;
                    }
                };

                total_fired += 1;
                tamper_fired += 1;

                let mut techniques: Vec<String> = mutation
                    .rules_applied
                    .iter()
                    .map(|r| (*r).to_string())
                    .collect();
                techniques.push(format!("tamper::{tamper_name}"));
                let is_blocked = verdict.is_blocked() || verdict.is_challenge();
                variant_outcomes.push((techniques.clone(), is_blocked));

                if is_blocked {
                    blocked += 1;
                    if args.format == "text" {
                        print!("{}", ".".bright_black());
                    }
                } else if matches!(verdict, wafrift_types::Verdict::RateLimited { .. }) {
                    _rate_limited += 1;
                    // Race the cooldown sleep against cancellation so
                    // Ctrl-C / budget-exhaustion exits within the
                    // millisecond window, not after `delay * 2`.
                    // Pre-fix the operator could be stuck waiting
                    // seconds for the next outer-loop check while
                    // every live request slot was held.
                    tokio::select! {
                        () = tokio::time::sleep(delay * 2) => {}
                        () = cancel.cancelled() => { break; }
                    }
                } else {
                    bypassed += 1;
                    tamper_bypassed += 1;
                    bypass_variants.push((
                        total_fired,
                        tampered,
                        techniques.clone(),
                        0.75, // Tamper bypasses get moderate-high confidence
                    ));
                    // Record winning tamper strategies for exploitation.
                    winning_strategies.insert(format!("tamper::{tamper_name}"));
                    if args.format == "text" {
                        print!("{}", "!".bright_green().bold());
                    }
                }

                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
            }
        }

        if scan_text && tamper_fired > 0 {
            let rate = f64::from(tamper_bypassed) / f64::from(tamper_fired) * 100.0;
            println!(
                "\n  {} {}",
                "Tamper results:".bold().cyan(),
                format!("{tamper_bypassed}/{tamper_fired} bypassed ({rate:.0}%)").yellow()
            );
        }
    }

    // Step 3c: GraphQL evasion probe — fire the wafrift-graphql battery
    // against the detected (or forced) GraphQL endpoint via POST with
    // `Content-Type: application/json`. The technique label is
    // `graphql::<class>` so the scan JSON is self-documenting and the
    // gene-bank can accumulate per-class bypass history.
    if let Some(ref gql_endpoint) = graphql_endpoint {
        let gql_endpoint = gql_endpoint.clone();
        let gql_count = graphql_payloads.len();
        if scan_text {
            println!(
                "\n{}",
                format!("[3c/7] GraphQL evasion probe — {gql_count} payloads → {gql_endpoint}")
                    .bold()
                    .cyan()
            );
        }
        let mut gql_bypassed = 0_u32;
        let mut gql_fired = 0_u32;
        for (gql_idx, body) in graphql_payloads.iter().enumerate() {
            if cancel.is_cancelled() {
                break;
            }
            // Classify payload class from body content so the technique
            // label is informative in the JSON/text output.
            let class_label = if body.contains("AliasFlood") {
                "alias-flood"
            } else if body.contains("operationName") {
                "op-name-mismatch"
            } else if body.contains("__schema") || body.contains("__type") {
                "introspection"
            } else if body.contains("DeepTest") || body.contains("FragmentTest") {
                "depth-bomb"
            } else if body.starts_with('[') {
                "batch"
            } else {
                "field-suggestion"
            };
            let verdict = match http
                .post(&gql_endpoint)
                .header("Content-Type", "application/json")
                .body(body.clone())
                .send()
                .await
            {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let resp_body = crate::safe_body::read_bounded(
                        resp,
                        crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES,
                    )
                    .await
                    .unwrap_or_default();
                    oracle.classify(&ResponseContext {
                        status,
                        body: resp_body.to_vec(),
                        ..Default::default()
                    })
                }
                Err(_) => {
                    errors += 1;
                    continue;
                }
            };

            total_fired += 1;
            gql_fired += 1;
            let techniques = vec![
                format!("graphql::{class_label}"),
                format!("graphql::payload#{gql_idx}"),
            ];
            let is_blocked = verdict.is_blocked() || verdict.is_challenge();
            variant_outcomes.push((techniques.clone(), is_blocked));

            if is_blocked {
                blocked += 1;
                if args.format == "text" {
                    print!("{}", ".".bright_black());
                }
            } else if matches!(verdict, wafrift_types::Verdict::RateLimited { .. }) {
                _rate_limited += 1;
                if !delay.is_zero() {
                    tokio::time::sleep(delay * 2).await;
                }
            } else {
                bypassed += 1;
                gql_bypassed += 1;
                bypass_variants.push((
                    total_fired,
                    body.clone(),
                    techniques.clone(),
                    0.85, // GraphQL evasion payloads have high structural confidence
                ));
                info!(
                    target: "wafrift::scan::graphql",
                    class = class_label,
                    endpoint = %gql_endpoint,
                    probe = total_fired,
                    "GraphQL bypass found"
                );
                if args.format == "text" {
                    print!("{}", "!".bright_green().bold());
                }
            }

            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
        }

        if scan_text && gql_fired > 0 {
            let rate = if gql_fired > 0 {
                f64::from(gql_bypassed) / f64::from(gql_fired) * 100.0
            } else {
                0.0
            };
            println!(
                "\n  {} {}",
                "GraphQL results:".bold().cyan(),
                format!("{gql_bypassed}/{gql_fired} bypassed ({rate:.0}%)").yellow()
            );
        }
    }

    // Step 4: Exploit — amplify winning strategies via chaining, cross-pollination, and fresh mutations.
    if !winning_strategies.is_empty() && !cancel.is_cancelled() {
        // Resolve winning strategy enums from their debug names.
        let all_strats = encoding::all_strategies();
        let mut exploit_strategies: Vec<Strategy> = all_strats
            .iter()
            .filter(|s| winning_strategies.contains(&format!("encoding::{s:?}")))
            .copied()
            .collect();
        // Expand with advisor-recommended strategies not already in the pool.
        for adv_strat in &advisor_strategies {
            if !exploit_strategies.contains(adv_strat) {
                exploit_strategies.push(*adv_strat);
            }
        }
        // Honor user --only/--exclude: even gene-bank winners and advisor
        // recommendations must respect the configured technique surface.
        exploit_strategies = filter.filter_strategies(exploit_strategies);

        // Collect the raw (pre-encoding) payloads that produced bypasses, paired with their encoding.
        // We'll cross-pollinate these with other winning encodings.
        let mut winning_raw_payloads: Vec<(String, Vec<String>)> = Vec::new();
        // Also collect already-encoded bypass payloads for chaining.
        let mut encoded_bypass_payloads: Vec<(String, Vec<String>)> = Vec::new();

        for v in &variants {
            // Check if this variant bypassed (exists in bypass_variants).
            if bypass_variants.iter().any(|(_, p, _, _)| p == &v.payload) {
                // The raw payload before encoding is the grammar mutation.
                // We can't perfectly recover it, but we CAN identify which grammar mutations
                // led to bypasses by looking at the techniques list.
                encoded_bypass_payloads.push((v.payload.clone(), v.techniques.clone()));
            }
        }

        // Also collect the grammar mutations that bypassed for cross-pollination.
        // We search the original build_variants output: for each bypassed variant,
        // find the mutation payload text and record it.
        // Strategy: re-derive from original mutations — the encode is invertible for our purposes
        // because we're going to re-encode with different strategies anyway.
        let original_mutations = if encoding_only {
            Vec::new()
        } else {
            grammar::mutate_as(
                &args.payload,
                payload_type,
                max_mutations_for_level(args.level),
            )
        };

        // Build a lookup: encoded_payload → list of grammar mutations that could produce it
        // (by trying all strategies against each mutation).
        for mutation in &original_mutations {
            for strategy in &exploit_strategies {
                if let Ok(encoded) = encoding::encode(&mutation.payload, *strategy)
                    && bypass_variants.iter().any(|(_, p, _, _)| p == &encoded)
                {
                    winning_raw_payloads.push((
                        mutation.payload.clone(),
                        mutation
                            .rules_applied
                            .iter()
                            .map(std::string::ToString::to_string)
                            .collect(),
                    ));
                    break; // Don't add the same raw payload multiple times for different strategies
                }
            }
        }

        // Dedup raw payloads
        winning_raw_payloads.sort_by(|a, b| a.0.cmp(&b.0));
        winning_raw_payloads.dedup_by(|a, b| a.0 == b.0);

        if scan_text {
            println!(
                "\n\n{}",
                format!(
                    "[4/7] Exploiting {} winning strategies × {} winning mutations...",
                    exploit_strategies.len(),
                    winning_raw_payloads.len(),
                )
                .bold()
                .green()
            );
            println!(
                "  {} encoding chaining (stack two encodings)",
                "→".bright_green()
            );
            println!(
                "  {} cross-pollination (winning mutations × all winning encodings)",
                "→".bright_green()
            );
            println!(
                "  {} fresh mutations with winning encodings",
                "→".bright_green()
            );
            println!();
        }

        let mut exploit_seen: HashSet<String> = HashSet::new();
        for v in &variants {
            exploit_seen.insert(v.payload.clone());
        }

        // Helper closure: fire a candidate and record results.
        // Returns true if bypass, false if blocked, None if error.
        // Pre-flag this was hardcoded `500_usize`; against a rate-
        // limited target with `--delay-ms 500` that silently added up
        // to 250 s to every scan. Operator now tunes via `--exploit-cap`.
        let exploit_cap = args.exploit_cap;
        let mut exploit_count = 0_usize;

        // ── Phase 4a: Encoding chaining ───────────────────────────────────────
        // Take already-bypassed encoded payloads and apply a SECOND encoding on top.
        // This creates double-encoded variants that are extremely hard for WAFs to decode.
        if scan_text {
            print!("  {}", "chaining: ".bright_cyan());
            let _ = io::stdout().flush();
        }
        let mut chain_bypassed = 0_u32;
        let mut chain_fired = 0_u32;

        // Only chain with URL-safe encodings (stacking Base64→Gzip makes no HTTP sense)
        let chainable: Vec<Strategy> = exploit_strategies
            .iter()
            .copied()
            .filter(|s| {
                matches!(
                    s,
                    Strategy::DoubleUrlEncode
                        | Strategy::TripleUrlEncode
                        | Strategy::UrlEncode
                        | Strategy::UrlEncodeLower
                        | Strategy::CaseAlternation
                        | Strategy::RandomCase
                        | Strategy::PercentagePrefix
                        | Strategy::HtmlEntityEncode
                        | Strategy::HtmlEntityDecimalEncode
                        | Strategy::UnicodeEncode
                        | Strategy::IisUnicodeEncode
                )
            })
            .collect();

        'chain_loop: for (bypass_payload, bypass_techs) in &encoded_bypass_payloads {
            for second_encoding in &chainable {
                if exploit_count >= exploit_cap {
                    break 'chain_loop;
                }
                let chained = match encoding::encode(bypass_payload, *second_encoding) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                if !exploit_seen.insert(chained.clone()) {
                    continue;
                }

                let url = scan_url_with_param(target, &args.param, &urlencoding::encode(&chained));

                let is_blocked = match http.get(&url).send().await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let body = crate::safe_body::read_bounded(
                            resp,
                            crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES,
                        )
                        .await
                        .unwrap_or_default();
                        is_waf_block(status, &body)
                    }
                    Err(_) => {
                        errors += 1;
                        continue;
                    }
                };

                total_fired += 1;
                exploit_count += 1;
                chain_fired += 1;

                let mut techniques = bypass_techs.clone();
                techniques.push(format!("chain::{second_encoding:?}"));
                variant_outcomes.push((techniques.clone(), is_blocked));

                if is_blocked {
                    blocked += 1;
                    if args.format == "text" {
                        print!("{}", ".".bright_black());
                    }
                } else {
                    bypassed += 1;
                    chain_bypassed += 1;
                    bypass_variants.push((total_fired, chained, techniques, 0.9));
                    if args.format == "text" {
                        print!("{}", "!".bright_green().bold());
                    }
                }

                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
            }
        }

        if scan_text && chain_fired > 0 {
            let rate = f64::from(chain_bypassed) / f64::from(chain_fired) * 100.0;
            println!(
                " {}",
                format!("{chain_bypassed}/{chain_fired} ({rate:.0}%)").yellow()
            );
        } else if scan_text {
            println!("{}", "skipped".bright_black());
        }

        // ── Phase 4b: Cross-pollination ──────────────────────────────────────
        // Take winning grammar mutations and try them with ALL winning encodings,
        // not just the one that originally worked.
        if scan_text {
            print!("  {}", "cross-pollination: ".bright_cyan());
            let _ = io::stdout().flush();
        }
        let mut xpol_bypassed = 0_u32;
        let mut xpol_fired = 0_u32;

        'xpol_loop: for (raw_payload, raw_rules) in &winning_raw_payloads {
            for strategy in &exploit_strategies {
                if exploit_count >= exploit_cap {
                    break 'xpol_loop;
                }
                let encoded = match encoding::encode(raw_payload, *strategy) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                if !exploit_seen.insert(encoded.clone()) {
                    continue;
                }

                let url = scan_url_with_param(target, &args.param, &urlencoding::encode(&encoded));

                let is_blocked = match http.get(&url).send().await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let body = crate::safe_body::read_bounded(
                            resp,
                            crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES,
                        )
                        .await
                        .unwrap_or_default();
                        is_waf_block(status, &body)
                    }
                    Err(_) => {
                        errors += 1;
                        continue;
                    }
                };

                total_fired += 1;
                exploit_count += 1;
                xpol_fired += 1;

                let mut techniques = raw_rules.clone();
                techniques.push(format!("encoding::{strategy:?}"));
                variant_outcomes.push((techniques.clone(), is_blocked));

                if is_blocked {
                    blocked += 1;
                    if args.format == "text" {
                        print!("{}", ".".bright_black());
                    }
                } else {
                    bypassed += 1;
                    xpol_bypassed += 1;
                    bypass_variants.push((
                        total_fired,
                        encoded,
                        techniques,
                        variant_confidence(payload_type, raw_rules.len(), false, *strategy),
                    ));
                    if args.format == "text" {
                        print!("{}", "!".bright_green().bold());
                    }
                }

                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
            }
        }

        if scan_text && xpol_fired > 0 {
            let rate = f64::from(xpol_bypassed) / f64::from(xpol_fired) * 100.0;
            println!(
                " {}",
                format!("{xpol_bypassed}/{xpol_fired} ({rate:.0}%)").yellow()
            );
        } else if scan_text {
            println!("{}", "skipped".bright_black());
        }

        // ── Phase 4c: Fresh mutations with winning strategies ────────────────
        // Generate MORE grammar mutations from the original seed and encode with winners.
        if scan_text {
            print!("  {}", "fresh mutations: ".bright_cyan());
            let _ = io::stdout().flush();
        }
        let mut fresh_bypassed = 0_u32;
        let mut fresh_fired = 0_u32;

        let max_exploit_rounds = 2;
        'fresh_outer: for round in 0..max_exploit_rounds {
            if exploit_count >= exploit_cap {
                break;
            }

            let round_mutations = max_mutations_for_level(args.level) + (round + 1) * 6;
            let fresh_mutations = if encoding_only {
                Vec::new()
            } else {
                grammar::mutate_as(&args.payload, payload_type, round_mutations)
            };

            for mutation in &fresh_mutations {
                for strategy in &exploit_strategies {
                    if exploit_count >= exploit_cap {
                        break 'fresh_outer;
                    }
                    let encoded = match encoding::encode(&mutation.payload, *strategy) {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    if !exploit_seen.insert(encoded.clone()) {
                        continue;
                    }

                    let url =
                        scan_url_with_param(target, &args.param, &urlencoding::encode(&encoded));

                    let is_blocked = match http.get(&url).send().await {
                        Ok(resp) => {
                            let status = resp.status().as_u16();
                            let body = crate::safe_body::read_bounded(
                                resp,
                                crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES,
                            )
                            .await
                            .unwrap_or_default();
                            is_waf_block(status, &body)
                        }
                        Err(_) => {
                            errors += 1;
                            continue;
                        }
                    };

                    total_fired += 1;
                    exploit_count += 1;
                    fresh_fired += 1;

                    let mut techniques: Vec<String> = mutation
                        .rules_applied
                        .iter()
                        .map(|r| (*r).to_string())
                        .collect();
                    techniques.push(format!("encoding::{strategy:?}"));
                    variant_outcomes.push((techniques.clone(), is_blocked));

                    if is_blocked {
                        blocked += 1;
                        if args.format == "text" {
                            print!("{}", ".".bright_black());
                        }
                    } else {
                        bypassed += 1;
                        fresh_bypassed += 1;
                        bypass_variants.push((
                            total_fired,
                            encoded,
                            techniques,
                            variant_confidence(
                                payload_type,
                                mutation.rules_applied.len(),
                                false,
                                *strategy,
                            ),
                        ));
                        if args.format == "text" {
                            print!("{}", "!".bright_green().bold());
                        }
                    }

                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        if scan_text && fresh_fired > 0 {
            let rate = f64::from(fresh_bypassed) / f64::from(fresh_fired) * 100.0;
            println!(
                " {}",
                format!("{fresh_bypassed}/{fresh_fired} ({rate:.0}%)").yellow()
            );
        } else if scan_text {
            println!("{}", "skipped".bright_black());
        }

        if scan_text {
            let exploit_total = chain_fired + xpol_fired + fresh_fired;
            let exploit_bypass = chain_bypassed + xpol_bypassed + fresh_bypassed;
            let rate = if exploit_total > 0 {
                f64::from(exploit_bypass) / f64::from(exploit_total) * 100.0
            } else {
                0.0
            };
            println!(
                "\n  {} {}",
                "Exploit total:".bold().cyan(),
                format!(
                    "{exploit_bypass}/{exploit_total} bypassed ({rate:.0}%) — {exploit_count} requests"
                )
                .yellow()
                .bold()
            );
        }
    } else if scan_text {
        println!(
            "\n\n{}",
            "[4/7] No bypasses found to exploit — skipping amplification".bright_black()
        );
    }

    // Step 5: Multi-vector — re-fire top bypass payloads through
    // alternative delivery vectors. The dispatch + per-vector
    // request shape lives in `scan::multi_vector`; this file is
    // just the caller that merges the phase's outcome back into
    // the running counters. Adding a new vector is a single-file
    // edit in `scan/multi_vector.rs`.
    //
    // The phase fires every vector against TWO pools:
    //   1. top_payloads (already bypassed) — broaden the bypass set
    //   2. rescue_payloads (top blocked) — rescue payloads that
    //      were viable but got caught on their original delivery
    //      shape. Header-obfuscation phase already does rescue;
    //      doing it for multi-vector roughly doubles the number
    //      of bypass opportunities the operator gets per scan.
    if (!bypass_variants.is_empty() || !variants.is_empty()) && !cancel.is_cancelled() {
        // Dedup the top-confidence payloads BEFORE handing them
        // to the phase — keeps the phase module ignorant of how
        // bypass_variants is structured.
        let mut top_payloads: Vec<(String, Vec<String>)> = bypass_variants
            .iter()
            .take(10)
            .map(|(_, payload, techs, _)| (payload.clone(), techs.clone()))
            .collect();
        // HashSet::retain — bypass_variants order is confidence-sorted
        // (highest-first), not payload-sorted. dedup_by would only
        // collapse adjacent equal payloads and leave non-adjacent
        // dupes to fire as wasted probes against rate-limit budget.
        let mut seen_top: std::collections::HashSet<String> = std::collections::HashSet::new();
        top_payloads.retain(|(payload, _)| seen_top.insert(payload.clone()));

        // Top blocked payloads for rescue attempts — any variant
        // whose payload string isn't already in the bypass set.
        // Take 20 (vs the earlier 10) — the bench against ModSec
        // PL4 shows the compression / BOM wrap vectors land at
        // 100% on these payloads, so doubling the rescue pool
        // doubles the bypass yield from this phase at the cost
        // of one bounded request per (payload × vector) pair.
        let bypass_payload_set: std::collections::HashSet<&String> =
            bypass_variants.iter().map(|(_, p, _, _)| p).collect();
        let mut rescue_payloads: Vec<(String, Vec<String>)> = variants
            .iter()
            .filter(|v| !bypass_payload_set.contains(&v.payload))
            .take(20)
            .map(|v| (v.payload.clone(), vec![]))
            .collect();
        // Same reasoning as top_payloads above: variants iter is
        // generation-order, not sorted, so dedup_by would miss
        // non-adjacent dupes.
        let mut seen_rescue: std::collections::HashSet<String> = std::collections::HashSet::new();
        rescue_payloads.retain(|(payload, _)| seen_rescue.insert(payload.clone()));

        let phase = multi_vector::run_phase(multi_vector::PhaseInput {
            http: &http,
            target,
            param: &args.param,
            top_payloads: &top_payloads,
            rescue_payloads: &rescue_payloads,
            cancel: &cancel,
            scan_text,
            delay,
            variant_id_base: total_fired,
        })
        .await;

        total_fired += phase.total_fired_delta;
        bypassed += phase.bypassed_delta;
        blocked += phase.blocked_delta;
        errors += phase.errors_delta;
        variant_outcomes.extend(phase.new_variant_outcomes);
        bypass_variants.extend(phase.new_bypass_variants);
    } else if scan_text {
        println!(
            "\n{}",
            "[5/7] No payloads — skipping multi-vector probing".bright_black()
        );
    }

    // Step 6/7: Header obfuscation probing — exploit WAF header
    // parser bugs. Dispatch + per-technique wire shape lives in
    // `scan::header_obf_phase`.
    if evasion_plan.use_header_obfuscation && !bypass_variants.is_empty() {
        let top_bypass_payloads: Vec<String> = bypass_variants
            .iter()
            .take(5)
            .map(|(_, p, _, _)| p.clone())
            .collect();
        let bypass_payload_set: std::collections::HashSet<&String> =
            bypass_variants.iter().map(|(_, p, _, _)| p).collect();
        let blocked_payloads: Vec<String> = variants
            .iter()
            .filter(|v| !bypass_payload_set.contains(&v.payload))
            .take(5)
            .map(|v| v.payload.clone())
            .collect();

        let phase = header_obf_phase::run_phase(header_obf_phase::PhaseInput {
            http: &http,
            target,
            param: &args.param,
            top_payloads: &top_bypass_payloads,
            rescue_payloads: &blocked_payloads,
            oracle: &oracle,
            cancel: &cancel,
            scan_text,
            delay,
            variant_id_base: total_fired,
        })
        .await;

        total_fired += phase.total_fired_delta;
        bypassed += phase.bypassed_delta;
        blocked += phase.blocked_delta;
        errors += phase.errors_delta;
        variant_outcomes.extend(phase.new_variant_outcomes);
        bypass_variants.extend(phase.new_bypass_variants);
    }

    // Step 7/7: Intelligence loop — evolution-guided candidate generation.
    if intel_loop.has_sufficient_data() {
        if scan_text {
            println!(
                "\n{}",
                "[7/7] Intelligence loop — evolving candidates..."
                    .bold()
                    .cyan()
            );
        }

        let max_intel_rounds = 50_usize.min(200_usize.saturating_sub(total_fired));
        let mut intel_bypassed = 0_u32;
        let mut intel_fired = 0_u32;

        // Seed the evolution with differential insights for smarter candidates.
        for _suggestion in &diff_suggestions {
            if let Some((idx, _)) = intel_loop.next_candidate() {
                // Record "virtual" positive feedback for the suggested technique
                // to bias the evolution towards it.
                intel_loop.record_feedback(idx, true);
            }
        }

        for _ in 0..max_intel_rounds {
            if let Some((idx, chromosome)) = intel_loop.next_candidate() {
                // Use the chromosome's gene flags to build a payload variant.
                let has_grammar = chromosome.genes.iter().any(|(k, _)| k == "grammar");
                let enc_gene = chromosome
                    .genes
                    .iter()
                    .find(|(k, _)| k == "encoding")
                    .map(|(_, v)| v.clone());

                let intel_payload = if has_grammar {
                    let mutations = grammar::mutate_as(&args.payload, payload_type, 1);
                    mutations
                        .first()
                        .map_or(args.payload.clone(), |m| m.payload.clone())
                } else {
                    args.payload.clone()
                };

                // Apply the chromosome's encoding if set.
                let encoded = if let Some(ref enc_name) = enc_gene {
                    encoding::all_strategies()
                        .iter()
                        .find(|s| s.as_str() == enc_name.as_str())
                        .map_or(intel_payload.clone(), |s| {
                            encoding::encode(&intel_payload, *s)
                                .unwrap_or_else(|_| intel_payload.clone())
                        })
                } else {
                    intel_payload.clone()
                };

                let url = scan_url_with_param(target, &args.param, &urlencoding::encode(&encoded));

                let verdict = match http.get(&url).send().await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let body = crate::safe_body::read_bounded(
                            resp,
                            crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES,
                        )
                        .await
                        .unwrap_or_default();
                        oracle.classify(&ResponseContext {
                            status,
                            body: body.to_vec(),
                            ..Default::default()
                        })
                    }
                    Err(_) => {
                        errors += 1;
                        intel_loop.record_feedback(idx, false);
                        continue;
                    }
                };

                let passed = !verdict.is_blocked() && !verdict.is_challenge();
                intel_loop.record_feedback(idx, passed);
                intel_fired += 1;
                total_fired += 1;

                if passed {
                    intel_bypassed += 1;
                    bypassed += 1;
                    let mut techs = Vec::new();
                    if has_grammar {
                        techs.push("intel::grammar".to_string());
                    }
                    if let Some(ref enc) = enc_gene {
                        techs.push(format!("intel::encoding::{enc}"));
                    }
                    techs.push("intel::evolution".to_string());
                    bypass_variants.push((total_fired, encoded, techs, 0.80));
                    if scan_text {
                        print!("{}", "!".bright_green().bold());
                    }
                } else if scan_text {
                    print!("{}", ".".bright_black());
                }

                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
            }
        }

        // Evolve population for future use.
        intel_loop.evolve();

        if scan_text && intel_fired > 0 {
            let rate = f64::from(intel_bypassed) / f64::from(intel_fired) * 100.0;
            println!(
                "\n  {} {} (diversity: {:.2})",
                "Intel results:".bold().cyan(),
                format!("{intel_bypassed}/{intel_fired} bypassed ({rate:.0}%)").yellow(),
                intel_loop.diversity()
            );
        }
    }

    // The intel-phase pretty-divider above. Guarded: in `--format json`
    // mode the only stdout bytes must be the JSON blob; a bare
    // `println!("\n")` here breaks `wafrift scan --format json | jq .`
    // (jq rejects the leading blank line).
    if scan_text {
        println!("\n");
    }

    // Results.
    let elapsed = scan_start.elapsed();
    // Rate-limited requests are real fired probes — including them in
    // the denominator keeps the bypass % honest. Pre-fix a target
    // that 80% rate-limited would inflate the apparent bypass rate
    // by 5× (50/100 instead of 50/500 = 10%), making a noisy run
    // look like a strong result on paper.
    // saturating_add: each counter is u32. A pathological scan (≫4 B probes)
    // would otherwise wrap, producing a bypass_rate that is wildly wrong.
    // Saturation to u32::MAX is the honest ceiling — the bypass % is still
    // computable (it just shows the minimum bounded rate, not garbage).
    let requests_completed = bypassed
        .saturating_add(blocked)
        .saturating_add(errors)
        .saturating_add(_rate_limited);
    let bypass_rate = if requests_completed > 0 {
        f64::from(bypassed) / f64::from(requests_completed) * 100.0
    } else {
        0.0
    };

    // ── Auto-distill pass (--auto-distill) ─────────────────────
    //
    // For each bypass found, run Zeller's ddmin to find the
    // minimum-edit-distance payload that STILL bypasses via the
    // URL-query shape. Off by default; opt-in via `--auto-distill`.
    // Distillation always fires via `scan_url_with_param`
    // regardless of which phase originally produced the bypass —
    // for multi-vector / header-obf bypasses the distilled form
    // tells the operator what the minimum URL-query equivalent is
    // (a useful artefact even when the original used a different
    // shape; operator interprets accordingly).
    let mut minimal_payloads: Vec<Option<String>> = vec![None; bypass_variants.len()];
    let mut auto_distill_fires_total: u64 = 0;
    if args.auto_distill && !bypass_variants.is_empty() && !cancel.is_cancelled() {
        if scan_text {
            println!(
                "  {} auto-distilling {} bypass(es) via URL-query shape (cap {} fires each)…",
                "[wafrift scan distill]".bright_cyan().bold(),
                bypass_variants.len().to_string().bold().yellow(),
                args.auto_distill_max_fires
            );
        }
        let http_arc = std::sync::Arc::new(http.clone());
        let target_owned = target.to_string();
        let param = args.param.clone();
        for (i, (_, original_payload, _, _)) in bypass_variants.iter().enumerate() {
            if cancel.is_cancelled() {
                break;
            }
            let fires = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
            let cap = args.auto_distill_max_fires;
            let predicate = {
                let http = http_arc.clone();
                let t = target_owned.clone();
                let p = param.clone();
                let fires = fires.clone();
                let cancel = cancel.clone();
                move |candidate: String| {
                    let http = http.clone();
                    let t = t.clone();
                    let p = p.clone();
                    let fires = fires.clone();
                    let cancel = cancel.clone();
                    async move {
                        if cancel.is_cancelled() {
                            return false;
                        }
                        if fires.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= cap {
                            return false;
                        }
                        let url = scan_url_with_param(&t, &p, &urlencoding::encode(&candidate));
                        match http.get(&url).send().await {
                            Ok(resp) => {
                                let status = resp.status().as_u16();
                                match resp.bytes().await {
                                    Ok(body) => !is_waf_block(status, &body),
                                    Err(_) => false,
                                }
                            }
                            Err(_) => false,
                        }
                    }
                }
            };
            let minimum = crate::distill_cmd::ddmin(original_payload, predicate).await;
            auto_distill_fires_total += u64::from(fires.load(std::sync::atomic::Ordering::SeqCst));
            minimal_payloads[i] = Some(minimum);
        }
    }

    if args.format == "json" {
        let scan = json!({
            "scan_schema_version": 1,
            "target": target,
            "waf": waf_name,
            "payload_type": payload_type_label(payload_type),
            // `total_variants` is misleadingly named — it's the count
            // of HTTP fires across ALL phases (explore + exploit +
            // multi-vector + header-obf + intelligence loop). The
            // initial variant pool size lives in `explore_variants`
            // below. We keep `total_variants` for backwards-compat
            // (existing scripts read it) and add the clearer alias
            // `total_requests_fired` so new consumers don't get
            // confused. Both fields hold the same value.
            "total_variants": total_fired,
            "total_requests_fired": total_fired,
            "explore_variants": variants.len(),
            "exploit_variants": total_fired.saturating_sub(variants.len()),
            "winning_strategies": winning_strategies.iter().cloned().collect::<Vec<_>>(),
            "requests_completed": requests_completed,
            "baseline_transport_ok": baseline_outcome.transport_ok,
            "bypassed": bypassed,
            "blocked": blocked,
            "errors": errors,
            "rate_limited": _rate_limited,
            "aborted_rate_limited": aborted_rate_limited,
            // How many of the RL responses came with a parseable
            // Retry-After header — distinguishes a polite WAF
            // (positive count) from a bare 429 limiter (zero).
            "retry_after_responses": retry_after_responses,
            // Max wait we obeyed (capped by retry_after::MAX_OBEYED).
            // Null when no RL response named one.
            "max_retry_after_obeyed_ms":
                max_retry_after_obeyed.map(|d| d.as_millis() as u64),
            "bypass_rate_pct": bypass_rate,
            "elapsed_ms": elapsed.as_secs_f64() * 1000.0,
            "auto_distill_enabled": args.auto_distill,
            "auto_distill_fires_total": auto_distill_fires_total,
            "bypass_variants": build_bypass_variants_json(target, &args.param, &bypass_variants, &minimal_payloads),
        });
        let json_output = if args.report_layers {
            build_layered_json(
                scan,
                target,
                baseline_status,
                &waf_name,
                &detected,
                raw_status,
                raw_blocked,
                baseline_outcome.transport_ok,
                total_fired,
                requests_completed,
                bypassed,
                blocked,
                errors,
                bypass_rate,
            )
        } else {
            scan
        };
        match serde_json::to_string_pretty(&json_output) {
            Ok(s) => {
                if let Some(ref path) = args.output {
                    if let Err(e) = std::fs::write(path, &s) {
                        eprintln!("failed to write scan output to {}: {e}", path.display());
                        return ExitCode::from(1);
                    }
                    eprintln!("scan results written to {}", path.display());
                } else {
                    println!("{s}");
                }
                // Exit 5 = run aborted because the target rate-limited
                // us; distinct from 0 (clean, no bypass) so CI / wrapper
                // scripts don't read throttling as "WAF held".
                return if aborted_rate_limited {
                    ExitCode::from(5)
                } else {
                    ExitCode::SUCCESS
                };
            }
            Err(e) => {
                eprintln!("failed to serialize scan JSON: {e}");
                return ExitCode::from(1);
            }
        }
    }

    // Text output. F77: --quiet now suppresses the final text
    // summary too. Pre-fix --quiet only silenced the pre-scan
    // banner + per-phase progress; the final 100KB+ report still
    // dumped to stdout, breaking the --quiet docstring contract
    // ("a script piping the JSON to disk sees only the JSON
    // blob"). When --format is text AND --quiet is set, suppress
    // the report entirely — operators who want a clean summary
    // should pass --format json explicitly.
    if !args.quiet {
        print!(
            "{}",
            render_summary_text_block(
                &waf_name,
                total_fired,
                requests_completed,
                blocked,
                bypassed,
                errors,
                bypass_rate,
                elapsed.as_secs_f64(),
            )
        );

        if !bypass_variants.is_empty() {
            print!(
                "{}",
                render_bypass_variants_text_block(&bypass_variants, &args.param, target)
            );
        }
    }

    // ── Gene Bank: per-technique successes and attempts across all fired variants ─────────
    let mut tech_acc: std::collections::HashMap<String, (u32, u32)> =
        std::collections::HashMap::new();
    for (techs, blocked) in variant_outcomes {
        for t in techs {
            let e = tech_acc.entry(t).or_insert((0, 0));
            e.1 += 1;
            if !blocked {
                e.0 += 1;
            }
        }
    }
    let stats: Vec<(String, u32, u32)> = tech_acc
        .into_iter()
        .map(|(name, (s, a))| (name, s, a))
        .collect();

    if !stats.is_empty() {
        // When `--payload-class` was set, persist BOTH the global
        // totals AND a per-class breakdown so subsequent scans of the
        // same `(waf, class)` warm-start with class-specific winners.
        let payload_class_post = args.payload_class.as_deref().unwrap_or("");
        match GeneBank::open_default() {
            Ok(mut bank) => {
                let save_result = if payload_class_post.is_empty() {
                    bank.merge_and_save(&waf_name, &stats)
                } else {
                    bank.merge_and_save_for_class(&waf_name, payload_class_post, &stats)
                };
                match save_result {
                    Ok(()) => {
                        // TRACING: gene bank write — confirms bypass artefacts were
                        // persisted, not just printed. Operators debugging "why did
                        // the next scan not warm-start?" can check this line.
                        info!(
                            target: "wafrift::scan",
                            waf = %waf_name,
                            techniques_saved = stats.len(),
                            payload_class = %payload_class_post,
                            "gene bank updated"
                        );
                        if scan_text {
                            let class_suffix = if payload_class_post.is_empty() {
                                String::new()
                            } else {
                                format!(" (class={payload_class_post})")
                            };
                            println!(
                                "\n{} {} {}",
                                "🧬".bold(),
                                "Gene bank updated:".bold().cyan(),
                                format!(
                                    "{} techniques saved for {waf_name}{class_suffix}",
                                    stats.len()
                                )
                                .yellow()
                            );
                        }
                    }
                    Err(e) => {
                        warn!(
                            target: "wafrift::scan",
                            waf = %waf_name,
                            error = %e,
                            "gene bank save failed"
                        );
                        eprintln!("  {} {}", "⚠ Gene bank save failed:".yellow(), e);
                    }
                }
            }
            Err(e) => {
                warn!(
                    target: "wafrift::scan",
                    error = %e,
                    "gene bank unavailable"
                );
                eprintln!("  {} {}", "⚠ Gene bank unavailable:".yellow(), e);
            }
        }
    }

    // Learning cache: save winning pipelines for future scans.
    if !bypass_variants.is_empty()
        && let Some(ref mut cache) = learning_cache
    {
        // Build a pipeline from the best winning technique combination.
        let best_techniques: Vec<wafrift_strategy::pipeline::EvasionStage> = bypass_variants
            .first()
            .map(|(_, _, techs, _)| {
                techs
                    .iter()
                    .map(|t| {
                        if t.starts_with("encoding::") {
                            wafrift_strategy::pipeline::EvasionStage {
                                technique: wafrift_types::Technique::PayloadEncoding(t.clone()),
                                context: None,
                            }
                        } else if t.starts_with("tamper::") {
                            wafrift_strategy::pipeline::EvasionStage {
                                technique: wafrift_types::Technique::GrammarMutation(t.clone()),
                                context: None,
                            }
                        } else if t.starts_with("vector::") {
                            wafrift_strategy::pipeline::EvasionStage {
                                technique: wafrift_types::Technique::ContentTypeSwitch(t.clone()),
                                context: None,
                            }
                        } else {
                            wafrift_strategy::pipeline::EvasionStage {
                                technique: wafrift_types::Technique::GrammarMutation(t.clone()),
                                context: None,
                            }
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Validate composition ordering.
        let layers: Vec<composition::EvasionLayer> = best_techniques
            .iter()
            .map(|t| match &t.technique {
                wafrift_types::Technique::PayloadEncoding(_) => composition::EvasionLayer::Encoding,
                wafrift_types::Technique::GrammarMutation(_) => composition::EvasionLayer::Grammar,
                wafrift_types::Technique::ContentTypeSwitch(_) => {
                    composition::EvasionLayer::ContentType
                }
                wafrift_types::Technique::HeaderObfuscation(_) => composition::EvasionLayer::Header,
                _ => composition::EvasionLayer::Encoding,
            })
            .collect();
        let valid_order = composition::is_valid_sequence(&layers);

        let techniques_for_cost: Vec<_> = best_techniques
            .iter()
            .map(|s| s.technique.clone())
            .collect();
        let pipeline_cost = cost::pipeline_cost(&techniques_for_cost);
        let pipeline = EvasionPipeline::new(
            format!("auto_{waf_name}_{payload_type_str}"),
            best_techniques,
            pipeline_cost,
        );

        let key = CacheKey::new(&waf_name, &payload_type_str);
        cache.record_success(key, pipeline);
        if let Err(e) = cache.save() {
            eprintln!("  {} {}", "⚠ Learning cache save failed:".yellow(), e);
        } else if scan_text {
            println!(
                "{} {} (cost: {}, valid order: {})",
                "📦".bold(),
                "Learning cache updated".bold().cyan(),
                pipeline_cost,
                if valid_order { "yes" } else { "no" }
            );
        }
    }

    if args.report_layers && scan_text {
        println!(
            "\n{}",
            "Layer summary (docs/GAP_CLOSURE_ROADMAP.md):"
                .bold()
                .bright_black()
        );
        println!(
            "  network: baseline_get_status={}  detection: {} candidate(s)  baseline_probe: raw_get_status={} treated_as_blocked={}  evasion: bypass_rate={:.1}%",
            baseline_status,
            detected.len(),
            raw_status,
            raw_blocked,
            bypass_rate,
        );
    }

    // OOB callback verification: when --callback-url was set and a
    // token was minted, delegate to `callback_poll::verify` which
    // hits the listener's /_wafrift/check/<TOKEN> management API.
    if let Some(ref pending) = callback_pending {
        let verdict =
            callback_poll::verify(pending, Duration::from_secs(args.callback_timeout_secs)).await;
        if scan_text {
            match verdict {
                callback_poll::CallbackVerdict::Verified => {
                    println!(
                        "{} {} (token {} fired at {})",
                        "📡".bold(),
                        "OOB callback VERIFIED — blind / stored vuln confirmed"
                            .bold()
                            .green(),
                        pending.token.bold().yellow(),
                        pending.callback_url.bright_white()
                    );
                }
                callback_poll::CallbackVerdict::NotObserved => {
                    println!(
                        "{} {} (token {})",
                        "📡".bright_black(),
                        "OOB callback not observed".bright_black(),
                        pending.token.bright_black()
                    );
                }
                callback_poll::CallbackVerdict::ListenerUnreachable => {
                    println!(
                        "{} {} — verify your listener is running at {}",
                        "📡".yellow(),
                        "OOB callback listener unreachable".yellow(),
                        pending.base_url.bright_white()
                    );
                }
            }
        }
    }

    if scan_text {
        // Trailing blank line for terminal-friendly spacing.
        // Gated on scan_text so --quiet truly produces NO stdout
        // (the F77 contract fix).
        println!();
    }
    if aborted_rate_limited {
        ExitCode::from(5)
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimate_clamps_to_one_second_minimum() {
        // A zero-variant zero-delay scan would compute 0s, which
        // reads as "broken" in the banner. The estimator floors at
        // 1 to keep the displayed value honest.
        assert_eq!(estimate_scan_seconds(0, 0), 1);
        assert_eq!(estimate_scan_seconds(1, 0), 1);
    }

    #[test]
    fn estimate_scales_roughly_with_variants() {
        // 100 variants at 50ms delay, 300ms RTT, 8-way parallel:
        // (100 * 350) / 8 = 4375ms ≈ 4s. Just sanity-check the
        // formula is in the right ballpark — exact tuning isn't
        // load-bearing.
        let est = estimate_scan_seconds(100, 50);
        assert!((3..=6).contains(&est), "estimate out of band: {est}");
    }

    #[test]
    fn estimate_grows_with_delay() {
        let fast = estimate_scan_seconds(50, 0);
        let slow = estimate_scan_seconds(50, 500);
        assert!(
            slow > fast,
            "raising delay must raise the estimate: {fast} vs {slow}"
        );
    }

    #[test]
    fn estimate_handles_saturation_without_panic() {
        // Pathologically large inputs (e.g. an operator typing
        // `--delay-ms 9999999999`) must not wrap arithmetic.
        let est = estimate_scan_seconds(usize::MAX, u64::MAX);
        // We don't assert a specific value — only that it didn't
        // panic and returned something non-zero.
        assert!(est >= 1);
    }

    #[test]
    fn scan_url_with_param_appends_query() {
        let url = scan_url_with_param("http://x/", "q", "abc");
        assert!(url.contains("q=abc"), "expected q=abc in {url}");
    }

    #[test]
    fn scan_url_with_param_falls_back_on_unparseable_input() {
        // resolve_target may pass through a string reqwest::Url
        // can't parse (e.g. when the operator typo'd the scheme).
        // The fallback must still produce something with the param
        // baked in — never throw the payload on the floor.
        let url = scan_url_with_param("not a url", "q", "abc");
        assert!(url.contains("q=abc"), "fallback dropped param: {url}");
    }

    /// Core anti-double-encoding contract.
    ///
    /// All firing paths pre-encode the payload with `urlencoding::encode`
    /// then pass the result to `scan_url_with_param`. The function must
    /// NOT re-encode — if it did, `%3C` (the pre-encoded `<`) would become
    /// `%253C` on the wire and every evasion payload would arrive at the
    /// WAF as visually mangled garbage, producing false "blocked" verdicts.
    #[test]
    fn scan_url_with_param_does_not_double_encode_pre_encoded_value() {
        // `<script>` → urlencoding::encode → `%3Cscript%3E`
        let pre_encoded = urlencoding::encode("<script>").to_string();
        let url = scan_url_with_param("http://target/", "q", &pre_encoded);
        // The pre-encoded form must survive verbatim.
        assert!(
            url.contains("%3Cscript%3E"),
            "pre-encoded value must not be re-encoded; got: {url}"
        );
        // Double-encoding would produce %253C. If that's in the URL the
        // WAF sees an escaped '%' instead of the payload — a guaranteed
        // false-block for every variant.
        assert!(
            !url.contains("%253C"),
            "double-encoding detected: %25 found, indicating % was re-encoded: {url}"
        );
    }

    #[test]
    fn scan_url_with_param_produces_valid_separator_without_existing_query() {
        let url = scan_url_with_param("http://target/search", "q", "test");
        assert!(url.contains('?'), "must use ? when no query exists: {url}");
        assert!(url.contains("q=test"), "param missing: {url}");
        // Must NOT have double ? or && which would produce malformed URLs.
        assert_eq!(url.matches('?').count(), 1, "exactly one ? expected: {url}");
    }

    #[test]
    fn scan_url_with_param_uses_ampersand_when_query_already_present() {
        let url = scan_url_with_param("http://target/search?existing=1", "q", "abc");
        // Should append with & not produce a second ?.
        assert!(
            url.contains("existing=1") && url.contains("q=abc"),
            "both params must survive: {url}"
        );
        assert_eq!(url.matches('?').count(), 1, "must not add a second ?: {url}");
        assert!(url.contains('&'), "must use & to append: {url}");
    }

    #[test]
    fn scan_url_with_param_preserves_special_chars_in_pre_encoded_value() {
        // A SQL tautology pre-encoded: "' OR '1'='1" → contains %27 etc.
        let raw = "' OR '1'='1";
        let pre = urlencoding::encode(raw).to_string();
        let url = scan_url_with_param("http://t/", "q", &pre);
        // The %27 (apostrophe) must arrive singly-encoded, not as %2527.
        assert!(url.contains("%27"), "apostrophe must be %27, got: {url}");
        assert!(
            !url.contains("%2527"),
            "double-encoded apostrophe detected: {url}"
        );
    }

    #[test]
    fn build_bypass_variants_json_single_encodes_payload_in_repro_url() {
        // build_bypass_variants_json passes the raw payload to
        // scan_url_with_param with a pre-encoding step. Verify no
        // double-encoding in the resulting full_url used for repro_curl.
        let variants = vec![(
            0usize,
            "<script>alert(1)</script>".to_string(),
            vec!["xss::raw".to_string()],
            0.9_f64,
        )];
        let minimal_payloads: Vec<Option<String>> = vec![None];
        let results = build_bypass_variants_json(
            "http://target/",
            "q",
            &variants,
            &minimal_payloads,
        );
        assert_eq!(results.len(), 1);
        let repro = results[0]["repro_curl"].as_str().unwrap_or("");
        // The curl reproducer must contain the encoded tag, not a double-encoded form.
        // %3Cscript%3E is the single-encoded form; %253Cscript%253E is double.
        assert!(
            !repro.contains("%253C"),
            "repro_curl must not double-encode the payload: {repro}"
        );
    }

    // ── --variants-cap honesty ───────────────────────────────
    //
    // The full firing path is end-to-end-tested via dogfood + the
    // legendary subprocess integration test. Here we pin the
    // truncation semantics on a synthetic variant Vec so a future
    // refactor (e.g. moving the cap check earlier or later in the
    // pipeline) keeps the contract: ordered truncation, no panic
    // on cap==0, no panic on cap>=len.

    #[test]
    fn variants_cap_zero_means_no_truncation() {
        let mut v: Vec<u32> = (0..10).collect();
        let cap: usize = 0;
        if cap > 0 && v.len() > cap {
            v.truncate(cap);
        }
        assert_eq!(v.len(), 10, "cap=0 must not truncate");
    }

    #[test]
    fn variants_cap_truncates_to_n_when_under_total() {
        let mut v: Vec<u32> = (0..100).collect();
        let cap: usize = 25;
        if cap > 0 && v.len() > cap {
            v.truncate(cap);
        }
        assert_eq!(v.len(), 25);
        // Order-preserving: first 25 elements survive (the build is
        // already ordered by confidence, so we keep the strongest).
        assert_eq!(v[0], 0);
        assert_eq!(v[24], 24);
    }

    #[test]
    fn variants_cap_no_op_when_at_or_above_total() {
        let mut v: Vec<u32> = (0..10).collect();
        let cap: usize = 100;
        if cap > 0 && v.len() > cap {
            v.truncate(cap);
        }
        assert_eq!(v.len(), 10, "cap above total must not truncate");
    }

    // ── Pure text-renderer extractions (post-modularization) ──
    //
    // These pin the output shape of the helpers extracted out of
    // the run_scan orchestrator. Each helper is pure (string in,
    // string out) so we can assert on the rendered bytes without
    // standing up a tokio runtime + mock target. ANSI color codes
    // are stripped before assertions so the tests pass under both
    // TTY and non-TTY colored detection.

    fn strip_ansi(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut iter = s.chars().peekable();
        while let Some(c) = iter.next() {
            if c == '\u{1b}' && iter.peek() == Some(&'[') {
                iter.next();
                for cc in iter.by_ref() {
                    if cc.is_alphabetic() {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    #[test]
    fn render_summary_text_block_contains_all_top_level_counters() {
        let s = strip_ansi(&render_summary_text_block(
            "Cloudflare",
            30,
            28,
            25,
            3,
            1,
            10.7,
            4.2,
        ));
        // Every counter must surface — operator scrolling the
        // banner needs to see the absolute numbers AND the rate.
        assert!(s.contains("WAF: Cloudflare"), "WAF line missing:\n{s}");
        assert!(s.contains("Variants (scheduled): 30"));
        assert!(s.contains("Requests completed: 28"));
        assert!(s.contains("Blocked: 25"));
        assert!(s.contains("Bypassed: 3"));
        assert!(s.contains("Errors: 1"), "errors > 0 must surface:\n{s}");
        assert!(s.contains("Bypass Rate: 10.7%"));
        assert!(s.contains("Elapsed: 4.2s"));
    }

    #[test]
    fn render_summary_text_block_hides_errors_row_when_zero() {
        let s = strip_ansi(&render_summary_text_block(
            "Akamai", 10, 10, 10, 0, 0, 0.0, 1.0,
        ));
        // Errors row is conditional — zero errors means the row
        // doesn't render (less visual noise).
        assert!(
            !s.contains("Errors:"),
            "Errors row must be hidden at 0:\n{s}"
        );
    }

    #[test]
    fn render_bypass_variants_text_block_omits_when_called_with_empty_slice() {
        // The orchestrator gates on `!is_empty()` before calling
        // the renderer, but the renderer itself must be safe to
        // call with an empty slice — defensive call sites.
        let s = strip_ansi(&render_bypass_variants_text_block(&[], "q", "https://x"));
        // The empty-call still emits the header line; no variant
        // bodies. This mirrors what the orchestrator would render
        // if it ever lost its guard.
        assert!(s.contains("Successful Bypasses:"));
        assert!(
            !s.contains("Variant #"),
            "no per-variant lines on empty input:\n{s}"
        );
    }

    #[test]
    fn render_bypass_variants_text_block_renders_one_full_variant() {
        let variants = vec![(
            7_usize,
            "' OR 1=1--".to_string(),
            vec!["url".to_string(), "case_swap".to_string()],
            0.88_f64,
        )];
        let s = strip_ansi(&render_bypass_variants_text_block(
            &variants,
            "q",
            "https://x.com/search",
        ));
        assert!(s.contains("Variant #7"));
        assert!(s.contains("Techniques: url → case_swap"));
        assert!(s.contains("Payload: ' OR 1=1-- (10 bytes)"));
        // Curl reproducer must escape the apostrophe via the
        // bash-safe '\'' sequence.
        assert!(
            s.contains("curl -G --data-urlencode q=$'") && s.contains("https://x.com/search"),
            "repro line missing:\n{s}"
        );
    }

    // ── JSON-builder extractions ──────────────────────────────

    #[test]
    fn build_bypass_variants_json_round_trips_payload_and_techniques() {
        let variants = vec![
            (1_usize, "p1".to_string(), vec!["url".to_string()], 0.9_f64),
            (
                17_usize,
                "/**/UNION/**/SELECT".to_string(),
                vec!["sql_comment".to_string(), "case_swap".to_string()],
                0.83_f64,
            ),
        ];
        let minimal = vec![None, Some("UNION SELECT".to_string())];
        let arr = build_bypass_variants_json("https://t/search", "q", &variants, &minimal);
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["variant"], 1);
        assert_eq!(arr[0]["payload"], "p1");
        assert_eq!(arr[0]["techniques"][0], "url");
        // Minimal absent on row 0 — must be null, not missing.
        assert!(arr[0]["minimal_payload"].is_null());
        // Minimal present on row 1 — must round-trip the string.
        assert_eq!(arr[1]["minimal_payload"], "UNION SELECT");
        // repro_curl always populated (URL-query carriers always
        // produce a reproducer from (target, param, payload)).
        assert!(arr[0]["repro_curl"].as_str().unwrap_or("").contains("p1"));
        // minimal_repro_curl only populated when minimal_payload is.
        assert!(arr[0]["minimal_repro_curl"].is_null());
        assert!(
            arr[1]["minimal_repro_curl"]
                .as_str()
                .unwrap_or("")
                .contains("UNION SELECT")
        );
    }

    #[test]
    fn build_bypass_variants_json_handles_empty_input() {
        let arr = build_bypass_variants_json("https://x", "q", &[], &[]);
        assert!(arr.is_empty());
    }

    #[test]
    fn build_layered_json_wraps_scan_body_under_scan_key() {
        let scan_body = serde_json::json!({"target": "https://x", "bypassed": 3});
        let layered = build_layered_json(
            scan_body,
            "https://x",
            200,
            "Cloudflare",
            &[],
            403,
            true,
            true,
            50,
            48,
            3,
            45,
            2,
            6.0,
        );
        assert!(layered.get("scan").is_some());
        assert_eq!(layered["scan"]["bypassed"], 3);
        assert_eq!(layered["layer_report"]["network"]["target"], "https://x");
        assert_eq!(
            layered["layer_report"]["detection"]["chosen_waf"],
            "Cloudflare"
        );
        assert_eq!(
            layered["layer_report"]["baseline_probe"]["raw_get_status"],
            403
        );
        assert_eq!(
            layered["layer_report"]["evasion_campaign"]["variants_generated"],
            50
        );
        assert!(
            (layered["layer_report"]["evasion_campaign"]["bypass_rate_pct"]
                .as_f64()
                .unwrap()
                - 6.0)
                .abs()
                < 1e-9
        );
    }
}
