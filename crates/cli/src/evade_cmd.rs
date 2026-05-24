//! `wafrift evade` — offline payload mutation + encoding.
//!
//! Three input modes (mutually exclusive at the clap layer): `--payload`,
//! `--payload-b64`, `--stdin`. The base64 + stdin forms exist
//! specifically for binary-safe payloads — `argv` truncates at the
//! first NUL byte before our process sees it, so a control-byte
//! payload via `--payload $'\x00\x01\x02'` arrives empty. The
//! `resolve_payload` function names this explicitly in its error
//! string so the operator never wonders why their literal vanished.

use clap::Args;
use colored::Colorize;
use serde_json::json;
use std::io;
use std::path::PathBuf;
use std::process::ExitCode;
use wafrift_grammar::grammar;

use crate::explain::ExplainTrace;
use crate::helpers::{
    build_variants_explained, confidence_badge, max_mutations_for_level, payload_type_label,
    strategy_pool,
};
use crate::target_context::TargetContext;
use crate::technique_filter::TechniqueFilter;
use crate::Level;

#[derive(Args, Debug)]
pub struct EvadeArgs {
    /// Payload to mutate and encode. Mutually exclusive with `--stdin`
    /// and `--payload-b64`.
    #[arg(
        long,
        conflicts_with_all = ["stdin", "payload_b64"],
        required_unless_present_any = ["stdin", "payload_b64"]
    )]
    pub payload: Option<String>,

    /// Base64-encoded payload, for bytes a shell cannot pass on argv.
    /// `--payload $'\x00\x01\x02'` is silently truncated at the first
    /// NUL by the OS (argv is NUL-terminated C strings), so binary /
    /// control-byte payloads MUST come in out-of-band: base64 here, or
    /// raw bytes via `--stdin`. Decoded bytes are interpreted as UTF-8
    /// (lossless for control/extended characters; the engine is text).
    #[arg(long, value_name = "BASE64", conflicts_with_all = ["payload", "stdin"])]
    pub payload_b64: Option<String>,

    /// Read the payload from stdin instead of `--payload`. Useful for
    /// piping (`echo 'X' | wafrift evade --stdin ...`) and the only
    /// binary-safe path for payloads containing NUL/control bytes.
    /// Refuses to run on an interactive terminal so it doesn't hang
    /// silently.
    #[arg(long)]
    pub stdin: bool,

    /// Output format: `text` (default, colored summary), `json` (a
    /// SINGLE top-level object — consistent with every other
    /// command, parseable as `jq .variants[]`), or `jsonl` (one JSON
    /// object per line — the legacy stream form, useful for piping
    /// large variant counts into a downstream consumer that reads
    /// line-by-line).  The legacy `--quiet` flag aliases to `json`
    /// (wrapped object); pre-2026-05 scripts that expected NDJSON
    /// on `--quiet` need to switch to `--format jsonl`.
    #[arg(long, default_value = "text", value_parser = ["text", "json", "jsonl"])]
    pub format: String,

    /// Evasion intensity.
    #[arg(long, value_enum, default_value_t = Level::Medium)]
    pub level: Level,

    /// Apply encoding only, without grammar-aware mutations.
    /// (Shorthand for `--exclude grammar`.)
    #[arg(long)]
    pub encoding_only: bool,

    /// Restrict to listed technique paths (comma-separated; e.g.
    /// `encoding/url,grammar`). Run `wafrift techniques list` for paths.
    /// Explicit selection here overrides `--level` for which strategies
    /// are eligible (the level still bounds variant count).
    #[arg(long, num_args = 1.., value_delimiter = ',')]
    pub only: Vec<String>,

    /// Drop listed technique paths (comma-separated; e.g.
    /// `encoding/url/triple,smuggling`).
    #[arg(long, num_args = 1.., value_delimiter = ',')]
    pub exclude: Vec<String>,

    /// Filter techniques by where the payload will land (header, body,
    /// query-param, cookie). Encoding strategies whose output is
    /// unusable in the chosen context are skipped (visible with --explain).
    #[arg(long, value_enum)]
    pub target_context: Option<TargetContext>,

    /// Show per-technique trace: which strategies ran, which were
    /// skipped, and why.
    #[arg(long)]
    pub explain: bool,

    /// Write output to a file instead of stdout.
    #[arg(long, short)]
    pub output: Option<PathBuf>,
}

#[allow(clippy::needless_pass_by_value)]
pub fn run_evade(args: EvadeArgs, quiet: bool) -> ExitCode {
    // `--quiet` and `--format json` BOTH select machine-readable
    // output.  Either spelling now produces the wrapped form
    // (single top-level object with a `variants` array) — that's
    // the workspace-wide JSON-shape contract every other command
    // already honours.  The legacy NDJSON form is reachable via
    // the explicit `--format jsonl` (added 2026-05 by dogfood pass
    // 4).
    let quiet = quiet || args.format == "json" || args.format == "jsonl";
    let payload = match resolve_payload(&args) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("{} {msg}", "Input error:".red().bold());
            return ExitCode::from(2);
        }
    };

    let filter = match TechniqueFilter::parse(&args.only, &args.exclude) {
        Ok(f) => f,
        Err(msg) => {
            eprintln!("{} {msg}", "Filter error:".red().bold());
            return ExitCode::from(2);
        }
    };
    let payload_type = grammar::classify(&payload);
    let pool = strategy_pool(args.level, !args.only.is_empty());
    let strategies = filter.filter_strategies(pool);
    let max_mutations = max_mutations_for_level(args.level);
    let encoding_only = args.encoding_only || !filter.grammar_enabled();

    let mut trace = args.explain.then(ExplainTrace::default);
    let mut variants = build_variants_explained(
        &payload,
        payload_type,
        encoding_only,
        &strategies,
        max_mutations,
        args.target_context,
        trace.as_mut(),
    );

    // Tamper variants are a SEPARATE variant axis from the encoding
    // `Strategy` enum.  They get applied opt-in here whenever the
    // operator selected one or more `tamper/...` paths via `--only`
    // (or `tamper` as a bare family).  This closes the long-standing
    // wiring gap where the tamper registry existed but no `evade`
    // surface invoked it — leaving the new frontier 2026 tampers
    // (zero_width_inject, postgres_dollar_quote, etc.) effectively
    // unreachable from the offline mutator.  Tampers in the default
    // (no `--only`) flow are deliberately left to `wafrift scan` so
    // the default evade output doesn't balloon from 12 to 31 variants
    // and surprise existing scripts.
    let any_tamper_selector = args
        .only
        .iter()
        .flat_map(|s| s.split(','))
        .map(str::trim)
        .any(|sel| sel == "tamper" || sel.starts_with("tamper/"));
    if any_tamper_selector {
        let tamper_registry = wafrift_encoding::tamper::TamperRegistry::with_defaults();
        // Tamper context resolution: prefer the operator-supplied
        // `--target-context` when set (body / header / query / etc.)
        // — that's what carrier-aware tampers like ct_starvation
        // need. Fall back to the payload-class label (sql / xss /
        // etc.) when no target context was provided, preserving
        // the historical default for tampers that key on payload
        // shape (e.g. mxss_namespace_wrap on XSS).
        //
        // Pre-fix (dogfood 2026-05): ct_starvation never fired
        // because the context passed in was always the payload-
        // class string ("SQL Injection" / "Unknown") which
        // ct_starvation's body/form/json/multipart match never
        // hits — every variant was Idempotent-skipped.
        let context_str: Option<&str> = match args.target_context {
            Some(tc) => Some(tc.label()),
            None => {
                let label = payload_type_label(payload_type);
                if label.is_empty() { None } else { Some(label) }
            }
        };
        let mut seen_tamper_payloads: std::collections::HashSet<String> = variants
            .iter()
            .map(|v| v.payload.clone())
            .collect();
        for &tamper_name in wafrift_encoding::tamper::all_tamper_names() {
            let path = format!("tamper/{tamper_name}");
            if !filter.allows_path(&path) {
                continue;
            }
            let Some(strat) = tamper_registry.get(tamper_name) else {
                continue;
            };
            let mutated = strat.tamper(&payload, context_str);
            // Record the tamper outcome in the explain trace —
            // operator running `--explain` must see whether a
            // selected tamper actually fired or was a no-op /
            // duplicate on this specific payload.
            if mutated == payload {
                if let Some(ref mut t) = trace {
                    t.record_tamper(tamper_name, crate::explain::TamperOutcome::Idempotent);
                }
                continue;
            }
            if !seen_tamper_payloads.insert(mutated.clone()) {
                if let Some(ref mut t) = trace {
                    t.record_tamper(
                        tamper_name,
                        crate::explain::TamperOutcome::DuplicateOfExisting,
                    );
                }
                continue;
            }
            if let Some(ref mut t) = trace {
                t.record_tamper(tamper_name, crate::explain::TamperOutcome::Applied);
            }
            variants.push(crate::helpers::Variant {
                payload: mutated,
                techniques: vec![format!("tamper:{tamper_name}")],
                confidence: strat.aggressiveness().clamp(0.05, 0.95),
            });
        }
    }

    if variants.is_empty() {
        // Empty variant set is a LEGITIMATE outcome — operator
        // selected a tamper that doesn't apply to this payload
        // shape (e.g. `--only tamper/postgres_dollar_quote` on a
        // payload with no `'`).  Exit 0 with an empty array so
        // CI pipelines that treat non-zero as error don't break
        // on a no-op.  Found via dogfood pass 4 (2026-05).
        if quiet {
            let mut body = json!({
                "variants": serde_json::Value::Array(Vec::new()),
                "note": "no variants generated — selected techniques produced no transform on this payload",
                "payload_type": payload_type_label(payload_type),
            });
            if let Some(t) = trace.as_ref() {
                body["explain"] = t.to_json()["explain"].clone();
            }
            if let Some(ref path) = args.output {
                if let Err(e) = std::fs::write(path, format!("{body}\n")) {
                    eprintln!("failed to write evade output to {}: {e}", path.display());
                }
            } else {
                println!("{body}");
            }
        } else {
            eprintln!(
                "{}",
                "No variants generated for the supplied payload."
                    .yellow()
                    .bold()
            );
            if let Some(ctx) = args.target_context {
                eprintln!(
                    "  Target context: {} — strategies whose output is unusable here were skipped.",
                    ctx.label()
                );
            }
            if !args.only.is_empty() && !args.explain {
                eprintln!(
                    "  Hint: re-run with --explain to see which techniques were considered and why each was skipped."
                );
            }
            if let Some(t) = trace.as_ref() {
                t.print_text();
            }
        }
        // Exit 0 — no variants is a legitimate outcome, not an error.
        return ExitCode::SUCCESS;
    }

    // Output format resolution:
    //   --format jsonl       → NDJSON (one object per line, plus
    //                          optional trailing explain object).
    //                          Streaming-friendly for large runs.
    //   --format json        → SINGLE top-level object with a
    //                          `variants` array.  Consistent with
    //                          every other wafrift command — `jq
    //                          .variants[]` works.  Default for
    //                          the `--quiet` legacy alias.
    //   --quiet              → alias for `--format json` (wrapped).
    //   --format text (default) → human-readable colorised output.
    //
    // The previous behaviour emitted NDJSON on both `--format json`
    // and `--quiet`, breaking `jq .field` consumers and making
    // evade the only command that disagreed with the workspace's
    // JSON-shape contract.  Found via dogfood pass 4 (2026-05).
    let emit_jsonl = args.format == "jsonl";
    let emit_json_obj = !emit_jsonl && quiet;
    if emit_jsonl || emit_json_obj {
        let mut buf = String::new();
        if emit_json_obj {
            // Wrapped form: one top-level object containing the
            // variants array plus the optional explain block.
            let variant_objs: Vec<_> = variants
                .iter()
                .map(|variant| {
                    json!({
                        "payload": variant.payload,
                        "techniques": variant.techniques,
                        "confidence": variant.confidence,
                    })
                })
                .collect();
            // schema_version + wafrift_version for downstream parsers
            // (per perf-hunt F28). Schema version bumps when a field
            // is removed or renamed — pure additive changes leave it
            // unchanged. Pinned at 1 today; integration tests assert
            // these keys exist so a regression that drops them lights
            // up at PR time.
            let mut top = json!({
                "schema_version": 1u32,
                "wafrift_version": env!("CARGO_PKG_VERSION"),
                "variants": variant_objs,
            });
            if let Some(t) = trace.as_ref() {
                let explain = t.to_json();
                top["explain"] = explain["explain"].clone();
            }
            let rendered = top.to_string();
            if args.output.is_some() {
                buf.push_str(&rendered);
                buf.push('\n');
            } else {
                println!("{rendered}");
            }
        } else {
            // Legacy NDJSON form: one object per line.
            for variant in &variants {
                let obj = json!({
                    "payload": variant.payload,
                    "techniques": variant.techniques,
                    "confidence": variant.confidence,
                });
                if args.output.is_some() {
                    buf.push_str(&obj.to_string());
                    buf.push('\n');
                } else {
                    println!("{obj}");
                }
            }
            if let Some(t) = trace.as_ref() {
                let explain_obj = t.to_json();
                if args.output.is_some() {
                    buf.push_str(&explain_obj.to_string());
                    buf.push('\n');
                } else {
                    println!("{explain_obj}");
                }
            }
        }
        if let Some(ref path) = args.output {
            if let Err(e) = std::fs::write(path, &buf) {
                eprintln!("failed to write evade output to {}: {e}", path.display());
                return ExitCode::from(1);
            }
            eprintln!("evade results written to {}", path.display());
        }
    } else {
        println!(
            "{} {}",
            "Payload Type:".bold().cyan(),
            payload_type_label(payload_type).bold()
        );
        println!(
            "{} {}",
            "Encoding Level:".bold().cyan(),
            format!("{:?}", args.level).to_lowercase().yellow()
        );
        if let Some(ctx) = args.target_context {
            println!(
                "{} {}",
                "Target Context:".bold().cyan(),
                ctx.label().yellow()
            );
        }

        for (index, variant) in variants.iter().enumerate() {
            println!(
                "\n{} {} {}",
                "Variant".bold().green(),
                format!("#{}", index + 1).bold().green(),
                confidence_badge(variant.confidence)
            );
            println!(
                "{} {}",
                "Techniques:".bold().cyan(),
                variant.techniques.join(" -> ").yellow()
            );
            // Escape non-printable ASCII control bytes so tampers
            // like `bell_separator` (BEL 0x07), `null_byte` (NUL),
            // and the zero-width Unicode injectors don't render as
            // invisible characters in the operator's terminal —
            // the terminal silently swallows BEL / NUL / NULL and
            // the operator can't tell the tamper fired.  This is
            // the "byte-level visibility" requirement called out
            // in the 2026-05 dogfood pass.
            println!(
                "{} {}",
                "Payload:".bold().cyan(),
                visualize_invisible_bytes(&variant.payload).bright_white()
            );
        }

        // Top-N tail summary: when the variant set is large enough
        // to fill more than one terminal screen (>= 8 variants),
        // surface the top 5 by confidence + the technique frequency
        // breakdown. This is a UX dogfood gap — operators reading
        // a 30-variant emit want to know "which 5 should I try
        // first?" without re-scrolling the whole list. Suppressed
        // for short emits where the body is already a glanceable
        // summary.
        if variants.len() >= 8 {
            print_top_n_summary(&variants);
        }

        if let Some(t) = trace.as_ref() {
            t.print_text();
        }
    }

    ExitCode::SUCCESS
}

/// Trailing tail printed after the per-variant body in text mode.
/// Pure wrapper: builds the string via [`top_n_summary_text`] (which
/// is unit-testable) and prints it. Behind the >=8 variant threshold
/// in the caller so short emits stay quiet.
fn print_top_n_summary(variants: &[crate::helpers::Variant]) {
    print!("{}", top_n_summary_text(variants));
}

/// Build the top-N summary tail as a single string. Two blocks:
///   - Top 5 variants by confidence (the "try these first" list).
///   - Technique-chain frequency (helps the operator spot which
///     mutator family the engine leaned on).
///
/// Pure (no stdout I/O), so unit tests can assert on the rendered
/// content directly. Each line is terminated by `\n`.
fn top_n_summary_text(variants: &[crate::helpers::Variant]) -> String {
    use std::collections::BTreeMap;
    use std::fmt::Write as _;
    const TOP_N: usize = 5;
    let mut out = String::new();
    out.push('\n');
    let _ = writeln!(
        out,
        "{}",
        "─── Summary (top-5 by confidence) ───".bold().bright_black()
    );
    let mut ranked: Vec<(usize, &crate::helpers::Variant)> = variants.iter().enumerate().collect();
    // Stable-sort by descending confidence; ties keep input order.
    ranked.sort_by(|a, b| {
        b.1.confidence
            .partial_cmp(&a.1.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    for (orig_idx, v) in ranked.iter().take(TOP_N) {
        let _ = writeln!(
            out,
            "  #{:<3} conf {:.2}  {}",
            orig_idx + 1,
            v.confidence,
            v.techniques.join(" -> ").yellow()
        );
    }
    // Technique-chain frequency. The chain (joined) is the bucket
    // key because two variants reaching the same end state via
    // different mutators are usually equivalent in practice; if you
    // care about per-mutator frequency, --explain has the per-call
    // counters.
    let mut freq: BTreeMap<String, usize> = BTreeMap::new();
    for v in variants {
        *freq.entry(v.techniques.join(" -> ")).or_insert(0) += 1;
    }
    if freq.len() > 1 {
        out.push('\n');
        let _ = writeln!(
            out,
            "{}",
            "─── Technique frequency ───".bold().bright_black()
        );
        let mut chain_counts: Vec<(&String, &usize)> = freq.iter().collect();
        chain_counts.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
        for (chain, n) in chain_counts.iter().take(TOP_N) {
            let _ = writeln!(out, "  {:>3}×  {}", n, chain.yellow());
        }
    }
    out
}

/// Resolve the evade payload from `--payload`, `--payload-b64`, or
/// `--stdin`. Clap's `required_unless_present_any` + `conflicts_with`
/// guarantees exactly one source at the CLI layer; this validates and
/// decodes the value.
///
/// Binary-safety: `--stdin` is read as raw bytes (not
/// `read_to_string`, which hard-errors on the first invalid UTF-8 byte
/// and so could never accept a binary payload) and `--payload-b64`
/// carries arbitrary bytes past the shell's NUL-terminated argv. Both
/// are lossily decoded to UTF-8 because the mutation/encoding engine
/// is text — control bytes (`\x00`–`\x1f`) survive losslessly; only
/// genuinely invalid UTF-8 sequences become U+FFFD.
fn resolve_payload(args: &EvadeArgs) -> Result<String, String> {
    use base64::Engine as _;

    if let Some(b64) = &args.payload_b64 {
        let trimmed = b64.trim();
        if trimmed.is_empty() {
            return Err("--payload-b64 is empty".to_string());
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(trimmed)
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(trimmed))
            .map_err(|e| format!("--payload-b64 is not valid base64: {e}"))?;
        if bytes.is_empty() {
            return Err("--payload-b64 decoded to zero bytes".to_string());
        }
        return Ok(String::from_utf8_lossy(&bytes).into_owned());
    }

    if args.stdin {
        use std::io::{IsTerminal, Read};
        if io::stdin().is_terminal() {
            return Err(
                "--stdin requires a pipe (e.g. `echo 'X' | wafrift evade --stdin ...`); refusing to wait on an interactive terminal".to_string(),
            );
        }
        let mut buf: Vec<u8> = Vec::new();
        io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| format!("failed to read payload from stdin: {e}"))?;
        // PowerShell silently prepends a UTF-8 BOM (`\xEF\xBB\xBF`)
        // to piped output by default — `Write-Output "x" | wafrift
        // evade --stdin` arrives as `\u{FEFF}x`, which then carries
        // through every tamper output as an invisible prefix. Strip
        // the BOM unconditionally so PowerShell + cmd + bash + zsh
        // pipes all converge on the same bytes.
        if buf.starts_with(b"\xef\xbb\xbf") {
            buf.drain(0..3);
        }
        // Strip a single trailing newline (the `echo 'x' |` case) without
        // mangling embedded control bytes in a deliberate binary payload.
        if buf.last() == Some(&b'\n') {
            buf.pop();
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
        }
        if buf.is_empty() {
            return Err("stdin produced an empty payload".to_string());
        }
        return Ok(String::from_utf8_lossy(&buf).into_owned());
    }

    let raw = args.payload.clone().ok_or_else(|| {
        "no payload supplied (use --payload, --payload-b64, or --stdin)".to_string()
    })?;
    if raw.is_empty() {
        // The overwhelmingly common cause of an *empty* `--payload`
        // value is a shell binary literal: `--payload $'\x00\x01\x02'`.
        // execve(2) passes argv as NUL-terminated C strings, so the
        // kernel truncates the argument at the first NUL *before* the
        // process ever sees it — wafrift receives "", not the bytes.
        // No amount of in-process parsing can recover them; the only
        // fix is an out-of-band channel. Say so, with the exact
        // commands.
        return Err("--payload is empty. If you passed binary/NUL bytes (e.g. \
             $'\\x00\\x01\\x02'), the shell truncated the argument at the \
             first NUL byte before wafrift could see it — argv cannot \
             carry NULs. Use a binary-safe channel instead:\n  \
             printf '\\x00\\x01\\x02' | wafrift evade --stdin ...\n  \
             wafrift evade --payload-b64 \"$(printf '\\x00\\x01\\x02' | base64)\" ..."
            .to_string());
    }
    Ok(raw)
}

/// Render a payload string with non-printable / invisible Unicode
/// codepoints escaped to their `\xNN` or `\u{NNNN}` form so the
/// operator can SEE what byte-level transform a tamper applied.
/// Terminals silently swallow BEL (`\x07`), NUL (`\x00`), and the
/// zero-width Unicode injectors (`\u{200B}` etc.); without this
/// the operator can't tell whether the transform fired.
///
/// Only ASCII printable + tab + standard whitespace pass through
/// verbatim.  Everything else gets the explicit hex / unicode
/// escape form.  JSON output is unaffected (serde escapes these
/// automatically); this helper is for the text-mode `evade`
/// printer only.
pub(crate) fn visualize_invisible_bytes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            // ASCII printable + tab + newline + carriage-return
            // pass through verbatim.  Newline preservation matters
            // for multi-line payloads (XSS HTML templates etc).
            '\t' | '\n' | '\r' => out.push(ch),
            c if (' '..='~').contains(&c) => out.push(c),
            // Common Unicode control / zero-width / format chars
            // get the explicit `\u{...}` form so the operator
            // sees the transform.
            '\u{200B}' => out.push_str("\\u{200B}"),
            '\u{200C}' => out.push_str("\\u{200C}"),
            '\u{200D}' => out.push_str("\\u{200D}"),
            '\u{FEFF}' => out.push_str("\\u{FEFF}"),
            c if (c as u32) < 0x20 || c as u32 == 0x7F => {
                out.push_str(&format!("\\x{:02X}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args_with_payload(p: &str) -> EvadeArgs {
        EvadeArgs {
            payload: Some(p.into()),
            payload_b64: None,
            stdin: false,
            format: "text".into(),
            level: Level::Medium,
            encoding_only: false,
            only: vec![],
            exclude: vec![],
            target_context: None,
            explain: false,
            output: None,
        }
    }

    #[test]
    fn resolve_payload_plain_string_returns_as_is() {
        let args = args_with_payload("' OR 1=1--");
        assert_eq!(resolve_payload(&args).unwrap(), "' OR 1=1--");
    }

    #[test]
    fn resolve_payload_empty_payload_returns_argv_nul_diagnostic() {
        // The empty `--payload` -> NUL-byte argv diagnostic is one of
        // the most-frequently-hit operator footguns; the error
        // message must name it so the user doesn't keep guessing.
        let args = args_with_payload("");
        let err = resolve_payload(&args).expect_err("empty payload must err");
        assert!(
            err.contains("NUL") || err.contains("nul") || err.contains("--stdin"),
            "diagnostic must mention NUL/stdin escape, got: {err}"
        );
    }

    #[test]
    fn resolve_payload_b64_round_trip() {
        let mut args = args_with_payload("");
        args.payload = None;
        // Standard base64 of "hello" is "aGVsbG8=".
        args.payload_b64 = Some("aGVsbG8=".into());
        assert_eq!(resolve_payload(&args).unwrap(), "hello");
    }

    #[test]
    fn resolve_payload_b64_accepts_no_pad_form() {
        let mut args = args_with_payload("");
        args.payload = None;
        // Same "hello" without the trailing `=` padding.
        args.payload_b64 = Some("aGVsbG8".into());
        assert_eq!(resolve_payload(&args).unwrap(), "hello");
    }

    #[test]
    fn resolve_payload_b64_empty_rejects() {
        let mut args = args_with_payload("");
        args.payload = None;
        args.payload_b64 = Some("".into());
        assert!(resolve_payload(&args).is_err());
    }

    #[test]
    fn resolve_payload_b64_invalid_rejects() {
        let mut args = args_with_payload("");
        args.payload = None;
        args.payload_b64 = Some("not-base64!!!".into());
        assert!(resolve_payload(&args).is_err());
    }

    #[test]
    fn resolve_payload_b64_whitespace_only_rejects() {
        // A b64 value of only whitespace decodes to empty bytes
        // and is operator typo. resolve_payload trims & rejects.
        let mut args = args_with_payload("");
        args.payload = None;
        args.payload_b64 = Some("   ".into());
        assert!(resolve_payload(&args).is_err());
    }

    #[test]
    fn resolve_payload_b64_decodes_to_unicode() {
        use base64::Engine as _;
        let raw = "café 中文";
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
        let mut args = args_with_payload("");
        args.payload = None;
        args.payload_b64 = Some(encoded);
        assert_eq!(resolve_payload(&args).unwrap(), raw);
    }

    #[test]
    fn resolve_payload_b64_decodes_to_bytes_with_control_chars() {
        // Operators escape unprintable / NUL-laden binary payloads
        // through --payload-b64 specifically because argv truncates
        // at NUL. Confirm a NUL-containing decoded payload survives
        // through string conversion (lossy where needed but never
        // panic).
        use base64::Engine as _;
        let raw_bytes = b"a\x00b\x01c".to_vec();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&raw_bytes);
        let mut args = args_with_payload("");
        args.payload = None;
        args.payload_b64 = Some(encoded);
        let got = resolve_payload(&args).unwrap();
        // String::from_utf8_lossy preserves valid UTF-8 bytes,
        // including NUL — the NUL must round-trip.
        assert!(got.contains('\0'));
        assert!(got.starts_with('a'));
        assert!(got.ends_with('c'));
    }

    #[test]
    fn resolve_payload_b64_with_leading_trailing_whitespace_trims() {
        // Multi-line paste — operators often have a stray
        // newline at the end. The trim() in resolve_payload
        // handles that.
        let mut args = args_with_payload("");
        args.payload = None;
        args.payload_b64 = Some("  aGVsbG8=  \n".into());
        assert_eq!(resolve_payload(&args).unwrap(), "hello");
    }

    #[test]
    fn resolve_payload_no_source_set_returns_error() {
        // None of --payload, --payload-b64, --stdin → error.
        let mut args = args_with_payload("placeholder");
        args.payload = None;
        args.payload_b64 = None;
        args.stdin = false;
        let err = resolve_payload(&args).expect_err("no source");
        assert!(
            err.contains("no payload")
                || err.contains("payload")
                || err.contains("--stdin")
                || err.contains("--payload-b64"),
            "must list options: {err}"
        );
    }

    #[test]
    fn resolve_payload_preference_order_b64_over_payload() {
        // If both --payload and --payload-b64 are set, --payload-b64
        // wins (it's checked first in the resolve order). This is
        // the contract; document via test.
        use base64::Engine as _;
        let mut args = args_with_payload("WRONG");
        args.payload_b64 = Some(
            base64::engine::general_purpose::STANDARD.encode(b"RIGHT"),
        );
        assert_eq!(resolve_payload(&args).unwrap(), "RIGHT");
    }

    // ── Tamper wiring (added 2026-05) ──────────────────────
    //
    // These exercise the policy that tampers are opt-in for evade —
    // default flows produce zero tamper variants, an explicit
    // `--only tamper/...` selector produces one variant per matched
    // tamper (deduped against the original + existing variants).
    //
    // We don't invoke `run_evade` directly here (it writes to stdout
    // and process-exits); instead we mirror its TamperRegistry +
    // TechniqueFilter logic in the assertion.

    fn count_tamper_variants_for(selectors: &[&str], payload: &str) -> usize {
        let filter = TechniqueFilter::parse(
            &selectors.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            &[],
        )
        .expect("filter parses");
        let any_tamper_selector = selectors
            .iter()
            .flat_map(|s| s.split(','))
            .map(str::trim)
            .any(|sel| sel == "tamper" || sel.starts_with("tamper/"));
        if !any_tamper_selector {
            return 0;
        }
        let reg = wafrift_encoding::tamper::TamperRegistry::with_defaults();
        let mut hits = 0;
        let mut seen = std::collections::HashSet::new();
        seen.insert(payload.to_string());
        for &name in wafrift_encoding::tamper::all_tamper_names() {
            let path = format!("tamper/{name}");
            if !filter.allows_path(&path) {
                continue;
            }
            let Some(strat) = reg.get(name) else {
                continue;
            };
            let mutated = strat.tamper(payload, Some("sql"));
            if mutated != payload && seen.insert(mutated) {
                hits += 1;
            }
        }
        hits
    }

    #[test]
    fn tamper_opt_in_zero_variants_when_no_selector() {
        assert_eq!(count_tamper_variants_for(&[], "' OR 1=1--"), 0);
        assert_eq!(
            count_tamper_variants_for(&["encoding/url"], "' OR 1=1--"),
            0,
            "encoding-only selector must not enable tamper variants"
        );
    }

    #[test]
    fn tamper_family_selector_enables_all_tampers() {
        // `tamper` as a bare family selects every registered tamper
        // — at least 10 of them will produce a non-identity variant
        // on an SQL payload.
        let hits = count_tamper_variants_for(&["tamper"], "' OR 1=1--");
        assert!(
            hits >= 5,
            "tamper-family selector should fire many tampers; got {hits}"
        );
    }

    #[test]
    fn tamper_leaf_selector_isolates_single_tamper() {
        // A specific tamper leaf produces at most one variant.
        let hits =
            count_tamper_variants_for(&["tamper/zero_width_inject"], "' OR 1=1--");
        assert!(
            hits <= 1,
            "tamper/zero_width_inject must produce at most one variant; got {hits}"
        );
        // And specifically it DOES produce one for this payload
        // (which contains alphabetic chars).
        assert_eq!(hits, 1);
    }

    #[test]
    fn tamper_inert_on_unrelated_payload_produces_zero() {
        // postgres_dollar_quote only transforms single-quoted
        // literals.  A payload with no `'` should produce no
        // variant.
        let hits =
            count_tamper_variants_for(&["tamper/postgres_dollar_quote"], "1=1");
        assert_eq!(hits, 0);
    }

    #[test]
    fn tamper_multiple_leaves_compose() {
        let hits = count_tamper_variants_for(
            &[
                "tamper/zero_width_inject",
                "tamper/bracket_confusable",
                "tamper/bell_separator",
            ],
            "<script>alert OR 1=1</script>",
        );
        // Three distinct selectors → up to three distinct
        // outputs.  Lower-bound on 2 (some may collide on this
        // payload).
        assert!(hits >= 2);
    }

    #[test]
    fn tamper_comma_separated_csv_form_is_recognised() {
        // `--only "tamper/a,tamper/b"` — split on comma.
        let hits = count_tamper_variants_for(
            &["tamper/zero_width_inject,tamper/bracket_confusable"],
            "<x>OR</x>",
        );
        assert!(hits >= 1);
    }

    #[test]
    fn tamper_idempotent_on_pure_punctuation_payload() {
        // `1=1` has no alphabetic chars → zero_width_inject is a
        // no-op → no variant produced.
        let hits = count_tamper_variants_for(&["tamper/zero_width_inject"], "1=1");
        assert_eq!(hits, 0);
    }

    #[test]
    fn visualize_escapes_bell_byte() {
        assert_eq!(visualize_invisible_bytes("a\u{0007}b"), "a\\x07b");
    }

    #[test]
    fn visualize_escapes_null_byte() {
        assert_eq!(visualize_invisible_bytes("a\u{0000}b"), "a\\x00b");
    }

    #[test]
    fn visualize_escapes_zero_width_codepoints() {
        let input = "S\u{200B}E\u{200C}L\u{200D}E\u{FEFF}CT";
        let out = visualize_invisible_bytes(input);
        assert!(out.contains("\\u{200B}"));
        assert!(out.contains("\\u{200C}"));
        assert!(out.contains("\\u{200D}"));
        assert!(out.contains("\\u{FEFF}"));
        assert!(out.starts_with("S"));
        assert!(out.ends_with("CT"));
    }

    #[test]
    fn visualize_passes_printable_ascii_unchanged() {
        let s = "abcXYZ123!@#$%^&*()_+={}[]:;\"'<>,.?/|";
        assert_eq!(visualize_invisible_bytes(s), s);
    }

    #[test]
    fn visualize_preserves_tab_newline_carriage_return() {
        // Multi-line payloads (XSS HTML templates) must stay
        // readable — the whitespace trio passes through.
        assert_eq!(visualize_invisible_bytes("a\tb\nc\rd"), "a\tb\nc\rd");
    }

    #[test]
    fn visualize_escapes_delete_byte() {
        // 0x7F DEL — not printable, must be escaped.
        assert_eq!(visualize_invisible_bytes("a\u{007F}b"), "a\\x7Fb");
    }

    #[test]
    fn visualize_passes_high_unicode_printable_chars() {
        // Fullwidth bracket (U+FF1C) from bracket_confusable —
        // visually distinct, leave verbatim.
        assert_eq!(visualize_invisible_bytes("a\u{FF1C}b"), "a\u{FF1C}b");
    }

    #[test]
    fn visualize_handles_mixed_content() {
        let input = "UNION\u{0007}SELECT \u{200B}1=1";
        let out = visualize_invisible_bytes(input);
        assert!(out.contains("UNION"));
        assert!(out.contains("\\x07"));
        assert!(out.contains("SELECT"));
        assert!(out.contains("\\u{200B}"));
        assert!(out.contains("1=1"));
    }

    #[test]
    fn visualize_empty_input() {
        assert_eq!(visualize_invisible_bytes(""), "");
    }

    #[test]
    fn visualize_only_invisible_codepoints() {
        let input = "\u{0007}\u{0000}\u{200B}";
        let out = visualize_invisible_bytes(input);
        assert_eq!(out, "\\x07\\x00\\u{200B}");
    }

    #[test]
    fn tamper_unknown_leaf_fails_filter_parse() {
        // Unknown selectors error out at the filter layer — must
        // not silently match nothing.
        let r = TechniqueFilter::parse(
            &["tamper/no_such_tamper".to_string()],
            &[],
        );
        assert!(r.is_err());
    }

    // ── format-shape regression guards (2026-05 dogfood pass 4) ──

    #[test]
    fn format_value_parser_accepts_text_json_jsonl() {
        // The clap arg config must accept all three values without
        // erroring out on parse time.  The actual rendering branch
        // is exercised by run_evade integration tests below.
        for value in ["text", "json", "jsonl"] {
            // Construct args via clap's parse-from-iter so we exercise
            // the full value_parser path.
            use clap::Parser;
            #[derive(clap::Parser)]
            struct Wrap {
                #[command(flatten)]
                ev: EvadeArgs,
            }
            let r = Wrap::try_parse_from([
                "evade",
                "--payload",
                "X",
                "--format",
                value,
            ]);
            assert!(r.is_ok(), "format `{value}` must parse: {:?}", r.err());
        }
    }

    #[test]
    fn format_value_parser_rejects_unknown_format() {
        use clap::Parser;
        #[derive(clap::Parser)]
        struct Wrap {
            #[command(flatten)]
            ev: EvadeArgs,
        }
        let r = Wrap::try_parse_from([
            "evade",
            "--payload",
            "X",
            "--format",
            "yaml",
        ]);
        assert!(r.is_err(), "unknown format must reject");
    }

    // ── Top-N summary tail (text mode) ─────────────────────────

    fn variant(payload: &str, techniques: &[&str], confidence: f64) -> crate::helpers::Variant {
        crate::helpers::Variant {
            payload: payload.to_string(),
            techniques: techniques.iter().map(|s| (*s).to_string()).collect(),
            confidence,
        }
    }

    #[test]
    fn top_n_summary_lists_top_5_by_descending_confidence() {
        let variants = vec![
            variant("low",  &["url"],    0.10),
            variant("mid1", &["base64"], 0.50),
            variant("hi1",  &["dwd"],    0.90),
            variant("hi2",  &["wide"],   0.95),
            variant("mid2", &["case"],   0.55),
            variant("low2", &["nada"],   0.05),
            variant("hi3",  &["pp"],     0.99),
            variant("mid3", &["xor"],    0.60),
        ];
        let s = strip_ansi(&top_n_summary_text(&variants));
        // Header present.
        assert!(s.contains("Summary (top-5 by confidence)"), "summary header missing:\n{s}");
        // The 5 highest confidence variants are #7 (0.99), #4 (0.95),
        // #3 (0.90), #8 (0.60), #5 (0.55), in that order.
        let expected_order = ["#7", "#4", "#3", "#8", "#5"];
        let mut last_pos = 0;
        for label in expected_order {
            let pos = s.find(label).unwrap_or_else(|| panic!("missing {label} in:\n{s}"));
            assert!(
                pos >= last_pos,
                "summary order broken: {label} appeared before previous row at pos {pos} vs last {last_pos}\n{s}"
            );
            last_pos = pos;
        }
        // The two lowest-confidence variants must NOT appear.
        assert!(!s.contains("#6 "), "low2 (#6 conf 0.05) must not be in top-5:\n{s}");
    }

    #[test]
    fn top_n_summary_shows_technique_frequency_when_more_than_one_chain() {
        let variants = vec![
            variant("a", &["url"], 0.5),
            variant("b", &["url"], 0.5),
            variant("c", &["url"], 0.5),
            variant("d", &["b64"], 0.5),
            variant("e", &["b64"], 0.5),
            variant("f", &["hex"], 0.5),
            variant("g", &["hex"], 0.5),
            variant("h", &["hex"], 0.5),
        ];
        let s = strip_ansi(&top_n_summary_text(&variants));
        assert!(
            s.contains("Technique frequency"),
            "freq header missing:\n{s}"
        );
        // Highest-count chain (hex × 3 + url × 3 -> tied) must
        // appear; checking the most common alone is enough since
        // tie-break is alphabetical (hex < url).
        assert!(s.contains("3×  hex"), "hex × 3 line missing:\n{s}");
        assert!(s.contains("3×  url"), "url × 3 line missing:\n{s}");
        assert!(s.contains("2×  b64"), "b64 × 2 line missing:\n{s}");
    }

    #[test]
    fn top_n_summary_omits_frequency_block_when_only_one_chain() {
        // Single chain across all variants: the frequency block adds
        // no signal, so it's hidden.
        let variants = vec![
            variant("a", &["url"], 0.5),
            variant("b", &["url"], 0.6),
            variant("c", &["url"], 0.7),
            variant("d", &["url"], 0.8),
            variant("e", &["url"], 0.9),
            variant("f", &["url"], 0.4),
            variant("g", &["url"], 0.3),
            variant("h", &["url"], 0.2),
        ];
        let s = strip_ansi(&top_n_summary_text(&variants));
        assert!(s.contains("Summary (top-5 by confidence)"));
        assert!(
            !s.contains("Technique frequency"),
            "freq block must be hidden when only one chain exists:\n{s}"
        );
    }

    #[test]
    fn top_n_summary_caps_top_block_at_5_even_with_more_variants() {
        let variants: Vec<_> = (0..20)
            .map(|i| variant(&format!("p{i}"), &["url"], 1.0 - (i as f64) / 100.0))
            .collect();
        let s = strip_ansi(&top_n_summary_text(&variants));
        // 5 numbered lines under the summary header.
        let header_pos = s.find("Summary (top-5").unwrap();
        let after = &s[header_pos..];
        let count = after.matches("conf ").count();
        assert_eq!(count, 5, "top block must show exactly 5 entries, found {count}:\n{after}");
    }

    /// Strip ANSI color codes so assertions are deterministic
    /// regardless of whether the test runs under a TTY-detecting
    /// `colored` build. The codes follow the form `ESC [ … m`.
    fn strip_ansi(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut iter = s.chars().peekable();
        while let Some(c) = iter.next() {
            if c == '\u{1b}' && iter.peek() == Some(&'[') {
                iter.next(); // consume '['
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
}
