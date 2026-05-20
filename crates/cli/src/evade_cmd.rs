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

    /// Output format: `text` (default) or `json`. `--format json` is
    /// equivalent to the global `--quiet` for this command and exists
    /// so `evade` matches `scan`/`bypass-probe`/`import-curl`, whose
    /// `--format` flag pentesters already script against.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
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
    // `--format json` is the per-command spelling of the global
    // `--quiet`: both select machine-readable NDJSON. Shadow `quiet`
    // so every downstream branch honours either spelling.
    let quiet = quiet || args.format == "json";
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
    let variants = build_variants_explained(
        &payload,
        payload_type,
        encoding_only,
        &strategies,
        max_mutations,
        args.target_context,
        trace.as_mut(),
    );

    if variants.is_empty() {
        if quiet {
            let mut body = json!({
                "error": "no variants generated",
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
                    .red()
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
        return ExitCode::from(1);
    }

    if quiet {
        // JSON output: one object per line (NDJSON), then an optional trailing
        // {"explain": [...]} object so consumers can stream variants and still
        // pick up the trace.
        let mut buf = String::new();
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
            println!(
                "{} {}",
                "Payload:".bold().cyan(),
                variant.payload.bright_white()
            );
        }

        if let Some(t) = trace.as_ref() {
            t.print_text();
        }
    }

    ExitCode::SUCCESS
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
}
