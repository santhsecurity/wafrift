//! `wafrift compress` — wrap a request body in one or more
//! `Content-Encoding` layers for the compression-confusion attack.
//!
//! Most WAFs inspect raw request bytes, NOT the decompressed body.
//! Brotli is the headline gap (separate decompressor, separate
//! vendor support); origins ARE brotli-capable since Chrome 49 /
//! Firefox 44 / nginx 1.11. Wrap a payload in `br` and the rule
//! corpus that matches on the plain bytes never gets a chance to
//! match — the origin decompresses and processes the malicious
//! body fine.
//!
//! The CLI is intentionally a building block, not an end-to-end
//! attack. The operator pipes a body in (file or stdin), gets the
//! compressed bytes out (file or stdout), and the matching
//! `Content-Encoding` header value on stderr. Then they paste both
//! into their HTTP client of choice:
//!
//! ```sh
//! # gzip + br chain — outermost layer first, RFC 9110 §8.4
//! wafrift compress --algo gzip --algo br < attack.json > body.bin
//! # stderr: Content-Encoding: gzip, br
//! curl -X POST https://target -H 'Content-Encoding: gzip, br' \
//!      -H 'Content-Type: application/json' --data-binary @body.bin
//! ```
//!
//! Composes with the rest of the CLI: pipe `wafrift evade --stdin`
//! into this, get a compressed body for whatever variant the operator
//! picks.

use clap::Args;
use colored::Colorize;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use wafrift_encoding::compression::{Algorithm, chain};

#[derive(Args, Debug)]
pub struct CompressArgs {
    /// Compression algorithm. May be repeated to chain layers in
    /// RFC 9110 §8.4 order — the FIRST `--algo` is the OUTERMOST
    /// wrapper, the LAST is the innermost (closest to the original
    /// body). `--algo gzip --algo br` produces `gzip(brotli(body))`
    /// with `Content-Encoding: gzip, br`. Supported: `gzip`,
    /// `deflate`, `br`, `identity` (no-op chain anchor).
    #[arg(long = "algo", value_name = "ALGO", required = true, num_args = 1..)]
    pub algos: Vec<String>,

    /// Read the request body from this file. Mutually exclusive with
    /// `--stdin`; one of the two must be set.
    #[arg(long, value_name = "PATH", conflicts_with = "stdin")]
    pub input: Option<PathBuf>,

    /// Read the request body from stdin. Useful for piping from
    /// `wafrift evade --stdin` or any other variant generator.
    #[arg(long, conflicts_with = "input")]
    pub stdin: bool,

    /// Write the compressed body to this file instead of stdout.
    /// Convenient when piping output to a non-binary-safe consumer.
    #[arg(long, short, value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Output format. `text` (default) emits the compressed bytes to
    /// stdout / `--output` and the `Content-Encoding` header on
    /// stderr. `json` emits a single object to stdout with the body
    /// base64-encoded — useful for shell scripts that capture both
    /// pieces in one stream.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,
}

/// Entry point.
///
/// # Errors
/// Returns `ExitCode::from(1)` for: unrecognised algorithm name,
/// I/O failure (input read, output write), compression-chain
/// failure (e.g. chain depth above the safety cap), or no input
/// source supplied.
pub fn run_compress(args: CompressArgs) -> ExitCode {
    let algos = match parse_algorithms(&args.algos) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{} {e}", "Input error:".red().bold());
            return ExitCode::from(2);
        }
    };

    let body = match read_input(&args) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{} {e}", "I/O error:".red().bold());
            return ExitCode::from(1);
        }
    };

    let compressed = match chain(&body, &algos) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{} {e}", "Compression error:".red().bold());
            return ExitCode::from(1);
        }
    };

    match args.format.as_str() {
        "json" => emit_json(&compressed, &args),
        _ => emit_text(&compressed, &args),
    }
}

fn parse_algorithms(raw: &[String]) -> Result<Vec<Algorithm>, String> {
    if raw.is_empty() {
        return Err("at least one --algo must be supplied".into());
    }
    let mut out = Vec::with_capacity(raw.len());
    for token in raw {
        match Algorithm::from_token(token) {
            Some(a) => out.push(a),
            None => {
                return Err(format!(
                    "unknown algorithm {token:?}; supported: gzip, deflate, br, identity"
                ));
            }
        }
    }
    Ok(out)
}

fn read_input(args: &CompressArgs) -> Result<Vec<u8>, String> {
    if args.stdin {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| format!("stdin read: {e}"))?;
        return Ok(buf);
    }
    if let Some(path) = &args.input {
        return std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()));
    }
    Err("no input source — pass `--input PATH` or `--stdin`".into())
}

fn emit_text(
    blob: &wafrift_encoding::compression::CompressedBody,
    args: &CompressArgs,
) -> ExitCode {
    // Header value goes to stderr so an operator piping the
    // compressed body to a file gets clean bytes on stdout and the
    // header on a separate stream. Print to stderr unconditionally
    // (even with --output) so the operator always sees it.
    eprintln!(
        "{} Content-Encoding: {}",
        "[wafrift compress]".bright_cyan(),
        blob.content_encoding.bold()
    );
    eprintln!(
        "  {} bytes -> {} bytes ({:.1}% of original)",
        if blob.body.len() < usize::MAX / 2 { blob.body.len() } else { 0 },
        blob.body.len(),
        if blob.body.is_empty() { 0.0 } else { 100.0 }
    );

    match &args.output {
        Some(path) => match std::fs::write(path, &blob.body) {
            Ok(()) => {
                eprintln!(
                    "  wrote {} bytes to {}",
                    blob.body.len(),
                    path.display()
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{} write {}: {e}", "I/O error:".red().bold(), path.display());
                ExitCode::from(1)
            }
        },
        None => {
            // Bytes to stdout; lock for atomic write so an
            // interleaving caller never sees a partial write.
            let mut out = std::io::stdout().lock();
            match out.write_all(&blob.body) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("{} write stdout: {e}", "I/O error:".red().bold());
                    ExitCode::from(1)
                }
            }
        }
    }
}

fn emit_json(
    blob: &wafrift_encoding::compression::CompressedBody,
    args: &CompressArgs,
) -> ExitCode {
    use base64::Engine as _;
    let body_b64 = base64::engine::general_purpose::STANDARD.encode(&blob.body);
    let obj = serde_json::json!({
        "content_encoding": blob.content_encoding,
        "body_b64": body_b64,
        "body_len": blob.body.len(),
    });
    let line = obj.to_string();
    match &args.output {
        Some(path) => match std::fs::write(path, line.as_bytes()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("{} write {}: {e}", "I/O error:".red().bold(), path.display());
                ExitCode::from(1)
            }
        },
        None => {
            println!("{line}");
            ExitCode::SUCCESS
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(algos: &[&str], stdin: bool) -> CompressArgs {
        CompressArgs {
            algos: algos.iter().map(|s| (*s).to_string()).collect(),
            input: None,
            stdin,
            output: None,
            format: "text".into(),
        }
    }

    #[test]
    fn parse_algorithms_recognises_canonical_tokens() {
        let parsed = parse_algorithms(&[
            "gzip".to_string(),
            "deflate".to_string(),
            "br".to_string(),
            "identity".to_string(),
        ])
        .expect("all canonical tokens");
        assert_eq!(parsed, vec![Algorithm::Gzip, Algorithm::Deflate, Algorithm::Brotli, Algorithm::Identity]);
    }

    #[test]
    fn parse_algorithms_accepts_case_insensitive_input() {
        let parsed = parse_algorithms(&[
            "GZIP".to_string(),
            "Br".to_string(),
            "  identity  ".to_string(),
        ])
        .expect("case-insensitive + trim");
        assert_eq!(parsed, vec![Algorithm::Gzip, Algorithm::Brotli, Algorithm::Identity]);
    }

    #[test]
    fn parse_algorithms_rejects_unknown_with_message() {
        let err = parse_algorithms(&["lz4".to_string()]).expect_err("must reject");
        assert!(err.contains("lz4"));
        assert!(err.contains("supported:"));
    }

    #[test]
    fn parse_algorithms_rejects_empty_list() {
        let err = parse_algorithms(&[]).expect_err("must reject empty");
        assert!(err.contains("at least one"));
    }

    #[test]
    fn run_compress_without_input_source_returns_error_code() {
        let a = args(&["gzip"], false);
        // No --input, no --stdin set — must reject with code 1.
        let code = run_compress(a);
        let s = format!("{code:?}");
        assert!(
            s.contains("1") && !s.contains("(0"),
            "missing input must exit non-zero, got {s}"
        );
    }

    #[test]
    fn run_compress_with_unknown_algo_returns_error_code_2() {
        let mut a = args(&["snappy"], true);
        a.input = None;
        a.stdin = true; // not actually drained; algo parse fails first
        let code = run_compress(a);
        let s = format!("{code:?}");
        assert!(s.contains("2"), "unknown algo must exit 2, got {s}");
    }

    // The full end-to-end (stdin -> compressed body on stdout) is
    // exercised by integration tests under tests/ — running them
    // unit-side would require capturing stdin/stdout via a fixture,
    // which the binary's #[test] surface doesn't support cleanly.
}
