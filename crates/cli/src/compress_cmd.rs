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

    let original_len = body.len();
    let compressed = match chain(&body, &algos) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{} {e}", "Compression error:".red().bold());
            return ExitCode::from(1);
        }
    };

    match args.format.as_str() {
        "json" => emit_json(&compressed, original_len, &args),
        _ => emit_text(&compressed, original_len, &args),
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

/// Cap on the input body. A compressed-confusion attack wraps a
/// single HTTP request body — even fat JSON payloads stay well
/// under 1 MiB in practice. 16 MiB is a generous cap that catches
/// both `--input /dev/zero` operator typos AND a malicious upstream
/// pipeline trying to OOM the CLI via unbounded stdin.
pub const MAX_COMPRESS_INPUT_BYTES: usize = 16 * 1024 * 1024;

fn read_input(args: &CompressArgs) -> Result<Vec<u8>, String> {
    if args.stdin {
        return read_bounded_stdin(MAX_COMPRESS_INPUT_BYTES);
    }
    if let Some(path) = &args.input {
        return read_bounded_file(path, MAX_COMPRESS_INPUT_BYTES);
    }
    Err("no input source — pass `--input PATH` or `--stdin`".into())
}

/// Read stdin in chunks, aborting at the cap. Replaces
/// `read_to_end` which has no upper bound — a hostile upstream in
/// a shell pipeline could otherwise OOM the CLI.
fn read_bounded_stdin(max_bytes: usize) -> Result<Vec<u8>, String> {
    let mut buf: Vec<u8> = Vec::with_capacity(64 * 1024);
    let mut chunk = [0u8; 64 * 1024];
    let mut stdin = std::io::stdin().lock();
    loop {
        let n = stdin
            .read(&mut chunk)
            .map_err(|e| format!("stdin read: {e}"))?;
        if n == 0 {
            break;
        }
        if buf.len().saturating_add(n) > max_bytes {
            return Err(format!(
                "input exceeded {max_bytes}-byte cap — bounded-stdin defence aborted \
                 the read. Use `--input PATH` for files larger than this if you really \
                 need them."
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(buf)
}

/// Read a file in chunks, aborting at the cap. Defends against
/// `--input /dev/zero` style operator typos AND symlink-to-large-
/// file traps.
fn read_bounded_file(path: &std::path::Path, max_bytes: usize) -> Result<Vec<u8>, String> {
    let mut f = std::fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut buf: Vec<u8> = Vec::with_capacity(64 * 1024);
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let n = f
            .read(&mut chunk)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        if buf.len().saturating_add(n) > max_bytes {
            return Err(format!(
                "{} exceeded {max_bytes}-byte cap — bounded-file defence aborted the read",
                path.display()
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(buf)
}

fn emit_text(
    blob: &wafrift_encoding::compression::CompressedBody,
    original_len: usize,
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
    let ratio_pct = if original_len == 0 {
        0.0
    } else {
        (blob.body.len() as f64 / original_len as f64) * 100.0
    };
    eprintln!(
        "  {} bytes -> {} bytes ({:.1}% of original)",
        original_len,
        blob.body.len(),
        ratio_pct
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
    original_len: usize,
    args: &CompressArgs,
) -> ExitCode {
    use base64::Engine as _;
    let body_b64 = base64::engine::general_purpose::STANDARD.encode(&blob.body);
    let obj = serde_json::json!({
        "content_encoding": blob.content_encoding,
        "body_b64": body_b64,
        "body_len": blob.body.len(),
        "original_len": original_len,
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

    #[test]
    fn read_bounded_file_returns_full_body_when_under_cap() {
        // Round-trip a small file through the bounded reader and
        // confirm we get the exact bytes back.
        let tmp = std::env::temp_dir().join(format!("wafrift-cb-{}.bin", std::process::id()));
        std::fs::write(&tmp, b"hello body").unwrap();
        let got = read_bounded_file(&tmp, 1024).unwrap();
        assert_eq!(&got, b"hello body");
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn read_bounded_file_errors_when_file_exceeds_cap() {
        let tmp = std::env::temp_dir().join(format!("wafrift-cb-big-{}.bin", std::process::id()));
        std::fs::write(&tmp, &vec![b'A'; 4096]).unwrap();
        let err = read_bounded_file(&tmp, 100).expect_err("must overrun");
        assert!(err.contains("100-byte cap"));
        assert!(err.contains(&tmp.display().to_string()));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn read_bounded_file_handles_empty_file() {
        let tmp = std::env::temp_dir().join(format!("wafrift-cb-empty-{}.bin", std::process::id()));
        std::fs::write(&tmp, b"").unwrap();
        let got = read_bounded_file(&tmp, 1024).unwrap();
        assert!(got.is_empty());
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn max_compress_input_bytes_is_at_least_one_megabyte() {
        // Floor: a refactor to a tiny cap would break legitimate
        // operator use on chunky JSON / multipart bodies. Lock the
        // floor so future tightening doesn't sneak past review.
        assert!(MAX_COMPRESS_INPUT_BYTES >= 1024 * 1024);
    }

    #[test]
    fn max_compress_input_bytes_is_at_most_one_gigabyte() {
        // Ceiling: a cap higher than 1 GiB defeats the DoS defence
        // on most laptops. 16 MiB is the current default and the
        // ceiling caps at 1 GiB to leave room for tuning without
        // disabling the defence.
        assert!(MAX_COMPRESS_INPUT_BYTES <= 1024 * 1024 * 1024);
    }
}
