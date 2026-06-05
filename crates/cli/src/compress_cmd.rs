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
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use wafrift_encoding::compression::{Algorithm, chain};

#[derive(Args, Debug)]
pub(crate) struct CompressArgs {
    /// Compression algorithm. May be repeated to chain layers in
    /// RFC 9110 §8.4 order — the FIRST `--algo` is the OUTERMOST
    /// wrapper, the LAST is the innermost (closest to the original
    /// body). `--algo gzip --algo br` produces `gzip(brotli(body))`
    /// with `Content-Encoding: gzip, br`. Supported: `gzip`,
    /// `deflate`, `br` (or `brotli`), `identity` (no-op chain anchor).
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
/// # Exit codes
/// - `ExitCode::from(2)` — bad user input: unrecognised algorithm name.
/// - `ExitCode::from(1)` — I/O failure (input read, output write),
///   compression-chain failure (e.g. chain depth above the safety cap),
///   or no input source supplied.
pub(crate) fn run_compress(args: CompressArgs) -> ExitCode {
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

    // N15 fix (dogfood R29 cohort): an empty body silently compressed
    // to a ~20-byte gzip-of-nothing exit-0 success. A pentester
    // piping the output of a failed upstream command (e.g.
    // `grep nonexistent file | wafrift compress --stdin`) was
    // getting a misleadingly-successful compressed body containing
    // zero attack surface. Refuse empty input.
    if body.is_empty() {
        eprintln!(
            "{} input was empty — refusing to emit a header-only \
             compressed blob. Did the upstream command fail or produce \
             zero bytes?",
            "Input error:".red().bold()
        );
        return ExitCode::from(2);
    }

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
        // CLI-layer convenience alias: `brotli` → `br`. This command's own
        // help prose ("gzip / deflate / brotli / chain", "Brotli is the
        // headline gap") names the algorithm in full, so an operator typing
        // `--algo brotli` is following the docs — but `br` is the only valid
        // HTTP Content-Encoding TOKEN, so the domain `Algorithm::from_token`
        // (which also parses real header strings in `decompress`) correctly
        // rejects `brotli`. We normalise at the CLI boundary instead of
        // loosening the wire-token parser, mirroring the existing `x-gzip`
        // tolerance. The emitted `Content-Encoding` is still `br`.
        let normalised = if token.trim().eq_ignore_ascii_case("brotli") {
            "br"
        } else {
            token.as_str()
        };
        match Algorithm::from_token(normalised) {
            Some(a) => out.push(a),
            None => {
                return Err(format!(
                    "unknown algorithm {token:?}; supported: gzip, deflate, br (brotli), identity"
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
pub(crate) const MAX_COMPRESS_INPUT_BYTES: usize = 16 * 1024 * 1024;

fn read_input(args: &CompressArgs) -> Result<Vec<u8>, String> {
    if args.stdin {
        return read_bounded_stdin(MAX_COMPRESS_INPUT_BYTES);
    }
    if let Some(path) = &args.input {
        return read_bounded_file(path, MAX_COMPRESS_INPUT_BYTES);
    }
    Err("no input source — pass `--input PATH` or `--stdin`".into())
}

/// Read stdin in chunks, aborting at the cap. Delegates to the
/// canonical bounded-stdin reader in `safe_body` — one OOM guard for
/// the whole crate — mapping its `ReadError` onto the `String` error
/// surface this command uses.
fn read_bounded_stdin(max_bytes: usize) -> Result<Vec<u8>, String> {
    crate::safe_body::read_bounded_stdin_bytes(max_bytes).map_err(|e| e.to_string())
}

/// Read a file in chunks, aborting at the cap. Defends against
/// `--input /dev/zero` style operator typos AND symlink-to-large-
/// file traps. Opens here so the `--input`-expects-a-PATH footgun
/// hint is preserved, then delegates the bounded read loop to the
/// canonical `safe_body::read_bounded_from` (single OOM guard).
fn read_bounded_file(path: &std::path::Path, max_bytes: usize) -> Result<Vec<u8>, String> {
    let f = std::fs::File::open(path).map_err(|e| {
        // Operator footgun: many users assume `--input PAYLOAD` is
        // the payload string itself, not a file path.  When the
        // "file" doesn't exist, point them at the correct flag —
        // `--stdin` for inline strings (the only argv-NUL-safe
        // path) or `echo 'X' | wafrift compress --stdin`.
        format!(
            "open {}: {e}\n  Hint: `--input` expects a PATH to a file. \
            For inline payloads use `echo 'X' | wafrift compress --stdin`.",
            path.display()
        )
    })?;
    // Prepend the path so an overrun / read error still names the file
    // (the canonical loop's message is medium-agnostic).
    crate::safe_body::read_bounded_from(f, max_bytes)
        .map_err(|e| format!("{}: {e}", path.display()))
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
                eprintln!("  wrote {} bytes to {}", blob.body.len(), path.display());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!(
                    "{} write {}: {e}",
                    "I/O error:".red().bold(),
                    path.display()
                );
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
                eprintln!(
                    "{} write {}: {e}",
                    "I/O error:".red().bold(),
                    path.display()
                );
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
        assert_eq!(
            parsed,
            vec![
                Algorithm::Gzip,
                Algorithm::Deflate,
                Algorithm::Brotli,
                Algorithm::Identity
            ]
        );
    }

    #[test]
    fn parse_algorithms_accepts_case_insensitive_input() {
        let parsed = parse_algorithms(&[
            "GZIP".to_string(),
            "Br".to_string(),
            "  identity  ".to_string(),
        ])
        .expect("case-insensitive + trim");
        assert_eq!(
            parsed,
            vec![Algorithm::Gzip, Algorithm::Brotli, Algorithm::Identity]
        );
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
        std::fs::write(&tmp, vec![b'A'; 4096]).unwrap();
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

    // ── parse_algorithms edge cases ───────────────────────────

    #[test]
    fn parse_algorithms_accepts_chain_of_same_algo() {
        // Layering gzip on gzip is a valid chain: stage one decoder
        // sees gzip, decodes, finds another gzip blob, decodes
        // again. Two-layer gzip with the same algo MUST work.
        let parsed = parse_algorithms(&["gzip".into(), "gzip".into()])
            .expect("repeated algo is a valid chain");
        assert_eq!(parsed, vec![Algorithm::Gzip, Algorithm::Gzip]);
    }

    #[test]
    fn parse_algorithms_rejects_whitespace_only_token() {
        // A token of just whitespace is operator typo — must
        // surface an error not silently map to a default algo.
        let err = parse_algorithms(&["   ".into()]).expect_err("whitespace-only invalid");
        assert!(err.contains("supported:"));
    }

    #[test]
    fn parse_algorithms_rejects_empty_string_token() {
        let err = parse_algorithms(&["".into()]).expect_err("empty string invalid");
        assert!(err.contains("supported:"));
    }

    #[test]
    fn parse_algorithms_error_message_includes_user_input_verbatim() {
        // Operator must see WHICH algo string was bad — the error
        // message must contain it.
        let err = parse_algorithms(&["snappy42".into()]).expect_err("unknown");
        assert!(err.contains("snappy42"), "must echo the bad token: {err}");
    }

    #[test]
    fn parse_algorithms_recognises_x_gzip_legacy_alias() {
        // The encoding crate accepts `x-gzip` as a gzip alias per
        // RFC 9110 §8.4.1.3. This contract leak-tests that the
        // CLI surface passes it through.
        let parsed = parse_algorithms(&["x-gzip".into()]).expect("x-gzip is gzip");
        assert_eq!(parsed, vec![Algorithm::Gzip]);
    }

    #[test]
    fn parse_algorithms_accepts_brotli_full_name_as_cli_alias_for_br() {
        // DOGFOOD (R2): the `compress` help prose names the algorithm in
        // full ("gzip / deflate / brotli / chain", "Brotli is the headline
        // gap"), so an operator following the docs types `--algo brotli` —
        // but `br` is the only valid HTTP Content-Encoding token, so the
        // wire-token parser (`Algorithm::from_token`, also used to parse real
        // header strings in `decompress`) correctly rejects `brotli`. The CLI
        // layer normalises `brotli` → `br`, case-insensitively and trimmed,
        // so the help text and the accepted input agree. The emitted
        // `Content-Encoding` must still be the RFC token `br`, never `brotli`.
        for spelling in ["brotli", "BROTLI", "Brotli", "  brotli  "] {
            let parsed = parse_algorithms(&[spelling.to_string()])
                .unwrap_or_else(|e| panic!("`{spelling}` must alias to br, got err: {e}"));
            assert_eq!(parsed, vec![Algorithm::Brotli], "spelling {spelling:?}");
            // The wire token is `br`, not the alias the operator typed.
            assert_eq!(parsed[0].content_encoding(), "br");
        }
    }

    #[test]
    fn parse_algorithms_brotli_alias_composes_in_a_chain() {
        // `--algo gzip --algo brotli` must produce the same chain as
        // `--algo gzip --algo br` — the alias is purely an input convenience.
        let via_alias = parse_algorithms(&["gzip".into(), "brotli".into()]).expect("alias chain");
        let via_token = parse_algorithms(&["gzip".into(), "br".into()]).expect("token chain");
        assert_eq!(via_alias, via_token);
        assert_eq!(via_alias, vec![Algorithm::Gzip, Algorithm::Brotli]);
    }

    #[test]
    fn parse_algorithms_error_set_advertises_the_brotli_alias() {
        // COHERENCE: the rejection message must name `br (brotli)` so an
        // operator who typo'd a different algo learns both the wire token
        // and the accepted full-name alias.
        let err = parse_algorithms(&["lz4".into()]).expect_err("unknown");
        assert!(
            err.contains("br (brotli)"),
            "must advertise the alias: {err}"
        );
    }

    // ── read_bounded_file boundary conditions ─────────────────

    #[test]
    fn read_bounded_file_succeeds_at_exact_cap() {
        let tmp = std::env::temp_dir().join(format!(
            "wafrift-cb-exact-{}-{}.bin",
            std::process::id(),
            line!()
        ));
        std::fs::write(&tmp, vec![b'A'; 100]).unwrap();
        let got = read_bounded_file(&tmp, 100).expect("cap == file len passes");
        assert_eq!(got.len(), 100);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn read_bounded_file_overruns_one_byte_above_cap() {
        let tmp = std::env::temp_dir().join(format!(
            "wafrift-cb-above-{}-{}.bin",
            std::process::id(),
            line!()
        ));
        std::fs::write(&tmp, vec![b'A'; 101]).unwrap();
        let err = read_bounded_file(&tmp, 100).expect_err("101 over 100");
        assert!(err.contains("100-byte cap"));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn read_bounded_file_succeeds_one_byte_under_cap() {
        let tmp = std::env::temp_dir().join(format!(
            "wafrift-cb-under-{}-{}.bin",
            std::process::id(),
            line!()
        ));
        std::fs::write(&tmp, vec![b'A'; 99]).unwrap();
        let got = read_bounded_file(&tmp, 100).expect("99 under 100");
        assert_eq!(got.len(), 99);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn read_bounded_file_zero_byte_file_with_zero_cap_succeeds() {
        let tmp = std::env::temp_dir().join(format!(
            "wafrift-cb-empty-zero-{}-{}.bin",
            std::process::id(),
            line!()
        ));
        std::fs::write(&tmp, b"").unwrap();
        let got = read_bounded_file(&tmp, 0).expect("empty file always passes");
        assert!(got.is_empty());
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn read_bounded_file_one_byte_file_with_zero_cap_overruns() {
        let tmp = std::env::temp_dir().join(format!(
            "wafrift-cb-onezero-{}-{}.bin",
            std::process::id(),
            line!()
        ));
        std::fs::write(&tmp, b"x").unwrap();
        let err = read_bounded_file(&tmp, 0).expect_err("1 > 0 cap");
        assert!(err.contains("0-byte cap"));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn read_bounded_file_preserves_nul_bytes() {
        let tmp = std::env::temp_dir().join(format!(
            "wafrift-cb-nul-{}-{}.bin",
            std::process::id(),
            line!()
        ));
        std::fs::write(&tmp, [b'a', 0, 0, b'b']).unwrap();
        let got = read_bounded_file(&tmp, 1024).unwrap();
        assert_eq!(&got[..], &[b'a', 0, 0, b'b']);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn read_bounded_file_missing_path_returns_clean_error() {
        let err = read_bounded_file(
            std::path::Path::new("/nonexistent/wafrift/path/does/not/exist"),
            1024,
        )
        .expect_err("missing file must error");
        assert!(err.to_lowercase().contains("open"));
    }

    #[test]
    fn read_bounded_file_handles_binary_payload_byte_identical() {
        // Compress-input MUST be binary-clean — gzip/brotli output
        // has no text guarantee. The bounded reader must preserve
        // every byte including high-bit and 0xFF.
        let tmp = std::env::temp_dir().join(format!(
            "wafrift-cb-bin-{}-{}.bin",
            std::process::id(),
            line!()
        ));
        let payload: Vec<u8> = (0..=255u8).collect();
        std::fs::write(&tmp, &payload).unwrap();
        let got = read_bounded_file(&tmp, 1024).unwrap();
        assert_eq!(got, payload);
        let _ = std::fs::remove_file(&tmp);
    }

    // ── End-to-end compression sanity ─────────────────────────

    #[test]
    fn chain_with_identity_alone_preserves_body_byte_identical() {
        // Identity is the no-op anchor. A chain of just `identity`
        // round-trips the body untouched. Anti-rig: a refactor that
        // made identity into a "compress with default" would silently
        // change the wire shape.
        let body = b"unchanged bytes";
        let blob = chain(body, &[Algorithm::Identity]).unwrap();
        assert_eq!(&blob.body[..], body);
        assert!(blob.content_encoding == "identity" || blob.content_encoding.is_empty());
    }

    #[test]
    fn chain_with_gzip_alone_produces_decodable_gzip() {
        use wafrift_encoding::compression::{CompressedBody, decompress};
        let body = b"some test payload";
        let blob = chain(body, &[Algorithm::Gzip]).unwrap();
        let recovered = decompress(&CompressedBody {
            body: blob.body.clone(),
            content_encoding: blob.content_encoding.clone(),
        })
        .unwrap();
        assert_eq!(&recovered[..], body);
    }

    #[test]
    fn chain_with_deflate_alone_produces_decodable_deflate() {
        // Mirror the gzip test for deflate — proves the CLI's
        // deflate path matches the encoding crate's contract end
        // to end.
        use wafrift_encoding::compression::{CompressedBody, decompress};
        let body = b"deflate test payload";
        let blob = chain(body, &[Algorithm::Deflate]).unwrap();
        let recovered = decompress(&CompressedBody {
            body: blob.body.clone(),
            content_encoding: blob.content_encoding.clone(),
        })
        .unwrap();
        assert_eq!(&recovered[..], body);
    }

    #[test]
    fn chain_with_gzip_then_br_emits_outer_to_inner_content_encoding() {
        // RFC 9110 §8.4 list order: leftmost is the OUTERMOST
        // wrapper. A `gzip, br` chain means body is gzip(br(payload)).
        // Confirm the resulting header value lists gzip before br.
        let blob = chain(b"payload", &[Algorithm::Gzip, Algorithm::Brotli]).unwrap();
        let gz_pos = blob.content_encoding.find("gzip").expect("gzip");
        let br_pos = blob.content_encoding.find("br").expect("br");
        assert!(gz_pos < br_pos, "ce={}", blob.content_encoding);
    }
}
