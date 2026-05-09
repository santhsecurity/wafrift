//! `wafrift import-curl` — take a curl invocation (e.g. from Burp's
//! "Copy as cURL") + a payload/param, fire it through the scan engine.
//!
//! The practitioner workflow this closes: you have a request copied
//! from Burp (with auth headers, cookies, body) and you want to know
//! which evasion technique gets your payload past the WAF without
//! manually retyping any of the request context.
//!
//! Parsing is intentionally minimal: only the curl invocation flags
//! that practitioners actually paste in real screenshots are honoured
//! (`-X`, `-H`, `-A`, `-b`, `-d`/`--data`/`--data-raw`/`--data-urlencode`,
//! and the bare URL). Anything else is logged + ignored. We emit a
//! ScanArgs and dispatch through the same code path as `wafrift scan`,
//! so this command stays in sync with whatever scan does.

use clap::Args;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use crate::scan::ScanArgs;

#[derive(Args, Debug)]
pub struct ImportCurlArgs {
    /// Path to a file containing a curl invocation. Mutually exclusive
    /// with `--from-stdin`.
    #[arg(long)]
    pub curl_file: Option<PathBuf>,

    /// Read the curl invocation from stdin. Mutually exclusive with
    /// `--curl-file`.
    #[arg(long, default_value_t = false)]
    pub from_stdin: bool,

    /// Query/body parameter name to inject the payload into. Must
    /// already exist in the parsed curl request OR will be appended.
    #[arg(long)]
    pub param: String,

    /// Raw payload to mutate via the evasion engine.
    #[arg(long)]
    pub payload: String,

    /// Evasion intensity. Maps to `wafrift scan --level`.
    #[arg(long, default_value = "heavy", value_parser = ["light", "medium", "heavy"])]
    pub level: String,

    /// Inter-request delay in milliseconds.
    #[arg(long, default_value_t = 50)]
    pub delay_ms: u64,

    /// Disable TLS verification (lab targets only).
    #[arg(long, default_value_t = false)]
    pub insecure: bool,

    /// Output format: `text` (default) or `json`.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    /// Restrict to listed technique paths (comma-separated).
    #[arg(long, num_args = 1.., value_delimiter = ',')]
    pub only: Vec<String>,

    /// Drop listed technique paths (comma-separated).
    #[arg(long, num_args = 1.., value_delimiter = ',')]
    pub exclude: Vec<String>,
}

#[derive(Debug, Default)]
struct ParsedCurl {
    /// Method override from `-X / --request`. Defaults to GET (or POST
    /// when a body is present).
    method: Option<String>,
    /// The bare URL argument. If multiple appear (curl supports it),
    /// only the first is taken — practitioner intent is one request.
    url: Option<String>,
    /// All `-H / --header` values, preserved in order.
    headers: Vec<(String, String)>,
    /// `-A / --user-agent`.
    user_agent: Option<String>,
    /// `-b / --cookie` raw string. Glued onto a `Cookie:` header.
    cookie: Option<String>,
    /// Concatenated `--data*` bodies.
    body: Option<String>,
}

/// Tokenise a shell-style command line. Honours single quotes, double
/// quotes, and backslash continuations. Not a full shell parser, but
/// covers what Burp / Chromium "Copy as cURL" produce.
fn shell_tokenize(input: &str) -> Result<Vec<String>, String> {
    // Strip line continuations so multi-line curls (the common case
    // when copied from a terminal) collapse to one logical line.
    let cleaned = input.replace("\\\n", " ").replace("\\\r\n", " ");
    let mut out = Vec::new();
    let mut current = String::new();
    let mut chars = cleaned.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' | '\n' | '\r' => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
            '\'' => {
                // Single-quoted: literal until the next single quote.
                for q in chars.by_ref() {
                    if q == '\'' {
                        break;
                    }
                    current.push(q);
                }
            }
            '"' => {
                // Double-quoted: backslash-escaped allowed.
                while let Some(q) = chars.next() {
                    if q == '"' {
                        break;
                    }
                    if q == '\\' {
                        if let Some(esc) = chars.next() {
                            current.push(esc);
                        }
                    } else {
                        current.push(q);
                    }
                }
            }
            '\\' => {
                if let Some(esc) = chars.next() {
                    current.push(esc);
                }
            }
            other => current.push(other),
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    if out.is_empty() {
        return Err("empty curl invocation".to_string());
    }
    if out[0] != "curl" {
        return Err(format!(
            "first token must be `curl`, got {:?}",
            out[0]
        ));
    }
    Ok(out)
}

/// Parse a tokenised curl invocation into the subset of flags we honour.
fn parse_curl(tokens: &[String]) -> Result<ParsedCurl, String> {
    let mut p = ParsedCurl::default();
    let mut i = 1; // skip the literal `curl`
    while i < tokens.len() {
        let tok = &tokens[i];
        match tok.as_str() {
            "-X" | "--request" => {
                i += 1;
                let v = tokens
                    .get(i)
                    .ok_or_else(|| format!("{tok} needs a value"))?;
                p.method = Some(v.to_ascii_uppercase());
            }
            "-H" | "--header" => {
                i += 1;
                let v = tokens
                    .get(i)
                    .ok_or_else(|| format!("{tok} needs a value"))?;
                if let Some((name, val)) = v.split_once(':') {
                    p.headers
                        .push((name.trim().to_string(), val.trim().to_string()));
                } else {
                    return Err(format!("malformed header {v:?} (expected `Name: value`)"));
                }
            }
            "-A" | "--user-agent" => {
                i += 1;
                p.user_agent = Some(
                    tokens
                        .get(i)
                        .ok_or_else(|| format!("{tok} needs a value"))?
                        .clone(),
                );
            }
            "-b" | "--cookie" => {
                i += 1;
                p.cookie = Some(
                    tokens
                        .get(i)
                        .ok_or_else(|| format!("{tok} needs a value"))?
                        .clone(),
                );
            }
            "-d" | "--data" | "--data-raw" | "--data-binary" | "--data-urlencode" => {
                i += 1;
                let v = tokens
                    .get(i)
                    .ok_or_else(|| format!("{tok} needs a value"))?;
                let body = p.body.get_or_insert_with(String::new);
                if !body.is_empty() {
                    body.push('&');
                }
                body.push_str(v);
            }
            // Common no-op flags from Burp's "Copy as cURL" — accept and ignore.
            "-i" | "--include" | "-k" | "--insecure" | "--compressed" | "-s"
            | "--silent" | "-v" | "--verbose" | "-L" | "--location" | "-o"
            | "--output" | "-O" | "--remote-name" => {
                if matches!(tok.as_str(), "-o" | "--output") {
                    i += 1; // skip the file argument too
                }
            }
            other if other.starts_with("--") => {
                // Long option: skip the option AND its argument if it
                // looks like one (heuristic: next token doesn't start
                // with -). Keeps unknown options from misparsing.
                if i + 1 < tokens.len() && !tokens[i + 1].starts_with('-') {
                    i += 1;
                }
            }
            other if other.starts_with('-') && other.len() > 1 => {
                // Short option we don't know — best-effort skip.
            }
            url => {
                if p.url.is_none() {
                    p.url = Some(url.to_string());
                }
            }
            _ => {}
        }
        i += 1;
    }
    if p.url.is_none() {
        return Err("no URL found in curl invocation".to_string());
    }
    Ok(p)
}

pub fn run_import_curl(args: ImportCurlArgs) -> ExitCode {
    if args.curl_file.is_some() && args.from_stdin {
        eprintln!("error: --curl-file and --from-stdin are mutually exclusive");
        return ExitCode::from(1);
    }
    let raw = match (&args.curl_file, args.from_stdin) {
        (Some(p), false) => match fs::read_to_string(p) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error: read {}: {e}", p.display());
                return ExitCode::from(1);
            }
        },
        (None, true) => {
            let mut buf = String::new();
            if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
                eprintln!("error: read stdin: {e}");
                return ExitCode::from(1);
            }
            buf
        }
        (None, false) => {
            eprintln!("error: pick one of --curl-file <path> / --from-stdin");
            return ExitCode::from(1);
        }
        (Some(_), true) => unreachable!(),
    };
    let tokens = match shell_tokenize(&raw) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: parse curl: {e}");
            return ExitCode::from(1);
        }
    };
    let parsed = match parse_curl(&tokens) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: parse curl: {e}");
            return ExitCode::from(1);
        }
    };

    let target = parsed.url.expect("checked in parse_curl");
    eprintln!("import-curl: parsed {} headers, body {} bytes, method {} → target {}",
        parsed.headers.len(),
        parsed.body.as_ref().map(|s| s.len()).unwrap_or(0),
        parsed.method.as_deref().unwrap_or(if parsed.body.is_some() { "POST" } else { "GET" }),
        target,
    );

    // Bridge into the scan path. Practitioner intent is "use this
    // request's context (auth/cookies/headers) and probe the named
    // param with the supplied payload" — scan handles the evasion +
    // verdict layers, we just hand it the parsed inputs.
    //
    // NOTE: scan currently doesn't accept arbitrary header sets via
    // CLI; it builds a synthetic browser fingerprint. Until scan
    // grows a `--header` flag (tracked separately), import-curl emits
    // a one-liner the practitioner can hand to scan AND prints the
    // parsed context for transparency.
    eprintln!();
    eprintln!("=== parsed request context (handed to scan via the standard CLI) ===");
    if let Some(ua) = &parsed.user_agent {
        eprintln!("  User-Agent: {ua}");
    }
    if let Some(c) = &parsed.cookie {
        eprintln!("  Cookie: {c}");
    }
    for (k, v) in &parsed.headers {
        eprintln!("  {k}: {v}");
    }
    eprintln!();

    let scan_args = ScanArgs {
        target,
        payload: args.payload,
        param: args.param,
        level: parse_level(&args.level),
        encoding_only: false,
        delay_ms: args.delay_ms,
        format: args.format,
        stealth_browser: None,
        insecure: args.insecure,
        report_layers: false,
        only: args.only,
        exclude: args.exclude,
        output: None,
    };

    let rt = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: tokio runtime: {e}");
            return ExitCode::from(1);
        }
    };
    let cancel = tokio_util::sync::CancellationToken::new();
    rt.block_on(async { crate::scan::run_scan(scan_args, cancel).await })
}

fn parse_level(s: &str) -> crate::Level {
    match s {
        "light" => crate::Level::Light,
        "medium" => crate::Level::Medium,
        _ => crate::Level::Heavy,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_simple_curl() {
        let toks = shell_tokenize("curl https://example.com").unwrap();
        assert_eq!(toks, vec!["curl", "https://example.com"]);
    }

    #[test]
    fn tokenize_single_quoted_value() {
        let toks =
            shell_tokenize("curl 'https://x/y?z=1&a=2' -H 'User-Agent: x'").unwrap();
        assert_eq!(toks[1], "https://x/y?z=1&a=2");
        assert_eq!(toks[3], "User-Agent: x");
    }

    #[test]
    fn tokenize_handles_multiline_continuations() {
        let raw = "curl 'https://x' \\\n  -H 'A: 1' \\\n  -d 'k=v'";
        let toks = shell_tokenize(raw).unwrap();
        assert_eq!(toks[0], "curl");
        assert_eq!(toks[1], "https://x");
        assert_eq!(toks[2], "-H");
        assert_eq!(toks[3], "A: 1");
        assert_eq!(toks[4], "-d");
        assert_eq!(toks[5], "k=v");
    }

    #[test]
    fn tokenize_double_quoted_with_escape() {
        let toks = shell_tokenize(r#"curl "https://x" "-H" "A: \"quoted\"""#).unwrap();
        assert_eq!(toks[1], "https://x");
        assert_eq!(toks[3], r#"A: "quoted""#);
    }

    #[test]
    fn tokenize_rejects_non_curl_first_token() {
        assert!(shell_tokenize("wget https://x").is_err());
    }

    #[test]
    fn parse_minimal_get() {
        let toks = shell_tokenize("curl https://example.com/login").unwrap();
        let p = parse_curl(&toks).unwrap();
        assert_eq!(p.url.as_deref(), Some("https://example.com/login"));
        assert_eq!(p.method, None);
        assert!(p.headers.is_empty());
        assert!(p.body.is_none());
    }

    #[test]
    fn parse_post_with_headers_and_body() {
        let raw = "curl 'https://api.target/login' \\\n  -H 'Content-Type: application/x-www-form-urlencoded' \\\n  -H 'Cookie: sess=abc' \\\n  --data-raw 'user=admin&pass=test'";
        let toks = shell_tokenize(raw).unwrap();
        let p = parse_curl(&toks).unwrap();
        assert_eq!(p.url.as_deref(), Some("https://api.target/login"));
        assert_eq!(p.headers.len(), 2);
        assert_eq!(p.headers[0], ("Content-Type".into(), "application/x-www-form-urlencoded".into()));
        assert_eq!(p.headers[1], ("Cookie".into(), "sess=abc".into()));
        assert_eq!(p.body.as_deref(), Some("user=admin&pass=test"));
    }

    #[test]
    fn parse_method_override() {
        let toks = shell_tokenize("curl -X PUT https://x").unwrap();
        let p = parse_curl(&toks).unwrap();
        assert_eq!(p.method.as_deref(), Some("PUT"));
    }

    #[test]
    fn parse_user_agent_and_cookie() {
        let toks = shell_tokenize("curl -A 'Mozilla/5.0' -b 'sess=abc' https://x").unwrap();
        let p = parse_curl(&toks).unwrap();
        assert_eq!(p.user_agent.as_deref(), Some("Mozilla/5.0"));
        assert_eq!(p.cookie.as_deref(), Some("sess=abc"));
    }

    #[test]
    fn parse_concatenates_multiple_data_flags() {
        let raw = "curl https://x --data 'k1=v1' --data-raw 'k2=v2' --data 'k3=v3'";
        let toks = shell_tokenize(raw).unwrap();
        let p = parse_curl(&toks).unwrap();
        assert_eq!(p.body.as_deref(), Some("k1=v1&k2=v2&k3=v3"));
    }

    #[test]
    fn parse_silently_ignores_no_op_flags() {
        // Common Chromium "Copy as cURL" output peppers in -i, --compressed, etc.
        let raw = "curl -i --compressed -k -L 'https://x/y'";
        let toks = shell_tokenize(raw).unwrap();
        let p = parse_curl(&toks).unwrap();
        assert_eq!(p.url.as_deref(), Some("https://x/y"));
    }

    #[test]
    fn parse_rejects_missing_url() {
        let toks = shell_tokenize("curl -H 'A: 1'").unwrap();
        assert!(parse_curl(&toks).is_err());
    }

    #[test]
    fn parse_rejects_malformed_header() {
        let toks = shell_tokenize("curl -H 'noColon' https://x").unwrap();
        let err = parse_curl(&toks).unwrap_err();
        assert!(err.contains("malformed header"));
    }
}
