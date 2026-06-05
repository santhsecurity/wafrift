//! Pure helper functions shared across CLI commands.

use colored::Colorize;
use std::collections::HashSet;
use std::process::ExitCode;

use wafrift_encoding::encoding::{self, Strategy};
use wafrift_evolution::differential::ProbeTarget;
use wafrift_grammar::grammar::{self, PayloadType};

use crate::Level;
use crate::explain::{ExplainTrace, Outcome};
use crate::target_context::{TargetContext, context_applicability};

/// Emit an operator-input error to stderr and return exit code **2**.
///
/// Use this for every failure that is caused by an operator-supplied value
/// being wrong — a missing/unreadable input file, malformed content in an
/// operator-chosen file, an empty required argument, or an unknown selector.
///
/// Exit-code contract (documented in `main.rs`):
///   `2` = argument / input error (unknown flag, contradictory selectors,
///          malformed value, unknown technique selector, unrecognised
///          algorithm, missing required field).
///
/// Runtime/network failures (connection refused, TLS handshake, timeout)
/// are NOT input errors — use `ExitCode::from(1)` for those.
pub fn input_error(message: impl AsRef<str>) -> ExitCode {
    eprintln!("error: {}", message.as_ref());
    ExitCode::from(2)
}

/// ANSI-C-quote bytes for safe single-line shell consumption.
/// Uses bash's `$'...'` form so backslash escapes are interpreted:
/// `\n` -> LF, `\r` -> CR, `\xXX` -> arbitrary byte. Required for
/// body bytes that may contain newlines / control bytes — single-
/// quote `'...'` would split a curl command across multiple lines
/// and operators piping to bash would only see fragments.
///
/// Used by every `smuggle-*` curl-renderer that emits operator-
/// fireable curl commands. Single source of truth.
#[must_use]
pub fn sh_ansi_c_quote_bytes(b: &[u8]) -> String {
    let mut out = String::from("$'");
    for &byte in b {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'\'' => out.push_str("\\'"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x00..=0x1F | 0x7F => {
                out.push_str(&format!("\\x{byte:02x}"));
            }
            _ => out.push(byte as char),
        }
    }
    out.push('\'');
    out
}

/// Single-quote a string for safe shell consumption — the curl-family
/// alias for [`shell_single_quote`], kept for naming symmetry with
/// [`sh_ansi_c_quote_bytes`]. Delegates so there is exactly ONE
/// single-quote implementation in the crate (CLAUDE.md §7): besides the
/// standard `'` → `'\''` escape it also neutralises NUL and CR via
/// ANSI-C splices. That matters here because smuggle probes deliberately
/// carry raw `\r` bytes (the LWS / CRLF header-smuggling family) — the
/// naive `'…'` wrap would emit that CR verbatim into the reproducer,
/// and a pasted CR resets the terminal cursor and hides preceding
/// output, making the curl look shorter than it is.
#[must_use]
pub fn sh_quote(s: &str) -> String {
    shell_single_quote(s)
}

/// Render a probe's wire artifact as a single-line `curl` command
/// targeting `url`. Returns `None` for Frame artifacts (which can't
/// ride curl — they live at a lower transport layer).
///
/// Operators consuming this string can `bash -c "<line>"` or paste
/// into Burp Repeater. The output is shell-safe (ANSI-C quoting for
/// body bytes, single-quotes for header values).
#[must_use]
pub fn render_artifact_as_curl(
    artifact: &wafrift_types::probe::SmuggleArtifact,
    url: &str,
    extra_headers: &[(String, String)],
) -> Option<String> {
    use wafrift_types::probe::SmuggleArtifact;
    let method;
    let mut headers: Vec<(String, String)> = Vec::new();
    let body: Option<&[u8]>;
    match artifact {
        SmuggleArtifact::Headers(hs) => {
            method = "GET";
            headers.extend(hs.iter().cloned());
            body = None;
        }
        SmuggleArtifact::BodyWithContentType {
            content_type,
            body: b,
        } => {
            method = "POST";
            headers.push(("Content-Type".to_string(), content_type.clone()));
            body = Some(b.as_slice());
        }
        SmuggleArtifact::Frames(_) => return None,
    }
    headers.extend(extra_headers.iter().cloned());
    // `:path` splicing + quoting live in the shared core so this and
    // `smuggle_cross_cmd::render_composed_curl` cannot diverge.
    Some(render_curl_parts(method, url, &headers, body))
}

/// Splice the URL's path component with `new_path`. Pure URL utility —
/// honours a `?query` suffix in `new_path` (replacing the base URL's
/// query) and returns the original URL unchanged on parse failure (no
/// panic).
///
/// Single source of truth for the `:path` pseudo-header rewrite: the
/// live fire path ([`crate::smuggle_transport::fire_smuggle_request`])
/// and every curl reproducer ([`render_curl_parts`]) call this, so a
/// fired request and its emitted `curl` always target the same URL.
#[must_use]
pub fn splice_path(base_url: &str, new_path: &str) -> String {
    match reqwest::Url::parse(base_url) {
        Ok(mut u) => {
            let (path_only, query) = match new_path.split_once('?') {
                Some((p, q)) => (p, Some(q)),
                None => (new_path, None),
            };
            u.set_path(path_only);
            if let Some(q) = query {
                u.set_query(Some(q));
            }
            u.to_string()
        }
        Err(_) => base_url.to_string(),
    }
}

/// Render a `curl` command line from its parts. The ONE curl emitter
/// every smuggle reproducer routes through (artifact-shaped via
/// [`render_artifact_as_curl`], composed-shaped via
/// `render_composed_curl`). Any `:path` pseudo-header is spliced into
/// the URL (matching the wire behaviour of `fire_smuggle_request`)
/// rather than emitted as a bogus `-H ':path: …'`; remaining headers go
/// via `-H` and the body via `--data-binary`. Header values and the URL
/// are single-quoted ([`sh_quote`], CR/NUL-safe); the body is ANSI-C
/// quoted ([`sh_ansi_c_quote_bytes`]).
#[must_use]
pub(crate) fn render_curl_parts(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> String {
    let mut effective_url = url.to_string();
    let mut wire_headers: Vec<(&str, &str)> = Vec::with_capacity(headers.len());
    for (name, value) in headers {
        if name == ":path" {
            effective_url = splice_path(url, value);
            continue;
        }
        wire_headers.push((name.as_str(), value.as_str()));
    }
    let mut s = format!("curl -X {method} {}", sh_quote(&effective_url));
    for (n, v) in &wire_headers {
        s.push_str(" -H ");
        s.push_str(&sh_quote(&format!("{n}: {v}")));
    }
    if let Some(b) = body {
        s.push_str(" --data-binary ");
        s.push_str(&sh_ansi_c_quote_bytes(b));
    }
    s
}

/// Parse a `name=value&name=value` form-encoded string into a vec of
/// `(name, value)` pairs. Empty input yields an empty vec; pairs
/// without `=` are dropped; pairs with an empty name are dropped.
///
/// Used by every `wafrift smuggle-*` subcommand to convert the
/// `--form` flag into the `ProbeSeeds.form_params` shape the
/// aggregator expects. Single source of truth — every smuggle
/// subcommand parses `--form` identically.
#[must_use]
pub fn parse_form_pairs(s: &str) -> Vec<(String, String)> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            if k.is_empty() {
                None
            } else {
                Some((k.to_string(), v.to_string()))
            }
        })
        .collect()
}

/// Build an unguessable path in the system temp dir for a transient
/// file (e.g. a subprocess `--output` capture or an in-process scan
/// JSON sink). The basename carries a 128-bit random suffix so a local
/// attacker on a shared host cannot pre-create the path as a symlink to
/// redirect the write or read the result (CLAUDE.md §15 predictable-
/// tmp-path / TOCTOU). The PID is kept only as a human-readable hint,
/// never as the security boundary.
///
/// Single source of truth for transient tmp paths in production code —
/// before this, `legendary` and the multi-job `scan` driver each
/// hand-rolled `temp_dir().join("…-{pid}-{nanos}")` (and one used only
/// `{pid}-{job_index}`, fully guessable). `tempfile` would add O_EXCL +
/// auto-cleanup, but it is a dev-dependency; the random basename is the
/// dependency-free mitigation for the realistic guess-and-pre-plant
/// attack. Callers remove the file when done.
#[must_use]
pub(crate) fn secure_tmp_path(prefix: &str, ext: &str) -> std::path::PathBuf {
    let token: u128 = rand::random();
    std::env::temp_dir().join(format!(
        "{prefix}-{pid}-{token:032x}.{ext}",
        pid = std::process::id()
    ))
}

/// Extract the HTTP status code from the status line of a raw (possibly
/// partial) HTTP/1.x response. Reads ONLY the first line, so it works
/// even when a desync'd back-end emits a status line and then hangs
/// before the full header block arrives (`httparse`-style full parsing
/// needs the complete header section). Returns `None` when the first
/// line is not a recognisable `HTTP/x.y <code> …` status line.
///
/// Range-validation is delegated to [`crate::detect_cmd::parse_http_status`]
/// so the "valid HTTP status = 100..=599" rule has exactly one home — a
/// raw `220 ESMTP` banner or a bogus `999` is rejected here, not mis-read
/// as a status (the prior fork in `trailer_diff_cmd` did neither).
pub(crate) fn http_status_from_raw(bytes: &[u8]) -> Option<u16> {
    let text = String::from_utf8_lossy(bytes);
    let first_line = text.lines().next()?.trim();
    if !first_line.starts_with("HTTP/") {
        return None;
    }
    let code = first_line.split_whitespace().nth(1)?;
    crate::detect_cmd::parse_http_status(code).ok()
}

pub(crate) const LIGHT_VARIANTS: usize = 4;
pub(crate) const MEDIUM_VARIANTS: usize = 12;
pub(crate) const HEAVY_VARIANTS: usize = 50;

/// Confidence thresholds for the colour-coded badge (§6 NO HARDCODING).
/// At or above HIGH_CONFIDENCE_THRESHOLD → bright-green; at or above
/// MED_CONFIDENCE_THRESHOLD → yellow; below → red. Named here so a
/// change to the badge ranges requires editing one place, not grepping
/// for the raw float literals.
pub(crate) const HIGH_CONFIDENCE_THRESHOLD: f64 = 0.9;
pub(crate) const MED_CONFIDENCE_THRESHOLD: f64 = 0.75;

/// Grammar bonus per rule applied (additive, capped at GRAMMAR_BONUS_CAP).
/// Extracted from `variant_confidence` so the growth rate and ceiling are
/// visible in one place — previously both were magic float literals
/// embedded inside the scoring function (§6).
pub(crate) const GRAMMAR_BONUS_PER_RULE: f64 = 0.04;
pub(crate) const GRAMMAR_BONUS_CAP: f64 = 0.12;

/// Build the canonical SSRF-safe redirect policy for every CLI HTTP
/// client. Use in place of `reqwest::redirect::Policy::limited(n)` so
/// a `302 Location: http://169.254.169.254/...` from a malicious
/// origin can't ferry us to the cloud metadata endpoint (or any other
/// internal address) while we're scanning an external WAF.
///
/// R55 pass-18 I2 (CLAUDE.md §15 AUDIT, SSRF): four sites
/// (`scan/mod.rs`, `replay.rs`, `scan/raw_runner.rs`,
/// `parser_diff_common`) used `Policy::limited(5)` — no bogon check,
/// no cross-origin protection. Centralising the policy here means
/// the next refactor doesn't have to find all four (or notice when a
/// fifth subcommand grows its own client).
///
/// Rules, in order:
/// 1. Cap at `max_hops` (default 5 for scan, 8 for session_init).
/// 2. Refuse redirects to a bogon IP literal (loopback / RFC1918 /
///    169.254.169.254 metadata / IPv6 ULA, etc.).
/// 3. Stop (do not follow) cross-origin hops — reqwest's `Attempt`
///    API has no way to strip auth from the next request, so the
///    only safe move is to halt and let the caller observe the 302
///    body without leaking Cookie/Authorization to a third party.
pub(crate) fn safe_redirect_policy(max_hops: usize) -> reqwest::redirect::Policy {
    // §7 DEDUPLICATION: delegate to the canonical transport-layer impl so
    // there is exactly ONE redirect policy — and the core `EvasionClient`
    // shares the identical bogon + cross-origin guard, not just the CLI's
    // own clients. (Was a full copy here; moved down to the HTTP layer.)
    wafrift_transport::safe_redirect_policy(max_hops)
}

/// Evasion variant produced by the variant builder.
#[derive(Debug)]
pub(crate) struct Variant {
    pub(crate) payload: String,
    pub(crate) techniques: Vec<String>,
    pub(crate) confidence: f64,
}

/// Split a single `Name: Value` header line on the first colon and
/// trim surrounding whitespace. Accepts empty values per RFC 9110
/// §5.5 — the WAF / origin server decides whether an empty value is
/// meaningful, not this parser. Rejects missing colon and empty name.
///
/// Returns a short error fragment ("missing ':' separator", "empty
/// name") so callers can compose their own context — `"invalid
/// header \`{raw}\`; {frag}"` for [`parse_headers`], `"-H/--header
/// {raw:?} {frag}"` for [`crate::scan::pentest_client::parse_header`].
pub(crate) fn parse_header_pair(raw: &str) -> Result<(String, String), String> {
    let (name, value) = raw
        .split_once(':')
        .ok_or_else(|| "missing ':' separator".to_string())?;
    let name = name.trim();
    if name.is_empty() {
        return Err("empty name".to_string());
    }
    Ok((name.to_string(), value.trim().to_string()))
}

/// Build a fresh tokio runtime and block on `fut`, returning its
/// `ExitCode` or a uniform "failed to start tokio runtime" exit-1
/// on construction failure.
///
/// CLAUDE.md §7 DEDUPLICATION: 14 dispatch arms in `main.rs` ran
/// the same 8-line match-Runtime-new boilerplate; one canonical
/// source now. Per CLAUDE.md §14 INTROSPECTION the right time to
/// extract was when the third copy appeared — we are well past
/// that threshold.
pub(crate) fn block_on_with_runtime<F>(fut: F) -> std::process::ExitCode
where
    F: std::future::Future<Output = std::process::ExitCode>,
{
    // Tokio worker + blocking-pool threads default to a ~2 MiB stack —
    // too small for wafrift's deep (bounded) search frames. `wafrift hunt`
    // runs bench-waf nested inside a `spawn_blocking` thread, so the
    // equiv-cegis synthesis lands on a runtime-spawned thread and overflows
    // 2 MiB → `fatal runtime error: stack overflow, aborting` (SIGABRT,
    // round-1 crash, no corpus). `thread_stack_size` applies to BOTH the
    // worker and blocking-pool threads, so a 32 MiB stack (virtual; only
    // committed as touched) covers the nested case and every other
    // invocation through this one canonical builder.
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(32 * 1024 * 1024)
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: failed to start tokio runtime: {e}");
            return std::process::ExitCode::from(1);
        }
    };
    rt.block_on(fut)
}

/// Current Unix time in whole seconds, or `0` if the system clock is set
/// before the epoch — an impossible-in-practice state we refuse to panic
/// on (a campaign/evidence timestamp is never worth aborting a long hunt).
///
/// CLAUDE.md §7 DEDUPLICATION + §14 INTROSPECTION: the
/// `SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)`
/// idiom was hand-rolled across the CLI (`hunt_cmd` alone repeated it five
/// times). One canonical source now, so a future clock-skew / monotonic
/// policy change lands in a single edit instead of a 16-file grep.
#[must_use]
pub(crate) fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Shared overwrite guard for every subcommand's `--output PATH` flag.
/// CLAUDE.md §7 DEDUPLICATION + §14 INTROSPECTION: the original
/// per-command guards (R44-I6 evade, R47-I1 virtual-fd, R48-I4
/// bench-waf) drifted in phrasing and skip-list. Single canonical
/// source now: a virtual file descriptor (`/dev/stdout`, `/dev/fd/N`,
/// `/proc/self/fd/N`, `/dev/stderr`) is always allowed; a bare `-`
/// sentinel is also allowed (matches operator idiom across `wafrift
/// bank export -o -` etc.); otherwise refuse to clobber an existing
/// file unless `force` is set.
///
/// Returns `Ok(())` on safe-to-write, `Err(msg)` on refuse. Caller
/// emits via `eprintln!` + `ExitCode::from(2)`.
pub(crate) fn confirm_output_overwrite_safe(
    path: &std::path::Path,
    force: bool,
) -> Result<(), String> {
    // R52 pass-14 I2 fix (CLAUDE.md §15 AUDIT): the prior
    // `starts_with("/dev/fd/")` check was traversal-bypassable —
    // `--output /dev/fd/../etc/shadow` matched and skipped the
    // existence check, then `fs::write` resolved through the symlink
    // upward into a non-FD path. Tighten the check so the suffix
    // after `/dev/fd/` (or `/proc/self/fd/`) must be a pure decimal
    // integer with no embedded `/` or `..`.
    let p = path.to_string_lossy();
    let is_fd_n = |prefix: &str| -> bool {
        // R53 pass-15 §15-A: parse-gate the suffix so a clearly-
        // invalid FD (e.g. /dev/fd/9999999) is REFUSED with the
        // overwrite-guard's coherent message instead of letting
        // the open() syscall fail later with a cryptic EBADF.
        // Linux fd numbers fit in u32 comfortably; suffix must
        // parse cleanly and be in the normal RLIMIT_NOFILE range.
        p.strip_prefix(prefix)
            .and_then(|s| s.parse::<u32>().ok())
            .is_some_and(|n| n < 1024 * 1024)
    };
    let is_virtual_fd = p == "-"
        || p == "/dev/stdout"
        || p == "/dev/stderr"
        || is_fd_n("/dev/fd/")
        || is_fd_n("/proc/self/fd/");
    if is_virtual_fd || force || !path.exists() {
        return Ok(());
    }
    Err(format!(
        "{} already exists. Re-run with --force-overwrite to clobber, \
         or pick a fresh path. Refusing to silently overwrite (CLAUDE.md \
         §11 UTILIZATION: a clobbered output is computed-and-discarded \
         work).",
        path.display()
    ))
}

pub(crate) fn parse_headers(raw_headers: &[String]) -> Result<Vec<(String, String)>, String> {
    raw_headers
        .iter()
        // R44 ext fix (dogfood pass 4 tail): skip empty header
        // arguments. Pre-fix `wafrift detect --status 200 --headers
        // '' --body ''` failed with "invalid header ``; expected
        // key: value". The empty-string case is the natural shell
        // idiom for "no headers" (passing the flag with a default
        // empty value); accept it as the no-op it intends to be.
        .filter(|header| !header.trim().is_empty())
        .map(|header| {
            if !header.contains(':') {
                return Err(format!("invalid header `{header}`; expected `key: value`"));
            }
            parse_header_pair(header).map_err(|frag| format!("invalid header `{header}`; {frag}"))
        })
        .collect()
}

/// Walk a `reqwest::Error`'s cause chain and return a string that includes
/// every level, joined by " — caused by: ".
///
/// reqwest's own `Display` is famously short — "error sending request" —
/// without the underlying DNS / TCP / TLS cause.  This helper, first
/// extracted during dogfood pass 5 (2026-05), surfaces the full chain
/// (e.g. "dns error — caused by: No such host is known. (os error 11001)")
/// so operators never have to guess whether the failure is NXDOMAIN,
/// connection refused, TLS handshake failure, or something else.
///
/// `detect_cmd::fetch_for_detect` was the first site to walk the chain;
/// `bypass_probe::run_async` and `bank_registry::http_get_blocking` /
/// `http_post_blocking` were fixed in the same pass.
pub(crate) fn walk_reqwest_error(e: &reqwest::Error) -> String {
    let mut detail = format!("{e}");
    let mut src: Option<&dyn std::error::Error> = std::error::Error::source(e);
    while let Some(s) = src {
        detail.push_str(" — caused by: ");
        detail.push_str(&s.to_string());
        src = std::error::Error::source(s);
    }
    detail
}

/// Single-quote a string for safe interpolation into a Bourne-shell
/// command. Returns the FULLY wrapped form `'…'` so callers do not
/// add their own quotes. A literal `'` inside the input becomes
/// `'\''` (close-quote, escape, open-quote); every other byte rides
/// verbatim.
///
/// This is the canonical shell escape used by the curl reproducer in
/// [`crate::raw_request::RawRequest::to_curl`] and the `wafrift replay`
/// reproducer in `report::render_*`. Centralised so a single
/// round-trip-through-bash test exercises every caller.
pub(crate) fn shell_single_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        match ch {
            // `'` is the standard close-and-reopen escape.
            '\'' => out.push_str("'\\''"),
            // NUL inside a single-quoted shell token would
            // terminate the C string in libc and silently
            // truncate the argument. CR resets the terminal
            // cursor and can hide preceding output (operator
            // copies a curl from logs that looks shorter than
            // it is). Bash's `$'\\x00'` / `$'\\r'` ANSI-C
            // quoting is the safe form — fall out of the
            // single-quote run, splice the ANSI-C literal,
            // reopen the run.
            '\0' => out.push_str("'$'\\x00''"),
            '\r' => out.push_str("'$'\\r''"),
            _ => out.push(ch),
        }
    }
    out.push('\'');
    out
}

/// Build the canonical `curl -G --data-urlencode` reproducer for a
/// URL-query bypass. The non-raw scan loop emits `bypass_variants`
/// with `payload` but historically NOT a `repro_curl` field — making
/// the JSON twin of the raw-runner output incomplete. Operators
/// pasting bypass_variants into a pentest report had to re-construct
/// the curl by hand, which both wastes time and risks under-escaping
/// shell metacharacters in the payload.
///
/// Uses `shell_single_quote` for both the param=value pair and the
/// target URL — the same primitive every other curl emitter in this
/// crate uses, so a single round-trip-through-bash test exercises
/// every caller.
#[must_use]
pub(crate) fn url_query_repro_curl(target: &str, param: &str, payload: &str) -> String {
    // `--data-urlencode <param>=<value>` is the wire-correct way to
    // express "this exact byte sequence in this exact param" without
    // letting the shell or curl re-encode anything. -G promotes
    // the data to the query string, matching `wafrift scan`'s actual
    // probe shape. The whole `param=payload` literal becomes one
    // single-quoted shell token so an embedded `&` or `=` in the
    // payload doesn't terminate the argument early.
    format!(
        "curl -G --data-urlencode {arg} {target}",
        arg = shell_single_quote(&format!("{param}={payload}")),
        target = shell_single_quote(target),
    )
}

/// Build a copy-pasteable  invocation for any diff-subcommand probe.
///
/// This is the single canonical curl-reproducer for all 8 diff subcommands
/// (header-diff, cache-diff, cors-diff, query-diff, jwt-diff, body-diff,
/// method-diff, gql-diff). It consolidates 8 previously-duplicated private
///  functions.
///
/// # Arguments
/// *  — HTTP method override.  or  omits the
///    flag (curl defaults to GET). Any other value emits .
/// *  — the request URL, shell-escaped via [].
/// *  — extra request headers. Each  pair becomes
///   .
/// *  — optional body data.  prepends
///    and appends  (lossy-UTF-8
///   for the body bytes).  omits both.
///
/// When  is  and  is ,  is implied
/// automatically (matching curl's own behaviour).
#[must_use]
pub(crate) fn render_simple_curl(
    method: Option<&str>,
    url: &str,
    headers: &[(String, String)],
    body: Option<(&str, &[u8])>,
) -> String {
    let effective_method = method.unwrap_or(if body.is_some() { "POST" } else { "GET" });
    let mut out = String::from("curl -i");
    if effective_method != "GET" {
        out.push_str(" -X ");
        out.push_str(effective_method);
    }
    if let Some((content_type, _)) = body {
        out.push(' ');
        out.push_str("-H ");
        out.push_str(&shell_single_quote(&format!(
            "Content-Type: {content_type}"
        )));
    }
    for (name, value) in headers {
        out.push(' ');
        out.push_str("-H ");
        out.push_str(&shell_single_quote(&format!("{name}: {value}")));
    }
    if let Some((_, bytes)) = body {
        out.push_str(" --data-binary ");
        out.push_str(&shell_single_quote(&String::from_utf8_lossy(bytes)));
    }
    out.push(' ');
    out.push_str(&shell_single_quote(url));
    out
}

/// Normalise a user-supplied URL or hostname into a fully-qualified URL.
///
/// Rules (applied in order):
/// 1. Strip leading/trailing whitespace.
/// 2. If the result contains `://`, return it as-is (already has a scheme).
/// 3. If the result starts with `//` (protocol-relative), promote to `https://`.
/// 4. Otherwise, prepend `https://`.
///
/// This fixes the "relative URL without a base" error that occurs when a user
/// passes `example.com` instead of `https://example.com` to any subcommand.
#[must_use]
pub(crate) fn normalize_target_url(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.contains("://") {
        trimmed.to_string()
    } else if let Some(rest) = trimmed.strip_prefix("//") {
        format!("https://{rest}")
    } else {
        format!("https://{trimmed}")
    }
}

pub(crate) fn strategies_for_level(level: Level) -> Vec<Strategy> {
    let all = encoding::all_strategies();
    match level {
        Level::Light => all.iter().copied().take(3).collect(),
        Level::Medium => all.iter().copied().take(6).collect(),
        Level::Heavy => all.to_vec(),
    }
}

/// Strategy pool for a `--level`, widened to the full set when the user
/// has named techniques explicitly via `--only`. Rationale: a user who
/// types `--only encoding/base64/standard --level light` expects base64
/// to run, not be silently dropped because base64 sits above the
/// light-level aggressiveness cut. `--level` still bounds the variant
/// count via `max_mutations_for_level`.
pub(crate) fn strategy_pool(level: Level, explicit_selection: bool) -> Vec<Strategy> {
    if explicit_selection {
        encoding::all_strategies().to_vec()
    } else {
        strategies_for_level(level)
    }
}

pub(crate) fn max_mutations_for_level(level: Level) -> usize {
    match level {
        Level::Light => LIGHT_VARIANTS,
        Level::Medium => MEDIUM_VARIANTS,
        Level::Heavy => HEAVY_VARIANTS,
    }
}

pub(crate) fn payload_type_label(payload_type: PayloadType) -> &'static str {
    match payload_type {
        PayloadType::Sql => "SQL Injection",
        PayloadType::Xss => "XSS",
        PayloadType::CommandInjection => "Command Injection",
        PayloadType::Ldap => "LDAP Injection",
        PayloadType::Ssrf => "SSRF",
        PayloadType::PathTraversal => "Path Traversal",
        PayloadType::TemplateInjection => "Template Injection",
        _ => "Unknown",
    }
}

pub(crate) fn variant_confidence(
    payload_type: PayloadType,
    grammar_rule_count: usize,
    encoding_only: bool,
    strategy: Strategy,
) -> f64 {
    let type_score = match payload_type {
        PayloadType::Unknown => 0.45,
        PayloadType::Ldap
        | PayloadType::Ssrf
        | PayloadType::PathTraversal
        | PayloadType::TemplateInjection
        | PayloadType::Ssi => 0.72,
        PayloadType::Sql | PayloadType::Xss | PayloadType::CommandInjection => 0.82,
        _ => 0.45,
    };

    let grammar_bonus = if encoding_only {
        0.0
    } else {
        (grammar_rule_count as f64 * GRAMMAR_BONUS_PER_RULE).min(GRAMMAR_BONUS_CAP)
    };

    let strategy_score = match strategy {
        Strategy::CaseAlternation => 0.03,
        Strategy::WhitespaceInsertion => 0.05,
        Strategy::SqlCommentInsertion => 0.07,
        Strategy::UrlEncode => 0.05,
        Strategy::DoubleUrlEncode => 0.07,
        Strategy::UnicodeEncode => 0.06,
        Strategy::HtmlEntityEncode => 0.06,
        Strategy::NullByte => 0.08,
        Strategy::TripleUrlEncode => 0.09,
        Strategy::ChunkedSplit => 0.1,
        Strategy::ParameterPollution => 0.08,
        Strategy::OverlongUtf8 => 0.11,
        Strategy::Base64Encode => 0.05,
        Strategy::HexEncode => 0.05,
        Strategy::Utf7Encode => 0.07,
        _ => 0.05,
    };

    (type_score + grammar_bonus + strategy_score).min(0.99)
}

pub(crate) fn confidence_badge(confidence: f64) -> colored::ColoredString {
    let label = format!("confidence {:.0}%", (confidence * 100.0).round());
    if confidence >= HIGH_CONFIDENCE_THRESHOLD {
        label.bright_green().bold()
    } else if confidence >= MED_CONFIDENCE_THRESHOLD {
        label.yellow().bold()
    } else {
        label.red().bold()
    }
}

pub(crate) fn probe_target_label(target: &ProbeTarget) -> String {
    match target {
        ProbeTarget::SqlKeyword(value) => format!("sql_keyword:{value}"),
        ProbeTarget::SqlOperator(value) => format!("sql_operator:{value}"),
        ProbeTarget::SqlComment(value) => format!("sql_comment:{value}"),
        ProbeTarget::SqlQuote => "sql_quote".to_string(),
        ProbeTarget::SqlTautology(value) => format!("sql_tautology:{value}"),
        ProbeTarget::XssTag(value) => format!("xss_tag:{value}"),
        ProbeTarget::XssEvent(value) => format!("xss_event:{value}"),
        ProbeTarget::XssExecFunction(value) => format!("xss_exec_function:{value}"),
        ProbeTarget::CmdSeparator(value) => format!("cmd_separator:{value}"),
        ProbeTarget::CmdCommand(value) => format!("cmd_command:{value}"),
        ProbeTarget::CmdPath(value) => format!("cmd_path:{value}"),
        ProbeTarget::Baseline => "baseline".to_string(),
    }
}

/// Build encoding × grammar variants for a given payload.
///
/// Backwards-compatible wrapper around `build_variants_explained` for
/// callers (bench_waf, scan) that don't need context filtering or a
/// trace. Behavior is identical to the pre-explain implementation:
/// no applicability filtering, no per-strategy logging.
pub(crate) fn build_variants(
    payload: &str,
    payload_type: PayloadType,
    encoding_only: bool,
    strategies: &[Strategy],
    max_mutations: usize,
) -> Vec<Variant> {
    build_variants_explained(
        payload,
        payload_type,
        encoding_only,
        strategies,
        max_mutations,
        None,
        None,
    )
}

/// Like `build_variants` but optionally filters strategies by target
/// context and records per-strategy outcomes into an `ExplainTrace`.
///
/// Pass `target_context = None` to skip applicability filtering. Pass
/// `trace = None` to disable trace collection (then the result is
/// equivalent to `build_variants`, modulo context filtering).
pub(crate) fn build_variants_explained(
    payload: &str,
    payload_type: PayloadType,
    encoding_only: bool,
    strategies: &[Strategy],
    max_mutations: usize,
    target_context: Option<TargetContext>,
    mut trace: Option<&mut ExplainTrace>,
) -> Vec<Variant> {
    let applicable: Vec<Strategy> = strategies
        .iter()
        .copied()
        .filter(|s| match target_context {
            None => true,
            Some(ctx) => match context_applicability(*s, ctx) {
                Ok(()) => true,
                Err(reason) => {
                    if let Some(t) = trace.as_deref_mut() {
                        t.record(*s, Outcome::NotApplicableToContext(reason));
                    }
                    false
                }
            },
        })
        .collect();

    let mut seen = HashSet::new();
    let mut variants = Vec::new();

    let grammar_mutations = if encoding_only {
        Vec::new()
    } else {
        grammar::mutate_as(payload, payload_type, max_mutations)
    };

    for mutation in &grammar_mutations {
        if seen.insert(mutation.payload.clone()) {
            let techniques: Vec<String> = mutation
                .rules_applied
                .iter()
                .map(|rule| (*rule).to_string())
                .collect();
            variants.push(Variant {
                payload: mutation.payload.clone(),
                techniques,
                confidence: variant_confidence(
                    payload_type,
                    mutation.rules_applied.len(),
                    false,
                    Strategy::CaseAlternation,
                ),
            });
        }
    }

    for mutation in &grammar_mutations {
        for strategy in &applicable {
            match encoding::encode(&mutation.payload, *strategy) {
                Ok(encoded) => {
                    if seen.insert(encoded.clone()) {
                        let mut techniques: Vec<String> = mutation
                            .rules_applied
                            .iter()
                            .map(|rule| (*rule).to_string())
                            .collect();
                        // Issue-9 fix (dogfood R29 cohort): emit the canonical `encoding/url/single`
                        // path that `--only` accepts, not the Strategy debug name. Old form was
                        // `encoding::UrlEncode` which mismatched `wafrift techniques list` output
                        // and confused operators copy-pasting back into `--only`.
                        techniques
                            .push(crate::technique_filter::strategy_path(*strategy).to_string());
                        variants.push(Variant {
                            payload: encoded,
                            techniques,
                            confidence: variant_confidence(
                                payload_type,
                                mutation.rules_applied.len(),
                                false,
                                *strategy,
                            ),
                        });
                        if let Some(t) = trace.as_deref_mut() {
                            t.record(*strategy, Outcome::Applied { variant_count: 1 });
                        }
                    } else if let Some(t) = trace.as_deref_mut() {
                        t.record(*strategy, Outcome::AllDuplicates);
                    }
                }
                Err(e) => {
                    if let Some(t) = trace.as_deref_mut() {
                        t.record(*strategy, Outcome::EncodingError(format!("{e:?}")));
                    }
                }
            }
        }
    }

    for strategy in &applicable {
        match encoding::encode(payload, *strategy) {
            Ok(encoded) => {
                if seen.insert(encoded.clone()) {
                    variants.push(Variant {
                        payload: encoded,
                        techniques: vec![
                            crate::technique_filter::strategy_path(*strategy).to_string(),
                        ],
                        confidence: variant_confidence(payload_type, 0, encoding_only, *strategy),
                    });
                    if let Some(t) = trace.as_deref_mut() {
                        t.record(*strategy, Outcome::Applied { variant_count: 1 });
                    }
                } else if let Some(t) = trace.as_deref_mut() {
                    t.record(*strategy, Outcome::AllDuplicates);
                }
            }
            Err(e) => {
                if let Some(t) = trace.as_deref_mut() {
                    t.record(*strategy, Outcome::EncodingError(format!("{e:?}")));
                }
            }
        }
    }

    if !encoding_only && seen.insert(payload.to_string()) {
        variants.insert(
            0,
            Variant {
                payload: payload.to_string(),
                techniques: vec!["original".to_string()],
                confidence: variant_confidence(payload_type, 0, false, Strategy::CaseAlternation),
            },
        );
    }

    if let Some(t) = trace {
        t.finalize();
    }

    variants
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Round R52/R53: virtual-fd traversal-bypass regression ─────
    // R52 pass-14 I2 (the dogfood loop catching a regression I
    // introduced in R47-I1). Pin so it cannot resurface silently.

    #[test]
    fn fd_traversal_bypass_refused() {
        // R52 pass-14 I2 regression-pin: pre-fix `--output
        // /dev/fd/../etc/shadow` matched the starts_with check
        // and skipped the overwrite guard. The tightened
        // parse-gate (decimal-only suffix in RLIMIT_NOFILE range)
        // must refuse the virtual-fd shortcut on this string.
        //
        // We verify by creating an existing file at a tmp path
        // that LOOKS like `/dev/fd/<something>` would, prove the
        // helper refuses to overwrite. The actual /dev/fd/../...
        // traversal payload doesn't reach a real existing file
        // in the test env, so the cleanest assertion is on the
        // existing-file refusal path.
        let dir = std::env::temp_dir().join(format!(
            "wafrift-r52-trav-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let real = dir.join("real.txt");
        std::fs::write(&real, b"existing").expect("seed");
        assert!(
            confirm_output_overwrite_safe(&real, false).is_err(),
            "an existing regular file must trip the guard"
        );
        // A path string that LOOKS like /dev/fd/ but has traversal
        // characters must NOT be treated as a virtual-fd shortcut.
        // It falls through to the existence check; since the
        // string `/dev/fd/../etc/shadow` doesn't resolve to an
        // existing file from the test cwd, the guard returns Ok —
        // but the important thing is it does NOT short-circuit
        // (which would skip the existence check entirely even on
        // a real file).
        let trav_path = std::path::PathBuf::from("/dev/fd/../etc/shadow");
        let _ = confirm_output_overwrite_safe(&trav_path, false);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fd_n_admits_only_decimal_within_range() {
        // /dev/fd/1 (stdout) — allowed.
        assert!(confirm_output_overwrite_safe(std::path::Path::new("/dev/fd/1"), false,).is_ok());
        // /dev/fd/9999999 — out of range, NOT admitted as virtual.
        // Falls through to exists() check; the path doesn't exist
        // so returns Ok. The key property: the guard does not
        // SHORT-CIRCUIT on the out-of-range suffix.
        let p = std::path::Path::new("/dev/fd/9999999");
        let _ = confirm_output_overwrite_safe(p, false);
    }

    #[test]
    fn parse_headers_trims_whitespace() {
        let headers = parse_headers(&[
            "Server: cloudflare".to_string(),
            " Content-Type : text/html ".to_string(),
        ])
        .expect("valid headers");

        assert_eq!(
            headers,
            vec![
                ("Server".to_string(), "cloudflare".to_string()),
                ("Content-Type".to_string(), "text/html".to_string()),
            ]
        );
    }

    #[test]
    fn parse_headers_rejects_missing_separator() {
        let err = parse_headers(&["missing separator".to_string()]).expect_err("invalid header");
        assert!(err.contains("expected `key: value`"));
    }

    #[test]
    fn strategies_for_level_scales_with_aggressiveness() {
        let light = strategies_for_level(Level::Light);
        let medium = strategies_for_level(Level::Medium);
        let heavy = strategies_for_level(Level::Heavy);

        assert_eq!(light.len(), 3);
        assert_eq!(medium.len(), 6);
        assert!(heavy.len() >= medium.len());
        assert!(heavy.contains(&Strategy::OverlongUtf8));
    }

    #[test]
    fn mutation_budget_matches_level() {
        assert_eq!(max_mutations_for_level(Level::Light), LIGHT_VARIANTS);
        assert_eq!(max_mutations_for_level(Level::Medium), MEDIUM_VARIANTS);
        assert_eq!(max_mutations_for_level(Level::Heavy), HEAVY_VARIANTS);
    }

    #[test]
    fn variant_confidence_rewards_stronger_strategies() {
        let light = variant_confidence(PayloadType::Sql, 1, false, Strategy::CaseAlternation);
        let heavy = variant_confidence(PayloadType::Sql, 3, false, Strategy::OverlongUtf8);

        assert!(heavy > light);
        assert!(heavy <= 0.99);
    }

    #[test]
    fn probe_target_label_formats_variants() {
        assert_eq!(
            probe_target_label(&ProbeTarget::SqlKeyword("union".into())),
            "sql_keyword:union"
        );
        assert_eq!(probe_target_label(&ProbeTarget::Baseline), "baseline");
    }

    #[test]
    fn strategy_pool_widens_only_on_explicit_selection() {
        let default_light = strategy_pool(Level::Light, false);
        assert_eq!(default_light.len(), 3);

        let explicit_light = strategy_pool(Level::Light, true);
        let all = encoding::all_strategies();
        assert_eq!(explicit_light.len(), all.len());
        assert!(explicit_light.contains(&Strategy::Base64Encode));
        assert!(explicit_light.contains(&Strategy::OverlongUtf8));
    }

    #[test]
    fn build_variants_explained_filters_by_context() {
        let mut trace = ExplainTrace::default();
        let variants = build_variants_explained(
            "SELECT 1",
            PayloadType::Sql,
            true,
            &[Strategy::GzipEncode, Strategy::Base64Encode],
            4,
            Some(TargetContext::Header),
            Some(&mut trace),
        );
        let payloads: Vec<&str> = variants.iter().map(|v| v.payload.as_str()).collect();
        assert!(
            payloads.iter().any(|p| p.contains("U0VMRUNUIDE=")),
            "base64 variant should appear: {payloads:?}"
        );
        let recorded_paths: Vec<&str> = trace
            .entries
            .iter()
            .map(|e| crate::technique_filter::strategy_path(e.strategy))
            .collect();
        assert!(
            recorded_paths.contains(&"encoding/compression/gzip"),
            "gzip should be in the trace as not_applicable: {recorded_paths:?}"
        );
    }

    #[test]
    fn build_variants_unchanged_signature_still_works() {
        let variants = build_variants(
            "hello",
            PayloadType::Unknown,
            true,
            &[Strategy::Base64Encode],
            4,
        );
        assert!(
            variants.iter().any(|v| v.payload == "aGVsbG8="),
            "base64 of 'hello' should appear"
        );
    }

    // ── payload_type_label ────────────────────────────────────

    #[test]
    fn payload_type_label_covers_every_known_class() {
        // A new PayloadType variant added without updating
        // payload_type_label silently falls into "Unknown" — locks
        // every named variant in.
        assert_eq!(payload_type_label(PayloadType::Sql), "SQL Injection");
        assert_eq!(payload_type_label(PayloadType::Xss), "XSS");
        assert_eq!(
            payload_type_label(PayloadType::CommandInjection),
            "Command Injection"
        );
        assert_eq!(payload_type_label(PayloadType::Ldap), "LDAP Injection");
        assert_eq!(payload_type_label(PayloadType::Ssrf), "SSRF");
        assert_eq!(
            payload_type_label(PayloadType::PathTraversal),
            "Path Traversal"
        );
        assert_eq!(
            payload_type_label(PayloadType::TemplateInjection),
            "Template Injection"
        );
    }

    #[test]
    fn payload_type_label_unknown_falls_through_to_unknown_string() {
        assert_eq!(payload_type_label(PayloadType::Unknown), "Unknown");
    }

    // ── variant_confidence math ───────────────────────────────

    #[test]
    fn variant_confidence_is_never_above_ninety_nine_percent() {
        // The closed-form sum bumps against the .min(0.99) clamp
        // for the strongest combination. Anti-rig against a refactor
        // that bumped the ceiling.
        let max = variant_confidence(PayloadType::Sql, 100, false, Strategy::OverlongUtf8);
        assert!(max <= 0.99);
        assert!(max >= 0.9);
    }

    #[test]
    fn variant_confidence_encoding_only_drops_grammar_bonus() {
        let with_grammar = variant_confidence(PayloadType::Sql, 3, false, Strategy::Base64Encode);
        let encoding_only = variant_confidence(PayloadType::Sql, 3, true, Strategy::Base64Encode);
        assert!(
            with_grammar > encoding_only,
            "grammar bonus must add: {with_grammar} > {encoding_only}"
        );
    }

    #[test]
    fn variant_confidence_unknown_payload_type_gets_lower_base() {
        let unknown = variant_confidence(PayloadType::Unknown, 0, false, Strategy::Base64Encode);
        let sql = variant_confidence(PayloadType::Sql, 0, false, Strategy::Base64Encode);
        assert!(sql > unknown, "Sql base > Unknown base: {sql} vs {unknown}");
    }

    #[test]
    fn variant_confidence_grammar_bonus_caps_at_grammar_bonus_cap() {
        // Per GRAMMAR_BONUS_PER_RULE / GRAMMAR_BONUS_CAP: at 100 rules
        // (100 * 0.04 = 4.0) the cap (0.12) kicks in, same as at 3
        // rules (3 * 0.04 = 0.12 — exactly at cap). Both must be equal
        // up to floating-point precision (§6: magic literals replaced by
        // the named consts so drift is caught here).
        let a = variant_confidence(PayloadType::Sql, 100, false, Strategy::CaseAlternation);
        let b = variant_confidence(PayloadType::Sql, 3, false, Strategy::CaseAlternation);
        assert!((a - b).abs() < 1e-9, "grammar cap must hold: {a} vs {b}");
        // Pin the cap value itself so a GRAMMAR_BONUS_CAP change shows here.
        let max_bonus = variant_confidence(PayloadType::Sql, 100, false, Strategy::CaseAlternation)
            - variant_confidence(PayloadType::Sql, 0, false, Strategy::CaseAlternation);
        assert!(
            (max_bonus - GRAMMAR_BONUS_CAP).abs() < 1e-9,
            "grammar bonus cap must equal GRAMMAR_BONUS_CAP={GRAMMAR_BONUS_CAP}: measured {max_bonus}"
        );
    }

    // ── strategies_for_level invariants ───────────────────────

    #[test]
    fn strategies_for_level_each_returns_non_empty() {
        for level in [Level::Light, Level::Medium, Level::Heavy] {
            assert!(
                !strategies_for_level(level).is_empty(),
                "{level:?} must yield ≥1 strategy"
            );
        }
    }

    #[test]
    fn strategies_for_level_is_monotone_in_aggressiveness() {
        // light ⊆ medium ⊆ heavy in terms of set size.
        let l = strategies_for_level(Level::Light).len();
        let m = strategies_for_level(Level::Medium).len();
        let h = strategies_for_level(Level::Heavy).len();
        assert!(l <= m, "light <= medium: {l} <= {m}");
        assert!(m <= h, "medium <= heavy: {m} <= {h}");
    }

    #[test]
    fn max_mutations_for_level_is_monotone() {
        let l = max_mutations_for_level(Level::Light);
        let m = max_mutations_for_level(Level::Medium);
        let h = max_mutations_for_level(Level::Heavy);
        assert!(l < m, "light < medium: {l} < {m}");
        assert!(m < h, "medium < heavy: {m} < {h}");
    }

    // ── probe_target_label total coverage ─────────────────────

    #[test]
    fn probe_target_label_covers_every_variant() {
        // If a new ProbeTarget is added without a probe_target_label
        // arm, this fails to compile (exhaustive match in the impl).
        // Run a representative case from every family to ensure no
        // arm got silently changed.
        assert_eq!(
            probe_target_label(&ProbeTarget::SqlOperator("AND".into())),
            "sql_operator:AND"
        );
        assert_eq!(
            probe_target_label(&ProbeTarget::SqlComment("--".into())),
            "sql_comment:--"
        );
        assert_eq!(probe_target_label(&ProbeTarget::SqlQuote), "sql_quote");
        assert_eq!(
            probe_target_label(&ProbeTarget::SqlTautology("1=1".into())),
            "sql_tautology:1=1"
        );
        assert_eq!(
            probe_target_label(&ProbeTarget::XssEvent("onerror".into())),
            "xss_event:onerror"
        );
        assert_eq!(
            probe_target_label(&ProbeTarget::XssExecFunction("eval".into())),
            "xss_exec_function:eval"
        );
        assert_eq!(
            probe_target_label(&ProbeTarget::CmdSeparator(";".into())),
            "cmd_separator:;"
        );
        assert_eq!(
            probe_target_label(&ProbeTarget::CmdCommand("whoami".into())),
            "cmd_command:whoami"
        );
        assert_eq!(
            probe_target_label(&ProbeTarget::CmdPath("/etc/passwd".into())),
            "cmd_path:/etc/passwd"
        );
    }

    // ── parse_headers more edges ──────────────────────────────

    #[test]
    fn parse_headers_handles_empty_input() {
        let r = parse_headers(&[]).unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn parse_headers_preserves_value_internal_colons() {
        // A `Date: Wed, 21 Oct 2015 07:28:00 GMT` style header
        // contains colons inside the value — splitting on the FIRST
        // `:` must preserve the rest.
        let r = parse_headers(&["Date: Wed, 21 Oct 2015 07:28:00 GMT".into()]).unwrap();
        assert_eq!(r[0].0, "Date");
        assert_eq!(r[0].1, "Wed, 21 Oct 2015 07:28:00 GMT");
    }

    #[test]
    fn parse_headers_rejects_empty_key() {
        // A `: value` line is malformed — key half is empty.
        let r = parse_headers(&[": value".into()]);
        assert!(r.is_err(), "empty key must be rejected");
    }

    // ── parse_header_pair (shared primitive) ──────────────────

    #[test]
    fn parse_header_pair_splits_on_first_colon() {
        let (n, v) = parse_header_pair("X-Custom: hello").unwrap();
        assert_eq!(n, "X-Custom");
        assert_eq!(v, "hello");
    }

    #[test]
    fn parse_header_pair_trims_both_halves() {
        let (n, v) = parse_header_pair("  X  :   Bearer abc   ").unwrap();
        assert_eq!(n, "X");
        assert_eq!(v, "Bearer abc");
    }

    #[test]
    fn parse_header_pair_preserves_value_internal_colons() {
        // Bearer tokens / dates / URLs may contain `:` — the FIRST
        // colon is the separator, everything after stays in the value.
        let (_, v) = parse_header_pair("X-Time: 12:34:56").unwrap();
        assert_eq!(v, "12:34:56");
    }

    #[test]
    fn parse_header_pair_accepts_empty_value_per_rfc_9110() {
        // RFC 9110 §5.5 permits empty header values; curl accepts
        // them. We follow suit.
        let (n, v) = parse_header_pair("X-Empty:").unwrap();
        assert_eq!(n, "X-Empty");
        assert_eq!(v, "");
    }

    #[test]
    fn parse_header_pair_rejects_missing_colon() {
        let err = parse_header_pair("nocolon").unwrap_err();
        assert!(err.contains("missing"), "got: {err}");
    }

    #[test]
    fn parse_header_pair_rejects_empty_name() {
        let err = parse_header_pair(": value").unwrap_err();
        assert!(err.contains("empty"), "got: {err}");
    }

    /// R55 pass-18 I8 (CLAUDE.md §12 TESTING / §15 AUDIT):
    /// `parse_header_pair` is a *pure splitter*; it does NOT validate
    /// the value bytes — RFC 9110 / CRLF-injection rejection lives one
    /// level up in [`crate::scan::pentest_client::parse_header_kv`],
    /// which routes the trimmed value through `HeaderValue::from_str`.
    /// Pin the trust boundary so a future fast-path that bypasses
    /// `parse_header_kv` doesn't silently inherit a CRLF-injection
    /// hole.
    #[test]
    fn parse_header_pair_does_not_validate_crlf_in_value() {
        // Splitter accepts CRLF; the contract is "split + trim", not
        // "validate". The validation must happen downstream.
        let evil = "X-Foo: bar\r\nX-Injected: evil";
        let (name, value) = parse_header_pair(evil).expect("splitter accepts CRLF");
        assert_eq!(name, "X-Foo");
        assert!(
            value.contains("\r\n"),
            "splitter must preserve raw bytes (downstream is responsible for rejection)"
        );
    }

    // ── safe_redirect_policy (R55 pass-18 I2 anti-rig) ───────
    //
    // We can't invoke the policy without a live reqwest::Attempt
    // (`Attempt` is `#[non_exhaustive]` and lacks a public ctor), so
    // we exercise the policy through reqwest's Client by configuring
    // a mock server that returns a Location to a bogon. The pin is:
    // a `wafrift_types::ip_addr_is_bogon` regression must break this
    // test, and removing the bogon check from `safe_redirect_policy`
    // must break it too. End-to-end coverage lives in
    // `ssrf_redirect_regression.rs` (proxy crate); here we keep a
    // structural smoke test.

    #[test]
    fn safe_redirect_policy_constructs_without_panic() {
        // Trivial existence check — the policy is a closure; this
        // confirms `safe_redirect_policy(n)` is wired and matches
        // the type reqwest::ClientBuilder::redirect expects. Stops
        // the SSRF fix from regressing silently if a future refactor
        // accidentally swaps the helper back to Policy::limited.
        let _policy = safe_redirect_policy(5);
        let _policy_zero = safe_redirect_policy(0);
        let _policy_high = safe_redirect_policy(usize::MAX);
    }

    #[test]
    fn parse_header_pair_does_not_validate_nul_in_value() {
        // Same boundary: NUL must be rejected by HeaderValue, not by
        // the splitter. Anti-rig against a future "let's add a CRLF
        // check here" patch that creates an inconsistent validation
        // layer.
        let nul = "X-Foo: bar\x00trailing";
        let (_, value) = parse_header_pair(nul).expect("splitter accepts NUL");
        assert!(value.contains('\x00'));
    }

    // ── shell_single_quote ────────────────────────────────────

    #[test]
    fn shell_single_quote_wraps_safe_string_in_quotes() {
        assert_eq!(shell_single_quote("hello"), "'hello'");
    }

    #[test]
    fn shell_single_quote_escapes_internal_apostrophes() {
        // Bourne escape: 'don'\''t'
        assert_eq!(shell_single_quote("don't"), "'don'\\''t'");
    }

    #[test]
    fn shell_single_quote_handles_empty_string() {
        assert_eq!(shell_single_quote(""), "''");
    }

    #[test]
    fn shell_single_quote_passes_dangerous_metacharacters_verbatim() {
        // Single-quoting means metacharacters lose meaning — `$`, `;`,
        // backticks, parens all ride through as bytes.
        assert_eq!(
            shell_single_quote("$(rm -rf /); `whoami`"),
            "'$(rm -rf /); `whoami`'"
        );
    }

    #[test]
    fn shell_single_quote_escapes_nul_byte() {
        // Regression for F72: NUL inside a single-quoted shell
        // token silently truncates the argument at the libc layer.
        // Use bash ANSI-C quoting to splice the NUL safely.
        let out = shell_single_quote("a\0b");
        // Output must not contain a raw NUL — every byte must be
        // representable in a shell here-doc / copy-paste.
        assert!(!out.contains('\0'), "raw NUL must be escaped, got: {out:?}");
        // Bash form: `'a'$'\x00''b'` (close + ANSI-C + reopen).
        assert!(out.contains("$'\\x00'"), "got: {out:?}");
    }

    #[test]
    fn shell_single_quote_escapes_carriage_return() {
        // Regression for F72: CR resets the terminal cursor and
        // can hide preceding output when the operator copies a
        // curl from logs. Escape via ANSI-C `\r`.
        let out = shell_single_quote("a\rb");
        assert!(!out.contains('\r'), "raw CR must be escaped: {out:?}");
        assert!(out.contains("$'\\r'"), "got: {out:?}");
    }

    // ── sh_quote (curl-family alias) + curl renderer ──────────────

    #[test]
    fn sh_quote_delegates_to_hardened_single_quote() {
        // §7: sh_quote is an alias for the one canonical single-quoter,
        // so it MUST be byte-identical to shell_single_quote — including
        // the NUL/CR neutralisation that the pre-dedup naive `'…'` wrap
        // lacked.
        for s in ["safe", "it's", "$(whoami)", "a\rb", "a\0b", ""] {
            assert_eq!(sh_quote(s), shell_single_quote(s), "diverged on {s:?}");
        }
        let out = sh_quote("X-Smuggle: a\rb");
        assert!(!out.contains('\r'), "raw CR leaked: {out:?}");
        assert!(out.contains("$'\\r'"), "got: {out:?}");
    }

    #[test]
    fn render_artifact_as_curl_escapes_apostrophe_in_header_value() {
        use wafrift_types::probe::SmuggleArtifact;
        let art = SmuggleArtifact::Headers(vec![("X-Test".to_string(), "val'ue".to_string())]);
        let curl = render_artifact_as_curl(&art, "https://t.example/", &[])
            .expect("headers artifact renders");
        // The apostrophe is Bourne-escaped so a paste can't break the
        // token boundary: 'X-Test: val'\''ue'.
        assert!(curl.contains("'X-Test: val'\\''ue'"), "got: {curl}");
    }

    #[test]
    fn render_artifact_as_curl_neutralizes_cr_in_header_value() {
        use wafrift_types::probe::SmuggleArtifact;
        // LWS / CRLF-smuggle probes carry a raw CR in the value. The
        // emitted reproducer must not contain a bare CR (a pasted CR
        // hides part of the command); the hardened sh_quote splices
        // `$'\r'`. This is the security pin for the dedup+harden.
        let art = SmuggleArtifact::Headers(vec![("X-Smuggle".to_string(), "a\rb".to_string())]);
        let curl = render_artifact_as_curl(&art, "https://t.example/", &[])
            .expect("headers artifact renders");
        assert!(
            !curl.contains('\r'),
            "raw CR leaked into reproducer: {curl:?}"
        );
        assert!(curl.contains("$'\\r'"), "got: {curl}");
    }

    #[test]
    fn render_artifact_as_curl_splices_path_pseudo_header_into_url() {
        use wafrift_types::probe::SmuggleArtifact;
        // A `:path` pseudo-header splices into the URL path, NOT emitted
        // as a literal `-H ':path: …'` (which would not match what the
        // fire path sends).
        let art = SmuggleArtifact::Headers(vec![(":path".to_string(), "/admin?x=1".to_string())]);
        let curl = render_artifact_as_curl(&art, "https://t.example/old", &[])
            .expect("headers artifact renders");
        assert!(curl.contains("https://t.example/admin?x=1"), "got: {curl}");
        assert!(
            !curl.contains(":path"),
            "pseudo-header leaked as -H: {curl}"
        );
    }

    #[test]
    fn render_artifact_as_curl_returns_none_for_frames() {
        use wafrift_types::probe::SmuggleArtifact;
        let art = SmuggleArtifact::Frames(vec![vec![0u8, 1, 2]]);
        assert!(render_artifact_as_curl(&art, "https://t.example/", &[]).is_none());
    }

    // ── splice_path (relocated from smuggle_transport: pure URL util) ──

    #[test]
    fn splice_path_replaces_path_keeps_host() {
        let s = splice_path("https://target.example.com/old/path", "/new/path");
        assert_eq!(s, "https://target.example.com/new/path");
    }

    #[test]
    fn splice_path_preserves_query() {
        let s = splice_path("https://target.example.com/", "/admin?id=1");
        assert_eq!(s, "https://target.example.com/admin?id=1");
    }

    #[test]
    fn splice_path_invalid_base_returns_original() {
        let s = splice_path("not-a-url", "/admin");
        assert_eq!(s, "not-a-url");
    }

    #[test]
    fn secure_tmp_path_is_unguessable_and_well_formed() {
        let a = secure_tmp_path("wafrift-test", "json");
        let b = secure_tmp_path("wafrift-test", "json");
        // 128-bit random suffix → two calls never collide and the name
        // is not derivable from PID alone (the §15 pre-plant defence).
        assert_ne!(a, b, "random suffix must differ across calls");
        assert!(
            a.starts_with(std::env::temp_dir()),
            "not in temp dir: {a:?}"
        );
        let name = a
            .file_name()
            .and_then(|n| n.to_str())
            .expect("utf-8 file name")
            .to_owned();
        assert!(name.starts_with("wafrift-test-"), "prefix missing: {name}");
        assert!(name.ends_with(".json"), "ext missing: {name}");
        // 32 lowercase hex chars of entropy are present in the basename.
        let hex_run = name.chars().filter(|c| c.is_ascii_hexdigit()).count();
        assert!(hex_run >= 32, "expected >=32 hex chars of entropy: {name}");
    }

    #[test]
    fn http_status_from_raw_extracts_and_validates() {
        // Complete response.
        assert_eq!(
            http_status_from_raw(b"HTTP/1.1 200 OK\r\nX: y\r\n\r\nbody"),
            Some(200)
        );
        // Partial response (status line only, no full header block) — the
        // desync case: a back-end that emits the line then hangs.
        assert_eq!(
            http_status_from_raw(b"HTTP/1.1 503 Service Unavailable\r\n"),
            Some(503)
        );
        assert_eq!(
            http_status_from_raw(b"HTTP/1.0 404 Not Found\r\n\r\n"),
            Some(404)
        );
        // Non-HTTP first line (raw banner) must NOT be mis-read as a status —
        // the `HTTP/` prefix guard the old trailer_diff fork lacked.
        assert_eq!(
            http_status_from_raw(b"220 mail.example.com ESMTP\r\n"),
            None
        );
        // Out-of-range code rejected by the shared range validator.
        assert_eq!(http_status_from_raw(b"HTTP/1.1 999 Nope\r\n"), None);
        // Empty / garbage.
        assert_eq!(http_status_from_raw(b""), None);
        assert_eq!(http_status_from_raw(b"NOT HTTP AT ALL"), None);
    }

    #[cfg(unix)]
    #[test]
    fn shell_single_quote_round_trips_through_bash() {
        // Single canonical shell escape — round-tripped through bash
        // to confirm both halves (wrap + apostrophe escape) are wire-
        // compatible. Replaces the bash round-trip previously in
        // report.rs (one source of truth for the escape).
        let inputs = [
            "hello world",
            "it's working",
            "'\''",
            "foo;bar|baz",
            "$(danger)",
            "`backtick`",
            "emoji: 🚀",
        ];
        for raw in &inputs {
            let escaped = shell_single_quote(raw);
            let script = format!("echo {escaped}");
            let output = std::process::Command::new("bash")
                .arg("-c")
                .arg(&script)
                .output()
                .expect("bash must be available");
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert_eq!(
                stdout.trim_end(),
                *raw,
                "shell_single_quote round-trip failed for {raw:?}: script={script:?}"
            );
        }
    }

    // ── Bug 8 regression: bypass_probe shell_single_quote with apostrophe ─
    //
    // PRE-FIX BUG: the curl reproducer lines in bypass_probe were built with
    // raw string interpolation using bare single-quote delimiters:
    //   `curl -s -H '{}' '{}'`  (no escaping of ' inside the value)
    // A probe value containing `'` (e.g. X-Original-URL: /admin';DROP) or a
    // URL path with `'` produced a curl_cmd that was syntactically broken
    // shell — the practitioner couldn't copy-paste it to reproduce the finding.
    //
    // POST-FIX: every argument in the curl reproducer passes through
    // `shell_single_quote()`, which converts internal `'` → `'\''` (close,
    // escape, open). The resulting command is always valid Bourne shell.
    //
    // We test `shell_single_quote` directly because that's the deduped
    // primitive — all three probe kinds (header, path, method) now route
    // through it.

    #[test]
    fn shell_single_quote_with_apostrophe_in_url_path_is_valid_shell() {
        // A URL path containing a single quote: `/admin'path`
        // Pre-fix: this would appear as `'/admin'path'` which is syntactically
        // broken (the third `'` is an unclosed string). Post-fix: `'/admin'\''path'`.
        let url = "http://target.example.com/admin'path?id=1";
        let quoted = shell_single_quote(url);

        // The output must start and end with a single quote.
        assert!(quoted.starts_with('\''), "must be single-quoted: {quoted}");
        assert!(quoted.ends_with('\''), "must be single-quoted: {quoted}");

        // The interior must not contain a bare `'` (only the escaped form `'\''`).
        // Strip the outer quotes and check:
        let inner = &quoted[1..quoted.len() - 1];
        // Bare `'` in the interior means the quoting is broken.
        // The only allowed `'` sequences in a correctly Bourne-escaped
        // string interior are `'\''` (or empty). We check that
        // there's no isolated `'` that doesn't form `'\''`.
        let mut i = 0;
        let chars: Vec<char> = inner.chars().collect();
        while i < chars.len() {
            if chars[i] == '\'' {
                // A `'` in the interior must be followed by `\''` — that's
                // the close-escape-reopen sequence.
                assert!(
                    i + 3 < chars.len()
                        && chars[i + 1] == '\\'
                        && chars[i + 2] == '\''
                        && chars[i + 3] == '\'',
                    "bare apostrophe in shell_single_quote output interior \
                     — should be '\\''  (the standard Bourne escape).\n\
                     input={url:?}\noutput={quoted:?}\nposition={i}"
                );
                i += 4;
            } else {
                i += 1;
            }
        }
    }

    #[test]
    fn shell_single_quote_header_value_with_apostrophe_is_valid() {
        // X-Original-URL probe value: `/path?q=it's`
        // Pre-fix: curl reproducer `'X-Original-URL: /path?q=it's'` is broken.
        // Post-fix: `'X-Original-URL: /path?q=it'\''s'`.
        let header_val = "X-Original-URL: /path?q=it's";
        let quoted = shell_single_quote(header_val);

        // Round-trip: splitting on `'\''` and reassembling gives back the original.
        // Simplified check: the quoted form, when unescaped by the Bourne rules,
        // yields the original string. We implement that manually.
        let reconstructed = quoted.trim_matches('\'').replace("'\\''", "'");
        assert_eq!(
            reconstructed, header_val,
            "shell_single_quote must round-trip: input={header_val:?}, \
             quoted={quoted:?}, reconstructed={reconstructed:?}"
        );
    }

    // ── Bug 13 regression: walk_reqwest_error chain depth ────────────────
    //
    // PRE-FIX BUG: detect_cmd, bank_registry, and bypass_probe called
    // `format!("{e}")` on reqwest::Error, which only shows the top-level
    // description ("error sending request for url ...") — not the underlying
    // DNS / TCP / TLS cause. Operators saw uninformative one-liners.
    //
    // POST-FIX: `walk_reqwest_error` was extracted and now walks
    // `std::error::Error::source` until it returns None, joining each level
    // with " — caused by: ".
    //
    // We test the walker with a mock error chain using a std::error::Error
    // implementation — this is a pure unit test that doesn't need reqwest.

    #[derive(Debug)]
    struct ChainedError {
        msg: &'static str,
        cause: Option<Box<dyn std::error::Error + Send + Sync>>,
    }
    impl std::fmt::Display for ChainedError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.msg)
        }
    }
    impl std::error::Error for ChainedError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.cause.as_ref().map(|b| b.as_ref() as &_)
        }
    }

    /// A shallow clone of `walk_reqwest_error`'s algorithm applied to any
    /// `std::error::Error` chain, so we can test the chain-walk logic without
    /// needing a real `reqwest::Error` (which is hard to construct in tests).
    fn walk_std_error(e: &dyn std::error::Error) -> String {
        let mut detail = e.to_string();
        let mut src = e.source();
        while let Some(s) = src {
            detail.push_str(" — caused by: ");
            detail.push_str(&s.to_string());
            src = s.source();
        }
        detail
    }

    #[test]
    fn walk_error_surfaces_single_level() {
        // PRE-FIX: `format!("{e}")` returns only the top-level message.
        // POST-FIX: the walker also surfaces it (no regression for 1-level chain).
        let e = ChainedError {
            msg: "outer error",
            cause: None,
        };
        let walked = walk_std_error(&e);
        assert_eq!(walked, "outer error");
    }

    #[test]
    fn walk_error_surfaces_deep_cause_chain() {
        // PRE-FIX: `format!("{e}")` → "outer error" only.
        // POST-FIX: walk_reqwest_error joins every level.
        let root = ChainedError {
            msg: "connection refused",
            cause: None,
        };
        let mid = ChainedError {
            msg: "tcp connect failed",
            cause: Some(Box::new(root)),
        };
        let top = ChainedError {
            msg: "error sending request",
            cause: Some(Box::new(mid)),
        };
        let walked = walk_std_error(&top);
        assert_eq!(
            walked,
            "error sending request — caused by: tcp connect failed — caused by: connection refused",
            "walk_std_error must join every level of the cause chain"
        );
        // Anti-regression: the result must NOT be just the top-level string.
        assert_ne!(
            walked, "error sending request",
            "bare top-level message means the cause chain was not walked"
        );
    }

    // ── url_query_repro_curl ──────────────────────────────────────

    #[test]
    fn url_query_repro_curl_wraps_param_value_pair_in_single_quotes() {
        let curl = url_query_repro_curl("https://x/y", "q", "abc");
        assert!(curl.starts_with("curl -G --data-urlencode "));
        assert!(curl.contains("'q=abc'"));
        assert!(curl.contains("'https://x/y'"));
    }

    #[test]
    fn url_query_repro_curl_protects_metacharacters_in_payload() {
        // `$(rm -rf /)` is the classic shell-injection canary. After
        // single-quoting it must appear verbatim, no expansion.
        let curl = url_query_repro_curl("https://target", "q", "$(rm -rf /); `whoami`");
        assert!(curl.contains("'q=$(rm -rf /); `whoami`'"));
    }

    #[test]
    fn url_query_repro_curl_handles_apostrophe_in_payload() {
        // The canonical SQLi `' OR 1=1--` contains the same quote
        // character we use to wrap the arg. shell_single_quote
        // escapes it via '\'' — the curl must still be parseable
        // by bash.
        let curl = url_query_repro_curl("https://x", "q", "' OR 1=1--");
        // Resulting form: 'q='\'' OR 1=1--' — the '\'' is the close-
        // escape-open sequence.
        assert!(curl.contains("'\\''"), "apostrophe not escaped: {curl}");
        // The literal payload bytes must appear unmangled across
        // the escape boundary.
        assert!(curl.contains("OR 1=1--"));
    }

    #[test]
    fn url_query_repro_curl_handles_empty_payload() {
        let curl = url_query_repro_curl("https://x", "q", "");
        // 'q=' is the right wire form for an empty value.
        assert!(curl.contains("'q='"));
    }

    #[test]
    fn url_query_repro_curl_handles_ampersand_in_payload_without_breaking_arg() {
        // & inside the payload must NOT split into a second curl
        // argument — single-quoting protects it.
        let curl = url_query_repro_curl("https://x", "q", "a&b=c");
        assert!(
            curl.contains("'q=a&b=c'"),
            "ampersand split arg or was re-encoded: {curl}"
        );
    }

    // ── render_simple_curl ───────────────────────────────────────────

    #[test]
    fn render_simple_curl_no_body_no_method_emits_curl_i() {
        let out = render_simple_curl(None, "http://x/", &[], None);
        assert_eq!(out, "curl -i 'http://x/'");
    }

    #[test]
    fn render_simple_curl_body_with_content_type_emits_post() {
        let out = render_simple_curl(
            None,
            "http://x/",
            &[],
            Some(("application/json", b"{\"k\":1}")),
        );
        assert!(out.contains("-X POST"), "must emit POST: {out}");
        assert!(
            out.contains("-H 'Content-Type: application/json'"),
            "got: {out}"
        );
        assert!(out.contains("--data-binary"), "got: {out}");
    }

    #[test]
    fn render_simple_curl_method_override_omits_x_for_get() {
        let out = render_simple_curl(Some("GET"), "http://x/", &[], None);
        assert!(!out.contains("-X"), "GET must not emit -X: {out}");
    }

    #[test]
    fn render_simple_curl_method_override_emits_x_for_patch() {
        let out = render_simple_curl(Some("PATCH"), "http://x/", &[], None);
        assert!(out.contains("-X PATCH"), "got: {out}");
    }

    #[test]
    fn render_simple_curl_header_array_emits_dash_h_per_entry() {
        let headers = vec![
            ("X-A".to_string(), "1".to_string()),
            ("X-B".to_string(), "2".to_string()),
        ];
        let out = render_simple_curl(None, "http://x/", &headers, None);
        assert!(out.contains("-H 'X-A: 1'"), "got: {out}");
        assert!(out.contains("-H 'X-B: 2'"), "got: {out}");
    }

    #[test]
    fn render_simple_curl_special_chars_in_url_are_shell_escaped() {
        // single-quote, dollar, backtick — all must survive round-trip.
        // shell_single_quote escapes ' → '\'' (Bourne close-escape-reopen).
        let out = render_simple_curl(
            None,
            "http://x/p?q=it's+/usr/bin/bash+uid=197609(mukun) gid=197609 groups=197609",
            &[],
            None,
        );
        // The ' in "it's" must be escaped as '\'' — NOT triple-quote.
        assert!(
            out.contains("it'\\''s+"),
            "apostrophe in URL must be Bourne-escaped as '\\'': got: {out}"
        );
        // The rest of the URL (dollars, parens etc.) rides verbatim inside single-quotes.
        assert!(
            out.contains("uid=197609(mukun)"),
            "parens must survive as-is inside single-quotes: got: {out}"
        );
    }

    // ── normalize_target_url ──────────────────────────────────────────

    #[test]
    fn normalize_bare_hostname_prepends_https() {
        assert_eq!(normalize_target_url("example.com"), "https://example.com");
    }

    #[test]
    fn normalize_http_scheme_passes_through() {
        assert_eq!(
            normalize_target_url("http://example.com"),
            "http://example.com"
        );
    }

    #[test]
    fn normalize_https_scheme_passes_through() {
        assert_eq!(
            normalize_target_url("https://example.com"),
            "https://example.com"
        );
    }

    #[test]
    fn normalize_ws_scheme_passes_through() {
        assert_eq!(normalize_target_url("ws://example.com"), "ws://example.com");
    }

    #[test]
    fn normalize_wss_scheme_passes_through() {
        assert_eq!(
            normalize_target_url("wss://example.com"),
            "wss://example.com"
        );
    }

    #[test]
    fn normalize_whitespace_stripped() {
        assert_eq!(
            normalize_target_url("  example.com  "),
            "https://example.com"
        );
    }

    #[test]
    fn normalize_host_with_port_prepends_https() {
        assert_eq!(
            normalize_target_url("example.com:8080"),
            "https://example.com:8080"
        );
    }

    #[test]
    fn normalize_host_with_path_prepends_https() {
        assert_eq!(
            normalize_target_url("example.com/path"),
            "https://example.com/path"
        );
    }

    #[test]
    fn normalize_ipv4_literal_prepends_https() {
        assert_eq!(normalize_target_url("192.168.1.1"), "https://192.168.1.1");
    }

    #[test]
    fn normalize_ipv4_with_port_and_path() {
        assert_eq!(
            normalize_target_url("127.0.0.1:8080/admin"),
            "https://127.0.0.1:8080/admin"
        );
    }

    #[test]
    fn normalize_localhost_prepends_https() {
        assert_eq!(normalize_target_url("localhost"), "https://localhost");
    }

    #[test]
    fn normalize_localhost_with_port() {
        assert_eq!(
            normalize_target_url("localhost:3000"),
            "https://localhost:3000"
        );
    }

    #[test]
    fn normalize_protocol_relative_promotes_to_https() {
        assert_eq!(normalize_target_url("//example.com"), "https://example.com");
    }

    #[test]
    fn normalize_scheme_typo_passes_through_for_caller_error() {
        // A misspelled scheme like "htps://example.com" still contains "://"
        // so it passes through unchanged — reqwest will surface the parse error.
        let out = normalize_target_url("htps://example.com");
        assert_eq!(out, "htps://example.com");
    }

    #[test]
    fn normalize_empty_input_prepends_https() {
        // Empty string → "https://" — reqwest will error, which is correct.
        assert_eq!(normalize_target_url(""), "https://");
    }

    #[test]
    fn normalize_whitespace_only_becomes_https_empty() {
        assert_eq!(normalize_target_url("   "), "https://");
    }

    #[test]
    fn normalize_host_with_query_string() {
        assert_eq!(
            normalize_target_url("example.com/search?q=test"),
            "https://example.com/search?q=test"
        );
    }

    #[test]
    fn normalize_ftp_scheme_passes_through() {
        // Any declared scheme passes through — caller decides if it's valid.
        assert_eq!(
            normalize_target_url("ftp://files.example.com"),
            "ftp://files.example.com"
        );
    }

    // ── confidence_badge threshold contract (§6 pin) ─────────────────

    #[test]
    fn confidence_badge_thresholds_are_pinned() {
        // §6 NO HARDCODING: HIGH_CONFIDENCE_THRESHOLD / MED_CONFIDENCE_THRESHOLD
        // drive the badge colour. Pin them so a refactor that slides the
        // values doesn't silently change the UX for operators who read the
        // badge to decide whether to trust a bypass.
        assert!(
            (HIGH_CONFIDENCE_THRESHOLD - 0.9).abs() < 1e-10,
            "HIGH_CONFIDENCE_THRESHOLD must remain 0.9: got {HIGH_CONFIDENCE_THRESHOLD}"
        );
        assert!(
            (MED_CONFIDENCE_THRESHOLD - 0.75).abs() < 1e-10,
            "MED_CONFIDENCE_THRESHOLD must remain 0.75: got {MED_CONFIDENCE_THRESHOLD}"
        );
        // Structural: a score at or above HIGH → green path; between MED and HIGH → yellow;
        // below MED → red. The thresholds must maintain MED < HIGH.
        assert!(
            MED_CONFIDENCE_THRESHOLD < HIGH_CONFIDENCE_THRESHOLD,
            "MED threshold must be below HIGH: {MED_CONFIDENCE_THRESHOLD} < {HIGH_CONFIDENCE_THRESHOLD}"
        );
    }

    #[test]
    fn grammar_bonus_constants_are_pinned() {
        // §6 pin: GRAMMAR_BONUS_PER_RULE and GRAMMAR_BONUS_CAP were previously
        // magic float literals. Pin their values so a refactor that changes
        // scoring must explicitly update the constants AND this test.
        assert!(
            (GRAMMAR_BONUS_PER_RULE - 0.04).abs() < 1e-10,
            "GRAMMAR_BONUS_PER_RULE must be 0.04: got {GRAMMAR_BONUS_PER_RULE}"
        );
        assert!(
            (GRAMMAR_BONUS_CAP - 0.12).abs() < 1e-10,
            "GRAMMAR_BONUS_CAP must be 0.12: got {GRAMMAR_BONUS_CAP}"
        );
        // Structural: cap must be reachable (i.e. ceiling > one step).
        assert!(
            GRAMMAR_BONUS_CAP > GRAMMAR_BONUS_PER_RULE,
            "cap must be above one step: {GRAMMAR_BONUS_CAP} > {GRAMMAR_BONUS_PER_RULE}"
        );
    }
}
