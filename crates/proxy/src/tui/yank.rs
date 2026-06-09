//! Render a captured request as a `curl` one-liner and ship it to the
//! operator's clipboard (best-effort) plus a `/tmp` file (always).
//!
//! The TUI runs inside the alt-screen so direct copy/paste isn't
//! available — the operator presses `y` on a selected request and
//! gets a portable curl command on disk and (when X11/Wayland is up)
//! on the system clipboard.

use std::path::{Path, PathBuf};

use super::state::RequestRecord;

/// Write `bytes` to `path` ONLY if the path does not already exist.
/// Uses `OpenOptions::create_new(true)` which maps to
/// `O_CREAT | O_EXCL` on POSIX — open fails with `AlreadyExists`
/// if the path exists, INCLUDING when it points at a symlink.
/// This is the defence against the predictable-tmp-path symlink
/// attack: an attacker pre-creating
/// `/tmp/wafrift-yank-0.curl -> /etc/cron.d/evil` would otherwise
/// see the curl content written through the symlink to the
/// attacker-chosen path. With create_new the write fails loudly
/// and the operator sees an error instead.
fn write_new_only(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

/// Outcome of a yank attempt — drives the toast banner.
#[derive(Debug, Clone)]
pub struct YankReport {
    pub path: PathBuf,
    pub clipboard_ok: bool,
    pub clipboard_error: Option<String>,
    pub bytes: usize,
}

/// Outcome of a replay attempt — drives the toast banner. Reports
/// both the on-disk reproducer and (when auto-exec is enabled) the
/// upstream HTTP status / body byte-count.
#[derive(Debug, Clone)]
pub struct ReplayReport {
    pub path: PathBuf,
    pub bytes: usize,
    /// `Some(status)` when `WAFRIFT_REPLAY_AUTOEXEC=1` was set and the
    /// shell-out completed (regardless of the upstream HTTP code).
    /// `None` when auto-exec was disabled — the operator is expected
    /// to run the curl command themselves.
    pub upstream_status: Option<i32>,
    /// First few bytes of the upstream response body, when auto-exec
    /// fired. Capped at 256 bytes.
    pub upstream_body_excerpt: Vec<u8>,
}

/// Headers that tend to be hop-by-hop or auto-managed by curl. We omit
/// them from the rendered command so the operator gets a clean
/// reproducer rather than something curl will refuse to send verbatim.
const HEADER_SKIP: &[&str] = &[
    "host",
    "content-length",
    "connection",
    "transfer-encoding",
    "te",
    "upgrade",
    "proxy-connection",
    "keep-alive",
];

/// Render `rec` as a multi-line `curl` command.
///
/// Scheme is inferred from `tls_profile` (Some → https) with https as
/// the default fallback — production targets are rarely plain HTTP.
/// Body is emitted via `--data-binary` with single-quote escaping;
/// non-UTF-8 bodies are emitted as a `--data-binary @PATH` reference
/// to a sibling `.body` file (path is single-quote-escaped so the
/// resulting shell fragment is safe to execute with `sh`).
#[must_use]
pub fn render_curl(rec: &RequestRecord, body_sidecar: Option<&PathBuf>) -> String {
    let scheme = if rec.tls_profile.is_some() || rec.host.ends_with(":443") {
        "https"
    } else if rec.host.ends_with(":80") {
        "http"
    } else {
        "https"
    };
    let url = format!("{scheme}://{}{}", rec.host, rec.path);

    let mut out = String::new();
    out.push_str("curl");
    if rec.method != "GET" {
        // Method must be single-quote-escaped: a server could craft a
        // response that sets the method in the record to something
        // containing `$(...)` or backticks — if the rendered file is
        // later passed to `sh`/`bash`, unquoted method tokens would be
        // interpreted as shell metacharacters.
        out.push_str(" -X '");
        out.push_str(&shell_escape_single(&rec.method));
        out.push('\'');
    }
    out.push_str(" \\\n  ");
    out.push('\'');
    out.push_str(&shell_escape_single(&url));
    out.push('\'');

    for (k, v) in &rec.req_headers {
        if HEADER_SKIP.iter().any(|s| s.eq_ignore_ascii_case(k)) {
            continue;
        }
        out.push_str(" \\\n  -H '");
        out.push_str(&shell_escape_single(&format!("{k}: {v}")));
        out.push('\'');
    }

    if !rec.req_body_excerpt.is_empty() {
        match (body_sidecar, std::str::from_utf8(&rec.req_body_excerpt)) {
            (_, Ok(text)) => {
                out.push_str(" \\\n  --data-binary '");
                out.push_str(&shell_escape_single(text));
                out.push('\'');
            }
            (Some(path), Err(_)) => {
                // The sidecar path is operator-controlled temp-dir output;
                // quote it so paths with spaces or special characters
                // (uncommon on Linux /tmp but possible) don't break shell
                // evaluation if the file is pasted into a terminal.
                out.push_str(" \\\n  --data-binary '@");
                out.push_str(&shell_escape_single(&path.display().to_string()));
                out.push('\'');
            }
            (None, Err(_)) => {
                out.push_str(" \\\n  # binary body omitted (no sidecar path provided)");
            }
        }
    }
    out.push('\n');
    out
}

/// Single-quote shell escape: replace each `'` with `'\''` so the
/// quoted string remains valid `sh` syntax.
fn shell_escape_single(s: &str) -> String {
    s.replace('\'', r"'\''")
}

/// Materialise the rendered curl onto disk and (best-effort) the
/// system clipboard. `seq` is the rotating filename counter held in
/// `State::yank_seq`.
pub fn yank_to_disk_and_clipboard(rec: &RequestRecord, seq: u64) -> std::io::Result<YankReport> {
    let dir = std::env::temp_dir();
    let curl_path = dir.join(format!("wafrift-yank-{seq}.curl"));
    let body_needs_sidecar =
        !rec.req_body_excerpt.is_empty() && std::str::from_utf8(&rec.req_body_excerpt).is_err();
    let body_path = if body_needs_sidecar {
        Some(dir.join(format!("wafrift-yank-{seq}.body")))
    } else {
        None
    };

    let curl = render_curl(rec, body_path.as_ref());
    // Symlink-attack defence: `std::fs::write` would FOLLOW a pre-
    // created symlink at the predictable path and clobber the
    // symlink's target (e.g. /etc/cron.d/wafrift-cron). O_CREAT |
    // O_EXCL refuses to open if the path already exists as anything
    // — including a symlink — so the attacker's pre-creation makes
    // the yank fail loudly instead of writing to the wrong file.
    write_new_only(&curl_path, curl.as_bytes())?;
    if let Some(p) = &body_path {
        write_new_only(p, &rec.req_body_excerpt)?;
    }

    let (clipboard_ok, clipboard_error) = try_set_clipboard(&curl);

    Ok(YankReport {
        path: curl_path,
        clipboard_ok,
        clipboard_error,
        bytes: curl.len(),
    })
}

/// Build the `curl` argv from a `RequestRecord` without going through a
/// shell. Every argument is pushed as a discrete `OsStr` element so no
/// shell metacharacter in the values (spaces, `$`, backticks, `'`, …)
/// can escape into code execution.
///
/// Used by `replay_to_disk_and_optionally_exec` when auto-exec is on.
fn build_curl_argv(rec: &RequestRecord, body_path: Option<&PathBuf>) -> Vec<std::ffi::OsString> {
    let scheme = if rec.tls_profile.is_some() || rec.host.ends_with(":443") {
        "https"
    } else if rec.host.ends_with(":80") {
        "http"
    } else {
        "https"
    };
    let url = format!("{scheme}://{}{}", rec.host, rec.path);

    let mut argv: Vec<std::ffi::OsString> = Vec::new();

    if rec.method != "GET" {
        argv.push("-X".into());
        argv.push((&rec.method).into());
    }
    argv.push(url.into());

    for (k, v) in &rec.req_headers {
        if HEADER_SKIP.iter().any(|s| s.eq_ignore_ascii_case(k)) {
            continue;
        }
        argv.push("-H".into());
        argv.push(format!("{k}: {v}").into());
    }

    if !rec.req_body_excerpt.is_empty() {
        match (body_path, std::str::from_utf8(&rec.req_body_excerpt)) {
            (_, Ok(text)) => {
                argv.push("--data-binary".into());
                argv.push(text.into());
            }
            (Some(p), Err(_)) => {
                argv.push("--data-binary".into());
                // The `@` prefix tells curl to read from the file.
                // Build `@<path>` as an OsString so paths with
                // non-UTF-8 bytes (possible on Linux) still work.
                let at_path: std::ffi::OsString = {
                    #[cfg(unix)]
                    {
                        use std::os::unix::ffi::{OsStrExt, OsStringExt};
                        let mut v = b"@".to_vec();
                        v.extend_from_slice(p.as_os_str().as_bytes());
                        std::ffi::OsString::from_vec(v)
                    }
                    #[cfg(not(unix))]
                    {
                        // On non-Unix targets paths are always UTF-8
                        // representable in Rust's OsStr, so this is
                        // safe to build via String.
                        format!("@{}", p.display()).into()
                    }
                };
                argv.push(at_path);
            }
            (None, Err(_)) => {}
        }
    }
    argv
}

/// Materialise the rendered curl as a replay reproducer at a temp file
/// and (when `WAFRIFT_REPLAY_AUTOEXEC=1` is set in the operator's
/// environment) execute it by spawning `curl` **directly** so the
/// upstream gets re-hit with the captured request bytes.
///
/// **Security model**: the previous implementation passed the rendered
/// curl file to `bash` as a shell script, creating a shell-injection
/// path: any value in the `RequestRecord` (hostname, header value, body)
/// that escaped the single-quote wrapping would be evaluated as shell
/// code by `bash`. The fix replaces `bash <file>` with
/// `Command::new("curl").args(build_curl_argv(rec))` — each argument is
/// a discrete `OsStr`, so no shell metacharacter interpretation is
/// possible regardless of what the captured request contained.
///
/// The on-disk `.curl` file is still produced (human-readable reproducer
/// for the operator to paste into a terminal); it is NOT passed to any
/// shell.
///
/// Auto-exec is gated by an env var, not a CLI flag, because it
/// performs an outbound network request — operators must opt in
/// explicitly per shell session. Without it, this function is
/// equivalent to a yank with a different filename prefix and no
/// clipboard set.
pub fn replay_to_disk_and_optionally_exec(
    rec: &RequestRecord,
    seq: u64,
) -> std::io::Result<ReplayReport> {
    let autoexec = std::env::var("WAFRIFT_REPLAY_AUTOEXEC")
        .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
    replay_to_disk_with_autoexec(rec, seq, autoexec)
}

/// Core of [`replay_to_disk_and_optionally_exec`] with the auto-exec
/// decision passed explicitly instead of read from the process
/// environment. Keeping the env read at the public boundary lets tests
/// drive both branches deterministically without `std::env::set_var`,
/// which requires `unsafe` and is UB under parallel test threads in
/// edition 2024 (a `getenv`/`setenv` data race). This is the only place
/// the crate would otherwise touch the global environment in a test.
pub(crate) fn replay_to_disk_with_autoexec(
    rec: &RequestRecord,
    seq: u64,
    autoexec: bool,
) -> std::io::Result<ReplayReport> {
    let dir = std::env::temp_dir();
    let curl_path = dir.join(format!("wafrift-replay-{seq}.curl"));
    let body_needs_sidecar =
        !rec.req_body_excerpt.is_empty() && std::str::from_utf8(&rec.req_body_excerpt).is_err();
    let body_path = if body_needs_sidecar {
        Some(dir.join(format!("wafrift-replay-{seq}.body")))
    } else {
        None
    };
    let curl = render_curl(rec, body_path.as_ref());
    // Same symlink-attack defence as yank_to_disk_and_clipboard.
    write_new_only(&curl_path, curl.as_bytes())?;
    if let Some(p) = &body_path {
        write_new_only(p, &rec.req_body_excerpt)?;
    }

    let (upstream_status, upstream_body_excerpt) = if autoexec {
        // Invoke `curl` directly — NOT via a shell — so no shell
        // metacharacter in any RequestRecord field (host, header
        // name/value, body) can execute as code. Each argv element is
        // a discrete OsStr handed straight to execve(2); the OS kernel
        // does not interpret them.
        let argv = build_curl_argv(rec, body_path.as_ref());
        match std::process::Command::new("curl").args(&argv).output() {
            Ok(out) => {
                let mut excerpt = out.stdout;
                excerpt.truncate(256);
                (out.status.code(), excerpt)
            }
            Err(_) => (None, Vec::new()),
        }
    } else {
        (None, Vec::new())
    };

    Ok(ReplayReport {
        path: curl_path,
        bytes: curl.len(),
        upstream_status,
        upstream_body_excerpt,
    })
}

/// Best-effort clipboard set. Compiled out when the `clipboard`
/// feature is off (headless boxes, CI). Returns `(ok, err_msg)`.
#[cfg(feature = "clipboard")]
fn try_set_clipboard(s: &str) -> (bool, Option<String>) {
    match arboard::Clipboard::new() {
        Ok(mut clip) => match clip.set_text(s.to_string()) {
            Ok(()) => (true, None),
            Err(e) => (false, Some(e.to_string())),
        },
        Err(e) => (false, Some(e.to_string())),
    }
}

#[cfg(not(feature = "clipboard"))]
fn try_set_clipboard(_s: &str) -> (bool, Option<String>) {
    (
        false,
        Some("clipboard feature disabled at build time".into()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec_full() -> RequestRecord {
        RequestRecord {
            timestamp: "12:34:56".into(),
            host: "api.target.com".into(),
            method: "POST".into(),
            path: "/admin?id=1".into(),
            status: 200,
            bypassed: true,
            blocked: false,
            techniques: "encoding:UrlEncode".into(),
            tls_profile: Some("chrome131".into()),
            body_padded: false,
            upstream_latency_ms: 45,
            waf_name: Some("Cloudflare".into()),
            req_headers: vec![
                ("Host".into(), "api.target.com".into()), // dropped (skip)
                ("X-Original-URL".into(), "/admin".into()),
                ("User-Agent".into(), "Mozilla'5.0".into()), // tests escape
                ("Content-Length".into(), "10".into()),      // dropped
            ],
            req_body_excerpt: b"q=' OR 1=1--".to_vec(),
            req_headers_pre: vec![],
            req_body_pre_excerpt: vec![],
            resp_headers: vec![],
            resp_body_excerpt: vec![],
            resp_body_total: 0,
            attempts: 1,
        }
    }

    #[test]
    fn curl_uses_https_when_tls_profile_set() {
        let r = rec_full();
        let s = render_curl(&r, None);
        assert!(s.contains("https://api.target.com/admin?id=1"));
        // Method is now single-quoted to prevent shell injection when the
        // rendered command is evaluated: `curl -X 'POST' ...`
        assert!(s.starts_with("curl -X 'POST'"));
    }

    #[test]
    fn curl_skips_host_and_content_length_headers() {
        let s = render_curl(&rec_full(), None);
        assert!(!s.contains("'Host: "));
        assert!(!s.contains("'Content-Length: "));
        assert!(s.contains("'X-Original-URL: /admin'"));
    }

    #[test]
    fn curl_escapes_single_quotes_in_header_value() {
        let s = render_curl(&rec_full(), None);
        // 'Mozilla'5.0' must escape to "Mozilla'\''5.0"
        assert!(s.contains(r"Mozilla'\''5.0"));
    }

    #[test]
    fn curl_emits_data_binary_with_escaping() {
        let s = render_curl(&rec_full(), None);
        // body contains a `'` character — needs escape
        assert!(s.contains(r"--data-binary 'q='\''"));
    }

    #[test]
    fn curl_uses_get_implicit_when_method_is_get() {
        let mut r = rec_full();
        r.method = "GET".into();
        r.req_body_excerpt.clear();
        let s = render_curl(&r, None);
        assert!(s.starts_with("curl \\\n"), "no -X for GET — got {s:?}");
    }

    #[test]
    fn curl_falls_back_to_http_when_host_has_port_80() {
        let mut r = rec_full();
        r.tls_profile = None;
        r.host = "intranet.local:80".into();
        let s = render_curl(&r, None);
        assert!(s.contains("http://intranet.local:80/"));
    }

    #[test]
    fn curl_emits_data_binary_at_path_for_binary_body() {
        let mut r = rec_full();
        r.req_body_excerpt = vec![0xff, 0xfe, 0x00, 0x01];
        let p = PathBuf::from("/tmp/wafrift-yank-7.body");
        let s = render_curl(&r, Some(&p));
        // Path is now single-quoted so shell metacharacters in tmp paths
        // (e.g. spaces) can't break evaluation. The `@` is INSIDE the
        // quotes so curl still interprets it as "read from file".
        assert!(s.contains("--data-binary '@/tmp/wafrift-yank-7.body'"));
    }

    #[test]
    fn replay_writes_curl_file_with_replay_prefix() {
        // autoexec passed explicitly (false) — no env mutation, so this
        // is deterministic under parallel `cargo test` and needs no
        // `unsafe`. Drives the no-exec branch.
        let r = rec_full();
        let report = replay_to_disk_with_autoexec(&r, 9999, false).expect("write");
        assert!(
            report
                .path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("wafrift-replay-"),
            "replay file must use the replay prefix, got {}",
            report.path.display()
        );
        assert!(
            report.upstream_status.is_none(),
            "no upstream call when autoexec is off"
        );
        assert!(report.path.exists(), "replay file must be on disk");
        let body = std::fs::read_to_string(&report.path).expect("read back");
        assert!(
            body.starts_with("curl"),
            "rendered curl recoverable: {body}"
        );
        std::fs::remove_file(&report.path).ok();
    }

    #[test]
    fn replay_autoexec_branch_runs_without_panic_against_loopback() {
        // Exercises the previously-untested autoexec=true branch. The
        // record targets a closed loopback port, so `curl` (if present)
        // fails fast with connection-refused — no real outbound traffic
        // and no dependency on a reachable host. If `curl` is absent the
        // spawn errors and the branch yields `None`. Either way the call
        // must succeed (file written) and never panic.
        let mut r = rec_full();
        r.host = "127.0.0.1:1".into();
        r.tls_profile = None; // plain http to the closed loopback port
        let report = replay_to_disk_with_autoexec(&r, 9998, true).expect("write");
        assert!(
            report.path.exists(),
            "replay file written even on the exec path"
        );
        // status is Some(curl-exit) when curl ran, None when curl was
        // missing — both valid; pin only that the excerpt never exceeds
        // the 256-byte truncation cap.
        assert!(
            report.upstream_body_excerpt.len() <= 256,
            "excerpt respects the 256-byte cap"
        );
        std::fs::remove_file(&report.path).ok();
    }

    #[test]
    fn shell_escape_handles_apostrophes() {
        assert_eq!(shell_escape_single("hello"), "hello");
        assert_eq!(shell_escape_single("it's me"), r"it'\''s me");
        assert_eq!(shell_escape_single("''"), r"'\'''\''");
    }

    // ── Argv injection: method quoting and build_curl_argv ───────────

    #[test]
    fn render_curl_quotes_method_field() {
        // A hostile server could craft a proxy-intercepted request whose
        // method contains shell metacharacters. Pre-fix the method was
        // emitted unquoted: `curl -X $(evil)`.  The fix wraps it in
        // single quotes: `curl -X '$(evil)'`.
        let mut r = rec_full();
        r.method = "POST$(id)".into();
        let s = render_curl(&r, None);
        // Must be single-quoted, not bare.
        assert!(
            s.contains("-X 'POST$(id)'") || s.contains("-X 'POST$(id)'\\'"),
            "method must be quoted in rendered curl, got: {s:?}"
        );
        // The dollar-paren must NOT appear as an unquoted bare token.
        assert!(
            !s.contains("-X POST$(id)"),
            "unquoted method would be shell-injected; got: {s:?}"
        );
    }

    #[test]
    fn build_curl_argv_does_not_include_shell_metacharacters_as_code() {
        // build_curl_argv returns a Vec<OsString> that is passed directly
        // to Command::new("curl").args(). No element should be interpreted
        // as shell code. We verify the argv contains the hostile string
        // verbatim rather than treating `$(id)` as a command substitution.
        let mut r = rec_full();
        r.method = "POST".into();
        r.req_headers = vec![("X-Injected".into(), "$(id)>/tmp/pwned".into())];
        r.req_body_excerpt = b"normal body".to_vec();
        let argv = build_curl_argv(&r, None);
        // The header value must appear verbatim in the argv.
        let header_arg: Vec<_> = argv
            .iter()
            .filter(|a| a.to_string_lossy().contains("$(id)"))
            .collect();
        assert!(
            !header_arg.is_empty(),
            "header with shell metacharacter must be carried verbatim"
        );
        // And critically: the value is a discrete OsString element, NOT
        // concatenated with `-H` or any quoting wrapper (those are shell's
        // job — since we skip the shell, no quoting is needed or applied).
        let h_idx = argv
            .iter()
            .position(|a| a.to_string_lossy() == "-H")
            .expect("-H flag present");
        let h_val = argv[h_idx + 1].to_string_lossy();
        assert!(
            h_val.contains("$(id)"),
            "header value must be a distinct OsString: got {h_val:?}"
        );
    }

    #[test]
    fn build_curl_argv_method_is_separate_element() {
        // The method is a discrete argv element, NOT shell-embedded.
        let mut r = rec_full();
        r.method = "DELETE".into();
        r.req_body_excerpt.clear();
        let argv = build_curl_argv(&r, None);
        let x_idx = argv
            .iter()
            .position(|a| a.to_string_lossy() == "-X")
            .expect("-X flag present for non-GET");
        assert_eq!(
            argv[x_idx + 1].to_string_lossy(),
            "DELETE",
            "method must be next element after -X, not concatenated"
        );
    }

    // ── Round 26: symlink-attack defence on predictable tmp paths ────

    #[test]
    fn write_new_only_refuses_to_overwrite_existing_file() {
        let path = std::env::temp_dir().join(format!(
            "wafrift-yank-r26-exists-{}-{}.curl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::write(&path, b"pre-existing").expect("seed");
        let err =
            super::write_new_only(&path, b"new content").expect_err("must refuse to overwrite");
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        // Original content must be preserved.
        let got = std::fs::read(&path).expect("read back");
        assert_eq!(got, b"pre-existing");
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn write_new_only_refuses_to_follow_symlink() {
        // The actual attack: attacker pre-creates a symlink at the
        // predictable yank path pointing at a sensitive file owned
        // by the operator. Pre-fix std::fs::write would follow the
        // symlink and clobber the target.
        let base = std::env::temp_dir().join(format!(
            "wafrift-r26-symlink-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&base).expect("mkdir");
        let target = base.join("secret.txt");
        std::fs::write(&target, b"OPERATOR-SECRET").expect("seed target");
        let link = base.join("yank.curl");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        let err =
            super::write_new_only(&link, b"ATTACKER-CONTENT").expect_err("must refuse symlink");
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        let got = std::fs::read(&target).expect("target intact");
        assert_eq!(got, b"OPERATOR-SECRET", "symlink target was clobbered");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn write_new_only_succeeds_on_fresh_path() {
        let path = std::env::temp_dir().join(format!(
            "wafrift-yank-r26-fresh-{}-{}.curl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        super::write_new_only(&path, b"hello").expect("must succeed");
        let got = std::fs::read(&path).expect("read");
        assert_eq!(got, b"hello");
        let _ = std::fs::remove_file(&path);
    }
}
