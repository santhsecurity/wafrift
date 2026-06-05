//! Out-of-process execution proof via the `detonate` CLI.
//!
//! Elevates a reflected WAF-bypass to a **proven exploit** — confirming the
//! injected payload's JavaScript actually executes (`alert(1)` fires), not
//! merely that the bytes reflected. The classic gap behind "a payload can pass
//! the WAF and echo back yet never reach an executable context."
//!
//! Runs the `detonate` tool as a subprocess so the heavy jsdet / wasmtime
//! sandbox never links into the wafrift binary (and the two trees' wasmtime
//! versions can't collide). Best-effort by design: when the tool is absent or
//! errors, execution proof is skipped — never fatal.

use std::ffi::OsStr;
use std::io::Write;
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};

/// Parsed `detonate` ExecutionProof. Serialize so it embeds directly in
/// wafrift's scan / harvest JSON output.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct ExecutionProof {
    /// True iff a dialog sink (`alert` / `confirm` / `prompt`) fired.
    pub executed: bool,
    /// Which sink fired, if any.
    #[serde(default)]
    pub sink: Option<String>,
    /// The argument the sink was called with — `"1"` for `alert(1)`.
    #[serde(default)]
    pub message: Option<String>,
}

/// Resolve the detonate binary: `$WAFRIFT_DETONATE_BIN`, else `detonate` on PATH.
fn detonate_bin() -> std::ffi::OsString {
    std::env::var_os("WAFRIFT_DETONATE_BIN").unwrap_or_else(|| "detonate".into())
}

/// The detonation engine wafrift requests of the `detonate` subprocess for this
/// run — `jsdet` (default) or `chrome` (real browser; also catches mutation-XSS
/// and browser-only handlers). Sourced from the global `--detonate-engine` flag.
fn detonate_engine() -> &'static str {
    crate::config::detonate_engine()
}

/// Whether a `detonate` binary is invokable — a cheap `--help` probe. Used to
/// warn ONCE when `--prove-execution` is requested but the tool is missing,
/// rather than silently producing no proofs.
#[must_use]
pub(crate) fn available() -> bool {
    available_with(&detonate_bin())
}

fn available_with(bin: &OsStr) -> bool {
    Command::new(bin)
        .arg("--help")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// Prove whether `body` (an HTML response served from `url`) executes injected
/// JavaScript. Returns `None` when the detonate tool is unavailable or errored
/// — callers degrade gracefully (no proof attached, not a failure).
#[must_use]
pub(crate) fn prove_execution(body: &str, url: &str) -> Option<ExecutionProof> {
    prove_execution_with(&detonate_bin(), body, url)
}

/// Inner form parameterized by the binary path — keeps the public API thin and
/// lets tests exercise the missing-binary degradation without mutating the
/// process environment.
fn prove_execution_with(bin: &OsStr, body: &str, url: &str) -> Option<ExecutionProof> {
    let mut child = Command::new(bin)
        .args(["--url", url, "--engine", detonate_engine()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    // detonate drains all of stdin (read_to_string) before emitting its one
    // JSON line, so writing the (bounded) body then closing stdin can't
    // deadlock against a full stdout pipe.
    child.stdin.take()?.write_all(body.as_bytes()).ok()?;
    let out = child.wait_with_output().ok()?;
    serde_json::from_slice::<ExecutionProof>(&out.stdout).ok()
}

/// Fetch the self-validated execution-PRESERVING XSS vectors from the detonate
/// tool (`detonate vectors --marker <marker>`, one per line). These are forms
/// proven (by detonate's own tests) to bypass-and-EXECUTE, unlike generic
/// evasion that often reflects inert. Empty when the tool is absent — the
/// caller falls back to its built-in templates.
#[must_use]
pub(crate) fn exec_preserving_vectors(marker: &str) -> Vec<String> {
    fetch_vectors(&["vectors", "--marker", marker])
}

/// Fetch the browser-only **mutation-XSS** catalog from the detonate tool
/// (`detonate vectors --mutation --marker <marker>`). These fire only through a
/// real browser's DOM-sink re-serialization, so they are only worth firing when
/// the run is using the chrome engine (`--detonate-engine chrome`). Empty when
/// the tool is absent.
#[must_use]
pub(crate) fn mutation_vectors(marker: &str) -> Vec<String> {
    fetch_vectors(&["vectors", "--mutation", "--marker", marker])
}

/// Fetch the **context-breakout** catalog from the detonate tool
/// (`detonate vectors --breakout --marker <marker>`). These escape the non-body
/// reflection contexts a real app exposes — quoted attribute, JS string literal,
/// `javascript:` URI — including JS-level alert obfuscation that carries no
/// literal `alert(` for a signature WAF. Unlike body/markup breakouts (which CRS
/// reflects inert), these EXECUTE once they bypass into their context. Empty when
/// the tool is absent.
#[must_use]
pub(crate) fn breakout_vectors(marker: &str) -> Vec<String> {
    fetch_vectors(&["vectors", "--breakout", "--marker", marker])
}

/// Run `detonate <args>` and collect its non-empty stdout lines as a vector
/// list. Shared by [`exec_preserving_vectors`], [`mutation_vectors`] and
/// [`breakout_vectors`].
fn fetch_vectors(args: &[&str]) -> Vec<String> {
    let out = Command::new(detonate_bin())
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .lines()
            .map(str::to_string)
            .filter(|l| !l.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_detonate_cli_json() {
        // The detonate CLI emits a `fragments_run` field wafrift ignores; the
        // subset must still parse, with executed/sink/message intact.
        let j = r#"{"executed":true,"sink":"alert","message":"1","fragments_run":1}"#;
        let p: ExecutionProof = serde_json::from_str(j).unwrap();
        assert!(p.executed);
        assert_eq!(p.sink.as_deref(), Some("alert"));
        assert_eq!(p.message.as_deref(), Some("1"));
    }

    #[test]
    fn missing_binary_degrades_to_none() {
        // A definitely-absent binary must yield None / false, never panic —
        // no env mutation needed (the _with form takes the path directly).
        let bogus = OsStr::new("/nonexistent/detonate-xyz-should-not-exist");
        assert!(prove_execution_with(bogus, "<script>alert(1)</script>", "https://x/").is_none());
        assert!(!available_with(bogus));
    }

    // ── Deserialize tolerance ─────────────────────────────────────

    #[test]
    fn deserialize_tolerates_unknown_fragments_run_field() {
        // The CLI may grow new fields (fragments_run, timing, …); wafrift
        // must keep parsing the subset it cares about (no deny_unknown_fields).
        let j =
            r#"{"executed":false,"sink":null,"message":null,"fragments_run":7,"elapsed_ms":12}"#;
        let p: ExecutionProof = serde_json::from_str(j).unwrap();
        assert!(!p.executed);
        assert_eq!(p.sink, None);
        assert_eq!(p.message, None);
    }

    #[test]
    fn deserialize_missing_optional_fields_default_to_none() {
        // sink/message are `#[serde(default)]` — absent ⇒ None, not an error.
        let j = r#"{"executed":true}"#;
        let p: ExecutionProof = serde_json::from_str(j).unwrap();
        assert!(p.executed);
        assert_eq!(p.sink, None, "absent sink must default to None");
        assert_eq!(p.message, None, "absent message must default to None");
    }

    #[test]
    fn deserialize_executed_only_false() {
        // The not-fired verdict: executed:false with no sink/message.
        let j = r#"{"executed":false}"#;
        let p: ExecutionProof = serde_json::from_str(j).unwrap();
        assert_eq!(p, ExecutionProof::default());
        assert!(!p.executed);
    }

    #[test]
    fn deserialize_partial_sink_present_message_absent() {
        // Only one optional field present — the other still defaults None.
        let j = r#"{"executed":true,"sink":"confirm"}"#;
        let p: ExecutionProof = serde_json::from_str(j).unwrap();
        assert!(p.executed);
        assert_eq!(p.sink.as_deref(), Some("confirm"));
        assert_eq!(p.message, None);
    }

    #[test]
    fn deserialize_message_with_special_chars_round_trips() {
        // The dialog argument can carry quotes / unicode / escapes; they must
        // survive JSON decoding intact (it's attacker-controlled by design).
        let j = r#"{"executed":true,"sink":"alert","message":"a\"b\\cé"}"#;
        let p: ExecutionProof = serde_json::from_str(j).unwrap();
        assert_eq!(p.message.as_deref(), Some("a\"b\\c\u{e9}"));
    }

    // ── Malformed / non-conforming JSON → parse error (Err) ───────

    #[test]
    fn deserialize_malformed_json_is_error() {
        // Truncated / syntactically-broken JSON must fail to parse, never
        // panic — the call layer turns the Err into None via `.ok()`.
        assert!(serde_json::from_str::<ExecutionProof>(r#"{"executed":tru"#).is_err());
        assert!(serde_json::from_str::<ExecutionProof>("{not json").is_err());
    }

    #[test]
    fn deserialize_empty_stdout_is_error() {
        // detonate emitting nothing (crash before its JSON line) must be an
        // Err, which `prove_execution_with` maps to None.
        assert!(serde_json::from_slice::<ExecutionProof>(b"").is_err());
    }

    #[test]
    fn deserialize_non_object_json_is_error() {
        // A bare array / string / number is valid JSON but not an
        // ExecutionProof — must be rejected at the type boundary.
        assert!(serde_json::from_str::<ExecutionProof>("[]").is_err());
        assert!(serde_json::from_str::<ExecutionProof>(r#""executed""#).is_err());
        assert!(serde_json::from_str::<ExecutionProof>("42").is_err());
        assert!(serde_json::from_str::<ExecutionProof>("null").is_err());
        assert!(serde_json::from_str::<ExecutionProof>("true").is_err());
    }

    #[test]
    fn deserialize_wrong_field_type_is_error() {
        // `executed` is a bool — a string there must NOT coerce silently.
        assert!(serde_json::from_str::<ExecutionProof>(r#"{"executed":"yes"}"#).is_err());
        // sink is Option<String> — a number is the wrong type.
        assert!(serde_json::from_str::<ExecutionProof>(r#"{"executed":true,"sink":3}"#).is_err());
    }

    #[test]
    fn deserialize_missing_required_executed_is_error() {
        // `executed` has no default — an object lacking it cannot parse.
        assert!(serde_json::from_str::<ExecutionProof>(r#"{"sink":"alert"}"#).is_err());
        assert!(serde_json::from_str::<ExecutionProof>("{}").is_err());
    }

    // ── Subprocess degradation (prove_execution_with / available_with) ──

    #[test]
    fn available_with_nonexistent_binary_is_false_no_panic() {
        let bogus = OsStr::new("definitely-not-a-real-binary-wafrift-xyz");
        assert!(!available_with(bogus));
    }

    #[test]
    fn prove_execution_with_nonexistent_binary_is_none() {
        // Empty body + bogus path: spawn fails, must degrade to None.
        let bogus = OsStr::new("definitely-not-a-real-binary-wafrift-xyz");
        assert!(prove_execution_with(bogus, "", "https://x/").is_none());
        assert!(prove_execution_with(bogus, "<svg onload=alert(1)>", "https://t/").is_none());
    }

    #[test]
    fn prove_execution_with_nonzero_exit_no_stdout_is_none() {
        // `false` exits non-zero and prints nothing; an empty stdout is not
        // valid ExecutionProof JSON ⇒ None. (POSIX `false` is ubiquitous on
        // the Linux test host; skip where absent rather than fail.)
        if available_with(OsStr::new("false")) {
            let r = prove_execution_with(
                OsStr::new("false"),
                "<script>alert(1)</script>",
                "https://x/",
            );
            assert!(
                r.is_none(),
                "empty/non-JSON stdout must yield None, got {r:?}"
            );
        }
    }

    #[test]
    fn prove_execution_with_non_json_stdout_is_none() {
        // A binary that prints plain (non-JSON) text to stdout: parse fails ⇒
        // None. `echo` writes its args then exits 0 — its output is not JSON.
        if available_with(OsStr::new("echo")) {
            let r = prove_execution_with(OsStr::new("echo"), "body", "https://x/");
            assert!(r.is_none(), "non-JSON stdout must yield None, got {r:?}");
        }
    }
}
