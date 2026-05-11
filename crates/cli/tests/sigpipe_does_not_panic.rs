//! Regression test: piping wafrift output to a downstream consumer
//! that closes its stdin (e.g. `head -3`) must NOT crash with
//! `failed printing to stdout: Broken pipe`.
//!
//! Pre-fix: Rust's default behaviour ignores SIGPIPE and panics on
//! the next `println!` after the pipe closes. Pentesters routinely
//! run `wafrift evade ... | head`, `wafrift evade ... | jq '.'`,
//! `wafrift evade ... | grep -m 1 ...` — every one of those would
//! produce a panic on stderr that breaks shell pipelines and
//! tarnishes credibility.
//!
//! Fix: install SIG_DFL for SIGPIPE early in main(), so the process
//! exits silently when the consumer closes the pipe (the canonical
//! Unix CLI idiom — `cat`, `ls`, `grep`, etc. all behave this way).

#![cfg(unix)]

use std::process::{Command, Stdio};

#[test]
fn evade_quiet_piped_to_closed_stdin_exits_clean() {
    let bin = env!("CARGO_BIN_EXE_wafrift");

    // Start the producer with a stdout pipe, then drop it without
    // reading anything — that closes the read-end immediately and
    // any subsequent write from the producer raises EPIPE.
    let mut producer = Command::new(bin)
        .args([
            "--quiet",
            "evade",
            "--payload",
            "' OR 1=1 --",
            "--level",
            "heavy", // emit many lines to maximise the chance of an
                     // EPIPE-after-first-write
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn wafrift");

    // Close the stdout pipe by dropping the handle; EPIPE will
    // propagate to the producer the next time it writes.
    drop(producer.stdout.take());

    let output = producer
        .wait_with_output()
        .expect("collect producer exit + stderr");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("Broken pipe"),
        "producer panicked on EPIPE — SIGPIPE handler not installed?\nSTDERR:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked"),
        "producer panicked on broken pipe:\nSTDERR:\n{stderr}"
    );
    // Exit code: SIG_DFL on SIGPIPE → 128 + 13 = 141 if the producer
    // actually got EPIPE before exiting normally, OR exit 0 if it
    // finished writing before the pipe closed (small payload, fast
    // path). Both are acceptable; a panic-driven 101 is not.
    let code = output.status.code();
    assert!(
        matches!(code, Some(0) | Some(141) | None),
        "unexpected exit code {code:?} — SIGPIPE should yield 0 or 141, got panic-style 101?"
    );
}
