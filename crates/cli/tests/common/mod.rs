//! Shared helpers for e2e tests. Cargo treats `tests/common/mod.rs` as
//! a NON-test helper module (not an integration-test binary), so this
//! file does not contribute to the test count. Each e2e file declares
//! `mod common;` to pull these helpers in.
//!
//! R66 pass-21 §7 DEDUP: pre-fix every e2e test file (19 of them as of
//! 2026-05-26) carried a byte-for-byte copy of `wait_for_server`. A
//! single CI tuning (raising the deadline because Windows loopback got
//! slower under parallel test load) would have had to land in 19 files
//! synchronously. Anchoring the loop here closes the drift.
//!
//! Helpers in this file are `pub`. Unused-import / dead-code warnings
//! per call site are suppressed via `#[allow(dead_code)]` on each
//! function — not every test uses every helper, and integration-test
//! binaries don't share a single linker root.
//!
//! See: <https://doc.rust-lang.org/cargo/reference/cargo-targets.html#integration-tests>

use std::net::SocketAddr;
use std::process::Command;
use std::time::{Duration, Instant};

/// Deadline for the `wait_for_server` poll loop. Pre-fix several
/// individual tests hardcoded `Duration::from_secs(30)` inline — if a
/// future CI change needed to raise this, every site had to agree.
///
/// 30s is the empirical worst-case on Windows under the heaviest
/// parallel test loads observed (1300+ concurrent tests, loopback
/// scheduling under contention). Don't lower without measuring.
pub const SERVER_READY_DEADLINE: Duration = Duration::from_secs(30);

/// Per-attempt connect timeout. Short enough that a misconfigured
/// target fails fast and the deadline takes effect; long enough that a
/// transient OS-level "still binding" hiccup doesn't flap-flap-fail.
pub const SERVER_READY_CONNECT_TIMEOUT: Duration = Duration::from_millis(100);

/// Backoff between failed attempts. Tight enough to make the first
/// successful bind visible within ~10ms of the listener's accept loop
/// starting, loose enough to avoid pegging a core under contention.
pub const SERVER_READY_BACKOFF: Duration = Duration::from_millis(10);

/// Probe `addr` until a TCP `connect` succeeds, or panic after
/// [`SERVER_READY_DEADLINE`]. Used by every e2e test that spawns an
/// in-process mock server on `127.0.0.1:0` and needs to know the
/// listener is accepting before driving the SUT against it.
///
/// Pre-R66 this loop was open-coded in 19 e2e test files. A single
/// tuning (raising the deadline because Windows loopback got slower)
/// would have had to land in 19 places. The honest contract — "poll
/// the listener until ready or panic at the budget" — lives here.
///
/// Panics with a message containing `addr` and the budget so the
/// failure message is self-describing on CI logs.
/// Spawn the `wafrift` binary with `args` and return `(exit_code, stdout, stderr)`.
///
/// This is the canonical definition — §7 DEDUP: 38 e2e test files previously
/// carried byte-for-byte copies. A single change here (binary name, env vars,
/// timeout policy) now propagates everywhere automatically.
#[allow(dead_code)]
pub fn wafrift(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_wafrift"))
        .args(args)
        .output()
        .expect("failed to execute wafrift binary");
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (code, stdout, stderr)
}

#[allow(dead_code)]
pub fn wait_for_server(addr: SocketAddr) {
    let deadline = Instant::now() + SERVER_READY_DEADLINE;
    loop {
        match std::net::TcpStream::connect_timeout(&addr, SERVER_READY_CONNECT_TIMEOUT) {
            Ok(_) => return,
            Err(_) => {
                if Instant::now() >= deadline {
                    panic!(
                        "mock server at {addr} never became ready within {:?}",
                        SERVER_READY_DEADLINE
                    );
                }
                std::thread::sleep(SERVER_READY_BACKOFF);
            }
        }
    }
}
