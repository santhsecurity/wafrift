//! Regression: `wafrift trailer-diff --url https://…` must not panic.
//!
//! rustls 0.23 panics ("no process-level CryptoProvider available") when a
//! `ClientConfig` is built before a default crypto provider is installed.
//! `trailer_diff_cmd::exchange_https` builds a `ClientConfig` directly, so
//! EVERY https target crashed the process (exit 101) at the builder call —
//! before any handshake. `main()` now installs the ring provider at
//! startup; this test pins that the https path runs without panicking.
//!
//! The panic site lives *after* the TCP connect (exchange_https takes an
//! already-connected stream), so the test stands up a plain-TCP listener:
//! the client's TCP connect succeeds → `ClientConfig::builder()` runs (the
//! former panic site) → the TLS handshake then fails gracefully against the
//! non-TLS server. Fully deterministic + loopback-only (no network).

use std::io::Read;
use std::net::TcpListener;
use std::process::Command;

#[test]
fn trailer_diff_https_does_not_panic_on_crypto_provider() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let port = listener.local_addr().unwrap().port();

    // Accept the client's TCP connection so the https code path advances
    // into exchange_https and runs ClientConfig::builder(). We only need
    // the connect to succeed; the TLS handshake will fail (we speak no
    // TLS) and trailer-diff must report that as a graceful error.
    let handle = std::thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let mut buf = [0u8; 64];
            let _ = sock.read(&mut buf);
        }
    });

    let url = format!("https://127.0.0.1:{port}/");
    let out = Command::new(env!("CARGO_BIN_EXE_wafrift"))
        .args(["trailer-diff", "--url", &url])
        .output()
        .expect("run wafrift trailer-diff");
    let _ = handle.join();

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_ne!(
        out.status.code(),
        Some(101),
        "trailer-diff exited 101 (panic) on an https target — rustls provider regression.\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("CryptoProvider"),
        "the rustls CryptoProvider panic resurfaced:\n{stderr}"
    );
    assert!(
        !stderr.to_ascii_lowercase().contains("panicked"),
        "trailer-diff panicked on an https target:\n{stderr}"
    );
}
