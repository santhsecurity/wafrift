//! Robustness audit: `body_padding::pad` must not panic on a hostile
//! `Content-Type`.
//!
//! The Content-Type is attacker-influenced (request header, or
//! `wafrift import-curl -H 'Content-Type: …'`). `extract_boundary`
//! did `p[..9]` on each `;`-split parameter; any multibyte character
//! straddling byte 9 panicked the whole body-padding evasion. Fixed
//! with boundary-safe `str::get`. These are the pinned regressions +
//! an adversarial fuzz so it can never come back.

use wafrift_evolution::body_padding::pad;

#[test]
fn regression_multibyte_content_type_param_no_panic() {
    let body = b"a=1&b=2";
    // Each of these has a `;`-parameter whose byte 9 lands inside a
    // multibyte codepoint — the exact crash input class.
    for ct in [
        "multipart/form-data; boundÿ=----x",      // 2-byte at the edge
        "multipart/form-data;日本語ary=----x",    // 3-byte chars
        "multipart/form-data; 𝕓𝕠𝕦𝕟𝕕ary=zzz",      // 4-byte chars
        "multipart/form-data; boundar\u{0301}=x", // combining mark
        "x; café=1; boundary=----realone",        // mixed
        "multipart/form-data;\u{00A0}boundary=----nb", // NBSP separator
        "boundary=短",                            // tiny multibyte value
        "ÿ",                                      // single 2-byte param
    ] {
        // Must return, never panic.
        let _ = pad(body, ct, 4096);
    }
    // The legitimate path still works (no regression in functionality).
    let out = pad(body, "multipart/form-data; boundary=----WafriftX", 4096);
    let _ = out; // any PadOutcome variant is acceptable; not panicking is the contract
}

#[test]
fn pad_survives_adversarial_bodies_and_content_types() {
    let bodies: [&[u8]; 5] = [
        b"",
        b"k=v",
        &[0u8, 1, 2, 0xFF, 0xFE],
        "café=値&🦀=1".as_bytes(),
        &[b'A'; 100_000],
    ];
    let cts = [
        "",
        ";;;;;;;;;;",
        "=========",
        "boundary=",
        "multipart/form-data; boundary=\u{0}\u{1}\u{2}",
        "application/json; charset=日本語",
        &"boundary=".repeat(500),
        "\u{202E}multipart; boundary=x",
    ];
    for b in bodies {
        for ct in cts {
            for n in [0usize, 1, 4096, 1 << 20] {
                let _ = pad(b, ct, n);
            }
        }
    }
}
