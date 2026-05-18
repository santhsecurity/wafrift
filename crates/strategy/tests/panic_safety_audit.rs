//! Deep robustness audit for the evasion pipeline entry points.
//!
//! `strategy_property.rs` already fuzzes `evade()` 10k times — but with
//! `body in "[ -~]{0,256}"`: **printable ASCII only, body only**. That
//! is precisely why a real panic survived it: the obs-fold header
//! evasion did `&value[..value.len()/2]` on the *User-Agent header*,
//! panicking on any multibyte UA (operators set custom UAs via
//! `import-curl -A`, `--stealth-browser`, or crafted requests). ASCII
//! body fuzzing can never reach that code path.
//!
//! This audit drives every public `evade*` variant and the pipeline
//! with hostile **headers and bodies**: multibyte/너비/emoji/control
//! User-Agents, oversized values, invalid-UTF8-lossy payloads. Contract:
//! no entry point panics for any request, ever.

use std::panic::{AssertUnwindSafe, catch_unwind};

use wafrift_strategy::{
    HostState,
    strategy::{evade, evade_smart},
};
use wafrift_types::{EvasionConfig, Request};

fn cfg() -> EvasionConfig {
    EvasionConfig {
        fingerprint_rotation: false,
        ..EvasionConfig::default()
    }
}

/// Hostile header/body building blocks. Each targets a byte-index
/// assumption (`len/2`, `[..n]`, split-on-delimiter) in the pipeline.
fn hostile_strings() -> Vec<String> {
    vec![
        String::new(),
        "x".into(),
        "Mozilla/5.0 café日本語𝕏".into(),       // multibyte UA → obs-fold /2
        "Mozilla/5.0 ".to_string() + &"😀".repeat(64), // every char 4 bytes
        "a\u{0}b\u{1}c\u{7f}".into(),            // control bytes
        "\u{202E}override".into(),               // RTL
        "e\u{0301}".repeat(40),                  // combining marks
        "ª²³¼½".repeat(20),                       // No-category unicode
        "A".repeat(100_000),                      // huge ASCII
        "あ".repeat(20_000),                      // huge multibyte
        String::from_utf8_lossy(&[0xFF, 0xFE, b'U', b'A']).into_owned(),
        "tok=\u{0}; path=/".into(),
        "1\u{00A0}OR\u{00A0}1=1".into(),
    ]
}

fn requests() -> Vec<Request> {
    let mut v = Vec::new();
    for s in hostile_strings() {
        // As body.
        v.push(Request::post("https://target.example/api", s.clone().into_bytes()));
        // As User-Agent (the obs-fold panic site).
        v.push(
            Request::get("https://target.example/p?q=1")
                .header("User-Agent", s.clone())
                .header("Accept", "*/*"),
        );
        // As an arbitrary custom header value + cookie.
        v.push(
            Request::post("https://target.example/login", b"u=admin&p=x".to_vec())
                .header("X-Custom", s.clone())
                .header("Cookie", format!("sid={s}"))
                .header("Content-Type", "application/x-www-form-urlencoded"),
        );
        // In the URL itself.
        v.push(Request::get(format!("https://target.example/{s}")));
    }
    v
}

#[test]
fn evasion_pipeline_survives_hostile_requests() {
    let config = cfg();
    let state = HostState::default();
    let mut failures: Vec<String> = Vec::new();

    for (i, req) in requests().into_iter().enumerate() {
        let label = format!(
            "req#{i} {} {} ({} headers, body {} B)",
            req.method,
            req.url.chars().take(40).collect::<String>(),
            req.headers.len(),
            req.body.as_ref().map_or(0, Vec::len)
        );

        let r = req.clone();
        let (c, s) = (config.clone(), state.clone());
        if catch_unwind(AssertUnwindSafe(|| {
            let _ = evade(&r, &s, &c);
        }))
        .is_err()
        {
            failures.push(format!("evade PANIC: {label}"));
        }

        let r = req.clone();
        let (c, s) = (config.clone(), state.clone());
        if catch_unwind(AssertUnwindSafe(|| {
            let _ = evade_smart(&r, &s, &c);
        }))
        .is_err()
        {
            failures.push(format!("evade_smart PANIC: {label}"));
        }

    }

    assert!(
        failures.is_empty(),
        "evasion pipeline robustness audit found {} panic(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Pinned regression for the obs-fold defect: a User-Agent whose byte
/// midpoint is mid-codepoint must NOT panic the pipeline.
#[test]
fn regression_obsfold_multibyte_user_agent_no_panic() {
    let config = cfg();
    let state = HostState::default();
    for ua in [
        "Mozilla/5.0 (X11) café",                 // 'é' straddles len/2 for some lengths
        "日本語ブラウザ/1.0 とても長いユーザエージェント文字列",
        &format!("UA-{}", "€".repeat(33)),         // 3-byte chars, odd length
        "x😀😀😀😀😀😀😀😀😀😀😀x",
    ] {
        let req = Request::get("https://t.example/")
            .header("User-Agent", ua.to_string());
        // Direct call — must return, not panic.
        let _ = evade(&req, &state, &config);
    }
}

mod fuzz {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        /// Arbitrary-unicode body AND User-Agent together (the gap the
        /// ASCII-only existing property test left open).
        #[test]
        fn unicode_body_and_header_never_panic(
            body in ".{0,512}",
            ua in ".{0,128}",
            cookie in ".{0,128}",
        ) {
            let req = Request::post("https://t.example/x?a=1", body.into_bytes())
                .header("User-Agent", ua)
                .header("Cookie", cookie)
                .header("Content-Type", "text/plain");
            let _ = evade(&req, &HostState::default(), &cfg());
        }
    }
}
