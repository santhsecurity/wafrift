//! Regression coverage for the 2026-05-10 oracle audit findings:
//!   CRITICAL #1: cmdi.rs OOM via per-command lowercase allocation
//!   CRITICAL #2: ssrf.rs "0" indicator host matches any digit zero
//!
//! Both tests would have failed pre-fix.

use wafrift_oracle::cmdi::CmdiOracle;
use wafrift_oracle::ssrf::SsrfOracle;
use wafrift_oracle::traits::PayloadOracle;

// ── CRITICAL #1: cmdi OOM ───────────────────────────────────────

#[test]
fn cmdi_does_not_oom_on_large_payload() {
    // Pre-fix: contains_word called text.to_ascii_lowercase() PER
    // command tested. A 4 MB payload × 40 commands = ~160 MB of
    // temporary allocations every call. The fix is byte-level
    // case-insensitive scanning with no allocations.
    let oracle = CmdiOracle;
    let mut huge = String::with_capacity(4 * 1024 * 1024 + 16);
    huge.push_str(";id;");
    huge.extend(std::iter::repeat_n(' ', 4 * 1024 * 1024));
    let start = std::time::Instant::now();
    let _ = oracle.is_semantically_valid(&huge, &huge);
    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs() < 5,
        "cmdi.is_semantically_valid on 4MB payload must complete in <5s; got {elapsed:?}"
    );
}

#[test]
fn cmdi_still_detects_real_injection_after_fix() {
    // Negative twin — the byte-level rewrite must not regress real
    // injection detection.
    let oracle = CmdiOracle;
    assert!(
        oracle.is_semantically_valid(";id;", ";id;"),
        "classic ; id must still be flagged as cmdi signal"
    );
    assert!(
        oracle.is_semantically_valid("`whoami`", "`whoami`"),
        "backtick whoami must still be flagged"
    );
    assert!(
        oracle.is_semantically_valid("$(cat /etc/passwd)", "$(cat /etc/passwd)"),
        "command substitution targeting passwd must still flag"
    );
}

#[test]
fn cmdi_does_not_false_positive_on_benign_text() {
    // Negative coverage: words like "category" (contains "cat")
    // must NOT trigger.
    let oracle = CmdiOracle;
    assert!(
        !oracle.is_semantically_valid("category=books", "category=books"),
        "`cat` inside `category` must not flag as command"
    );
    assert!(
        !oracle.is_semantically_valid("identity=user42", "identity=user42"),
        "`id` inside `identity` must not flag as command"
    );
}

// ── CRITICAL #2: SSRF "0" false positive ─────────────────────────

#[test]
fn ssrf_does_not_false_positive_on_digit_zero_in_path() {
    // Pre-fix: `host = "0"` in indicators.toml was matched via
    // substring, so any URL containing the digit '0' anywhere
    // (e.g. /page?id=100) was falsely flagged as SSRF.
    let oracle = SsrfOracle;
    assert!(
        !oracle.is_semantically_valid("http://public.example.com/page?id=100", "http://public.example.com/page?id=100"),
        "digit '0' inside a public URL must NOT trigger SSRF"
    );
    // Avoid using "/api" / "/v1" / "/admin" etc. in the URL — those
    // are real internal_path indicators and would correctly trigger
    // SSRF independent of the digit-zero issue.
    assert!(
        !oracle.is_semantically_valid(
            "https://store.example.com/orders/2026-05-10",
            "https://store.example.com/orders/2026-05-10",
        ),
        "year/date digits must not trigger SSRF on benign path"
    );
}

#[test]
fn ssrf_still_detects_zero_shorthand_loopback() {
    // Negative twin — the legitimate "0" → "0.0.0.0" shorthand
    // (a real SSRF vector when the resolver allows it) must still
    // be caught when '0' is the actual host token.
    let oracle = SsrfOracle;
    assert!(
        oracle.is_semantically_valid("http://0/admin", "http://0/admin"),
        "http://0/ must still flag as SSRF (the audit's real vector)"
    );
    assert!(
        oracle.is_semantically_valid("http://0:8080/internal", "http://0:8080/internal"),
        "http://0:port/ must still flag as SSRF"
    );
}

#[test]
fn ssrf_still_detects_other_loopback_shorthands() {
    // Defence-in-depth — make sure the fix didn't accidentally
    // disable the other indicator hosts.
    let oracle = SsrfOracle;
    assert!(
        oracle.is_semantically_valid("http://127.0.0.1/admin", "http://127.0.0.1/admin"),
        "127.0.0.1 must still flag as SSRF"
    );
    assert!(
        oracle.is_semantically_valid("http://localhost/internal", "http://localhost/internal"),
        "localhost must still flag as SSRF"
    );
}
