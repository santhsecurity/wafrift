//! wafrift-types — Core types shared by all WAF Rift crates.
//!
//! This crate contains the foundational types that every other wafrift
//! crate depends on: HTTP request representation, evasion technique
//! identifiers, result types, and configuration. (Each crate carries
//! its own domain error — a shared error was attempted and removed
//! 2026-05-23 because no caller wanted it.)

pub mod bogon;
pub mod calibration;
pub mod canary;
pub mod config;
pub mod discovery;
pub mod pick;
pub mod probe;
pub mod entropy;
pub mod escalation;
pub mod explanation;
pub mod format;
pub mod gene_bank_io;
pub mod hash;
pub mod injection_context;
pub mod loaders;
pub mod oob;
pub mod request;
pub mod result;
pub mod session;
pub mod technique;
pub mod utf7;
pub mod verdict;
pub mod waf_class;

// ──────────────────────────────────────────────
//  Workspace-wide tunables (single source of truth so the proxy,
//  scan-side, and replay paths all agree on baseline timeouts).
// ──────────────────────────────────────────────

/// Default per-request HTTP timeout (seconds). Used by every reqwest
/// client builder in the workspace unless the caller explicitly opts
/// into a different value (e.g. `bench-waf --timeout-secs`).
///
/// Why 30s: the bench corpus includes deliberate ReDoS-style inputs
/// that may legitimately keep a backend busy for tens of seconds, and
/// a too-tight default turns slow-but-real bypasses into spurious
/// "blocked" verdicts. The CLI scan path historically used 10s — that
/// is now considered the override knob, not the floor.
pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;

/// Default redirect chain depth allowed when wafrift acts as an HTTP
/// client. Mirrors curl's default to minimise practitioner surprise.
pub const DEFAULT_MAX_REDIRECTS: usize = 5;

/// Default egress-pool "burn threshold" — the number of challenge /
/// rate-limit verdicts on a single egress identity before that egress
/// rotates into cooldown. Pre-R63 the literal `3` was open-coded at 7
/// production sites (cli config defaults, scan/raw_runner, hunt_cmd,
/// import_curl, model_evade_cmd, and main.rs clap defaults). Anchoring
/// here makes the value tunable in one place and prevents the silent
/// divergence where one site updates and others don't.
pub const DEFAULT_EGRESS_CHALLENGE_THRESHOLD: u32 = 3;

/// Default egress-pool cooldown duration in seconds after `threshold`
/// strikes. Pre-R63 the literal `300` was hardcoded at 6 sites
/// including `wafrift_transport::egress_pool`'s builder's `unwrap_or`
/// fallback — meaning a CLI default and a builder default could
/// silently disagree.
pub const DEFAULT_EGRESS_COOLDOWN_SECS: u64 = 300;

/// Default cap on emitted composed artifacts in
/// `smuggle-cross-product` / `smuggle-chain`. The cartesian
/// product grows polynomially — 64 is the empirical sweet spot
/// between coverage and operator-readable output volume.
pub const DEFAULT_SMUGGLE_COMPOSED_CAP: usize = 64;

/// Default inter-request delay (ms) in sequential fire mode.
/// Rate-limit-friendly default; operators raise/lower per target.
pub const DEFAULT_SMUGGLE_FIRE_DELAY_MS: u64 = 200;

/// Default per-request HTTP timeout (seconds) for smuggle-fire
/// subcommands. 10s matches the scan-path convention.
pub const DEFAULT_SMUGGLE_FIRE_TIMEOUT_SECS: u64 = 10;

/// Default body-length divergence threshold for the fire-mode
/// classifier. 5% delta = `body-diverged` signal. Tuned to avoid
/// noise from server-timestamp headers while catching real
/// per-route page-shape divergence.
pub const DEFAULT_SMUGGLE_BODY_DIVERGENCE_THRESHOLD: f64 = 0.05;

/// Default concurrent in-flight smuggle-fire probes. 1 =
/// sequential (respects `--delay-ms`); >1 = parallel.
pub const DEFAULT_SMUGGLE_FIRE_PARALLEL: usize = 1;

/// Workspace-canonical compiled NFA byte-size limit for `RegexBuilder::size_limit`
/// and `RegexSetBuilder::size_limit`.
///
/// A pattern like `(a?){200}` is 10 bytes — well within any reasonable length
/// cap — but causes O(2^N) NFA expansion during `build()`. Capping the
/// *compiled* NFA size at 4 MiB converts that exponential-compile-time
/// attack into a fast, controlled `Err`, regardless of pattern length.
///
/// Every component that compiles untrusted or operator-supplied regexes must
/// use this constant so the protection level is uniform across the workspace
/// and the value is tunable in one place.
///
/// # Scope
///
/// Used by:
/// - `wafrift-detect` (`waf_detect/rules.rs`, `dns_fingerprint/rules.rs`)
/// - `wafrift-wafmodel` (`oracle.rs`)
///
/// Not used by `wafrift-plugin-api`, which intentionally applies a stricter
/// 1 MiB limit for fully untrusted third-party plugin patterns.
pub const REGEX_NFA_SIZE_LIMIT: usize = 4 * 1024 * 1024; // 4 MiB

/// Workspace-canonical ceiling on the largest HTTP response / decoded body
/// wafrift holds in memory at once. ONE source of truth for the three sites
/// that each previously defined their own `64 * 1024 * 1024` and were kept in
/// sync only by a comment (§7 DEDUPLICATION — "two = a future drift bug"):
/// - `wafrift_transport::response::MAX_RESPONSE_BODY_BYTES` (bounded read)
/// - `wafrift_encoding::compression::DECOMPRESSED_BODY_MAX_BYTES`
///   (decompression-bomb defence — its doc already noted "matches the
///   response-body cap elsewhere")
/// - `wafrift_cli::safe_body::HEADROOM_MAX_RESPONSE_BYTES` (absolute read
///   ceiling above the 8 MiB default)
///
/// 64 MiB is generously above any legitimate WAF-evasion payload (kilobytes
/// of attack vector wrapped in at most megabytes of bulk) while still
/// stopping a decompression bomb / runaway mirror from OOMing the process.
/// Tune here and all three move together.
pub const MAX_RESPONSE_BODY_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

/// Workspace-canonical cap on the in-memory per-host evasion/state map
/// shared by `wafrift-transport`'s `EvasionClient` and the scan-path
/// clients. The cap prevents a long-running session scanning thousands of
/// distinct hostnames from growing the map unboundedly.
///
/// `wafrift-proxy`'s runtime `ProxyState::hosts` map uses the same limit
/// (named `MAX_RESTORED_HOSTS` in `proxy::gene_bank_io` for the restore
/// path). If either is intentionally changed, update both.
pub const HOST_STATES_CAP: usize = 10_000;

/// Workspace-canonical cap on the `prioritized_techniques` and
/// `avoided_techniques` hint lists stored in a `wafrift_strategy::HostState`
/// (a downstream crate, so this is a plain code span, not an intra-doc link).
///
/// Used by `wafrift-strategy` (where the struct is defined) and by
/// `wafrift-transport` (where inbound WAF profile signals are merged into
/// the per-host state). Both must enforce the same limit — if they drift,
/// transport can grow the list past the cap that strategy enforces, undoing
/// the bound.
pub const HOST_TECHNIQUE_HINTS_CAP: usize = 200;

/// Workspace-canonical body-scan window size (bytes) used by every
/// WAF-block classifier that reads the response body.
///
/// Block pages universally front-load their indicator phrases (access-denied
/// banners, CAPTCHA prompts, WAF vendor boilerplate). Reading only the first
/// 4 KiB is sufficient to catch every known indicator while bounding both
/// memory allocation and scan time. The same limit is enforced by:
///
/// - `wafrift-types::calibration::analyze_calibration`
/// - `wafrift-detect`'s `blocking::is_blocked_response` and `response_fingerprint`
/// - `wafrift-transport`'s `response::is_waf_block` and `signal::classify`
/// - `wafrift-evolution`'s `custom_rules` body scan
///
/// If this value is tuned, all six scan paths update automatically.
pub const BLOCK_SCAN_BODY_WINDOW: usize = 4096;

// ──────────────────────────────────────────────
//  Glob matcher — shared by proxy scope filter and CLI report filter
// ──────────────────────────────────────────────

/// Tiny ASCII glob matcher: `*` matches any byte run (including empty),
/// `?` matches exactly one byte, everything else is a case-insensitive
/// literal. The match is anchored at both ends (full-string).
///
/// # Complexity
///
/// O(|pattern| × |subject|) worst-case, O(|pattern| + |subject|) typical.
/// Uses the classic two-pointer algorithm with a saved star-position and
/// star-match backtrack index — NO recursion, NO exponential branch tree.
/// Safe to call on attacker-controlled `subject` values from the proxy
/// hot path.
///
/// # Semantics (preserved exactly from the original recursive impl)
///
/// - `*` matches any byte sequence including empty.
/// - `?` matches exactly one byte; fails on empty subject.
/// - Literal bytes compare case-insensitively (`eq_ignore_ascii_case`).
/// - Match is anchored: `glob_match("a*", "ba")` → `false`.
/// - Empty pattern matches only empty subject.
/// - Multiple adjacent `*` are equivalent to one (the algorithm
///   naturally collapses them in the star-advance loop).
#[must_use]
pub fn glob_match(pattern: &str, subject: &str) -> bool {
    glob_match_bytes(pattern.as_bytes(), subject.as_bytes())
}

/// Byte-slice core of [`glob_match`]. Exported for crates that already
/// hold `&[u8]` and want to avoid the UTF-8 round-trip.
#[must_use]
pub fn glob_match_bytes(p: &[u8], s: &[u8]) -> bool {
    let (mut pi, mut si) = (0usize, 0usize);
    // `star_pi` and `star_si` record the position AFTER the last `*` in
    // the pattern and the subject index where we tried to match from it.
    let (mut star_pi, mut star_si) = (usize::MAX, 0usize);

    while si < s.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi].eq_ignore_ascii_case(&s[si])) {
            // `?` or matching literal — advance both pointers.
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            // Record the star position; try matching zero characters
            // (advance pattern only, leave subject pointer where it is).
            star_pi = pi;
            star_si = si;
            pi += 1;
        } else if star_pi != usize::MAX {
            // Current character didn't match — backtrack: let the saved
            // `*` consume one more character of the subject and retry.
            star_si += 1;
            si = star_si;
            pi = star_pi + 1;
        } else {
            return false;
        }
    }

    // Consume any trailing `*` in the pattern (they match the empty
    // remainder of the subject).
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }

    pi == p.len()
}

// ──────────────────────────────────────────────
//  Public re-exports
// ──────────────────────────────────────────────

pub use bogon::ip_addr_is_bogon;
pub use calibration::CalibrationResult;
pub use config::EvasionConfig;
pub use entropy::{binary_shannon, shannon};
pub use escalation::EscalationLevel;
pub use hash::{FNV_OFFSET_64, FNV_PRIME_64, fnv1a_64, fnv1a_64_extend, fnv1a_64_step};
// `WafRiftError` + `Result` alias removed 2026-05-23 (consolidation
// F09/F23) — no external caller; every other crate defines its own
// domain error. If a shared error is needed later, design it from
// actual call-site needs, not from a stub.
pub use request::{Method, Request};
pub use result::EvasionResult;
pub use technique::Technique;
pub use verdict::{BlockReason, ConnectionBehavior, Signal, Verdict};
pub use waf_class::WafClass;


#[cfg(test)]
mod tests {
    use super::*;

    // ── glob_match semantics ──────────────────────────────────────────────

    #[test]
    fn glob_empty_pattern_matches_only_empty_subject() {
        assert!(glob_match("", ""));
        assert!(!glob_match("", "a"));
        assert!(!glob_match("", "abc"));
    }

    #[test]
    fn glob_star_matches_any_string_including_empty() {
        assert!(glob_match("*", ""));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", "a.b.c.d.e"));
    }

    #[test]
    fn glob_question_matches_exactly_one_byte() {
        assert!(!glob_match("?", ""));
        assert!(glob_match("?", "x"));
        assert!(!glob_match("?", "xy"));
    }

    #[test]
    fn glob_star_mid_pattern() {
        assert!(glob_match("*.example.com", "api.example.com"));
        assert!(glob_match("*.example.com", "deep.api.example.com"));
        assert!(!glob_match("*.example.com", "example.com"));
        assert!(glob_match("/api/*", "/api/v1/users"));
        assert!(!glob_match("/api/*", "/web/v1"));
    }

    #[test]
    fn glob_case_insensitive_literal() {
        assert!(glob_match("Example.com", "example.COM"));
        assert!(glob_match("example.com", "EXAMPLE.COM"));
        assert!(!glob_match("example.com", "example.net"));
        assert!(!glob_match("example.com", "example.comm"));
    }

    #[test]
    fn glob_anchored_both_ends() {
        // Must NOT match a substring
        assert!(!glob_match("example.com", "api.example.com"));
        assert!(!glob_match("example.com", "example.com.evil"));
    }

    #[test]
    fn glob_star_at_end_matches_any_suffix() {
        assert!(glob_match("/api/*", "/api/"));
        assert!(glob_match("/api/*", "/api/v2/users/me"));
    }

    #[test]
    fn glob_star_at_start_matches_any_prefix() {
        assert!(glob_match("*.js", "bundle.js"));
        assert!(glob_match("*.js", "a/b/c.js"));
        assert!(!glob_match("*.js", "bundle.ts"));
    }

    #[test]
    fn glob_double_star_acts_as_single_star() {
        assert!(glob_match("**", "anything"));
        assert!(glob_match("a**b", "ab"));
        assert!(glob_match("a**b", "aXXb"));
    }

    #[test]
    fn glob_no_wildcards_is_exact_case_insensitive_match() {
        assert!(glob_match("example.com", "EXAMPLE.COM"));
        assert!(!glob_match("example.com", "example.net"));
        assert!(!glob_match("example.com", "example.comm"));
    }

    /// ReDoS guard: the iterative O(|p|·|s|) matcher must return
    /// immediately on an adversarial `*a*a*...*a` pattern against a
    /// long non-matching subject with 30 wildcards and a 128-char subject.
    #[test]
    fn glob_worst_case_does_not_hang() {
        let start = std::time::Instant::now();
        // 30 interleaved wildcards — exponential recursive impl would
        // take O(128^30) steps; the iterative impl is O(30 × 128).
        let pattern = "*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a";
        let subject = "b".repeat(128);
        let result = glob_match(pattern, &subject);
        let elapsed = start.elapsed();
        assert!(!result, "expected no match");
        assert!(
            elapsed.as_millis() < 100,
            "glob_match took {elapsed:?} on adversarial input — iterative impl required"
        );
    }

    /// Anti-rig: pin the canonical timeout constant so silent retunes
    /// (e.g. someone changes 30 to 10 thinking it is only used here)
    /// break the build instead of silently degrading bypass recall.
    #[test]
    fn default_request_timeout_secs_is_30() {
        assert_eq!(DEFAULT_REQUEST_TIMEOUT_SECS, 30u64);
    }

    /// Pin egress constants so concurrent agents don't silently drift them.
    #[test]
    fn default_egress_constants_are_stable() {
        assert_eq!(DEFAULT_EGRESS_CHALLENGE_THRESHOLD, 3u32);
        assert_eq!(DEFAULT_EGRESS_COOLDOWN_SECS, 300u64);
    }

    /// Pin smuggle-fire constants. Anti-rig: a silent change to
    /// "be more aggressive" (lower delay, higher parallel) would
    /// surprise rate-limited targets and degrade scan reliability.
    #[test]
    fn default_smuggle_constants_are_stable() {
        assert_eq!(DEFAULT_SMUGGLE_COMPOSED_CAP, 64);
        assert_eq!(DEFAULT_SMUGGLE_FIRE_DELAY_MS, 200);
        assert_eq!(DEFAULT_SMUGGLE_FIRE_TIMEOUT_SECS, 10);
        assert!(
            (DEFAULT_SMUGGLE_BODY_DIVERGENCE_THRESHOLD - 0.05).abs() < f64::EPSILON
        );
        assert_eq!(DEFAULT_SMUGGLE_FIRE_PARALLEL, 1);
    }

    /// Pin the workspace-wide NFA size limit so a silent retune
    /// (e.g., bumping to `usize::MAX` "for performance") removes the
    /// ReDoS guard without a visible test failure.
    #[test]
    fn regex_nfa_size_limit_is_4_mib() {
        assert_eq!(REGEX_NFA_SIZE_LIMIT, 4 * 1024 * 1024);
    }

    /// Pin the host-states cap so silent changes (e.g., bumping to
    /// usize::MAX "to cache more") don't silently remove the DoS bound.
    #[test]
    fn host_states_cap_is_10k() {
        assert_eq!(HOST_STATES_CAP, 10_000);
    }

    /// Pin the technique-hints cap so a drift between transport and strategy
    /// (the two enforcement sites) is caught at compile time via this shared
    /// constant, and any attempted retune is blocked here first.
    #[test]
    fn host_technique_hints_cap_is_200() {
        assert_eq!(HOST_TECHNIQUE_HINTS_CAP, 200);
    }

    /// Pin the block-scan body window. A silent bump (e.g. to 64 KiB "for
    /// better recall") would silently increase per-request memory allocation
    /// on every classifier call and is a DoS vector with large responses.
    #[test]
    fn block_scan_body_window_is_4096() {
        assert_eq!(BLOCK_SCAN_BODY_WINDOW, 4096);
    }

    /// Pin the canonical response-body ceiling at 64 MiB. The three crate-
    /// local aliases (transport `MAX_RESPONSE_BODY_BYTES`, encoding
    /// `DECOMPRESSED_BODY_MAX_BYTES`, cli `HEADROOM_MAX_RESPONSE_BYTES`) all
    /// resolve to this value now; a silent change here moves all three, and
    /// an accidental bump (OOM exposure) or shrink (legit body truncation)
    /// trips this anti-rig pin.
    #[test]
    fn max_response_body_bytes_is_64_mib() {
        assert_eq!(MAX_RESPONSE_BODY_BYTES, 64 * 1024 * 1024);
    }
}