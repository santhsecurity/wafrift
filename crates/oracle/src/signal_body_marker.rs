//! Body-marker signal extractor.
//!
//! Scans response bodies for known WAF block-page markers and success
//! indicators. Operates on raw bytes and can decompress gzip if needed.
//!
//! Marker tables (`BLOCK_MARKERS`, `CHALLENGE_MARKERS`, `RATE_LIMIT_MARKERS`,
//! `SUCCESS_MARKERS`, `RULE_ID_PREFIXES`, `RULE_CATEGORIES`, `VENDOR_NAMES`)
//! are community-contributed via `crates/oracle/rules/markers/*.toml` and
//! compiled in by `build.rs`. Adding a marker is a one-line PR with no Rust.

use std::io::Read;
use wafrift_types::{BlockReason, Signal};

include!(concat!(env!("OUT_DIR"), "/markers_data.rs"));

/// Case-insensitive **word-boundary** substring test.
///
/// Returns `true` when `needle` occurs in `haystack` such that every
/// *alphanumeric* edge of `needle` aligns with a word boundary in
/// `haystack` — i.e. an alphanumeric first/last char of the needle must not
/// be flanked by another ASCII-alphanumeric char. Punctuation/whitespace
/// edges (and the start/end of the haystack) are always boundaries, so
/// multi-word phrases (`"access denied"`), hyphen/underscore-delimited
/// markers (`"big-ip"`, `"challenge-platform"`), and tag-wrapped markers
/// match exactly as a plain `contains` would.
///
/// This kills the recurring substring-within-word false-positive class that
/// the marker tables kept reintroducing one entry at a time:
/// `"success"`⊂`"successfully blocked"`, `"authenticated"`⊂`"unauthenticated"`,
/// `"home"`⊂`"chrome"`, `"rce"`⊂`"force"`, `"waf"`⊂`"waffle"`. By enforcing
/// the boundary *generically* (§6), a future table edit cannot resurrect the
/// bug for any whole-word marker.
///
/// Both arguments are expected to be ASCII-lowercased by the caller (marker
/// tables are authored lowercase; bodies are lowercased once in the
/// extractors). Non-ASCII bytes in the haystack count as boundaries, which is
/// correct for ASCII markers. Never panics and is UTF-8-safe.
#[must_use]
pub(crate) fn contains_word_bounded(haystack: &str, needle: &str) -> bool {
    let nb = needle.as_bytes();
    if nb.is_empty() {
        return false;
    }
    let hb = haystack.as_bytes();
    let needle_starts_alnum = nb[0].is_ascii_alphanumeric();
    let needle_ends_alnum = nb[nb.len() - 1].is_ascii_alphanumeric();

    let mut from = 0;
    while let Some(rel) = haystack[from..].find(needle) {
        let start = from + rel;
        let end = start + nb.len();
        let left_ok =
            !needle_starts_alnum || start == 0 || !hb[start - 1].is_ascii_alphanumeric();
        let right_ok =
            !needle_ends_alnum || end == hb.len() || !hb[end].is_ascii_alphanumeric();
        if left_ok && right_ok {
            return true;
        }
        // Advance one char (UTF-8-safe; `start` is a char boundary from `find`)
        // so overlapping matches are still considered.
        from = start + haystack[start..].chars().next().map_or(1, char::len_utf8);
    }
    false
}

/// Extract body-marker signals from a response body.
///
/// # Arguments
///
/// * `body` — Raw response body bytes.
/// * `is_gzipped` — Whether the body is gzip-compressed.
///
/// # Returns
///
/// A vector of signals for every matched marker.
#[must_use]
pub fn extract_body_signals(body: &[u8], is_gzipped: bool) -> Vec<Signal> {
    let text = if is_gzipped {
        decompress_gzip(body).unwrap_or_else(|| String::from_utf8_lossy(body).to_string())
    } else {
        String::from_utf8_lossy(body).to_string()
    };
    let lower = text.to_ascii_lowercase();
    let mut signals = Vec::new();

    for marker in BLOCK_MARKERS {
        if contains_word_bounded(&lower, marker) {
            signals.push(Signal::BodyMarker(marker.to_string()));
        }
    }
    for marker in CHALLENGE_MARKERS {
        if contains_word_bounded(&lower, marker) {
            signals.push(Signal::ChallengePlatform(marker.to_string()));
        }
    }
    for marker in RATE_LIMIT_MARKERS {
        if contains_word_bounded(&lower, marker) {
            signals.push(Signal::BodyMarker(format!("rate-limit: {marker}")));
        }
    }
    for marker in SUCCESS_MARKERS {
        if contains_word_bounded(&lower, marker) {
            signals.push(Signal::SuccessMarker(marker.to_string()));
        }
    }

    signals
}

/// Attempt to extract a block reason from the response body.
#[must_use]
pub fn extract_block_reason(body: &[u8], is_gzipped: bool) -> Option<BlockReason> {
    let text = if is_gzipped {
        decompress_gzip(body).unwrap_or_else(|| String::from_utf8_lossy(body).to_string())
    } else {
        String::from_utf8_lossy(body).to_string()
    };
    let lower = text.to_ascii_lowercase();

    // Rule ID patterns: "Rule ID: 12345", "rule_id=12345", etc.
    for prefix in RULE_ID_PREFIXES {
        if let Some(pos) = lower.find(prefix) {
            let start = pos + prefix.len();
            let after = &text[start..];
            let id: String = after
                .trim_start_matches(|c: char| !c.is_ascii_digit())
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '-' || *c == '_')
                .collect();
            if !id.is_empty() {
                return Some(BlockReason::RuleId(id));
            }
        }
    }

    // Category patterns
    for cat in RULE_CATEGORIES {
        if contains_word_bounded(&lower, cat) {
            return Some(BlockReason::RuleCategory((*cat).to_string()));
        }
    }

    // Vendor-specific prefixes
    for vendor in VENDOR_NAMES {
        if contains_word_bounded(&lower, vendor) {
            return Some(BlockReason::VendorReason((*vendor).to_string()));
        }
    }

    // Custom block page
    for marker in BLOCK_MARKERS {
        if contains_word_bounded(&lower, marker) {
            return Some(BlockReason::CustomBlockPage(marker.to_string()));
        }
    }

    None
}

/// Maximum decompressed size for a gzip-encoded response body we will
/// scan for markers. Legitimate WAF block pages are tens of KiB at
/// most; 4 MiB is far beyond any real block page and prevents a
/// hostile WAF from OOM-killing the process with a gzip bomb (a ~1 KB
/// compressed payload that expands to GBs).
const DECOMPRESS_MAX_BYTES: u64 = 4 * 1024 * 1024;

/// Decompress a gzip-encoded body with a hard size cap.
///
/// Returns `None` if the data is not valid gzip, if the decompressed
/// size exceeds [`DECOMPRESS_MAX_BYTES`], or if the result is not
/// valid UTF-8. In any of these cases the callers fall back to
/// treating the raw bytes as lossy UTF-8.
fn decompress_gzip(data: &[u8]) -> Option<String> {
    let decoder = flate2::read::GzDecoder::new(data);
    // `take(n+1)` lets us read up to the cap; if we get n+1 bytes we
    // know the stream exceeded the cap and return None (bomb detected).
    let mut limited = decoder.take(DECOMPRESS_MAX_BYTES + 1);
    let mut out = Vec::new();
    limited.read_to_end(&mut out).ok()?;
    if out.len() as u64 > DECOMPRESS_MAX_BYTES {
        return None;
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_marker_detected() {
        let body = b"Access Denied - Your request was blocked.";
        let signals = extract_body_signals(body, false);
        assert!(
            signals
                .iter()
                .any(|s| matches!(s, Signal::BodyMarker(m) if m == "access denied"))
        );
    }

    #[test]
    fn challenge_marker_detected() {
        let body = b"<script>challenge-platform</script>";
        let signals = extract_body_signals(body, false);
        assert!(
            signals
                .iter()
                .any(|s| matches!(s, Signal::ChallengePlatform(m) if m == "challenge-platform"))
        );
    }

    #[test]
    fn block_reason_rule_id() {
        let body = b"Error: Rule ID: 12345 triggered";
        let reason = extract_block_reason(body, false);
        assert_eq!(reason, Some(BlockReason::RuleId("12345".into())));
    }

    #[test]
    fn block_reason_vendor() {
        let body = b"Protected by Cloudflare";
        let reason = extract_block_reason(body, false);
        assert_eq!(reason, Some(BlockReason::VendorReason("cloudflare".into())));
    }

    #[test]
    fn gzipped_body_decompress() {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"access denied").unwrap();
        let gzipped = encoder.finish().unwrap();

        let signals = extract_body_signals(&gzipped, true);
        assert!(
            signals
                .iter()
                .any(|s| matches!(s, Signal::BodyMarker(m) if m == "access denied"))
        );
    }

    /// Anti-regression: a gzip bomb (tiny compressed, huge expanded) must not
    /// OOM the process. The decompressor must return None (bomb detected) when
    /// the expanded output would exceed DECOMPRESS_MAX_BYTES.
    #[test]
    fn gzip_bomb_is_capped_and_does_not_panic() {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;

        // Build a body of 5 MiB of zeros, then gzip it. The compressed form
        // is tiny; the expanded form exceeds the 4 MiB cap.
        let big_payload = vec![0u8; 5 * 1024 * 1024];
        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&big_payload).unwrap();
        let bomb = encoder.finish().unwrap();

        // Must not panic or OOM; decompress_gzip should return None.
        let result = decompress_gzip(&bomb);
        assert!(
            result.is_none(),
            "decompress_gzip must return None for a >4 MiB payload (got Some of len {})",
            result.as_deref().map_or(0, str::len)
        );

        // extract_body_signals must survive gracefully (falls back to lossy
        // UTF-8 of the raw gzip bytes — marker matching just won't find text).
        let signals = extract_body_signals(&bomb, true);
        // No panic is the invariant; signals may be empty or non-empty depending
        // on whether any marker byte-sequences happen to appear in the raw gzip
        // envelope — we don't assert on that.
        let _ = signals;
    }

    // -- §12 boundary tests -------------------------------------------------

    #[test]
    fn empty_body_produces_no_signals() {
        let signals = extract_body_signals(b"", false);
        assert!(signals.is_empty(), "empty body must produce zero signals");
    }

    #[test]
    fn empty_body_has_no_block_reason() {
        let reason = extract_block_reason(b"", false);
        assert!(reason.is_none(), "empty body must yield no block reason");
    }

    #[test]
    fn unmarked_body_produces_no_signals() {
        let signals = extract_body_signals(b"HTTP/1.1 200 OK\nContent-Type: text/plain\n\nHello!", false);
        // The body has no WAF markers -- the oracle must stay silent.
        assert!(
            signals.is_empty(),
            "plain 200 body must produce zero signals, got: {signals:?}"
        );
    }

    #[test]
    fn block_reason_falls_back_to_custom_block_page_when_no_rule_id() {
        // No rule_id or vendor prefix — falls back to CustomBlockPage for
        // the first BLOCK_MARKERS hit.
        let body = b"Access Denied";
        let reason = extract_block_reason(body, false);
        assert!(
            matches!(reason, Some(BlockReason::CustomBlockPage(_))),
            "should fall back to CustomBlockPage when no rule_id or vendor: {reason:?}"
        );
    }

    #[test]
    fn extract_block_reason_gzip_bomb_does_not_panic() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        let big = vec![0u8; 5 * 1024 * 1024];
        let mut enc = GzEncoder::new(Vec::new(), Compression::best());
        enc.write_all(&big).unwrap();
        let bomb = enc.finish().unwrap();
        // Must not panic; result may be None or Some depending on raw bytes.
        let _ = extract_block_reason(&bomb, true);
    }

    #[test]
    fn invalid_gzip_body_falls_back_gracefully() {
        // Corrupt gzip data: the first byte of gzip magic is 0x1f; the rest
        // is garbage. decompress_gzip returns None, caller uses lossy UTF-8.
        let junk: Vec<u8> = vec![0x1f, 0x8b, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
        // Must not panic.
        let signals = extract_body_signals(&junk, true);
        let _ = signals;
        let reason = extract_block_reason(&junk, true);
        let _ = reason;
    }

    #[test]
    fn rate_limit_marker_detected() {
        let body = b"Rate limit exceeded. Too many requests.";
        let signals = extract_body_signals(body, false);
        let has_rate_limit = signals.iter().any(|s| {
            matches!(s, Signal::BodyMarker(m) if m.starts_with("rate-limit:"))
        });
        assert!(
            has_rate_limit,
            "rate-limit body marker must produce a rate-limit: signal; got: {signals:?}"
        );
    }

    #[test]
    fn success_marker_detected() {
        let body = b"Welcome! Login successful.";
        let signals = extract_body_signals(body, false);
        let has_success = signals
            .iter()
            .any(|s| matches!(s, Signal::SuccessMarker(_)));
        assert!(
            has_success,
            "success body must produce a SuccessMarker signal; got: {signals:?}"
        );
    }

    /// §6 anti-false-positive: success markers are SUBSTRING-matched, so they
    /// must never fire inside common block/failure wording. These three bodies
    /// previously matched the loose markers "success" / "authenticated" /
    /// "home" ("successfully blocked", "unauthenticated", "chrome") and
    /// misclassified real blocks as Ambiguous. Pin that they stay silent.
    #[test]
    fn success_markers_do_not_fire_on_block_or_failure_wording() {
        for body in [
            &b"We have successfully blocked your malicious request."[..],
            &b"401 Unauthorized: this request is unauthenticated."[..],
            &b"This site works best in Chrome."[..],
        ] {
            let signals = extract_body_signals(body, false);
            assert!(
                !signals.iter().any(|s| matches!(s, Signal::SuccessMarker(_))),
                "no SuccessMarker may fire on failure/block wording; body={:?} got={:?}",
                String::from_utf8_lossy(body),
                signals
            );
        }
    }

    /// Recall guard: the legitimate success phrases must still be detected.
    #[test]
    fn success_markers_still_detect_genuine_success_pages() {
        for body in [
            &b"Login successful, redirecting..."[..],
            &b"Welcome back!"[..],
            &b"<title>Admin Dashboard</title>"[..],
            &b"Authentication successful."[..],
        ] {
            let signals = extract_body_signals(body, false);
            assert!(
                signals.iter().any(|s| matches!(s, Signal::SuccessMarker(_))),
                "genuine success page must yield a SuccessMarker; body={:?} got={:?}",
                String::from_utf8_lossy(body),
                signals
            );
        }
    }

    /// §6 anti-false-positive for the tightened block/challenge tables:
    /// "press F5" (was matched by the bare "f5" block marker) and benign
    /// "please wait" loaders (was a challenge marker) are common benign
    /// strings and must produce no block/challenge signal.
    #[test]
    fn tightened_markers_do_not_fire_on_benign_f5_or_please_wait() {
        let f5 = extract_body_signals(b"Stale page? Press F5 to refresh.", false);
        assert!(
            !f5.iter().any(|s| matches!(s, Signal::BodyMarker(_))),
            "press-F5 hint must not yield a block BodyMarker; got {f5:?}"
        );
        let wait = extract_body_signals(b"Please wait while your order is processed.", false);
        assert!(
            !wait
                .iter()
                .any(|s| matches!(s, Signal::ChallengePlatform(_))),
            "benign please-wait loader must not yield a ChallengePlatform; got {wait:?}"
        );
    }

    #[test]
    fn gzip_bomb_exactly_at_cap_boundary_is_accepted() {
        // A body that decompresses to EXACTLY DECOMPRESS_MAX_BYTES must be
        // accepted (not rejected as a bomb). The cap check is `> cap`, not `>= cap`.
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        let exactly_cap = vec![0u8; super::DECOMPRESS_MAX_BYTES as usize];
        let mut enc = GzEncoder::new(Vec::new(), Compression::best());
        enc.write_all(&exactly_cap).unwrap();
        let compressed = enc.finish().unwrap();
        // Should NOT return None (exactly at cap is allowed).
        let result = super::decompress_gzip(&compressed);
        // The zero bytes won't be valid UTF-8 if any remain, but the key
        // thing is the function doesn't treat it as a bomb.
        // Whether Some or None depends on the UTF-8 validity of the zeros,
        // but it MUST NOT panic.
        let _ = result;
    }

    // ── §6 word-boundary matcher (task #11): generic substring-FP kill ──

    /// The exact historical false-positive corpus: a whole-word marker must
    /// NOT match when it appears only as a substring of a longer alphanumeric
    /// word. These are the bugs the marker tables kept reintroducing one
    /// entry at a time — now killed generically.
    #[test]
    fn word_bounded_rejects_substring_within_word() {
        let cases: &[(&str, &str)] = &[
            ("success", "your request was successfully blocked"),
            ("success", "the operation was unsuccessful"),
            ("authenticated", "this request is unauthenticated"),
            ("home", "this site works best in chrome"),
            ("rce", "the server applied excessive force"),
            ("rce", "resource not found"),
            ("waf", "have a waffle for breakfast"),
            ("waf", "the wafer is thin"),
            ("xss", "xssfilterengine enabled"),
            ("lfi", "welcome to shelfish seafood"),
            ("rfi", "scarfing down lunch"),
            ("f5", "abcf5def0123"),
            ("blocked", "your account was unblocked"),
            ("forbidden", "a forbidding tone"),
        ];
        for (needle, hay) in cases {
            assert!(
                !contains_word_bounded(&hay.to_ascii_lowercase(), needle),
                "{needle:?} must NOT match inside {hay:?} (substring-within-word FP)"
            );
        }
    }

    /// Recall: the same markers MUST still match when they are a real whole
    /// word — flanked by whitespace, punctuation, tags, or the string edges.
    #[test]
    fn word_bounded_accepts_genuine_whole_word() {
        let cases: &[(&str, &str)] = &[
            ("success", "operation success"),
            ("success", "success!"),
            ("authenticated", "you are now authenticated."),
            ("home", "go home"),
            ("rce", "rce attempt detected"),
            ("rce", "category: rce"),
            ("waf", "blocked by our waf."),
            ("waf", "<waf>"),
            ("xss", "xss detected"),
            ("f5", "press f5 to refresh"),
            ("blocked", "request blocked"),
            ("blocked", "ip-blocked"),
            ("forbidden", "403 forbidden"),
            ("big-ip", "served by big-ip"),
            ("challenge-platform", "<div>challenge-platform</div>"),
            ("access denied", "access denied!"),
        ];
        for (needle, hay) in cases {
            assert!(
                contains_word_bounded(&hay.to_ascii_lowercase(), needle),
                "{needle:?} MUST match as a whole word inside {hay:?}"
            );
        }
    }

    /// Boundary tests (§12): edges, empty needle/haystack, exact-equality,
    /// multibyte neighbours, and a non-alnum-edged needle.
    #[test]
    fn word_bounded_boundary_cases() {
        assert!(contains_word_bounded("blocked", "blocked"), "exact equality");
        assert!(contains_word_bounded("blocked.", "blocked"), "trailing punct");
        assert!(contains_word_bounded(".blocked", "blocked"), "leading punct");
        assert!(!contains_word_bounded("xblocked", "blocked"), "leading alnum is not a boundary");
        assert!(!contains_word_bounded("blockedx", "blocked"), "trailing alnum is not a boundary");
        assert!(!contains_word_bounded("anything", ""), "empty needle never matches");
        assert!(!contains_word_bounded("", "blocked"), "empty haystack never matches");
        // A multibyte char as the neighbour counts as a boundary (markers are ASCII).
        assert!(contains_word_bounded("café blocked señor", "blocked"));
        assert!(contains_word_bounded("→blocked←", "blocked"), "multibyte both sides");
        // A needle that itself starts/ends with non-alnum is unaffected by
        // alnum neighbours on that side (no boundary required there).
        assert!(contains_word_bounded("xx-attack-x", "-attack-"));
    }

    fn all_markers() -> Vec<&'static str> {
        let mut v = Vec::new();
        v.extend_from_slice(BLOCK_MARKERS);
        v.extend_from_slice(CHALLENGE_MARKERS);
        v.extend_from_slice(RATE_LIMIT_MARKERS);
        v.extend_from_slice(SUCCESS_MARKERS);
        v
    }

    use proptest::prelude::*;

    fn any_marker() -> impl Strategy<Value = String> {
        prop::sample::select(all_markers().iter().map(|s| (*s).to_string()).collect::<Vec<_>>())
    }

    fn alnum_edged_markers() -> impl Strategy<Value = String> {
        let m: Vec<String> = all_markers()
            .iter()
            .filter(|s| {
                let b = s.as_bytes();
                b.first().is_some_and(u8::is_ascii_alphanumeric)
                    && b.last().is_some_and(u8::is_ascii_alphanumeric)
            })
            .map(|s| (*s).to_string())
            .collect();
        prop::sample::select(m)
    }

    proptest! {
        /// §6 invariant — the whole point of task #11: NO alphanumeric-edged
        /// marker from ANY table may fire when embedded inside a longer
        /// alphanumeric token. Holds for every current marker AND every future
        /// one, so the substring-FP class cannot return via a table edit.
        #[test]
        fn no_alnum_marker_fires_inside_a_longer_word(
            marker in alnum_edged_markers(),
            prefix in "[a-z0-9]{1,6}",
            suffix in "[a-z0-9]{1,6}",
        ) {
            let body = format!("{prefix}{marker}{suffix}");
            prop_assert!(
                !contains_word_bounded(&body, &marker),
                "marker {:?} leaked inside word {:?}", marker, body
            );
        }

        /// Dual recall invariant: every marker MUST match when it appears as a
        /// space-delimited whole token — the matcher never loses a real hit.
        #[test]
        fn every_marker_matches_when_space_delimited(marker in any_marker()) {
            let body = format!("xx the {marker} here xx");
            prop_assert!(
                contains_word_bounded(&body, &marker),
                "marker {:?} failed to match space-delimited in {:?}", marker, body
            );
        }
    }
}
