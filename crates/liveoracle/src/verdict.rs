//! Reliability-aware classification of a live WAF response.
//!
//! The naïve "2xx = pass, else = block" mapping silently corrupts results
//! against real WAFs in two ways a pen-tester cannot afford:
//!
//! - **Rate-limit / transient as block.** A `429` / `503` / gateway timeout is
//!   the WAF (or an upstream) saying *"later"*, not *"this payload is blocked"*.
//!   Counting it as a block manufactures false `Policed` / `unbypassable`
//!   verdicts — the differential silently rots the moment the target throttles.
//! - **200 block page as pass.** Cloudflare, Akamai, Imperva, F5 ASM, AWS WAF
//!   and others serve a block / challenge interstitial with HTTP **200**.
//!   Status-only classification reads that as the attack *passing* — a
//!   FABRICATED bypass, the single worst outcome for an operator who will act
//!   on it.
//!
//! This module maps a response to [`LiveVerdict::Allowed`],
//! [`LiveVerdict::Blocked`], or [`LiveVerdict::Transient`] using the status code
//! AND a Tier-B set of block-page body signatures, then drives a **bounded
//! retry** on transient (honouring `Retry-After`) so rate-limiting degrades to
//! "inconclusive", never to a wrong answer. The core is pure and network-free —
//! the live oracle injects the probe and the sleep.

use std::time::Duration;

use wafrift_wafmodel::{Outcome, WafModelError};

/// Embedded Tier-B block-page signatures (the data file is the single source).
const DEFAULT_BLOCK_SIGNATURES_TOML: &str = include_str!("../rules/waf/block_signatures.toml");

/// Maximum bytes of a 2xx body inspected for block-page signatures. Block pages
/// announce themselves early; the cap bounds the per-probe cost.
pub const BLOCK_SCAN_BYTES: usize = 16 * 1024;

/// Default retries on a transient status before giving up as inconclusive.
pub const MAX_TRANSIENT_RETRIES: usize = 3;

/// Hard ceiling on any single backoff sleep (a malicious/broken `Retry-After`
/// must not stall the session for minutes).
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// The reliability-aware verdict for one live response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveVerdict {
    /// The request reached the application and got a normal response.
    Allowed,
    /// The WAF stopped the request — by status code, or a 2xx block page.
    Blocked,
    /// Rate-limit / gateway / overload — a deferral, not a block decision.
    Transient,
}

/// What one live probe observed: status, an optional `Retry-After` hint, and the
/// (bounded) body — only populated for 2xx, where block-page detection applies.
pub struct ProbeResponse {
    pub status: u16,
    pub retry_after_secs: Option<u64>,
    pub body: Vec<u8>,
}

/// Classify one response. `block_signatures` are lowercased substrings.
///
/// Mapping (a strict refinement of the old status-only rule — the only changes
/// are that 429/502/503/504 become `Transient` instead of `Blocked`, and a 2xx
/// body carrying a block signature becomes `Blocked` instead of `Allowed`):
/// - `429 | 502 | 503 | 504` → `Transient`
/// - `2xx` without a block signature → `Allowed`; with one → `Blocked`
/// - everything else (3xx, other 4xx, non-gateway 5xx) → `Blocked`
#[must_use]
pub fn classify_live_response(
    status: u16,
    body: &[u8],
    block_signatures: &[String],
) -> LiveVerdict {
    if matches!(status, 429 | 502 | 503 | 504) {
        return LiveVerdict::Transient;
    }
    if (200..300).contains(&status) {
        if body_matches_block_signature(body, block_signatures) {
            return LiveVerdict::Blocked;
        }
        return LiveVerdict::Allowed;
    }
    LiveVerdict::Blocked
}

/// Does the (bounded, lowercased) body contain any block-page signature?
fn body_matches_block_signature(body: &[u8], block_signatures: &[String]) -> bool {
    if block_signatures.is_empty() {
        return false;
    }
    let scan = &body[..body.len().min(BLOCK_SCAN_BYTES)];
    let hay = String::from_utf8_lossy(scan).to_ascii_lowercase();
    block_signatures.iter().any(|s| hay.contains(s.as_str()))
}

/// Backoff before the `retry_number`-th retry (1-based): honour `Retry-After`
/// when the target gave one, else exponential (1s, 2s, 4s, …), both capped.
#[must_use]
fn backoff_delay(retry_number: usize, retry_after_secs: Option<u64>) -> Duration {
    if let Some(secs) = retry_after_secs {
        return Duration::from_secs(secs).min(MAX_BACKOFF);
    }
    let shift = retry_number.saturating_sub(1).min(5) as u32;
    Duration::from_secs(1u64 << shift).min(MAX_BACKOFF)
}

/// Probe `probe` and classify each response with the injected `classify`,
/// retrying on [`LiveVerdict::Transient`] up to `max_retries` times (sleeping
/// via the injected `sleep`). On exhaustion the result is an `Oracle` error —
/// i.e. **inconclusive**, never a fabricated `Block` — so a rate-limited target
/// degrades safely.
///
/// `classify` is injected so the caller can compose the static
/// signature/status classifier with a learned per-target discriminator
/// ([`super::calibration`]) without this retry policy knowing about either.
/// Pure: probe, classify, and sleep are all injected → unit-testable offline.
pub fn classify_with_retry<P, C, S>(
    mut probe: P,
    mut classify: C,
    max_retries: usize,
    mut sleep: S,
) -> Result<Outcome, WafModelError>
where
    P: FnMut() -> Result<ProbeResponse, WafModelError>,
    C: FnMut(&ProbeResponse) -> LiveVerdict,
    S: FnMut(Duration),
{
    let mut retries = 0usize;
    loop {
        let resp = probe()?;
        match classify(&resp) {
            LiveVerdict::Allowed => return Ok(Outcome::Pass),
            LiveVerdict::Blocked => return Ok(Outcome::Block),
            LiveVerdict::Transient => {
                if retries >= max_retries {
                    return Err(WafModelError::Oracle(format!(
                        "target returned a transient status ({}) after {retries} retries — \
                         rate-limited or overloaded; treated as inconclusive rather than a \
                         false block",
                        resp.status,
                    )));
                }
                retries += 1;
                sleep(backoff_delay(retries, resp.retry_after_secs));
            }
        }
    }
}

/// The embedded default block signatures (lowercased), parsed from the Tier-B
/// data file. Validated by tests.
#[must_use]
pub fn default_block_signatures() -> Vec<String> {
    load_block_signatures(DEFAULT_BLOCK_SIGNATURES_TOML)
        .expect("embedded block-signature data file must be valid (asserted in tests)")
}

/// Parse a Tier-B block-signature file: `signature = [ "...", ... ]`. Lowercases
/// every entry (matching is case-insensitive) and fails closed on an empty set.
pub fn load_block_signatures(src: &str) -> Result<Vec<String>, String> {
    #[derive(serde::Deserialize)]
    struct SigFile {
        #[serde(default)]
        signature: Vec<String>,
    }
    let parsed: SigFile =
        toml::from_str(src).map_err(|e| format!("parsing block-signature TOML: {e}"))?;
    if parsed.signature.is_empty() {
        return Err("block-signature file has no `signature` entries".into());
    }
    Ok(parsed
        .signature
        .into_iter()
        .map(|s| s.to_ascii_lowercase())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sigs() -> Vec<String> {
        vec!["access denied".to_string(), "request blocked".to_string()]
    }

    #[test]
    fn plain_2xx_is_allowed() {
        assert_eq!(
            classify_live_response(200, b"<html>welcome</html>", &sigs()),
            LiveVerdict::Allowed
        );
    }

    #[test]
    fn two_hundred_block_page_is_blocked_not_allowed() {
        let body = b"<html><h1>Access Denied</h1> your request was stopped</html>";
        assert_eq!(
            classify_live_response(200, body, &sigs()),
            LiveVerdict::Blocked
        );
    }

    #[test]
    fn block_signature_match_is_case_insensitive() {
        let body = b"ACCESS DENIED";
        assert_eq!(
            classify_live_response(200, body, &sigs()),
            LiveVerdict::Blocked
        );
    }

    #[test]
    fn forbidden_status_is_blocked() {
        assert_eq!(
            classify_live_response(403, b"", &sigs()),
            LiveVerdict::Blocked
        );
    }

    #[test]
    fn rate_limit_and_gateway_are_transient_not_blocked() {
        for status in [429u16, 502, 503, 504] {
            assert_eq!(
                classify_live_response(status, b"", &sigs()),
                LiveVerdict::Transient,
                "status {status} must be Transient, not a false Block"
            );
        }
    }

    #[test]
    fn server_error_500_stays_blocked_not_transient() {
        assert_eq!(
            classify_live_response(500, b"", &sigs()),
            LiveVerdict::Blocked
        );
    }

    #[test]
    fn empty_signature_set_never_blocks_a_2xx_on_body() {
        assert_eq!(
            classify_live_response(200, b"access denied", &[]),
            LiveVerdict::Allowed
        );
    }

    #[test]
    fn body_scan_is_bounded_but_still_matches_early_signature() {
        let mut body = b"request blocked".to_vec();
        body.extend(std::iter::repeat_n(b'x', BLOCK_SCAN_BYTES * 2));
        assert_eq!(
            classify_live_response(200, &body, &sigs()),
            LiveVerdict::Blocked
        );
    }

    #[test]
    fn retry_succeeds_after_transient_then_clean() {
        let seq = std::cell::RefCell::new(vec![429u16, 429, 200]);
        let slept = std::cell::RefCell::new(Vec::<Duration>::new());
        let s = sigs();
        let out = classify_with_retry(
            || {
                let status = seq.borrow_mut().remove(0);
                Ok(ProbeResponse {
                    status,
                    retry_after_secs: None,
                    body: Vec::new(),
                })
            },
            |r| classify_live_response(r.status, &r.body, &s),
            MAX_TRANSIENT_RETRIES,
            |d| slept.borrow_mut().push(d),
        )
        .unwrap();
        assert_eq!(out, Outcome::Pass);
        assert_eq!(slept.borrow().len(), 2);
        assert_eq!(slept.borrow()[0], Duration::from_secs(1));
        assert_eq!(slept.borrow()[1], Duration::from_secs(2));
    }

    #[test]
    fn persistent_transient_is_inconclusive_not_a_false_block() {
        let s = sigs();
        let out = classify_with_retry(
            || {
                Ok(ProbeResponse {
                    status: 429,
                    retry_after_secs: None,
                    body: Vec::new(),
                })
            },
            |r| classify_live_response(r.status, &r.body, &s),
            2,
            |_d| {},
        );
        assert!(out.is_err());
        assert!(format!("{}", out.unwrap_err()).contains("transient"));
    }

    #[test]
    fn retry_after_header_is_honoured_over_exponential() {
        let first = std::cell::Cell::new(true);
        let slept = std::cell::RefCell::new(Vec::<Duration>::new());
        let s = sigs();
        let _ = classify_with_retry(
            || {
                if first.replace(false) {
                    Ok(ProbeResponse {
                        status: 503,
                        retry_after_secs: Some(7),
                        body: Vec::new(),
                    })
                } else {
                    Ok(ProbeResponse {
                        status: 200,
                        retry_after_secs: None,
                        body: Vec::new(),
                    })
                }
            },
            |r| classify_live_response(r.status, &r.body, &s),
            MAX_TRANSIENT_RETRIES,
            |d| slept.borrow_mut().push(d),
        )
        .unwrap();
        assert_eq!(slept.borrow()[0], Duration::from_secs(7));
    }

    #[test]
    fn retry_after_is_capped() {
        assert_eq!(backoff_delay(1, Some(99_999)), MAX_BACKOFF);
    }

    #[test]
    fn embedded_block_signatures_load_and_are_lowercased() {
        let s = default_block_signatures();
        assert!(s.len() >= 8, "embedded signature set unexpectedly small");
        assert!(s.iter().all(|x| x.chars().all(|c| !c.is_ascii_uppercase())));
        assert!(s.iter().any(|x| x.contains("access denied")));
    }

    #[test]
    fn load_block_signatures_fails_closed_on_empty() {
        assert!(load_block_signatures("# nothing\n").is_err());
    }
}
