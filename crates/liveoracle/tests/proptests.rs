//! Property tests for the calibrated live oracle — thousands of generated cases
//! per property, asserting the *contract* (not the shape) of every classifier.
//!
//! The verdict classifier is differentially checked against an independent
//! reference; calibration is checked for its two load-bearing soundness
//! guarantees (reflection is never a block, ambiguity defers); the retry policy
//! is checked for termination, bounded backoff, and never fabricating a block.

use std::cell::{Cell, RefCell};
use std::time::Duration;

use proptest::prelude::*;
use wafrift_liveoracle::calibration::{Baseline, calibrate};
use wafrift_liveoracle::verdict::{
    BLOCK_SCAN_BYTES, LiveVerdict, MAX_TRANSIENT_RETRIES, ProbeResponse, classify_live_response,
    classify_with_retry, default_block_signatures, load_block_signatures,
};
use wafrift_wafmodel::Outcome;

/// Independent reference implementation of the verdict contract. If the shipped
/// classifier and this ever disagree, one of them changed behaviour.
fn reference(status: u16, body: &[u8], sigs: &[String]) -> LiveVerdict {
    if matches!(status, 429 | 502 | 503 | 504) {
        return LiveVerdict::Transient;
    }
    if (200..300).contains(&status) {
        let scan = &body[..body.len().min(BLOCK_SCAN_BYTES)];
        let hay = String::from_utf8_lossy(scan).to_ascii_lowercase();
        if !sigs.is_empty() && sigs.iter().any(|s| hay.contains(s.as_str())) {
            return LiveVerdict::Blocked;
        }
        return LiveVerdict::Allowed;
    }
    LiveVerdict::Blocked
}

/// A lowercase ASCII "word" signature (the shape `load_block_signatures` yields).
fn sig_strategy() -> impl Strategy<Value = String> {
    "[a-z0-9 ]{3,12}"
        .prop_map(|s| s.trim().to_string())
        .prop_filter("non-empty", |s| s.len() >= 3)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    /// The shipped classifier never panics and always matches the reference.
    #[test]
    fn prop_classify_matches_reference(
        status in 100u16..600,
        body in proptest::collection::vec(any::<u8>(), 0..512),
        sigs in proptest::collection::vec(sig_strategy(), 0..6),
    ) {
        prop_assert_eq!(
            classify_live_response(status, &body, &sigs),
            reference(status, &body, &sigs),
        );
    }

    /// 429/502/503/504 are ALWAYS transient — never a false block — whatever the
    /// body or signature set says. This is the rate-limit reliability guarantee.
    #[test]
    fn prop_gateway_statuses_are_always_transient(
        body in proptest::collection::vec(any::<u8>(), 0..256),
        sigs in proptest::collection::vec(sig_strategy(), 0..6),
    ) {
        for status in [429u16, 502, 503, 504] {
            prop_assert_eq!(classify_live_response(status, &body, &sigs), LiveVerdict::Transient);
        }
    }

    /// A signature embedded anywhere within the scan window of a 2xx body forces
    /// Blocked — the 200-block-page guarantee.
    #[test]
    fn prop_signature_in_window_forces_blocked(
        status in 200u16..300,
        sig in sig_strategy(),
        prefix_len in 0usize..256,
        suffix in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        // Keep the signature strictly inside the scan window.
        let prefix_len = prefix_len.min(BLOCK_SCAN_BYTES.saturating_sub(sig.len() + 1));
        let mut body = vec![1u8; prefix_len]; // 0x01 filler never appears in a word sig
        body.extend_from_slice(sig.as_bytes());
        body.extend_from_slice(&suffix);
        prop_assert_eq!(
            classify_live_response(status, &body, std::slice::from_ref(&sig)),
            LiveVerdict::Blocked,
        );
    }

    /// A signature that appears ONLY past the scan window is not seen — the scan
    /// is bounded, so a huge benign 2xx body stays Allowed.
    #[test]
    fn prop_signature_past_window_is_not_seen(
        status in 200u16..300,
        sig in sig_strategy(),
        tail in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let mut body = vec![1u8; BLOCK_SCAN_BYTES]; // window is all 0x01 filler
        body.extend_from_slice(sig.as_bytes());
        body.extend_from_slice(&tail);
        prop_assert_eq!(
            classify_live_response(status, &body, std::slice::from_ref(&sig)),
            LiveVerdict::Allowed,
        );
    }

    /// An empty signature set never blocks a 2xx on body content.
    #[test]
    fn prop_empty_signatures_never_block_2xx(
        status in 200u16..300,
        body in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        prop_assert_eq!(classify_live_response(status, &body, &[]), LiveVerdict::Allowed);
    }

    /// Non-2xx, non-gateway statuses are always Blocked.
    #[test]
    fn prop_other_statuses_are_blocked(
        status in 300u16..600,
        body in proptest::collection::vec(any::<u8>(), 0..128),
        sigs in proptest::collection::vec(sig_strategy(), 0..4),
    ) {
        prop_assume!(!matches!(status, 429 | 502 | 503 | 504));
        prop_assert_eq!(classify_live_response(status, &body, &sigs), LiveVerdict::Blocked);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// `classify_with_retry` over a probe that is transient `k` times then clean
    /// returns Pass, sleeps exactly `k` times, and every backoff is capped.
    #[test]
    fn prop_retry_then_clean_passes_with_bounded_backoff(k in 0usize..MAX_TRANSIENT_RETRIES) {
        let seq = RefCell::new({
            let mut v = vec![429u16; k];
            v.push(200);
            v
        });
        let slept = RefCell::new(Vec::<Duration>::new());
        let sigs = default_block_signatures();
        let out = classify_with_retry(
            || {
                let status = seq.borrow_mut().remove(0);
                Ok(ProbeResponse { status, retry_after_secs: None, body: Vec::new() })
            },
            |r| classify_live_response(r.status, &r.body, &sigs),
            MAX_TRANSIENT_RETRIES,
            |d| slept.borrow_mut().push(d),
        )
        .expect("a clean final probe must resolve to a verdict");
        prop_assert_eq!(out, Outcome::Pass);
        prop_assert_eq!(slept.borrow().len(), k);
        for d in slept.borrow().iter() {
            prop_assert!(*d <= Duration::from_secs(30), "backoff must be capped at 30s");
        }
    }

    /// A permanently transient target is inconclusive (Err), NEVER a fabricated
    /// block, and stops after exactly `max_retries` sleeps.
    #[test]
    fn prop_permanent_transient_is_inconclusive(max_retries in 0usize..6) {
        let slept = Cell::new(0usize);
        let sigs = default_block_signatures();
        let out = classify_with_retry(
            || Ok(ProbeResponse { status: 503, retry_after_secs: None, body: Vec::new() }),
            |r| classify_live_response(r.status, &r.body, &sigs),
            max_retries,
            |_d| slept.set(slept.get() + 1),
        );
        prop_assert!(out.is_err());
        prop_assert_eq!(slept.get(), max_retries);
    }

    /// `Retry-After` is honoured but never exceeds the 30s cap.
    #[test]
    fn prop_retry_after_is_honoured_and_capped(secs in 0u64..100_000) {
        let first = Cell::new(true);
        let slept = RefCell::new(Vec::<Duration>::new());
        let sigs = default_block_signatures();
        let _ = classify_with_retry(
            || {
                if first.replace(false) {
                    Ok(ProbeResponse { status: 503, retry_after_secs: Some(secs), body: Vec::new() })
                } else {
                    Ok(ProbeResponse { status: 200, retry_after_secs: None, body: Vec::new() })
                }
            },
            |r| classify_live_response(r.status, &r.body, &sigs),
            MAX_TRANSIENT_RETRIES,
            |d| slept.borrow_mut().push(d),
        );
        let waited = slept.borrow()[0];
        prop_assert_eq!(waited, Duration::from_secs(secs).min(Duration::from_secs(30)));
    }
}

/// Build a baseline whose body echoes its control (a reflection).
fn reflected(status: u16, control: &str) -> Baseline {
    Baseline {
        status,
        body: format!("you searched for {control} results").into_bytes(),
        control: control.as_bytes().to_vec(),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// A reflecting (non-blocking) target is NEVER calibrated as blocking when
    /// reflection is the only signal — the false-bypass-killer guarantee.
    #[test]
    fn prop_reflection_alone_never_calibrates_a_block(
        ctrl in "[a-z]{4,10}",
        benign_words in "[a-z ]{10,40}",
    ) {
        let benign = Baseline {
            status: 200,
            body: benign_words.into_bytes(),
            control: b"benign_marker".to_vec(),
        };
        // The only malicious control reflects its payload — must be skipped.
        let cal = calibrate(benign, vec![reflected(200, &ctrl)]);
        prop_assert!(cal.is_none(), "reflection alone must not yield a block calibration");
    }

    /// A status-discriminating target calibrates and classifies its two baselines
    /// correctly, regardless of body noise.
    #[test]
    fn prop_status_discriminator_classifies_both_baselines(
        benign_status in 200u16..210,
        block_status in 400u16..500,
        probe_body in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        prop_assume!(benign_status != block_status);
        let benign = Baseline { status: benign_status, body: b"normal landing page".to_vec(), control: b"c".to_vec() };
        let blocked = Baseline { status: block_status, body: b"forbidden".to_vec(), control: b"1' OR '1'='1".to_vec() };
        let cal = calibrate(benign, vec![blocked]).expect("distinct statuses calibrate");
        prop_assert_eq!(cal.classify(block_status, &probe_body), Some(LiveVerdict::Blocked));
        prop_assert_eq!(cal.classify(benign_status, &probe_body), Some(LiveVerdict::Allowed));
    }

    /// `load_block_signatures` round-trips any word list: every entry survives,
    /// lowercased, and the set is non-empty (fails closed otherwise).
    #[test]
    fn prop_signature_loader_roundtrips(words in proptest::collection::vec("[A-Za-z0-9]{3,10}", 1..12)) {
        let toml_src = format!(
            "signature = [{}]",
            words.iter().map(|w| format!("{w:?}")).collect::<Vec<_>>().join(", ")
        );
        let loaded = load_block_signatures(&toml_src).expect("non-empty list loads");
        prop_assert_eq!(loaded.len(), words.len());
        for (w, got) in words.iter().zip(loaded.iter()) {
            prop_assert_eq!(got, &w.to_ascii_lowercase());
        }
    }
}
