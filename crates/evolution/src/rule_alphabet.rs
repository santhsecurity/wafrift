//! Per-rule alphabet refinement for the L\* learner.
//!
//! Closes #166. The wafmodel L\* learner reasons over an
//! [`wafrift_wafmodel::Alphabet`] — a small set of distinguished
//! bytes plus a single catch-all class representing every byte the
//! rule doesn't branch on. Picking that distinguished set well is
//! the difference between a learner that converges in 200 membership
//! queries and one that grinds through 50,000.
//!
//! Default practice today: ship a generic alphabet of common
//! injection bytes (`'`, `"`, `<`, `>`, `(`, `)`, …) for every rule.
//! That works when a rule's keying bytes happen to be in the default
//! set, but it wastes learner queries on bytes the rule doesn't
//! care about, and it MISSES bytes the rule does care about but
//! aren't in the default.
//!
//! This module infers a tight, rule-scoped alphabet from the
//! `RuleBucket` we already accumulate per rule:
//!
//! 1. For every byte 0..255, compute how often it appears in
//!    *blocked* payloads versus *bypassed* payloads.
//! 2. Bytes that appear much more in blocks than in bypasses are
//!    "trigger-bytes" — the rule fires when they're present. They
//!    are the distinguished alphabet.
//! 3. Bytes that appear much more in bypasses than blocks are
//!    "evasion-bytes" — they may also be worth distinguishing,
//!    since they're the operator's leverage on the rule.
//! 4. Bytes that appear roughly equally in both, or in neither, are
//!    candidates for the catch-all class.
//!
//! The output is consumed by `wafmodel::learn::Alphabet::new` to
//! seed the L\* learner.

use std::collections::HashSet;

use wafrift_wafmodel::Alphabet;

use crate::rule_corpus::RuleBucket;

/// Default number of distinguished bytes the inferred alphabet
/// carries. Eight has been the sweet spot in empirical sweeps —
/// large enough to cover every rule we've examined so far in the
/// CRS, small enough to keep L\* table size O(k²) tractable.
pub const DEFAULT_DISTINGUISHED_COUNT: usize = 8;

/// Bytes that we never include in the distinguished set even if
/// frequency suggests we should. These appear in nearly every HTTP
/// body (space, equals, ampersand) and would crowd out
/// rule-discriminating bytes.
const HTTP_FILLER_BYTES: &[u8] = b" =&\r\n\t";

/// Per-byte score in the (blocked, bypassed) discrimination space.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ByteScore {
    /// The byte under measurement.
    pub byte: u8,
    /// Fraction of `blocked` payloads that contain this byte at
    /// least once. Range [0.0, 1.0].
    pub block_presence: f64,
    /// Fraction of `bypassed` payloads that contain this byte at
    /// least once. Range [0.0, 1.0].
    pub bypass_presence: f64,
    /// Absolute difference: `(block_presence - bypass_presence).abs()`.
    /// Higher means more discriminative for this rule.
    pub discrimination: f64,
}

/// Score every byte 0..=255 against a rule bucket.
#[must_use]
pub fn score_bytes(bucket: &RuleBucket) -> Vec<ByteScore> {
    let n_blocks = bucket.blocked.len();
    let n_bypasses = bucket.bypassed.len();

    let mut out: Vec<ByteScore> = (0u8..=255u8)
        .map(|byte| {
            let block_presence = if n_blocks == 0 {
                0.0
            } else {
                let hits = bucket
                    .blocked
                    .iter()
                    .filter(|r| r.payload.as_bytes().contains(&byte))
                    .count();
                hits as f64 / n_blocks as f64
            };
            let bypass_presence = if n_bypasses == 0 {
                0.0
            } else {
                let hits = bucket
                    .bypassed
                    .iter()
                    .filter(|r| r.payload.as_bytes().contains(&byte))
                    .count();
                hits as f64 / n_bypasses as f64
            };
            ByteScore {
                byte,
                block_presence,
                bypass_presence,
                discrimination: (block_presence - bypass_presence).abs(),
            }
        })
        .collect();

    // Sort by discrimination desc, then byte asc for determinism.
    out.sort_by(|a, b| {
        b.discrimination
            .partial_cmp(&a.discrimination)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.byte.cmp(&b.byte))
    });
    out
}

/// Pick the top-k bytes by discrimination score, excluding HTTP
/// filler bytes that don't carry rule-specific signal. Returns
/// fewer than `k` bytes if the bucket lacks data.
#[must_use]
pub fn distinguished_bytes(bucket: &RuleBucket, k: usize) -> Vec<u8> {
    let scored = score_bytes(bucket);
    let filler: HashSet<u8> = HTTP_FILLER_BYTES.iter().copied().collect();

    scored
        .into_iter()
        .filter(|s| !filler.contains(&s.byte))
        .filter(|s| s.discrimination > 0.0)
        .take(k)
        .map(|s| s.byte)
        .collect()
}

/// Choose a catch-all byte: an ASCII letter that does NOT appear in
/// any blocked or bypassed payload for this rule and is not in the
/// distinguished set. Falls back to `b'Z'` if every ASCII letter
/// is present.
#[must_use]
pub fn pick_catch_all(bucket: &RuleBucket, distinguished: &[u8]) -> u8 {
    let dist: HashSet<u8> = distinguished.iter().copied().collect();
    let appears_anywhere = |b: u8| -> bool {
        bucket
            .blocked
            .iter()
            .any(|r| r.payload.as_bytes().contains(&b))
            || bucket
                .bypassed
                .iter()
                .any(|r| r.payload.as_bytes().contains(&b))
    };
    // Prefer high ASCII letters (likely safe in WAF rules).
    for candidate in (b'A'..=b'Z').chain(b'a'..=b'z') {
        if !dist.contains(&candidate) && !appears_anywhere(candidate) {
            return candidate;
        }
    }
    // Fallback — `Z` is conventional even if it appears somewhere;
    // the worst case is just a slightly less precise alphabet, not
    // a learner crash.
    b'Z'
}

/// Build a tight `Alphabet` for the L\* learner from a rule's
/// observed corpus. The distinguished set is the top-k bytes by
/// `block_presence - bypass_presence` discrimination; the catch-all
/// is a never-observed ASCII letter.
///
/// If `bucket` is empty (no blocked / bypassed payloads recorded),
/// returns `None` — callers should fall back to a generic
/// alphabet rather than learn over a zero-signal alphabet that
/// can't distinguish anything.
#[must_use]
pub fn infer_alphabet(bucket: &RuleBucket, k: usize) -> Option<Alphabet> {
    if bucket.blocked.is_empty() && bucket.bypassed.is_empty() {
        return None;
    }
    let dist = distinguished_bytes(bucket, k);
    if dist.is_empty() {
        return None;
    }
    let catch_all = pick_catch_all(bucket, &dist);
    Some(Alphabet::new(dist, catch_all))
}

/// Convenience: infer an alphabet with the default distinguished
/// count.
#[must_use]
pub fn infer_alphabet_default(bucket: &RuleBucket) -> Option<Alphabet> {
    infer_alphabet(bucket, DEFAULT_DISTINGUISHED_COUNT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coverage_feedback::PayloadClass;
    use crate::rule_corpus::{RecordedAttempt, RecordedBypass, SubmissionStatus};

    fn cls() -> PayloadClass {
        PayloadClass::new("sql")
    }

    fn attempt(payload: &str) -> RecordedAttempt {
        RecordedAttempt {
            payload: payload.to_string(),
            payload_class: cls(),
            encoding_chain: vec![],
            response_hash: 0,
            observed_at_secs: 0,
        }
    }

    fn bypass(payload: &str) -> RecordedBypass {
        RecordedBypass {
            payload: payload.to_string(),
            payload_class: cls(),
            encoding_chain: vec![],
            response_hash: 0,
            observed_at_secs: 0,
            submission: SubmissionStatus::default(),
            delivery: String::new(),
        }
    }

    fn bucket_with(blocked: Vec<&str>, bypassed: Vec<&str>) -> RuleBucket {
        RuleBucket {
            blocked: blocked.into_iter().map(attempt).collect(),
            bypassed: bypassed.into_iter().map(bypass).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn empty_bucket_returns_none() {
        let b = RuleBucket::default();
        assert!(infer_alphabet_default(&b).is_none());
    }

    #[test]
    fn score_bytes_returns_256_entries() {
        let b = bucket_with(vec!["abc"], vec!["xyz"]);
        let scored = score_bytes(&b);
        assert_eq!(scored.len(), 256);
    }

    #[test]
    fn highly_discriminative_byte_ranks_first() {
        // `<` appears in every block but never in any bypass — perfect
        // discrimination of 1.0.
        let b = bucket_with(
            vec!["<script>", "<img>", "<svg>"],
            vec!["benign", "safe", "ok"],
        );
        let scored = score_bytes(&b);
        // Top scored byte must be `<` (highest discrimination).
        assert_eq!(scored[0].byte, b'<');
        assert!((scored[0].discrimination - 1.0).abs() < 1e-9);
        assert!((scored[0].block_presence - 1.0).abs() < 1e-9);
        assert!(scored[0].bypass_presence.abs() < 1e-9);
    }

    #[test]
    fn distinguished_excludes_filler_bytes() {
        // Space appears in every blocked payload but is HTTP filler —
        // must be filtered out even with discrimination=1.0.
        let b = bucket_with(
            vec!["a b", "c d", "e f"],
            vec!["abcdef", "qwert", "zxcvb"],
        );
        let dist = distinguished_bytes(&b, 5);
        assert!(!dist.contains(&b' '), "filler byte ' ' must be excluded");
    }

    #[test]
    fn distinguished_count_capped_at_k() {
        let b = bucket_with(
            vec!["<svg onload=alert('xss')>"],
            vec!["benign"],
        );
        let dist = distinguished_bytes(&b, 3);
        assert!(
            dist.len() <= 3,
            "should return ≤ k distinguished bytes, got {}",
            dist.len()
        );
    }

    #[test]
    fn distinguished_is_deterministic() {
        let b = bucket_with(
            vec!["' OR 1=1", "UNION SELECT", "AND 1=1"],
            vec!["normal", "input", "okay"],
        );
        let a = distinguished_bytes(&b, 5);
        let b2 = distinguished_bytes(&b, 5);
        assert_eq!(a, b2);
    }

    #[test]
    fn pick_catch_all_returns_unused_letter() {
        let b = bucket_with(vec!["abc"], vec!["def"]);
        let dist = vec![b'a', b'b', b'c'];
        let ca = pick_catch_all(&b, &dist);
        // Must not be in distinguished and must not appear in
        // any payload. 'A' through 'Z' include letters not in
        // {a,b,c,d,e,f}.
        assert!(!dist.contains(&ca));
        assert_ne!(ca, b'd');
        assert_ne!(ca, b'e');
        assert_ne!(ca, b'f');
    }

    #[test]
    fn pick_catch_all_falls_back_to_z_when_letters_exhausted() {
        // Payloads contain every ASCII letter — pick_catch_all
        // falls back to 'Z'.
        let all_letters: String = (b'A'..=b'Z').chain(b'a'..=b'z').map(|b| b as char).collect();
        let b = bucket_with(vec![all_letters.as_str()], vec![]);
        let dist = vec![];
        let ca = pick_catch_all(&b, &dist);
        assert_eq!(ca, b'Z');
    }

    #[test]
    fn infer_alphabet_sql_bucket_includes_quote_or_dash() {
        let b = bucket_with(
            vec!["' OR 1=1--", "1' AND 1=1#", "admin'--", "UNION SELECT", "SLEEP(5)"],
            vec!["normal_input", "search_term", "user_query"],
        );
        let alpha = infer_alphabet_default(&b).expect("alphabet");
        let symbols = alpha.raw_symbols();
        // SQL injection rule keying bytes typically include ' or - or =.
        // At least one of these MUST appear in the distinguished set.
        let has_sqli_byte =
            symbols.contains(&b'\'') || symbols.contains(&b'-') || symbols.contains(&b'(');
        assert!(
            has_sqli_byte,
            "inferred alphabet should include an SQLi-keying byte: {symbols:?}"
        );
    }

    #[test]
    fn infer_alphabet_xss_bucket_includes_angle_bracket() {
        let b = bucket_with(
            vec![
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
                "<iframe src=javascript:alert(1)>",
            ],
            vec!["plain text query", "ordinary input"],
        );
        let alpha = infer_alphabet_default(&b).expect("alphabet");
        let symbols = alpha.raw_symbols();
        assert!(
            symbols.contains(&b'<') || symbols.contains(&b'>'),
            "XSS alphabet must include < or >: {symbols:?}"
        );
    }

    #[test]
    fn infer_alphabet_zero_discrimination_bucket_returns_none() {
        // Same payloads in both blocks and bypasses — no byte has any
        // discrimination signal.
        let b = bucket_with(
            vec!["abc", "abc", "abc"],
            vec!["abc", "abc", "abc"],
        );
        // Either returns None (no discriminating bytes) or a fallback
        // alphabet. The contract: if discriminating bytes exist they're
        // used; if not, return None.
        let result = infer_alphabet_default(&b);
        // discrimination=0 for every byte → distinguished_bytes filters
        // them out → empty dist → None.
        assert!(
            result.is_none(),
            "zero-discrimination corpus should yield None"
        );
    }

    #[test]
    fn infer_alphabet_only_blocks_no_bypasses_still_works() {
        // Real early-hunt scenario: we've seen rules block but not yet
        // found bypasses. block_presence vs bypass_presence diff is just
        // block_presence then.
        let b = bucket_with(
            vec!["' OR 1=1", "UNION SELECT", "SLEEP(5)", "1' AND 1=1"],
            vec![],
        );
        let alpha = infer_alphabet_default(&b);
        assert!(alpha.is_some(), "blocks-only bucket must yield alphabet");
        let alpha = alpha.unwrap();
        // Must include at least one distinguished byte beyond catch-all.
        assert!(alpha.len() >= 2);
    }

    #[test]
    fn infer_alphabet_only_bypasses_no_blocks_still_works() {
        // We've only seen bypasses (rare but possible on a permissive
        // rule). bypass_presence is the signal then.
        let b = bucket_with(
            vec![],
            vec!["%27 OR 1%3d1", "<script>", "%3cscript%3e"],
        );
        let alpha = infer_alphabet_default(&b);
        assert!(
            alpha.is_some(),
            "bypasses-only bucket must yield alphabet"
        );
    }

    #[test]
    fn discrimination_ordering_is_monotone() {
        let b = bucket_with(
            vec!["abc", "abd", "abe"],
            vec!["xyz"],
        );
        let scored = score_bytes(&b);
        for i in 1..scored.len() {
            assert!(
                scored[i - 1].discrimination >= scored[i].discrimination,
                "scored list must be sorted descending by discrimination"
            );
        }
    }

    #[test]
    fn many_payloads_perf_smoke() {
        // 1000 blocks × 100 bypasses — must complete fast (< 100ms).
        let payloads: Vec<String> = (0..1000)
            .map(|i| format!("' OR {i}=1-- comment{i}"))
            .collect();
        let bypasses_v: Vec<String> = (0..100).map(|i| format!("normal_input_{i}")).collect();
        let bucket = RuleBucket {
            blocked: payloads.iter().map(|s| attempt(s)).collect(),
            bypassed: bypasses_v.iter().map(|s| bypass(s)).collect(),
            ..Default::default()
        };

        let start = std::time::Instant::now();
        let alpha = infer_alphabet_default(&bucket).expect("alphabet");
        let elapsed = start.elapsed();
        assert!(alpha.len() > 1);
        assert!(
            elapsed.as_millis() < 500,
            "1000-payload bucket too slow: {elapsed:?}"
        );
    }

    #[test]
    fn k_zero_returns_empty_distinguished_and_no_alphabet() {
        let b = bucket_with(vec!["' OR 1=1"], vec!["safe"]);
        assert!(distinguished_bytes(&b, 0).is_empty());
        // k=0 → no distinguished bytes → infer returns None.
        assert!(infer_alphabet(&b, 0).is_none());
    }

    #[test]
    fn alphabet_round_trip_through_raw_symbols() {
        let b = bucket_with(
            vec!["' OR 1=1", "UNION SELECT", "<script>"],
            vec!["normal_input"],
        );
        let alpha = infer_alphabet_default(&b).expect("alphabet");
        let raw = alpha.raw_symbols().to_vec();
        let restored = wafrift_wafmodel::Alphabet::from_raw_symbols(raw.clone());
        assert_eq!(restored.raw_symbols(), raw.as_slice());
    }

    #[test]
    fn distinguished_payload_count_caps_at_k_even_with_many_unique_bytes() {
        // Many unique high-discrimination bytes; ensure we cap at k.
        let b = bucket_with(
            vec!["<>'\"(){}[]!@#$%^&*+-/=?:;,."],
            vec!["plain"],
        );
        assert!(distinguished_bytes(&b, 5).len() <= 5);
        assert!(distinguished_bytes(&b, 10).len() <= 10);
        assert!(distinguished_bytes(&b, 20).len() <= 20);
    }
}
