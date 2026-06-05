//! Per-target self-calibration of the live block/pass signal.
//!
//! The static classifier ([`crate::verdict`]) catches *known* block shapes —
//! recognised status codes and listed block-page phrases. But a WAF we have
//! never seen can signal a block in a way no signature lists: a bespoke 200
//! page, an unusual status, a redirect to a captcha host. Calibration **learns
//! this target's block signal** before the session starts:
//!
//! 1. Send a known-benign control and a few known-malicious controls.
//! 2. Observe how the target responds to each.
//! 3. If a malicious control is *distinguishable* from the benign baseline (a
//!    different status, or a substantially different body), derive a
//!    discriminator from that difference.
//!
//! Every later probe is then classified by comparison to the two learned
//! baselines. When calibration cannot find a distinction — no WAF in front, or
//! one that blocks even the benign control — it **declines** ([`calibrate`]
//! returns `None`) and the oracle falls back to the static classifier. It never
//! guesses: an ambiguous probe yields `None` from [`Calibration::classify`] so
//! the caller can defer to the static rule rather than fabricate a verdict.

use std::collections::HashSet;

use crate::verdict::LiveVerdict;

/// Bytes of body considered when comparing responses (block pages and
/// reflections both reveal their shape early; the cap bounds cost).
const COMPARE_BYTES: usize = 16 * 1024;

/// Two bodies with Jaccard token similarity at or below this are "different
/// pages" — the threshold below which a malicious control counts as a distinct
/// (block) response from the benign baseline.
const DISTINCT_MAX_SIMILARITY: f64 = 0.5;

/// Minimum similarity margin required to assign a probe to one baseline over the
/// other; within the margin the probe is ambiguous (defer to the static rule).
const ASSIGN_MARGIN: f64 = 0.15;

/// A harmless control value that no reasonable WAF rule should block — its
/// response is the "allowed" baseline.
#[must_use]
pub fn benign_control() -> &'static str {
    "wafrift_calibration_benign_lookup_7x9q"
}

/// Obvious attacks across classes. The first one the target treats differently
/// from the benign baseline defines the learned block signal — using several
/// guards against a target that polices only one class.
#[must_use]
pub fn malicious_controls() -> &'static [&'static str] {
    &[
        "<script>alert(1)</script>",
        "1' OR '1'='1' -- ",
        "../../../../etc/passwd",
        "; cat /etc/passwd",
    ]
}

/// One observed control response, tagged with the control value that produced
/// it so calibration can tell a *reflection* (the body echoes the input — the
/// payload reached the app) from a *block* (a fixed page that does not).
#[derive(Debug, Clone)]
pub struct Baseline {
    pub status: u16,
    pub body: Vec<u8>,
    pub control: Vec<u8>,
}

/// Does `body` contain `needle` as a contiguous byte substring?
fn body_contains(body: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > body.len() {
        return false;
    }
    body.windows(needle.len()).any(|w| w == needle)
}

/// How the target was found to distinguish a block from an allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Discriminator {
    /// Block and allow carry different status codes.
    Status,
    /// Same status; block and allow differ in body content.
    Body,
}

/// A learned per-target block/allow discriminator.
#[derive(Debug, Clone)]
pub struct Calibration {
    benign: Baseline,
    blocked: Baseline,
    by: Discriminator,
}

/// Build a calibration from the benign baseline and the malicious baselines.
/// Returns `None` when no malicious control is distinguishable from benign —
/// i.e. calibration could not learn a signal and the caller must fall back.
#[must_use]
pub fn calibrate(benign: Baseline, malicious: Vec<Baseline>) -> Option<Calibration> {
    for m in malicious {
        // A reflected control — the body echoes the payload — means the attack
        // REACHED the app (it was not blocked). Reflection makes every body
        // differ just because the input differs, so it must NOT be read as a
        // block signal; skip it and try the next control.
        if body_contains(&m.body, &m.control) {
            continue;
        }
        if benign.status != m.status {
            return Some(Calibration { benign, blocked: m, by: Discriminator::Status });
        }
        if body_similarity(&benign.body, &m.body) <= DISTINCT_MAX_SIMILARITY {
            return Some(Calibration { benign, blocked: m, by: Discriminator::Body });
        }
    }
    None
}

impl Calibration {
    /// Classify a probe response against the learned baselines. `None` means
    /// *ambiguous* — neither baseline clearly fits — so the caller should defer
    /// to the static classifier rather than guess.
    #[must_use]
    pub fn classify(&self, status: u16, body: &[u8]) -> Option<LiveVerdict> {
        match self.by {
            Discriminator::Status => {
                if status == self.blocked.status {
                    Some(LiveVerdict::Blocked)
                } else if status == self.benign.status {
                    Some(LiveVerdict::Allowed)
                } else {
                    None
                }
            }
            Discriminator::Body => {
                let to_benign = body_similarity(body, &self.benign.body);
                let to_blocked = body_similarity(body, &self.blocked.body);
                if to_blocked >= to_benign + ASSIGN_MARGIN {
                    Some(LiveVerdict::Blocked)
                } else if to_benign >= to_blocked + ASSIGN_MARGIN {
                    Some(LiveVerdict::Allowed)
                } else {
                    None
                }
            }
        }
    }

    /// Human description of what was learned (for the operator).
    #[must_use]
    pub fn describe(&self) -> String {
        match self.by {
            Discriminator::Status => format!(
                "learned block signal: HTTP status {} (allow = {})",
                self.blocked.status, self.benign.status
            ),
            Discriminator::Body => format!(
                "learned block signal: a distinct {}-status block page (body differs from the \
                 benign baseline)",
                self.blocked.status
            ),
        }
    }
}

/// Token set of a body: lowercased ASCII-alphanumeric words of length ≥ 3 from
/// the first [`COMPARE_BYTES`]. Short tokens and the echoed probe value
/// contribute little, so this is robust to a reflecting target.
fn tokenize(body: &[u8]) -> HashSet<String> {
    let scan = &body[..body.len().min(COMPARE_BYTES)];
    String::from_utf8_lossy(scan)
        .to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| w.len() >= 3)
        .map(str::to_string)
        .collect()
}

/// Jaccard similarity of two bodies' token sets, in `[0.0, 1.0]`.
fn body_similarity(a: &[u8], b: &[u8]) -> f64 {
    let sa = tokenize(a);
    let sb = tokenize(b);
    if sa.is_empty() && sb.is_empty() {
        return 1.0;
    }
    let inter = sa.intersection(&sb).count() as f64;
    let union = sa.union(&sb).count() as f64;
    if union == 0.0 { 1.0 } else { inter / union }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(status: u16, body: &str) -> Baseline {
        Baseline { status, body: body.as_bytes().to_vec(), control: Vec::new() }
    }

    fn b_ctl(status: u16, body: &str, control: &str) -> Baseline {
        Baseline { status, body: body.as_bytes().to_vec(), control: control.as_bytes().to_vec() }
    }

    #[test]
    fn a_reflected_malicious_control_is_not_mistaken_for_a_block() {
        let benign = b_ctl(200, "you searched for benignval template", "benignval");
        let reflected = b_ctl(200, "<script>alert(1)</script>", "<script>alert(1)</script>");
        assert!(
            calibrate(benign, vec![reflected]).is_none(),
            "a reflecting (non-blocking) target must not be calibrated as blocking"
        );
    }

    #[test]
    fn a_real_block_still_calibrates_even_among_reflected_controls() {
        let benign = b_ctl(200, "search results template footer", "benignval");
        let reflected = b_ctl(200, "<script>alert(1)</script>", "<script>alert(1)</script>");
        let blocked = b_ctl(403, "forbidden", "1' OR '1'='1");
        let cal = calibrate(benign, vec![reflected, blocked]).expect("the 403 control calibrates");
        assert_eq!(cal.classify(403, b""), Some(LiveVerdict::Blocked));
    }

    #[test]
    fn calibrates_on_a_distinct_status() {
        let cal = calibrate(b(200, "welcome home page"), vec![b(403, "forbidden")])
            .expect("a 200-vs-403 target is calibratable");
        assert_eq!(cal.classify(403, b"anything"), Some(LiveVerdict::Blocked));
        assert_eq!(cal.classify(200, b"some normal page"), Some(LiveVerdict::Allowed));
    }

    #[test]
    fn calibrates_on_a_custom_200_block_page_with_no_known_signature() {
        let benign = b(200, "search results for your query item one item two item three");
        let malicious = b(200, "go away robot you are not welcome attack detected nope");
        let cal = calibrate(benign, vec![malicious]).expect("distinct bodies are calibratable");
        assert_eq!(
            cal.classify(200, b"go away robot you are not welcome attack detected nope"),
            Some(LiveVerdict::Blocked)
        );
        assert_eq!(
            cal.classify(200, b"search results for your query item four item five"),
            Some(LiveVerdict::Allowed)
        );
    }

    #[test]
    fn declines_when_target_does_not_distinguish_benign_from_malicious() {
        let page = "the same identical application landing page for every request";
        let cal = calibrate(b(200, page), vec![b(200, page), b(200, page)]);
        assert!(cal.is_none(), "an undiscriminating target must decline calibration");
    }

    #[test]
    fn uses_the_first_distinguishable_malicious_control() {
        let benign = b(200, "normal page body text here for the app");
        let xss_passes = b(200, "normal page body text here for the app");
        let sqli_blocked = b(406, "not acceptable");
        let cal = calibrate(benign, vec![xss_passes, sqli_blocked]).expect("SQLi discriminates");
        assert_eq!(cal.classify(406, b""), Some(LiveVerdict::Blocked));
    }

    #[test]
    fn ambiguous_probe_defers_to_static_rule() {
        let benign = b(200, "alpha bravo charlie delta echo foxtrot");
        let malicious = b(200, "one two three four five six seven eight");
        let cal = calibrate(benign, vec![malicious]).expect("calibratable");
        assert_eq!(cal.classify(200, b"completely unrelated zulu yankee xray words"), None);
    }

    #[test]
    fn body_similarity_is_one_for_identical_and_low_for_disjoint() {
        assert!((body_similarity(b"the quick brown fox", b"the quick brown fox") - 1.0).abs() < 1e-9);
        assert!(body_similarity(b"alpha bravo charlie", b"xxx yyy zzz") < 0.2);
    }

    #[test]
    fn reflection_noise_does_not_flip_an_allowed_probe() {
        let benign = b(200, "you searched for benignvalue here are results template footer nav");
        let malicious = b(200, "blocked request id 9931 contact support reference number");
        let cal = calibrate(benign, vec![malicious]).expect("calibratable");
        assert_eq!(
            cal.classify(200, b"you searched for someotherthing here are results template footer nav"),
            Some(LiveVerdict::Allowed),
        );
    }
}
