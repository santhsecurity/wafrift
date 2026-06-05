//! Origin-normalization fingerprinting — *measure* which decode/normalize
//! stages a target's origin applies, so the P2 solver TARGETS its preimage to
//! the real pipeline instead of speculatively trying every canonical sink.
//!
//! [`solve`](crate::solve) inverts a *given* sink [`Pipeline`]. The open
//! question on a real target is *which* pipeline the origin is. This module
//! answers it from behaviour: send a marker that carries exactly one reversible
//! transform, observe the value that reaches the sink (the reflection), and
//! admit the stage **only on an exact, unambiguous fold** — the folded ASCII
//! marker appears and the sent (homoglyph/encoded) form does not survive. The
//! returned `Vec<Stage>` plugs straight into
//! [`solve_bypass`](crate::solve::solve_bypass) /
//! [`norm_mismatch_members`](crate::norm_mismatch_members) as the sink.
//!
//! The markers are **data-driven**: their homoglyph forms come from the same
//! [`nfkc_preimage`]/[`bestfit`] engines the solver inverts (no hand-listed
//! confusables), so the probe set and the bypass generator can never drift.
//!
//! Soundness contract: a stage is proposed, not trusted. `solve_bypass`
//! re-verifies that its preimage reconstructs the attack through the proposed
//! pipeline, so a mis-detected or mis-ordered stage can only fail to produce a
//! bypass — never fabricate one.

use crate::error::Result;
use crate::transduce::Stage;
use wafrift_grammar::grammar::{bestfit, nfkc_preimage};

/// A reflection oracle: returns the bytes that reached the **sink** for a given
/// input — what the origin's decode/normalize pipeline produced. On a live
/// target this is "send `?q=<input>`, read the value reflected into the
/// response". Distinct from [`WafOracle`](crate::oracle::WafOracle) (block/pass
/// verdict); here we observe the *transformed value*.
pub trait ReflectionOracle {
    /// Reflect `input` back through the origin. Errors are transport-style
    /// (retryable), not a signal about normalization.
    fn reflect(&mut self, input: &[u8]) -> Result<Vec<u8>>;
}

/// Wrap any `FnMut(&[u8]) -> Result<Vec<u8>>` as a [`ReflectionOracle`] — the
/// seam a live HTTP probe (scald / the wafrift CLI client) plugs into without
/// dragging an HTTP stack into this crate. Mirrors
/// [`FnOracle`](crate::oracle::FnOracle).
pub struct FnReflector<F>(pub F);

impl<F> ReflectionOracle for FnReflector<F>
where
    F: FnMut(&[u8]) -> Result<Vec<u8>>,
{
    fn reflect(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        (self.0)(input)
    }
}

/// A unique, normalization-neutral marker. Lowercase alphanumerics only, so it
/// is itself unchanged by any stage — only the *carrier* transform moves it.
///
/// High-entropy on purpose: for the byte/whole-value probes (base64, hex,
/// overlong, NUL-strip) the *fold* is the bare marker, so a live target whose
/// page happens to contain the marker for any unrelated reason would make those
/// stages spuriously fire. A 16-char random-looking token makes ambient
/// collision astronomically unlikely, and [`scan_origin`]'s differential
/// baseline rejects the residual case explicitly rather than trusting luck.
const MARKER: &str = "wz7qx4k9mfp2r8td";

/// A second neutral token used only for the baseline control request in
/// [`scan_origin`]: distinct from [`MARKER`] (neither is a substring of the
/// other) so a baseline that reflects `CONTROL` proves the channel echoes,
/// while the absence of `MARKER` in that same baseline proves the marker is not
/// ambient page content. Lowercase alphanumerics ⇒ normalization-neutral.
const CONTROL: &str = "ctl8b3n6haje5wq1";

/// One normalization probe: the stage it tests, the marker as sent on the wire
/// (carrying the homoglyph/encoded form), and the ASCII the origin reflects iff
/// it applied that stage.
struct Probe {
    stage: Stage,
    /// Sent on the wire — `Vec<u8>` (not `String`) because the overlong-UTF-8
    /// carrier is *invalid* UTF-8 by construction.
    sent: Vec<u8>,
    folded: Vec<u8>,
}

/// Overlong-encode each ASCII byte as its non-canonical 2-byte form — the
/// carrier the overlong-decode probe sends (mirror of `solve::overlong_encode`,
/// inlined here to avoid widening that module's API for a 2-line helper).
fn overlong_bytes(s: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(s.len() * 2);
    for &b in s {
        if b <= 0x7F {
            v.push(0xC0 | (b >> 6));
            v.push(0x80 | (b & 0x3F));
        } else {
            v.push(b);
        }
    }
    v
}

/// The probe battery, in canonical pipeline order (decode before normalize:
/// `wire → … → decode → normalize → sink`). Order only sets the proposed
/// pipeline order; `solve_bypass` re-verifies reconstruction regardless.
fn probes() -> Vec<Probe> {
    let marker = MARKER.as_bytes().to_vec();
    let mut out = Vec::new();

    // ── Byte-level decodes (earliest in the pipeline) ──

    // URL-decode: `%2D` → `-`. `-` is the only literal here (it is the
    // definition of percent-encoding, not a confusables list).
    out.push(Probe {
        stage: Stage::UrlDecode { plus_is_space: false },
        sent: format!("{MARKER}%2D").into_bytes(),
        folded: format!("{MARKER}-").into_bytes(),
    });

    // Double URL-decode: `%252D` survives one pass as `%2D` and only a *second*
    // pass yields `-` — the exact asymmetry the double-encode bypass exploits.
    // A double-decoding origin folds this; a single-decoding one does not, so
    // the two are distinguished. (A double-decoder also folds the single `%2D`
    // probe above and so reports both; `run_probes` drops the subsumed single.)
    out.push(Probe {
        stage: Stage::DoubleUrlDecode,
        sent: format!("{MARKER}%252D").into_bytes(),
        folded: format!("{MARKER}-").into_bytes(),
    });

    // Base64: the marker base64-encoded; a decoding origin yields the marker.
    {
        use base64::Engine;
        out.push(Probe {
            stage: Stage::Base64Decode,
            sent: base64::engine::general_purpose::STANDARD.encode(&marker).into_bytes(),
            folded: marker.clone(),
        });
    }

    // Hex: the marker hex-encoded; a hex-decoding origin yields the marker.
    out.push(Probe {
        stage: Stage::HexDecode,
        sent: hex::encode(&marker).into_bytes(),
        folded: marker.clone(),
    });

    // Overlong UTF-8: the marker encoded in the non-canonical 2-byte form.
    out.push(Probe {
        stage: Stage::OverlongUtf8Decode,
        sent: overlong_bytes(&marker),
        folded: marker.clone(),
    });

    // NUL-strip: a marker with an embedded NUL the origin drops.
    let mut nul_sent = marker.clone();
    nul_sent.insert(2, 0);
    out.push(Probe { stage: Stage::StripNulls, sent: nul_sent, folded: marker.clone() });

    // ── Framework string decodes (after byte decodes, before normalize) ──

    // HTML entity decode: `&#x2d;` → `-` (framework templating / browser). The
    // numeric-hex entity form is exactly the solver's `html_entity_encode`
    // inverse, so probe and bypass generator can never drift.
    out.push(Probe {
        stage: Stage::HtmlEntityDecode,
        sent: format!("{MARKER}&#x2d;").into_bytes(),
        folded: format!("{MARKER}-").into_bytes(),
    });

    // JSON string unescape: the `-` escape → `-` (what a JSON body parser
    // hands the app). Disjoint escape syntax from the URL and HTML carriers, so
    // no cross-detection — each origin reports only its own decode.
    out.push(Probe {
        stage: Stage::JsonUnescape,
        sent: format!("{MARKER}\\u002d").into_bytes(),
        folded: format!("{MARKER}-").into_bytes(),
    });

    // ── Character-level normalizers (later in the pipeline) ──

    // NFKC: a fully-homoglyph form of the marker, generated by the engine the
    // solver inverts. `normalize(sent) == MARKER` holds by the engine's gate.
    if let Some(h) = nfkc_preimage::variants(MARKER, 1).into_iter().next() {
        debug_assert_eq!(nfkc_preimage::normalize(&h), MARKER);
        out.push(Probe { stage: Stage::NfkcNormalize, sent: h.into_bytes(), folded: marker.clone() });
    }

    // Best-fit: a marker carrying a curly quote the engine coerces to `'`.
    let bf_ascii = format!("{MARKER}'");
    if let Some(h) = bestfit::variants(&bf_ascii, 1).into_iter().next() {
        debug_assert_eq!(bestfit::normalize(&h), bf_ascii);
        out.push(Probe {
            stage: Stage::BestFitDownconvert,
            sent: h.into_bytes(),
            folded: bf_ascii.into_bytes(),
        });
    }

    out
}

/// Run the probe battery once. Returns `(reflection_observed, stages)`:
///
/// * `reflection_observed` is true if ANY probe's folded or sent form came back
///   — i.e. the channel demonstrably echoes our input (possibly transformed).
///   This is derived from the probes themselves, NOT a verbatim control echo,
///   so it stays correct even for whole-value origins (base64/hex) that
///   transform every value including a control token.
/// * `stages` are the admitted stages, in canonical order. When `suppress` is
///   set (ambient marker collision) no stage is admitted — fail-closed.
fn run_probes(oracle: &mut dyn ReflectionOracle, suppress: bool) -> Result<(bool, Vec<Stage>)> {
    let mut stages = Vec::new();
    let mut reflection_observed = false;
    for p in probes() {
        let reflected = oracle.reflect(&p.sent)?;
        let folded_seen = contains(&reflected, &p.folded);
        let sent_survived = contains(&reflected, &p.sent);
        if folded_seen || sent_survived {
            reflection_observed = true;
        }
        // Admit ONLY on an exact fold: the decoded/folded marker is present and
        // the carrier form did not survive. Anything else (unchanged, partial,
        // mangled) leaves the stage out — fail-closed, never a guess.
        if !suppress && folded_seen && !sent_survived {
            stages.push(p.stage);
        }
    }
    // A double-URL-decoding origin folds BOTH the single `%2D` and the double
    // `%252D` probe, so it admits UrlDecode *and* DoubleUrlDecode. These are not
    // independent stages to chain: the double subsumes the single, and chaining
    // both in the sink pipeline would over-decode (a third pass). Keep only the
    // deeper one so the pipeline handed to the solver matches the real origin.
    if stages.iter().any(|s| matches!(s, Stage::DoubleUrlDecode)) {
        stages.retain(|s| !matches!(s, Stage::UrlDecode { .. }));
    }
    Ok((reflection_observed, stages))
}

/// Fingerprint the origin's normalization pipeline by reflection. Returns the
/// stages the origin demonstrably applies, in canonical order — the sink
/// `Pipeline` to hand to the solver. An empty result means a non-normalizing
/// origin (correctly reported: the solver will then find no homoglyph bypass
/// rather than fabricate one).
///
/// For a *live* target prefer [`scan_origin`], which adds the differential
/// baseline that distinguishes "non-normalizing" from "never observed the
/// reflection" and rejects ambient-marker false positives.
pub fn detect_origin_normalization(oracle: &mut dyn ReflectionOracle) -> Result<Vec<Stage>> {
    Ok(run_probes(oracle, false)?.1)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// The outcome of a live origin scan. Separates the *measurement was valid*
/// question from the *what did it find* answer — a distinction
/// [`detect_origin_normalization`] alone cannot express (an empty `Vec` there
/// means either "non-normalizing origin" or "we never saw the reflection", and
/// on a real target those demand opposite operator actions).
#[derive(Debug, Clone, PartialEq)]
pub struct OriginScan {
    /// Our probe content (folded or raw) was observed coming back — the channel
    /// demonstrably echoes, so a negative result is trustworthy. When `false`,
    /// the scan is inconclusive (wrong parameter, no reflection, or a transform
    /// that ate every probe) and `stages` is empty by construction, NOT a clean
    /// bill of health.
    pub reflection_observed: bool,
    /// The fold marker was already present in the baseline response (ambient
    /// page content collided with our marker). When `true` the byte/whole-value
    /// probes cannot be trusted, so `stages` is empty — fail-closed rather than
    /// report luck-driven detections.
    pub marker_collision: bool,
    /// Detected origin stages, in canonical order. Meaningful only when
    /// `reflection_observed && !marker_collision`.
    pub stages: Vec<Stage>,
}

/// Live origin scan with a **differential baseline** that makes the result
/// trustworthy on a real target — the production entry point the CLI uses.
///
/// One control request is sent first (a neutral [`CONTROL`] token that is not a
/// carrier for any probe): if [`MARKER`] appears in that baseline it is ambient
/// page content, not a fold, so the byte/whole-value probes are suppressed
/// (`marker_collision`). The probe battery then runs and `reflection_observed`
/// is taken from whether any probe's content (folded or raw) actually came
/// back — robust even for whole-value origins that also transform the control,
/// so an empty `stages` with `reflection_observed = true` is a real "this
/// origin normalizes nothing" rather than "we pointed at the wrong parameter".
pub fn scan_origin(oracle: &mut dyn ReflectionOracle) -> Result<OriginScan> {
    // CONTROL is not a carrier for any probe, so it can never *fold* to MARKER;
    // MARKER appearing here therefore means ambient page content.
    let baseline = oracle.reflect(CONTROL.as_bytes())?;
    let marker_collision = contains(&baseline, MARKER.as_bytes());
    let (reflection_observed, stages) = run_probes(oracle, marker_collision)?;
    Ok(OriginScan {
        reflection_observed,
        marker_collision,
        stages,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transduce::Pipeline;

    /// A faithful origin double: it reflects exactly what its declared sink
    /// pipeline produces — the inverse role of `SimRegexWaf` for `WafOracle`.
    struct FakeOrigin(Pipeline);
    impl ReflectionOracle for FakeOrigin {
        fn reflect(&mut self, input: &[u8]) -> Result<Vec<u8>> {
            Ok(self.0.apply(input))
        }
    }

    fn detect(stages: Vec<Stage>) -> Vec<Stage> {
        let mut o = FakeOrigin(Pipeline(stages));
        detect_origin_normalization(&mut o).unwrap()
    }

    #[test]
    fn identity_origin_detects_nothing() {
        assert!(detect(vec![Stage::Identity]).is_empty());
    }

    #[test]
    fn nfkc_origin_is_detected() {
        assert_eq!(detect(vec![Stage::NfkcNormalize]), vec![Stage::NfkcNormalize]);
    }

    #[test]
    fn bestfit_origin_is_detected() {
        assert_eq!(detect(vec![Stage::BestFitDownconvert]), vec![Stage::BestFitDownconvert]);
    }

    #[test]
    fn url_decoding_origin_is_detected() {
        assert_eq!(
            detect(vec![Stage::UrlDecode { plus_is_space: false }]),
            vec![Stage::UrlDecode { plus_is_space: false }]
        );
    }

    #[test]
    fn null_stripping_origin_is_detected() {
        assert_eq!(detect(vec![Stage::StripNulls]), vec![Stage::StripNulls]);
    }

    #[test]
    fn overlong_utf8_decoding_origin_is_detected() {
        assert_eq!(detect(vec![Stage::OverlongUtf8Decode]), vec![Stage::OverlongUtf8Decode]);
    }

    #[test]
    fn base64_decoding_origin_is_detected() {
        assert_eq!(detect(vec![Stage::Base64Decode]), vec![Stage::Base64Decode]);
    }

    #[test]
    fn hex_decoding_origin_is_detected() {
        assert_eq!(detect(vec![Stage::HexDecode]), vec![Stage::HexDecode]);
    }

    #[test]
    fn base64_and_hex_do_not_cross_report() {
        // Both are whole-value text decodes over overlapping alphabets; assert
        // each origin reports ONLY itself (the marker's hex is not valid base64
        // of the marker, and vice versa).
        assert_eq!(detect(vec![Stage::Base64Decode]), vec![Stage::Base64Decode]);
        assert_eq!(detect(vec![Stage::HexDecode]), vec![Stage::HexDecode]);
    }

    #[test]
    fn base64_origin_does_not_falsely_report_other_decodes() {
        // Precision: a base64-decoding origin must report ONLY base64 — the
        // url/overlong/null markers are not valid base64 of those folds.
        assert_eq!(detect(vec![Stage::Base64Decode]), vec![Stage::Base64Decode]);
    }

    #[test]
    fn byte_decodes_are_independent_no_cross_detection() {
        // Precision: a NUL-stripping origin must NOT report overlong-decode (or
        // url/normalize), and vice versa — the probes are mutually exclusive.
        assert_eq!(detect(vec![Stage::StripNulls]), vec![Stage::StripNulls]);
        assert_eq!(detect(vec![Stage::OverlongUtf8Decode]), vec![Stage::OverlongUtf8Decode]);
    }

    #[test]
    fn json_unescaping_origin_is_detected() {
        assert_eq!(detect(vec![Stage::JsonUnescape]), vec![Stage::JsonUnescape]);
    }

    #[test]
    fn html_entity_decoding_origin_is_detected() {
        assert_eq!(detect(vec![Stage::HtmlEntityDecode]), vec![Stage::HtmlEntityDecode]);
    }

    #[test]
    fn double_url_decoding_origin_is_detected_and_subsumes_single() {
        // A double-decoder folds both the single and the double probe; detection
        // must report ONLY DoubleUrlDecode — chaining UrlDecode too would
        // over-decode the solver's preimage with a spurious third pass.
        let d = detect(vec![Stage::DoubleUrlDecode]);
        assert_eq!(d, vec![Stage::DoubleUrlDecode], "got {d:?}");
        assert!(!d.contains(&Stage::UrlDecode { plus_is_space: false }));
    }

    #[test]
    fn single_url_decode_is_not_reported_as_double() {
        // Precision twin: a single-decoding origin must NOT trip the double
        // probe — `%252D` survives one pass as `%2D` and never folds to `-`.
        let d = detect(vec![Stage::UrlDecode { plus_is_space: false }]);
        assert_eq!(d, vec![Stage::UrlDecode { plus_is_space: false }]);
        assert!(!d.contains(&Stage::DoubleUrlDecode));
    }

    #[test]
    fn json_and_html_decodes_do_not_cross_report() {
        // Disjoint escape syntaxes: a JSON-unescaping origin must not report
        // HTML-entity-decode, and vice versa (neither carrier folds the other).
        let j = detect(vec![Stage::JsonUnescape]);
        assert_eq!(j, vec![Stage::JsonUnescape]);
        assert!(!j.contains(&Stage::HtmlEntityDecode));
        let h = detect(vec![Stage::HtmlEntityDecode]);
        assert_eq!(h, vec![Stage::HtmlEntityDecode]);
        assert!(!h.contains(&Stage::JsonUnescape));
    }

    #[test]
    fn framework_decodes_do_not_falsely_report_url_or_base64() {
        // Precision: the HTML/JSON carriers are not valid percent-encoding,
        // base64, or hex of the fold, so those origins must report only
        // themselves — never a spurious byte-decode.
        for st in [Stage::HtmlEntityDecode, Stage::JsonUnescape] {
            let d = detect(vec![st.clone()]);
            assert_eq!(d, vec![st.clone()], "stage {st:?} reported {d:?}");
        }
    }

    #[test]
    fn every_invertible_solver_stage_has_a_detection_probe() {
        // Anti-drift guard — this is the test that catches a stage gaining a
        // non-identity `solve::stage_inverse` without a fingerprint probe here.
        // When that happens the offline solver can bypass an origin class the
        // LIVE decompiler is blind to (exactly the gap this commit closes for
        // DoubleUrlDecode/JsonUnescape/HtmlEntityDecode). The list mirrors the
        // non-identity arms of `stage_inverse`; keep them in lockstep.
        use std::collections::HashSet;
        use std::mem::discriminant;
        let probed: HashSet<_> = probes().iter().map(|p| discriminant(&p.stage)).collect();
        let invertible = [
            Stage::UrlDecode { plus_is_space: false },
            Stage::DoubleUrlDecode,
            Stage::JsonUnescape,
            Stage::HtmlEntityDecode,
            Stage::NfkcNormalize,
            Stage::BestFitDownconvert,
            Stage::StripNulls,
            Stage::OverlongUtf8Decode,
            Stage::Base64Decode,
            Stage::HexDecode,
        ];
        for st in &invertible {
            assert!(
                probed.contains(&discriminant(st)),
                "invertible solver stage {st:?} has no detection probe in probes() \
                 — the live fingerprinter is blind to an origin the solver can bypass"
            );
        }
    }

    #[test]
    fn composite_url_then_nfkc_origin_detects_both_in_order() {
        // A framework that url-decodes then NFKC-normalizes: both probes fold,
        // and the canonical order (decode before normalize) is returned.
        let detected = detect(vec![Stage::UrlDecode { plus_is_space: false }, Stage::NfkcNormalize]);
        assert_eq!(
            detected,
            vec![Stage::UrlDecode { plus_is_space: false }, Stage::NfkcNormalize]
        );
    }

    #[test]
    fn nfkc_normalizing_origin_does_not_falsely_report_bestfit() {
        // Precision twin: NFKC does NOT fold the curly quote, so the best-fit
        // probe must stay unfolded and best-fit must be absent.
        let detected = detect(vec![Stage::NfkcNormalize]);
        assert!(!detected.contains(&Stage::BestFitDownconvert));
        assert!(detected.contains(&Stage::NfkcNormalize));
    }

    #[test]
    fn detected_pipeline_drives_the_solver_to_a_targeted_bypass() {
        // The payoff: fingerprint the origin, then feed the detected sink to
        // the SAME solver — and it lands a homoglyph bypass with no sink guess.
        use crate::canon::Channel;
        use crate::normalize::Transform;
        use crate::oracle::{ChannelSet, Rule, SimRegexWaf};
        use crate::{solve_bypass, Outcome, WafOracle};
        use wafrift_types::Request;

        let detected = detect(vec![Stage::NfkcNormalize]);
        assert_eq!(detected, vec![Stage::NfkcNormalize]);
        let sink = Pipeline(detected);

        let attack = b"<script>";
        let mut waf = SimRegexWaf::new(
            vec![Rule {
                id: "941".into(),
                channels: ChannelSet::none().with(Channel::Body),
                transforms: vec![Transform::UrlDecodeUni, Transform::Lowercase],
                pattern: regex::bytes::Regex::new("<script").unwrap(),
                score: 5,
            }],
            5,
        );
        let build =
            |b: &[u8]| Request::post("https://h/p", b.to_vec()).header("Content-Type", "text/html");

        let sol = solve_bypass(attack, &sink, &mut waf, &build)
            .unwrap()
            .expect("a fingerprinted NFKC origin must yield a targeted homoglyph bypass");
        assert!(!sol.input.contains(&b'<') && !sol.input.contains(&b'>'));
        let mut replay = SimRegexWaf::new(
            vec![Rule {
                id: "941".into(),
                channels: ChannelSet::none().with(Channel::Body),
                transforms: vec![Transform::UrlDecodeUni, Transform::Lowercase],
                pattern: regex::bytes::Regex::new("<script").unwrap(),
                score: 5,
            }],
            5,
        );
        assert_eq!(replay.classify(&build(&sol.input)).unwrap(), Outcome::Pass);
    }

    #[test]
    fn detected_double_decode_origin_drives_the_classic_double_encode_bypass() {
        // The headline trick, closed on the live path: fingerprint an origin
        // that URL-decodes TWICE, hand the detected pipeline to the solver, and
        // it derives the double-encoded payload — `%253Cscript` survives the
        // WAF's single decode as `%3Cscript` (inert) but the origin's second
        // pass reconstitutes `<script`. Before this commit the detector could
        // not see DoubleUrlDecode at all, so this end-to-end was unreachable.
        use crate::canon::Channel;
        use crate::normalize::Transform;
        use crate::oracle::{ChannelSet, Rule, SimRegexWaf};
        use crate::{solve_bypass, Outcome, WafOracle};
        use wafrift_types::Request;

        let detected = detect(vec![Stage::DoubleUrlDecode]);
        assert_eq!(detected, vec![Stage::DoubleUrlDecode], "got {detected:?}");
        let sink = Pipeline(detected);

        let attack = b"<script";
        // WAF decodes ONCE (urlDecodeUni is single-pass) — the asymmetry the
        // double-decode origin exploits.
        let rule = || Rule {
            id: "941".into(),
            channels: ChannelSet::none().with(Channel::Body),
            transforms: vec![Transform::UrlDecodeUni, Transform::Lowercase],
            pattern: regex::bytes::Regex::new("<script").unwrap(),
            score: 5,
        };
        let mut waf = SimRegexWaf::new(vec![rule()], 5);
        let build =
            |b: &[u8]| Request::post("https://h/p", b.to_vec()).header("Content-Type", "text/html");

        let sol = solve_bypass(attack, &sink, &mut waf, &build)
            .unwrap()
            .expect("a fingerprinted double-decoding origin must yield a double-encoded bypass");
        // The solved input carries no raw `<` (the WAF would catch it); the
        // bypass lives entirely in the second percent layer.
        assert!(!sol.input.contains(&b'<'), "solved input must not contain raw '<': {:?}",
            String::from_utf8_lossy(&sol.input));
        // The origin's pipeline reconstructs the literal attack.
        assert!(sink.apply(&sol.input).windows(attack.len()).any(|w| w == attack));
        let mut replay = SimRegexWaf::new(vec![rule()], 5);
        assert_eq!(replay.classify(&build(&sol.input)).unwrap(), Outcome::Pass);
    }

    // ── scan_origin: differential-baseline robustness on live-style oracles ──

    /// Reflects exactly the input it is sent (a perfectly echoing, otherwise
    /// non-normalizing origin). Used to prove the baseline confirms reflection.
    struct EchoOrigin;
    impl ReflectionOracle for EchoOrigin {
        fn reflect(&mut self, input: &[u8]) -> Result<Vec<u8>> {
            Ok(input.to_vec())
        }
    }

    /// Always returns a fixed body, ignoring the input — models a target that
    /// does NOT reflect the probed parameter at all (wrong param / no echo).
    struct ConstOrigin(Vec<u8>);
    impl ReflectionOracle for ConstOrigin {
        fn reflect(&mut self, _input: &[u8]) -> Result<Vec<u8>> {
            Ok(self.0.clone())
        }
    }

    /// Echoes the input but ALSO injects the bare marker into every response —
    /// models a live page whose ambient content collides with our fold marker.
    struct MarkerInjectOrigin;
    impl ReflectionOracle for MarkerInjectOrigin {
        fn reflect(&mut self, input: &[u8]) -> Result<Vec<u8>> {
            let mut out = input.to_vec();
            out.extend_from_slice(MARKER.as_bytes());
            Ok(out)
        }
    }

    #[test]
    fn scan_confirms_reflection_on_an_echoing_identity_origin() {
        // The control reflects, the marker is not ambient ⇒ a trustworthy
        // "this origin normalizes nothing" (empty stages, reflection observed).
        let scan = scan_origin(&mut EchoOrigin).unwrap();
        assert!(scan.reflection_observed, "echoing origin must be observed");
        assert!(!scan.marker_collision);
        assert!(scan.stages.is_empty(), "identity origin has no stages");
    }

    #[test]
    fn scan_reports_no_reflection_when_the_channel_does_not_echo() {
        // A non-reflecting target ⇒ reflection_observed=false. The empty stage
        // list is explicitly NOT a clean bill of health (the whole point of the
        // baseline: distinguish "no echo" from "no normalization").
        let scan = scan_origin(&mut ConstOrigin(b"static page, no echo".to_vec())).unwrap();
        assert!(
            !scan.reflection_observed,
            "a non-echoing channel must not be reported as observed"
        );
        assert!(scan.stages.is_empty());
    }

    #[test]
    fn scan_fails_closed_on_ambient_marker_collision() {
        // The dangerous live false positive: the page already contains the fold
        // marker, so base64/hex/overlong/nul probes would all spuriously fire.
        // The baseline detects the collision and refuses to report ANY stage.
        let scan = scan_origin(&mut MarkerInjectOrigin).unwrap();
        assert!(scan.reflection_observed, "the echo channel still works");
        assert!(
            scan.marker_collision,
            "ambient marker must be detected at baseline"
        );
        assert!(
            scan.stages.is_empty(),
            "marker collision must yield NO detections (fail-closed), got {:?}",
            scan.stages
        );
    }

    #[test]
    fn scan_still_detects_a_real_stage_through_the_baseline() {
        // The baseline must not suppress a genuine detection: a base64-decoding
        // origin still fingerprints as Base64Decode after the control passes.
        let mut o = FakeOrigin(Pipeline(vec![Stage::Base64Decode]));
        let scan = scan_origin(&mut o).unwrap();
        assert!(scan.reflection_observed);
        assert!(!scan.marker_collision);
        assert_eq!(scan.stages, vec![Stage::Base64Decode]);
    }

    #[test]
    fn marker_and_control_are_distinct_and_non_overlapping() {
        // The differential baseline relies on CONTROL reflecting while MARKER
        // is absent — which only works if neither token contains the other.
        assert_ne!(MARKER, CONTROL);
        assert!(!CONTROL.contains(MARKER));
        assert!(!MARKER.contains(CONTROL));
        // Both must be normalization-neutral (lowercase alnum) so no stage
        // moves them — otherwise the baseline itself could fold.
        for tok in [MARKER, CONTROL] {
            assert!(
                tok.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
                "{tok} must be lowercase-alnum (normalization-neutral)"
            );
        }
    }
}
