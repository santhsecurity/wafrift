//! Workspace-wide `SmuggleProbe` trait — uniform interface for the
//! seven (and growing) probe families wafrift emits.
//!
//! Each smuggle module (`content-type::multipart_smuggle`,
//! `http3-evasion::capsule`, `smuggling::ws_compression`,
//! `encoding::cookie_smuggle`, …) produces its own probe struct with
//! domain-specific fields. From an operator's perspective, those
//! domain differences are noise: every probe ultimately reduces to a
//! triple of "wire artifact + per-probe correlation token + which
//! technique fired." The trait below exposes exactly that triple,
//! letting `wafrift-core` / `wafrift-cli` iterate every wafrift
//! probe through one code path.
//!
//! ## Why the artifact is an enum and not a `Vec<u8>`
//!
//! Different probe families produce different wire shapes:
//!
//! - Header-injection probes (Cookie, Authorization, Range): a list
//!   of `(header_name, header_value)` pairs.
//! - Body-shaping probes (multipart smuggle): a Content-Type header
//!   value paired with a body byte stream.
//! - Frame-stream probes (HTTP/3 capsule, QUIC datagram, WebSocket
//!   compression): one or more pre-serialized binary frames to inject
//!   into a wire-format stream.
//!
//! Forcing all three into `Vec<u8>` would lose enough structure that
//! the operator-facing CLI couldn't choose the right attach-point
//! (header vs body vs frame). The enum keeps the shape information
//! alongside the bytes.

use crate::canary::Canary;
use crate::request::Request;

/// What kind of wire artifact a smuggle probe produces.
///
/// JSON layout uses the `tag = "kind", content = "value"`
/// internally-tagged adjacent representation per serde docs — it
/// works uniformly across tuple variants (which the simple
/// `tag = "kind"` form cannot serialize when the payload is a
/// sequence). Example wire shapes:
///
/// ```json
/// {"kind":"headers","value":[["Cookie","name=evil"]]}
/// {"kind":"body_with_content_type","value":{"content_type":"text/plain","body":[0x68,0x69]}}
/// {"kind":"frames","value":[[0,1,2]]}
/// ```
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum SmuggleArtifact {
    /// One or more `(header_name, header_value)` pairs to attach to
    /// the outgoing HTTP request. Used by header-injection probes
    /// (Cookie, Authorization, Range). Duplicate names are allowed
    /// — that's the whole point of the duplicate-header variants.
    Headers(Vec<(String, String)>),
    /// A complete HTTP request body paired with the
    /// `Content-Type` header value the caller should send.
    /// Used by multipart smuggle probes.
    BodyWithContentType {
        /// The exact bytes of the `Content-Type:` request header.
        content_type: String,
        /// The HTTP request body.
        body: Vec<u8>,
    },
    /// One or more pre-serialized binary frames. The caller is
    /// responsible for placing them inside the right transport
    /// envelope (HTTP/2 DATA frame, HTTP/3 STREAM frame, WebSocket
    /// frame, QUIC packet). Used by frame-stream probes.
    Frames(Vec<Vec<u8>>),
}

impl SmuggleArtifact {
    /// Total byte count of the artifact's wire footprint. For
    /// `Headers`, sums `name + ": " + value + "\r\n"` per pair. For
    /// `BodyWithContentType`, sums header line + body length. For
    /// `Frames`, sums all frame byte counts. Useful for budget
    /// accounting in scan campaigns.
    #[must_use]
    pub fn wire_byte_count(&self) -> usize {
        match self {
            Self::Headers(hs) => hs
                .iter()
                .map(|(n, v)| n.len() + 2 + v.len() + 2) // ": " + CRLF
                .sum(),
            Self::BodyWithContentType { content_type, body } => {
                "Content-Type: ".len() + content_type.len() + 2 + body.len()
            }
            Self::Frames(fs) => fs.iter().map(Vec::len).sum(),
        }
    }
}

/// Workspace-wide smuggle probe interface. Every wafrift probe
/// struct implements this so consumers (CLI, telemetry, tests) can
/// iterate generically across families.
pub trait SmuggleProbe {
    /// Per-probe correlation token. Splice into a custom header
    /// (`X-Probe-Id`, etc.) so server-side responses can be
    /// attributed to the specific variant that triggered them.
    fn canary(&self) -> &Canary;

    /// Stable technique identifier in `family.variant` form. Used
    /// in telemetry, JSON output, and reproducer logs. Example:
    /// `"cookie.duplicate-name-last-wins"`.
    fn technique(&self) -> String;

    /// Human-readable one-line description for operator logs.
    fn description(&self) -> &str;

    /// The wire artifact this probe produces.
    fn artifact(&self) -> SmuggleArtifact;
}

/// The merged wire artifact produced by `compose_artifacts` — one
/// header set, one optional body, one optional frame stream, plus a
/// list of the technique tags that were merged together. Operators
/// chain multiple smuggle techniques into a single outgoing request
/// (e.g. a duplicate-Cookie header alongside a multipart preamble-
/// smuggle body) and get the composed wire shape back as one
/// structure.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ComposedArtifact {
    /// Every header line, in input-probe order. Duplicates allowed
    /// — that's intentional for variants like
    /// `auth.duplicate-header-first-wins-benign` whose whole point
    /// is the duplication.
    pub headers: Vec<(String, String)>,
    /// `Content-Type` value + body bytes from the (at most one)
    /// `BodyWithContentType` artifact in the input. If two probes
    /// each contribute a body, the **last** one wins — the operator
    /// should normally compose at most one body-shaping probe per
    /// request.
    pub body: Option<(String, Vec<u8>)>,
    /// Concatenated frame stream. Every `Frames` artifact in input
    /// order. Used for WS / HTTP/3 transports that ride pre-built
    /// frame bytes.
    pub frames: Vec<Vec<u8>>,
    /// Stable technique tags of the merged probes, in input order.
    /// Useful for correlation logs ("this request was a cookie +
    /// multipart compose").
    pub techniques: Vec<String>,
    /// Per-probe canary tokens of the merged probes, in input order
    /// (1:1 with `techniques`). Preserved so OOB callback
    /// correlation still works post-composition — a chain of N
    /// probes can be reverse-mapped to its N canaries from a single
    /// inbound callback. `#[serde(default)]` keeps old JSON
    /// (without the field) deserializable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub canaries: Vec<String>,
}

impl ComposedArtifact {
    /// Splice this composed artifact into a base [`Request`]:
    /// extend its headers with the composed header pairs, replace
    /// its body+Content-Type if the composition has a body, and
    /// return any frame streams separately (the caller decides
    /// where to inject them — they don't live inside the HTTP
    /// request struct).
    ///
    /// Returns the leftover frame stream so the caller doesn't lose
    /// it; `Vec::is_empty()` means the composition was purely
    /// header-and-body.
    pub fn apply_to_request(&self, req: &mut Request) -> Vec<Vec<u8>> {
        req.headers.extend(self.headers.iter().cloned());
        if let Some((ct, body)) = &self.body {
            // Replace any existing Content-Type with the composed
            // one. The composed body wins because the caller chose
            // to compose a body-shaping probe; honouring an earlier
            // Content-Type set on the base request would silently
            // mismatch the body shape and break parsing.
            req.headers
                .retain(|(n, _)| !n.eq_ignore_ascii_case("content-type"));
            req.headers.push(("Content-Type".to_string(), ct.clone()));
            req.body = Some(body.clone());
        }
        self.frames.clone()
    }
}

/// Merge an ordered list of `SmuggleProbe` artifacts into a single
/// composed wire shape. Each probe contributes its artifact:
///
/// - `Headers` pairs extend the composed `headers`.
/// - `BodyWithContentType` overwrites the composed `body` (last
///   writer wins — composing two bodies is operator error and
///   collapses to the last one rather than panicking).
/// - `Frames` extend the composed `frames` in input order.
///
/// Returns the composed artifact ready to splice into an outbound
/// request.
#[must_use]
pub fn compose_artifacts(probes: &[&dyn SmuggleProbe]) -> ComposedArtifact {
    let mut out = ComposedArtifact::default();
    for p in probes {
        out.techniques.push(p.technique());
        out.canaries.push(p.canary().token.clone());
        match p.artifact() {
            SmuggleArtifact::Headers(hs) => out.headers.extend(hs),
            SmuggleArtifact::BodyWithContentType { content_type, body } => {
                out.body = Some((content_type, body));
            }
            SmuggleArtifact::Frames(fs) => out.frames.extend(fs),
        }
    }
    out
}

/// Build the cartesian product of N probe families as composed
/// artifacts. For every tuple `(p_0, p_1, …, p_{N-1})` where each
/// `p_i` is drawn from `families[i]`, emit one [`ComposedArtifact`]
/// carrying every probe's artifact merged in family order.
///
/// Output size is `∏ |family_i|`. For N=2 this matches
/// [`compose_cross_product`] (which is now a thin wrapper around
/// this primitive). For N=3+ this is the generalised triple /
/// quadruple chain. Cap input sizes carefully — 4 families of 10
/// probes each emits 10,000 composed artifacts.
///
/// Returns an empty Vec when `families` is empty or any
/// constituent family is empty (the cartesian product of an empty
/// set is empty).
#[must_use]
pub fn compose_n_product(families: &[&[Box<dyn SmuggleProbe>]]) -> Vec<ComposedArtifact> {
    if families.is_empty() || families.iter().any(|f| f.is_empty()) {
        return Vec::new();
    }
    let total: usize = families.iter().map(|f| f.len()).product();
    let mut out = Vec::with_capacity(total);
    let mut idx = vec![0usize; families.len()];
    loop {
        let refs: Vec<&dyn SmuggleProbe> = families
            .iter()
            .zip(idx.iter())
            .map(|(f, &i)| f[i].as_ref())
            .collect();
        out.push(compose_artifacts(&refs));

        // Advance the multi-radix counter — increment the rightmost
        // family's index, carry on overflow into the family to the
        // left. Returns the accumulated artifacts when the leftmost
        // family overflows.
        let mut k = families.len();
        loop {
            if k == 0 {
                return out;
            }
            k -= 1;
            idx[k] += 1;
            if idx[k] < families[k].len() {
                break;
            }
            idx[k] = 0;
        }
    }
}

/// Build the cartesian product of two probe Vecs as composed
/// artifacts — convenience wrapper around [`compose_n_product`]
/// preserved for backwards compatibility (and ergonomics for the
/// common 2-family case).
///
/// Use case: sweep "every cookie smuggle × every multipart smuggle"
/// to surface bypass-chain interactions that no single technique
/// produces. The output size is `lhs.len() * rhs.len()` so cap the
/// inputs in scan campaigns.
#[must_use]
pub fn compose_cross_product(
    lhs: &[Box<dyn SmuggleProbe>],
    rhs: &[Box<dyn SmuggleProbe>],
) -> Vec<ComposedArtifact> {
    compose_n_product(&[lhs, rhs])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal in-test impl so we can exercise the trait + compose
    /// without depending on any of the smuggle crates (which depend
    /// on wafrift-types, so a dependency in the other direction would
    /// be a cycle).
    struct StubProbe {
        canary: Canary,
        technique: String,
        description: String,
        artifact: SmuggleArtifact,
    }

    impl SmuggleProbe for StubProbe {
        fn canary(&self) -> &Canary {
            &self.canary
        }
        fn technique(&self) -> String {
            self.technique.clone()
        }
        fn description(&self) -> &str {
            &self.description
        }
        fn artifact(&self) -> SmuggleArtifact {
            self.artifact.clone()
        }
    }

    fn header_probe(name: &str, value: &str, tag: &str) -> StubProbe {
        StubProbe {
            canary: Canary::generate(),
            technique: tag.into(),
            description: "header probe stub".into(),
            artifact: SmuggleArtifact::Headers(vec![(name.into(), value.into())]),
        }
    }

    fn body_probe(ct: &str, body: &[u8], tag: &str) -> StubProbe {
        StubProbe {
            canary: Canary::generate(),
            technique: tag.into(),
            description: "body probe stub".into(),
            artifact: SmuggleArtifact::BodyWithContentType {
                content_type: ct.into(),
                body: body.into(),
            },
        }
    }

    fn frames_probe(frames: Vec<Vec<u8>>, tag: &str) -> StubProbe {
        StubProbe {
            canary: Canary::generate(),
            technique: tag.into(),
            description: "frames probe stub".into(),
            artifact: SmuggleArtifact::Frames(frames),
        }
    }

    #[test]
    fn headers_wire_byte_count_includes_separator_and_crlf() {
        // Header "X: Y\r\n" is 6 bytes (1+2+1+2). Anti-rig: a
        // regression that dropped the CRLF accounting would silently
        // miscount byte-budgets in scan campaigns.
        let a = SmuggleArtifact::Headers(vec![("X".into(), "Y".into())]);
        assert_eq!(a.wire_byte_count(), 1 + 2 + 1 + 2);
    }

    #[test]
    fn body_with_content_type_wire_count_sums_header_and_body() {
        let a = SmuggleArtifact::BodyWithContentType {
            content_type: "text/plain".into(),
            body: b"hello".to_vec(),
        };
        // "Content-Type: " (14) + "text/plain" (10) + CRLF (2) + body (5).
        assert_eq!(a.wire_byte_count(), 14 + 10 + 2 + 5);
    }

    #[test]
    fn frames_wire_count_sums_each_frame() {
        let a = SmuggleArtifact::Frames(vec![vec![1, 2, 3], vec![4, 5]]);
        assert_eq!(a.wire_byte_count(), 5);
    }

    #[test]
    fn empty_artifacts_have_zero_byte_count() {
        assert_eq!(SmuggleArtifact::Headers(vec![]).wire_byte_count(), 0);
        assert_eq!(SmuggleArtifact::Frames(vec![]).wire_byte_count(), 0);
        // Empty body with empty CT: just the "Content-Type: " prefix + CRLF.
        let a = SmuggleArtifact::BodyWithContentType {
            content_type: String::new(),
            body: Vec::new(),
        };
        assert_eq!(a.wire_byte_count(), "Content-Type: ".len() + 2);
    }

    #[test]
    fn compose_empty_input_returns_default() {
        let composed = compose_artifacts(&[]);
        assert_eq!(composed, ComposedArtifact::default());
    }

    #[test]
    fn compose_two_header_probes_concatenates_headers() {
        let a = header_probe("Cookie", "session=evil", "cookie.x");
        let b = header_probe("Authorization", "Bearer T", "auth.y");
        let probes: Vec<&dyn SmuggleProbe> = vec![&a, &b];
        let composed = compose_artifacts(&probes);
        assert_eq!(composed.headers.len(), 2);
        assert_eq!(
            composed.headers[0],
            ("Cookie".into(), "session=evil".into())
        );
        assert_eq!(
            composed.headers[1],
            ("Authorization".into(), "Bearer T".into())
        );
        assert_eq!(composed.techniques, vec!["cookie.x", "auth.y"]);
        assert!(composed.body.is_none());
        assert!(composed.frames.is_empty());
    }

    #[test]
    fn compose_header_plus_body_carries_both() {
        // The realistic operator use-case: a duplicate-Cookie probe
        // (headers) chained with a multipart preamble-smuggle probe
        // (body). One request, both probes.
        let h = header_probe("Cookie", "a=evil", "cookie.dup");
        let b = body_probe(
            "multipart/form-data; boundary=xyz",
            b"--xyz\r\n\r\nbody\r\n--xyz--\r\n",
            "multipart.preamble",
        );
        let probes: Vec<&dyn SmuggleProbe> = vec![&h, &b];
        let composed = compose_artifacts(&probes);
        assert_eq!(composed.headers.len(), 1);
        let (ct, body) = composed.body.as_ref().expect("body present");
        assert_eq!(ct, "multipart/form-data; boundary=xyz");
        assert!(body.starts_with(b"--xyz"));
        assert_eq!(composed.techniques.len(), 2);
    }

    #[test]
    fn compose_last_body_wins_when_two_supplied() {
        // Documented contract: two body probes collapse to the last.
        let b1 = body_probe("text/plain", b"first", "x.first");
        let b2 = body_probe("application/json", b"{\"k\":\"second\"}", "x.second");
        let probes: Vec<&dyn SmuggleProbe> = vec![&b1, &b2];
        let composed = compose_artifacts(&probes);
        let (ct, body) = composed.body.as_ref().expect("body");
        assert_eq!(ct, "application/json");
        assert_eq!(body, b"{\"k\":\"second\"}");
    }

    #[test]
    fn compose_frame_probes_concatenate_in_input_order() {
        let f1 = frames_probe(vec![vec![1, 2], vec![3, 4]], "frame.a");
        let f2 = frames_probe(vec![vec![5]], "frame.b");
        let probes: Vec<&dyn SmuggleProbe> = vec![&f1, &f2];
        let composed = compose_artifacts(&probes);
        assert_eq!(composed.frames, vec![vec![1, 2], vec![3, 4], vec![5]]);
    }

    #[test]
    fn compose_mixed_three_kinds_in_one_request() {
        let h = header_probe("X-Probe", "abc", "tag.h");
        let b = body_probe("text/plain", b"hello", "tag.b");
        let f = frames_probe(vec![vec![0xFF]], "tag.f");
        let probes: Vec<&dyn SmuggleProbe> = vec![&h, &b, &f];
        let composed = compose_artifacts(&probes);
        assert_eq!(composed.headers.len(), 1);
        assert!(composed.body.is_some());
        assert_eq!(composed.frames, vec![vec![0xFF]]);
        assert_eq!(composed.techniques, vec!["tag.h", "tag.b", "tag.f"]);
    }

    #[test]
    fn compose_preserves_techniques_in_input_order() {
        let a = header_probe("X", "1", "alpha");
        let b = header_probe("Y", "2", "beta");
        let c = header_probe("Z", "3", "gamma");
        let composed = compose_artifacts(&[&a, &b, &c]);
        assert_eq!(composed.techniques, vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn apply_to_request_extends_headers_in_place() {
        let h1 = header_probe("Cookie", "a=1", "cookie.one");
        let h2 = header_probe("Authorization", "Bearer T", "auth.one");
        let composed = compose_artifacts(&[&h1, &h2]);

        let mut req = Request::get("https://example.com/");
        req.add_header("Accept", "*/*");
        let leftover_frames = composed.apply_to_request(&mut req);

        assert!(
            leftover_frames.is_empty(),
            "header-only compose returns no frames"
        );
        // Original Accept + two composed headers = 3 total.
        assert_eq!(req.headers.len(), 3);
        assert!(req.headers.iter().any(|(n, v)| n == "Accept" && v == "*/*"));
        assert!(req.headers.iter().any(|(n, v)| n == "Cookie" && v == "a=1"));
        assert!(
            req.headers
                .iter()
                .any(|(n, v)| n == "Authorization" && v == "Bearer T")
        );
        assert!(req.body.is_none());
    }

    #[test]
    fn apply_to_request_replaces_existing_content_type_when_body_present() {
        let b = body_probe("multipart/form-data; boundary=xyz", b"body", "mp.one");
        let composed = compose_artifacts(&[&b]);

        let mut req = Request::post("https://example.com/", b"original-body".to_vec());
        req.add_header("Content-Type", "application/x-www-form-urlencoded");
        let _ = composed.apply_to_request(&mut req);

        // Old Content-Type gone, new one in place.
        let ct: Vec<&str> = req
            .headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(ct.len(), 1, "exactly one Content-Type header");
        assert_eq!(ct[0], "multipart/form-data; boundary=xyz");
        // Body replaced with composed body.
        assert_eq!(req.body.as_deref(), Some(b"body".as_slice()));
    }

    #[test]
    fn apply_to_request_preserves_unrelated_headers() {
        let h = header_probe("Cookie", "x", "c.x");
        let composed = compose_artifacts(&[&h]);

        let mut req = Request::get("https://example.com/");
        req.add_header("User-Agent", "Mozilla/5.0");
        req.add_header("Accept-Language", "en-US");
        let _ = composed.apply_to_request(&mut req);

        // Both unrelated headers must survive.
        assert!(req.headers.iter().any(|(n, _)| n == "User-Agent"));
        assert!(req.headers.iter().any(|(n, _)| n == "Accept-Language"));
        assert!(req.headers.iter().any(|(n, _)| n == "Cookie"));
    }

    #[test]
    fn composed_artifact_roundtrips_through_json() {
        // Anti-rig: serde shape must stay stable. Operators pipe
        // composed artifacts to jq / Splunk / etc; a regression
        // that changed the JSON field names would break their
        // downstream tooling silently.
        let h = header_probe("Cookie", "a=1", "cookie.x");
        let b = body_probe("text/plain", b"body", "tag.b");
        let composed = compose_artifacts(&[&h, &b]);
        let json = serde_json::to_string(&composed).expect("serialize");
        let back: ComposedArtifact = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, composed);
    }

    #[test]
    fn smuggle_artifact_json_tags_kind_and_value_fields() {
        // The serde `tag = "kind", content = "value"` surface is
        // part of the public contract. Pin both fields so a
        // regression that drops either (untagged enum) breaks here.
        let a = SmuggleArtifact::Headers(vec![("X".into(), "Y".into())]);
        let json = serde_json::to_string(&a).expect("serialize");
        assert!(json.contains("\"kind\":\"headers\""), "json: {json}");
        assert!(json.contains("\"value\""), "json: {json}");

        let a = SmuggleArtifact::Frames(vec![vec![1, 2]]);
        let json = serde_json::to_string(&a).expect("serialize");
        assert!(json.contains("\"kind\":\"frames\""), "json: {json}");

        let a = SmuggleArtifact::BodyWithContentType {
            content_type: "text/plain".into(),
            body: b"abc".to_vec(),
        };
        let json = serde_json::to_string(&a).expect("serialize");
        assert!(
            json.contains("\"kind\":\"body_with_content_type\""),
            "json: {json}"
        );
        // BodyWithContentType is a struct variant — its fields go
        // inside `value`.
        assert!(json.contains("\"value\""), "json: {json}");
        assert!(json.contains("\"content_type\""), "json: {json}");
    }

    #[test]
    fn smuggle_artifact_each_variant_roundtrips_through_json() {
        // Anti-rig: every variant must serialize AND deserialize.
        // A regression that broke tuple-variant + serde-tag would
        // surface here.
        for original in [
            SmuggleArtifact::Headers(vec![
                ("Cookie".into(), "a=1".into()),
                ("Authorization".into(), "Bearer T".into()),
            ]),
            SmuggleArtifact::Frames(vec![vec![1, 2, 3], vec![4, 5]]),
            SmuggleArtifact::BodyWithContentType {
                content_type: "multipart/form-data; boundary=x".into(),
                body: b"--x\r\n\r\nhi\r\n--x--\r\n".to_vec(),
            },
        ] {
            let json = serde_json::to_string(&original).expect("serialize");
            let back: SmuggleArtifact = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, original);
        }
    }

    #[test]
    fn compose_cross_product_emits_lhs_times_rhs_artifacts() {
        let h1 = header_probe("Cookie", "a=1", "c.1");
        let h2 = header_probe("Cookie", "b=2", "c.2");
        let h3 = header_probe("Authorization", "Bearer X", "a.1");
        let lhs: Vec<Box<dyn SmuggleProbe>> = vec![Box::new(h1), Box::new(h2)];
        let rhs: Vec<Box<dyn SmuggleProbe>> = vec![Box::new(h3)];
        let cross = compose_cross_product(&lhs, &rhs);
        // 2 × 1 = 2 composed artifacts.
        assert_eq!(cross.len(), 2);
        for c in &cross {
            // Each composed has 1 from lhs + 1 from rhs = 2 headers.
            assert_eq!(c.headers.len(), 2);
            assert_eq!(c.techniques.len(), 2);
            // First technique always from lhs, second from rhs.
            assert!(c.techniques[0].starts_with("c."));
            assert!(c.techniques[1].starts_with("a."));
            // Canaries propagate 1:1 with techniques.
            assert_eq!(c.canaries.len(), 2);
            for token in &c.canaries {
                assert_eq!(token.len(), 16, "canary token must be 16 chars");
            }
        }
    }

    #[test]
    fn compose_artifacts_preserves_canaries_in_technique_order() {
        // The whole point of carrying canaries through the composer
        // is to keep OOB-callback attribution working when N probes
        // chain into one request. Pin the invariant.
        let a = header_probe("Cookie", "x", "cookie.a");
        let b = header_probe("Authorization", "Bearer y", "auth.b");
        let c = header_probe("Range", "bytes=0-1", "range.c");
        let composed = compose_artifacts(&[&a, &b, &c]);
        assert_eq!(composed.canaries.len(), 3);
        assert_eq!(composed.canaries[0], a.canary.token);
        assert_eq!(composed.canaries[1], b.canary.token);
        assert_eq!(composed.canaries[2], c.canary.token);
        // Aligned 1:1 with techniques (same order).
        assert_eq!(composed.canaries.len(), composed.techniques.len());
    }

    #[test]
    fn composed_canaries_field_omitted_from_json_when_empty() {
        // Anti-rig: skip_serializing_if = "Vec::is_empty" must keep
        // old-shape JSON consumers working — an empty canaries field
        // does NOT appear in the serialized form.
        let empty = ComposedArtifact::default();
        let json = serde_json::to_string(&empty).expect("serialize");
        assert!(
            !json.contains("\"canaries\""),
            "empty canaries must be skip-serialized: {json}"
        );
    }

    #[test]
    fn composed_artifact_roundtrips_with_canaries() {
        let a = header_probe("Cookie", "x", "cookie.a");
        let composed = compose_artifacts(&[&a]);
        let json = serde_json::to_string(&composed).expect("serialize");
        assert!(json.contains("\"canaries\""), "json: {json}");
        let back: ComposedArtifact = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, composed);
    }

    #[test]
    fn legacy_composed_json_without_canaries_field_still_loads() {
        // Backwards-compat: external JSON files written before the
        // canaries field existed must still deserialize cleanly.
        let legacy = r#"{
            "headers": [["Cookie", "a=1"]],
            "body": null,
            "frames": [],
            "techniques": ["cookie.x"]
        }"#;
        let parsed: ComposedArtifact = serde_json::from_str(legacy).expect("legacy load");
        assert_eq!(parsed.techniques, vec!["cookie.x"]);
        assert!(
            parsed.canaries.is_empty(),
            "legacy JSON without canaries field must default to empty"
        );
    }

    #[test]
    fn compose_n_product_three_families_emits_full_cartesian_product() {
        // Three families, sizes 2 × 2 × 2 = 8 composed artifacts.
        let h1 = header_probe("Cookie", "x", "cookie.a");
        let h2 = header_probe("Cookie", "y", "cookie.b");
        let a1 = header_probe("Authorization", "Bearer p", "auth.a");
        let a2 = header_probe("Authorization", "Bearer q", "auth.b");
        let r1 = header_probe("Range", "bytes=0-1", "range.a");
        let r2 = header_probe("Range", "bytes=2-3", "range.b");

        let cookies: Vec<Box<dyn SmuggleProbe>> = vec![Box::new(h1), Box::new(h2)];
        let auths: Vec<Box<dyn SmuggleProbe>> = vec![Box::new(a1), Box::new(a2)];
        let ranges: Vec<Box<dyn SmuggleProbe>> = vec![Box::new(r1), Box::new(r2)];

        let nway = compose_n_product(&[&cookies, &auths, &ranges]);
        assert_eq!(nway.len(), 8, "2 × 2 × 2 = 8");

        for c in &nway {
            // Each composed merges 3 probes -> 3 headers, 3
            // techniques, 3 canaries.
            assert_eq!(c.headers.len(), 3);
            assert_eq!(c.techniques.len(), 3);
            assert_eq!(c.canaries.len(), 3);
            // Family order is preserved: cookie -> auth -> range.
            assert!(c.techniques[0].starts_with("cookie."));
            assert!(c.techniques[1].starts_with("auth."));
            assert!(c.techniques[2].starts_with("range."));
        }
    }

    #[test]
    fn compose_n_product_empty_input_returns_empty() {
        let out = compose_n_product(&[]);
        assert!(out.is_empty());
    }

    #[test]
    fn compose_n_product_any_empty_family_yields_empty_output() {
        // Cartesian product with a 0-element factor is the empty
        // set — pin this so a regression doesn't silently emit
        // duplicates from the non-empty factor.
        let h1 = header_probe("Cookie", "x", "cookie.a");
        let nonempty: Vec<Box<dyn SmuggleProbe>> = vec![Box::new(h1)];
        let empty: Vec<Box<dyn SmuggleProbe>> = vec![];
        assert!(compose_n_product(&[&empty, &nonempty]).is_empty());
        assert!(compose_n_product(&[&nonempty, &empty]).is_empty());
        assert!(compose_n_product(&[&nonempty, &empty, &nonempty]).is_empty());
    }

    #[test]
    fn compose_n_product_single_family_emits_one_per_probe() {
        // N=1 collapses to "one composed artifact per input probe"
        // — useful as a degenerate case that surfaces the
        // composed-shape wrapper without merging anything.
        let h1 = header_probe("Cookie", "x", "cookie.a");
        let h2 = header_probe("Cookie", "y", "cookie.b");
        let h3 = header_probe("Cookie", "z", "cookie.c");
        let one: Vec<Box<dyn SmuggleProbe>> = vec![Box::new(h1), Box::new(h2), Box::new(h3)];
        let out = compose_n_product(&[&one]);
        assert_eq!(out.len(), 3);
        for c in &out {
            assert_eq!(c.techniques.len(), 1);
            assert_eq!(c.canaries.len(), 1);
        }
    }

    #[test]
    fn compose_n_product_equals_compose_cross_product_for_two_families() {
        // Anti-rig: the 2-arg cross_product MUST be byte-identical
        // to n_product with two families. A regression that
        // diverged the wrapper from the primitive would surface
        // here (techniques out of order, headers misaligned, etc.).
        let h1 = header_probe("Cookie", "x", "cookie.a");
        let h2 = header_probe("Cookie", "y", "cookie.b");
        let a1 = header_probe("Authorization", "Bearer p", "auth.a");
        let lhs: Vec<Box<dyn SmuggleProbe>> = vec![Box::new(h1), Box::new(h2)];
        let rhs: Vec<Box<dyn SmuggleProbe>> = vec![Box::new(a1)];

        let cross = compose_cross_product(&lhs, &rhs);
        let nway = compose_n_product(&[&lhs, &rhs]);
        assert_eq!(cross.len(), nway.len());
        // Both share the same probe Boxes (we borrow into both
        // calls), so every emitted ComposedArtifact must match
        // byte-for-byte — techniques, headers, body, frames,
        // canaries. Anti-rig against a regression that diverges
        // the wrapper from the primitive.
        for (a, b) in cross.iter().zip(nway.iter()) {
            assert_eq!(a, b, "cross_product must equal n_product[N=2]");
        }
    }

    #[test]
    fn compose_cross_product_empty_inputs_yield_empty_output() {
        let empty: Vec<Box<dyn SmuggleProbe>> = vec![Box::new(header_probe("X", "1", "t.x"))];
        let none: Vec<Box<dyn SmuggleProbe>> = vec![];
        assert!(compose_cross_product(&none, &empty).is_empty());
        assert!(compose_cross_product(&empty, &none).is_empty());
        assert!(compose_cross_product(&none, &none).is_empty());
    }

    #[test]
    fn apply_to_request_returns_frame_stream_for_non_http_transports() {
        // Frame artifacts (capsule, WS compression, QUIC datagram)
        // can't ride inside the Request struct — they live at a
        // lower transport layer. apply_to_request hands them back
        // to the caller untouched.
        let f = frames_probe(vec![vec![0xFF, 0xAB], vec![0x42]], "frame.x");
        let composed = compose_artifacts(&[&f]);

        let mut req = Request::get("https://example.com/");
        let frames = composed.apply_to_request(&mut req);
        assert_eq!(frames, vec![vec![0xFF, 0xAB], vec![0x42]]);
        // Request itself is otherwise untouched.
        assert!(req.headers.is_empty());
        assert!(req.body.is_none());
    }
}
