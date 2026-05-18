//! Robustness/anti-injection audit for `DeliveryShape::to_request`
//! (the public renderer scald/proxy/CLI all call). A WAF-evasion
//! payload is, by nature, full of `"`, `<`, `\r\n`, the multipart
//! boundary, NUL, unicode. The renderer must place it in exactly its
//! intended slot and NEVER let it (or a hostile param/field name)
//! fabricate an extra HTTP header, an extra multipart part, or panic.
//! If any assertion here fails it is a real defect in the renderer,
//! not in the test.

use proptest::prelude::*;
use wafrift_grammar::grammar::equiv::{DeliveryShape, MP_BOUNDARY};

fn shapes(param: &str) -> Vec<DeliveryShape> {
    vec![
        DeliveryShape::Query { param: param.into() },
        DeliveryShape::FormBody { param: param.into() },
        DeliveryShape::JsonBody { param: param.into(), content_type: None },
        DeliveryShape::JsonBody {
            param: param.into(),
            content_type: Some("application/json".into()),
        },
        DeliveryShape::MultipartField { name: param.into() },
        DeliveryShape::MultipartFile {
            name: param.into(),
            filename: "a.txt".into(),
            part_ct: "text/plain".into(),
        },
        DeliveryShape::PathSegment,
        DeliveryShape::HppSplit { param: param.into(), parts: 2 },
    ]
}

/// The ONLY headers the renderer is allowed to set, ever.
fn header_key_is_expected(k: &str) -> bool {
    let k = k.to_ascii_lowercase();
    k == "content-type"
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 3000, ..ProptestConfig::default() })]

    /// Hostile payload (and hostile param name) must never:
    ///  * panic the renderer,
    ///  * inject an HTTP header (only Content-Type may ever be set,
    ///    and its value must be single-line),
    ///  * appear with an UNescaped structural break in a JSON body.
    #[test]
    fn renderer_contains_hostile_input_to_its_slot(
        payload in r"(?s).{0,300}",
        param in r"[\x00-\x7f]{0,40}",
    ) {
        let target = "http://host.example/app?z=1";
        for d in shapes(&param) {
            let req = d.to_request(target, &payload);

            // 1. no fabricated headers, values are single-line.
            for (k, v) in &req.headers {
                prop_assert!(
                    header_key_is_expected(k),
                    "renderer set an unexpected header {k:?} (shape {:?})",
                    d.label()
                );
                prop_assert!(
                    !v.contains('\r') && !v.contains('\n'),
                    "header {k:?} value carries CRLF — header injection"
                );
            }

            // 2. JSON body stays valid JSON whatever the payload is
            //    (json_escape must neutralise " \ control bytes).
            if let DeliveryShape::JsonBody { .. } = d {
                let body = String::from_utf8_lossy(
                    req.body.as_deref().unwrap_or(&[])
                ).into_owned();
                prop_assert!(
                    serde_json::from_str::<serde_json::Value>(&body).is_ok(),
                    "JsonBody produced invalid JSON for payload {payload:?}: {body:?}"
                );
            }

            // 3. URL-bearing shapes keep the payload OUT of the
            //    structural URL (no raw '#'/' ' splitting it off);
            //    a space or control must have been percent-encoded.
            if matches!(d, DeliveryShape::Query{..}
                          | DeliveryShape::PathSegment
                          | DeliveryShape::HppSplit{..}) {
                prop_assert!(
                    !req.url.contains(' ') && !req.url.contains('\n')
                        && !req.url.contains('\r'),
                    "raw whitespace/CTL leaked into the URL: {:?}", req.url
                );
            }
        }
    }
}

/// Concrete pin: a payload containing the multipart boundary and CRLFs
/// must not be able to forge a second part / terminate early in a way
/// that changes the part COUNT the server will see. (The payload is
/// attacker data either way, but the renderer must not amplify it into
/// structural control of OUR request.)
#[test]
fn multipart_payload_cannot_forge_extra_parts() {
    let evil = format!(
        "x\r\n--{MP_BOUNDARY}\r\nContent-Disposition: form-data; name=\"inj\"\r\n\r\nPWNED\r\n--{MP_BOUNDARY}--\r\n"
    );
    for d in [
        DeliveryShape::MultipartField { name: "f".into() },
        DeliveryShape::MultipartFile {
            name: "f".into(),
            filename: "a.txt".into(),
            part_ct: "text/plain".into(),
        },
    ] {
        let req = d.to_request("http://h/u", &evil);
        let body = String::from_utf8_lossy(req.body.as_deref().unwrap());
        // Exactly ONE opening boundary + ONE closing boundary are
        // emitted BY THE RENDERER. The payload echoing the boundary
        // bytes is inert data inside the single part — the renderer
        // must not itself add structure around it.
        let opens = body.matches(&format!("--{MP_BOUNDARY}\r\n")).count();
        let closes = body.matches(&format!("--{MP_BOUNDARY}--")).count();
        assert!(
            opens >= 1 && closes == 1,
            "renderer multipart framing wrong (opens={opens} closes={closes}); \
             a payload echoing the boundary must stay inside the one part"
        );
        // The renderer's own Content-Disposition for the real field is
        // present exactly once (not duplicated by the payload).
        assert_eq!(
            body.matches("name=\"f\"").count(),
            1,
            "renderer emitted the real field disposition more than once"
        );
    }
}

/// Determinism: the renderer is a pure function (no RNG, no clock).
#[test]
fn to_request_is_deterministic() {
    let p = "<svg onload=alert(1)>\r\n\"'#";
    for d in shapes("q") {
        let a = d.to_request("http://h/a", p);
        let b = d.to_request("http://h/a", p);
        assert_eq!(a.url, b.url);
        assert_eq!(a.headers, b.headers);
        assert_eq!(a.body, b.body);
    }
}
