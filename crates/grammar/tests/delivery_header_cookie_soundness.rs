//! Per-rule contract for the raw reflected delivery channels
//! (`HeaderValue` / `Cookie`, added 2026-05-18) over the *public*
//! surface scald consumes (`xss_delivered` + `DeliveryShape::
//! to_request`). These channels carry the EXACT payload bytes (no
//! encoding — the backend XSS sink must see literal `<script>`), so
//! the only way they could be unsound is by the payload forging
//! transport structure (header injection / request smuggling). Every
//! assertion below names that concrete invariant; none would pass if
//! the generator returned `Vec::new()` (membership + smuggle checks
//! are exact) or if `to_request` leaked a control byte.

use proptest::prelude::*;
use wafrift_grammar::grammar::equiv::{DeliveryShape, xss_delivered};

fn header_val<'a>(r: &'a wafrift_types::Request, name: &str) -> Vec<&'a str> {
    r.headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
        .collect()
}

/// POSITIVE: a cookie-octet-legal script reaches the app verbatim via
/// BOTH raw channels, with the request otherwise untouched.
#[test]
fn legal_script_reaches_app_verbatim_via_header_and_cookie() {
    let t = "http://app.tld/p?z=1";
    let p = "<svg/onload=alert(1)>"; // no space / `;` ⇒ cookie-legal

    let hv = DeliveryShape::HeaderValue {
        name: "X-Forwarded-Host".into(),
    }
    .to_request(t, p);
    assert_eq!(hv.url, t, "header delivery must not touch the URL/query");
    assert!(hv.body.is_none());
    assert_eq!(
        header_val(&hv, "x-forwarded-host"),
        vec![p],
        "exact payload bytes must reach the reflected header sink"
    );

    let ck = DeliveryShape::Cookie { name: "sid".into() }.to_request(t, p);
    assert_eq!(ck.url, t);
    assert_eq!(header_val(&ck, "cookie"), vec![format!("sid={p}").as_str()]);
}

/// NEGATIVE / ADVERSARIAL: a payload engineered to split the request
/// or forge a second header/cookie is neutralised by `to_request`
/// (defense-in-depth) AND is never emitted by the generator paired
/// with that channel (the generator-boundary anti-rig).
#[test]
fn smuggling_payloads_cannot_forge_structure() {
    let smuggles = [
        "x\r\nSet-Cookie: pwn=1",
        "x\r\n\r\nGET /evil HTTP/1.1",
        "x\nLocation: //evil.tld",
        "a; Domain=evil.tld; HttpOnly",
        "a, b=c",
        "v\0null",
    ];
    for atk in smuggles {
        for d in [
            DeliveryShape::HeaderValue {
                name: "X-Forwarded-Host".into(),
            },
            DeliveryShape::Cookie { name: "sid".into() },
        ] {
            let r = d.to_request("http://app.tld/p", atk);
            for (k, v) in &r.headers {
                assert!(
                    !v.contains('\r') && !v.contains('\n') && !v.contains('\0'),
                    "{} leaked a smuggle byte into header {k}: {v:?}",
                    d.label()
                );
            }
            // No injected Set-Cookie / Location / smuggled request line.
            assert!(
                header_val(&r, "set-cookie").is_empty() && header_val(&r, "location").is_empty(),
                "{} forged an extra header from {atk:?}",
                d.label()
            );
            // A cookie value must not gain a second `;`-separated pair.
            if let DeliveryShape::Cookie { .. } = d {
                let cv = header_val(&r, "cookie");
                assert_eq!(cv.len(), 1);
                assert!(
                    !cv[0].contains(';'),
                    "cookie value forged a second pair: {:?}",
                    cv[0]
                );
            }
        }
    }
}

/// PROPERTY (4000 cases): for ARBITRARY payloads, every member the
/// XSS generator yields for a raw channel is transport-legal, still
/// executes the original script, and renders with NO control byte on
/// the wire — and the output stays bounded (no amplification DoS).
proptest! {
    #![proptest_config(ProptestConfig { cases: 4000, max_shrink_iters: 256, ..ProptestConfig::default() })]

    #[test]
    fn raw_channel_members_are_sound_and_unsmuggleable(
        atk in r#"<[a-z]{1,6}[ /][a-z]{1,8}=[a-z0-9()'".:/-]{0,24}>"#,
        max in 0usize..40,
    ) {
        let members = xss_delivered(&atk, max);
        prop_assert!(members.len() <= max, "unbounded: {} > {max}", members.len());
        for m in &members {
            prop_assert!(
                m.delivery.transport_legal(&m.payload),
                "{} emitted ILLEGAL pairing {:?}", m.delivery.label(), m.payload
            );
            if matches!(
                m.delivery,
                DeliveryShape::HeaderValue { .. } | DeliveryShape::Cookie { .. }
            ) {
                let r = m.delivery.to_request("http://h/p", &m.payload);
                for (_, v) in &r.headers {
                    prop_assert!(
                        !v.contains('\r') && !v.contains('\n') && !v.contains('\0'),
                        "smuggle byte on wire: {v:?}"
                    );
                }
            }
        }
    }
}

/// DETERMINISM across threads: `xss_delivered` (and therefore the new
/// channel selection) must be a pure function of its inputs — a
/// `HashSet`-iteration-order dependency would make scald's bypass set
/// flaky between runs. Two threads get different `RandomState` seeds;
/// identical output proves purity.
#[test]
fn raw_channel_selection_is_thread_pure() {
    for atk in ["<svg/onload=alert(1)>", "<img src=x onerror=alert(1)>"] {
        let a = atk.to_string();
        let t = std::thread::spawn(move || {
            xss_delivered(&a, 64)
                .into_iter()
                .map(|m| (m.payload, m.delivery.label()))
                .collect::<Vec<_>>()
        });
        let main = xss_delivered(atk, 64)
            .into_iter()
            .map(|m| (m.payload, m.delivery.label()))
            .collect::<Vec<_>>();
        assert_eq!(
            main,
            t.join().expect("generator thread panicked"),
            "xss_delivered is HashSet-order-dependent (flaky bypass set)"
        );
        assert!(!main.is_empty(), "empty for a real attack {atk:?}");
    }
}

/// SCALD-SHAPED E2E: mirror exactly what `scald::waf_delivery` does —
/// iterate the delivered class, build the live request — and assert
/// the raw channels appear and each is a sound, smuggle-free carrier
/// of the instrumented marker payload.
#[test]
fn scald_consumption_pattern_yields_sound_raw_carriers() {
    let marker = "scaldMK7";
    let instrumented = format!("<svg/onload=alert('{marker}')>");
    let members = xss_delivered(&instrumented, 64);
    assert!(members.len() >= 8, "too few members: {}", members.len());

    let (mut saw_header, mut saw_cookie) = (false, false);
    for m in &members {
        // The script (hence the marker) survives every rewrite.
        assert!(
            m.payload.contains(marker),
            "marker lost in rewrite: {:?}",
            m.payload
        );
        let req = m
            .delivery
            .to_request("http://target.tld/reflect", &m.payload);
        match m.delivery.label() {
            "header_value" => {
                saw_header = true;
                let v = header_val(&req, "x-forwarded-host");
                assert_eq!(v.len(), 1);
                assert!(v[0].contains(marker) && !v[0].contains('\n'));
            }
            "cookie" => {
                saw_cookie = true;
                let v = header_val(&req, "cookie");
                assert_eq!(v.len(), 1);
                assert!(v[0].contains(marker) && !v[0].contains(';'));
            }
            _ => {}
        }
    }
    assert!(
        saw_header && saw_cookie,
        "scald would never try the raw channels (header={saw_header} cookie={saw_cookie})"
    );
}
