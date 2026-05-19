//! Truth contract for request canonicalization.
//!
//! Every assertion names exact channels and exact bytes, and every
//! positive has a sanitized negative twin. A test here that would still
//! pass if `canonicalize` returned `CanonView { method, segments: vec![] }`
//! is forbidden by construction — each checks specific extracted bytes.

use wafrift_types::Request;
use wafrift_wafmodel::{Channel, canonicalize};

fn seg(view: &wafrift_wafmodel::CanonView, ch: Channel) -> Vec<Vec<u8>> {
    view.channel(ch).into_iter().map(<[u8]>::to_vec).collect()
}

#[test]
fn query_args_split_into_exact_name_value_segments() {
    let r = Request::get("https://t.example/app?q=hello&x=1");
    let v = canonicalize(&r);

    assert_eq!(v.method, "GET");
    assert_eq!(seg(&v, Channel::Path), vec![b"/app".to_vec()]);
    assert_eq!(
        seg(&v, Channel::ArgName),
        vec![b"q".to_vec(), b"x".to_vec()]
    );
    assert_eq!(
        seg(&v, Channel::ArgValue),
        vec![b"hello".to_vec(), b"1".to_vec()]
    );

    // Negative twin: no query string ⇒ exactly one Path segment and
    // ZERO arg segments (no phantom empty value).
    let r2 = Request::get("https://t.example/app");
    let v2 = canonicalize(&r2);
    assert_eq!(seg(&v2, Channel::Path), vec![b"/app".to_vec()]);
    assert!(seg(&v2, Channel::ArgName).is_empty());
    assert!(seg(&v2, Channel::ArgValue).is_empty());
}

#[test]
fn raw_bytes_are_preserved_without_decoding() {
    // The single most important invariant: the WAF view is the bytes
    // ON THE WIRE, never decoded here. P2's whole normalization-
    // mismatch solver depends on this not lying.
    let r = Request::get("https://t.example/p?inp=%3Cscript%3Ealert(1)%3C%2Fscript%3E");
    let v = canonicalize(&r);
    assert_eq!(
        seg(&v, Channel::ArgValue),
        vec![b"%3Cscript%3Ealert(1)%3C%2Fscript%3E".to_vec()],
        "canonicalize MUST NOT url-decode — that is a transducer concern"
    );
    // Negative twin: the decoded form must NOT appear anywhere.
    assert!(
        !v.segments
            .iter()
            .any(|s| s.bytes.windows(8).any(|w| w == b"<script>")),
        "decoded payload leaked into the canonical view (rig risk)"
    );
}

#[test]
fn cookie_header_is_broken_out_non_cookie_header_is_not() {
    let r = Request::get("https://t.example/")
        .header("Cookie", "sid=abc; role=admin")
        .header("X-Api-Key", "k=secret; not-a-cookie");
    let v = canonicalize(&r);

    assert_eq!(
        seg(&v, Channel::CookieName),
        vec![b"sid".to_vec(), b"role".to_vec()]
    );
    assert_eq!(
        seg(&v, Channel::CookieValue),
        vec![b"abc".to_vec(), b"admin".to_vec()]
    );
    // Negative twin: the non-cookie header is NOT split on `;`/`=`; it
    // stays a single header name/value pair verbatim.
    assert_eq!(seg(&v, Channel::HeaderName), vec![b"X-Api-Key".to_vec()]);
    assert_eq!(
        seg(&v, Channel::HeaderValue),
        vec![b"k=secret; not-a-cookie".to_vec()]
    );
    assert!(
        !seg(&v, Channel::CookieName).contains(&b"k".to_vec()),
        "non-cookie header must not bleed into the cookie channel"
    );
}

#[test]
fn form_body_splits_but_json_body_stays_opaque() {
    let form = Request::post(
        "https://t.example/login",
        b"user=admin&pw=%27OR%271".to_vec(),
    )
    .header("Content-Type", "application/x-www-form-urlencoded");
    let v = canonicalize(&form);
    assert_eq!(
        seg(&v, Channel::ArgName),
        vec![b"user".to_vec(), b"pw".to_vec()]
    );
    assert_eq!(
        seg(&v, Channel::ArgValue),
        vec![b"admin".to_vec(), b"%27OR%271".to_vec()]
    );
    assert!(seg(&v, Channel::Body).is_empty());

    // Negative twin: identical bytes, JSON content-type ⇒ ONE opaque
    // Body segment, NOT mis-parsed into args (JSON sub-extraction is a
    // transducer concern, never canonicalization).
    let json = Request::post(
        "https://t.example/login",
        b"user=admin&pw=%27OR%271".to_vec(),
    )
    .header("Content-Type", "application/json");
    let vj = canonicalize(&json);
    assert_eq!(
        seg(&vj, Channel::Body),
        vec![b"user=admin&pw=%27OR%271".to_vec()]
    );
    assert!(seg(&vj, Channel::ArgName).is_empty());
    assert!(seg(&vj, Channel::ArgValue).is_empty());
}

#[test]
fn path_strips_authority_query_and_fragment_exactly() {
    let r = Request::get("https://user:pw@host:8443/a/b/c?d=e#frag");
    let v = canonicalize(&r);
    assert_eq!(seg(&v, Channel::Path), vec![b"/a/b/c".to_vec()]);
    // The fragment must not contaminate the last arg value.
    assert_eq!(seg(&v, Channel::ArgValue), vec![b"e".to_vec()]);
    // total_bytes accounts for every attacker byte: /a/b/c (6) + d (1) + e (1)
    assert_eq!(v.total_bytes(), 8);
}

#[test]
fn edge_shapes_are_total_not_dropped() {
    // Bare param (no `=`), leading `=` (empty name), trailing `&`.
    let r = Request::get("https://t/p?flag&=v&k=&");
    let v = canonicalize(&r);
    assert_eq!(
        seg(&v, Channel::ArgName),
        vec![b"flag".to_vec(), b"".to_vec(), b"k".to_vec(), b"".to_vec()]
    );
    assert_eq!(
        seg(&v, Channel::ArgValue),
        vec![b"".to_vec(), b"v".to_vec(), b"".to_vec(), b"".to_vec()]
    );
}
