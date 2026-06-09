//! Canonicalize a [`wafrift_types::Request`] into the ordered set of
//! byte-segments a CRS-class WAF actually inspects.
//!
//! ModSecurity / Coraza CRS does not match against "the request" — it
//! matches against *variables*: `REQUEST_URI`, `ARGS` / `ARGS_NAMES`,
//! `REQUEST_HEADERS`, `REQUEST_COOKIES`, `REQUEST_BODY`. Each is a
//! distinct inspection channel with its own rule coverage (this is the
//! whole reason delivery-shape beats payload-string evasion: the same
//! bytes land in a *less-covered* channel).
//!
//! This module extracts the **raw on-the-wire bytes per channel**. It
//! deliberately does *not* apply CRS transformations
//! (`t:urlDecodeUni`, `t:htmlEntityDecode`, …) — that decoding layer is
//! the job of the pipeline transducers (P2), and keeping the raw view
//! separate is exactly what lets the composition solver discover
//! WAF↔origin normalization mismatches. Extraction here is total and
//! lossless: every byte the client sent is attributed to exactly one
//! channel segment.

use wafrift_types::Request;

/// A CRS inspection channel. Mirrors the ModSecurity variable families
/// that carry attacker-controlled bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Channel {
    /// The request path (`REQUEST_FILENAME` / path part of `REQUEST_URI`).
    Path,
    /// A query- or body-parameter *name* (`ARGS_NAMES`).
    ArgName,
    /// A query- or body-parameter *value* (`ARGS`).
    ArgValue,
    /// A request header name (`REQUEST_HEADERS_NAMES`).
    HeaderName,
    /// A request header value (`REQUEST_HEADERS`).
    HeaderValue,
    /// A cookie name (`REQUEST_COOKIES_NAMES`).
    CookieName,
    /// A cookie value (`REQUEST_COOKIES`).
    CookieValue,
    /// The raw request body when it is not form-decodable
    /// (`REQUEST_BODY` — JSON / multipart / opaque). Structured
    /// sub-extraction is a transducer concern (P2), not canonicalization.
    Body,
}

/// One inspectable unit: which channel it lands in and its raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// The CRS channel this segment is matched under.
    pub channel: Channel,
    /// Raw bytes exactly as they appear on the wire (no decoding).
    pub bytes: Vec<u8>,
}

/// The full per-channel view of a request, in stable wire order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonView {
    /// Request method, uppercased (CRS matches `REQUEST_METHOD` case-insensitively).
    pub method: String,
    /// Every attacker-controlled segment, in extraction order.
    pub segments: Vec<Segment>,
}

impl CanonView {
    /// All segments that land in `channel`, in order.
    #[must_use]
    pub fn channel(&self, channel: Channel) -> Vec<&[u8]> {
        self.segments
            .iter()
            .filter(|s| s.channel == channel)
            .map(|s| s.bytes.as_slice())
            .collect()
    }

    /// Total attacker-controlled bytes across all channels — used by
    /// the learner's alphabet sizing and by perf gates.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.segments.iter().map(|s| s.bytes.len()).sum()
    }
}

/// Split a `name=value&name2=value2` string into raw `(name, value)`
/// pairs without decoding. A bare `name` (no `=`) yields an empty
/// value; a leading `=` yields an empty name — both are real shapes a
/// WAF must classify, so neither is silently dropped.
fn split_form(raw: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    if raw.is_empty() {
        return Vec::new();
    }
    raw.split(|&b| b == b'&')
        .map(|pair| match pair.iter().position(|&b| b == b'=') {
            Some(i) => (pair[..i].to_vec(), pair[i + 1..].to_vec()),
            None => (pair.to_vec(), Vec::new()),
        })
        .collect()
}

/// Parse a `Cookie:` header value into raw `(name, value)` pairs.
/// `a=1; b=2` — split on `;`, trim one optional leading space (RFC
/// 6265 `cookie-string` uses `"; "` as the separator), then split the
/// first `=`.
fn split_cookies(raw: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    raw.split(';')
        .filter_map(|c| {
            let c = c.strip_prefix(' ').unwrap_or(c);
            if c.is_empty() {
                return None;
            }
            let cb = c.as_bytes();
            Some(match c.find('=') {
                Some(i) => (cb[..i].to_vec(), cb[i + 1..].to_vec()),
                None => (cb.to_vec(), Vec::new()),
            })
        })
        .collect()
}

/// Extract the canonical per-channel view a CRS-class WAF inspects.
///
/// Lossless and total: path, every query arg name+value, every header
/// name+value (cookies broken out of the `Cookie` header into
/// cookie-name/cookie-value channels), and the body — form-urlencoded
/// bodies are broken into arg pairs (CRS does this via
/// `REQUEST_BODY_PROCESSOR=URLENCODED`), everything else is one opaque
/// `Body` segment.
#[must_use]
pub fn canonicalize(req: &Request) -> CanonView {
    let mut segments = Vec::new();

    // ── REQUEST_URI: path + query ──────────────────────────────────
    let url = req.url();
    // Strip scheme://authority so `Path` is the origin-form path. A
    // URL with no scheme is treated as already origin-form.
    let after_authority = match url.find("://") {
        Some(s) => {
            let rest = &url[s + 3..];
            rest.find('/').map_or("/", |p| &rest[p..])
        }
        None => url,
    };
    let (path, query) = match after_authority.find('?') {
        Some(q) => (&after_authority[..q], Some(&after_authority[q + 1..])),
        None => (after_authority, None),
    };
    let path = path.split('#').next().unwrap_or(path);
    segments.push(Segment {
        channel: Channel::Path,
        bytes: path.as_bytes().to_vec(),
    });
    if let Some(q) = query {
        let q = q.split('#').next().unwrap_or(q);
        for (n, v) in split_form(q.as_bytes()) {
            segments.push(Segment {
                channel: Channel::ArgName,
                bytes: n,
            });
            segments.push(Segment {
                channel: Channel::ArgValue,
                bytes: v,
            });
        }
    }

    // ── REQUEST_HEADERS / REQUEST_COOKIES ──────────────────────────
    for (name, value) in req.headers() {
        if name.eq_ignore_ascii_case("cookie") {
            for (cn, cv) in split_cookies(value) {
                segments.push(Segment {
                    channel: Channel::CookieName,
                    bytes: cn,
                });
                segments.push(Segment {
                    channel: Channel::CookieValue,
                    bytes: cv,
                });
            }
        } else {
            segments.push(Segment {
                channel: Channel::HeaderName,
                bytes: name.as_bytes().to_vec(),
            });
            segments.push(Segment {
                channel: Channel::HeaderValue,
                bytes: value.as_bytes().to_vec(),
            });
        }
    }

    // ── REQUEST_BODY ───────────────────────────────────────────────
    if let Some(body) = req.body_bytes() {
        // F131: Content-Type matching is case-insensitive per RFC
        // 7231 §3.1.1.1 (`type/subtype` tokens are case-insensitive,
        // parameters case-sensitive). Pre-fix used a case-sensitive
        // `starts_with` and a request with
        // `Content-Type: Application/X-WWW-Form-URLencoded` got
        // canonicalized as opaque Body — but CRS / Coraza / ModSec
        // DO normalize the type and would treat that same request
        // as URL-encoded form. The SFA learner then sees a different
        // inspection channel than the live WAF and any bypass it
        // mines is unsound. Compare the type/subtype slice with
        // eq_ignore_ascii_case to match WAF behavior.
        let is_form = req.content_type().is_some_and(|ct| {
            let type_subtype = ct.split(';').next().unwrap_or(ct).trim();
            type_subtype.eq_ignore_ascii_case("application/x-www-form-urlencoded")
        });
        if is_form {
            for (n, v) in split_form(body) {
                segments.push(Segment {
                    channel: Channel::ArgName,
                    bytes: n,
                });
                segments.push(Segment {
                    channel: Channel::ArgValue,
                    bytes: v,
                });
            }
        } else {
            segments.push(Segment {
                channel: Channel::Body,
                bytes: body.to_vec(),
            });
        }
    }

    CanonView {
        method: req.method().as_str().to_ascii_uppercase(),
        segments,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wafrift_types::Request;

    fn req_with_content_type(ct: &str, body: &[u8]) -> Request {
        let mut r = Request::post("http://t/", body.to_vec());
        r.headers_mut().push(("Content-Type".into(), ct.into()));
        r
    }

    // F131 regression: Content-Type is case-insensitive per RFC 7231.
    // The pre-fix `starts_with("application/x-www-form-urlencoded")`
    // was case-sensitive — requests with mixed-case content type were
    // canonicalized as opaque Body even though every CRS-class WAF
    // (ModSecurity, Coraza) would have treated them as form-decoded
    // ARGS. Any SFA learned against the mismatched view is unsound.

    #[test]
    fn form_body_with_lowercase_content_type_splits_into_args() {
        let r = req_with_content_type("application/x-www-form-urlencoded", b"a=1&b=2");
        let view = canonicalize(&r);
        // ArgName segments should be ["a", "b"], ArgValue ["1", "2"].
        let names: Vec<_> = view
            .channel(Channel::ArgName)
            .iter()
            .map(|b| std::str::from_utf8(b).unwrap().to_string())
            .collect();
        assert_eq!(names, vec!["a", "b"]);
    }

    #[test]
    fn form_body_with_mixed_case_content_type_still_splits_into_args() {
        // The F131 case: capital Application/X-WWW-Form-URLencoded.
        let r = req_with_content_type("Application/X-WWW-Form-URLencoded", b"a=1&b=2");
        let view = canonicalize(&r);
        let names: Vec<_> = view
            .channel(Channel::ArgName)
            .iter()
            .map(|b| std::str::from_utf8(b).unwrap().to_string())
            .collect();
        assert_eq!(
            names,
            vec!["a", "b"],
            "mixed-case content type must still parse as form per RFC 7231 §3.1.1.1"
        );
        // And the Body channel must be empty — we did NOT also dump
        // the bytes there.
        assert!(view.channel(Channel::Body).is_empty());
    }

    #[test]
    fn form_body_with_uppercase_content_type_still_splits_into_args() {
        let r = req_with_content_type("APPLICATION/X-WWW-FORM-URLENCODED", b"x=y");
        let view = canonicalize(&r);
        assert_eq!(view.channel(Channel::ArgName)[0], b"x");
        assert_eq!(view.channel(Channel::ArgValue)[0], b"y");
    }

    #[test]
    fn form_body_with_charset_parameter_splits_into_args() {
        // Parameters after `;` are case-sensitive (per RFC) but
        // shouldn't affect type/subtype matching.
        let r = req_with_content_type("application/x-www-form-urlencoded; charset=UTF-8", b"k=v");
        let view = canonicalize(&r);
        assert_eq!(view.channel(Channel::ArgName)[0], b"k");
    }

    #[test]
    fn json_body_does_not_split_into_args() {
        let r = req_with_content_type("application/json", br#"{"a":1}"#);
        let view = canonicalize(&r);
        assert!(view.channel(Channel::ArgName).is_empty());
        assert_eq!(view.channel(Channel::Body)[0], br#"{"a":1}"#);
    }

    #[test]
    fn form_body_with_unrelated_subtype_does_not_split() {
        // application/x-www-form-urlencoded-NOT-REALLY shouldn't
        // pass — the eq_ignore_ascii_case is on the whole token, not
        // a starts_with.
        let r = req_with_content_type("application/x-www-form-urlencoded-extra", b"a=1");
        let view = canonicalize(&r);
        assert!(view.channel(Channel::ArgName).is_empty());
        assert_eq!(view.channel(Channel::Body)[0], b"a=1");
    }
}
