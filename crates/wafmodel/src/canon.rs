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
        let is_form = req
            .content_type()
            .is_some_and(|ct| ct.starts_with("application/x-www-form-urlencoded"));
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
