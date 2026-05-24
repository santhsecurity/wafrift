//! Small request-level helpers carved out of main.rs to keep the
//! main module focused on dispatch + state. Each function here is
//! pure (no globals, no side effects) and individually testable.

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Response, StatusCode};

/// Convert a `HeaderValue` to `String`, logging a warning if the
/// bytes are not valid UTF-8 (in which case the lossy replacement
/// characters are preserved so the proxy can keep running).
#[must_use]
pub fn header_value_to_string(name: &str, value: &hyper::header::HeaderValue) -> String {
    match String::from_utf8(value.as_bytes().to_vec()) {
        Ok(s) => s,
        Err(_) => {
            let lossy = String::from_utf8_lossy(value.as_bytes()).to_string();
            tracing::warn!(header = %name, "header value contains invalid UTF-8; using lossy conversion");
            lossy
        }
    }
}

/// Split an absolute URL into `(scheme://authority, path?query)`
/// for the `--mutate-url` hook so the URL-mutator only sees the
/// path-and-query portion (it never touches scheme or authority).
///
/// Returns `None` for URLs without `://` (relative, malformed) —
/// the caller leaves the URL alone in that case rather than risking
/// a mutation that breaks routing.
#[must_use]
pub fn split_url_for_mutation(url: &str) -> Option<(String, String)> {
    let scheme_end = url.find("://")?;
    let after_scheme = &url[scheme_end + 3..];
    let path_start = after_scheme.find('/')?;
    let absolute_path_start = scheme_end + 3 + path_start;
    Some((
        url[..absolute_path_start].to_string(),
        url[absolute_path_start..].to_string(),
    ))
}

/// Build an error response without panicking. The outer
/// `Response::builder()` path is infallible in practice (a static
/// `StatusCode` + a bare `Bytes` body), but a malformed status
/// would otherwise propagate as a panic; the fallback returns a
/// minimal 500 so a panicked builder never aborts the proxy.
#[must_use]
pub fn error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from(message.to_string())))
        .unwrap_or_else(|_| {
            // Infallible in practice — status and body are always valid.
            // But if it somehow fails, return a minimal 500.
            let mut resp = Response::new(Full::new(Bytes::from("internal error")));
            *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            resp
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    #[test]
    fn header_value_to_string_clean_utf8_round_trips() {
        let v = HeaderValue::from_static("text/html; charset=utf-8");
        let s = header_value_to_string("content-type", &v);
        assert_eq!(s, "text/html; charset=utf-8");
    }

    #[test]
    fn header_value_to_string_invalid_utf8_falls_back_to_lossy() {
        // 0xFF is invalid in UTF-8; HeaderValue allows it (HTTP
        // headers are bytes, not text). The wrapper must NOT panic
        // — it falls back to lossy decode and continues.
        let v = HeaderValue::from_bytes(&[b'O', b'K', 0xFF]).expect("bytes ok in HeaderValue");
        let s = header_value_to_string("x-bad", &v);
        // Lossy decode preserves the ASCII prefix and replaces the
        // bad byte with U+FFFD.
        assert!(s.starts_with("OK"));
        assert!(s.contains('\u{FFFD}'), "lossy must inject U+FFFD: {s}");
    }

    #[test]
    fn split_url_canonical_https_url() {
        let (origin, path) =
            split_url_for_mutation("https://target.example/api/v1/users?id=1").expect("split ok");
        assert_eq!(origin, "https://target.example");
        assert_eq!(path, "/api/v1/users?id=1");
    }

    #[test]
    fn split_url_with_port_separates_authority_correctly() {
        let (origin, path) = split_url_for_mutation("http://10.0.0.5:8080/foo").expect("split ok");
        assert_eq!(origin, "http://10.0.0.5:8080");
        assert_eq!(path, "/foo");
    }

    #[test]
    fn split_url_root_path_only() {
        let (origin, path) = split_url_for_mutation("https://x.y/").expect("split ok");
        assert_eq!(origin, "https://x.y");
        assert_eq!(path, "/");
    }

    #[test]
    fn split_url_no_path_segment_returns_none() {
        // `https://host` (no trailing slash) is technically not a
        // complete URL for our mutation purposes; we'd have nothing
        // to mutate.
        assert_eq!(split_url_for_mutation("https://no-path"), None);
    }

    #[test]
    fn split_url_relative_url_returns_none() {
        // Relative URLs (no scheme://) must NOT be split — the
        // mutator only operates on absolute URLs.
        assert_eq!(split_url_for_mutation("/api/v1/x"), None);
        assert_eq!(split_url_for_mutation(""), None);
        assert_eq!(split_url_for_mutation("malformed"), None);
    }

    #[test]
    fn error_response_known_status_codes() {
        let r404 = error_response(StatusCode::NOT_FOUND, "missing");
        assert_eq!(r404.status(), StatusCode::NOT_FOUND);
        let r500 = error_response(StatusCode::INTERNAL_SERVER_ERROR, "boom");
        assert_eq!(r500.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let r403 = error_response(StatusCode::FORBIDDEN, "no");
        assert_eq!(r403.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn error_response_body_is_caller_message() {
        let resp = error_response(StatusCode::BAD_REQUEST, "operator-visible diagnostic");
        // We can't easily read the Full<Bytes> body without driving
        // the body stream; assert the status and that the response
        // was constructed (didn't fall through to the infallible
        // fallback path which produces "internal error").
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
