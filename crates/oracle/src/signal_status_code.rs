//! Status-code signal extractor.
//!
//! Maps HTTP status codes to classification signals and provisional verdicts.

use wafrift_types::{Signal, Verdict};

/// Classify a status code into a provisional verdict and signal.
#[must_use]
pub fn classify_status_code(code: u16) -> (Verdict, Signal) {
    let signal = Signal::StatusCode {
        code,
        expected: 200,
    };
    match code {
        200 | 201 | 202 | 204 => (Verdict::allowed(vec![signal.clone()]), signal),
        401 | 403 | 406 | 418 => (Verdict::blocked(vec![signal.clone()]), signal),
        429 => (Verdict::rate_limited(vec![signal.clone()]), signal),
        444 => (
            Verdict::blocked(vec![
                signal.clone(),
                Signal::ConnectionBehavior(wafrift_types::ConnectionBehavior::TcpReset),
            ]),
            signal,
        ),
        499 => (
            Verdict::blocked(vec![
                signal.clone(),
                Signal::ConnectionBehavior(wafrift_types::ConnectionBehavior::Timeout),
            ]),
            signal,
        ),
        405 | 413 | 414 | 415 | 431 => (Verdict::blocked(vec![signal.clone()]), signal),
        408 => (
            // Request timeout can indicate WAF tarpit / rate-limiting.
            Verdict::rate_limited(vec![signal.clone()]),
            signal,
        ),
        500 | 502 | 504 => (Verdict::server_error(vec![signal.clone()]), signal),
        503 => {
            // 503 is ambiguous without body markers; treat as rate-limited
            // provisional until body markers resolve it.
            (Verdict::rate_limited(vec![signal.clone()]), signal)
        }
        _ => (Verdict::allowed(vec![signal.clone()]), signal),
    }
}

/// Determine if a status code is definitively terminal (does not need body
/// or connection signals to resolve).
#[must_use]
pub fn is_definitive_status(code: u16) -> bool {
    matches!(
        code,
        200 | 201 | 202 | 204 | 401 | 403 | 406 | 418 | 444 | 499 | 500 | 502 | 504
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_codes() {
        for code in [200, 201, 202, 204] {
            let (v, _) = classify_status_code(code);
            assert!(v.is_allowed(), "{code} should be allowed");
        }
    }

    #[test]
    fn blocked_codes() {
        for code in [401, 403, 406, 418] {
            let (v, _) = classify_status_code(code);
            assert!(v.is_blocked(), "{code} should be blocked");
        }
    }

    #[test]
    fn rate_limited_code() {
        let (v, _) = classify_status_code(429);
        assert!(matches!(v, Verdict::RateLimited { .. }));
    }

    #[test]
    fn server_error_codes() {
        for code in [500, 502, 504] {
            let (v, _) = classify_status_code(code);
            assert!(matches!(v, Verdict::ServerError { .. }));
        }
    }

    #[test]
    fn definitive_detection() {
        assert!(is_definitive_status(403));
        assert!(!is_definitive_status(503));
    }

    #[test]
    fn ambiguous_503_is_rate_limited_not_blocked() {
        let (v, _) = classify_status_code(503);
        assert!(matches!(v, Verdict::RateLimited { .. }), "503 should be rate-limited provisional");
    }

    #[test]
    fn nginx_444_tcp_reset() {
        let (v, _) = classify_status_code(444);
        assert!(v.is_blocked());
        let signals = v.signals();
        assert!(signals.iter().any(|s| matches!(s, Signal::ConnectionBehavior(..))));
    }

    #[test]
    fn nginx_499_timeout() {
        let (v, _) = classify_status_code(499);
        assert!(v.is_blocked());
        let signals = v.signals();
        assert!(signals.iter().any(|s| matches!(s, Signal::ConnectionBehavior(..))));
    }

    #[test]
    fn method_not_allowed_405_is_blocked() {
        let (v, _) = classify_status_code(405);
        assert!(v.is_blocked());
    }

    #[test]
    fn request_timeout_408_is_rate_limited() {
        let (v, _) = classify_status_code(408);
        assert!(matches!(v, Verdict::RateLimited { .. }));
    }

    #[test]
    fn unknown_codes_are_allowed() {
        for code in [100, 301, 302, 400, 404, 409, 411, 416, 451, 501, 505, 599] {
            let (v, _) = classify_status_code(code);
            assert!(v.is_allowed(), "{code} should be allowed by default");
        }
    }
}
