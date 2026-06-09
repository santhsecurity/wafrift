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
        // Catch-all: be conservative. Unknown 4xx codes are more likely to be
        // WAF blocks than benign responses; unknown 5xx are server errors.
        // 1xx/2xx/3xx that weren't matched above are treated as allowed.
        other => {
            let verdict = if (400..=499).contains(&other) {
                Verdict::blocked(vec![signal.clone()])
            } else if (500..=599).contains(&other) {
                Verdict::server_error(vec![signal.clone()])
            } else {
                Verdict::allowed(vec![signal.clone()])
            };
            (verdict, signal)
        }
    }
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
    fn ambiguous_503_is_rate_limited_not_blocked() {
        let (v, _) = classify_status_code(503);
        assert!(
            matches!(v, Verdict::RateLimited { .. }),
            "503 should be rate-limited provisional"
        );
    }

    #[test]
    fn nginx_444_tcp_reset() {
        let (v, _) = classify_status_code(444);
        assert!(v.is_blocked());
        let signals = v.signals();
        assert!(
            signals
                .iter()
                .any(|s| matches!(s, Signal::ConnectionBehavior(..)))
        );
    }

    #[test]
    fn nginx_499_timeout() {
        let (v, _) = classify_status_code(499);
        assert!(v.is_blocked());
        let signals = v.signals();
        assert!(
            signals
                .iter()
                .any(|s| matches!(s, Signal::ConnectionBehavior(..)))
        );
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
    fn unknown_2xx_and_3xx_are_allowed() {
        for code in [100, 301, 302, 303, 307] {
            let (v, _) = classify_status_code(code);
            assert!(v.is_allowed(), "{code} should be allowed");
        }
    }

    #[test]
    fn unknown_4xx_are_blocked() {
        for code in [400, 404, 409, 411, 416, 451] {
            let (v, _) = classify_status_code(code);
            assert!(v.is_blocked(), "{code} should be blocked (unknown 4xx)");
        }
    }

    #[test]
    fn unknown_5xx_are_server_error() {
        for code in [501, 505, 599] {
            let (v, _) = classify_status_code(code);
            assert!(
                matches!(v, Verdict::ServerError { .. }),
                "{code} should be server_error"
            );
        }
    }

    // -- §12 boundary tests -------------------------------------------------

    #[test]
    fn boundary_exactly_400_is_blocked() {
        // 400 is not in the explicit match arm but falls in 400..=499
        // catch-all, so it must be blocked.
        let (v, _) = classify_status_code(400);
        assert!(v.is_blocked(), "400 must be classified as blocked");
    }

    #[test]
    fn boundary_exactly_499_is_blocked() {
        let (v, _) = classify_status_code(499);
        // 499 is explicitly handled as blocked + Timeout signal
        assert!(v.is_blocked(), "499 must be classified as blocked");
    }

    #[test]
    fn boundary_exactly_500_is_server_error() {
        let (v, _) = classify_status_code(500);
        assert!(
            matches!(v, Verdict::ServerError { .. }),
            "500 must be server_error"
        );
    }

    #[test]
    fn boundary_exactly_599_is_server_error() {
        let (v, _) = classify_status_code(599);
        assert!(
            matches!(v, Verdict::ServerError { .. }),
            "599 must be server_error"
        );
    }

    #[test]
    fn boundary_exactly_600_is_allowed_catch_all() {
        // 600 falls outside 400..=499 and 500..=599, so it becomes
        // the last catch-all branch (allowed). Pin this so a future
        // re-ordering of the match arms doesn't silently change the
        // semantics.
        let (v, _) = classify_status_code(600);
        assert!(v.is_allowed(), "600 must fall through to allowed catch-all");
    }

    #[test]
    fn signal_carries_the_original_status_code() {
        // The signal must embed the exact code that was classified,
        // not a normalized or rounded value.
        let (_, sig) = classify_status_code(418);
        match sig {
            Signal::StatusCode { code, .. } => {
                assert_eq!(code, 418, "signal must carry code=418");
            }
            other => panic!("unexpected signal: {other:?}"),
        }
    }

    #[test]
    fn signal_expected_is_always_200() {
        // `expected` is pinned at 200 for all status codes so the
        // operator sees "I expected 200, got 418" in reports.
        let (_, sig) = classify_status_code(418);
        match sig {
            Signal::StatusCode { expected, .. } => {
                assert_eq!(expected, 200, "expected must be 200");
            }
            other => panic!("unexpected signal: {other:?}"),
        }
    }
}
