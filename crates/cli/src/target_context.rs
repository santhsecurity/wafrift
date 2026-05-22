//! Target-context applicability for evasion techniques.
//!
//! WAF evasion behaves very differently depending on where the payload
//! lands: a base64 blob in a header is normal, gzip in a query string is
//! meaningless, NUL bytes are stripped by header parsers, etc. This
//! module captures those rules so `--target-context` can filter strategy
//! pools honestly and `--explain` can surface the reasoning.

use clap::ValueEnum;
use wafrift_encoding::encoding::Strategy;

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum TargetContext {
    /// HTTP request header value (X-*, Authorization, etc.).
    Header,
    /// Request body (POST/PUT body, freeform).
    Body,
    /// URL query parameter value.
    QueryParam,
    /// Cookie value (a constrained header).
    Cookie,
}

impl TargetContext {
    pub fn label(self) -> &'static str {
        match self {
            Self::Header => "header",
            Self::Body => "body",
            Self::QueryParam => "query-param",
            Self::Cookie => "cookie",
        }
    }
}

/// Decide whether `strategy` is meaningfully applicable in `context`.
/// Returns `Ok(())` if applicable, or `Err(reason)` with a short
/// human-readable explanation.
///
/// Rules are conservative: only strategies whose output is clearly
/// unusable in a context are excluded. Borderline cases (e.g. base64
/// anywhere) stay in — `--explain` shows the reasoning and the user
/// decides.
pub fn context_applicability(s: Strategy, ctx: TargetContext) -> Result<(), &'static str> {
    use Strategy::{ChunkedSplit, DeflateEncode, GzipEncode, NullByte, ParameterPollution};
    use TargetContext::{Cookie, Header, QueryParam};
    match (s, ctx) {
        (GzipEncode | DeflateEncode, Header | Cookie | QueryParam) => Err(
            "compression produces binary output; HTTP text contexts can't carry it directly (use Content-Encoding on a body)",
        ),
        (NullByte, Header | Cookie | QueryParam) => {
            Err("NUL bytes are stripped or rejected by HTTP header / URL parsers")
        }
        // Body intentionally NOT included: parameter-pollution output (`a=1&b=2`)
        // is valid in `application/x-www-form-urlencoded` bodies. Whether it's
        // useful in a given body subtype (JSON, multipart, raw) is the user's
        // call — we don't model body subtypes, so we permit and let them decide.
        (ParameterPollution, Header | Cookie) => Err(
            "parameter pollution operates on `key=val&key=val` syntax — headers/cookies don't parse that way",
        ),
        (ChunkedSplit, Header | Cookie | QueryParam) => {
            Err("chunked-split is a body transfer encoding — N/A in this context")
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gzip_blocked_in_header_allowed_in_body() {
        assert!(context_applicability(Strategy::GzipEncode, TargetContext::Header).is_err());
        assert!(context_applicability(Strategy::GzipEncode, TargetContext::Body).is_ok());
    }

    #[test]
    fn parameter_pollution_allowed_in_query_and_body() {
        // Body is OK because form-urlencoded bodies use `a=1&b=2` syntax —
        // we don't model body subtypes, so we leave the judgment to the user.
        assert!(
            context_applicability(Strategy::ParameterPollution, TargetContext::QueryParam).is_ok()
        );
        assert!(context_applicability(Strategy::ParameterPollution, TargetContext::Body).is_ok());
        assert!(
            context_applicability(Strategy::ParameterPollution, TargetContext::Header).is_err()
        );
        assert!(
            context_applicability(Strategy::ParameterPollution, TargetContext::Cookie).is_err()
        );
    }

    #[test]
    fn base64_applicable_everywhere() {
        for ctx in [
            TargetContext::Header,
            TargetContext::Body,
            TargetContext::QueryParam,
            TargetContext::Cookie,
        ] {
            assert!(context_applicability(Strategy::Base64Encode, ctx).is_ok());
        }
    }

    #[test]
    fn null_byte_blocked_in_text_contexts() {
        assert!(context_applicability(Strategy::NullByte, TargetContext::Header).is_err());
        assert!(context_applicability(Strategy::NullByte, TargetContext::Body).is_ok());
    }

    // ── Density ramp ────────────────────────────────────────

    #[test]
    fn chunked_split_blocked_in_every_text_context() {
        for ctx in [
            TargetContext::Header,
            TargetContext::Cookie,
            TargetContext::QueryParam,
        ] {
            assert!(
                context_applicability(Strategy::ChunkedSplit, ctx).is_err(),
                "ChunkedSplit must be blocked in {ctx:?}"
            );
        }
        // Body is the legitimate carrier — must be OK.
        assert!(context_applicability(Strategy::ChunkedSplit, TargetContext::Body).is_ok());
    }

    #[test]
    fn deflate_encode_blocked_in_text_contexts() {
        // Symmetric with gzip: HTTP text contexts can't carry
        // raw binary compression output.
        assert!(context_applicability(Strategy::DeflateEncode, TargetContext::Header).is_err());
        assert!(context_applicability(Strategy::DeflateEncode, TargetContext::Cookie).is_err());
        assert!(
            context_applicability(Strategy::DeflateEncode, TargetContext::QueryParam).is_err()
        );
        assert!(context_applicability(Strategy::DeflateEncode, TargetContext::Body).is_ok());
    }

    #[test]
    fn url_encode_applicable_in_every_context() {
        for ctx in [
            TargetContext::Header,
            TargetContext::Cookie,
            TargetContext::QueryParam,
            TargetContext::Body,
        ] {
            assert!(
                context_applicability(Strategy::UrlEncode, ctx).is_ok(),
                "url-encode must be applicable in {ctx:?}"
            );
        }
    }

    #[test]
    fn unicode_encode_applicable_in_every_context() {
        for ctx in [
            TargetContext::Header,
            TargetContext::Cookie,
            TargetContext::QueryParam,
            TargetContext::Body,
        ] {
            assert!(context_applicability(Strategy::UnicodeEncode, ctx).is_ok());
        }
    }

    #[test]
    fn hex_encode_applicable_in_every_context() {
        for ctx in [
            TargetContext::Header,
            TargetContext::Cookie,
            TargetContext::QueryParam,
            TargetContext::Body,
        ] {
            assert!(context_applicability(Strategy::HexEncode, ctx).is_ok());
        }
    }

    #[test]
    fn applicability_error_message_is_human_readable() {
        // Operator-facing strings must be specific — no `Err(())`
        // tuples or opaque codes.
        let err = context_applicability(Strategy::GzipEncode, TargetContext::Header).unwrap_err();
        assert!(err.contains("compression"));
        assert!(err.len() > 20);
    }

    #[test]
    fn applicability_error_mentions_recovery_path_when_possible() {
        // The compression error tells the user where compression IS
        // applicable (the body via Content-Encoding) — operator
        // doesn't have to guess what to do next.
        let err = context_applicability(Strategy::GzipEncode, TargetContext::Cookie).unwrap_err();
        assert!(
            err.contains("body") || err.contains("Content-Encoding"),
            "error should mention the supported context: {err}"
        );
    }

    #[test]
    fn target_context_labels_are_lowercase_kebab() {
        // Match clap's `rename_all = kebab-case`.
        for ctx in [
            TargetContext::Header,
            TargetContext::Body,
            TargetContext::QueryParam,
            TargetContext::Cookie,
        ] {
            let label = ctx.label();
            assert!(
                label.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
                "label `{label}` must be lowercase-kebab"
            );
            assert!(!label.is_empty());
            assert!(!label.starts_with('-'));
            assert!(!label.ends_with('-'));
        }
    }

    #[test]
    fn query_param_label_uses_hyphen_not_underscore() {
        assert_eq!(TargetContext::QueryParam.label(), "query-param");
    }

    #[test]
    fn target_context_copy_is_cheap() {
        // TargetContext is `Copy`; passing by value should be the
        // norm.  This compile-test guards against accidentally
        // adding a non-Copy field.
        fn takes_by_value(ctx: TargetContext) -> bool {
            matches!(ctx, TargetContext::Header)
        }
        let ctx = TargetContext::Header;
        assert!(takes_by_value(ctx));
        // ctx is still usable after the call — proving Copy.
        let _ = ctx.label();
    }

    #[test]
    fn applicability_is_deterministic_across_invocations() {
        // Same input → same output, every time (no global state /
        // randomness in the rule check).
        for _ in 0..10 {
            assert!(context_applicability(Strategy::GzipEncode, TargetContext::Header).is_err());
            assert!(context_applicability(Strategy::Base64Encode, TargetContext::Header).is_ok());
        }
    }

    #[test]
    fn parameter_pollution_message_explains_syntax_mismatch() {
        let err =
            context_applicability(Strategy::ParameterPollution, TargetContext::Header).unwrap_err();
        assert!(err.contains("key=val") || err.contains("parameter pollution"));
    }
}
