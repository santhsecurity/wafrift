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
    use TargetContext::{Body, Cookie, Header, QueryParam};
    match (s, ctx) {
        (GzipEncode | DeflateEncode, Header | Cookie | QueryParam) => Err(
            "compression produces binary output; HTTP text contexts can't carry it directly (use Content-Encoding on a body)",
        ),
        (NullByte, Header | Cookie | QueryParam) => Err(
            "NUL bytes are stripped or rejected by HTTP header / URL parsers",
        ),
        (ParameterPollution, Body | Header | Cookie) => Err(
            "parameter pollution operates on the query string (`?a=1&a=2`) — N/A in this context",
        ),
        (ChunkedSplit, Header | Cookie | QueryParam) => Err(
            "chunked-split is a body transfer encoding — N/A in this context",
        ),
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
    fn parameter_pollution_only_in_query() {
        assert!(
            context_applicability(Strategy::ParameterPollution, TargetContext::QueryParam).is_ok()
        );
        assert!(
            context_applicability(Strategy::ParameterPollution, TargetContext::Body).is_err()
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
}
