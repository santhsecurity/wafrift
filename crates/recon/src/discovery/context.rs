use wafrift_types::discovery::ParameterLocation;
use wafrift_types::injection_context::InjectionContext;

pub fn auto_detect_context(
    content_type: Option<&str>,
    param_location: ParameterLocation,
    schema_type: Option<&str>,
) -> InjectionContext {
    match param_location {
        ParameterLocation::Query => InjectionContext::UrlQuery,
        ParameterLocation::Path => InjectionContext::UrlPath,
        ParameterLocation::Header => InjectionContext::HeaderValue,
        ParameterLocation::Cookie => InjectionContext::CookieValue,
        ParameterLocation::Body => {
            if let Some(ct) = content_type {
                if ct.contains("application/json") {
                    if schema_type == Some("string") {
                        return InjectionContext::JsonString;
                    } else if schema_type == Some("integer") || schema_type == Some("number") {
                        return InjectionContext::JsonNumber;
                    }
                } else if ct.contains("xml") {
                    return InjectionContext::XmlText;
                } else if ct.contains("html") {
                    return InjectionContext::HtmlText;
                } else if ct.contains("multipart/form-data") {
                    if schema_type == Some("file") {
                        return InjectionContext::MultipartFileName;
                    }
                    return InjectionContext::MultipartField;
                }
            }
            InjectionContext::PlainBody
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parameter location → fixed context ────────────────────

    #[test]
    fn query_param_is_url_query_regardless_of_other_inputs() {
        assert_eq!(
            auto_detect_context(None, ParameterLocation::Query, None),
            InjectionContext::UrlQuery
        );
        // Even with body-shaped content-type / schema, query wins.
        assert_eq!(
            auto_detect_context(
                Some("application/json"),
                ParameterLocation::Query,
                Some("string")
            ),
            InjectionContext::UrlQuery
        );
    }

    #[test]
    fn path_param_is_url_path() {
        assert_eq!(
            auto_detect_context(None, ParameterLocation::Path, None),
            InjectionContext::UrlPath
        );
    }

    #[test]
    fn header_param_is_header_value() {
        assert_eq!(
            auto_detect_context(None, ParameterLocation::Header, None),
            InjectionContext::HeaderValue
        );
    }

    #[test]
    fn cookie_param_is_cookie_value() {
        assert_eq!(
            auto_detect_context(None, ParameterLocation::Cookie, None),
            InjectionContext::CookieValue
        );
    }

    // ── body + content-type → typed body context ──────────────

    #[test]
    fn body_without_content_type_is_plain_body() {
        assert_eq!(
            auto_detect_context(None, ParameterLocation::Body, None),
            InjectionContext::PlainBody
        );
    }

    #[test]
    fn body_unknown_content_type_falls_through_to_plain() {
        assert_eq!(
            auto_detect_context(
                Some("application/octet-stream"),
                ParameterLocation::Body,
                None
            ),
            InjectionContext::PlainBody
        );
    }

    // ── application/json variants ─────────────────────────────

    #[test]
    fn json_string_schema_yields_json_string() {
        assert_eq!(
            auto_detect_context(
                Some("application/json"),
                ParameterLocation::Body,
                Some("string")
            ),
            InjectionContext::JsonString
        );
    }

    #[test]
    fn json_integer_schema_yields_json_number() {
        assert_eq!(
            auto_detect_context(
                Some("application/json"),
                ParameterLocation::Body,
                Some("integer")
            ),
            InjectionContext::JsonNumber
        );
    }

    #[test]
    fn json_number_schema_yields_json_number() {
        assert_eq!(
            auto_detect_context(
                Some("application/json"),
                ParameterLocation::Body,
                Some("number")
            ),
            InjectionContext::JsonNumber
        );
    }

    #[test]
    fn json_without_schema_falls_back_to_plain_body() {
        // Important behavior: JSON without a schema hint doesn't
        // get classified as either JsonString or JsonNumber — the
        // injector would otherwise pick the wrong escape grammar.
        assert_eq!(
            auto_detect_context(Some("application/json"), ParameterLocation::Body, None),
            InjectionContext::PlainBody
        );
    }

    #[test]
    fn json_unknown_schema_falls_back_to_plain_body() {
        assert_eq!(
            auto_detect_context(
                Some("application/json"),
                ParameterLocation::Body,
                Some("array")
            ),
            InjectionContext::PlainBody
        );
    }

    #[test]
    fn json_content_type_with_charset_still_matches() {
        // Real-world responses include "application/json; charset=utf-8".
        // contains() must still fire.
        assert_eq!(
            auto_detect_context(
                Some("application/json; charset=utf-8"),
                ParameterLocation::Body,
                Some("string")
            ),
            InjectionContext::JsonString
        );
    }

    // ── XML / HTML / multipart ────────────────────────────────

    #[test]
    fn application_xml_is_xml_text() {
        assert_eq!(
            auto_detect_context(Some("application/xml"), ParameterLocation::Body, None),
            InjectionContext::XmlText
        );
    }

    #[test]
    fn text_xml_is_xml_text() {
        // contains("xml") fires for "text/xml" too.
        assert_eq!(
            auto_detect_context(Some("text/xml"), ParameterLocation::Body, None),
            InjectionContext::XmlText
        );
    }

    #[test]
    fn text_html_is_html_text() {
        assert_eq!(
            auto_detect_context(Some("text/html"), ParameterLocation::Body, None),
            InjectionContext::HtmlText
        );
    }

    #[test]
    fn multipart_default_is_field() {
        assert_eq!(
            auto_detect_context(
                Some("multipart/form-data; boundary=----xyz"),
                ParameterLocation::Body,
                None
            ),
            InjectionContext::MultipartField
        );
    }

    #[test]
    fn multipart_with_file_schema_is_file_name() {
        // Test the upload-shaped injection — schema="file" steers
        // toward the filename slot, not the field value.
        assert_eq!(
            auto_detect_context(
                Some("multipart/form-data; boundary=----xyz"),
                ParameterLocation::Body,
                Some("file")
            ),
            InjectionContext::MultipartFileName
        );
    }

    #[test]
    fn multipart_with_non_file_schema_is_field() {
        assert_eq!(
            auto_detect_context(
                Some("multipart/form-data"),
                ParameterLocation::Body,
                Some("string")
            ),
            InjectionContext::MultipartField
        );
    }

    // ── arg ordering ──────────────────────────────────────────

    #[test]
    fn content_type_only_consulted_for_body_location() {
        // Repeats the Query test with content-type — the
        // content-type must NOT leak into a Query/Path/Header
        // classification.
        for loc in &[
            ParameterLocation::Query,
            ParameterLocation::Path,
            ParameterLocation::Header,
            ParameterLocation::Cookie,
        ] {
            let ctx = auto_detect_context(Some("application/json"), *loc, Some("string"));
            assert!(
                !matches!(ctx, InjectionContext::JsonString),
                "loc={loc:?} leaked JSON classification"
            );
        }
    }
}
