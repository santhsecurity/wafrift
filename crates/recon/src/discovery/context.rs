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
