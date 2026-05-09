//! HTTP method and request types for wafrift-core.
//!
//! Intentionally simple — no dependency on any HTTP library. The transport
//! layer converts to/from `reqwest::Request` or raw bytes as needed.

use std::fmt;

use serde::{Deserialize, Serialize};

/// HTTP method — enforced at the type level instead of a bare `String`.
///
/// Using an enum prevents typos like `"POSTT"` and makes exhaustive
/// matching possible. The `Custom` variant preserves extensibility.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Method {
    /// HTTP GET.
    Get,
    /// HTTP POST.
    Post,
    /// HTTP PUT.
    Put,
    /// HTTP DELETE.
    Delete,
    /// HTTP PATCH.
    Patch,
    /// HTTP HEAD.
    Head,
    /// HTTP OPTIONS.
    Options,
    /// Non-standard or extension method.
    Custom(String),
}

impl std::str::FromStr for Method {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_ascii_uppercase().as_str() {
            "GET" => Self::Get,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "DELETE" => Self::Delete,
            "PATCH" => Self::Patch,
            "HEAD" => Self::Head,
            "OPTIONS" => Self::Options,
            other => Self::Custom(other.to_string()),
        })
    }
}

impl Method {
    /// Return the method as an uppercase string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Patch => "PATCH",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
            Self::Custom(s) => s.as_str(),
        }
    }

    /// Check if this method typically carries a request body.
    #[must_use]
    pub fn has_body(&self) -> bool {
        matches!(self, Self::Post | Self::Put | Self::Patch | Self::Custom(_))
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&str> for Method {
    fn from(s: &str) -> Self {
        s.parse().unwrap_or_else(|_| Method::Custom(s.to_string()))
    }
}

impl From<String> for Method {
    fn from(s: String) -> Self {
        s.parse().unwrap_or(Method::Custom(s))
    }
}

/// A request that wafrift can transform.
///
/// Intentionally simple — no HTTP library dependency. The transport
/// layer converts to/from `reqwest::Request` or raw bytes as needed.
///
/// # Construction
///
/// Use the provided constructors ([`Request::get`], [`Request::post`], etc.)
/// and builder methods ([`Request::header`], [`Request::with_body`]).
/// Direct struct construction is prevented by `#[non_exhaustive]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Request {
    /// HTTP method.
    pub method: Method,
    /// Full request URL.
    pub url: String,
    /// Request headers as `(name, value)` pairs.
    pub headers: Vec<(String, String)>,
    /// Optional request body.
    pub body: Option<Vec<u8>>,
}

impl Request {
    /// Create a GET request.
    pub fn get(url: impl Into<String>) -> Self {
        Self {
            method: Method::Get,
            url: url.into(),
            headers: Vec::new(),
            body: None,
        }
    }

    /// Create a POST request with a body.
    pub fn post(url: impl Into<String>, body: impl Into<Vec<u8>>) -> Self {
        Self {
            method: Method::Post,
            url: url.into(),
            headers: Vec::new(),
            body: Some(body.into()),
        }
    }

    /// Create a PUT request with a body.
    pub fn put(url: impl Into<String>, body: impl Into<Vec<u8>>) -> Self {
        Self {
            method: Method::Put,
            url: url.into(),
            headers: Vec::new(),
            body: Some(body.into()),
        }
    }

    /// Create a DELETE request.
    pub fn delete(url: impl Into<String>) -> Self {
        Self {
            method: Method::Delete,
            url: url.into(),
            headers: Vec::new(),
            body: None,
        }
    }

    /// Create a request with an arbitrary method.
    pub fn with_method(method: impl Into<Method>, url: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            url: url.into(),
            headers: Vec::new(),
            body: None,
        }
    }

    // ── Accessors ────────────────────────────────────────────────

    /// Returns a reference to the HTTP method.
    #[must_use]
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// Returns a mutable reference to the HTTP method.
    pub fn method_mut(&mut self) -> &mut Method {
        &mut self.method
    }

    /// Returns the URL as a string slice.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Returns a mutable reference to the URL.
    pub fn url_mut(&mut self) -> &mut String {
        &mut self.url
    }

    /// Returns a slice of the header pairs.
    #[must_use]
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    /// Returns a mutable reference to the headers vec.
    pub fn headers_mut(&mut self) -> &mut Vec<(String, String)> {
        &mut self.headers
    }

    /// Returns a reference to the body, if present.
    #[must_use]
    pub fn body_bytes(&self) -> Option<&[u8]> {
        self.body.as_deref()
    }

    /// Sets the body, replacing any existing body.
    pub fn set_body(&mut self, body: impl Into<Vec<u8>>) {
        self.body = Some(body.into());
    }

    /// Clears the body.
    pub fn clear_body(&mut self) {
        self.body = None;
    }

    // ── Builder methods ──────────────────────────────────────────

    /// Add a header to the request (builder pattern).
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Add a header to the request (mutable reference version).
    pub fn add_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.headers.push((name.into(), value.into()));
    }

    /// Set the request body.
    #[must_use]
    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = Some(body.into());
        self
    }

    // ── Query methods ────────────────────────────────────────────

    /// Get the value of a header by name (case-insensitive).
    #[must_use]
    pub fn get_header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Get all values for a header name (case-insensitive).
    #[must_use]
    pub fn get_headers(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// Get the Content-Type header value.
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.get_header("content-type")
    }

    /// Check if this request has a body.
    #[must_use]
    pub fn has_body(&self) -> bool {
        self.body.as_ref().is_some_and(|b| !b.is_empty())
    }

    /// Get the body as a UTF-8 string, if present and valid.
    #[must_use]
    pub fn body_str(&self) -> Option<&str> {
        self.body.as_ref().and_then(|b| std::str::from_utf8(b).ok())
    }
}

impl fmt::Display for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.method, self.url)?;
        if let Some(ct) = self.content_type() {
            write!(f, " [{ct}]")?;
        }
        if let Some(body) = &self.body {
            write!(f, " ({} bytes)", body.len())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_from_str() {
        assert_eq!("GET".parse::<Method>().unwrap(), Method::Get);
        assert_eq!("post".parse::<Method>().unwrap(), Method::Post);
        assert_eq!(
            "PURGE".parse::<Method>().unwrap(),
            Method::Custom("PURGE".into())
        );
    }

    #[test]
    fn method_as_str_roundtrip() {
        for method in &[
            Method::Get,
            Method::Post,
            Method::Put,
            Method::Delete,
            Method::Patch,
            Method::Head,
            Method::Options,
        ] {
            assert_eq!(method.as_str().parse::<Method>().unwrap(), *method);
        }
    }

    #[test]
    fn method_has_body() {
        assert!(!Method::Get.has_body());
        assert!(Method::Post.has_body());
        assert!(Method::Put.has_body());
        assert!(!Method::Head.has_body());
    }

    #[test]
    fn method_display() {
        assert_eq!(Method::Get.to_string(), "GET");
        assert_eq!(Method::Custom("PURGE".into()).to_string(), "PURGE");
    }

    #[test]
    fn request_builder() {
        let req = Request::get("https://example.com")
            .header("X-Test", "value")
            .header("Content-Type", "text/html");
        assert_eq!(req.get_header("x-test"), Some("value"));
        assert_eq!(req.content_type(), Some("text/html"));
    }

    #[test]
    fn request_get_headers_multiple() {
        let mut req = Request::get("https://example.com");
        req.add_header("Cookie", "a=1");
        req.add_header("Cookie", "b=2");
        assert_eq!(req.get_headers("cookie").len(), 2);
    }

    #[test]
    fn request_body_str() {
        let req = Request::post("https://example.com", b"hello".to_vec());
        assert_eq!(req.body_str(), Some("hello"));
        assert!(req.has_body());
    }

    #[test]
    fn request_display() {
        let req = Request::post("https://example.com/api", b"data".to_vec())
            .header("Content-Type", "application/json");
        let display = req.to_string();
        assert!(display.contains("POST"));
        assert!(display.contains("example.com"));
        assert!(display.contains("4 bytes"));
    }

    #[test]
    fn request_equality() {
        let a = Request::get("https://example.com");
        let b = Request::get("https://example.com");
        assert_eq!(a, b);
    }

    #[test]
    fn request_with_method() {
        let req = Request::with_method("PURGE", "https://example.com/cache");
        assert_eq!(req.method, Method::Custom("PURGE".into()));
    }

    #[test]
    fn request_put_and_delete() {
        let put = Request::put("https://example.com/api", b"data".to_vec());
        assert_eq!(put.method, Method::Put);
        assert!(put.has_body());

        let del = Request::delete("https://example.com/api/1");
        assert_eq!(del.method, Method::Delete);
        assert!(!del.has_body());
    }

    #[test]
    fn request_serde_roundtrip() {
        let req = Request::post("https://example.com", b"body".to_vec()).header("X-Test", "value");
        let json = serde_json::to_string(&req).expect("serialize");
        let deserialized: Request = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(req, deserialized);
    }

    #[test]
    fn request_accessors() {
        let req = Request::post("https://example.com", b"test".to_vec())
            .header("Host", "example.com");
        assert_eq!(req.url(), "https://example.com");
        assert_eq!(*req.method(), Method::Post);
        assert_eq!(req.headers().len(), 1);
        assert_eq!(req.body_bytes(), Some(b"test".as_slice()));
    }

    #[test]
    fn request_mutators() {
        let mut req = Request::get("https://example.com");
        req.set_body(b"new body");
        assert!(req.has_body());
        assert_eq!(req.body_str(), Some("new body"));
        req.clear_body();
        assert!(!req.has_body());
        *req.url_mut() = "https://other.com".to_string();
        assert_eq!(req.url(), "https://other.com");
    }
}
