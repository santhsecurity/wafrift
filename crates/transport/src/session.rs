use reqwest::cookie::Jar;
use std::path::Path;
use thiserror::Error;
use wafrift_types::Request;
use wafrift_types::session::CsrfInjectionLocation;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("Cookie jar corrupt at line {line}: {path}")]
    CookieJarCorrupt { path: String, line: usize },
    #[error("CSRF regex invalid: {reason}")]
    CsrfRegexInvalid { regex: String, reason: String },
    #[error("CSRF token not found at {url}")]
    CsrfTokenNotFound { url: String },
    #[error("Auth header invalid: {header}")]
    AuthHeaderInvalid { header: String },
    #[error("io error on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// Load a cookie jar from disk.
///
/// Reads a newline-delimited file of `Set-Cookie | url` pairs. Lines
/// starting with `#` are comments. Returns an empty jar if the file
/// does not exist (caller can `save_jar` to create it later).
///
/// # Limitation
///
/// Stock `reqwest::cookie::Jar` does not expose its internal cookie
/// store. We track cookies on disk by recording each `add_cookie_str`
/// call separately — but `load_jar` has no way to enumerate cookies
/// added to a `Jar` produced elsewhere. Cookies added programmatically
/// after `load_jar` returns are NOT persisted unless `save_jar` is
/// called with the updated jar AND the wrapper that tracked the adds.
/// For full bi-directional persistence, see the `cookie_store` crate.
pub fn load_jar(path: &Path) -> Result<Jar, SessionError> {
    let jar = Jar::default();
    if !path.exists() {
        return Ok(jar);
    }
    let contents = std::fs::read_to_string(path).map_err(|e| SessionError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    for (lineno, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((cookie_spec, url_str)) = line.split_once(" | ") else {
            return Err(SessionError::CookieJarCorrupt {
                path: path.display().to_string(),
                line: lineno + 1,
            });
        };
        let Ok(url) = reqwest::Url::parse(url_str.trim()) else {
            return Err(SessionError::CookieJarCorrupt {
                path: path.display().to_string(),
                line: lineno + 1,
            });
        };
        jar.add_cookie_str(cookie_spec.trim(), &url);
    }
    Ok(jar)
}

/// Save a cookie jar to disk.
///
/// Writes the magic header + a placeholder marker. Per the limitation
/// noted on `load_jar`, stock `reqwest::cookie::Jar` does not expose
/// its cookie store, so we cannot enumerate cookies from an arbitrary
/// jar to serialize them. The file is created (so subsequent `load_jar`
/// finds something) but has no cookie payload.
///
/// For real bi-directional persistence, callers should track
/// `add_cookie_str` calls themselves and write the file via this
/// function's same line format: `Set-Cookie | https://origin/`.
pub fn save_jar(_jar: &Jar, path: &Path) -> Result<(), SessionError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| SessionError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
    }
    let header = "# wafrift cookie jar v1\n# format: Set-Cookie | https://origin/\n";
    std::fs::write(path, header).map_err(|e| SessionError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    Ok(())
}

pub fn extract_csrf(response_body: &str, regex: &regex::Regex) -> Result<String, SessionError> {
    if let Some(m) = regex.captures(response_body).and_then(|c| c.get(1))
        && !m.as_str().is_empty()
    {
        return Ok(m.as_str().to_string());
    }
    Err(SessionError::CsrfTokenNotFound {
        url: "unknown".into(),
    })
}

pub fn inject_csrf(request: &mut Request, token: &str, location: CsrfInjectionLocation) {
    match location {
        CsrfInjectionLocation::Header => {
            request
                .headers
                .push(("X-CSRF-Token".to_string(), token.to_string()));
        }
        CsrfInjectionLocation::Query => {
            let sep = if request.url.contains('?') { "&" } else { "?" };
            request.url = format!(
                "{}{sep}csrf_token={}",
                request.url,
                urlencoding::encode(token)
            );
        }
        CsrfInjectionLocation::Body => {
            if let Some(ref mut body) = request.body {
                let mut body_str = String::from_utf8_lossy(body).into_owned();
                let sep = if body_str.is_empty() { "" } else { "&" };
                body_str = format!("{}{sep}csrf_token={}", body_str, urlencoding::encode(token));
                *body = body_str.into_bytes();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_jar_missing_file_returns_empty() {
        let tmp = std::env::temp_dir().join("wafrift_test_nonexistent_jar_12345.txt");
        let _ = std::fs::remove_file(&tmp);
        let jar = load_jar(&tmp).unwrap();
        // Jar is empty — we can't inspect it, but loading didn't panic.
        let _ = jar;
    }

    #[test]
    fn load_jar_parses_cookie_line() {
        let tmp = std::env::temp_dir().join("wafrift_test_jar_12345.txt");
        std::fs::write(&tmp, "session=abc123 | https://example.com/\n").unwrap();
        let jar = load_jar(&tmp).unwrap();
        let _ = jar;
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn load_jar_skips_comments_and_empty_lines() {
        let tmp = std::env::temp_dir().join("wafrift_test_jar_comments_12345.txt");
        std::fs::write(
            &tmp,
            "# comment\n\nfoo=bar | https://example.com/\n# another comment\n",
        )
        .unwrap();
        let jar = load_jar(&tmp).unwrap();
        let _ = jar;
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn load_jar_invalid_format_errors() {
        let tmp = std::env::temp_dir().join("wafrift_test_jar_bad_12345.txt");
        std::fs::write(&tmp, "badline\n").unwrap();
        let result = load_jar(&tmp);
        assert!(result.is_err());
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn save_jar_creates_file_with_header() {
        let tmp = std::env::temp_dir().join("wafrift_test_jar_save_12345.txt");
        let _ = std::fs::remove_file(&tmp);
        let jar = Jar::default();
        save_jar(&jar, &tmp).unwrap();
        let contents = std::fs::read_to_string(&tmp).unwrap();
        assert!(contents.contains("wafrift cookie jar"));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn extract_csrf_finds_token() {
        let re = regex::Regex::new(r#"name="csrf" value="([^"]+)""#).unwrap();
        assert_eq!(
            extract_csrf(r#"<input name="csrf" value="tok123">"#, &re).unwrap(),
            "tok123"
        );
    }

    #[test]
    fn extract_csrf_missing_returns_error() {
        let re = regex::Regex::new(r#"name="csrf" value="([^"]+)""#).unwrap();
        assert!(extract_csrf("no token here", &re).is_err());
    }

    #[test]
    fn inject_csrf_into_header() {
        let mut req = Request::get("https://example.com/");
        inject_csrf(&mut req, "tok123", CsrfInjectionLocation::Header);
        assert!(
            req.headers
                .contains(&("X-CSRF-Token".to_string(), "tok123".to_string()))
        );
    }

    #[test]
    fn inject_csrf_into_query_no_existing() {
        let mut req = Request::get("https://example.com/");
        inject_csrf(&mut req, "tok123", CsrfInjectionLocation::Query);
        assert_eq!(req.url, "https://example.com/?csrf_token=tok123");
    }

    #[test]
    fn inject_csrf_into_query_with_existing() {
        let mut req = Request::get("https://example.com/?id=1");
        inject_csrf(&mut req, "tok 123", CsrfInjectionLocation::Query);
        assert!(req.url.contains("&csrf_token=tok%20123"));
    }

    #[test]
    fn inject_csrf_into_empty_body() {
        let mut req = Request::post("https://example.com/", b"");
        inject_csrf(&mut req, "tok123", CsrfInjectionLocation::Body);
        assert_eq!(req.body, Some(b"csrf_token=tok123".to_vec()));
    }

    #[test]
    fn inject_csrf_into_existing_body() {
        let mut req = Request::post("https://example.com/", b"id=1");
        inject_csrf(&mut req, "tok123", CsrfInjectionLocation::Body);
        assert_eq!(req.body, Some(b"id=1&csrf_token=tok123".to_vec()));
    }
}
