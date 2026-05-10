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
