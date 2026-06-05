use authjar::{AuthJarError, AuthSession, SessionStore};
use std::path::Path;
use thiserror::Error;
use wafrift_types::Request;
use wafrift_types::session::CsrfInjectionLocation;

/// Cookie jars are a few KB in practice (a few dozen cookies + CSRF
/// tokens). 16 MiB catches `--session-jar /dev/zero`, hostile
/// symlinks pointed at log files, or accidental aliasing — without
/// rejecting any legitimate jar we've seen in the wild.
const SESSION_JAR_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// Read a file as UTF-8 with a hard size cap enforced DURING the
/// read (so symlinks reporting len=0 cannot evade the gate the way
/// they would against a metadata()-then-read TOCTOU pattern).
fn read_capped_text(path: &Path, max_bytes: u64) -> Result<String, std::io::Error> {
    use std::io::Read;
    let f = std::fs::File::open(path)?;
    let mut limited = f.take(max_bytes + 1);
    let mut buf = Vec::with_capacity(8 * 1024);
    limited.read_to_end(&mut buf)?;
    if (buf.len() as u64) > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{}: session jar exceeds {}-byte cap",
                path.display(),
                max_bytes,
            ),
        ));
    }
    String::from_utf8(buf).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{}: session jar is not valid UTF-8: {e}", path.display()),
        )
    })
}

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
    #[error("authjar error: {0}")]
    AuthJar(#[from] AuthJarError),
    /// Body CSRF injection requires `application/x-www-form-urlencoded`.
    /// For multipart, JSON, or binary bodies the caller must use a header-
    /// based CSRF mechanism or inject the token out-of-band.
    #[error("CSRF body injection requires application/x-www-form-urlencoded, got '{content_type}'")]
    CsrfInjectIncompatibleBody { content_type: String },
    /// Body CSRF injection failed because the existing body is not valid UTF-8.
    #[error("CSRF body injection failed: body is not valid UTF-8")]
    CsrfInjectInvalidUtf8,
}

/// Load a cookie jar from disk.
///
/// Reads a newline-delimited file of `Set-Cookie | url` pairs. Lines
/// starting with `#` are comments. Returns an empty store if the file
/// does not exist (caller can `save_jar` to create it later).
///
/// Since v0.2.4 adoption, the in-memory representation is an
/// [`authjar::SessionStore`] (named session `"default"`). This gives
/// wafrift full cookie domain/path scoping, CSRF token tracking, and
/// JSON persistence for free.
pub fn load_jar(path: &Path) -> Result<SessionStore, SessionError> {
    let mut store = SessionStore::new();

    if !path.exists() {
        return Ok(store);
    }

    let mut session = AuthSession::new("default");

    let contents = read_capped_text(path, SESSION_JAR_MAX_BYTES).map_err(|e| SessionError::Io {
        path: path.display().to_string(),
        source: e,
    })?;

    // If the file looks like JSON (starts with '{' or '['), treat it as
    // an authjar SessionStore dump.
    let first_non_ws = contents.trim_start().chars().next();
    if first_non_ws == Some('{') || first_non_ws == Some('[') {
        let loaded = SessionStore::load_from_file(path)?;
        return Ok(loaded);
    }

    // Legacy newline-delimited format: Set-Cookie | https://origin/
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
        session.add_set_cookie(cookie_spec.trim(), url.host_str().unwrap_or(""));
    }

    store.add(session);
    Ok(store)
}

/// Save a cookie jar to disk.
///
/// Persist the [`SessionStore`] as JSON (authjar's native format).
/// This finally gives wafrift bi-directional cookie persistence — the
/// old `reqwest::cookie::Jar` implementation could not enumerate its
/// cookies, so `save_jar` was a stub that only wrote a header.
pub fn save_jar(store: &SessionStore, path: &Path) -> Result<(), SessionError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| SessionError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
    }
    store.save_to_file(path)?;
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

/// Bridge wafrift's 3-variant `CsrfInjectionLocation` onto authjar's
/// 5-variant `CsrfInjectionLocation`, then apply to a `Request`.
///
/// # Errors
///
/// Returns [`SessionError::CsrfInjectIncompatibleBody`] when the injection
/// location is `Body` and the request's `Content-Type` is not
/// `application/x-www-form-urlencoded`. Form-field injection into JSON,
/// multipart, or binary bodies silently corrupts them; callers should use
/// `Header` injection or set the correct content type instead.
///
/// Returns [`SessionError::CsrfInjectInvalidUtf8`] when the location is
/// `Body` and the existing body bytes are not valid UTF-8.
pub fn inject_csrf(
    request: &mut Request,
    token: &str,
    location: CsrfInjectionLocation,
) -> Result<(), SessionError> {
    let authjar_loc: authjar::CsrfInjectionLocation = match location {
        CsrfInjectionLocation::Header => {
            authjar::CsrfInjectionLocation::Header("X-CSRF-Token".to_string())
        }
        CsrfInjectionLocation::Query => {
            authjar::CsrfInjectionLocation::QueryParam("csrf_token".to_string())
        }
        CsrfInjectionLocation::Body => {
            authjar::CsrfInjectionLocation::FormField("csrf_token".to_string())
        }
    };

    let injection = authjar_loc.with_token(token);
    match injection {
        authjar::CsrfInjection::Header { name, value } => {
            request.headers.push((name, value));
        }
        authjar::CsrfInjection::QueryParam { name, value } => {
            let sep = if request.url.contains('?') { "&" } else { "?" };
            request.url = format!(
                "{}{sep}{}={}",
                request.url,
                name,
                urlencoding::encode(&value)
            );
        }
        authjar::CsrfInjection::FormField { name, value } => {
            if let Some(ref mut body) = request.body {
                // Form-field CSRF injection only applies to
                // application/x-www-form-urlencoded. For any other content
                // type (multipart, JSON, binary) we refuse rather than
                // silently corrupt. The previous `from_utf8_lossy` path
                // wrote mojibake into the body — invisible in happy-path
                // tests, catastrophic for non-Latin payloads.
                let ct = request
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                    .map(|(_, v)| v.as_str())
                    .unwrap_or("");
                if !ct.contains("application/x-www-form-urlencoded") {
                    return Err(SessionError::CsrfInjectIncompatibleBody {
                        content_type: ct.to_string(),
                    });
                }
                let body_str =
                    std::str::from_utf8(body).map_err(|_| SessionError::CsrfInjectInvalidUtf8)?;
                let sep = if body_str.is_empty() { "" } else { "&" };
                let new_body = format!("{}{sep}{}={}", body_str, name, urlencoding::encode(&value));
                *body = new_body.into_bytes();
            }
        }
        _ => {
            // JsonPath / MultipartField are not reachable from the 3-variant
            // wafrift bridge, but CsrfInjection is non_exhaustive.
            tracing::warn!("Unsupported CSRF injection variant in wafrift bridge");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use authjar::SessionSettings;

    /// Return a collision-resistant temp path for session-jar tests.
    /// Uses PID + nanosecond timestamp so parallel `cargo test` workers
    /// never collide even when running on the same machine.
    fn tmp_jar_path(suffix: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "wafrift-jar-{}-{}-{}.{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
            suffix,
            if suffix.ends_with("json") {
                "json"
            } else {
                "txt"
            },
        ))
    }

    #[test]
    fn load_jar_missing_file_returns_empty() {
        let tmp = tmp_jar_path("nonexistent");
        let _ = std::fs::remove_file(&tmp);
        let store = load_jar(&tmp).unwrap();
        assert!(store.is_empty());
    }

    #[test]
    fn load_jar_parses_cookie_line() {
        let tmp = tmp_jar_path("parses");
        std::fs::write(&tmp, "session=abc123 | https://example.com/\n").unwrap();
        let store = load_jar(&tmp).unwrap();
        assert_eq!(store.len(), 1);
        let session = store.get("default").unwrap();
        let header = session.cookie_header("example.com", &SessionSettings::default());
        assert!(header.contains("session=abc123"));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn load_jar_skips_comments_and_empty_lines() {
        let tmp = tmp_jar_path("comments");
        std::fs::write(
            &tmp,
            "# comment\n\nfoo=bar | https://example.com/\n# another comment\n",
        )
        .unwrap();
        let store = load_jar(&tmp).unwrap();
        assert_eq!(store.len(), 1);
        let session = store.get("default").unwrap();
        let header = session.cookie_header("example.com", &SessionSettings::default());
        assert!(header.contains("foo=bar"));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn load_jar_invalid_format_errors() {
        let tmp = tmp_jar_path("bad");
        std::fs::write(&tmp, "badline\n").unwrap();
        let result = load_jar(&tmp);
        assert!(result.is_err());
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn save_jar_creates_file_with_json() {
        let tmp = tmp_jar_path("save.json");
        let _ = std::fs::remove_file(&tmp);
        let mut store = SessionStore::new();
        store.add(AuthSession::new("default"));
        save_jar(&store, &tmp).unwrap();
        let contents = std::fs::read_to_string(&tmp).unwrap();
        assert!(contents.contains("default"));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn save_and_load_jar_roundtrip() {
        let tmp = tmp_jar_path("roundtrip.json");
        let _ = std::fs::remove_file(&tmp);

        let mut store = SessionStore::new();
        let mut session = AuthSession::new("default");
        session.add_cookie("session", "abc123", "example.com");
        store.add(session);

        save_jar(&store, &tmp).unwrap();
        let loaded = load_jar(&tmp).unwrap();
        assert_eq!(loaded.len(), 1);
        let session = loaded.get("default").unwrap();
        let header = session.cookie_header("example.com", &SessionSettings::default());
        assert!(header.contains("session=abc123"));

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
        inject_csrf(&mut req, "tok123", CsrfInjectionLocation::Header).unwrap();
        assert!(
            req.headers
                .contains(&("X-CSRF-Token".to_string(), "tok123".to_string()))
        );
    }

    #[test]
    fn inject_csrf_into_query_no_existing() {
        let mut req = Request::get("https://example.com/");
        inject_csrf(&mut req, "tok123", CsrfInjectionLocation::Query).unwrap();
        assert_eq!(req.url, "https://example.com/?csrf_token=tok123");
    }

    #[test]
    fn inject_csrf_into_query_with_existing() {
        let mut req = Request::get("https://example.com/?id=1");
        inject_csrf(&mut req, "tok 123", CsrfInjectionLocation::Query).unwrap();
        assert!(req.url.contains("&csrf_token=tok%20123"));
    }

    #[test]
    fn inject_csrf_into_empty_body() {
        let mut req = Request::post("https://example.com/", b"");
        req.headers.push((
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        ));
        inject_csrf(&mut req, "tok123", CsrfInjectionLocation::Body).unwrap();
        assert_eq!(req.body, Some(b"csrf_token=tok123".to_vec()));
    }

    #[test]
    fn inject_csrf_into_existing_body() {
        let mut req = Request::post("https://example.com/", b"id=1");
        req.headers.push((
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        ));
        inject_csrf(&mut req, "tok123", CsrfInjectionLocation::Body).unwrap();
        assert_eq!(req.body, Some(b"id=1&csrf_token=tok123".to_vec()));
    }

    #[test]
    fn inject_csrf_body_rejects_json_content_type() {
        let mut req = Request::post("https://example.com/", b"{\"a\":1}");
        req.headers
            .push(("Content-Type".into(), "application/json".into()));
        let err = inject_csrf(&mut req, "tok123", CsrfInjectionLocation::Body).unwrap_err();
        assert!(matches!(
            err,
            SessionError::CsrfInjectIncompatibleBody { .. }
        ));
    }

    #[test]
    fn inject_csrf_body_rejects_missing_content_type() {
        // No Content-Type header → treated as incompatible (not form-encoded)
        let mut req = Request::post("https://example.com/", b"id=1");
        let err = inject_csrf(&mut req, "tok123", CsrfInjectionLocation::Body).unwrap_err();
        assert!(matches!(
            err,
            SessionError::CsrfInjectIncompatibleBody { .. }
        ));
    }

    #[test]
    fn inject_csrf_body_rejects_non_utf8() {
        let mut req = Request::post("https://example.com/", b"\xff\xfe");
        req.headers.push((
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        ));
        let err = inject_csrf(&mut req, "tok123", CsrfInjectionLocation::Body).unwrap_err();
        assert!(matches!(err, SessionError::CsrfInjectInvalidUtf8));
    }

    // ── Round 20: bounded session-jar reads (TOCTOU defence) ─────────
    //
    // Pre-fix `std::fs::read_to_string` over an operator-supplied
    // path could OOM on `--session-jar /dev/zero`, a hostile symlink,
    // or a runaway log file alias. The bounded reader caps DURING
    // the read so symlinks reporting len=0 cannot evade the gate.

    #[test]
    fn read_capped_text_rejects_oversize_input() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!(
            "wafrift-sess-overrun-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("oversize.jar");
        {
            let mut f = std::fs::File::create(&path).expect("create");
            f.write_all(&vec![b'x'; 4096]).expect("write");
        }
        let err = super::read_capped_text(&path, 256).expect_err("must reject");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds"), "msg: {err}");
    }

    #[test]
    fn session_jar_cap_is_sane() {
        assert!(
            super::SESSION_JAR_MAX_BYTES >= 1024 * 1024,
            "SESSION_JAR_MAX_BYTES below 1 MiB — could reject legitimate jars"
        );
    }
}
