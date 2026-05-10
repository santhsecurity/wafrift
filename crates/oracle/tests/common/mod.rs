//! Shared helpers for oracle integration tests.
#![allow(dead_code)] // `oracle_property` links only constants; fp/tp tests use corpus helpers.

pub const SAMPLE_DELIM: &str = "<<<SAMPLE>>>";

/// Split vendored corpus files into individual UTF-8 snippets (often synthetic HTTP bodies).
pub fn split_corpus(raw: &str) -> Vec<String> {
    raw.split(SAMPLE_DELIM)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(std::string::ToString::to_string)
        .collect()
}

pub const CANON_CMDI: &str = "; cat /etc/passwd";
pub const CANON_PATH: &str = "../../../etc/passwd";
pub const CANON_SSRF: &str = "http://127.0.0.1/internal";
